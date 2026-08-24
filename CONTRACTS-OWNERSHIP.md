# Cross-Repository Contract Ownership (Phase 5)

The three repositories — `KidCarmi/Culvert`, `KidCarmi/tac-platform`,
`KidCarmi/tac-infrastructure` — communicate **only** across explicit, versioned
wire contracts. No repository depends on another's internal source packages. In
particular, **Culvert never imports any `github.com/KidCarmi/tac-platform`
internal Go package** (verified: no such import exists in the Culvert tree, and
`tac-platform` is a nested module excluded from Culvert's `go build ./...`).

This document names each cross-boundary contract, its **single owner**, its
versioning rule, and where the machine-checkable schema lives.

---

## 1. Ownership model

| Boundary | Producer | Consumer | Contract owner |
|---|---|---|---|
| Support bundle (CSB) payload | Culvert appliance | TAC Cloud (tac-platform) | **Culvert** |
| Secure-upload API (bundle upload, receipts, case binding) | tac-platform (server) | Culvert appliance (client) | **shared — server schema owned by tac-platform, appliance client-contract owned by Culvert; the wire schema is the single source both pin to** |
| Case identifiers | tac-platform (issues them) | Culvert (references them) | **tac-platform** |
| Appliance identity / enrollment (appliance → cloud auth) | Culvert (presents) | tac-platform (verifies) | **shared — identity format owned by Culvert, verification policy owned by tac-platform** |
| Error codes (upload / case API) | tac-platform | Culvert | **tac-platform** |
| Protocol-version negotiation | both | both | **shared registry — additive only** |
| Deployed-artifact provenance (digest/version/commit/SBOM) | tac-platform (produces) | tac-infrastructure (consumes) | **tac-platform** |

**Rule:** every contract has exactly one owner. The owner is the only party that
may make a breaking change, and only via a new major version. The consumer pins
a version and negotiates.

---

## 2. Contract catalogue

### 2.1 Culvert Support Bundle — `csb/1`  (owner: Culvert)
- **Spec:** `docs/support/SUPPORT-BUNDLE-SPEC.md` (format id `csb/1`, `manifest.json` first entry).
- **Shape:** gzipped tar (or `backupcrypt`/age envelope when encrypted for upload);
  `manifest.json` + `SUMMARY.md` + `redaction-report.json` + `sections/**`.
- **Versioning:** `format id` (`csb/N`) in `manifest.json`. Additive sections are
  minor and backward-compatible; removing/retyping a required section is a new
  `csb/N+1`. The cloud extractor advertises the `csb` versions it accepts.
- **Why Culvert owns it:** the appliance is the sole producer; redaction and
  consent happen appliance-side before the bytes ever leave (ADR-0031/0014).

### 2.2 Secure-upload API  (server: tac-platform · client contract: Culvert)
- **Spec:** `docs/support/SECURE-UPLOAD-ARCHITECTURE.md` (outbound-only HTTPS,
  consent-gated, encrypted-before-send).
- **Surface:** bundle upload (resumable), upload receipt, case binding, queue/offline export.
- **Versioning:** URL-path major version (`/v1/…`) + a negotiated `csb` payload
  version. The server owns the endpoint schema; the appliance pins a major and
  degrades to queue/export if the server advertises only a newer major.
- **Invariant:** connection is always outbound from Culvert; the cloud can never
  initiate into the appliance; cloud-down ⇒ appliance operates normally and the
  bundle queues.

### 2.3 Case identifiers  (owner: tac-platform)
- Issued by the cloud when a support case is opened; the appliance treats a case
  id as an **opaque, immutable token** and never mints its own.
- **Versioning:** opaque string; any structural change is cloud-internal and MUST
  remain opaque to the appliance.

### 2.4 Appliance identity / enrollment  (format: Culvert · verification: tac-platform)
- The appliance presents an enrollment/identity credential on every outbound call.
- **Versioning:** identity document carries its own version field; the cloud's
  verification policy pins the versions it accepts. Rotation is additive
  (accept old+new during an overlap window).

### 2.5 Error codes  (owner: tac-platform)
- Stable, enumerated error codes for the upload/case API (e.g. consent-required,
  case-closed, payload-too-large, unsupported-`csb`-version).
- **Versioning:** codes are **append-only**; a code's meaning never changes. New
  codes are backward-compatible; the appliance treats unknown codes as a generic
  retryable/terminal class by range.

### 2.6 Protocol-version negotiation  (shared, additive-only registry)
- A single negotiation handshake advertises supported `csb` versions, API major,
  and identity-document versions.
- **Versioning:** the registry of capabilities is **append-only**. Negotiation
  always selects the highest mutually-supported version; absence of overlap is a
  clean, logged failure (appliance falls back to offline export), never a crash.

### 2.7 Deployed-artifact provenance  (owner: tac-platform)
- tac-platform produces immutable artifacts identified by **image digest
  (`sha256:…`), release version, source commit, and SBOM/provenance reference**.
- tac-infrastructure consumes them **by digest only** — a mutable tag (`latest`)
  is rejected in `modules/analysis_worker/variables.tf` and by the
  `no-mutable-tags` CI guard.
- **Versioning:** the provenance tuple is the contract; the infra repo pins an
  exact digest per environment in `environments/<env>/release-pin.auto.tfvars`.

---

## 3. Where the machine-checkable schemas live

Today the cross-boundary contracts are specified in prose (the `docs/support/*`
specs above) plus the executable behaviour in each repo's tests. The **frozen,
versioned, independently-testable** schema artifacts are introduced as the real
cloud slice lands, each in its owner's repo:

| Contract | Schema artifact (planned home) | Owner repo |
|---|---|---|
| `csb/N` manifest + section shapes | JSON Schema, `contracts/csb/<N>/` | Culvert |
| Secure-upload API | OpenAPI 3.1, `contracts/upload-api/v<major>/` | tac-platform |
| Error codes | enum table + JSON, `contracts/upload-api/errors.json` | tac-platform |
| Identity document | JSON Schema, `contracts/identity/<N>/` | Culvert |
| Provenance tuple | JSON Schema, `contracts/provenance/<N>/` | tac-platform |

Each schema is **versioned by directory**, has **one owner**, and is validated in
that owner's CI. The consumer vendors a **copy of the pinned version** (never a
live cross-repo import) and runs a compatibility check on a schedule — see
`CROSS-REPO-CI.md`.

---

## 4. Hard rules (enforced by construction)

1. **No source-level cross-repo dependency.** Culvert does not import tac-platform
   Go packages; tac-infrastructure contains no application services; tac-platform
   does not import Culvert internals.
2. **One owner per contract.** Only the owner cuts a breaking (major) version.
3. **Additive by default.** New fields/sections/codes/capabilities are minor and
   backward-compatible; breaking changes require a new major and an overlap window.
4. **Consumers pin, then negotiate.** No consumer follows an unpinned "latest".
5. **Appliance degrades safely.** Any contract mismatch ends in queue/offline
   export, never a failed appliance.
