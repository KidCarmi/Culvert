# Culvert Supportability Framework (CSF) — Architecture

- **Status:** Proposed target architecture (design; no implementation)
- **Date:** 2026-07-12
- **Owner:** Principal Supportability Architect
- **Depends on:** `CURRENT-STATE-GAP-ANALYSIS.md` (evidence base). This document is the top-level design; the companion specs (`SUPPORT-BUNDLE-SPEC`, `COLLECTOR-CONTRACT`, `REDACTION-MODEL`, `DIAGNOSTIC-COMMAND-FRAMEWORK`, `HEALTH-AND-EVENT-MODEL`, `SECURE-UPLOAD-ARCHITECTURE`, `SUPPORTABILITY-THREAT-MODEL`, `SUPPORTABILITY-TEST-STRATEGY`) refine each subsystem. ADRs 0028–0031 record the load-bearing decisions.

> **REVISION 2 (2026-07-13) — cloud-first.** This document was revised after the analysis-location decision (`ANALYSIS-MODEL-DECISION.md`, ADR-0012). **The appliance collects, classifies, redacts, previews, obtains consent, builds the manifest, encrypts, and uploads — it does not analyze.** All analysis, timeline construction, correlation, known-issue matching, AI, and TAC workflow live in the cloud-hosted TAC platform (`TAC-CLOUD-ARCHITECTURE.md`). The orchestration-layer components below that perform *analysis* (timeline construction, incident correlation, cluster discriminators) are **re-homed to Tier 3 (cloud)**; the appliance retains only their *collection* half plus the existing lightweight local health (`OperatorContract`). Where §2/§7 below describe appliance-side timeline/correlation, read them as **cloud responsibilities fed by appliance-collected raw evidence** — the tier split in §0.5 governs.

---

## 0.5 The three tiers (authoritative — cloud-first, ADR-0012/0014/0015)

| Tier | Runs where | Owns | Depends on cloud? |
|---|---|---|---|
| **1 — On-Prem Culvert Product** | customer environment | proxy enforcement, config, HA, admin UI, **lightweight local health/`OperatorContract`**, evidence probes | **No — never** |
| **2 — Optional Outbound Support Integration** | appliance → cloud | collect → classify → redact → privacy preview → consent → manifest+integrity → encrypt → outbound upload / queue / offline export | optional |
| **3 — Cloud-Hosted TAC Operating System** | vendor cloud | verify → sandbox extract → deterministic analysis → normalized findings → timeline → CP/DP+cluster correlation → known-issue/runbook → AI (normalized input) → TAC workflow → escalation | — |

**Mandatory principles (ADR-0014/0015):** every connection is **outbound from Culvert** over authenticated HTTPS; the cloud can never initiate into Culvert, run commands, retrieve evidence without local consent/policy, modify config, affect enforcement, access keys/credentials, request arbitrary files, or bypass redaction. If the cloud is unavailable: the product operates normally, local health stays available, the bundle queues locally, upload retries later, and offline export remains. The appliance MUST NOT host a local analyzer framework, known-issue DB, runbook search, heavy correlation, or local AI (ADR-0013).

---

## 0. Canonical vocabulary (single source of truth for all support docs)

| Term | Meaning | Identifier / type |
|---|---|---|
| **CSF** | Culvert Supportability Framework — the whole system | — |
| **CSB** | Culvert Support Bundle — the collectible artifact | format `csb/1`; file `culvert-support-<node>-<utc>.csb.tgz` / `.csb.age` when encrypted |
| **Collector** | A plugin that produces one section of a CSB | Go `Collector` iface + `CollectorMeta` |
| **Redactor** | The centralized classify-and-mask engine | `redaction.Redactor` |
| **DataClass** | Sensitivity class assigned to every field/file/stream | `PUBLIC · INTERNAL · SENSITIVE · SECRET · NEVER_EXPORT` |
| **CHR** | Component Health Record — explainable per-component health | extends `OperatorContractCheck` |
| **Timeline** | Operational timeline of correlated events | `TimelineEvent`, keyed by `correlation_id` |
| **Incident scope** | Named collector/test set for one failure class | `IncidentScope` |
| **Debug level** | L0–L4 escalation of diagnostic depth | `DebugLevel` |
| **Collect Op** | The maintenance-agent read-only host-collection operation | `POST /v1/collect` |
| **Support case** | Vendor-side case a CSB is bound to | `case_id` (opaque string) |

These names are normative. Any doc, code symbol, API field, or CLI flag that names one of these concepts MUST use the spelling above.

---

## 1. Design principles (non-negotiable, each with an enforcement hook)

| # | Principle | Enforcement mechanism (test/gate) |
|---|---|---|
| P1 | **No unrestricted OS/shell access, ever.** | No new `exec` in the proxy; host collection only via maintenance-agent argv-template registry (no `sh -c`). `TestNoShellInCollectors`, sudoers-diff CI check. |
| P2 | **A broken collector never aborts the bundle.** | Each collector runs isolated with timeout + panic recovery; failures become manifest `collection_errors` entries. `TestPartialBundle_OneCollectorPanics`. |
| P3 | **Secrets are never collected by default; fail closed on the highest class.** | Redactor default-denies unknown fields to `SENSITIVE`; `NEVER_EXPORT` material has no code path into a CSB. `TestNoSecretInBundle` (golden secret-leak test). |
| P4 | **Nothing is uploaded automatically.** | No background transfer; upload is an explicit, audited, admin-gated action with a preview gate. `TestNoAutoUpload`. |
| P5 | **Support tooling works when the appliance is degraded.** | Recovery-mode CLI path independent of GUI/control-plane/DB; collectors degrade to `unavailable`, never block. `TestBundleUnderDegradation` (DB down, disk full, GUI down). |
| P6 | **Telemetry consent ≠ support consent.** They are separate switches with separate audit trails. | Distinct config keys, distinct API scopes, distinct audit actions; `TestConsentSeparation`. |
| P7 | **Every claim is typed, bounded, deterministic, auditable.** | Explicit schemas; per-collector byte/time budgets; deterministic manifest ordering; every state transition audited. Golden-schema + determinism tests. |
| P8 | **Design for multi-runtime; build for Compose+HA.** | Collector abstraction hides runtime; runtime-specific collectors are feature-gated. `TestCollectorRuntimeGating`. |
| P9 | **Verbose debug can never stay on by accident.** | Every debug level has a mandatory TTL + watchdog auto-revert + audit; no "until disabled" state exists. `TestDebugLevelAutoRevert`. |
| P10 | **Local diagnostics never depend on the cloud.** | The catalog/upload origin is optional; all collection + redaction + encryption is in-binary and offline. `TestAirGappedBundle`. |

---

## 2. Layered architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  ACCESS LAYER  (identical contracts, three front-ends)                     │
│  • GUI: data-view="support"  • Culvert CLI: `culvert support|diagnose`     │
│  • Admin API: /api/support/* (registerSupportRoutes + uiRoutes metadata)   │
└───────────────┬──────────────────────────────────────────────────────────┘
                │ RBAC (requireRole) + C2 metadata gate + audit + rate limit
┌───────────────▼──────────────────────────────────────────────────────────┐
│  ORCHESTRATION LAYER  (in-proxy, package main → internal/support)          │
│  • Bundle lifecycle FSM     • Incident-scope resolver                      │
│  • Collector registry+runner• Debug-level controller (TTL watchdog)        │
│  • Health aggregator (CHR)  • Timeline recorder (correlation_id)           │
└───────┬───────────────────────────────────────┬──────────────────────────┘
        │                                        │
┌───────▼─────────────────┐          ┌───────────▼──────────────────────────┐
│  COLLECTOR PLANE         │          │  GOVERNANCE PLANE                     │
│  application collectors  │          │  • Redactor (DataClass registry)      │
│  read in-proc state via  │          │  • internal/secret (NEVER_EXPORT)     │
│  safe accessors only     │          │  • Manifest builder + integrity hash  │
└───────┬─────────────────┘          │  • Encryptor (backupcrypt / age)      │
        │ (host/container facts)      └───────────────────────────────────────┘
┌───────▼──────────────────────────────────────────────────────────────────┐
│  PRIVILEGED COLLECTION LAYER  (maintenance agent, separate binary)         │
│  POST /v1/collect  — read-only async op, argv-template registry, no shell  │
│  returns pre-redacted, size-bounded, field-allowlisted sections           │
└───────────────────────────────────────────────────────────────────────────┘
```

**Boundary rule:** redaction happens **at the source, inside the collector**, before any value crosses a process/network/disk boundary — never as a post-hoc scrub of an assembled blob (ADR-0029). The Governance Plane's Redactor is the *shared library* every collector calls; the orchestration layer re-validates the assembled bundle against the classifier as defense-in-depth, but the primary guarantee is source-side.

---

## 3. Where the code lives (respecting the flat-package + ADR-0002 conventions)

| Concern | Location | Rationale |
|---|---|---|
| Collector engine, registry, runner, bundle FSM, manifest | **`internal/support`** (new package) | Engine owns logic/state/persistence, per ADR-0002; testable in isolation. |
| Redaction engine + DataClass registry | **`internal/redaction`** (new package) | Reusable by collectors *and* by logging later; parity-tested like `config_surfaces`. |
| `NEVER_EXPORT` enforcement | **`internal/secret`** (existing, ADR-0007) | Already compiler-enforced; `NEVER_EXPORT` = "has no accessor that yields bytes." |
| Route family, handlers, SPA wiring, CLI one-shots, shims/aliases | **`package main`** (`support.go`, `support_ui.go`, `ui_support.go`, `support_startup.go`) | Composition root keeps singletons + wiring, per the existing shim pattern. |
| Host collect op, `/v1/collect`, collection templates | **`cmd/culvert-maint/internal/{server,runner,collect}`** | Extends the existing privileged agent; no new privileged process. |
| Cluster correlation collectors | `internal/support/cluster*` + small CP/DP instrumentation additions | Fills the per-DP-version / failover-history gaps (§7). |

New `data-view="support"` SPA panel in `static/index.html` (nav-item + view div + load/render JS) satisfies the mandatory GUI-parity rule.

---

## 4. The three front-ends share one contract

All three call the same orchestration API; none has privileged logic of its own.

- **GUI** (`data-view="support"`): request bundle (scope picker), watch progress (reuse SSE or poll `/api/support/bundles/{id}`), preview redaction, download or upload, health-explain view, timeline view, debug-level toggles with countdown.
- **Culvert CLI** (idiomatic to this codebase — one-shot flags + a thin verb shim over the same API, see `DIAGNOSTIC-COMMAND-FRAMEWORK.md`): `culvert support status|collect|inspect|validate|history|upload`; `culvert diagnose dns|tls|upstream|storage|policy|cluster`; `culvert health explain`. **Critical:** the CLI must also work in **recovery mode** as a direct one-shot (`--support-bundle <out>`) that boots a minimal collector set without the full server — this is the P5 degraded-appliance path (`main.go:319` one-shot dispatch is the seam).
- **Admin API** `/api/support/*`: the canonical surface; GUI and CLI are clients.

---

## 5. Data-flow of a bundle (happy path)

1. **Request** — admin/operator picks an incident scope (or "standard") via GUI/CLI/API. Authorized (RBAC + C2) and audited (`support.bundle.request`).
2. **Preflight** — check disk headroom (reuse `probeStorageWritability` + a fresh free-space read), estimate size, refuse if headroom < bundle budget.
3. **Scope resolution** — `IncidentScope` → ordered collector set + time window + any temporary debug level.
4. **Collection** — runner executes collectors concurrently within budgets; each redacts at source; host facts fetched via `POST /v1/collect`; failures recorded, never fatal (P2).
5. **Assembly** — manifest builder stamps versions/timestamps/ownership/hashes/collection-errors; sections written into the tar.
6. **Redaction validation** — assembled bundle re-scanned by the classifier (defense-in-depth); any `SECRET`/`NEVER_EXPORT` hit fails the bundle closed and audits it.
7. **Preview** — the operator sees the manifest + a redaction report (what was masked, counts, classes) before anything leaves the box (P3/P4).
8. **Finalize** — optional encryption (offline passphrase, or recipient public key for TAC); integrity hash sealed; bundle registered with a deterministic ID + optional `case_id`.
9. **Export** — download (offline) or explicit upload (online, post-MVP). Retention timer starts.
10. **Lifecycle** — retention → expiration → deletion, each audited (`SUPPORT-BUNDLE-SPEC.md §lifecycle`).

---

## 6. Privileged host collection — the internal diagnostics service

**Decision (ADR-0030):** do not give the proxy host access; extend the maintenance agent with a **read-only `POST /v1/collect`** operation. Attack-surface contract:

- **Transport/auth unchanged:** UDS `0660`, `SO_PEERCRED` UID allowlist; the proxy is the only allowed peer.
- **Capabilities:** an **allowlisted, read-only** template set only — `docker compose ps` (state), `docker compose logs --no-color --tail=N` (bounded), `df`/`stat` on the data volume, `docker inspect --format {{json .Image}}` (image identity only, reusing the existing enumerated whitespace-safe pattern), `date -u`/clock, `uname`. **No `--format {{json .Config.Env}}`, no arbitrary path, no write op.**
- **Redaction before return:** the agent applies a **field-allowlist / line-level scrubber to logs and inspect output before it is ever written to an op log or returned** (the `capture_running.go` parse-only pattern generalized). Raw container/system logs are scrubbed for known secret shapes (env-style `KEY=…`, `Authorization:`/`token`/`passphrase`/PEM blocks) at the agent boundary, then re-classified by the proxy Redactor.
- **Bounded:** per-call byte cap (reuse `boundedBuffer`), time budget, single-flight lock, ULID op ID, per-op audit with peer identity.
- **Sudoers:** any new read requires **narrowly enumerated, whitespace-safe** entries under the project's existing four-step contract (`packaging/sudoers/culvert-maint:12-19`); reviewed as security-critical; no wildcards; no state-changing verbs added.

If host collection is unavailable (agent absent, non-Compose runtime), the host section degrades to `unavailable` with a reason — the bundle still generates (P5/P8).

---

## 7. Cluster correlation (local-vs-cluster fault isolation)

The framework must answer "is it just this node?" The audit found this under-instrumented. Three small, high-value CP/DP instrumentation additions (each independently shippable, M5):

1. **Per-DP applied config version reported to CP** — extend `MetricsReport` (`controlplane.go:73-79`) with `applied_snapshot_version`, `applied_epoch`, `policy_version`, `ca_fingerprint`, `culvert_version`. Enables a CP-side fleet lag/drift table.
2. **Populate `EnrolledNode.Version`** (`enrollment.go:69-81`) at enroll + heartbeat — makes version skew observable.
3. **Failover/self-fence event ring** — a bounded ring of `{ts, from_role, to_role, reason, epoch}` exposed on `/api/cluster/ha` and collected into the CSB — turns the current bare counter into a timeline.

A **cluster CSB** is a fan-out: the requesting node collects its own bundle *and* the redacted `/healthz` (term/epoch → split-brain), `/api/cluster/status` (CA fingerprint → cert drift), and applied-version of each reachable peer, plus an independent etcd-endpoint reachability probe (Culvert cannot see quorum). The bundle's cluster section explicitly labels each finding **local** vs **cluster-wide** using the discriminators in `HEALTH-AND-EVENT-MODEL.md §cluster`.

---

## 8. Multi-runtime strategy

The `Collector` interface hides the runtime. Collectors declare a `Runtime` capability (`any`, `compose`, `k8s`, `host-systemd`) and a `Platform` gate; the runner skips collectors whose capability the current runtime can't satisfy, recording a `skipped:runtime` manifest note (never a failure). This lets the same bundle spec target Compose today and OVA/k8s later without re-architecting — only new runtime-specific collectors are added. HA/cluster collectors are feature-gated on `clusterRole != standalone`.

---

## 9. What the framework deliberately does NOT do (scope fence)

- It is **not** a backup/restore system (that is `backup.go`; a CSB is diagnostic, not a restore source).
- It is **not** telemetry (no continuous phone-home; opt-in telemetry is M7 and separately consented, P6).
- It does **not** open a shell, remote or local (remote support is a deferred, tightly-bounded design — `SECURE-UPLOAD-ARCHITECTURE.md §remote`).
- It does **not** collect full packet captures or raw traffic bodies by default (privacy + size); PCAP-class capture is a gated L3 diagnostic with automatic stop conditions.
- It does **not** mutate config or state (all collectors are read-only; the only "writes" are the debug-level toggle and the bundle files themselves, both audited and bounded).

---

## 10. Cross-cutting requirements traceability

| PANW-caliber requirement | CSF mechanism | Spec |
|---|---|---|
| Machine- *and* human-readable bundle | `manifest.json` + human `SUMMARY.md` in every CSB | BUNDLE-SPEC |
| Stable schema + versioning + compat rules | `csb/1` + `collector_schema_version` per section | BUNDLE-SPEC |
| Per-subsystem collector ownership | `Collector`/`CollectorMeta.Owner` | COLLECTOR-CONTRACT |
| Fail-closed on sensitive data | Redactor default `SENSITIVE`; `NEVER_EXPORT` unreachable | REDACTION-MODEL |
| Explainable health (cause/impact/evidence/remediation) | `CHR` | HEALTH-AND-EVENT-MODEL |
| "What changed before the incident" | Timeline + `correlation_id` | HEALTH-AND-EVENT-MODEL |
| Incident-scoped collection | `IncidentScope` catalog | HEALTH-AND-EVENT-MODEL |
| Bounded debug escalation | `DebugLevel` L0–L4 + TTL watchdog | HEALTH-AND-EVENT-MODEL |
| Deterministic bundle IDs + case association | `bundle_id` = hash(node, created_at, nonce); `case_id` | BUNDLE-SPEC |
| Offline + online export | passphrase / recipient-key crypto; opt-in resumable upload | SECURE-UPLOAD |
| Full threat model with controls+tests | 18 threats × control × test | THREAT-MODEL |
| CI gate: new field ⇒ classification+collector coverage | `data_surfaces_test.go` parity wall | TEST-STRATEGY |

Proceed to the subsystem specs; the milestone sequencing is in `SUPPORTABILITY-ROADMAP.md`.
