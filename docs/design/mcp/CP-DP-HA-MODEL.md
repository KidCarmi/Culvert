# MCP Control Plane / Data Plane & High Availability Model

This document specifies the Control Plane (CP) → Data Plane (DP) configuration-publication model and
the high-availability (HA) fencing posture for the two MCP capabilities defined in
[`BLUEPRINT.md`](BLUEPRINT.md) §19 (Capability A — Culvert Management MCP Server; Capability B — MCP
Security Gateway). Both capabilities publish and consume policy/catalog/credential-metadata state through
the **same shared Control-Plane publication mechanism** (per the platform doctrine in
[`README.md`](README.md): shared Control Plane services, separate enforcement engines and trust
boundaries) — this document defines that shared mechanism once. It also inventories what the existing
Culvert SWG CP/DP implementation already provides as reusable prior art, and what is net-new for MCP.

**Status:** PR-0 design artifact (Proposed). No runtime change. Repository facts are cited from
[`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md); everything else is marked `[INFER]`,
`[REC]`, or `[EXT]` per the claim legend below. Requirement IDs (`MCP-CPDP-###`, `MCP-HA-###`) are
canonical in [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) and are only referenced, not
renumbered, here. Threat IDs (`MCP-T-###`) are canonical in [`THREAT-MODEL.md`](THREAT-MODEL.md).

## Claim legend

- **[FACT]** — verified by repository read (path · symbol · lines).
- **[INFER]** — architectural inference from verified facts.
- **[REC]** — recommendation for PR-10.
- **[EXT]** — externally unverified / needs a non-repository source.
- **NOT VERIFIED** — a claim this document cannot confirm one way or the other in this session; treated
  as absent until confirmed.

---

## 1. Purpose and scope

MCP tool catalogs, policy bundles, credential-profile metadata, and server-registry entries must be
published from a Control Plane to one or more Data Planes as a single, versioned, integrity-checked unit —
mirroring the design already adopted for SWG policy/blocklist/threat-feed distribution in
[`BLUEPRINT.md`](BLUEPRINT.md) §19, but with two properties the current SWG snapshot does not yet have:
(1) a genuine **whole-snapshot validator** (signature, schema, caps, revisions, minimum version — not just
size caps), and (2) **snapshot signing** (the current SWG CP↔DP channel authenticates via mTLS + a fencing
epoch only; it does not sign the payload).

This document does not itself decide the signing scheme (ed25519 vs. a different primitive, single-key vs.
rotating trust roots) — that decision, together with its rationale, is deferred to
[`OPEN-DECISIONS.md`](OPEN-DECISIONS.md). It references the one relevant piece of prior art in-repo: the
release-catalog subsystem's ed25519 signing (`release_catalog.go` / `release_catalog_sigstore.go`, per
`CLAUDE.md`'s Release Catalog Trust sections), which is architecturally adjacent (both are "CP publishes a
signed bundle a peer must verify before trusting") but serves a different subsystem (release/update
distribution, not MCP catalog/policy distribution) and is cited here as reference prior art only, not as an
implementation this document claims exists for MCP.

---

## 2. Snapshot fields

The table below mirrors [`BLUEPRINT.md`](BLUEPRINT.md) §19's Snapshot Field / Purpose table and adds, per
field, what the existing Culvert `ConfigSnapshot` (the SWG CP→DP mechanism) already has versus what is
missing and therefore net-new for the MCP snapshot.

| Snapshot Field | Purpose | Repo status today |
|---|---|---|
| `configuration_epoch` | Fencing across Control Plane generations — a DP must reject a snapshot from a Control Plane whose epoch is behind the DP's last-observed epoch, so a partitioned/stale/zombie CP cannot roll a DP backward. | **[FACT]** HAS. `ConfigSnapshot.Epoch` — controlplane_snapshot.go:22-112 (see the `Epoch` field and its doc comment: "the issuing CP's fencing epoch (ADR-0005 S3; 0 = legacy)... DPs reject snapshots below their last-seen epoch and ratchet forward otherwise"). |
| `config_revision` | Overall configuration revision (monotonic, used for change detection / idempotent re-apply). | **[FACT]** HAS (as `Version`). `ConfigSnapshot.Version int64` — controlplane_snapshot.go:22-112. |
| `policy_revision` | Policy bundle revision, tracked independently of the overall config revision so policy-only changes are distinguishable. | **[FACT]** HAS (as `PolicyVersion`). `ConfigSnapshot.PolicyVersion int64` — controlplane_snapshot.go:22-112, doc-commented "monotonic policy version". |
| `catalog_revision` | Server-and-tool inventory revision — MCP-specific; the SWG snapshot has no analogous concept because SWG has no tool/server registry. | **MISSING.** No `catalog_revision`-equivalent field exists on `ConfigSnapshot` — controlplane_snapshot.go:22-112 has no server/tool-inventory field of any kind. Net-new for PR-2 (Registry & Catalog) / PR-10. |
| `credential_revision` | Credential-profile **metadata/version only** — never the secret material itself; lets a DP detect that its cached credential-profile shape is stale without ever receiving a secret over the CP→DP channel. | **MISSING.** `ConfigSnapshot` carries `SessionHMAC` (a shared session-signing secret, redacted from unauthenticated `GetConfig` callers per `config_surfaces.go`) but has no credential-**profile** revision concept at all — MCP credential brokering (PR-4) is a different mechanism from the session-secret sync that exists today. Net-new for PR-10; the Credential Broker (PR-4) design must define what "metadata" means here (profile ID + scope + provider version, explicitly never a secret value or ciphertext). |
| `minimum_dp_version` | Prevents publication of a snapshot to a Data Plane binary that cannot interpret required semantics (mixed-version safety gate). | **MISSING.** No field on `ConfigSnapshot` — controlplane_snapshot.go:22-112. See §5 (Mixed-version behavior) for the conflicting-docs caveat on whether any *runtime* version gate exists elsewhere in the repo. |
| `content_hash` | Integrity — a deterministic digest of the snapshot payload, used both to detect corruption/truncation and as the rollback identity (§7) that a DP acknowledges and a rollback target references. | **MISSING.** No content-hash field or computation over `ConfigSnapshot` — controlplane_snapshot.go:22-112. |
| `signature` | Authenticity — proves the snapshot was produced by a trusted Control Plane, independent of and in addition to transport (mTLS) authentication. | **MISSING.** No signature field or verification path for `ConfigSnapshot`. Integrity/authenticity today is **mTLS + epoch only** — there is no snapshot signing in the SWG CP↔DP channel. ed25519 signing exists **only** in the release-catalog subsystem (a different subsystem, cited as prior art in §1, not as an existing MCP/SWG snapshot capability). Signing-scheme selection is deferred to [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md). |
| `acknowledgement` | The DP's report back to the CP that a specific `content_hash` was received, validated, applied, and what health state resulted — closes the publish loop and is the basis for rollout/canary gating and rollback targeting. | **MISSING** as a `content_hash`-keyed acknowledgement. **[FACT]** Partial prior art exists in the *epoch* dimension only: `persistDPLastSeenEpoch` (ha_fencing.go, see §4) durably ratchets the DP's last-accepted epoch, which is a form of fencing acknowledgement — but it acknowledges an epoch, not a specific signed snapshot's content hash, and it is not reported back to the CP as an RPC acknowledgement. A genuine hash-keyed apply/health acknowledgement is net-new for PR-10. |

**Summary — fields MISSING today:** `catalog_revision`, `credential_revision`, `minimum_dp_version`,
`content_hash`, `signature`, and a hash-keyed `acknowledgement`. **Fields the repo already HAS** (under
different names, on the existing `ConfigSnapshot`): `configuration_epoch` (`Epoch`), `config_revision`
(`Version`), `policy_revision` (`PolicyVersion`).

This gap is exactly the scope of **MCP-CPDP-001** (SECURITY-REQUIREMENTS.md): *"The CP→DP snapshot MUST
carry `configuration_epoch`, config/policy/catalog/credential revisions, `minimum_dp_version` and
`content_hash`+`signature`. Repo snapshot lacks catalog/credential rev, min_dp_version, hash, signature."*

---

## 3. Whole-snapshot validation and atomic publication

**Requirement (MCP-CPDP-002):** the DP **MUST** validate signature, schema, caps, revisions, and minimum
version, and **reject partial/corrupt snapshots whole** — there is no partial-apply path.

**Repo status today [FACT]:** `validateConfigSnapshot` (controlplane_snapshot.go:263-290) exists and is
whole-reject in its *current* scope, but that scope is **size caps only** — it walks
`configSnapshotSliceCaps` and an aggregate host-scale bound, and returns an error naming the first
overflowing field so the caller rejects the entire snapshot rather than truncating it. It does **not**
check a signature (there is none — see §2), does not validate schema beyond Go's own JSON unmarshalling,
and does not check `catalog_revision`/`credential_revision`/`minimum_dp_version` (none of which exist yet).
A genuine whole-snapshot validator — signature verification, schema conformance, per-slice and aggregate
caps, revision monotonicity, and a minimum-version gate, all evaluated before any state mutation — is
**net-new** for the MCP snapshot and is the direct deliverable of MCP-CPDP-001/002.

**Atomic publication [FACT]:** the CP-side publish path already gives useful atomic-swap prior art:
`ConfigStore.Update` (controlplane_snapshot.go:443-493) performs an atomic swap of the *current* snapshot
pointer under a `maxSnapshotWireBytes` (120 MiB) frame-size ceiling. This is the CP-side "publish a new
version" primitive; it is reused conceptually for MCP catalog/policy publication, but MCP-CPDP-001/002
require the *validation* step (schema/signature/caps/revisions/min-version) to run and pass **before**
`Update` swaps the pointer — i.e., validate-then-swap, never swap-then-validate.

---

## 4. Data Plane apply sequence

[`BLUEPRINT.md`](BLUEPRINT.md) §19 specifies a seven-step DP apply sequence. The table maps each step to
its current repository state.

| # | BLUEPRINT §19 step | Repo status |
|---|---|---|
| 1 | Receive a complete snapshot. | **[FACT]** `fetchAndApply` (controlplane_client.go:274-353) is the DP-side receive loop: "validate-before-advance, fence-before-mutate." |
| 2 | Validate signature, schema, caps, revisions and minimum version. | **[FACT]** Partial — today only size-cap validation exists (`validateConfigSnapshot`, controlplane_snapshot.go:263-290, see §3). Signature/schema/revision/min-version validation is **MISSING** (net-new, §2/§3). |
| 3 | Build indexes and runtime objects outside the active path. | **NOT VERIFIED** for MCP catalog/policy objects (they do not exist yet — PR-2/PR-6). **[INFER]** the SWG DP apply path (`applyConfigSnapshot`, controlplane_snapshot.go:637-673) builds its in-memory structures as part of the same call that performs the epoch fence check; whether that construction is fully isolated from the currently-active serving path (i.e., built off to the side before the swap) versus mutated in place is not confirmed by the evidence read in this session and is called out here as a design requirement for the MCP apply path regardless of the SWG precedent. |
| 4 | Run self-validation and dry policy samples. | **MISSING / net-new.** No dry-run / self-validation-before-activation step is evidenced for the SWG snapshot apply path, and no policy-simulator-against-candidate-snapshot mechanism exists for MCP (the policy simulator itself is a PR-6/PR-9 deliverable). This is a design requirement for PR-10, not a repo capability today. |
| 5 | Atomically swap the active pointer. | **[FACT]** Prior art: `ConfigStore.Update` (controlplane_snapshot.go:443-493) atomic swap on the CP publish side; DP-side apply (`applyConfigSnapshot`, controlplane_snapshot.go:637-673) performs the DP's own activation, fencing first (`dpObserveEpoch`, called first per :644 per the verified evidence). |
| 6 | Retain the previous snapshot for rollback. | **[FACT]** Prior art: DP fail-static / last-known-good persistence exists today via `applyDPLastGoodConfigSnapshot` (controlplane_snapshot.go:981-997) and its companion `dp_last_config_snapshot.json` file — this is the retain-previous-snapshot mechanism the MCP DP apply path should reuse or mirror, not reinvent. See §7 for the rollback design proper. |
| 7 | Acknowledge the applied hash and health state. | **MISSING.** There is no `content_hash` to acknowledge (§2) and no hash-keyed CP-bound acknowledgement RPC. The closest existing analogue is epoch-ratchet persistence (`persistDPLastSeenEpoch`, ha_fencing.go, §5), which acknowledges an epoch, not a snapshot hash + health state. Net-new for PR-10. |

---

## 5. Fencing, stale-CP rejection, and last-known-good

The MCP CP/DP model reuses the existing ADR-0005 HA fencing-lease architecture rather than inventing a
parallel fencing mechanism. This is prior art, not something built for MCP specifically — it is generic
epoch-based fencing already wired into the SWG CP/DP path.

- **[FACT]** `internal/halease` — the etcd-backed fencing-lease engine; the lease key's `create_revision`
  serves as the monotonic epoch. This is the source of the `configuration_epoch` values a CP stamps onto
  a snapshot (§2).
- **[FACT]** `ha_fencing.go` `dpObserveEpoch:122-150` — the DP-side epoch ratchet: rejects any inbound
  message whose epoch is behind the DP's last-observed epoch (`epoch < last` → rejected as "from a stale
  control plane"), and rejects an unfenced/zero-epoch message once a positive epoch has already been seen
  (closing the zombie-CP-masquerading-as-legacy gap). This is the concrete mechanism satisfying
  "reject snapshots below the last-seen epoch" for MCP-HA-001.
- **[FACT]** `ha_lease.go` `WriteAllowed:251-261` — the lease-holder's own write-authority gate: in legacy
  (nil-provider) mode always allows; in lease mode, allows writes only while a grant is held **and** the
  last etcd-confirmed validity window (minus a write margin) still covers "now." This is the CP-side
  analogue that prevents a CP that has silently lost its lease from continuing to publish as if it still
  held leadership.
- **[FACT]** DP fail-open-to-fail-static behavior: `applyDPLastGoodConfigSnapshot` (controlplane_snapshot.go:981-997)
  — when a fresh snapshot cannot be validated/applied, the DP falls back to the last snapshot it durably
  persisted as good, rather than either blocking indefinitely on the CP or discarding its configuration.

**Requirement mapping:** MCP-HA-001 (SECURITY-REQUIREMENTS.md) — *"Stale Control-Plane publications MUST
be fenced by epoch; the DP MUST keep the last valid snapshot and never depend on a CP round-trip per
call. Prior art: `halease`, `dpObserveEpoch`, fail-static."*

### Hard rule: the Data Plane MUST NOT depend on the Control Plane per tool call

This is a hard architectural rule, not a performance optimization: **the request/tool-call decision path
must never perform a synchronous round trip to the Control Plane.** A DP always decides using its last
validated, activated, locally-held snapshot. This mirrors [`BLUEPRINT.md`](BLUEPRINT.md) §19's explicit
statement: *"If the Control Plane is unavailable, the Data Plane continues to decide using the last valid
snapshot. The request path never depends on a Control Plane round trip."* It is cited here as **MCP-HA-001**
and applies identically to both MCP capabilities (Management MCP inventory/policy reads and Security
Gateway per-tool-call decisions) — neither may synchronously block a decision on CP reachability.

---

## 6. Mixed-version behavior and the `minimum_dp_version` gate

**Requirement (MCP-CPDP-003):** mixed-version CP/DP behavior **MUST** be defined; a DP below
`minimum_dp_version` **MUST NOT** apply a snapshot that requires semantics it cannot interpret. This maps
to threat **MCP-T-050** (mixed-version CP/DP behavior, High severity per THREAT-MODEL.md).

**Repo status — NOT VERIFIED, conflicting documentation.** The repository has clear evidence of
**version/epoch tracking** in the CP/DP channel (the epoch ratchet described in §5, plus `PolicyVersion`
and `Version` monotonic counters, §2). What this document **cannot verify in this session** is whether any
**runtime gate** exists today that would refuse to apply a snapshot to a DP binary below some declared
minimum-version requirement — i.e., a check equivalent to "this DP's build/schema version is too old to
safely interpret this snapshot, refuse to apply." Two repository documents describe adjacent but
non-identical mixed-version postures (one framed around rolling-upgrade compatibility for the existing
SWG cluster-gaps work, the other around the MCP-specific requirement being defined here), and this
document does not have enough verified evidence to reconcile them into a single claim. Accordingly: **the
existence of a runtime `minimum_dp_version`-style gate is marked NOT VERIFIED**, and MCP-CPDP-003 should be
treated as a **net-new requirement to build**, not an existing capability to merely wire an MCP field into.
PR-10 must not assume a gate already exists elsewhere that it can silently inherit.

---

## 7. Rollback

**Design target (not measured):** atomic rollback to the previous snapshot, target SLO **< 5 minutes**
(per [`BLUEPRINT.md`](BLUEPRINT.md) §20's "Policy rollback" row) — this is a design target only, not a
measured result, and remains so until validated in a staging/canary environment. See
[`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md) for the rollout-stage gating this target feeds into.

**What "retain previous snapshot" means:** the DP must keep enough of the prior snapshot (or a reference to
it, plus the means to re-fetch/re-verify it) to atomically revert its active pointer without re-deriving
state from scratch. The closest existing prior art is the fail-static `applyDPLastGoodConfigSnapshot`
mechanism (§4/§5) — but that mechanism today serves a **fail-open-on-error** purpose (fall back to
last-known-good when a new snapshot cannot be applied), not an **operator-initiated rollback** purpose
(deliberately revert a healthy DP to an earlier signed snapshot by `content_hash`, e.g. in response to a
policy regression). MCP-HA-002 requires both directions to be supported; only the fail-static direction has
existing prior art today.

**Adjacent prior art for the rollback-identity concept (not the same mechanism):** `internal/configver`
(`DefaultMax=50`) is the existing numbered-snapshot rollback store for the **admin-config surface**
(`configversion.go` capture/apply/diff), capped at 50 retained versions. It is cited here only as evidence
that Culvert already has a "bounded, numbered, revert-to-a-prior-snapshot" pattern in production use
elsewhere in the codebase — it is a different surface (admin config, not CP→DP MCP snapshots) and is not
itself the CP→DP rollback mechanism this document specifies.

**Requirement mapping:** MCP-HA-002 (SECURITY-REQUIREMENTS.md) — *"The DP MUST retain the previous
snapshot and support atomic rollback within the rollback SLO target. Recover without partial state."*

---

## 8. Threats covered

| Threat ID | Threat | Severity | Primary requirement(s) | Where addressed in this document |
|---|---|---|---|---|
| MCP-T-047 | Stale snapshot applied | High | MCP-CPDP-002, MCP-HA-001 | §3 (whole-snapshot validation), §5 (epoch fencing) |
| MCP-T-048 | Split-brain | High | MCP-HA-001, MCP-HA-002 | §5 (fencing / lease write-authority), §7 (rollback) |
| MCP-T-049 | Stale Control-Plane publication | High | MCP-HA-001 | §5 (`dpObserveEpoch` stale-CP rejection) |
| MCP-T-050 | Mixed-version CP/DP behavior | High | MCP-CPDP-003 | §6 (`minimum_dp_version` gate — NOT VERIFIED as existing; net-new) |

## 9. Publish / validate / fence / swap / ack sequence, with rollback

```mermaid
sequenceDiagram
    participant CP as Control Plane
    participant DP as Data Plane
    participant Store as DP local store<br/>(active + last-good)

    CP->>CP: Build snapshot (config/policy/catalog/<br/>credential-metadata revisions,<br/>epoch, content_hash, signature)
    CP->>DP: Publish snapshot
    DP->>DP: Fence: reject if epoch < last-seen epoch<br/>(dpObserveEpoch, MCP-T-049)
    alt epoch rejected
        DP-->>CP: Reject (stale CP)
        DP->>Store: Continue serving last valid snapshot<br/>(no CP round-trip on the request path)
    else epoch accepted
        DP->>DP: Validate whole snapshot: signature,<br/>schema, caps, revisions, minimum_dp_version<br/>(MCP-CPDP-002, MCP-T-047)
        alt validation fails (partial/corrupt/<br/>below minimum_dp_version)
            DP-->>CP: Reject whole snapshot
            DP->>Store: Continue serving last valid snapshot
        else validation passes
            DP->>DP: Build indexes/runtime objects<br/>outside the active path
            DP->>DP: Self-validate + dry policy samples
            DP->>Store: Atomically swap active pointer;<br/>retain previous snapshot (MCP-T-048)
            DP-->>CP: Acknowledge content_hash + health state
        end
    end

    Note over CP,DP: Request/tool-call path always reads<br/>the DP's current active pointer —<br/>never blocks on a CP round-trip (MCP-HA-001)

    rect rgba(200,120,120,0.15)
        Note over DP,Store: Rollback path (operator- or<br/>health-triggered, MCP-HA-002)
        DP->>Store: Atomically revert active pointer<br/>to retained previous snapshot
        DP-->>CP: Acknowledge rollback (prior content_hash, health)
    end
```

---

## 10. Cross-references

- [`BLUEPRINT.md`](BLUEPRINT.md) §19 — source table and apply-sequence this document elaborates.
- [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) — canonical MCP-CPDP-001..003, MCP-HA-001..002
  requirement text.
- [`THREAT-MODEL.md`](THREAT-MODEL.md) — canonical MCP-T-047..050 threat definitions.
- [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) — the deferred snapshot-signing-scheme decision (§1, §2).
- [`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md) — rollout-stage gating that the rollback SLO (§7)
  feeds into.
- [`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md) — source of every `[FACT]` citation in
  this document.
