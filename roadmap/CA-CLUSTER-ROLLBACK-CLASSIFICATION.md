# CA / Cluster-Admin — Rollback Classification Spec (P6.3 CA-1 + P6.4 CL-8)

**Status:** discovery / classification only. No production behavior changes in
this PR. No `saveConfigVersion` changes, no rollback capture/apply changes, no
ConfigSnapshot changes, no handler changes.

**Question:** of the CA/cert and cluster-admin mutating handlers — all of which
emit `auditEvent` but **never call `saveConfigVersion`** — does any belong on
the config-version rollback surface, or should they all be documented as
intentionally out-of-surface? This closes the last two of the four
cross-discovery groups (UC-4 ✅ #269, SC-1 ✅ #274, **CA-1**, **CL-8**) that
`roadmap/CONFIG-VERSIONING-TRIAGE.md` deferred to a single triage.

**One concern:** classification of CA + cluster-admin handlers w.r.t. rollback.
CA-1 and CL-8 are the same shape (the triage groups them); this is one concern,
not a bundle. No CA-3 key-at-rest fix, no audit-gap fix, no implementation.

---

## 0. The three authority surfaces (the lens)

Per `CATEGORY-D-PRIME-DIRECTION.md` §1, plus the threat-feed finding (#280),
state can live on up to three independent surfaces. Correct classification
requires placing each handler's state on the right one:

| Surface | Authority | Capture / Apply |
|---|---|---|
| **Rollback surface** | operator "rollback to vN" | `captureConfigBackup`/`applyConfigBackup` (configversion.go) |
| **HA / ConfigSnapshot** | CP→DP replication each heartbeat | `CurrentConfigSnapshot`/`applyConfigSnapshot` (controlplane.go) |
| **Runtime cluster state** | reconstructed at process start / by gossip | none (ephemeral) |

**Verified ConfigSnapshot membership for CA/cluster trust state**
(controlplane.go): the snapshot carries **only the cluster CA *fingerprint***
(`CAFingerprint`, captured controlplane.go:1656; applied :1550–1560 — a
fingerprint *change* triggers DP cert renewal via `caRotationNotify`, it does
**not** ship CA material) and `SessionHMAC` (:1693/:1593, auth, out of scope).
**NOT carried:** cluster CA cert/key material, the node revocation list,
enrollment tokens, the Root CA bundle, DP node keys/certs. So cluster trust
*material* is provisioned/managed out-of-band (enrollment gRPC + per-node
provisioning), never replicated as config.

---

## 1. Inventory (verified, code-grounded)

All handlers confirmed to call `auditEvent` and **never** `saveConfigVersion`
(grep: no `saveConfigVersion` in `ui_cluster.go` / `ca.go` / `enrollment.go`).

### 1a. CA / cert (P6.3 CA-1) — `ui_security.go`

| Handler | Line | Method/role | Mutates | Persists to | audit |
|---|---|---|---|---|---|
| `apiCACert` | 226 | GET/viewer | — (returns CA PEM) | — | no |
| `apiCertsUpload` | 253 | POST/admin | `certMgr.LoadCustomCA` (:278) / `ParseTLSPair` (:288) | runtime (MITM live; UI cert needs restart) | yes (:283/:293) |
| `apiCACacheClear` | 1052 | POST/admin | `certMgr.ClearCache` (:1060) | in-mem LRU only | yes (:1061) |
| `apiCARotate` | 1065 | POST/admin | `certMgr.InitCA` (:1124) + `SaveCA` (:1129) | **`/data/ca.bundle` — encrypted AES-256-GCM + PBKDF2** (ca.go:153) | yes (:1097/:1133) |
| `apiOCSPConfig` | 1159 | GET/viewer; POST/admin | `globalOCSP.Enable/Disable` (:1178/:1195) + transport swap | runtime | yes (:1197) |

### 1b. Cluster-admin (P6.4 CL-8) — `ui_cluster.go`, `ha.go`, `update_cluster.go`

| Handler | Line | Method/role | Mutates | Persists to | audit |
|---|---|---|---|---|---|
| `apiClusterMode` | 50 | POST/admin | `enableControlPlane` | cluster.json | yes |
| `apiClusterTokenCreate` | 143 | POST/admin | `globalClusterStore.GenerateToken` (:192) | cluster.json (enrollment.go:163) | yes (:208) |
| `apiClusterRevoke` | 234 | POST/admin | `globalClusterStore.RevokeNode` (:260, internal Save) | cluster.json | yes (:271) |
| `apiClusterCA` | 279 | GET/viewer; POST/admin | `globalClusterCA.ImportCA` (:317) | cluster CA store | yes (:321) |
| `apiClusterLabels` | 418 | POST/admin | `globalClusterStore.SetNodeLabels` (:445) | cluster.json | yes (:449) |
| `apiClusterDrain` | 454 | POST/admin | `globalClusterStore.SetNodeDraining` (:474) | cluster.json | yes (:484) |
| `apiClusterHAEnable` | ha.go:383 | POST/admin | `globalHA.EnableAsLeader` (:412) | runtime (HA token) | yes (:422) |
| `apiClusterUpdate` | update_cluster.go:1067 | POST/admin | `startClusterUpdate` (:1126) | runtime (`clusterUpdateState`) | yes (:1133) |

Read-only (no classification needed): `apiClusterStatus`, `apiClusterNodes`,
`apiClusterRateLimits`, `apiClusterRotation` (GET), `apiClusterAudit`,
`apiClusterRevocations`, `apiClusterMetrics`, `apiClusterUpdateStatus`.

### 1c. Cert/key persistence at rest

| Material | File / var | Encryption |
|---|---|---|
| Root CA bundle | `/data/ca.bundle` (ca.go) | **Encrypted** — AES-256-GCM + PBKDF2-SHA256 (ca.go:153) |
| Cluster CA + revocation list + (hashed) tokens | `cluster.json` (`globalClusterStore`, enrollment.go) | **Plaintext JSON**, `atomicWriteFile` 0o600 (enrollment.go:178) — tokens SHA-256-hashed |
| DP node key/cert | `dp-node.key` / `dp-node.crt` / `cluster-ca.crt` (main.go) | **Plaintext PEM**, 0o600 |

The cluster.json + DP-key plaintext-at-rest is **P6.3 CA-3** — a separate,
already-tracked design item. This spec does not address it (see §5).

---

## 2. Classification

**No handler qualifies for the rollback surface.** Each lands in one of:

| Class | Meaning | Handlers |
|---|---|---|
| **D-sec** | rollback = security regression (reverts a forward-only trust/secret decision) | `apiCARotate`, `apiCertsUpload`, `apiClusterCA`, `apiClusterRevoke`, `apiOCSPConfig` (posture) |
| **D-topology / trust** | membership/enrollment; rollback conceptually wrong | `apiClusterTokenCreate`, `apiClusterLabels`, `apiClusterDrain` |
| **Runtime-only / lifecycle (E)** | no persistent config to version | `apiCACacheClear`, `apiClusterMode`, `apiClusterHAEnable`, `apiClusterUpdate` |

**Justification that none qualify for rollback inclusion:** every mutating
handler here either (a) changes trust/secret material whose reversal is a
security regression (§3.1), (b) changes cluster membership/topology where
point-in-time rollback is semantically meaningless (a token an operator already
used, a node already drained), or (c) mutates only ephemeral runtime state with
nothing durable to restore. There is no handler whose state is both
durable-config-like AND safe to silently reverse — the bar URL categories /
DPI bypass / RateLimitExempt cleared when they were brought on-surface.

---

## 3. Hazards

### 3.1 Rollback hazards (security regression)
Rolling back any D-sec handler **silently reverses a forward-only trust
decision**: `apiCARotate` → restores the pre-rotation Root CA; `apiCertsUpload`
→ restores superseded MITM/UI certs; `apiClusterCA` → reverts to the prior
cluster CA; `apiClusterRevoke` → **un-revokes a node the operator banned**;
`apiOCSPConfig` → silently re-relaxes revocation checking. Trust and secret
rotations are monotonic by intent; the rollback log must never be a vector to
undo them. (Same shape as `auth.password_change` / `cdr.instance.revoke_rpc`,
already resolved as remove-the-saveCV in PRs #261/#263.)

### 3.2 HA-propagation hazards (dual-authority)
Cluster CA rotation already propagates fleet-wide via the `CAFingerprint`
renewal mechanism (controlplane.go:1550–1560). If cluster CA / revocation state
were *also* on the rollback surface, a CP-side rollback would change the
fingerprint and **trigger immediate cert renewal across every DP** against a
*reverted* CA — mass re-issuance or a fleet-wide trust break from a single-node
operator action. Two authorities over one trust artifact is exactly the
dual-authority hazard the domain-allowlist spec (#280) flagged; here the blast
radius is the cluster's entire trust fabric.

### 3.3 Secret / key-material risks
The Root CA bundle is **encrypted at rest** (AES-GCM+PBKDF2). Config-version
snapshots are **plaintext JSON** in `/data/config_versions/v{N}.json` (0o600).
Putting CA material on the rollback surface would write the **CA private key in
plaintext to up to 50 version files** — catastrophic key exposure that defeats
the bundle encryption. Cluster CA + DP node keys are already plaintext PEM
(CA-3); rollback would multiply that exposure surface. Key material must never
enter the rollback surface.

### 3.4 Trust-boundary impacts
Enrollment tokens, the revocation list, and the cluster CA *define the cluster
trust boundary*. Rollback rewriting them = silently re-admitting revoked nodes,
resurrecting consumed/expired tokens, or invalidating currently-trusted nodes —
the version log becomes an attack surface against cluster admission control.

### 3.5 Fleet-wide blast radius
CA/revocation changes cascade to all CPs/DPs through heartbeat + renewal. A
single-node rollback that altered them would ripple fleet-wide (mass renewal, or
re-trusting a revoked node on every node). Rollback's blast radius must stay
local-config-scoped; cluster trust changes are inherently fleet-scoped and
belong to the deliberate enrollment/rotation paths, not the rollback log.

---

## 4. Explicit surface separation

| State | Rollback surface | HA / ConfigSnapshot | Runtime cluster state |
|---|---|---|---|
| Root CA material (`/data/ca.bundle`) | **NO** (§3.3) | NO (only fingerprint, indirectly) | provisioned at start |
| Cluster CA material | **NO** (§3.1–3.3) | NO — only `CAFingerprint` (renewal trigger) | provisioned / imported |
| Node revocation list | **NO** (§3.1/3.4) | NO | `globalClusterStore` (cluster.json) |
| Enrollment tokens | **NO** (§3.4) | NO | `globalClusterStore` |
| MITM/UI certs | **NO** (§3.1/3.3) | NO | `certMgr` |
| Leaf cert cache | **NO** | NO | in-mem LRU (rebuilt) |
| OCSP enable/posture | **NO** (§3.1) | NO | runtime + transport |
| Node labels / drain | **NO** (§3.4) | (labels via NodeGroups elsewhere) | `globalClusterStore` |
| HA leader state | **NO** | NO | `globalHA` (runtime) |
| Rolling-update lifecycle | **NO** | NO | `clusterUpdateState` (runtime) |

Bottom line: CA + cluster-admin trust state is owned by the **enrollment /
CA-rotation / HA** subsystems (with the `CAFingerprint` renewal hook as its only
ConfigSnapshot touchpoint), and is **categorically out of the rollback
surface.**

---

## 5. Recommended direction & sequencing

**Direction:** close **P6.3 CA-1** and **P6.4 CL-8** as **documented
out-of-(rollback)-surface**. Do **not** add `saveConfigVersion` to any CA/cert
or cluster-admin handler, and do **not** extend `captureConfigBackup` /
`applyConfigBackup` for any of this state. (Matches how SC-1 / YARA /
scan-exclusions closed in PR #274.)

**Sequencing (spec first; implementation only if later desired, each its own
small PR, NOT bundled):**
1. **This spec PR** — records the classification; closes CA-1 + CL-8.
2. **Optional docs-only follow-up** (mirrors Finding 10.3 PR-1): brief
   "out-of-rollback-surface (see this spec)" comments on the D-sec handlers + a
   CLAUDE.md architecture note, so a future maintainer doesn't re-bucket them.

**Out of scope / separate items (flagged, NOT addressed here):**
- **P6.3 CA-3** — cluster CA + DP node key plaintext at rest (§1c). A real
  key-at-rest design item, independent of rollback; reinforced by §3.3 but not
  fixed here.
- Any audit-completeness review of these handlers (all emit `auditEvent`
  today, so no gap analogous to the domain-allowlist one).
- No CA/cluster/security-handler *behavior* changes of any kind in this track.
