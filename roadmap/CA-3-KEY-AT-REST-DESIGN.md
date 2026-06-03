# CA-3 — Private Key Material At Rest: Security Architecture Design

**Status:** Design / discovery only. **No production code in this PR.** No Go
files changed, no encryption implemented, no rollback / HA / `ConfigSnapshot`
behavior changed. This is an architecture decision record (ADR) that inventories
every persisted private-key artifact, defines a threat model, fixes the
non-negotiable rules, evaluates encryption models, recommends an MVP, and lays
out a small-PR implementation split. Implementation is **intentionally
deferred** to follow-up PRs.

**Origin:** CA-3 was filed in `roadmap/ROOT-CA-DISCOVERY.md` §10 (finding
**CA-3**) and re-flagged in `roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md` §1c /
§5 as a real key-at-rest design item, independent of rollback. PR #281
reinforced the governing rule: **CA / private-key material must never enter
plaintext config-version rollback snapshots.** This document picks up CA-3 from
that handoff.

**Scope of the concern (one item):** plaintext-at-rest private key material —
principally the **cluster CA private key** (`cluster-ca.key`) and the **DP node
private key** (`dp-node.key`), plus the secondary **CDR/Sluice client key**
(`cdr_health.go`). The Root CA bundle (`ca.bundle`) is already
encrypted and is in scope only as the reference design and the empty-passphrase
edge case. Everything else (rollback classification, metrics, the CA-R-3 race,
the HA plaintext fallback) is owned by its own track and is referenced, not
re-litigated, here.

---

## 0. TL;DR

| | Today | After CA-3 MVP (proposed) |
|---|---|---|
| Root CA key (`ca.bundle`) | **Encrypted** — AES-256-GCM + PBKDF2-SHA256 (600k), or plaintext PEM if passphrase empty | Unchanged primary; document/optionally warn on the empty-passphrase plaintext fallback |
| Cluster CA key (`cluster-ca.key`) | **Plaintext PEM 0600** | Encrypted with the same envelope format as `ca.bundle`, gated by a local KEK |
| DP node key (`dp-node.key`) | **Plaintext PEM 0600** | Encrypted with the same envelope format, gated by a local KEK |
| CDR/Sluice client key | **Plaintext PEM 0600** (`cdr_health.go`) | Encrypted with the same envelope format (secondary target) |
| `cluster.json` (tokens/revocations) | Plaintext JSON 0600; **tokens already SHA-256-hashed** | Unchanged — contains no private keys (out of CA-3 scope) |
| UI TLS key | Self-signed regenerated each boot (not persisted); operator-supplied key is an **external** file Culvert never writes | Unchanged — Culvert does not own it at rest |
| config-version rollback / `ConfigSnapshot` | Carry **no** private key material (only `CAFingerprint` + `SessionHMAC`) | Unchanged — must stay that way (hard rule §3) |

**Recommended MVP (§5):** a single reusable encrypted-file envelope (reuse the
existing `ca.bundle` `encryptBundle`/`decryptBundle` format) wrapped by a
**file-based local KEK** (model **B**) as the default, with an
**environment/secret-manager-supplied KEK** (model **C**) as the
container/automation-friendly override, and a **passphrase-derived KEK** (model
**A**) as the interactive option. No mandatory KMS. Fail-closed on corrupt or
undecryptable material. Deterministic, auditable, opt-in-first migration.

---

## 1. Inventory of persisted private-key material (code-grounded)

All paths, modes, and functions below were read directly from the repository.
Atomic writes use `atomicWriteFile(path, data, mode)` (the hardened helper:
unique tmp → chmod → `fsync(file)` → rename → best-effort `fsync(parentdir)`;
defined in `main.go` ~`:2093`).

### 1.1 Root CA (MITM) — **already encrypted** (reference design)

| Field | Value |
|---|---|
| Artifact | Root CA cert + private key (ECDSA P-256) |
| Path | `ca.bundle` at `caRuntime.path` (CLI `-ca-path` / config `proxy.ca_path`; commonly `/data/ca.bundle`) |
| Owning component | `certMgr *CertManager` (`ca.go:59`) |
| Current format | **Encrypted bundle**: magic `PSCA` (`ca.go:84`) + version byte + iter count + 32-byte salt + 12-byte nonce + AES-256-GCM ciphertext; key = PBKDF2-SHA256, `pbkdf2Iter = 600_000` (`ca.go:86–91`). **Plaintext PEM if passphrase is empty** (`ca.go:166–168`). |
| Permissions | `0o600` via `atomicWriteFile` (`ca.go:179`) |
| Creation path | `LoadOrInitCA` → `InitCA` + `SaveCA` (`ca.go:141–183`) |
| Load path | `LoadCA` (`ca.go:187–`); decrypts via `decryptBundle` (`ca.go:204`) |
| Rotation / import | `apiCARotate` → `InitCA` + `SaveCA(caRuntime.path, caRuntime.passphrase)` (`ui_security.go:1065–`); `apiCertsUpload target=mitm` → `LoadCustomCA` (runtime, `ui_security.go:253–`) |
| Backup | Tier-1, `backup.go:62` (`Required: true`) |
| HA / cluster distribution | **No** — MITM Root CA is per-node, never in `ConfigSnapshot` or any HA bundle (`ROOT-CA-DISCOVERY.md` §2.6) |
| ConfigSnapshot / rollback | **No** — never captured (`CA-CLUSTER-ROLLBACK-CLASSIFICATION.md` §4) |
| Current risk | **LOW** when a passphrase is set; **MEDIUM** in the empty-passphrase plaintext-PEM fallback path |

### 1.2 Cluster CA — **plaintext at rest (the core CA-3 gap)**

| Field | Value |
|---|---|
| Artifact | Cluster-issuance CA cert + private key (ECDSA P-256, `EC PRIVATE KEY`) — trust anchor that signs every DP node's gRPC client cert |
| Path | `<dir>/cluster-ca.crt` + `<dir>/cluster-ca.key` (`ca.dir`, `enrollment.go:727`) |
| Owning component | `globalClusterCA *clusterCA` (`enrollment.go:705`) |
| Current format | **Plaintext PEM** — `pem.EncodeToMemory({Type:"EC PRIVATE KEY"})` after `x509.MarshalECPrivateKey` (`enrollment.go:825–829`) |
| Permissions | `0o600` via `atomicWriteFile` (key: `enrollment.go:838`; import path: `enrollment.go:1062`) |
| Creation path | `InitOrLoadCA` — generates + writes both files (`enrollment.go:791–846`) |
| Load path | `loadFromPEM` — `pem.Decode` + `x509.ParseECPrivateKey` (`enrollment.go:849–`) |
| Rotation / import | `apiClusterCA` POST → `ImportCA` (`ui_cluster.go:317`, persists at `enrollment.go:1059/1062`); auto-rotation ticker (`ca.go:525`) |
| Backup | Tier-1, `backup.go:63–64` (`Required: true`) — **plaintext key lands in every backup tarball** |
| HA / cluster distribution | **Yes** — HA leader→standby via `HAStateBundle.CAKeyEncrypted` (AES-256-GCM via HA token) + a **deprecated plaintext `CAKeyPEM`** fallback (`controlplane.go:844`; consumed at `ha.go:230–232`). The cert *fingerprint* (`CAFingerprint`) — not the key — flows in `ConfigSnapshot` (`controlplane.go:79`) |
| ConfigSnapshot / rollback | **No** — never captured; only `CAFingerprint` is in the snapshot |
| Current risk | **HIGH** — private key plaintext on disk **and** plaintext in every backup tarball; compromise lets an attacker mint cluster-trusted DP certs |

### 1.3 DP node key — **plaintext at rest, and NOT in the backup tier**

| Field | Value |
|---|---|
| Artifact | DP node client cert + private key (ECDSA P-256, `EC PRIVATE KEY`) + the cluster CA cert it trusts |
| Path | `./dp-node.crt`, `./dp-node.key`, `./cluster-ca.crt` — **CWD-relative**, hardcoded (`main.go:1968`) |
| Owning component | `persistEnrollCerts` (`main.go:1965–2019`) |
| Current format | **Plaintext PEM** — `x509.MarshalECPrivateKey` → `pem.EncodeToMemory({Type:"EC PRIVATE KEY"})` (`main.go:1970–1974`) |
| Permissions | `0o600` via `atomicWriteFile` (`main.go:1985`) |
| Creation path | Enrollment flow `persistEnrollCerts` after `EnrollResponse` received |
| Load path | DP startup reads `dp_enrollment.json` (`dpEnrollmentConfig.KeyFile`, `main.go:1993–1999`) → `buildClientTLS` (`controlplane.go:1783`) |
| Rotation / import | `RenewCert` RPC response carries new `CertPEM`/`CAPEM` (`controlplane.go:779`); cert renews on `CAFingerprint` change (`controlplane.go:1529–1538`) |
| Backup | **NOT in `defaultBackupArtifacts`** — `backup.go:62–67` lists only `ca.bundle`, `cluster-ca.crt/.key`, `cluster.json`, `ui_users.json`, `config_versions`; `dp-node.key` is CWD-relative, not under `dataDir`, so it is not packed |
| HA / cluster distribution | **No** — minted per node at enrollment; not replicated |
| ConfigSnapshot / rollback | **No** |
| Current risk | **HIGH** on disk (plaintext); note the **divergent ownership** — unlike the CP artifacts it is not under `dataDir` and not in the backup tier, so any CA-3 design must treat the DP key path explicitly, not assume `dataDir` |

### 1.4 CDR / Sluice client key — **plaintext at rest (secondary CA-3 gap)**

| Field | Value |
|---|---|
| Artifact | Client mTLS cert + private key Culvert presents to an external CDR/Sluice scanner; key is issued server-side by Sluice and returned in the `RenewCert` response |
| Path | `inst.ClientCertPath` / `inst.ClientKeyPath` (+ `CACertPath`), configurable per enrolled instance (`cdrstore.go` `CDREnrolledInstance`) |
| Owning component | `cdr_health.go` (`runRenewFor`), `cdr_pool.go` (`loadCDRCertBundle`) |
| Current format | **Plaintext PEM** |
| Permissions | `0o600` — written via `os.WriteFile(path+".tmp", …, 0o600)` then `os.Rename` (`cdr_health.go:220–233`); note this uses a **plain tmp+rename, not the hardened `atomicWriteFile`** helper |
| Creation / rotation | Enrollment + periodic renewal in `runRenewFor` (`cdr_health.go:201–`); atomic swap via rename |
| Load path | `loadCDRCertBundle(...)` (`cdr_pool.go:351, 398`) |
| Backup / ConfigSnapshot / rollback | **No** — instance paths are integration-specific, not in `defaultBackupArtifacts`, not in any snapshot |
| Current risk | **MEDIUM/HIGH** — persisted plaintext private key; same class as the cluster-CA/DP-key gap. **In CA-3 scope** as a secondary target (see §12 PR-split). |

### 1.5 UI / admin TLS key — Culvert does not persist it

| Field | Value |
|---|---|
| Artifact (self-signed) | Admin-UI server cert + key, ECDSA P-256, **regenerated fresh on every process start** by `selfSignedTLS()` (`tls.go:28–`) — never written to disk |
| Artifact (operator-supplied) | `-tls-cert` / `-tls-key` (or `proxy.tls_cert` / `proxy.tls_key`) point at **external** PEM files the operator manages; Culvert **reads** them at startup (`ui.go` ~`:104–112`) but never writes them |
| `apiCertsUpload target=ui` | **Validation only** — `certMgr.ParseTLSPair` parses the pair and returns 200; **does not persist or apply** (`ui_security.go:287–294`; gap documented as CA-9 in `ROOT-CA-DISCOVERY.md`) |
| Upstream-proxy client key (mTLS to parent) | `-client-cert`/`-client-key` (`cfg.ClientCertFile`/`ClientKeyFile`); loaded read-only via `tls.LoadX509KeyPair` (`mtls_ocsp_startup.go:39`); **operator-supplied external file Culvert never writes** (load failure is non-fatal) |
| Current risk | **N/A for CA-3** at rest — the self-signed key is ephemeral; the operator-supplied UI key and the upstream client key are external files outside Culvert's at-rest ownership. **CA-3 must not silently take ownership of operator-managed TLS key files** (rule 11). |

### 1.6 `cluster.json` — no private keys (token hashes only)

| Field | Value |
|---|---|
| Artifact | `globalClusterStore` state: enrolled-node registry, enrollment tokens, revocation list, CA-rotation progress (`enrollment.go:106–113`) |
| Path | `cluster.json`; `atomicWriteFile(path, data, 0o600)` (`enrollment.go:178`) |
| Format | **Plaintext JSON**, but **tokens are stored as `SHA-256(token)` hex — plaintext token bytes never persist** (`enrollment.go`; noted in `ROOT-CA-DISCOVERY.md` §1.5) |
| Backup | Tier-1, `backup.go:65` |
| CA-3 relevance | **Out of scope** — no asymmetric private-key material. Tokens are already one-way hashed; revocation/registry data is not secret key material. Flagged only so a future reviewer does not over-scope CA-3 to encrypt `cluster.json`. |

### 1.7 Non-persisted / transient (recorded so they are not re-scoped)

| Artifact | Why out of CA-3 at-rest scope |
|---|---|
| Leaf-cert LRU cache (`certMgr.cache`) | **Memory-only**, never persisted (`ROOT-CA-DISCOVERY.md` §5.1) |
| `caRuntime.passphrase` | In-memory plaintext for the lifetime of the process (operational tradeoff, finding CA-8). Memory-disclosure is **explicitly out of the at-rest threat model** (§2). |
| `HAStateBundle.CAKeyEncrypted` / `CAKeyPEM` | **In-transit** leader→standby, not at-rest. The deprecated plaintext field is finding CA-4, owned by an HA-protocol PR. CA-3 references it because removing on-disk plaintext is hollow if HA still ships plaintext over the wire (§8). |
| `SessionHMAC` | Auth secret in `ConfigSnapshot` (redacted for unenrolled callers, `controlplane.go:582`); symmetric, not asymmetric key material; out of CA-3 scope. |
| Session secret (`session.go`) + session revocation list | Symmetric HMAC key (env/config-supplied or random per boot) and a list of revoked **token hashes** — no asymmetric private keys; out of CA-3 scope. |

### 1.8 Confirmation: keys do **not** touch rollback / snapshot / export surfaces

Verified against `CA-CLUSTER-ROLLBACK-CLASSIFICATION.md` §0/§4 and
`ROOT-CA-DISCOVERY.md` §5.3/§5.4:

- **config-version rollback** (`captureConfigBackup`/`applyConfigBackup`,
  `configversion.go`; snapshots at `/data/config_versions/v{N}.json`, plaintext
  JSON 0600) — carries **no** CA/private-key material. No CA handler calls
  `saveConfigVersion`.
- **`ConfigSnapshot`** (CP→DP) — carries only `CAFingerprint` (`controlplane.go:79`)
  and `SessionHMAC`; **no** key material.
- **export/import** (`apiConfigExport`/`apiConfigImport`, `configBackup`) — does
  not round-trip CA/cluster-CA/DP private keys.

This is the single most important invariant to preserve; §3 hard-codes it.

---

## 2. Threat model

CA-3 is **encryption of private-key files at rest**. Be explicit about what that
can and cannot do.

### 2.1 In scope (what encryption-at-rest is meant to defend)

| # | Threat | How plaintext keys lose today |
|---|---|---|
| T1 | **Offline disk read after host compromise** | `cluster-ca.key` / `dp-node.key` are plaintext PEM; a stolen disk image yields the cluster trust anchor outright |
| T2 | **Backup archive exposure** | `cluster-ca.key` is Tier-1 in every backup tarball (`backup.go:64`); a leaked backup leaks the cluster CA key |
| T3 | **Snapshot / VM image exposure** | A cloned VM or volume snapshot contains the plaintext key files |
| T4 | **Accidental log / export inclusion** | A future code path that logs or exports a key file would emit plaintext |
| T5 | **Accidental config-version snapshot inclusion** | If a future change ever captured key material into `config_versions/`, it would be plaintext × up to 50 files (the PR #281 hazard) |
| T6 | **Stale plaintext files after migration** | A half-migrated install that leaves the old plaintext `.key` next to the new encrypted file |
| T7 | **Operator misconfiguration** | World-readable mode, wrong directory, key committed to a repo, etc. |

### 2.2 Out of scope (unless explicitly noted)

| # | Non-goal | Rationale |
|---|---|---|
| N1 | Attacker with **live root on the running host** | Can read the KEK and the decrypted in-memory key regardless; at-rest encryption is not a defense against live root |
| N2 | Attacker with **process memory read** | Decrypted keys and (for model A/C) the KEK live in process memory; finding CA-8 already records this tradeoff |
| N3 | **Malicious admin intentionally exporting keys** | An authorized admin with the KEK can always obtain plaintext; CA-3 raises the bar for *accidental* exposure, not insider exfiltration |
| N4 | **Full-disk / OS-level encryption** assumptions | CA-3 must add value *independent* of FDE (defense in depth); we neither assume FDE is present nor that it is absent |

### 2.3 What encryption-at-rest can and cannot promise

- **Can:** make a stolen disk / backup / VM snapshot useless *without the
  separately-held KEK*; shrink the blast radius of T1–T7.
- **Cannot:** protect against a live attacker who already has the KEK or
  process memory (N1, N2); substitute for correct KEK custody — if the KEK sits
  next to the ciphertext, the protection collapses to "obfuscation" (§3, §4.B).

---

## 3. Non-negotiable architecture rules

These are hard constraints on any CA-3 implementation PR. They restate and
extend the invariants already enforced by the rollback-classification and
root-CA-discovery work.

1. **Private keys must never be stored in config-version rollback snapshots.**
   (`config_versions/v{N}.json` stays key-free; PR #281's rule.)
2. **Private keys must never be emitted in metrics.** No key bytes, no
   fingerprints, no serials in any `culvert_*` metric or label.
3. **Private keys must never be emitted in audit detail.** Audit records name
   the object and the outcome only (§10).
4. **Private keys must never be emitted in logs.** Including on error paths;
   wrap any path/identifier with `sanitizeLog` + `%q` and never log key bytes.
5. **No labels/identifiers containing fingerprints, SANs, subjects, node IDs,
   or key material** in metrics/log labels (consistent with the existing
   metrics-cardinality rules in CA-2/CL-9 work).
6. **Key loading must fail closed on corrupted/undecryptable material.** A bad
   MAC, wrong KEK, truncated file, or unknown version must return an error and
   refuse to start the affected subsystem — never fall back to generating a new
   key that would silently break trust, and never serve with a partial key.
7. **Migration must be deterministic and auditable.** Same input → same result;
   every migration step emits an audit event (§10).
8. **Existing installations must have a safe migration path.** No flag day; a
   running cluster with plaintext keys must be upgradable without manual
   re-enrollment.
9. **No mandatory external KMS dependency.** KMS/HSM is an optional future hook
   (§4.D), never required to boot.
10. **Do not store the encryption key next to the encrypted private keys**
    unless the threat model explicitly accepts that limited protection. The
    file-based KEK (model B) MUST be documented as protecting **T2/T3 only when
    the KEK is excluded from the same backup/snapshot** (§4.B, §9).
11. **Do not silently take ownership of operator-supplied TLS key files**
    (`-tls-key`); those are external (§1.4).
12. **The encrypted-file format is the existing `PSCA` envelope** (`ca.go:84`)
    reused verbatim where possible — one format, one audited code path, no new
    crypto primitive invented for CA-3.

---

## 4. Encryption-model options

All four wrap a per-file **DEK**-less design first: the simplest correct shape
is to encrypt the key file directly with a KEK-derived AES-256-GCM key, reusing
`encryptBundle`/`decryptBundle`. (A DEK layer can be added later for KEK
rotation without re-encrypting; called out in §5 as a forward hook.) The models
differ only in **where the KEK / unlock material comes from.**

### A. Passphrase-derived local encryption key

- Admin supplies a passphrase / boot-unlock secret; KEK = KDF(passphrase, salt).
- **KDF:** Argon2id preferred (memory-hard, modern). Fallback: reuse the
  existing **PBKDF2-SHA256 @ 600k** already in `ca.go` if avoiding a new
  dependency is preferred for the MVP. (`golang.org/x/crypto/argon2` is the only
  add; PBKDF2 is already vendored and battle-tested in this repo.)
- **Cipher:** AES-256-GCM (already in-tree) or XChaCha20-Poly1305 (24-byte
  nonce — nicer for random-nonce safety, but a new dependency).
- **Pros:** nothing secret on disk; matches the existing
  `CULVERT_CA_PASSPHRASE` mental model; strongest against T1–T3.
- **Cons / UX:** someone/something must supply the passphrase at every boot.
- **Restart behavior:** fails closed if passphrase absent (rule 6).
- **Automation impact:** needs the passphrase in an env var / secret on
  unattended restart — which collapses into model C in practice.
- **HA implications:** every CP that may promote must have the same passphrase
  (§8); a standby without it cannot decrypt the cluster CA key on failover.

### B. File-based local KEK

- Generate a random 32-byte master key file (e.g. `kek.key`, 0600); use it to
  encrypt the key files.
- **Pros:** zero operator interaction; trivial unattended restart; one code
  path; immediate big win against T2 (backup) **iff the KEK is excluded from
  the backup set**.
- **Cons:** if the KEK lives in the same directory / same backup / same
  snapshot as the ciphertext, it protects **nothing** against T2/T3 (rule 10) —
  it only defends T4/T5 (accidental log/snapshot of the *key file* specifically)
  and raises the bar on T1 marginally. Must be paired with explicit
  backup-exclusion (§9).
- **Operational simplicity:** highest of the four.

### C. Environment / secret-manager-supplied KEK

- KEK supplied via env var (e.g. `CULVERT_KEK` / `CULVERT_CLUSTER_CA_PASSPHRASE`),
  mounted secret file, or a system secret manager (systemd-creds, Docker/K8s
  secret, Vault agent sidecar writing a file).
- **Optional integration point**, **no mandatory KMS** (rule 9).
- **Pros:** KEK never sits on the data disk; strong against T1–T3 when the
  secret is delivered out-of-band; container/orchestrator-native.
- **Cons:** secret delivery is the operator's responsibility; a misconfigured
  mount fails closed (good) but is an ops failure mode.
- **Container/VM implications:** the natural fit for Docker/K8s — the secret is
  injected, the data volume holds only ciphertext.

### D. External KMS / HSM (future hook only)

- **Not required for the first implementation.** Design an interface seam — the
  codebase already has `KeyProvider` (`ca.go`, `keyProvider KeyProvider`) as an
  HSM/KMS extensibility point. A future `KEKProvider`/envelope hook (AWS KMS,
  GCP KMS, PKCS#11) plugs in here.
- Keep the MVP's KEK resolution behind a small interface so D is additive, not a
  rewrite.

---

## 5. Recommended MVP

**Primary model: B (file-based local KEK) as default, with C
(env/secret-supplied KEK) as the override and A (passphrase) as the interactive
option — all resolving to the same `PSCA` envelope.** This mirrors the existing
Root CA design (which already does "passphrase or empty"), minimizes new
surface, and reuses one audited crypto path.

**KEK resolution order (first match wins, fail-closed if an explicitly-named
source is set but unreadable):**

1. `CULVERT_KEK` env / mounted secret file (model C) — if set.
2. Passphrase env (e.g. reuse/extend `CULVERT_CA_PASSPHRASE`, or a dedicated
   `CULVERT_CLUSTER_CA_PASSPHRASE`) → KDF (model A) — if set.
3. Local KEK file `kek.key` under the data dir, **auto-generated 0600 on first
   run if absent** (model B) — the zero-config default.

Answers to the required MVP questions:

- **What is encrypted:** `cluster-ca.key` and `dp-node.key` (the two plaintext
  gaps). `ca.bundle` already is. The same envelope is reused.
- **What stays plaintext:** all **public** material — `cluster-ca.crt`,
  `dp-node.crt`, certs in general, and `cluster.json` (token *hashes*, no
  private keys). Public certs staying plaintext is required so peers can read
  them without the KEK.
- **Algorithm:** AES-256-GCM, KEK derived via PBKDF2-SHA256 @ 600k (reuse
  `ca.go`) for the MVP; Argon2id is a fast-follow option for model A.
- **File format:** the existing `PSCA` envelope (`ca.go:84–91`) — magic +
  version + iter + 32-byte salt + 12-byte nonce + ciphertext. **One format
  across all three key files.**
- **Metadata storage:** in the file header itself (salt, nonce, iter, version) —
  no sidecar, no DB. KEK *source* is config/env, not stored beside the data.
- **Nonce generation:** 12 random bytes per write from `crypto/rand` (as
  `encryptBundle` already does); fresh salt + nonce on every save so re-encrypt
  is always safe.
- **Permissions:** `0o600` via `atomicWriteFile`, unchanged from today; the KEK
  file (model B) also `0o600`.
- **Atomic writes:** reuse `atomicWriteFile` (tmp → fsync → rename → dir fsync)
  for both the encrypted key and any quarantined plaintext (§6).
- **Corrupted files:** fail closed (rule 6) — bad magic/version/MAC → error,
  refuse to start the affected subsystem; never regenerate-and-overwrite.
- **Startup with unlock material missing:** fail closed for the affected
  subsystem. For model B the KEK auto-generates only on *first* run (no
  ciphertext yet); if ciphertext exists but the KEK is gone, that is an
  unrecoverable-without-backup error, surfaced clearly (§7, §9).
- **Operator recovery:** restore the KEK (model C secret / B `kek.key` from
  secure backup) or the passphrase; documented break-glass in §9.
- **Docker / non-interactive:** model C — inject `CULVERT_KEK` as a secret; data
  volume holds only ciphertext; no interactive prompt ever required.
- **HA / clustered:** each node may use its **own per-node KEK** (model B is
  valid for HA). The cluster CA key reaches a standby **in transit**, encrypted
  with the shared **HA token** (not an at-rest KEK), and the standby re-encrypts
  it at rest under its own local KEK. A shared at-rest KEK is therefore **not
  required** for failover; model C (shared injected KEK) remains an *option* for
  operators who prefer uniform key custody. Details in §8.

**Why this MVP fits Culvert:** secure by default (B auto-generates, but §9
documents its T2 limitation and how C closes it), deterministic, testable
(one envelope, table-driven round-trip + tamper tests), backward-compatible
(plaintext detected and migrated, §6), and small enough to ship in the PR split
of §12.

**Forward hook (not MVP):** a per-file DEK wrapped by the KEK enables KEK
rotation without re-encrypting every key. Leave the envelope versioned (the
`caVersion` byte) so a DEK-layer v2 is additive.

---

## 6. Migration strategy (plaintext → encrypted)

Deterministic, auditable, idempotent (rules 7–8). Per key file:

1. **Detect plaintext:** on load, read the file; if it lacks the `PSCA` magic
   (`ca.go:194` already does exactly this check for the Root CA), treat as
   plaintext PEM.
2. **Load + validate:** parse the PEM key (`x509.ParseECPrivateKey`); a parse
   failure is a hard error — do **not** overwrite or delete an unparseable file.
3. **Quarantine the plaintext FIRST (copy, do not move):** copy the original to
   a quarantine name (e.g. `cluster-ca.key.plaintext.bak`, 0600) **before
   touching `path`**. Use a *copy*, not a rename — `path` must remain the
   readable key until the encrypted replacement is written **and** verified.
   This is the ordering correction: the encrypted write in step 5 replaces
   `path` via rename-over, so the only safe rollback source after that point is
   the `.bak` made here.
4. **Encrypt to new format:** `encryptBundle(plaintextPEM, kek)` → `PSCA`
   envelope.
5. **Atomic write encrypted file:** `atomicWriteFile(path, ciphertext, 0o600)`
   — fsync-safe via the existing helper (rule reuses `ca.go`/`enrollment.go`
   machinery). This rename-over replaces the plaintext at `path`; the `.bak`
   from step 3 is now the only plaintext copy.
6. **Verify round-trip:** re-read `path` + `decryptBundle` and confirm it parses
   to the same key. **On failure, restore `path` from the `.bak`** and fail
   closed — never leave a `path` the subsystem cannot load.
7. **Remove or retain the quarantine copy:** only after a successful verified
   read, either delete the `.bak` or retain it for a grace window (operator
   choice; default = retain + warn). **Plaintext must not remain the active
   load target** — `path` is the encrypted file; `.bak` is recovery-only and is
   never read for trust on the happy path (tests in §11 prove this).
8. **Audit event:** emit `keyatrest.migrate.started` / `.completed` / `.failed`
   (§10) — object name + outcome only.
9. **Idempotent re-run:** a file already in `PSCA` format is a no-op (detected
   at step 1); re-running migration changes nothing. A stale `.bak` from a prior
   aborted run is overwritten by the fresh copy in step 3.
10. **Rollback on mid-migration failure:** the `.bak` copy from step 3 is the
    invariant that makes rollback real. If encryption (4), the encrypted write
    (5), or verification (6) fails, restore `path` from `.bak`, the subsystem
    fails closed with a clear error, and the operator re-runs after fixing the
    KEK. Because step 3 copies before step 5 overwrites, a readable plaintext
    key always exists at either `path` (pre-overwrite) or `.bak` (post-overwrite)
    — there is no window in which the only copy of the key has been destroyed.

**Rollout posture (recommended sequencing):**

- **Phase 1 — warning-only / opt-in:** detect plaintext keys and **log a
  warning + emit an audit event**; encrypt only when a KEK source is explicitly
  configured. No behavior change for installs that do nothing.
- **Phase 2 — default-on for new installs:** fresh `InitOrLoadCA` /
  `persistEnrollCerts` write encrypted from the start (model B auto-KEK).
- **Phase 3 — default-on for all installs after migration:** once the migration
  path has soaked, migrate existing plaintext on next start by default, keeping
  the quarantine `.bak` for a grace window.

This staged posture honors rule 8 (safe migration) and avoids a flag day.

---

## 7. Runtime load / unlock behavior

- **How secrets are provided:** env var / mounted secret (C), passphrase env
  (A), or auto/loaded local KEK file (B) — resolved in the §5 order, **read once
  at startup** (consistent with `CULVERT_CA_PASSPHRASE` being read once).
- **When unlock happens:** during the existing init sites —
  `initRootCA`/`LoadOrInitCA` for the Root CA (already), `InitOrLoadCA` for the
  cluster CA, and DP enrollment load (`dpEnrollmentConfig` → `buildClientTLS`).
- **How errors surface:** a clear, key-free error (`sanitizeLog` on paths) +
  an audit `keyatrest.unlock.failed` event; never log the KEK or key bytes.
- **Degraded vs fail-closed:** **fail closed for the affected subsystem.** If
  the cluster CA key cannot be decrypted, the control plane does not start /
  does not serve enrollment — it must not fall back to minting a new CA. The
  proxy data path (MITM) is independent and unaffected by a cluster-CA unlock
  failure.
- **UI prompt vs env/config-only:** **config/env-only for the MVP.** No
  interactive UI unlock prompt (keeps it automation-first and avoids holding
  unlock material in a web session). The admin UI may *display unlock status*
  (locked/unlocked, which source) read-only — never accept the secret over the
  web in MVP.
- **Background agents / DP nodes without keys:** a DP node with no enrollment
  cert/key starts the enrollment flow (unchanged); a DP whose `dp-node.key` is
  encrypted but whose KEK is missing **fails closed** — it cannot present a
  client cert, so it cannot join. This is correct (better than joining with a
  silently-regenerated identity).
- **Rotation / import writes encrypted material:** `apiCARotate`,
  `apiClusterCA`/`ImportCA`, auto-rotation, and `RenewCert` persistence must all
  go through the same `encryptBundle` write path so no path ever re-introduces
  plaintext (tests in §11 pin this).

---

## 8. HA / cluster implications

- **Cluster CA private key:** encrypted at rest with the CP's KEK. On HA
  leader→standby, it already travels as `HAStateBundle.CAKeyEncrypted`
  (AES-256-GCM via HA token, `controlplane.go:845`). **CA-3 at-rest encryption
  must compose with — not duplicate — this in-transit encryption.** The
  deprecated plaintext `CAKeyPEM` fallback (`ha.go:230–232`, finding CA-4) is a
  *separate* HA-protocol concern; CA-3 should note that **encrypting on disk is
  hollow if HA still ships plaintext**, and flag CA-4 as a co-requisite for the
  HA-complete story (but not implement it here).
- **Root CA:** per-node, already encrypted; not cluster-distributed; no change.
- **DP node key:** encrypted at rest with the **local node KEK** (each node has
  its own); not replicated.
- **Do encrypted key files replicate?** No. Only public material
  (`CAFingerprint`) flows in `ConfigSnapshot`; DP certs flow via
  `Enroll`/`RenewCert` responses. CA-3 changes nothing here.
- **Must the at-rest KEK be shared across CP nodes? No.** The cluster CA key
  reaches a standby **in transit**: `HAState.syncFromLeader` decrypts
  `HAStateBundle.CAKeyEncrypted` with the **HA token** and imports it via
  `ImportCASilent` (`ha.go:223–227`). The HA token — not any node's at-rest KEK
  — is the shared secret, and HA already provisions it. A standby therefore does
  **not** need the leader's at-rest KEK to receive the CA key or to promote. Each
  node persists its **own** at-rest copy under its **own local KEK** (model B is
  valid for HA). Model C (a shared injected KEK) stays an *option* for operators
  who want uniform key custody across nodes, **not a requirement**.
- **Leader/standby expectations:** the standby holds the shared **HA token** out
  of band (as today); on promotion it decrypts the in-transit bundle with that
  token, then persists its at-rest copy under its own local KEK. No shared
  at-rest KEK is implied.
- **Failover if the standby lacks its own local KEK:** for model B the local KEK
  auto-generates, so the normal failover path does not fail closed on missing
  at-rest material. The only fail-closed case is a standby that cannot obtain
  the **HA token** (already an HA prerequisite today) or, under model A/C, cannot
  obtain its configured KEK source at persist time — in which case it fails
  closed loudly rather than persisting plaintext.
- **Caveat (do not over-encrypt in transit):** because the cluster CA key is
  already AES-256-GCM-encrypted in the HA bundle via the HA token, CA-3's
  at-rest encryption must wrap the **on-disk** copy only — it must not change or
  double-wrap the in-transit `CAKeyEncrypted` path.
- **`ConfigSnapshot` carries only public material:** unchanged — only
  `CAFingerprint`. CA-3 must not add any key/secret to the snapshot.
- **How DP nodes receive certs/keys:** unchanged — minted at enrollment, renewed
  via `RenewCert`; CA-3 only changes how the DP persists its *own* key locally.
- **Avoiding dual-authority with rollback:** CA-3 must not put any key material
  on the rollback surface (rule 1); the existing classification
  (`CA-CLUSTER-ROLLBACK-CLASSIFICATION.md`) already establishes CA/cluster trust
  state as categorically out-of-rollback-surface — CA-3 reinforces it.

---

## 9. Backup / restore / disaster recovery

- **What must be backed up:** the encrypted key files (`cluster-ca.key` now
  ciphertext, `ca.bundle` already ciphertext) **and** a record of *which KEK
  source* protects them — but **not** the model-B `kek.key` in the same archive
  (rule 10).
- **What must NOT be backed up together:** the **KEK and the ciphertext must not
  live in the same backup tarball / snapshot.** Today `backup.go` packs
  `cluster-ca.key`; once it is encrypted, the tarball is safe **only if** the KEK
  is excluded. The backup design (`D1.3a-backup-design.md`) must add a rule:
  KEK material is never in the default backup set; it is provisioned out of
  band. (Concrete change deferred to the backup-owning track; CA-3 states the
  requirement.)
- **How to restore encrypted keys:** restore the tarball (ciphertext) **and**
  re-provide the KEK (model C secret / model A passphrase / model B `kek.key`
  from its separate secure store). Both halves are required.
- **If the KEK / passphrase is lost:** the encrypted keys are unrecoverable by
  design (that is the point). For the **cluster CA**, recovery = generate a new
  cluster CA and **re-enroll** DP nodes (the cluster trust fabric is rebuilt).
  For the **DP node key**, recovery = re-enroll that node. Document this loudly.
- **Break-glass story:** operators must store the KEK in a separate secret
  system (password manager / KMS / sealed secret) **before** enabling
  encryption; the migration warning phase (§6 Phase 1) exists precisely to force
  this step before plaintext is removed.
- **Expected operator warnings:** on first encryption, on plaintext detection,
  on KEK-source = model-B-default (warn that backup must exclude `kek.key`), and
  on any decrypt failure.
- **Compatibility with existing backup layout:** the file *paths* are unchanged
  (`cluster-ca.key` is still `cluster-ca.key`, just ciphertext), so the backup
  manifest shape is unchanged; only the new exclusion rule for the KEK is added.

---

## 10. Audit / logging expectations

Reuse `auditEvent` / `auditEventDiff` (`ui_helpers.go`). **Object names and
high-level outcomes only — never key bytes, passphrases, fingerprints, serials,
SANs, subjects, node IDs, or file contents** (rules 2–5). Proposed events:

| Event | When |
|---|---|
| `keyatrest.migrate.started` | A plaintext key file is detected and migration begins |
| `keyatrest.migrate.completed` | Encrypted file written + round-trip verified + plaintext quarantined |
| `keyatrest.migrate.failed` | Any migration step failed (plaintext preserved, subsystem fails closed) |
| `keyatrest.key.loaded` | An encrypted key file decrypted and loaded successfully |
| `keyatrest.plaintext.detected` | Warning-phase detection (no migration yet) |
| `keyatrest.plaintext.quarantined` | Old plaintext renamed to `.bak` after successful migration |
| `keyatrest.rotate.wrote_encrypted` | Rotation/import persisted new encrypted material |
| `keyatrest.unlock.failed` | KEK/passphrase missing or wrong; load failed closed |

Each event's object field is the **logical name** (e.g. `cluster-ca`,
`dp-node`, `root-ca`) — not the path content, not the key. Audit ring is the
in-memory `maxAuditLogs = 500` ring; tests assert on **content discriminators**,
not `len()` deltas (per the test-authoring pitfall in `CLAUDE.md`).

---

## 11. Test plan

All under `-race -count=1`, whitebox `_test.go`, table-driven where possible.

| # | Test | Asserts |
|---|---|---|
| 1 | Plaintext → encrypted migration success | After migrate, file has `PSCA` magic; decrypts to the original key; `.bak` quarantined |
| 2 | Encrypted key load success | `PSCA` file with correct KEK loads + parses |
| 3 | Wrong passphrase / KEK | Load returns error, **fails closed**, no new key generated |
| 4 | Corrupted ciphertext | Truncated / flipped-MAC file → error, fail closed |
| 5 | Missing KEK (ciphertext present) | Fail closed with clear error; no overwrite |
| 6 | Atomic-write failure preserves prior good key | Inject write error → original file intact and still loadable |
| 7 | Permissions enforced | Encrypted file + `kek.key` are `0o600` |
| 8 | Rotation writes encrypted output | `apiCARotate` / `ImportCA` produce `PSCA`, never plaintext |
| 9 | Import writes encrypted output | `apiClusterCA` import path persists ciphertext |
| 10 | No private key in `ConfigSnapshot` / config-version snapshot | Marshal snapshot + a version JSON; assert no `PRIVATE KEY` / key bytes present |
| 11 | Backup excludes / separates KEK | `defaultBackupArtifacts` does not include `kek.key`; manifest has no KEK |
| 12 | HA standby without KEK fails safely | Promotion path with missing cluster-CA KEK → fail closed, no silent new CA |
| 13 | Idempotent migration | Running migration twice on an already-`PSCA` file is a no-op |
| 14 | Old plaintext not used after success | After migration, the active load target is the encrypted file; the plaintext `.bak` is never read for trust |
| 15 | Empty-KEK / dev mode parity | The existing empty-passphrase plaintext path remains explicit + warned (no silent downgrade) |

(Existing `ca_test.go` round-trip / wrong-passphrase tests are the template for
1–4; `coldstart_clusterca_test.go` is the template for 8–9, 12.)

---

## 12. Implementation split (small PRs)

Adjusted to the actual findings — the Root CA is already encrypted, so the work
centers on the cluster CA and DP node keys, and the DP key's divergent path
(`./dp-node.key`, not under `dataDir`, not in backup) gets its own PR.

| PR | Scope | Notes |
|---|---|---|
| **PR1** | **KEK resolution + reusable encrypted-key helpers** | Extract/share the `encryptBundle`/`decryptBundle` envelope into a key-file helper; add KEK resolution (B/C/A order, §5); warning-only plaintext **detection** (no migration yet). No behavior change beyond logging/audit. |
| **PR2** | **Cluster CA key encryption / load / migration** | Encrypt `cluster-ca.key` (`enrollment.go` `InitOrLoadCA`/`ImportCA`); migrate plaintext (§6); fail-closed load; audit events. The core CA-3 gap. |
| **PR3** | **DP node key encryption / load / migration** | Encrypt `dp-node.key` (`persistEnrollCerts`, `main.go`); handle the CWD-relative path; migrate on DP start; **also** decide DP-key backup ownership (currently un-backed). |
| **PR3b** | **CDR/Sluice client key encryption (secondary)** | Encrypt `ClientKeyPath` (`cdr_health.go runRenewFor` / `cdr_pool.go loadCDRCertBundle`); migrate; also upgrade its plain tmp+rename write to the hardened `atomicWriteFile`. Independent of the cluster path; ship after PR1. |
| **PR4** ✅ | **Backup / DR rules + KEK exclusion** | **Shipped (#322).** `backup.go` excludes any `*.kek` (defense-in-depth on the named allowlist + the `config_versions/` walk); restore validation accepts an encrypted `PSCA` cluster-CA key on its cert alone (added in PR2 #319); operator KEK/break-glass notes in `docs/operator/docker-compose-backup-restore.md` § 9.4 / § 12. Full KEK-based decrypt during restore intentionally deferred. |
| **PR5** ✅ | **HA composition + CA-4 co-requisite** | **Shipped (#326).** Removed the deprecated plaintext `HAStateBundle.CAKeyPEM` field (finding CA-4); the standby now imports the CA from `CAKeyEncrypted` only and **fails closed** on a missing/invalid encrypted key (no plaintext fallback, sync returns false). The standby persists the replicated CA via the #319 cluster-CA write path (`persistReplicatedKey` → `writeClusterCAKey`), so it is encrypted at rest iff `CULVERT_CLUSTER_CA_ENCRYPT` is set **on the standby** — per-node KEK, no shared at-rest KEK, no double-wrap of the in-transit path. |
| **PR6** ✅ | **Audit / logging / diagnostics + UI status** | **Shipped.** Wired the §10 audit events that map to real code paths — `keyatrest.migrate.completed`/`.failed` (per-subsystem, deferred outcome) and `keyatrest.unlock.failed` (decrypt failure), object = logical name only (`cluster-ca`/`dp-node`/`cdr-client`), no key material/paths/detail. Added a read-only `key_at_rest` check to the existing `/api/diagnostics` operator contract (viewer-gated, GUI-wired) reporting per-subsystem encryption mode + process KEK source as enums only — never key bytes. Warning-phase `plaintext.detected` / `rotate.wrote_encrypted` deferred (no distinct code path today). No UI secret input. |
| **PR7** ✅ | **Operator guide + docs** | **Shipped.** [`docs/operator/key-at-rest.md`](../docs/operator/key-at-rest.md): enable/verify/troubleshoot/recover runbook covering all three subsystems (cluster-ca / dp-node / cdr-client), both KEK modes (env `CULVERT_KEK` + local file KEK) with Docker/K8s/systemd provisioning, the migration + `.plaintext.bak` quarantine flow, the PR6 `/api/diagnostics` `key_at_rest` statuses, the three `keyatrest.*` audit events, KEK troubleshooting, and DR/break-glass. Placeholder values only; cross-links this ADR. |

**Dependency order:** PR1 → (PR2, PR3 in parallel) → PR4/PR5 → PR6 → PR7. Each
PR is independently shippable behind the warning-only → default-on staging of
§6.

---

## 13. Explicitly out of scope for CA-3

Recorded so the implementation PRs stay tight and do not absorb adjacent work:

- **Rollback classification** of CA/cluster handlers — closed by
  `CA-CLUSTER-ROLLBACK-CLASSIFICATION.md` (#281). CA-3 only *preserves* the
  "no keys on the rollback surface" rule.
- **CA-4** (deprecated HA plaintext `CAKeyPEM` fallback) — **resolved in PR5
  (#326)**: the field is removed and the standby is encrypted-only + fail-closed.
- **CA-7** (`cpTLSConfig.ClientCAs` race test) — unrelated concurrency item.
- **CA-8** (passphrase in process memory) — out-of-scope per threat model N2.
- **CA-9** (`apiCertsUpload target=ui` persist/apply gap) — UI cert UX item.
- **Encrypting `cluster.json`** — contains no asymmetric private keys (tokens
  are SHA-256 hashes); not a CA-3 target.
- **Operator-supplied `-tls-key` files** — external, not Culvert-owned at rest
  (rule 11).
- **Metrics for key operations** — belongs with the observability tracks
  (CA-2/CL-9 lineage); CA-3 only forbids leaking key material *into* metrics.

---

## 14. References (code-grounded)

- `ca.go:59, 79–91, 95–133, 141–208` — `certMgr`, `PSCA` envelope, `pbkdf2Iter`,
  `InitCA`/`LoadOrInitCA`/`SaveCA`/`LoadCA`, `encryptBundle`/`decryptBundle`,
  empty-passphrase plaintext path, magic-header detection (`:194`).
- `enrollment.go:106–113, 705, 727, 754, 780–847, 849–`, `1059/1062` —
  `globalClusterStore`, `globalClusterCA`, `InitOrLoadCA`, plaintext
  `EC PRIVATE KEY` write, `loadFromPEM`, `ImportCA` persistence, `cluster.json`
  save (`:178`).
- `main.go:1965–2019` — `persistEnrollCerts`, `./dp-node.key` plaintext write
  (`:1985`), `dp_enrollment.json`; `:2093` `atomicWriteFile`.
- `controlplane.go:79, 779, 837–848, 1529–1538` — `ConfigSnapshot.CAFingerprint`,
  `RenewCert` `CAPEM`, `HAStateBundle` (`CACertPEM`/`CAKeyEncrypted`/deprecated
  `CAKeyPEM`), DP fingerprint-driven renewal.
- `ha.go:223–232` — HA standby `ImportCASilent` (encrypted + deprecated
  plaintext paths).
- `tls.go:28–` — `selfSignedTLS()` (ephemeral admin-UI key, not persisted).
- `cdr_health.go:201–233`, `cdr_pool.go:351, 398` — CDR/Sluice client key plaintext
  tmp+rename write (`:220–233`) and `loadCDRCertBundle`.
- `mtls_ocsp_startup.go:38–79` — upstream-proxy client key (operator-supplied, external, read-only load).
- `ui_security.go:253–295, 1065–` — `apiCertsUpload` (mitm/ui), `apiCARotate`.
- `ui_cluster.go:279–321` — `apiClusterCA` / `ImportCA`.
- `backup.go:53–67` — `defaultBackupArtifacts` (Tier-1: `ca.bundle`,
  `cluster-ca.crt/.key`, `cluster.json`; **no** `dp-node.key`).
- `configversion.go`, `ui_policy.go` (`configBackup`) — rollback surface
  (key-free).
- `roadmap/ROOT-CA-DISCOVERY.md` §1–§5, §10 (finding **CA-3**, plus CA-4/CA-8/CA-9).
- `roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md` §0, §1c, §3.3, §4, §5 (CA-3 as
  separate key-at-rest item; "keys never on rollback surface").
- `roadmap/D1.3a-backup-design.md` — backup/restore ownership (KEK-exclusion
  rule lands here).
- `CLAUDE.md` — `atomicWriteFile`/fsync conventions, `sanitizeLog`/`%q` logging,
  audit-ring test pitfall, GUI-parity rule.
