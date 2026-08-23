# Tier 2 — Optional Outbound Support Integration (Export, Upload, Consent, Trust)

- **Status:** Proposed (design). Revised for the cloud-first model (`ANALYSIS-MODEL-DECISION.md`, ADR-0012). This is the **only** channel between the on-prem appliance (Tier 1) and the TAC Cloud (Tier 3).
- **Depends on:** `SUPPORT-BUNDLE-SPEC.md`, `REDACTION-MODEL.md`, `TAC-CLOUD-ARCHITECTURE.md`, `internal/backupcrypt`, `internal/ssrf`.
- **Mandatory invariants (ADR-0014/0015/0017):** every connection is **outbound from Culvert** over authenticated HTTPS; the cloud can never initiate into Culvert; if the cloud is down the appliance operates normally, health stays local, and the bundle queues/exports; nothing uploads automatically or without consent.

---

## 1. The appliance pipeline (Tier 2 is the appliance's whole job)

```
collect → classify → redact → PRIVACY PREVIEW → CUSTOMER CONSENT
        → manifest + integrity hashes → ENCRYPT → outbound upload (or queue / offline export)
```

The appliance never analyzes. Its terminal state is "encrypted bundle uploaded, queued, or exported." Everything after that is Tier 3.

---

## 2. Consent model (explicit, layered, separate from telemetry — ADR-0022/P6)

Four independent switches, four audit trails; enabling one never enables another:

| Switch | Governs | Default | Granularity | Audit |
|---|---|---|---|---|
| Bundle collection | producing a local bundle | available (RBAC-gated) | per-bundle | `support.bundle.*` |
| **Upload** | sending a bundle to TAC Cloud | **off** | **per-bundle, per-case, explicit** | `support.upload` |
| Remote support | interactive TAC session | **off / not-enabled** (deferred, §7) | per-session, time-bound | `support.remote.*` |
| Telemetry | continuous opt-in metrics | **off** | global opt-in, separate | `telemetry.*` |

**Consent is a hard gate in the state machine.** No bundle reaches `UPLOADED`/`EXPORTED` without:
1. the operator viewing the **privacy preview** (`redaction-report.json`: counts by class, per-section `class_max`, profile + exclusions — never the redacted values), and
2. an explicit consent action (GUI confirm / CLI `--yes`), audited with actor + case.

A **cloud "please send a bundle for case X" policy** the appliance may poll for on its outbound schedule still requires this local consent/policy before anything is collected or sent — the cloud can request, never compel (ADR-0014).

---

## 3. Encryption trust model (E2E to TAC — ADR-0016)

- **Two at-rest/export modes** (both reuse audited primitives):
  1. **Passphrase** — `internal/backupcrypt` (AES-256-GCM, PBKDF2-SHA256 600k iters, AAD-bound header, opaque error). For operator-controlled offline transfer; verifiable by `culvert support validate`.
  2. **Recipient public key (default for upload)** — hybrid public-key encryption (HPKE / age-style X25519) to TAC's **published, pinned public key**, with a **per-case data key**. Only TAC's cloud-KMS-held private key decrypts; the appliance holds no decryption secret. This is the "encrypt-to-TAC without a shared secret" model.
- **Trust roots** — TAC recipient public keys are **public material**, baked into the release + operator-overridable for private/regional/staging TAC, pinned exactly like the release-catalog trust roots. Rotation is additive (overlap window), key id recorded in the manifest.
- **E2E independent of TLS** — the bundle is encrypted to TAC *before* the HTTPS POST, so even a MITM or a compromised transit hop cannot read it. TLS 1.3 is defense-in-depth for transport auth, not the confidentiality boundary.
- **Never exported:** the per-bundle redaction salt, any appliance private key. `NEVER_EXPORT` material has no path into a bundle (ADR-0007/0009).

---

## 4. Upload protocol (outbound, authenticated, resumable)

Chunked, resumable, offset-based HTTPS. Appliance-initiated only.

```
POST /v1/uploads:init      {case_id, bundle_id, bundle_sha256, size, key_id}
   → 200 {upload_id, chunk_size, accepted}         (gateway: authn + entitlement + size/format gate)
PUT  /v1/uploads/{id}/chunks/{offset}   <chunk bytes>   (idempotent per offset; resumable)
   → 200 {received_offset}
POST /v1/uploads/{id}:complete   {bundle_sha256}
   → 200 signed RECEIPT {case_id, bundle_id, bundle_sha256, received_at, sig}
GET  /v1/uploads/{id}                                  (poll status / resume point after a drop)
```

- **Authentication:** per-appliance credential (enrollment-style, rotatable) or mTLS; tenant-scoped so a bundle can only land in that customer's case.
- **SSRF guard (CLAUDE.md convention):** inline `url.Parse` + scheme check + `isPrivateHost()` at the call site **plus** `internal/ssrf.SafeDialContext` — the upload origin cannot be pointed at internal infra; private-IP origins rejected (mirrors the release-catalog SSRF posture). Origin is operator-overridable (air-gap/regional) with a trust-safe opt-out.
- **Server-side validation:** the gateway verifies the manifest is well-formed, within size bounds, non-duplicate (`bundle_id`+hash), and entitled **before** accepting chunks; `complete` re-checks the hash; a mismatch rejects the upload.
- **Receipt:** signed `{case_id, bundle_id, bundle_sha256, received_at}` stored in the local immutable audit + bundle history — proof of what was sent, when, and that the hash matched.
- **No auto-upload:** there is no timer or trigger that uploads without the per-bundle consent action (§2). `TestNoAutoUpload`.

---

## 5. Failure & retry semantics (cloud-independence — ADR-0015/0017)

The appliance must degrade to *normal operation + queued bundle*, never to a stall.

| Condition | Appliance behavior |
|---|---|
| Cloud unreachable (DNS/timeout/5xx) at `init` | bundle → **local queue** (`status: queued`); proxy/health unaffected |
| Connection drops mid-upload | resume from `received_offset` on the next attempt (idempotent chunks) |
| Retry policy | bounded exponential backoff (e.g. 2s→…→capped), jittered, on the appliance's **own outbound schedule**; capped attempt count then `deferred` (operator can re-arm or offline-export) |
| Gateway rejects (entitlement/format/hash) | bundle → `rejected` with a redacted reason; no silent retry loop; surfaced to operator |
| Disk pressure during queue | preflight + retention janitor apply; oldest queued bundle aged out with audit; new queue refused if headroom < budget |
| Cloud down indefinitely | **offline export always available** — write the encrypted `.csb` to disk/media for manual transfer |
| Appliance restart while queued | queue is persisted under `<dataDir>/support`; resumes after boot |

Retries and queueing run in a bounded background op that **never blocks the proxy hot path** and never holds the single-flight collection lock.

---

## 6. Air-gapped workflow (first-class, not an afterthought)

For customers with no outbound path:
1. Appliance runs the full local pipeline: collect → redact → **privacy preview** → consent → manifest → encrypt (passphrase or TAC recipient key).
2. **Offline export**: `culvert support collect … --export <path>` / GUI download writes the encrypted `.csb.age`/`.csb.enc`.
3. A human courier transfers the file on approved media to a machine with portal access; the customer uploads it to the TAC portal.
4. The cloud ingests it through the **same** pipeline and entitlement — air-gap is a transport difference, not a separate code path.
5. Integrity is verifiable offline (`culvert support validate`) before and after transfer.

Local health/OperatorContract and `diagnose` probes remain fully available offline throughout (they never need the cloud).

---

## 7. Remote support — deferred, interface-only (recommendation: NOT this stage)

Unchanged from the prior design and reinforced by cloud-first: **do not build remote interactive support now.** The appliance's value is no-shell; offline/online bundle exchange + local probes cover the workflow. The CLI/API reserve `support remote {approve|status|revoke}` returning `not_enabled`. If ever built it must be per-session-approved, time-bound (auto-revoke watchdog), per-command allowlisted (same `DiagCommand` registry — **never a shell**), mutually authenticated, fully recorded, instantly revocable, tenant-isolated, **and still outbound-initiated** (the appliance opens the session; the cloud cannot dial in) — behind its own ADR + threat model.

---

## 8. Appliance resource budgets for bundle generation

Bundle generation is a background, deprioritized activity that must not perturb the relay hot path (the decision matrix's decisive dimension).

| Budget | Default | Enforcement |
|---|---|---|
| Wall-clock (whole bundle) | 60 s soft / 120 s hard | runner deadline; hard-kill → `FAILED` bundle, hot path untouched |
| Per-collector timeout | 3–10 s (per `CollectorMeta`) | `ctx` deadline |
| Peak transient memory | ≤ 256 MB | streamed section writes (no whole-bundle-in-RAM); byte budgets |
| CPU | best-effort, below hot-path priority; single-flight per node | one bundle at a time; collectors bounded; no busy loops |
| Output — uncompressed | ≤ 100 MB default (scope-tunable) | per-section + total byte budgets; `truncated` flag |
| Output — compressed on disk | ≤ 25 MB default | gzip; retention janitor |
| Disk headroom to start | refuse if free < 3× bundle budget | preflight (reuse `probeStorageWritability` + free-space read) |
| Local retention | 7 days or 5 bundles (whichever first), configurable | janitor, oldest-first, audited |
| Debug capture (L2–L4) | mandatory TTL, disk + duration auto-stop | watchdog (HEALTH-AND-EVENT §6) |
| Upload bandwidth | bounded, backgrounded, never on the proxy connection pool | separate transport; no hot-path contention |

These are hard ceilings; exceeding one truncates/fails the bundle rather than expanding it (T-DISK/T-CPU/T-BOMB).

---

## 9. Test surface

| Test | Asserts |
|---|---|
| `TestNoInboundTACSurface` | no listener/route exists for TAC to dial in |
| `TestOperationWithoutCloud` | proxy/config/enforcement unaffected when cloud unreachable |
| `TestHealthWithoutCloud` | local health/OperatorContract + `diagnose` probes answer offline |
| `TestNoAutoUpload` | no path uploads without per-bundle consent |
| `TestUploadResumable` | drop mid-upload resumes from last offset |
| `TestUploadSSRFGuarded` | private-IP/internal origins rejected |
| `TestUploadRequiresCaseConsentAdmin` | upload without case_id / consent / admin refused |
| `TestUploadReceiptHashMatch` | receipt hash equals bundle hash; mismatch rejected |
| `TestRecipientEncryptOnlyTACDecrypts` | recipient-mode bundle decrypts only with the TAC key |
| `TestOfflineExportAirGapped` | full pipeline + export works with no network |
| `TestBundleQueuePersistsRestart` | queued bundle survives restart and resumes |
| `TestConsentSeparation` | enabling support never enables telemetry/upload/remote |
| `TestBundleBudgetsEnforced` | wall-clock/memory/output/disk ceilings hold; hot path unperturbed |
