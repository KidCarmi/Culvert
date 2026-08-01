# M7 — Proactive support & opt-in telemetry: implementation-authoritative design

- **Status:** Proposed (design), **Revision 3 — implementation-authoritative.** This
  document is the binding implementation contract for the M7 slices: a future
  implementation agent must be able to answer every question in §18 (Definition of
  done) from this text without inventing behavior. Final milestone of the
  supportability roadmap (`docs/support/SUPPORTABILITY-ROADMAP.md` §M7). M0–M6 shipped.
- **Depends on:** M1–M6 (all merged); the scoped support-metric registry this
  document introduces; the M6 consent/SSRF/`sealbox`/TAC-trust machinery it reuses;
  **a TAC-side telemetry ingestion gateway that does not yet exist** (§13).

## Revision history

> **Revision 3 (implementation contract).** Closes the precision gaps that made Rev 2
> unsafe to build from: (1) a complete versioned wire protocol (§3); (2) removed the
> fake `MTLS` boolean — bearer-only for v1, mTLS explicitly deferred (§4); (3) a full
> delivery/retry/restart/idempotency + bounded-spool + disable model with a
> non-identifying sample-identity scheme (§5); (4) the registry is a **scoped support
> metric registry** (`supportMetricRegistry`), NOT a claim to mirror every Prometheus/
> OTLP metric (§6); (5) a concrete default-deny eligibility **table** with per-metric
> justification (§7); (6) a corrected preview guarantee via `registry_hash` +
> `schema_version` (§8); (7) hardened endpoint canonicalization — fixed path, origin
> only (§9); (8) explicit TAC key-rotation behavior, fail-closed (§10); (9) a durable
> proactive **degradation state machine** replacing the naïve `ok→fail` compare (§11);
> (10) a TAC-side retention/privacy contract with the AI-consumption boundary (§12);
> (11) a mandatory cross-repo gateway checkpoint — **Slice 3 is blocked** until
> `tac-platform` ships the gateway + golden vectors (§13). New slice structure (§14),
> test walls (§15), red-team from 10 perspectives folded in (§16).
>
> **Revision 2 (Codex review).** Telemetry requires an authenticated identity to
> enable (Rev 3 finalizes this as bearer-mandatory, §4); the `node_id`-removal is
> scoped to the telemetry payload/config only — locally staged support bundles keep
> their normal manifest node identity (`clusterRole.nodeID`), which is expected and
> redaction-governed.
>
> **Revision 1 (red-team).** `node_id` removed from the telemetry payload entirely
> (gateway attributes from authenticated transport); telemetry payload E2E-sealed to
> the TAC key (`sealbox`) as defense-in-depth; telemetry metrics are structurally
> label-free scalars with default-deny eligibility.

---

## 1. What M7 delivers

Three capabilities, all **off by default** and **consent-separated** (the 4th
independent switch), decomposed into slices with **egress isolated to Slice 3**:

1. **Opt-in telemetry** — periodically sends a *proven strict subset* of
   **support-health scalar** metrics (label-free; no traffic/scale/posture/identity),
   E2E-sealed to TAC's key, over authenticated HTTPS. The admin previews the exact
   sample before enabling.
2. **Proactive local support-bundle staging** — a durable degradation-tracking state
   machine that, on a sustained health degradation, **pre-stages a bundle scoped to
   the degraded check, locally** (never auto-sent).
3. **Alert → support-scope linkage** — a fired alert *suggests* the matching incident
   scope (suggestion only).

**Non-goals:** telemetry on by default; conflating telemetry with support/upload; any
cloud→appliance push; auto-upload of staged bundles; mTLS in v1; sending
traffic/scale/security-posture metrics.

---

## 2. Code-seam grounding (what exists vs. what M7 adds)

Claims below are anchored to inspected code. **EXISTING** = reuse as-is; **NEW** =
M7 builds it; **CROSS-REPO** = must be built in `tac-platform`; **DEFERRED** = later.

| Concern | Status | Anchor |
|---|---|---|
| Consent switch pattern (node-local JSON, fail-closed, atomic 0600, `xxxEnabled()` gate, redacted read model) | EXISTING (reuse shape) | `support_upload.go` `uploadConfig` |
| E2E seal to TAC key + active-key selection + `key_id` | EXISTING | `support_tac_trust.go` `sealBundleToTAC`→`(sealed,keyID)`, `activeTACTrustKey`, `CULVERT_TAC_ACTIVE_KEY_ID`; envelope `internal/sealbox` (`CVRTSB01`+ver+`box.SealAnonymous`) |
| SSRF guards (config-time origin check; dial-time; per-request origin preflight) | EXISTING | `validateUploadOrigin` (`support_upload.go`), `ssrf.SafeDialContext`, `ssrf.PrivateHost`; `internal/supportupload` per-request preflight |
| Small periodic outbound POST loop | EXISTING (template) | `internal/otlp` `pushLoop`/`push` (`validEndpoint` regex, `NewRequestWithContext`, bounded read) |
| Background worker start after restored config | EXISTING (seam) | `loadPersistentAdminState` (after `LoadAdminSettings`) — next to upload worker |
| Incident scope catalog + collector selection | EXISTING | `support_scopes.go` `supportIncidentScopes`,`resolveSupportScope`; `createSupportBundle(ctx,scope,level,caseID)` |
| Readiness rows (health thresholds) | EXISTING | `healthcheck.go` `computeReadiness` checks: `ca`,`ca_expires_days`,`clamav`,`geoip`,`yara`,`policy_loaded`,`session_secret`,`config_snapshot_validator`,`state_file_*` |
| Alert producer + `Source` category | EXISTING | `fireAlert(event,AlertPayload{Source,…})`; sources `ca`/`storage`/`proxy`/`scan`/`policy`/`auth` |
| Bundle manifest node identity | EXISTING (unchanged) | `internal/support/manifest.go` `NodeID` ← `clusterRole.nodeID` |
| **No central metric registry** — metrics are hardcoded `Fprintf` + per-subsystem `WritePrometheus`; OTLP re-lists as `culvert.*` | EXISTING constraint | `metrics.go` `handleMetrics`; `otlp.go` `culvertMetricsSnapshot` |
| Scoped support-metric registry (`supportMetricRegistry`) | **NEW** (§6) | — |
| Telemetry consent switch + config + preview + sender + spool | **NEW** (§4/§5/§14) | — |
| Proactive degradation state machine + durable ledger | **NEW** (§11) | — |
| Telemetry ingestion gateway (`/v1/telemetry/samples`), TAC decryption, idempotency, retention | **CROSS-REPO — partial:** TAC 2.5-0 gateway skeleton + 2.5-A strict contract/fixture consumption shipped (PRs #10/#11/#12); **still owed:** telemetry route, authentication, crypto/decryption, persistence/ingestion (2.5-B/C/D) | `KidCarmi/tac-platform` (§13) |
| mTLS transport auth; canonical repo-wide metrics architecture | **DEFERRED** (§4, §6) | — |

---

## 3. Telemetry wire protocol v1 (`application/vnd.culvert.telemetry-sealed+json`)

The complete appliance→TAC contract. Versioned, with a **closed** top-level member
set per schema version (the binding schema-evolution rule below).

**Schema-evolution rule (binding — this supersedes any earlier "additive-only within
a major" wording).** For the current wire schema, `schema_version == 3`:

1. For `schema_version == 3`, the **outer** top-level member set is **closed**.
2. For `schema_version == 3`, the **inner** top-level member set is **closed**.
3. Adding **any** new top-level member requires a **new `schema_version`** — it is not
   an additive extension of version 3.
4. Additive evolution within schema version 3 is allowed **only inside the governed
   `metrics` map** (a new governed metric descriptor, §6/§7).
5. Any metric-set evolution changes `registry_hash` (§8).
6. A gateway that knows schema version 3 MAY accept different governed metric sets only
   according to its supported registry-hash policy (§8).
7. A newer, unsupported `schema_version` is rejected **cleanly** (`422`, §3.5) — it is
   **not** parsed optimistically.

Consequently the two failure cases are **distinct and not equivalent**:

- An **unknown top-level member under a known `schema_version`** is a **malformed
  request** (`400`, §3.5) — never an additive extension.
- A **newer, unsupported `schema_version`** is an **unsupported-version failure**
  (`422`, §3.5).

The exact closed member sets for `schema_version == 3` are pinned in §3.2 (outer,
exactly eight members) and §3.3 (inner, exactly six members).

### 3.1 Request

```http
POST /v1/telemetry/samples HTTP/1.1
Host: <canonical TAC origin, §9>
Authorization: Bearer <per-appliance credential>
Content-Type: application/vnd.culvert.telemetry-sealed+json
Idempotency-Key: <sample_id>            # equals outer.sample_id; §5
User-Agent: culvert/<major.minor>
```

- **Method / path:** `POST` to the **fixed** path `/v1/telemetry/samples`. The
  operator configures only an **origin** (§9); the appliance appends this path — an
  arbitrary operator request path is not accepted.
- **Auth:** `Authorization: Bearer <credential>` is **mandatory** (§4). The gateway
  authenticates + attributes the appliance/tenant from this credential; **no identity
  is carried in the body**.
- **Request size limit:** the serialized request body MUST be ≤ **64 KiB**. The
  sample is a few dozen scalars, so this is generous; the sender refuses to POST a
  body over the cap (bug-guard) and the gateway rejects oversize with `413`.
- **Timeout:** per-request **10 s** (matches `otlp` client). No chunking.

### 3.2 Outer transport envelope (plaintext JSON; carries NO telemetry values)

For `schema_version == 3` the outer top-level member set is **closed** — **exactly
these eight members**, no more and no fewer:

```
envelope_version
key_id
algorithm
ciphertext
ciphertext_sha256
sample_id
schema_version
registry_hash
```

```json
{
  "envelope_version": 1,
  "key_id": "tac-prod-2026-01",
  "algorithm": "x25519-sealbox",
  "ciphertext": "<standard padded base64 of the sealbox blob>",
  "ciphertext_sha256": "<64 lowercase hex chars: sha256 of the RAW sealbox blob (pre-base64)>",
  "sample_id": "<32 lowercase hex chars (128-bit random), = Idempotency-Key>",
  "schema_version": 3,
  "registry_hash": "<64 lowercase hex chars: sha256 of the governed eligibility schema, §8>"
}
```

An **unknown outer member under `schema_version == 3` is a malformed request (`400`)**,
not an additive extension; adding a ninth member requires a new `schema_version` (§3).

- `key_id` — the `key_id` of the TAC recipient key the ciphertext is sealed to. The
  appliance selects the active TAC recipient key via `activeTACTrustKey` (§10) and seals
  the inner plaintext to its X25519 public key (raw `crypto_box_seal`, above). TAC selects
  the matching private key. *(The `CVRTSB01`-framed `sealBundleToTAC` path is the M4
  support-bundle export, a different envelope; telemetry uses the raw sealed box.)*
- `algorithm` — fixed `"x25519-sealbox"`: libsodium `crypto_box_seal` — an anonymous
  X25519 sealed box (`golang.org/x/crypto/nacl/box`'s `SealAnonymous`, opened with
  `OpenAnonymous`). This is the **RAW** sealed box and **NOT** the `CVRTSB01`-framed
  support-bundle envelope (`internal/sealbox`, M4): the TAC recipient opens the
  ciphertext directly with `box.OpenAnonymous`, so there is **no `CVRTSB01` magic and no
  version prefix**. A reader that does not recognize the label rejects (`422`).
  *(Reconciled in M7 Slice 2.5-C3: the merged TAC consumer — `FileRecipientKeyProvider`
  and `VerifyAndOpen` — opens the raw `crypto_box_seal` blob directly, so the producer
  telemetry sealer emits the raw box rather than reusing the `CVRTSB01`-framed
  support-bundle path.)*
- `ciphertext` — **standard padded base64** (the RFC 4648 standard alphabet) of the raw
  sealed-box blob: exactly the `box.SealAnonymous` output — ephemeral X25519 public key ‖
  ciphertext ‖ Poly1305 tag, a fixed **48-byte overhead**, with **no `CVRTSB01` magic or
  version prefix**. **No** URL-safe alphabet, **no** whitespace, carriage returns, or line
  breaks — none of those are part of the producer format.
- `ciphertext_sha256` — integrity digest over the **raw sealed-box blob** (the exact bytes
  above, pre-base64); exactly **64 lowercase hex** characters. TAC recomputes after
  base64-decode and rejects on mismatch (`422`) before attempting decryption.
- `sample_id` — exactly **32 lowercase hex** characters (128-bit random); equals the
  `Idempotency-Key` header.
- `registry_hash` — exactly **64 lowercase hex** characters.
- `sample_id`, `schema_version`, `registry_hash` — delivery metadata; **non-identifying**
  (§5/§8). These live in the *outer* envelope (not sealed) so the gateway can dedupe,
  size-check, and route without decrypting.

### 3.3 Inner sealed plaintext (what `ciphertext` decrypts to — TAC-only)

For `schema_version == 3` the inner top-level member set is **closed** — **exactly
these six members**, no more and no fewer:

```
schema_version
registry_hash
generated_at
sample_epoch
sequence
metrics
```

```json
{
  "schema_version": 3,
  "registry_hash": "<same 64 lowercase hex as outer>",
  "generated_at": "<canonical UTC RFC3339Nano, e.g. 2026-07-24T12:00:00Z>",
  "sample_epoch": "<32 lowercase hex chars (128-bit random), per process/reset epoch, §5>",
  "sequence": 42,
  "metrics": { "support_health_ca_ready": 1, "support_health_clamav_ready": 0, "...": 0 }
}
```

An **unknown inner member under `schema_version == 3` is a malformed request (`400`)**,
not an additive extension; adding a seventh member requires a new `schema_version` (§3).

- `metrics` — **label-free scalar** name→number map, ONLY the registry's
  telemetry-eligible descriptors (§6/§7). No labels, no strings, no identifiers. **This
  is the sole surface that may grow additively within schema version 3** (a new governed
  descriptor, §6/§7), and any such change moves `registry_hash` (§8).
- `metrics` **values** are Go `float64` values serialized through `encoding/json`
  (§3.3.1); the accepted literal for a value is exactly what that encoder produces.
- `generated_at` — **canonical UTC**, formatted `t.UTC().Format(time.RFC3339Nano)`, so a
  whole-second instant renders as `2026-07-24T12:00:00Z` with a trailing `Z`. Alternate
  spellings that decode to the same instant (`+00:00`, a fixed `.000Z` fractional field)
  are **not** producer-canonical. Clock plausibility is a separate concern — TAC does not
  reject on `generated_at` clock skew (§3.5).
- `sample_epoch` — exactly **32 lowercase hex** characters (128-bit random).
- `sample_epoch` + `sequence` — let TAC order/dedup within an epoch and detect counter
  resets **without** a stable appliance id in the body (§5). Both are inside the seal
  so a MITM sees neither.
- The **outer `registry_hash`/`schema_version` MUST equal the inner values**; TAC
  rejects a mismatch (`422`) — this binds the unencrypted routing metadata to the
  sealed content.

#### 3.3.1 Canonical `metrics` number literals

Culvert's producer serializes each metric value as a Go `float64` through
`encoding/json`. The binding accepted literal is the **exact representation that encoder
produces**, e.g.:

- `100` is canonical; `1e2` is not.
- `0` is canonical; `0.0` and `0e10` are not.
- `-0` is distinct and **is** emitted canonically by Go for a negative-zero `float64`.
- A literal that silently changes value when parsed as `float64` is outside the producer
  contract.

This is **not** an invitation to introduce decimal or arbitrary-precision metric
semantics — Culvert does not produce those. (`v1` metrics happen to be small integral
`float64`, but a consumer parses `metrics` values as floating-point JSON numbers, not
integers — see `testdata/telemetry/v1/README.md`.)

### 3.4 Success response

```json
{ "accepted": true, "sample_id": "<echoed>", "received_at": "<RFC3339>", "duplicate": false }
```

- `duplicate: true` (still `accepted: true`, HTTP `200`) when the gateway has already
  ingested this `(authenticated appliance identity, sample_id)` — the acknowledgement
  a lost-ack retry needs (§5).

### 3.5 Error taxonomy + retry classification

These are the **final gateway semantics** the sender is built against (later TAC slices
implement the checks; §13). Each status has one precise meaning:

| HTTP | Meaning | Sender action |
|---|---|---|
| `200` | accepted (incl. `duplicate:true`) | **success** — delete pending sample |
| `400` | malformed request (see below) | **terminal** — drop sample, log, surface status; do not retry |
| `401` | credential authentication failed (see below) | **terminal-until-reconfig** — stop sending; retry only after credential/config state changes |
| `403` | authenticated, but the credential's server-side state forbids telemetry (see below) | **terminal-until-reconfig** — stop sending; retry only after server-side state changes |
| `409` | dedupe key already exists with **different raw request bytes** | **terminal** — drop; must never happen under seal-once (§5), indicates a bug |
| `413` | serialized request body exceeds 64 KiB | **terminal** — drop; bug-guard |
| `422` | structurally well-formed but unsupported/unverifiable contract data (see below) | **terminal for this sample** — drop; if `schema_version`/`registry_hash` unsupported, surface "schema unsupported by gateway" (the appliance is newer than TAC) |
| `429` | rate-limited | **transient** — honor `Retry-After`, back off |
| `5xx`, timeout, connection error, DNS failure | gateway/transport | **transient** — exponential backoff + jitter, capped (§5) |

**`400` — malformed request.** Terminal for the sample. Includes: malformed JSON;
duplicate members; a missing required member; an **unknown top-level member under the
current known `schema_version`**; an invalid JSON type; malformed base64; a malformed
fixed-width field (e.g. a hex id of the wrong length). An unknown member under a known
schema is a `400` malformed request — it is **not** an additive extension and is **not**
the same as an unsupported version (§3, §3.5 `422`).

**`401` — credential authentication failed.** The sender stops until configuration or
credential state changes. Causes: missing credential; unknown credential; expired
credential; revoked credential.

**`403` — authenticated, but administratively forbidden.** The credential authenticated
successfully, but its **server-side appliance/tenant state** is: not entitled for
telemetry; suspended; quarantined; or otherwise administratively forbidden. There is **no
"wrong tenant" case in the sense of the request selecting a tenant** — the request body
carries **no trusted tenant or appliance identity**, so a sender cannot submit a
client-controlled target tenant. Attribution comes **only** from the server-side
credential record (§3.5 attribution, §12), so `403` is a property of that record, never
of a body field.

> **Recovery mechanism (deferred to Slice 3, not decided here).** A server-side state
> change (an admin re-entitling the credential on TAC) cannot notify or wake the
> appliance, so "retry only after server-side state changes" (401/403) is **not** an
> automatic server push. The concrete recovery trigger — an explicit local re-enable
> action and/or a bounded periodic re-probe of a stopped-on-`401`/`403` sender — is a
> **Slice 3 sender-behavior decision** and is intentionally out of scope for this contract
> sync (§13/§14: Slice 3 is blocked). This taxonomy fixes only what each status *means*,
> not the sender's recovery cadence.

**`422` — structurally well-formed but unsupported or unverifiable contract data.**
Terminal for the sample. Includes, as applicable: unsupported `envelope_version`;
unsupported `algorithm`; unsupported `schema_version`; unknown `key_id`; ciphertext
digest mismatch; outer/inner schema mismatch; outer/inner registry-hash mismatch;
unsupported governed registry hash. These are the **final** gateway semantics for later
slices — TAC 2.5-A does **not** yet perform crypto verification, key resolution, or
decryption (§13), so the digest/decrypt/key `422` cases are the receive-path contract
they will satisfy, not a claim that they exist today.

- **Schema compatibility (binding, §3).** The top-level member set is **closed** per
  `schema_version`; within schema version 3 only the governed `metrics` map grows. The
  gateway accepts a `schema_version` it knows and rejects a newer one **cleanly** with
  `422` (fail-clean, not silent, not optimistic). A newer gateway tolerates an older
  appliance's known schema. An unknown top-level member under a known schema is a `400`
  (malformed), **distinct** from the `422` unsupported-version case.
- **Clock-skew policy:** TAC does not reject on `generated_at` skew (the appliance
  clock may drift); ordering uses `sample_epoch`+`sequence`, not wall-clock. Canonical
  representation (§3.3) and clock plausibility are separate concerns. TAC MAY record skew
  for diagnostics.
- **Replay handling (raw-byte idempotency, §5.2):** dedupe key is
  `(authenticated appliance identity, sample_id)`. A replay with the **identical raw
  request-body SHA-256** returns `200 duplicate:true`; a replay of the same dedupe key
  with a **different raw-body SHA-256** is `409`. Idempotency is over the **exact
  serialized request bytes**, never over semantic JSON equivalence.
- **Gateway attribution:** the appliance/tenant is derived **only** from the
  authenticated transport (bearer credential → tenant+appliance mapping at the
  gateway). Nothing in the body identifies the appliance.
- **Data-retention expectations:** see §12 (TAC-side contract).

---

## 4. Authentication — bearer only for v1; mTLS deferred

`telemetryConfig{Enabled, Origin, Credential}` (**no `MTLS` boolean** — Rev 3 removes
the fake field; a boolean cannot wire client certs, key sources, selection, rotation,
revocation, or tenant attribution).

- **`telemetryEnabled()` = `Enabled && Origin != "" && Credential != ""`.** A real,
  usable auth mechanism (a bearer credential) is required for the gate to become true;
  an origin-only config is **refused at PUT (400)** and the sender never runs. Because
  Rev 1 removed the in-body identifier, authenticated transport is the *sole*
  attribution mechanism, so it is mandatory.
- **mTLS is explicitly DEFERRED** to a later authenticated-transport milestone. When
  built it must fully specify: an auth-mode enum, client-cert source + reference,
  private-key source, EKU expectations, rotation, revocation, TAC tenant/appliance
  mapping, and fail-closed behavior. Until then M7 ships **bearer only**. No
  placeholder that can enable telemetry without real auth wiring.
- Credential stored `0600`, node-local, **never echoed** (read model reports only
  `credential_set`); preserved across posture flips; explicit `clear_credential`.
  https-only (§9) so the bearer never leaks over plaintext.

---

## 5. Sample identity, delivery, retry, restart, idempotency, spool

### 5.1 Non-identifying sample identity

| Field | Where | Rule |
|---|---|---|
| `sample_id` | outer + `Idempotency-Key` | 32 lowercase hex (128-bit random) per **logical sample**; **reused verbatim across retries** of that sample; NOT a stable appliance id (fresh each sample) |
| `sample_epoch` | inner (sealed) | 32 lowercase hex (128-bit random) per **process start / counter-reset epoch**; lets TAC detect resets without an appliance id |
| `sequence` | inner (sealed) | monotonic uint within an epoch; resets to 0 on a new epoch |
| `generated_at` | inner | canonical UTC `t.UTC().Format(time.RFC3339Nano)` (trailing `Z`, §3.3); advisory (§3.5 skew) |
| `schema_version`, `registry_hash` | outer + inner | governed-schema identity (§8); `registry_hash` is 64 lowercase hex |

TAC deduplicates by **(authenticated appliance identity, `sample_id`)** — the identity
comes from the transport, the `sample_id` from the body; neither alone is a stable
appliance fingerprint in the payload.

### 5.2 Seal-once + raw-byte idempotency (binding — not an open decision)

Idempotency is defined over the **exact raw serialized request bytes**, not over semantic
JSON equivalence. This is a **settled, non-negotiable** rule and **not** an undecided
2.5-D question: there is no alternative under which the request is canonicalized before
hashing — the SHA-256 is always over the exact raw bytes.

```
dedupe key = (authenticated appliance identity, sample_id)

same dedupe key + identical SHA-256 of the exact raw serialized request body
    => 200 accepted, duplicate:true

same dedupe key + different raw-body SHA-256
    => 409 conflict
```

Semantic JSON equivalence is **irrelevant** to idempotency. Whitespace changes, member
reordering, or alternate JSON escapes produce **different request bytes** even when they
decode to equal values — and therefore a different SHA-256 and a `409` on the same dedupe
key. The Culvert sender must therefore:

1. build **one** complete sealed request;
2. persist the **exact serialized bytes**;
3. retry **those exact bytes**;
4. reuse the **same** `sample_id` and `Idempotency-Key`;
5. **never** rebuild, reseal, or reserialize a pending sample between attempts.

That is the binding meaning of **seal-once**.

- A sample is **built once**, **sealed once**, and the **same request bytes are retried**
  until acknowledged or dropped. Retries reuse the same `sample_id`, the same
  `Idempotency-Key`, and the same sealed blob — so a lost ack (TAC accepted but the
  response was lost) resolves as `duplicate:true` on retry (identical raw bytes → same
  SHA-256 → duplicate, never `409`).
- **Cumulative-counter reset:** counters are read at build time; a process restart
  starts a new `sample_epoch` (counters reset to their post-restart values). TAC
  interprets a lower `sequence`/new `epoch` as a reset, never as a rollback.

### 5.3 Bounded local spool + restart

- **At most ONE pending telemetry sample** at a time (a one-slot spool under
  `<dataDir>/support/telemetry_pending.json`, `0600`). **No unbounded history queue.**
- On the send cadence (§14 Slice 3), if no pending sample exists and telemetry is
  enabled, the sender **builds + seals a new sample** (new `sample_id`, next
  `sequence`); it becomes the pending sample.
- **Retry:** exponential backoff with jitter, capped (e.g. 1 min → … → 1 h cap) on
  transient failures; terminal failures (§3.5) drop the sample.
- **Latest-sample-wins:** a pending sample older than a bounded age (e.g. > 1 send
  interval, so at most one interval stale) is **replaced** by a freshly built sample
  rather than retried forever — telemetry values should be current, and there is never
  a backlog. The replaced sample's bytes are discarded (never sent).
- **Restart:** the one-slot pending sample persists and is retried after boot **only if
  telemetry is still enabled**; its `sample_epoch` is from when it was built (pre-restart
  epoch), so TAC still dedupes correctly. If telemetry is disabled at boot, see §5.4.
- **Acknowledged samples are deleted** (the slot is cleared).

### 5.4 Disable behavior (privacy-preserving choice — explicit)

Disabling telemetry (`Enabled=false`, or clearing the credential/origin) **immediately
deletes the pending sample from disk** and stops all transmission. It is NOT retained
for a future re-enable. Rationale: the most privacy-preserving posture is that turning
telemetry off leaves **no staged outbound data** on the box; re-enabling builds a fresh
current sample. The sender goes inert the same tick (gate = `telemetryEnabled()`).

---

## 6. The scoped support-metric registry (`supportMetricRegistry`)

There is no repo-wide metric registry today (metrics are hardcoded `Fprintf` +
per-subsystem `WritePrometheus`; OTLP re-lists names independently). Rev 3 does **not**
introduce a registry claiming to mirror every emitted `culvert_*` metric — that would
be a false third source of truth. Instead a **deliberately scoped** registry:

```go
type PrivacyClass int // Public, Aggregate, LocalOnly

type MetricType int    // Gauge, Counter (values are always label-free scalars)

type supportMetricDescriptor struct {
    ID                string          // stable telemetry id, e.g. "support_health_ca_ready"
    Type              MetricType
    Read              func() float64  // reads the live value (a subsystem gauge/derived bit)
    InSupportBundle   bool            // included in the support bundle's health section
    TelemetryEligible bool            // default false (default-deny)
    PrivacyClass      PrivacyClass
    TelemetryReason   string          // MANDATORY when TelemetryEligible: recorded justification
}

var supportMetricRegistry = []supportMetricDescriptor{ /* §7 */ }
```

**Authoritative scope (only):** (a) the **support-health** data included in support
bundles, (b) the telemetry **preview**, (c) telemetry **transmission**. It is the
shared source for those three surfaces so preview == send == bundle-health by
construction. It is **NOT** claimed authoritative for the broader Prometheus/OTLP
metric set; a future canonical metrics architecture is separate follow-up (DEFERRED).

The telemetry payload builder emits `{d.ID: d.Read()}` for exactly the descriptors with
`TelemetryEligible==true`.

---

## 7. Initial telemetry eligibility table (default-deny)

Eligibility is **default-deny**; each eligible metric carries a recorded justification.
"Label-free" ≠ "non-sensitive": exact scalars can leak traffic volume, customer scale,
policy/blocklist size, detection activity, inspection posture, uptime, product usage —
so those are **rejected** or admitted only as coarse buckets with justification.

**Design decision:** the v1 eligible set is intentionally **minimal — the appliance's
own subsystem-health bits only**. These directly serve "we noticed X degrading," are
not customer traffic/posture, and do not fingerprint a tenant.

| Metric (telemetry id) | Operational purpose | Privacy class | Exact/bucketed | Eligible | Justification / why rejected |
|---|---|---|---|---|---|
| `support_health_ca_ready` (0/1) | is the internal CA usable | Aggregate | exact bit | **Yes** | appliance's own health; the point of proactive support; no customer data |
| `support_health_clamav_ready` (0/1) | AV engine reachable | Aggregate | exact bit | **Yes** | own health; not detection *activity* |
| `support_health_yara_ready` (0/1) | YARA engine loaded | Aggregate | exact bit | **Yes** | own health |
| `support_health_policy_loaded` (0/1) | policy engine loaded | Aggregate | exact bit | **Yes** | own health; not policy *content/size* |
| `support_health_session_ready` (0/1) | session subsystem key present | Aggregate | exact bit | **Yes** | own health; no secret material |
| `support_health_config_snapshot_valid` (0/1) | last config snapshot validated | Aggregate | exact bit | **Yes** | own health; not config content |
| `support_health_ca_expiry_bucket` (0..3) | CA cert nearing expiry | Aggregate | bucketed (`>90d/≤90/≤30/≤7`) | **Yes** | proactive renewal signal; bucketed to avoid a precise cert-timeline fingerprint |
| `support_uptime_bucket` (0..3) | restart cadence | Aggregate | bucketed (`<1d/<7/<30/≥30`) | **Yes** | coarse stability signal; **exact uptime rejected** (fingerprint/correlation). The shipped registry id is `support_uptime_bucket` (see `support_telemetry_registry.go` and the golden fixture `testdata/telemetry/v1/inner_sample.json`) — it deliberately does **not** carry the `support_health_*` prefix the health-bit metrics use, because uptime is a stability signal, not a subsystem-health bit |
| `culvert_requests_total` | traffic volume | LocalOnly | — | **No** | reveals customer scale |
| `culvert_requests_blocked`/`allowed`/`auth_fail` | policy/auth outcomes | LocalOnly | — | **No** | security posture + attack signal (auth failures) |
| `culvert_bytes_sent_total`/`recv_total` | throughput | LocalOnly | — | **No** | customer scale |
| `culvert_policy_rule_hits_total` (per-rule) | rule usage | LocalOnly | — | **No** | labelled + posture + high cardinality |
| `culvert_blocklist_size`, `culvert_threat_feed_entries` | config scale | LocalOnly | — | **No** | reveals deployment/config scale |
| `culvert_threat_feed_blocked_total`, `culvert_cdr_threats_detected_total`, `culvert_dpi_blocked_total` | detection activity | LocalOnly | — | **No** | reveals threat exposure/activity |
| `culvert_decrypt_sessions_total`, decrypt/autoexclude family | inspection posture | LocalOnly | — | **No** | reveals inspection posture |
| `culvert_version` (string) | product version | — | — | **No (v1)** | a string, not a label-free scalar; aids build fingerprinting in a small tenant — defer |
| `culvert_enrollment_nodes`/`_connected` | fleet size | LocalOnly | — | **No (v1)** | reveals deployment scale; a coarse "all-nodes-connected" *bit* is a future candidate, not v1 |

New eligible metrics require a new descriptor with a `TelemetryReason` and bump the
`registry_hash` (§8). The subset/label-free/no-identity walls (§15) enforce this
mechanically.

---

## 8. Preview guarantee (corrected) — governed schema, not byte-forever

The preview does **not** promise the exact bytes of a send an hour later — metric values
and timestamps change. The real guarantee:

- Preview and sender use the **same registry and serializer** (§6).
- The preview shows the **exact current sample** (current metric names, meanings, and
  current values) that *would* be sealed and sent right now — plus `schema_version` and
  `registry_hash`.
- `registry_hash` = `sha256` over the **governed schema**: the sorted list of
  `(ID, Type, PrivacyClass, TelemetryEligible)` for every registry descriptor. **Any
  eligibility change changes the hash.** The GUI shows the hash + schema version; the
  sender includes the same hash in every envelope; TAC can pin/verify it.
- Future transmissions use the same approved schema + eligible set (same
  `registry_hash`) but current values.
- An admin can therefore inspect exactly *what categories of data* leave the box, and
  their current values, before enabling — and detect any later schema change via the
  hash.

`TestSupportTelemetryPreviewMatchesBuiltSample` builds **one immutable sample**,
previews it, seals **that same sample**, and asserts the decrypted ciphertext equals the
previewed plaintext byte-for-byte — the sample is **not rebuilt** between preview and
send.

---

## 9. Endpoint canonicalization (hardened)

Config stores an **origin only** (e.g. `https://tac.culvertlabs.com`); the appliance
appends the fixed `/v1/telemetry/samples` path internally. `validateTelemetryEndpoint`
(config-time, no network I/O) enforces, and **rejects otherwise**:

- **https** scheme only.
- host **required**.
- **no** userinfo (`user:pass@`), **no** fragment, **no** embedded credentials.
- **no** operator-provided request path/query (origin only — there is no documented
  enterprise requirement for an arbitrary path).
- private/internal **literal IPs rejected** (reuse `isPrivateIP`, IPv6-zone-stripped as
  in `validateUploadOrigin`).

At **request time**: DNS resolved + checked via `ssrf.SafeDialContext` (DNS-rebind
safe); per-request `ssrf.PrivateHost` origin preflight (defeats `HTTPS_PROXY`-based
SSRF). **Redirects are disabled entirely** (`CheckRedirect` returns an error) — the
telemetry endpoint is a fixed known origin, so no redirect is ever legitimate, and this
guarantees `Authorization` is never forwarded to another origin. The read model returns
only the canonical safe origin; it never exposes userinfo or secret material.

---

## 10. TAC key-rotation behavior (fail-closed)

Telemetry reuses the M6 TAC recipient trust store (`support_tac_trust.go`).

- **Key selection:** a **new** sample is sealed to the **active** key
  (`activeTACTrustKey` / `CULVERT_TAC_ACTIVE_KEY_ID`, else first resolved); its `key_id`
  goes in the envelope.
- **Pending sample is bound to its seal key:** a sample sealed to `key_id=K` is
  **retried with the same ciphertext** even if the active key rotates to `K'` — it is
  **never silently re-sealed** (seal-once, §5.2). Only a *new* sample (after the pending
  one is acked/dropped/aged-out) uses `K'`. TAC retains previous private keys for the
  documented overlap window (§12), so an in-flight `K`-sealed sample still decrypts.
- **No active TAC key:** telemetry is **unavailable** — `telemetryEnabled()` may be true
  (consent given) but the sender **cannot build a sample**; it emits **no egress**,
  surfaces status `encryption_unavailable`, and reports a **local health degradation**
  (a readiness/status row: "telemetry enabled but no TAC encryption key"). Fail-closed.
- **Invalid/low-order configured active key:** rejected by the existing trust-store
  validation; treated as "no active key" above (fail-closed, logged).

---

## 11. Proactive degradation state machine (durable)

A naïve `ok→fail` compare over `computeReadiness()` is insufficient (readiness mixes
gating/report-only/optional/DP-specific/startup-flapping checks). M7 defines an explicit
**proactive check registry** + a durable **degradation** model. (This is a distinct
concept from the existing **incident scope** catalog below — "degradation" is the new
stateful open/closed health record this section defines; "incident scope" stays the
pre-existing, stateless `support_scopes.go` catalog key. Per `docs/design/
PRODUCT-TERMINOLOGY.md`, "Incident" itself is not a product concept and must not become
a GUI-facing entity name — Slice 4's GUI (§14) must surface this as "degradation",
never "incident".)

```go
type proactiveCheckDescriptor struct {
    Name                string        // e.g. "ca"
    Scope               string        // support incident scope, e.g. "tls" (must be a real scope)
    Severity            string        // "critical" | "warn"
    ConsecutiveFailures int           // crossings required before staging (default 3)
    Cooldown            time.Duration // min gap between stagings for the same degradation
    StageOnBootFailure  bool          // false — never stage during startup grace
    Evaluate            func() CheckResult
}
```

**Eligible checks + scope mapping** (a curated subset of readiness — **not** every row;
report-only/optional/DP-dependency rows are excluded):

| Check | Scope | Severity | Stage-worthy |
|---|---|---|---|
| `ca` (CA unusable) | `tls` | critical | yes |
| `policy_loaded` (policy engine down) | `policy` | critical | yes |
| `config_snapshot_validator` (bad snapshot) | `cluster` | critical | yes |
| `clamav`/`yara` (scan engine down) | `scan` | warn | yes |
| `session_secret` | — | critical | **no** (config error, not an evolving degradation) |
| `geoip` | — | warn | **no** (optional/data-file; low value) |
| `state_file_*`, DP-dependency rows | — | — | **no** (report-only) |

**Durable local degradation state** (`<dataDir>/support/proactive_degradations.json`,
`0600`, bounded): per check `{ last_status, consecutive_failures,
degradation_fingerprint, degradation_start, last_staged_at, last_staged_bundle_id,
recovered_at, cooldown_until }`.

**Transitions** (`unknown → healthy | degraded`; `healthy → degraded`;
`degraded → degraded`; `degraded → healthy`):

- **Startup grace:** no staging during an initial boot grace window (e.g. 5 min) —
  `unknown → degraded` at boot never immediately stages.
- **Threshold:** stage only after `ConsecutiveFailures` (default **3**) consecutive
  failing evaluations — a single flap never stages.
- **One degradation, one stage:** staging sets `cooldown_until`; `degraded → degraded`
  does **not** re-stage until cooldown elapses (persistent degradation ⇒ no storm).
- **Recovery closes the degradation:** `degraded → healthy` records `recovered_at` and
  resets counters; a **new** failure after recovery opens a **new** degradation record
  (new fingerprint) and stages again after threshold.
- **Cooldown survives restart** (persisted ledger) — a restart mid-cooldown does not
  re-stage.
- **Local-only, per-node:** each node evaluates its **own** readiness and stages its
  **own** node-local bundle (`createSupportBundle(scope, level, "")`). No cross-node/HA
  coordination in M7. **No upload or telemetry consent is inferred** — staging is purely
  local evidence; the operator still separately consents to any upload.

Alert→scope linkage (§1.3) is a `map[AlertPayload.Source]→scope` that annotates a fired
alert with a **suggested** scope; it never triggers collection (suggestion only).

---

## 12. TAC-side retention & privacy contract (mostly `tac-platform`)

M7 is not appliance-only; the receiving side has obligations. Minimum requirements
(implemented in `KidCarmi/tac-platform`, marked **[TAC]**):

- **[TAC] Tenant isolation** — a sample is scoped to the authenticating appliance's
  tenant; no cross-tenant read.
- **[TAC] Attribution** — appliance/tenant derived only from the authenticated
  transport (bearer→mapping); never from the body.
- **[TAC] Key ownership / decryption boundary** — TAC's KMS holds the recipient private
  keys; decryption happens server-side only; the appliance holds no decrypt key.
- **[TAC] Retention** — raw samples retained a bounded period (recommend ≤ 30 d) then
  deleted; aggregate roll-ups retained longer (recommend ≤ 13 mo); **regional
  residency** honored per tenant.
- **[TAC] Query authorization + audit** — every telemetry read is authz-checked and
  audit-logged.
- **[TAC] Deletion + credential revocation** — a tenant can request deletion; a revoked
  appliance credential immediately stops ingestion (`401`, §3.5).
- **[TAC] Replay/dedup storage** — dedupe index on `(appliance, sample_id)` with bounded
  retention.

**Default posture (binding on both sides):**

- **No AI consumption by default.** Raw telemetry is **never** passed to a model; no
  credential or key material reaches any AI component. Any future AI use of *aggregates*
  is separately governed and out of M7 scope.
- **No cross-tenant aggregation** that exposes tenant-level values.
- **No raw bundle content** in telemetry; **no support-bundle auto-upload**.
- Telemetry **may** be joined to a support case only within the same tenant, audit-logged.

---

## 13. Cross-repo gateway checkpoint — **Slice 3 is BLOCKED until this exists**

**Current cross-repository state (as of this contract sync).** `KidCarmi/tac-platform`
has landed **TAC M7 Slice 2.5-0** (gateway service skeleton) and **Slice 2.5-A** (the
strict contract layer + producer-fixture consumption + a stabilized public opaque-carrier
API), through TAC PRs #10, #11, and #12. TAC 2.5-A enforces: strict bounded outer and
inner JSON decoding; **closed** top-level member sets for `schema_version == 3`; additive
metric growth only inside the governed `metrics` map; producer-canonical metric number
literals; raw-request-byte idempotency; and a producer-owned inner fixture copied
byte-for-byte from Culvert. What TAC has **not** yet built: **no telemetry route yet, no
authentication, no crypto/decryption, no persistence.** So the receive path is **not yet
functional**, and Slice 3 (the only egress slice) still **must not** be built against it.

| Milestone | Status |
|---|---|
| Culvert Slice 1 — inner-sample producer registry | **Complete** |
| Culvert Slice 2 — consent/configuration (zero egress) | **Complete** |
| Culvert A1 — producer-owned golden fixture (§3.3) | **Complete** |
| TAC F0 — versioned migration foundation | **Complete** |
| TAC 2.5-0 — gateway service skeleton | **Complete** |
| TAC 2.5-A — strict contract, fixture consumption, stabilized opaque carrier API | **Complete** |
| TAC 2.5-B — credential identity + server-side attribution | **Not implemented** |
| TAC 2.5-C — key resolution, digest verification, decryption, sealed interop vectors | **Not implemented** |
| TAC 2.5-D — idempotent transactional ingestion | **Not implemented** |
| Retention / deletion / read-side operations | **Not implemented** |
| Culvert Slice 3 — sender, spool, retry, egress | **Blocked** (this checkpoint) |

The telemetry gateway is therefore **not yet functional**. Culvert Slice 3 remains
**blocked** until the relevant TAC receive path (2.5-B/C/D) **and** the cross-repository
sealed interoperability gate exist.

**Prerequisite — before Slice 3 begins, `tac-platform` must ship (the still-owed 2.5-B/C/D
work above):**
- versioned `POST /v1/telemetry/samples` (or the final agreed equivalent),
- bearer authentication + tenant/appliance attribution,
- sealed-envelope parsing + TAC-side decryption,
- schema validation, idempotency, replay handling, size limits, the §3.5 error taxonomy,
- retention enforcement (§12) + an audit event,
- **contract test vectors** (golden fixtures).

**Shared golden interoperability vectors** (versioned fixtures copied into both repos)
must verify:
- a Culvert-generated envelope is accepted by TAC and decrypts to exactly the expected
  plaintext,
- an invalid `key_id` fails closed (`422`),
- modified ciphertext is rejected (`422`, digest/AEAD),
- a duplicate sample (identical raw request bytes) returns `200 duplicate:true`,
- attribution is **credential-derived only**: the request body carries no tenant/appliance
  identity, so there is **no client-selected target tenant** to spoof; a credential whose
  server-side state forbids telemetry is rejected with `403` (§3.5),
- an unsupported `schema_version`/`envelope_version` is rejected cleanly (`422`).

**Producer-contract record (the cross-repository fixture identity).** The inner-plaintext
golden fixture has one producing repository and one cross-repository identity — the
SHA-256 over its original raw bytes:

```
producer repository: KidCarmi/Culvert
producer fixture:    testdata/telemetry/v1/inner_sample.json
producer PR:         #938
producer merge:      c612b63e45681f9b2926793de7586077841d5170
producer head:       c7889223bb22b7cebdcf54cefa2c08f816cc0394
exact size:          476 bytes
SHA-256:             22df6ee3b323b46332e0073be7925886d6d15121a781165f8ba79b6657549005
schema_version:      3
registry_hash:       061fe684aaabb895e87130943649ef37e450cc62e9d63c6c9d7fddfce73b15a7
```

- **Culvert owns the inner plaintext fixture; TAC carries an exact copied fixture.** The
  SHA-256 over the **original raw bytes** is the cross-repository identity both sides
  verify (never a re-normalized/re-serialized copy — §5.2).
- **TAC sealed outer-envelope fixtures are still deferred to `2.5-C`** (§3.2).
- **This fixture alone does not unblock Culvert Slice 3** (the sealed interop gate + the
  functional TAC receive path are still owed).
- The record above is contract metadata, **not** wire content — none of it goes inside the
  telemetry wire JSON (the inner plaintext is exactly the six §3.3 members).

**Fixture ownership (clarification, no design change).** The golden fixtures above are
**copied**, so each one has exactly one producing repository:

- **Culvert owns the inner plaintext fixture** (§3.3). Culvert is the producer of that
  shape, so its fixture is generated and byte-verified by Culvert's real production
  serialization path (`supportmetrics.Registry.BuildSample` → `json.Marshal` →
  `Sample.MarshalJSON`) against the live `supportMetricRegistry` schema — never
  hand-written, and never invented on the TAC side. Shipped as **Slice 2.5-A1**:
  `testdata/telemetry/v1/inner_sample.json` + `support_telemetry_golden_fixture_test.go`
  (see `testdata/telemetry/v1/README.md` for the recorded copy-contract metadata).
- **`tac-platform` consumes a copied version** of those exact bytes and verifies the
  recorded SHA-256. Both repositories stay hermetic — no submodule, no network fetch, no
  cross-repository test dependency.
- **Sealed outer-envelope fixtures (§3.2) remain deferred to TAC `2.5-C`.** Slice 2.5-A1
  carries no envelope, encryption, key, credential, sender, or spool.
- **Test naming:** `TestTelemetryGatewayGoldenVector` (named in §14/§15) remains the
  **Slice 3** envelope/interop vector against the live gateway. A1's inner-plaintext
  half of that contract is the `TestTelemetryGoldenFixture*` family — those tests
  satisfy the producer side only; `TestTelemetryGatewayGoldenVector` is still owed.

**The M7 plan states: Slice 3 is blocked until the TAC telemetry gateway contract and
the golden interoperability test pass.** This is Slice 2.5 (§14). The inner-plaintext
fixture landing does **not** unblock Slice 3.

---

## 14. Revised slice structure

### Slice 1 — Support metric registry + preview (ZERO EGRESS)
`supportMetricRegistry` (§6) + the initial eligibility table (§7) + privacy classes +
`registry_hash` (§8) + the pure sample builder (§3.3 inner) + the preview API
(`GET /api/support/telemetry/preview`, admin). **No sender, no consent, no config.**
Tests: `TestSupportTelemetrySubset`, `TestSupportTelemetryLabelFree`,
`TestSupportTelemetryRegistryDefaultDeny`, `TestSupportTelemetryRegistryHasJustification`,
`TestSupportTelemetrySampleHasNoStableIdentity`, `TestSupportTelemetryRegistryHashStable`,
`TestSupportTelemetryPayloadNoDrift`.

### Slice 2 — Consent + bearer auth + GUI (ZERO EGRESS)
`telemetryConfig{Enabled, Origin, Credential}` node-local; canonical origin +
`validateTelemetryEndpoint` (§9); `telemetryEnabled()` bearer-mandatory (§4); credential
preserve/clear; audit `support.telemetry.config`; the preview GUI (shows metrics +
`registry_hash` + schema version before enabling). **No mTLS placeholder, no sender.**
Tests: `TestConsentSeparation` (extended — enabling telemetry touches only its file),
`TestTelemetryRequiresBearerAuth`, `TestSupportTelemetryPreviewMatchesBuiltSample`,
endpoint-canonicalization tests (§15), credential redaction.

### Slice 2.5 — TAC telemetry gateway contract (CROSS-REPO, in `tac-platform`)
The §13 gateway + golden fixtures. **Blocks Slice 3.** Ships in `tac-platform`; Culvert
side is the shared golden vectors + `TestTelemetryGatewayGoldenVector`.
**Status (§13 matrix):** TAC 2.5-0 (skeleton) and 2.5-A (strict contract + fixture
consumption + stabilized opaque-carrier API) are **complete** (PRs #10/#11/#12); 2.5-B
(credential identity/attribution), 2.5-C (key resolution/digest verify/decryption + sealed
interop vectors), and 2.5-D (idempotent transactional ingestion) are **not implemented**.
So the receive path is not yet functional and Slice 3 stays blocked.

### Slice 3 — Bounded telemetry delivery (ONLY EGRESS SLICE)
Seal-once sample (§5.2), fixed envelope (§3), one-slot bounded spool (§5.3), idempotent
retries + backoff/jitter (§5), redirects disabled + SSRF (§9), ack processing (§3.4),
key-rotation behavior (§10), disable behavior (§5.4), local status/health
(`encryption_unavailable`, auth-failed), and the cross-repo contract tests. Sender
started in `loadPersistentAdminState` next to the upload worker; idles when disabled;
exits on ctx.
Tests: `TestNoAutoTelemetry`, `TestTelemetryRejectsURLUserinfo`,
`TestTelemetryRejectsFragment`, `TestTelemetryRejectsPrivateOrigin`,
`TestTelemetryRedirectDoesNotLeakCredential`, `TestTelemetrySealOnceAcrossRetries`,
`TestTelemetryDuplicateAckIsSuccess`, `TestTelemetryPendingSampleBounded`,
`TestTelemetryDisableStopsEgress`, `TestTelemetryNoTrustKeyFailsClosed`,
`TestTelemetryKeyRotationDoesNotResealPendingSample`, `TestTelemetryGatewayGoldenVector`.

### Slice 4 — Durable proactive support degradation tracking (LOCAL ONLY)
Proactive check registry (§11) + degradation state machine + durable cooldown ledger +
startup grace + consecutive-failure threshold + recovery handling + scope mapping +
local bundle staging + alert→scope suggestion + GUI + runbook
(`docs/operator/proactive-support.md`). **No upload, no telemetry send.**
Tests: `TestProactiveStartupGrace`, `TestProactiveConsecutiveFailureThreshold`,
`TestProactiveCooldownSurvivesRestart`, `TestProactiveRecoveryClosesDegradation`,
`TestProactivePersistentFailureDoesNotStorm`, `TestProactiveStaysLocal`,
`TestAlertScopeMapValid`.

---

## 15. Test plan / architecture walls (behaviors — names may adapt to conventions)

```
# registry + privacy (Slice 1)
TestSupportTelemetrySubset                    # telemetry_eligible ⊆ in_bundle
TestSupportTelemetryLabelFree                 # no eligible metric carries any label
TestSupportTelemetryRegistryDefaultDeny       # eligibility defaults false
TestSupportTelemetryRegistryHasJustification  # every eligible metric has a TelemetryReason
TestSupportTelemetrySampleHasNoStableIdentity # payload has no node_id/hostname/IP-shaped string
TestSupportTelemetryRegistryHashStable        # hash deterministic; changes iff eligibility changes
TestSupportTelemetryPayloadNoDrift            # builder emits exactly the eligible set
TestSupportTelemetryPreviewMatchesBuiltSample # one immutable sample: preview == unseal(send)
# consent + auth + endpoint (Slice 2)
TestConsentSeparation                         # 4 independent switches
TestTelemetryRequiresBearerAuth               # endpoint-only config refused; gate stays false
TestTelemetryRejectsURLUserinfo
TestTelemetryRejectsFragment
TestTelemetryRejectsPrivateOrigin
# delivery (Slice 3)
TestTelemetryRedirectDoesNotLeakCredential    # redirects disabled; Authorization never re-sent
TestTelemetrySealOnceAcrossRetries            # same ciphertext bytes across retries
TestTelemetryDuplicateAckIsSuccess            # duplicate:true resolves a lost ack
TestTelemetryPendingSampleBounded             # one-slot spool; no unbounded queue
TestTelemetryDisableStopsEgress               # disable deletes pending + stops send same tick
TestTelemetryNoTrustKeyFailsClosed            # no active key ⇒ no egress + health degraded
TestTelemetryKeyRotationDoesNotResealPendingSample
TestTelemetryGatewayGoldenVector              # cross-repo interop fixtures (§13)
TestNoAutoTelemetry                           # static scan: gate not in startup files
# proactive (Slice 4)
TestProactiveStartupGrace
TestProactiveConsecutiveFailureThreshold
TestProactiveCooldownSurvivesRestart
TestProactiveRecoveryClosesDegradation
TestProactivePersistentFailureDoesNotStorm
TestProactiveStaysLocal
TestAlertScopeMapValid
```

Plus: `route-classification.yaml` rows + `uiRoutes` metadata for the new endpoints
(OpenAPI coverage gate); the no-egress source wall extended to the telemetry files
(dials only via the guarded sender).

---

## 16. Red-team (10 perspectives; valid findings folded into the design above)

1. **Privacy engineer** — *"exact scalars leak scale/posture even without labels."* →
   Folded: §7 eligibility is default-deny and admits **only own-health bits + coarse
   buckets**; traffic/scale/posture/detection metrics explicitly rejected.
2. **Network/SSRF attacker** — *"redirect or proxy to reach internal infra / leak the
   bearer."* → Folded: §9 redirects **disabled entirely**, origin-only + fixed path,
   config-time + dial-time + per-request SSRF guards, `Authorization` never forwarded.
3. **Malicious/compromised TAC endpoint** — *"a hostile endpoint reads the payload or
   replays."* → Folded: §3 payload **E2E-sealed** (endpoint sees only ciphertext +
   non-identifying routing metadata); §5 seal-once + idempotency; the endpoint is
   operator-set and origin-pinned.
4. **Multi-tenant SaaS reviewer** — *"cross-tenant leakage / attribution spoofing."* →
   Folded: §3/§12 attribution from **authenticated transport only** — the body carries no
   tenant/appliance identity, so there is no client-selected target tenant to spoof; tenant
   isolation [TAC], `403` when the authenticated credential's server-side state forbids
   telemetry, golden vector for it (§13).
5. **SRE (retries/restart/outage)** — *"lost acks, restart dupes, counter resets,
   backlog."* → Folded: §5 seal-once + `duplicate:true` + `sample_epoch`/`sequence` +
   one-slot bounded spool + latest-wins + cooldown/pending survive restart.
6. **Enterprise customer (consent claims)** — *"does 'off' really send nothing? can I
   see what leaves?"* → Folded: §4 default-off + bearer-mandatory; §5.4 disable deletes
   pending immediately; §8 preview + `registry_hash` shows the governed schema and
   current values before enabling.
7. **Support engineer (flapping node)** — *"a flapping check storms bundles / fills
   disk."* → Folded: §11 startup grace + 3-consecutive-failure threshold + per-degradation
   cooldown surviving restart + single-flight + §8 bundle budgets/retention.
8. **Crypto/trust-rotation reviewer** — *"rotation re-seals a pending sample
   unpredictably / no-key silently sends plaintext."* → Folded: §10 pending bound to its
   seal key (never re-sealed), TAC overlap window, **no active key ⇒ fail-closed** (no
   egress + health degraded), invalid key rejected.
9. **AppSec (secret leakage)** — *"credential in logs/read model/redirects; key material
   to AI."* → Folded: §4 credential `0600`, never echoed (only `credential_set`); §9
   https-only, redirects disabled; §12 **no credential/key material to any AI**.
10. **Architect (source-of-truth drift)** — *"a new metric-registry becomes a third,
    lying mirror."* → Folded: §6 registry is **scoped** to bundle-health/preview/send
    only, explicitly **not** a repo-wide metrics mirror; the drift/subset/label walls
    (§15) keep it honest; canonical metrics architecture is separate DEFERRED work.

---

## 17. Cross-milestone invariants honored
1. No ship on a red Security gate.
2. Every new route: `uiRoutes` metadata + UI affordance + `route-classification.yaml`
   row (GUI parity + OpenAPI coverage gate).
3. Every new persisted state (`telemetry_config.json`, `telemetry_pending.json`,
   `proactive_degradations.json`, staged bundles) lives under `<dataDir>/support` and is
   bounded. The telemetry payload carries **no** identifier; staged bundles keep their
   normal manifest node identity (redaction-governed; never sent without upload consent).
4. Closed top-level member set per `schema_version` (§3): within schema version 3 only the
   governed `metrics` map grows additively; any new top-level member requires a new
   `schema_version`, and a newer unsupported version is rejected cleanly (§3.5 `422`).
   Telemetry + proactive independent, both default-off (clean rollback).

---

## 18. Definition of done — every answer is in this document

- **What bytes leave the appliance?** §3.2 outer envelope (plaintext routing metadata) +
  §3.3 sealed inner scalars; ≤ 64 KiB.
- **Which endpoint?** §3.1 `POST https://<origin>/v1/telemetry/samples`.
- **How authenticated?** §4 bearer credential (mandatory); mTLS deferred.
- **Attribution without a body id?** §3.5/§12 authenticated transport → tenant/appliance.
- **How encrypted / key identified?** §3/§10 `sealbox` (`x25519-sealbox`), `key_id` in
  the envelope, active TAC key.
- **After a timeout?** §3.5 transient → backoff/jitter retry of the **same** sealed
  sample.
- **Duplicates?** §3.4/§5 `(appliance, sample_id)` dedup → `duplicate:true`.
- **After restart?** §5.3 one-slot pending sample persists + retries if still enabled;
  new `sample_epoch` on a fresh build.
- **Counter reset?** §5.2 restart = new epoch; TAC reads it as a reset, not a rollback.
- **Stored locally?** §5.3 one pending sample; §11 degradation ledger; both bounded, `0600`.
- **Consent disabled?** §5.4 pending sample **deleted immediately**, egress stops same
  tick.
- **Which metrics + why?** §7 eligibility table (default-deny, own-health bits only, with
  justifications).
- **Admin verifies the schema?** §8 preview + `registry_hash` + schema version.
- **TAC retention/isolation?** §12 tenant isolation, bounded retention, no-AI default.
- **What must exist in `tac-platform` first?** §13 the gateway + golden vectors (Slice
  2.5); **Slice 3 is blocked** until it passes.
- **What stages a proactive bundle?** §11 an eligible check failing
  `ConsecutiveFailures` times after startup grace, outside cooldown.
- **Storms across restart/HA?** §11 durable per-degradation cooldown survives restart;
  per-node local only; no cross-node coordination.
- **Proven no auto-upload?** §11 staging is local-only + `TestProactiveStaysLocal`;
  §5/§14 telemetry send is separate, gated, `TestNoAutoTelemetry`.
