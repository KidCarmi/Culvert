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
> proactive **incident state machine** replacing the naïve `ok→fail` compare (§11);
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
2. **Proactive local support-bundle staging** — a durable incident state machine that,
   on a sustained health degradation, **pre-stages an incident-scoped bundle locally**
   (never auto-sent).
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
| Proactive incident state machine + durable ledger | **NEW** (§11) | — |
| Telemetry ingestion gateway (`/v1/telemetry/samples`), TAC decryption, idempotency, retention | **CROSS-REPO** — confirmed absent in `tac-platform` (`internal/`: approval/audit/domain/executor/fsm/opsvc/plan/policy/provider/releasemanifest/store/validator; no telemetry/ingest/upload route) | `KidCarmi/tac-platform` (§13) |
| mTLS transport auth; canonical repo-wide metrics architecture | **DEFERRED** (§4, §6) | — |

---

## 3. Telemetry wire protocol v1 (`application/vnd.culvert.telemetry-sealed+json`)

The complete appliance→TAC contract. Versioned; additive-only within a major.

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

```json
{
  "envelope_version": 1,
  "key_id": "tac-prod-2026-01",
  "algorithm": "x25519-sealbox",
  "ciphertext": "<base64-std of the sealbox blob>",
  "ciphertext_sha256": "<lowercase hex sha256 of the RAW sealbox blob (pre-base64)>",
  "sample_id": "<128-bit random hex, = Idempotency-Key>",
  "schema_version": 3,
  "registry_hash": "<lowercase hex sha256 of the governed eligibility schema, §8>"
}
```

- `key_id` — the `key_id` of the TAC recipient key the ciphertext is sealed to
  (from `sealBundleToTAC`/`activeTACTrustKey`, §10). TAC selects the matching private
  key.
- `algorithm` — fixed `"x25519-sealbox"` (the `CVRTSB01` `box.SealAnonymous` scheme).
  A reader that does not recognize it rejects (`422`).
- `ciphertext` — std-base64 of the raw `sealbox` blob (`CVRTSB01` magic + version +
  anonymous-box bytes).
- `ciphertext_sha256` — integrity digest over the **raw** blob; TAC recomputes after
  base64-decode and rejects on mismatch (`422`) before attempting decryption.
- `sample_id`, `schema_version`, `registry_hash` — delivery metadata; **non-identifying**
  (§5/§8). These live in the *outer* envelope (not sealed) so the gateway can dedupe,
  size-check, and route without decrypting.

### 3.3 Inner sealed plaintext (what `ciphertext` decrypts to — TAC-only)

```json
{
  "schema_version": 3,
  "registry_hash": "<same hex as outer>",
  "generated_at": "<RFC3339 UTC>",
  "sample_epoch": "<128-bit random hex, per process/reset epoch, §5>",
  "sequence": 42,
  "metrics": { "support_health_ca_ready": 1, "support_health_clamav_ready": 0, "...": 0 }
}
```

- `metrics` — **label-free scalar** name→number map, ONLY the registry's
  telemetry-eligible descriptors (§6/§7). No labels, no strings, no identifiers.
- `sample_epoch` + `sequence` — let TAC order/dedup within an epoch and detect counter
  resets **without** a stable appliance id in the body (§5). Both are inside the seal
  so a MITM sees neither.
- The **outer `registry_hash`/`schema_version` MUST equal the inner values**; TAC
  rejects a mismatch (`422`) — this binds the unencrypted routing metadata to the
  sealed content.

### 3.4 Success response

```json
{ "accepted": true, "sample_id": "<echoed>", "received_at": "<RFC3339>", "duplicate": false }
```

- `duplicate: true` (still `accepted: true`, HTTP `200`) when the gateway has already
  ingested this `(authenticated appliance identity, sample_id)` — the acknowledgement
  a lost-ack retry needs (§5).

### 3.5 Error taxonomy + retry classification

| HTTP | Meaning | Sender action |
|---|---|---|
| `200` | accepted (incl. `duplicate:true`) | **success** — delete pending sample |
| `400` | malformed envelope / bad base64 / missing field | **terminal** — drop sample, log, surface status; do not retry |
| `401`/`403` | bad/expired credential, wrong tenant, not entitled | **terminal-until-reconfig** — stop sending, surface "auth failed"; retry only after a config change |
| `409` | idempotency conflict (same `sample_id`, different bytes) | **terminal** — drop; must never happen (seal-once), indicates a bug |
| `413` | body over size cap | **terminal** — drop; bug-guard |
| `422` | unknown `envelope_version`/`algorithm`/`schema_version`, digest mismatch, unknown `key_id`, registry-hash mismatch | **terminal for this sample** — drop; if `schema_version`/`registry_hash` unknown, surface "schema unsupported by gateway" (the appliance is newer than TAC) |
| `429` | rate-limited | **transient** — honor `Retry-After`, back off |
| `5xx`, timeout, connection error, DNS failure | gateway/transport | **transient** — exponential backoff + jitter, capped (§5) |

- **Schema compatibility:** additive-only within a major `schema_version`; the gateway
  accepts a `schema_version` it knows and `422`s a newer one (fail-clean, not silent).
  A newer gateway tolerates an older appliance's known schema.
- **Clock-skew policy:** TAC does not reject on `generated_at` skew (the appliance
  clock may drift); ordering uses `sample_epoch`+`sequence`, not wall-clock. TAC MAY
  record skew for diagnostics.
- **Replay handling:** dedupe key is `(authenticated appliance identity, sample_id)`;
  a replayed identical sample returns `duplicate:true`. A different-bytes replay of a
  used `sample_id` is `409`.
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
| `sample_id` | outer + `Idempotency-Key` | 128-bit random per **logical sample**; **reused verbatim across retries** of that sample; NOT a stable appliance id (fresh each sample) |
| `sample_epoch` | inner (sealed) | 128-bit random per **process start / counter-reset epoch**; lets TAC detect resets without an appliance id |
| `sequence` | inner (sealed) | monotonic uint within an epoch; resets to 0 on a new epoch |
| `generated_at` | inner | RFC3339 UTC; advisory (§3.5 skew) |
| `schema_version`, `registry_hash` | outer + inner | governed-schema identity (§8) |

TAC deduplicates by **(authenticated appliance identity, `sample_id`)** — the identity
comes from the transport, the `sample_id` from the body; neither alone is a stable
appliance fingerprint in the payload.

### 5.2 Seal-once + retry

- A sample is **built once**, **sealed once**, and the **same ciphertext bytes are
  retried** until acknowledged or dropped. Retries reuse the same `sample_id` and the
  same sealed blob — so a lost ack (TAC accepted but the response was lost) resolves as
  `duplicate:true` on retry.
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
| `support_uptime_bucket` (0..3) | restart cadence | Aggregate | bucketed (`<1d/<7/<30/≥30`) | **Yes** | coarse stability signal; **exact uptime rejected** (fingerprint/correlation) |
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

## 11. Proactive incident state machine (durable)

A naïve `ok→fail` compare over `computeReadiness()` is insufficient (readiness mixes
gating/report-only/optional/DP-specific/startup-flapping checks). M7 defines an explicit
**proactive check registry** + a durable **incident** model.

```go
type proactiveCheckDescriptor struct {
    Name                string        // e.g. "ca"
    Scope               string        // support incident scope, e.g. "tls" (must be a real scope)
    Severity            string        // "critical" | "warn"
    ConsecutiveFailures int           // crossings required before staging (default 3)
    Cooldown            time.Duration // min gap between stagings for the same incident
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
| `session_secret` | — | critical | **no** (config error, not an evolving incident) |
| `geoip` | — | warn | **no** (optional/data-file; low value) |
| `state_file_*`, DP-dependency rows | — | — | **no** (report-only) |

**Durable local incident state** (`<dataDir>/support/proactive_incidents.json`, `0600`,
bounded): per check `{ last_status, consecutive_failures, incident_fingerprint,
incident_start, last_staged_at, last_staged_bundle_id, recovered_at, cooldown_until }`.

**Transitions** (`unknown → healthy | degraded`; `healthy → degraded`;
`degraded → degraded`; `degraded → healthy`):

- **Startup grace:** no staging during an initial boot grace window (e.g. 5 min) —
  `unknown → degraded` at boot never immediately stages.
- **Threshold:** stage only after `ConsecutiveFailures` (default **3**) consecutive
  failing evaluations — a single flap never stages.
- **One incident, one stage:** staging sets `cooldown_until`; `degraded → degraded`
  does **not** re-stage until cooldown elapses (persistent degradation ⇒ no storm).
- **Recovery closes the incident:** `degraded → healthy` records `recovered_at` and
  resets counters; a **new** failure after recovery opens a **new** incident (new
  fingerprint) and stages again after threshold.
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

**Confirmed:** `KidCarmi/tac-platform` has **no** telemetry ingestion gateway today
(inspected `internal/`, `cmd/`; telemetry appears only under `docs/design/`). Slice 3
(the only egress slice) **must not** be built against an imaginary gateway.

**Prerequisite — before Slice 3 begins, `tac-platform` must ship:**
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
- a duplicate sample returns `200 duplicate:true`,
- a wrong-tenant credential cannot submit as another appliance (`403`),
- an unsupported `schema_version`/`envelope_version` is rejected cleanly (`422`).

**The M7 plan states: Slice 3 is blocked until the TAC telemetry gateway contract and
the golden interoperability test pass.** This is Slice 2.5 (§14).

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

### Slice 4 — Durable proactive support incidents (LOCAL ONLY)
Proactive check registry (§11) + incident state machine + durable cooldown ledger +
startup grace + consecutive-failure threshold + recovery handling + scope mapping +
local bundle staging + alert→scope suggestion + GUI + runbook
(`docs/operator/proactive-support.md`). **No upload, no telemetry send.**
Tests: `TestProactiveStartupGrace`, `TestProactiveConsecutiveFailureThreshold`,
`TestProactiveCooldownSurvivesRestart`, `TestProactiveRecoveryClosesIncident`,
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
TestProactiveRecoveryClosesIncident
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
   Folded: §3/§12 attribution from **authenticated transport only**, tenant isolation
   [TAC], `403` on wrong-tenant, golden vector for it (§13).
5. **SRE (retries/restart/outage)** — *"lost acks, restart dupes, counter resets,
   backlog."* → Folded: §5 seal-once + `duplicate:true` + `sample_epoch`/`sequence` +
   one-slot bounded spool + latest-wins + cooldown/pending survive restart.
6. **Enterprise customer (consent claims)** — *"does 'off' really send nothing? can I
   see what leaves?"* → Folded: §4 default-off + bearer-mandatory; §5.4 disable deletes
   pending immediately; §8 preview + `registry_hash` shows the governed schema and
   current values before enabling.
7. **Support engineer (flapping node)** — *"a flapping check storms bundles / fills
   disk."* → Folded: §11 startup grace + 3-consecutive-failure threshold + per-incident
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
   `proactive_incidents.json`, staged bundles) lives under `<dataDir>/support` and is
   bounded. The telemetry payload carries **no** identifier; staged bundles keep their
   normal manifest node identity (redaction-governed; never sent without upload consent).
4. Additive-only wire/schema within a major; telemetry + proactive independent, both
   default-off (clean rollback).

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
- **Stored locally?** §5.3 one pending sample; §11 incident ledger; both bounded, `0600`.
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
- **Storms across restart/HA?** §11 durable per-incident cooldown survives restart;
  per-node local only; no cross-node coordination.
- **Proven no auto-upload?** §11 staging is local-only + `TestProactiveStaysLocal`;
  §5/§14 telemetry send is separate, gated, `TestNoAutoTelemetry`.
