# M7 — Proactive support & opt-in telemetry: design + red-team + 4-slice plan

- **Status:** Proposed (design), **Revision 2** — the red-team (Rev 1) and Codex
  review (Rev 2) are folded back into the design as concrete changes, not just a
  threat list. Final milestone of the supportability roadmap
  (`docs/support/SUPPORTABILITY-ROADMAP.md` §M7). M0–M6 shipped.

> **Revision 2 (Codex-review design changes).**
> - **Telemetry requires an authenticated identity to enable.** Rev 1 removed
>   `node_id`, making authenticated transport the *sole* attribution mechanism — so
>   `telemetryEnabled()` now mandates a bearer credential **or** explicit mTLS
>   (`Enabled && Endpoint!="" && (Credential!="" || MTLS)`); an endpoint-only config
>   is refused. The sender can never emit unauthenticated/unattributable telemetry.
> - **The `node_id` removal is scoped to the telemetry payload/config**, not to
>   locally pre-staged support bundles — those keep their normal node identity in the
>   manifest (expected, redaction-governed, never sent without separate upload consent).

> **Revision 1 (red-team-driven design changes).** Three red-team findings are
> resolved *in the design* rather than only by tests:
> - **R1-C → `node_id` removed from the payload entirely.** The gateway already
>   authenticates the appliance (per-appliance credential / mTLS) and knows the
>   tenant, so it groups server-side with **nothing identifying in the body**. This
>   deletes an identity-leak vector by construction rather than trying to make an
>   in-body id "safe".
> - **R10 → telemetry payload is E2E-sealed to the TAC key** (reuse M6 `sealbox` +
>   the merged TAC trust store), *in addition to* the subset wall + TLS. The no-E2E
>   posture made confidentiality "load-bearing on the walls holding"; sealing makes a
>   wall regression **non-catastrophic** (a leaked payload is still opaque to a MITM
>   and to everything short of TAC's KMS). Cost is trivial — the payload is a few
>   dozen scalars.
> - **R1-A → telemetry metrics are structurally label-free scalars** (no label
>   allowlist to mis-curate), and eligibility is **default-deny**: a metric is
>   telemetry-ineligible unless explicitly marked with a recorded per-metric
>   justification.
- **Depends on:** M1–M6; the metric `{in_bundle, local_only, telemetry_eligible}`
  registry (HEALTH-AND-EVENT §7 — **does not exist yet; M7 builds it**); the M6
  consent/SSRF/outbound machinery it reuses.
- **Mandatory invariants (P6 / ADR-0011/0014):** four independent consent switches,
  four audit trails; telemetry is a **strict subset of bundle-eligible aggregate**
  metrics (no identities, no bundle contents); everything **default-off**; proactive
  collection is **local-only** (no auto-send); every byte is **outbound-initiated**
  (the cloud can never dial in).

---

## 1. What M7 delivers

Three capabilities, all off by default and consent-separated:

1. **Opt-in telemetry** — a 4th independent consent switch that periodically sends a
   *proven strict subset* of bundle-eligible **aggregate** metrics (counts/gauges,
   no per-user/per-host raw, no bundle bytes, no identities) to a consented TAC
   endpoint, over authenticated HTTPS. An admin can preview the **exact** payload
   before enabling.
2. **Proactive health self-checks** — a bounded loop that, on a health/readiness
   threshold crossing, **pre-stages an incident-scoped bundle locally** (no
   auto-send — the operator still consents to any upload).
3. **Alert → scope linkage** — a fired alert *suggests* the matching support
   incident scope for a bundle (suggestion only; never auto-collects).

**Non-goals:** telemetry-on-by-default; conflating telemetry with support/upload;
any cloud→appliance push; remote interactive support (still deferred).

---

## 2. The load-bearing constraint: there is no metric registry today

`culvert_*` metrics are emitted as hardcoded `fmt.Fprintf` blocks + per-subsystem
`WritePrometheus` appenders (`metrics.go`); the `prometheus` client library is not
used. The nearest struct-shaped seam is the OTLP snapshot builders
(`otlpCounterMetrics`/`otlpGaugeMetrics` in `otlp.go`, which already hold
`{name, desc, val}` slices). **M7 must introduce a registry** that tags each metric
`{in_bundle, local_only, telemetry_eligible}`. This registry is the single source of
truth for "what a telemetry payload may contain" and is therefore the security spine
of the whole milestone — it is Slice 1, and it carries the strictest walls.

Everything else clones a proven M6 seam:
- Consent switch ← `support_upload.go` `uploadConfig` (node-local JSON, fail-closed,
  atomic 0600, `xxxEnabled()` gate, redacted read model).
- Outbound sender ← `internal/otlp` `pushLoop`/`push` (SSRF-guarded transport,
  `validEndpoint` regex sanitiser) + `internal/supportupload`'s per-request
  `ssrf.PrivateHost` origin preflight (matters under `HTTPS_PROXY`).
- Config-time endpoint check ← `validateUploadOrigin` (https-only, private-IP refused).
- Background worker start ← `loadPersistentAdminState` **after `LoadAdminSettings`**
  (next to the upload worker), so it observes restored consent.
- Proactive self-check loop ← `startSupportRetentionJanitor` (boot sweep + tick).
- Incident scope selection ← `resolveSupportScope` + `supportIncidentScopes`
  (`support_scopes.go`); `createSupportBundle(ctx, scope, level, caseID)`.
- Alert seam ← `fireAlert(event, AlertPayload{Source,…})` (`alerts.go`).

---

## 3. Four-slice decomposition

Egress is isolated to **Slice 3**. Slices 1–2 are zero-egress foundations; Slice 4
is local-only. This mirrors the M6 shape (spine → consent → egress → polish),
consolidated to four.

### Slice 1 — Telemetry metric registry + strict-subset wall + payload builder (ZERO EGRESS)

**Ships**
- A metric registry: `telemetryMetric{Name, Help, Type, InBundle, LocalOnly,
  TelemetryEligible}` — a curated list over the **label-free scalar aggregate**
  `culvert_*` metrics. Built over the OTLP `{name,desc,val}` seam so it is a real
  struct list. Eligibility is **default-deny**: `TelemetryEligible` is false unless a
  metric is explicitly marked with a recorded justification (R1-A/R8).
- `buildTelemetryPayload()` — a **pure** function: registry ∩ telemetry_eligible →
  `{schema_version, generated_at, metrics:{name:value}}`. Scalar values only. **No
  `node_id`, no appliance/host/user identifier of any kind** — the receiving gateway
  attributes the payload from the authenticated transport (credential/mTLS + tenant),
  so nothing identifying is ever in the body (R1-C).
- `GET /api/support/telemetry/preview` (admin) — returns the exact payload that
  *would* be sent (the plaintext, pre-seal, so the admin sees the real content).
  Read-only; no consent, no sender.

**Walls / tests (`telemetry_registry_test.go`)**
- `TestTelemetrySubset` — telemetry_eligible ⊆ in_bundle **and** no local_only metric
  is telemetry_eligible (the §7 strict-subset invariant).
- `TestTelemetryLabelFree` — no telemetry_eligible metric carries **any** label
  (structurally label-free scalars — no allowlist to mis-curate). A label is the
  identity/cardinality vector, so telemetry admits none (R1-A).
- `TestTelemetryPayloadHasNoIdentity` — the serialized payload contains no `node_id`
  or identifier key, and no IP-shaped / hostname-shaped string (heuristic scrub over
  the exact bytes that would be sealed) (R1-C).
- `TestTelemetryPayloadNoDrift` — the builder emits **exactly** the registered
  telemetry_eligible names (no raw-store reads, no drift).
- `TestTelemetryRegistryCoversEmittedMetrics` — reverse-parity: every emitted
  `culvert_*` name has a registry row (or an explicit exemption), so a new metric
  cannot silently escape governance (mirrors the `config_surfaces`/`uiRoutes` walls).

**Why first:** it is the security spine. Nothing can be sent that the registry does
not bless, and the wall makes "provably non-sensitive" a machine-checked fact.

---

### Slice 2 — Telemetry consent switch + config + preview GUI (ZERO EGRESS)

**Ships**
- `telemetryConfig{Enabled, Endpoint, Credential, MTLS}` at
  `<dataDir>/support/telemetry_config.json` — cloned from `uploadConfig`
  (fail-closed load, atomic 0600 save, redacted read model reporting only
  `credential_set`). **Its own** endpoint + credential — never borrows upload's.
- **`telemetryEnabled()` requires an authenticated identity (Rev 2, Codex):**
  `Enabled && Endpoint!="" && (Credential!="" || MTLS)`. Because Rev 1 removed
  `node_id` from the payload, the gateway attributes the appliance **solely** from
  authenticated transport — so a bearer credential (or explicit client-cert/mTLS
  config) is **mandatory** to enable telemetry. An endpoint-only config is refused at
  PUT time (400) and `telemetryEnabled()` stays false, so the sender can never emit
  unauthenticated/unattributable telemetry. The PUT validates this alongside the
  endpoint; the credential is stored 0600, never echoed.
- `validateTelemetryEndpoint` (https-only, non-private literal IP refused; mirrors
  `validateUploadOrigin`).
- `GET/PUT /api/support/telemetry/config` (viewer/admin), audited
  `support.telemetry.config`, node-local (no `saveConfigVersion`).
- GUI: a Telemetry panel in the Support view with the **payload preview** (from
  Slice 1) shown *before* enabling — the "clear payload preview" the roadmap requires.

**Walls / tests**
- `TestConsentSeparation` **extended**: enabling telemetry writes **only**
  `telemetry_config.json` — never the upload/bundle/remote surfaces (the 4-switch
  invariant, now with 2 of 4 real).
- Config round-trip + fail-closed-on-corrupt; RBAC + audit; credential redaction
  (never echoed; preserved across posture flips; explicit clear).
- `TestTelemetryRequiresAuth` — enabling with an endpoint but no credential and no
  mTLS is refused (400) and `telemetryEnabled()` stays false (Rev 2).

**Still zero egress:** no sender is wired. This isolates the consent model + preview
from the phone-home.

---

### Slice 3 — The telemetry sender (EGRESS — most security-sensitive; CHECKPOINT before building)

**Ships**
- A bounded periodic sender: mirror `otlp.pushLoop`/`push` (SSRF-guarded
  `http.Client` with `ssrf.SafeDialContext`) + `supportupload`'s per-request
  `ssrf.PrivateHost` origin preflight + `validateTelemetryEndpoint`. Takes
  `buildTelemetryPayload()`, **E2E-seals it to the active TAC trust key** (reuse
  `sealBundleToTAC` / `sealbox` + the merged M6 TAC trust store — no new trust
  material), and POSTs the sealed blob to the consented endpoint on a jittered
  bounded cadence (default hourly, min clamp), gated on `telemetryEnabled()`. Bearer
  credential via `Authorization: Bearer`; **no** http-downgrade redirects (bearer
  never leaks).
- Started in `loadPersistentAdminState` next to the upload worker; idles when
  disabled; exits on ctx.

**E2E-sealed, as defense-in-depth (R10).** The payload is a proven non-sensitive
aggregate (Slice 1 wall), so in principle TLS transport auth would suffice — but
resting confidentiality on "the walls hold" is fragile. Sealing the payload to TAC's
public key (the same mechanism M6 bundles use; the appliance holds no decryption
key) makes a wall regression **non-catastrophic**: even a payload that wrongly
included sensitive data would be opaque to a MITM and to anything short of TAC's KMS.
Cost is trivial (a few dozen scalars). If no TAC trust key is configured, telemetry
is **unavailable** (fail-closed) — the same posture as encrypt-to-TAC upload.

**Walls / tests**
- `TestNoAutoTelemetry` — static scan of startup/background sources for
  `telemetryEnabled(`/`telemetryConfigGet(` (mirrors `TestNoAutoUpload`): the gate
  lives in the sender, not a startup file; nothing sends unless explicitly enabled.
- `TestTelemetrySSRFGuarded` — a private/internal endpoint is refused (config-time
  and dial-time).
- `TestTelemetrySendMatchesPreview` — the send path **seals the same
  `buildTelemetryPayload()` bytes** the preview shows (modulo timestamp): sealing a
  test key pair and opening the sent blob yields exactly the previewed plaintext, so
  the preview cannot lie about what leaves the box.
- No-egress source wall extended to the telemetry files (dials only via the sender's
  guarded client).

---

### Slice 4 — Proactive self-checks + alert→scope linkage + GUI + runbook (LOCAL-ONLY)

**Ships**
- A proactive self-check loop (model on `startSupportRetentionJanitor`: boot sweep +
  tick) reading `computeReadiness()` rows / CHR verdicts. On a threshold crossing
  (a check flips `ok→fail`), it **pre-stages an incident-scoped bundle locally**
  (`createSupportBundle` with the matched scope) — **no auto-send**. Debounced: at
  most one staged bundle per incident per cooldown; single-flight (the existing
  bundle lock); off by default (its own flag); bounded by the §8 bundle budgets +
  retention.
- `alertSourceToScope map[string]string` bridging `AlertPayload.Source`
  (`ca`,`storage`,`proxy`,`scan`,`policy`,`auth`…) → `supportIncidentScopes` keys
  (`tls`,`storage`,`upstream`,`scan`,`policy`,`dns`…). A fired alert is annotated
  with a **suggested** scope; the operator acts.
- GUI: proactive config + a "we noticed X degrading — here is a pre-staged bundle"
  affordance; telemetry panel polish.
- `docs/operator/proactive-telemetry.md` runbook.

**Walls / tests**
- `TestProactiveStaysLocal` — a threshold crossing pre-stages a bundle but never
  calls the upload/telemetry sender (no auto-send).
- `TestProactiveDebounced` — rapid threshold flaps produce at most one staged bundle
  per cooldown (no storm).
- `TestAlertScopeMapValid` — every `alertSourceToScope` target is a real scope
  (mirrors `TestSupportScopes_ReferenceRealCollectors`).
- `TestConsentSeparation` (final form: all four switches independent).

---

## 4. Red-team (adversarial analysis)

The dominant threat class is **exfiltration through a channel the operator opted
into for a narrow purpose**. Each item is attack → defense → test.

### R1 — Data exfiltration via the telemetry payload (CRITICAL)
- **A. Identity-bearing metric slips into the telemetry set.** A future dev tags a
  per-host/per-user/per-URL metric `telemetry_eligible` (a label = identity +
  cardinality). → **Resolved by design (Rev 1):** telemetry metrics are
  **structurally label-free scalars** — no allowlist to mis-curate — and eligibility
  is **default-deny** (per-metric sign-off). → `TestTelemetrySubset`,
  `TestTelemetryLabelFree`.
- **B. Builder reads a raw store directly** (e.g. `topHosts`, the request ring),
  bypassing the registry. → **Defense:** the builder emits only registered
  telemetry_eligible names; drift test asserts builder keys == registry set. →
  `TestTelemetryPayloadNoDrift`.
- **C. In-body identifier carries identity** (`node_id`, hostname, public IP, a
  license id tied to a person). → **Resolved by design (Rev 1):** there is **no
  identifier in the payload at all** — the gateway attributes it from the
  authenticated transport (credential/mTLS + tenant). → `TestTelemetryPayloadHasNoIdentity`.
- **D. Defense-in-depth for A–C:** even a payload that *wrongly* included sensitive
  data is **E2E-sealed to TAC's key** (Rev 1, R10), so a wall regression is not an
  immediate leak.

### R2 — Consent conflation
- **Attack:** enabling telemetry also arms upload (shared config / shared
  endpoint+credential / a UI toggle that flips both), or vice versa. → **Defense:**
  separate node-local file, separate `telemetryEnabled()` gate, separate audit
  action, telemetry's **own** endpoint+credential. → `TestConsentSeparation`
  (extended to assert enabling telemetry touches only its file).

### R3 — Auto-send / default-on
- **Attack:** a startup or background path sends telemetry, or auto-uploads a
  pre-staged bundle, without opt-in. → **Defense:** sender gated on
  `telemetryEnabled()` (default false); proactive staging is local-only and never
  calls a sender; both switches default-off and independently rollback-able. →
  `TestNoAutoTelemetry`, `TestProactiveStaysLocal`.

### R4 — SSRF on the telemetry endpoint
- **Attack:** point telemetry at `169.254.169.254` (cloud metadata) or internal
  infra to exfiltrate/pivot. → **Defense:** `validateTelemetryEndpoint` (config-time
  https-only + private-IP refusal) + `ssrf.SafeDialContext` (dial-time, DNS-rebind
  safe) + per-request `ssrf.PrivateHost` origin preflight (defeats the `HTTPS_PROXY`
  bypass). → `TestTelemetrySSRFGuarded`.

### R5 — Preview integrity ("the preview lies")
- **Attack:** the preview shows a minimal payload but the sender adds fields, so
  consent is given against a false representation. → **Defense:** sender and preview
  call the **same** `buildTelemetryPayload()`. → `TestTelemetrySendMatchesPreview`.

### R6 — Proactive resource storm / hot-path starvation
- **Attack:** a flapping health signal drives continuous bundle builds, starving the
  relay hot path or filling disk. → **Defense:** debounce (one staged bundle per
  incident per cooldown), single-flight, off by default, bounded by the §8
  generation budgets + retention. → `TestProactiveDebounced`.

### R7 — Bearer credential leak
- **Attack:** an http-downgrade redirect or a log line leaks the telemetry bearer.
  → **Defense:** https-only + refuse non-https redirects (reuse the M6 redirect
  guard); credential 0600, never echoed (redacted read model), never logged.

### R8 — Metric-registry governance drift
- **Attack:** a new `culvert_*` metric ships unclassified and escapes both the bundle
  and telemetry governance. → **Defense:** reverse-parity wall — every emitted
  `culvert_*` name must have a registry row or an explicit exemption. →
  `TestTelemetryRegistryCoversEmittedMetrics`.

### R9 — Alert→scope suggestion abuse
- **Attack:** the linkage auto-collects on every alert (storm), or an attacker floods
  alerts to trigger collection. → **Defense:** suggestion-only (no auto-collect from
  the linkage); proactive staging is separately debounced.

### R10 — Trust boundary / E2E for telemetry
- **Original consideration:** should telemetry skip the E2E seal M6 bundles get,
  since the payload is a proven non-sensitive aggregate? Resting confidentiality on
  "the walls hold" is fragile. → **Resolved by design (Rev 1):** telemetry **is
  E2E-sealed** to the active TAC trust key (reuse `sealbox` + the merged M6 trust
  store), *in addition to* the subset wall + TLS. Confidentiality no longer depends
  solely on the walls; a wall regression is non-catastrophic. Fail-closed with no
  trust key (telemetry unavailable), same as encrypt-to-TAC upload.

---

## 5. Cross-milestone invariants honored
1. No ship on a red Security gate.
2. Every new route has `uiRoutes` metadata + a UI affordance + a
   `route-classification.yaml` row (GUI parity + OpenAPI coverage gate).
3. Every new persisted state (`telemetry_config.json`, staged bundles) lives under
   `<dataDir>/support` and is bounded (retention/preflight). The `node_id` removal
   (Rev 1) applies to the **telemetry payload/config only**; locally pre-staged
   support bundles (Slice 4) keep their normal node identity in the manifest
   (`clusterRole.nodeID`, `SUPPORT-BUNDLE-SPEC.md`) — that is expected, redaction-
   governed, and never leaves the box without the operator's separate upload consent
   (Rev 2, Codex).
4. Additive-only wire/format; telemetry opt-in defaults off; telemetry + proactive
   are independent, both default-off (clean rollback).

## 6. Build order + checkpoints
- **Slice 1 → 2** back-to-back (zero egress).
- **Checkpoint before Slice 3** (the phone-home slice), as with M6's PR-5.
- **Slice 4** last (local-only + GUI + docs).
Each slice is an independent PR off main; Slice 3 is the only one that opens egress.
