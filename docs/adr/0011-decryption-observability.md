# ADR-0011: Decryption Observability — a canonical decryption-outcome model

- **Status:** Accepted (ratified 2026-07-16) — implementing in phases (§9). Each phase is
  additive telemetry; feature-off stays byte-identical. **Phase 1 is landing as small
  reviewable slices** — Slice 1 (the `internal/decryptobs` bounded-enum vocabulary) is in,
  dark/unwired; the `DecryptionOutcome` struct + `Entry.dec` block + record wiring follow.
- **Date:** 2026-07-16
- **Deciders:** Engineering Advisor (proposed); project maintainer (ratified)
- **Depends on:** nothing blocking (observability is additive); relates to F9a (#740) / F10 (#741) which
  tune the same subsystem. Closes qualification findings **F6** and **F7**.

## Context

Culvert MITM-decrypts, runs an adaptive decryption-exclusion cache (`internal/autoexclude`), and already
emits the *inputs* of good decryption telemetry — the classifier reason tokens
(`classifyOriginInspectFailure`/`classifyClientInspectFailure`), the `culvert_decrypt_autoexclude_*`
metrics, per-rule decision attribution (`Entry.RuleID`/`RuleMatched`), and a `TUNNEL_CLOSED` accounting
record. What is missing is a **single canonical model** that answers, for every relevant session, *what
decryption decision was made, why, by which rule/profile, and — on failure — where and why it failed*,
and that feeds every surface (request/tunnel records, audit, alerts, Prometheus, API, GUI, SIEM) from
**one schema** rather than N incompatible ones.

The Palo Alto reference design (see `roadmap/PALO-ALTO-ARCHITECTURE-COMPARISON.md`) points directly here:
PAN-OS's dedicated **Decryption Log** with a normalized **Error-Index** taxonomy and an **ACC SSL
Activity** dashboard is its most portable concept. Culvert already has the right *precedent* in-tree: the
request/tunnel `Entry` (`internal/logstore`) carries a **normalized SIEM block** — `SchemaVersion` plus a
categorical, `omitempty`, identity-safe `auth_*` group — shared by the in-memory ring, the JSONL writer,
the SSE live feed, and the store. This ADR extends that exact pattern to decryption.

## Primary objective

One canonical `DecryptionOutcome` value, assembled **once** per relevant session on the existing decision
path, that answers:

- Was decryption attempted? What was the outcome (inspected / manual-bypass / learned-exclusion /
  live-rescue / failure / not-applicable)?
- Which policy rule and decryption profile made the decision?
- At which TLS stage did a failure occur, and what normalized failure category applies?
- What TLS version, cipher, ALPN, SNI, and origin-cert verification status were observed?
- Was the autoexclude cache consulted / hit / contributed-to-learn / rescued for this session? (Cache
  *lifecycle* transitions — promoted / expired / evicted / cleared — are modelled as events, §2.4.)
- What is the operational blast radius (owning profile + how many rules reference it)?

That one value is then **projected** onto each surface. No surface gets its own schema.

## Decision (proposed)

### 2.1 Canonical model — one struct, one serialization

Introduce a single internal value, `DecryptionOutcome` (package `main`, wiring; the pure enums live in a
small `internal/decryptobs` so the engine and glue share them). It is **assembled from values already
computed on the decision path** — `resolveSSLAction`'s decision, the matched `*PolicyMatch` (rule id/name),
the resolved decryption profile (id/name), the completed handshake's `tls.ConnectionState`, and the
autoexclude classifier's reason — so it adds no new probing.

Its **serialization is a nested, optional `dec` object on `Entry`** — `Dec *DecryptionBlock
json:"dec,omitempty"`. This deliberately diverges from the *flat* `auth_*` precedent for one reason: the
decryption block carries **booleans whose `false` is meaningful** (`cache_consulted`, `cache_hit`,
`rescued`, …). A flat `omitempty` bool cannot serialize an explicit `false`, so SIEM/API consumers could
not distinguish "cache not consulted" from "field absent / old record / path forgot to populate it" — and
it would contradict the §8 test that asserts `dec.cache_consulted == false` is observable on a fail-close
session. The nested-pointer shape resolves both concerns:

- **Block-level `omitempty`** — when no decryption decision occurred (plain non-CONNECT, feature-off), the
  whole `dec` key is **absent**, so the wire stays byte-identical (the perf budget in §4).
- **Field-level: booleans and required enums are NOT `omitempty`** — once the block is present, every
  boolean serializes its explicit `true`/`false` and every required enum serializes its value (including
  `none`), so negative outcomes are queryable. Only genuinely-optional strings inside the block (`sni`,
  `cipher`, `cert_fingerprint`) keep `omitempty`.

Because `Entry` is still the single shared wire type, the block flows automatically to the ring, JSONL, SSE
feed, store, and SIEM — **one schema, all surfaces.**

Fields (inner shape of the `dec` object). The `dec_*` identifiers in the JSON column below name the
fields for readability; the **actual JSON keys are relative to the block** (e.g. `dec.outcome`,
`dec.cache_consulted`). Serialization rule per the shape above: **booleans and required enums are
non-`omitempty`** (explicit `false`/`none` always present when the block is); **optional strings**
(`sni`, `cipher`, `cert_fingerprint`, `host` when redacted) keep `omitempty`.

| Field | JSON | Type | Notes |
|---|---|---|---|
| Schema version | `dec_schema_version` | int | independent version for the decryption block |
| Outcome | `dec_outcome` | enum | §2.2 `Outcome` |
| Decision source | `dec_decision_source` | enum | §2.2 `DecisionSource` |
| Rule ID | `dec_rule_id` | string | ULID of the matched forward-proxy rule (reuses `Entry.RuleID` semantics) |
| Rule name | `dec_rule_name` | string | display name |
| Profile ID | `dec_profile_id` | string | decryption-profile stable ID (the autoexclude `scopeID`) |
| Profile name | `dec_profile_name` | string | current display name |
| Normalized host | `dec_host` | string | CONNECT authority / normalized host (redactable, §4) |
| SNI | `dec_sni` | string | client-hello SNI when available (redactable, §4) |
| TLS version | `dec_tls_version` | enum | `1.2` \| `1.3` \| `unknown` |
| Cipher suite | `dec_cipher` | string | IANA suite name (bounded set; record-only, **never a metric label**) |
| ALPN | `dec_alpn` | enum | `h2` \| `http/1.1` \| `` |
| Cert verification | `dec_cert_verify` | enum | §2.2 `CertVerify` |
| Failure stage | `dec_fail_stage` | enum | §2.2 `FailStage` |
| Failure category | `dec_fail_category` | enum | §2.2 `FailCategory` (normalized, PAN Error-Index-like) |
| Bounded failure reason | `dec_fail_reason` | enum | small fixed token set; **never** a raw Go error string |
| Exclusion reason | `dec_excl_reason` | enum | engine reason: `client_cert_required` \| `unsupported_params` \| `client_pinned` \| `` |
| Exclusion scope | `dec_excl_scope` | string | owning profile ID (same as `dec_profile_id`; explicit for SIEM joins) |
| Cache consulted | `dec_cache_consulted` | bool | read path ran (fail-open session) |
| Cache hit | `dec_cache_hit` | bool | a learned entry bypassed this session |
| Contributed to learn | `dec_cache_learned` | bool | this session's evidence was recorded (may or may not promote) |
| Rescued | `dec_rescued` | bool | live-rescue fired for this session |
| Blast radius | `dec_scope_rule_count` | int | rules referencing the owning profile (bounded small int) |
| Node identity | `dec_node_id` | string | CP/DP `NodeID`; empty in single-binary mode |
| Timestamps | (reuse `Entry.TS`/`Time`/`DurationMs`) | — | no new time fields; decision-to-close duration already on `TUNNEL_CLOSED` |

**Raw error strings never appear.** `dec_fail_reason`/`dec_fail_category` are the *normalized* projection of
the classifier output; the unbounded Go error text stays out of the record (and out of metrics), matching
the CWE-117 / log-injection posture (`auditSafe`, `sanitizeLog`).

### 2.2 Bounded enums (every categorical value is closed)

- `Outcome` = `inspected` | `bypass_manual` | `bypass_learned` | `rescued` | `failed` | `not_decrypted`
  (plain-HTTP / non-TLS or no decision) — 6 values.
- `DecisionSource` = `policy_inspect` | `manual_ssl_bypass` | `autoexclude_cache` | `autoexclude_rescue` |
  `no_fail_open_502` | `cert_verify_block` | `non_tls_fallback` | `inspect_unavailable` — 8 values.
  (`inspect_unavailable` = a rule selected inspection but the MITM CA was not ready, so `handleTunnel`
  degraded to bypass — a misconfiguration that must be visible on the coverage view, not hidden inside
  manual bypass. Added by the PR #758 red-team; see the corrections section.)
- `FailStage` = `none` | `tcp_connect` | `client_hello` | `upstream_handshake` | `cert_verify` |
  `client_leaf_reject` | `relay` — 7 values.
- `FailCategory` = `none` | `certificate` | `protocol` | `version` | `cipher` | `client_cert_required` |
  `client_pinned` | `resource` | `timeout` | `other` — 10 values (deliberately mirrors PAN Error-Index
  classes so operators moving from PAN-OS recognise it).
- `CertVerify` = `not_checked` | `verified` | `skipped` | `untrusted_issuer` | `expired` |
  `hostname_mismatch` | `unknown` — 7 values.
- `TLSVersion` = `1.2` | `1.3` | `unknown`. `ALPN` = `h2` | `http/1.1` | ``.
- Exclusion reason reuses the engine's existing `autoexclude.Reason` enum (already bounded, `allReasons`).

Every enum has a compile-time `String()`/validity list and an `_test.go` exhaustiveness pin (the same
drift-guard discipline as `allReasons` / `uiRoutes`). Adding a value is a deliberate, tested change.

### 2.3 Projections — how the one model feeds each surface

- **Request/tunnel record** — serialize `DecryptionOutcome` into the `Entry.dec_*` block at the existing
  close/accounting point (`recordTunnelClose*` for tunnels; the plain-HTTP path for `handleHTTP`). This is
  the canonical record and the SIEM source (JSONL + syslog forwarder already ship `Entry`).
- **Prometheus** — increment counters whose labels are drawn **only** from the bounded enums + the
  capped profile-scope. Proposed series (all reuse the existing cardinality-cap machinery,
  `maxAutoExcludeLabels`):
  - `culvert_decrypt_sessions_total{outcome,decision_source,tls_version}` — the coverage counter.
  - `culvert_decrypt_failures_total{fail_category,fail_stage}` — failure taxonomy.
  - existing `culvert_decrypt_autoexclude_total{reason,scope}`, `_hit_total`, `_active`, `_pending`,
    `_rescue_total`, `_surge_total` stay as-is (now consistent with the record's fields). F6 (per-scope
    hit/active labels) is satisfied by adding `{scope}` to `_hit_total`/`_active` using the same capped
    label set.
  - **Hard rule:** `dec_host`, `dec_sni`, `dec_cipher`, `dec_profile_id`, identity, and any cert subject
    are **NEVER** Prometheus labels (unbounded / attacker-influenced). Only closed enums + the
    admin-created, count-capped profile *name* may be a label.
- **Audit** — unchanged actions, now sharing the enums: `decryption.autoexclude.learn` /
  `.rescue` / `.evict` / `.clear` already exist; they carry `reason`/`scope` that now equal the record's
  `dec_excl_reason`/`dec_excl_scope`. No new per-session audit (audit is for state changes, not every
  session).
- **Alerts** — unchanged events (`decryption_autoexclude`, `_rescue`, `_surge`) via `alerts.Payload`;
  their `Detail` is built from the same normalized tokens.
- **API** — a read-only `GET /api/decryption/health` (viewer) returning the aggregate counters + top-N
  (failure reasons, excluded hosts, profiles-by-bypass) computed server-side, plus the existing
  `/api/decryption-exclusions` (list + Stats + blast radius). Session drill-down reuses the existing
  request-feed API — **but that requires extending it**: `buildLogFilterPredicate` (`ui_config.go:258`)
  today reads only `filter`/`status`/`level`/`method`/`identity`, so the implementation MUST add
  structured `dec.*` filter params (at least `dec_outcome`, `dec_decision_source`, `dec_fail_category`,
  `dec_profile_id`) to `buildLogFilterPredicate` **and** the history-store query path (the predicate is
  shared by the in-memory ring and the store, so both stay consistent). Without this, drill-down links
  would be silently ignored and return unfiltered sessions — so this extension is an explicit
  deliverable of Phase 3, not an assumed capability.
- **GUI** — one new **Decryption Health** SPA panel (§3), reusing existing components; drill-down links
  into the existing request-feed view with a `dec_outcome`/`dec_fail_category` filter.
- **SIEM export** — automatic: the `dec_*` block ships in the JSONL + syslog `Entry`, already wired.

### 2.4 Cache lifecycle vs per-session — modelled distinctly

Per-session indicators (`dec_cache_consulted/hit/learned/rescued`) live on the **record**. Cache
*lifecycle* transitions — **promoted / expired / evicted / cleared** — are not per-session; they are
modelled as the existing **audit + metric events** (`.learn` on promotion, `.evict`/`.clear` on operator
action) plus the `_active` gauge (occupancy) and would gain an `_expired_total` counter. This keeps the
per-session record honest (it records only what that session observed) while still making lifecycle
answerable from audit + metrics.

## 3. Operational dashboard design — "Decryption Health" (ACC-style)

A single SPA panel (`data-view="decryption-health"`, nav item, view div, load/render JS — the standard
Culvert panel shape), reusing existing chart/table components. Every widget answers a concrete operational
question — **no decorative charts**:

1. **Outcome mix (now)** — inspected vs manual-bypass vs learned-exclusion vs live-rescue vs failure, as a
   single stacked bar. *Question: how much of my traffic is actually being inspected right now?*
2. **Inspection-coverage trend** — inspected ÷ (inspected + all bypass/exclusion) over time. *Question: is
   my coverage eroding?* (This is the number an auditor asks for; it pairs with the provable-OFF footprint
   the exclusions panel already shows.)
3. **Top failure reasons** — `fail_category` × `fail_stage` table, descending. *Question: what is breaking
   decryption, and where in the handshake?*
4. **Top excluded hosts** — from the exclusions list (host, reason, hit count, TTL remaining, owning
   profile). *Question: which hosts are dark, and is that expected?*
5. **Top profiles by bypass volume** — profile name, bypass/exclusion count, blast radius (rule count).
   *Question: which fail-open profile is doing the most bypassing — over-adoption signal?*
6. **Abnormal learning/rescue surge** — the existing `_surge` signal + rescue-rate sparkline. *Question: am
   I being poisoned right now?*
7. **Affected rules & profile blast radius** — reuse the existing where-used/`objectReferences` behavior to
   show, for a selected profile, exactly which rules would be affected. *Question: if I evict/retighten,
   what does it touch?*
8. **Drill-down** — every row links to the request-feed filtered on the matching `dec.*` fields (the
   structured session records), so an operator goes dashboard → reason → sessions in two clicks (PAN's
   ACC → Decryption Log → drill-down loop). This depends on the request-log API gaining `dec.*` filter
   params (see §2.3) — a Phase-3 deliverable, without which the links would return unfiltered results.

RBAC: viewer reads the dashboard/API; operator evicts (existing `/api/decryption-exclusions` DELETE);
admin only for any future tunables (ADR-0010). All via `requireRole` + `uiRoutes` metadata (C2).

## 4. Performance & privacy budgets (hard constraints)

**Observability must never block or change the traffic decision.**

- **Hot-path overhead** — the `DecryptionOutcome` is populated from values already in hand on the decision
  path; budget: **≤ 1 heap allocation per decrypted/decisioned session** (one struct, value-passed where
  possible), **zero** additional network/syscalls on the hot path, and **no new lock** on the proxy hot
  path beyond the atomic reads already present (F9a). Serialization to JSON happens at the close/log point,
  off the latency-critical decision, on the same path that already builds the `TUNNEL_CLOSED` entry.
- **Allocation budget / feature-off parity** — when a request makes no decryption decision (plain non-CONNECT,
  or feature-off), the `Dec` pointer stays `nil` and the block-level `omitempty` drops the whole `dec` key,
  keeping the wire **byte-identical** (no `dec.*` fields, including no explicit-`false` booleans, appear);
  benchgate pins zero added allocs on that path.
- **Event-buffer bounds** — **no new buffer.** Reuse the existing bounded `reqlog` ring (cap ~20k, decays)
  and JSONL rotation. The dashboard aggregates are computed from Prometheus counters + the exclusions
  Stats, not from an unbounded event log.
- **Retention** — rides the existing request-log retention (ring + rotating JSONL); no new retention store.
- **Cardinality controls** — enums only for labels; profile *name* label reuses `maxAutoExcludeLabels`
  (200) cap with inline sanitisation so CodeQL sees the guard; host/SNI/cipher/identity/cert-subject are
  **record fields, never labels**.
- **Redaction requirements** — the node-local `decryption_redact_hosts` toggle is a **global
  destination-privacy posture** (PR3 Option B, `traffic_redaction.go`). When on, the destination is
  pseudonymized with a **keyed HMAC** (`h_`+12hex, never omission) at the single `persistLogEntry`
  chokepoint, so the top-level `host`/`uri` AND the nested `dec_host`/`dec_sni` — across **every** sink
  (feed, JSONL/history, SIEM, drill-down) — carry the identical token and no plaintext destination. The key
  is node-local (a stable per-node pseudonym; fleet-wide correlation via a synced key is the deferred B3
  follow-up) and **fail-closed** (posture on + key missing ⇒ a constant `redacted` sentinel, never
  plaintext). The retired unsalted 48-bit hash is gone. `dec_host`/`dec_sni` are never required for a metric.
  Design + sink inventory: `roadmap/PR3-privacy-posture-v2-DECISION.md`. Log-injection: all string fields
  pass `auditSafe`/`sanitizeLog` before entering any log/audit/alert projection.
- **Certificate-metadata privacy** — do **not** store full cert subject/issuer strings by default. If a
  cert fingerprint is recorded at all, it is a bounded **SPKI/cert SHA-256 hash** (hex, fixed length),
  redactable, and **record-only** (never a label, never an autoexclude key — see §5). Default posture:
  record `dec_cert_verify` (the *status* enum) and omit raw cert identity unless an operator opts in.
- **Telemetry-storage-unavailable** — if the log store / JSONL write fails, the traffic decision is
  unaffected (best-effort, exactly as the current `reqlog` behaves); a failed telemetry write never
  propagates to the proxy path and never changes inspect-vs-bypass.

## 5. Investigation — server-certificate identity as a signal (NOT implemented here)

**Constraint:** do not implement origin-cert CN matching as an enforcement/lookup key in this slice, and do
not expand the autoexclude lookup or bypass blast radius. This section records the analysis and defers the
decision to its own ADR.

- **CN alone is not authoritative identity.** Modern PKI puts identity in **SANs**; CN is legacy and often
  absent/generic. Shared certs, CDNs (one cert for thousands of hosts), and certificate rotation mean CN/SAN
  are **many-to-many** with hosts — using them to widen a bypass could let an exclusion learned for host A
  silently cover unrelated host B on the same shared/CDN cert. That is a blast-radius expansion, forbidden
  here.
- **Ordering problem.** An exclusion decision can be required **before** the origin certificate is available
  (e.g. the strip path decides fail-open on an upstream handshake that never completes; the native-ALPN path
  has already sent `200`). So cert identity cannot be a *precondition* of the bypass decision without
  changing the decision's timing — out of scope.
- **What this slice DOES do with cert identity:** record it as **bounded, redacted metadata only** —
  `dec_cert_verify` (status enum) always; optionally a fixed-length SPKI/cert **fingerprint hash** behind a
  privacy opt-in — purely for the record/SIEM, feeding **no** lookup and **no** key. It never enters the
  `(profileID, host)` boundary.
- **Deferred question (own ADR):** whether a *future* exclusion match should consider SAN/SPKI (not CN) as a
  **narrowing** signal (e.g. "only bypass if BOTH host and pinned SPKI match"), which would *reduce* blast
  radius rather than expand it. That is the only cert-identity direction worth pursuing, and it needs its
  own design + threat model.

## 6. Investigation — same-ID profile-edit staleness (verify, don't broadly flush)

**Constraint:** verify whether same-ID decryption-profile edits make existing cache entries semantically
stale; prefer deterministic generation-based invalidation over broad flushing; **do not change the
`(profileID, host)` isolation boundary without a separate approved ADR.**

- **Current behavior (to confirm in code, `resolveFailOpen`/`resolveDecryptionProfile`):** the read path
  re-reads the *current* profile, so a flip to **fail-close** immediately stops consulting the cache, and a
  **delete→recreate** yields a new profile ID that orphans old entries. **[CULVERT? — verify]** The residual
  case is a **same-ID edit that stays fail-open but changes a security-relevant field** (e.g. raises the TLS
  floor, changes `CertVerification`): entries learned under the old semantics remain consulted until TTL.
- **Options compared:**
  1. **Explicit flush-on-change** (PAN-OS behavior) — simple, but nukes coverage state on any edit
     (including cosmetic ones) and causes a re-learn blip. Coarse.
  2. **Profile generation/version in the entry** — stamp each entry with a **generation token** derived
     deterministically from the profile's *security-relevant* fields (a hash of `{OnInspectError,
     MinTLSVersion, MaxTLSVersion, CertVerification, InspectHTTP2}`); at read time, an entry whose generation
     ≠ the profile's current generation is treated as a **miss** (selective, self-healing, no broad flush).
     This is **entry metadata**, not part of the key — the `(profileID, host)` boundary is unchanged.
  3. **Selective invalidation only when relevant fields change** — same as (2) but eager (walk + drop on
     edit) instead of lazy (drop on read). Lazy (2) integrates more cleanly (no walk under lock).
- **Recommendation (for its own slice/ADR):** option **2 (deterministic generation, lazy)** — a cosmetic
  rename or an unrelated edit does not invalidate; only a security-relevant change does, and it self-heals on
  next read. **Not implemented in this observability slice**; recorded so the observability record can carry
  `dec_profile_id` today and a generation later without a schema break.

## 7. Non-goals (explicitly out of scope for this slice)

Do **not** implement here: a separate decryption-policy rulebase; SP3 / single decoded-stream scanning;
continuous protocol re-classification; curated feed-delivered exclusions; cluster-wide cache eviction (F8);
CN/SAN-based bypass expansion; and any change to the `(profileID, host)` isolation boundary. Runtime
behavior does not change until this ADR and design are reviewed and a subsequent implementation slice lands.

## 8. CI & qualification plan (permanent tests the implementation must add)

- **Outcome × decision-source matrix** — a table-driven test asserting every reachable `(Outcome,
  DecisionSource)` pair produces the correct `dec_*` block (and that unreachable pairs are unreachable).
- **TLS 1.2 and TLS 1.3** — real handshakes (reuse the `probeClientCertDetection` / MITM e2e harness) for
  each outcome; `dec_tls_version` correct on both.
- **Manual bypass vs learned exclusion vs live rescue** — three distinct outcomes/decision-sources, each
  pinned (extends `TestMITM_*` and the autoexclude suite).
- **Origin cert failure** — untrusted/expired/mismatch ⇒ `Outcome=failed`, `FailStage=cert_verify`,
  `FailCategory=certificate`, `CertVerify` correct, **and no learn** (fail-closed).
- **Client pinning** — `FailCategory=client_pinned`, identity-gating (ADR-0008) reflected in
  `dec_cache_learned`.
- **Unsupported parameters** — `FailCategory=version|cipher` as classified; learn-only (no rescue).
- **Fail-open and fail-close** — fail-close ⇒ `dec.cache_consulted == false` **explicitly serialized**
  (proving the non-`omitempty` boolean shape from §2.1) and no exclusion fields;
  byte-identical wire when feature-off.
- **Cross-profile isolation** — a host learned under profile A yields `dec_cache_hit=false` for a profile-B
  session (mirrors `TestResolveSSLAction_CrossScopeContamination`).
- **Metric cardinality** — assert the exposition contains **only** bounded-enum + capped-scope labels;
  a test that feeds 10k distinct hosts/ciphers/identities and asserts label count stays bounded.
- **Redaction / log-injection** — CR/LF/quote in host/SNI/cert fields cannot forge a record/audit/alert
  field (`auditSafe`); redaction toggle hides host/SNI.
- **Feature-off performance parity** — benchgate: zero added allocs and no measurable latency on the
  no-decision path.
- **GUI/API schema parity** — a parity test (mirroring `ui_routes_meta_test.go` / `config_surfaces_test.go`)
  asserting the `dec_*` record fields, the API response shape, and the dashboard's consumed fields agree —
  so a field can't be added to one surface without the others.

## 9. Phased implementation roadmap

Each phase is one reviewable slice; behavior-visible only from Phase 2 (metrics) onward, and even then only
additive telemetry.

1. **Phase 1 — Minimum viable structured event.** The `internal/decryptobs` enums + `DecryptionOutcome`
   struct + the `Entry.dec_*` block, populated at the tunnel-close and plain-HTTP points. Enum
   exhaustiveness + outcome-matrix + redaction tests. No metrics/UI yet. *(Wire-additive; feature-off
   byte-identical.)*
2. **Phase 2 — Metrics & API.** `culvert_decrypt_sessions_total` + `_failures_total` (+ `{scope}` on
   hit/active, closing F6), the read-only `GET /api/decryption/health` aggregate, cardinality test.
3. **Phase 3 — GUI dashboard.** The Decryption Health SPA panel + **the `dec.*` filter extension to
   `buildLogFilterPredicate` + `apiLogs` + the history-store query path** (required for drill-down, §2.3) +
   GUI/API schema-parity test.
4. **Phase 4 — Alerting.** Fold the coverage-erosion + failure-spike signals into the existing alert events
   (reuse `_surge`; add a coverage-drop alert), each fired once per threshold crossing.
5. **Phase 5 — SIEM/export.** Confirm the `dec_*` block ships cleanly over the JSONL + syslog forwarder;
   publish the field dictionary; add a normalized CEF/ECS mapping note.
6. **Phase 6 — Qualification & rollout.** The full CI matrix (§8) green; operator-doc section (a
   "Decryption Health" how-to mirroring the PAN ACC→log→exclusion workflow); staged rollout note.

## Red-team corrections (PR #758 fleet)

An adversarial multi-agent red-team of Phase-1 slice 1 (the enum vocabulary) plus this
design confirmed nine findings (none P0/P1). The code fixes landed in slice 1; the design
corrections below are recorded here and are binding on the slices that implement them.

- **[fixed, code] Model completeness — `inspect_unavailable`.** `handleTunnel`
  (`proxy_tunnel.go`) silently degrades an `SSLInspect` decision to bypass when
  `certMgr.Ready()` is false (no CA/passphrase). No `DecisionSource` could represent that
  reachable state, so a coverage view would misattribute it to manual bypass. Added
  `DecisionSource=inspect_unavailable` (§2.2). The wiring slice MUST emit it on that branch;
  whether the coverage chart also needs a distinct `Outcome` bucket (vs folding into
  `bypass_manual`) is a wiring-slice decision, flagged here.
- **[fixed, code] Drift-guard is now a source-scan.** The exhaustiveness claim ("adding a
  value is a deliberate, tested change") was previously a slice-vs-literal pin that could
  NOT detect an orphan const (declared but absent from `All<Type>`) or a new enum type with
  no pin. `decryptobs_parity_test.go` now AST-parses the source and asserts declared-consts ≡
  `All<Type>` per type, and that every `All<Type>` slice is pinned — the real uiRoutes-style
  reverse parity. `Valid()` is now a compile-time switch (not a scan of the exported slice),
  so mutating an `All<Type>` var cannot corrupt validation.
- **[design, `dec_fail_reason`] §2.1 lists a `dec_fail_reason` enum with a vocabulary defined
  nowhere.** It is redundant with `dec_fail_category` (`FailCategory`). **Resolution:** the
  wiring slice either (a) drops `dec_fail_reason` and lets `FailCategory` be the single
  normalized reason, or (b) defines a `FailReason` enum in `decryptobs` (with its own pin)
  before any field references it. No §2.1 field may reference an undefined vocabulary.
- **[design, `dec_excl_reason`] the empty "no exclusion" member.** §2.1 lists
  `client_cert_required | unsupported_params | client_pinned | ""` but §2.2 says the field
  reuses `autoexclude.Reason`, whose `allReasons` has **no** empty member. **Resolution:** the
  wiring slice models `dec_excl_reason` as `autoexclude.Reason` PLUS an explicit empty
  sentinel (mirroring ALPN's valid empty member), documented as such.
- **[design, `dec_host` omitempty] redaction contradiction.** §2.1 lists `dec_host` among the
  `omitempty` optional strings while §4 says a privacy toggle "may omit" it. **Resolution:**
  host is redacted by **hashing to a fixed-length token** (a present, non-empty sentinel), not
  by omission; `dec_host` keeps a single static tag. The wiring slice reconciles the §2.1
  category and the §4 wording so host appears in exactly one bucket.
- **[design, int fields] §2.1 serialization rule is silent on the two int fields**
  (`dec_schema_version`, `dec_scope_rule_count`). A `0` `scope_rule_count` (orphaned profile)
  must remain queryable. **Resolution:** the int fields are **non-`omitempty`** once the block
  is present (same rule as the booleans/enums) so an explicit `0` serializes; the wiring slice
  pins this.
- **[design, cardinality] profile-NAME label churn.** §4 relies on the
  `maxAutoExcludeLabels` (200) cap, but the existing counter is keyed on the mutable profile
  *name* with no eviction/decay, so renames can permanently exhaust the budget and bury live
  counts in `_other_`. **Resolution:** Phase 2 keys the label on the **stable profile ID**
  (bounded by admin-created profiles, rename-immune) or resolves ID→current-name at exposition
  time — never the raw mutable name as the cardinality-bearing key.

## Consequences

- **Positive:** one canonical model behind every surface (no schema drift); closes F6 + F7; gives operators
  a coverage/health view Culvert lacks; PAN-familiar taxonomy eases migration; SIEM export is automatic.
- **Neutral:** no traffic-decision change; feature-off is byte-identical; the autoexclude security
  semantics (ADR-0008/0009) are untouched.
- **Cost:** a new enum package + record block + two metric families + one API endpoint + one SPA panel +
  the parity/cardinality/redaction test suite. Spread across six additive slices.
- **Deferred (own ADRs):** cert-identity-as-signal (§5), profile-edit generation invalidation (§6), and all
  §7 non-goals.

## Related

- `roadmap/PALO-ALTO-ARCHITECTURE-COMPARISON.md` — the study this derives from (Decryption Log + ACC).
- Qualification findings **F6** (per-scope hit/active labels) and **F7** (SIEM-queryable bypass reason) —
  `roadmap/AUTOEXCLUDE-PRODUCTION-QUALIFICATION.md`; both closed by this work.
- ADR-0008 / ADR-0009 (autoexclude security semantics — unchanged), ADR-0010 / F9a (#741 / #740 — tunables
  on the same subsystem).
- The `auth_*` SIEM block on `logstore.Entry` — the in-tree precedent this pattern extends.
- `docs/operator/traffic-log-destination-privacy.md` — the operator runbook for the §4
  destination-privacy posture (enabling, key rotation, cluster behavior, troubleshooting).
