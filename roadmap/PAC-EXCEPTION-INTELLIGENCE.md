# PAC Exception Intelligence — R&D Report & Target Architecture

> Status: **PARTIALLY IMPLEMENTED.** P0 (config-derived DIRECT inventory, `internal/pac/inventory.go`),
> P2 (governance/exception records, `internal/pac/exceptions.go`), and P3 change-diff have shipped with
> admin APIs (`pac_posture_api.go`, `pac_exceptions_api.go`) and behavioral tests. P1 telemetry, P4
> endpoint-agent evidence, and P5 fleet analytics remain **not started**. The evidence-class taxonomy
> (§2), the de-scalarisation rule (§7), and "absence of evidence is never evidence" (AC-2) are the
> reusable doctrine cited by ADR-0025 (Policy Learning). Originally authored from a 9-reviewer
> independent fleet; per-reviewer verdicts are in §10.

---

## 0. Terminology (Phase 0 — the truth layer)

Two concepts that the product, UI, metrics, risk scoring, audit and docs **must never conflate**:

| Term | Meaning | What still happens | What is lost |
|------|---------|--------------------|--------------|
| **Full Security-Path Bypass** (`DIRECT`) | A PAC rule returns `DIRECT` | Nothing reaches Culvert at all | TLS inspection, DLP, CDR, URL filtering, threat inspection, auth/identity, policy runtime, **all** proxy logging, future RBI |
| **TLS-Decryption Bypass** | Traffic transits Culvert but TLS is not decrypted | Connection reaches the proxy; logging, policy, threat-by-SNI, allow/deny still apply | Only deep TLS inspection (DLP/CDR/content) |

**Naming rule (frozen):** the bare word "bypass" is banned unqualified. `DIRECT` = "FULL BYPASS · DIRECT" (solid highest-severity red, severed-link glyph). TLS-decryption = "TLS NOT INSPECTED" (amber outline, open-lock glyph). No shared UI component or color token between them.

**The governing physical fact:** `store.go:1106` records observed destinations (`topHosts`) only for `status == "OK" || "POLICY_ALLOW"` — i.e. **proxied** traffic. A `DIRECT` request never opens a connection to Culvert. **Therefore the proxy data plane has zero observation of any DIRECT bypass.** This is not an engineering gap; it is the definition of DIRECT. Every claim in this product is bounded by it.

---

## 1. Executive R&D Report

### 1.1 Problem
Enterprises accumulate PAC `DIRECT` rules, exclusions, private-network bypasses and broad wildcards over years. Each one is a full security-path bypass, yet today they are invisible configuration exceptions: no owner, no justification, no expiry, no risk score, no blast-radius understanding, and — critically — **no way to know if they can be safely removed.** The administrator's question is: *"Where does PAC bypass exist, who depends on it, why does it exist, what risk does it create, and can we safely remove it?"*

### 1.2 Who owns this today
Nobody, or a spreadsheet. The rule lives in a PAC file edited by the network team; the risk is owned by security; the breakage-if-removed is feared by the help desk. A SIEM sees the *proxied* traffic and the customer's egress firewall sees *some* DIRECT egress, but neither ties a flow back to the PAC rule that caused it, and neither governs the rule's lifecycle.

### 1.3 Current-state gaps (verified in code — not inferred from labels)
- **PAC-fetch telemetry is ~zero.** Serving `/proxy.pac` and `/pac/{id}.pac` records no useful fetch telemetry: `pacObserveServe` (`pac_metrics.go:50`) bumps global counters and — on a *degraded* compile only, latched once per profile — also takes a mutex, `logger.Printf`s, and **calls `fireAlert` synchronously** (`pac_metrics.go:80`; every other site uses `go fireAlert`). No fetcher source IP, User-Agent, profile-as-label, served revision, or durable per-fetch record. Serving never calls `reqlog.Add` or `topHosts.Record`. **The telemetry must be built — and the existing synchronous serve-path coupling (fire-alert + the un-latched `logger.Printf`) is a pre-existing violation of the analytics-off-serve-path rule that P1-a must fix, not just avoid re-introducing.**
- **No client / device / endpoint-agent / tenant identity.** Only authenticated username + per-request source IP + cluster DP-node identity exist. `device_id` is a reserved-but-unimplemented policy predicate. The only agent is the **host-ops** maintenance agent (`packaging/culvert-maint`, `release_dispatch_service.go`) — there is no endpoint agent. Single-tenant per deployment. A **redaction/data-handling precedent already exists** and PEI must inherit it — `docs/support/REDACTION-MODEL.md` plus ADR-0009/0010/0016 (5-class DataClass taxonomy, redaction-on-export, raw-vs-normalized retention) — so the earlier "no privacy docs" characterisation was wrong; there is no PAC-*fetch*-specific privacy doc, which P1/P2 must add.
- **Existing PAC metrics** are 10 unlabeled global scalars, Prometheus-text only, token-gated, not OTLP-exported.
- **The strong PAC engine already exists and is reusable — but on the unmerged PAC Traffic Steering branches, NOT on `main`:** compiler + simulator + `impact.go` (`DiffProfiles`, `AnalyzeImpact`; `NewDirectPaths`/`SecuritySensitive` are struct fields) + lifecycle (revision history, digest, typed-DIRECT publish confirmation) + profiles/pools share **one** rule model and sync CP→DP. **Hard prerequisite:** all of this ships in PRs #799 / #802 / #804; on the current `main` the PAC surface is only `pac.go` + `internal/pac/pac.go` (proxy host/port/exclusions + `/proxy.pac`). PEI's P0/P3 "reuse existing machinery" is therefore conditional — **PAC Traffic Steering must merge first**, or PEI must be built on that branch. The P0/P3 PRs must not be scoped as reuse of machinery absent from their base.

> **Consequence:** ~80% of the *honest* product (inventory, governance, change-diff, blast-radius over proxied destinations, static risk) is buildable on existing machinery. The net-new, high-risk part is the inference layer — which must be tightly constrained.

### 1.4 Technical feasibility
- **High** for governance, inventory, static risk, change-diff, publish guardrails (mostly exists).
- **Medium** for PAC-fetch telemetry (must build, but source IP/UA/profile/ETag are all in hand at `writePACResponse`; the honest unit is *fetch origin* = site/egress-IP, not endpoint).
- **Not feasible without an endpoint agent (or customer firewall/DNS log ingest):** actual DIRECT usage, per-endpoint/identity dependency, "what breaks if removed" as fact, true never-used staleness, a client's *effective* (vs *fetched*) revision.

### 1.5 Main constraints (the non-negotiables, restated as engineering law)
1. Do not fake DIRECT visibility; never render inference as fact.
2. Analytics is **never** in the PAC serving critical path; PAC delivery survives total intelligence failure.
3. No unbounded Prometheus labels; no cloud dependency; not a SIEM; not an ITSM.
4. `DIRECT` ≠ TLS-decryption bypass; PAC failover ≠ NLB.
5. Minimize data by default; air-gap/local-only must work.

### 1.6 Recommended product scope
Ship **"PAC Bypass Governance & Posture"** — reposition away from "measurable bypass intelligence." Deliver Phases 0–2 fully (truth/terminology, distribution+posture telemetry, exception governance) and Phase 3 as **candidate blast-radius over proxied destinations only** (explicitly labelled, no usage claims). Defer all true-usage inference to Phase 4, gated on an endpoint agent or firewall/DNS log ingest.

### 1.7 GO / NO-GO
**GO WITH CONDITIONS.** Unanimous across the fleet (8× APPROVE WITH CONDITIONS, 1× GO WITH CONDITIONS). The single hard gate: **if the org insists on the "measurable / evidence-backed bypass" framing before a real traffic source (agent or firewall/DNS ingest) exists, this flips to NO-GO.** The conditions in §1.5 + §10 are mandatory, not advisory.

---

## 2. Evidence Matrix

Evidence tiers (never silently combined): **A** deterministic/authoritative · **B** corroborating/imported · **C** inference from a biased sample · **D** human attestation. Confidence = tier × cross-source agreement × freshness × survivorship caveat → {High, Medium, Low, Unknown}.

| Insight | Evidence source(s) | Class | Accuracy | Confidence | Blind spots | Needs agent? | Needs proxy traffic? | Needs customer input? |
|---|---|---|---|---|---|---|---|---|
| Which rules *can* bypass (DIRECT/availability/private/wildcard/CIDR) | Static config analysis (E4: `validate`, `analyzeRuleList`) | Observable | Exact | **High** | none | No | No | No |
| Which change *introduced* a bypass | Revision diff (E3: `DiffProfiles`/`NewDirectPaths`) | Observable | Exact | **High** | none | No | No | No |
| Broad / shadowed / duplicate / dead-by-shape rules | Static analysis (E4) | Observable | Exact | **High** | intent unknown | No | No | No |
| Which clients *fetched* which profile + revision | PAC-fetch events (E2 — **build**) | Observable (fetch) | Good at site/egress-IP | **Medium** | NAT/VPN collapse; caching; Chrome no-304 | No | No | No |
| Clients likely on an outdated PAC | E2 + `X-Culvert-PAC-Version` | Inferred | Lag hours–days | **Low–Medium** | can't distinguish "old rev" from "not refetched" | Endpoint agent for truth | No | No |
| Fetch failures / denials | E2 serving-layer | Observable | Exact at server | **Medium** | a returned 403 = client about to fail-**open** to DIRECT | No | No | No |
| DIRECT-rule blast radius (which recent destinations *would* match) | Candidate-replay (E5: `AnalyzeImpact` over `topHosts`) | Inferred | Upper-bound on proxied set only | **Medium** | **survivorship bias** — blind to hosts already going DIRECT; ≤100 sample; CIDR/private → undetermined | No | Yes | No |
| Which DIRECT rules are actually **used** | — | **Not observable** | — | **Unknown** | DIRECT never reaches Culvert | **Yes** (or fw/DNS logs) | — | Optional import |
| **Who depends** on a rule (endpoint/user) | — | **Not observable** | — | **Unknown** | no per-endpoint attribution | **Yes** | — | Optional |
| **What breaks** if a rule is removed | Simulation bound + (future) agent | Inferred→Unverified | Bounded by sim only | **Low** | the dependent pop is exactly the traffic that never reaches the proxy | **Yes** for fact | Partial | Optional attestation |
| True "never used / safe to delete" | — | **Not observable** | — | **Unknown** | absence of evidence ≠ unused | **Yes** | — | — |
| Corroborating DIRECT evidence | Imported DNS/SIEM/firewall (E8/E9) | Corroborating | Varies | **Medium** | customer-dependent | No | No | **Yes** |

**Wording contract (frozen, testable):** never "used" for a DIRECT rule. Split facts, never sum across sources:
> "347 clients fetched a profile containing this rule (E2, 7d). 82 of the last 100 proxy-observed destinations would match it (E5, blast-radius upper bound — cannot see destinations already going DIRECT). Confidence: Medium. As-of 2026-07-18T09:00Z."

---

## 3. Threat Model

**Assets:** PAC content (reveals internal topology/pool hosts); the steering config; the intelligence/evidence store (may hold IPs/domains); PAC-access tokens; the posture verdicts operators trust.
**Actors:** unauthenticated PAC fetcher (anyone who can reach the proxy port), malicious insider/admin, network attacker, a compromised endpoint, a curious tenant (future multi-tenant).
**Trust boundaries:** unauthenticated PAC serving ↔ authenticated admin API ↔ CP↔DP sync ↔ (future) agent ↔ optional cloud enrichment.

| # | Abuse case | Class | Mitigation |
|---|---|---|---|
| AC-1 | **Stale-PAC replay = bypass persistence** — a removed DIRECT rule keeps working on pinned/offline/air-gapped clients; no server-side revocation exists | HIGH | Track `X-Culvert-PAC-Version` re-fetch per client population; surface non-revalidated clients as **residual live bypass**; never mark a removal "complete" from server state alone |
| AC-2 | **"Unused ⇒ safe to remove"** presented as fact | HIGH (structural) | DIRECT usage is NOT OBSERVABLE; label as such; never auto-propose deletion from absence of evidence |
| AC-3 | **Gaming adoption** — spoofed source IP/UA on unauthenticated fetches fake "N clients adopted" | Med | Count distinct **authenticated identity** over raw IP where available; confidence chip; cap single-source contribution |
| AC-4 | **Poisoning `topHosts`** — flood to inflate a host (make a DIRECT candidate look "used") or evict honest heavy-hitters via decay (suppress) | Med | Sample-boundedness disclosed; flag evidence concentration; treat replay as upper-bound only |
| AC-5 | Profile enumeration / PAC content disclosure (IDs not opaque; pool hostnames leak topology) | Med | Optional opaque-token access; treat PAC content as disclosed; never expose pool credentials |
| AC-6 | Host-header / XFF poisoning to misattribute or mis-route | Med | Never trust `r.Host`/`X-Forwarded-Host`; `realClientIP()` only behind a configured trusted proxy |
| AC-7 | Token leakage (opaque PAC URL in GPO/MDM/Referer/upstream logs) | Med | `no-referrer`, never log token, rotating bearer secret; PAC still treated as disclosed |
| AC-8 | **CIDR access policy misconfig bricks a fleet → fail-OPEN to DIRECT** | HIGH | CIDR optional; safe staged rollout + one-click rollback; never a hard authz gate |
| AC-9 | Export exfiltration of domains/IPs/identities | Med | Admin-only + audited export; redact by default; counts-only default |
| AC-10 | Cross-tenant/region evidence bleed (future) | Med | Scope evidence per profile/tenant (autoexclude `(scopeID,host)` pattern); raw PII node-local + off CP→DP + off cross-region |

**Failure modes → §8/§4/§5. Residual risk (accepted, documented):** DIRECT usage is unobservable; stale/pinned PACs cannot be fully revoked; IP/UA adoption is not spoof-proof; PAC topology is disclosed to unauthenticated proxy-port clients.

---

## 4. Scale Model

Assumptions: re-fetch interval ~1800 s, ≥90 % 304 (where the client honors caching). Tiers: **Small** 1 node/1 k clients/10 profiles/100 rules · **Medium** 20 nodes/100 k/500/50 k · **Large** 500 nodes/5 M/10 k/1 M.

| Quantity | Small | Medium | Large |
|---|---|---|---|
| PAC fetch req/s (avg / peak) | 0.56 / 3.3 | 55 / 167 | **2,778 / 5,556** (~5.6/s/node) |
| Non-304 event rate | 0.06/s | 5.5/s | **278/s ≈ 24 M/day** |
| Naive "one row forever" (REJECTED) | — | — | 2.4 GB/day = **876 GB/yr** |
| Per-node sketch memory (constant vs client count) | ~11 MB | ~11 MB | **~11 MB** |
| CP rollup ingress | negligible | ~few KB/s | **533 KB/s** (trivial) |
| Analytics store steady-state | MB | ~GB | **~16 GB (~4 GB compressed)**, 1 min→1 h→1 d rollup ladder |
| Failure recovery | — | — | **one 60 s window** (sketches reconverge) |
| Posture query p99 | — | — | ≤ 200 ms |

**Bounded structures (mapped to insights):** HyperLogLog (p=12, 4 KB, mergeable) → estimated/outdated clients with **zero stored IPs** (fleet estimate = HLL union at CP — the privacy+memory keystone). Count-Min (256 KB) → per-rule evidence over 1 M rules. Space-Saving Top-K (the existing `topHosts` pattern) → top rules/profiles/unknown-profile names. Bloom (1.2 MB) → dead-rule candidates (false-positive direction is safe: never wrongly proposes deletion). Reservoir (10 k) → forensic drill-down without storing 24 M/day.

**Hard rule:** DP aggregates locally → CP rolls up **mergeable sketches** → Prometheus stays bounded (`/metrics` cardinality is O(hundreds) identically at Small and Large) → heavy analytics live in a **separate store**. No raw per-request event leaves its node or is retained forever.

---

## 5. Target Architecture

```
PAC Configuration (pacProfiles/pacStore) ──┐
        │ compile (deterministic)          │
        ▼                                   │  (authoritative config; syncs CP→DP)
Published Steering Bundle (lifecycle, digest, revisions)
        │
        ▼
PAC Distribution  /pac/{id}.pac /proxy.pac   ← SERVING CRITICAL PATH (must never depend on analytics)
        │  enqueue-only, drop-on-full hook (≤1µs)
        ▼
Fetch Telemetry (E2, new)  ─┐
Proxy Traffic Evidence (E1, reqlog/topHosts) ─┤
Optional Agent Evidence (E6/E7, future) ─────┤
Imported DNS/SIEM/firewall (E8/E9, optional) ┘
        │  server receive-time, idempotent upsert, drop-oldest backpressure
        ▼
Evidence Correlation (node-local sketches + rollups)  ── DP aggregates → CP rolls up (NOT CP-authoritative)
        │
        ▼
PAC Exception Intelligence (governance state: owner/reason/expiry/reviews + derived findings)
        │
        ▼
Posture · Risk · Impact · Recommendations (read-only API + SPA)  →  optional SIEM export / optional cloud enrichment (opt-in, off by default)
```

**Component ownership & failure isolation:**
- **PAC compiler / distribution** — existing `internal/pac` + `pac.go`. Unchanged serving contract. The **only** new coupling is a non-blocking, drop-on-full telemetry hook. (**Fix required:** `pacObserveServe` currently calls `fireAlert` *synchronously* on the serve path — move to the async hook.)
- **Telemetry ingestion** — new `internal/pacintel` (proposed): bounded channels, sketches, rollups; strictly downstream of serving.
- **Evidence correlation / reporting / alerting** — separate goroutines/contexts, drained on shutdown; node-local Tier-3 (regenerable) state.
- **Governance** — exception owner/reason/expiry/review as versioned admin config (reuses `auditEvent` + `saveConfigVersion`); mutations flow through the existing validated PAC-config path (PEI *proposes*, never auto-mutates).
- **Agent integration / SIEM export** — stable extension points only; both optional and off by default.

**Enforced boundary:** an architecture/wall test (repo idiom: `config_surfaces_test.go`, C1 route parity) asserts the serve functions reach only `pac.*` + counters + the drop-on-full hook — never CP, store, or analytics. **Fail-open for analytics; fail-closed for serving and publish guardrails.**

---

## 6. Data & Metric Specification

### 6.1 Data model (every record carries: tenant/deployment scope, stable object ID, revision, timestamp, evidence source, confidence, retention class, privacy class)

| Record | Authoritative or Derived | Key fields | Privacy class | Retention |
|---|---|---|---|---|
| `PACProfile` / `PACRule` | Authoritative (exists) | id, kind, pattern, action, mode, privateNetworks | rule pattern = INTERNAL | config lifetime |
| `PublishedSteeringBundle` | Authoritative (exists) | revision, digest, generatedAt | INTERNAL | 50-revision cap (exists) |
| `PACFetchEvent` | Derived (new, E2) | server-recv-ts, profile, served-revision, srcIP→/24 or HLL, UA-class, status/304 | raw IP/UA = SENSITIVE → **aggregate by default** | ≤7 d raw (opt-in), else sketch-only |
| `ClientObservation` | Derived | site/egress-IP bucket, last-seen-revision, HLL membership | SENSITIVE if raw; INTERNAL as bucket | rollup ladder |
| `ProxyTrafficEvidence` | Derived (E1, exists) | registrable domain (eTLD+1), rule matched | FQDN = SENSITIVE; **eTLD+1 = POTENTIALLY-SENSITIVE** (a registrable domain can identify an app/vendor/cohort — consent-gated + small-cell suppression before any count/Top-K/export; see §14/F-PR1..4) | reqlog retention; domain aggregates gated by suppression floor |
| `AgentPACEvaluationEvent` | Derived (future E6) | — | SENSITIVE | future |
| `RuleEvidence` | Derived | rule-id, count sketch, last-evidence-ts, source, confidence | INTERNAL (aggregate) | rollup |
| `ExceptionOwner` / `ExceptionReview` / `ExceptionExpiration` | Authoritative (new) | owner, reason, businessApp, ticket?, expiresAt, reviewCadence | INTERNAL | config lifetime |
| `ImpactSnapshot` | Derived | candidate diff, blast-radius bounds, survivorship caveat | INTERNAL | ephemeral |
| `PostureFinding` / `Recommendation` | Derived | severity, score components, evidence class, confidence, as-of | INTERNAL | recomputed |

Raw destination **full URLs are never collected by default** (PHI/SC hazard; hard-blocked in a healthcare profile). Reuse the appliance's existing `LogFullURI` opt-in-per-rule precedent. The `(srcIP, domain)` pair is more sensitive than either field alone — never store it raw by default.

### 6.2 Metric specification (Prometheus vs analytics store)

| Metric | Type | Labels (max card.) | Store | Notes |
|---|---|---|---|---|
| `culvert_pac_fetch_total` | counter | `profile_bucket`(≤500 or "other"), `result`{200,304} | Prom | collected at serve hook |
| `culvert_pac_fetch_not_modified_total` | counter | — | Prom | |
| `culvert_pac_fetch_denied_total` | counter | `reason`{cidr,token,disabled} | Prom | a denial ⇒ likely client fail-**open** |
| `culvert_pac_unknown_profile_total` | counter | **none** | Prom | requested name is attacker-controllable → name → Top-K in analytics |
| `culvert_pac_profile_active_revision` | gauge | `profile`(≤500) | Prom | integer value, never `revision_hash` |
| `culvert_pac_profile_direct_rules` | gauge | `profile`(≤500) + fleet **SUM** always | Prom | security-critical count always exported unlabeled-sum |
| `culvert_pac_profile_risk_findings` | gauge | `severity`(4) | Prom | not per-finding |
| `culvert_pac_publish_total` / `_publish_blocked_total` | counter | `reason`(bounded) | Prom | exist today |
| `culvert_pac_clients_estimated` / `_clients_outdated_estimated` | gauge | `revision_bucket`{current,-1,-2,older} | Prom | **HLL only — never client_ip/device_id** |
| `culvert_pac_rule_evidence_total` | counter | total + `rank`{1..20} | Prom | rule_id at 1 M = unbounded → identity only in analytics JSON |
| `culvert_pac_rule_unused_candidates` | gauge | — | Prom | Bloom-backed; FP-safe direction |
| `culvert_pac_events_dropped_total` | counter | — | Prom | backpressure visibility |

**Banned as labels everywhere:** `domain`, `url`, `client_ip`, `username`, `device_id`, `raw_rule_pattern`, `revision_hash`. A cardinality test (`pei_cardinality_test.go`) must pin this.

---

## 7. UX Specification

New SPA view `data-view="pac-posture"` (operator=view, admin=act), beside the shipped Steering Profiles/Pools/Simulator panels. Four cross-linked tabs:

1. **Executive Summary** — one **PAC Security Posture** score with a *clickable component breakdown* + five attention counters (high-risk DIRECT rules; exclusions without recent evidence; clients possibly on outdated PAC; fail-open profiles; profiles fetched from unexpected networks). Each figure carries a **confidence pill + evidence-class tag + as-of** and one verb CTA.
2. **Recommended Actions** — the worklist. Each row: title, why-risky (consequence, not adjective), evidence+confidence, owner slot, "what could break" blast-radius preview (Simulator-diff), a **reversible** CTA. Canonical actions: review broad wildcard `*.cloudfront.net`; assign owner to `PAC-142`; expire unused exception `PAC-087`; canary-remove `PAC-052` on 5 %; investigate secondary-proxy usage.
3. **DIRECT Rules Inventory → Rule Detail** — classification banner (FULL BYPASS vs TLS-not-inspected), explainable score, owner/reason, evidence table (source+timestamp+class), blast radius with a **Verified/Observed/Inferred/Unverified** tag, affected profiles/sites, history, expiration, recommended action.
4. **Score Methodology** — the DIRECT Exposure Score as an **explainable** labeled stacked bar of named factors (match breadth, destination sensitivity, evidence freshness, owner accountability, client reach, fail-open context, confidence penalty) + a plain-language sentence + input timestamps. "Explainable" not "transparent": the *factors* are shown, but the *weights* are editorial (no usage ground truth exists to calibrate them). The score is **not a single posture number** — see §7's de-scalarisation note below.

> **De-scalarisation (red-team fix).** A single "PAC Security Posture: 72/100" scalar is banned: it silently sums across evidence classes (violating §2's "never sum across sources") and it strips its confidence/evidence chips the moment it is copied into a slide. The Executive Summary instead shows **class-segregated indicators** — an Observable panel (config facts: DIRECT-rule count, fail-open profiles, missing owner/expiry) that may carry a headline number, and a separate Inferred panel (fetch distribution, blast-radius bounds) that never collapses into one figure. A persistent banner on every posture tab states the blind spot: *"Culvert cannot observe DIRECT traffic; usage figures require an endpoint agent or imported firewall/DNS logs."*

**Copy rules (frozen, testable UI invariant):** "347 clients **fetched a profile containing** this rule" (not "used"); "82 recently observed destinations **would match**" (not "bypassed"); "~412 clients **last fetched** a PAC ≥14 days ago" (not "outdated"). Every number ships its confidence pill + evidence-class from day one. Recommendations are reversible suggestions, not verdicts.

---

## 8. Phased Delivery Plan

Each phase: independently valuable, additive, `omitempty`/downgrade-safe, backed by tests, with rollback = revert (state is node-local Tier-3, off backup/rollback/CP-raw surfaces).

| Phase | Scope | Customer value | Evidence class | Deferred |
|---|---|---|---|---|
| **P0 Truth & terminology** | FULL-BYPASS vs TLS-bypass naming/visual split; evidence-class + confidence primitives; DIRECT inventory read-model from existing config | Honest vocabulary; a real inventory of every bypass rule | Observable (config) | all telemetry |
| **P1 Distribution & posture metrics** (red-team-scoped, per §14/F-SCOPE + F-EV3) | Build `PACFetchEvent` (E2) via async drop-on-full serve hook; **bounded per-node counters + ONE fleet HLL** for a coarse **fetch-distribution** estimate; revision-bucket + fetch-failure/denial metrics; posture dashboard v1. **The full sketch/scale program (Count-Min/Bloom/reservoir/per-profile HLL) is NOT in P1 — demoted to P4-conditional.** | Coarse **fetch distribution** (NOT "adoption") at **egress-IP/24** (or customer-supplied site map) | Observable (fetch) / Inferred (distribution, Low–Med) | per-endpoint; usage; adoption-as-fact; per-profile sketches |
| **P2 Exception governance** | Required owner/reason/business-app; optional ticket; default expiration; review cadence; renewal/approval/emergency workflow; expiry notifications; where-used; stale-rule retire recommendations | Every bypass owned, justified, time-bounded, auditable | Observable (governance) | usage inference |
| **P3 Change-diff, blast-radius & static risk** | `DiffProfiles`/`NewDirectPaths` posture integration (+ **reorder & pool-mutation** detection — see red-team §14/F-EV2); candidate-replay **labelled "impact on currently-proxied destinations", survivorship caveat, upper/lower bound, marked Unknown for *existing* DIRECT rules**; explainable DIRECT Exposure Score; canary-removal workflow | Safe-change review; explainable risk; bounded "what might break" | Inferred (disclosed) | **no usage claims** |
| **P4 Endpoint-agent (or firewall/DNS ingest) evidence** | Real DIRECT observation; per-endpoint/identity dependency; true usage-weighted risk; "safe to remove" backed by evidence | The measurable claims — **only now** | Observable (agent) | — |
| **P5 Large-scale analytics & anomaly detection** | CP rollup ladder, sketches at fleet scale, deterministic-rule anomalies (DIRECT-capable rules spiked; fetch volume dropped; unexpected source network; expired-but-active exception; deleted-profile requests) — thresholds/state-machines, **not** AI | Fleet-wide posture + early warning | mixed, labelled | — |

**Phase 3 hard gate:** no usage/"used"/per-endpoint claim ships before P4. If that gate is removed, the initiative is NO-GO.

---

## 9. PR Plan (only after §8 scope approval)

Small, mergeable, each green and reversible:
1. **P0-a** Terminology + FULL-BYPASS/TLS visual+copy tokens as testable invariants (UI + docs). No behavior change.
2. **P0-b** DIRECT inventory read-model + `/api/pac/posture/inventory` (viewer) from existing config; unit + route-parity tests.
3. **P1-a** Async drop-on-full serve telemetry hook + `culvert_pac_events_dropped_total`; **fix `pacObserveServe` sync `fireAlert`**; latency-regression test proving serving is identical with intelligence killed.
4. **P1-b** `PACFetchEvent` + HLL client estimation + bounded metric set + `pei_cardinality_test.go`.
5. **P1-c** Posture dashboard v1 (Exec Summary + adoption), all figures with confidence/evidence tags.
6. **P2-a** Exception governance model (owner/reason/expiry/review) + versioned mutations + audit; `pei_surfaces_test.go` privacy/parity wall.
7. **P2-b** Expiry/review/renewal workflow + notifications + stale-rule recommendations.
8. **P3-a** Change-diff (incl. reorder + pool-mutation bypass detection) + explainable DIRECT Exposure Score in posture.
9. **P3-b** Candidate blast-radius (labelled, survivorship-disclosed) + canary-removal workflow.
Each PR: gofmt/vet/build, `-race`, determinism, lint, cardinality test, privacy-wall test.

---

## 10. Independent Final Review

| Reviewer | Verdict | Binding condition(s) |
|---|---|---|
| R1 PAC & Client Compatibility | APPROVE WITH CONDITIONS | Adoption/outdated from an agent, not fetch/304 logs; every access-restriction mode designed as fail-OPEN; CIDR/cert gated to on-net/agent |
| R2 Enterprise Network Architect | APPROVE WITH CONDITIONS | Site/egress-IP aggregates only (never per-endpoint); user metrics gated on Identity; risk-separate private vs internet DIRECT; NLB is a distinct future layer |
| R3 Security Architect | APPROVE WITH CONDITIONS | DIRECT-usage claims labelled NOT-OBSERVABLE; inference never shown as fact; stale-PAC replay surfaced as residual live bypass; never auto-mutate policy |
| R4 Detection & Telemetry | APPROVE WITH CONDITIONS | Evidence/confidence/wording contract enforced verbatim; the four agent-only insights ship as explicit "Unknown" |
| R5 Hyperscale Observability | APPROVE WITH CONDITIONS | No high-card labels beyond ~500 cap (detail → analytics store on mergeable sketches); HLL client estimates with no raw IDs; analytics off the serve path with drop-oldest backpressure |
| R6 Privacy & Compliance | APPROVE WITH CONDITIONS | Aggregate-and-irreversible by default; raw opt-in + TTL + redact; no raw destination URLs by default; CI parity walls enforce it |
| R7 Product & Enterprise UX | APPROVE WITH CONDITIONS | Anti-overclaim copy contract + FULL-vs-TLS visual language as hard testable UI invariants; every figure ships confidence pill + evidence-class |
| R8 SRE & Failure-Mode | APPROVE WITH CONDITIONS | Fail-safe boundary enforced by a wall test; enqueue-only drop-on-full serve hook; additive/omitempty telemetry; server-time + idempotent ingestion; node-local Tier-3 evidence; freshness/confidence mandatory states |
| R9 Adversarial | **GO WITH CONDITIONS** | Reposition to governance; Phases 0–2 only + P3 blast-radius-over-proxied (no usage); P3 usage-inference forbidden until an agent/firewall-log source; never per-endpoint pre-agent; confidence chip + source label on every number; **flips to NO-GO if the measurement/evidence-backed framing ships pre-agent** |

**Unresolved disagreements (surfaced, not hidden):**
1. **Candidate-replay: valuable (R4) vs fatally biased (R9).** *Resolution adopted:* ship it, but only as an explicitly-labelled "impact on currently-**proxied** destinations" upper bound carrying the survivorship caveat ("cannot see destinations already going DIRECT"). Both positions are satisfied by the label; it never becomes a usage claim.
2. **How much inference is honest pre-agent.** *Resolution adopted:* Phase 3 = blast-radius over the proxied set only; all true-usage inference deferred to Phase 4. This is the hard gate on which the GO depends.
3. **CIDR access policy** (R1 fail-open inversion vs R3 CIDR-as-weak-identity). *Resolution adopted:* CIDR access remains **optional**, never a hard authz gate, with staged rollout + one-click rollback; default is Public (safe for all clients) or agent-authenticated.

---

## 11. Business Analysis

1. **Pain solved:** ungoverned, invisible full-security-path bypasses accreted in PAC over years.
2. **Owned today by:** nobody / a spreadsheet — split across network, security, and help desk.
3. **Teams served:** Network (distribution/adoption), Security & AppSec (risk/exposure), SOC (residual-bypass & anomaly signals), Endpoint (future agent), Compliance (owner/justification/expiry/audit).
4. **Why a SIEM is insufficient:** a SIEM sees proxied traffic (and maybe firewall egress) but never ties a flow to the PAC rule that caused it, and does not govern the rule's lifecycle.
5. **Why a spreadsheet/ticket is insufficient:** no linkage to live config, no change-diff/blast-radius, no expiry enforcement, no evidence, drifts instantly.
6. **Culvert differentiators:** the config↔posture linkage, compiler-parity simulation/blast-radius, the immutable revision timeline with typed-DIRECT publish confirmation, and the honesty contract (evidence class on every number).
7. **Table stakes:** inventory, ownership, expiry.
8. **Safe to market:** "governed, owned, justified, time-bounded, reviewable, diffable, **safely-*reviewable*** exceptions," plus honestly-labelled blast-radius over proxied destinations. ("Safely-*removable*" is **struck** — removal safety depends on the DIRECT-usage evidence that does not exist pre-agent; §2 grades it Unknown and §3 AC-2 flags it HIGH. Claiming it would repeat the "measurable" overclaim we already dropped.)
9. **Would be misleading (pre-agent):** "measurable," "evidence-backed," "risk-scored" if implying traffic volume, and anything per-endpoint.
10. **Helps sales pre-agent?** Yes — governance + posture + change-safety is a real, demoable, differentiated product on existing machinery, and it *seeds* the agent story ("today govern the config; with the agent, measure the traffic").

**Positioning (validated as technically defensible, red-team-corrected):** *"Culvert turns PAC DIRECT rules from invisible configuration exceptions into governed, explainable and safely-**reviewable** security bypasses."* (Deliberately drops both "measurable" **and** "safely-removable" until Phase 4 — both depend on a DIRECT-traffic source that does not exist pre-agent.)

---

## 12. Testing Strategy & SLOs

- **Unit / property / determinism / fuzz** on the read-models, score, diff, and evidence classification.
- **Metric-cardinality test** (`pei_cardinality_test.go`) — pins banned labels and the ≤500 cap.
- **Privacy/parity wall** (`pei_surfaces_test.go`) — every PEI field classified; SENSITIVE fail-closed; off CP→DP raw + off cross-region + off backup Tier-1/2.
- **High-volume ingestion / retention / eviction** tests (drop-oldest, oldest-first, no OOM).
- **Multi-tenant isolation / privacy redaction / air-gap / no-telemetry / agent-absent** modes.
- **Cluster convergence, partial failure, corrupt-event, old-client compat, upgrade/downgrade, backup/restore.**
- **Serve-path latency-regression test** proving PAC serving is byte- and latency-identical with the intelligence plane killed.
- **Browser E2E** (advisory `uie2e`) for the copy contract + FULL-vs-TLS visual invariants.
- **SLO/budgets:** PAC fetch p99 ≤ 5 ms (cache hit), 304 ≤ 2 ms, serving availability ≥ 99.99 %, serve-hook ≤ 1 µs; ingestion p99 ≤ 1 s; rollup convergence ≤ 30 s; posture query p99 ≤ 200 ms; ≤ ~256 MB memory and ≤ ~1 GB storage per 100 k clients (hard-bounded); telemetry loss ≤ 1 % normal / 100 % tolerable under overload (counted + confidence-penalized).

---

## 13. Non-Negotiable Principles (compliance checklist)

- [x] Do not fake DIRECT visibility · [x] Estimates ≠ facts · [x] No unbounded Prometheus labels · [x] Analytics never in the PAC serving path · [x] No cloud dependency · [x] Not a SIEM · [x] Not an ITSM · [x] PAC failover ≠ NLB · [x] DIRECT ≠ TLS bypass · [x] No unnecessary exposure of sensitive domains/client data · [x] Not single-node-only · [x] Phase 1 not overengineered · [x] No implementation before this report is approved.

---

## 14. Red-Team Pass — Findings & Revisions Applied

The report was adversarially attacked by a second 9-agent fleet, each tasked to *disprove* it (not validate) and to verify every claim against the real code. **Result: 9/9 NEEDS REVISION, 0 FAILS.** The core thesis (DIRECT is structurally unobservable → the honest product is *governance*) survived, and every load-bearing **code anchor was verified true** (no false code claim was found — `store.go:1106`, the sync-`fireAlert`, `device_id` reserved, `≤100` sample, etc.). The corrections below are adopted; the highest-severity self-contradictions are already fixed inline above.

| Attack | Verdict | Landed finding | Resolution |
|---|---|---|---|
| A1 Client/telemetry | NEEDS REVISION | §1.3 understated the serve path (sync fire-alert); "denial ⇒ fail-open" is first-fetch-only (cached clients fail *static* = AC-1); "outdated" row cited an **outbound** header; ≥90 %-304 breaks for the `no-store` HostFallback default | §1.3 fixed inline; §2/§6.2 reworded (F-EV3); §4 caveat (F-SC4) |
| A2 Network/identity | NEEDS REVISION | "site/egress-IP" has **no egress→site map in code** (only country GeoIP); blast-radius sample is fleet-global not rule-scoped; "secondary-proxy usage" action has **no backing signal** (that's the *upstream* pool, not client PAC chains); AC-3 "authenticated identity" is inapplicable on the unauthenticated fetch | F-ID1, F-ID2, F-UX-action, F-SEC-AC3 |
| A3 Security | NEEDS REVISION | Missed ACs: **rogue DP node poisons the sketch rollup**, **PAC-body MITM/WPAD injection** (no integrity AC), **insider governance-gaming** (no maker-checker); AC-1 partly unimplementable (pinned/offline clients are dark); AC-10 leans on a non-existent tenant primitive | F-SEC1..4 |
| A4 Evidence | NEEDS REVISION | Confidence "formula" is **decorative/non-reproducible**; "change introduced a bypass = blind-spots:none" is false (**reorder-promotion & pool-mutation**); the Exposure Score **is the cross-source sum §2 forbids**; E5 should be **Unknown for existing DIRECT rules**; **three** evidence-class vocabularies | F-EV1, F-EV2, F-UX-score, F-EV4, F-EV5 |
| A5 Scale | NEEDS REVISION | "~11 MB constant" & "533 KB/s" hide a **≤500-profile fidelity ceiling** (10 k profiles = ~160 MB / ~68 MB/s); "16 GB" mislabeled (7-day raw, not the ladder); `rule_evidence{rank}` counter is unsound; **cold-tail blindness** (sketches miss the rarely-fetched high-risk rule) | F-SC1..3, F-MET1, F-MET2 |
| A6 Privacy | NEEDS REVISION | **No small-cell suppression** → "aggregate ⇒ anonymous" fails in small branches; **eTLD+1 is not "safe"**; **GDPR Art-17 vs irreversible sketches**; §1.3 "no privacy docs" was **false**; base-appliance catalog egress vs air-gap | F-PR1..4; §1.3 fixed inline |
| A7 UX | NEEDS REVISION | Single "72/100" score = **caveat-laundering + hidden sum**; "transparent" oversells the weights; no home for the "we can't see DIRECT" **non-action**; naming **collides with shipped `static/index.html`**; "safely-removable" | Fixed inline (§7 de-scalarisation, "explainable", banner, §11 wording); F-UX-migrate |
| A8 SRE | NEEDS REVISION | `fireAlert` fix **incomplete** (un-latched `logger.Printf` + `pacProfileAlertOnce.mu` + `pacArtifactCache.mu` also on the serve path); wall test can't see mutex contention; **SLOs have no baseline and test the OFF path**; **additive sketches double-count under HA failover** (only HLL/Bloom are idempotent); byte-cap vs 7-day spill conflict | F-SRE1..4 |
| A9 Chief skeptic | NEEDS REVISION | No false code claim; **"safely-removable" violates the report's own frozen wording** (sharpest defect); P1 "adoption" oversold; **§4/§5/§6 sketch/scale machinery is not needed for the P0-P2(+P3-static) differentiated value** and should be demoted to P4-conditional | Fixed inline (§11); F-SCOPE; F-EV3 |

### Adopted corrections not yet inlined above (binding on the PR plan)

- **F-SCOPE (from A9, strongest scoping change):** demote the hyperscale sketch/scale program (§4/§5/§6 HLL/Count-Min/Bloom/reservoir + CP rollup) from Phases 1–3 to **P4-conditional**. The differentiated, honest value — P0 relabel+inventory, P2 governance CRUD (on existing `auditEvent`/`saveConfigVersion`), P3 static blast-radius (on existing `AnalyzeImpact`) — needs **none** of it. P1 collapses to bounded per-node counters + a single fleet HLL for a coarse *fetch-distribution* estimate; the full sketch stack ships only when P4's real traffic source justifies it.
- **F-EV1 (confidence rubric):** replace the pseudo-formula with an explicit, reproducible **rubric table** (evidence tier × freshness bucket → confidence label), enumerated per insight; two engineers must derive the same label.
- **F-EV2 (change-diff completeness):** `newDirectPaths` must also flag **precedence-reorder** that promotes an existing DIRECT rule above a PROXY rule, and **pool-content mutation** (members changing under a stable PoolID); until then the insight is "High **with** reorder/pool blind spots," not "blind-spots: none."
- **F-EV3 (label honesty):** P1's deliverable is **"fetch distribution,"** not "adoption"; "outdated" is inferred Low-confidence from fetch-absence, never from the outbound `X-Culvert-PAC-Version`.
- **F-EV4/F-EV5:** E5 blast-radius is **Unknown for existing DIRECT rules** (Medium only for *candidate* rules); collapse the three evidence-class vocabularies into **one** frozen 4-tier set.
- **F-ID1/F-ID2 (identity honesty):** the aggregate unit is **egress-IP/24**, not "site," unless the customer supplies a CIDR→site map (a new optional input); every blast-radius figure carries a **population-mismatch** caveat (proxied on-net sample ≠ off-net roaming DIRECT population), not only the survivorship caveat.
- **F-SEC1..4:** add abuse cases + mitigations for **rogue-DP sketch poisoning** (per-node attribution, bounded per-node contribution, divergence anomaly — note this compounds A8's double-count), **PAC-delivery integrity** (WPAD/MITM), and **insider governance-gaming** (maker-checker / second-approver for new DIRECT rules and for owner/justification attestation). Reword **AC-1** to name the truly-dark (pinned/offline) subset; drop **AC-3**'s reliance on authenticated identity (unauthenticated fetch) and **AC-10**'s non-existent tenant primitive.
- **F-PR1..4 (privacy):** add a **small-cell suppression floor** (min-count k before any count/Top-K/domain is shown); reclassify **eTLD+1 as potentially-sensitive** (consent + suppression gated); resolve **GDPR Art-17** by keeping personal data out of irreversible sketches unless a small-cell floor holds, and documenting that sketches contain no per-subject-erasable PII only under that floor; flag the **base-appliance catalog egress** (`CULVERT_RELEASE_CATALOG_URL=off`) in the air-gap note; align to `docs/support/REDACTION-MODEL.md`.
- **F-MET1 (rule evidence):** rule evidence uses **exact per-rule counters over the bounded rule set** (rules are config-bounded, unlike attacker-controlled hosts), not heavy-hitter sketches — the governance target *is* the cold tail; replace `rule_evidence_total{rank}` with a gauge / analytics-only series (the floating-rank counter breaks `rate()`).
- **F-SC1..4 (scale):** disclose the **≤500-profile fidelity ceiling** and its consequence (per-profile posture degrades exactly at Large); relabel the "16 GB" figure as **7-day opt-in-raw**, with sketch-only default in the hundreds of MB; reconcile the 1800 s re-fetch assumption with A1 (mark it illustrative; adoption is *less* observable if refetch is rarer).
- **F-SRE1..4:** broaden the P1-a fix to move **all** serve-path synchronous couplings off the hot path (fire-alert, the un-latched `logger.Printf`; audit `pacArtifactCache.mu`/`pacProfiles` read contention); the isolation guarantee is enforced by a **runtime latency-regression measuring ON overhead** (not only a call-graph wall, and not the OFF path) against an established serving **baseline**; make CP sketch rollup **failover-idempotent** (additive Count-Min/reservoir double-count when a DP reaches both leaders — use HLL/Bloom or per-node-attributed merges); name a **byte-cap** for the spill (the 7-day time-bound alone conflicts with ≤1 GB).
- **F-UX-migrate:** P0-a must include a **terminology migration** for the existing `static/index.html` (unqualified "bypass", the shared gray `.badge.bypass` token, the overloaded "posture") — the "terminology as testable invariant" cannot pass on day one otherwise.

**Net effect on the verdict:** unchanged — **GO WITH CONDITIONS**, now with a tighter and *smaller* first increment (P0 + P2 + P3-static; sketch/scale demoted to P4-conditional) and the above corrections folded into the §8/§9 scope. The red-team strengthened, not overturned, the recommendation.
