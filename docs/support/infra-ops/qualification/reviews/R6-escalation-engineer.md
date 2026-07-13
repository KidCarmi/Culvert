# R6 — Senior Escalation Engineer Qualification Review

- **Reviewer role:** Independent Senior Escalation Engineer (public benchmarks only)
- **Date:** 2026-07-13
- **Question under test:** Does the system give engineering enough evidence to DISTINGUISH product bug vs configuration problem vs customer-environment problem vs capacity problem vs version regression vs cluster-convergence problem?
- **Inputs reviewed:** `HEALTH-AND-EVENT-MODEL.md`, `SUPPORT-BUNDLE-SPEC.md`, `COLLECTOR-CONTRACT.md`, `TAC-CLOUD-ARCHITECTURE.md`, `CURRENT-STATE-GAP-ANALYSIS.md`, `evidence/audit_sample.json`.

---

## 1. Verdict

**Conditional NO-GO for escalation-grade fault-class discrimination.** The design is intellectually strong and, on paper, names every fault class the escalation objective requires (`CauseClass` enum + `Locality` + the §8 cluster discriminators map cleanly onto the six distinctions). But the review question is about *evidence sufficiency*, and the evidence chain has three hard breaks:

1. The **GitHub engineering-escalation package is entirely unspecified** — the docs delegate "GitHub issue linkage" to the cloud (TAC-CLOUD §2/§4.9) but define no schema, no evidence-reference contract, no reproduction payload, and no engineering-tier redaction boundary. The prompt explicitly asks me to review this artifact and it does not exist.
2. The distinctions that are *hardest* and most valuable — **cluster-convergence, capacity, version-regression, and product-bug (crash)** — all depend on instrumentation the gap analysis itself marks as **not built** (§5 items 4.4, 13, 16, 17, 18, 19). The discriminator *logic* is designed against raw facts the product does not emit.
3. The only concrete evidence artifact supplied (`audit_sample.json`) is the **cloud's internal deploy audit**, not a customer diagnostic bundle. There is **no sample CSB, health.json, timeline.jsonl, or escalation issue** to qualify against, so the schemas' ability to *actually* separate fault classes is unproven.

The two distinctions the design can support **today** with real reused primitives are **configuration problem** and (weakly) **version regression via upgrade-timeline correlation**. The other four are design-complete but evidence-empty.

## 2. Maturity: 2 / 5 (Emerging)

Consistent with the docs' own 2.1/5 self-assessment. Design altitude and reuse discipline are 4/5; the *assembled, evidence-producing escalation path* is 1–2/5. The fault-class taxonomy exists; the facts that populate it largely do not, and the engineering-facing terminus (GitHub package) is absent.

## 3. Unusually strong

- **`CauseClass` enum is a direct answer to the objective.** `config|capacity|dependency|software|environment|certificate|network|storage|policy` (HEALTH §1) is a deliberate one-to-one with the escalation objective's fault classes, and "every CHR must set it." This is better than most shipping vendors, who infer cause class post-hoc.
- **`Locality` + §8.3 discriminators** are a textbook local-vs-cluster isolation model — "Is it just me?" (this DP's applied version vs CP published) is exactly the right first question, and the design labels each finding rather than averaging into one light (§2, "no single cluster green light").
- **Evidence-as-references, not dumps.** CHR `Evidence []string` is "stable references (metric names, log markers, check codes) — NOT raw values" (HEALTH §1); cloud `Finding` records carry "pointers into the bundle, not raw dumps" (TAC-CLOUD §4.5). This keeps escalation payloads reviewable and redaction-safe.
- **The cloud operation audit model (`audit_sample.json`) is genuinely mature** — full state machine (`CREATED→…→SUCCEEDED`), bound plan signature, dual-actor approval (`claude:planner` plan, `human:bob` approve), scoped-credential minting with "no value logged," and nine validation gates (V1_health…V9_rollback_restorable) including an explicit rollback-restorability gate. This is exactly the auditability engineering wants — it is just pointed at the wrong subject (see F7).

## 4. Blocking findings

### R6-F1 — No GitHub engineering-escalation package specification
- **Severity:** Critical (blocking)
- **Affected component:** TAC Cloud escalation workflow / cross-tier evidence contract
- **Realistic scenario:** TAC confirms a reproducible TLS-inspection failure is a product defect and escalates to engineering. An engineer opens the linked GitHub issue and finds a free-text summary with no version matrix, no evidence pointers, no reproduction, and no guarantee customer identity/secrets were stripped for the (differently-trusted) GitHub surface.
- **Business impact:** Escalations bounce back to TAC for missing data; MTTR inflates; risk of leaking customer-identifying data into a vendor-internal (or public-fork) issue tracker.
- **Technical impact:** Engineering cannot distinguish fault classes from the escalation artifact because the artifact's contents are undefined; the fault-class taxonomy never reaches the engineer who acts on it.
- **Evidence:** TAC-CLOUD §2 and §4.9 list "engineering escalation · GitHub issue linkage" as cloud responsibilities with zero schema; no doc defines issue fields, evidence-reference format, reproduction payload, version/environment matrix, or a GitHub-tier redaction profile (distinct from the raw-plane and shareable-bundle profiles).
- **Required correction:** Specify a `GitHubEscalationPackage` schema: bound `case_id`+`bundle_id`(s), `CauseClass`/`Locality`/`Confidence` from the driving CHR(s), product/build/go versions + fleet version-skew table, config-version diff reference, top timeline events, reproduction block (F3), and an explicit engineering-tier redaction profile with a fail-closed assertion. Add a CI parity test mirroring `config_surfaces_test.go`.
- **Acceptance test:** `TestGitHubEscalationPackage_Schema` pins the golden schema; `TestGitHubEscalationPackage_RedactsAtSource` plants secrets/identities of every class and asserts zero reach the rendered issue body.
- **Recommended milestone:** Pre-GA / cloud escalation MVP (blocks first paid engineering escalation).

### R6-F2 — Cluster-convergence discriminators depend on unbuilt raw facts
- **Severity:** Critical (blocking for the cluster distinction)
- **Affected component:** CP/DP MetricsReport, EnrolledNode, HA event ring (HEALTH §8.1)
- **Realistic scenario:** A customer reports "policy changes aren't taking effect on some nodes." Engineering needs to know: one DP behind (local) or all DPs behind (cluster convergence) or version skew. The bundle cannot answer — CP has no per-DP applied version.
- **Business impact:** The single most valuable distributed-system distinction (local vs cluster-wide) is unanswerable; escalations for a distributed appliance stall on the exact question the product is meant to isolate.
- **Technical impact:** §8.3's five discriminators are pure functions over `applied_snapshot_version`, `EnrolledNode.Version`, and a failover ring that **do not exist**: gap analysis §5 items 17 ("CP has zero visibility into per-DP applied config version"), 18 ("`EnrolledNode.Version`… never populated"), 19 ("no failover/self-fence history ring").
- **Evidence:** CURRENT-STATE §5 items 17–19; HEALTH §8.1 lists these three as "M5… independently shippable" — i.e. future work.
- **Required correction:** Ship §8.1.1–8.1.3 (per-DP `applied_snapshot_version`/`applied_epoch`/`policy_version`/`ca_fingerprint`/`culvert_version` in MetricsReport; populate `EnrolledNode.Version`; failover ring) before claiming cluster-convergence discrimination.
- **Acceptance test:** `TestClusterDiscriminator_JustMeVsCluster` — seed a 1-CP/3-DP fixture with one lagging DP and separately all-lagging; assert `config_lag` locality resolves `local` vs `cluster` respectively.
- **Recommended milestone:** M5 (cluster instrumentation) — gate the cluster-convergence claim on it.

### R6-F3 — No reproduction / failing-transaction capture
- **Severity:** Critical (blocking for product-bug distinction)
- **Affected component:** Incident scopes, request-log collector (SUPPORT-BUNDLE §7)
- **Realistic scenario:** Engineering receives a "product bug" escalation but has no failing request/response exemplar, no headers, no minimal repro — only aggregate stats and redacted logs with query strings stripped.
- **Business impact:** Engineering cannot reproduce, so cannot confirm product bug vs config vs environment; the escalation degenerates into a back-and-forth for "can you get us a repro."
- **Technical impact:** No doc captures the triggering transaction. `logs/requests.jsonl` "excludes query strings" and masks identity (SUPPORT-BUNDLE §7), removing the exact discriminator; there is no captured-exemplar or repro-harness section.
- **Evidence:** SUPPORT-BUNDLE §7 (requests section privacy posture); no `reproduction` section in the §1 tar layout or §7 catalog; no incident scope in HEALTH §5 collects a failing exemplar.
- **Required correction:** Add an opt-in, consent-gated `reproduction/` section capturing a bounded, redacted failing-transaction exemplar (method, host, sanitized headers, TLS handshake outcome, policy decision, upstream result) tied to the incident `correlation_id`, plus a deterministic "steps observed" block.
- **Acceptance test:** `TestReproductionSection_CapturesFailingExemplar` — inject a synthetic TLS-inspect failure and assert the section contains the decisive fields with secrets redacted.
- **Recommended milestone:** M-incident-scopes (must ship with the product-bug scope).

### R6-F4 — No crash/panic telemetry to collect
- **Severity:** High (blocking for the crash sub-class of product bug)
- **Affected component:** request/relay/UI/socks paths; timeline `crash` category; `runtime/*` sections
- **Realistic scenario:** A panic drops a customer connection. The escalation asks "did it crash and why?" The bundle's `crash` timeline category and `runtime/goroutine.txt` have nothing, because no recovery ever fired.
- **Business impact:** Software-defect crashes are invisible in evidence; engineering cannot distinguish a crash-induced outage from an environment reset.
- **Technical impact:** Gap §4.4: "No top-level panic recovery in the request path… A panic drops the connection with a stderr stack — no metric, structured log, event, or crash artifact." HEALTH §4/§6 reference a "new top-level panic recovery (crash — see §6/T-CRASH)" that is unbuilt.
- **Evidence:** CURRENT-STATE §4.4; §5 item 13 ("no crash/panic telemetry").
- **Required correction:** Add recovery middleware emitting a structured crash event + timeline `crash` entry + bounded stack artifact; wire it as the timeline's crash tap.
- **Acceptance test:** `TestPanicRecovery_EmitsCrashEvent` — induce a handler panic; assert one crash timeline event + metric increment + no process exit.
- **Recommended milestone:** M-runtime-introspection.

## 5. High-priority

### R6-F5 — Capacity fault class under-instrumented
- **Severity:** High
- **Affected component:** Metrics-for-diagnostics (HEALTH §7 M1 gauges)
- **Realistic scenario:** "Browsing is slow." Engineering must separate capacity saturation from a software slow path. The bundle carries only the 60-minute request-rate ring and latency histogram — no worker-pool/scan-engine/queue-depth saturation.
- **Business impact:** Capacity vs software distinction relies on the customer over-provisioning by trial and error; wrong root-cause attribution.
- **Technical impact:** The saturation/queue-depth gauges that make `CauseClass=capacity` diagnosable are "New… (M1)" (HEALTH §7) and gap §5 item 16 ("No historical metrics… 60-minute ring is the only in-process series").
- **Evidence:** HEALTH §7 M1 bullet; CURRENT-STATE §5 item 16.
- **Required correction:** Ship the M1 scalar gauges (worker saturation, scan in-flight, SSE count, logstore queue depth, relay goroutine count) and include them in `metrics/window.json`.
- **Acceptance test:** `TestSaturationGauges_InWindowMetrics` asserts each gauge present and bounded in the window section under load.
- **Recommended milestone:** M1.

### R6-F6 — Version-regression distinction has no known-good baseline
- **Severity:** High
- **Affected component:** `product.json`, timeline `upgrade`, cluster version skew
- **Realistic scenario:** A symptom appears fleet-wide right after an upgrade. The bundle shows the current version and an upgrade event but offers no last-known-good version, no per-version behavioral delta, and (per F2) no fleet version-skew table.
- **Business impact:** "Version regression vs new-config interaction" is decided by cloud known-issue matching alone; if the KB lacks the issue, engineering has only a correlation, not a comparison.
- **Technical impact:** Distinction rests on timeline-upgrade correlation + `product.json` version only; `culvert_version` per DP (skew) is unbuilt (F2); no prior-version baseline captured.
- **Evidence:** SUPPORT-BUNDLE §7 `product.json`; HEALTH §4 upgrade category; §8.1.2 (unbuilt).
- **Required correction:** Record `previous_version`/`last_upgrade_at`/`upgrade_from→to` in `product.json` (sourced from the release-dispatch/rollback history already implied by `update_failure` scope) so a regression window is explicit; include fleet version spread once F2 lands.
- **Acceptance test:** `TestProductSection_RecordsUpgradeDelta` asserts from/to/at present after a simulated upgrade.
- **Recommended milestone:** M-bundle-MVP.

### R6-F7 — Supplied proof artifact does not exercise the customer evidence path
- **Severity:** High
- **Affected component:** Qualification evidence set
- **Realistic scenario:** A qualifier is asked "prove the bundle distinguishes fault classes" and is handed `audit_sample.json` — a TAC *deploy* operation audit, proving only that the cloud can audit its own worker deploys.
- **Business impact:** The qualification cannot be evidence-based; the strongest artifact demonstrates a capability adjacent to, not on, the escalation-evidence chain — investment asymmetry that could mask the real gaps (F1–F4).
- **Technical impact:** No sample `manifest.json`, `health.json` (CHR set), `events/timeline.jsonl`, `cluster/correlation.json`, or GitHub package exists to verify the schemas actually separate the six classes; every doc is "Proposed (design)."
- **Evidence:** `evidence/audit_sample.json` (operation `kind:"deploy"`, worker `tac-analysis-worker-1`, gates V1–V9) — internal ops, not a CSB; SUPPORT-BUNDLE/HEALTH all "Proposed (design)."
- **Required correction:** Produce golden sample artifacts for at least three fault classes (config, cluster-convergence, capacity) run through the real (even stubbed) collectors, plus a rendered sample GitHub package.
- **Acceptance test:** `TestGoldenBundle_FaultClassSeparation` — three fixtures, assert each yields the expected `CauseClass`/`Locality` in `health.json`.
- **Recommended milestone:** M-bundle-MVP (qualification gate).

### R6-F8 — Customer-environment class relies on weak/absent signals
- **Severity:** High
- **Affected component:** clock-skew CHR, host facts collector, partition CHR
- **Realistic scenario:** An intermittent failure is actually a host clock-skew or upstream-DNS/proxy environment issue. `clock_skew` needs a heartbeat timestamp field that does not exist; host facts require the L2/admin-gated agent that may be absent.
- **Business impact:** Environment problems get misfiled as product bugs when the agent is unavailable or clock-skew is undetectable.
- **Technical impact:** HEALTH §8.2 `clock_skew` depends on a "new field" in heartbeat replies; gap §5 item 20 ("No clock-skew detection between nodes"); host facts are `RequiresHost`/L2 and degrade to `unavailable` when the agent is nil (COLLECTOR §7).
- **Evidence:** HEALTH §8.2; CURRENT-STATE §5 item 20; COLLECTOR §7.
- **Required correction:** Add heartbeat timestamp exchange for clock-skew; define an agent-absent environment fallback (bundle records `host: unavailable` prominently and downgrades environment-class confidence rather than silently omitting).
- **Acceptance test:** `TestClockSkew_DetectedFromHeartbeat` and `TestHostUnavailable_LowersEnvironmentConfidence`.
- **Recommended milestone:** M5 (skew) / M-bundle-MVP (fallback).

## 6. Medium-priority

### R6-F9 — "Since when" does not survive restart
- **Severity:** Medium
- **Affected component:** health-transition tracker (`FailingSince`/`LastSuccess`)
- **Realistic scenario:** A node restarts during an intermittent incident; the CHR's `FailingSince` resets, so the escalation loses the degradation-onset anchor for correlation.
- **Business impact:** Weakens timeline anchoring for flapping faults, the ones most often escalated.
- **Technical impact:** HEALTH §1 states the tracker is "persisted lightly so 'since when' survives a scrape but not necessarily a restart (documented limitation)."
- **Evidence:** HEALTH §1 (`FailingSince`/`LastSuccess` note).
- **Required correction:** Persist transition records durably (reuse audit/JSONL discipline) so onset survives restart, or cross-reference the timeline's durable history at bundle build.
- **Acceptance test:** `TestHealthTransition_SurvivesRestart`.
- **Recommended milestone:** M-health-model.

### R6-F10 — Redaction may erase the load-bearing discriminator with no engineering-tier path
- **Severity:** Medium
- **Affected component:** redaction profile vs engineering needs
- **Realistic scenario:** The exact discriminator between config and environment is a specific host or identity that redaction masks; engineering has no higher-trust evidence tier to request it.
- **Business impact:** Over-redaction forces slow, manual break-glass on the cloud raw plane for routine escalations.
- **Technical impact:** Requests section strips query strings and masks identity (SUPPORT-BUNDLE §7); the only deeper path is dual-control break-glass on the raw plane (TAC-CLOUD §3/§6) — heavyweight for a routine field-level need.
- **Evidence:** SUPPORT-BUNDLE §7; TAC-CLOUD §3 (raw plane "no standing human access").
- **Required correction:** Define a consent-scoped "engineering evidence excerpt" tier (approved-for-reuse excerpts, TAC-CLOUD §6 already contemplates this for AI) usable for engineering escalation without full raw break-glass.
- **Acceptance test:** `TestEngineeringExcerpt_ConsentScoped`.
- **Recommended milestone:** M-cloud-escalation.

### R6-F11 — Timeline correlation ID plumbing does not exist today
- **Severity:** Medium
- **Affected component:** shared `correlation_id` across audit/reqlog/syslog/health
- **Realistic scenario:** A latency spike and the config change that caused it cannot be joined because no shared ID threads the subsystems.
- **Business impact:** "What changed before the incident" — the timeline's raison d'être — degrades to manual timestamp alignment.
- **Technical impact:** Gap §5 item 10: "no shared correlation ID across audit / reqlog / syslog / health." HEALTH §4 assumes reuse of `X-Request-ID`/config-version as keys, which is design, not wiring.
- **Evidence:** CURRENT-STATE §5 item 10; HEALTH §4 (correlation-ID reuse).
- **Required correction:** Thread one correlation ID from `connlimit.go`'s generator through audit/reqlog/health taps before claiming correlated timelines.
- **Acceptance test:** `TestCorrelationID_ThreadsSubsystems`.
- **Recommended milestone:** M-timeline.

## 7. Over-engineered

- **Cloud internal deploy auditing (`audit_sample.json`) vastly outpaces the customer evidence path.** Nine validation gates, bound plan signatures, dual-actor approval, and scoped-credential minting are shipped/exercised for how the cloud deploys *its own* analysis workers — while the customer-facing CSB, health.json, and escalation package are entirely "Proposed." The escalation objective is served by the latter, not the former. Rebalance: the rigor visible in `audit_sample.json` is exactly what the *escalation package* (F1) and *golden bundles* (F7) need and currently lack.
- **Debug levels L0–L4 with per-level TTL/watchdog/break-glass/sensitive-data acknowledgement (HEALTH §6)** are appropriately safe but heavy relative to the evidence they gate; for MVP escalation, L2 (goroutine dump + host facts) covers most product-bug/capacity needs. L4 "engineering restricted capture" is speculative until F3/F4 give it something to capture.

## 8. Under-engineered

- **The engineering terminus (GitHub package, F1)** — the artifact the reviewing role actually consumes — is the least-specified thing in the entire doc set.
- **Reproduction/failing-transaction capture (F3)** — absent; the single biggest driver of escalation round-trips.
- **Crash telemetry (F4)** — the product-bug crash sub-class has literally nothing to collect.
- **Cross-node raw facts (F2)** — the cluster-convergence distinction is all logic, no data.

## 9. Exact proposed changes

1. **Author `GITHUB-ESCALATION-PACKAGE.md`** defining `GitHubEscalationPackage` (F1): fields = `case_id`, `bundle_id[]`, driving `CauseClass`/`Locality`/`Confidence`, version+build+go, fleet version-skew table, config-version diff ref, top-N timeline events, reproduction block, engineering-tier redaction profile + fail-closed assertion. Add `github_escalation_test.go` schema+redaction parity.
2. **Add a `reproduction/` CSB section** (F3) and a `product_bug` incident scope that collects it; consent-gated, redacted, correlation-ID-bound.
3. **Ship panic-recovery middleware + crash timeline tap + bounded stack artifact** (F4).
4. **Ship §8.1.1–8.1.3** (per-DP applied version/epoch/policy/ca-fp/culvert_version; populate `EnrolledNode.Version`; failover ring) and wire §8.3 discriminators to them (F2).
5. **Ship M1 saturation/queue-depth gauges** into `metrics/window.json` (F5).
6. **Record upgrade delta** (`previous_version`/`upgrade_from→to`/`at`) in `product.json` (F6).
7. **Produce golden sample artifacts** for config, cluster-convergence, and capacity fault classes + a rendered escalation package (F7).
8. **Add heartbeat-timestamp clock-skew** + agent-absent environment fallback (F8).
9. **Thread a shared correlation ID** across audit/reqlog/health taps (F11); persist health transitions durably (F9); define a consent-scoped engineering excerpt tier (F10).

## 10. Measurable acceptance criteria

- **AC-1 (fault-class separation):** Given three seeded fixtures (config drift on one node; policy lag on all DPs; worker saturation), the generated `health.json` sets `CauseClass`∈{config, ?, capacity} and `Locality`∈{local, cluster, local} correctly with `Confidence≥medium`. 3/3 pass.
- **AC-2 (cluster discriminator):** `config_lag` resolves `local` when exactly one DP is behind and `cluster` when all are, from real `applied_snapshot_version` values. 2/2 pass.
- **AC-3 (product bug):** An induced panic produces exactly one `crash` timeline event, one metric increment, and a bounded stack artifact; no process exit.
- **AC-4 (reproduction):** The `product_bug` scope captures a failing exemplar containing the decisive fields with zero planted secrets/identities surviving (`RedactsAtSource`).
- **AC-5 (escalation package):** `GitHubEscalationPackage` renders with all required fields populated from a golden bundle and zero class-≥SENSITIVE values in the issue body.
- **AC-6 (version regression):** `product.json` carries `upgrade_from→to`+`at`; a fleet with mixed versions yields a non-empty skew table.
- **AC-7 (capacity):** All five M1 gauges present and bounded in `metrics/window.json` under synthetic load.
- **AC-8 (proof):** At least three golden CSBs + one rendered escalation package checked into the qualification evidence dir and validated by `culvert support validate`.

## 11. Go / No-Go

**NO-GO** for qualifying escalation-grade fault-class discrimination at this stage. The taxonomy is right and the reuse strategy is sound, but four of six distinctions (product-bug crash, capacity, version-regression, cluster-convergence) rest on unbuilt instrumentation, reproduction capture is absent, and the engineering-facing GitHub escalation package — the artifact this role consumes — is unspecified. **Reassess to GO when R6-F1, F2, F3, F4 are closed and AC-1, AC-2, AC-5, AC-8 pass** on golden evidence. Configuration-problem discrimination alone would pass today; that is not sufficient for a distributed appliance whose hardest escalations are cluster- and version-shaped.

---

## Appendix — Fault-class distinction → supporting evidence map

| Fault-class distinction | Evidence intended to support it | Built today? | Verdict |
|---|---|---|---|
| **Product bug** | crash artifact/panic recovery (T-CRASH), `runtime/goroutine.txt`+`heap.pprof`, failing-transaction exemplar, `diagnostics.json` | crash recovery **absent** (gap 4.4); runtime dumps = new endpoints; exemplar **not designed** (F3) | **FAILS today** |
| **Configuration problem** | `config.json`, `config-versions.json`+`diffConfigs`, timeline `config`/`policy` events with actor, config-version rollback validity in OperatorContract | Yes — reuses existing `apiConfigExport`/`configver` | **SUPPORTED** |
| **Customer-environment** | `host/*.json` (agent `/v1/collect`), `clock_skew` CHR, `partition` CHR, `diagnose dns/upstream` | host facts agent-gated (L2, may be nil); clock-skew needs new heartbeat field (gap 20) | **WEAK / PARTIAL** (F8) |
| **Capacity** | 60-min request ring, latency histogram, M1 saturation/queue-depth gauges, `slow_browsing`/`high_cpu` scopes | ring+histogram built; **M1 gauges unbuilt** (gap 16) | **PARTIAL** (F5) |
| **Version regression** | `product.json` version/build, timeline `upgrade` event, config-version diff, fleet `culvert_version` skew | version+upgrade correlation buildable; **no known-good baseline / no fleet skew** (gap 18) | **PARTIAL** (F6) |
| **Cluster-convergence** | §8.3 discriminators over `applied_snapshot_version`/`applied_epoch`/`EnrolledNode.Version`/failover ring, `cluster/correlation.json` | discriminator **logic designed**; underlying facts **all unbuilt** (gap 17/18/19) | **FAILS today** (F2) |
| **(terminus) Engineering escalation** | GitHub issue linkage carrying the above + reproduction + version matrix + engineering-tier redaction | **unspecified** (TAC-CLOUD names it; no schema) | **FAILS** (F1) |
