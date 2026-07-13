# R1 — Independent Qualification Review: Enterprise Supportability Architect

- **Reviewer role:** Principal Supportability / Enterprise-Support Architect (mature NGFW/SASE vendor perspective; independent, no proprietary knowledge — public enterprise-vendor practice only).
- **Date:** 2026-07-13
- **Scope reviewed:** `docs/support/*.md` (12 architecture/contract docs + 2 decision records), `docs/support/infra-ops/*.md` (6 docs), `docs/support/infra-ops/proof-slice/*` (7 docs + schema), and the executable staging proof `docs/support/infra-ops/qualification/staging-proof/` (harness + 7 evidence files). Proof re-run locally: `python3 tac_proof.py demo` (13/13 pass) and `failtest` (16/16 land in specified state).
- **Central question:** Would a mature enterprise network-security vendor reasonably choose this architecture for its support & infra-ops platform, given Culvert's small budget/team?

---

## 1. Verdict

**Conditional yes on the *design direction*, firm no on *current readiness for serious enterprise use*.**

The architecture is one a mature vendor would recognize and largely endorse. The strategic calls are correct: (a) the appliance is a thin, outbound-only, source-side-redacting *evidence producer* and never an analyzer (`ANALYSIS-MODEL-DECISION.md` — the hot-path-safety reasoning is exactly what a security-appliance vendor would insist on); (b) redaction is fail-closed at the source with a CI parity wall rather than a post-hoc scrub (`REDACTION-MODEL.md §2`, `data_surfaces_test.go`); (c) no interactive shell, ever — support without SSH via bundle + local probes (`SUPPORTABILITY-ARCHITECTURE.md P1`); (d) reuse of already-hardened primitives (`backup.go` tar/manifest, `internal/backupcrypt`, `internal/secret`, the maintenance agent) instead of greenfield. The gap analysis is genuinely evidence-first (file:line grounded) and refreshingly honest about its own 2.1/5 maturity.

But three facts dominate the readiness judgment. **First, the entire program is design-only** — every document is stamped "Proposed (design); no implementation," and the *only* executable artifact simulates the vendor **cloud** ops-control-plane (Tier 3), not the appliance support bundle that customers actually consume. The load-bearing control of the whole framework — fail-closed redaction proven by `TestNoSecretInBundle` on real `/data` — has never been implemented or run. **Second, cloud-first hard-couples all diagnostic *value* to a secure, multi-tenant TAC cloud that does not exist and has no costed/staffed build plan**, which is a serious mismatch for a small-budget/small-team org; the appliance-only fallback produces redacted bundles that, absent the cloud, nobody analyzes. **Third, the one thing that *is* executable — the infra-ops proof — demonstrates the control-loop *shape* convincingly but simulates its two hardest safety properties** (crash recovery via lease-TTL expiry, and concurrency) rather than exercising them, and stubs the cryptographic integrity that the safety story rests on.

Net: the *paper* is stronger than a conventional vendor tech-support-file platform (better redaction rigor, better cloud-boundary hygiene). The *delivered capability* is far weaker (a conventional vendor already ships a working bundle generator, a portal, and a staffed TAC; Culvert has documents and a cloud simulation). A mature vendor would adopt this blueprint for the appliance side and stage it — but would not represent it as enterprise-ready, and would challenge whether a small team should commit to operating a bespoke analysis cloud at all.

---

## 2. Maturity score

**2 / 5 (Emerging — excellent primitives and design, near-zero assembled/proven product).**

This matches the program's own self-assessment (`CURRENT-STATE-GAP-ANALYSIS.md §6`, 2.1/5). Design quality alone would earn a 4; delivered/validated capability is a 1. Rationale by axis:

| Axis | Score | Basis |
|---|---|---|
| Architecture & contracts quality | 4 | Coherent tier split, reuse discipline, enforceable invariants |
| Redaction/governance design | 4 | Source-side fail-closed + three parity walls; best-in-class *on paper* |
| Delivered appliance capability | 1 | No collector, no bundle, no route implemented |
| Proven safety (executed evidence) | 2 | Infra-ops loop runs; crash/concurrency/signing are simulated |
| Cloud (Tier 3) realism for this team | 1 | No build/cost/staffing plan for a secure multi-tenant cloud |
| Auditability | 3 | Hash-chained, post-session-reconstructable audit genuinely works in the proof |
| **Weighted overall** | **2** | Strong design (~4), near-absent proven product (~1.3) |

---

## 3. What is unusually strong

1. **Evidence-first gap analysis with a reuse/DO-NOT-reuse matrix.** `CURRENT-STATE-GAP-ANALYSIS.md §3–7` cites file:line for every asset and, critically, *refuses* to reuse the obvious-but-wrong thing: it flags that a raw `backup.go` bundle is a full secret export (bcrypt hashes, TOTP secrets, CA private keys) and must never be handed to TAC (§4.1). Recognizing that is exactly the judgment that separates a support architect from a feature engineer.
2. **Source-side, fail-closed redaction with a CI parity wall.** Unclassified fields default to `SENSITIVE`, `SECRET`/`NEVER_EXPORT` are *dropped* (never masked-and-kept), and a reflection-based `data_surfaces_test.go` fails the build if a new collected field lacks a `DataClass` (`REDACTION-MODEL.md §2, §9`). This is materially stronger than the post-hoc scrub most conventional tech-support-file generators use.
3. **Cloud-boundary hygiene.** Outbound-only, no inbound TAC listener, E2E-encrypt-to-TAC *before* the HTTPS POST, cloud-can-request-but-never-compel, structural cloud-independence of the proxy hot path (`TAC-CLOUD-ARCHITECTURE.md §1`, `SECURE-UPLOAD-ARCHITECTURE.md §3–5`). A compromised cloud cannot reach the appliance by construction — the correct posture for an egress-critical box.
4. **No-shell support model end to end.** Host facts come only through the existing maintenance-agent argv-template registry (`POST /v1/collect`, read-only, no `sh -c`), and remote interactive support is explicitly deferred (`SECURE-UPLOAD-ARCHITECTURE.md §7`). This is how modern appliance vendors avoid the "support engineer SSHes into a customer box" liability.
5. **The infra-ops proof is a real, honest, reproducible control-loop demonstration.** It executes an 18-state FSM, produces a hash-chained audit reconstructable in a fresh process after the session ends (`evidence/audit_sample.json`, `console_operation_view.txt`), rejects self-approval and stale/plan-mismatched approvals, and proves full operability with the AI absent via `tacctl`. The staging-proof README's "does NOT establish" list (§6) is candid about being synthetic/offline/$0.
6. **Debug escalation with a mandatory kill switch.** L0–L4 with a TTL + restart-surviving watchdog auto-revert and "no until-disabled state" (`HEALTH-AND-EVENT-MODEL.md §6`) matches the discipline real vendors enforce so a field-enabled debug mode can't silently burn the box.

---

## 4. Blocking findings

### R1-F1 — All diagnostic value is hard-coupled to a Tier-3 cloud that has no costed/staffed/build plan; the appliance-only fallback yields unanalyzed bundles
- **Severity:** Blocking
- **Affected component:** Tier-3 TAC Cloud (`TAC-CLOUD-ARCHITECTURE.md`), the cloud-first decision (`ANALYSIS-MODEL-DECISION.md`, ADR-0012), appliance-track fallback (`SUPPORTABILITY-ROADMAP.md` REVISION 2).
- **Realistic scenario:** Culvert ships the appliance track (M1–M4). A customer generates a redacted CSB and either uploads it or hands it over air-gapped. There is no cloud to ingest, extract, run deterministic analyzers, correlate, or match known issues — because the cloud is prose plus a Python simulation. The "value-add" (timeline construction, cluster correlation, known-issue/runbook match, AI diagnosis, TAC workflow) does not exist.
- **Business impact:** The program can deliver a bundle a customer cannot get *analysis* from. A small team is quietly signed up to build and 24/7-operate a secure multi-tenant analysis cloud (raw evidence plane with per-case KMS keys, ephemeral network-isolated sandboxes, entitlement/SLA/queue, dual-control break-glass, incident grouping, GitHub linkage). The decision matrix scored "operational cost" 4/5 for cloud-first on the premise "you do run a cloud" (`ANALYSIS-MODEL-DECISION.md §2 row 11`) — but no cloud is run and none is budgeted. This is the central architecture-choice risk for a small-budget org.
- **Technical impact:** The most expensive, highest-security-blast component is the least concretely specified relative to its difficulty. There is no cloud build plan in the roadmap (the roadmap re-homes analysis "to the TAC Cloud" without a milestone owning its construction), no cost model, no staffing model, no security review of the multi-tenant raw-evidence plane beyond a threat table.
- **Evidence:** `SUPPORTABILITY-ROADMAP.md` REVISION 2 ("timeline construction… re-homed to the TAC Cloud") lists no cloud-build milestone; `TAC-CLOUD-ARCHITECTURE.md §2, §5` enumerate heavy responsibilities with worker budgets but no delivery/cost/staffing plan; `ANALYSIS-MODEL-DECISION.md §2` row 11 assumes the cloud exists.
- **Required correction:** Produce a `TAC-CLOUD-DELIVERY-PLAN.md` with (a) a concrete build milestone set and dependency on managed services (so the team operates as little bespoke infra as possible), (b) a monthly cost model at 10/100/1000 appliances, (c) a staffing/on-call model for the raw-evidence plane and break-glass, and (d) an explicit committed **appliance-only MVP** that delivers standalone value (local health + explained CHRs + redacted bundle + `culvert support validate`) so the product is useful before the cloud exists. Alternatively, re-open the analysis-location decision with a *managed-analysis-as-a-thin-service* or *deferred-cloud* variant sized to the team.
- **Acceptance test:** A reviewed delivery plan exists with a costed cloud and a named appliance-only MVP; a customer walkthrough shows tangible support value (health-explain + validated bundle) with the cloud stubbed/absent.
- **Recommended milestone:** Before M1 code (gates the whole program direction); appliance-only MVP = M1.

### R1-F2 — Program is design-only; the load-bearing redaction wall is unimplemented and unrun, and no appliance bundle has ever been produced
- **Severity:** Blocking
- **Affected component:** `internal/redaction` and `internal/support` (do not exist), `TestNoSecretInBundle` (described, never run), the entire appliance collect/redact/bundle path.
- **Realistic scenario:** A stakeholder reads "18 threats × control × test," "three parity walls," and "TestNoSecretInBundle (golden, planted secrets)" and concludes the redaction is proven. It is not: none of these tests exist as code; the packages they test are unwritten. The one executable artifact (`tac_proof.py`) simulates the *cloud ops control plane*, not the support bundle.
- **Business impact:** The single control that makes a support bundle safe to leave a security appliance — fail-closed redaction proven on real `/data` — is entirely unvalidated. Shipping to an enterprise customer on the strength of the design would risk exactly the secret leak (`ca.bundle` key, `ui_users.json` hashes, session HMAC) the design correctly warns about.
- **Technical impact:** Redaction correctness is the acknowledged highest risk (`SUPPORTABILITY-ROADMAP.md` M1 Risks). The free-form scrubber's ReDoS/false-negative exposure (`REDACTION-MODEL.md §3.4`) has no mitigating code. There is no evidence any collector reads only safe accessors in practice.
- **Evidence:** Every `docs/support/*.md` header reads "Proposed (design); no implementation"; `CURRENT-STATE-GAP-ANALYSIS.md §5` lists redaction engine, collector framework, and bundle assembly as MISSING; the only runnable code is `staging-proof/tac_proof.py`, whose docstring states it is a stand-in for the cloud loop, not the appliance.
- **Required correction:** Implement the M1/M2 slice — `internal/redaction` (DataClass + `Redactor.Struct` + fail-closed default), the `data_surfaces_test.go` parity wall, and the two thinnest collectors (`product`, `diagnostics`) behind `POST /api/support/bundles` — and make `TestNoSecretInBundle` pass with planted secrets on a realistic `/data` fixture. Fuzz the free-form scrubber with live-secret seeding.
- **Acceptance test:** `go test ./internal/redaction ./internal/support -run 'NoSecretInBundle|UnclassifiedFieldIsMasked|RawStateFilesExcluded'` passes; a produced `csb/1` bundle over a fixture containing all §10 NEVER_EXPORT/SECRET material contains none of them (raw or masked); the parity wall fails CI when a classified field is removed.
- **Recommended milestone:** M1 (first code slice), extended in M2.

---

## 5. High-priority findings

### R1-F3 — The proof simulates its two hardest safety properties (lease-TTL crash recovery, concurrency) rather than exercising them
- **Severity:** High
- **Affected component:** `staging-proof/tac_proof.py` — `reconcile_after_crash`, `acquire_lease`, failtest cases 7/8/12/14.
- **Realistic scenario:** A reviewer treats the 16/16-green matrix as proof the recovery reconciler and concurrency serialization work. In reality, a "crash" is modeled as a Python `RuntimeError` caught in-process (`execute()` catches it, releases the lease, sets `FAILED`), then `reconcile_after_crash` is called *synchronously in the same process*. The genuinely dangerous path — the executor process dies uncaught, the op is stuck in `EXECUTING`, and a lease-TTL *expiry* is what triggers the reconciler — is never exercised: no clock advances, lease `expires_at` is never crossed, and the reconciler is invoked by the test harness directly, not by lease expiry. Case 12 "concurrent op" is fully sequential single-threaded code; the optimistic-CAS `version` column is never actually contended.
- **Business impact:** The claim "a lost session, model error, or executor crash never corrupts infrastructure" (`INFRA-OPS-ARCHITECTURE.md §1`) — the core reason the whole "Claude operates infra" model is deemed safe — is asserted but not demonstrated under the conditions that matter.
- **Technical impact:** Case 8 even transitions `FAILED → VALIDATING` via the reconciler, which contradicts the documented FSM (`APPROVAL-STATE-AUDIT.md §3` shows `FAILED → ROLLING_BACK`); the harness papers over the "stuck EXECUTING past lease TTL" state it claims to handle.
- **Evidence:** `tac_proof.py:268–284` (in-process catch → FAILED), `:335–344` (reconciler called directly, no time check), `:220–227` (`acquire_lease` reads a row; no concurrency), failtest case 12 `:566–573` (sequential).
- **Required correction:** Add a test that (a) advances an injected clock past the lease TTL to trigger the reconciler *by expiry* with the op left in `EXECUTING`, and (b) runs two real concurrent executors/threads against one worker and asserts exactly one apply via the UNIQUE idempotency key + CAS. Reconcile the case-8 transition with the documented FSM.
- **Acceptance test:** A concurrency test spawns ≥2 parallel appliers on one `resource_key` and asserts a single `execution_results` row; a crash test leaves `state='EXECUTING'`, advances the clock, and shows the sweeper (not a direct call) driving resolution.
- **Recommended milestone:** Infra-ops G0/G3 (spine + first apply), before any live-model exposure.

### R1-F4 — Plan/approval integrity is HMAC with an in-file key and a caller-supplied `is_author` flag; the "cannot forge / no self-approval" properties are simulated, not demonstrated
- **Severity:** High
- **Affected component:** `tac_proof.py` — `SIGN_KEY`, `sign()`, `approve()`, `verify_approval()`, `verify_audit_chain()`.
- **Realistic scenario:** The design's safety rests on "Claude cannot forge a plan or an approval (it holds no signing key)" (`INFRA-OPS-ARCHITECTURE.md §6`) and "approver ≠ author, policy-enforced." In the proof, the signing key is a constant in the same file (`SIGN_KEY = b"local-demo-signing-key-…"`), so "signed" adds nothing over the hash chain — anyone with file access forges freely. Self-approval rejection is a boolean the *caller* passes (`approve(..., is_author=True)`); no identity is authenticated or bound. Author↔approver identity binding — the actual crux — is entirely stubbed.
- **Business impact:** The two properties an auditor cares about most (tamper-evident approvals, four-eyes enforcement) are demonstrated only in a form that would not survive security review. A real deployment substituting Ed25519/KMS + authenticated identity is a materially different (and harder) system than what the proof exercises.
- **Technical impact:** Deferring real signing to "Stage 4" (staging-proof README §6) means the highest-consequence trust boundary is the least proven. Approval single-use is enforced by a DB flag but replay/forgery of the signature itself is untested.
- **Evidence:** `tac_proof.py:29` (in-file key), `:38` (HMAC as "sign"), `:232–241` (`is_author` caller flag), `:355–363` (chain verify uses the same in-file key); staging-proof README §6 defers Ed25519/KMS + real OIDC.
- **Required correction:** In the next slice, bind approvals to a plan signature produced by a key the executor reads from a KMS/HSM the *planner cannot access*, and derive `is_author` from the authenticated approver identity vs the plan's `created_by` — never a parameter. Add `TestApproverIdentityBound` and a negative test that a forged signature is rejected.
- **Acceptance test:** An approval carrying a signature not produced by the executor's key is rejected; an approval whose authenticated identity equals the plan author is rejected without the caller asserting authorship.
- **Recommended milestone:** Infra-ops G0 (signing/identity spine).

### R1-F5 — CP/DP + HA troubleshooting gaps are correctly identified but unbuilt, and cross-node correlation is re-homed to the nonexistent cloud
- **Severity:** High
- **Affected component:** `controlplane.go` `MetricsReport`, `enrollment.go` `EnrolledNode.Version`, `/api/cluster/ha`; `HEALTH-AND-EVENT-MODEL.md §8`.
- **Realistic scenario:** A customer hits an HA inconsistency (suspected split-brain / config drift / version skew). Today the CP has zero per-DP applied-version visibility, a bare `culvert_ha_failovers_total` counter, a 500-entry audit ring, and a 60-minute metric ring (`CURRENT-STATE-GAP-ANALYSIS.md §5 items 17–20`). The design's three fixes (per-DP applied version in `MetricsReport`, populate `EnrolledNode.Version`, failover/self-fence ring) are the right instrumentation — but they are deferred to M5 and the *correlation* (split-brain/drift/version-skew discriminators) is moved to a cloud that does not exist.
- **Business impact:** The distributed-troubleshooting scenario a TAC most needs to answer ("is it just this node or the cluster?") remains unanswerable in-product, and the answer now also requires a cloud round-trip. For air-gapped/cloud-absent customers it is unanswerable at all.
- **Technical impact:** These are additive, backward-compatible wire fields (old binaries ignore unknown keys) that could ship independently and locally with high value; re-homing their *interpretation* to the cloud strands the instrumentation's payoff.
- **Evidence:** `CURRENT-STATE-GAP-ANALYSIS.md §5 (17–20)`; `HEALTH-AND-EVENT-MODEL.md` REVISION 2 banner ("split-brain/drift/version-skew CORRELATION are computed IN THE CLOUD"); `SUPPORTABILITY-ROADMAP.md` M5.
- **Required correction:** Ship the three instrumentation additions AND a *local* `diagnose cluster` discriminator (the five canonical questions in `HEALTH-AND-EVENT-MODEL.md §8.3` are simple, bounded, and need no cloud) so cluster fault-isolation works on-box; treat cloud correlation as enrichment, not the only path.
- **Acceptance test:** On a 1-CP/2-DP compose cluster with one DP pinned to a stale snapshot, `diagnose cluster` labels the finding `local` vs `cluster` correctly with no cloud reachable.
- **Recommended milestone:** M5 (pull the local discriminator forward; do not gate it on the cloud).

### R1-F6 — The Tier-2 appliance→cloud channel (auth, entitlement, resumable upload, receipt) is entirely unproven
- **Severity:** High
- **Affected component:** `SECURE-UPLOAD-ARCHITECTURE.md §4` upload protocol; gateway ingest (`TAC-CLOUD-ARCHITECTURE.md §4`).
- **Realistic scenario:** The proof exercises only the cloud-*internal* ops loop (restart/deploy a worker). The channel a real customer uses — per-appliance credential/mTLS, `init/chunk/complete`, dedup by `bundle_id`+hash, SSRF-guarded origin, signed receipt, tenant scoping — has no executable evidence and no simulation.
- **Business impact:** The one interaction every supported customer performs (get a bundle to TAC) is the least validated. Resumability under a flaky link, replay rejection, and tenant isolation are asserted via unwritten tests.
- **Technical impact:** Entitlement evaluation, size/format gating "before accepting bytes," and receipt-hash matching are all gateway behaviors with no counterpart in the proof; the appliance-side queue/retry/offline-export state machine (`SECURE-UPLOAD-ARCHITECTURE.md §5`) is unbuilt.
- **Evidence:** `staging-proof/README.md §1` (components represented are all cloud-ops; no upload channel); `SECURE-UPLOAD-ARCHITECTURE.md §9` test surface is all unimplemented (`TestUploadResumable`, `TestUploadReceiptHashMatch`, etc.).
- **Required correction:** Add a thin upload proof (even synthetic) covering init/resume-from-offset/complete + receipt-hash match + tenant-scope reject + SSRF reject + queue-persists-restart, mirroring the infra-ops proof's rigor.
- **Acceptance test:** A dropped mid-upload resumes from `received_offset`; a `complete` with a mismatched hash is rejected; a bundle for tenant A cannot land in tenant B's case.
- **Recommended milestone:** M6 (bring a minimal channel proof forward alongside M4 encryption).

---

## 6. Medium-priority findings

### R1-F7 — Hot-path safety is the decision matrix's "decisive" dimension yet bundle-generation budgets are never load-tested against the live relay path
- **Severity:** Medium
- **Affected component:** `SECURE-UPLOAD-ARCHITECTURE.md §8` budgets (60s/120s, 256MB, single-flight).
- **Realistic scenario:** Cloud-first was chosen primarily because a co-resident analyzer threatens CONNECT/relay latency (`ANALYSIS-MODEL-DECISION.md §2 row 4, "Decisive"`). Yet even the *collection* path (concurrent collectors, tar/gzip, 256MB transient) has no measurement against the proxy under load; the ceilings are asserted, not proven non-perturbing.
- **Business impact:** A support-bundle request during peak egress could still perturb the exact hot path the architecture was built to protect, undermining the central rationale.
- **Technical impact:** No `TestBundleBudgetsEnforced`/latency-under-collection benchmark exists; the "decisive" claim is unquantified for the code that will actually run on-box.
- **Evidence:** `SECURE-UPLOAD-ARCHITECTURE.md §8`; `SUPPORTABILITY-TEST-STRATEGY` referenced but budgets untested; proof `metrics.json` are cloud-sim timings only.
- **Required correction:** Add a benchmark that generates a standard bundle while the proxy sustains representative CONNECT/relay load and asserts p99 latency delta below a stated bound.
- **Acceptance test:** Bundle generation under load keeps relay p99 within, e.g., +5% of baseline; hard-kill on wall-clock leaves the hot path untouched.
- **Recommended milestone:** M1 (ship with the first bundle).

### R1-F8 — IncidentScope catalog and the redaction registry are in-binary, so tuning them needs a signed appliance release — the same update-velocity penalty used to reject local analyzers
- **Severity:** Medium
- **Affected component:** `HEALTH-AND-EVENT-MODEL.md §5` (fixed in-binary scope registry), `REDACTION-MODEL.md §2` registries.
- **Realistic scenario:** A new failure class or a newly discovered secret-shape needs a new incident scope or data-class. Because both are compiled in, the fix ships only via the deliberately heavy release-catalog + maintenance-agent path — the very slowness the design cites against local analyzers (`ANALYSIS-MODEL-DECISION.md §2 rows 6–7`).
- **Business impact:** TAC cannot rapidly retarget collection for an emerging incident without a customer upgrade, blunting the incident-driven-diagnostics story.
- **Technical impact:** Customer-controlled exclusions can only *tighten* redaction (correct), but there is no safe mechanism to *add* a scope or a masking rule out-of-band.
- **Evidence:** `HEALTH-AND-EVENT-MODEL.md §5` ("fixed in-binary registry"); `REDACTION-MODEL.md §5` (exclusions additive/tighten-only).
- **Required correction:** Allow a signed, cloud-delivered *scope/redaction-rule pack* (data, not code) the appliance validates and loads read-only — reusing the release-catalog trust chain — so collection targeting can move at cloud speed while masking stays fail-closed.
- **Acceptance test:** A signed scope pack adds a new `IncidentScope` at runtime without a binary upgrade; an unsigned pack is rejected.
- **Recommended milestone:** M3/M7.

### R1-F9 — Panic-recovery middleware (gap 4.4) is still absent, so crash telemetry/timeline has nothing to collect
- **Severity:** Medium
- **Affected component:** request path (`proxy.go`/`proxy_tunnel.go`/`ui_middleware.go`/`socks5.go`); `T-CRASH` control.
- **Realistic scenario:** A panic in the request path today drops the connection with a stderr stack — no metric, structured event, or crash artifact (`CURRENT-STATE-GAP-ANALYSIS.md §4.4`). The crash timeline category and the `high_cpu`/crash incident scopes therefore have no source.
- **Business impact:** "What happened at the crash?" — a routine TAC question — is unanswerable; the design's crash-telemetry story depends on a control that isn't built.
- **Technical impact:** M1 lists panic-recovery middleware as a deliverable, but it is not yet present; `TestPanicRecoveryRedacted` is unwritten.
- **Evidence:** `CURRENT-STATE-GAP-ANALYSIS.md §4.4`; `SUPPORTABILITY-ROADMAP.md` M1 scope; `SUPPORTABILITY-THREAT-MODEL.md` T-CRASH.
- **Required correction:** Add top-level panic recovery emitting a bounded, redacted crash record + metric + timeline event, as scoped in M1.
- **Acceptance test:** An induced panic yields a redacted crash record (no raw bodies), a metric increment, and a `category:crash` timeline entry; the connection fails cleanly.
- **Recommended milestone:** M1.

### R1-F10 — No cross-version bundle-compat corpus can exist yet, so `csb/1` backward-compatibility and case reproducibility across upgrades are unvalidated
- **Severity:** Medium
- **Affected component:** `SUPPORT-BUNDLE-SPEC.md §4` versioning; `TestBundleBackwardCompat`.
- **Realistic scenario:** The versioning scheme (three axes, additive-only, reject unknown major) is sound on paper, but no frozen-bundle corpus exists because nothing generates bundles. A TAC re-opening a 12-month-old case cannot be shown to still parse that bundle under the current tool.
- **Business impact:** Case reproducibility across appliance versions — a core enterprise-support expectation — is asserted, not demonstrated.
- **Technical impact:** The golden-schema and cross-version gates (`SUPPORT-BUNDLE-SPEC.md §4.3–4.4`) have no fixtures.
- **Evidence:** `SUPPORT-BUNDLE-SPEC.md §4`; no `testdata` bundles exist (no generator).
- **Required correction:** As soon as M1 produces bundles, freeze a per-`collector_version` corpus and wire `TestBundleBackwardCompat`.
- **Acceptance test:** A frozen `csb/1` bundle from an earlier `collector_version` validates and parses under the current tool.
- **Recommended milestone:** M2/M4.

---

## 7. What is over-engineered

- **The "Claude operates the entire TAC cloud from chat" control plane, relative to what it currently proves.** A full deterministic spine — gateway + policy engine (OPA) + approval service (single/dual, four-eyes) + identity broker (OIDC/workload-id) + signed-plan executor + drift reconciler + 9 typed MCP tools + append-only signed audit — is being designed to safely **restart one stateless worker** in a `$0` staging pilot (`proof-slice/README.md §1`, `INFRA-OPS-ARCHITECTURE.md §7`). GitOps + signed plan/apply is the right *pattern*, but a bespoke conversational-ops gateway is heavy for the proven surface, and it is being built *before* the appliance support bundle the customer actually needs. Priority is inverted: the proof proves the ops spine, not the supportability product. Recommendation: keep the pattern, radically shrink the bespoke surface (lean on managed CI/CD + IaC + a thin approval gate) until the support-bundle product is delivered.
- **Five DataClass tiers × three parity registries × three named profiles (default/strict/paranoid) × per-bundle salt tokenization before a single collector ships.** The rigor is justified in principle, but this is a large governance surface for M1; a two-tier (drop-secret / mask-sensitive) start over the two thinnest collectors would prove the wall with less to carry.
- **18-state operation FSM + dual-approval classes + break-glass** are appropriate at scale but elaborate for the one reversible, data-free resource the slice actually exercises.

---

## 8. What is under-engineered

- **The Tier-3 cloud itself** (see R1-F1): the most expensive and highest-security-blast component has the least concrete delivery/cost/staffing plan. For a small team this is the inverse of where the engineering detail should concentrate.
- **Redaction correctness on real data** (R1-F2): the load-bearing control has no code and no run; the free-form scrubber's ReDoS/false-negative risk is acknowledged but unmitigated.
- **The appliance→cloud channel** (R1-F6): auth, entitlement, resumable upload, receipt, and the queue/retry/offline state machine are unproven.
- **Real crash telemetry** (R1-F9): still absent despite being M1 scope.
- **Local cluster fault-isolation** (R1-F5): the cheap, high-value, cloud-independent discriminator is deferred and then made cloud-dependent.

---

## 9. Exact proposed changes

1. **Write `TAC-CLOUD-DELIVERY-PLAN.md`** (addresses R1-F1): build milestones leaning on managed services; monthly cost at 10/100/1000 appliances; on-call/staffing for the raw-evidence plane + break-glass; and a **named appliance-only MVP** (local health-explain + redacted standard bundle + `culvert support validate`) that is useful with the cloud absent.
2. **Implement the M1/M2 redaction+bundle slice** (R1-F2): `internal/redaction` (DataClass + `Redactor.Struct` + fail-closed default), `data_surfaces_test.go` parity wall, `product`+`diagnostics` collectors, `POST /api/support/bundles`; make `TestNoSecretInBundle` pass on a realistic `/data` fixture; fuzz the scrubber with seeded live secrets.
3. **Harden the infra-ops proof** (R1-F3/F4): add a clock-advance lease-TTL crash test that leaves the op in `EXECUTING`; add a true parallel two-executor double-apply test; move signing to a KMS/HSM key the planner cannot read; derive `is_author` from authenticated identity, not a parameter; reconcile case-8's `FAILED→VALIDATING` with the documented FSM.
4. **Pull local cluster discriminators forward** (R1-F5): ship the three `MetricsReport`/`EnrolledNode.Version`/failover-ring additions plus an on-box `diagnose cluster` implementing the five §8.3 questions, cloud-independent.
5. **Add a minimal Tier-2 channel proof** (R1-F6): init/resume/complete + receipt-hash match + tenant-scope reject + SSRF reject + queue-persists-restart.
6. **Add a hot-path-under-collection benchmark** (R1-F7) with a stated p99 bound.
7. **Support a signed scope/redaction-rule pack** (R1-F8) via the release-catalog trust chain (data, not code).
8. **Implement panic-recovery middleware** (R1-F9) emitting a redacted crash record + metric + timeline event.
9. **Freeze a cross-version bundle corpus** (R1-F10) once M1 generates bundles.

---

## 10. Measurable acceptance criteria

| # | Criterion | Threshold / proof |
|---|---|---|
| A1 | Redaction wall proven | `TestNoSecretInBundle` green over a fixture containing every §10 NEVER_EXPORT/SECRET item; 0 hits (raw or masked) in any produced bundle |
| A2 | Parity wall enforces | Removing a `DataClass` from a collected struct fails CI with the field named |
| A3 | Appliance-only value | With the cloud unreachable, a demo shows explained CHRs + a validated, downloadable bundle; `TestHealthWithoutCloud`/`TestOperationWithoutCloud` green |
| A4 | Crash recovery real | Op left `EXECUTING`; injected clock crosses lease TTL; sweeper (not a direct call) resolves to a clean terminal state |
| A5 | Concurrency real | ≥2 parallel appliers on one worker ⇒ exactly one `execution_results` apply row |
| A6 | Approval integrity | Forged-signature approval rejected; identity-derived author==approver rejected without a caller flag |
| A7 | Cloud delivery realism | Reviewed cost model + staffing plan + named appliance-only MVP exist |
| A8 | Upload channel | Dropped upload resumes from offset; hash-mismatch `complete` rejected; cross-tenant landing rejected |
| A9 | Hot-path safety | Relay p99 during bundle generation within a stated bound (e.g. +5%) of baseline |
| A10 | Local cluster isolation | On 1-CP/2-DP with one stale DP, `diagnose cluster` labels local vs cluster correctly, cloud absent |
| A11 | Crash telemetry | Induced panic ⇒ redacted crash record + metric + `category:crash` timeline event |
| A12 | Version compat | A frozen earlier-`collector_version` bundle validates under the current tool |

---

## 11. Go / No-go recommendation

**GO to continue and implement — as a staged program — with an explicit NO-GO on representing it as enterprise-ready or on committing to build a bespoke analysis cloud before A1, A3, and A7 are met.**

- **Design direction: GO.** A mature vendor would keep the appliance-side blueprint almost wholesale: thin outbound-only evidence producer, source-side fail-closed redaction with a CI parity wall, no-shell host collection via the existing agent, bounded debug with auto-revert, hash-chained reconstructable audit, and E2E-encrypt-to-TAC. These are the right calls and are, on paper, stronger than a conventional tech-support-file platform.
- **What a mature vendor would REJECT / re-scope:** committing a small team to build and 24/7-operate a bespoke secure multi-tenant analysis cloud with no cost/staffing plan (R1-F1), and building the heavy conversational-ops control plane before the support bundle exists (over-engineering, §7). Re-scope the cloud to managed services + a committed appliance-only MVP.
- **What is MISSING before serious enterprise use:** an implemented+proven redaction wall on real `/data` (R1-F2), a real (not simulated) demonstration of crash recovery, concurrency, and signing integrity (R1-F3/F4), local cluster fault-isolation (R1-F5), the appliance→cloud channel (R1-F6), panic/crash telemetry (R1-F9), and a costed cloud delivery plan (R1-F1).
- **Gating conditions to reach "enterprise pilot":** A1 (redaction proven), A3 (appliance-only value with cloud absent), A4–A6 (real safety proofs), and A7 (cloud delivery realism) all green. Until then the correct posture is: proceed with M1/M2 implementation and the hardened proof; do not sell or represent enterprise readiness; do not begin bespoke-cloud construction.

**Stronger or weaker than a conventional support-bundle platform?** As a *design*, stronger (redaction and cloud-boundary rigor exceed the norm). As a *delivered capability today*, materially weaker (a conventional vendor already ships a working bundle generator, portal, and staffed TAC; this is documents plus a cloud simulation). The gap is execution and cloud-operability, not architectural soundness.
