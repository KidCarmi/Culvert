# R4 — Independent Qualification Review: TAC Operations Manager

- **Reviewer role:** TAC Operations Manager at a security vendor (independent; not a PANW employee). Public benchmarks only.
- **Question under test:** Can a *small* TAC team run this platform in production **without the founder becoming the manual escalation point for every case?**
- **Sources read:** `TAC-CLOUD-ARCHITECTURE.md`, `HEALTH-AND-EVENT-MODEL.md`, `SECURE-UPLOAD-ARCHITECTURE.md`, `infra-ops/qualification/staging-proof/README.md`.
- **Date:** 2026-07-13.

---

## 1. Verdict

The **platform architecture** (three-tier isolation, raw/normalized plane split, consent + E2E encryption, and the operations control loop) is genuinely strong and, for the infra-ops mutation spine, honestly proven. But the **TAC operations-management layer that this review exists to judge** — case queues, assignment/routing, SLA mechanics, escalation criteria, incident grouping, engineering handoff, known-issue/runbook lifecycle, and management reporting — is present in the design **only as an enumerated list of "cloud responsibilities" (`TAC-CLOUD-ARCHITECTURE.md §2`) with no mechanics specified.**

The consequence is direct and answers the review's core question: because assignment, SLA breach handling, and escalation have **no automated routing logic**, every one of those decisions defaults to a human. In a small team that human is the founder. The design does not just *risk* a founder bottleneck — as specified, it **structurally guarantees one**, because there is no rule anywhere that routes a case to anyone else or flags it for anyone else without a person first looking at it. The reviewable staging proof does not cover this layer at all; it proves worker restart/deploy/rollback, not case flow.

**Not qualified for the "small team, no founder bottleneck" claim as it stands.** Fixable — the bones are good — but the fixes are the entire operations workflow layer, not polish.

## 2. Maturity score: **2 / 5**

- Platform/security architecture surface (tiers, isolation, crypto, consent): 4/5.
- Infra-ops control loop (mutation spine, plan-bound approval, rollback, hash-chained audit, AI-independence): 4/5 and honestly scoped.
- **TAC case-operations surface (the subject of this review):** **1.5/5** — responsibilities named, mechanics absent, zero reviewable evidence.
- Weighted to the review's mandate: **2/5.**

## 3. Unusually strong

- **Tier boundary is airtight and load-bearing (`TAC-CLOUD-ARCHITECTURE.md §1, §7`).** Outbound-only, cloud has no inbound path to the appliance, "cloud compromise reaching the appliance = impossible by construction." This is a real operational safety property, not a slogan — it means a cloud incident can never become a customer-fleet incident.
- **Raw ≠ normalized plane split with no standing human access to raw, short retention, dual-control break-glass (`§3, §6`).** This is above the maturity of most commissioned TAC clouds and materially de-risks the analyst workflow (analysts work findings, not raw customer evidence).
- **The operations control loop is properly built and honestly bounded (`staging-proof README §2, §6`).** Single mutation spine, deterministic policy gate, content-addressed signed plans, plan-bound approval with self-approval rejection, validation that does not trust provider-200, explicit reverse-deploy rollback → `MANUAL_INTERVENTION_REQUIRED`, hash-chained audit reconstructable after the session, and full AI-independent operation via `tacctl`. The honesty statement (SQLite-for-Postgres, HMAC-for-Ed25519, "$0, synthetic, no production credentials") is exactly what a qualification board should see.
- **AI is a draft-only actor with prompt-injection containment and no appliance action path (`§6`).** Correct posture: AI never auto-sends and cannot trigger an appliance action because no such path exists.

## 4. Blocking findings

### R4-F1 — No case assignment / routing engine; assignment defaults to a human, i.e. the founder
- **Severity:** Blocking.
- **Affected component:** Cloud TAC workflow — "cases and interactions", "SLA & queue management" (`TAC-CLOUD-ARCHITECTURE.md §2, §4 step 9, §8`).
- **Realistic scenario:** Monday morning, 22 bundles landed overnight from paid and community appliances. Nothing in the design decides *who owns each case*. A person must open the queue, read each case, and hand it to an analyst. With three analysts and a founder, that triage-and-hand-off is a person's whole morning — and it is the founder's, because the founder is the only one with the whole-fleet picture (see R4-F5).
- **Business impact:** First-response SLA burned before an analyst even sees the case; founder becomes a full-time dispatcher; throughput caps at "how fast one person can triage." Directly the bottleneck the review was commissioned to find.
- **Technical impact:** "Human TAC ownership" is an entitlement *flag* (`§8`), not an assignment *mechanism*. There is no round-robin, load-based, skill/tag-based, or entitlement-based auto-assignment; no "unassigned queue" SLA; no reassignment/hand-back rule; no capacity model.
- **Evidence:** `TAC-CLOUD-ARCHITECTURE.md §2` lists "cases and interactions" and "SLA & queue management" as owned responsibilities but `§4 step 9` reduces the entire TAC workflow to "approval, customer comms, escalation, GitHub linkage, SLA/queue" with no routing logic; `§8` differentiates ownership only as a ✅/❌ entitlement.
- **Required correction:** Specify an assignment engine: (a) auto-assign on case creation by a documented policy (entitlement → queue → least-loaded eligible analyst, with skill/product tags); (b) an explicit *unassigned* queue with its own age SLA and alert; (c) reassignment + hand-back rules; (d) a per-analyst concurrent-case cap. Assignment must require **no founder action** for the common path.
- **Acceptance test:** In a seeded 50-case simulation with 3 analysts and 1 founder, ≥95% of cases reach an owning analyst by automated policy within 5 minutes of creation, with **zero** founder actions; the founder appears in the assignment audit for <5% of cases (explicit exceptions only).
- **Recommended milestone:** Stage 2 (pre-pilot) — blocking for any pilot with paid SLA.

### R4-F2 — No escalation criteria or engineering-handoff trigger; hard cases informally escalate to the founder
- **Severity:** Blocking.
- **Affected component:** "engineering escalation", "GitHub issue linkage" (`TAC-CLOUD-ARCHITECTURE.md §2, §4 step 9, §8`).
- **Realistic scenario:** An analyst hits a case the known-issue matcher didn't resolve. Nothing defines *when* and *to whom* it escalates or what package engineering receives. In practice the analyst walks to the founder. Every non-templated case routes to the one person who "knows the code."
- **Business impact:** Founder is the de facto Tier-3/engineering queue of one; escalations are unbounded and untracked; engineering gets ad-hoc pings instead of a triaged handoff. This is the second structural founder-bottleneck.
- **Technical impact:** No severity/impact thresholds that *trigger* escalation, no defined handoff artifact (findings + timeline + repro + affected-fleet), no on-call/rotation target, no back-pressure or SLA on the engineering side, no linkage between GitHub issue state and case state.
- **Evidence:** `§2`/`§4 step 9` name "engineering escalation" and "GitHub issue linkage"; `§8` gates it to paid — but no criteria, artifact, or routing target is defined anywhere in the three architecture docs.
- **Required correction:** Define (a) explicit escalation triggers (severity × entitlement × time-in-state × "no known-issue match after N analyst hours"); (b) a structured handoff artifact auto-assembled from the normalized findings + timeline + correlation; (c) an engineering target that is a **rotation/queue, not a named person**; (d) bidirectional case↔GitHub state sync. Escalation must be initiable by any analyst without founder sign-off.
- **Acceptance test:** In the case simulation, an analyst can escalate a case and produce a complete handoff artifact (findings + timeline + affected nodes + GitHub issue) in one action, routed to an on-call rotation; founder is not a required approver or recipient on any escalation path; escalation SLA breaches raise an alert to a rota, not to the founder by name.
- **Recommended milestone:** Stage 2 (pre-pilot).

### R4-F3 — Dual-control approval is unworkable at small-team headcount and hard-routes to the founder
- **Severity:** Blocking (for the operations path a small team will actually run).
- **Affected component:** Plan-bound approval workflow (`staging-proof README §2 demo #8, §3`).
- **Realistic scenario:** An analyst prepares a worker restart/deploy to recover a customer's stuck analysis. The proof **rejects self-approval by the author** and requires an *independent human* approver (`bob`). On a 2-person on-call (one is the author), the only independent approver is the founder — so every mutating operation waits on the founder. At 1-person coverage (nights/weekends) it deadlocks into break-glass.
- **Business impact:** The founder is the mandatory second approver for operations, 24/7; after-hours recovery stalls or forces break-glass, eroding the very control the approval gate provides.
- **Technical impact:** Correct separation-of-duties, but no small-team accommodation: no tiered approval (low-risk L2 restart vs high-risk L3 deploy), no time-boxed break-glass with post-hoc dual review, no approver pool/rotation, no delegated approver role distinct from the founder.
- **Evidence:** `staging-proof README §2 demo #8` "self-approval by author REJECTED; independent human (`bob`) approval bound to plan signature"; `§3` reiterates plan-bound approval. No policy for how the *second* human is guaranteed to exist without being the founder.
- **Required correction:** Introduce risk-tiered approval (auto-approve or single-approver for reversible low-blast-radius ops like L2 restart of an idempotent worker; dual-control retained for L3 deploys / non-reversible ops), a **named approver pool ≥3 excluding the founder**, and a time-boxed break-glass with mandatory post-hoc independent review. Keep self-approval rejection for high-risk tiers.
- **Acceptance test:** Simulate a 2-analyst after-hours shift: a low-risk L2 restart completes with a single non-founder approver (or auto-approval per policy) and full audit; a high-risk L3 deploy still requires an independent approver drawn from a ≥3-person pool that does not include the founder; founder approval count over 100 simulated ops is 0 on the common path.
- **Recommended milestone:** Stage 3.

## 5. High-priority

### R4-F4 — SLA is a label, not a mechanism (no clock, breach detection, pause/resume, or breach escalation)
- **Severity:** High.
- **Affected component:** "SLA & queue management" (`TAC-CLOUD-ARCHITECTURE.md §2, §8`).
- **Realistic scenario:** A paid customer's case sits 6 hours unassigned. Nothing computes elapsed time against a target, nothing pauses the clock while awaiting customer info, nothing fires on breach. The founder finds out when the customer complains.
- **Business impact:** SLA commitments are unmanaged; breaches discovered by customer escalation (to the founder); no defensible SLA reporting to renew contracts.
- **Technical impact:** No first-response/resolution targets per entitlement tier, no clock model, no "awaiting customer" pause, no breach event, no pre-breach warning, no breach → escalation wiring.
- **Evidence:** `§8` lists "SLA ✅/❌" as an entitlement bit; `§2`/`§4` name "SLA/queue" with no timing semantics.
- **Required correction:** Define SLA policy objects (per-tier first-response + resolution targets), a clock with documented pause states, pre-breach (e.g. 80%) warnings, breach events that auto-escalate to a rota (not the founder), and a breach audit record.
- **Acceptance test:** Seeded cases with mixed entitlements produce correct first-response/resolution clocks; a case crossing 80% raises a warning and at 100% raises a breach event routed to a rotation; pausing for "awaiting customer" stops the clock; a breach report is queryable without founder involvement.
- **Recommended milestone:** Stage 3.

### R4-F5 — No management reporting surface exists anywhere in the design
- **Severity:** High.
- **Affected component:** TAC workflow (cross-cutting) — absent from `TAC-CLOUD-ARCHITECTURE.md §2` and all three docs.
- **Realistic scenario:** The ops manager wants queue depth, SLA-compliance %, analyst throughput, MTTR, and escalation volume for the weekly review. No such surface is designed. The only person able to answer "how is the queue doing?" is whoever holds the whole-fleet picture — the founder.
- **Business impact:** No workload visibility → the manager cannot rebalance load, justify headcount, or spot a drowning analyst; the founder remains the single point of situational awareness, which *is itself* a bottleneck (they get pulled into every "how are we doing" question).
- **Technical impact:** No metrics/reporting entities: no queue-depth/age gauges, no SLA-compliance report, no per-analyst throughput/backlog, no MTTR/MTTA, no escalation-rate, no known-issue-match-rate.
- **Evidence:** `§2` enumerates responsibilities and stops at "retention/audit/privacy controls"; management reporting is not listed. `HEALTH-AND-EVENT-MODEL.md §7` covers *appliance* diagnostics metrics, not TAC operational KPIs.
- **Required correction:** Specify a reporting surface: live queue-health (depth, oldest-unassigned, per-analyst backlog), SLA-compliance report, throughput/MTTA/MTTR, escalation and known-issue-match rates, exportable for management review — readable by a manager role without founder involvement.
- **Acceptance test:** A manager-role user retrieves, for a seeded dataset, queue depth, SLA-compliance %, per-analyst throughput/backlog, and MTTR over a chosen window, with no founder action and no raw-plane access.
- **Recommended milestone:** Stage 3.

### R4-F6 — Every customer communication is gated on human approval, with no tiering, auto-acknowledgment, or canned responses
- **Severity:** High.
- **Affected component:** AI-draft + TAC-approval customer comms (`TAC-CLOUD-ARCHITECTURE.md §4 step 8–9, §6`).
- **Realistic scenario:** 22 overnight cases each need at least a "we received your bundle, case #X opened" acknowledgment. Every one is an AI draft awaiting human approval before send (`§6`: "never auto-sent to the customer"). That is 22 human approvals before any diagnosis work starts.
- **Business impact:** Per-message human gate throttles throughput and delays first response; the approval load lands on senior staff / the founder at volume.
- **Technical impact:** Correct for *diagnostic* responses, but no risk tier: no auto-acknowledgment (case-received, case-assigned) that is safe to send without human review, no pre-approved canned templates, no "approve-and-send-all similar" batching.
- **Evidence:** `§6` "AI outputs are drafts for TAC approval, never auto-sent"; `§4 step 8–9` routes all comms through TAC approval with no exception class.
- **Required correction:** Tier customer comms: system-generated transactional acknowledgments (receipt, assignment, SLA updates) auto-send from pre-approved templates without per-message human approval; diagnostic/remediation content keeps the human-approval gate; add canned-response library and batch approval for like cases.
- **Acceptance test:** In the simulation, case-received and case-assigned notices auto-send from templates with zero human approvals and full audit, while any AI-drafted diagnostic response cannot send without an explicit human approval; template edits are RBAC-gated and audited.
- **Recommended milestone:** Stage 3.

### R4-F7 — Incident detection & grouping is named but has no grouping key, dedup rule, or lifecycle
- **Severity:** High.
- **Affected component:** "incident detection & grouping", "release linkage" (`TAC-CLOUD-ARCHITECTURE.md §2, §4 step 6`).
- **Realistic scenario:** A bad release causes the same failure across 15 appliances. Without grouping, 15 independent cases open and 15 analysts (or one founder) re-diagnose the same root cause.
- **Business impact:** Duplicated diagnosis effort, inconsistent customer messaging, no single "this is a known incident" fan-out; the founder becomes the human de-duplicator who recognizes "these are all the same thing."
- **Technical impact:** No grouping keys (finding-code + version + correlation signature), no dedup/merge into a parent incident, no incident→cases fan-out for status/comms, no auto-link to a release.
- **Evidence:** `§2`/`§4 step 6` name correlation, known-issue match, and "incident detection & grouping" but specify no grouping algorithm or incident object lifecycle.
- **Required correction:** Define an incident object with a grouping key derived from normalized findings + release + cluster correlation; auto-attach new matching cases; propagate incident status/comms to member cases; auto-link to the offending release.
- **Acceptance test:** Fifteen seeded bundles sharing a finding signature auto-group into one incident with 15 linked cases; a status update on the incident propagates to all members; the incident auto-links to the release; grouping requires no founder action.
- **Recommended milestone:** Stage 3.

## 6. Medium-priority

### R4-F8 — Known-issue / runbook lifecycle undefined (curation, match confidence, feedback loop)
- **Severity:** Medium.
- **Affected component:** "known-issue/runbook match" (`TAC-CLOUD-ARCHITECTURE.md §4 step 7`).
- **Realistic scenario:** Matching quality decides how many cases self-serve vs escalate. But nothing defines who authors known-issues/runbooks, how a resolved case becomes a reusable known-issue, match confidence thresholds, or the false-match feedback loop. Weak matching → more manual diagnosis → founder.
- **Business impact:** Automation leverage (the main productivity lever besides AI drafts) is ungoverned; deflection rate is unmeasured and unimprovable.
- **Technical impact:** No KB entity schema, no authoring/review workflow, no confidence score surfaced to analysts, no "promote this resolution to a known-issue" action, no match-accuracy metric.
- **Evidence:** `§4 step 7` "findings matched against the vendor knowledge base and prior incidents" — matching named, lifecycle absent.
- **Required correction:** Define KB/runbook entities, an authoring+review workflow (analyst-proposable, reviewer-approved), a surfaced match confidence, a "promote resolution → known-issue" action, and a match-accuracy metric feeding R4-F5 reporting.
- **Acceptance test:** An analyst promotes a resolved case to a known-issue via a reviewed workflow; a subsequent matching case surfaces it with a confidence score; match-accuracy is reported over the seeded dataset.
- **Recommended milestone:** Stage 4.

### R4-F9 — The reviewable staging proof covers the infra-ops control loop, not the TAC case workflow this review judges
- **Severity:** Medium.
- **Affected component:** Staging proof scope (`staging-proof README §2, §6`).
- **Realistic scenario:** The board asks for behavioral evidence that queues/assignment/SLA/escalation work. The proof demonstrates worker restart/deploy/rollback and audit — infra operations — not a single case-queue, assignment, SLA, or escalation demonstration.
- **Business impact:** The operations-management claims (the subject of this review) have **no reviewable evidence** — they are prose only, so the board cannot judge behavior on exactly the dimensions that determine the founder-bottleneck risk.
- **Technical impact:** The 13 demonstrations and 16-case failure matrix all exercise operations state machine + policy + approval + rollback of *workers*; none exercise case creation → auto-assignment → SLA clock → escalation → grouping → comms.
- **Evidence:** `staging-proof README §2` demonstrations are restart/deploy/validate/rollback/persist; `§6` "Establishes … single mutation spine … Does NOT establish … real provider integration …" — case workflow is not even in the not-established list, i.e. out of scope entirely.
- **Required correction:** Extend the proof harness with a case-workflow slice: seed synthetic cases, exercise auto-assignment, SLA clocks/breach, escalation handoff, incident grouping, and templated comms; produce `evidence/` artifacts mirroring the operations proof (run log, metrics, audit).
- **Acceptance test:** `tac_proof.py` gains a `case-demo`/`case-failtest` mode whose evidence shows auto-assignment, SLA breach detection, escalation, and grouping executing with zero founder actions on the common path.
- **Recommended milestone:** Stage 2 (pre-pilot) — needed before the queue/SLA claims can be qualified.

### R4-F10 — Queue model unspecified beyond a priority entitlement bit (no queue definitions, overflow, or aging)
- **Severity:** Medium.
- **Affected component:** "queue management" (`TAC-CLOUD-ARCHITECTURE.md §2, §8`).
- **Realistic scenario:** "Queue priority ✅ paid / ❌ community best-effort" is the entire queue design. There are no queue definitions (by product/severity/region), no overflow handling when a queue saturates, no aging/starvation guard so community cases aren't ignored forever.
- **Business impact:** Community cases can starve indefinitely (reputational/community-health risk); no way to shape workload across analyst skill sets; the founder becomes the manual queue-shaper.
- **Technical impact:** No named queues, no queue-selection policy, no overflow/spillover, no anti-starvation aging, no queue-level SLA.
- **Evidence:** `§8` "Queue priority ✅/❌"; `§2` names "queue management" without queue objects.
- **Required correction:** Define queue objects (selection policy by product/severity/entitlement), overflow/spillover rules, an anti-starvation aging boost for best-effort cases, and per-queue depth/age surfaced to R4-F5 reporting.
- **Acceptance test:** Seeded mixed-entitlement load routes to defined queues; paid cases get priority while community cases age-boost to guarantee bounded max wait; queue depth/age is reportable; no founder action required to shape flow.
- **Recommended milestone:** Stage 4.

## 7. Over-engineered (relative to the missing operations layer)

- **AI prompt-injection containment + HPKE/per-case-data-key E2E crypto (`TAC-CLOUD-ARCHITECTURE.md §6`, `SECURE-UPLOAD-ARCHITECTURE.md §3`)** are built to a very high bar while assignment/SLA/escalation are one-word entries. The security substrate is more mature than the workflow it protects. Not wrong — but effort is front-loaded onto ingest security while the operations layer that determines the founder-bottleneck is unspecified. Rebalance next increment toward workflow.
- **Appliance debug levels L0–L4 with watchdogs, TTLs, and cleanup guarantees (`HEALTH-AND-EVENT-MODEL.md §6`)** are elaborate for a stage where the cloud can't yet route or track a case. Correct design, premature depth relative to the gap.
- **First-class air-gap courier path (`TAC-CLOUD-ARCHITECTURE.md §11`, `SECURE-UPLOAD-ARCHITECTURE.md §6`)** is fully specified while the *online* case lifecycle after ingest is not. The transport is more finished than the destination workflow.

## 8. Under-engineered

- **Everything in `TAC-CLOUD-ARCHITECTURE.md §2` after "ingestion/analysis":** cases and interactions, SLA & queue management, engineering escalation, incident detection & grouping, customer notifications — enumerated as owned responsibilities, zero mechanics. These are the operations layer and they are the review's subject.
- **Assignment/routing:** absent (R4-F1).
- **Escalation criteria + handoff artifact:** absent (R4-F2).
- **SLA clock/breach:** label only (R4-F4).
- **Management reporting:** absent entirely (R4-F5).
- **Incident grouping algorithm + object:** named only (R4-F7).
- **Known-issue/runbook lifecycle:** matching named, lifecycle absent (R4-F8).

## 9. Exact proposed changes

1. **Add an Assignment Engine spec** to `TAC-CLOUD-ARCHITECTURE.md` (new §): auto-assign on case creation (entitlement → queue → least-loaded eligible analyst with skill/product tags), an explicit unassigned queue with age SLA + alert, reassignment/hand-back rules, per-analyst concurrent-case cap. (R4-F1)
2. **Add an Escalation & Engineering-Handoff spec:** triggers = severity × entitlement × time-in-state × "no known-issue match after N analyst-hours"; auto-assembled handoff artifact (findings + timeline + correlation + affected fleet); target is an on-call **rotation**; bidirectional case↔GitHub state sync. (R4-F2)
3. **Introduce risk-tiered approval** in the operations control loop: auto/single-approver for reversible low-blast-radius ops (L2 restart), dual-control for L3/non-reversible; approver pool ≥3 excluding the founder; time-boxed break-glass with post-hoc independent review. (R4-F3)
4. **Add SLA policy objects + clock:** per-tier first-response/resolution targets, documented pause states, 80% warning, breach event auto-routed to a rota, breach audit. (R4-F4)
5. **Add a Management Reporting surface** (new §): live queue health, SLA-compliance %, per-analyst throughput/backlog, MTTA/MTTR, escalation + known-issue-match rates, manager-role readable, exportable. (R4-F5)
6. **Tier customer comms:** auto-send transactional acknowledgments from pre-approved templates; keep human-approval gate for diagnostic content; add canned-response library + batch approval. (R4-F6)
7. **Define the Incident object + grouping key** (finding-code + version + correlation signature), auto-attach + status fan-out + release linkage. (R4-F7)
8. **Define KB/runbook lifecycle:** entity schema, analyst-proposable/reviewer-approved authoring, surfaced match confidence, promote-resolution action, match-accuracy metric. (R4-F8)
9. **Extend the proof harness** with a `case-demo`/`case-failtest` slice producing `evidence/` artifacts for assignment, SLA breach, escalation, grouping, and templated comms — zero founder actions on the common path. (R4-F9)
10. **Define queue objects** with selection policy, overflow/spillover, anti-starvation aging, per-queue depth/age reporting. (R4-F10)

## 10. Measurable acceptance criteria (roll-up)

The platform passes the "small team, no founder bottleneck" bar when, in a seeded ≥50-case simulation with 3 analysts + 1 founder + after-hours single-coverage shifts:

- **Assignment:** ≥95% of cases auto-owned within 5 min; founder in the assignment audit for <5% of cases. (R4-F1)
- **Escalation:** any analyst escalates with a complete auto-assembled handoff to an on-call rotation; founder is never a required approver/recipient. (R4-F2)
- **Approval:** low-risk ops complete with a single non-founder (or auto) approver; high-risk keeps independent approval from a ≥3 non-founder pool; founder approvals over 100 ops = 0 on the common path. (R4-F3)
- **SLA:** clocks correct per tier; 80% warns, 100% breaches to a rota; pause states honored; breach report queryable without the founder. (R4-F4)
- **Reporting:** a manager-role user pulls queue depth, SLA-compliance %, throughput/backlog, MTTR with no founder action and no raw-plane access. (R4-F5)
- **Comms:** transactional acks auto-send (0 approvals); diagnostic content cannot send without human approval. (R4-F6)
- **Grouping:** 15 same-signature bundles auto-group into 1 incident, status fans out, release auto-links, no founder action. (R4-F7)
- **Evidence:** the proof harness emits case-workflow `evidence/` demonstrating all of the above. (R4-F9)

**Overall gate:** founder actions on the common path across the full simulation = **0**; founder appears only in explicit, audited exception flows.

## 11. Go / No-Go

**NO-GO** for a paid pilot under the "small team runs it without the founder as the manual escalation point" claim.

- **Platform/security architecture and the infra-ops control loop:** GO (Stage-1 evidence is credible and honest).
- **TAC operations-management layer (the reviewed surface):** NO-GO — assignment, SLA mechanics, escalation criteria, incident grouping, and management reporting are unspecified, so the founder-bottleneck is structural, not incidental, and there is **no reviewable evidence** for these claims.

**Conditional GO** once R4-F1, R4-F2, R4-F3 (blocking) and R4-F9 (evidence) are specified and demonstrated with founder-actions = 0 on the common path, with R4-F4/F5/F6/F7 landed before general availability. The architecture can support this — the work is to build the operations workflow layer, not to redesign the platform.
