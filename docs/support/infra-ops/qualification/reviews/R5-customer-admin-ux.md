# R5 — Customer-Admin UX Qualification Review

- **Reviewer role:** Independent qualification reviewer acting as an **Enterprise Customer Administrator** opening and running support cases under pressure.
- **Scope reviewed:** `SECURE-UPLOAD-ARCHITECTURE.md`, `REDACTION-MODEL.md`, `DIAGNOSTIC-COMMAND-FRAMEWORK.md`, `HEALTH-AND-EVENT-MODEL.md`, `TAC-CLOUD-ARCHITECTURE.md`, `SUPPORT-BUNDLE-SPEC.md` (all `Status: Proposed (design)`).
- **Benchmark:** publicly observable experience of opening a case with an established security vendor (portal "Open a Case" front door, auto-generated tech-support file, one-click attach, visible case queue/status, e-mail thread). No proprietary claims.
- **Date:** 2026-07-13.

The design is reviewed as a **customer-facing experience**, independent of implementation status. Where the design defers a capability (e.g. upload gated `not_enabled` until M6), the deferral is assessed as part of the experience a customer actually receives at the milestone the docs describe as shippable.

---

## 1. Verdict

The **evidence-collection and data-governance machinery is excellent** — the redaction model, consent separation, encryption-to-TAC, resumable upload, and cloud-independence design are stronger than what most established vendors expose. But the **customer-facing support journey is missing its two bookends**: there is **no described way for a customer to open a case / obtain a `case_id`** (which is a required input almost everywhere), and there is **no in-product surface that shows case status or TAC's responses back to the administrator**. The appliance is a superb *evidence producer* wired to a well-specified cloud, but the *customer's case experience* — the thing a support UX lives or dies on — is under-designed. A customer in an active outage today would collect a beautiful bundle and then hit a wall: no case to attach it to, upload gated off (MVP), and an undescribed portal to fall back on. **No-go for customer-facing GA** until the front door (case origination) and the feedback loop (case status/TAC-request inbox) exist. The internals earn a go; the customer UX does not yet.

---

## 2. Maturity: **2 / 5**

Scoring the **reviewed dimension (customer-admin UX)**, not the internals.

- Internal collection/redaction/upload-protocol machinery, assessed on its own, is ~4/5.
- Customer-facing journey (case origination → consent → send → status → resolution) is **2/5**: two blocking gaps (no case creation, no status/response loop), a milestone mismatch (marketed cloud happy-path vs. MVP deliverable), heavy jargon, and an undescribed portal. It is coherent and safe, but a customer cannot complete the round-trip a support relationship requires using what is designed.

---

## 3. Unusually strong (better than the established-vendor benchmark)

- **Consent model (SECURE-UPLOAD §2).** Four independent switches, four audit trails, enabling one never enables another; upload is a hard state-machine gate; per-bundle + per-case + explicit. Most vendors bury consent in a portal EULA. This is best-in-class.
- **Mandatory privacy preview before export (REDACTION §6, BUNDLE §6).** The customer sees *what* is masked/dropped (counts by class) before anything leaves. Established vendors ship the tech-support file blind. This directly answers the enterprise admin's "prove nothing sensitive leaves" objection.
- **Structural redaction with a CI parity wall (REDACTION §2, §9).** "A new field with no classification fails CI" is a governance guarantee a customer's security team can actually audit — rare in the market.
- **Encrypt-to-TAC independent of TLS (SECURE-UPLOAD §3).** HPKE to a pinned, published TAC key with a per-case data key; appliance holds no decryption secret. Stronger confidentiality story than "TLS to our portal."
- **Genuine cloud-independence + first-class air-gap (SECURE-UPLOAD §5–6, TAC-CLOUD §10–11).** Cloud down = normal operation + queued/offline bundle; air-gap is "a transport difference, not a separate code path." Excellent posture.
- **Explainable health with `CauseClass`/`UserImpact`/`Collectors` (HEALTH §1).** "One-click from a red health row to exactly the right bundle" is a better diagnostic on-ramp than a generic "download logs" button.

---

## 4. Blocking findings

### R5-F1 — No case-origination flow; `case_id` is a required input with no described source
- **Finding ID:** R5-F1
- **Severity:** Blocking
- **Affected component:** Cross-document (DIAGNOSTIC-COMMAND-FRAMEWORK §2 `support upload --case <id>`, `collect [--case]`; SECURE-UPLOAD §2/§4 `case_id`; TAC-CLOUD §2 "cases and interactions"; SUPPORT-BUNDLE manifest `case_id`).
- **Realistic scenario:** Admin has a production TLS-inspection outage. They run `culvert support collect --scope tls_inspection_failure`, get a clean bundle, then try to send it. Every send path demands `--case <id>` / `case_id`. Nothing in any of the six documents tells them how to create a case or where a `case_id` comes from. The cloud "owns cases and interactions" but the *customer's* act of opening one is unspecified.
- **Business impact:** The front door of the entire support relationship is missing. A customer under pressure cannot start. This is the single most common first action at every established vendor ("Open a Case") and it does not exist in the design.
- **Technical impact:** `case_id` is threaded through upload init, manifest binding, tenant scoping, and receipts as a precondition, but its *creation* has no API, CLI verb, GUI affordance, or portal flow. The tenant→case binding that makes uploads land correctly (SECURE-UPLOAD §4) has no described origin event.
- **Evidence:** DIAGNOSTIC §2 lists `support upload <bundle> --case <id>` but no `support case open`; SECURE-UPLOAD §4 `POST /v1/uploads:init {case_id,…}` assumes `case_id` exists; TAC-CLOUD §2 lists "cases and interactions" as a cloud responsibility with no appliance-side or portal-side origination flow; SUPPORT-BUNDLE manifest marks `case_id` "optional; binds bundle to a support case" — optional at the bundle, mandatory at upload, never created anywhere.
- **Required correction:** Specify a first-class case-origination flow with three parity surfaces: (a) `culvert support case open --summary … [--severity …]` → returns `case_id`; (b) `POST /api/support/cases` with `uiRoutes` metadata + a GUI "Open a Case" affordance in `data-view="support"`; (c) the air-gap/portal equivalent (customer opens a case in the TAC portal, receives a `case_id`, feeds it to `collect`/`export`). Define the community-vs-paid entitlement at case creation (mirrors TAC-CLOUD §8).
- **Acceptance test:** `TestCaseOpenReturnsID` (online path returns a tenant-scoped `case_id` an upload can bind to); `TestBundleBindsExistingCaseOnly` (upload/attach rejects an unknown/foreign-tenant `case_id`); GUI e2e: an admin opens a case and attaches a bundle without leaving the panel.
- **Recommended milestone:** M-Frontdoor (must precede any upload GA / M6).

### R5-F2 — No in-product case-status / TAC-response surface (broken feedback loop)
- **Finding ID:** R5-F2
- **Severity:** Blocking
- **Affected component:** SECURE-UPLOAD §2 (poll-for-policy), TAC-CLOUD §2/§9 ("customer comms", "customer notifications", "email intake/delivery"), DIAGNOSTIC §2 (`support status`, `support history`).
- **Realistic scenario:** Admin uploads a bundle for a case and then wants to know: did TAC receive it, is it in queue, has an engineer responded, what did they ask for? The appliance surfaces only a signed *receipt* (proof of send) and local *history*. Case state ("queued / under review / responded / resolved") and TAC's actual replies live entirely in the cloud and reach the customer only via out-of-band e-mail. There is no described appliance surface that pulls case status back.
- **Business impact:** "Where is my case?" is the second-most-common support action and it is unanswerable in-product. The admin is forced into e-mail and an undescribed portal, fragmenting the experience the vendor benchmark keeps in one place (portal case timeline).
- **Technical impact:** The architecture is outbound-only and the appliance "polls for policy on its own schedule" (SECURE-UPLOAD §2) — the transport to *pull case status* already exists conceptually, but no status/response object, endpoint, or GUI surface is defined. `support status` returns local health + recent bundles, not case state.
- **Evidence:** DIAGNOSTIC §2 `support status` = "health verdict + active debug level + recent bundles" (no case state); SECURE-UPLOAD §4 receipt is send-proof only; TAC-CLOUD §2 lists "customer notifications" as cloud-owned with no appliance-side rendering; no document defines a `GET /api/support/cases/{id}` returning status/replies.
- **Required correction:** Define a read-only, outbound-pulled case-status surface: `culvert support case status <id>` + `GET /api/support/cases/{id}` (state, queue position/SLA where entitled, TAC's latest request/response summary, redacted) + a GUI case timeline in `data-view="support"`. Reuse the existing outbound poll schedule; no inbound path (preserves ADR-0014). Keep e-mail as a redundant channel, not the only one.
- **Acceptance test:** `TestCaseStatusPulledOutbound` (status fetched on the appliance's own schedule, no inbound listener — extends `TestNoInboundTACSurface`); `TestCaseStatusOfflineDegrades` (air-gapped shows "status unavailable offline", never errors); GUI e2e: case timeline renders TAC's latest response.
- **Recommended milestone:** M-Frontdoor (paired with R5-F1).

---

## 5. High-priority

### R5-F3 — MVP send-path is offline-export to an undescribed portal; marketed cloud happy-path is not deliverable at the reviewed milestone
- **Finding ID:** R5-F3
- **Severity:** High
- **Affected component:** DIAGNOSTIC §2/§7 (`upload` gated `not_enabled` until M6), TAC-CLOUD §9/§11 (portal upload), SECURE-UPLOAD §6.
- **Realistic scenario:** A customer reads TAC-CLOUD §9's polished "upload → receipt → analysis → notification" happy-path, then discovers upload is `not_enabled` (M6) and the only working send is `--export` to a file they must hand-carry to "the TAC portal" — a portal whose customer UX (login, entitlement, case selection, upload widget) is described nowhere.
- **Business impact:** Expectation/delivery mismatch. The experience the docs advertise as the primary flow is unavailable at MVP; the fallback the customer actually gets has no specified UX. Erodes trust at first contact.
- **Technical impact:** Two of the three send surfaces in DIAGNOSTIC §1 (Admin API, GUI) depend on the gated upload; only offline export works, and its downstream (portal ingest) is a cloud responsibility with no customer-facing spec.
- **Evidence:** DIAGNOSTIC §7 "gated `not_enabled` until M6"; TAC-CLOUD §11 "manual upload to TAC portal" with no portal UX; SECURE-UPLOAD §6 step 3 "the customer uploads it to the TAC portal" — undefined.
- **Required correction:** Either (a) pull minimal authenticated upload into the same milestone as case origination so the in-product happy-path is real at GA, or (b) specify the TAC-portal customer UX (case selection, entitlement, drag-drop `.csb.age`, offline `validate` guidance) and label the docs' §9 sequence as "post-M6" so no customer expects it earlier.
- **Acceptance test:** `TestMVPSendPathDocumented` (a doc/CI check that the milestone's *shippable* send path — export + portal — has an end-to-end customer walkthrough); portal e2e: customer selects a case and uploads an exported bundle.
- **Recommended milestone:** M6 (align upload GA with case origination) or M-Frontdoor (portal UX).

### R5-F4 — "TAC requests more evidence" has no appliance-side notification/consent inbox
- **Finding ID:** R5-F4
- **Severity:** High
- **Affected component:** SECURE-UPLOAD §2 ("cloud 'please send a bundle for case X' policy the appliance may poll for"), HEALTH §4 timeline (`category: support`).
- **Realistic scenario:** TAC needs a fresh `tls_inspection_failure` bundle. The cloud sets a policy the appliance polls for. The admin has no in-product inbox showing "TAC requested a bundle for case X — review scope & consent." They learn only by e-mail, then must reconstruct the exact scope/window TAC wanted by hand.
- **Business impact:** The evidence back-and-forth — a core TAC interaction — has no guided in-product path, adding latency and mis-scoped bundles to every non-trivial case.
- **Technical impact:** The poll mechanism is specified but its *rendering* (a pending-request surface that pre-fills `collect --scope --window --case` and routes into the existing privacy-preview + consent gate) is not.
- **Evidence:** SECURE-UPLOAD §2 describes the poll and reaffirms local consent, but no CLI verb, endpoint, or GUI element surfaces a pending request; DIAGNOSTIC §2 has no `support requests` verb.
- **Required correction:** `culvert support requests` + `GET /api/support/requests` + a GUI "TAC requested" card that deep-links into a pre-scoped Collect wizard (still gated by the mandatory preview + explicit consent — cloud requests, never compels, per ADR-0014).
- **Acceptance test:** `TestTACRequestRequiresLocalConsent` (a polled request never auto-collects/uploads; still hits preview + consent); GUI e2e: a pending request pre-fills scope/window/case and requires an explicit confirm.
- **Recommended milestone:** M6.

### R5-F5 — Customer-facing surfaces inherit vendor-internal jargon
- **Finding ID:** R5-F5
- **Severity:** High
- **Affected component:** All docs → GUI/CLI strings (REDACTION §1 class names, SUPPORT-BUNDLE `class_max`/`CSB`, HEALTH `CHR`, SECURE-UPLOAD `HPKE`/`Tier 2/3`, DIAGNOSTIC `DiagCommand`).
- **Realistic scenario:** A stressed admin reads a privacy preview citing `NEVER_EXPORT`, `class_max ≤ INTERNAL`, `SENSITIVE→redacted`, `csb/1`, `HPKE recipient key`, "Tier 2 pipeline." They cannot tell, at a glance, whether their users' data is safe — the exact question the preview exists to answer.
- **Business impact:** The strongest asset (the preview/consent flow) is undermined by unreadable labels; increases support-about-support tickets and slows the consent decision.
- **Technical impact:** Internal taxonomies (5-class `DataClass`, 3-registry model, tier vocabulary) are surfaced verbatim in customer-facing counts and manifests without a plain-language layer.
- **Evidence:** REDACTION §6 preview is defined in `class` counts; SUPPORT-BUNDLE §2 uses `class_max`/`csb/N` in customer-visible manifest; HEALTH §1 exposes `CHR` naming in `health explain`.
- **Required correction:** Add a plain-language layer for every customer-facing string ("Secrets — never sent", "Personal data — masked", "Safe to share") mapped 1:1 to the internal classes; keep machine fields internal. Provide a one-line glossary in `SUMMARY.md` and the GUI preview.
- **Acceptance test:** `TestPreviewHasPlainLabels` (every class/status shown to a customer has a plain-language string); usability check: a non-Culvert admin correctly answers "does this contain passwords?" from the preview alone.
- **Recommended milestone:** M-Frontdoor.

### R5-F6 — Upload-rejection reason is redacted, blocking self-service recovery
- **Finding ID:** R5-F6
- **Severity:** High
- **Affected component:** SECURE-UPLOAD §5 (gateway rejects → `rejected` with a "redacted reason"), TAC-CLOUD §7 gateway gate.
- **Realistic scenario:** A bundle is `rejected` (entitlement/format/hash). The admin sees a redacted reason, cannot tell whether to re-collect, check entitlement, or call support — so they call support to ask why support rejected their support bundle. Circular.
- **Business impact:** A recoverable failure becomes a ticket. Established vendors return actionable upload errors ("file too large", "case closed", "entitlement expired").
- **Technical impact:** Redaction of the reason is over-applied to a *control-plane* message (entitlement/format/hash) that carries no customer secret and is exactly the actionable signal.
- **Evidence:** SECURE-UPLOAD §5 "bundle → `rejected` with a redacted reason; no silent retry loop; surfaced to operator" — surfaced but not actionable.
- **Required correction:** Define a **closed enum of rejection reasons** (`entitlement_expired`, `size_exceeded`, `format_unsupported`, `hash_mismatch`, `duplicate`, `case_closed`, `case_not_found`) with a plain remediation string each; redact only free-form detail, never the coded reason.
- **Acceptance test:** `TestRejectReasonEnumActionable` (every reject returns a coded reason + remediation; no bare "rejected"); `TestRejectReasonNoSecretLeak` (the enum + remediation carry no bundle content).
- **Recommended milestone:** M6.

---

## 6. Medium-priority

### R5-F7 — Refusing/tightening collection has no surfaced diagnostic-completeness trade-off
- **Finding ID:** R5-F7
- **Severity:** Medium
- **Affected component:** REDACTION §5 (profiles `strict`/`paranoid`, section opt-out).
- **Realistic scenario:** A privacy-conscious admin selects `paranoid` (drops request logs + audit detail) and opts out of `logs/requests.jsonl`. TAC later can't diagnose the `website_unreachable` case without exactly that evidence and asks for it — a round-trip the admin would have avoided if warned.
- **Business impact:** Silent under-collection lengthens cases; the customer feels they "did it right" and is then bounced.
- **Technical impact:** `skipped:operator` is recorded in the manifest for TAC, but nothing warns the *customer* at selection time that a chosen incident scope's key evidence is being excluded.
- **Evidence:** REDACTION §5 records exclusions for TAC; HEALTH §5 scopes name required collectors — the two aren't cross-checked for the customer.
- **Required correction:** At exclusion time, if an opt-out removes a collector the selected `IncidentScope` marks as key, show a non-blocking "this may slow resolution for <scope>" note. Advisory only — never override consent.
- **Acceptance test:** `TestExclusionWarnsAgainstScope` (excluding a scope-critical collector emits an advisory; consent still honored).
- **Recommended milestone:** M6.

### R5-F8 — Counts-only preview gives no sample-of-masking to build trust
- **Finding ID:** R5-F8
- **Severity:** Medium
- **Affected component:** REDACTION §6 ("counts only, never the redacted values").
- **Realistic scenario:** A security lead wants to *see* that a client IP becomes `203.0.113.0/24` and an email becomes `user_9c2e…` before approving. The preview shows only "142 SENSITIVE items masked" — technically reassuring, experientially opaque.
- **Business impact:** The counts-only stance (correct for privacy) can read as "trust us"; some enterprises need to *see* the masking shape once to sign off.
- **Technical impact:** No affordance renders a **synthetic** masking example (masked forms of fabricated inputs) that reveals technique without revealing any real datum.
- **Evidence:** REDACTION §4 defines masked forms; §6 forbids showing values. A synthetic example bridges the two without violating §6.
- **Required correction:** Add an optional "show masking examples" panel rendering §4's masked *forms* over fabricated inputs (never bundle data), clearly labeled synthetic.
- **Acceptance test:** `TestMaskingExamplesSynthetic` (examples derive only from fabricated inputs; no bundle value reachable).
- **Recommended milestone:** M7.

### R5-F9 — Per-bundle explicit consent is repetitive during an active case
- **Finding ID:** R5-F9
- **Severity:** Medium
- **Affected component:** SECURE-UPLOAD §2 (per-bundle, per-case explicit consent).
- **Realistic scenario:** During one active `ha_inconsistency` case, TAC requests three bundles over an afternoon; the admin walks the full preview+consent gate three times. Vendor benchmark: attach-to-open-case is one click after the first authorization.
- **Business impact:** Friction in exactly the moment (active incident) where speed matters; may push admins toward over-broad initial collection to avoid repeat gates.
- **Technical impact:** No "case-scoped standing consent with mandatory per-bundle preview" option; the design treats every bundle as a cold start.
- **Evidence:** SECURE-UPLOAD §2 makes consent a per-bundle hard gate with no case-scoped variant.
- **Required correction:** Offer an **optional, time-boxed, revocable, audited** case-scoped consent that still forces the preview each time but collapses the confirm to one click; default remains per-bundle explicit. Audit as a distinct `support.upload.case_consent` action.
- **Acceptance test:** `TestCaseConsentStillPreviews` (case-scoped consent never skips the preview; auto-expires; revocable; separately audited).
- **Recommended milestone:** M7.

### R5-F10 — Long collection (up to 120 s) has no specified customer progress/status UX
- **Finding ID:** R5-F10
- **Severity:** Medium
- **Affected component:** SECURE-UPLOAD §8 (60 s soft/120 s hard), SUPPORT-BUNDLE §6 state machine, DIAGNOSTIC §3 (`Cancellable` op id).
- **Realistic scenario:** An admin runs a cluster bundle; the GUI shows nothing for up to two minutes. They don't know if it hung, and the rich state machine (`COLLECTING`/`REDACTING`/…) is never surfaced.
- **Business impact:** Perceived hang → duplicate runs (blocked by single-flight, but confusing) or abandonment.
- **Technical impact:** The op-id/cancel contract and the persisted per-state machine exist but no progress rendering (current state, per-collector `ok/failed`, elapsed vs. budget) is specified for CLI/GUI.
- **Evidence:** DIAGNOSTIC §3 returns an op id; SUPPORT-BUNDLE §6 persists each state — neither is surfaced as progress.
- **Required correction:** Specify a progress surface: `GET /api/support/bundles/{op}` streaming/poll of current state + per-collector status + elapsed/budget; GUI progress bar with a Cancel button (reusing `DELETE …/{id}`).
- **Acceptance test:** `TestCollectProgressObservable` (op id yields live state + per-collector status; cancel cleans partial artifacts).
- **Recommended milestone:** M6.

### R5-F11 — Air-gapped portal customer experience is unspecified despite "first-class" claim
- **Finding ID:** R5-F11
- **Severity:** Medium
- **Affected component:** SECURE-UPLOAD §6, TAC-CLOUD §11.
- **Realistic scenario:** An air-gapped customer exports `.csb.age`, couriers it out, and reaches "the TAC portal" — with no described login, entitlement check, case selection, upload widget, or post-upload `validate` guidance. The "first-class, not an afterthought" claim isn't matched by portal UX detail.
- **Business impact:** The segment most likely to be high-value/regulated gets the least-specified customer journey.
- **Technical impact:** Portal ingest reuses the same pipeline (good), but the *customer's* portal steps are undefined, so air-gap is first-class in transport only.
- **Evidence:** SECURE-UPLOAD §6 step 3 and TAC-CLOUD §11 both say "uploads it to the TAC portal" with no UX.
- **Required correction:** Specify the portal customer flow: authenticate → select entitled case (ties to R5-F1) → upload `.csb.age` → server-side `validate` echo → receipt. Document offline `culvert support validate` before/after transfer as the integrity bookend.
- **Acceptance test:** Portal e2e: air-gapped customer uploads an exported bundle to a case and receives a validated receipt; `TestOfflineValidateBeforeUpload` (customer can prove integrity pre-courier).
- **Recommended milestone:** M-Frontdoor / M6.

---

## 7. Over-engineered (for the customer-facing dimension)

- **Consent surface depth vs. the missing front door.** Four switches + four audit trails + per-bundle preview + L0–L4 acknowledgements is heavier than the vendor benchmark (generate tech-support file → attach → submit ≈ 3 steps), yet the *simplest* customer act — opening a case — is absent (R5-F1). Investment is lopsided toward the guard rails and away from the door they guard.
- **Five-class taxonomy + three registries + parity walls surfaced to the customer.** Superb internally; but the customer only needs "secrets never sent / personal data masked / safe to share." Exposing `class_max`, `NEVER_EXPORT`, `csb/N` verbatim (R5-F5) is more governance vocabulary than a customer decision requires.
- **L3/L4 debug ceremony** (break-glass + `case_id` + sensitive-data acknowledgement + watchdog) is appropriate for depth but risks overwhelming an admin who just wants a standard bundle; ensure the L1 standard path is a genuine one-click default, not a wizard.

## 8. Under-engineered (relative to the machinery)

- **Case origination (R5-F1)** — no front door; the most-used first action is undefined.
- **Case status / TAC-response loop (R5-F2)** — no in-product "where is my case," no rendering of TAC replies; the customer is pushed to e-mail + an undescribed portal.
- **TAC-request inbox (R5-F4)** — the evidence back-and-forth has no guided surface.
- **Portal customer UX (R5-F3, R5-F11)** — the MVP-actual and air-gap send targets have no described customer journey.
- **Actionable upload errors (R5-F6)** and **progress visibility (R5-F10)** — recovery and status, the two things a stressed admin needs, are thin.

Net: the appliance is engineered as a world-class *evidence producer*; the *customer's case relationship* (open → track → converse → resolve) is the under-built half.

---

## 9. Exact proposed changes

1. **Add a case-origination flow (R5-F1).** New verb `culvert support case open --summary … [--severity …] [--product-area …]`; new `POST /api/support/cases` with a `uiRoutes` metadata row (C1 parity), `requireRole(operator)`, `auditEvent("support.case.open")`; GUI "Open a Case" button in `data-view="support"` returning a `case_id`. Portal equivalent for air-gap. Bind entitlement (community/paid) at creation.
2. **Add a case-status surface (R5-F2).** `culvert support case status <id>` + `GET /api/support/cases/{id}` (state, SLA/queue where entitled, latest TAC request/response summary — redacted), pulled on the existing outbound poll; GUI case timeline. No inbound path.
3. **Add a TAC-request inbox (R5-F4).** `culvert support requests` + `GET /api/support/requests` + GUI "TAC requested" card deep-linking a pre-scoped Collect wizard through the existing preview+consent gate.
4. **Reconcile MVP send-path (R5-F3).** Either pull minimal upload into the case-origination milestone, or fully specify the TAC-portal customer UX and re-label TAC-CLOUD §9 as post-M6.
5. **Add a plain-language layer (R5-F5).** Map every customer-visible class/status/format token to a plain string; one-line glossary in `SUMMARY.md` + GUI preview.
6. **Enumerate upload-rejection reasons (R5-F6).** Closed reason enum + per-reason remediation; redact only free-form detail.
7. **Warn on scope-critical exclusions (R5-F7);** add synthetic masking examples (R5-F8); optional case-scoped consent that still previews (R5-F9); collection progress surface + cancel (R5-F10); specify air-gap portal flow + offline `validate` bookend (R5-F11).

---

## 10. Measurable acceptance criteria

- **Front door:** A new admin, no docs beyond in-product help, **opens a case and attaches a bundle in ≤ 4 steps** (parity with the vendor benchmark). `TestCaseOpenReturnsID`, `TestBundleBindsExistingCaseOnly`, GUI e2e green.
- **Feedback loop:** `culvert support case status <id>` and the GUI timeline show state + TAC's latest response for an online case; **offline degrades to "unavailable" without error**. `TestCaseStatusPulledOutbound`, `TestCaseStatusOfflineDegrades`, `TestNoInboundTACSurface` still green.
- **TAC request:** A polled request renders in-product and pre-fills scope/window/case, still gated by preview+consent. `TestTACRequestRequiresLocalConsent`.
- **Plain language:** A non-Culvert admin correctly answers "does this contain passwords / personal data?" from the preview alone. `TestPreviewHasPlainLabels`.
- **Recovery:** Every upload rejection returns a coded reason + remediation, no secret leak. `TestRejectReasonEnumActionable`, `TestRejectReasonNoSecretLeak`.
- **Status during collect:** A ≥ 60 s collection shows live state + per-collector status and is cancellable. `TestCollectProgressObservable`.
- **Air-gap:** A customer uploads an exported bundle to a case in the portal and receives a validated receipt; integrity provable offline before courier. Portal e2e + `TestOfflineValidateBeforeUpload`.
- **No regressions:** consent separation, no-auto-upload, SSRF, no-inbound-surface, redaction fail-closed tests all remain green (`TestConsentSeparation`, `TestNoAutoUpload`, `TestUploadSSRFGuarded`, `TestNoSecretInBundle`).

---

## 11. Go / No-go

**NO-GO for customer-facing GA** at the reviewed milestone.

The internal evidence-collection, redaction, consent, encryption, and cloud-independence design is a **GO on its own merits** — genuinely strong, in places best-in-class. But a support product is judged by the customer's round-trip: **open a case → send evidence → see status → converse → resolve.** Two of those five stages (open, status/converse) have **no described customer surface** (R5-F1, R5-F2), the MVP send-path and portal UX are undefined (R5-F3), and the evidence back-and-forth has no in-product loop (R5-F4). Until case origination and a case-status/response surface exist and the MVP send-path is reconciled, an enterprise admin cannot complete a support interaction using what is designed, and the experience is measurably harder than opening a case with an established vendor.

**Conditions to flip to GO:** ship R5-F1 and R5-F2 (blocking), resolve R5-F3, R5-F4, R5-F5, R5-F6 (high), and meet the §10 acceptance criteria. The medium findings can follow in M7 without gating GA.

---

## Appendix — Per-scenario step / clarity / trust table

Steps counted as discrete customer actions to reach a *useful outcome* (diagnose + get evidence to TAC + know what happens next). Clarity/Trust rated 1–5 (5 = matches or beats the established-vendor benchmark). "Benchmark steps" = comparable established-vendor flow.

| # | Scenario | Steps (design) | Benchmark steps | Clarity | Trust | Dominant friction |
|---|---|---|---|---|---|---|
| 1 | Traffic outage | ~8 (health explain → diagnose ×N → collect → preview → consent → **obtain case_id?** → upload gated / export → portal) | ~3 | 2 | 3 | No case to attach to (R5-F1); upload gated, portal undescribed (R5-F3) |
| 2 | TLS problem | ~7 (`diagnose tls` → scope `tls_inspection_failure` → L2 ack → collect → preview → consent → send) | ~3 | 3 | 4 | Strong scope+preview; still blocked by case_id + send path |
| 3 | Stale data-plane config | ~7 (`diagnose cluster` → scope `ha_inconsistency` → fan-out collect → preview → consent → send → **status?**) | ~3 | 3 | 4 | Good discriminator UX; no case status to confirm fix (R5-F2) |
| 4 | Bundle upload failure | ~5 (upload → `rejected`/`queued` → read reason → re-collect? → retry/export) | ~2 | 2 | 3 | Redacted reject reason blocks self-recovery (R5-F6); good queue/retry |
| 5 | TAC requests more evidence | ~6 (learn via **e-mail only** → reconstruct scope/window → collect → preview → consent → send) | ~2 | 2 | 3 | No in-product request inbox (R5-F4) |
| 6 | Customer refuses sensitive collection | ~5 (choose `paranoid`/opt-out → collect → preview → consent → send) | ~3 | 4 | 5 | Best-in-class control; no completeness trade-off warning (R5-F7) |
| 7 | Cloud unavailable | ~4 (collect → preview → consent → **auto-queue**/export) | ~3 | 4 | 5 | Graceful by design; unaffected operation is a strength |
| 8 | Air-gapped support | ~7 (collect → preview → consent → export → validate → courier → **portal upload?**) | ~4 | 2 | 4 | First-class transport, undescribed portal customer UX (R5-F11) |

**Reading:** trust is consistently high (the redaction/consent/cloud-independence design earns it); **clarity and step-count are consistently worse than the benchmark**, and every scenario except 6 and 7 is gated by the two missing bookends — case origination and case status. Scenarios 6 and 7, where the design's strengths (consent control, cloud-independence) dominate and no case round-trip is required, are the only ones that meet or beat the benchmark.
