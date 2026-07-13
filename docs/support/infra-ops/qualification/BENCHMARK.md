# Stage 3 — Enterprise Vendor Benchmark (public sources only)

- **Method:** compare the Culvert TAC design to **generally observable** enterprise security-vendor support practices (public docs, support-portal UX, published TSF/tech-support-file guidance, release-notes/known-issue pages, status pages, trust/compliance pages). **No proprietary or internal-system claims.** Vendors referenced only as public archetypes (NGFW/SASE/EDR support portals, "tech support file" / "show tech-support" bundles, health-check services, case portals). Culvert is weighted for its **small budget and team** — the bar is *equivalent value*, not feature-parity.
- **Classification per capability:** `Ahead` · `Comparable` · `Behind` · `Intentionally deferred` · `Not publicly verifiable`.

---

## 1. Benchmark table

| # | Capability | Public vendor norm (observable) | Culvert design | Class | Notes |
|---|---|---|---|---|---|
| 1 | **Customer support portal** | Web portal: open/track cases, entitlements, downloads | TAC Cloud cases + entitlement (design); customer console (design) | **Behind** | portal is designed, not built; norm is table-stakes and mature |
| 2 | **Technical support file** (show tech-support / TSF) | One-command redacted diagnostic bundle, documented contents | `csb/1` collector-based bundle: manifest, per-section SHA-256, source-side fail-closed redaction, integrity, versioning | **Ahead (on rigor)** / Comparable (on availability) | Culvert's *typed schema + fail-closed redaction + parity-wall CI* exceeds the typical opaque TSF; but the vendor's is shipping and Culvert's is designed |
| 3 | **Health checks** | Periodic health/best-practice assessments; some cloud-delivered | `OperatorContract` local health (exists in product) + CHR model + incident scopes (design) | **Comparable** | local health already ships; explainable CHR is a design strength |
| 4 | **Telemetry** | Broad opt-in device telemetry feeding proactive support | Opt-in, strict-subset, separately-consented telemetry (M7, deferred) | **Intentionally deferred** | correct sequencing for budget; norm is large-scale and expensive |
| 5 | **Case status visibility** | Real-time case state, updates, ETAs in portal | Operation/case state machine + audit; customer notifications (design) | **Behind** | strong internal state model; customer-facing status UX not built |
| 6 | **Evidence upload** | Portal upload, size limits, secure transfer | Outbound-only, resumable, E2E recipient-encrypted, case-bound, consent-gated, offline export | **Ahead (on security model)** | recipient-key E2E + outbound-only + fail-closed redaction is stronger than a typical portal upload; not yet built |
| 7 | **Case escalation** | Tiered TAC → engineering, severity/SLA driven | Engineering handoff + GitHub linkage (design); reviewer R4/R6 to assess depth | **Behind** | escalation *workflow* is thin in the design; see reviewer findings |
| 8 | **Incident communication** | Status page, advisories, mass comms | Incident state + drafted comms with human approval (design) | **Behind** | no status-page/mass-comm design yet; deferred-appropriate for pilot |
| 9 | **Known-issue handling** | Public known-issue / release-notes DB, searchable | Cloud known-issue matching (design; explicitly cloud-homed, ADR-0013) | **Behind** | designed but unbuilt; norm is mature and public |
| 10 | **Software-release linkage** | Bug ↔ fixed-in-release mapping, upgrade advice | Release linkage in cloud + the appliance's signed release-catalog trust chain (exists) | **Comparable** | the appliance-side release trust chain is unusually strong and shipping |
| 11 | **Role-based support access** | Portal RBAC, entitlement scoping | Three-role RBAC (product, exists) + gateway scope + tenant scoping (design) | **Comparable** | RBAC discipline is a genuine strength |
| 12 | **Audit & privacy** | Compliance pages, data-handling terms | Hash-chained signed audit; source-side redaction; raw≠normalized planes; short raw retention; break-glass | **Ahead (on design rigor)** | the audit + data-governance model is more explicit than most public vendor material; unbuilt |
| 13 | **HA / CP-DP troubleshooting** | Cluster health, HA status, drift tooling | Appliance HA/lease posture (exists) + cluster fan-out + local-vs-cluster discriminators (design, M5) | **Comparable** | the local-vs-cluster discriminator design is a differentiator; instrumentation gaps noted in gap analysis |

---

## 2. Where Culvert is genuinely ahead (and why it's affordable)

The design is **ahead on rigor, not scale**: typed bundle schemas, fail-closed source-side redaction, hash-chained signed audit, outbound-only + E2E recipient encryption, and CI parity walls that make "no config field without redaction/diagnostic coverage" a build-time guarantee. These are **cheap** — they are design discipline and small deterministic mechanisms, not large infrastructure — so a small team can hold a bar that large vendors reach with headcount. This is exactly the "smaller deterministic system giving equivalent value" the task asks for.

## 3. Where Culvert is behind (and correctly so for now)

Customer-facing portal UX, case-status visibility, incident communication, and a searchable known-issue base are all **behind** — but each is a *build-out* item, not an architectural gap, and each is either scheduled (cloud track) or deferred by budget. None implies a rewrite. The most important "behind" for enterprise credibility is **customer-facing status/portal UX** (reviewers R4/R5 focus).

## 4. Deferred vs missing (the honest distinction)

- **Intentionally deferred (defensible):** broad telemetry (M7), status-page/mass-comms, advanced SSO, multi-region — all gated behind scale triggers.
- **Behind but on the roadmap:** portal, case status, known-issue DB, escalation depth — cloud track.
- **Not publicly verifiable (so not scored against):** any vendor's internal analyzer tooling, internal case-routing, or private telemetry pipelines — explicitly not compared.

## 5. Benchmark verdict

Against public, observable practice and **weighted for a small team/budget**, the Culvert TAC design is **Comparable-to-Ahead on security/audit/bundle rigor** and **Behind on customer-facing support operations UX**, with the gaps being build-out rather than architecture. A mature vendor would recognize the *bones* as credible and, in several places, more disciplined than a conventional support-bundle platform — while noting that the customer-facing and workflow layers are the unfinished, higher-effort half. No benchmarked capability requires abandoning the architecture.
