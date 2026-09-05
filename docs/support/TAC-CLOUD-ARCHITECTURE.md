# Cloud-Hosted TAC Operating System — Architecture

- **Status:** Proposed (design). Ratified by ADR-0012 (cloud-first). Companion to `ANALYSIS-MODEL-DECISION.md` (why) and `OUTBOUND-SUPPORT-INTEGRATION.md` (the wire between appliance and cloud — see `SECURE-UPLOAD-ARCHITECTURE.md`).
- **Scope:** the cloud-hosted, secure, **optional** platform that ingests support bundles and performs all analysis, correlation, known-issue matching, AI-assisted diagnosis, and TAC workflow. It is **never** in the traffic path and **never** required for appliance operation.

---

## 1. The three tiers (the correction)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  TIER 1 — ON-PREM CULVERT PRODUCT  (customer environment; fully self-sufficient)│
│  proxy enforcement · config · HA · admin UI · local health/OperatorContract    │
│  NOTHING here depends on the cloud. Removing the cloud changes nothing about     │
│  enforcement, availability, or configuration.                                    │
└───────────────┬────────────────────────────────────────────────────────────────┘
                │  TIER 2 — OPTIONAL OUTBOUND SUPPORT INTEGRATION
                │  collect → classify → redact → preview → CONSENT → manifest →
                │  encrypt → OUTBOUND HTTPS upload (resumable, ret/queue, or offline export)
                │  ▲ the ONLY channel. Always initiated BY the appliance. No inbound path.
                ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│  TIER 3 — CLOUD-HOSTED TAC OPERATING SYSTEM  (vendor cloud)                      │
│  ingest → verify → sandboxed extract → deterministic analysis → normalized       │
│  findings → timeline → CP/DP+cluster correlation → known-issue/runbook match →   │
│  AI-assisted diagnosis (normalized input) → TAC approval → customer comms →       │
│  engineering escalation → GitHub linkage → incident detection/grouping →          │
│  entitlement/SLA/queue → retention/audit/privacy                                  │
└────────────────────────────────────────────────────────────────────────────────┘
```

**Tier boundary rule:** Tier 3 has **no network path into Tier 1**. Every byte flows Tier 1 → Tier 3, appliance-initiated, over authenticated HTTPS. The cloud's only "request" to an appliance is a **policy the appliance polls for on its own outbound schedule** (e.g. "TAC would like a fresh bundle for case X"), which still requires local consent/policy before anything is collected or sent (ADR-0014).

---

## 2. Cloud responsibilities (owned exclusively by Tier 3)

Customer & entitlement management · cases and interactions · secure bundle ingestion · encrypted raw storage · sandboxed extraction · deterministic analyzer execution · normalized findings · operational timeline construction · CP/DP & cluster correlation · known-issue matching · runbook matching · AI-assisted diagnosis and response drafting · TAC approval workflow · email intake/delivery · SLA & queue management · engineering escalation · GitHub issue linkage · incident detection & grouping · release linkage · customer notifications · retention/audit/privacy controls.

None of these run on the appliance (ADR-0013). The appliance keeps only lightweight health + evidence probes (`ANALYSIS-MODEL-DECISION.md §4`).

---

## 3. Cloud data planes (raw ≠ normalized — ADR-0016)

Two physically separate stores with different trust, access, and retention:

| Plane | Contents | Encryption | Access | Retention |
|---|---|---|---|---|
| **Raw evidence store** | uploaded `csb` bundles exactly as received (already redacted + E2E encrypted by the appliance) | encrypted at rest under a per-case data key; appliance-side E2E envelope on top | **no standing human access**; only sandboxed extract workers (per-job, audited) and audited **exceptional access** (break-glass, dual-control, logged) | **short** (e.g. 30 days default, contractually adjustable), then hard-deleted |
| **Normalized findings store** | analyzer outputs: typed findings, timeline, correlations, known-issue matches, redacted excerpts approved for reuse | encrypted at rest | TAC engineers per entitlement/case scope; AI (normalized input) | longer (case lifetime + contractual audit window) |

The raw plane is **write-once, read-by-sandbox-only**. Findings are derived in isolated workers and written to the findings plane; TAC and AI work from findings, not raw bundles, by default (§6, ADR-0036).

---

## 4. Ingestion & extraction pipeline

```
upload → [1 gateway: authn + entitlement + size/format gate] 
       → [2 raw store: encrypted, case-scoped, dedup by bundle_id+hash]
       → [3 extract worker (SANDBOX): decrypt → verify integrity → safe untar]
       → [4 deterministic analyzers] → [5 normalize] → [6 correlate] 
       → [7 known-issue/runbook match] → [8 AI draft (normalized)] 
       → [9 TAC workflow] → findings store + case
```

1. **Gateway** — authenticates the appliance (per-appliance credential/mTLS), checks entitlement (community vs paid), enforces size/format/rate limits, verifies the manifest is well-formed **before** accepting bytes. Rejects malformed/oversized/replayed uploads.
2. **Raw store** — the encrypted bundle lands untouched; dedup on `bundle_id`+`bundle_sha256`; no analyzer runs in the ingest path.
3. **Sandboxed extract worker** — an **ephemeral, network-isolated** worker (no route to any customer network, no route to the findings store's write path except its own output queue) decrypts with the per-case key, verifies `bundle_sha256` + per-section hashes + AEAD tag, then untars with hardened extraction (bounded decompression, path-traversal/symlink rejection — reusing the same discipline as `backup.go` restore). Malware/zip-bomb/prompt-injection defenses apply here (§7).
4. **Deterministic analyzers** — pure functions over the extracted, normalized sections (versioned per `csb` schema). This is where the "full local analyzer framework" the appliance must *not* host actually lives — updated by deploying the cloud, not by shipping an appliance release (the update-velocity/version-drift win from the decision matrix).
5. **Normalize** — analyzer outputs become typed `Finding` records with stable codes, severity, evidence references (pointers into the bundle, not raw dumps), and remediation.
6. **Correlate** — timeline construction from the appliance's raw event records; CP/DP + cluster correlation across all node bundles in the case (split-brain, drift, version-skew — the cross-node analysis a single appliance can't do); release linkage.
7. **Known-issue / runbook match** — findings matched against the vendor knowledge base and prior incidents (cross-fleet learning).
8. **AI-assisted diagnosis** — receives **normalized findings + approved evidence excerpts by default**, not raw bundle contents (ADR-0036); drafts diagnosis and customer response for TAC review.
9. **TAC workflow** — approval, customer comms, escalation, GitHub linkage, SLA/queue.

---

## 5. Cloud worker resource budgets

| Worker | vCPU | Memory | Wall-clock | Egress | Isolation |
|---|---|---|---|---|---|
| Gateway | 0.5 | 512 MB | 5 s/request | ingress only | shared, stateless |
| Extract (sandbox) | 2 | 4 GB | 5 min hard | **none to customer nets; output queue only** | **ephemeral, per-bundle, single-use container/microVM** |
| Deterministic analyzers | 2 | 4 GB | 10 min hard | none | ephemeral, per-job |
| Correlation | 4 | 8 GB | 15 min | findings store only | pooled, per-case |
| AI diagnosis | model-dependent | — | bounded | model endpoint only; **no raw store access** | per-request, normalized input only |

Hard caps: decompression ≤ 500 MB per bundle; extraction file-count/path-depth bounded; a worker that exceeds any budget is killed and the bundle flagged for manual review (never silently partial). Workers are stateless and destroyed after each job.

---

## 6. AI boundary (ADR-0036)

- **Default input:** normalized `Finding` records + evidence *excerpts explicitly approved* for AI reuse (already redacted by the appliance and re-checked in normalization). AI never receives the raw bundle by default.
- **Exceptional raw access:** only via audited, dual-control break-glass on the raw plane, never through the AI path.
- **Prompt-injection containment:** bundle-derived text reaching AI is treated as untrusted data, delimited/escaped, and the AI operates under a fixed system policy it cannot be argued out of; AI outputs are **drafts for TAC approval**, never auto-sent to the customer and never able to trigger an action on the appliance (there is no such path — outbound-only).
- **No training on customer data** without explicit contractual consent, tracked as a separate entitlement flag.

---

## 7. Cloud threat controls (summary; full model in `SUPPORTABILITY-THREAT-MODEL.md §cloud`)

| Threat | Control |
|---|---|
| Malicious/oversized/replayed upload | gateway format+size+dedup gate; entitlement + per-appliance auth |
| Decompression bomb | bounded decompression (≤500 MB), file-count/depth caps in the sandbox |
| Path traversal / symlink | hardened untar (traversal/symlink reject) reusing `backup.go` restore discipline |
| Malware in a bundle | sandbox is network-isolated, ephemeral, no exec of bundle contents; AV scan on raw |
| Prompt injection | normalized-only AI input, untrusted-data delimiting, TAC-approval gate, no appliance action path |
| Raw evidence exposure | separate encrypted plane, no standing access, short retention, audited break-glass |
| Cross-tenant leakage | case + tenant scoping end-to-end; per-case data keys |
| Cloud compromise reaching the appliance | **impossible by construction** — outbound-only, no inbound path (ADR-0014) |

---

## 8. Entitlement model (one platform, policy-differentiated — not a separate architecture)

Community and paid appliances use the **same** upload pipeline and the **same** analysis; entitlement policy differentiates *service*, not *code path*:

| Capability | Community | Paid |
|---|---|---|
| Secure upload + automated analysis + known-issue match + automated guidance | ✅ | ✅ |
| Queue priority | ❌ (best-effort) | ✅ |
| SLA | ❌ | ✅ |
| Human TAC ownership | ❌ (best-effort) | ✅ |
| Engineering escalation / incident coordination | ❌ | ✅ |
| Extended raw retention (where contractually approved) | ❌ (short default) | ✅ (contractual) |

Entitlement is evaluated at the gateway and threaded through the workflow; there is **no separate Community system** (ADR requirement). A community appliance is a paid appliance with a leaner policy.

---

## 8.5 Case lifecycle & assignment (STAGE-5 additions — R4-F1, R5-F1/F2)

The qualification board found `case_id` required everywhere but never *issued*, and no case-status surface. Closing that:

- **Case creation:** a customer opens a case from the **customer console** or **in-product** ("Open support case"), which calls `POST /cases {tenant, severity, summary}` → returns a `case_id`. A bundle upload may also **auto-create** a case if none is supplied (the `case_id` becomes a return value, not a prerequisite the admin must find elsewhere). Target: an admin creates a case + uploads in **≤3 steps, no email**.
- **Assignment/routing (no founder bottleneck):** an auto-triage + routing engine assigns each case to a queue by tenant/severity/entitlement and applies known-issue matching **before** any human — so the common path reaches a suggested diagnosis with **`founder_actions == 0`** (acceptance: `TestCommonPathNoFounderAction`). Human TAC ownership is a *routing outcome*, not a manual default.
- **Case status:** `GET /cases/{case_id}` powers an in-product + console **case-status surface** (state, last TAC update, requested evidence, ETA) so "where is my case?" is answerable without email. A **TAC-request inbox** shows any "please send X" asks (which still gate on local consent, ADR-0014).
- **Escalation:** SLA-driven; a second-approver pool (not the founder) satisfies dual-approval; escalation to engineering produces the package below.

## 8.6 Engineering escalation package (STAGE-5 addition — R6-F1)

When a case escalates to engineering, the cloud emits a **versioned escalation package** (not an ad-hoc GitHub comment):

```jsonc
{
  "escalation_id": "ESC-…", "case_id": "…", "schema_version": 1,
  "fault_hypothesis": "product_bug|config|environment|capacity|version_regression|cluster_convergence",
  "product_version": "vX.Y.Z", "build": {…}, "runtime": "compose|k8s", "role": "…",
  "timeline_ref": "findings://…/timeline",          // reference into the normalized findings plane, not raw
  "health_findings": [ { "code":"…","severity":"…","cause_class":"…","locality":"…" } ],
  "evidence_refs": [ { "section":"…","bundle_id":"…","sha256":"…" } ],   // pointers, not raw dumps
  "reproduction": { "steps":[…], "synthetic_input_ref":"…" },
  "rollback_info": { "known_good_version":"…", "available":true },
  "release_linkage": { "suspected_regression_in":"vX.Y.Z" },
  "redaction_tier": "engineering",                    // engineering-tier boundary; still no secrets/raw customer data
  "github_issue": { "repo":"…","title":"…","labels":[…] }               // linkage, created on approval
}
```
The package references the **normalized findings plane** (ADR-0016), carries an **engineering-tier redaction boundary** (more than customer-facing, but still no secrets/raw customer data), and is the artifact the escalation engineer consumes. Acceptance: a **golden escalation package** validates against the schema and reproduces a synthetic bug (`TestEscalationPackageReproduces`).

---

## 9. End-to-end sequence — happy path

```
Appliance                          Tier 2 (outbound HTTPS)              TAC Cloud
─────────                          ────────────────────────            ─────────
health/OperatorContract (local, always)
operator picks scope + window
run collectors ─► classify ─► redact (source-side, fail-closed)
build redaction-report ─► PRIVACY PREVIEW ──────────────────────────────────────────►(shown to customer)
customer CONSENT ✔
build manifest + integrity hashes
encrypt (recipient/HPKE, per-case data key)
                    ── upload.init(case_id, bundle_id, size) ─────────► gateway: authn+entitlement+gate
                    ◄─ 200 {upload_id, chunk_size} ──────────────────
                    ── PUT chunk[0..n] (resumable, offset) ──────────► raw store (encrypted, case-scoped)
                    ── upload.complete(bundle_sha256) ───────────────► verify size/hash → ACK
                    ◄─ signed RECEIPT {case_id,bundle_id,sha256,ts} ─
store receipt in local audit + history
                                                                       sandbox extract ─► verify ─► untar
                                                                       deterministic analyzers ─► normalize
                                                                       timeline + cluster correlation
                                                                       known-issue/runbook match
                                                                       AI draft (normalized) ─► TAC approves
                                                                       customer notification / case update
```

## 10. End-to-end sequence — cloud unavailable (must be graceful)

```
Appliance                                          TAC Cloud
─────────                                          ─────────
proxy enforcement, config, HA, admin UI ── UNAFFECTED ──
local health/OperatorContract ── STILL ANSWERS ──
operator builds bundle ─► redact ─► consent ─► encrypt
                    ── upload.init ──► (timeout / 5xx / DNS fail)   ✗ unreachable
bundle → LOCAL QUEUE (status: queued)
retry with bounded backoff on the appliance's own schedule
offline export remains available (write encrypted .csb to disk/media)
… later …
                    ── upload.init (retry) ──► gateway  ✓  → resume from last chunk
```

## 11. End-to-end sequence — air-gapped

```
Appliance (air-gapped)                             Human courier            TAC Cloud
──────────────────────                             ────────────            ─────────
collect ─► redact ─► consent ─► encrypt ─► OFFLINE EXPORT (.csb.age)
                                   └── file on approved media ──► manual upload to TAC portal ──► gateway → ingest
                                                                  (same pipeline, same entitlement)
```

---

## 12. What this changes vs the prior design

The prior `HEALTH-AND-EVENT-MODEL.md` built the timeline, incident correlation, and cluster discriminators **on the appliance**. Under cloud-first:
- The appliance **emits raw event records** (config-version changes, failover events, cert rotations, crashes) into the bundle; it does **not** construct the correlated timeline.
- The appliance performs **cluster fan-out collection at most** (or, preferably, each node uploads its own bundle); the **cloud** computes split-brain/drift/version-skew across the case's bundles.
- The appliance keeps **lightweight local health** (`OperatorContract`) so health survives cloud loss.
Those docs are re-homed accordingly (see their revision banners).
