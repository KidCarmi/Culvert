# Support Analysis-Location Decision — Local vs Hybrid vs Cloud-First

- **Status:** Decision record (design). This is the **gating validation** required before the architecture is revised; ADR-0012 ratifies its outcome.
- **Date:** 2026-07-13
- **Owner:** Principal Supportability Architect
- **Question:** Where does support *analysis* execute — on the Culvert appliance, split, or in the cloud-hosted TAC platform? Collection, classification, redaction, consent, and encryption are **local by necessity** (they touch customer data and the customer network); the open question is *analysis*: verification, deterministic analyzers, timeline correlation, known-issue matching, AI-assisted diagnosis.
- **Non-negotiable context:** Culvert is an on-prem, egress-critical security appliance. Normal proxy enforcement, config, and availability must never depend on the cloud. The cloud can never initiate a connection into Culvert.

---

## 1. The three models

| Model | Appliance does | Cloud does |
|---|---|---|
| **1. Full local** | collect + classify + redact + **verify + deterministic analysis + timeline + known-issue DB + correlation + AI** | nothing (or thin case tracking) |
| **2. Hybrid** | collect + redact + **some analyzers + partial correlation**; cloud does the rest | heavy analyzers, cross-fleet matching, AI |
| **3. Cloud-first** (proposed) | collect + classify + redact + preview + consent + manifest + encrypt + **outbound upload**; plus *existing* lightweight local health/OperatorContract and active evidence probes | verify + extract + deterministic analysis + timeline + correlation + known-issue + AI + workflow + escalation |

---

## 2. Decision matrix

Scores 1 (worst) – 5 (best) per dimension per model, each with repository evidence. Equal weights; the outcome is not close enough for weighting to change it.

| # | Dimension | Full local | Hybrid | Cloud-first | Evidence / rationale |
|---|---|:--:|:--:|:--:|---|
| 1 | Appliance CPU | 1 | 3 | 5 | Analyzers/known-issue matching/AI are CPU-heavy; the appliance is sized for the proxy relay path, not batch analysis. |
| 2 | Appliance memory | 1 | 3 | 5 | A local known-issue DB + log-correlation indexes + model weights would dwarf the proxy's own footprint (`/api/dashboard/health` shows the process tracks memstats precisely because RAM is scarce). |
| 3 | Appliance disk I/O | 2 | 3 | 4 | Local analyzers need on-disk DBs/indexes on the single `/data` volume; cloud-first writes only bounded bundles + short retention. |
| 4 | Effect on proxy hot path | 1 | 3 | 5 | The codebase obsessively protects the CONNECT/relay hot path (read-only `upstreamTransport`, pooled 128 KB relay buffers, lock-free histogram, sharded limiter). A co-resident analyzer competes for CPU/GC and is the single biggest risk to egress latency. **Decisive.** |
| 5 | Implementation complexity (appliance-weighted) | 1 | 2 | 4 | Full-local means building analyzers, a known-issue store, correlation, and AI *on a constrained, security-critical box*. Cloud-first keeps the appliance thin; complexity lives where it is cheap to build and iterate. |
| 6 | Analyzer update velocity | 1 | 3 | 5 | Updating a local analyzer means a signed, digest-pinned appliance release (release-catalog + maintenance-agent path is deliberately heavy). Cloud analyzers redeploy in minutes. |
| 7 | Version drift | 1 | 2 | 5 | Local analyzers fork per appliance version → an N-version analyzer support matrix. Cloud runs one analyzer version against a **versioned bundle format** (`csb/1`). |
| 8 | Offline behavior | 5 | 4 | 2 | Full-local analyzes with no network. Cloud-first defers analysis until upload — **but local health/OperatorContract and offline export remain**, so it is 2, not 1 (§4). |
| 9 | Privacy | 5 | 3 | 4 | Nothing leaving is strictly most private. Cloud-first is close: source-side fail-closed redaction + mandatory consent + E2E encryption + AI-sees-normalized-only. Hybrid is worst-of-both (data leaves *and* more local surface). |
| 10 | Cloud dependency | 5 | 3 | 2 | Cloud-first depends on the cloud for the *analysis value-add only* — **never for product operation** (the load-bearing invariant, ADR-0015). So 2, not 1. |
| 11 | Operational cost | 2 | 2 | 4 | Full-local pays per-appliance compute + an analyzer support matrix. Cloud-first centralizes elastic compute (you do run a cloud). |
| 12 | Support accuracy | 2 | 3 | 5 | Local analyzers are stale, compute-bound, and blind to other customers. Cloud gets fresh analyzers, cross-fleet known-issue matching, real compute, and engineering linkage. |
| 13 | Incident correlation | 2 | 3 | 5 | The audit found correlation is exactly what a single node cannot do well: CP has no per-DP applied-version view, bounded audit ring (500), 60-min metric ring. Cross-node/cross-time/cross-customer correlation needs the cloud's full corpus. |
| 14 | Community support | 2 | 3 | 5 | Community gets only what's baked locally. Cloud-first gives community the *same pipeline* with automated analysis, gated by entitlement policy. |
| 15 | Enterprise support | 2 | 3 | 5 | SLA, human TAC ownership, escalation, and case management are inherently cloud/central functions. |
| 16 | Air-gapped customers | 5 | 4 | 3 | Full-local works fully offline. Cloud-first supports air-gap via offline export → manual transfer → cloud ingest, plus local health — so 3, not 1 (§4). |
| 17 | Security blast radius | 2 | 2 | 4 | Full/hybrid put analyzers + a known-issue DB + AI + untrusted-bundle parsing **on the customer's egress-critical appliance**. Cloud-first shrinks the appliance to collect/redact/encrypt/upload (outbound-only) and isolates analyzer blast radius in ephemeral cloud sandboxes. |
| | **Total (85 max)** | **40** | **49** | **72** | |

---

## 3. Recommendation

**Adopt Model 3 — cloud-first analysis with local collection and security controls only.** It wins 72 vs 49 vs 40 and dominates every dimension that matters for a security appliance: hot-path safety, update velocity, version drift, correlation, accuracy, and blast radius. The four dimensions where local wins — offline (8), privacy (9), cloud-dependency (10), air-gapped (16) — are all mitigated by the design invariants below, so they do not overturn the result.

The appliance is a **secure evidence producer and transmitter**, not an analyzer. All heavy analysis, correlation, known-issue matching, AI, and TAC workflow live in the cloud-hosted TAC platform (`TAC-CLOUD-ARCHITECTURE.md`).

---

## 4. Challenge: does any analyzer have to run locally? (evidence review)

The expected direction is cloud-first; the instruction is to challenge it if the repository shows a meaningful local-analysis need. It does **not** show one — with one honest, correctly-classified exception that is *collection, not analysis*:

**A. Lightweight health / `OperatorContract` stays local — because it must survive cloud loss, and it already exists.**
`diagnostics.go`'s `buildOperatorContract` is side-effect-free, cheap, and already produces per-check status + remediation. The requirement "if TAC Cloud is unavailable, health diagnostics remain available locally" *mandates* keeping this local. It is not an "analyzer framework"; it is ~20 bounded posture checks the product already ships. **Verdict: keep local; do not grow it into a general analyzer.**

**B. Active evidence probes stay local — because the cloud has zero network reach into the customer environment.**
`diagnose dns|tls|upstream|storage|policy` must execute *from the appliance's network position*: only the appliance can resolve the customer's DNS, complete a TLS handshake to an internal origin, read the upstream pool's live circuit state, stat the `/data` volume, or evaluate a policy against live rules. The outbound-only invariant (ADR-0014) means the cloud can never do this. **But these are evidence *collectors* — they gather a fact (DNS→X, TLS alert Y, disk 98% full); they do not interpret it.** The interpretation ("that TLS alert means a client-cert-required origin; here's the runbook") is analysis and stays in the cloud. **Verdict: keep the *probe* local as a bounded collector; keep the *diagnosis* cloud.**

**C. Everything else is cloud.** No repository evidence supports a local known-issue database (would require signed releases to update — evidence: the release-catalog trust chain), local runbook search, heavy log correlation (bounded by the 500-entry audit ring and 60-min metric ring), incident clustering, or local AI (a security appliance is the wrong place to run a model near the hot path, and it would balloon the image + attack surface). **Verdict: cloud-only.**

**Net:** cloud-first, with local execution strictly limited to (A) existing lightweight health and (B) network-position-bound evidence probes — both of which are collection/health, not the "full local analyzer framework" the user rightly wants to avoid. This challenge *strengthens* the cloud-first recommendation rather than weakening it.

---

## 5. Design invariants that make cloud-first safe (each enforced + tested)

| Invariant | Enforcement | ADR |
|---|---|---|
| Normal product operation never depends on the cloud | No cloud call in the proxy/config/enforcement paths; `TestOperationWithoutCloud` | 0015 |
| Cloud can never initiate a connection into Culvert | Outbound-only; no inbound listener for TAC; `TestNoInboundTACSurface` | 0014 |
| Health remains local if cloud is down | `OperatorContract` is in-binary, offline; `TestHealthWithoutCloud` | 0015 |
| No local analyzer framework / known-issue DB / AI | Fitness test: `internal/support` ships no analyzer/DB/model; `TestNoLocalAnalyzer` | 0013 |
| Nothing leaves without redaction + consent | Source-side fail-closed redaction + mandatory preview + explicit consent | 0009 |
| Raw evidence ≠ normalized findings | Encrypted raw stored separately; AI sees normalized by default | 0016, 0018 |
| Offline export + local retry always available | Bundle queues locally; resumable upload; air-gap export | 0017 |

---

## 6. Revised qualification scenarios (cloud-first)

Each scenario is re-cast to show the **local/cloud split** explicitly. The appliance's job ends at "encrypted bundle uploaded (or queued/exported)"; the cloud's job is the diagnosis.

| Scenario | Appliance (local) | TAC Cloud |
|---|---|---|
| **TLS inspection failure** | health check flags `ssl_inspection`; collectors gather cert state, decryption profiles, autoexclude stats; `diagnose tls <host>` probe records the handshake alert; redact→consent→encrypt→upload | verify+extract; deterministic analyzer maps the alert to "client-cert-required origin"; known-issue match; runbook; AI drafts response; TAC approves |
| **Authentication failure** | collect auth diagnostics, redacted IdP config, recent auth_fail request logs; upload | correlate config-version change vs failure onset; match known IdP-misconfig issue; propose fix |
| **Website unreachable** | `diagnose dns/tls/upstream` probes + policy dry-run + blocklist/threat-feed match evidence; upload | interpret which layer blocked; cross-reference threat-feed/known-issue; guidance |
| **High CPU / slow browsing** | goroutine dump (L2/L3, bounded), metrics window, saturation gauges; upload | correlate with a release, config change, or upstream circuit trips; cluster fleet comparison |
| **Update failure** | release/catalog state, agent op logs, rollback history; upload | link to the specific release + known regression; escalate to engineering with GitHub issue linkage |
| **HA inconsistency** | each node uploads its own bundle (role, applied version, lease posture, failover ring); upload | **cloud** computes split-brain / drift / version-skew across the case's node bundles (the correlation the audit showed a single node can't do) |
| **Disk exhaustion** | `diagnose storage` + largest-artifacts evidence (agent); upload | interpret growth source; retention runbook |
| **Cloud unavailable (any scenario)** | health + diagnose probes still answer locally; bundle **queued**; retries later; offline export available | (deferred until reachable) |
| **Air-gapped customer** | full local collect→redact→consent→encrypt→**offline export** to file | customer manually transfers the encrypted bundle to the portal; cloud ingests + analyzes |

---

## 7. Verdict

Cloud-first is the correct model and is now the program's committed direction (ADR-0012). The appliance becomes a thin, hardened, outbound-only evidence producer; the TAC Cloud owns all analysis and workflow. Proceed to revise the architecture docs accordingly — **do not begin implementation until the responsibility split in this document and `TAC-CLOUD-ARCHITECTURE.md` is confirmed.**
