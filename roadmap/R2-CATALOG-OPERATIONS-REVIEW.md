# Culvert Release Operations Review

**Lens:** VP Engineering / Director Platform Eng / Director Release Eng / Product
Operations / SRE / Customer Success. **Not** a security-architecture review — the
architecture (untrusted transport, in-binary keyless verification, digest-pinned
dispatch, R2 hosting) is **accepted as-is**. The only question is whether Culvert
can be *operated, released, maintained, and supported* as a commercial enterprise
security product for years — and specifically at **500 enterprise customers**.

Every operational claim is grounded in the actual repo. Where a capability does
not exist today it is marked **[GAP]**; where it is a structural property of the
model it is marked **[STRUCTURAL]**.

---

## 0. The main question, answered first

> **If Culvert had 500 enterprise customers today, would the proposed release
> process still work?**

**The publishing side: yes, effortlessly. The operational model around it: no.**

The reason is one structural fact that dominates this entire review:

> **Culvert is self-hosted and PULL-BASED. Each customer runs their own Control
> Plane that independently fetches a public, signed catalog and an operator
> confirms each update. There is NO vendor-operated fleet and NO telemetry channel
> back to the vendor.** (Confirmed in-repo: `release_dispatch*.go` is
> operator-confirmed per-CP; `update.go`'s reports are written **locally**
> (`apiUpdateReports`, `update.go:743`); every `heartbeat`/`report` path is
> **intra-cluster** CP↔DP within one customer (`enrollment.go`, `update_cluster.go`),
> never vendor-bound. `metrics.go` is a **local** Prometheus surface.)

This cuts both ways and is the crux of the whole review:

- **Why it scales (the good):** publishing is a single static signed artifact on a
  CDN. 10 customers or 50,000 customers pull the *same* object. There is **zero
  per-customer state on the publish side** — the release process's cost is
  **O(releases)**, not **O(customers)**. At 500 customers the R2 publish pipeline
  is *identical* to 5 customers. This is the architecture's greatest operational
  strength and it is real.
- **Why the *operations* break (the gap):** the vendor has **no visibility and no
  control** past the CDN edge. At 500 customers you cannot answer "what version is
  the fleet on?", "did the CVE fix land?", "which customers are failing to
  update?", or "roll 5% first" — because there is no fleet data and no way to
  target or force uptake. The release *process* (publish) works; the release
  *operations* (observe, drive, support, prove) do not exist yet.

So the honest verdict: **the pull-based static-catalog model is the RIGHT
foundation and scales beautifully, but three operational layers are missing and
must be built before 500 enterprise customers is a supportable business:**

1. **Fleet observability** — an *opt-in, privacy-preserving* health/telemetry
   channel (a security product cannot force phone-home; many customers air-gap).
2. **A vendor Release Console** — so PM/RE run releases without touching JSON,
   tags, R2, or CI by hand.
3. **Uptake control** — wiring the (currently unwired, RB-3) client refresher and
   an *opt-in* auto-apply so the vendor can actually drive rollout and emergency
   uptake instead of hoping each operator clicks "apply."

**At 500 customers today you would fly blind, be unable to prove CVE remediation
reached the fleet, and support would be purely reactive.** None of these is a
scale-of-load problem — they are missing capabilities. Build those three and the
model scales to 5,000+ without redesign.

---

## 1. Release Operations — the lifecycle

### Current state (grounded)

```
Dev (merge to main) → CI validates → auto-tag bumps patch, waits for BOTH gates,
pushes v* → tag build: images pushed+signed, catalog gen+gated+signed, attached +
(proposed) published to R2 stable → each customer CP pulls the catalog → operator
confirms dispatch → agent pulls digest, restarts, verifies.
```

What exists: `ci.yml` (build/sign/gate/tag), the signed catalog, per-CP dispatch
(`release_dispatch*.go`), intra-cluster rolling update (`update_cluster.go` —
canary→soak→error-budget, but **within one customer's cluster**, not across
customers). What does **not** exist: RC/Beta rings (stable-only chosen), a
promotion console, release-note generation, EOL signaling, and any cross-customer
rollout/observability.

### Lifecycle assessment

| Stage | Today | Verdict / change |
|---|---|---|
| **Development** | merge→CI→auto-tag | ✅ mature; keep |
| **Release Candidate** | none (stable-only) | **[GAP]** RC exists only as pre-release tags; fine for launch, but add a `beta` ring before you have design partners who need pre-GA. Defer, don't skip. |
| **Beta** | none | **[GAP]** needed for staged confidence once you have telemetry to judge beta health. Sequenced *after* observability, not before. |
| **Stable** | the one ring | ✅ correct initial choice |
| **Hotfix** | new patch tag through the same pipeline | ✅ works; needs an *expedited* gate path (§4) |
| **Rollback** | forward-supersede at a higher `catalog_version` (the floor forbids down-versioning) | ✅ correct *mechanism*, but **[GAP]** it's a manual CI dispatch today; must become a one-click console action, and its *reach* depends on refresh being wired (RB-3) |
| **End of Life** | none | **[GAP]** no EOL/deprecation signal in the catalog. Enterprises need "this version is EOL on DATE" to plan. Add an additive `eol_at`/`supported_until` field + a dashboard countdown. |

**Change I would make:** treat **freshness re-sign** and **EOL** as first-class
lifecycle events, not afterthoughts. The 90-day expiry foot-gun (raised to 180d +
weekly re-sign) means the *release calendar has a heartbeat even when no software
ships* — that heartbeat is an operational asset (prove liveness, carry EOL
notices), not just a security chore.

---

## 2. Product Manager workflow

**Principle (from the brief, endorsed): the PM makes product decisions and
touches nothing else — never JSON, manifests, digests, R2, Actions, or
Cloudflare.** Today there is **no PM surface at all [GAP]**; release ops = git
tags + CI + per-customer operator dispatch. This is greenfield.

### Target PM workflow (a vendor-side "Release Console")

```
CREATE RELEASE ──► REVIEW ──► APPROVE ──► PROMOTE ──► MONITOR ──► COMPLETE
   (select)        (evidence)  (1 click)   (ring/%)    (health)   (auto)
```

| Step | PM does | System does (automated) | PM never touches |
|---|---|---|---|
| **Create** | picks the build to release (a green `main` SHA / RC), writes/edits the human release-note prose | assembles the spec from the *pushed digest*, generates the catalog, runs the gate, signs | the digest, `list_digest`, `catalog_version`, `manifest_sha256`, R2 keys |
| **Review** | reads the auto-assembled evidence card (§3) | shows: gate results, image signature identity, SBOM, provenance, changelog diff, catalog freshness, what-changed-since-current | any file |
| **Approve** | one click in the protected `release` environment | records the approval (GitHub Environment review = the audit record) | Actions YAML |
| **Promote** | chooses target (stable now; later: ring + rollout %) | publishes to R2 (stage→verify→promote), purges cache, confirms served version | R2 objects, cache API |
| **Monitor** | watches release health (§3) | collects opt-in telemetry, computes success rate, flags failures | telemetry plumbing |
| **Complete** | nothing (or "advance rollout") | auto-marks stable when health SLO holds for the soak window | — |

**Build:** this is a thin internal web app over three data sources — the catalog
(R2), CI/Rekor (evidence), and the opt-in telemetry service (health). It is the
single highest-leverage operational investment. Until it exists, "the PM only
makes product decisions" is aspirational — today a PM (or an engineer proxying for
them) must cut a git tag and dispatch a workflow, which is a release-engineering
defect by the brief's own standard.

**Callout — where the proposal still forces manual editing:** the current plan's
`catalog-revoke` and `catalog-resign` are `workflow_dispatch` jobs a human
triggers with inputs — acceptable for launch, but they must be **wrapped by the
console** (a "Revoke" and "Re-sign" button) before 500 customers, or PMs/engineers
will be hand-entering `release_id`s into Actions, which is exactly the failure the
brief forbids.

---

## 3. Release dashboard specification

Two audiences, two dashboards. **The customer-side one largely exists; the
vendor-side one is greenfield and is gated on telemetry.**

### 3a. Customer-side (per-CP) — exists, extend

`/api/releases` already surfaces `available`, `verify_mode`, `trust_schemes`,
`catalog_version`, `expires_at`, `generated_at`, releases, channels
(`release_api.go`), and the admin UI has a Release Management panel
(`static/index.html`). **Extend with:** current running digest vs. offered,
catalog freshness countdown, last refresh time + outcome, rollback availability
(the recorded anchor digest), and a clear "up to date / update available /
catalog stale / catalog unavailable" state.

### 3b. Vendor-side Release Console — greenfield [GAP], telemetry-gated

| Tile | Source | Available today? |
|---|---|---|
| Current Stable / Beta / RC (version + digest) | R2 catalog + `.well-known` | ✅ from the catalog |
| Catalog Version (per ring, monotonic) | R2 catalog | ✅ |
| Signing Status (identity, Rekor entry, verify-back green) | CI + Rekor | ✅ |
| SBOM Status (present, signed) | CI artifacts | ✅ |
| Catalog Freshness (days to `expires_at`, last re-sign) | R2 catalog | ✅ |
| Pending Promotion (RC awaiting approval) | console state | ✅ once console exists |
| Emergency Status (active revocation/CVE banner) | console state | ✅ once console exists |
| **Release Health (update success/fail rate)** | **opt-in telemetry** | **❌ [GAP] — no telemetry channel** |
| **Customer / Fleet Adoption** | **opt-in telemetry** | **❌ [GAP] [STRUCTURAL]** |
| **Fleet Version Distribution** | **opt-in telemetry** | **❌ [GAP] [STRUCTURAL]** |
| **Failed Updates (who, why)** | **opt-in telemetry** | **❌ [GAP]** |
| **Current Rollout (%, cohort health)** | **telemetry + rollout field** | **❌ [GAP], both unbuilt** |
| **Rollback Availability (fleet)** | **opt-in telemetry** | **❌ [GAP]** |
| **Update Success Rate (trend)** | **opt-in telemetry** | **❌ [GAP]** |

**The honest headline: 6 of the 16 requested tiles are computable today from the
catalog + CI + Rekor. The 7+ tiles that require *fleet* data (adoption, version
distribution, failed updates, rollout health, success rate) are impossible without
an opt-in telemetry channel that does not exist — and that a meaningful fraction of
enterprise security customers will decline or air-gap.** Design the console to
**degrade gracefully**: show catalog/signing/freshness always; show fleet metrics
as "coverage: N% of customers reporting" so a partial (or zero) telemetry
population is honestly represented, never faked.

### The telemetry design (the missing keystone)

- **Opt-in, aggregate, privacy-first.** A "release health beacon": on update
  outcome, a CP *may* POST a minimal, anonymized record (anonymous install-id,
  from/to `catalog_version`, outcome, error-class, arch) to a vendor endpoint.
  **Default off; per-customer consent; documented data schema; no PII, no policy,
  no traffic data.** A security product must earn this, not assume it.
- **Air-gap path:** the CP can **export a signed health bundle** the customer
  hands the vendor through their existing support channel — same schema, offline.
- **This is the single capability that turns "we publish and hope" into "we
  operate a release channel."** Everything in §3b that's ❌ becomes ✅ once it
  exists — for the reporting population.

---

## 4. Emergency operations — critical CVE

**Scenario:** a critical CVE in Culvert is public; a fix is built.

### Target timeline (with the console + wired refresh + opt-in auto-apply)

| T+ | Action | Auto / Manual |
|---|---|---|
| 0:00 | CVE confirmed; incident opened; fix branch cut | Manual (eng) |
| 0:30 | Fix merged; **expedited hotfix pipeline** (full gates, no RC soak) runs | Auto |
| 1:00 | Images built+signed, catalog gen+gated+signed | Auto |
| 1:05 | PM sees the hotfix in the console with `severity: critical`; **one-click approve** | Manual (PM/security lead approval — the only gate) |
| 1:10 | Publish to R2 stable (stage→verify→promote), cache purged, verify-back green | Auto |
| 1:15 | `critical` channel points at the fix; **customer CPs on wired refresh pull within the refresh interval (~1h)**; opt-in auto-apply customers update automatically; others get a prominent "critical update available" banner | Auto (pull) + Manual (operator apply, unless auto-apply opted in) |
| 1:15 | **Customer comms:** advisory email/portal/RSS with CVE id, fixed version+digest, and "update now" instructions | Manual (trigger) / templated |
| 2:00+ | Console tracks adoption via telemetry; chase non-updated high-value customers via CustSuccess | Auto (observe) + Manual (chase) |

### The uncomfortable truths for a CVE at 500 customers

- **Mean-time-to-fleet-patched is customer-controlled, not vendor-controlled.**
  Apply is operator-confirmed; refresh isn't even wired today (RB-3). **You can
  publish a fix in ~75 min; you cannot make 500 customers *apply* it.** Without
  (a) wired refresh and (b) opt-in auto-apply for critical severity, "emergency
  fix" means "emergency *availability* of a fix," not "emergency remediation."
- **You cannot prove remediation without telemetry.** A CVE response you can't
  measure is a CVE response you can't close out with customers, auditors, or your
  own board.
- **Revocation ≠ recall.** `catalog-revoke` (forward-supersede) stops *offering*
  the bad build to CPs that pull afterward, but a CP that already applied it is
  only fixed by pushing the *next* version — which again depends on uptake.

**Required for a credible enterprise CVE story:** expedited-but-full-gate hotfix
lane + console one-click approve + wired refresh + **opt-in auto-apply for
`critical` severity** (a deliberate, per-customer setting) + a customer-comms
mechanism + telemetry to measure uptake. Today only the build+sign+publish half
exists.

---

## 5. Failure operations

For each: **detected / who notices / who responds / automated / manual / max
acceptable downtime.** The recurring good news is the **fail-safe design**: the
catalog is *not on the proxy hot path*, so release-channel failures never take a
customer's proxy down — they only pause *updates*.

| Failure | Detected by | Who notices | Auto | Manual | Max downtime |
|---|---|---|---|---|---|
| **Cloudflare/R2 unavailable** | external verify canary [GAP-must-build] + CF status | vendor SRE | edge ret/caching absorbs blips; CPs keep last-good catalog | failover to secondary origin [GAP until built]; re-serve `history/` | Updates paused: hours OK (proxy unaffected). **[GAP]** no canary today → *undetected* until a customer reports |
| **GHCR unavailable** | pull failures on apply | customer operator | agent retries; digest verify intact | wait / mirror | Pauses *updates* only; hours OK. Public images → any customer can mirror |
| **GitHub unavailable** | CI can't run/tag | vendor eng | none | wait; GitHub is not in the customer runtime path | Blocks *new releases*, not customers. Hours OK |
| **Signing (Fulcio/Rekor) unavailable** | CI sign step fails | vendor eng | CI fails closed (no unsigned publish) | wait; ed25519 escape hatch if built | Blocks new releases; existing catalog verifies offline. Hours OK |
| **Telemetry unavailable** | console coverage drops | vendor ProdOps | none | none needed | Cosmetic — no customer impact (once built) |
| **Update/catalog server unavailable** | = R2 case | customer operator | last-good served | secondary origin | Updates paused; proxy fine |
| **Release interrupted (mid-publish)** | CI red + verify-back fail | vendor eng | stage→verify→promote leaves live pointer intact on failure | re-run — **BUT [BLOCKER RB-2]** wall-clock spec + create-only history can *wedge* a version on re-run; must fix determinism first | Minutes; must not wedge |
| **Promotion interrupted** | console + verify-back | vendor PM/eng | live pointer only flips after verify | re-promote | Minutes |
| **Rollback interrupted** | console | vendor eng | forward-supersede is idempotent-ish once deterministic | re-run | Minutes |
| **Operator mistake (wrong build promoted)** | verify-back green but *wrong* content; caught by human/telemetry | vendor PM | none | revoke → supersede with correct build | Minutes to publish; uptake is customer-paced |

**Biggest failure-ops gap: there is no external verify canary or alerting on the
release channel today [GAP].** At 500 customers you cannot learn about an R2/edge
problem from customer tickets — you need a synthetic monitor that fetches + verifies
every ring every few minutes and pages SRE. This is cheap and mandatory.

---

## 6. Customer operations

| Task | Today | Enterprise-happy? |
|---|---|---|
| **Install** | `scripts/install.sh` quick-start; seeds pinned image; wires the maint agent | ✅ solid; self-hosted autonomy is a *selling point* |
| **Update** | operator confirms dispatch in the Release panel; agent pulls digest, restarts, verifies | ⚠️ works, but **fully manual per update**; no scheduled/auto option → toil at scale on the *customer* side |
| **Rollback** | manual `rollbacks` with the recorded anchor digest | ⚠️ mechanism exists; **[GAP]** not a one-click guided flow |
| **Mirror updates** | air-gap repo-rewrite design (P1.6 §4) + public images = easy mirroring | ✅ good for enterprises with a private registry |
| **Air-gap updates** | signed bundle import design; offline verification (baked root) | ✅ genuinely strong — a differentiator for security buyers |
| **Pin versions** | digest-pinned by construction; operator chooses when to move | ✅ |
| **Disable updates** | don't set the catalog URL / don't dispatch | ✅ but implicit; **[GAP]** make it an explicit, auditable setting |
| **Recover** | fail-closed (proxy stays up); re-seed catalog; re-serve history | ✅ good posture; **[GAP]** needs a written customer runbook |
| **Support** | reactive; vendor is blind without telemetry | ❌ **the weak point** — see below |

**Would enterprise customers be happy?** On *autonomy, air-gap, pinning, and
fail-safety* — yes, and these are competitive strengths for a security product.
On *update UX and support* — not yet: updates are manual toil on their side, and
when something goes wrong the vendor has no data to help them. **Enterprise
Customer Success requires either telemetry (opt-in) or a first-class "generate a
support bundle" export** so a customer can hand the vendor a signed snapshot of
catalog state, running digest, and update history. That export is small, offline,
privacy-safe, and should exist regardless of telemetry.

---

## 7. Engineering operations

| Task | Today | New-engineer-safe? |
|---|---|---|
| Create a release | merge→auto-tag, or cut a `v*` tag | ⚠️ tag mechanics are tribal knowledge; **console makes it safe** |
| Promote | (stable-only: none) / dispatch a workflow | ⚠️ manual; console-ify |
| Generate release notes | **[GAP]** manual; `changelog_url`/`notes` fields exist but nothing populates them | ❌ automate from conventional-commit PRs (`git-cliff`/`release-please`) |
| Verify a release | `TestReleaseCatalogGate` / keyless verify in CI | ✅ strong; **[BLOCKER RB-4]** the *served*-verify test doesn't exist yet |
| Monitor a release | **[GAP]** none (no canary, no telemetry) | ❌ |
| Hotfix | new tag through the pipeline | ⚠️ needs an expedited lane (§4) |
| Handle a failed deploy | fail-closed; re-run | ⚠️ **[BLOCKER RB-2]** re-run can wedge a version — fix determinism |
| Remove a bad release | `catalog-revoke` dispatch | ⚠️ manual inputs; console-ify |
| Audit changes | GitHub Environment approvals + Rekor + audit ring (customer-side) | ✅ good primitives; **[GAP]** no single vendor-side release audit trail |

**Could a new engineer safely do these today? Mostly no** — too much is
tribal git-tag choreography with sharp edges (RB-1 concurrent writers, RB-2
wedge-on-rerun). The fixes are cheap and the console turns "safe only for the
person who built it" into "safe for any engineer."

---

## 8. Automation review

| Manual task today | Classification |
|---|---|
| Cutting/moving `v*` tags by hand | **Should never be manual** → auto-tag exists; enforce ruleset, remove human tag-pushing |
| Entering `release_id`/version into revoke/resign `workflow_dispatch` | **Should never be manual** → wrap in the console |
| Writing release notes | **Can automate now** → conventional-commit generation |
| Choosing *what* to release / *when* to promote / CVE severity call | **Must remain manual** (product/security judgment) |
| Approving a promotion | **Must remain manual** (the one human gate — GitHub Environment review) |
| Cloudflare provisioning, cache rules, bucket policy, custom domain, GitHub env protections, `v*` ruleset, monitors | **Should be IaC** (see below) |
| Reacting to an R2/edge outage | **Can automate detection now** (verify canary + page); response stays human |
| Chasing non-updated customers | **Can automate later** (telemetry-driven CustSuccess prompts) |

**Smallest operational platform that removes repetitive work (do NOT overbuild):**
1. **The Release Console** (thin app over catalog + CI + telemetry) — removes all
   JSON/tag/R2 hand-editing. Highest leverage.
2. **Opt-in telemetry + support-bundle export** — removes "we're blind."
3. **A verify canary + alerting** — removes "we learn from tickets."
4. **Release-note generation** — removes a recurring manual write.

That's it for launch. Everything else (multi-ring, percentage rollout, per-product
consoles) is deferred until data justifies it.

### IaC recommendation (smallest practical)

**Yes, put the infra under code — but the *smallest* footprint.** Use the
**Terraform Cloudflare provider** for the durable, security-relevant config that
must not drift: R2 bucket + policy, custom domain, cache rules, WAF/rate-limit,
and (via the GitHub provider) the protected `release` environment + `v*` tag
ruleset + required checks. Keep object *uploads* out of Terraform — those are the
CI publish job's responsibility (`aws s3`/`wrangler`), not IaC. **Rule of thumb:
Terraform owns the *guardrails* (buckets, domains, rules, env protections);
the pipeline owns the *artifacts*.** This is a few hundred lines, reviewable,
and it makes GATE-A's "verify the ruleset, don't assume it" a `terraform plan`
diff instead of a manual attestation. Do **not** adopt a heavier control plane
(Crossplane, a bespoke operator) at this stage — it's overengineering for one
bucket and one zone.

---

## 9. Scale review

| Customers | Publish pipeline | Observability | Support | Rollout control | Verdict |
|---|---|---|---|---|---|
| **10** | trivial | tolerable to be blind (you know them by name) | white-glove, manual | manual is fine | Works today |
| **100** | trivial (same object) | blindness starts to hurt; can't answer "who's exposed?" | linear, still human | manual chasing painful | **Telemetry becomes necessary** |
| **500** | **still trivial** (CDN static artifact, O(releases)) | **blind = unacceptable**; can't prove CVE uptake | **linear support cost = the bottleneck**; reactive | can't do phased rollout without the `rollout` field | **Publish scales; ops do not — build the 3 keystones** |
| **5,000** | **still trivial** | must be automated + SLO'd | must be self-serve + telemetry-triaged or it's a cost sink | percentage rollout + auto-apply essential | **No publish redesign needed; ops platform must be mature** |

**What breaks operationally at scale: not the pipeline — the *human* loops around
it.** Support cost is **O(customers)** and, without telemetry, is *reactive and
blind*, which is the classic way a security vendor's margins and NPS both erode.
**What becomes expensive:** R2 egress is negligible (small JSON behind a CDN;
manifests immutable/cached) — the expensive thing is **people** doing blind support
and manual release choreography. **What requires redesign: nothing in the publish
architecture** — that's the whole point of pull-based static hosting. The redesign
is *adding* the operational layer, not changing the core.

---

## 10. Five-year, multi-product review (SWG · CDR · Browser · Agent · DLP · Zero Trust)

**Can this release platform support all six products? Yes — the *operational
model* generalizes cleanly, because it's pull-based and per-artifact.** Each
product becomes:

- its own **catalog namespace** under the same R2 domain
  (`catalog.culvertlabs.com/<product>/<ring>/…`), each independently signed with
  the same keyless identity scheme;
- its own **image repo** + digest-pinned dispatch;
- the **same** console, telemetry, canary, and IaC — parameterized by product.

**What does NOT generalize for free (redesign the operational model here):**

1. **One console, many products** — the console must become product-aware (a
   release is `{product, version, ring}`), and the dashboard must roll up fleet
   health *per product*. Build it multi-product-shaped from day one even while
   only SWG ships, or you'll refactor later.
2. **Dependency & compatibility matrix** — Agent + Browser + DLP interoperate; a
   release is no longer a single artifact but a *compatible set*. You'll need a
   **compatibility/bundle concept** (which Agent works with which Browser) — the
   catalog `min_upgrade_from` field is the seed, but cross-product compatibility
   is new. **This is the real five-year operational redesign**, and it's a
   *metadata + console* problem, not a hosting problem.
3. **Telemetry schema per product** + unified fleet view.
4. **Support taxonomy** scales combinatorially across products — invest in
   self-serve + telemetry triage early.

**Verdict: the R2/signing/pull foundation carries all six products with no
architectural change. The operational model needs exactly one addition —
product-and-compatibility awareness in the console + catalog metadata — and it
should be designed in now, not retrofitted.**

---

## Deliverables

### 1. Executive verdict

**Conditionally viable, and on the right foundation.** The pull-based, signed,
static-catalog architecture is genuinely enterprise-grade and scales to 5,000+
customers with **no publish-side redesign** — a real strength. But Culvert today
has a strong *release pipeline* and an *immature release operation*. At 500
customers the pipeline works and the operation does not: **you would fly blind on
fleet health, be unable to prove CVE remediation, drive no rollout, and support
reactively.** Ship-worthy for a first cohort of design-partner enterprises;
**not** ready to *operate* 500 without three additive keystones: **(1) opt-in
telemetry + support-bundle export, (2) a vendor Release Console, (3) wired refresh
+ opt-in auto-apply for critical.** None requires touching the accepted
architecture.

### 2–6. Maturity scores (operational lens, 0–10)

| Discipline | Score | One-line justification |
|---|---|---|
| **Operations maturity** | **4** | Publishing solid + fail-safe; but no console, no observability, manual choreography, no canary |
| **Release Engineering maturity** | **6** | Excellent CI/signing/provenance/gates; weak release-ops tooling, manual tags, RB-1/RB-2 correctness gaps, no release notes |
| **Product Operations maturity** | **3** | No PM console, no adoption data, no rollout control — PM cannot yet operate without touching machinery |
| **SRE maturity** | **4** | Strong fail-closed design (proxy never impacted); but no release-channel SLOs, no synthetic canary, no on-call runbook, single-origin DR |
| **Customer Operations maturity** | **5** | Great autonomy/air-gap/pinning/recovery; manual update UX and blind, reactive support |

### 7. Biggest operational risks

1. **Blind at scale** — no fleet visibility → can't prove CVE uptake, can't triage.
2. **Uptake is customer-controlled** — refresh unwired (RB-3) + apply-confirm → the vendor can't drive emergency remediation.
3. **Concurrent-writer / re-run wedge** (RB-1/RB-2) — self-inflicted release outages the moment re-sign + tag builds coexist.
4. **Single-origin DR** — deleting Pages before a tested secondary strands the update channel on one origin.
5. **Support cost is O(customers) and reactive** — the margin/NPS killer.

### 8. Biggest operational bottlenecks

1. **Manual release choreography** (tags, dispatch inputs) — doesn't scale past a few engineers.
2. **No telemetry** — every "how's the fleet?" question is a bottleneck.
3. **Manual per-update operator toil on the customer side** — friction that slows uptake and generates tickets.
4. **No release-note automation** — recurring manual write on the critical path.

### 9. Manual work that should disappear

Hand-cutting/moving tags; entering `release_id`/version into revoke/resign
dispatches; writing release notes; hand-provisioning Cloudflare/GitHub protections;
learning about outages from tickets. All either console-, generation-, IaC-, or
canary-automated.

### 10. Release dashboard specification

See §3 — customer-side (extend the existing `/api/releases` panel) + vendor-side
console (6 tiles buildable now from catalog/CI/Rekor; 7+ fleet tiles gated on
opt-in telemetry, shown with an explicit "coverage %" so partial data is honest).

### 11. Product Manager workflow

See §2 — Create→Review→Approve→Promote→Monitor→Complete, PM touches only the
build selection, note prose, and the single approval; the console does everything
else; revoke/resign wrapped as buttons.

### 12. Engineering workflow

See §7 — merge→auto-tag→gated build→console-driven promote/verify/monitor; RB-2
determinism + RB-4 served-verify test are prerequisites for "any engineer can do
this safely."

### 13. Emergency response workflow

See §4 — expedited full-gate hotfix lane, one-click PM approve, stage→verify→promote
publish, `critical` channel + wired refresh + opt-in auto-apply, templated customer
comms, telemetry-measured uptake. ~75 min to *publish*; uptake needs the refresh +
auto-apply keystones to be *fast*.

### 14. Daily operations runbook

- Check the **verify canary** dashboard: every ring fetches + verifies, freshness
  countdown healthy, edge serving the expected `catalog_version`.
- Triage any release-channel alerts (verify fail, version regression, R2/edge).
- Review overnight opt-in telemetry: update success rate, new failures by
  error-class; open CustSuccess follow-ups for high-value non-updaters.
- Confirm no catalog is within N days of `expires_at` without a scheduled re-sign.

### 15. Weekly operations runbook

- **Freshness re-sign** runs (or verify the cron did): stable index re-signed with
  fresh timestamps at the **same** `catalog_version` (RB-1 fix), served + verified.
- Review fleet version distribution (telemetry): adoption curve of the latest
  release; flag stragglers/EOL-approaching versions.
- Review release-channel SLOs (publish success, verify-back pass rate, canary
  uptime); rotate any near-expiry infra tokens on schedule.
- Dependency/CVE scan triage for the *next* release.

### 16. Monthly operations runbook

- **DR drill:** fail over to the secondary origin; re-serve `history/` last-good;
  confirm appliances converge. Rotate Cloudflare/purge credentials.
- **Trust hygiene:** confirm the baked Sigstore `trusted_root.json` is not
  approaching expiry (build-time check green); review Rekor identity-monitor
  alerts; exercise the identity-rotation runbook on paper.
- **Access review:** who can approve releases / push `v*` / hold R2 creds.
- **EOL calendar:** publish upcoming EOL notices in the catalog metadata.
- Operational retro: release lead-time, hotfix MTTR, uptake half-life, ticket
  volume by cause.

### 17. Recommended roadmap for operational maturity

**Phase A — Make it safe to run (pre-500, weeks):** fix RB-1 (re-sign doesn't bump
version) + RB-2 (deterministic spec); wire the production refresher (RB-3); ship
the served-verify test (RB-4); stand up the **verify canary + alerting**; put
Cloudflare/GitHub guardrails in **Terraform**. *Outcome: releases can't wedge or
silently fail; outages are detected, not reported.*

**Phase B — Make it operable (the 500 keystones):** build the **Release Console**
(PM never touches machinery; revoke/resign as buttons); ship **opt-in telemetry +
signed support-bundle export**; automate **release notes**. *Outcome: PMs operate
releases; the vendor can see (for the reporting population) and prove fleet health.*

**Phase C — Make it drive (emergency + rollout):** expedited hotfix lane; **opt-in
auto-apply for `critical`**; templated **customer comms**; percentage rollout via
the additive catalog field. *Outcome: the vendor can actually remediate the fleet
fast, and measure it.*

**Phase D — Make it multi-product (five-year):** product-aware console +
per-product catalogs; **cross-product compatibility/bundle metadata**; unified
fleet view. *Outcome: one operational platform for SWG/CDR/Browser/Agent/DLP/ZT.*

**Do NOT build before its phase:** multi-ring beta/dev, per-customer targeting,
heavy fleet-management UI, or a bespoke IaC control plane. Sequence observability
*before* rollout sophistication — you cannot safely stage what you cannot measure.

---

## The five things to internalize

1. **The pull-based static-catalog model is the right call and scales to 5,000+
   with zero publish redesign — that is a genuine strategic asset.**
2. **The vendor is blind by design; a security product must earn telemetry
   (opt-in) — that gap, not scale, is what breaks at 500.**
3. **Publishing a fix is fast; making the fleet *apply* it is not — wire refresh
   and offer opt-in auto-apply or "emergency response" is only half-true.**
4. **A Release Console is the single highest-leverage investment — it is what makes
   "the PM only makes product decisions" real instead of aspirational.**
5. **Fix the two cheap correctness blockers (RB-1/RB-2) before any of this — a
   release process that can wedge itself under its own weekly cron is not
   operable at any customer count.**
