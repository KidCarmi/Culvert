# Culvert Language & Terminology Governance Review — 2026-08-07

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `d2c5a51`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-06.md` (baseline `6a2960eb`). 64 commits separate the two
> reviews, dominated by a new MCP "QUAL-4" node-local Policy subsystem (`mcp_policy.go`,
> `docs/operator/mcp-qualification-policy.md`, a third key — `"policy"` — added to
> `GET /api/mcp/overview`), CHAOS-47 identity-backend-unreachable handling (`auth_backend_health.go`),
> CHAOS-25 HA standby sync-panic containment (`ha.go`), a QUAL-6 MCP Observe acceptance-test harness
> (`internal/mcpacceptance`), a YARA regex-runner refactor, a new "Process Log I/O Backpressure" stat, a
> CDR per-instance circuit-breaker GUI badge, and install-script/docker-compose ClamAV-healthcheck fixes.
> Method: (1) diffed the actual cited lines/identifiers (not just file touches) for every one of the
> nineteen carried-over open findings — T-9, T-11, T-12, T-13 residual, T-16, T-17, T-18, T-21, T-25
> residual, T-29 through T-34, T-36, T-37, T-38, T-39 — against every file each depends on; (2) read the
> new QUAL-4 policy subsystem in full, since it landed directly adjacent to both T-38's and T-39's
> territory (`ui_mcp.go`'s `apiMCPOverview`, the MCP Policy GUI panel), to check whether it touched either
> finding's cited fields or introduced new drift of its own; (3) audited CHAOS-47's alert-naming surface
> end-to-end (wire event string, GUI checkbox, doc comments) against the pre-existing, unrelated "IdP"
> (federated Identity Provider registry) vocabulary; (4) checked the CDR breaker-badge, Process Log I/O
> Backpressure, and MCP-Policy-vs-proxy-Policy areas for collisions and found each internally consistent
> or covered by existing precedent.
> **Companion change:** T-40 (new — CHAOS-47's `idp_unreachable` alert renamed to
> `identity_backend_unreachable`) fixed same-day: brand new this window, zero test dependency on the wire
> string itself (the one test referencing it mocks the function seam, not the literal), zero operator-doc
> references, and the cheapest point to fix is before any deployment or webhook subscription depends on it
> — the same reasoning this program has applied to QUAL-4/T-39 and to T-35 previously. T-38 remains queued
> (unchanged this window, still a pre-existing tested wire field). T-39 is **not** fixed and is now
> **compounded**: QUAL-4 is a fourth independent PR stream reusing "qualification" for a third unrelated
> concept, and the first of the family to put the bare word in front of an admin in the GUI.

---

## Executive Summary

**All nineteen carried-over findings re-verified at the cited-line level; eighteen are unchanged.**
T-38 is confirmed byte-identical (the new QUAL-4 window added a third `"policy"` key to
`GET /api/mcp/overview` but touched neither the `"health"` nor `"inventory"` blocks the finding depends
on). T-11, T-29, T-31, and T-34 each had a dependent file touched this window, but in every case the touch
was unrelated code in the same file (schedule-timezone caching, QUAL-4 config keys, the new CHAOS-47
metrics block, an inline SSRF guard) — the actual cited identifiers are unchanged. T-33 gained a new
*test*-only reference (`internal/mcp/runtime/policy_tenant_test.go`) to `PolicyAction`; the finding's
"zero production consumers" claim is unaffected since the three production files it depends on
(`runtime/policy.go`, `events.go`, `observe.go`) are untouched.

**T-39 is not fixed and is now worse.** This window's QUAL-4 policy subsystem (`mcp_policy.go`,
`config.go:235` `QualificationPolicyFile`, `docs/operator/mcp-qualification-policy.md`) is a *fourth*
independent PR stream that reuses "qualification" for yet another unrelated concept — a node-local
Observe-only policy source file — and it is the first of the QUAL-2/3/4 family to put the bare word
"qualification" directly in front of an admin: `static/index.html:20255`'s MCP Policy panel labels the
active snapshot source `'qualification startup (local Observe evaluation snapshot; not fleet
distributed)'`. That card renders on the `mcp-policies` view — a different tab from the pre-existing
Production Qualification receipt-gate card (`mcp-rollout` view) — so there is still no *same-screen*
collision, but T-39's original "not yet GUI-visible" mitigating factor for the Medium priority no longer
fully holds now that a fourth stream has crossed into the GUI under the same overloaded word. The finding
entry below is updated to reflect this; the priority call is left to whoever owns the next dedicated
naming-decision follow-up, consistent with this program's practice of surfacing evidence rather than
making product-design calls unilaterally.

**One new finding, fixed same-day (T-40): CHAOS-47's `idp_unreachable` alert event collided with the
pre-existing, unrelated "IdP" (federated Identity Provider registry) vocabulary.** Culvert already has a
large, GUI-prominent "Identity Providers" feature (`auth_idp.go`, `static/index.html`'s
`data-view="idproviders"` panel, SAML/OIDC provider wizard) that CLAUDE.md documents as a *different*
subsystem from CHAOS-47's legacy LDAP-bind/OIDC-introspection auth-caching path — the two are even called
out by name as having different cache/poisoning properties. CHAOS-47 itself avoids "IdP" everywhere else
(`diagnostics.go`'s `identity_backend` contract code, the GUI checkbox's own label text "Identity backend
unreachable"), except in the one wire alert-event string. An admin wiring a webhook on `idp_unreachable`
would reasonably expect it to fire on a federated-IdP outage; it never does. Renamed to
`identity_backend_unreachable` (`auth_backend_health.go`, `internal/alerts/store.go`,
`static/index.html:17620`, `diagnostics.go`, `auth_backend_health_test.go`, `CLAUDE.md`) — verified: no
test asserts the literal wire string (the one test mocking this path captures through the
`fireIdentityBackendUnreachableAlert` function-variable seam, not the event name), no operator runbook
references it, and it shipped this window with (per a repo grep) no prior release, so there is no
deployed webhook subscription to break.

**Terminology Health Score: 8.4 / 10** (up slightly from 8.3 — the carried-over backlog held with zero
regressions across a 64-commit window, and this window's dominant new feature caught and fixed its own
drift same-day before any consumer could depend on the collision; offset by T-39 compounding for a fourth
time, which is the strongest evidence yet that this needs a real design decision rather than continuing to
accumulate independent PR streams under the same word).

---

## Wave 1 — Carried-over findings re-confirmed unchanged

`git diff 6a2960eb..HEAD` (64 commits) was checked against every file each of the nineteen open findings
depends on; every finding whose files *were* touched had the actual cited lines/identifiers diffed, not
just the file.

| Finding | Files it depends on | Touched this window? | Collision status |
|---|---|---|---|
| T-9 | export/import + parity-test surface (`exportedAt`) | No | Unchanged |
| T-11 | `policy.go`'s default-action vocabulary, `ui_policy.go` core | `policy.go` touched (48 lines) | Touch is `precomputeSubjectNets`/schedule-timezone caching; zero `allow`/`deny` default-action code touched — unchanged |
| T-12 | Maintenance-Agent `/v1/upgrades/*` wire routes | No | Unchanged |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | No | Unchanged |
| T-16 | ADR numbering (0008–0011) | No | Unchanged |
| T-17 | `decryption_redact_hosts` / `/api/decryption/redaction` | No | Unchanged |
| T-18 | `internal/sealbox.Seal`/`Open` call sites | No | Unchanged |
| T-21 | `cluster_convergence.go`, `configversion.go`'s rollback `cp_version` surface | No | Unchanged |
| T-25 residual | `support_recipients.go` / `support_tac_trust.go` | No | Unchanged |
| T-29 | YAML `rate_limit` (`config.go`/`main.go`) vs. `rate_limit_rpm` (API/wire/metric) | `config.go` touched (13 lines, QUAL-4) | Zero `rate_limit`-adjacent lines — unchanged |
| T-30 | YAML `max_conns_per_ip`/wire `MaxConnsPerIP` vs. `conn_limit_max_per_ip` | No | Unchanged |
| T-31 | `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` | `metrics.go` touched (30 lines) | Touch is the new CHAOS-47 `culvert_auth_backend_*` block; zero ClamAV lines — unchanged |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` overloads "snapshot" | No | Unchanged |
| T-33 | MCP `PolicyAction`/`PolicyReason` mixing three vocabularies (`internal/mcp/runtime/policy.go`, `events.go`, `observe.go`) | No production files touched (0 lines); new *test* file `internal/mcp/runtime/policy_tenant_test.go` references `out.Record.PolicyAction` | A new test consumer, not a new production vocabulary consumer — "zero production consumers today" claim unaffected — unchanged |
| T-34 | SaaS feed status field-name split (`saas_feed_download.go`, `ui_policy.go`) | `saas_feed_download.go` touched (7 lines) | Touch is an inline SSRF scheme/host guard for CodeQL; `failures_since_start`/`syncFailures` split untouched — unchanged |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | No | Unchanged |
| T-37 | "Manual feed sync" naming split across blocklist/SaaS/threat feeds | No | Unchanged |
| T-38 | `ui_mcp.go`, `internal/mcp/adminapi/health.go`, `mcp_inventory.go`, `static/index.html` (`drifted_tools`/`review_required_tools`) | `ui_mcp.go` (+41), `static/index.html` (+82) touched; `internal/mcp/adminapi/health.go`, `mcp_inventory.go` untouched (0 lines) | `ui_mcp.go`'s only change is a third `"policy": mcpPolicyStatus()` key added to `apiMCPOverview`; the `"health"`/`"inventory"` blocks and both field names are byte-identical. `static/index.html` has zero new hits for `drifted`/`review_required` — unchanged |
| T-39 | `internal/mcp/rollout` (Production Qualification), QUAL-2/3 config/docs | QUAL-4 (`mcp_policy.go`, `config.go`, new doc) lands directly in this namespace | **Compounded — see below, not a regression of prior evidence but new evidence of the same collision** |

## Wave 2 — New territory audited this pass (64 commits since `6a2960eb`)

**QUAL-4 (`mcp_policy.go`, the `"policy"` key on `/api/mcp/overview`, the MCP Policy GUI panel) holds
discipline everywhere except the "qualification" word itself.** The subsystem's harder design property —
that the runtime `PolicyProvider`, the `/api/mcp/policy` admin read, and the simulator baseline all read
the identical compiled snapshot from one shared, node-local holder (`mcpPolicy.stores()`,
`ui_mcp.go:38-42`) — is real and correctly wired, matching the single-source-of-truth discipline this
program has repeatedly verified for prior MCP windows. Its state vocabulary (`not_configured` / `loaded` /
`invalid`) is distinct, load-bearing, and does not reuse the `not_started`/`synthetic_non_qualifying`/
`unavailable` evidence-truth vocabulary from the QUAL-2/3 inventory/telemetry read-models — no collision
there. The *only* naming problem QUAL-4 introduces is compounding T-39 (see Findings below): its config
key, error-reason vocabulary, doc title, and now its own GUI card all say "qualification" for a concept
that is neither the pre-existing Production Qualification receipt gate nor the QUAL-2/3 bootstrap fleet.

**CHAOS-47 (`auth_backend_health.go`, CHAOS-25 (`ha.go`), the QUAL-6 acceptance harness
(`internal/mcpacceptance`), and the CDR/Process-Log GUI additions: all clean except the one CHAOS-47
finding fixed this pass.** CHAOS-25's `sync_panics` field / `ha_sync_panic` alert / "Sync faults
(contained)" GUI label are internally consistent and deliberately reuse the pre-existing
`culvert_crash_records_total{component="ha-standby-sync"}` vocabulary rather than inventing a parallel
concept — the same pattern the 08-06 report already verified clean for the sibling CHAOS-24 sweep. QUAL-6
(`docs/operator/mcp-observe-acceptance-runbook.md:536`, "Qualification-clock guard") is a positive
counter-example to T-39, not new drift: it explicitly disclaims touching the Production receipt gate
("must not invoke the qualification issuer… Production remains qualification-locked throughout"). The new
"Process Log I/O Backpressure" stat (`static/index.html:2356`, `:7662-7667`) ships with an explicit
tooltip distinguishing it from the pre-existing "Log I/O Backpressure" ("a separate subsystem… which
covers the persistent request-log JSONL") — this is the internal/logsink-vs-internal/reqlog split CLAUDE.md
already documents, correctly and legibly disambiguated in the GUI, not accidental duplication. The CDR
per-instance circuit-breaker badge (`cdr_ui.go`, `static/index.html`'s `cdrBreakerBadge`) reuses "circuit
breaker" for the same concept the pre-existing upstream-pool breaker already names — same word, same
concept, no collision; its wire fields (`cbState`/`cbConsecFails`/`cbTotalOpens`/`cbTotalTrips`) use an ad
hoc `cb`-prefix convention that the sibling `internal/upstream.Status` breaker fields
(`circuit`/`failures`/`openedAtMs`/`retryAfterMs`) do not share — noted as a **soft finding** below (an
inconsistent wire-key convention across two similar admin endpoints, not a collision — CLAUDE.md's
same-word-same-concept bar is met). MCP "Policy" (`mcp_policy.go`) vs. the pre-existing main-proxy "Policy"
engine (`policy.go`) is covered by `docs/design/PRODUCT-TERMINOLOGY.md:12`'s existing precedent tolerating
"Policy" as a per-screen evaluation-domain name (already applied to Stage-1 Auth policy and Stage-2 Access
policy) — the MCP Gateway Policy panel is a third instance of an already-sanctioned pattern, not a new
finding.

---

## Findings

### T-40 — CHAOS-47's `idp_unreachable` alert reused the unrelated "IdP" (federated Identity Provider) vocabulary (new — fixed same-day)

- **Business concept:** the legacy LDAP-bind / OIDC-introspection proxy-auth backend (the credential
  verifier every proxied request authenticates against) could not be reached, so authentication is failing
  closed (CHAOS-47).
- **Current names / collision (before this fix):** every CHAOS-47 surface names the concept "identity
  backend" — `diagnostics.go`'s `Code: "identity_backend"` contract row, the GUI checkbox's own label text
  "Identity backend unreachable (auth failing closed)" (`static/index.html:17620`), CLAUDE.md's section
  title "Identity-backend availability (CHAOS-47…)" — **except** the wire alert-event string itself:
  `auth_backend_health.go:172,175` fired `HasSubscriber("idp_unreachable")` / `fireAlert("idp_unreachable",
  …)`, and `internal/alerts/store.go:28`'s event catalog documented it under that name.
- **Why this is real drift, not cosmetic:** Culvert has a large, separately-shipped, GUI-prominent feature
  already named "IdP" — `auth_idp.go`'s `IdPRegistry` / IdP profiles, and the admin GUI's "Identity
  Providers" panel (`static/index.html`, `data-view="idproviders"`, "Add Identity Provider" SAML/OIDC
  wizard). CLAUDE.md's own (unchanged this window) CHAOS-47 section text explicitly documents these as
  *different* subsystems with different failure-caching properties: *"The IdP-registry path
  (`auth_oidc_flow.go`) has no cache and is therefore un-poisonable but also un-cached — tracked as
  CHAOS-49"* — a direct contrast with CHAOS-47's own cached backend. An admin wiring a webhook on the event
  literally spelled `idp_unreachable` would reasonably read it as "a configured federated Identity
  Provider (SAML/OIDC) is unreachable" — it never fires for that; it fires only for the legacy proxy-auth
  LDAP/OIDC-introspection cache path CHAOS-47 covers, and never for the IdP-registry path per CLAUDE.md's
  own text.
- **Why same-day-fixable (unlike T-38's `drifted_tools`):** brand new this window (CHAOS-47 first shipped
  in the commits between 08-06 and this pass), so there is no prior release and no deployed webhook
  subscription that could depend on the string. The one test that exercises this path
  (`auth_backend_health_test.go:284-313`, `TestOIDC_UnreachableIdPFiresAlert`) mocks the function-variable
  seam `fireIdPUnreachableAlert`, not the literal wire string — confirmed via `go build ./...`, `go vet
  ./...`, and a targeted test run, all clean after the rename. No operator runbook references the string
  (grepped `docs/operator/`, zero hits). This clears the same bar T-35 cleared on 08-04: no wire/API
  compatibility cost, verified zero test/doc dependency on the literal string being renamed.
- **Fix applied:** renamed `idp_unreachable` → `identity_backend_unreachable` everywhere: the wire alert
  event string and its `HasSubscriber` gate (`auth_backend_health.go:172,175`), the package-level seam
  function `fireIdPUnreachableAlert` → `fireIdentityBackendUnreachableAlert` (and its three call sites,
  including the test mock), the event catalog comment in `internal/alerts/store.go:28` (with an added
  explanatory line distinguishing it from the IdP-registry vocabulary so this collision cannot silently
  recur), the GUI checkbox's `value` attribute (`static/index.html:17620` — the visible label text was
  already correct and unchanged), `diagnostics.go:409`'s comment, and CLAUDE.md's CHAOS-47 section.
- **Priority:** was High-if-unfixed (a live, admin-configurable webhook event name actively misleading
  about scope). **Migration risk:** None (pre-release string, no test/doc dependency, verified by build +
  targeted test run). **Est. PR size:** Trivial (already applied this pass).

### T-39 — "Qualification" now names FOUR unrelated concepts across independent PR streams in the same `mcp.gateway.*`/`/api/mcp/*` surface (carried over — compounded this window, still not fixed)

- **Business concept A (pre-existing):** **Production Qualification** — the cryptographically-verified
  receipt gating promotion of an MCP rollout-mode capability to Production
  (`internal/mcp/rollout.ProductionQualificationVerifier`).
- **Business concept B (pre-existing, QUAL-2/3):** a bounded, disposable pre-production
  inventory/telemetry bootstrap fleet used to validate the Observe listener itself
  (`qualification_inventory_file`, `qualification_telemetry`, `mcp_inventory.go`, `mcp_telemetry.go`).
- **Business concept C — new this window (QUAL-4):** a node-local, Observe-only policy *source file* that
  is explicitly never fleet-published and never Production-enforced —
  `qualification_policy_file`/`QualificationPolicyFile` (`config.go:235`), the `qualification_startup`
  source label and `errPolicy` prefix `"mcp qualification policy: "` (`mcp_policy.go`), and reason codes
  `qualification_policy_uncompilable`/`_wrong_capability`/`_traversal`/`_unreadable`/`_oversize`/`_empty`.
  `docs/operator/mcp-qualification-policy.md:1`'s own title is "MCP qualification policy (QUAL-4, Gateway
  Observe)"; line 145 goes further, using "qualification" as a bare adjective for listener maturity
  ("before Observe qualification") — a distinct, fourth flavor of the same word inside one sentence of one
  new doc.
- **Business concept D (still speculative, per 08-06):** `docs/operator/mcp-qualification-telemetry.md:150`
  still names "a defined qualification environment" as a future deliverable.
- **What changed this window:** QUAL-4 is a *fourth independent PR stream* — landing separately from the
  QUAL-1 (Production), QUAL-2/3 (bootstrap fleet), and QUAL-6 (acceptance harness) streams — that once
  again reuses "qualification" without cross-referencing any prior sense, and it is the **first of the
  QUAL-2/3/4 family to reach the GUI under the bare word**: `static/index.html:20255`
  (`mcpxPolActiveCard`, the MCP Policy panel, `data-view="mcp-policies"`) renders
  `srcLabel=(q.state==='loaded')?'qualification startup (local Observe evaluation snapshot; not fleet
  distributed)'…` and, two lines later, *"The qualification startup snapshot is EVALUATED for decision
  evidence only…"*. This sits on a different tab from the pre-existing Production Qualification card
  (`mcpxRfQualCard`, `data-view="mcp-rollout"`) — so there is still no *same-screen* collision — but T-39's
  08-06 mitigating note ("not yet GUI-visible for QUAL-2/3 specifically") is now only true for the QUAL-2/3
  sense; the QUAL-4 sense of "qualification" is live GUI text today.
- **Why this is real, compounding drift, not cosmetic:** four unrelated authors/PR streams across roughly
  three weeks have each independently reached for "qualification" to name a different thing in the exact
  same `mcp.gateway.*` config namespace and `/api/mcp/*` admin surface, with zero cross-referencing between
  any of them except QUAL-6's explicit, deliberate disclaimer. That QUAL-6's own runbook needed to write
  "Production remains qualification-locked throughout" to keep its own authors from being confused is
  itself the clearest evidence this word is now overloaded past the point new contributors can be expected
  to reach for the right sense unprompted.
- **Why not fixed this pass:** unchanged from 08-06 — this needs a real product-naming decision (what to
  call the QUAL-2/3 bootstrap fleet and the QUAL-4 node-local policy source; whether to reserve bare
  "Qualification" exclusively for the Production receipt gate matching `internal/mcp/rollout`'s
  established usage), not a mechanical rename. `qualification_policy_file` is, like
  `qualification_inventory_file`/`qualification_telemetry` before it, new-this-window with (per a targeted
  grep) no shipped deployment depending on it yet — still the cheapest point to rename, and getting cheaper
  to defer only in the sense that a fourth entrenched user makes the eventual decision proportionally more
  disruptive to walk back.
- **Recommended canonical name / fix:** unchanged recommendation from 08-06, now covering three streams
  instead of two — rename the QUAL-2/3/4 config keys and operator-doc titles to an environment-scoped
  vocabulary (e.g. "staging"/"pilot"/"bootstrap fleet" for QUAL-2/3, a distinct term such as "local policy
  source" or "Observe-only policy" for QUAL-4) and reserve bare "Qualification"/"qualification-locked"
  exclusively for the Production-promotion receipt gate, matching `internal/mcp/rollout`'s usage and
  QUAL-6's own careful disclaiming language.
- **Priority:** raised from Medium to **Medium-High** this pass (the underlying design ambiguity has not
  worsened, but the fact-pattern has: a fourth independent stream landed under the same word, and the word
  is now live in the GUI for the first time under a sense that is neither business concept A nor B).
  **Migration risk:** Medium (three checked-in YAML config keys and three-plus doc titles; genuinely
  cheapest to change now, before any of the three later-arriving senses accrues more surface area).
  **Est. PR size:** Small-Medium (needs a naming decision first).

---

## Carried over, still open (re-confirmed this pass, see Wave 1 table for evidence)

| Finding | Business concept | Status |
|---|---|---|
| T-9 | `exportedAt` → `capturedAt` rename | Open since 07-07. Unchanged. |
| T-11 | `allow`/`deny` default-action vocabulary vs. 4-value `PolicyAction` | Open since 07-16. Unchanged. |
| T-12 | Maintenance-Agent wire API "upgrade" vs. GUI/API "update"/"Dispatch" | Open since 07-16. Unchanged. |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | Open since 07-24 (soft/low). Unchanged. |
| T-16 | ADR numbering collision: 0008–0011 | Open since 07-19. Unchanged. |
| T-17 | Traffic-log destination-privacy config key/route still says "decryption" | Open since 07-19. Unchanged. |
| T-18 | "Seal" names two unrelated cryptographic operations | Open since 07-19, grew 07-24. Unchanged. |
| T-21 | "Config Version" names two unrelated, independently-incrementing counters | Open since 07-24. Unchanged; still compounded by T-32. |
| T-25 residual | Two disjoint "recipient"/"TAC trust key" registries | Open since 07-24. Unchanged. |
| T-29 | Per-IP rate limit: `rate_limit` (YAML/CLI) vs. `rate_limit_rpm` (API/wire/metric) | Open since 08-01. Unchanged. |
| T-30 | Per-IP connection cap: `max_conns_per_ip`/`MaxConnsPerIP` vs. `conn_limit_max_per_ip` | Open since 08-01. Unchanged. |
| T-31 | ClamAV metric family: `clamav` everywhere except `culvert_clam_scan_errors_total` | Open since 08-01. Unchanged. |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` reuses the overloaded term "snapshot" | Open since 08-01. Unchanged. |
| T-33 | MCP `PolicyAction`/`PolicyReason` observation fields mix three vocabularies | Open since 08-02. Unchanged; zero production consumers, now also zero-plus-one test consumers. |
| T-34 | SaaS feed status field-name split across two admin endpoints | Open since 08-02. Unchanged. |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | Open since 08-04. Unchanged. |
| T-37 | "Manual feed sync" audit-action naming split across blocklist/SaaS/threat feeds | Open since 08-04. Unchanged. |
| T-38 | `drifted_tools` vs. `review_required_tools` — same count, same API response, two names | Open since 08-06. Unchanged; still a pre-existing tested wire field, dual-emit remains the recommended fix. |
| T-39 | "Qualification" names four unrelated concepts in the same config/admin namespace | Open since 08-06. **Compounded this pass** — see Findings; a fourth stream (QUAL-4) landed and reached the GUI for the first time. |

*T-40 is not listed here — fixed same-day, see Findings.*

## Soft findings — no action recommended

- Carried over unchanged from 07-24 onward: "Bootstrap" covering two unrelated features (no on-screen
  collision yet); the T3 "seed"/`CULVERT_PROXY_SEED_REF` vocabulary (internally consistent).
- Carried over unchanged from 08-03: the `culvert_decrypt_*` metric prefix vs. the fully-spelled
  `decryption`/`decryption-profile` API/audit/alert namespace — internally consistent, documented as a
  deliberate abbreviation in CLAUDE.md.
- Carried over unchanged from 08-04: `roadmap/google-captcha-swg-investigation.md:177`'s speculative
  `culvert_connlimit_rejections_total` metric citation for a counter that shipped as a REST field only.
- Carried over unchanged from 08-06: `drifted_tools`'s absence from `api/openapi/openapi.json`/`.yaml`
  despite being a live, tested field — an OpenAPI-spec coverage gap, worth closing in the same change that
  fixes T-38; the pre-existing "Telemetry (opt-in)" support-panel feature vs. MCP Qualification Telemetry
  as a third generic sense of "telemetry" — different routes/screens, no on-screen adjacency, consistent
  with `PRODUCT-TERMINOLOGY.md`'s tolerance for screen-scoped generic-noun reuse.
- **New this pass:** the new CDR per-instance circuit-breaker fields
  (`cdr_ui.go:181-184` — `cbState`/`cbConsecFails`/`cbTotalOpens`/`cbTotalTrips`) use an ad hoc `cb`-prefix
  wire-key convention the sibling `internal/upstream.Status` breaker fields
  (`circuit`/`failures`/`openedAtMs`/`retryAfterMs`) do not share. Same concept, same word ("circuit
  breaker") on both admin surfaces — no collision — just an inconsistent key-naming convention across two
  similar per-instance-health endpoints. Not queued: the new CDR fields are already covered by this
  window's own new test (`cdr_ui_test.go`), so an immediate key rename would be a live-field change, not a
  same-day one; noted for a future pass to decide whether it is worth aligning.
- **New this pass:** QUAL-4's node-local policy-state vocabulary (`not_configured`/`loaded`/`invalid`),
  the new "Process Log I/O Backpressure" stat, the CDR breaker-badge feature, and CHAOS-25's sync-panic
  naming were all checked in detail and found clean or already correctly disambiguated — continued
  positive pattern, not findings.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium-High | T-39 (carried over, compounded) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename `qualification_inventory_file`/`qualification_telemetry`/`qualification_policy_file` and their operator-doc titles/GUI strings away from bare "qualification"; reserve that word for the Production receipt gate | Medium | Small-Medium (needs a naming decision first) |
| High | T-38 (carried over) | Dual-emit `CapabilityHealth.ReviewRequiredTools`/`review_required_tools` alongside the existing `DriftedTools`/`drifted_tools` (keep the old field for wire compatibility); update the GUI label; add both fields to the OpenAPI spec | Low (additive) | Small |
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-16 (carried over) | Renumber the Supportability-track's colliding ADRs (0008–0011 → 0019–0022) | Low (docs only) | Medium |
| Medium | T-21 + T-32 (carried pairing) | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 (carried over) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 (carried over) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-36 (carried over) | Give `saveConfigVersion`'s rollback call a `config.rollback`-prefixed action string alongside the version number | Low | Small |
| Medium | T-37 (carried over) | Rename `security.feeds_sync` → `threatfeed.sync`; update `security_feedsync_audit_test.go`'s three literal assertions | Low | Small |
| Medium | T-33 (carried over) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field for those instead | None today (zero production consumers); rises once a consumer exists | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 (carried over) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit | Low | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

*T-40 is omitted — already fixed this pass.*

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass re-confirmed, via a cited-line diff against every one
of nineteen previously-open findings, that eighteen are unchanged across a 64-commit window — including
four findings whose dependent files were touched by unrelated code in the same window, each verified by
reading the actual diff rather than assuming file-touch implies drift. It found and same-day-fixed one new
finding (T-40) on code that shipped this window, before any consumer could come to depend on the
collision — the same "catch it, the earlier the cheaper" pattern this program has followed since T-35. It
also found that T-39, queued since 08-06 pending a design decision, has genuinely worsened: a fourth
independent PR stream (QUAL-4) reused the same overloaded word for a third distinct concept and, for the
first time, put it in front of an admin in the GUI. This is escalated to Medium-High priority in the
refactoring plan below, with the recommendation unchanged in substance (a design decision is still
required) but the urgency raised given the accumulating fact pattern. No cosmetic or preference-driven
renames were proposed.
