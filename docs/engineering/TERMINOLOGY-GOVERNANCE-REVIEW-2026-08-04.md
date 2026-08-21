# Culvert Language & Terminology Governance Review — 2026-08-04

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `3d13f7a`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-03.md` (baseline `49cb52f`). One day and 22 commits separate the
> two reviews, dominated by three more MCP UX legs (PR-UX-3 entity pivots/evidence chain, PR-UX-4
> standardized dangerous-action confirmations, PR-UX-5 truthful rollout/scope/fleet state) plus a small
> connection-limit observability addition and a cluster bootstrap-route governance fix. Method: (1)
> `git diff --name-only 49cb52f..HEAD` checked against every file each of the fifteen carried-over open
> findings (T-9, T-11, T-12, T-13 residual, T-16, T-17, T-18, T-21, T-25 residual, T-29, T-30, T-31, T-32,
> T-33, T-34) depends on — **none of the cited files appear in this window's diff at all**, the cleanest
> possible re-confirmation (no touched-but-unrelated-region case this time); (2) audited PR-UX-3/4/5 in
> full: traced every `mcpxDangerDialog(...)` call's on-screen "Audit evidence" claim
> (`static/index.html:18487-18780`) against the real `auditEvent(...)` call in the handler it targets
> (`ui_mcp.go`, `ui_mcp_rollout.go`) — all five matched exactly (`mcp.rollout.emergency.disable/.clear`,
> `mcp.rollout.rehearse-rollback`, `mcp.rollout.transition.request/.rejected`, `mcp.rollback.request`);
> checked PR-UX-5's new "Desired / Locally-active / Fleet-effective" mode triad against
> `internal/mcp/rollout`'s `desired`/`mode` API fields and confirmed "Fleet-effective" is a GUI-side
> derived label over `distribution_state`, not a second wire field under a colliding name; (3) applied a
> self-consistency check this program had not run before — nav-sidebar label vs. the page's own displayed
> title vs. its `<h3>` vs. its body copy vs. `CLAUDE.md`/design-doc language, for **every** MCP nav item,
> not just cross-referencing GUI against the API as prior passes did — which surfaced T-35 (below) on
> code that shipped in PR-UX-1/2, before 08-03's baseline, and that 08-03 itself had marked "clean" under
> its narrower GUI-vs-API check; (4) extended the audit-event inventory begun in earlier passes to two
> areas not previously covered end-to-end — config-version-rollback's action-string pairing, and
> "manually sync this feed now" across all three independent feed subsystems — surfacing T-36 and T-37,
> both on pre-existing code untouched this window.
> **Companion change:** T-35 fixed same-day (GUI-copy + one nav label, zero API/wire impact, confirmed
> zero test dependency on the changed text — `ui_mcp_ux_e2e_test.go` selects by `data-view` attribute, not
> label text). T-36 and T-37 are left open: T-36 needs a small design decision (whether config-version
> history should carry a stable action token at all, alongside its existing human-readable sentence), and
> T-37 touches an audit-event string with an existing test assertion on the literal value
> (`security_feedsync_audit_test.go`), so it is queued rather than blind-renamed same-day.

---

## Executive Summary

No regressions: all fifteen carried-over open findings (T-9, T-11, T-12, T-13 residual, T-16, T-17, T-18,
T-21, T-25 residual, T-29, T-30, T-31, T-32, T-33, T-34) are re-confirmed unchanged — this window's diff
does not touch a single file any of them depends on (see Wave 1 table).

**PR-UX-3/4/5 hold the same discipline already praised for PR-1 through PR-11.** PR-UX-4's standardized
danger-confirmation dialog states an "Audit evidence" token to the admin before every mutating MCP action;
tracing all five distinct actions (emergency disable/clear, rollback rehearsal, rollout transition,
rollback) to their handlers confirms the dialog's claimed token is the exact literal string the backend
passes to `auditEvent(...)` in every case — a GUI surface making an explicit truthfulness claim about
audit behavior, verified true. PR-UX-5's three-way "Desired / Locally-active / Fleet-effective" mode split
is a deliberate disambiguation of a state the commit message says "the previous surface blurred," and
"Fleet-effective" is confirmed to be a presentation label derived from the real `distribution_state` field
rather than a second, colliding wire name for something else.

**New finding, on code that predates this window (T-35): the two MCP Command-Center-family nav items
each show a different name in the sidebar than on the page they open.** `MCP Overview` (nav) opens a page
whose own title and `<h3>` both say `MCP Command Center` — the name `CLAUDE.md`, the design doc, and this
window's own UX-audit screenshot filenames (`command-center-*.png`) already use. `MCP Decisions & Explain`
(nav) opens a page titled `MCP Investigations` in its own title/`<h3>`, whose body copy in the same panel
calls itself "Activity," which is also what `CLAUDE.md`, the design doc, and this window's screenshot
filenames (`activity-shadow-drawer-*.png`, `activity-tool-drawer-*.png`) call it — a genuine four-way split
inside a single GUI screen's own markup, not just a doc-vs-doc disagreement. Both nav items shipped in
PR-UX-1/2 (before 08-03's baseline `49cb52f`); 08-03 checked this exact GUI against the API for field-name
parity and found it clean, but did not check the GUI's nav label against its own page title — a different,
narrower lens than this pass ran. **Fixed same-day**: both nav labels now read `MCP Command Center` and
`MCP Activity`, matching the name already established everywhere else (`static/index.html:713-714,
719-720,3572,3594`, `5618-5621` `viewMeta`).

**Two more new findings, also on pre-existing code untouched this window (T-36, T-37):** a config-rollback
action-string mismatch between the audit ring and the config-version history list, and a three-way split
in how "manually sync this feed now" is named across the blocklist-feed, SaaS URL-category-feed, and
threat-feed subsystems' audit events. Neither is a same-day fix (see each finding for why); both join the
backlog at Medium/Low priority.

**Terminology Health Score: 8.5 / 10** (unchanged — three new findings on a genuinely deeper set of checks
this pass ran for the first time, one already fixed same-day, is consistent with this program's expected
background rate of "catch it, the earlier the cheaper," not a regression; the fifteen-strong carried-over
backlog had its cleanest re-confirmation yet, with zero touched-but-unrelated files to reason through).

**Fixed in this change:** T-35 (GUI copy only, see above). T-36 and T-37 do not clear the same-day bar —
see their entries below.

---

## Wave 1 — Carried-over findings re-confirmed unchanged

`git diff --name-only 49cb52f..HEAD` (22 commits, listed in the Method note above) was checked against
every file citation across all fifteen open findings. Unlike 08-01/08-02/08-03, **none of the cited files
appear in this window's diff at all** — the window's real changes (MCP UX GUI/admin-API additions,
`internal/connlimit`, `ui_middleware.go`'s bootstrap-route fix, `CLAUDE.md`, `api/openapi/*`,
`docs/design/mcp/ux-audit-assets/**`) simply do not intersect any of the fifteen findings' file lists.

| Finding | Files it depends on | Touched this window? |
|---|---|---|
| T-9 | export/import + parity-test surface (`exportedAt`) | No |
| T-11 | `policy.go`'s default-action vocabulary, `ui_policy.go` core | No |
| T-12 | Maintenance-Agent `/v1/upgrades/*` wire routes | No |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | No |
| T-16 | ADR numbering (0008–0011) | No |
| T-17 | `decryption_redact_hosts` / `/api/decryption/redaction` | No |
| T-18 | `internal/sealbox.Seal`/`Open` call sites | No |
| T-21 | `cluster_convergence.go`, `configversion.go`'s rollback `cp_version` surface | No |
| T-25 residual | `support_recipients.go` / `support_tac_trust.go` | No |
| T-29 | YAML `rate_limit` (`config.go`/`main.go`) vs. `rate_limit_rpm` (API/wire/metric) | No |
| T-30 | YAML `max_conns_per_ip`/wire `MaxConnsPerIP` vs. `conn_limit_max_per_ip` | No |
| T-31 | `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` | No |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` overloads "snapshot" | No |
| T-33 | MCP `PolicyAction`/`PolicyReason` mixing three vocabularies (`internal/mcp/runtime/policy.go`, `events.go`, `observe.go`) | No — this window's MCP changes are in `adminapi/decisions.go`, `cpdp/publication/distribution.go`, and the root `mcp_ack_readmodel.go`/`mcp_scope_readmodel.go`/`ui_mcp*.go` GUI-backend files, none of which touch `runtime/policy.go`/`events.go`/`observe.go` |
| T-34 | SaaS feed status field-name split across two admin endpoints (`saas_feed_status_api.go`, `ui_policy.go`) | No |

## Wave 2 — New territory audited this pass (22 commits since `49cb52f`)

**PR-UX-3 (entity pivots + evidence-chain navigation), PR-UX-4 (standardized dangerous-action
confirmations), PR-UX-5 (truthful rollout/scope/fleet state): clean.** PR-UX-4's `mcpxDangerDialog`
states an explicit "Audit evidence" token to the admin before every one of its five mutating actions
(`static/index.html:18599-18780`); each was traced to its backend handler and matches the real
`auditEvent(...)` call verbatim — `emergency-disable`→`mcp.rollout.emergency.disable`,
`emergency-clear`→`mcp.rollout.emergency.clear`, `rehearse`→`mcp.rollout.rehearse-rollback`,
`transition`→`mcp.rollout.transition.request`/`.rejected` (Production path), `rollback`→
`mcp.rollback.request` (all verified against `ui_mcp_rollout.go:73-186` and `ui_mcp.go:283`). PR-UX-5's
mode triad ("Desired," "Locally-active," "Fleet-effective") is a deliberate disambiguation per its own
commit message; "Fleet-effective" is a GUI-computed label over the real `distribution_state` API field
(`ui_mcp_rollout.go:38`, `static/index.html:17905-17922,18864-18891`), not a second, independently-named
wire concept — no collision. PR-UX-3's 11-stage "Evidence Chain" and entity-pivot vocabulary
(`static/index.html`, `f31a926`) introduces no name this pass found reused elsewhere for a different
concept.

**`internal/connlimit`'s new rejection counter and the cluster bootstrap-route fix: clean, no findings.**
The new `ConnLimiter.Rejected()` / `rejectedTotal` (API field, `GET /api/connlimit`) observability
addition (`506924a`) introduces one name for one concept with no existing sibling to collide with; it
ships as a REST field only, no Prometheus metric, so it does not intersect the pre-existing
`culvert_connlimit_*` name a roadmap investigation doc (`roadmap/google-captcha-swg-investigation.md:177`)
speculatively referenced for a metric that was never built under that or any name — noted for
completeness as a **soft finding** below, not a collision (a doc citing a metric name for a
not-yet-built metric is not two names for one *implemented* concept). The `ui_middleware.go` /
`ui_routes_meta.go` bootstrap-route governance fix (`b1b7e07`, `b2e1bb5`, `023cbe7`) is an auth-path
correction with no new naming surface.

**A deeper self-consistency lens applied to the MCP GUI surfaces this pass (not new code): T-35, T-36,
T-37.** See Findings below. All three were found by checking a dimension prior passes had not run
end-to-end (nav-vs-title-vs-body self-consistency; config-rollback's action-string pairing convention;
the full three-subsystem "manual feed sync" audit-name inventory) rather than by this window's diff.

---

## Findings

### T-35 — MCP Command-Center-family nav items disagree with their own page title/heading/body copy (new — fixed same-day)

- **Business concept:** the two top-level MCP admin screens — the gateway-posture-at-a-glance overview,
  and the historical decision/activity log with evidence drawer.
- **Current names / collision (before this fix):**
  - Overview screen: nav label `MCP Overview` (`static/index.html:714`) vs. page title + `<h3>`
    `MCP Command Center` (`viewMeta['mcp-overview'].title`, `static/index.html:3572`) — the latter also
    used verbatim by `CLAUDE.md:74,189`, `docs/design/mcp/PRODUCTION-INTEGRATION.md:18,28`, and this
    window's own UX-audit screenshots (`docs/design/mcp/ux-audit-assets/production/command-center-*.png`).
  - Decisions screen: nav label `MCP Decisions & Explain` (`static/index.html:720`) vs. page title +
    `<h3>` `MCP Investigations` (`viewMeta['mcp-decisions'].title`, `static/index.html:3594`) vs. the
    same panel's own body copy, one line below its `<h3>`: *"**Activity** as a story: a Shadow-executed
    policy DENY is shown as..."* (`static/index.html:3595`) — "Activity" is also `CLAUDE.md`'s and the
    design doc's name (`docs/design/mcp/PRODUCTION-INTEGRATION.md:18,33`: *"PR-UX-2 Activity
    (`#view-mcp-decisions`)"*), this window's screenshot filenames
    (`activity-shadow-drawer-*.png`, `activity-tool-drawer-*.png`), and the JS/DOM internals that render
    the panel (`renderMCPActivity()`, `mcpx-act-live`, `static/index.html:18045,3600`) — i.e. every layer
    of the implementation *except* the nav label and the page's own title/heading already called this
    "Activity."
- **Why this is real drift, not cosmetic:** this is not a doc-vs-doc disagreement (the class most prior
  findings in this series are) — it is the live GUI disagreeing with itself. A support engineer following
  a runbook or a screenshot in `docs/design/mcp/` that says "open the Command Center" or "check the
  Activity view" has no matching nav item to click; landing on the page after clicking the *differently
  labeled* nav item, they see a heading that matches the docs but a nav trail that didn't. 08-03 audited
  this exact GUI area and marked it "clean" — but its check was GUI-field-vs-API-field parity (mode/
  desired, action taxonomy, posture chips), not nav-label-vs-own-title self-consistency; this pass ran
  that additional check for the first time.
- **Fix applied:** `static/index.html` nav label `MCP Overview` → `MCP Command Center`
  (line 714); nav label `MCP Decisions & Explain` → `MCP Activity` (line 720); `<h3>MCP Investigations</h3>`
  → `<h3>MCP Activity</h3>` (line 3594); `viewMeta['mcp-decisions'].title` `'MCP Investigations'` →
  `'MCP Activity'` (line 5621). `MCP Overview`'s target title/`<h3>` (`MCP Command Center`) already
  matched `CLAUDE.md`/the design doc, so only the nav label needed to move; `MCP Activity` was chosen as
  the decisions screen's canonical name because it is what every other layer — pre-implementation design
  doc, `CLAUDE.md`, JS/DOM internals, and this window's own screenshot filenames — already called it, so
  aligning the two outlier strings (nav label, page title/`<h3>`) onto "Activity" required touching the
  fewest places and zero non-GUI surfaces.
- **Compatibility check before fixing:** `ui_mcp_ux_e2e_test.go` (the only test file referencing these
  views) selects both nav items exclusively by `.nav-item[data-view="mcp-overview"|"mcp-decisions"]` —
  the stable `data-view` attribute, unchanged by this fix — never by visible text; confirmed via
  `go build ./...` and `go vet ./...` (both clean) that no Go source or test asserts on the old label
  strings.
- **Priority:** Medium (a live, self-contradictory GUI surface support/QA and new admins interact with
  directly). **Migration risk:** None (GUI copy only, no wire/API/audit-string change, no test
  dependency). **Est. PR size:** Trivial (already applied this pass).

### T-36 — Config-rollback's audit action and its config-version-history action string are two different tokens (new — documented, not fixed)

- **Business concept:** "an admin rolled the running configuration back to a prior numbered version" —
  one event, recorded in two places every other config-mutating action keeps in lockstep.
- **Current names / collision:** every other admin write handler in the codebase passes the **same**
  literal string to both `auditEvent(...)` and `saveConfigVersion(actor, action)` — e.g. `"policy.add"`,
  `"blocklist.add"`, `"urlcat.create"`, `"authpolicy.reorder"`, `"dpi.add"` all appear identically in both
  calls at their respective call sites. Config rollback breaks the pattern:
  `configversion.go:293` — `auditEvent(r, "config.rollback", "system", auditDetail)` (a stable,
  namespaced token) vs. `configversion.go:295` — `saveConfigVersion(actor, fmt.Sprintf("rollback to
  v%d", req.Version))` (a freeform sentence that is a *different string for every rollback* — `"rollback
  to v3"`, `"rollback to v7"`, etc. — with no `.`-namespace and no substring shared with `config.rollback`).
- **Why this trips someone up:** the audit ring records the stable token every other action uses; the
  Config Versions history (what the admin UI/API shows as each snapshot's "action") records a one-off
  sentence instead. Anyone correlating "what config-mutating actions happened" between the audit log and
  the version-history list — or building tooling/reporting keyed on the action field, the way every other
  action type supports — finds no stable, matching identifier for rollbacks specifically.
- **Why not fixed this pass:** unlike T-35, this is a behavior/shape question, not a copy alignment —
  should `saveConfigVersion` gain a stable `config.rollback` token *in addition to* the human-readable
  version number (so the "which version" detail isn't lost), or should the audit side adopt a
  per-version-numbered action instead? That's a real design call, not a same-day mechanical rename, and
  config-version history is a persisted, user-visible list (unlike T-35's pure GUI copy).
- **Recommended canonical name / fix:** keep `saveConfigVersion`'s call for rollback passing an action
  string that *starts with* `config.rollback` (e.g. `fmt.Sprintf("config.rollback v%d", req.Version)`),
  so grepping/filtering on the stable prefix works the same way it already does for every other action
  family, while still keeping the version number visible in the history list.
- **Priority:** Medium (touches a user-visible, persisted history list, but is additive/reformatting only
  — no field is removed). **Migration risk:** Low (no schema change; existing numbered version files keep
  whatever action string they were saved with, only new rollbacks get the new format).
  **Est. PR size:** Small.

### T-37 — "Manually sync this feed now" has three different audit-action naming patterns across three feed subsystems (new — documented, not fixed)

- **Business concept:** an admin-triggered, immediate refresh of one of Culvert's three independent feed
  subsystems (blocklist feed, signed SaaS URL-category feed, threat feed).
- **Current names / collision:**
  - Blocklist feed: `ui_policy.go:381` — `auditEvent(r, "blocklist.feed.sync", feedURL, "")`.
  - Signed SaaS URL-category feed: `saas_feed_status_api.go:110` — `auditEvent(r, "saasfeed.refresh",
    "feed", "result="+outcome.String())`.
  - Threat feed (`internal/threatfeed`, URLhaus/OpenPhish): `ui_security.go:553` —
    `auditEvent(r, "security.feeds_sync", "manual", "")`, on `apiSecFeedsSync` (`POST
    /api/security-scan/feeds/sync`), which calls `globalThreatFeed.Sync()` directly.
- **Why this trips someone up:** the first two follow a `<subsystem>.<verb>` pattern, so grepping audit
  history for `blocklist.feed.` or `saasfeed.` finds the sibling events for those two feeds. The threat
  feed's manual sync is filed under the generic `security.feeds_sync` — it does not mention "threat" at
  all, and it sits in the same file as `threatfeed.allowlist.update`/`update_unpersisted`
  (`ui_security.go:595,624`), which *do* use the `threatfeed.` namespace for the same subsystem's other
  admin actions. An admin filtering audit history for threat-feed activity by the `threatfeed.` prefix —
  the pattern that works for every other action on that same subsystem — will silently miss every manual
  sync event. The verb also differs three ways (`sync` / `refresh` / `feeds_sync`) for what is
  functionally the identical operator action (force an immediate feed refresh) across all three feeds.
- **Why not fixed this pass:** `security_feedsync_audit_test.go` asserts the literal string
  `"security.feeds_sync"` in three places; a same-day rename would need that test updated in the same
  change, and — per this program's standing compatibility bar for already-shipped, live audit strings
  (the same bar T-31/T-34 were held to) — a rename to a live, externally-visible audit token is queued for
  dedicated follow-up rather than folded into a governance pass.
- **Recommended canonical name / fix:** rename `security.feeds_sync` → `threatfeed.sync`, matching the
  `threatfeed.` prefix already used by the subsystem's other two actions, and update
  `security_feedsync_audit_test.go`'s three literal-string assertions in the same change. (Standardizing
  the verb across all three feeds — `sync` vs. `refresh` — is a further, lower-priority nice-to-have; the
  namespace fix alone closes the "it's invisible to a `threatfeed.` search" gap, which is the concrete
  harm.)
- **Priority:** Medium (an audit-search blind spot on a security-relevant action, but no data-shape or
  API change). **Migration risk:** Low (an audit-event string, not a persisted/versioned field; the one
  test asserting the literal value is updated in the same change). **Est. PR size:** Small.

---

## Carried over, still open (re-confirmed this pass, see Wave 1 table for the file-absence evidence)

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
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` reuses the overloaded term "snapshot" | Open since 08-01. Unchanged; still not wired onto any live GET response. |
| T-33 | MCP `PolicyAction`/`PolicyReason` observation fields mix three vocabularies | Open since 08-02. Unchanged this window (files untouched — Wave 1). |
| T-34 | SaaS feed status field-name split across two admin endpoints | Open since 08-02. Unchanged. |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | **New, open.** See Findings. |
| T-37 | "Manual feed sync" audit-action naming split across blocklist/SaaS/threat feeds | **New, open.** See Findings. |

*T-35 is not listed here — fixed same-day, see Findings.*

## Soft findings — no action recommended

- Carried over unchanged from 07-24 onward: "Bootstrap" covering two unrelated features (no on-screen
  collision yet); the T3 "seed"/`CULVERT_PROXY_SEED_REF` vocabulary (internally consistent).
- Carried over unchanged from 08-03: the `culvert_decrypt_*` metric prefix vs. the fully-spelled
  `decryption`/`decryption-profile` API/audit/alert namespace — internally consistent on each side and
  already documented verbatim in `CLAUDE.md`'s autoexclude section; read as a deliberate abbreviation.
- **New this pass:** `roadmap/google-captcha-swg-investigation.md:177` cites a Prometheus metric name
  (`culvert_connlimit_rejections_total`) for the per-IP connection-limit rejection count; this window's
  actual implementation (`506924a`) shipped the same concept as a REST field (`rejectedTotal` on
  `GET /api/connlimit`) only, with no Prometheus metric of any name. Not counted as a naming collision
  (the doc's cited metric was never built under any name, so there is no second live name to collide
  with) — noted so a future Prometheus exporter for this counter picks a `culvert_connlimit_*`-prefixed
  name consistent with the doc's expectation, rather than introducing a third variant.
- **New this pass:** PR-UX-3/4/5's evidence-chain, dangerous-action-confirmation, and
  desired/locally-active/fleet-effective vocabularies all held discipline against their own design intent
  and against each other under direct tracing (every "Audit evidence" claim checked against the real
  backend call, not assumed) — continued positive pattern, not a finding.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-16 (carried over) | Renumber the Supportability-track's colliding ADRs (0008–0011 → 0019–0022) | Low (docs only) | Medium |
| Medium | T-21 + T-32 (carried pairing) | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 (carried over) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 (carried over) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-36 (new) | Give `saveConfigVersion`'s rollback call a `config.rollback`-prefixed action string alongside the version number | Low | Small |
| Medium | T-37 (new) | Rename `security.feeds_sync` → `threatfeed.sync`; update `security_feedsync_audit_test.go`'s three literal assertions | Low | Small |
| Medium | T-33 (carried over) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field for those instead | None today (re-verified zero consumers); rises once a consumer exists | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 (carried over) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit | Low | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

*T-35 is omitted — already fixed this pass.*

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass re-confirmed, via a diff check against every cited file
across all fifteen previously-open findings, that none of them were touched at all this window — the
cleanest re-confirmation this series has produced. It then ran a strictly deeper self-consistency check
than any prior pass on the MCP GUI (nav label vs. own page title vs. own heading vs. own body copy, not
just GUI-vs-API), which found and same-day-fixed T-35 on code that had already been marked "clean" once
under a narrower lens — a useful signal that "clean" findings should be read as "clean under the checks
run so far," not "provably complete." It also extended the audit-event inventory into two areas not
previously walked end-to-end, surfacing two further real, evidenced findings (T-36, T-37), both queued
per this program's standing compatibility bar rather than blind-renamed. PR-UX-3/4/5, the connection-limit
observability addition, and the cluster bootstrap-route fix were all audited for the same class of drift
and found clean, including an explicit trace of every dangerous-action dialog's on-screen audit-evidence
claim against the real backend call. No cosmetic or preference-driven renames were proposed.
