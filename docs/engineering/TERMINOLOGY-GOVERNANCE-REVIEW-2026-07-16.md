# Culvert Language & Terminology Governance Review — 2026-07-16

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Three parallel concept-cluster audits — (1) authentication/identity/session/RBAC,
> (2) cluster CP-DP/HA/release-catalog/maintenance-agent, (3) policy engine/SSL-decryption/content
> scanning — each cross-referencing source code, REST API, GUI copy (`static/index.html`), CLI/env,
> audit/log messages, metrics, and docs. Findings verified against the tree at `d5585d5`, following
> up on the two prior reviews at `ea0f2ff` (2026-07-07) and `8e88a40` (2026-07-10).
> **Companion change:** one real bug fix (masquerading as a naming issue) and a completed cleanup
> of a previously-partial fix ship with this review (see "Fixed in this change").

---

## Executive Summary

This pass re-verified every cluster the two prior reviews marked clean (still holds — no drift
reintroduced) and turned up one genuine, user-facing **functional bug** hiding behind what looked
like a naming question, plus confirmation that one previously-declared-fixed item
(T-7, 2026-07-07) was only partially fixed. Both are corrected in this change. Two further
findings are new and, per the same migration-cost bar the prior two reviews used for T-9/T-10, are
documented for a dedicated follow-up rather than folded in here.

1. **The IdP login-selection screen showed the internal `type:ID` machine key instead of the
   admin-configured display name** (`Continue with oidc:a1b2c3d4e5f6` instead of `Continue with
   Corporate Okta`). This surfaced during the auth/identity audit as a "naming" question — which
   name does `Name()` return — but the answer is that the *wrong* value was being shown to actual
   end users signing in, not just an internal inconsistency. Fixed by adding a `DisplayName()`
   method to the `IdentityProvider` interface; `Name()` keeps its existing machine-key contract
   (policy `providerRefs` filtering, logs) untouched.
2. **T-7 ("host agent" → "Maintenance Agent") was declared fixed on 2026-07-07 but only touched 2
   files / 3 lines.** Ten further instances of "host agent" / "host-side agent" survived in CI
   workflow comments, the compose files, the quick-start installer's own operator-visible log
   line, and three enterprise/operator docs. All ten are now aligned on "Maintenance Agent."

**Terminology Health Score: 8.5 / 10** (unchanged in spirit — the two carried-over medium items
(T-9, T-10) are still correctly sized for a dedicated follow-up rather than a same-day fix; the one
new functional bug found this pass is a real defect, not a score-moving terminology gap, and is
fixed here).

**Fixed in this change:**
- `identity.go`, `auth_oidc_flow.go`, `auth_saml.go`, `ui_auth.go` — `DisplayName()` added to
  `IdentityProvider`; `authSelectProvider` renders it instead of `Name()`. Regression test added
  (`auth_idp_displayname_test.go`). Two test fakes (`proxy_test.go`, `authpolicy_phase3_slice4_test.go`)
  updated to satisfy the widened interface.
- Ten "host agent"/"host-side agent" → "Maintenance Agent" fixes across
  `.github/workflows/{install-lifecycle-e2e,appliance-catalog-update-e2e,qa-gate,security-release-gate}.yml`,
  `docker-compose.yml`, `test/e2e/catalog-update/docker-compose.catalog-e2e.yml`, `scripts/install.sh`,
  `docs/operator/release-management-agent.md`, `docs/enterprise/{ENTERPRISE-DEPLOYMENT-GUIDE,OPERATIONS-RUNBOOK}.md`,
  `docs/engineering/ENTERPRISE-IMPLEMENTATION-GAP-REGISTER.md`.

**No renames of stable REST API routes, JSON fields, CLI flags, config keys, or exported Go
identifiers were made** — the interface addition is additive (widens `IdentityProvider`, does not
change `Name()`'s contract or any wire format), and every other fix in this pass is a comment/doc/
log-line change with zero compatibility risk.

---

## Re-verified clean (no new drift since 2026-07-10)

`defaultAuthOutcome`/`UnauthMode`, session-cookie naming, IdP/SSO profile terminology (aside from
Finding G-1 below), threat-feed vs blocklist vs blocklist-feed, URL category naming, CDR, Zero
Trust/default-deny, bandwidth/QoS, node groups, CP/DP/enrollment naming, fencing-lease/term
equivalence, config-version/export/snapshot three-surface split, "canary" scoping
(`update_cluster.go` vs `release_alerts.go`), release catalog vs "release index," `Administrators`/
`Provider` naming (`docs/design/PRODUCT-TERMINOLOGY.md`).

---

## Findings

### G-1 — IdP login-selection button showed the machine key, not the admin-configured label (FIXED)
- **Business concept:** the human-readable label an end user sees when choosing an identity
  provider at `/auth/select`.
- **Current names before fix:** `IdPProfile.Name` (`auth_idp.go:29`) is documented as the
  admin-entered "human-readable label" (e.g. "Corporate Okta"). But `OIDCFlowProvider.Name()`
  (`auth_oidc_flow.go:331`, pre-fix) and `SAMLProvider.Name()` (`auth_saml.go:103`) return
  `"oidc:"+profile.ID` / `"saml:"+profile.ID` — the machine key used elsewhere for
  `providerRefs` filtering (`ui_auth.go:885`, `filterProvidersByID`/`stripIdPPrefix`).
  `authSelectProvider` (`ui_auth.go:908-915`, pre-fix) rendered the login button text with that
  same `Name()` value, so an admin who named their provider "Corporate Okta" saw end users land on
  a button reading **"Continue with oidc:a1b2c3d4e5f6"**.
- **Why this is more than cosmetic:** this is the one place a real end user (not an admin, not a
  developer) reads the string, and no test asserted on the button's rendered text — the bug was
  invisible to `go test`. It would generate real support tickets ("why does SSO show a random
  string").
- **Fix:** added `DisplayName() string` to the `IdentityProvider` interface (`identity.go`),
  implemented on `OIDCFlowProvider`/`SAMLProvider` as `profile.Name` (falling back to `Name()` if
  the label is unset); `authSelectProvider` now renders `p.DisplayName()`. `Name()` is untouched —
  it stays the "type:ID" machine key for filtering/logs. Two test fakes implementing
  `IdentityProvider` (`testProxyIdentityProvider`, `ssoTestProvider`) were given a same-valued
  `DisplayName()` to satisfy the widened interface without changing their existing test semantics.
  New regression tests (`auth_idp_displayname_test.go`) cover both providers' `DisplayName()`/
  fallback behavior and the rendered HTML.
- **Priority:** High (real functional/UX defect on a production admin-facing feature, found via a
  terminology audit). **Migration risk:** none — additive interface method, no wire/API change.

### G-2 — T-7 ("host agent" → "Maintenance Agent") was only partially fixed (FIXED — completing T-7)
- **Business concept:** the local `culvert-maint` privileged helper process.
- **Current names before this pass:** T-7 (2026-07-07) declared this fixed, touching
  `install-lifecycle-e2e.yml:13` and `appliance-catalog-update-e2e.yml:259,293,317` — but a
  broader grep this pass found ten further, then-unfixed instances: one line *above* the T-7 fix in
  the same file (`install-lifecycle-e2e.yml:7`), two more spots in
  `appliance-catalog-update-e2e.yml` (lines 23, 77 — a different section than the one T-7 touched),
  `qa-gate.yml:382`, `security-release-gate.yml:92`, both compose files' comments, the quick-start
  installer's own operator-visible log line (`scripts/install.sh:718` — the one instance a real
  operator watching `install.sh` run would actually see, not just a code comment), a doc-section
  heading (`docs/operator/release-management-agent.md:160`), and two enterprise docs
  (`ENTERPRISE-DEPLOYMENT-GUIDE.md:98`, `OPERATIONS-RUNBOOK.md:191`,
  `ENTERPRISE-IMPLEMENTATION-GAP-REGISTER.md:77`).
- **Why it matters:** these are current, operator-facing docs and a user-visible install log line,
  not just internal comments — someone reading `OPERATIONS-RUNBOOK.md`'s "Remove the host agent"
  next to the canonical "Maintenance Agent" used everywhere else could reasonably wonder if they're
  different things. T-7's own fix only verified the two files/lines it touched weren't
  grep-matched by downstream automation; the same check was re-run for all ten new instances before
  fixing (verified: none are step `name:` fields or strings any other job/script string-matches).
- **Fix:** all ten instances now say "Maintenance Agent."
- **Assessment:** T-7 is now genuinely complete — a full-repo grep for "host agent" / "host-side
  agent" / "host-agent" turns up zero remaining hits outside historical review documents (this file
  and its two predecessors, which are point-in-time records and intentionally left unedited) and
  one legitimate unrelated usage (`roadmap/D1.6-maintenance-agent-design.md:47`, "no cross-host
  agent dial" — describing the absence of cross-host RPC, not naming the agent itself).
- **Priority:** Low. **Migration risk:** none — comment/doc/log-line text only.

### T-11 — Default-action fallback uses a different action vocabulary than per-rule actions (new — documented, not fixed)
- **Business concept:** what happens to a request when no policy rule matches vs. when a rule
  explicitly matches and acts.
- **Current names:**
  - Per-rule: `PolicyAction` enum — `Allow` / `Drop` / `Block_Page` / `Redirect`
    (`policy.go:22-27`, mixed-case, four values).
  - No-match fallback: `defaultPolicyAction()`/`setDefaultPolicyAction()` — a *different*, all-
    lowercase, two-value vocabulary, `"allow"` / `"deny"` (`proxy.go:18-32`), surfaced identically
    via `AdminSettings.DefaultAction` (`admin_settings.go:25`, comment: `// "allow" or "deny"`) and
    `GET/PUT /api/default-action` (`ui_policy.go:1978-2002`, `body.Action != "allow" && != "deny"`).
- **Why this is real drift:** there is no `Deny` value in `PolicyAction`, so an admin reading
  `"defaultAction":"deny"` in the API response or a config export has no rule-level equivalent to
  map it to — the closest matches (`Drop`, silent connection reset, vs. `Block_Page`, a 403 page)
  are behaviorally different from each other, and neither is spelled "Deny." Two separate
  vocabularies for "what happens when access is refused," one capitalized/four-valued and one
  lowercase/two-valued, in the same policy domain, is a genuine cross-surface naming split — not
  just a casing nit, since the fallback vocabulary is structurally narrower (no page/redirect
  option) in a way its own name doesn't signal.
- **Why it is NOT fixed in this pass:** this touches an external contract — the
  `/api/default-action` JSON body/response (`{"action":"allow"|"deny"}`), the
  `admin_settings.json` `default_action` field, and (per `config_surfaces.go`) the config-version/
  export surfaces — any of which a scripted integration or exported config file could depend on
  today. That crosses the same risk threshold the prior reviews used to defer T-9/T-10 rather than
  fold into a same-day, zero-risk pass.
- **Recommendation:** two options, in order of preference: (1) minimal — keep the wire values
  `"allow"`/`"deny"` (avoid a breaking API/config change) but rename the *GUI label* and any new
  documentation to spell out that the fallback is a two-state "Allow / Deny (no matching rule)"
  concept distinct from the four-state per-rule action, with an explicit one-line note near the
  Default Action control cross-referencing `Drop`/`Block_Page` as the closest per-rule analogues
  (mirrors how T-5's HA-panel fix added a clarifying note rather than a field rename); (2) if a
  future major-version API cleanup is ever justified, consider whether the fallback should instead
  be expressed as a restricted subset of `PolicyAction` (`Allow`/`Drop`/`Block_Page`, dropping
  `Redirect` which needs a target) rather than a parallel enum — deferred, larger surface.
- **Priority:** Medium (real admin/support/config-export correlation confusion; no functional bug).
  **Estimated PR size:** small for option (1) (GUI copy + one doc note, zero compatibility risk);
  medium-large for option (2) (API/config shape change, deferred further).

### T-12 — "Upgrade" (maintenance-agent wire API/packaging) vs. "Dispatch"/"update" (GUI/CLAUDE.md) for the same release-deployment operation (new — documented, not fixed)
- **Business concept:** pushing a pinned proxy image and restarting via the Maintenance Agent —
  what the GUI calls "Release Management" / "Dispatch."
- **Current names:**
  - GUI: "Dispatch Release" / "+ Dispatch" (`static/index.html:4011,4071,4096`); admin API
    `/api/releases/dispatch`; CLAUDE.md prose: "self-update"/"rolling update"/"day2 update path."
  - Maintenance Agent wire API and packaging: `POST /v1/upgrades/apply`, `POST /v1/upgrades/check`
    (`release_dispatch.go:577`, `cmd/culvert-maint/internal/ops/ops.go:81,88`);
    `packaging/systemd/culvert-maint.service:4,8` ("…drive backup, restore, cleanup, and (later)
    upgrade operations…"); `packaging/culvert-maint/config.example.toml:96` ("D1.6c upgrade target
    allowlist"); `cmd/culvert-maint/internal/config/config.go:90,94` ("Default upgrade-target
    image-ref allowlist"); `roadmap/D1.6-maintenance-agent-design.md` uses "upgrade" pervasively
    ("Standalone CP upgrade," "HA CP rolling upgrade," "pre-upgrade backup").
- **Why this is real drift:** an operator who configures `config.example.toml`, reads the systemd
  unit, or curls the agent directly (`docs/operator/release-management-agent.md` shows raw curl
  examples against the agent) sees "upgrade" everywhere at that layer, while the GUI/API layer they
  correlate it to calls the identical operation "Dispatch"/"update"/"Release Management" — a real
  cross-layer name split for a support engineer correlating a GUI action to agent-side logs/config.
  This is the same shape as T-10 (config/API layer keeping an original internal name while the
  UI/observability layer independently adopted a different canonical term) but in the
  release-management domain rather than content scanning.
- **Why it is NOT fixed in this pass:** the wire routes (`/v1/upgrades/apply`, `/v1/upgrades/check`)
  are a live contract between the proxy and the `culvert-maint` binary; renaming them, even though
  both ship from this repo, is not a same-day zero-risk change (needs a compatibility window for
  mixed-version fleets during a rolling update — precisely the scenario this feature exists to
  handle). The packaging/config naming (`config.example.toml`, `config.go` comments,
  `culvert-maint.service`) could be renamed with lower risk, but doing so without the wire rename
  would just relocate the split rather than close it.
- **Recommendation:** in a dedicated follow-up PR: (1) decide the single canonical term — "update"
  (already unanimous in GUI/API/CLAUDE.md; "dispatch" is the specific GUI action verb, "update" the
  broader concept) — (2) add `/v1/updates/apply`/`/v1/updates/check` as the primary wire routes with
  `/v1/upgrades/*` kept as a deprecated, logged-on-use alias for one release window (mirrors the
  alias approach T-10 recommends for `content_scan_*`/`dpi_*`), (3) rename the packaging/config
  comments and `config.example.toml` key documentation to "update," (4) leave
  `roadmap/D1.6-maintenance-agent-design.md` as a historical design record (not rewritten) but add
  a one-line terminology note at its top pointing to the canonical "update" term, matching how this
  document itself is never retroactively edited by later governance passes.
- **Priority:** Medium (genuine operator/support cross-layer confusion; no functional bug).
  **Estimated PR size:** medium — touches the agent wire protocol (needs alias/compat handling),
  `cmd/culvert-maint` config, packaging files, and one roadmap-doc note.

### Soft findings — no action recommended
- **"Role" labels two unrelated enums across GUI panels** — RBAC permission level
  (`admin`/`operator`/`viewer`, Admin Users panel) vs. cluster topology role
  (`control-plane`/`data-plane`/`standalone`, Cluster Overview panel). Each panel's own context
  disambiguates it; flagged only as the same *class* of risk as the Provider-collision pattern the
  2026-07-07 review's methodology looks for, not an instance of actual confusion observed. No
  change recommended.
- **"Profile" is reused across three unrelated domains** (`PolicyRule.FileProfile`,
  `PolicyRule.DecryptionProfile`, `CDRPolicyRule.ProfileName`) and **"Group" across three domains**
  (`SourceGroup`, category "Group," node "Group") — both are consistently qualified in every
  GUI/API surface (no bare "Profile"/"Group" appears without a qualifier where it could be
  ambiguous), so this is intentional-by-context rather than drift. Worth a glossary callout in
  developer docs if the schema grows a fourth "Profile"/"Group" concept, not urgent today.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium | T-10 (carried over from 2026-07-10, still open) | Alias `content_scan_*` config/API/audit names to `dpi_*` | Medium (config file + API + SIEM-facing audit strings) | Medium |
| Medium | T-9 (carried over from 2026-07-07, still open) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium (on-disk format, parity-test surface) | Medium |
| Medium | T-11 (new) | Clarify/reconcile the `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum (GUI copy first; API/schema change deferred) | Low for the GUI-copy option; medium-large if the enum itself is later unified | Small (copy) / Medium-large (schema) |
| Medium | T-12 (new) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*`, rename packaging/config comments to "update" | Medium (agent wire protocol, needs rolling-update-safe compat window) | Medium |
| Informational | T-1 (carried over, no action) | `/api/settings/unauth-mode` route name — already a documented, deliberate decision | N/A | N/A |

G-1 and G-2 are fixed in this change (one real bug fix, one completed cleanup of a prior partial
fix) and require no further action. T-8 (2026-07-10) remains closed.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent — this pass found and fixed one genuine functional/UX bug
that had been hiding behind a naming question (G-1), completed a previously-partial fix (G-2:
T-7), and surfaced two new findings (T-11, T-12) sized for dedicated follow-up, consistent with how
T-9 and T-10 continue to be handled. **T-9 and T-10 remain open after three consecutive review
passes** (2026-07-07, 2026-07-10, 2026-07-16) with unchanged, already-specified compatibility-alias
plans; this review deliberately did not execute them itself — both cross into on-disk/wire config
surfaces (`config_surfaces_test.go` parity, a live JSON API, a deployed `config.yaml`) where an
unsupervised background pass making the actual rename carries more downside than three passes'
worth of clear written specification carries upside. They are flagged here as ready for a deliberate,
reviewed PR rather than another same-day deferral. No cosmetic or preference-driven renames were
proposed or made in this pass.
