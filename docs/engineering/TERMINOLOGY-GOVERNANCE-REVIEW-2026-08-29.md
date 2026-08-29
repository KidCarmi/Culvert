# Culvert Language & Terminology Governance Review — 2026-08-29

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `403ef54..HEAD` (158 commits, 14 on the first-parent path — almost entirely the MCP
> Shadow-execution/canary-activation program: tool-trust approval, admission fairness, canary execution
> architecture, and the shadow/live-execution readiness split). Method: (1) full-repo grep for every
> `# ADR-NNNN` header, prompted by this window adding two new `docs/adr/` files (`0034`, `0035`) — checking
> whether either collided with an existing number, given this is now the fourth time in this program's
> history that two independent streams have raced for "the next number"; (2) diffed `static/index.html`
> (2 lines changed) and `frontend/src/api/types.gen.ts` (194 lines added, one new endpoint) for new
> GUI/API-doc copy; (3) checked every one of the sixteen still-open carry-over finding IDs' dependent files
> against this window's changed-file list (145 files) — none intersect, so all sixteen are re-confirmed
> unchanged by file-list absence; (4) on discovering the ADR collision, read every citation of the
> contested number across `docs/` and `internal/` to classify which meaning each one carries, rather than
> assuming from the number alone; (5) prompted by the collision being a *fourth* recurrence — one review
> cycle after the third — re-read the standing "new recommendation" from `TERMINOLOGY-GOVERNANCE-REVIEW-
> 2026-08-25.md` (a process-level ADR-numbering-collision guard, deliberately left unimplemented as "out of
> scope for a docs-only terminology pass" pending a fourth recurrence) and, having now observed one,
> implemented it; (6) spot-audited two GUI surfaces flagged by an independent terminology sweep of this
> repository against `docs/design/PRODUCT-TERMINOLOGY.md`'s own already-recorded rules — the "Appliance:
> Not used" row and the "Steering profile: never bare 'profile' on this screen" row — for violations
> introduced or left unresolved since those rules were written, since neither had previously been checked
> for GUI-string compliance rather than just documented as a rule.
> **Companion change:** four fixes ship with this review — a fourth ADR-numbering collision (this time
> finally closed with a mechanical guard instead of only a renumber), a bare-word "kill switch" collision
> across three unrelated subsystems, a documented-but-unenforced "steering profile" wording rule, and two
> genuine "Appliance" leaks into GUI/API-doc copy the rule was written specifically to prevent.

---

## Executive Summary

**Headline finding: the ADR-numbering collision recurred a FOURTH time, exactly as the prior review
predicted, and this pass finally lands the mechanical guard instead of a fifth manual renumber.**
`docs/adr/0034-mcp-tool-trust-approval.md` (ACCEPTED 2026-08-28, deeply wired into `internal/mcp/tooltrust`,
`mcp_tooltrust.go`, `ui_mcp_tooltrust.go`, and 40+ other citations) landed the very next window after the
08-25 review renumbered the still-**PROPOSED, NOT ADOPTED** support RFC to `0034` — reclaiming the number a
third time in three review cycles. Same root cause as T-16, T-46, and T-47: no reservation mechanism exists
for architecture-decision-record numbers, so "grep the tree for the next free one" is a race two independent
branches can both win. **Fix:** the established, code-wired, ACCEPTED decision keeps `0034`; the RFC
(`docs/support/rfc/0034-ai-receives-normalized-evidence.md`, unchanged status since 2026-07-13) is
renumbered to `0036` — the next number confirmed clean against every `# ADR-NNNN` header in the repository,
including both new files from this window (`0034`, `0035`) — with its five downstream citations
(`docs/support/TAC-CLOUD-ARCHITECTURE.md` ×3, `docs/support/SUPPORTABILITY-THREAT-MODEL.md` ×1,
`docs/adr/0016-raw-evidence-vs-normalized-findings.md`'s "Relates to" line ×1) updated to match. **New this
pass: a fourth recurrence is the threshold the 08-25 review set for moving past "keep fixing it each time it
happens."** `docs_adr_numbering_test.go` is a new root-package test that walks `docs/adr/` and
`docs/support/rfc/`, extracts each file's self-declared `# ADR-NNNN` header, and fails with an actionable
message naming every colliding file the moment two files ever claim the same number again. It was verified
failing against the reintroduced pre-fix collision (both `0034` files present) and passing against the fix,
matching this repository's own "defect gates must be proven against the shape they catch" convention. This
closes the standing process recommendation; a fifth recurrence should now be structurally impossible rather
than merely likely to be caught within a few days by the next scheduled review.

**A second, previously-undocumented collision: "kill switch" is used, unqualified, for three unrelated
safety mechanisms visible in the same admin GUI.** `authExemptKillSwitchEngaged`/`CULVERT_AUTHBYPASS_DISABLE`
(the Stage-1 Exempt-outcome fail-safe when no credential-capable backend is configured; extensively tested
across nine `authpolicy_*_test.go` files going back to Phase 2) is a long-established, independently correct
name in its own domain. So is the MCP rollout's per-capability `EngageKillSwitch`/`ClearKillSwitch` emergency
admission stop, and so is the C2 governance `CULVERT_C2_ENFORCE` revert-to-shadow toggle. None of the three
should be renamed — each is a tested, domain-appropriate fail-safe name, and `PRODUCT-TERMINOLOGY.md` already
tracks several terms (Profile, Bypass, Engine) that legitimately mean different things in different bounded
contexts. But two of the three already self-qualify on screen ("Authentication kill switch" was NOT one of
them — the Auth Policy Simulator rendered bare **"Kill switch engaged"** with no qualifier, one screen away
from the MCP Command Center's "Emergency kill switch active on gateway/management" and the Governance panel's
"Kill switch: `CULVERT_C2_ENFORCE`"). Fixed: `static/index.html`'s Auth Policy Simulator string now reads
"**Authentication** kill switch engaged"; `PRODUCT-TERMINOLOGY.md` gains a **Kill switch** row recording all
three concepts and the qualifier-not-rename rule, so a future fourth kill-switch-shaped mechanism has
somewhere to check before reusing the bare word.

**A third, previously-undocumented violation of an existing rule: the Steering Profiles screen said bare
"Profile" inside the very panel `PRODUCT-TERMINOLOGY.md` already singles out as needing "always 'steering
profile,' never bare 'profile.'"** Five strings — the "+ New Profile" button, "Profile ID (URL-safe)" field
label, "Save Profile" button, the Steering Simulator's prose ("what a profile would return"), and its
"Profile" dropdown label — violated a rule written specifically for this screen, one panel below where the
rule itself explains *why* ("the fourth distinct Profile concept alongside file/decryption/CDR profiles").
All five now say "Steering Profile" / "steering profile." Verified the `data-click` attributes the one
Playwright e2e test covering this panel (`ui_pac_e2e_test.go`) selects on are unchanged — the test targets
element attributes, not button text, so it is unaffected.

**A fourth, previously-undocumented finding: two genuine "Appliance" leaks into GUI/API-documentation text,
the exact pattern `PRODUCT-TERMINOLOGY.md`'s "Appliance: *Not used* ... avoid inventing appliance language"
row exists to prevent.** The v2 frontend's login screen (`frontend/src/features/auth/AuthScreen.tsx`)
labeled its management-plane identity row **"Appliance"** where the legacy GUI and every other screen say
"Node" — now `<dt>Node</dt>`. `GET /api/settings`'s OpenAPI summary/description said "Appliance settings
summary" / "Returns core appliance settings" and its `settings` tag said "Appliance settings — logging,
session, connection limits" — now "Node settings summary" / "Returns core node settings" / "Node settings —
logging, session, connection limits," regenerated end to end (`make api-bundle` → `openapi.json`/
`index.html`; `frontend/src/api/types.gen.ts`'s two corresponding JSDoc lines hand-synced to match, since the
frontend's pinned-toolchain generator (Node v24.19.0/npm 11.17.0 per `.node-version` — a CI-enforced
"toolchain identity gate") is not available in this environment; the substitution is a mechanical two-line
text swap with no structural change, and the repository's own `frontend-verify.yml` drift gate will confirm
byte-exactness against the real generator on the next CI run). **Not actioned, and recorded as a soft
finding rather than a fix:** `x-culvert-tenant-scope: appliance` (~350 occurrences in `openapi.yaml`) is a
structural vendor-extension classification value, not user-facing product language — out of scope for the
same reason the 07-31B review declined to touch an internal build-tag comment saying "the appliance ships as
a Linux container." Likewise left alone: the OpenAPI spec's general descriptive prose ("This appliance and
its documentation are designed for...", "The appliance serves this API...") and the two "never a stable
appliance fingerprint" negative-constraint phrases (support-telemetry sample epoch) — none of these name a
labeled product concept the way "Appliance settings summary" or a GUI `<dt>` did; renaming generic descriptive
prose on spec would be exactly the cosmetic, non-mechanical rename this program declines to make. Also noted,
not actioned: `frontend/src/design-system/appliance.tsx`/`.module.css` ("Golden appliance components") is an
internal design-system module name with zero rendered user-facing text (verified: its only consumers,
`GalleryPage.tsx` and `DiagnosticsPage.tsx`, import fixture types and components, not the string "Appliance"
itself) — same "internal, zero visibility, not new invention" disposition as the 07-31B build-tag comment.

**Terminology Health Score: 8.8 / 10** (up from 8.6 — the ADR-numbering defect class is now closed by a
mechanical CI-visible guard after four recurrences instead of remaining a recurring manual fix, and three
previously-undocumented, zero-risk GUI/doc collisions were found and fixed in the same pass: the unqualified
"kill switch" ambiguity, the Steering Profiles panel's own rule violation, and two genuine "Appliance" leaks
into user/developer-facing text. The score does not move further because the sixteen-item carry-over backlog
is unchanged (none of those items' dependent files were touched by this window's diff), and because this
pass's own discovery method — checking existing `PRODUCT-TERMINOLOGY.md` rules for GUI-string compliance
rather than assuming a written rule is an enforced one — surfaced three real violations on the first attempt,
suggesting other documented-but-unverified rows in that table may repay the same check in a future pass.)

---

## Findings

### T-48 — Fourth recurrence of the ADR-numbering collision, on `0034`; closed with a mechanical guard (new — fixed this pass)

- **Business concept:** the unique identifier for one architecture decision record, AND (new this pass) the
  absence of any mechanism preventing two decision records from claiming the same identifier.
- **Current names before this fix:** `# ADR-0034` claimed simultaneously by
  `docs/adr/0034-mcp-tool-trust-approval.md` (ACCEPTED 2026-08-28; the MCP tool-trust source-of-truth and
  approval-purpose-binding decision, cited from 40+ code and doc sites) and
  `docs/support/rfc/0034-ai-receives-normalized-evidence.md` (PROPOSED — NOT ADOPTED, dated 2026-07-13,
  itself only renumbered to `0034` in the immediately prior review cycle after colliding on `0032`).
- **Recommended canonical name:** `docs/adr/0034-mcp-tool-trust-approval.md` keeps ADR-0034 (established,
  ACCEPTED, code-wired across `internal/mcp/tooltrust`, `mcp_tooltrust.go`, `ui_mcp_tooltrust.go`,
  `ui_mcp.go`, `mcp_shadow_preflight.go`, `main.go`, `ui_routes_meta.go`, `internal/mcp/catalog`,
  `internal/mcp/mcperr`, `internal/mcp/execution`, and multiple docs — by a wide margin the more expensive of
  the two to move); the RFC becomes ADR-0036.
- **Why the current naming was problematic:** identical to T-16, T-46, and T-47 — a bare "ADR-0034" citation
  was ambiguous between the MCP tool-trust decision and the AI-input-normalization decision, with no way to
  disambiguate from the number alone; unlike the prior three instances, this is the same defect recurring a
  fourth time, and a second time within roughly one review cycle of the previous fix.
- **Why the new name is better:** restores a 1:1 mapping between decision-record number and decision; `0036`
  is confirmed clean against every `# ADR-NNNN` header in the repository as of this pass, including both new
  files from this window; the accompanying test makes a fifth collision fail CI immediately rather than wait
  for the next scheduled governance pass to notice.
- **Affected code:** new file `docs_adr_numbering_test.go` (root package; no production code touched).
- **Affected API:** none.
- **Affected GUI:** none.
- **Affected Documentation:** `docs/support/rfc/0034-ai-receives-normalized-evidence.md` renamed to
  `0036-ai-receives-normalized-evidence.md` (header updated), `docs/support/TAC-CLOUD-ARCHITECTURE.md` (3
  citations), `docs/support/SUPPORTABILITY-THREAT-MODEL.md` (1 citation),
  `docs/adr/0016-raw-evidence-vs-normalized-findings.md` (1 "Relates to" citation).
- **Affected Configuration:** none.
- **Verification:** `go build ./...` clean; `go test -run TestADRNumbersAreUnique .` passes on the fixed
  tree; verified failing (both `0034` files present, exact colliding paths named in the failure message) when
  the pre-fix collision was reintroduced, then confirmed the restore was byte-identical to the fix and the
  test passes again — the defect-gate-proof convention this repository already uses elsewhere
  (`shutdown_chaos_test.go`, `cluster_ca_chaos_test.go`, etc.) applied to a docs-governance gate for the first
  time in this program.
- **Migration Complexity:** Trivial (docs-only renumber, one new stdlib-only test file, zero code/API/GUI
  surface).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** High — not because any individual renumber is urgent (Medium, matching T-16/T-46/T-47), but
  because the defect class recurring a fourth time, twice within one review cycle, made "the next scheduled
  review will catch it" no longer an adequate control; closing it mechanically is the higher-priority action
  in this pass.

### T-49 — "Kill switch" names three unrelated safety mechanisms visible in the same admin GUI, one of them unqualified on screen (new — fixed this pass)

- **Business concept:** three independent, individually well-named safety/fail-safe mechanisms that happen
  to share one bare English phrase: (1) the Stage-1 authentication Exempt-outcome fail-safe
  (`authExemptKillSwitchEngaged`, `CULVERT_AUTHBYPASS_DISABLE`, `authpolicy.go`), (2) the MCP rollout's
  per-capability emergency admission stop (`EngageKillSwitch`/`ClearKillSwitch`,
  `internal/mcp/rollout/state.go`), (3) the C2 governance enforcement-mode revert-to-shadow toggle
  (`CULVERT_C2_ENFORCE`, `ui_governance.go`).
- **Current names before this fix:** all three rendered as "kill switch" in GUI copy in the same admin
  console: Auth Policy Simulator — bare **"Kill switch engaged"** (`static/index.html:15143`, no qualifier);
  MCP Command Center — **"Emergency kill switch active on gateway/management"** (`static/index.html:19130-
  19131`, already self-qualified as MCP-scoped and "emergency"); Governance panel — **"Kill switch:
  `CULVERT_C2_ENFORCE`"** (`static/index.html:17452`, already self-qualified by showing the env var name
  inline).
- **Recommended canonical name:** not a rename of any of the three underlying mechanisms (each is
  independently well-established and heavily tested in its own domain) — a qualifier on the one surface that
  lacked one. "Authentication kill switch" for (1), matching the pattern the other two already followed.
- **Why the current naming was problematic:** an admin or support engineer reading "the kill switch is
  active" out of context, or grepping a screenshot/log excerpt, could not tell which of three structurally
  unrelated mechanisms was meant — one is a runtime auth fail-safe reacting to backend availability, one is
  an admin-triggered emergency stop with its own generation counter and durable state, and one is a
  build/env-time governance override read once at startup. This is exactly the class of ambiguity
  `PRODUCT-TERMINOLOGY.md` exists to prevent, and none of the three concepts nor their shared name had ever
  been recorded in that document.
- **Why the new name is better:** "Authentication kill switch" disambiguates immediately and matches the
  self-qualifying pattern already used by the other two mechanisms' GUI copy, at zero cost to the two mature,
  independently-correct subsystem names.
- **Affected code:** `static/index.html` (one string).
- **Affected API:** none (the underlying `killSwitch`/`KillSwitch` JSON field names and Go identifiers are
  unchanged — this is copy-only, per the "never rename a stable, tested public field for a documentation
  clarity issue" guidance).
- **Affected GUI:** Auth Policy Simulator panel.
- **Affected Documentation:** `docs/design/PRODUCT-TERMINOLOGY.md` (new **Kill switch** row).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (one GUI string, one doc row).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Medium — no functional ambiguity (the underlying mechanisms behave correctly and
  independently), but a real support/onboarding clarity gap on a security-relevant surface.

### T-50 — Steering Profiles panel violates its own already-documented "never bare 'profile'" rule (new — fixed this pass)

- **Business concept:** a PAC traffic-steering ruleset assigning client networks to proxy pools
  (`internal/pac`, `/api/pac/profiles`) — already canonically named "Steering Profile" in
  `PRODUCT-TERMINOLOGY.md`, with an explicit note that it is "the fourth distinct Profile concept alongside
  file/decryption/CDR profiles" and a rule to "always say 'steering profile,' never bare 'profile,' on this
  screen."
- **Current names before this fix:** within the Steering Profiles panel and its adjoining Steering Simulator
  (`static/index.html:2302-2390`), five strings said bare "Profile": the "+ New Profile" button
  (line 2308), the "Profile ID (URL-safe)" field label (line 2319), the "Save Profile" button (line 2343),
  the simulator's prose "Explain what a profile would return..." (line 2385), and the simulator's "Profile"
  dropdown label (line 2390).
- **Recommended canonical name:** "Steering Profile" / "steering profile" — the name the rule already
  prescribes for this exact screen.
- **Why the current naming was problematic:** the rule this violates was written specifically because
  "Profile" is overloaded four ways in this product (file profile, decryption profile, CDR profile, steering
  profile); a screen that mixes bare "Profile" with the panel title "Steering Profiles" reintroduces the
  exact ambiguity the rule exists to close, in the one screen the rule calls out by name.
- **Why the new name is better:** brings the panel into compliance with a rule that was written for it and
  had simply never been checked against the shipped strings.
- **Affected code:** `static/index.html` (five strings).
- **Affected API:** none.
- **Affected GUI:** Steering Profiles panel, Steering Simulator panel (both under the PAC nav section).
- **Affected Documentation:** none (the rule already existed; this closes the gap between rule and
  implementation).
- **Affected Configuration:** none.
- **Verification:** confirmed `ui_pac_e2e_test.go`'s `TestUIE2E_PACEditorsOpen` — the one Playwright e2e test
  covering this panel — selects elements by `data-click` attribute (`[data-click="newPACProfile"]`), not by
  button text, so it is unaffected by the label changes; `go build ./...` clean.
- **Migration Complexity:** Trivial (GUI copy only).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Low-Medium — no functional impact, but a documented rule silently unenforced on its own
  named screen since the rule was written (2026-07-11).

### T-51 — "Appliance" leaks into two user/developer-facing surfaces the terminology doc already forbids it from (new — fixed this pass)

- **Business concept:** a single deployed Culvert instance — canonically "**Node**" per
  `PRODUCT-TERMINOLOGY.md` ("Appliance: *Not used.* Culvert deploys as binary/container; the UI says node or
  instance").
- **Current names before this fix:** the v2 frontend's login screen showed a management-plane identity row
  labeled **"Appliance"** (`frontend/src/features/auth/AuthScreen.tsx:72`, `<dt>Appliance</dt>` next to
  `window.location.host`) where every other screen and the legacy GUI say "Node"; `GET /api/settings`'s
  OpenAPI summary/description said "**Appliance** settings summary" / "Returns core **appliance** settings"
  and its `settings` tag said "**Appliance** settings — logging, session, connection limits"
  (`api/openapi/openapi.yaml`), propagating into the generated API docs page and
  `frontend/src/api/types.gen.ts`'s JSDoc comments.
- **Recommended canonical name:** "Node" for the login-screen label; "Node settings" for the API
  summary/description/tag, matching every other reference to this endpoint's subject.
- **Why the current naming was problematic:** this is precisely the invented product-identity language the
  terminology doc's "Appliance: Not used" row exists to prevent — the login screen is the very first thing an
  admin sees in the new frontend, and it disagreed with the product's own established vocabulary on its own
  identity field.
- **Why the new name is better:** consistent with every other node/instance reference across both GUIs, the
  OpenAPI spec's own `Node`-scoped concepts (cluster/enrollment), and the terminology doc's explicit rule.
- **Affected code:** `frontend/src/features/auth/AuthScreen.tsx` (one label), `api/openapi/openapi.yaml`
  (summary, description, tag description — 3 strings).
- **Affected API:** `GET /api/settings` (human-readable OpenAPI summary/description only — no field, path, or
  schema change; `SettingsSummary` schema and its JSON fields are untouched).
- **Affected GUI:** v2 login screen (`/app` route, `CULVERT_EXPERIMENTAL_UI`-gated, default off).
- **Affected Documentation:** `api/openapi/openapi.json`, `api/openapi/index.html`,
  `frontend/src/api/types.gen.ts` regenerated/synced to match (see verification).
- **Affected Configuration:** none.
- **Verification:** `make api-bundle` regenerated `openapi.json`/`index.html`/`index.public.html`/
  `docs/api/API-INVENTORY.md` from the edited spec; `make api-bundle-check` confirmed the committed artifacts
  are exactly what the spec produces. `frontend/src/api/types.gen.ts`'s two corresponding JSDoc lines were
  hand-synced to the same text (its generator requires the pinned Node v24.19.0/npm 11.17.0 toolchain, not
  available in this environment; the change is a mechanical two-line text substitution with no structural
  diff, and `frontend-verify.yml`'s existing drift gate will independently confirm byte-exactness against the
  real generator on the next CI run — flagged here rather than silently assumed correct). `go build ./...`
  clean. Not actioned: `x-culvert-tenant-scope: appliance` (~350 occurrences, a structural vendor-extension
  classification value, not user-facing product language); general descriptive prose in the OpenAPI `info`
  block and two "never a stable appliance fingerprint" negative-constraint phrases (neither names a labeled
  concept); `frontend/src/design-system/appliance.tsx` (internal component-library module name, zero rendered
  user-facing text, same disposition as the 07-31B build-tag-comment finding).
- **Migration Complexity:** Trivial (GUI/doc copy + generated-artifact regen, no schema change).
- **Compatibility Risk:** None (no JSON field, path, or type change).
- **Estimated PR Size:** Small.
- **Priority:** Medium — confined to a default-off preview surface and one endpoint's documentation text, but
  the exact pattern (a "no appliance language" rule silently violated on a primary screen) a prior review
  (08-22, the Dashboard/Overview finding) already flagged as worth catching before the frontend's first
  production exposure rather than after.

---

## Carried-Over Findings (unchanged — re-confirmed by file-list absence)

All sixteen remaining previously-open finding IDs were re-checked against this window's 145-file changed
list; none of their dependent files appear in it, so each is re-confirmed open and unchanged with no further
diffing needed: T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21 + T-32 (paired), T-25 (residual), T-29,
T-30, T-31, T-33, T-34, T-39. Full descriptions remain in the reports where each was first raised and in
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md`'s carry-over list, to avoid duplicating unchanged text.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-25 for the still-open carry-over items; T-48 through T-51 are resolved in this pass and do
not appear on the plan.

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium-High | T-39 (carried over) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename `qualification_inventory_file`/`qualification_telemetry`/`qualification_policy_file` and their operator-doc titles/GUI strings away from bare "qualification"; reserve that word for the Production receipt gate | Medium | Small-Medium (needs a naming decision first) |
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-21 + T-32 (carried pairing) | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 (carried over) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 (carried over) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-33 (carried over) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field for those instead | None today (zero production consumers); rises once a consumer exists | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 (carried over) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit | Low | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass closed a process-level gap that four prior findings
(T-16, T-46, T-47, and now T-48) had each individually worked around but never fixed: a mechanical guard now
makes a fifth ADR-numbering collision fail CI immediately. It also found and fixed three previously-
undocumented, zero-migration-risk collisions by checking existing `PRODUCT-TERMINOLOGY.md` rows for actual
GUI-string compliance rather than assuming a documented rule is an enforced one: the unqualified
"kill switch" ambiguity across three subsystems (T-49), the Steering Profiles panel's violation of its own
already-written rule (T-50), and two genuine "Appliance" leaks into user/developer-facing text (T-51). All
sixteen still-open carry-over findings were re-confirmed unchanged. No cosmetic or preference-driven renames
were proposed; every fix in this pass is copy/docs/test-only with zero API, schema, or wire-format change.
This review's discovery method for T-49–T-51 (auditing existing documented rules for compliance, rather than
only scanning new diffs for new drift) surfaced three real findings on its first application and is worth
repeating in a future pass against the remaining rows of `PRODUCT-TERMINOLOGY.md`.
