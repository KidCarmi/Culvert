# Culvert Language & Terminology Governance Review — 2026-07-31

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Four parallel audit lanes against the tree at `6810fce`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-07-24.md` (baseline `2eef667`, 180 commits prior). Lane 1
> re-verified the M7 proactive-telemetry work now that it has shipped real code (Slices 1–2:
> `support_telemetry_registry.go`, telemetry preview/consent/bearer-config, admin GUI) against the
> 07-24 fix that renamed its stateful entity from the glossary-banned "Incident" to "degradation"
> pre-implementation. Lane 2 re-audited the ~59-commit `docs/design/mcp/` + `docs/adr/` "round N"
> self-review sweep for new ADR collisions or unpropagated renames. Lane 3 re-verified all nine
> still-open carried-over findings (T-9, T-11, T-12, T-13 residual, T-16, T-17, T-18, T-21, T-25
> residual) against every commit that touched their surface area. Lane 4 swept the remainder of the
> 180-commit diff (sslbypass normalization, OTLP push-health, kin-openapi dependency bump, connlimit,
> admin-user creation, urlcat feed-status) for new drift outside the other three lanes' scope.
> **Companion change:** one zero-risk, doc-only fix ships with this review (see "Fixed in this
> change"). No REST route, JSON field, CLI flag, config key, audit-event name, or exported Go
> identifier was renamed.

---

## Executive Summary

This is the cleanest pass since the review cadence started. Three of the four lanes found **zero new
drift**: the M7 telemetry code that shipped since the last review correctly carries forward the
07-24 pre-implementation fix — grep across every new Slice 1/2 file (`support_telemetry_registry.go`,
`support_telemetry_config.go`, `support_telemetry_preview.go`, `support_telemetry_bundle.go`) returns
no hits for "incident" at all, and the `support_uptime_bucket` metric ID matches the corrected design
doc exactly. The MCP design-doc set's ~59-commit "round N" self-review sweep (its own internal
terminology-correction process, now CI-enforced via `predicates/predicate-24.py` and friends) shows no
new ADR-numbering collisions and full propagation on every rename spot-checked. Eight of the nine
carried-over open findings are completely untouched by the 180 intervening commits — the files
involved simply weren't in this window's diff.

The one genuine new finding is a small, familiar failure class this program has now caught twice: a
dependency version bump (`getkin/kin-openapi` v0.144.0 → v0.145.0, merged the same day as this review)
landed in `go.mod` without its four doc mentions being updated — the same class of drift the 07-19→
07-24 window already fixed once for the same package (commit `5e18664`). Fixed directly below.

The ninth carried-over finding, **T-18 ("Seal" names two unrelated cryptographic operations)**, grew
again: M7's telemetry-preview GUI copy added two more bare "Seal" strings describing a future,
not-yet-implemented sender path (`static/index.html:4440,4453`), on top of the ~20 existing TAC-upload/
export GUI strings the 07-24 review already catalogued. No code backs the new strings yet — a test
(`support_telemetry_golden_fixture_test.go:1493`) explicitly forbids `seal*`/`unseal*` identifiers in
this slice, deferring the real work to a future TAC slice — but the GUI-copy blast radius keeps
growing every time a new feature touches this surface. This reinforces last review's recommendation:
**T-18 should be the next dedicated terminology PR**, before a third or fourth feature adds more bare
"Seal" copy on top.

**Terminology Health Score: 8.5 / 10** (unchanged from 07-19 and 07-24 — a review this clean, on a
program shipping real features every week, reflects the governance cadence working as designed rather
than an absence of things to check).

**Fixed in this change (doc-only, zero compatibility risk):**

- **T-29 — `kin-openapi` version references went stale one release after the last fix.** `go.mod`
  now pins `github.com/getkin/kin-openapi v0.145.0` (dependabot, merged 2026-07-31 — the same day as
  this review), but `docs/api/API-IMPLEMENTATION-REPORT.md:70`, `docs/api/API-OPENAPI-RESEARCH.md`
  (lines 24, 56, 126), and `docs/adr/0018-openapi-contract.md:81` still cited `v0.144.0`. This is the
  identical failure class the 07-19→07-24 window already fixed once for this exact package (commit
  `5e18664`, "update kin-openapi version references from v0.142.0 to v0.144.0") — the fix held (no
  stale `0.142.0` reference survives anywhere in the repo), but the *next* bump reintroduced the same
  staleness one version later, because nothing enforces doc/go.mod parity for this package. Updated
  all four references to `v0.145.0`. Doc-only; no behavior, API, or schema change. **Recommend a
  standing fix**, not just this one-off: either drop the specific version number from prose (say
  "the pinned `go.mod` version" instead of hardcoding it in four places) or add it to the existing
  `go.mod`-vs-doc parity class of CI checks this repo already runs for other pinned dependencies —
  sized as a Low-priority follow-up in the plan below.

**Documented, not fixed this pass (unchanged from 07-24 unless noted):**

- **T-18 (carried over, grown again)** — now the top recommendation for the next dedicated
  terminology PR (see Findings and Recommended Refactoring Plan).
- **T-9, T-11, T-12, T-13 residual, T-16, T-17, T-21, T-25 residual** — all re-confirmed unchanged;
  none of the 180 commits since 07-24 touched their surface area. No new evidence to add.

---

## Lane 1 — M7 proactive telemetry (Slices 1–2, now shipped) re-verified clean

Since 07-24, M7 shipped its first real code: "Slice 1: scoped support-metric registry + telemetry
preview" and "Slice 2: telemetry consent, bearer config, and admin GUI" (`support_telemetry_registry.go`,
`support_telemetry_config.go`, `support_telemetry_preview.go`, `support_telemetry_bundle.go`,
`static/index.html` telemetry panel). The 07-24 review's pre-implementation catch — renaming M7's
stateful entity from the glossary-banned "Incident" to "degradation" before any code existed — held:

- Zero hits for "incident" (case-insensitive) in any new M7 file. Every remaining "incident" hit in
  the repo traces to the pre-existing, correct, out-of-scope M3 "incident scope" catalog
  (`support_scopes.go`, `ui_support.go`, `internal/support/{runner,manifest}.go`) — a stateless,
  unrelated concept the glossary has always allowed.
- The `support_uptime_bucket` metric shipped exactly as the 07-24 review's superseded note predicted
  (`support_telemetry_registry.go:96`), matching the design doc's own explanatory correction
  (`M7-proactive-telemetry-plan.md:504`).
- Telemetry/consent/bearer-config vocabulary is consistent top-to-bottom: the Go struct
  (`Enabled`/`Origin`/`Credential`), the JSON wire (`enabled`/`origin`/`credential`/
  `clear_credential`), and the GUI field ids (`telemetry-origin`, `telemetry-enabled`,
  `telemetry-credential`) all agree; "consent" is used only as prose describing `Enabled`, never as a
  second competing field name.

Two Low-priority, non-blocking notes carried into "Soft findings" below (a "support-health" wording
overlap with the pre-existing Health-verdict widget, and new M7 vocabulary — "Telemetry," "Consent,"
"Bearer credential," "support-health scalar" — that has no `PRODUCT-TERMINOLOGY.md` row yet since the
glossary predates M7). Neither is a violation or requires a code change.

## Lane 2 — MCP design-doc set (`docs/design/mcp/`, `docs/adr/`) re-verified clean

59 commits landed on this doc set since 07-24, all doc-only — the set's own internal "round N"
self-review loop (now CI-gated: `ci(mcp): run design predicates in the required fast gate`,
`predicates/predicate-19.py` through `predicate-29.py`). Checked and confirmed clean:

- **No new ADR-numbering collision.** The T-16 collision (0008–0011, decryption-exclusion track vs.
  Supportability track) is unchanged — same two pairs, no third track added. A new ADR,
  `docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md`, claims an unclaimed number and does
  not collide with anything, including the 0019–0022 range still reserved for T-16's eventual
  renumber.
- **No unpropagated renames.** Spot-checked the three largest terminology corrections visible in the
  commit log ("denial lockout" → "denial-event lockout"/removed entirely per a later design change,
  "Management Host/Origin" → resolved header-validation terminology, `MCP-CRED-006` →
  `MCP-POLICY-004` citation fix) — all fully propagated; the only surviving "denial lockout" strings
  live in the set's own historical changelog file narrating what a past round found and fixed, not in
  a normative spec.
- **No new collision with the shipped product glossary.** The doc set still doesn't cite
  `PRODUCT-TERMINOLOGY.md` directly (as before), and no newly-added MCP term collides with a shipped
  product term outside the already-self-declared "Action" divergence noted in the 07-24 review.
- Still 100% design-doc-only — no `internal/*mcp*` package or `package mcp` exists yet, so any
  residual naming decisions remain cheap to change.

## Lane 3 — Carried-over findings re-verified

| Finding | Status this pass |
|---|---|
| T-9 (`exportedAt`→`capturedAt`) | Unchanged, not touched — `configversion.go` had zero commits in the window. |
| T-11 (`allow`/`deny` vs. 4-value `PolicyAction`) | Unchanged — the two `policy.go`/`ui_policy.go` commits in-window are unrelated (schedule-eval perf, URL-category feed status). |
| T-12 (Maintenance-Agent `/v1/upgrades/*` vs. GUI "update") | Unchanged — no renames or aliases added. |
| T-13 residual (README "TLS Inspection" vs. in-app "SSL") | Unchanged — README's one touch this window is an unrelated Go-version fix. |
| T-16 (ADR 0008–0011 collision) | Unchanged in scope (see Lane 2); renumber target still 0019–0022. |
| T-17 (`decryption_redact_hosts`/`/api/decryption/redaction`) | Unchanged — no commits touched the relevant files. |
| **T-18 ("Seal" collision)** | **Grown.** See Findings below — now the top recommendation for the next dedicated terminology PR. |
| T-21 (`cp_version`/"CP Config Version" vs. rollback "Config Version") | Unchanged — `cluster_convergence.go` and its GUI untouched. |
| T-25 residual (Sealing-recipients vs. TAC-trust-key registries) | Unchanged since the 07-24 GUI-copy fix — `support_recipients.go`/`support_tac_trust.go` had zero commits this window. |

## Lane 4 — Remainder of the diff (sslbypass, OTLP, dependency bumps, misc.)

Swept everything outside Lanes 1–3's scope: `internal/sslbypass` two-pass normalization work, the new
OTLP push-health surfacing (`f583267`), the `kin-openapi` dependency bump, `connlimit` (no changes in
window), the admin-user empty-password fix, and urlcat feed-status additions. All clean except the
`kin-openapi` version-doc skew fixed above (T-29). One comment-only, non-actionable note: a new code
comment in `nofollow_windows.go:25` ("the appliance ships as a Linux container") extends — but does
not introduce — a pre-existing, unchanged "appliance" comment pattern already present in
`nofollow_unix.go:16`; `PRODUCT-TERMINOLOGY.md` scopes its "avoid inventing appliance language" rule to
"UI labels, docs, and new code," but this is an internal build-tag comment with zero user visibility,
not new invention. Folded into "Soft findings," no action recommended.

---

## Findings

### T-29 — `kin-openapi` doc version skew (FIXED)
- **Business concept:** the pinned version of the `getkin/kin-openapi` dependency, as cited in
  operator/API-contract documentation.
- **Current names before fix:** `go.mod` said `v0.145.0`; four doc locations
  (`API-IMPLEMENTATION-REPORT.md:70`, `API-OPENAPI-RESEARCH.md:24,56,126`,
  `0018-openapi-contract.md:81`) still said `v0.144.0`.
- **Why this is real drift:** identical failure class to the 07-19→07-24 window's `5e18664` fix for
  the same package — a version bump lands in `go.mod` without a corresponding doc-sync commit,
  repeatedly, because nothing currently enforces the parity.
- **Fix:** updated all four references to `v0.145.0`. Doc-only, zero compatibility risk.
- **Priority:** was Low. **Recommended standing fix (not done this pass):** stop hardcoding the exact
  version number in prose (reference "the pinned `go.mod` version" instead), or extend this repo's
  existing dependency-pin CI parity pattern to cover doc mentions of `kin-openapi` specifically, so a
  third recurrence doesn't require a third manual pass.

### T-18 — "Seal" names two unrelated cryptographic operations (grown further, still deferred)
- **Business concept:** two operations share the bare word "Seal"/"sealed": (1) the M6 NaCl one-way
  TAC/support-bundle export operation (`internal/sealbox.Seal`/`Open`, called from
  `support_export.go:207` and, via `sealBundleToTAC`, `support_tac_trust.go:247` /
  `support_upload_wire.go:159,217`); (2) the unrelated KEK-at-rest key-wrapping operation
  (`internal/secret.Seal`, ~17 call sites across `dp_node_keyatrest.go`, `cdr_client_keyatrest.go`,
  `cluster_ca_keyatrest.go`, `enrollment.go`, `cdrstore.go`, `internal/secret/secret.go`).
- **What's new this pass:** M7's telemetry-preview GUI added two more bare "Seal" strings
  (`static/index.html:4440`: "would be periodically sealed end-to-end and sent to TAC";
  `:4453`: "preview of the exact governed support-health sample that would be sealed and sent"),
  describing a *future* telemetry-sender path with no backing code yet — a test
  (`support_telemetry_golden_fixture_test.go:1493`) explicitly forbids `seal*`/`unseal*` identifiers
  in the shipped slice, so the real implementation (and its naming) is deferred to a later TAC slice.
  This adds a third GUI surface reusing "Seal" on top of the ~20 existing TAC-upload/export strings the
  07-24 review already catalogued (buttons, tooltips, toasts, confirms).
- **Why this keeps mattering:** the two concepts are cryptographically and operationally unrelated
  (one is a one-way public-key envelope to an external party, the other is at-rest key wrapping under
  a local KEK) and every new feature that touches the TAC-upload surface reaches for the same bare
  word by precedent, growing the eventual rename's footprint without anyone deciding to.
- **Recommended canonical name:** unchanged from prior reviews — rename the NaCl one-way TAC/export
  operation to something naming its trust property (e.g. "seal-to-recipient" / "TAC envelope") and
  reserve bare "Seal" for the KEK-at-rest sense, or vice versa; then update the ~7 code identifiers,
  ~20+ GUI strings, and one audit-event string together.
- **Priority:** Medium, and the top recommendation for the next dedicated terminology PR — deferred
  again this pass only because a coordinated GUI+code rename is out of scope for a doc-audit-cadence
  review, not because the size has stopped growing.

## Soft findings — no action recommended

- **M7 "support-health" wording overlap (Low, informational).** The pre-existing Health-verdict
  widget (`static/index.html:4353`, `id="support-health"`, M1/diagnostics `OperatorContract`-backed
  pass/fail checklist) sits in the same Support panel as M7's new telemetry copy calling its payload
  "support-health scalars"/"a support-health sample" (`static/index.html:4440,4453`, backed by the
  unrelated `supportMetricRegistry`). Same panel, same "health" word, two different data models
  (checks-with-verdict vs. scalar gauges). Not an ID collision — different DOM elements — but worth a
  glossary/copy pass if a support engineer ever reports confusing the two.
- **New M7 vocabulary absent from `PRODUCT-TERMINOLOGY.md` (Low, housekeeping).** "Telemetry,"
  "Consent," "Bearer credential"/"bearer config," and "support-health scalar" have no glossary row.
  Expected gap (the glossary predates M7, dated 2026-07-11) rather than drift; flagged for the next
  glossary-maintenance pass rather than fixed here, since adding rows for a still-in-progress feature
  (M7 has two more slices to ship) risks needing revision again shortly.
- **`nofollow_windows.go:25` "appliance" comment.** Extends a pre-existing, unchanged comment pattern
  (`nofollow_unix.go:16`); internal build-tag comment, zero user visibility. Not new invention, not
  actioned.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium | T-18 (carried over, grown again) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel ~20+ GUI strings (now including two M7 preview-copy sites); rename the audit-event string | Low (young feature family, ~7 code call sites) | Small-Medium |
| Medium | T-16 (carried over) | Renumber the Supportability-track's colliding ADRs (0008–0011 → 0019–0022) and their cross-references | Low (docs only, but 40+ files to check meaning before touching any) | Medium |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped canonical names (T-10 DPI pattern) | Medium (config + API + admin-settings field) | Medium |
| Medium | T-21 (carried over) | Rename Cluster panel's `cp_version`/"CP Config Version" to a cluster-sync-scoped name (e.g. `sync_version`/"Cluster Sync Version") | Low (GUI label + one API field, CP-UI-only) | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store (or reject upload-config save when no trust key exists) | Medium (touches `/api/support/tac-trust` contract or upload-config validation) | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium (on-disk format, parity-test surface) | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low (GUI copy) / Medium-large (schema) | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*`; rename packaging/config comments | Medium (agent wire protocol, rolling-update compat window) | Medium |
| Low | T-29 residual (new) | Stop hardcoding `kin-openapi`'s exact version in doc prose, or add doc/go.mod parity to CI | Low (doc-only or a small CI check) | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with the in-app "SSL" terminology | Low (doc titles only, but externally linked) | Small |

T-29 (the version-skew fix) ships in this change and requires no further action beyond the standing-fix
recommendation above.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent, but this pass found essentially no *new* substantive drift —
three of four audit lanes returned entirely clean, and the fourth's only finding was a familiar,
zero-risk doc/version-skew issue fixed directly in this change. The nine carried-over findings remain
correctly triaged: eight are genuinely untouched by the last 180 commits, and the ninth (T-18) grew by
two GUI strings in a not-yet-implemented feature path, reinforcing rather than changing its existing
Medium-priority, next-in-line recommendation. No cosmetic or preference-driven renames were proposed or
made in this pass; the one fix shipped here closes a factual staleness (dependency version cited in
docs), and every other observation is either confirmed unchanged or explicitly deferred as a sized,
already-tracked follow-up.
