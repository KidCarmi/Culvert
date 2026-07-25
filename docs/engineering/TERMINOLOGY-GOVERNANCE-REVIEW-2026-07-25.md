# Culvert Language & Terminology Governance Review — 2026-07-25

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Three parallel audits against the tree at `d06ff85`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-07-24.md` (baseline `c7d27f7`). 80 commits landed in the
> intervening 24 hours — heavily concentrated in two areas: M7 proactive-support/telemetry, which
> went from a 100%-unimplemented design doc to **shipped code** (Slice 1 + Slice 2: scoped
> support-metric registry, telemetry preview, telemetry consent + bearer config + admin GUI), and the
> MCP Agent Security Gateway design-doc set, which grew from ~6,955 to ~12,600 lines across ~49
> commits of self-review iteration (still 100% documentation, zero shipped code). One lane audited
> the newly-shipped M7 code against the design doc's T-24 corrections and the glossary; one lane
> re-audited the MCP doc set for drift after its large iteration round; one lane re-confirmed the nine
> previously-open findings (T-9, T-11, T-12, T-13 residual, T-16, T-17, T-18, T-21, T-25 residual) and
> swept the handful of unrelated commits (sslbypass normalization, a dependency bump, an empty-password
> fix, a catalog User-Agent header) for incidental terminology impact.
> **Companion change:** two zero-risk fixes ship with this review (see "Fixed in this change"). No
> REST route, JSON field, CLI flag, config key, or audit-event *name* was renamed. One internal Go
> metric ID (`support_uptime_bucket`) is renamed to match its own sibling convention and its own design
> doc — it is not yet wire-exposed as a literal string anywhere, so this is still a same-day, free fix.

---

## Executive Summary

The M7 telemetry feature shipped its first real code in this window, which made yesterday's T-24
design-doc fix ("Incident" → "degradation", `support_uptime_bucket` → `support_health_uptime_bucket`)
testable against reality for the first time. The good news dominates: **the banned "Incident" concept
did not leak into any shipped Go identifier, JSON field, GUI string, or metric name** — the T-24 fix
is holding exactly as intended. The bad news is narrower than it sounds: T-24's rename of
`support_uptime_bucket` assumed M7 "has shipped zero code," but Slice 1 had actually landed **11 hours
before** that fix, under the pre-rename name — so the design doc and the shipped code disagreed with
each other from the moment T-24 merged. Fixed here (see below).

Separately, a full-repo sweep for the glossary's explicitly-banned "Appliance" language (`PRODUCT-
TERMINOLOGY.md`: *"Appliance | Not used ... avoid inventing appliance language"*) found it had quietly
reached five **GUI-facing** strings in `static/index.html` — two pre-existing from M6 (never caught by
six prior reviews) and three new from M7 Slice 2 reusing the same M6 wording. Fixed here. (The word
also appears in ~84 internal Go-comment sites across the support/release subsystem, generically
describing "this deployed instance" — that usage predates every prior review, is not user-facing, and
is left alone; the glossary's ban is scoped to product nomenclature, not a ban on the English word in
engineering prose.)

The MCP design-doc set, despite nearly doubling in size this pass, remains as disciplined as the 07-24
review found it: zero new "Incident" leakage, zero new ID-numbering collisions (it correctly renamed
its own ADR off a collision with an external open PR before merging), zero trailing-reference
inconsistencies survive in the current tree (its own six executable consistency predicates all pass),
and its deliberate "Action" divergence remains explicitly self-declared. Still zero shipped code, so
still free to fix if anything is ever found.

One new *documented-not-fixed* finding: M7's new "Telemetry" feature section and the pre-existing
Cluster Convergence panel's "No telemetry" node-reporting status now use the same word for two
unrelated concepts in the same admin UI. Not fixed this pass (renaming a live GUI status label used in
existing runbooks needs a design decision on which side moves, not a same-day copy edit).

**Terminology Health Score: 8.5 / 10** (unchanged from 07-24 — one real drift item caught in newly
shipped code within a day of it landing, plus a six-review-old GUI copy issue finally surfaced by this
pass's full-repo "Appliance" sweep, both fixed at zero risk; one new soft collision documented for a
future dedicated pass; no regression in the previously-audited clusters).

**Fixed in this change:**

- **T-29 — `support_uptime_bucket` shipped one day before, and then disagreed with, its own
  corrected design-doc name.** `support_telemetry_registry.go` (M7 Slice 1, commit `d552168`,
  2026-07-24 11:22 UTC) shipped the metric ID `support_uptime_bucket`, breaking the `support_health_*`
  convention every one of its 7 sibling metrics follows. The 07-24 governance review's T-24 fix (commit
  `c7d27f7`, 22:25 UTC the same day) renamed the design doc's proposed name to
  `support_health_uptime_bucket` specifically *because* of that convention break, under the stated
  premise that "M7 has shipped zero code" — a premise that was already 11 hours stale when the fix
  landed. No later M7 commit (Slice 2, CI-feedback, or re-review fixes) corrected the shipped code to
  match. Renamed the ID, its two `Read`-field references, the `readSupportUptimeBucket` closure, and
  the test/comment sites that named it: `support_telemetry_registry.go` (struct entry ID, `Read` field,
  and the `readSupportHealthUptimeBucket` closure definition), `support_telemetry_registry_test.go`
  (the exact-eligible-set map key and the bucketed-closures slice), and
  `internal/supportmetrics/buckets.go` (the doc comment on `UptimeBucketLadder`). Confirmed the ID is
  not yet wire-exposed as a literal string anywhere (`registry_hash` is a dynamically computed SHA-256
  over the descriptor set, not a pinned golden value — `grep`-confirmed no test asserts a fixed hash
  string), so this remains a same-day, zero-compatibility-risk fix, same as T-24 itself.
- **T-30 — Banned "Appliance" wording reached five GUI strings (two six-reviews-old, three new from
  M7).** `PRODUCT-TERMINOLOGY.md` bans "Appliance" outright ("the UI says node or instance ... avoid
  inventing appliance language"). `static/index.html` had:
  - `"Per-appliance bearer credential; ..."` (two input tooltips — one added by M6 PR-6, commit
    `8c43aa2`; one added by M7 Slice 2, commit `40e48aa`, copy-pasting the same wording),
  - `"...a small set of the appliance's own support-health scalars..."` (M7 Slice 2, `40e48aa`),
  - `"...(E2E - appliance holds no decrypt key)"` and `"...the appliance keeps no decrypt key."` (both
    M6, predating even the 07-19 review, in the support-bundle "Seal" download flow).
  Reworded all five to "node" ("Per-node bearer credential", "this node's own support-health scalars",
  "the node holds no decrypt key", "the node keeps no decrypt key") — copy-only, no ID/field/route
  changes, no behavior change.

**Documented, not fixed this pass (sized for a dedicated follow-up, same bar as T-9/T-11/T-12/T-17/
T-18):**

- **T-31 (new) — "Telemetry" now names two unrelated concepts in the same admin UI.** The pre-existing
  Cluster Convergence panel (`static/index.html`, driven by `cluster_convergence.go`, T3-era, commit
  `906fd6f`) labels a data-plane node that hasn't reported its config-sync heartbeat/fingerprint as
  **"No telemetry"** (`n.reporting` false → status "No telemetry"). M7 Slice 2 now ships an entirely
  separate, unrelated "Telemetry" feature — opt-in sharing of support-health metrics with TAC — with
  its own prominent GUI section literally titled **"Telemetry (opt-in)"**. Both are now live in the
  same admin UI, meaning different things: one is a config-sync liveness signal per DP node, the other
  is an admin-configured, currently-inert (no sender exists yet) support-metrics-sharing feature.
  Pre-dates this pass (the Cluster Convergence label is older) but M7 shipping is what turns it from a
  latent naming choice into an actual on-screen collision. **Recommended canonical name:** narrow one
  side — e.g. relabel the Cluster Convergence status to something config-sync-scoped ("No sync
  report"/"Not reporting") and reserve "Telemetry" exclusively for the M7 opt-in feature, mirroring how
  T-21's recommendation narrows "CP Config Version" to avoid colliding with the rollback feature's
  "Config Version." **Why not fixed this pass:** the Cluster Convergence label is a live,
  externally-observable status string (`static/index.html`'s JS render function) that may already be
  referenced in ops runbooks/screenshots — same care as T-17/T-21's alias-on-read treatment, not a
  same-day blind relabel. **Priority:** Low-Medium (support/ops confusion only; both features function
  correctly). **Estimated PR size:** Small (one JS status-label string + a grep for any doc/runbook
  reference to "No telemetry").

---

## Wave 1 — Re-verified clean / unchanged (no new drift since 2026-07-24)

All nine previously-open findings were checked against the 80 new commits and are **unchanged**:

| Finding | Status this pass |
|---|---|
| T-9 (`exportedAt`→`capturedAt`) | Unchanged — no commit touches support-export files. |
| T-11 (`allow`/`deny` vs 4-value `PolicyAction`) | Unchanged — `policy.go`/`ui_policy.go` untouched. |
| T-12 (Maintenance-Agent "upgrade" vs "update") | Unchanged — the one release-catalog commit this pass (`e4d8f39`) only adds a `catalogUserAgent` HTTP header string to fix a CDN 403; no wire-route or vocabulary change. |
| T-13 residual (README "TLS Inspection" vs in-app "SSL") | Unchanged — no README/enterprise-doc touches. |
| T-16 (ADR 0008–0011 collision, target 0019–0022) | Unchanged and target range still fully unclaimed (`docs/adr/` now has 0024 from the MCP program, which correctly avoided colliding with 0019–0022). |
| T-17 (traffic-log "decryption" key naming) | Unchanged — `decryption_redaction.go`/`admin_settings.go` untouched. |
| T-18 ("Seal" collision, flagged as growing) | Unchanged this pass — no new commits touch `internal/sealbox`/`support_export.go`/the TAC-upload GUI strings. Still recommended as the next dedicated terminology PR per 07-24. |
| T-21 (two "Config Version" counters) | Unchanged — `configversion.go`/`cluster_convergence.go` untouched. |
| T-25 residual (recipient vs TAC-trust-key registries) | Unchanged — `support_recipients.go`/`support_tac_trust.go` untouched. |

The handful of unrelated commits this pass (three `sslbypass` two-pass-normalization fixes, a
`kin-openapi` dependency bump for a CVE, a reject-empty-password fix, and the catalog User-Agent
header) introduce no new product-facing vocabulary, config keys, or GUI strings — confirmed by direct
diff review.

## Wave 2 — New territory audited this pass

**M7 proactive-support/telemetry (Slices 1–2, ~10 commits, first shipped code):** audited every new
Go file (`support_telemetry_*.go`, `internal/supportmetrics/*.go`), the full `static/index.html` diff,
and the OpenAPI spec additions against `PRODUCT-TERMINOLOGY.md` and the corrected design doc. Findings
T-29/T-30/T-31 above are new to this pass; everything else — the `/api/support/telemetry/{preview,
config}` routes, the `support.telemetry.config` audit event, the `telemetry_config.json` persisted
file, `registry_hash`/`schema_version`/`sample_epoch`/`sequence` wire fields, and the GUI labels/JS —
maps 1:1 across Go identifiers, API fields, and GUI text with no drift.

**MCP Agent Security Gateway design-doc set (~49 commits, doc set nearly doubled to ~12,600 lines):**
re-ran the doc set's own six executable consistency predicates (all pass, all seeded known-positives
still fire, all live residuals are the same pre-existing, explicitly-documented, deliberately-ungated
items as 07-24) and independently re-checked the five dimensions the 07-24 review certified clean:
"Incident" (all ~35 hits are the generic security-operations word, none are a proposed backend
entity), trailing-reference drift (none — the doc set's own final commit's self-reported "74 threats /
91 requirements / 0 duplicates" independently verified), ID-numbering collisions (none new — the set's
own ADR, `0024-mcp-agent-security-gateway-trust-boundary.md`, was itself renamed off a collision with
an *external* open PR's ADR-0023 before merging, per its own remediation ledger), the self-declared
"Action" divergence (still explicitly documented, still 9 distinct values, no conflation found), and
zero shipped code (confirmed — no `internal/mcp` package exists; every commit message in range ends
"PR-1 not begun").

---

## Findings

### T-29 — `support_uptime_bucket` shipped code disagreed with its own corrected design doc (FIXED)
See "Fixed in this change" above. **Priority:** was Medium (a shipped, if not-yet-wire-exposed, naming
inconsistency with the doc that is supposed to govern it). **Migration risk:** none — the old ID string
appeared only in the two Go files renamed here plus their tests; no persisted data, no wire schema, no
golden hash pins it.

### T-30 — Banned "Appliance" wording reached five GUI strings (FIXED)
See "Fixed in this change" above. **Priority:** Medium (two of the five sites predate six prior
reviews — a genuine miss, not new drift — and all five are on customer-facing security/support
screens). **Migration risk:** none — tooltip/hint copy only, no ID or behavior change.

### T-31 — "Telemetry" collision between Cluster Convergence status and the new M7 feature (new — documented, not fixed)
See "Documented, not fixed this pass" above.

---

## Soft findings — no action recommended

- **"Appliance" in ~84 internal Go-comment sites** across the support/release/telemetry subsystem
  (`release_alerts.go`, `config_surfaces.go`, `controlplane_snapshot.go`, and 43 others) generically
  describes "this deployed instance" in engineering prose, not a UI/product noun. The glossary's ban
  targets inventing "Appliance" as product nomenclature (the alternative it names — "node" or
  "instance" — is itself just as informal a word choice); it does not require purging the plain English
  word from code comments. No action recommended; flagged only so a future pass doesn't have to
  re-derive this scope boundary from scratch.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium | T-18 (carried over, still growing) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI (4+ strings); rename the audit-event string | Low (young feature) | Small-Medium |
| Medium | T-16 (carried over) | Renumber the Supportability-track's colliding ADRs (0008–0011 → 0019–0022) and their cross-references | Low (docs only, 40+ files to check meaning before touching any) | Medium |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped canonical names (T-10 DPI pattern) | Medium (config + API + admin-settings field) | Medium |
| Medium | T-21 (carried over) | Rename Cluster panel's `cp_version`/"CP Config Version" to a cluster-sync-scoped name (e.g. `sync_version`/"Cluster Sync Version") | Low (GUI label + one API field, CP-UI-only) | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium (touches `/api/support/tac-trust` contract or upload-config validation) | Small-Medium |
| Low-Medium | T-31 (new) | Relabel Cluster Convergence's "No telemetry" node status to a config-sync-scoped term, reserving "Telemetry" for the M7 feature | Low (one JS status string; check runbooks) | Small |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium (on-disk format, parity-test surface) | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low (GUI copy) / Medium-large (schema) | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*`; rename packaging/config comments | Medium (agent wire protocol, rolling-update compat window) | Medium |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low (doc titles only, externally linked) | Small |

T-29 and T-30 are fixed in this change and require no further action.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass confirmed the eight already-open carried-over
findings are unchanged, re-verified the MCP design-doc set held its discipline through a ~49-commit,
near-doubling revision round, caught and fixed a same-day design-doc/shipped-code disagreement in M7's
first shipped metric (T-29) — the cheapest point to fix it, one day after it landed — closed a
six-review-old GUI copy gap (T-30, the banned "Appliance" term) that a full-repo sweep finally
surfaced, and documented one new cross-feature naming collision (T-31, "Telemetry") sized for a
dedicated follow-up rather than a same-day relabel. No cosmetic or preference-driven renames were
proposed or made in this pass; every fix shipped here closes a genuine glossary violation or a
design-doc/code disagreement, not a stylistic preference.
