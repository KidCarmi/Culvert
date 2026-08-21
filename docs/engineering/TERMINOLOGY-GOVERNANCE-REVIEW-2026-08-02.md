# Culvert Language & Terminology Governance Review — 2026-08-02

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `b9fafff`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-01.md` (baseline `8524751`). Only one day and 40 commits
> separate the two reviews, so this pass is narrowly scoped rather than a full re-sweep: (1) checked
> `git diff --name-only 8524751..HEAD` against every file each of the eleven carried-over open findings
> (T-9, T-11, T-12, T-16, T-17, T-18, T-21, T-25 residual, T-13 residual, T-29, T-30, T-31) depends on —
> most were not touched at all; the few that were (`policy.go`, `ui_policy.go`, `configversion.go`,
> `controlplane_snapshot.go`, `metrics.go`) were then read in full diff to confirm the edits fall in
> unrelated regions (F3b-4's SaaS-feed code, a one-line unrelated metrics-writer addition) rather than
> the specific fields/keys each finding cites — so all eleven are re-confirmed unchanged, by inspection
> rather than by file-absence alone; (2) audited the two feature areas that shipped in the window in full — the MCP Agent
> Security Gateway's PR-7 (bounded inspection/DLP/SSRF) and PR-8 (durable decision events), and the F5
> dormant public-feed publisher (`publish-feeds.yml`); (3) closed out T-32's open question, since the
> blocklist/URL-category SaaS feed's F3b-4 slice (signed-feed status API + GUI) — the change T-32
> explicitly flagged as "the next slice" — shipped in this exact window.
> **Companion change:** none. Both new findings (T-33, T-34) are internal/admin-surface naming splits on
> code that either has zero consumers today (T-33) or is a live-but-narrow admin API pairing (T-34) —
> neither is a pre-implementation design-doc or GUI-copy correction, so neither clears this program's
> same-day fix bar on its own terms; see each finding for the specific reasoning.

---

## Executive Summary

No regressions: all eleven carried-over open findings (T-9, T-11, T-12, T-16, T-17, T-18, T-21, T-25
residual, T-13 residual, T-29, T-30, T-31) are re-confirmed unchanged. Most of their cited files are
completely absent from `git diff --name-only 8524751..HEAD`; the handful that do appear
(`policy.go`/`ui_policy.go` for T-11, `configversion.go` for T-21, `controlplane_snapshot.go` and
`metrics.go` for T-29/T-30/T-31's `ConfigSnapshot`/metrics surfaces) were read in full and confirmed to
touch only unrelated regions — see the Wave 1 table below for the per-finding evidence. (`ui_config.go`
also appears in the diff — an unrelated reqlog-backpressure stat addition — but is not cited by any
open finding.)

The two feature areas newly audited this pass split cleanly:

**F5 (dormant public-feed publisher) and MCP PR-8's events subsystem: clean, no findings.** F5's
`feeds_gen.go` / `publish-feeds.yml` reuse the F0/F3b `feed_version`/manifest/artifact vocabulary
exactly, introducing no synonym for an existing concept. PR-8's decision-event model
(`internal/mcp/events/**`) matches `docs/design/mcp/EVENT-MODEL.md` verbatim down to the exact
partition names (`P-CRIT`/`P-ORD`/`P-DEN`) and state strings
(`denial-lane-degraded`/`critical-durability-degraded`/`recovering`) — the same discipline the 08-01
review praised for PR-1..PR-6, now demonstrated across two more PRs and a materially more complex
subsystem (durability, reclamation ordering, encrypted spool). The design doc's own status line was
updated in-window from "PR-0 design artifact (Proposed)" to "now IMPLEMENTED by PR-8," so the doc-to-code
sync stayed proactive.

**One new finding inside MCP PR-7/PR-8 (T-33): the `PolicyAction`/`PolicyReason` observation fields,
exclusively the nine-action/dotted-`MCP.*` taxonomy through PR-6, now also carry a second, unrelated
vocabulary.** PR-7's inspection hard-fail and PR-8's redaction-failure and decision-event
commit-failure paths write ad-hoc literal strings (`"BLOCKED_BY_INSPECTION"`, `"REDACTION_FAILED"`,
`"BLOCKED_BY_DURABILITY"`) and snake_case `mcperr.Reason` codes into fields whose own doc-comment
promises only the canonical taxonomy. Zero-consumer today (verified: no other `.go` file, including
tests, reads `PolicyReason`), so this is the same "catch it while it's free" class of finding as T-32,
not a compatibility-risk one.

**One new finding on the newly-shipped F3b-4 admin surface (T-34): the SaaS feed's failure-count and
last-success fields get two different names depending which of two admin GET endpoints returns them.**
`GET /api/saas-feed/status` (new this window) returns `failures_since_start` /
`last_successful_activation`; `GET /api/urlcat/feed-status`'s SaaS block — rewritten in this same window
to read from the identical status snapshot — returns the same two values under `syncFailures` /
`lastSuccess`. Both endpoints are now live admin API, so (per this program's standing compatibility bar)
this is documented, not blind-renamed.

**T-32 re-checked and confirmed still open, not escalated.** F3b-4 shipped in this window and is the
exact slice T-32 predicted would decide its fate — but `saasFeedStatusJSON` (`saas_feed_status_api.go`)
does not return `snapshot_sha256` or any successor field; it exposes only the F0 §14 field set. T-32's
underlying on-disk/internal collision is unchanged and unescalated.

**Terminology Health Score: 8.5 / 10** (unchanged from 07-19 through 08-01 — two new small, low-exposure
findings on a one-day/40-commit window, both caught in the same "before it ships further" mode that has
characterized every recent pass, is consistent with the expected background rate, not a regression).

**Fixed in this change:** none. Both new findings touch code other in-flight MCP/feed work already
builds on or a live admin API pairing; neither is a doc-only or pre-implementation correction, so neither
clears the same-day bar. Both are sized below for dedicated follow-up.

---

## Wave 1 — Re-confirmed unchanged (file-diff + region check against this window's commits)

`git diff --name-only 8524751..HEAD` was checked against every file citation in the eleven open
carried-over findings. Where a cited file does appear in that diff, the actual diff hunk (not just the
filename) was read to confirm it falls outside the specific field/key/route each finding is about:

| Finding | Files it depends on | Touched this window? |
|---|---|---|
| T-9 | export/import + parity-test surface (`exportedAt`) | No |
| T-11 | `policy.go`'s default-action vocabulary (pre-F3b-4 sections), `ui_policy.go` core | File touched, finding unaffected — this window's `policy.go`/`ui_policy.go` edits are the F3b-4 `matchCategory`/`lookupHostCategory` source-aware resolution and the new SaaS status routes, a different region of both files from the `allow`/`deny` default-action code T-11 cites |
| T-12 | Maintenance-agent `/v1/upgrades/*` wire routes | No |
| T-16 | ADR numbering (0008–0011) | No |
| T-17 | `decryption_redact_hosts` / `/api/decryption/redaction` | No |
| T-18 | `internal/sealbox.Seal`/`Open` call sites | No |
| T-21 | `cluster_convergence.go`, `configversion.go`'s rollback `cp_version` surface | File touched, finding unaffected — `configversion.go`'s one edit this window is the unrelated F3b-4 category-overrides rollback recompose, `configversion.go:515-525`, not the `cp_version` rollback code T-21 cites |
| T-25 residual | `support_recipients.go` / `support_tac_trust.go` | No |
| T-13 residual | README/enterprise "TLS Inspection" branding | No |
| T-29 | YAML `security.rate_limit` (`config.go`), CLI `-rate-limit` (`main.go`), `rate_limit_rpm` (`admin_settings.go`, `ui_security.go`, `controlplane_snapshot.go`, `configversion.go`, `metrics.go`) | `config.go`/`main.go`/`admin_settings.go`/`ui_security.go` not touched; `controlplane_snapshot.go`'s window diff is the F3b-4 SaaS-feed overrides/persistence code (no `rate_limit`/`RateLimit` hit), `metrics.go`'s one-line addition is an unrelated `saasFeedWritePrometheus` call, `configversion.go`'s edit is the T-21-adjacent F3b-4 recompose above — none touch the rate-limit surface |
| T-30 | YAML `max_conns_per_ip` (`config.go`), wire `MaxConnsPerIP` (`controlplane_snapshot.go`), `conn_limit_max_per_ip` (`admin_settings.go`, `ui_policy.go`) | `config.go`/`admin_settings.go` not touched; `controlplane_snapshot.go`'s window diff (as above) has no `MaxConnsPerIP`/`conn_limit` hit; `ui_policy.go`'s window edits are the F3b-4 `matchCategory`/status-route changes noted under T-11, not the conn-limit persistence code |
| T-31 | `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` (`metrics.go`), `clam_vars.go` | `clam_vars.go` not touched; `metrics.go`'s one-line addition (above) is unrelated to either clam/clamav metric |

Two findings' files were touched but in unrelated regions (T-11, T-21); three more findings' files were
touched only via changes verified unrelated to those specific findings (T-29, T-30, T-31, via
`controlplane_snapshot.go`/`metrics.go`/`configversion.go`); the remaining six findings' files do not
appear in the diff at all. This is a stronger guarantee than a manual re-read for the six untouched
cases, and an actual line-level check (not an assumption) for the five touched-but-unrelated cases.

## Wave 2 — New territory audited this pass (40 commits since `8524751`)

**MCP Agent Security Gateway, PR-7 (bounded inspection/DLP/SSRF) + PR-8 (durable decision events): clean
except T-33.** The DLP/SSRF/destination reason-code additions in `internal/mcp/mcperr/mcperr.go`
(`ReasonSecretDetected`, `ReasonSSRFBlocked`, `ReasonDestinationMalformed`, `ReasonInjectionSuspected`,
etc.) extend the existing snake_case kernel-reason convention exactly as PR-1..PR-6 established it, and
stay correctly distinct from the policy-authoring-facing `MCP.INSPECTION.*` vocabulary in
`MCP-POLICY-MODEL.md` (a rule author's YAML and the Go kernel constant were never meant to be the same
string — verified this split is intentional and consistently applied, e.g. `respond.go` keeps JSON-RPC
error bodies cleanly separated by error class). The one place this pass found the two taxonomies
improperly touching is `PolicyAction`/`PolicyReason` on the shared observation record — see T-33. No
admin API or GUI panel exists yet for MCP (`mcp` does not appear in any root `*.go` route registration or
`static/index.html`), so there is no live cross-surface collision to check beyond the internal record
itself — self-declared deferral, same posture as PR-1..PR-6.

**F5 dormant public-feed publisher (`publish-feeds.yml`, `feeds_gen.go`): clean, no findings.** Reuses
`feed_version`, "manifest envelope," "artifact," and the CAS `If-Match`/`If-None-Match` fencing vocabulary
identically to `roadmap/FEEDS-DISTRIBUTION-F0-DESIGN.md` §11 and the pre-existing F3b consumer side
(`saas_feed_floor.go`, `saas_feed_activation.go`, `saas_feed_genstore.go`). No parallel or synonymous
version-counter name was introduced for what F3b already calls `feed_version`.

**Blocklist/URL-category SaaS feed F3b-4 (signed-feed status API + GUI): one new finding (T-34).** The
new `GET /api/saas-feed/status` (full runtime snapshot) and the rewritten SaaS block of the pre-existing
`GET /api/urlcat/feed-status` (compact dual-feed summary) both surface the identical
`saasFeedStatusSnapshot` fields under different JSON key names for the count and timestamp fields — see
below. The rest of the SaaS feed's F3b vocabulary ("floor," "activation," "candidate," "generation")
remains internally consistent and does not collide with pre-existing uses, as already established
07-24 through 08-01.

---

## Findings

### T-33 — MCP `PolicyAction`/`PolicyReason` observation fields mix the canonical policy taxonomy with two unrelated ones (new — documented, not fixed)

- **Business concept:** the stable, sanitized "what did the policy engine decide, and why" pair recorded
  on every MCP decision-point request's observation record (`internal/mcp/runtime/observe.go`), intended
  per its own doc-comment to carry exactly the nine-action policy taxonomy
  (`ALLOW`/`DENY`/`MONITOR`/`QUARANTINE`/…) and the dotted `MCP.POLICY.*`/`MCP.MANAGEMENT.*` reason-code
  taxonomy from `docs/design/mcp/MCP-POLICY-MODEL.md` — the same taxonomy the 08-01 review confirmed
  PR-1..PR-6 held verbatim.
- **Current names / collision:**
  - `observe.go:103-104` — field doc-comments: `PolicyAction string // policy action (e.g. "ALLOW",
    "DENY", "QUARANTINE"), if evaluated` and `PolicyReason string // stable policy reason code (e.g.
    "MCP.POLICY.NO_MATCH_DEFAULT_DENY")`.
  - Conforming assignments (unchanged since PR-6): `policy.go:42-43` (`policy.ActionDeny.String()` /
    `policy.ReasonSnapshotUnavailable.String()` → `"MCP.POLICY.SNAPSHOT_UNAVAILABLE"`) and `policy.go:69-70`
    (`d.Action.String()` / `string(d.Reason)`, the real policy-engine decision).
  - PR-7's non-conforming assignment: `policy.go:59-60` — `rb.rec.PolicyAction = "BLOCKED_BY_INSPECTION"`
    (a literal string outside the nine-action enum) / `rb.rec.PolicyReason =
    insp.result.HardReason.Code()` (a snake_case `mcperr.Reason` code, e.g. `"ssrf_blocked"`,
    `"schema_invalid"`) — fired when PR-7's semantic inspection hard-fails **before the policy engine
    ever evaluates** (per the code's own comment at `policy.go:49-52`).
  - Another PR-7 non-conforming assignment: `policy.go:81-82` — `rb.rec.PolicyAction = "REDACTION_FAILED"`
    / `rb.rec.PolicyReason = mcperr.ReasonRedactionFailed.Code()` (`"redaction_failed"`) — fired when an
    `ALLOW_WITH_REDACTION` decision's redaction obligation cannot be satisfied, i.e. after the real policy
    decision already ran and produced a *different* `d.Action`/`d.Reason` that gets overwritten.
  - PR-8's non-conforming assignment: `events.go:67-68` — `rb.rec.PolicyAction =
    "BLOCKED_BY_DURABILITY"` (a second literal string outside the nine-action enum, alongside PR-7's
    `"BLOCKED_BY_INSPECTION"`) / `rb.rec.PolicyReason = mcperr.ReasonOf(err).Code()`, fired when durably
    committing the decision event itself fails (`"event_commit_failed"`, `"event_queue_saturated"`) — a
    durability-layer failure, not a policy decision, overwriting whatever `d.Action`/`d.Reason` the
    policy engine had just produced.
  - Confirmed via `git show 8524751:internal/mcp/runtime/policy.go` that before this window
    `PolicyReason` had exactly the two conforming assignments; all three non-conforming ones are new in
    this window's PR-7/PR-8 commits.
- **Why this is real drift, not cosmetic:** the inspection hard-fail case is a clear case of redundant,
  conflicting recording — `recordInspection` (`inspection.go:125-133`) already populates dedicated,
  purpose-built fields for exactly this outcome (`InspectionDisp`, `InspectionSchema`,
  `InspectionDestClass`, `SecretFound`, `PIIFound`, `InjectionSuspected`) *before* the hard-fail check
  runs, so `PolicyAction`/`PolicyReason` did not need to also carry it. An engineer or support person
  reading a stream of these records — or eventually building a dashboard grouped by `PolicyReason`, which
  its own doc-comment says is safe to treat as one of the documented `MCP.*` codes — will instead see
  `MCP.POLICY.NO_MATCH_DEFAULT_DENY` sitting next to `ssrf_blocked` and `event_commit_failed` in the same
  column, three shapes for what the field's own contract promises is one. This is exactly T-32's pattern
  repeated one layer down: a fresh subsystem (PR-7/PR-8) reusing an already-scoped field for a second,
  unrelated purpose, caught here before anything downstream is built to consume `PolicyReason` (confirmed
  zero consumers repo-wide, including tests).
- **Why not fixed this pass:** consistent with this program's treatment of T-29 through T-32, a
  behavioral source change to a security-relevant, actively-developing subsystem (the MCP gateway has
  had eight PRs land in three weeks) is left to a dedicated PR rather than folded into a governance pass,
  even though the zero-consumer state means the compatibility risk specifically is nil today.
- **Recommended canonical name / fix:** stop overwriting `PolicyAction`/`PolicyReason` for the three
  pre-policy/post-policy gate cases (`"BLOCKED_BY_INSPECTION"`, `"REDACTION_FAILED"`,
  `"BLOCKED_BY_DURABILITY"`); either leave them at whatever the policy engine actually produced (or
  unset, for the inspection case where policy never ran) and rely on the fields already scoped for that
  purpose (`InspectionDisp`/`InspectionSchema`/etc. for inspection; a new dedicated field, e.g.
  `GateAction`/`GateReason` or `HardFailReason`, for the redaction-failure and event-commit-failure
  cases). Land this before any PR-9 work builds a consumer (log pipeline, dashboard, or export mapping)
  on top of `PolicyAction`/`PolicyReason`'s current, contract-violating values — the same "cheapest point
  to fix it" framing as T-32.
- **Priority:** Low-Medium (internal observation field, zero consumers, no admin/API/GUI exposure yet).
  **Migration risk:** None today (verified no other reader); rises the moment a consumer is built.
  **Est. PR size:** Small.

### T-34 — SaaS feed status: the same failure-count and last-success fields get two names across two live admin endpoints (new — documented, not fixed)

- **Business concept:** the SaaS signed feed's cumulative failure count since process start, and its most
  recent successful activation timestamp — one pair of facts, tracked by one struct
  (`saasFeedStatusSnapshot`, `saas_feed_status.go:135,142`).
- **Current names / collision:**
  - `GET /api/saas-feed/status` (new this window, F3b-4's dedicated status endpoint,
    `saas_feed_status_api.go:41,59`): `"failures_since_start": snap.FailuresSinceStart` and
    `"last_successful_activation": rfc3339OrNull(snap.LastSuccessfulActivation)`.
  - `GET /api/urlcat/feed-status`'s SaaS block (pre-existing endpoint, but its SaaS block was rewritten
    in this exact window to read the same snapshot — `ui_policy.go:1183-1184`): `"lastSuccess":
    rfc3339OrEmpty(sf.LastSuccessfulActivation)` and `"syncFailures": sf.FailuresSinceStart`.
  - Both endpoints are exercised by the admin GUI in the same window: `static/index.html:6391,6393`
    reads `last_successful_activation`/`failures_since_start` off the new detailed panel, while the
    compact `ut1`/`saas` summary (wherever it is rendered) would read `lastSuccess`/`syncFailures` off the
    older endpoint.
  - This is a genuinely new pairing, not a pre-existing split inherited from history: `syncFailures`
    predates this window as a field name on `/api/urlcat/feed-status`, but there was no second endpoint
    exposing the same underlying value under a different name until F3b-4 added
    `/api/saas-feed/status` in this exact commit range — the collision could not have existed before this
    window.
- **Why this trips someone up:** a support engineer correlating a customer's screenshot of the compact
  Policy/URL-Categories status card (`syncFailures: 3`) against a support-bundle dump of
  `/api/saas-feed/status` (`failures_since_start`) — or the other way for `lastSuccess` vs.
  `last_successful_activation` — will not find a name match by grep, despite both being the exact same
  underlying integer/timestamp for the exact same feed. `activeFeedVersion` (compact) vs.
  `active_feed_version` (full) is the same pattern but differs only in casing convention (a codebase-wide,
  pre-existing, out-of-scope-for-this-pass camelCase/snake_case mix — not counted as part of this
  finding); `syncFailures`/`lastSuccess` vs. `failures_since_start`/`last_successful_activation` are
  different words, not just different casing, which is the concrete part of this finding.
- **Why not fixed this pass:** both are already-shipped, live admin GET endpoints (not pre-implementation
  or doc-only), so this follows the same compatibility bar as T-29/T-30/T-31 rather than a blind
  same-day rename.
- **Recommended canonical name:** standardize the compact endpoint's SaaS block on the same field names
  and casing as the full status endpoint (`failures_since_start`, `last_successful_activation`) the next
  time `apiURLCatFeedStatus` is touched — it is the newer, more fully-specified endpoint's vocabulary
  (F0 §14) that should win, not the older compact summary's ad-hoc names.
- **Priority:** Low (both are internal admin-API surfaces with no known external consumer; the compact
  endpoint is described in its own header comment as intentionally a different, smaller field set,
  which somewhat mitigates but does not eliminate the specific two-name overlap for the fields both
  endpoints do share).
  **Migration risk:** Low (admin GUI-only consumer, in-repo). **Est. PR size:** Small.

---

## Carried over, still open (re-confirmed this pass, see Wave 1 table for the file/region evidence)

| Finding | Business concept | Status |
|---|---|---|
| T-9 | `exportedAt` → `capturedAt` rename | Open since 07-07. Unchanged. |
| T-11 | `allow`/`deny` default-action vocabulary vs. 4-value `PolicyAction` | Open since 07-16. Unchanged; `policy.go`/`ui_policy.go` were touched this window, but only in the unrelated F3b-4 region (Wave 1). |
| T-12 | Maintenance-Agent wire API "upgrade" vs. GUI/API "update"/"Dispatch" | Open since 07-16. Unchanged. |
| T-16 | ADR numbering collision: 0008–0011 | Open since 07-19. Unchanged. |
| T-17 | Traffic-log destination-privacy config key/route still says "decryption" | Open since 07-19. Unchanged. |
| T-18 | "Seal" names two unrelated cryptographic operations | Open since 07-19, grew 07-24. Unchanged — no new sealing call site this window. |
| T-21 | "Config Version" names two unrelated, independently-incrementing counters | Open since 07-24. Unchanged; `configversion.go` was touched this window, but only in the unrelated F3b-4 recompose (Wave 1); still compounded by T-32 (unescalated this pass). |
| T-25 residual | Two disjoint "recipient"/"TAC trust key" registries | Open since 07-24. Unchanged. |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | Open since 07-24 (soft/low). Unchanged. |
| T-29 | Per-IP rate limit: `rate_limit` (YAML/CLI) vs. `rate_limit_rpm` (API/wire/metric) | Open since 08-01. Unchanged; `controlplane_snapshot.go`/`metrics.go` were touched this window, but neither hunk touches the rate-limit surface (Wave 1). |
| T-30 | Per-IP connection cap: `max_conns_per_ip`/`MaxConnsPerIP` vs. `conn_limit_max_per_ip` | Open since 08-01. Unchanged; `controlplane_snapshot.go`/`ui_policy.go` were touched this window, but neither hunk touches the conn-limit surface (Wave 1). |
| T-31 | ClamAV metric family: `clamav` everywhere except `culvert_clam_scan_errors_total` | Open since 08-01. Unchanged; `metrics.go`'s one-line addition this window is unrelated to either clam metric (Wave 1). |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` reuses the overloaded term "snapshot" | Open since 08-01. **Re-checked this pass**: F3b-4 shipped and did NOT wire this field onto any live GET response — `saasFeedStatusJSON` exposes only the F0 §14 field set. Not escalated; recommendation unchanged (rename before any future slice wires it live). |

## Soft findings — no action recommended

- Carried over unchanged from 07-24/08-01: "Bootstrap" covering two unrelated features (no on-screen
  collision yet); the T3 "seed"/`CULVERT_PROXY_SEED_REF` vocabulary (internally consistent).
- **New this pass:** MCP PR-7/PR-8's DLP/SSRF/destination reason-code taxonomy and F5's feed-publisher
  vocabulary both held discipline against their design docs — worth noting as continued positive
  pattern, not a finding.

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
| Medium | T-33 (new) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures (inspection hard-fail, redaction failure, event-commit failure); add a dedicated field for those instead | None today (zero consumers); rises once a consumer exists | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 (carried over) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit | Low | Small |
| Low | T-34 (new) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary (`failures_since_start`, `last_successful_activation`) | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This narrow, one-day pass re-confirmed, via file-diff checks
backed by line-level reads of every touched-but-cited file, that all eleven previously-open findings
(T-9, T-11, T-12, T-16, T-17, T-18, T-21, T-25 residual, T-13 residual, T-29, T-30, T-31) are unchanged,
found the two feature areas newly shipped in this window
(F5's dormant publisher and MCP PR-8's decision-event subsystem) held the same design-doc-to-code
discipline already praised for PR-1..PR-6, closed out T-32's open prediction (F3b-4 shipped without
escalating the "snapshot" collision), and surfaced two new findings — T-33 (a fresh subsystem's
observation field absorbing a second, unrelated reason-code vocabulary, zero consumers today) and T-34
(the same status fields getting two names across two live admin endpoints introduced/rewritten in the
same window). Neither meets this program's same-day fix bar: T-33 touches actively-developing security
logic (even though currently zero-risk), and T-34 touches two already-shipped admin API responses. Both
are documented here for dedicated follow-up at the same priority bar as the program's existing backlog.
No cosmetic or preference-driven renames were proposed.
