# Culvert Language & Terminology Governance Review — 2026-08-03

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `49cb52f`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-02.md` (baseline `b9fafff`). One day and 55 commits separate the
> two reviews — a materially larger window than 08-01→08-02's 40 commits, dominated by three MCP Agent
> Security Gateway legs (PR-9 admin surface, PR-10 signed CP→DP snapshots, PR-11 guarded execution +
> rollout) plus a production GUI (PR-UX-1/UX-2 Command Center and Activity). Method: (1) `git diff
> --name-only b9fafff..HEAD` checked against every file each of the fourteen carried-over open findings
> (T-9, T-11, T-12, T-13 residual, T-16, T-17, T-18, T-21, T-25 residual, T-29, T-30, T-31, T-32, T-33,
> T-34) depends on; where a cited file appears in the diff, the actual hunk was read to confirm it falls
> outside the specific field/route each finding is about; (2) given T-33's own recommendation explicitly
> flagged PR-9 as the moment its "zero consumers" premise could flip, traced PR-9's new decision
> search/explain admin surface (`internal/mcp/adminapi/decisions.go`) to its actual data source; (3)
> audited PR-11's new `EvaluatedAction`/`EffectiveAction` rollout-execution vocabulary and PR-10's new
> epoch/revision/compat-version triad for the same class of drift T-21/T-32/T-33 already flag elsewhere in
> the codebase (a fresh subsystem reusing an overloaded name); (4) spot-checked the rollout mode ladder
> (disabled/observe/shadow/canary/production) and the "desired vs. locally active" mode split across
> `internal/mcp/rollout`, `mcp_rollout.go`, and the new `static/index.html` Command Center panel for
> cross-surface name consistency; (5) confirmed the F6 feeds-readiness workflow additions
> (`resign-feeds.yml`, `FEEDS-F6-ACTIVATION-RUNBOOK.md`) and the alerts save-lock/gating refactor
> (`alerts.go`, `internal/alerts/store.go`) introduce no new naming surface.
> **Companion change:** none. No new finding cleared this program's same-day fix bar (see below).

---

## Executive Summary

No regressions: all fourteen carried-over open findings (T-9, T-11, T-12, T-13 residual, T-16, T-17,
T-18, T-21, T-25 residual, T-29, T-30, T-31, T-32, T-33, T-34) are re-confirmed unchanged. Of the files
they cite, only `main.go`, `controlplane_snapshot.go`, `config_surfaces.go`/`config_surfaces_test.go`, and
`internal/mcp/runtime/policy.go` appear in this window's diff; each was read at the hunk level and touches
a region unrelated to the specific field/route the finding is about (Wave 1 table below).

**T-33's own prediction was checked directly and did not materialize.** The 08-02 review's exact
recommendation was to fix `PolicyAction`/`PolicyReason`'s three contract-violating assignments "before any
PR-9 work builds a consumer" on top of them. PR-9 shipped in this window and does add a durable decision
search/explain admin surface (`GET` handlers backed by `internal/mcp/adminapi/decisions.go`) — but tracing
its `Action`/`ReasonCode` fields back to their source shows it reads `evmodel.DecisionEvidence.Action` /
`.ReasonCode`, populated in `internal/mcp/runtime/events.go:decisionFacts` from `d.Action.String()` /
`string(d.Reason)` — the real, un-overwritten policy decision, never `rb.rec.PolicyAction`/`PolicyReason`.
T-33's tainted fields (`ObserveRecord.PolicyAction`/`PolicyReason` in `internal/mcp/runtime/observe.go`)
remain, by construction, un-consumed by the new admin surface: confirmed zero consumers repo-wide still
holds. T-33 is unescalated; its priority and recommendation are unchanged.

**PR-11 extends the canonical policy-action taxonomy correctly.** `internal/mcp/runtime/execute.go:94`
writes `rb.rec.PolicyAction = out.EvaluatedAction`, a new assignment site this window. Traced through
`internal/mcp/execution/{run,executor}.go`, every `EvaluatedAction` value is `in.Decision.Action.String()`
— i.e. always one of the nine canonical policy actions, never a rollout-specific string. `EffectiveAction`
(a genuinely separate, rollout-scoped concept — "execute" / "shadow_execute" / "record_only" / "block") is
correctly kept off `PolicyAction`/`PolicyReason` entirely. This is the disciplined pattern the program has
praised in PR-1..PR-8 and F5, now demonstrated on the exact field T-33 warns about.

**PR-10's epoch is a genuine reuse, not a namesake collision.** PR-10 introduces three new counters scoped
to `internal/mcp/cpdp` — `EpochRatchet` (fencing), `Revisions{Config,Policy,Catalog,Credential}` (change
detection), `CompatVersion`/`DPCompatVersion` (capability gating) — each with an explicit doc comment
distinguishing it from the others (MCP-CPDP-001/003) and from the pre-existing `ConfigSnapshot.Epoch`. The
concern this raises unprompted is whether "epoch" now means two different things (the existing ADR-0005
HA-lease fencing epoch vs. a new MCP-specific one); tracing `mcpHAWriteAuthority.CurrentEpoch()`
(`mcp_distribution_adapters.go:28`) to `globalHA.CurrentEpoch()` confirms the MCP envelope's `epoch` field
carries the *same* ADR-0005 fencing-lease epoch value, not a second counter under a shared name — correct
reuse of an existing canonical concept, consistent with `config_surfaces.go`'s own `AppliesOnDP: true`
framing for the two new snapshot rows added this window (`mcp_gateway_snapshot`, `mcp_management_snapshot`).

**Rollout mode ladder and desired/active split: clean.** The five-value mode token
(`disabled`/`observe`/`shadow`/`canary`/`production`, `internal/mcp/rollout/rollout.go`) is used
identically across the Go package, the admin API (`mcp_rollout.go`), and the new Command Center GUI panel
(`static/index.html`); the GUI's rollout-transition dropdown omits `production` as an option, but that is
a feature-scoping choice (Production is unreachable without a separate qualification-receipt flow per the
type's own doc comment), not a naming split. The GUI's "Desired" vs. "Locally active" mode distinction
matches the API's `desired` JSON field (`internal/mcp/rollout/state.go:246`) exactly.

**F6 feeds hardening and the alerts save-lock refactor: no new naming surface.** F6's
`resign-feeds.yml`/`FEEDS-F6-ACTIVATION-RUNBOOK.md` reuse "publish"/"generate"/"activation" identically to
the F0/F3b/F5 vocabulary already praised on 08-01/08-02; the alerts change
(`alerts.go`/`internal/alerts/store.go`) is an internal save-lock/dispatch-decision refactor with no new
field, metric, or route name.

**Terminology Health Score: 8.5 / 10** (unchanged — no new findings, no regressions, and a
disproportionately large window of new development, including the exact subsystem T-33 flagged as the
risk to watch, held discipline).

**Fixed in this change:** none — nothing crossed the same-day fix bar this pass. This review itself is the
change (a documentation-only continuation of the series).

---

## Wave 1 — Carried-over findings re-confirmed unchanged

| Finding | Files it depends on | Touched this window? |
|---|---|---|
| T-9 | export/import + parity-test surface (`exportedAt`) | No (only `config_surfaces.go`/`_test.go` touched — see below, unrelated) |
| T-11 | `policy.go`'s default-action vocabulary, `ui_policy.go` core | No |
| T-12 | Maintenance-Agent `/v1/upgrades/*` wire routes | No |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | No |
| T-16 | ADR numbering (0008–0011) | No |
| T-17 | `decryption_redact_hosts` / `/api/decryption/redaction` | No |
| T-18 | `internal/sealbox.Seal`/`Open` call sites | No |
| T-21 | `cluster_convergence.go`, `configversion.go`'s rollback `cp_version` surface | No (`configversion.go` does not appear in this window's diff at all) |
| T-25 residual | `support_recipients.go` / `support_tac_trust.go` | No |
| T-29 | YAML `rate_limit` (`config.go`/`main.go`) vs. `rate_limit_rpm` (API/wire/metric) | `main.go`/`controlplane_snapshot.go` touched, finding unaffected — `main.go`'s window diff has no `rate_limit`/`rate-limit` hit; `controlplane_snapshot.go`'s sole `RateLimitRPM` hit is an unchanged log-format string (`"rate=%d rpm"`), not a naming change |
| T-30 | YAML `max_conns_per_ip`/wire `MaxConnsPerIP` vs. `conn_limit_max_per_ip` | No |
| T-31 | `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` | No |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` overloads "snapshot" | No |
| T-33 | MCP `PolicyAction`/`PolicyReason` mixing three vocabularies | `internal/mcp/runtime/policy.go` touched, finding unaffected — this window's hunk only inserts the new PR-11 `p.executor != nil` dispatch branch above the finding's cited lines; the three non-conforming assignments (`policy.go:59-60,81-82`, `events.go:67-68`) are untouched. **Explicitly re-checked per its own "before PR-9" warning** — see Executive Summary; unescalated. |
| T-34 | SaaS feed status field-name split across two admin endpoints | No (`saas_feed_status_api.go`, `ui_policy.go` do not appear in this window's diff) |

`config_surfaces.go`'s window diff (two new rows, `mcp_gateway_snapshot`/`mcp_management_snapshot`, PR-10)
and `config_surfaces_test.go`'s one-line parity-count bump are new PR-10 registry entries, not a T-9-related
edit — T-9's `exportedAt` field is untouched.

## Wave 2 — New territory audited this pass (55 commits since `b9fafff`)

**MCP PR-9 (admin HTTP API, OpenAPI, GUI backend), PR-10 (signed CP→DP snapshots), PR-11 (guarded
execution + rollout): clean except the already-open T-33, whose risk this window explicitly tested and
did not confirm.** See Executive Summary for the decision-search/explain trace, the `EvaluatedAction`
taxonomy-conformance check, and the epoch-reuse trace. `internal/mcp/rollout`'s mode ladder, the
`desired`/`mode` API-to-GUI mapping, and PR-10's `Revisions{Config,Policy,Catalog,Credential}` tuple all
carry distinct, individually doc-commented names with no observed collision against each other or against
pre-existing Culvert vocabulary (`config_surfaces.go`'s `kindMeta`/`AppliesOnDP` framing already
distinguishes the two new MCP snapshot rows from the general `ConfigSnapshot` surface they ride on).

**PR-UX-1/UX-2 (Command Center, Activity — the first production MCP GUI): clean.** The panel is the first
GUI surface built directly on the PR-9 admin API rather than internal-only state, so it was checked
specifically for the T-34 pattern (a GUI reading one field name while the API returns another) on the
fields it renders — mode/desired, the nine-action policy taxonomy via decision search, and the
gateway/management posture chips. No split found; the GUI consumes the API's exact field names and enum
tokens.

**F6 feeds-readiness hardening and the alerts save-lock/HasSubscriber-gate refactor: clean, no findings.**
Both reuse pre-existing, already-reviewed vocabulary (feeds: F0/F3b/F5's "publish"/"generate"/"activation"
family; alerts: the `HasSubscriber` gating pattern CLAUDE.md already documents) and introduce no new
field, route, or metric name.

---

## Findings

No new findings this pass.

## Carried over, still open (re-confirmed this pass, see Wave 1 table for the file/region evidence)

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
| T-29 | Per-IP rate limit: `rate_limit` (YAML/CLI) vs. `rate_limit_rpm` (API/wire/metric) | Open since 08-01. Unchanged; touched files re-verified unrelated this window. |
| T-30 | Per-IP connection cap: `max_conns_per_ip`/`MaxConnsPerIP` vs. `conn_limit_max_per_ip` | Open since 08-01. Unchanged. |
| T-31 | ClamAV metric family: `clamav` everywhere except `culvert_clam_scan_errors_total` | Open since 08-01. Unchanged. |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` reuses the overloaded term "snapshot" | Open since 08-01. Unchanged; still not wired onto any live GET response. |
| T-33 | MCP `PolicyAction`/`PolicyReason` observation fields mix three vocabularies | Open since 08-02. **Explicitly re-tested this pass against its own "before PR-9" trigger condition — did not escalate** (see Executive Summary and Wave 1). Recommendation unchanged. |
| T-34 | SaaS feed status field-name split across two admin endpoints | Open since 08-02. Unchanged. |

## Soft findings — no action recommended

- Carried over unchanged from 07-24 onward: "Bootstrap" covering two unrelated features (no on-screen
  collision yet); the T3 "seed"/`CULVERT_PROXY_SEED_REF` vocabulary (internally consistent).
- **New this pass:** PR-9/10/11's decision-evidence, rollout-mode, and epoch/revision vocabularies all held
  discipline against their design docs and against each other under direct adversarial tracing (not just a
  diff-region check) — the strongest positive signal yet for this program's "catch it before a consumer is
  built" framing, since T-33 is the first carried-over finding whose exact predicted trigger condition
  landed and was checked, not merely re-confirmed absent.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-02 — no new items, no re-prioritization. Reproduced for continuity:

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-16 (carried over) | Renumber the Supportability-track's colliding ADRs (0008–0011 → 0019–0022) | Low (docs only) | Medium |
| Medium | T-21 + T-32 (carried pairing) | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 (carried over) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 (carried over) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-33 (carried over) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field for those instead | None today (re-verified zero consumers); rises once a consumer exists | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 (carried over) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit | Low | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass re-confirmed, via file-diff checks backed by
line-level reads of every touched-but-cited file, that all fourteen previously-open findings are
unchanged, and went further than a routine carry-over check on one of them: T-33's own stated trigger
condition ("before any PR-9 work builds a consumer") arrived in this exact window, and was traced end to
end rather than assumed — the new admin decision-search surface reads a different, clean struct, so the
predicted escalation did not occur. The window's two other major new subsystems (PR-10's signed CP→DP
snapshots, PR-11's guarded execution/rollout ladder, and the first production MCP GUI built on top of
both) were audited for the same class of drift and found clean, including one non-obvious check (whether
PR-10's new "epoch" is the same fencing concept as the existing ADR-0005 lease epoch or a silent
namesake — confirmed genuine reuse). No new findings. No cosmetic or preference-driven renames were
proposed.
