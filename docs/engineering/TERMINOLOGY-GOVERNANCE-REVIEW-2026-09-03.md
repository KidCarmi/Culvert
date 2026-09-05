# Culvert Language & Terminology Governance Review — 2026-09-03

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** `main` has not advanced past `c20c17b` since the 2026-09-02 review ran (no new merge landed
> in between), so this pass is not a fresh commit-range audit. Instead: (1) full-repo `# ADR-NNNN` header
> sweep, the same mechanical check that has now caught this defect class five times; (2) a review of every
> **open, unmerged** PR this program has previously opened against `main` (`gh`-equivalent
> `list_pull_requests`/`pull_request_read`) — two were found: #1284 (2026-09-01 report) and #1294
> (2026-09-02 report), both still open, both independently re-fixing the identical `ADR-0034` collision
> because neither PR stream could see the other's unmerged branch; (3) re-verification of every finding
> either PR claims to fix, by reading the current file contents on `main` directly rather than trusting
> either PR's diff; (4) re-confirmation of all still-open carry-over finding IDs, which is unchanged work
> since `main` itself has not moved.
> **Companion change:** this pass consolidates and lands the better-designed of the two duplicate,
> unmerged fixes (adding the CI guard #1294 lacked), fixes one small drift item (T-50) both prior PRs had
> already independently identified and fixed identically, and carries forward three findings (T-49, T-51,
> T-52) that #1284 discovered on 2026-09-01 but that never entered the permanent record because that PR
> was never merged.

---

## Executive Summary

**No new terminology drift was found in the product itself this pass.** The one substantive event this
review addresses is process, not vocabulary: this program has now opened **two separate unmerged pull
requests on two consecutive days (#1284 on 09-01, #1294 on 09-02) that independently re-solved the exact
same `ADR-0034` numbering collision**, because each ran against `main` with no visibility into the other's
still-open branch. Neither PR has been merged, so — from `main`'s point of view — the collision this
program first flagged on 2026-09-01 was, until this pass, still live four calendar days later, and two
redundant fixes for it were sitting in the PR queue rather than one. This is the terminology-governance
routine's own process failing in the same way the ADR-numbering defect class it tracks fails: two
independent streams computing "the fix" without a way to see that the other had already computed it.

**This pass does not open a third duplicate.** It consolidates the better of the two designs — #1284's,
which pairs the rename with a permanent CI guard (`docs_adr_numbering_test.go`, verified in this pass to
fail against a reintroduced collision and pass against the fixed tree) — applies it fresh against current
`main`, and folds in #1284's other already-designed fix (T-50, a design-doc/enum-vocabulary mismatch in
`MCP-POLICY-MODEL.md`) plus its three not-yet-landed findings (T-49, T-51, T-52) so they survive into the
permanent record regardless of which PR a human eventually merges. **Recommendation: close #1284 and #1294
as superseded by this PR once it merges**, rather than merging all three (the docs content would converge
to the same end state, but #1284 and #1294 would then be dead, unmergeable branches left in the queue).

**Terminology Health Score: 8.6 / 10** (recovering the 08-25 baseline; the 09-01 report's 8.5 reflected a
collision that, as of that review, was still open — it is closed as of this pass, with a durable guard
against a sixth recurrence). The underlying vocabulary of the product continues to show no new drift this
pass; the score is bounded by the same standing carry-over backlog (T-9 through T-52 below) as every recent
review, plus the fresh process observation above.

---

## Findings

### T-48 — Fifth-generation state of the recurring ADR-numbering collision, on `0034` (consolidated fix, landed this pass with a permanent guard)

- **Business concept:** the unique identifier for one architecture decision record.
- **Current names before this fix:** `# ADR-0034` claimed simultaneously by
  `docs/adr/0034-mcp-tool-trust-approval.md` (Accepted, 2026-08-28, the MCP Tool Trust decision — cited
  from ~40 call sites across `internal/mcp/tooltrust/`, `internal/mcp/catalog/`, `ui_mcp*.go`, `mcp_tooltrust.go`,
  `docs/adr/0035`, `docs/design/mcp/SHADOW-ACTIVATION.md`, `docs/operator/mcp-tool-trust-approvals.md`, and
  `docs/engineering/TECHNICAL-DEBT-REGISTER.md`) and `docs/support/rfc/0034-ai-receives-normalized-evidence.md`
  (PROPOSED — NOT ADOPTED, 2026-07-13, itself already renumbered twice before — `0018` → `0032` → `0034` —
  across the 08-21/08-25 reviews' fixes for the identical defect class).
- **Why this was still real, live drift as of this pass:** verified directly against `main` (not inferred
  from either open PR) — `docs/support/rfc/0034-ai-receives-normalized-evidence.md` still opened with
  `# ADR-0034: AI receives normalized findings...`, and five citations were still ambiguous between the two
  meanings: `docs/adr/0016-raw-evidence-vs-normalized-findings.md`'s own "Relates to" line, and
  `docs/support/TAC-CLOUD-ARCHITECTURE.md` (§3-4 prose, the pipeline step-8 line, and the §6 heading), and
  `docs/support/SUPPORTABILITY-THREAT-MODEL.md`'s `T-PROMPT` row.
- **Recommended canonical name:** `docs/adr/0034-mcp-tool-trust-approval.md` keeps `ADR-0034` (established,
  Accepted, by far the more heavily cross-referenced of the two — moving it would touch ~40 call sites
  instead of 5); the RFC becomes `ADR-0036` (`0035` is already claimed by `docs/adr/0035-mcp-canary-execution-architecture.md`;
  `0036` reconfirmed clean against every `# ADR-NNNN` header in the repository as of this pass).
- **Fix (applied fresh against current `main`, not cherry-picked from either PR):**
  `docs/support/rfc/0034-ai-receives-normalized-evidence.md` renamed to `0036-ai-receives-normalized-evidence.md`
  with its header updated; the five citations above updated to `ADR-0036`. The historical
  `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md` reference to "the RFC becomes ADR-0034" is left as the
  point-in-time record it correctly was at that time, per this program's standing practice of never
  rewriting past reports.
- **Structural fix, adopted from #1284's design (superior to #1294's rename-only fix) and re-verified fresh
  in this pass:** `docs_adr_numbering_test.go` (root, `package main`) — `TestDocsADRNumberingIsUnique` walks
  every Markdown file under `docs/` for its own self-declared `# ADR-NNNN` header (a body citation like
  "Relates to ADR-0016" never starts a line with `# `, so it can't be mistaken for a self-declaration) and
  fails, listing every claimant file, if any number is shared. `TestDocsADRNumberingHeaderFormat` is a
  ≥30-header sanity floor so a Markdown convention change can't make the uniqueness check pass vacuously.
  **Verified in this pass, not assumed:** both tests pass on the fixed tree (`go test -run
  TestDocsADRNumbering -v .`); reintroducing a duplicate `# ADR-0034` header (a throwaway probe file, deleted
  immediately after) makes `TestDocsADRNumberingIsUnique` fail with the exact colliding-file names in its
  message, confirming the guard actually catches the defect class rather than passing by construction.
  `go build ./...` and `gofmt -l` are clean.
- **Affected code:** `docs_adr_numbering_test.go` (new).
- **Affected API:** none.
- **Affected GUI:** none.
- **Affected Documentation:** `docs/support/rfc/0034-...md` → `0036-...md` (renamed, header updated),
  `docs/adr/0016-raw-evidence-vs-normalized-findings.md`, `docs/support/TAC-CLOUD-ARCHITECTURE.md` (×3),
  `docs/support/SUPPORTABILITY-THREAT-MODEL.md`.
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (docs-only rename/citation-fix, 5 files, plus one additive, non-production
  `_test.go` file with no production code path).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Medium for the rename itself (unchanged from T-16/T-46/T-47's precedent); the CI guard is
  process infrastructure rather than a vocabulary fix, included because two further, fully independent
  re-derivations of the identical fix in the intervening 48 hours is the clearest possible demonstration
  that "catch it in the next review" had already stopped scaling.

### T-50 — `MCP-POLICY-MODEL.md`'s lifecycle diagram named "Active" where its own cited authority defines "Production" (re-verified live on `main`, fixed this pass)

Independently identified and identically fixed by #1284 on 2026-09-01; re-verified against current `main`
before reapplying (the file still read `... → Canary → Active` and "Observe/Shadow → Canary → Active:
staged rollout" at the time of this pass) rather than trusted from the PR diff. `internal/mcp/rollout.Mode`
(`internal/mcp/rollout/rollout.go:81-113`) defines exactly `ModeDisabled`/`ModeObserve`/`ModeShadow`/
`ModeCanary`/`ModeProduction` — no `Active` value exists in the type, confirmed by reading the enum
declaration directly in this pass.

- **Business concept:** the terminal, fully-enforcing stage of the MCP rollout ladder
  (`internal/mcp/rollout.ModeProduction`).
- **Fix:** "Active" → "Production" in both the fenced diagram and the following bullet, which now also
  names `internal/mcp/rollout.Mode` directly so the correspondence is checkable rather than asserted. The
  diagram's trailing "Monitor" stage is left as-is (an informal post-launch note, not a named ladder state,
  and does not collide with anything).
- **Affected code:** none. **Affected API/GUI:** none. **Affected Documentation:**
  `docs/design/mcp/MCP-POLICY-MODEL.md`. **Affected Configuration:** none.
- **Migration Complexity:** Trivial (docs-only, one file). **Compatibility Risk:** None. **Estimated PR
  Size:** Small.
- **Priority:** Low (a design-doc-internal citation mismatch on a subsystem gated well below Production in
  every shipped build; no runtime, API, or GUI surface reads this document).

---

## Carried forward from the unmerged #1284 (2026-09-01) findings — not fixed this pass, added to the permanent backlog

These three findings were discovered by #1284's review on 2026-09-01 but, because that PR was never merged
and the 09-02 review ran against a `main` that never saw it, they were absent from the 09-02 report and
would have been silently lost from this program's record if not re-added here. Re-read against current
`main` in this pass to confirm they are still accurate; not fixed (each needs either a naming decision or
is flagged as lower priority than T-48/T-50).

### T-49 — "MCP Agent Security Gateway" vs. "MCP Security Gateway" — needs a canonical-name decision, not a mechanical fix

Re-confirmed present: `docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md`'s own title says "MCP
Agent Security Gateway," but its body uses the shorter "MCP Security Gateway" in the Context section and
binding rule #1 — and that shorter form is the dominant, systematically-used name across the
`docs/design/mcp/` corpus (`PRODUCT-SCOPE.md`, `SECURITY-REQUIREMENTS.md`, `EVENT-MODEL.md`,
`THREAT-MODEL.md`, `BLUEPRINT.md`, `ROLLOUT-AND-ROLLBACK.md`, and others) plus several Go doc-comments
(`internal/mcp/policy/enums.go`, `internal/mcp/protocol/protocol.go`, `internal/mcp/rollout/rollout.go`,
`internal/mcp/cpdp/cpdp.go`, `internal/mcp/credentials/profile/ids.go`). CLAUDE.md's own package-summary
line and several root files (`metrics.go`, `healthcheck.go`) use the longer form. This is a large,
roughly-even, already-established split (~34 vs. ~35 occurrences per the 09-01 count) that needs one
deliberate decision — which form is canonical, and whether the other survives as documented shorthand (the
same treatment `docs/design/PRODUCT-TERMINOLOGY.md` already gives "IdP" for "Identity Provider") — not a
same-day mechanical edit that risks making one file an isolated outlier against its own corpus (exactly the
mistake the 09-01 review caught and reverted in itself before committing). Not fixed this pass; sized for a
dedicated follow-up.

### T-51 — MCP Tool Trust's `/api/mcp/tool-approvals`/`tool-approval-decision` routes share a naming shape with the pre-existing, structurally different `/api/mcp/approvals`/`approval-decision`

Re-confirmed present. `internal/mcp/approval`'s four-eyes operational-approval workflow (PR-9, both
operational approvals and policy-publication requests) and `internal/mcp/tooltrust`'s supply-chain
tool-trust decision ("never an execution authorization," per its own doc comment) are different concepts
that now differ in their route/handler names only by a "tool-" prefix. Flagged as time-sensitive rather
than merely medium priority because the tool-trust routes are still new and unshipped as of this pass — a
rename now costs strictly less than it will once any consumer or documentation depends on the current
shape. Not fixed this pass (needs a naming decision, not a same-day edit).

### T-52 — `/api/upstream` alone lacks the `/api/cluster/` prefix its route-registry domain-siblings (`bandwidth`, `node-groups`) carry

Re-confirmed present (`ui_routes_meta.go`, `Domain: "cluster"` still without the path prefix). Soft finding,
Low priority — a path-convention gap, not a same-concept-two-names collision; GUI/config naming around
Upstream Proxies is otherwise fully consistent. An additive alias (`/api/cluster/upstream` reachable
alongside the existing path) would close it at effectively zero migration risk whenever someone picks it
up.

---

## Carried-Over Findings (unchanged — re-confirmed; `main` has not moved since the 09-02 review's window)

All fourteen previously-tracked, still-open finding IDs from the 08-25/09-02 record remain open and
unchanged, since `main` itself has not advanced past `c20c17b` in the interim: T-9, T-11, T-12, T-13
(residual), T-17, T-18, T-21 + T-32 (paired), T-25 (residual), T-29, T-30, T-31, T-33, T-34, T-39. Full
descriptions remain in the reports where each was first raised, to avoid duplicating unchanged text.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 09-02 for the still-open carry-over items; T-48 and T-50 are resolved in this pass and do not
appear on the plan. T-49, T-51, T-52 are restored from #1284's unmerged findings.

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium-High | T-39 (carried over) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename away from bare "qualification" | Medium | Small-Medium (needs a naming decision first) |
| Medium | T-49 (restored) | Decide the canonical name for MCP Capability B ("MCP Agent Security Gateway" vs. "MCP Security Gateway") across ~16 design docs, several Go doc-comments, CLAUDE.md, and ADR-0024's title/body; document the loser as accepted shorthand if one survives, or unify | Low (docs/comments only; no API/config/wire identifier uses either phrase literally) | Medium (needs a naming decision first; touches ~20 files) |
| Medium | T-51 (restored) | Rename the ADR-0034 tool-trust routes/handlers off the bare "approval" pattern shared with PR-9's generic `/api/mcp/approvals` before any external consumer depends on the current shape | Low today (brand-new, unshipped surface — rises the longer it waits) | Small |
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-21 + T-32 (carried pairing) | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 (carried over) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 (carried over) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-33 (carried over) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field instead | None today (zero production consumers); rises once a consumer exists | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 (carried over) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit | Low | Small |
| Low | T-52 (restored) | Alias `/api/upstream` → also reachable at `/api/cluster/upstream` to match its domain-siblings | Low (additive alias, keep the original) | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

---

## Process Recommendation (repeated, now with an added observation)

The ADR-number reservation-mechanism recommendation stands from 08-25/09-01 — still out of scope for a
docs-only pass, still belongs with whoever owns `docs/adr/0001-record-architecture-decisions.md` — but this
pass adds one more data point: the *review program itself* fell into the identical class of failure it
documents (two independent unmerged PR streams each computing "the fix" with no visibility into the other),
one review cycle after landing a mechanical guard against the *documentation* version of the same failure
mode. The practical mitigation adopted starting this pass: before opening a new fix for any previously-flagged
finding, check open PRs against `main` first (this pass did, via `list_pull_requests`) rather than assuming
a finding is still unaddressed just because it was still open in the last *merged* state. This is recorded
as a process note for the routine's own operation, not a terminology finding, and is not added to the
priority-ordered backlog above.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent, though no *new* vocabulary drift was found in the product this
pass — `main` has not advanced since the previous review, so there was no new commit-range surface to audit.
The substantive work this pass did was consolidating two redundant, unmerged fixes for the same
already-flagged ADR-numbering collision into one, landing the better-designed of the two (with its CI
guard, freshly re-verified rather than trusted from the diff), fixing one small already-identified drift
item (T-50), and recovering three findings (T-49, T-51, T-52) that a prior unmerged PR had found but that
had fallen out of the permanent record. All fourteen standing carry-over findings were re-confirmed open
and unchanged. No cosmetic or preference-driven renames were proposed or made. **Recommendation for the PR
reviewer:** merge this PR and close #1284 and #1294 as superseded — merging all three would either conflict
or leave two dead branches with no further purpose once this one lands.
