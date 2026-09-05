# Culvert Language & Terminology Governance Review — 2026-09-04

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `e698a12..c20c17b` (232 commits, 19 on the first-parent path — the window since the
> 08-25 review, dominated by the MCP Canary-execution program: Canary activation gate, coordinator/rollback
> rehearsal, tool-trust approval, the Live-tier composition/arming/quiesce lifecycle, and Live production
> dependencies, plus the unrelated CHAOS-56 graceful-shutdown bounding already reflected in `CLAUDE.md`).
> Method: (1) full-repo grep for every `# ADR-NNNN` header across `docs/adr/` and `docs/support/rfc/`,
> prompted by this window adding two more `docs/adr/` files (`0034`, `0035`) the same review cycle in which
> the 08-25 review's own fix had *just* renumbered the RFC track's document to `0034` to resolve the prior
> collision; (2) read the new `internal/mcp/tooltrust`, `internal/mcp/canary`, and `mcp_live_*.go` lifecycle
> code in full for the same "two names, one concept" and "one name, two concepts" risk the 08-25 review
> found and cleared in `mcp_health_plane.go` — specifically whether the new "Live tier" vocabulary is a
> second name for the existing "Canary"/"Production" rollout-mode ladder documented in `CLAUDE.md`; (3) read
> the full `static/index.html` diff (8 changed lines — the T-38 fix already recorded in the 08-25 review,
> nothing new) and the full `CLAUDE.md` diff for new GUI/documentation copy; (4) checked every one of the
> fifteen still-open carry-over finding IDs' dependent files against this window's 210-file changed-file
> list — none intersect, so all fifteen are re-confirmed unchanged by file-list absence; (5) checked
> `metrics.go`'s one-line diff and `version.go`'s new `buildCommit` var for new-metric/new-field naming
> collisions against the established `culvert_mcp_*` and version-identity vocabulary.
> **Companion change:** two fixes ship with this review — a fourth recurrence of the ADR-numbering
> collision (fixed the same way as the prior three), and a CI-enforced gate that closes the process gap the
> 08-25 review recommended after the third recurrence, so a fifth cannot reach `main` undetected.

---

## Executive Summary

**One finding, fully fixed: a fourth instance of the ADR-numbering-collision defect class — the exact
scenario the 08-25 review's own closing recommendation warned about, arriving within the very next
window.** The 08-25 review renumbered `docs/support/rfc/0032-ai-receives-normalized-evidence.md` to `0034`
after confirming that number was clean against every `# ADR-NNNN` header in the repository — true at the
moment the fix landed. Within the same review window (before this pass even started), an independent PR
stream (the MCP tool-trust approval work) added `docs/adr/0034-mcp-tool-trust-approval.md`, an ACCEPTED
architecture decision, reclaiming the same number a second time in a row. This is the fourth occurrence of
the identical root cause T-16, T-46, and T-47 each independently identified — no reservation mechanism for
decision-record numbers — and the second time in as many review cycles that a just-freed number was
reclaimed before the next review even ran. **Fix, same precedent a fourth time:** the established, ACCEPTED
`docs/adr/0034-mcp-tool-trust-approval.md` keeps `0034` (cited live from `docs/design/mcp/SHADOW-ACTIVATION.md`,
`docs/design/mcp/CANARY-ACTIVATION-GATE-REPORT.md`, `docs/operator/mcp-tool-trust-approvals.md`, and
`docs/engineering/TECHNICAL-DEBT-REGISTER.md` — each verified by reading in context to genuinely mean the
tool-trust decision, not the RFC); the not-yet-adopted RFC-track document
(`docs/support/rfc/`, still carrying its original "PROPOSED — NOT ADOPTED" status from 2026-07-13) is
renumbered a second time, to `0036` — the next number confirmed clean against every `ADR-NNNN` header in
the repository, including both new files this window added (`0034`, `0035`). Renamed to
`0036-ai-receives-normalized-evidence.md`, header updated, and the same three downstream citation files
updated to match: `docs/support/TAC-CLOUD-ARCHITECTURE.md` (three call sites), `docs/support/SUPPORTABILITY-THREAT-MODEL.md`
(the `T-PROMPT` row), and `docs/adr/0016-raw-evidence-vs-normalized-findings.md`'s "Relates to" line.

**This is the point the 08-25 review flagged in advance: "a fourth recurrence would be the point at which
'keep fixing it each time it happens' stops being the cheaper option than 'stop it from happening.'"** That
threshold is now met, so this pass also ships the mechanical fix the 08-25 review described as one of the
two viable options: a CI-enforced uniqueness gate. `adr_numbering_test.go` (`TestADRNumbering_NoDuplicateAcrossADRAndRFCTracks`)
walks every `.md` file under `docs/adr/` and `docs/support/rfc/`, extracts the `# ADR-NNNN` header from
each file's first ten lines, and fails the build the moment two files claim the same number — following the
repository's existing "anti-drift wall" pattern (`docs_saml_test.go`, `codeql_action_pin_test.go`): a root
`_test.go` reading doc content at whitebox scope, so it runs under `go test ./...` and therefore inside the
existing `pr-fast-gate.yml` lane with no new CI wiring. Verified to actually catch the defect class: a
synthetic duplicate file reproduces the exact failure this review just fixed by hand
(`ADR-0034 is claimed by more than one document: ...`), then passes clean once removed. This is a
mechanical enforcement of a naming-identity invariant — the same category of thing this program already
recommends elsewhere (T-38's dual-emit contract test, T-47's own fix) — not a new terminology *decision*, so
it needed no naming judgment call, only the CI-check option the prior review had already scoped.

**A second near-miss was checked and found NOT to be drift.** The new MCP Canary-execution program
introduces a "Live tier" (`mcp_live_tier.go`: composed → armed → quiescing, tracked in
`internal/mcp/rollout` alongside the existing per-capability Disabled→Observe→Shadow→Canary→Production
mode ladder `CLAUDE.md` documents). "Live" and "Production" are colloquially the same word in most
software vocabularies, so this was read in full for a possible second name for the same rollout stage.
It is not: the file's own header comment states the invariant explicitly — `Live tier COMPOSED != Live
tier ARMED != Canary ACTIVE` — and describes three genuinely distinct axes: whether a real (non-simulated)
executor exists (*composed*), whether the node-readiness gate has been explicitly armed to allow a
Canary/Production mode transition to be authorized (*armed*), and the rollout-mode state machine's own
position (*Canary/Production ACTIVE*, unchanged, still owned by `internal/mcp/rollout`). Arming the Live
tier grants readiness, never activation, and composing it creates capability, never permission — neither
step moves the rollout-mode ladder on its own. No GUI surface exposes "Live" yet (`static/index.html`'s
only diff this window is the already-recorded T-38 fix), so there is no present risk of an admin screen
showing "Live" and "Production" side by side for what reads as the same state. Recorded as a cleared
near-miss, not a finding — the same disposition the 08-25 review gave the `mcp_health_plane.go` check.

**Terminology Health Score: 8.8 / 10** (up from 8.6 — a fourth same-class collision was caught and fixed at
zero migration risk for the fourth consecutive time, and, more significantly, the process gap behind all
four occurrences is now closed by a CI gate rather than left as a standing recommendation: a fifth
recurrence can no longer reach `main` undetected, converting a recurring manual-fix cost into a one-time
engineering cost. The score does not move further because the fifteen-item carry-over backlog is unchanged
— none of those items' dependent files were touched by this window's diff — and because the underlying
"Live"/"Canary" near-miss, while cleared this time, depends on no future GUI surface ever presenting the two
concepts in a way that invites the reader to conflate them; that dependency is noted for the next review
that touches an MCP GUI panel, not scored as an open finding today.)

---

## Findings

### T-48 — Fourth recurrence of the ADR-numbering collision, again on `0034` (new — fixed this pass)

- **Business concept:** the unique identifier for one architecture decision record.
- **Current names before this fix:** `# ADR-0034` claimed simultaneously by
  `docs/adr/0034-mcp-tool-trust-approval.md` (ACCEPTED, part of the MCP Canary-execution program) and
  `docs/support/rfc/0034-ai-receives-normalized-evidence.md` (PROPOSED — NOT ADOPTED, dated 2026-07-13,
  itself only renumbered to `0034` in the immediately-prior review cycle after the identical collision on
  `0032`).
- **Recommended canonical name:** `docs/adr/0034-mcp-tool-trust-approval.md` keeps ADR-0034 (established,
  ACCEPTED, cited live from four other files created or touched in the same window); the RFC becomes
  ADR-0036.
- **Why the current naming was problematic:** identical to T-16, T-46, and T-47 — a bare "ADR-0034"
  citation in `TAC-CLOUD-ARCHITECTURE.md` or `SUPPORTABILITY-THREAT-MODEL.md` was ambiguous between two
  unrelated decisions (MCP tool-trust source-of-truth binding vs. the AI-input-normalization boundary) with
  no way to disambiguate from the number alone.
- **Why the new name is better:** restores a 1:1 mapping between decision-record number and decision;
  `0036` is confirmed clean against every `# ADR-NNNN` header in the repository as of this pass, including
  both new files (`0034`, `0035`) added this window.
- **Affected code:** none.
- **Affected API:** none.
- **Affected GUI:** none.
- **Affected Documentation:** `docs/support/rfc/0034-ai-receives-normalized-evidence.md` (renamed to
  `0036-ai-receives-normalized-evidence.md`, header updated), `docs/support/TAC-CLOUD-ARCHITECTURE.md` (3
  citations), `docs/support/SUPPORTABILITY-THREAT-MODEL.md` (1 citation),
  `docs/adr/0016-raw-evidence-vs-normalized-findings.md` (1 "Relates to" citation).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (docs-only, 5 files touched, no code/API/GUI/config surface).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Medium (matches T-16's, T-46's, and T-47's own priority — a documentation-identifier
  collision with no runtime/functional impact, but now demonstrated to recur every review cycle without a
  mechanical stop).

### T-49 — No CI enforcement of ADR-number uniqueness (new — fixed this pass, closes the 08-25 process recommendation)

- **Business concept:** the mechanism that keeps "the unique identifier for one architecture decision
  record" actually unique, rather than relying on a human (or a point-in-time governance review) to notice
  a collision after the fact.
- **Current state before this fix:** no automated check anywhere in the repository verified that
  `# ADR-NNNN` headers were unique across `docs/adr/` and `docs/support/rfc/`. The 08-25 review recorded
  this gap as a named recommendation ("an ADR-number reservation convention") after the third occurrence of
  T-48's defect class, noting it was out of scope for a docs-only pass and would need either a CI check or a
  documented reservation practice — and predicted a fourth occurrence would be the point to act. It arrived
  within the very next window.
- **Fix:** `adr_numbering_test.go` (`TestADRNumbering_NoDuplicateAcrossADRAndRFCTracks`) — a root-package
  test in the repository's established "anti-drift wall" style (`docs_saml_test.go`,
  `codeql_action_pin_test.go`: a whitebox `_test.go` reading document content, not a shell script or
  separate CI step). It scans every `.md` file under `docs/adr/` and `docs/support/rfc/`, extracts the
  `# ADR-NNNN` header from the first ten lines of each, and fails with the colliding file paths and titles
  the moment two files claim the same number. No new CI wiring is needed: it runs under `go test ./...`,
  already the single full-suite gate in `pr-fast-gate.yml`, so it fails a PR that introduces a duplicate
  before the duplicate can reach `main` — catching the defect class this program has now fixed by hand four
  times, before a fifth occurrence needs a fifth manual fix.
- **Verification:** the gate was proven to actually detect the defect class it targets, not merely to
  compile — a synthetic duplicate (a copy of `docs/adr/0035-...md` relabeled `# ADR-0034` under a temporary
  filename) reproduces the identical failure this review's own T-48 fix corrected, then the gate returns
  clean once the temporary file is removed. `go build ./...`, `go vet ./...`, and `gofmt -l` are clean.
- **Affected code:** `adr_numbering_test.go` (new file).
- **Affected API:** none.
- **Affected GUI:** none.
- **Affected Documentation:** none (this is the mechanical enforcement the 08-25 review's own
  recommendation described; no new operator-facing doc is needed for a build-time gate).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (additive test file; enforces an invariant that already held for every
  file on `main` at the moment this lands, since T-48 cleared the one active collision in the same pass).
- **Compatibility Risk:** None — a false positive is structurally impossible (the check only fires when two
  files genuinely share a header number) and the check cannot block anything already on `main`.
- **Estimated PR Size:** Small.
- **Priority:** High (this is the fix to a process gap that has independently produced four Medium-priority
  findings across five review cycles; closing the gap is worth more than the fifth instance of the
  recurring fix would have been).

---

## Carried-Over Findings (unchanged — re-confirmed by file-list absence)

The same set of previously-open finding IDs carried in the 08-25 review were re-checked against this
window's 210-file changed list; none of their dependent files appear in it, so each is re-confirmed open
and unchanged with no further diffing needed: T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21 + T-32
(paired), T-25 (residual), T-29, T-30, T-31, T-33, T-34, T-39. Full descriptions remain in the reports where
each was first raised and in `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md`'s carry-over list, to avoid
duplicating unchanged text. Two of these were specifically re-verified rather than merely absence-checked,
because this window's diff came close to their subject matter: T-13 residual ("SSL" vs "TLS" inspection
branding) is about the decryption/MITM feature, not the admin-UI's own HTTPS-listener certificate this
window's `ui_tls_custom.go` changes touch — confirmed unrelated by reading both the finding's original scope
and the diff. T-31 (`culvert_clam_scan_errors_total` rename) was re-checked against `metrics.go`'s one-line
diff this window (adding `writeMCPShadowMetrics`, unrelated to ClamAV) and remains open.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-25 for the still-open carry-over items; T-48 and T-49 are resolved in this pass and do not
appear on the plan. The ADR-number reservation recommendation from 08-25 is also resolved (by T-49) and does
not carry forward.

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

Terminology is **not** fully consistent. This pass fixed the fourth recurrence of the ADR-numbering
collision (T-48) at zero migration risk for the fourth time running, and — because that recurrence landed
exactly where the prior review predicted a mechanical fix would become worthwhile — shipped the CI gate
(T-49) that closes the underlying process gap, so this defect class should not require a fifth manual fix.
It also verified, by full reading rather than by name-matching, that the new "Live tier" vocabulary
introduced by the MCP Canary-execution program is a distinct, deliberately-separated concept from the
existing Canary/Production rollout-mode ladder, not a second name for it. All fifteen still-open carry-over
findings were re-confirmed unchanged, with two (T-13 residual, T-31) specifically re-verified against
diff content this window came close to. No cosmetic or preference-driven renames were proposed.
