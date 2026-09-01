# Culvert Language & Terminology Governance Review — 2026-09-01

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `e698a12..0336149` (202 commits, 16 on the first-parent path — by far the largest
> first-parent window this program has processed, dominated by the MCP Canary Execution Architecture
> (ADR-0035) and MCP Tool Trust (ADR-0034) subsystems: 8 new `internal/mcp/canary`/`internal/mcp/tooltrust`
> packages, the Shadow-execution/Canary-readiness root wiring, and five new MCP design/operator docs).
> Method: (1) four parallel concept-cluster audits — node/tunnel/relay vocabulary, policy-action/alert
> vocabulary, GUI/API/config-key parity (decryption exclusions, HA/cluster, upstream/bandwidth), and
> identity-backend/MCP naming — each instructed to exclude anything CLAUDE.md or a prior review already
> documents as deliberate; (2) a full-repo `# ADR-NNNN` header sweep, prompted by this window adding two new
> ADRs (`0034`, `0035`) one review cycle after the *previous* `0032` collision was fixed by renumbering the
> colliding RFC to `0034` — checking whether that fix's own number survived contact with this window; (3)
> read the new `internal/mcp/canary/doc.go` and `internal/mcp/tooltrust/tooltrust.go` package-doc comments in
> full for vocabulary introduced by two brand-new trust concepts (canary readiness, tool trust) landing in
> the same window; (4) read `docs/design/mcp/MCP-POLICY-MODEL.md`'s policy-lifecycle diagram against the
> canonical `internal/mcp/rollout.Mode` ladder it cites, since the routine's own charter calls for spot-
> checking a cited authority against the citation; (5) checked every one of the sixteen still-open carry-over
> finding IDs' dependent files against this window's 185-file changed-file list — fifteen have no
> intersection (re-confirmed unchanged by file-list absence); one, T-33, has a real intersection
> (`internal/mcp/runtime/policy.go` was touched) and was re-verified by reading the diff rather than by
> absence.
> **Companion change:** two fixes ship with this review — a fourth ADR-numbering collision (this time
> introduced within a single review cycle of the previous fix, prompting a mechanical CI guard rather than
> another one-off rename) and a stale-vocabulary doc fix in `MCP-POLICY-MODEL.md`.

---

## Executive Summary

**The headline finding is process, not vocabulary: the ADR-numbering collision defect class this program
has now fixed three times (T-16, T-46, T-47) recurred a fourth time, within a single review cycle of the
third fix, exactly as the 08-25 review's own recommendation warned it might.** `docs/adr/0034-mcp-tool-trust-approval.md`
(Accepted 2026-08-28, part of this window's MCP Tool Trust work) claimed the same number `docs/support/rfc/0034-ai-receives-normalized-evidence.md`
had only just been renumbered to on 2026-08-25 to resolve the *previous* collision. Two independent PR
streams again each computed "the next free number" by grepping the tree at the moment they needed one, with
no reservation mechanism — the exact root cause identified after the first three occurrences. **This time,
the fix is not just another rename: a mechanical guard is added so a fifth occurrence fails the build
instead of waiting for the next review cycle to notice.**

1. **T-48 — fourth ADR-numbering collision, on `0034` (fixed, same precedent as T-16/T-46/T-47, plus a new
   CI guard).** The established, ACCEPTED `docs/adr/0034-mcp-tool-trust-approval.md` keeps `0034`; the
   still-`PROPOSED — NOT ADOPTED` RFC is renumbered again, to `0036` (the next number confirmed clean against
   every `ADR-NNNN` header in the repository, including both new files from this window — `0035` is already
   claimed by the same window's `docs/adr/0035-mcp-canary-execution-architecture.md`). Five downstream
   citations that genuinely mean the RFC's topic (AI receives normalized findings, not raw bundles) are
   updated to match: `docs/support/TAC-CLOUD-ARCHITECTURE.md` (three call sites), `docs/support/SUPPORTABILITY-THREAT-MODEL.md`
   (one), and `docs/adr/0016-raw-evidence-vs-normalized-findings.md`'s own "Relates to" line. The one citation
   in `docs/design/mcp/SHADOW-ACTIVATION.md` that names "ADR-0034" was verified to genuinely mean the *new*
   Tool Trust document and was left untouched, and the 08-25 review's own historical text (which correctly
   recorded "the RFC becomes ADR-0034" as true *at that time*) is left as the point-in-time record it is,
   per this program's standing practice of not rewriting prior reviews.
   **New this pass:** the 08-25 review recorded that "a fourth recurrence would be the point at which
   'keep fixing it each time it happens' stops being the cheaper option than 'stop it from happening'" but
   left the actual mechanism (a CI check, or a claim-by-placeholder convention) as a recommendation for
   whoever owns the ADR-process ADR, out of scope for "a docs-only terminology pass." The fourth recurrence
   has now happened, so this pass adds `TestDocsADRNumberingIsUnique` (root `docs_adr_numbering_test.go`): it
   walks every Markdown file under `docs/`, collects each file's own self-declared `# ADR-NNNN` header (a
   body citation of another decision's number is prose, not a self-declaration, and is deliberately not
   counted), and fails if any number is claimed by more than one file — turning this from a review-cadence-
   dependent catch into a same-PR, CI-enforced one. A companion `TestDocsADRNumberingHeaderFormat` pins that
   the scanner is actually finding the expected volume of headers, so a future Markdown reformat can't make
   the uniqueness test pass vacuously. Verified to fail against the pre-fix tree (caught the real `0034`
   collision) and pass after the rename.

2. **T-49 — new finding, not fixed (needs a naming decision, sized for a dedicated follow-up): "MCP Agent
   Security Gateway" and "MCP Security Gateway" are used near-interchangeably for the identical Capability-B
   concept, roughly 34 vs. 35 occurrences across dozens of files, including inside the *same* documents.**
   `docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md`'s own title says "MCP Agent Security Gateway,"
   but its body twice drops to "MCP Security Gateway" (Context section, and binding rule #1) — and that
   shorter form is in fact the dominant, systematically-used name across the ~16-document `docs/design/mcp/`
   corpus this whole subsystem is specified from (`PRODUCT-SCOPE.md`, `SECURITY-REQUIREMENTS.md`,
   `EVENT-MODEL.md`, `THREAT-MODEL.md`, `BLUEPRINT.md`, `ROLLOUT-AND-ROLLBACK.md`, and others each title
   Capability B "MCP Security Gateway"), plus several Go doc-comments (`internal/mcp/policy/enums.go`,
   `internal/mcp/protocol/protocol.go`, `internal/mcp/rollout/rollout.go`, `internal/mcp/cpdp/cpdp.go`,
   `internal/mcp/credentials/profile/ids.go`). Meanwhile "MCP Agent Security Gateway" is the form CLAUDE.md
   uses in its own package-summary line and the form the ADR-0024 *title* and several root-level files
   (`metrics.go`, `healthcheck.go`) use. **This was initially misread as a two-line typo fix** (see
   "Self-correction" below) — the actual shape is a large, already-established, roughly-even split that
   needs one deliberate decision (which form is canonical, and whether the other survives as documented
   shorthand — the same treatment `docs/design/PRODUCT-TERMINOLOGY.md` already gives "IdP" as acceptable
   shorthand for "Identity Provider" in dense contexts) rather than a same-day mechanical edit. Not fixed
   this pass; added to the backlog below.
   - **Self-correction, recorded for the audit trail:** this review's first pass edited only
     `docs/adr/0024-...md`'s two body instances to add "Agent" back, matching the ADR's own title. Before
     committing that, a repo-wide occurrence count was run (per this program's "trust but verify" practice
     for any subagent-surfaced finding) and it showed the edit would have made ADR-0024 an isolated outlier
     against its own extensively-cited design corpus rather than fixing anything — so the edit was reverted
     (`git checkout --`) before this document was written. Recorded here rather than silently discarded,
     since the same misreading is an easy trap for a future pass that stops at the first file.

3. **T-50 — `docs/design/mcp/MCP-POLICY-MODEL.md`'s own policy-lifecycle diagram diverged from the
   canonical rollout ladder it cites as its authority (fixed).** Section 4's lifecycle diagram rendered
   `... → Canary → Active → Monitor → Roll Back / Retire` and its prose called this "staged rollout
   ([`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md))" — but that document, and the canonical
   `internal/mcp/rollout.Mode` enum it implements, define the ladder as `Disabled → Observe → Shadow →
   Canary → Production`, with no "Active" value anywhere (`rollout.go:81-113`: `ModeDisabled`,
   `ModeObserve`, `ModeShadow`, `ModeCanary`, `ModeProduction`). A document that names its own source of
   truth and then uses different words than that source is exactly the "different docs describing the same
   feature differently" pattern this program watches for. **Fix:** "Active" → "Production" in both the
   diagram and its prose line, which now also names the enum it maps to
   (`internal/mcp/rollout.Mode`) so a reader can verify the correspondence directly. The diagram's trailing
   "Monitor" stage (an informal note about ongoing post-launch observation, not a rollout-mode value) is left
   as-is — it does not collide with any formal state name, unlike "Active" did with the absent "Production."

4. **New candidate checked and found NOT to be drift: the brand-new ADR-0034 tool-trust API routes
   (`/api/mcp/tool-approvals`, `/api/mcp/tool-approval-decision`) share a route-naming shape with the
   pre-existing, structurally different `/api/mcp/approvals`/`/api/mcp/approval-decision` (PR-9's generic
   four-eyes operational-approval workflow).** Verified this is a real naming proximity between two
   different concepts (`internal/mcp/approval`'s doc comment: "bounded, four-eyes approval state machine...
   for both operational approvals... and local policy-publication requests," vs. `internal/mcp/tooltrust`'s:
   "a SUPPLY-CHAIN TRUST decision, never an execution authorization") — both real MCP admin routes, added in
   different windows, now differing only by a "tool-" prefix. **Recorded as a backlog item, not fixed same-day**:
   see T-51 below. Given the tool-approval routes are brand-new this window (shipped nowhere yet, so a
   rename now costs strictly less than it ever will again), this is the one backlog item where "wait for the
   next dedicated pass" has a real, growing cost — flagged as such in the priority table.

5. **Soft finding, no action:** `/api/upstream` is classified `Domain: "cluster"` in the route registry
   (`ui_routes_meta.go:651`), the same domain as `/api/cluster/bandwidth` and `/api/cluster/node-groups`, but
   — alone among its domain-siblings — does not carry the `/api/cluster/` path prefix. This is a path-
   convention gap rather than a same-concept-two-names collision, GUI/config naming around Upstream Proxies
   is otherwise fully consistent, and the fix (a compatibility alias) has no urgency driver comparable to
   T-51's. Added to the backlog at Low priority rather than fixed same-day.

**Terminology Health Score: 8.5 / 10** (down 0.1 from 08-25's 8.6). The ADR-numbering defect class recurring
a fourth time — the second recurrence within roughly one review cycle — is what moves the needle, not new
vocabulary drift: every other audit this pass ran (node/tunnel/relay, policy-action/alert, decryption-
exclusion, HA/cluster, upstream/bandwidth, identity-backend) came back clean or reconfirmed already-tracked
items. The score is not lower because this pass, unlike the prior three ADR-collision fixes, finally shipped
the structural fix (a CI guard) rather than a fourth rename-only patch, which should make a fifth occurrence
a same-PR build failure instead of a future review's finding.

---

## Findings

### T-48 — Fourth ADR-numbering collision, on `0034` (new — fixed this pass, with a mechanical guard)

- **Business concept:** the unique identifier for one architecture decision record.
- **Current names before this fix:** `# ADR-0034` claimed simultaneously by
  `docs/adr/0034-mcp-tool-trust-approval.md` (Accepted, 2026-08-28, the MCP Tool Trust decision) and
  `docs/support/rfc/0034-ai-receives-normalized-evidence.md` (PROPOSED — NOT ADOPTED, 2026-07-13, itself
  renumbered to `0034` only one review cycle ago — 2026-08-25 — after the identical collision on `0032`).
- **Recommended canonical name:** `docs/adr/0034-mcp-tool-trust-approval.md` keeps ADR-0034 (established,
  ACCEPTED, already cited from `docs/design/mcp/SHADOW-ACTIVATION.md` and `docs/adr/0035-...md` within the
  same window it was created); the RFC becomes ADR-0036.
- **Why the current naming was problematic:** identical to T-16, T-46, and T-47 — a bare "ADR-0034" citation
  in `TAC-CLOUD-ARCHITECTURE.md` or `SUPPORTABILITY-THREAT-MODEL.md` was ambiguous between two unrelated
  decisions (MCP tool-trust supply-chain binding vs. AI-input-normalization boundary) with no way to
  disambiguate from the number alone.
- **Why the new name is better:** restores a 1:1 mapping between decision-record number and decision; `0036`
  is confirmed clean against every `# ADR-NNNN` header in the repository as of this pass (`0035` is already
  claimed by this same window's Canary ADR).
- **Fix:** `docs/support/rfc/0034-ai-receives-normalized-evidence.md` → `0036-ai-receives-normalized-evidence.md`
  (renamed + header updated); five downstream citations updated to `ADR-0036`
  (`docs/support/TAC-CLOUD-ARCHITECTURE.md` ×3, `docs/support/SUPPORTABILITY-THREAT-MODEL.md` ×1,
  `docs/adr/0016-raw-evidence-vs-normalized-findings.md` ×1 "Relates to" line). The one other live "ADR-0034"
  citation in the repo, `docs/design/mcp/SHADOW-ACTIVATION.md:6` ("lets a privileged human trust an exact
  observed fingerprint"), was read and confirmed to mean the *new* Tool Trust document — left unchanged.
- **Structural fix, new this pass:** `docs_adr_numbering_test.go` (root, `package main`) adds
  `TestDocsADRNumberingIsUnique` — walks `docs/` for every file's own `# ADR-NNNN` self-declared header
  (first match per file only, so an inline "Relates to ADR-000X" body citation is never mistaken for a
  self-declaration) and fails listing every file if any number has more than one claimant — plus
  `TestDocsADRNumberingHeaderFormat`, a low-bar sanity floor (≥30 headers found) so a Markdown convention
  change can't make the uniqueness check pass vacuously by finding nothing. Verified: fails against the
  pre-fix tree citing exactly the two colliding files; passes after the rename.
- **Affected code:** `docs_adr_numbering_test.go` (new).
- **Affected API:** none.
- **Affected GUI:** none.
- **Affected Documentation:** `docs/support/rfc/0034-...md` (renamed to `0036-...md`, header updated),
  `docs/support/TAC-CLOUD-ARCHITECTURE.md`, `docs/support/SUPPORTABILITY-THREAT-MODEL.md`,
  `docs/adr/0016-raw-evidence-vs-normalized-findings.md`.
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (docs-only rename/citation-fix, 6 files touched, no code/API/GUI/config
  surface) plus one small, additive, non-production `_test.go` file.
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Medium for the rename (matches T-16/T-46/T-47's own priority); the accompanying guard is
  process-level infrastructure, not a terminology-drift rename, but is included in this change because the
  fourth recurrence is the trigger the 08-25 review named for building it.

### T-50 — `MCP-POLICY-MODEL.md`'s lifecycle diagram named "Active"/an unmapped "Monitor" stage where its own cited authority defines "Production" (new — fixed this pass)

- **Business concept:** the terminal, fully-enforcing stage of the MCP rollout ladder
  (`internal/mcp/rollout.ModeProduction`).
- **Current names before this fix:** `docs/design/mcp/MCP-POLICY-MODEL.md:105-119`'s "Policy lifecycle"
  section rendered `... → Canary → Active → Monitor → Roll Back / Retire` and captioned the
  Observe/Shadow→Canary segment "staged rollout ([`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md))" —
  but `ROLLOUT-AND-ROLLBACK.md` and the `internal/mcp/rollout.Mode` enum it specifies
  (`internal/mcp/rollout/rollout.go:81-113`) define exactly five stages — `Disabled`, `Observe`, `Shadow`,
  `Canary`, `Production` — with no "Active" value anywhere in the type.
- **Why this is real drift:** the document names its own authority and then diverges from it in the very
  next clause — a reader who takes the diagram at face value and later reads `ROLLOUT-AND-ROLLBACK.md` or
  the Go enum has no way to tell whether "Active" is a synonym for "Production," a distinct sixth stage, or
  a stale draft the rollout redesign left behind (it is the first of these, but nothing in the document says
  so).
- **Why the new name is better:** restores a 1:1 mapping between the design doc's diagram and the canonical
  `Mode` enum it is describing; the prose now cites `internal/mcp/rollout.Mode` directly so the
  correspondence is checkable rather than asserted.
- **Fix:** "Active" → "Production" in both the fenced diagram and the following bullet, which now reads
  "**Observe/Shadow → Canary → Production:** staged rollout ([`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md)),
  the same `Disabled → Observe → Shadow → Canary → Production` ladder that document defines
  (`internal/mcp/rollout.Mode`)." The diagram's final "Monitor → Roll Back / Retire" segment is left
  unchanged — "Monitor" reads as an informal note about ongoing post-launch operational monitoring, not a
  named rollout-mode value, and does not collide with any state in the formal ladder the way "Active" did
  with the missing "Production."
- **Affected code:** none.
- **Affected API:** none.
- **Affected GUI:** none.
- **Affected Documentation:** `docs/design/mcp/MCP-POLICY-MODEL.md`.
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (docs-only, one file, two clauses).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Low (a design-doc-internal citation mismatch on a subsystem still gated well below
  Production in every shipped build; no runtime, API, or GUI surface reads this document).

---

## Carried-Over Findings

Fifteen of the sixteen previously-open finding IDs were re-checked against this window's 185-file changed
list; none of their dependent files appear in it, so each is re-confirmed open and unchanged with no further
diffing needed: T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21 + T-32 (paired), T-25 (residual), T-29,
T-30, T-31, T-34, T-39. Full descriptions remain in the reports where each was first raised and in
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md`'s carry-over list, to avoid duplicating unchanged text.

**T-33 was actually touched this window** (`internal/mcp/runtime/policy.go`, part of the Shadow-activation
executor-dispatch rework) and was re-verified by reading the diff rather than by file-list absence. The
change relocates an existing emergency-kill check inline and adds a new `rollout.EffectRecordOnly`-vs-execute
branch, but the literal, non-enum string it assigns on that path — `rb.rec.PolicyAction =
"BLOCKED_BY_EMERGENCY_KILL"` — is the same string T-33 already documented as part of the
`PolicyAction`/`PolicyReason` field's three-vocabulary mix (enum `.String()` output, ad hoc
`BLOCKED_BY_*`/`*_FAILED` literals, and `mcperr.Reason` codes), not a new instance. T-33 is re-confirmed open,
unchanged in substance, still "zero production consumers" per its original finding.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-25 for the still-open carry-over items; T-48 and T-50 are resolved in this pass and do not
appear on the plan. T-49 and T-51 are added.

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium-High | T-39 (carried over) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename away from bare "qualification" | Medium | Small-Medium (needs a naming decision first) |
| Medium | T-49 (new) | Decide the canonical name for MCP Capability B ("MCP Agent Security Gateway" vs. "MCP Security Gateway") across ~16 design docs, several Go doc-comments, CLAUDE.md, and the ADR-0024 title/body; document the loser as accepted shorthand (à la "IdP") if one survives, or unify | Low (docs/comments only; no API/config/wire identifier uses either phrase as a literal) | Medium (needs a naming decision first; touches ~20 files) |
| Medium | T-51 (new) | Rename the ADR-0034 tool-trust routes/handlers off the bare "approval" pattern shared with PR-9's generic `/api/mcp/approvals` (e.g. keep `tool-trust` in the path/handler name throughout, not just the doc-comment) before any external consumer depends on the current shape | Low today (brand-new, unshipped surface — rises the longer it waits) | Small |
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
| Low | T-52 (new, soft) | Alias `/api/upstream` → also reachable at `/api/cluster/upstream` to match its domain-siblings `/api/cluster/bandwidth`/`/api/cluster/node-groups` | Low (additive alias, keep the original) | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

Also queued (process-level, addressed this pass rather than deferred again): the ADR-number reservation
convention the 08-25 review recommended is now `docs_adr_numbering_test.go`, a CI-enforced uniqueness check
rather than a written-only recommendation.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass fixed the fourth occurrence of the recurring
ADR-numbering collision defect class and, unlike the first three fixes, shipped the structural guard (a
CI-enforced uniqueness test) the program had been recommending since the second occurrence — a fifth
collision will now fail the build rather than wait for the next review cycle. It also fixed one genuine
docs-only vocabulary drift (T-50, a design doc using different words than the rollout-mode authority it
itself cites) and surfaced two new, appropriately-deferred findings that need a naming decision rather than
a mechanical edit (T-49's MCP Capability-B name split, largest in scope this program has found; T-51's
brand-new "approval" naming proximity, flagged as time-sensitive precisely because it is new and unshipped).
One candidate finding (an initial misreading of T-49 as an isolated ADR-0024 typo) was caught and reverted
before being committed, and is recorded rather than silently discarded, since verifying a subagent-surfaced
finding against the full corpus — not just the file it was first spotted in — is exactly the discipline this
routine exists to enforce on itself. Fifteen of sixteen carried-over findings are unchanged by file-list
absence; the sixteenth (T-33) was actually touched this window and was re-verified by reading the diff,
confirming the same already-tracked pattern rather than a new instance. No cosmetic or preference-driven
renames were proposed or made.
