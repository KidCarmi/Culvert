# Culvert Language & Terminology Governance Review — 2026-08-25

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `9b1ba86..e698a12` (95 commits, 10 on the first-parent path — the largest
> first-parent-commit window this program has processed, dominated by one 154-file addition: the MCP
> Shadow-execution subsystem, plus the CHAOS-55 HA-lease-recovery slice CLAUDE.md already documents,
> SEC-WHSIGN-1's webhook-signing-degraded surface, an LDAP edge-case test sweep, and a new custom
> UI-TLS-certificate upload path). Method: (1) full-repo grep for every `ADR-NNNN` header, prompted by
> this window landing two brand-new `docs/adr/` files (`0032`, `0033`) one day after the prior review's
> own fix claimed `0032` for a renumbered RFC — checking whether that fix's own number survived contact
> with the next window; (2) read the new `mcp_health_plane.go` (353 lines) and its `metrics.go` companion
> in full against the existing `internal/mcp/adminapi` health surface and the pre-existing
> `culvert_mcp_telemetry_ready` series, the two places a same-window collision was most likely given both
> now say "MCP" + "health"/"telemetry" in the same binary; (3) read the full `static/index.html` diff (38
> changed lines) for new GUI copy; (4) checked every one of the sixteen still-open carry-over finding IDs'
> dependent files against this window's changed-file list (154 files) — none intersect, so all sixteen are
> re-confirmed unchanged by file-list absence rather than by diffing unchanged lines; (5) spot-checked
> `mcp_inventory_test.go` (the one file this window touches that a carry-over finding, T-39, depends on) —
> confirmed the touch is an unrelated authentication-oracle security test (SEC-MCP-06/OVN-08), not a change
> to the `qualification_*` vocabulary T-39 is about.
> **Companion change:** one fix ships with this review — a new ADR-0032 collision, created today.

---

## Executive Summary

**One finding, fully fixed: a third instance of the ADR-numbering-collision defect class, this time
surfacing within about a day of the prior fix.** The 08-24 review renumbered
`docs/support/rfc/0018-ai-receives-normalized-evidence.md` to `0032` after confirming that number was
"clean against every `# ADR-NNNN` header in the repository" — true at the moment it was checked. Within
the very next window, an independent PR stream (this window's MCP Shadow-readiness work) added
`docs/adr/0032-mcp-assurance-authn-vs-sender-binding.md`, an ACCEPTED architecture decision, reclaiming the
same number the ink had barely dried on. The two PR streams never cross-referenced each other — the same
root cause T-16, T-46, and T-39 each independently identified: this codebase's decision-record numbering
has no reservation mechanism, so any two branches racing to claim "the next number" can collide, and a
just-freed number is exactly as available to a concurrent stream as a genuinely fresh one. **Fix, same
precedent a third time:** the established, ACCEPTED `docs/adr/` decision keeps `0032`; the not-yet-adopted
RFC-track document (`docs/support/rfc/`, self-titled `# ADR-0032` despite living outside `docs/adr/`, still
carrying its original "PROPOSED — NOT ADOPTED" status from 2026-07-13) is renumbered again, this time to
`0034` — the next number confirmed clean against every `ADR-NNNN` header in the repository, including the
two new files that caused this collision. `docs/support/rfc/0032-ai-receives-normalized-evidence.md` →
`0034-ai-receives-normalized-evidence.md`, header updated, and the five downstream citations that
genuinely mean the RFC's topic (AI receives normalized findings, not raw bundles) updated to match:
`docs/support/TAC-CLOUD-ARCHITECTURE.md` (three call sites: §3 prose, the §8 pipeline step, the §6 section
heading), `docs/support/SUPPORTABILITY-THREAT-MODEL.md` (the `T-PROMPT` row), and
`docs/adr/0016-raw-evidence-vs-normalized-findings.md`'s own "Relates to" line. The two citations in
`docs/design/mcp/SHADOW-ARCHITECTURE.md` that cite "ADR-0032" were verified to genuinely mean the *new*
document (authentication-assurance/sender-binding separation) and left untouched.

**A second concrete near-miss in the same window was checked and found NOT to be drift, because the
authors already disambiguated it in the same change.** `metrics.go` adds `culvert_mcp_telemetry_composed`
(process-level: is the durable-telemetry runtime instantiated) alongside the pre-existing, differently-
scoped `culvert_mcp_telemetry_ready{capability=...}` (per-capability: is export actually functioning) — two
distinct concepts that share the word "telemetry" and sit one HELP-line apart in the same `/metrics`
output. The new metric's own HELP text states "Distinct from the labelled
`culvert_mcp_telemetry_ready{capability=...}` series, which reports per-capability export readiness" —
verified accurate against `mcp_telemetry_metrics.go`. This is exactly the kind of same-word,
adjacent-surface collision this program exists to catch, caught and resolved by the authors themselves
before it ever reached this review. Recorded as a positive continuation pattern, not a finding.

**The new `mcp_health_plane.go` (353 lines, a brand-new unauthenticated `/healthz`+`/readyz`+`/metrics`
surface for MCP) was read in full against the existing authenticated `internal/mcp/adminapi` health
surface (`CapabilityHealth`/`HealthView`, the same file this review's own T-38 fix touches below) for a
naming collision — both now say "MCP" and "health" in the same binary.** No collision found: the two are
distinct Go identifier families (`mcpHealthSnapshot`/`mcpCapabilityState` vs. `CapabilityHealth`/
`HealthView`), serve structurally different audiences (unauthenticated proxy-port monitoring vs.
authenticated admin-port detail), and the new file's own header comment explicitly frames the boundary
("Three postures are kept strictly distinct, and the distinction is the whole point of this file") —
mirroring the same three-surface pattern (`/healthz` field + `/readyz` row + `culvert_*` metrics) already
established by `storage_health.go`, `ca_health.go`, `socks5_health.go`, and `cluster_ca_health.go`. The
capability-state vocabulary (`disabled`/`invalid`/`starting`/`ready`/`degraded`/`draining`/`stopped`) is a
coarser seven-state classification than the admin surface's eight-state `RuntimeStateHealth.State`
(which additionally distinguishes `configured_not_started`); this is a deliberate simplification for a
public, unauthenticated surface, not two names for the same concept, and introduces no collision.

**Also fixed this pass, closing a long-queued item: T-38.** `GET /api/mcp/overview`'s
`health.gateway.drifted_tools` field now dual-emits under the canonical `review_required_tools` name too
(`internal/mcp/adminapi/health.go`), the GUI's "Drifted tools" label is renamed to "Review required tools"
and now reads the canonical field (`static/index.html`), and a unit test pins the dual-emit contract
(`internal/mcp/adminapi/health_test.go`). **The OpenAPI-spec portion of the original recommendation is
declined, with reasoning recorded below** — the entire `/api/mcp/*` GET-response family in
`api/openapi/openapi.yaml` is uniformly and deliberately schema-loose (`type: object,
additionalProperties: true`, zero field-level `properties:` on any GET response across all 25 MCP admin
endpoints; `properties:` appears only on five POST request bodies in that section). Adding field-level
schema for exactly these two fields on exactly these two endpoints would be the first field-level MCP
GET-response schema in the spec and would be inconsistent with, not a fix to, the established convention
for this section — so it is not done. This narrows (does not discharge) the "soft finding" the 08-06 review
recorded about `drifted_tools`'s spec absence: it is not a coverage gap specific to that field, it is the
section's uniform, apparently intentional posture, and any future decision to add field-level typing to
`/api/mcp/*` responses is a section-wide design change, not a two-field patch alongside this fix.

**Terminology Health Score: 8.6 / 10** (up from 8.5 — one new same-window collision (a third recurrence of
the ADR-numbering defect class) was caught and fixed same-day, and one long-queued High-priority backlog
item (T-38) was closed at zero migration risk after two prior reviews left it queued for the tested-field
compatibility bar. The score does not move further because the sixteen-item carry-over backlog is
unchanged — none of those items' dependent files were touched by this window's diff — and because the ADR
numbering defect class recurring a third time, twice now within one day of the previous fix, indicates the
underlying process gap (no reservation/allocation mechanism for decision-record numbers) is still
unaddressed; see the new recommendation below.)

---

## New Recommendation: an ADR-number reservation convention

This is the third occurrence of the identical defect class (T-16 → 0008–0011 vs. main sequence; T-46 →
first `0018` collision; today → second `0032` collision, this time within about a day of the fix that
created the available slot). All three shared one root cause: two independent PR streams each computed
"the next free number" by grepping the tree at the moment they needed one, with no mechanism to claim a
number before the document merges. A convention this program cannot mechanically fix by itself (it would
need either a CI check that fails a PR introducing a duplicate `# ADR-NNNN` header, or a documented
practice of claiming a number via a near-empty placeholder file at proposal time) is out of scope for a
docs-only terminology pass, but is now recorded here for whoever owns `docs/adr/0001-record-architecture-decisions.md`
(the ADR-process ADR itself) to consider — a fourth recurrence would be the point at which "keep fixing it
each time it happens" stops being the cheaper option than "stop it from happening." Not added to the
priority-ordered backlog below because it is a process recommendation, not a terminology-drift finding with
a mechanical fix.

---

## Findings

### T-47 — Second recurrence of the ADR-numbering collision, this time on `0032` (new — fixed this pass)

- **Business concept:** the unique identifier for one architecture decision record.
- **Current names before this fix:** `# ADR-0032` claimed simultaneously by
  `docs/adr/0032-mcp-assurance-authn-vs-sender-binding.md` (ACCEPTED, dated 2026-08-25, part of the MCP
  Shadow-readiness architecture) and `docs/support/rfc/0032-ai-receives-normalized-evidence.md`
  (PROPOSED — NOT ADOPTED, dated 2026-07-13, itself only renumbered to `0032` the previous review cycle
  after the identical collision on `0018`).
- **Recommended canonical name:** `docs/adr/0032-mcp-assurance-authn-vs-sender-binding.md` keeps ADR-0032
  (established, ACCEPTED, expensive to move — cited twice from `docs/design/mcp/SHADOW-ARCHITECTURE.md`
  within the same window it was created); the RFC becomes ADR-0034.
- **Why the current naming was problematic:** identical to T-16 and T-46 — a bare "ADR-0032" citation in
  `TAC-CLOUD-ARCHITECTURE.md` or `SUPPORTABILITY-THREAT-MODEL.md` was ambiguous between two unrelated
  decisions (the MCP authentication-assurance/sender-binding split vs. the AI-input-normalization boundary)
  with no way to disambiguate from the number alone.
- **Why the new name is better:** restores a 1:1 mapping between decision-record number and decision;
  `0034` is confirmed clean against every `# ADR-NNNN` header in the repository as of this pass, including
  both new files from this window.
- **Affected code:** none.
- **Affected API:** none.
- **Affected GUI:** none.
- **Affected Documentation:** `docs/support/rfc/0032-ai-receives-normalized-evidence.md` (renamed to
  `0034-ai-receives-normalized-evidence.md`, header updated), `docs/support/TAC-CLOUD-ARCHITECTURE.md` (3
  citations), `docs/support/SUPPORTABILITY-THREAT-MODEL.md` (1 citation),
  `docs/adr/0016-raw-evidence-vs-normalized-findings.md` (1 "Relates to" citation).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (docs-only, 5 files, no code/API/GUI/config surface).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Medium (matches T-16's and T-46's own priority — a documentation-identifier collision with
  no runtime/functional impact, but a real and now-demonstrated-recurring risk of a reader or an AI agent
  citing or acting on the wrong decision record).

### T-38 — `GET /api/mcp/overview` returns the identical tool-eligibility count under two field names (carried over — fixed this pass)

- **Business concept:** a tool whose observed schema/behavior has semantically drifted from its last known
  fingerprint and now needs human review — `catalog.ReviewRequired`.
- **Fix:** `internal/mcp/adminapi/health.go`'s `CapabilityHealth` struct gains
  `ReviewRequiredTools int \`json:"review_required_tools"\`` alongside the pre-existing, tested
  `DriftedTools int \`json:"drifted_tools"\`` field; both are populated from the same
  `InventoryCounts.Counts()` value in `capability()` (one assignment, `c.ReviewRequiredTools =
  c.DriftedTools`, immediately after the existing `Counts()` call — no change to the `InventoryCounts`
  interface or its `mcp_inventory.go` implementation). `drifted_tools` is kept permanently for wire
  compatibility with any existing consumer of the tested field (`ui_mcp_ux_e2e_test.go`'s fixture, updated
  in the same change to carry both fields, matching the real server's now-dual-emit shape); no consumer is
  asked to migrate. `static/index.html`'s `mcpxRfKv(dl,'Drifted tools', cap.drifted_tools)` becomes
  `mcpxRfKv(dl,'Review required tools', cap.review_required_tools)` — the GUI now speaks the same word the
  `catalog` package's own `String()` method, the per-tool inventory DTO's `"review_required"` fields, and
  four other GUI chip labels already use for this exact state. A new unit test,
  `TestHealth_ReviewRequiredToolsDualEmit`, pins the contract that both fields always carry the identical
  count from the same source.
- **OpenAPI spec: declined, see Executive Summary.** The original 08-06 recommendation to "add both fields
  to the OpenAPI spec" is not carried out — the entire `/api/mcp/*` GET-response family is uniformly
  schema-loose by established, apparently deliberate convention (verified: zero field-level `properties:`
  blocks across all 25 MCP admin GET responses in `api/openapi/openapi.yaml`), and adding schema for
  exactly these two fields would be the first exception to that pattern rather than a fix consistent with
  it. This is recorded as a corrected understanding of the original finding, not a new deferral.
- **Verification:** `go build ./...` (clean), `go test ./internal/mcp/... .` (all pass, including the new
  test and the existing `TestHealth_CapabilityIsolation`/`TestHealth_ManagementAccessFromConfig`/
  `TestHealth_ConcurrentSnapshots`), `gofmt -l` clean on all four touched files.
- **Affected code:** `internal/mcp/adminapi/health.go`.
- **Affected API:** `GET /api/mcp/overview`, `GET /api/mcp/health` (additive field; `drifted_tools`
  unchanged).
- **Affected GUI:** MCP Command Center panel, gateway/management health detail rows.
- **Affected Documentation:** none (OpenAPI change declined, see above).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (additive field, zero breaking change).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** High (matches the original 08-06 finding's priority — the most concrete, wired collision
  this program had found to date, on a live tested field).

---

## Carried-Over Findings (unchanged — re-confirmed by file-list absence)

All sixteen remaining previously-open finding IDs were re-checked against this window's 154-file changed
list; none of their dependent files appear in it, so each is re-confirmed open and unchanged with no
further diffing needed (a stronger confirmation than a touched-but-unrelated-diff check, since there is no
diff at all to misread): T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21 + T-32 (paired), T-25
(residual), T-29, T-30, T-31, T-33, T-34, T-39. Full descriptions remain in the reports where each was first
raised and in `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-24.md`'s carry-over list, to avoid duplicating
unchanged text. (T-33's apparent file-list touch — `internal/mcp/policy/{enums,fields,input}.go` — is a
different, MCP-tool-call-scoped `policy.Action` enum unrelated to the root package's request-log
`Entry.PolicyAction`/`PolicyReason` fields T-33 is about; verified by reading the finding's original file
citations, which are all root-package files absent from this window's diff.)

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-24 for the still-open carry-over items; T-38 and T-47 are resolved in this pass and do
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

Also queued (process-level, not a mechanical rename): the ADR-number reservation convention recommended
above.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass fixed a High-priority, two-review-cycle-queued backlog
item (T-38) within its established compatibility bar, and caught and fixed a new same-window collision
(T-47) — the third instance of a recurring defect class, closed at zero migration risk and zero
compatibility impact for the third time. It also verified, by full reading rather than by name-matching,
that two other same-window near-misses (the `mcp_health_plane.go` health-surface naming and the
`culvert_mcp_telemetry_composed`/`culvert_mcp_telemetry_ready` metric pair) are not drift — both are
deliberately distinct concepts, and the second was already self-disambiguated by its authors in the same
change. All sixteen still-open carry-over findings were re-confirmed unchanged. No cosmetic or
preference-driven renames were proposed. The recurrence of the ADR-numbering defect class, now three times
with two of those within roughly 24 hours of each other, is recorded as a process-level recommendation
rather than re-litigated as a fourth ad-hoc fix waiting to happen.
