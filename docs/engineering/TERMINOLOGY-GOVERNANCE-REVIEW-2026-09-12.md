# Culvert Language & Terminology Governance Review — 2026-09-12

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `d378dff..2833db3` — the window since the 2026-09-11 report's merge point,
> confirmed as the current `origin/main` HEAD by a fetch immediately before this report was written (per
> the DEBT-014 lesson recorded in the 2026-09-09 report: sync against `main` right before opening a PR,
> not only at review-start). The window covers 9 first-parent merges / 95 files / ~12,100 insertions,
> dominated by the new MCP-First Controlled Canary feature (ADR-0035: `internal/mcp/canary`,
> `internal/mcp/execution`, `internal/mcp/runtime`, `internal/mcp/tooltrust`,
> `internal/mcp/upstreamclient`, the root `mcp_canary_*.go`/`mcp_live_*.go`/`mcp_tooltrust.go` wiring,
> `ui_mcp_tooltrust.go`, and four new/changed docs), the CHAOS-65 OCSP revocation-checking hardening's new admin
> JSON surface, the CHAOS-63 admin-login oversized-username counter's new legacy-GUI surface
> (`loginOversizeRejected`), an expansion of the existing `trust_forwarded_headers` config key's
> documentation, a rate-limit exempt-view internal refactor, and a SOCKS5 log-injection fix.
> **Correction made before this report's initial version merged:** the first draft of this report
> under-scoped Part B — it described only the OCSP/rate-limit-exempt/SOCKS5 changes as "the remaining
> window" and mischaracterized the OCSP admin-JSON naming as "casing only." `chatgpt-codex-connector`'s
> automated review on this report's own PR (#1372) caught both: the diff also added the
> `loginOversizeRejected` GUI/API field and expanded `trust_forwarded_headers` documentation (neither
> audited in the first draft), and three of the six new OCSP JSON fields are genuinely inconsistent in
> wording with their own Go accessor and/or the `/metrics` reason label, not just differently cased. Both
> are fixed below (Part B now covers the omitted items; the OCSP finding is now T-54, not waved off).
> This is recorded rather than quietly corrected: it is a concrete instance of the same class of risk
> DEBT-014 already tracks for this program — a scheduled, unwatched review can produce an incomplete or
> incorrect conclusion — except here the catch came from automated PR review rather than a parallel run.
> **Second correction, same PR, requested manual re-review:** a follow-up "@codex review" on the fixed
> commit found the T-54 fix itself was still incomplete — `staleResponseTotal` (`ui_security.go:1841`)
> has the exact same "Response"-insertion mismatch against `StaleTotal()`/`stale` that the first fix
> already named for `malformedResponseTotal`, and the first pass missed it despite auditing the same
> block of code. T-54 below now covers all three mismatched identifiers. Two rounds of external review
> catching gaps in one report is itself a signal about this routine's own audit thoroughness, not just
> about OCSP naming, and is left visible here rather than smoothed into a single clean-looking finding.
> **Third correction, same PR, a second manual re-review:** the very next "@codex review" found three
> more gaps, all now fixed: (1) `responder_blocked` — a pre-request SSRF/scheme/parse refusal — is
> charged under the SAME `culvert_ocsp_response_rejected_total` metric family as the five genuine
> discarded-response reasons, contradicting T-54's own "why was this response discarded" framing for one
> of the six labels it claimed to fully cover; folded into T-54 as a metric-family scope correction, not
> a rename. (2) `CHANGELOG.md` gained an 18-line rate-limit-exemption entry this window that the report
> had claimed didn't exist — checked directly and found clean (consistent identifiers, explicitly states
> no API/metric/dashboard change). (3) `docker-compose.yml`'s YARA-rules-directory documentation
> (`/app/yara`→`/data/yara`) was not in the audited doc list — checked directly and found to be a
> real, already-fixed, now test-pinned pre-existing defect (the old doc told operators to mount a
> directory that the runtime never actually read from), not new drift. **Three rounds of review, three
> genuine catches, on one report about terminology audits — the irony is not lost, and is recorded rather
> than hidden**: the fixes below are complete as far as this report currently knows, and the process
> lesson (this routine's own single-pass audits are not reliably complete without adversarial review) is
> more durable than any one of the three individual OCSP/CHANGELOG/compose findings.
> **Fourth correction round, same PR, when the PR was brought up to date with `main` on 2026-09-25:**
> further "@codex review" passes found five more gaps, all now fixed: (1) the CHAOS-65 OCSP entries in
> `CHANGELOG.md` — the largest changelog addition in the window — were never audited (now Part 2 item 5;
> clean, with one pre-existing GUI-label observation); (2) T-54 recommended a plain rename of two fields in
> the stable `GET /api/ocsp` schema, which `docs/api/API-VERSIONING-POLICY.md` classifies as breaking (now
> additive + deprecate); (3) Reviewed Operation Class was described as a read/write/control classification
> when it is deliberately binary (`read_only`/`mutating`); (4) the report credited itself with the OCSP
> operator-doc table fix after `main` had landed those rows independently; (5) the summary counted four
> audits while enumerating five. Four review rounds on one terminology report strengthens, rather than
> changes, the process lesson above.

---

## Executive Summary

**One new finding (T-54, queued to the backlog; its missing-doc-table-rows half was resolved independently on `main`
before this report merged); the large new MCP Canary surface introduced no drift.**

Five bounded audits were run against the diff since the last review (up from two in the first draft, after
later review rounds found real coverage gaps — see the corrections above):

1. **Full naming audit of the new MCP-First Controlled Canary surface**, the largest new user/operator-
   facing vocabulary introduced since the last review. Three concept groups that could plausibly have
   collapsed into loose synonyms were checked end-to-end across Go internals, root wiring, the admin API
   (`ui_mcp_tooltrust.go`), and all four new/changed docs (`docs/adr/0035-mcp-canary-execution-architecture.md`,
   `docs/design/mcp/CANARY-FIRST-RUNBOOK.md`, `docs/design/mcp/CANARY-READINESS-MATRIX.md` — row 4a, added
   this window, maps `canary_scope_not_exact_first_canary`/`canary.ValidateFirstCanaryScope` to the same
   "First Canary" concept verified below, reinforcing rather than contradicting the conclusion —
   `docs/operator/mcp-first-controlled-canary-review.md`), and each turned out to be genuinely distinct,
   consistently-applied concepts rather than drift:
   - **"Canary"** (the overall architecture/phase) vs. **"First Canary"** (the deliberately narrower,
     exact-scope gate for the one initial experiment — explicitly called out in the ADR itself as "a
     SEPARATE predicate on purpose," `docs/adr/0035-mcp-canary-execution-architecture.md:96-106`) vs. the
     **"MCP First Controlled Canary Review"** document (the authorization gate for that same First-Canary
     experiment). All three are used consistently for their own, distinct referents everywhere checked.
   - **"Tool Trust"** (the subsystem, `internal/mcp/tooltrust`) vs. **"Tool Approval"** (the reviewed grant
     record, `tooltrust.ToolApproval`, exposed at `/api/mcp/tool-approvals`) vs. **"Reviewed Operation
     Class"** (a narrower field *on* a Tool Approval — the deliberately BINARY read-only-versus-mutating
     determination stated at review time, `ToolApproval.ReviewedOperationClass`, wire labels `read_only` /
     `mutating` with a fail-closed `unset` zero value; it intentionally does not mirror the richer policy
     operation taxonomy, `internal/mcp/tooltrust/reviewed_operation.go`) — three altitudes of one coherent hierarchy, not
     rival names for one thing. Test-file phrases like "trust binding" / "atomic binding" describe
     behavior, not a fourth noun; no production code or doc promotes them to first-class vocabulary.
   - **"Live Gate"** (the execution-layer admission check, `internal/mcp/execution/livegate.go`) vs. **"Live
     Execution"** (a `tooltrust.Purpose` value/tier name) vs. **"Read-First"** (the classifier in
     `mcp_canary_read_first.go`, used uniformly ~30+ times in the operator doc) — no cross-contamination
     found between the three.
   No new `culvert_mcp_*` metrics were introduced in this window (the only `metrics.go` change wires
   pre-existing OCSP counters), so there was nothing new to check on that surface.
2. **Full audit of the OCSP admin-JSON surface (`ui_security.go`, new this window) against its own Go
   accessors, `/metrics` reason labels, the OpenAPI spec, and the operator doc — found genuine drift,
   not mere casing, in two directions.** See **T-54** below (now covering three mismatched identifiers
   plus a metric-family scope correction for `responder_blocked`). The rate-limit exempt-view change
   (`security.go`'s `rlExemptView`/`loadExemptView`) has no new GUI/API/metric surface (correction: it
   DOES have a new doc surface — see item 4 below, checked and clean) and the SOCKS5 log-injection fix
   remains internal-only with no new surface at all — per the 2026-09-11 report's rule that internal
   reliability engines with no independent admin surface are not findings, the SOCKS5 fix is out of scope.
3. **Audit of the two other new user-facing surfaces in this window** (both missed by this report's first
   draft): the CHAOS-63 admin-login oversized-username counter's new legacy-GUI element
   (`static/index.html`'s `oversize-login-hint`/`oversize-login-text`, wired to the `loginOversizeRejected`
   JSON field added in `ui_config.go`), and the expanded documentation of the pre-existing
   `trust_forwarded_headers` config key (`config.example.yaml`, `docs/OPERATIONS.md`). Neither is drift:
   `loginOversizeRejected` (JSON) / `oversize-login-*` (HTML element IDs, not user-visible text) /
   `culvert_login_oversize_rejected_total` (metric, `events.go:291-293`) all use the same three words
   ("login," "oversize," "rejected") — the element IDs merely reorder them, which is a naming-order
   choice inside non-visible internal HTML ids, not a different name for a different concept, and the
   actual displayed copy ("… refused for an oversized username …") matches the concept unambiguously.
   `trust_forwarded_headers` is spelled identically — YAML key, Go variable (`trustForwardedHeaders`),
   JSON field, and every doc reference — across all ~25 call sites checked (`config.go:40`,
   `admin_settings.go:137`, `store.go:1616`, `ui_config.go:2044`, `docs/OPERATIONS.md:196-224`,
   `docs/saml-idp-configuration-reference.md:36,70`, etc.); this window only added explanatory prose about
   an already-consistent key. Neither surface is a finding.
4. **`CHANGELOG.md`'s new rate-limit-exemption entry, and `docker-compose.yml`'s YARA-rules-directory
   change** (both also missed by the first draft — see the corrections above). The `CHANGELOG.md` entry
   is release-note prose describing the `rlExemptView`/`IsExempt`/`AddExemptions`/`prefixSet` work using
   exactly those identifiers and explicitly states "No API, metric, or dashboard change" — consistent, not
   a new operator-facing vocabulary surface (a changelog entry is a historical record, not a live
   reference an admin cross-checks against the GUI). `docker-compose.yml`'s change (`/app/yara`→`/data/yara`
   in the top-of-file comment, the documented override instruction, and the commented-out volume example)
   is a **real, already-fixed pre-existing defect**, not new drift: `docker_compose_yara_rules_dir_test.go`
   (added this window) documents that the OLD comment told an operator to mount a host directory over
   `/app/yara` and reload — which had silently NO EFFECT, because the proxy's actual `-yara-rules-dir` flag
   was always `/data/yara` and neither `globalYARA.LoadDir`/reload nor the first-boot seed ever read back
   from `/app/yara` after that seed. The fix makes the documented override path match the runtime flag,
   and is now pinned by that test so the two can't drift apart again. `main.go:1217`'s
   `const bundledDir = "/app/yara"` is correctly left alone — it names a DIFFERENT concept, the read-only,
   image-baked seed source `seedYARARules` copies from once on first boot, distinct from the persistent,
   operator-mountable `/data/yara` runtime directory — confirmed by checking `docs/operator/` for any
   remaining `/app/yara` reference (none found). Both checked and clean.
5. **`CHANGELOG.md`'s CHAOS-65 OCSP entries (`CHANGELOG.md:12-76` at `2833db3`)** — omitted from the
   second draft's Part 2 even though they are the largest changelog addition in this window (found in
   review). Audited against the API, metrics, GUI and operator doc at `2833db3`: `coverage` /
   `uncheckedEnforcingPaths` match the `GET /api/ocsp` keys (`ui_security.go:1836-1837`,
   `api/openapi/openapi.yaml:480`) and the GUI reader (`static/index.html:17519`);
   `culvert_ocsp_path_checked{path}` matches the operator doc (`docs/operator/ocsp-revocation-checking.md:27,89`);
   the `security.ocsp_check` key, `ParseResponseForCert`, `id-kp-OCSPSigning` and the `HTTP(S)_PROXY`
   behaviour change are spelled identically in code (`config.go:47`, `internal/ocsp/ocsp.go:664,716,179`) and
   the doc (`:3,124`). "Responder" is used consistently throughout. The entries name none of the
   discarded-response reason labels, so they neither extend nor contradict T-54. One observation, recorded
   here rather than filed as a new finding: the changelog says "a banner on the OCSP panel", and the panel
   is actually titled **"OCSP / CRL Revocation"** (`static/index.html:4477`), a title that names a CRL
   capability the product does not have (no CRL fallback exists — register row OCSP-10). That is a
   pre-existing GUI label, not drift introduced this window; it belongs with T-54's GUI follow-up when that
   is scheduled.

**Carry-over backlog re-verified, one item's evidence base updated (no change to its finding or priority).**
T-29 (`rate_limit`/`rate_limit_rpm`) was re-checked directly against the current tree and is unchanged
(`config.go:56` vs. `admin_settings.go:34`/`config_surfaces.go:214-221`). T-39 (bare "qualification" config
keys) is also unchanged in its core citations (`config.go:237,250,261-277`), but this window added more
reason-code strings sharing the same unqualified "qualification" prefix (`mcp_observe_startup.go:171-213`,
`mcp_policy.go:145-341`: `qualification_inventory_invalid`, `qualification_policy_uncompilable`,
`qualification_policy_traversal`, etc.) — the same underlying naming gap, now with a slightly larger
footprint, not a new finding and not a change to T-39's recommended action or priority.

**Terminology Health Score: 8.6 / 10** (down from 8.7, held since 2026-09-08). Not for the size or
severity of T-54 — it is a Low/Medium-priority, admin-telemetry-only naming gap — but because the backlog
genuinely grew by one item this pass (14 entries, up from 13), and because this report's own first draft
initially missed it and understated its audit scope, which this program's own precedent (DEBT-014) treats
as a real, recorded process signal rather than something to paper over. A 95-file, security/reliability-
heavy window that also introduced a brand-new, multi-layer MCP feature with real potential for
concept-name collapse (Canary/Tool-Trust/Live-Gate) showed strong naming discipline there; the one gap
found was in a much smaller, already-shipped admin-telemetry addition, and was caught by review before
this report merged rather than after.

---

## Findings

### T-54 — OCSP "discarded response" reason vocabulary disagrees across Go accessors, `/metrics` labels, and the new admin/OpenAPI JSON fields (new — queued; its doc-table sub-part was resolved independently on `main`)

- **Business concept:** the reason a fetched OCSP response was discarded rather than treated as an
  affirmative revocation verdict (`internal/ocsp/ocsp.go`, CHAOS-65) — **with one scope correction**:
  `culvert_ocsp_response_rejected_total{reason="responder_blocked"}` is NOT actually one of these. Its
  HELP text ("OCSP responses discarded without producing a verdict") and its membership in the same
  labelled series as the other five reasons both claim it describes a fetched-and-discarded response, but
  `queryOCSP` charges `blockedTotal` (`internal/ocsp/ocsp.go:587,591,601`) for an unparseable responder
  URL, a disallowed scheme, or an SSRF-blocked host — all three BEFORE any HTTP request is sent, and the
  code's own comment says so directly ("no response existed to reject"). So the metric family conflates
  two different concepts under one business-concept label: a response that arrived and was found
  wanting (five reasons), and a responder that was never queried at all (one reason). This is a distinct
  defect from the identifier-spelling mismatches below — a metric-family scope mismatch, not a wording
  mismatch — folded into the same T-54 because it is the same newly-audited surface and the same
  underlying lesson (a claim this report made about "all six reasons" needed to be checked against all
  six, not four).
- **Current names:**
  - Go accessors (`internal/ocsp/ocsp.go:243,248,252,256`): `MalformedTotal()`,
    `UnauthorizedResponderTotal()`, `StaleTotal()`, `UnknownTotal()`.
  - `/metrics` `reason=` labels (`ocsp_metrics.go:58-61`): `malformed`, `unauthorized_responder`, `stale`,
    `unknown_status`.
  - New admin JSON fields, added this window (`ui_security.go:1839-1842`, also documented in
    `api/openapi/openapi.yaml:488-491` and `openapi.json:2675-2741`, and already consumed by
    `static/index.html:17514-17527`): `malformedResponseTotal`, `unauthorizedResponderTotal`,
    `staleResponseTotal`, `unknownStatusTotal`.
  - Operator doc's canonical rejection-reasons table (`docs/operator/ocsp-revocation-checking.md:44-47`,
    §2 "Posture"): lists `not_for_certificate`, `stale`, `unknown_status`, `responder_blocked` — but
    **omits `malformed` and `unauthorized_responder` entirely** from the table (the GUI's red banner does
    describe the `unauthorized_responder` case in prose, and `malformed` is mentioned once in passing
    GUI-banner text, but neither has a table row in the doc an operator would consult first).
  - `UnauthorizedResponderTotal`/`unauthorized_responder`/`unauthorizedResponderTotal` are, by contrast,
    spelled identically across all three code surfaces — only the doc-table omission is the problem for
    that one reason.
- **Why the current naming is problematic:** for `malformed` and `stale`, three code surfaces use three
  different spellings for each one concept (`Malformed`/`malformed`/`malformedResponseTotal`,
  `Stale`/`stale`/`staleResponseTotal` — in both cases the JSON field alone inserts "Response"), so an
  admin cross-referencing the Go source, a `/metrics` scrape, and the admin API response for the same
  discarded-response reason sees three different names. For `unknown_status`, the Go accessor
  (`UnknownTotal`) omits "Status" that both the metric label and the JSON field include — a smaller but
  real two-vs-one inconsistency. Separately, two of the six discard reasons that already have live
  counters and (for `unauthorized_responder`) a dedicated red GUI banner are missing from the operator
  doc's own canonical reference table for "why was this response discarded" — the exact question that
  table exists to answer.
- **Why the new name is better:** using the `/metrics` `reason=` label as the canonical spelling for each
  concept (it is already the vocabulary an operator learns from `/metrics`, from any Prometheus alert
  rule, and from the doc's existing table rows) and applying it consistently to the Go accessor and the
  JSON field removes the three-way ambiguity with zero change to the label an operator already searches
  for; adding the two missing table rows lets the doc answer the question it already claims to answer for
  all six reasons, not four.
- **Affected code:** `internal/ocsp/ocsp.go` (rename `UnknownTotal`→`UnknownStatusTotal` to match its own
  metric label — `MalformedTotal`/`UnauthorizedResponderTotal`/`StaleTotal` already match their labels
  and need no Go change); `ui_security.go` (ADD JSON fields `malformedTotal` and `staleTotal` alongside
  the existing `malformedResponseTotal` / `staleResponseTotal`, which stay and are deprecated — see
  Compatibility Risk); `ocsp_metrics.go` (the metric-family scope correction above:
  `responder_blocked` must MOVE OUT of `culvert_ocsp_response_rejected_total` into an appropriately named
  series, with a compatibility window for dashboards and alerts that read the old label. Changing only the
  HELP text is NOT sufficient — the family name itself would still say "response rejected" for a case in
  which no response existed. The new series' name is a naming decision left to the implementing change).
- **Affected API:** `api/openapi/openapi.yaml`/`openapi.json` — an additive MINOR contract change
  (`docs/api/API-VERSIONING-POLICY.md`) that must follow `docs/api/API-DEPRECATION-POLICY.md` in full for
  the two old properties (`deprecated: true`, `x-culvert-deprecated-since`, replacement and migration text
  in the description, a `Deprecated` CHANGELOG entry), then `make api-bundle`. The old names must keep
  working. This report records the requirement; the implementing change owns the exact steps, which the
  repository's API-governance checks enforce.
- **Affected GUI:** `static/index.html:17515` (read the new JSON keys) AND the OCSP panel's aggregate
  (`:4485,17514-17517`), which today adds `responderBlockedTotal` into "Responses rejected" — once the
  split lands it must be shown separately (e.g. "Responders refused"), or the GUI keeps the same
  mismatch the metric split removes.
- **Affected Documentation:** `docs/operator/ocsp-revocation-checking.md` §2 — the rejection-reasons table
  was missing rows for `malformed` and `unauthorized_responder`. **Resolved independently on `main`**, not
  by this report: an earlier draft of this PR added the two rows, but `main` landed them first (with more
  precise wording), so the branch keeps `main`'s table verbatim and this report changes no file other than
  itself. That closes the MISSING-ROWS gap only. When the `responder_blocked` split lands, the same
  runbook must also move `responder_blocked` out of its discarded-response table and out of the old
  family's description (`docs/operator/ocsp-revocation-checking.md:38-49,107-114`) — that part is queued
  with the code/API half.
- **Affected Configuration:** none.
- **Migration Complexity:** Small-Medium (the Go accessor rename `UnknownTotal`→`UnknownStatusTotal` is
  internal; the two JSON fields `malformedResponseTotal` / `staleResponseTotal` must be handled as an API
  change — see Compatibility Risk — plus one generated-spec regen and a naming decision for the
  `responder_blocked` family-scope correction).
- **Compatibility Risk:** Medium for the JSON half. Both fields are published in the `OCSPStatus` schema of
  the stable `GET /api/ocsp` operation, and `docs/api/API-VERSIONING-POLICY.md` classifies renaming or
  removing a field as BREAKING (Gate 7). An earlier draft of this report called the rename low-risk because
  the fields were new; that is not a safe assumption once a field is in a published stable schema. The
  recommended path is ADDITIVE: emit the new names `malformedTotal` / `staleTotal` alongside the old ones,
  mark the old ones deprecated in the OpenAPI spec, and remove them only through the policy's MAJOR-version
  exception process. The Go accessor rename carries no external compatibility risk.
- **Estimated PR Size:** Small.
- **Priority:** Low-Medium (admin-only telemetry naming; not a security or correctness issue, but the doc
  gap it's paired with directly affects an operator's ability to diagnose OCSP rejections, which is why it
  isn't Low).

---

## Carried-Over Findings (unchanged except as noted)

All fourteen previously-open finding IDs (thirteen backlog entries, since T-21 and T-32 are tracked as one
paired item) remain open, unchanged, and re-confirmed against the current tree:
T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33, T-34,
T-39 (evidence base for T-39 grew slightly this pass — see above; its finding, name, and priority are
unchanged). Full descriptions and the priority-ordered refactoring plan are unchanged from
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` and are not restated here to avoid drift between two
descriptions of the same open items — see that report (or its predecessors, cited therein) for the
canonical text of each. **T-54 (above) is new this pass and is now also carried into the backlog**,
bringing the open count to fifteen IDs (fourteen backlog entries).

The "Content & Scanning" vs. "Content Security" soft finding (design-document reconciliation between two
deliberate naming decisions, not a mechanical rename) also remains unresolved and is not queued to the
numbered backlog, per 2026-09-09's reasoning.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 2026-09-09/09-11 for the carried-over rows — no existing item moved this pass. One row
added for the new finding:

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
| Low-Medium | **T-54 (new)** | Add OCSP admin JSON fields `malformedTotal` and `staleTotal` alongside `malformedResponseTotal` / `staleResponseTotal` and deprecate the old names (removal only via the API-versioning MAJOR exception — a plain rename is breaking); rename Go accessor `UnknownTotal`→`UnknownStatusTotal`; regenerate the OpenAPI bundle; update the two GUI references; move `responder_blocked` out of the `response_rejected` family into its own series with a compatibility window (a HELP-text change alone does not fix it), and carry that split through the GUI aggregate and the operator runbook's table; follow `API-DEPRECATION-POLICY.md` in full and bump the MINOR contract version. (Missing doc-table rows already resolved on `main`; the runbook update for the `responder_blocked` split is part of this item.) | Medium (stable API field — additive only) | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

Also flagged (design-document reconciliation, not a numbered backlog item): "Content & Scanning" vs.
"Content Security" — see the 2026-09-09 report's soft finding.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass found one genuinely new, small, well-evidenced backlog
item (T-54: the OCSP discarded-response reason vocabulary disagrees across Go/`/metrics`/admin-JSON for
three identifiers, two of six reasons were missing from the operator doc's own reference table, and one
reason — `responder_blocked` — is charged under a metric family whose own business-concept framing does
not fit it, since it fires before any response is ever received). Its missing-doc-table-rows half was resolved
independently on `main` before this report merged; the code/API half (a Go accessor rename plus an additive, deprecating JSON/OpenAPI change, plus a
naming decision for the metric-family scope correction) is queued to the backlog rather than rushed into
this documentation PR, consistent with how this program has always treated renames that touch a shipped,
documented API surface (see T-29/T-30/T-12). The 9-merge window's dominant new feature — MCP-First
Controlled Canary (ADR-0035) — was checked in depth across code, API, and all four new/changed docs
(including `CANARY-READINESS-MATRIX.md`'s new row 4a, which reinforces rather than contradicts the
conclusion) and found internally consistent throughout: the Canary/First-Canary/Review trio, the
Tool-Trust/Tool-Approval/Reviewed-Operation trio, and the Live-Gate/Live-Execution/Read-First trio are each
genuinely distinct concepts used consistently, not drift. The five other new/changed surfaces in the
window (`loginOversizeRejected`, expanded `trust_forwarded_headers` documentation, `CHANGELOG.md`'s
rate-limit-exemption entry, `docker-compose.yml`'s YARA-directory fix, and `CHANGELOG.md`'s CHAOS-65 OCSP
entries) were all checked directly and are clean — the YARA one is a genuine, already-fixed, now
test-pinned pre-existing defect, not new drift, and the OCSP entries carry one pre-existing GUI-label
observation recorded in Part 2 item 5.
The carry-over backlog grew from thirteen to fourteen entries (T-54 added, now covering three identifiers
plus the metric-family correction); T-39's evidence was refreshed without changing its finding or
priority. No cosmetic or preference-driven renames are proposed. **Process note, recorded rather than
smoothed over, across all four correction rounds:** this report's own first draft initially missed the
`loginOversizeRejected`/`trust_forwarded_headers` surfaces and mischaracterized the OCSP naming as
casing-only; the immediate fix then still missed `staleResponseTotal`'s identical mismatch; the fix after
that still missed the `responder_blocked` metric-family scope issue and the `CHANGELOG.md`/
`docker-compose.yml` coverage gaps; and the fourth round found the unaudited OCSP changelog entries, a
breaking-rename recommendation, a mis-described binary field, a self-credited fix that `main` had made, and
an audit miscount. All four rounds were caught and corrected by automated review
(`chatgpt-codex-connector`) on this report's own PR before it merged, not by a parallel run — a concrete
instance of the scheduled-review-can-be-incomplete risk DEBT-014 already tracks, and evidence that this
routine's own single-pass audits should not be trusted as complete without adversarial review, independent
of how thorough any one pass feels while writing it. This report was written, and then corrected in four
review rounds, only after a fresh sync against `origin/main` immediately before opening (and before addressing
each round of review comments on) its PR.
