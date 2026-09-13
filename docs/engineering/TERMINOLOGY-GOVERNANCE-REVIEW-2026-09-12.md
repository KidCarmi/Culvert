# Culvert Language & Terminology Governance Review — 2026-09-12

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `d378dff..2833db3` — the window since the 2026-09-11 report's merge point,
> confirmed as the current `origin/main` HEAD by a fetch immediately before this report was written (per
> the DEBT-014 lesson recorded in the 2026-09-09 report: sync against `main` right before opening a PR,
> not only at review-start). The window covers 9 first-parent merges / 95 files / ~12,100 insertions,
> dominated by the new MCP-First Controlled Canary feature (ADR-0035: `internal/mcp/canary`,
> `internal/mcp/execution`, `internal/mcp/runtime`, `internal/mcp/tooltrust`,
> `internal/mcp/upstreamclient`, the root `mcp_canary_*.go`/`mcp_live_*.go`/`mcp_tooltrust.go` wiring,
> `ui_mcp_tooltrust.go`, and three new docs), the CHAOS-65 OCSP revocation-checking hardening's new admin
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

---

## Executive Summary

**One new finding (T-54, queued to the backlog) and one small doc-only fix made this pass; the large new
MCP Canary surface introduced no drift.**

Three bounded audits were run against the diff since the last review:

1. **Full naming audit of the new MCP-First Controlled Canary surface**, the largest new user/operator-
   facing vocabulary introduced since the last review. Three concept groups that could plausibly have
   collapsed into loose synonyms were checked end-to-end across Go internals, root wiring, the admin API
   (`ui_mcp_tooltrust.go`), and all three new docs (`docs/adr/0035-mcp-canary-execution-architecture.md`,
   `docs/design/mcp/CANARY-FIRST-RUNBOOK.md`, `docs/operator/mcp-first-controlled-canary-review.md`), and
   each turned out to be genuinely distinct, consistently-applied concepts rather than drift:
   - **"Canary"** (the overall architecture/phase) vs. **"First Canary"** (the deliberately narrower,
     exact-scope gate for the one initial experiment — explicitly called out in the ADR itself as "a
     SEPARATE predicate on purpose," `docs/adr/0035-mcp-canary-execution-architecture.md:96-106`) vs. the
     **"MCP First Controlled Canary Review"** document (the authorization gate for that same First-Canary
     experiment). All three are used consistently for their own, distinct referents everywhere checked.
   - **"Tool Trust"** (the subsystem, `internal/mcp/tooltrust`) vs. **"Tool Approval"** (the reviewed grant
     record, `tooltrust.ToolApproval`, exposed at `/api/mcp/tool-approvals`) vs. **"Reviewed Operation
     Class"** (a narrower field *on* a Tool Approval — the read/write/control classification stated at
     review time, `ToolApproval.ReviewedOperationClass`) — three altitudes of one coherent hierarchy, not
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
   not mere casing.** See **T-54** below. The rate-limit exempt-view change (`security.go`'s
   `rlExemptView`/`loadExemptView`) and the SOCKS5 log-injection fix are both internal-only with no new
   GUI/API/doc/metric surface, so — per the 2026-09-11 report's rule that internal reliability engines
   with no independent admin surface are not findings — neither is in scope.
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

### T-54 — OCSP "discarded response" reason vocabulary disagrees across Go accessors, `/metrics` labels, and the new admin/OpenAPI JSON fields (new — queued, not fixed this pass; one sub-part fixed)

- **Business concept:** the reason a fetched OCSP response was discarded rather than treated as an
  affirmative revocation verdict (`internal/ocsp/ocsp.go`, CHAOS-65).
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
  and need no Go change); `ui_security.go` (rename JSON fields `malformedResponseTotal`→`malformedTotal`
  and `staleResponseTotal`→`staleTotal`).
- **Affected API:** `api/openapi/openapi.yaml`/`openapi.json` (regenerate via `make api-bundle` after the
  JSON field renames — this is a documented, already-shipped API surface, not a same-PR drive-by rename).
- **Affected GUI:** `static/index.html:17515` (update the two field references to match the renamed JSON
  keys).
- **Affected Documentation:** `docs/operator/ocsp-revocation-checking.md` §2 — **fixed in this pass** (two
  rows added to the rejection-reasons table for `malformed` and `unauthorized_responder`; zero code/API
  risk, so unlike the Go/JSON rename this needed no coordinated PR and was applied immediately, consistent
  with this program's practice of fixing trivial, zero-compat-risk gaps on sight — see e.g. T-53 and the
  panel-title fix in the 2026-09-09 report).
- **Affected Configuration:** none.
- **Migration Complexity:** Small (three identifier renames — `UnknownTotal`, `malformedResponseTotal`,
  `staleResponseTotal` — plus one generated-spec regen; the JSON fields are new this same window and have
  exactly one known consumer, `static/index.html`, updated in the same change).
- **Compatibility Risk:** Low — the field is documented in the OpenAPI spec but shipped only in this same
  merge window, so no external consumer has had time to depend on the specific spelling being changed.
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
| Low-Medium | **T-54 (new)** | Rename OCSP admin JSON fields `malformedResponseTotal`→`malformedTotal` and `staleResponseTotal`→`staleTotal`, and Go accessor `UnknownTotal`→`UnknownStatusTotal`; regenerate the OpenAPI bundle; update the two GUI references. (Doc-table gap already fixed this pass.) | Low | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

Also flagged (design-document reconciliation, not a numbered backlog item): "Content & Scanning" vs.
"Content Security" — see the 2026-09-09 report's soft finding.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass found one genuinely new, small, well-evidenced backlog
item (T-54: the OCSP discarded-response reason vocabulary disagrees across Go/`/metrics`/admin-JSON, and
two of its six reasons were missing from the operator doc's own reference table) and fixed the doc-table
half of it on the spot, at zero code/compat risk; the code/API half (a small, coordinated Go+JSON+OpenAPI
rename) is queued to the backlog rather than rushed into this documentation PR, consistent with how this
program has always treated renames that touch a shipped, documented API surface (see T-29/T-30/T-12). The
9-merge window's dominant new feature — MCP-First Controlled Canary (ADR-0035) — was checked in depth
across code, API, and three new docs and found internally consistent throughout: the Canary/First-Canary/
Review trio, the Tool-Trust/Tool-Approval/Reviewed-Operation trio, and the Live-Gate/Live-Execution/
Read-First trio are each genuinely distinct concepts used consistently, not drift. The two other new
surfaces in the window (`loginOversizeRejected`, and expanded `trust_forwarded_headers` documentation)
were also checked and are clean. The carry-over backlog grew from thirteen to fourteen entries (T-54
added); T-39's evidence was refreshed without changing its finding or priority. No cosmetic or
preference-driven renames are proposed. **Process note, recorded rather than smoothed over:** this
report's own first draft initially missed the `loginOversizeRejected`/`trust_forwarded_headers` surfaces
and mischaracterized the OCSP naming as casing-only; both were caught and corrected by automated review
(`chatgpt-codex-connector`) on this report's own PR before it merged — a concrete instance of the
scheduled-review-can-be-incomplete risk DEBT-014 already tracks, this time caught by review rather than by
a parallel run. This report was written, and then corrected, only after a fresh sync against `origin/main`
immediately before opening (and before addressing review comments on) its PR.
