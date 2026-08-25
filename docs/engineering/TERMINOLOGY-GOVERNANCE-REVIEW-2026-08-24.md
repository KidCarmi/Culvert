# Culvert Language & Terminology Governance Review — 2026-08-24

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `9b1ba86`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-22.md` (baseline `fdad525`). The full range separating the
> two reviews is `fdad525..9b1ba86` — 52 commits total (34 excluding merges, 18 on the first-parent
> path). An earlier draft of this report scoped its audit to only the last 30 of those (from
> `a12cc1c` onward) and mischaracterized `fdad525` as already-fully-audited; a review comment on this
> PR caught the gap (chatgpt-codex-connector), and the omitted 22-commit span (`fdad525..a12cc1c`)
> was audited before this report was finalized. That span breaks down as: four commits that are
> themselves the 08-22 review's own tail (`72fc168`/`e17f0cc`/`1e9e4d1`/`f41d37e` — the Dashboard-label
> fix and two follow-up corrections already described in that report, not new material); CHAOS-53
> (`3371778`/`f8e26d1`/`79ede6f`/`9f49411` — the remote scan-sidecar failure/slowness/saturation
> hardening, incl. three additive `SecurityScanStatus` fields regenerated into the frontend types);
> the request-latency histogram sharding rewrite (`8034ec8`/`7d89571`/`94ef9c7` — internal-only,
> `metrics.go`, no API/GUI-facing name); an OIDC JWKS stale-trust-ceiling diagnostics addition
> (`8bfec93` — new `oidc_jwks_trust` operator-contract row) plus its own follow-up race fix
> (`2257c0b`); and a cloud-metadata/public-IP probe concurrency fix (`6fa90fe`/`598badd`,
> `internal/uitls` — internal-only, no naming surface). None of these introduced terminology drift:
> CHAOS-53's new fields (`stat_remote_scan_fail`, `stat_remote_scan_saturated`, `remote_scan_inflight`)
> match the `culvert_remote_scan_*` vocabulary CLAUDE.md already documents for that subsystem, and
> `oidc_jwks_trust` is a new, distinctly-scoped operator-contract code (signing-key trust ceiling, not
> reachability) that does not collide with the existing `identity_backend` row. The remaining 30
> commits from `a12cc1c` onward are as this report originally described: two are this program's own
> prior work landing late (`a12cc1c`/`aec9dff`, PR #1203 — the T-16 ADR-renumbering fix queued since
> 08-21; `9ec8eb0` — the PAC-exclusions GUI-label fix folded into this review's record below); 27 are
> dependency bumps (no terminology surface), the CHAOS-54 SOCKS5 accept-loop slice, the lock-free
> IP-filter slice, a pre-auth TLS-fallback-reason redaction fix, a D1.5 backup-surface completeness
> fix, and an `/api/diagnostics` addition for interactive-login callback-state evictions — all
> checked and found consistent with CLAUDE.md's already-pinned vocabulary for each subsystem, per the
> original method below. Method: (1) diffed every file touched across the full `fdad525..9b1ba86`
> range against the naming this program has already pinned for its subsystem; (2) traced the residual
> ADR-0018 collision that both the 07-19 and 08-23 reviews flagged and explicitly deferred, to close
> it this pass; (3) re-confirmed the previously-open carry-over findings (T-9 through T-39, all still
> open per 08-22) against the full window's diff — none of their dependent files were touched in a way
> bearing on their naming (`configversion.go`/`connlimit_startup.go` were touched, but only for the
> IP-filter bulk-load call sites, not the T-29/T-30/T-36 territory those files also carry); (4) a
> targeted check of every new/changed user-facing surface in the window (SOCKS5 health GUI checkbox +
> metrics + alert name, TLS-fallback-reason JSON field vs. frontend camelCase binding, backup
> filenames vs. their owning subsystem's established name, diagnostics eviction wording, the new
> `oidc_jwks_trust` contract row, CHAOS-53's new `SecurityScanStatus` fields) for internal
> consistency — none introduced drift.
> **Companion change:** one fix ships with this review — the ADR-0018 double-claim both the 07-19
> and 08-23 reviews flagged as a known, deferred defect is now resolved.

---

## Executive Summary

**One finding, fully fixed: the residual ADR-0018 collision, flagged and explicitly deferred twice
before (07-19, 08-23), is now resolved.** `docs/adr/0018-openapi-contract.md` (the durable,
CI-enforced OpenAPI contract ADR — 30+ call sites across `docs/api/`, `docs/adr/ADR-FE-001-*`,
`docs/design/mcp/*`, `api/README.md`) and `docs/support/rfc/0018-ai-receives-normalized-evidence.md`
(an exploratory, NOT-ADOPTED infra-ops RFC that self-titled its header `# ADR-0018` despite living
outside `docs/adr/`) both claimed the same decision-record number. This is the identical defect class
the T-16 fix (08-23) closed for the `0008`–`0011` block — a reader or an AI agent citing "ADR-0018"
in `docs/support/TAC-CLOUD-ARCHITECTURE.md` or `SUPPORTABILITY-THREAT-MODEL.md` (both of which cite
it for the *AI input* decision) could not tell, from the number alone, that it did not mean the
OpenAPI contract decision — the exact cross-surface correlation failure this program exists to catch.
The T-16 fix's own commit message flagged this residual case and recommended it "should get its own
T-16-style entry"; it sat open through the 08-22 review's carry-over sweep because that review's
window predated the flag (the flag landed the next day, 08-23, alongside the T-16 fix itself).

**Fix, mirroring the T-16 precedent exactly:** the established, heavily-cited ADR
(`docs/adr/0018-openapi-contract.md`, unchanged) keeps its number; the lower-blast-radius document
was renumbered instead. `docs/support/rfc/0018-ai-receives-normalized-evidence.md` →
`docs/support/rfc/0032-ai-receives-normalized-evidence.md` (the next number confirmed clean against
every `# ADR-NNNN` header in the repo, continuing directly after the `0028`–`0031` block the T-16 fix
just claimed). Its own self-titled header was updated (`# ADR-0018:` → `# ADR-0032:`), and the three
downstream citations that genuinely meant the RFC's topic (AI receives normalized findings, not raw
bundles) were updated to match: `docs/support/TAC-CLOUD-ARCHITECTURE.md` (§3 prose, the §8 pipeline
step, and the §6 section heading — three call sites), `docs/support/SUPPORTABILITY-THREAT-MODEL.md`
(the `T-PROMPT` threat-mitigation row), and `docs/adr/0016-raw-evidence-vs-normalized-findings.md`'s
own "Relates to" cross-reference line. Verified by full-repo grep that every remaining `ADR-0018`
citation (`docs/api/*`, `docs/design/mcp/*`, `docs/design/FRONTEND-CURRENT-STATE.md`,
`docs/adr/ADR-FE-001-frontend-platform.md`, `api/README.md`) is genuinely about the OpenAPI contract
and was left untouched, and that no other RFC-series file (`0012`, `0019`–`0022`) cross-references
`0018` internally. `docs/engineering/TERMINOLOGY-GOVERNANCE-REVIEW-2026-07-19.md` (the historical
record that first flagged this) is left as-is — it is a point-in-time record of what was true on
07-19 and is not retroactively edited by later reviews, matching this program's existing practice for
every other historical report. Docs-only change; no code, API, or GUI surface touched; zero migration
risk.

**Also folded into this review's record (already landed, no separate report existed):** `9ec8eb0`
("Qualify PAC exclusions GUI label per frozen bypass-naming rule", 2026-08-23) relabeled the legacy
admin GUI's PAC DIRECT-bypass exclusion list from the bare, unqualified "Bypass Exclusions" to "PAC
Exclusions (DIRECT Bypass)" — closing a violation of the project's own frozen naming rule in
`roadmap/PAC-EXCEPTION-INTELLIGENCE.md` (DIRECT bypass skips the entire security stack and must
always be qualified, unlike the narrower SSL-only/DPI-only bypasses) and aligning the GUI label with
the canonical field name already used everywhere else for this exact config (`pac_exclusions` API
JSON tag, `pac_exclusions` diff/audit key, `PACExclusions` struct field — confirmed unchanged and
still consistent in this pass). This landed correctly and needed no further action; it is recorded
here so the fix has a governance-visible paper trail.

**All 18 previously carried-over finding IDs (T-9, T-11, T-12, T-13 residual, T-17, T-18, T-21, T-25
residual, T-29, T-30, T-31, T-32, T-33, T-34, T-36, T-37, T-38, T-39 — 17 backlog rows, since T-21
and T-32 share one paired row) were re-checked against the full `fdad525..9b1ba86` window's diff and
remain open, unchanged** — none of their dependent files were touched in a way that bears on their
naming (the two files this window's diff shares with that backlog, `configversion.go` and
`connlimit_startup.go`, were touched only for an unrelated IP-filter bulk-load performance change, not
the T-29/T-30/T-36 config-key/rollback-action territory those same files also carry).

**Terminology Health Score: 8.5 / 10** (up 0.1 from 08-22's 8.4 — the ADR-numbering
collision-prevention gap is now fully closed for the second and, per this pass's full-repo grep, last
known instance; the score does not move further because the 18-item carry-over backlog is
unchanged and is what continues to cap it).

---

## Findings

### T-46 — Second ADR-0018 collision (RFC-track document self-titling the same number as the established OpenAPI ADR) — FIXED

- **Business concept:** the unique identifier for one architecture decision record.
- **Current names before this fix:** `# ADR-0018` claimed simultaneously by
  `docs/adr/0018-openapi-contract.md` (adopted, CI-enforced, 30+ citations) and
  `docs/support/rfc/0018-ai-receives-normalized-evidence.md` (proposed, not adopted, exploratory
  infra-ops RFC series, 4 citations).
- **Recommended canonical name:** `docs/adr/0018-openapi-contract.md` keeps ADR-0018 (established,
  expensive to move); the RFC becomes ADR-0032.
- **Why the current naming was problematic:** a bare "ADR-0018" citation in
  `TAC-CLOUD-ARCHITECTURE.md` or `SUPPORTABILITY-THREAT-MODEL.md` was ambiguous between two
  unrelated decisions (the OpenAPI contract vs. the AI-input-normalization boundary) with no way to
  disambiguate from the number alone — exactly the class of defect the T-16 fix closed for the
  `0008`–`0011` block the day before, and explicitly flagged by that same fix's commit message as a
  known residual case needing its own entry.
- **Why the new name is better:** restores a 1:1 mapping between decision-record number and decision;
  `0032` is confirmed clean against every `# ADR-NNNN` header in the repository (`docs/adr/`,
  `docs/support/rfc/`, and the `ADR-PROPOSAL-*`/`ADR-FE-*` letter-prefixed series checked too).
- **Affected code:** none.
- **Affected API:** none.
- **Affected GUI:** none.
- **Affected Documentation:** `docs/support/rfc/0018-ai-receives-normalized-evidence.md` (renamed to
  `0032-ai-receives-normalized-evidence.md`, header updated), `docs/support/TAC-CLOUD-ARCHITECTURE.md`
  (3 citations), `docs/support/SUPPORTABILITY-THREAT-MODEL.md` (1 citation),
  `docs/adr/0016-raw-evidence-vs-normalized-findings.md` (1 "Relates to" citation).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (docs-only, 5 files, no code/API/GUI/config surface).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Medium (matches T-16's own priority — a documentation-identifier collision with no
  runtime/functional impact, but a real risk of a reader or an AI agent citing or acting on the wrong
  decision record).

---

## Carried-Over Findings (unchanged, re-confirmed against this window's diff)

Unchanged from 08-22. Re-confirmed open; none of their dependent files were touched by this window's
52-commit diff in a way that bears on their naming. Full descriptions remain in the 08-22 report (and,
for the older items, the reports where they were first raised) to avoid duplicating unchanged text.
18 finding IDs, 17 backlog rows (T-21 and T-32 share one paired row):
T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21 + T-32 (pairing), T-25 (residual), T-29, T-30, T-31,
T-33, T-34, T-36, T-37, T-38, T-39.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-22 for the still-open carry-over items; T-46 is resolved in this pass and does not
appear on the plan.

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium-High | T-39 (carried over) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename `qualification_inventory_file`/`qualification_telemetry`/`qualification_policy_file` and their operator-doc titles/GUI strings away from bare "qualification"; reserve that word for the Production receipt gate | Medium | Small-Medium (needs a naming decision first) |
| High | T-38 (carried over) | Dual-emit `CapabilityHealth.ReviewRequiredTools`/`review_required_tools` alongside the existing `DriftedTools`/`drifted_tools`; update the GUI label; add both fields to the OpenAPI spec | Low (additive) | Small |
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-21 + T-32 (carried pairing) | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 (carried over) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 (carried over) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-36 (carried over) | Give `saveConfigVersion`'s rollback call a `config.rollback`-prefixed action string alongside the version number | Low | Small |
| Medium | T-37 (carried over) | Rename `security.feeds_sync` → `threatfeed.sync`; update `security_feedsync_audit_test.go`'s three literal assertions | Low | Small |
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

Terminology is **not** fully consistent, but this was a productive pass: one genuinely tracked
finding — flagged and deferred twice before, across two separate prior reviews — was fully closed at
zero migration risk, a small already-landed fix was folded into the governance record, and all 18
still-open carry-over finding IDs (17 backlog rows) were re-confirmed unchanged against the full
`fdad525..9b1ba86` window's diff. No
cosmetic or preference-driven renames were proposed. The large SOCKS5 chaos-engineering and IP-filter
performance slices in this window were audited specifically for new terminology surface (metrics
names, alert names, GUI strings, doc vocabulary) and found to introduce none — both were built
directly against vocabulary this program had already reviewed and CLAUDE.md already documents.
