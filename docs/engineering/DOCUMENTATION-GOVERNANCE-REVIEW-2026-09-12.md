# Culvert Documentation Governance & Knowledge Guardian Review — 2026-09-12

> **Owner:** Documentation Governance routine (new series; distinct from the
> existing `TERMINOLOGY-GOVERNANCE-REVIEW-*` series, which audits naming
> drift only). **Status:** Point-in-time review (repeatable). **Method:**
> full-repository sweep against `origin/main` at `2833db3` (verified live via
> `git ls-remote`, not a stale local ref) — not diff-scoped, since this is the
> first run of this series and no prior baseline exists to diff against.

---

## Executive Summary

This is the first run of a documentation-governance pass distinct from the
existing terminology-drift series. Scope: legacy/removed-feature docs,
missing documentation for shipped features, contradictions between docs and
implementation, missing best-practice/enterprise guides, and structural
issues (broken cross-references). Six checks were run; one CRITICAL/HIGH
finding rose to the fix bar and was corrected this pass, one MEDIUM finding
was verified and recorded but not fixed (numeric-accuracy fix, deferred to
keep this PR single-concern), and four checks came back clean.

**Documentation Health Score: 8.5 / 10.** Very strong for a codebase this
size — 366 pre-existing Markdown files, zero broken relative links, all 61
`docs/`+`roadmap/` paths CLAUDE.md cites resolve, and every peer feature
(LDAP, SAML, PAC, decryption profiles, upstream proxies, HA/lease, every
CHAOS-* reliability subsystem) already has a dedicated `docs/operator/*.md`
runbook. The score is not higher because one comparably-sized, comparably
security-sensitive feature (CDR) had none, and because the MCP subpackage
count in the canonical architecture doc has drifted by 48%.

---

## Findings

### 1. [FIXED] Missing operator documentation — CDR (Content Disarm & Reconstruction)

- **Priority:** High
- **Problem:** CDR (`cdr.go` + 13 sibling root files, ~6,900 lines; a full
  5-tab React feature area) is a substantial, security-critical,
  admin-facing integration with an external "Sluice" gRPC engine —
  mTLS + trust-on-first-use certificate pinning, a 21-route admin API,
  credential enrollment/rotation/revocation, and its own policy-rule
  language. Every other feature of comparable size and security surface
  in this codebase (LDAP identity provider, SAML, PAC steering,
  decryption profiles, upstream proxy pools) has a dedicated
  `docs/operator/*.md` guide. CDR had none.
- **Evidence:** `find docs -iname "*cdr*"` returned zero results before this
  pass. The only existing coverage was `docs/OPERATIONS.md` §6 (a
  ~28-line diagnostics/recovery troubleshooting section, not a
  configuration or security-model guide) and `roadmap/SLUICE-CDR-HANDOFF.md`
  (a pre-implementation design brief, explicitly not current-state
  documentation).
- **Current documentation:** `docs/OPERATIONS.md` §6 only.
- **Implementation evidence:** `cdr.go`, `cdr_ui.go`, `cdrpolicy.go`,
  `cdrstore.go`, `cdr_enroll_receipts.go`, `cdr_health.go`,
  `cdr_breaker.go`, `cdr_pool.go`, `cdr_client_keyatrest.go`,
  `cdr_startup*.go`, `config.go`, `ui_routes_meta.go:748-779`,
  `static/index.html:812-833`, `frontend/src/features/security/CDRPage.tsx`.
  Every non-obvious claim in the new guide (TOFU pinning mechanics,
  fail-open default, revocation's durable-proof requirement, the
  config-rollback exclusion, RBAC, key-at-rest) was independently
  spot-checked against the cited file:line before being written — see the
  "Self review" section below for what was verified and one correction
  made to the first draft (see next bullet).
- **One correction made during review:** the first draft claimed a
  supplied CA bundle provides chain verification alongside the fingerprint
  pin. Reading `buildCDRTLSConfig` (`cdr.go:216-307`) and the two verify
  callbacks (`cdr.go:324-356`) directly showed this is false — when a
  fingerprint is configured, verification is fingerprint-only regardless
  of whether a CA bundle is also present; the CA bundle only matters in
  the separate no-fingerprint fallback mode, which the enrollment flow
  never uses. The published guide states this correctly.
- **Why this matters:** CDR's trust model has sharp edges an operator must
  understand to use it safely — e.g., deleting an enrolled instance does
  *not* revoke it on the Sluice side (trust must be explicitly revoked via
  a *different* pooled instance), and CDR state is deliberately excluded
  from config-version rollback, export/import, and cluster sync (so
  "rolling back" a config version cannot silently un-revoke a compromised
  credential, but also cannot be used to move CDR policy between nodes).
  Neither property is discoverable from the GUI or from `docs/OPERATIONS.md`
  §6 alone.
- **Who is affected:** Any operator enabling CDR for the first time, or
  investigating a stuck/ambiguous enrollment or revocation.
- **Canonical source of truth:** `cdr_ui.go`'s own header doc comment (route
  list) plus the implementation files above; there was no pre-existing
  operator-facing document to reconcile against.
- **Files changed:**
  - Added `docs/operator/cdr-content-disarm-reconstruction.md` (new, 280
    lines) — architecture, enrollment, certificate rotation, revocation,
    policy configuration, fail-open/closed behavior, security
    considerations, admin API reference, GUI, and cross-links.
  - `docs/OPERATIONS.md` (+3 lines) — one cross-reference from §6 to the
    new guide, so the existing recovery section becomes discoverable from
    the new one and vice versa (no content duplicated in either
    direction).
- **Estimated effort:** Done (this pass).
- **Risk:** Low. Purely additive; no existing document's meaning changed.
  The new guide's claims were verified against source, not derived from
  the pre-implementation design brief or inferred from the GUI.

### 2. [RECORDED, NOT FIXED] Stale package count — `internal/mcp` subpackages

- **Priority:** Medium
- **Problem:** CLAUDE.md's Project Structure section and its MCP Agent
  Security Gateway bullet both state `internal/mcp (27 subpackages...)`,
  and `docs/engineering/ENGINEERING-DASHBOARD.md` repeats "27 subpackages"
  in its ADR-0024 governance row. The actual current count is **40**
  subpackages (each with `.go` files) — the figure has drifted 48% since
  it was written, most likely accumulated across the PR-12 distribution
  work and subsequent canary/credential-broker/event-model splits that
  didn't circle back to update this specific count.
- **Evidence:**
  ```
  find internal/mcp -type d | while read d; do ls "$d"/*.go >/dev/null 2>&1 && echo "$d"; done | wc -l
  # => 40
  ```
  (`internal/mcp` itself has zero direct `.go` files — it is a pure
  namespace directory, not a package — so it is correctly excluded from
  both the old and new count.) The top-level `internal/` count CLAUDE.md
  states separately (**68** packages) *is* still accurate: it counts
  `internal/mcp` as a single logical entry (labelled with its own
  subpackage count) rather than expanding its children, and the 67
  actual top-level `internal/*` Go packages plus that one logical `mcp`
  entry sum to exactly 68. The `~47k LOC excluding tests` figure for
  `internal/mcp` is also still accurate (measured 48,665 lines today,
  within the stated approximation). Only the "27 subpackages" figure
  itself is wrong.
- **Current documentation:** `CLAUDE.md` lines 10, 86, 250;
  `docs/engineering/ENGINEERING-DASHBOARD.md` line 83;
  `roadmap/CHAOS-ENGINEERING-REVIEW.md` line 1703 (a fifth instance, in
  prose reasoning about ADR-0024's rollout ladder rather than a structural
  claim).
- **Implementation evidence:** `find internal/mcp -type d` (directory
  enumeration, reproducible by anyone), cross-checked against `go list
  ./internal/mcp/...`-style package boundaries (a directory only counts if
  it has `.go` files, matching how CLAUDE.md counts every other package in
  the same sentence).
- **Why this matters:** This is the canonical, most-referenced project
  instructions file in the repository (checked into the codebase and
  loaded into every session touching this code). A structural fact wrong
  by 48% in the file every contributor and agent treats as ground truth
  is a credibility risk for the surrounding claims in the same paragraph,
  even though (as verified above) the other two numbers in that paragraph
  are still correct.
- **Who is affected:** Any engineer or agent using CLAUDE.md's package
  count to gauge the size/scope of the MCP subsystem before diving in.
- **Canonical source of truth:** `CLAUDE.md`'s Project Structure section
  (line 10) is the primary instance; the ADR-0024 bullet (line 250) and
  `ENGINEERING-DASHBOARD.md` row should mirror it exactly.
- **Files to update:** `CLAUDE.md` (3 occurrences), `ENGINEERING-DASHBOARD.md`
  (1 occurrence); `CHAOS-ENGINEERING-REVIEW.md`'s prose mention is optional
  (it doesn't present the number as a current structural fact).
- **Estimated effort:** Trivial (single-token numeric correction in 4
  places, plus a fresh count captured at fix time since new subpackages
  may land between this report and that fix).
- **Risk:** Very low.
- **Not fixed in this PR:** deliberately deferred rather than bundled into
  the CDR-documentation PR above, per this routine's "one documentation
  concern per PR" discipline. This is a ready-to-apply, fully-verified fix
  for the next pass (or an immediate follow-up, at the maintainer's
  discretion) — re-run the `find` command above at fix time rather than
  reusing "40" blindly, since the subpackage count is a moving target on
  an actively-developed subsystem.

---

## Checks that came back clean (no finding)

1. **Legacy/removed-feature documentation.** Checked the one instance
   CLAUDE.md itself flags as removed (`roadmap/docker-system-update.md`
   describing the Docker updater sidecar, explicitly superseded by the
   maintenance agent) — the file is still present but is a `roadmap/`
   design artifact, not operator-facing documentation, and CLAUDE.md
   already states the supersession inline; no operator-facing doc
   describes the removed sidecar as current. Also checked `docker-
   compose.yml` for a leftover `updater` service definition (none) and
   `CULVERT_PROXY_IMAGE` (CLAUDE.md says this env var "and its env_keep
   are removed") — every remaining reference in `.go`/`.yml` source is a
   negative/historical comment confirming its removal, not a live usage.
   No contradiction found.
2. **Broken cross-references.** Scanned all 442 Markdown files (366
   pre-existing + this pass's additions) for relative links; zero broken
   links found (one regex false-positive in a security-review doc, a
   character class mis-parsed as a link, not an actual link).
3. **Missing/orphaned `docs/`+`roadmap/` files CLAUDE.md cites.** All 61
   `docs/*.md` and `roadmap/*.md` paths referenced by path in CLAUDE.md
   exist on disk.
4. **Undocumented operator-facing environment variables.** Diffed all
   `CULVERT_*` environment variables read by non-test `.go` files against
   CLAUDE.md's "Key Environment Variables" list. All variables not in that
   curated list are either test-harness-only (verified by grep: found only
   in `_test.go` files or CI/e2e generator tooling) or already documented
   in a non-CLAUDE.md canonical location — e.g. `CULVERT_PUBLIC_IP` is
   covered in `docs/enterprise/ENTERPRISE-PREREQUISITES.md` §3 and was
   already correctly triaged as "not drift" by
   `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-12.md` (CLAUDE.md's list is an
   explicitly curated subset of ~8 non-obvious variables out of 100+, not
   an exhaustive index). No new gap found.

---

## Stop-Condition Assessment

One production-worthy documentation improvement was identified and shipped
this pass (CDR operator guide, finding 1) — a genuine, previously-absent
piece of documentation for a shipped, security-sensitive feature, grounded
directly in source and cross-checked against the existing recovery-only
coverage to avoid duplication. A second, smaller, fully-verified fix
(finding 2, the MCP subpackage count) was intentionally left unapplied to
keep this PR single-concern, per this routine's own governance rules; it is
ready for immediate application.

No other change in this repository met the bar for a documentation-
governance PR this pass: the existing `TERMINOLOGY-GOVERNANCE-REVIEW-*`
series already runs frequently and covers naming-drift comprehensively;
zero broken links or dangling references were found across 442 files;
every other major feature already has adequate operator documentation; and
no contradictions between two documents describing the same feature were
found. This report itself, plus the CDR guide and its cross-link, are the
deliverables of this pass.
