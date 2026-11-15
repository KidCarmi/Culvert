# Culvert Language & Terminology Governance Review — 2026-11-12

> **Status:** Point-in-time review. **Window:** `6623fe5..3b09cff` (identity-cache eviction, upstream-pool degraded
> diagnostic, null-record cluster-state repair, `state_file_corrupt` partial-load alert, policy `sourceIP` validation,
> OIDC userinfo `sub` check).

## Executive Summary

One production-worthy improvement was identified and applied. The new null-record repair text told the operator to
"re-enrol the affected nodes and re-issue any pending enrollment tokens" in a single sentence. That mixes two spellings
of one concept. The repository spells it **enroll / re-enroll / enrollment** (≈90 uses: `enrollment.go`,
`--accept-dp-reenrollment`, alert `cluster_node_reenrolled`, GUI, runbooks) and "enrol / enrolment" in about 40 places.
Those include operator-visible text: the `state_file_corrupt` `OperatorAction`, the HA-replicated cluster-state alert
detail, and the break-glass TOTP reset message printed by the CLI. No wire value, metric, config key or GUI label
changes. Operators searching alerts, logs or runbooks for "enroll" no longer miss these lines.

Terminology Health Score: 93/100 (unchanged).

## Finding T-1 (Low): British "enrol/enrolment" mixed with "enroll/enrollment"

- **Business concept:** admitting a node, instance or authenticator into trust, and repeating that after loss.
- **Current names:** `re-enrol`, `de-enrolment`, `re-enrolment` (text and comments) vs `re-enroll`, `enrollment`
  (identifiers, GUI, API, alerts, metrics).
- **Recommended canonical name:** **Enrollment** (two Ls). Added to `docs/design/PRODUCT-TERMINOLOGY.md`.
- **Why the current naming is a problem:** one sentence in `state_corruption.go` used both spellings. A search for
  "enroll" misses the `enrol` lines, and support cannot grep an alert text back to the runbook.
- **Affected code:** `state_corruption.go`, `enrollment.go` (alert detail and comment), `main.go` (CLI output),
  the admin GUI banner (`static/index.html`), and comments/test messages in `store.go`, `ui_middleware.go` and five test files.
- **Affected API / GUI / configuration:** none. Only free text changes.
- **Affected documentation:** `OPERATIONS-RUNBOOK.md` and `admin-roster-durability.md` (quote the CLI/error text), `PRODUCT-TERMINOLOGY.md` (new row). Earlier review and CHANGELOG entries are
  point-in-time records and are left as written.
- **Migration complexity / compatibility risk:** none. No test or consumer matches these strings by value.
- **Estimated PR size:** S (text-only, many files).

## Candidates considered and rejected

- **"Upstream pool configuration" (alert) vs GUI "Upstream Proxies":** the alert's `OperatorAction` names the GUI
  location; "pool" is the established term for the set in the diagnostics code and the glossary reserves "proxy pool"
  for PAC. Consistent.
- **"unusable record(s)" vs "null record(s)":** the first is the generic partial-load wording (`state_file_corrupt`);
  the second names the specific cause in the cluster-state repair. Different precision, not different concepts.
- **Legacy-term sweep:** no new "unauth mode", "whitelist/blacklist", "hash cache" or "expansion ratio".

## Priority

Critical none · High none · Medium none · **Low 1 (T-1, fixed)**.

Checks: `gofmt` clean; `go vet`; focused tests for state corruption, CHAOS-117, TOTP, Basic auth, roster durability, static index and bootstrap pass. No wire fields, metrics or GUI labels changed.
