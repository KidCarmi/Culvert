# Culvert Language & Terminology Governance Review — 2026-11-13

> **Status:** Point-in-time review. **Window:** `b21e430..feb11e8` (CHAOS-117 dropped-record re-enrollment evidence,
> CHAOS-118 background rounds, parent-proxy diagnostics row, SSRF DNS verdict cache bound, bare-IP auth-subject fix).

## Executive Summary

One production-worthy improvement was identified and applied: the "enrollment" spelling decision recorded in the
2026-11-12 review (T-1) regressed in the next window. Newly added code reintroduced "enrolment" in an operator-visible
alert detail, and two older operator-visible strings were still using the verb "enrol".

Terminology Health Score: 93/100 (unchanged).

## Finding T-2 (Low): "enrolment" / "enrol" reintroduced after T-1

- **Business concept:** admitting a node, CDR instance or authenticator into trust.
- **Current names:** "enrolment", "re-enrolment", "enrol" (controlplane_server.go alert detail and comments, CDR
  diagnostics `OperatorAction`, `docs/OPERATIONS.md` CDR runbook line, test names/messages) vs the canonical
  **Enrollment / enroll / re-enroll** used by identifiers, GUI, API, alerts and `PRODUCT-TERMINOLOGY.md`.
- **Recommended canonical name:** Enrollment (already in the glossary; no change to the glossary needed).
- **Why it is a problem:** the CHAOS-117 alert text ("confirm this enrollment was expected") sits next to the alert event
  `cluster_node_reenrolled` and function `recordDroppedNodeReenrollment`; a grep for "enroll" missed the operator text.
  The CDR diagnostics action said "Enrol at least one Sluice instance" while the GUI says "Enrolling".
- **Affected code:** `controlplane_server.go`, `diagnostics.go`, `enroll_dropped_record_reenroll_test.go`,
  `auth_totp_preservation_test.go`, `ui_basic_auth_test.go` (two test function names and comments).
- **Affected API / GUI / configuration:** none (free text only; no wire value, metric, config key or label changes).
- **Affected documentation:** `docs/OPERATIONS.md` (one line). Point-in-time reviews, CHANGELOG and history files are
  left as written.
- **Migration complexity / compatibility risk:** none; no test matched these strings by value.
- **Estimated PR size:** S.

## Candidates considered and rejected

- **behavior / behaviour** (≈445 vs ≈400 in Go comments): comment prose only, no operator-visible or wire effect; a
  mass rename would be cosmetic churn. Not recommended.
- **"parent proxy" (diagnostics) vs "Upstream Proxies" (GUI):** the new row says "parent-proxy chain / parent proxy" and
  the established pool code and glossary use both; the row text names the same concept the GUI panel configures.
  Pre-existing recorded split, not widened here.
- **DNS verdict cache (SSRF)**, "re-enrollment evidence", "bare-IP auth subject": single established names, no competitor.

## Priority

Critical none · High none · Medium none · **Low 1 (T-2, fixed)**.

Checks: `gofmt` clean; `go vet .`; focused tests (`Enroll|TOTP|Diagnostics|SECBASIC|CDR`) pass.
