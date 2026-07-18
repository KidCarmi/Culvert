# PAC Exception Intelligence — behavioral-test backlog

This file collects **real bugs / gaps found while writing behavioral tests** that
prove the feature does what it is intended to do. When a test asserting the
*intended* behavior fails for a legitimate reason, the assertion is captured here
(and the test is marked `t.Skip("BACKLOG PEI-###: …")` so the intent stays
recorded in code without breaking the suite), and testing continues to the next
case.

Format: `PEI-###  <severity>  <area>  — <one-line description>` followed by the
concrete failing case (config + input → expected vs actual) and the test that
records it.

## Open

_(none in the PEI feature itself — the behavioral suite passes; the feature does
what it is intended to do.)_

## Review gaps — CLOSED

The self-review identified five coverage gaps; four were code and are now closed
(the fifth, "not enforced until merged", is a PR-open action):

- **G1 finite matrix → seeded generator.** `inventory_generated_test.go` fuzzes
  600 reproducibly-seeded random profiles through the evaluator and asserts the
  no-under-report invariant on all of them.
- **G2 uncovered error branches.** `atoiPrefix` 72.7%→100% (direct branch test);
  `pacExceptionDelete` 80%→100% and `pacExceptionPut`→95.8% via a persist-failure
  handler test (unwritable backing dir → 500). The only remaining sub-100 lines
  are an unreachable `json.MarshalIndent` error (a `map[string]struct` always
  marshals) and the `os.ReadFile` read-error arm of `Load` (needs an injected FS
  fault) — documented, not forced.
- **G3 UI untested here.** `pac_exceptions_uicontract_test.go` pins the
  governance panel/modal identifiers, CSP-safe dispatch cases, endpoint calls,
  and the admin-gate (string-scan, matching the auth-policy UI test pattern).
  Full interaction stays on the Playwright e2e lane.
- **G4 no full backup→restore cycle.** `pac_exceptions_infra_test.go` seeds a
  governance file into a real-CA backup, `runBackup`, `runRestoreCommit`
  (ModeFull) into a distinct `/data`, then reloads the restored file and asserts
  the record + status survived.

## Found & reconciled (not PEI-specific)

- **PEI-BL-001  medium  route-metadata walls  — main's route-count locks were
  stale (parallel-merge drift).** While running the new PEI behavioral suite,
  the full root `go test` surfaced that clean `origin/main` (e9b53105) fails
  `TestC1_RouteMetadata_Locked141` and `TestD0_RouteInventory_Locked141`:
  `uiRoutes` has **178** entries but the lock was **177**. Two routes landed in
  parallel — `/api/diagnose/support` (#834) and `/api/decryption/redaction`
  (ADR-0011 §4) — each bumping the count, but one const bump was overwritten by
  the other's merge, so actual (178) outran the lock (177). Forward/reverse C1
  parity is green (both routes carry metadata), so this is purely a stale count
  lock, i.e. the required Fast PR Gate on `main` is currently red on it.
  Reconciled here by bumping both `const want` to 178 (the standard drift fix,
  matching the repo's own count-history precedent at 166). Not a PEI bug; noted
  because it was found by this work and it blocked a green suite.

## Closed

_(resolved backlog items move here with the fixing commit.)_
