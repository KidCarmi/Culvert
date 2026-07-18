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
