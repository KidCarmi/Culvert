# ADR-0057: The MCP live-tier lifecycle state machine is owned by internal/mcp/livetier

- Status: Proposed for review with the implementation PR (IM-025, 2026-11-21).
- Numbering: ADR-0055 is the highest merged. ADR-0056 is reserved by open
  PR #1992 (IM-024) and ADR-0040 by open PR #1526. No other open PR adds a
  numbered file under `docs/adr/` (checked against every open PR on
  2026-11-21).
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-025.
  Related: ADR-0002, ADR-0035 (which defines the lifecycle this package now
  holds), ADR-0038 (instance-owned state), ADR-0046, ADR-0047 and ADR-0055
  (the earlier MCP extractions).

## Context

`mcp_live_tier.go` (424 lines, package main) held the lifecycle ADR-0035
defines for the live-execution tier, `absent → composed → armed → quiescing →
composed`, as one type, `mcpLiveTier`. It was already an instance with its own
mutex and condition variable, built by `newMCPLiveTier`. It decides three
things that matter for safety:

1. whether a live execution may be admitted (`admitExecution`, and its
   read-only form `admissionOpen` used for the final-boundary revalidation);
2. when the readiness bit the rollout commit gate reads is set and cleared;
3. how a quiesce revokes readiness, in what lock order, and how long it may
   wait for in-flight work.

It read three names from other root files:

- `setLiveExecDepsArmed` (`mcp_rollout_execdeps.go`), to mirror the armed bit
  into the registry `modeExecReady` reads;
- `liveExecDepsConfigured`, to report that bit in its status row;
- `getMCPRollout().durableMu`, which `quiesce` takes before its own lock so a
  revocation cannot land between a rollout commit's armed read and its
  install (Codex P1 round 5, PR #1290).

One piece of the engine lived in a second file: `drainWaitFn`
(`mcp_live_arming.go`) locked the tier's mutex, read `inFlight` and waited on
`drainCond` from outside the type.

ADR-0002 keeps MCP composition in main. The lifecycle object is not
composition: it composes no executor, opens no listener and reads no
configuration. ADR-0035 names the file (`mcp_live_tier.go`) when it describes
the lifecycle; the lifecycle it describes is unchanged and the file still
exists as the composition point. So there is no decision to supersede.

## Decision

Move the state machine to `internal/mcp/livetier`. Keep the two process
tiers, their wiring and every caller in main.

Exported surface, 10 package-level identifiers: `State` with `Absent`,
`Composed`, `Armed` and `Quiescing`; `ErrNotComposed` and `ErrNotReady`;
`Tier`, `Options` and `New`. This is above the program's usual cap of 8 and
the boundary test states the number. Five of the ten are one enumeration and
two are the sentinel errors main already compared against; splitting the
package to reach 8 would separate a state type from the machine that owns it.

- **The three root dependencies become `Options`.** `SetArmed func(bool)`,
  `DepsReady func() bool` and `CommitLock func() sync.Locker`. Main binds
  them in `newMCPLiveTier` to `setLiveExecDepsArmed(capb, …)`,
  `liveExecDepsConfigured(…)` and `&getMCPRollout().durableMu`. The tier no
  longer knows which capability it serves; the closures do.
- **The commit lock is resolved on every `Quiesce`.** The old code called
  `getMCPRollout()` inside `quiesce`, and tests replace that owner. Capturing
  the lock at construction would be a behavior change, and a test pins that
  it is not captured.
- **Lock order and coverage are unchanged and now tested in isolation.**
  Commit lock, then tier lock; the armed bit is cleared with both held; the
  commit lock is released before the drain. `UnarmForDemote` and
  `DisarmForRestart` still take only the tier lock, because their caller
  holds the commit lock.
- **`drainWaitFn`'s body moves into the type as `Tier.DrainWait`.** No code
  outside the package touches the tier's mutex, counter or condition variable
  any more. Main keeps `drainWaitFn(lt, deadline)` as a one-line binding so
  `quiesceLiveTier` and the two root tests that call it read as before.
- **The status row stays a `map[string]any` built under the tier lock**, with
  `live_deps_ready` read through `DepsReady` inside that lock as before, so
  the row still reports the state and the bit as of one instant. A typed
  status would be cleaner and would also change every reader; not done here.
- **Nil options are safe and closed.** A tier built with no `SetArmed` can
  change state but writes no readiness bit, so nothing can authorize a live
  mode from it. Main always supplies all three.
- **Methods are exported by renaming.** `composed` → `IsComposed`, `armed` →
  `IsArmed`, and the other eleven by capitalizing. 4 root production files
  (`mcp_live_gate.go`, `mcp_live_production_deps.go`, `mcp_live_startup.go`,
  `mcp_rollout.go`) and 9 root test files change on those call sites only; a
  script checked that reversing the renames reproduces each of the 13 from
  main byte for byte. `mcp_live_arming.go` changes on four call sites and
  loses `drainWaitFn`'s body.
- **Root keeps its names** (`mcpLiveTier`, `liveTierAbsent` … `liveTierQuiescing`,
  `errLiveTierNotComposed`, `errLiveTierNotReady`, `newMCPLiveTier`,
  `mcpLiveTierFor`) as bindings.

Lifecycle, in one sentence: main builds one `Tier` per capability at package
initialization and holds it for the life of the process; the tier starts no
goroutine and owns no context, file or connection, and its only timer is the
one a `DrainWait` arms for its caller's deadline and stops before returning.

### Two source-scanning walls

- `TestExecPosture_ArmingDispatcherCalledOnlyByLifecycle` allows
  `setLiveExecDepsArmed` to be called only from `mcp_live_tier.go`. It is not
  edited and still passes: the one call is now the `SetArmed` binding in that
  file. What it proves has narrowed from "only the lifecycle object calls the
  dispatcher" to "only the lifecycle's wiring can". The other half, that the
  tier invokes the binding from `Arm` and the three revocations and nowhere
  else, is now pinned in the package
  (`TestTier_ArmedBitWrittenOnlyByArmAndTheRevocations`).
- The credential-matrix wall's allowlist quotes the not-ready error text at a
  file path and fails when an entry matches nothing. The text moved, so the
  entry's path changes from `mcp_live_tier.go` to
  `internal/mcp/livetier/tier.go`; its reason is unchanged. This is the one
  edit to an existing wall and needs a reviewer's eye.

Unchanged: every state transition and its guard, both error values and
texts, the compose-reason strings, the status row's keys and values, the
admission rule, the once-only release, the lock order, the timed drain, and
the default (absent, unarmed) posture.

## Tests

Moved with its name and assertions unchanged (it writes the tier's
unexported fields): `TestAdmissionOpen_MatchesAdmitExecution`, from
`mcp_live_gate_auxiliary_test.go`.

Stay root, edited only on the renamed method calls: the tier, arming, gate,
quiesce-rehearsal, production-deps, race and end-to-end tests in nine files.
They need the readiness registry, the rollout owner, the gate or the
executor.

New engine tests: which transitions write the armed bit and with what value;
that every such write happens under the tier lock; commit-lock order,
coverage of the revocation and release before the drain; per-call resolution
of the commit lock; re-entry into quiescing with residual in-flight work; the
four answers of the bounded drain wait; independent instances; the closed
behavior of an unwired tier; the status row for each state; the state names;
and a boundary test (no Culvert import, no I/O, logging or network import, no
`init`, no package variable except an `errors.New` sentinel, exported-surface
cap) with negative controls.

Mutation checks, run against a copy of the package: 13 single-line changes
(no commit lock, commit lock held across the drain, reversed lock order,
residual retry reporting clean, demote leaving the bit set, `AdmissionOpen`
ignoring the closed bit, the bit set before the readiness check, quiesce not
closing admission, quiesce not clearing the bit, no deadline timer, release
not waking the drain, restart disarm leaving an armed state, commit lock
captured at construction). Each one fails at least one new test.

## Consequences

The lifecycle can be tested without compiling the application or resetting
process globals. The tier's mutex, counter and condition variable have one
owner. The two process tiers and the readiness registry remain package
globals in main; that is composition state and is not changed here. The root
bindings can be removed later by naming the package at their uses.
