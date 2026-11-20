# ADR-0049: The SyncRevocations budget planner is owned by internal/session/revsync

- Status: Proposed for review with the implementation PR (IM-015, 2026-11-20).
- Numbering: ADR-0047 is the highest merged; ADR-0040 is reserved by open
  PR #1526 and ADR-0048 by open PR #1965 (IM-013). No other open PR adds a file
  under `docs/adr/`.
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-015.
  Related: ADR-0002, ADR-0038 (instance-owned state), ADR-0042..0048.

## Context

`revocation_sync_budget.go` (337 lines, package main; AU-50 and AU-71) held
two responsibilities:

1. **An engine.** The planner that decides which session-revocation entries
   ride one `SyncRevocations` message when the full set exceeds a leg's byte
   budget: the three priority classes, the total order (class, latest expiry,
   token), the strict half-budget priority prefix, the rotating window that
   resumes from a key cursor, the exact comma and envelope byte accounting,
   the oversize-entry jam guard, and the DP→CP request envelope. Its rule is
   a security property: a leg that does not fit is deferred, never dropped,
   because removing an entry to make a message fit would un-revoke a session.
   It referenced one root name, `RevocationEntry`, which is already an alias
   of `internal/session.RevocationEntry`.
2. **Composition.** The two byte budgets, derived from the cluster gRPC frame
   limits (`maxClusterInboundMsgSize`, `maxClusterGRPCMsgSize`,
   `haBundleFrameReserve`); the two budget variables a root gate lowers; the
   deferral counters and their `/metrics` series; and the rate-limited,
   sanitized log line.

The planner's state is already instance-owned: a cursor value held by
`DataPlaneClient` (request leg) and one per requesting node in the Control
Plane's `revocationAggregator` (reply leg). No package-level variable takes
part in planning.

ADR-0002 classifies `controlplane.go` as a core hub that stays in main and
records its extraction as rejected. This ADR does not move it, the aggregator,
the RPC handlers or the sync loop. `revocation_sync_budget.go` is not on
ADR-0002's list; the reasons recorded there (large inbound surface, shared
mutable globals) do not hold for the planner, which has two call sites and no
global. So there is no conflict to supersede.

## Decision

Move the engine (1) to `internal/session/revsync` with 4 exported identifiers:
`Cursor` (zero value ready; method `Active`), `Request`, `BuildRequest` and
`BuildResponse`. Keep the composition (2) in main, unchanged.

Main keeps its four names as bindings (`revSyncCursor` and
`revocationSyncRequest` as type aliases, `buildRevocationSyncRequest` and
`buildRevocationSyncResponse` as one-line forwards), so the call sites in
`controlplane_client.go` and `controlplane_server.go` and every root test are
untouched. One production line outside the file changed: the aggregator read
the cursor's unexported `set` field to release an idle per-node cursor
(`controlplane.go`), and now calls `Cursor.Active()`.

The package sits under `internal/session` because the entries it orders are
that package's wire type and the two inputs of the request leg are
`ExportRevocationsByOrigin`'s two results. It is a separate package, not more
of `session`, because `session` owns the revocation lists and their
persistence, while this is the transport-leg policy over an exported copy;
the dependency runs one way (`revsync` → `session`).

Lifecycle, in one sentence: main owns every `Cursor` and passes it with the
budget into each call from the single goroutine (or under the aggregator
mutex's get/set pair) that owns that leg; the package holds no state between
calls, starts no goroutines and does no I/O or logging.

Unchanged: the bytes of both legs (pinned by digests captured from main
`530445b` before the move, over twelve over-budget ticks per leg), the
fitting-list fast path (one marshal, byte-identical, cursor cleared), error
strings, the budgets and their derivation, the deferral counters and metric
text, the log line and its `sanitizeLog`/`%q` handling of the peer-supplied
node id, and the per-node cursor release.

## Tests

Moved with names and assertions unchanged (engine-only):
`TestAU50_PlannerSendsLocalFirstAndRotatesEveryEntry` and
`TestAU50_ControlFittingListIsSentWholeAndUnchanged` (the latter constructs a
cursor from its unexported fields, so it belongs beside the type).

Stay root (they need the application): `TestAU50_RevocationListOverTheRequestCapStillSyncs`
(real gRPC limits over bufconn, the session store, the DP client),
`TestAU71_ReplyOverBudgetRotatesPerNode` (the CP handler and aggregator) and
`TestAU50_ControlFixedPrefixStarvesTheTail` (compares against the HA trim,
`fitRevocationsToBudget`).

New engine tests: the pre-move wire digests with a negative control, the
reply leg's account-first order and full rotation, cursor independence, the
oversize-entry jam guard, and a boundary test (only `internal/session`
imported, no package variable, no `init`, no I/O/logging/sync imports,
exported-surface cap) with negative controls. Mutating the prefix fraction,
the expiry order or the resume comparison fails the digest test.

## Consequences

The deferred-never-dropped planner is testable without compiling the
application, and its only inputs are its arguments. The budgets stay where
the frame limits they derive from live. Main's four binding names can be
removed in a later change by having the two call sites name the package
directly; that touches `controlplane_client.go` and `controlplane_server.go`
and was left out to keep this move free of overlap with open work on those
files.
