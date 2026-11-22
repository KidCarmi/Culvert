# ADR-0056: The node-local qualification archive is owned by internal/mcp/events/qualarchive

- Status: Proposed for review with the implementation PR (IM-024, 2026-11-21).
- Numbering: ADR-0055 is the highest merged. ADR-0040 is reserved by open
  PR #1526. No other open PR adds a numbered file under `docs/adr/` (checked
  against every open PR on 2026-11-21).
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-024.
  Related: ADR-0002, ADR-0046, ADR-0047 and ADR-0055 (the earlier MCP
  extractions).

## Context

`mcp_telemetry.go` (915 lines) held two different things.

The first is composition: the startup configuration check, the KEK provider,
the events manager, the published holder, the flush and export loops with
their panic containment, the shutdown drain, and the rule that a partition's
cursor advances only after the archive accepted the batch.

The second, from line 578 to the end, is a storage engine with two types.
`qualArchiveExporter` writes one file per exported batch under
`<root>/<capability>/<partition>/<batch id>.json`, is idempotent for an
identical batch, rejects a different batch under the same identity, refuses to
pass a byte cap, and keeps counters. `telemetryCursorStore` keeps one
`<partition>.cursor` file per partition and never moves backward. Together
they were about 340 lines. Their only Culvert imports were `internal/fileutil`
and `internal/mcp/events/model`. They read four root names: two permission
constants, the `errTelemetry` phrase builder, and `gatewayPartitions` (the
cursor store's open loop).

This engine decides what MCP qualification evidence is durably on a node and
whether an export step is acknowledged. It was testable only by compiling all
of package main.

ADR-0002 keeps MCP composition in main. That stays true: no loop, holder,
state, configuration rule or shutdown step moves.

## Decision

Create `internal/mcp/events/qualarchive` with 6 exported package-level names:

- `Exporter`, `NewExporter(root string, maxBytes int64) (*Exporter, error)`
- `Stats` (the counter snapshot `Exporter.Stats` returns)
- `CursorStore`, `NewCursorStore(dir string, parts []evmodel.Partition) (*CursorStore, error)`
- `PartitionName(evmodel.Partition) string`

Methods: `Exporter.Export`, `NoteExported`, `NoteFailure`, `Stats`;
`CursorStore.Get`, `Advance`.

Decisions inside that:

- **The code is moved unchanged.** Every body is the root body with names
  substituted. The batch identity and content hash, the JSON field names, the
  directory layout, the 0700/0600 modes, the capacity arithmetic (including
  the discount for a corrupt prior file), the two `#nosec G304` annotations
  and the `#nosec G115` one are what they were.
- **A new package, not `internal/mcp/events/export`.** That package is the
  authorized read and the pump; it imports no filesystem code. Putting a file
  sink there would give every importer of the export contract a dependency on
  `fileutil` and a second responsibility.
- **One package for both types.** The cursor is meaningful only relative to
  the archive (it records what the archive has accepted), both name their
  files with `PartitionName`, and main always opens them together.
- **The partition list is a parameter.** `NewCursorStore` loaded the root
  variable `gatewayPartitions`; it now takes the list. Main passes the same
  variable. Management partitions are still never loaded.
- **Error text stays, including the `mcp telemetry: ` prefix.** Main's
  `errClass` reduces an export error to `conflict` / `saturated` / `canceled`
  / `write_error` by substring, and those classes reach health and metrics.
  Typed errors would be a better contract, but they are a behavior-adjacent
  change and are not made here. The text contract is pinned on both sides
  instead (see Tests).
- **`NoteExported` keeps reading the wall clock.** It did not use the root
  `mcpTelemetryClock` before; that variable is the events manager's clock.
- **No root aliases.** Six call sites in three root files name the package
  directly. `telemFilePerm` had no remaining reader and is removed.

Ownership in one sentence: `qualarchive` owns the bytes under the archive and
cursor directories it is handed and the counters of the instances it returns;
main owns configuration, the events manager, the loops, and when a cursor
advances.

Lifecycle: none. No package-level variable, no `init`, no goroutine, no
logging, no network. An instance holds no file handle between calls, so there
is nothing to close; main's `telemetryRuntime.Close` is unchanged.

Not moved, deliberately:

- `exportStep`, `exportWithRetry`, `drainPartition`, `exportLag`. They read
  the events manager and own the ack ordering. The three chaos registries
  that name `mcp_telemetry.go:flushLoop`, `exportLoop`, `exportWithRetry` and
  `Close` by file are therefore untouched.
- `errClass`. It is main's reduction of an error for its own health output.
- `gatewayPartitions`. Which partitions a Gateway exports is composition.

## Unchanged

Every persisted byte, file name and mode; which batches are accepted; every
error phrase; the counters; `culvert_mcp_export_*` metrics and the telemetry
health document. No wire or configuration format is involved, and no
authorization check is touched. A node restarted across this change finds its
existing batch files and cursors under the same names.

## Tests

Four engine-only tests move with their names and assertions unchanged:
`TestArchiveExporter_AtomicIdempotentConflict`,
`TestArchiveExporter_SaturationNoSilentDrop`,
`TestTelemetryCursor_DurableAndPerPartition` and
`TestValidateBatch_AcceptsV1AndV2RejectsUnknown`. The other root
`TestTelemetry_*` tests stay: they build the real manager, spool and listener.

New in the package:

- An on-disk format pin. Four batches (v1 and v2, both capabilities, an
  out-of-range partition) and three cursor writes produce seven files whose
  names and tree digest were captured by running the same inputs through the
  root functions on main `ef94311` before the move.
- Every fixed error phrase, exactly, and that none carries the archive path.
- Restart capacity accounting; repair of a corrupt prior file at the cap
  (this branch of `Export` had no test before); the uncapped case; counters.
- Cursor open rules: an undecodable file starts at zero, an unlisted
  partition is not loaded, an unusable directory is an error.
- Two exporters and two cursor stores share nothing; a concurrent run of all
  methods under the race detector with exact totals.
- A compile-time assertion that `*Exporter` is an `export.Exporter`.
- A boundary test: Culvert imports limited to `fileutil` and `events/model`;
  no `log`, `log/slog`, `fmt`, `net*` or `sync/atomic` import; no package
  variable; no `init`; no `go` statement; exactly the 6 exported names.
  Fourteen negative controls and one positive control.

New in root: `TestTelemetry_ErrClassReadsArchiveErrors` runs real archive
errors through `errClass`, so rewording a phrase in the package fails a root
test instead of silently reporting `write_error`.

## Consequences

`mcp_telemetry.go` drops from 915 to about 575 lines and holds only
composition. The archive can be tested with
`go test ./internal/mcp/events/qualarchive` in about a second.

Costs: the substring contract between `errClass` and the package's phrases
now crosses a package boundary (pinned as above; typed errors are the
follow-up if the owner wants them). The dated suppression inventory
(`docs/engineering/security-reviews/2026-10-03-inline-suppression-inventory.tsv`)
names three `mcp_telemetry.go` lines that moved; it is a dated audit record
and is left as written.
