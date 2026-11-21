# ADR-0055: The qualification inventory document is owned by internal/mcp/qualinventory

- Status: Proposed for review with the implementation PR (IM-023, 2026-11-21).
- Numbering: ADR-0054 is the highest merged. ADR-0040 is reserved by open
  PR #1526. The two open program PRs (#1989 and #1990, both IM-022) add no
  numbered file under `docs/adr/` (checked against every open PR on
  2026-11-21).
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-023.
  Related: ADR-0002, ADR-0046 and ADR-0047 (the two earlier MCP extractions).

## Context

`mcp_inventory.go` (604 lines) held two different things.

The first is application state and wiring: the `not_configured` / `loaded` /
`invalid` state, the process-wide holder published once at startup, the three
adapters that hand the same registry and catalog to the Admin API, the status
view for the admin overview, and `loadQualificationInventory`, which decides
from the startup configuration whether a file is expected at all.

The second is an input engine for one operator-supplied file: a bounded read
with a traversal check, a strict JSON decode, field validation (opaque
identifier rules, the route-safe server id rule, the capability and
destination-class vocabularies) and the seeding of a fresh registry/catalog
pair through `registry.Register`, `registry.VerifyIdentity` and
`catalog.Ingest`, with bounded error phrases. That is about 350 lines. It
read no root symbol: its only non-stdlib imports were `internal/mcp/catalog`,
`limits`, `protocol` and `registry`. It had no package variable, no clock and
no logging.

The engine is security-relevant input handling. It is what stands between a
hostile or mistyped inventory file and the registry the Gateway pipeline
resolves against, and it fails closed as a whole. It was testable only by
compiling all of package main.

ADR-0002 keeps MCP composition in main ("do not move the entire adapter
layer"). That stays true: no adapter, holder, state or startup decision moves.
This ADR narrows nothing in ADR-0002; the engine was never composition.

## Decision

Create `internal/mcp/qualinventory` with 7 exported package-level names:

- `ReadFile(path string) ([]byte, error)`
- `Decode(raw []byte) (*Doc, error)`
- `Seed(doc *Doc, lim limits.CatalogLimits) (*registry.Registry, *catalog.Catalog, error)`
- `Doc`, `ServerEntry`, `ToolEntry` (the document's three JSON shapes)
- `MaxFileBytes`

Decisions inside that:

- **The code is moved unchanged.** Every function body is the root body with
  the names above substituted. Validation order, error phrases, the sort
  before seeding, the Register → VerifyIdentity → Ingest → optional disable
  order and the `#nosec G304` annotation on the one `os.Open` are what they
  were.
- **Three steps, not one `Load`.** Root tests in ten files build registry and
  catalog fixtures with decode-then-seed from an in-memory document, without
  a file. A single `Load(path)` would force them through the filesystem or
  need a second entrypoint anyway.
- **The limits stay the caller's.** `Seed` takes `limits.CatalogLimits` as
  before; the package picks no default. Main passes
  `limits.DefaultCatalog()`, the same value it uses for the empty pair.
- **The schema version constant is not exported.** Only `Decode` reads it.
- **Root keeps three bindings and one alias** (`readInventoryFile`,
  `decodeInventory`, `seedInventory`, `qualInventoryDoc`).
  `loadQualificationInventory` calls them, so its body is unchanged, and the
  ten root test files that build fixtures through them are not edited.
- **No options, no instance.** There is no state to own: each `Seed` call
  builds and returns its own pair.

Ownership in one sentence: `qualinventory` owns the document's grammar,
validation and seeding and returns a fresh pair to its caller; main owns
whether a file is expected, the pair once returned, its publication and the
fail-closed activation.

Lifecycle: none. No package-level state, no `init`, no goroutine, no logging.
The only I/O is the bounded read of the path the caller passes.

Not moved, deliberately:

- `loadQualificationInventory`. It reads the root startup configuration type
  and returns the root state type; it is the composition decision.
- The holder, `publishMCPInventory`, the Admin API adapters and
  `inventoryStatus`.

## The provenance wall

`TestPeerWall_SeedReachesOnlyTheSeededEntrypoint`
(`mcp_peer_refresh_wall_test.go`) pins the exact set of production functions
that name `catalog.Ingest`, as `file:Func`. Its own failure text says what to
do when the path moves: "move this entry with it". The entry changes from
`mcp_inventory.go:seedTools` to
`internal/mcp/qualinventory/inventory.go:seedTools`; the set is still exactly
one function and it is the same function. The converse check (nothing in the
provisioning path may name `IngestObserved`) now covers both the root file
and the new package directory, so it is wider than before, not narrower. The
package's own boundary test also rejects any mention of `IngestObserved`.

The wall scans every production file in the module, so it sees the package
without a scanner change.

## Unchanged

Which documents are accepted, every error phrase, the registry and catalog
revisions a document produces, every stamped server field, every tool
fingerprint and eligibility, the 1 MiB bound, the activation's
`qualification_inventory_invalid` reason and the log line that carries the
phrase. No wire, configuration or persistence format is involved. No
authorization check is touched.

## Tests

Three engine-only tests move with their names unchanged:
`TestInventory_TraversalPathRejected`, `TestInventory_OversizedFileRejected`
and `TestInventory_Deterministic`. The other eighteen `TestInventory_*` tests
stay in root, unedited: they drive the real activation, the mTLS listener,
the holder or the Admin API.

New in the package:

- A verdict table of 87 documents (28 accepted). Its digest was captured by
  running the same corpus through the root functions on main `6795ec63a`
  before the move, and covers the error phrase or both revisions and every
  seeded record. A control shows the digest moves when one outcome moves.
- The read bound at exactly the limit, one byte over, empty, missing, a
  directory and a traversal path, each with its exact phrase.
- Seeded tools are Quarantined and operator-seeded (no peer observation); a
  disabled server is registered, verified and not usable.
- A failed seed returns no pair; `Seed` does not reorder the caller's
  document; two seeds share nothing; 16 concurrent seeds agree; a smaller
  server cap passed by the caller is honoured.
- Which of two different failures is reported (the one that sorts first, for
  servers and for tools). Nothing tested the sort before: with either sort
  removed, every earlier test, the verdict table included, still passed.
- A fuzz target over decode-then-seed.
- A boundary test: Culvert imports limited to the four packages above; no
  logging, network, clock or `sync` import; no package variable; no `init`;
  no mention of `IngestObserved`; exactly the 7 exported names. Fifteen
  negative controls and one positive control.

## Consequences

`mcp_inventory.go` drops from 604 to about 270 lines and holds only state,
adapters and the loader. The inventory grammar can be tested and fuzzed with
`go test ./internal/mcp/qualinventory` in about a second.

One cost: the wall entry and the suppression inventory
(`docs/engineering/security-reviews/2026-10-03-inline-suppression-inventory.tsv`,
a dated audit record that names `mcp_inventory.go:307`) now point at a moved
line. The wall entry is updated here; the dated audit record is left as
written.
