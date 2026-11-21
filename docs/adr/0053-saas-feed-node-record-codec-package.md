# ADR-0053: The SaaS feed's node-local record codec is owned by internal/urlcatfeed/noderecord

- Status: Proposed for review with the implementation PR (IM-020, 2026-11-21).
- Numbering: ADR-0051 is the highest merged; ADR-0052 is reserved by open
  PR #1981 (IM-019) and ADR-0040 by open PR #1526. No other open PR adds a
  numbered file under `docs/adr/`.
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-020.
  Related: ADR-0002, ADR-0042..0052, and IM-012 (the same finding for the
  timestamp and digest grammar).

## Context

The F3 node-local store keeps four durable record kinds under the feed's data
directory: the rollback floor (`saas_feed_floor.go`), the activation record
(`saas_feed_activation.go`), the authority record (`saas_feed_authority.go`)
and the generation metadata (`saas_feed_genstore.go`, read back by
`saas_feed_gc.go` and `saas_feed_reverify.go`). `saas_feed_client.go` also
encodes the normalized snapshot whose digest those records bind.

All of them share two rules, and both lived in the floor file:

1. **The canonical bytes.** `floorCanonicalBytes` was called from six other
   root production files. It was a line-for-line second copy of
   `urlcatfeed.canonicalJSON`, the feed protocol's one encoder; its own
   comment called it "the shared canonical scheme (§B.3 / F1)". Two encoders
   for one scheme is the duplicate-rule problem IM-012 removed for the
   timestamp and digest grammar: a change to either copy would make a
   node-local record disagree with the signed document it binds.
2. **The seal.** `floorCRCTable` (CRC-32C) was read directly by the activation
   and authority files, each of which repeated the same four lines to print it
   with `%08x`, and `validCRC32Hex` (over `isLowerHex`/`isHexByte`) checked the
   stored form for all three records.

So the floor file was the codec owner for every F3 record by accident, which
is part of why IM-002 measured 23 names read from it by other root files.

ADR-0002 does not list the `saas_feed_*.go` files, and nothing here moves a
store, a state machine or a lifecycle. There is no conflict to supersede.

## Decision

Create `internal/urlcatfeed/noderecord` with 4 exported functions and no
types, variables or constants exported:

- `Canonical(v any) ([]byte, error)`: the canonical bytes.
- `Checksum(canon []byte) string`: CRC-32C as exactly 8 lowercase hex digits.
- `Seal(sansChecksum any) (string, error)`: `Checksum` over the canonical
  bytes of a record's checksum-omitted view.
- `ValidChecksum(s string) bool`: the stored form, 8 lowercase hex digits.

Decisions inside that:

- **One encoder.** `urlcatfeed` exports its encoder as `CanonicalJSON` (a
  one-line name for the existing function) and `noderecord.Canonical` calls
  it. The root copy is deleted. The roadmap asked whether the codec is
  feed-protocol grammar or a node-local format: it is both, in two parts. The
  byte form is the protocol's; the checksum is node-local.
- **The seal is not in `urlcatfeed`.** That package is the signed protocol's
  trust kernel. A CRC is corruption detection that any local writer can
  recompute; putting it beside signature verification would blur which checks
  authenticate. The subpackage imports the protocol; the protocol does not
  import it.
- **The failure text is kept.** An encode failure still reads
  `saas feed floor: canonical encode: <encoding/json error>`. `Canonical`
  re-wraps the protocol encoder's cause under the old prefix. No record type
  in main can hit this path today (their fields are strings, integers,
  booleans and string slices), but the text is pinned so the move changes no
  message.
- **No package variable.** `crc32.MakeTable(crc32.Castagnoli)` returns the
  standard library's shared table, so the root's `floorCRCTable` variable has
  no successor.
- **Root keeps its names as bindings.** `floorCanonicalBytes` and
  `validCRC32Hex` are one-line bindings, so none of the six calling files and
  none of the root tests that use them changed. The three `*ComputeCRC`
  functions call `noderecord.Seal`. `floorCRCTable`, `isLowerHex` and
  `isHexByte` are removed; nothing else read them.

Ownership in one sentence: `noderecord` owns the byte form and the checksum of
a node-local record, and each record's owner in main keeps its type, field
validation, strict decoder, sentinel errors, file and write path.

Lifecycle: none. The package has no state, starts no goroutine, performs no
I/O and logs nothing.

Not moved, deliberately:

- The three strict decoders (`decodeFloorRecord`, `decodeActivationRecord`,
  `decodeSaaSFeedAuthorityRecord`). They have one shape, but each returns its
  own sentinel errors and message prefix, and a generic decoder would need
  those injected. That is a separate change with its own differential test.
- `validGenerationID`. It is the generation store's path-segment identity
  (IM-012 note), not record codec, and belongs with the store.
- The record types, the floor's two-file quorum and everything in IM-002 and
  IM-003.

## Unchanged

Every stored byte of every record; the checksum polynomial and its 8-digit
form; which records are accepted and refused; every sentinel error and
message, including the encode-failure text; file names, permissions and the
write quorum. No wire, configuration or persistence format changes, so a node
upgraded across this change reads the records it wrote before it.

## Tests

No existing test moved or changed. `TestFloor_GoldenBytes` already pins the
floor record's full bytes (crc `43d5a692`) and passes unedited.

New in the package:

- Differential tests against frozen copies of the root functions
  (`floorCanonicalBytes`, the `%08x` Castagnoli seal, `validCRC32Hex`) over
  encodable values (HTML-significant characters, U+2028/2029, control bytes,
  invalid UTF-8, nested slices, maps, pointers), unencodable values (exact
  error text), 4,096 checksum inputs and a 541-string checksum-form table
  that walks all 256 byte values at both ends.
- The CRC-32C check values from RFC 3720 and the `123456789` vector, and a
  check that the polynomial is not IEEE.
- The encoder is the protocol's (`urlcatfeed.CanonicalJSON` gives the same
  bytes), returned bytes are the caller's, the seal changes with every field,
  and concurrent callers do not affect one another.
- A fuzz target over the same oracles.
- A boundary test: the only Culvert import is `internal/urlcatfeed`; no
  `os`, `io`, `log`, `net`, `sync`, `time` or `path` import; no package
  variable; no `init`; exactly 4 exported names. Eleven negative controls,
  including the tempting one (a package-level CRC table).

New in root (`saas_feed_record_seal_binding_test.go`): the full bytes of an
activation record (crc `def7bec8`) and an authority record (crc `4b2fd64f`)
captured from main before the bind, each also decoded; an IEEE-sealed record
is refused; the root names agree with the package.

Mutation checks, each run against the package and the root pins: the IEEE
polynomial, unpadded hex, a wider digit set, the protocol's error prefix
instead of the root's, a 7-digit form, and HTML escaping turned on in the
protocol encoder. The results are in the PR's verification log.

## Consequences

The canonical form has one implementation, so the node-local records cannot
drift from the signed documents they bind. The activation and authority files
no longer reach into the floor file for a CRC table, and the floor file no
longer owns a codec for records it does not define: the names other root
files read from it drop by two (`floorCRCTable`, and `floorCanonicalBytes`
once its callers name the package). `isLowerHex` in `internal/bootstrap` is a
separate private helper for certificate fingerprints and is unrelated.

Follow-ups this makes smaller, none started: naming `noderecord.Canonical` at
the six call sites and deleting the root binding; one strict decoder for the
three records; IM-002 and IM-003, whose blocker was the surface of the floor
file.
