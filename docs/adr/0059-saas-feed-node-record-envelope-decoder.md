# ADR-0059: The SaaS feed's node-local record envelope is decoded by internal/urlcatfeed/noderecord

- Status: Proposed for review with the implementation PR (IM-028, 2026-11-22).
- Numbering: ADR-0055 is the highest merged. ADR-0056, ADR-0057 and ADR-0058
  are reserved by open PRs #1992 (IM-024), #1993 (IM-025) and #1997 (IM-026);
  ADR-0040 by open PR #1526. No other open PR adds a numbered file under
  `docs/adr/` (checked against every open PR on 2026-11-22).
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-028.
  Amends one sentence of [ADR-0053](0053-saas-feed-node-record-codec-package.md);
  related: ADR-0002 and IM-012 (the same finding for the field grammar).

## Context

ADR-0053 moved the canonical bytes and the CRC-32C seal of the F3 node-local
records to `internal/urlcatfeed/noderecord` and left the three strict decoders
in main, with this note:

> They have one shape, but each returns its own sentinel errors and message
> prefix, and a generic decoder would need those injected. That is a separate
> change with its own differential test.

This is that change. At main `ef9431189` the bodies of `decodeFloorRecord`
(`saas_feed_floor.go`), `decodeActivationRecord` (`saas_feed_activation.go`)
and `decodeSaaSFeedAuthorityRecord` (`saas_feed_authority.go`) were the same
steps with three things substituted: the record type, the size
constant and four sentinel errors.

1. zero length: the record's `Empty` sentinel;
2. longer than the record's bound: its `Oversize` sentinel, wrapped as
   `"%w: %d > %d"`;
3. `encoding/json` decode with `DisallowUnknownFields`: `"<prefix>: decode: %w"`;
4. `dec.More()`: its `Trailing` sentinel;
5. re-encode with the canonical encoder and compare bytes: its
   `Noncanonical` sentinel;
6. the record's own field and seal validation.

Steps 1 to 5 are what make a file on disk "a record" at all. Step 5 is the one
that refuses reordered or duplicate keys, whitespace, HTML escaping and
alternate scalar encodings, and it is only correct while it uses the same
encoder the writer used. That encoder already lives in `noderecord`. Three
copies of the steps around it is the duplicate-rule problem IM-012 and IM-020
removed for the grammar and the seal: an edit to one copy (a reordered check,
a `>=`, a dropped `More()`) changes which stored bytes one record kind accepts
and not the others, and no test compares the three.

ADR-0002 does not list the `saas_feed_*.go` files. No store, state machine or
lifecycle moves. The only prior decision this touches is ADR-0053's "Not
moved" entry quoted above, which named this as a follow-up.

## Decision

Add two exported names to `internal/urlcatfeed/noderecord` (4 → 6):

```go
type Envelope struct {
	Name     string // prefixes a strict-decode refusal: "<Name>: decode: <cause>"
	MaxBytes int    // largest accepted record, inclusive

	Empty, Oversize, Trailing, Noncanonical error
}

func Decode[T any](data []byte, e Envelope) (T, error)
```

`Decode` performs steps 1 to 5 in that order and returns the first refusal.
Step 6 stays with the record's owner. In main each decoder is now
`noderecord.Decode[<record>](data, <record>Envelope())` followed by its
`validate*Record` call, and one small function per record
(`floorEnvelope`, `activationEnvelope`, `saasFeedAuthorityEnvelope`) names
that record's prefix, bound and sentinels.

Decisions inside that:

- **Sentinels are injected, not shared.** The package declares no error
  value. Each record's four sentinels stay where they are declared, with
  their texts, so every `errors.Is` in main and in the tests keeps working
  and an activation refusal can never satisfy `errors.Is(err, errFloorEmpty)`.
  A package-level `ErrEmpty` would have been shorter and would have merged
  three vocabularies into one; the boundary test refuses it.
- **A missing sentinel cannot become success.** If an `Envelope` leaves a
  sentinel nil, `Decode` answers that refusal with an unnamed error
  (`noderecord: empty record`, and so on), never with a nil error. The zero
  `Envelope` therefore accepts nothing: its `MaxBytes` of 0 refuses every
  non-empty input. No caller in main relies on this; it exists so a future
  record kind that forgets a field fails closed.
- **A generic function over the record type.** `Decode[T]` decodes into a
  `T` and canonicalises that `T` by value, exactly as the three bodies did.
  The alternative, `Decode(data, e, &rec)`, would canonicalise through a
  pointer and leave a partly filled record in the caller's variable on
  refusal. On refusal `Decode` returns the zero `T`.
- **An envelope function, not a package variable, in main.** The three
  `*Envelope()` functions build a small struct of existing values on each
  call. A `var floorEnvelope = …` would add three mutable root globals for
  no measured gain; decode runs on startup, on activation and on authority
  change, not per request.
- **The package stays stateless.** `Decode` adds `bytes` and `encoding/json`
  imports and nothing else: no variable, no `init`, no I/O, no clock.
- **Still not moved.** The record types, the size constants, the field and
  seal validation, the sentinels, the encoders (`encode*Record`), the files,
  the floor's two-file quorum, and the two generation-metadata readers
  (`gcCollector.validateGenerationDir` returns a bool and
  `checkGenerationMeta` wraps one `errReverifyMeta` with `%v`; neither has
  the four-sentinel shape, so binding them is a separate decision).

Ownership in one sentence: `noderecord` owns the byte form, the seal and the
envelope steps that decide whether bytes are a record's canonical bytes, and
each record's owner in main keeps its type, bound, sentinels, field
validation, file and write path.

Lifecycle: none. The package has no state, starts no goroutine, performs no
I/O and logs nothing.

## Unchanged

Which bytes each of the three decoders accepts and refuses; the order of the
checks; every sentinel and every message, including the `"%d > %d"` oversize
text and the `"<prefix>: decode: "` wrap of `encoding/json`'s error; the size
bounds (floor 4096, activation and authority 8192, inclusive); every stored
byte. No wire, configuration or persistence format changes, so a node
upgraded across this change reads the records it wrote before it. No caller
of the three decoders is edited and no existing test is edited.

## Tests

Root, new (`saas_feed_record_decode_binding_test.go`):

- A verdict table over 17,384 inputs (floor 4,793, activation 8,426,
  authority 4,165) derived from one valid record of each kind: every
  truncation, every single-byte deletion, a space at every offset, eleven
  byte substitutions at every offset, and whole-document shapes around the
  size bound. For each input the test records the accepted record or the
  refusal's class and text. The three digests and the per-class counts were
  captured from main `ef9431189` **before** the bind and are pinned. A
  strict-decode refusal is recorded by class and prefix only, because the
  text after the prefix is `encoding/json`'s.
- The four refusal texts per record, the inclusive bound, and the decode
  prefix, pinned outside the digest so a failure names the line that moved.
- The three root decoders agree with `noderecord.Decode` under their own
  envelope on every envelope refusal in the table, and each envelope carries
  that record's own prefix, bound and sentinels.

Package, new (`decode_test.go`):

- A differential test against a frozen copy of the pre-move body over more than
  20,000 inputs (every byte value at every offset of a valid record), comparing the
  returned record, the full error text, `errors.Is` against each sentinel and
  whether a `*json.SyntaxError` is wrapped.
- Step order and texts; `Decode` validates no field and no seal; a nil
  sentinel still refuses; the zero and negative-bound envelopes accept
  nothing; two record kinds keep their own sentinels under concurrent use;
  the input is not modified.
- `FuzzDecode` over the same oracle, plus "accepted implies the input is the
  canonical bytes of the result".
- The boundary test now expects 6 exported names and 3 production files, and
  gains two negative controls: a package-level sentinel and a reader-based
  API.

Existing tests that exercise the bound decoders pass unedited, among them
`TestFloor_StrictDecode_Rejections`, `TestFloor_FieldValidation`,
`TestFloor_GoldenBytes` and `TestIM020_RecordSealsUnchangedByBinding`.

Mutation checks, each failing at least one test (results in the PR's
verification log): an exclusive size bound; unknown fields allowed; trailing
data ignored; the canonical comparison dropped; the canonical comparison
before the trailing check; a nil sentinel returned as nil; the oversize text
without its lengths; the decode cause formatted with `%v`; a non-zero record
returned on refusal; and in main, swapped floor sentinels, the floor's bound
on the activation record, the floor's prefix on the authority record, the
activation's sentinel on the authority record, and field validation skipped.

## Consequences

The rule "these bytes are a record only if they are its canonical bytes" has
one implementation beside the encoder it depends on, and a new F3 record kind
gets it by naming an envelope. The three root files lose 33 lines net and
their `bytes` import; two of them also lose `encoding/json`.

`noderecord` grows from 4 to 6 exported names, inside the program's limit of
8. The cost is one generic function in a package that had none.

Not a consequence: this does not reduce the names other root files read from
`saas_feed_floor.go`, because the decoders were not among them. IM-002 and
IM-003 stay blocked on that surface.

Follow-ups this makes smaller, none started: binding the two
generation-metadata readers to the same steps (needs a decision on their
single-sentinel refusal shape); naming `noderecord.Canonical` at the six call
sites and deleting the root binding.
