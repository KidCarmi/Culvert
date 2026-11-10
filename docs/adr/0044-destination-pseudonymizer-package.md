# ADR-0044: The destination pseudonymizer engine is owned by internal/pseudonym

- Status: Proposed for review with the implementation PR (IM-008, 2026-11-09).
- Numbering: ADR-0043 is the highest merged; no open PR touches `docs/adr/`.
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-008.
  Related: ADR-0002, ADR-0038 (instance-owned state pattern), ADR-0041/0042/0043.

## Context

`traffic_redaction.go` mixed two responsibilities: (a) the keyed-HMAC engine
(node-local key + durable non-secret key id + generation fence + pooled HMAC +
token encoding + whole-host case-insensitive replace) held in three package
globals, and (b) the policy that decides when to apply it (`decRedactHosts`
posture, URI scrubbing order). Only (b) depends on root state.

## Decision

Move (a) to `internal/pseudonym` as an instance-owned `Pseudonymizer`
(`New`, `Set`, `SetPair`, `Key`, `KeyID`, `Rotate`, `Ensure`, `MintPair`,
`Pseudonymize`) plus `ReplaceHostFold` and constants `Sentinel`, `Prefix`,
`KeyLen` (6 exported identifiers). The pool, key state and generation counter
are instance fields; the package has no package-level variables or `init`.

Main keeps: the single application instance `trafficPseudonymizer`, the posture
gate, `redactDestinationHost/URI`, persistence of key/id in admin settings, the
admin handlers and every call site. The previous function names remain as
one-line wrappers so no caller changed. Lifecycle: main constructs the instance
at package init, publishes the key at settings load / first enable; the package
starts no goroutines and owns no files.

Unchanged: token bytes (pinned by the moved reference-HMAC oracle), fail-closed
sentinel, key-generation fence, key/id persistence format, audit and
config-versioning behavior.

## Tests

Engine-only tests moved with their names unchanged (TokenMatchesReferenceHMAC,
PooledHasherIsKeyFenced, ClearedKeyFailsClosedThenRecovers,
ConcurrentTokensAreStable, ConcurrentRotationNeverPanics,
BenchGate_PseudonymizeHostAllocs). New: instance independence, SetPair
aliasing/id, Ensure idempotence, `ReplaceHostFold` boundaries, and a boundary
test with negative controls. Posture, URI, chokepoint, export-surface and
`recordStats` tests stay in root.

## Consequences

The token algorithm and fail-closed contract can be tested without compiling
the application, and a second independent instance cannot observe the first's key.
