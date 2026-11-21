# ADR-0054: The per-key lock is owned by internal/keyedmutex

- Status: Proposed for review with the implementation PR (IM-021, 2026-11-21).
- Numbering: ADR-0051 is the highest merged. ADR-0052 is reserved by open
  PR #1981 (IM-019), ADR-0053 by open PR #1985 (IM-020) and ADR-0040 by open
  PR #1526. No other open PR adds a numbered file under `docs/adr/` (checked
  against every open PR head on 2026-11-21).
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-021.
  Related: ADR-0002, ADR-0038 (instance-owned state), ADR-0042..0053.

## Context

`keyedMutex` is a 40-line per-key lock: callers naming the same string key run
one at a time, callers naming different keys do not wait for each other, and
an entry is removed when its last holder or waiter releases it. It was
declared at the bottom of `saas_feed_genstore.go`, where it was written for
the SaaS feed generation store ("serialize in-process writers of the SAME
generation id").

It has a second, unrelated owner. `cdr_lineage.go` builds the process-wide
`cdrLifecycle` from the same constructor, and `cdr_lineage.go`, `cdr_ui.go`
and `cdr_health.go` take it for renewal, revoke, delete and enroll of one CDR
instance. So the CDR control plane depended on a type that lives in a SaaS
feed storage file, and the generation store file carried a concurrency
primitive that is not about generations. The IM-019 measurement of IM-003
names it directly: "`keyedMutex`, a generic per-key lock declared in the
genstore file and also used by `cdr_lineage.go`", and lists `newKeyedMutex`
among the 16 names other root files read from that file.

The type reads no root symbol, imports only `sync`, and no root test names it
or its fields.

ADR-0002 keeps the CDR/Sluice cluster in main as a subsystem program and does
not list the `saas_feed_*.go` store files. Nothing here moves CDR or feed
logic, state or lifecycle; the two owners keep their instances. There is no
conflict to supersede.

## Decision

Create `internal/keyedmutex` with 2 exported package-level names:

- `New() *Mutex`
- `Mutex`, with one method, `Lock(key string) (unlock func())`

Decisions inside that:

- **The code is moved unchanged.** The body of `Lock` is the body of the old
  `lock`, statement for statement: register under the table lock, release the
  table lock, take the entry lock, and on unlock release the entry, then
  decrement and collect under the table lock. Fairness, the order of the two
  locks and the collection rule are what they were.
- **No root binding.** A method cannot be re-exported under a lower-case
  name, and a wrapper type in main whose only job is to spell `lock` would be
  a second name for one thing. The nine call sites in four root files name
  the package: `keyedmutex.New()` (2) and `.Lock(` (7).
- **No options.** It has no clock, sink or configuration to inject.
- **The zero value stays unusable**, as before (`Lock` on a `Mutex` not built
  by `New` writes to a nil map). Making it usable would be a behavior change
  nobody asked for.
- **Not folded into an existing package.** `internal/fileutil` is filesystem
  durability and `internal/session` is session state; neither is a home for a
  lock, and a `sync`-helpers package would be the dumping ground the program
  rules exclude. One primitive, one small package.

Ownership in one sentence: `keyedmutex` owns the per-key locking algorithm,
and each `Mutex` is owned by whoever constructed it (the generation store
instance; the `cdrLifecycle` variable in main), which also decides what a key
means.

Lifecycle: none. The package has no package-level state, no `init`, starts no
goroutine, performs no I/O and logs nothing.

Not moved, deliberately:

- `cdrLifecycle`. It is a process-wide instance in main and stays one; making
  the CDR control plane instance-owned is the CDR program's decision.
- The key vocabulary (`inst.Name`, `"op:" + OperationID`, a generation id).
- `fsyncDir`, `isBenignDirSyncErr` and `sha256Hex`, the other generic helpers
  in the generation store file (roadmap IM-022).

## Unchanged

Which operations exclude each other, in what order the two internal locks are
taken, when an entry is collected, and every caller's critical section. No
wire, configuration or persistence format is involved. No log line, error or
metric changes.

## Tests

No existing test moved or changed; none named the type. The root tests that
exercise the two owners (`TestF3b2_*` for the generation store, including its
concurrent-persist cases, and the CDR enroll, renew, revoke, hygiene and
health tests) pass unedited.

New in the package, which had no direct test before:

- Same key: 16 goroutines × 300 rounds over an unsynchronized counter, so the
  race detector fails the test on any overlap.
- Different keys are acquired while another is held (a single shared lock
  would deadlock), including the empty key and an `op:`-prefixed key.
- A waiter does not enter until the holder releases; waiters enter one at a
  time; the reference count tracks holders plus waiters; the entry is
  collected after the last one.
- 2,000 distinct uncontended keys leave an empty table; a collected key is
  reusable.
- Two `Mutex` values do not share state.
- A mixed-key concurrent run with exact per-key counters.
- A boundary test: the only import is `sync`; no package variable; no
  `init`; exactly 2 exported names. Nine negative controls, including a
  package-level shared instance.

Mutation checks run against these tests (results in the PR's verification
log): entry never collected; one lock for every key; entry lock never taken;
a package-level shared instance.

## Consequences

The CDR control plane no longer depends on a SaaS feed storage file, and the
generation store file is 40 lines shorter and holds only generation-store
code plus three generic helpers. The names other root files read from
`saas_feed_genstore.go` drop by one (`newKeyedMutex`), which removes the
`keyedMutex` owner question recorded against IM-003. It does not unblock
IM-003: the remaining 15 names are the store's own types and constants.
