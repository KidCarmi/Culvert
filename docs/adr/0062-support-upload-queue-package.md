# ADR-0062: The support upload queue is owned by internal/supportupload/uploadqueue

- Status: Proposed for review with the implementation PR (IM-029, 2026-11-22).
- Numbering: ADR-0061 is the highest merged. ADR-0040 is reserved by open
  PR #1526. No other open PR adds an ADR (checked against all eight open PRs
  on 2026-11-22).
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-029.
  Related: ADR-0002, ADR-0038 (instance-owned state), ADR-0060 (the previous
  extraction that kept root names as bindings).

## Context

M6 Secure Upload keeps a node-local queue of the support bundles an operator
has consented to upload. All of it lived in one root file,
`support_upload_queue.go` (379 lines):

- the entry record and its JSON form, one file per bundle under
  `<dataDir>/support/upload_queue/`;
- the five states and the rules between them: idempotent enqueue, re-arm of a
  deferred or rejected entry, the classification of one attempt's result;
- the two capacity bounds, terminal-record pruning and the retry ladder;
- a process-wide mutex over the files.

The file's own header called it "the queue ENGINE only". It read five names
from the rest of main: `dataDir`, `supportBundleIDRe`, `mkdirDurableSupport`,
`durableSupportWrite` and `sanitizeLog`. None of the five is a queue rule.
They are where the node keeps state, which strings are bundle ids, how the
support domain makes a write durable and visible to storage health, and how
the application scrubs a log value.

The engine could not be exercised on its own. Every test first pointed the
process-wide `dataDir` at a temporary directory, and three tests overwrote
and restored the package variables `maxUploadQueue` and `maxUploadTerminal`,
which existed as variables only so tests could do that.

`internal/supportupload` already owns the transfer client, `Receipt` and
`GatewayError`, and the queue's record embeds the first and classifies on the
second.

ADR-0002's "Decomposition Complete" predates M6 and does not classify
`support_upload_*.go`. It keeps process lifecycle, HTTP binding and
cross-domain wiring in main; this decision keeps them there. There is no
conflict to supersede.

## Decision

Create `internal/supportupload/uploadqueue` with 10 exported package-level
names:

- `Queue`, with methods `Enqueue`, `List`, `Load`, `Save`, `Due`, `Attempt`,
  `Path` and `BoundErr`
- `New(Options) *Queue`
- `Options`
- `Entry`
- `State` and its five values `StateQueued`, `StateUploading`,
  `StateUploaded`, `StateDeferred`, `StateRejected`

Decisions inside that:

- **Ten names, two over the program's eight.** Five of the ten are the values
  of one vocabulary that is persisted in every entry and returned by
  `/api/support/uploads`. Main names all five: the consent gate tests three,
  the worker audits the other three outcomes differently, and root tests set
  two. Hiding them behind predicates would need at least as many methods and
  would leave root tests unable to build an entry. The alternatives that
  reach eight were rejected as worse designs: a `Queue` struct with exported
  configuration fields in place of `New` and `Options` makes the bounds
  mutable after publication; dropping the `State` type makes the vocabulary
  untyped strings. The surface without the vocabulary is five names.
- **The engine is moved statement for statement.** Each function became a
  method with the same body. The order inside `Enqueue` (lock, id check,
  load, capacity check, save, prune) and inside a save (id check, directory,
  marshal, write) is unchanged, as are the two error texts, the indented JSON
  and every struct tag.
- **The mutex is the instance's.** `uploadQueueMu` was a package variable;
  it is now a field. Two queues share nothing, and the boundary test refuses
  any package-level variable that is not an unexported error value.
- **Five functions and four bounds are options, with no defaults.** `Dir`,
  `ValidID`, `Mkdir`, `Write` and `Sanitize` are the five root names above.
  `MaxPending`, `MaxTerminal`, `MaxAttempts` and `MaxErrLen` are the four
  bounds, which stay declared in main because main's API reports one of them
  and main's architecture test asserts on three. A gap fails closed: with no
  `Dir` or `ValidID` every id is invalid; with no `Mkdir` or `Write` nothing
  is saved; with no `Sanitize` the error text is withheld, not stored raw; a
  zero `MaxPending` refuses every enqueue.
- **`Dir` is a function.** Main resolves the queue directory from `dataDir`
  on every call today, and its tests move `dataDir` between calls. A string
  captured at construction would silently pin the first value.
- **Writes and directory creation never bypass the options.** The package
  calls `os.ReadFile`, `os.ReadDir` and `os.Remove` (one pruned entry) and no
  other filesystem function; the boundary test refuses `os.WriteFile`,
  `os.Rename`, `os.MkdirAll` and the rest. This keeps
  `TestSupportPersistence_RoutesThroughDurableChokepoint` true by
  construction: the only way to commit an entry is main's
  `durableSupportWrite`.
- **The package does not import `regexp`, `internal/fileutil` or a logger.**
  The id rule, the durable write and the sanitizer each have one owner
  already; importing a second copy of any would make two.
- **The capacity error stays unexported.** `errUploadQueueFull` was
  unexported in main and no caller matched on it; the consent handler answers
  every enqueue error the same way. It is exported when a caller needs it.
- **The retry ladder's base and ceiling are the engine's constants**, not
  options: nothing in main reads them and no test varies them.
- **`Attempt` takes an unnamed function type.** Main keeps its `uploadFunc`
  type for the worker; a named type in the package would be an eleventh name
  for a signature used once.
- **Root keeps its names as bindings.** `uploadQueueEntry` is an alias, the
  five state constants equal the package's, and `enqueueUpload`,
  `listUploadQueue`, `loadUploadQueueEntry`, `saveUploadQueueEntry`,
  `dueUploadEntries`, `drainUploadEntry`, `uploadQueuePath` and
  `boundUploadErr` each call one method of the process's one queue,
  `supportUploadQueue`. `support_upload_worker.go`, `support_tac_trust.go`,
  the consent gate's code and every root test that uses the queue compile
  unedited, with one exception below.
- **A sub-package, not `internal/supportupload` itself.** The parent is an
  outbound HTTP client and `TestNoInboundTACSurface` reads it as one. A file
  store and a state machine are a different responsibility with a different
  boundary (no network at all).

Ownership in one sentence: a `Queue` owns its entries' files, their states
and its mutex; main owns where the directory is, which ids are valid, the
durable write, the bounds, and when anything is enqueued or attempted.

Lifecycle: the package starts no goroutine, holds no file open and has no
`init`. The process's one queue is a package variable of main, built from
functions and constants, so it needs no start or stop. The worker goroutine
that drains it is `startSupportUploadWorker`, parented to the application
lifecycle context, and is not moved.

Not moved, deliberately:

- `uploadQueueDir` (placement under `dataDir`), the four bounds, and
  `uploadFunc`.
- `support_upload_worker.go`: the tick, the `uploadEnabled()` gate, the audit
  records, removal of the sealed blob.
- `support_upload_wire.go`: the consent gate, sealing, the transfer, the API
  read model.
- `support_durable_write.go`: the durable-write seam is the support domain's,
  used by five other writers.

## Unchanged

Which bundles are enqueued and when, which attempts are made, every state
transition, the retry times, both capacity bounds, what is pruned, the bytes
of every entry file, the file names and modes, the directory mode, every
error text, the API responses, the audit records and the log lines. No wire,
configuration or persisted format changes.

## Tests

Moved to the package with names and assertions unchanged, 12 tests: the five
`TestEnqueueUpload_*`, `TestLoadUploadQueueEntry_RejectsBundleIDMismatch`,
the four `TestDrainUploadEntry_*`, `TestUploadRetryBackoff` and
`TestDueUploadEntries`. Each now builds a queue over its own directory; the
three that overwrote a package bound pass the bound to `New`.

Stay in root, unedited: the 14 tests in `support_upload_wire_test.go`, the
three in `support_upload_arch_test.go`, and every other test that reaches the
queue through the consent gate or the worker.

Edited in root, one test:
`TestSupportPersistence_RoutesThroughDurableChokepoint` took
`uploadQueueMu` and called `saveUploadQueueEntryLocked`; it now calls
`saveUploadQueueEntry`, which takes the same lock around the same save. Its
assertion (the queue entry's path was seen at the `fileutil` chokepoint) is
unchanged.

New in root, 2 tests (`support_upload_queue_wiring_test.go`):

- The bytes of one entry file after each of six steps (queued, transient
  failure with control bytes and an over-long text, gateway rejection,
  re-arm, deferral after six failures, upload with a receipt), compared with
  SHA-256 digests captured by running the same test file on main before the
  move.
- What main hands the engine: the path under `dataDir`, the four bound
  values, `boundUploadErr` agreeing with `sanitizeLog`, six malformed ids
  refused by enqueue, save and load with nothing written, and the directory
  following `dataDir` between calls.

New in the package:

- `Attempt` against a frozen copy of main's body over 756 inputs (21 error
  kinds including thirteen gateway statuses around both ends of 4xx, a wrapped
  gateway error, control bytes and texts at, over and inside the byte bound;
  attempts 0 to 8; new and prior session ids), with a check that all four
  outcomes occur.
- The retry ladder against a frozen copy for attempts -3 to 80, and against
  the literal ladder.
- Two queues with different bounds share no entry, capacity or bound.
- `Dir` is asked on every call.
- Each missing option and a zero or negative bound refuses and writes
  nothing; no sanitizer withholds the text.
- Nine malformed ids are refused by all three id-taking operations and create
  nothing; files whose names the rule refuses, and a directory with a valid
  entry name, are not listed.
- Every write and directory creation goes through the options, directory
  first; an owner write or mkdir error is returned and no entry is reported.
- 26 concurrent enqueues against a bound of 5 leave 5 entries (run under
  `-race`).
- `Attempt` does not hold the lock across the transfer.
- The persisted form of a queued and a retried entry, as literal JSON, and
  the five state words.
- Rules main had no test of, each found by a mutation that passed: a deferred
  or in-flight entry holds capacity and a delivered one does not; a re-arm
  drops the old session, retry time and receipt, and a delivered bundle is
  not re-armed; pruning removes the oldest and the list is oldest first; an
  entry is due at its retry second and not one second before; load refuses a
  well-formed file under a name the id rule refuses.
- A boundary test: ten allowed imports; no package variable except
  unexported error values; no `init`; no goroutine; no clock read, sleep or
  timer; no environment read; no write, rename or directory creation; from
  the parent package only `Receipt` and `GatewayError`; exactly 10 exported
  names; two production files. Twenty-one negative controls.

Forty-two mutation checks were run against the finished package tests; forty
fail at least one. The two survivors: removing the lock from `List` (the race
detector does not see file reads, and the interleaving is not observable
without a seam the package does not have), and not skipping directories in
the listing (equivalent: reading a directory as a file fails, so the entry is
skipped anyway).

## Consequences

`support_upload_queue.go` goes from 379 lines to bindings. The queue can be
built over any directory with any bounds, so its tests no longer move the
process-wide `dataDir` or overwrite package variables, and
`maxUploadQueue`/`maxUploadTerminal` become constants. The engine cannot
commit a byte except through the function main gives it.

`.github/qa-root-shard-timings.json` keeps timing rows for the 12 moved test
names; that file only balances shards and never decides whether a test
runs, and it is regenerated from a reference run, not edited by hand. The fuzz matrix and the benchmark gates are unaffected: the package
has no parser of remote input and is not on a request path.
