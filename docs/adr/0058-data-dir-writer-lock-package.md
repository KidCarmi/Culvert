# ADR-0058: The data-directory single-writer lock is owned by internal/writerlock

- Status: Proposed for review with the implementation PR (IM-026, 2026-11-21).
- Numbering: ADR-0055 is the highest merged. ADR-0056 is reserved by open
  PR #1992 (IM-024), ADR-0057 by open PR #1993 (IM-025) and ADR-0040 by open
  PR #1526 (checked against every open PR on 2026-11-21).
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-026.
  Related: ADR-0002, ADR-0038 (instance-owned state), ADR-0054 (the previous
  leaf with no options).

## Context

CHAOS-103 added a single-writer guard on the persisted-state root: a second
Culvert process started against the same data directory is refused at boot.
The guard lived in three root files:

- `datadir_writer_lock.go`: the lock acquisition (`acquireDataDirWriterLock`),
  the verdict type, the lock file name, and the boot decision
  (`checkDataDirSingleWriter`, the `CULVERT_ALLOW_MULTIPLE_WRITERS` override,
  the deferred log notice, the posture kept for Diagnostics).
- `datadir_writer_lock_unix.go` and `datadir_writer_lock_other.go`: the flock
  call and its stub for platforms without one.

Two different things shared those files. The acquisition answers "does a live
process hold this directory?" by creating the directory if needed, opening one
file and calling `flock`. It reads no root name: no logger, no configuration,
no environment. The boot decision reads the answer and decides what the
process does about it. Only the second is startup policy.

The acquisition also kept its result in a package variable
(`dataDirWriterLockHandle`), written inside the function, so the function
could not be called without touching process-wide state. The ten root tests
save and restore that variable around every case.

ADR-0002's "Decomposition Complete" predates CHAOS-103 and does not classify
these files. It keeps startup and process lifecycle in main; this decision
keeps them there. There is no conflict to supersede.

The comment in `datadir_writer_lock_unix.go` records an earlier decision not
to reuse `internal/storeguard`'s `flockFile`, because that package's locks are
per-attempt markers around one store open and this lock is held for the life
of the process. This ADR keeps that decision: the lock gets its own package
and does not import `storeguard`.

## Decision

Create `internal/writerlock` with 8 exported package-level names:

- `Take(dir string) Attempt`
- `Attempt`: `Verdict`, `Path`, `Cause`, `Lock`
- `Verdict` and its three values `Acquired`, `Held`, `Undetermined`
- `Lock`, with one method, `Close() error`
- `FileName`

Decisions inside that:

- **The entry point is named `Take`.** `Acquire` is the natural name and is
  not available: the root wall
  `TestChaos71_Wall_EveryLeaseGrantIsInstalledOrCleared` treats every call
  to something named `Acquire` outside `acquireLeaseAttempt` as a direct HA
  lease acquisition and fails. Exempting this caller would mean editing a
  fencing wall for a change that has nothing to do with fencing, so the
  package uses a name the wall does not key on. `TryLock` is keyed by
  `ha_alert_lock_chaos_test.go` and was passed over for the same reason.
- **The acquisition is moved statement for statement.** Empty directory name,
  `MkdirAll` at 0700, `OpenFile` with `O_CREATE|O_RDWR` at 0600, the
  non-blocking exclusive flock, and the three outcomes are what they were,
  including which outcomes carry a path and which carry a cause. The two
  `#nosec` annotations move with their lines.
- **The handle is returned, not stored.** `Take` returns the open lock in
  the `Attempt`. Main stores it in the same variable as before. The package
  has no package-level variable, so two acquisitions on two directories share
  nothing.
- **A result struct in place of three return values plus a handle.** The old
  function returned `(verdict, path, cause)` and wrote the handle as a side
  effect. Returning four positional values would work; a struct names them
  and makes "the lock is non-nil exactly when acquired" one documented field.
- **`Lock.Close` is new surface.** The root tests already closed the retained
  `*os.File` in their cleanup; `Close` keeps those lines compiling unedited
  and gives a test a way to release. Production never calls it: the kernel
  releases the lock at exit, as before.
- **No options.** There is no clock, sink or configuration to inject. The
  file name is a constant because a running older process holds its lock on
  that exact name; an option would let two binaries disagree.
- **The override stays out.** The package does not read
  `CULVERT_ALLOW_MULTIPLE_WRITERS` or any other environment variable, and the
  boundary test rejects an `os.Getenv` there. Whether a `Held` verdict
  refuses the boot is main's decision.
- **Root keeps its names as bindings.** `dataDirWriterLockName`,
  `dataDirWriterVerdict` (an alias) and the three verdict constants now equal
  the package's; `acquireDataDirWriterLock` calls `writerlock.Take`,
  stores the lock and returns the same three values. `main.go`,
  `datadir_writer_diagnostics.go` and every root test are unedited.
- **Not folded into an existing package.** `internal/storeguard` is excluded
  above. `internal/fileutil` is durable writes; a process-lifetime lock is
  not one.

Ownership in one sentence: `writerlock` owns how the lock is taken and what
the three verdicts mean, the caller owns the returned `Lock` and its lifetime,
and main owns what the process does with a verdict.

Lifecycle: the package starts no goroutine and has no `init`. The one
resource is the open descriptor inside `Lock`; main holds it in
`dataDirWriterLockHandle` from the boot guard until the process exits.

Not moved, deliberately:

- `checkDataDirSingleWriter`, its position in `main()` (after
  `checkInterruptedRestore`, before the logger opens a file), the refusal and
  notice texts, `allowMultipleWriters`, `logDataDirWriterLockNotice`,
  `dataDirWriterPosture` and the Diagnostics row.
- `errDataDirWriterHeld`. It is the error of the boot decision, not of the
  acquisition, which reports `Held` as a verdict.

## Unchanged

When a second process is refused, when the boot degrades, the lock file's
name, mode and location, the directory mode on a first boot, every log and
error text, and the order of the boot guards. No wire, configuration or
persisted format is involved.

## Tests

No existing test moved or changed. The ten tests in
`datadir_writer_lock_test.go` and the two in
`datadir_writer_diagnostics_test.go` call `checkDataDirSingleWriter` or read
main's handle, notice and posture, so they are tests of the boot decision and
stay in root. They pass unedited.

New in the package:

- A first acquisition succeeds and a second on the same directory is `Held`,
  with no lock, no cause and the expected path.
- `Close` releases; refused attempts neither disturb the holder nor keep the
  lock alive after it closes.
- Two directories are independent.
- No directory named: `Undetermined`, empty path. A root that is a file and a
  root under a file: `Undetermined`, with the path that would have been used.
- An absent root is created with no mode bit outside 0700, the lock file is
  zero bytes with no bit outside 0600, and the lock excludes a second
  attempt. An existing 0750 root keeps its mode.
- A leftover lock file is not a lock.
- The file name and the three verdict values are pinned.
- The lock file's place taken by a directory: `Undetermined`.
- The flock call itself: a live holder is `(false, nil)`, and an error other
  than would-block is an error, not a holder.
- A boundary test: imports limited to `errors`, `os`, `path/filepath` and
  `golang.org/x/sys/unix`; no package variable; no `init`; no environment
  read, process exit, remove or rename; exactly 8 exported names; four
  production files. Twelve negative controls.

Eighteen mutation checks were run against these tests on a copy of the
package; seventeen fail at least one test. The survivor reports a failed
flock call as `Held` inside `Take`: no test can make flock fail on a file it
just opened without a seam the package does not have. The flock function's
own error mapping is tested directly, and main had no test of this branch
either.

## Consequences

Root loses two files and the acquisition body; `datadir_writer_lock.go` now
holds only the boot decision and its bindings. The lock can be exercised
without saving and restoring a process-wide handle. Nothing else can reach
the flock call, and the package cannot grow a policy decision without failing
its boundary test.

The fuzz matrix and the benchmark gates are unaffected: the package has no
parser and is not on a request path.
