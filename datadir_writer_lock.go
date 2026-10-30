package main

// datadir_writer_lock.go — CHAOS-103: the single-writer guard on the
// persisted-state root.
//
// # WHY THIS EXISTS
//
// Nothing in the tree detected a SECOND Culvert process opened against the same
// `/data`. Both processes booted, both served, and neither logged a word about
// the other. The embedded BadgerDB directories are the only surfaces that were
// protected, by badger's own directory flock, and `internal/storeguard`
// deliberately DEGRADES on that signal ("another process holds the store" is on
// its environmental deny-list) rather than refusing — correctly, for a store,
// and the net effect was that the second process kept booting with the rest of
// the volume unguarded.
//
// The JSON state plane has no such lock. Every durable surface on it is
// whole-file-replaced through `internal/fileutil`'s temp-then-rename, and rename
// succeeds regardless of who else has the file open, so two processes are two
// last-writer-wins racers over the roster, the policy, the admin settings, the
// hit counters, the cluster store and the config-version series.
//
// The admin control plane is worse than the data at rest. `uiAuthMiddleware`
// grants unauthenticated RoleAdmin for as long as `cfg.IsConfigured()` is false
// (the documented first-run bootstrap window), and that predicate is per-process
// in-memory state. A second process that booted before the operator ran the
// wizard therefore keeps the window open FOREVER: it answers `needsSetup:true`
// after the real gateway is configured, and an unauthenticated caller can drive
// every admin API on it straight onto the live volume. `setup_bootstrap_window.go`
// closes that window from the durable side; this file closes the class.
//
// # THE RULE
//
// A positively identified LIVE holder refuses the boot. Everything else degrades
// with a notice. That is `checkInterruptedRestore`'s doctrine ("don't block boot
// on a transient FS issue") and `internal/storeguard`'s ("the fail-safe default
// is to leave the disk alone"), applied to the one signal that is unambiguous:
// the kernel releases an flock when its owner dies, so a lock that cannot be
// taken belongs to a process that is running RIGHT NOW. A SIGKILL, an OOM, a
// kernel panic or a power loss leaves no lock behind, so there is no stale-lock
// recovery path to get wrong and no file to clean up by hand.
//
// Refusing is the fail-closed answer the register's posture asks for, because
// recovery is impossible rather than merely hard: the two processes cannot be
// reconciled after the fact — whichever one writes last wins, and the operator
// has no way to tell which did. An unbootable second instance is loud, bounded
// (the next start succeeds as soon as the first process exits) and self-
// correcting; a silent second writer is none of those. Precedent is every other
// single-writer store an operator runs: badger itself, etcd, Postgres.
//
// CULVERT_ALLOW_MULTIPLE_WRITERS=1 overrides the refusal for an operator whose
// storage reports lock state wrongly. It is deliberately loud and deliberately
// not a config-file setting: it is an escape hatch for a false positive at 3am,
// not a supported deployment mode.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// dataDirWriterLockName is the lock file's name inside the persisted-state root.
// It lives IN the volume rather than beside it so it travels with a bind mount,
// a docker volume and an NFS export — the three ways two processes actually end
// up sharing one `/data`. It is not in backup.go's manifest, so it is neither
// archived nor restored.
const dataDirWriterLockName = ".culvert-writer.lock"

// allowMultipleWritersEnv names the escape hatch described in the file comment.
const allowMultipleWritersEnv = "CULVERT_ALLOW_MULTIPLE_WRITERS"

// dataDirWriterVerdict is the outcome of one acquisition attempt.
type dataDirWriterVerdict int

const (
	// dataDirWriterAcquired — this process is the single writer. The lock is
	// held for the life of the process.
	dataDirWriterAcquired dataDirWriterVerdict = iota
	// dataDirWriterHeld — a LIVE process holds the lock. The only refusing
	// verdict.
	dataDirWriterHeld
	// dataDirWriterUndetermined — the lock state could not be established
	// (no path configured, the file could not be created, the platform has no
	// advisory locking, the lock call failed). Boot proceeds; the caller
	// reports it.
	dataDirWriterUndetermined
)

// errDataDirWriterHeld is the sentinel the boot guard wraps so callers and tests
// can match the refusing case without parsing the message.
var errDataDirWriterHeld = errors.New("another Culvert process is already using this data directory")

// dataDirWriterLockHandle keeps the locked descriptor alive for the life of the
// process. The flock is tied to the open file description, so the handle must
// outlive acquisition — dropping it would release the lock at the next GC and
// re-open the window this file exists to close. Released by the kernel on exit.
var dataDirWriterLockHandle *os.File

// dataDirWriterLockNotice carries an undetermined verdict's cause from the boot
// guard (which runs before the application logger exists) to the first log line
// after initLogger. Empty when there is nothing to report.
var dataDirWriterLockNotice string

// acquireDataDirWriterLock takes the single-writer lock on dir.
//
// It returns the verdict, the lock path it used (empty when it never got that
// far) and the underlying cause for a non-acquiring verdict. It writes nothing
// but the zero-byte lock file itself and never blocks: a live holder is reported
// immediately rather than waited for, because waiting would turn a
// misconfiguration into a hang.
func acquireDataDirWriterLock(dir string) (dataDirWriterVerdict, string, error) {
	if dir == "" {
		return dataDirWriterUndetermined, "", errors.New("no persisted-state root configured")
	}
	// The data root may not exist yet on a genuine fresh install, and the guard
	// runs long before the statement that would otherwise create it (initPAC →
	// loadPAC's own MkdirAll). Opening the lock file first would return ENOENT,
	// degrade, and leave the process holding NOTHING for its whole life — while
	// startup then created the directory, so a second process could take the
	// lock and boot alongside it. On a healthy filesystem. Creating the root
	// here is what makes the guard real on a first boot; a creation that
	// genuinely fails (read-only volume, no permission, a root that is a file)
	// still degrades below, which is the CHAOS-05/07 posture.
	//
	// 0o700 matches loadPAC, the statement that creates this directory today.
	// MkdirAll is a no-op on an existing directory and never changes its mode,
	// so an operator's 0o750 volume is left exactly as it is.
	if err := os.MkdirAll(dir, 0o700); err != nil { // #nosec G304 G703 -- the operator-configured persisted-state root itself; no request input reaches it
		return dataDirWriterUndetermined, filepath.Join(dir, dataDirWriterLockName), err
	}
	path := filepath.Join(dir, dataDirWriterLockName)
	// O_CREATE without O_EXCL by design: the lock file is expected to survive
	// across boots and is meaningless on its own — the flock is the state, the
	// file is only something to hold it on. Mode 0600 matches every other file
	// this process creates on the volume.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 G703 -- operator-configured persisted-state root joined with a compile-time basename; no request input reaches this path
	if err != nil {
		// A read-only or permission-denied volume is an existing, documented
		// degraded mode (CHAOS-05/07), not a reason to refuse a boot that would
		// otherwise serve.
		return dataDirWriterUndetermined, path, err
	}
	held, lockErr := flockExclusiveNonBlocking(f)
	if lockErr != nil {
		_ = f.Close()
		return dataDirWriterUndetermined, path, lockErr
	}
	if !held {
		_ = f.Close()
		return dataDirWriterHeld, path, nil
	}
	dataDirWriterLockHandle = f
	return dataDirWriterAcquired, path, nil
}

// checkDataDirSingleWriter is main's boot guard. It returns a non-nil error
// ONLY for a live holder, so the caller refuses the boot exactly as it does for
// an interrupted restore. Any other outcome records a notice and returns nil.
//
// Position in main is load-bearing: it must run before the first write to the
// volume (initLogger may open and ROTATE a log file on it, and rotation renames
// the inode a live process is still writing to) and after the one-shot commands,
// so --list/--restore/--cleanup-restore-leftovers keep working on an orphaned
// state directory. That is the same slot checkInterruptedRestore occupies, for
// the same reasons.
//
// It also has to run after checkInterruptedRestore specifically, not merely
// near it: acquiring the lock CREATES the data root, and an interrupted restore
// is diagnosed by that root being ABSENT with a `.bak` sibling. Creating it
// first would erase the evidence of the very condition that refusal exists to
// catch. checkInterruptedRestore exits the process, so its refusal is always
// reached first.
func checkDataDirSingleWriter(dir string) error {
	verdict, path, cause := acquireDataDirWriterLock(dir)
	switch verdict {
	case dataDirWriterAcquired:
		dataDirWriterLockNotice = ""
		return nil
	case dataDirWriterHeld:
		if allowMultipleWriters() {
			dataDirWriterLockNotice = fmt.Sprintf(
				"DataDir: WARNING — another Culvert process holds the single-writer lock on %q, but %s is set, so this process is starting anyway. "+
					"Two processes on one data directory overwrite each other's roster, policy, admin settings and config versions, and the second one keeps the "+
					"unauthenticated first-run setup window open. Unset %s and run one process per data directory.",
				path, allowMultipleWritersEnv, allowMultipleWritersEnv)
			return nil
		}
		return fmt.Errorf("%w (%s). Run one Culvert process per data directory: stop the other process, "+
			"or give this one its own volume via CULVERT_DATA_DIR. Two processes on one directory overwrite each "+
			"other's roster, policy, admin settings and config versions. Set %s=1 to start anyway if this lock is "+
			"reported wrongly by your storage",
			errDataDirWriterHeld, path, allowMultipleWritersEnv)
	default:
		dataDirWriterLockNotice = fmt.Sprintf(
			"DataDir: single-writer lock not established on %q (%v); a second Culvert process on this data directory "+
				"would NOT be detected. Run one process per data directory.", path, cause)
		return nil
	}
}

// allowMultipleWriters reports whether the operator set the escape hatch.
func allowMultipleWriters() bool { return os.Getenv(allowMultipleWritersEnv) == "1" }

// logDataDirWriterLockNotice emits the notice recorded by checkDataDirSingleWriter,
// once, now that the application logger exists. A no-op on a clean acquisition.
func logDataDirWriterLockNotice() {
	if dataDirWriterLockNotice == "" {
		return
	}
	logger.Printf("%s", dataDirWriterLockNotice)
	dataDirWriterLockNotice = ""
}
