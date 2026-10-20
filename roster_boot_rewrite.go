package main

// roster_boot_rewrite.go — exact write evidence for the admin_roster_durability
// row (Codex P2s on PR #1601).
//
// Boot only READS ui_users.json, and every check that stops short of a real
// write to the real file can be fooled: a stat passes on a read-only mount,
// and a scratch-file create+rename test passes in a sticky (1777) or
// ACL-restricted directory where the roster belongs to another user — the
// rename over THAT file is the one step refused (EPERM), so the first admin
// mutation would be refused while the row read "persisting to disk".
//
// So LoadUIUsersFile writes the roster back once, in place, with the exact
// bytes it just parsed and the file's own mode, owner and group, through
// fileutil.RewriteInPlace. Its outcome is the row's evidence.
//
// The rewrite must never destroy content it did not load (Codex P2
// 4315243806 on PR #1601). saveUIUsersMu serialises only Culvert's own
// writers; an external one (a configuration manager, an operator) can replace
// the file after checkRosterUnchanged, and a rename would then silently put
// the older bytes back — undoing a credential rotation, role change or
// revocation. So RewriteInPlace EXCHANGES its temp file with the roster
// (Linux renameat2 RENAME_EXCHANGE), compares what it displaced with what was
// loaded, and swaps a mismatch straight back (ErrConcurrentChange; if that
// fails, the newer content is left in the temp file and ErrExchangeBackFailed
// names it). The exchange is subject to rename(2)'s permission checks on the
// roster, so a refusal is still the evidence a save would be refused. Where
// there is no exchange (non-Linux, or a kernel or filesystem without it) it
// writes nothing (ErrRewriteUnsupported) and the row stays "not verified"
// until the first save lands.
//
// The rewrite must not change the roster's metadata either (Codex P2s on PR
// #1601): RewriteInPlace gives the replacement the roster's owner, group,
// full mode (setuid, setgid and sticky included) and every extended attribute
// (POSIX ACL, SELinux label, user.*), requires matching inode flags, verifies
// all of it before the exchange and compares it after; the complete list,
// and what is not preserved (timestamps), is its contract. If any of it
// cannot be kept (an unprivileged process cannot give the replacement to
// another account) it replaces nothing (ErrMetadataNotPreservable) and the
// row stays "not verified" the same way. An immutable or append-only roster
// is a plain write refusal: no save can replace it.
//
// Exact bytes
// rather than SaveUIUsersFile's re-serialisation, because that is not a pure
// normalisation: it reorders accounts (map iteration), drops unknown fields,
// converts a legacy bare-array file to the envelope, adds default_auth_outcome
// and forces mode 0600. None of that may happen to an operator's file just
// because the process started.
//
// What the rewrite deliberately does NOT do, because it is not an admin
// mutation: no audit entry, no configuration version, no refused/degraded or
// not-durable counter, no auth-cache invalidation beyond the load's own, and
// no fileutil write-observer notification (see fileutil.RewriteInPlace — a
// failure would otherwise be logged as lost persisted state and consume the
// storage_write_failed alert gate before the webhooks are even loaded). It
// fires no alert of its own either: the row reports the state, and the one log
// line below says what to fix.
//
// On Linux the file gets a new inode and mtime at every boot (as at every
// save). Its content, owner, group, mode, inode flags and extended attributes
// do not change.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// loadedRosterFile is what LoadUIUsersFile parsed: the exact bytes and the
// FileInfo of the open file they were read from.
type loadedRosterFile struct {
	data []byte
	info os.FileInfo
}

var (
	// errRosterIsSymlink: a save renames over the LINK, replacing it with a
	// regular file, so the boot rewrite refuses to do that on the operator's
	// behalf and the row reports the path instead.
	errRosterIsSymlink = errors.New("the roster path is a symbolic link")
	// errRosterChangedDuringLoad: the file at path is no longer the one that
	// was read, so writing the old bytes back would clobber someone's change.
	errRosterChangedDuringLoad = errors.New("the roster file changed on disk while it was being loaded")
)

// rosterRewriteInPlace is the boot rewrite's write step. A package-level seam
// so a test can inject the refusal a non-owner gets in a sticky directory or
// on a read-only mount (CI runs as root, which bypasses both), an unsupported
// exchange, or an external write that lands just before the real one.
var rosterRewriteInPlace = fileutil.RewriteInPlaceUnless

// readRosterFile reads path and the FileInfo of exactly the file it read.
func readRosterFile(path string) (*loadedRosterFile, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-configured -ui-users-file path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // #nosec G104 -- read-only handle
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return &loadedRosterFile{data: data, info: info}, nil
}

// rewriteLoadedRoster writes loaded back onto path and returns the outcome
// the durability row records. ErrReplacedNotSynced counts as landed, exactly
// as it does for an admin mutation: the exchange happened. Any other outcome
// is logged once (LoadUIUsersFile runs once per configured path) and never
// stops boot.
//
// abandoned (nil: never) is the background rewrite's give-up signal
// (bootRewriteRoster). ErrReplacedNotSynced is returned as is: the rewrite
// landed, and the caller records that its directory was not synced. The two
// outcomes that name a preserved recovery file are always logged, even when
// the rewrite was abandoned meanwhile.
func rewriteLoadedRoster(path string, loaded *loadedRosterFile, abandoned func() bool) error {
	err := checkRosterUnchanged(path, loaded)
	if err == nil {
		err = rosterRewriteInPlace(path, loaded.data, loaded.info, abandoned)
	}
	superseded := abandoned != nil && abandoned()
	switch {
	case err == nil:
	case errors.Is(err, fileutil.ErrExchangeBackFailed):
		logRosterBootRewrite("CHANGED ON DISK during the startup rewrite, and the newer file could NOT be "+
			"restored to the roster path: it is preserved at the temporary path in this message, and the roster "+
			"file and the roster in use are the OLDER version. Make no admin account changes; move the preserved "+
			"file over the roster path and restart", path, err)
	case errors.Is(err, fileutil.ErrRestoreNotSynced):
		logRosterBootRewrite("CHANGED ON DISK during the startup rewrite; the newer file was restored to the "+
			"roster path, but the restore could not be synced to disk, so a crash could revert it. The entry the "+
			"restore displaced is kept at the temporary path in this message: keep it until a restart has loaded "+
			"the roster file as it now is", path, err)
	case superseded, errors.Is(err, fileutil.ErrRewriteAbandoned):
		// Culvert's own save took over, or the deadline passed (logged by
		// bootRewriteRoster): not an operator problem.
		if !errors.Is(err, fileutil.ErrRewriteAbandoned) {
			err = fmt.Errorf("%w (%w)", fileutil.ErrRewriteAbandoned, err)
		}
	case errors.Is(err, fileutil.ErrReplacedNotSynced):
		logRosterBootRewrite("rewritten in place at startup, but its directory could not be fsynced afterward", path, err)
	case errors.Is(err, fileutil.ErrRewriteUnsupported):
		logRosterBootRewrite("was not rewritten in place at startup: this platform or filesystem has no atomic "+
			"exchange, and a plain replace could destroy a concurrent change, so whether admin account changes "+
			"can be saved is unverified until the first one is", path, err)
	case errors.Is(err, fileutil.ErrMetadataNotPreservable):
		logRosterBootRewrite("was not rewritten in place at startup: its owner, group, mode, inode flags, "+
			"extended attributes or ACL could not be kept exactly on the replacement, and a rewrite must not change "+
			"the file's metadata, so nothing was replaced and whether admin account changes can be saved is unverified until the first one is",
			path, err)
	case errors.Is(err, fileutil.ErrConcurrentChange), errors.Is(err, errRosterChangedDuringLoad):
		logRosterBootRewrite("changed on disk while it was loaded at startup; the newer file was kept and "+
			"the rewrite is not verified. The roster in use predates that change: restart to load it, and make "+
			"no admin account change until then (saving one would overwrite it)", path, err)
	default:
		logRosterBootRewrite("loaded, but could not be rewritten in place at startup — it is in use read-only, "+
			"and every admin account change will be REFUSED until the path or its permissions are fixed "+
			"and the process restarted", path, err)
	}
	return err
}

// checkRosterUnchanged confirms that path is not a symlink and still names the
// very file loaded was read from.
func checkRosterUnchanged(path string, loaded *loadedRosterFile) error {
	cur, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat before rewrite: %w", err)
	}
	if cur.Mode()&os.ModeSymlink != 0 {
		return errRosterIsSymlink
	}
	if !os.SameFile(cur, loaded.info) || cur.Size() != loaded.info.Size() ||
		!cur.ModTime().Equal(loaded.info.ModTime()) {
		return errRosterChangedDuringLoad
	}
	return nil
}

func logRosterBootRewrite(what, path string, err error) {
	if logger == nil {
		return
	}
	logger.Printf("UIUsers: admin roster %q %s: %q", sanitizeLog(path), what, sanitizeLog(err.Error()))
}

// rosterBootRewriteWait bounds how long LoadUIUsersFile waits for the boot
// rewrite (Codex P1 4319946910 on PR #1601). A var only so tests can shorten
// it.
var rosterBootRewriteWait = 3 * time.Second

// errRosterRewriteSlow is the recorded evidence when the boot rewrite did not
// finish within rosterBootRewriteWait: startup went on, the rewrite was
// abandoned, and nothing about the target is proven.
var errRosterRewriteSlow = errors.New("the startup rewrite did not finish in time (slow or stalled storage) and was abandoned")

// bootRewriteRoster runs the boot rewrite of loaded on its own goroutine,
// without saveUIUsersMu, and waits for it at most rosterBootRewriteWait.
//
//   - Finished in time: its outcome is the recorded evidence, as before.
//   - Deadline passed: the evidence is errRosterRewriteSlow ("not verified,
//     storage slow"), startup continues, and the rewrite is ABANDONED: it
//     checks the flag before its exchange (fileutil.RewriteInPlaceUnless),
//     removes its temp file and never exchanges. The one window that cannot
//     be closed is an exchange syscall already in flight when the deadline
//     fires; it carries the roster's own loaded bytes and metadata and still
//     goes through the compare and swap-back. Its late outcome is logged but
//     never recorded over the "slow" evidence.
//   - A Culvert roster write meanwhile (a save, or SetUIUsersFile): the write
//     generation moves, the rewrite abandons itself, and the save's own
//     evidence stands — the save always wins.
func (c *Config) bootRewriteRoster(path string, loaded *loadedRosterFile) {
	c.beginRosterWrite()
	gen := c.uiUsersWriteGen.Load() // after our own begin: any later move is someone else
	var timedOut atomic.Bool
	abandoned := func() bool { return timedOut.Load() || c.uiUsersWriteGen.Load() != gen }
	var outcome struct {
		sync.Mutex
		finished, timedOut bool
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer c.endRosterWrite()
		err := rewriteLoadedRoster(path, loaded, abandoned)
		outcome.Lock()
		defer outcome.Unlock()
		if outcome.timedOut {
			return // the evidence already says "slow"; a late outcome is only logged
		}
		outcome.finished = true
		c.recordBootRewrite(path, loaded, gen, err)
	}()
	timer := time.NewTimer(rosterBootRewriteWait)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
	}
	outcome.Lock()
	defer outcome.Unlock()
	if outcome.finished {
		return
	}
	outcome.timedOut = true
	timedOut.Store(true)
	logRosterBootRewrite(fmt.Sprintf("was not rewritten in place within %v at startup (slow or stalled "+
		"storage); startup continues, the rewrite is abandoned, and whether admin account changes can be "+
		"saved is unverified until one is", rosterBootRewriteWait), path, errRosterRewriteSlow)
	c.recordBootRewrite(path, loaded, gen, errRosterRewriteSlow)
}

// recordBootRewrite records the boot rewrite's outcome as the row's evidence,
// unless a Culvert write took over since it began (its own evidence stands)
// or the path was re-pointed. ErrReplacedNotSynced is a landed rewrite whose
// directory could not be synced.
func (c *Config) recordBootRewrite(path string, loaded *loadedRosterFile, gen uint64, err error) {
	if errors.Is(err, fileutil.ErrRewriteAbandoned) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.uiUsersFile != path || c.uiUsersWriteGen.Load() != gen {
		return
	}
	landed := err == nil || errors.Is(err, fileutil.ErrReplacedNotSynced)
	c.uiUsersWriteTried, c.uiUsersWriteErr = true, err
	c.uiUsersWritten, c.uiUsersWriteSynced = rosterWrittenDigest{}, false
	if landed {
		// The rewrite put exactly the loaded bytes, with the file's own
		// metadata, on disk.
		c.uiUsersWriteErr = nil
		c.uiUsersWritten = digestRosterWrite(path, loaded.data, ownerOf(loaded.info))
		c.uiUsersWriteSynced = err == nil
	}
}
