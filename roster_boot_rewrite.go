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
// bytes it just parsed and the file's own mode (owner and group preserved
// where the process may set them), through fileutil.RewriteInPlace — the
// AtomicWrite sequence itself. Its outcome is the row's evidence. Exact bytes
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
// The file gets a new inode and mtime at every boot (as at every save). Its
// content and permission bits do not change.

import (
	"errors"
	"fmt"
	"io"
	"os"

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
// on a read-only mount: CI runs as root, which bypasses both.
var rosterRewriteInPlace = fileutil.RewriteInPlace

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
// as it does for an admin mutation: the rename happened. A failure is logged
// once (LoadUIUsersFile runs once per configured path) and never stops boot.
func rewriteLoadedRoster(path string, loaded *loadedRosterFile) error {
	err := checkRosterUnchanged(path, loaded)
	if err == nil {
		err = rosterRewriteInPlace(path, loaded.data, loaded.info)
	}
	if errors.Is(err, fileutil.ErrReplacedNotSynced) {
		logRosterBootRewrite("rewritten in place at startup, but its directory could not be fsynced afterward", path, err)
		return nil
	}
	if err != nil {
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
