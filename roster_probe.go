package main

// roster_probe.go — the admin_roster_durability row's ONE live filesystem
// probe (Codex P2s 4319224642 and 4319224648 on PR #1601).
//
// The row used to combine past write evidence with piecemeal live checks: a
// stat of the target, a stat of its parent when it was missing, an identity
// read. Each ran per request on the caller's goroutine, so a stalled NFS or
// FUSE mount added one more blocked goroutine per request; and none of them
// re-checked whether the directory still lets this process create and rename
// the save's temp file, so a chmod 0555, an ACL revocation or a read-only
// remount after the last landed write still read "persisting".
//
// Now every filesystem access the row makes is in probeRosterTarget and the
// probeRoster* helpers it calls (pinned by
// TestWall_RosterRowFilesystemAccessIsOnlyInTheProbe):
//
//   - the target's stat (regular file, or absent under an existing directory);
//   - the parent directory's write capability, live and without side effects
//     (probeRosterParent: faccessat(W_OK|X_OK, AT_EACCESS) for mode bits,
//     ACLs and the effective uid, and statfs for a read-only mount; no probe
//     file is ever created, because a diagnostic must not write);
//   - the identity read: size, SHA-256 and owner against what Culvert last
//     wrote, with the sticky-directory owner logic (roster_disk_identity.go).
//
// The probe is coalesced and bounded (sharedRosterProbe): it runs on its own
// goroutine, at most one at a time however many requests arrive; a result is
// reused for rosterProbeTTL while the write generation is unchanged; and
// each caller waits at most rosterProbeWait, after which the row reports the
// storage as not responding — persistence not verified, never ok — and
// returns without starting another probe. No roster lock is held during the
// probe: the identity result is accepted only if the write generation did
// not move (retried once, then "in flux").

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// rosterProbeResult is everything the row learns from the filesystem.
type rosterProbeResult struct {
	statProblem   string            // the target or its directory is unusable ("" when usable)
	missing       bool              // the target is absent under an existing directory
	parentProblem string            // rosterParentNotWritable, or ""
	disk          rosterDiskVerdict // the identity read's verdict
	diskErr       error             // the identity read failed
}

var (
	// rosterProbeTTL is how long a completed probe answers for an unchanged
	// write generation, so polling does not re-probe.
	rosterProbeTTL = 5 * time.Second
	// rosterProbeWait bounds how long a request waits for the shared probe.
	rosterProbeWait = 2 * time.Second
)

// Filesystem seams, only for tests: they block or fail these calls to stand
// in for a stalled volume, a revoked ACL or a read-only remount.
var (
	rosterProbeStat    = os.Stat
	rosterIdentityOpen = func(path string) (*os.File, error) {
		// O_NONBLOCK: the path is not trusted to still be a regular file.
		return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) // #nosec G304 -- operator-configured -ui-users-file path
	}
)

// rosterProbeFlight holds the one probe in flight and the last completed one.
var rosterProbeFlight struct {
	mu      sync.Mutex
	pending *rosterProbeCall
	cached  *rosterProbeCall
}

type rosterProbeCall struct {
	c    *Config
	path string
	gen  uint64 // write generation when the probe started
	at   time.Time
	done chan struct{}
	res  rosterProbeResult
}

// sharedRosterProbe returns the live probe of the roster at path, and false when
// the storage did not answer within rosterProbeWait (or the one probe slot is
// busy with another roster). It never blocks on the filesystem itself.
func (c *Config) sharedRosterProbe(path string) (rosterProbeResult, bool) {
	gen := c.uiUsersWriteGen.Load()
	f := &rosterProbeFlight
	f.mu.Lock()
	if k := f.cached; k != nil && k.c == c && k.path == path && k.gen == gen && time.Since(k.at) < rosterProbeTTL {
		f.mu.Unlock()
		return k.res, true
	}
	call := f.pending
	if call == nil {
		call = &rosterProbeCall{c: c, path: path, gen: gen, done: make(chan struct{})}
		f.pending = call
		go c.runRosterProbe(call)
	}
	f.mu.Unlock()
	timer := time.NewTimer(rosterProbeWait)
	defer timer.Stop()
	select {
	case <-call.done:
		if call.c != c || call.path != path {
			return rosterProbeResult{}, false
		}
		return call.res, true
	case <-timer.C:
		return rosterProbeResult{}, false
	}
}

// runRosterProbe is the probe goroutine: the only one that touches the
// filesystem for the row.
func (c *Config) runRosterProbe(call *rosterProbeCall) {
	call.res = c.genCheckedRosterProbe(call.path)
	call.at = time.Now()
	f := &rosterProbeFlight
	f.mu.Lock()
	f.pending, f.cached = nil, call
	f.mu.Unlock()
	close(call.done)
}

// genCheckedRosterProbe runs probeRosterTarget with the identity snapshot it
// compares against, and accepts its identity verdict only if no Culvert write
// moved the generation meanwhile (retried once; then "in flux", which is
// rosterDiskSame).
func (c *Config) genCheckedRosterProbe(path string) rosterProbeResult {
	var res rosterProbeResult
	for attempt := 0; attempt < 2; attempt++ {
		gen := c.uiUsersWriteGen.Load()
		c.mu.RLock()
		d := c.uiUsersWritten
		c.mu.RUnlock()
		res = probeRosterTarget(path, d) // all of the row's disk I/O; no lock held
		if gen%2 == 0 && c.uiUsersWriteGen.Load() == gen {
			return res
		}
	}
	res.disk, res.diskErr = rosterDiskSame, nil // in flux: Culvert itself is writing it
	return res
}

// probeRosterTarget is the row's ONLY filesystem access (with the
// probeRoster* helpers below). READ-ONLY: it stats, checks access, and reads;
// it never creates, opens for writing or modifies anything.
func probeRosterTarget(path string, d rosterWrittenDigest) rosterProbeResult {
	var res rosterProbeResult
	dir := filepath.Dir(path)
	fi, err := rosterProbeStat(path)
	di, dirErr := rosterProbeStat(dir)
	switch {
	case err == nil && !fi.Mode().IsRegular():
		res.statProblem = "the configured roster path is not a regular file"
		return res
	case err != nil && !os.IsNotExist(err):
		res.statProblem = "the configured roster path cannot be inspected"
		return res
	case dirErr != nil || !di.IsDir():
		if err != nil {
			res.statProblem = "the configured roster file's parent directory does not exist"
		} else {
			res.statProblem = "the configured roster file's directory cannot be inspected"
		}
		return res
	}
	res.missing = err != nil
	res.parentProblem = probeRosterParent(dir)
	if !res.missing {
		res.disk, res.diskErr = probeRosterIdentity(path, d, di)
	}
	return res
}

// probeRosterIdentity compares the file at path with d (roster_disk_identity.go).
// dir is the probe's stat of its parent, for the sticky-directory owner logic.
func probeRosterIdentity(path string, d rosterWrittenDigest, dir os.FileInfo) (rosterDiskVerdict, error) {
	if d.path == "" || d.path != path {
		return rosterDiskSame, nil
	}
	f, err := rosterIdentityOpen(path)
	if err != nil {
		return rosterDiskSame, err
	}
	defer func() { _ = f.Close() }() // #nosec G104 -- read-only handle
	fi, err := f.Stat()
	if err != nil {
		return rosterDiskSame, err
	}
	if !fi.Mode().IsRegular() || fi.Size() != d.size {
		return rosterDiskReplaced, nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, d.size+1)); err != nil {
		return rosterDiskSame, err
	}
	if !bytes.Equal(h.Sum(nil), d.sum[:]) {
		return rosterDiskReplaced, nil
	}
	if now := ownerOf(fi); d.owner.known && now.known && now.uid != d.owner.uid && renameLikelyRefused(dir, nil, now) {
		return rosterDiskOwnerChanged, nil
	}
	return rosterDiskSame, nil
}
