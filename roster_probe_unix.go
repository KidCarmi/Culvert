//go:build unix

package main

import "golang.org/x/sys/unix"

// rosterParentAccess checks, without side effects, the mode bits and ACL
// that govern creating and renaming entries in dir: faccessat(W_OK|X_OK) with
// AT_EACCESS, so the EFFECTIVE uid and gid are checked. It also fails with
// EROFS on a read-only mount. A seam only for tests, which run as root and
// inject the EACCES a revoked ACL gives.
//
// ADVISORY (Codex P2 4326010251 on PR #1601): a refusal is a problem worth
// reporting, but a pass authorises nothing. The kernel checks access(2)
// against DAC and ACLs, not the operation-specific MAC permissions a save
// needs (SELinux add_name/remove_name on dir, AppArmor), and a server-side
// NFSv4 ACL or a quota is decided only when the save happens. No read-only
// probe can authorise those without performing the operation, and a
// self-test write is what this PR removed. So the row never reads a pass as
// capability: its ok states the evidence of the last landed write
// (rosterDurabilityLandedOK), and a refused save reports itself through the
// refused/degraded counters on the next read.
var rosterParentAccess = func(dir string) error {
	return unix.Faccessat(unix.AT_FDCWD, dir, unix.W_OK|unix.X_OK, unix.AT_EACCESS)
}

// rosterParentReadOnly reports whether dir's filesystem is mounted read-only
// (statfs; roster_statfs_*.go). A seam only for tests. An error, or a
// platform without the flag, is "not known read-only": faccessat already
// reports EROFS, so this is a second, independent signal.
var rosterParentReadOnly = statfsReadOnly

// probeRosterParent reports the problems it can see with the next save
// creating its temp file in dir and renaming it over the roster (advisory;
// see rosterParentAccess): rosterParentNotWritable when faccessat
// refuses (mode bits, ACL, effective uid, a read-only mount — any error is
// doubt, and doubt is not ok) or statfs reports a read-only mount; "" when
// neither sees a problem, which is not a claim that the save is authorised.
// The sticky-directory owner case is decided per target in
// probeRosterIdentity. It creates nothing: a diagnostic must not write.
func probeRosterParent(dir string) string {
	if err := rosterParentAccess(dir); err != nil {
		return rosterParentNotWritable
	}
	if ro, err := rosterParentReadOnly(dir); err == nil && ro {
		return rosterParentNotWritable
	}
	return ""
}
