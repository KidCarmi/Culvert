//go:build unix

package main

import "golang.org/x/sys/unix"

// rosterParentAccess checks, without side effects, that this process may
// create and rename entries in dir: faccessat(W_OK|X_OK) with AT_EACCESS, so
// the EFFECTIVE uid and gid are checked against the mode bits and any ACL.
// It also fails with EROFS on a read-only mount. A seam only for tests,
// which run as root and inject the EACCES a revoked ACL gives.
var rosterParentAccess = func(dir string) error {
	return unix.Faccessat(unix.AT_FDCWD, dir, unix.W_OK|unix.X_OK, unix.AT_EACCESS)
}

// rosterParentReadOnly reports whether dir's filesystem is mounted read-only
// (statfs; roster_statfs_*.go). A seam only for tests. An error, or a
// platform without the flag, is "not known read-only": faccessat already
// reports EROFS, so this is a second, independent signal.
var rosterParentReadOnly = statfsReadOnly

// probeRosterParent reports whether the next save can create its temp file in
// dir and rename it over the roster: rosterParentNotWritable when faccessat
// refuses (mode bits, ACL, effective uid, a read-only mount — any error is
// doubt, and doubt is not ok) or statfs reports a read-only mount; "" when
// both allow it. The sticky-directory owner case is decided per target in
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
