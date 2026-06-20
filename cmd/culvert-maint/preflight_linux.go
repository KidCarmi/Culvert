//go:build linux

package main

import "syscall"

// dirTraversable reports whether THIS process (the culvert-maint service
// identity) can search/traverse dir — i.e. chdir into it. The runner sets
// cmd.Dir = compose_project_dir BEFORE sudo, so without execute (search)
// permission on dir and every ancestor the very first operation fails with a
// chdir error before sudo is ever reached.
//
// This is an ADVISORY startup probe (fail-soft): the real authority boundary
// is the sudoers allowlist and the actual `docker compose` run, which re-checks
// access at exec time. We only want to surface a clear diagnostic at start.
//
// syscall.Access uses the process's REAL uid/gid — which IS culvert-maint (the
// service never changes uid and is not setuid) — so it answers exactly "can I
// traverse this", honoring group bits (e.g. the hardened 0750 root:culvert-maint
// layout) and ACLs as evaluated by the kernel. We probe X_OK (search) on the
// directory, not R_OK on the compose file: the agent never reads that file
// (docker, under sudo as root, does); it only needs to chdir in.
func dirTraversable(dir string) error {
	const xOK = 0x1 // X_OK — search/execute permission
	return syscall.Access(dir, xOK)
}
