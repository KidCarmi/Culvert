//go:build linux

package runner

import (
	"os/exec"
	"syscall"
)

// setProcGroup puts the child into its own process group (Setpgid), so the
// child's PID becomes the process-group ID. Every descendant it spawns — the
// real `docker` / `docker compose` process behind the `sudo` wrapper, plus any
// buildkit grandchildren — inherits that group. Signaling the group (see
// killProcGroup) then reaches the whole tree, not just the sudo wrapper.
func setProcGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killProcGroup sends sig to the entire process group led by cmd's child
// (negative PID → the group). This is what prevents an orphaned, stack-mutating
// `docker compose up` from surviving a stage timeout and racing a subsequent
// rollback (C-H3): the sudo wrapper is not the only target — its docker child
// dies too. No-op if the process never started (test hooks / start failure).
func killProcGroup(cmd *exec.Cmd, sig syscall.Signal) error {
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		return nil
	}
	// Negative PID targets the process group whose PGID == the child PID.
	return syscall.Kill(-cmd.Process.Pid, sig)
}
