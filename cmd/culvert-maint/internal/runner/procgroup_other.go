//go:build !linux

package runner

import (
	"os/exec"
	"syscall"
)

// setProcGroup is a no-op off Linux: process-group semantics (Setpgid) are a
// Unix concept and the maintenance agent only runs Docker host operations on
// Linux. Non-Linux builds exist for compilation/tests only, where signaling the
// single process is sufficient.
func setProcGroup(_ *exec.Cmd) {}

// killProcGroup falls back to signaling the single process off Linux (no group
// semantics). No-op if the process never started.
func killProcGroup(cmd *exec.Cmd, sig syscall.Signal) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Signal(sig)
}
