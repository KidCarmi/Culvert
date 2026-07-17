//go:build linux

package runner

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestKillProcGroup_ReapsGrandchild is the C-H3 guarantee: killing the process
// group must terminate a grandchild that outlives its parent — the class of
// orphaned, stack-mutating `docker compose up` that would otherwise race a
// rollback. Without Setpgid, signaling only the leader leaves the grandchild
// alive; with it, the whole group dies.
func TestKillProcGroup_ReapsGrandchild(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "grandchild.pid")

	// Parent sh backgrounds a `sleep` grandchild (records its PID), then sleeps
	// itself. The grandchild is in the parent's process group thanks to
	// setProcGroup on the parent.
	cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", "sleep 60 & echo $! > "+pidFile+"; sleep 60") //nolint:gosec // fixed test argv
	setProcGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Skipf("start sh: %v", err)
	}

	// Wait for the grandchild PID to be recorded.
	var gcPID int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(pidFile); err == nil && len(b) > 0 { //nolint:gosec // test path
			if _, err := fmtSscanPID(string(b), &gcPID); err == nil && gcPID > 0 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if gcPID <= 0 {
		_ = killProcGroup(cmd, syscall.SIGKILL)
		_ = cmd.Wait()
		t.Fatal("grandchild PID never recorded")
	}

	// Sanity: the grandchild is alive before we kill the group.
	if err := syscall.Kill(gcPID, 0); err != nil {
		t.Fatalf("grandchild %d not alive pre-kill: %v", gcPID, err)
	}

	// Kill the whole group and reap the leader.
	if err := killProcGroup(cmd, syscall.SIGKILL); err != nil {
		t.Fatalf("killProcGroup: %v", err)
	}
	_ = cmd.Wait()

	// The grandchild must be gone within a short grace period. NOTE: after the
	// group kill the grandchild's parent (the sh leader) is dead too, so the
	// grandchild is reparented and becomes a ZOMBIE until PID 1 reaps it — and
	// kill(pid,0) succeeds for a zombie. In container CI the test is not the
	// reaper, so we must treat zombie state as gone, not just ESRCH.
	gone := false
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if procGone(gcPID) {
			gone = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !gone {
		// Clean up the leaked grandchild so the test host isn't polluted.
		_ = syscall.Kill(gcPID, syscall.SIGKILL)
		t.Errorf("grandchild %d survived the group kill (orphaned — C-H3 not closed)", gcPID)
	}
}

// TestSetProcGroup_SetsPgid pins that setProcGroup requests a new process group.
func TestSetProcGroup_SetsPgid(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "/bin/true") //nolint:gosec // fixed test argv
	setProcGroup(cmd)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Fatal("setProcGroup must set SysProcAttr.Setpgid=true on linux")
	}
}

// procGone reports whether pid is no longer a live process. It is gone if the
// PID is unknown (ESRCH) OR it is a reaped-but-unwaited ZOMBIE — kill(pid,0)
// keeps succeeding for a zombie until PID 1 reaps it, which does not happen
// promptly when the test is not the reaper (container CI), so the /proc state
// is the authoritative signal.
func procGone(pid int) bool {
	if err := syscall.Kill(pid, 0); err != nil {
		return true // ESRCH — no such process
	}
	return procIsZombie(pid)
}

// procIsZombie parses /proc/<pid>/stat and reports whether the process state is
// Z (zombie). A missing /proc entry means it was already reaped → gone.
func procIsZombie(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat") //nolint:gosec // test-controlled pid
	if err != nil {
		return true // /proc entry gone → reaped
	}
	// Format: "pid (comm) STATE ...". comm may contain spaces/parens, so the
	// state is the first field after the LAST ')'.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return false
	}
	return s[i+2] == 'Z'
}

// fmtSscanPID parses a decimal PID (avoids importing fmt just for Sscan in the
// build-tagged test).
func fmtSscanPID(s string, out *int) (int, error) {
	n := 0
	v := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			if n == 0 {
				continue
			}
			break
		}
		v = v*10 + int(c-'0')
		n++
	}
	*out = v
	if n == 0 {
		return 0, os.ErrInvalid
	}
	return n, nil
}
