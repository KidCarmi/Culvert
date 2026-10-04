//go:build linux

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Models systemctl accepting an asynchronous shutdown and the helper exiting:
// the flock is free, but this boot must admit no further mutating operation.
func TestHostLock_PendingShutdownSurvivesHelperExit(t *testing.T) {
	for _, phase := range []string{"pending", "aborted"} {
		t.Run(phase, func(t *testing.T) {
			rig := startApplyRig(t)
			defer rig.stop()
			release, busy, err := acquireHostMaintenanceLock(rig.stateDir)
			if err != nil || busy {
				t.Fatalf("take maintenance lock: %v busy=%v", err, busy)
			}
			t.Cleanup(release)
			boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(rig.stateDir, shutdownFenceName)
			data := "culvert-shutdown-v1 " + strings.TrimSpace(string(boot)) + " reboot " + phase + "\n"
			// #nosec G306 -- mirrors the root-created fence readable by the agent.
			if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
			release()
			status, body := rig.post(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
			if status != http.StatusConflict || !strings.Contains(string(body), "host_maintenance_in_progress") {
				t.Fatalf("fenced request admitted: %d %s", status, body)
			}
			if rig.sawCommand("pull") || rig.sawCommand("up") {
				t.Fatal("fenced admission touched Docker")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew}); op["state"] != "succeeded" {
				t.Fatalf("cleared fence should permit admission: %+v", op)
			}
		})
	}
}

func TestHostLock_StaleShutdownFenceClearedUnderLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, shutdownFenceName)
	// #nosec G306 -- mirrors the root-created fence readable by the agent.
	if err := os.WriteFile(path, []byte("culvert-shutdown-v1 00000000-0000-0000-0000-000000000000 poweroff pending\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	release, busy, err := acquireHostMaintenanceLock(dir)
	if err != nil || busy {
		t.Fatalf("stale fence blocked new boot: %v busy=%v", err, busy)
	}
	defer release()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("stale fence not removed: %v", err)
	}
	if _, busy, err := acquireHostMaintenanceLock(dir); err != nil || !busy {
		t.Fatalf("stale cleanup released serialization: %v busy=%v", err, busy)
	}
}

func TestHostLock_UnsafeShutdownFenceRefuses(t *testing.T) {
	for _, kind := range []string{"malformed", "oversized", "symlink", "fifo", "writable"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, shutdownFenceName)
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(path, path)
			case "fifo":
				err = syscall.Mkfifo(path, 0o600)
			case "oversized":
				// #nosec G306 -- malformed public fence fixture, no private data.
				err = os.WriteFile(path, []byte(strings.Repeat("x", 129)), 0o644)
			default:
				// #nosec G306 -- malformed public fence fixture, no private data.
				err = os.WriteFile(path, []byte("malformed\n"), 0o644)
				if kind == "writable" && err == nil {
					err = os.Chmod(path, 0o666)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if release, busy, err := acquireHostMaintenanceLock(dir); err == nil || busy || release != nil {
				t.Fatalf("unsafe fence treated as available: err=%v busy=%v release=%v", err, busy, release != nil)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			release, busy, err := acquireHostMaintenanceLock(dir)
			if err != nil || busy {
				t.Fatalf("failed fence read leaked lock: %v busy=%v", err, busy)
			}
			release()
		})
	}
}

// While culvert-os-update holds the shared host maintenance lock, no
// state-changing agent op may be admitted (Codex P1, PR #1528).
func TestHostLock_RefusesAdmissionWhileOSMaintenanceHoldsIt(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	release, busy, err := acquireHostMaintenanceLock(rig.stateDir) // stands in for culvert-os-update
	if err != nil || busy {
		t.Fatalf("test could not take the lock: busy=%v err=%v", busy, err)
	}
	status, body := rig.post(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	var out map[string]interface{}
	_ = json.Unmarshal(body, &out)
	if status != http.StatusConflict || out["error"] != "host_maintenance_in_progress" {
		t.Fatalf("admission during OS maintenance: %d %s", status, body)
	}
	if rig.sawCommand("pull") || rig.sawCommand("up") {
		t.Fatal("a refused op must not touch Docker")
	}
	release()
	// CONTROL: once OS maintenance is done the same request is admitted.
	if op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew}); op["state"] != "succeeded" {
		t.Fatalf("after release the upgrade must run: %+v", op)
	}
}

// The other direction: while an agent op runs, the lock is held, so
// culvert-os-update's flock -n fails; it is released when the op ends.
func TestHostLock_HeldForTheWholeOperation(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.blockUp = make(chan struct{})
	status, body := rig.post(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if status != http.StatusAccepted {
		t.Fatalf("apply: %d %s", status, body)
	}
	var ack map[string]interface{}
	_ = json.Unmarshal(body, &ack)
	deadline := time.Now().Add(5 * time.Second)
	for !rig.sawCommand("up") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if _, busy, _ := acquireHostMaintenanceLock(rig.stateDir); !busy {
		t.Fatal("the lock must be held while the op is running (os-update would not see it)")
	}
	close(rig.blockUp)
	rig.waitOp(t, ack["op_id"].(string))
	var release func()
	for i := 0; i < 100; i++ { // the goroutine releases just after the flow returns
		var busy bool
		if release, busy, _ = acquireHostMaintenanceLock(rig.stateDir); !busy {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if release == nil {
		t.Fatal("the lock must be released when the op ends")
	}
	release()
}

// An indeterminate lock (the file cannot be opened) must refuse, not admit
// with only the in-memory lock (Codex P1, PR #1528). A self-referential
// symlink fails open(2) with ELOOP even for root, so the gate does not
// depend on file permissions.
func TestHostLock_UnopenableLockRefusesAdmission(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	lockPath := filepath.Join(rig.stateDir, hostMaintenanceLockName)
	if err := os.Symlink(lockPath, lockPath); err != nil {
		t.Fatal(err)
	}
	status, body := rig.post(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	var out map[string]interface{}
	_ = json.Unmarshal(body, &out)
	if status != http.StatusServiceUnavailable || out["error"] != "host_maintenance_lock_unavailable" {
		t.Fatalf("admission with an unopenable host lock: %d %s", status, body)
	}
	if rig.sawCommand("pull") || rig.sawCommand("up") {
		t.Fatal("a refused op must not touch Docker")
	}
	// CONTROL: a sound lock file admits the same request.
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew}); op["state"] != "succeeded" {
		t.Fatalf("with a sound lock the upgrade must run: %+v", op)
	}
}
