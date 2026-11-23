package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// upCalls counts the `compose up` calls the agent made.
func (r *crashRig) upCalls() int {
	n := 0
	for _, c := range r.mutatingCalls() {
		if f := strings.Fields(c); len(f) > 3 && f[0] == "compose" && f[3] == "up" {
			n++
		}
	}
	return n
}

// TestUpRetry_RecoversACleanupOnlyPass: after a recreate interrupted between
// Compose's stop and its delete, the next `up` only tidies up and exits 0 with
// nothing running. The rollback must notice from Docker that no proxy is
// running and run `up` once more, instead of failing its health gate and
// leaving the proxy down until a second rollback is submitted.
func TestUpRetry_RecoversACleanupOnlyPass(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	r.crashAt("up_before:1")
	r.start()
	// The state the crash left: the proxy is not running, and Compose's next
	// pass will be clean-up only.
	if err := os.Remove(filepath.Join(r.model, "running")); err != nil {
		t.Fatal(err)
	}
	r.put("up_cleanup_only", "1")
	r.clearCalls()

	op := r.rollbackToA()
	done := r.waitOp(op)
	if done.State != "succeeded" {
		t.Fatalf("rollback = %s(%s); agent output:\n%s\nop log:\n%s", done.State, done.FailureReason, r.logs.String(), r.opLogs(op))
	}
	if n := r.upCalls(); n != 2 {
		t.Errorf("`compose up` ran %d times, want 2 (the clean-up-only pass and one retry)", n)
	}
	if r.read("pinned") != imgA || r.read("running") != imgA {
		t.Errorf("after rollback: tag %.8s container %.8s, want both on the prior image", r.read("pinned"), r.read("running"))
	}
	if logs := r.opLogs(op); !strings.Contains(logs, "running `up` again (1/1)") {
		t.Errorf("the operation log does not record the retry:\n%s", logs)
	}
	if files := r.waitJournal(); len(files) != 0 {
		t.Errorf("journal still holds %v after the rollback succeeded", files)
	}
}

// TestUpRetry_IsBounded: if `up` keeps exiting 0 with nothing running, the
// agent retries once and then lets the health gate fail the operation. It does
// not loop, does not report success, and keeps the interrupted record.
func TestUpRetry_IsBounded(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	r.crashAt("up_before:1")
	r.start()
	if err := os.Remove(filepath.Join(r.model, "running")); err != nil {
		t.Fatal(err)
	}
	r.put("up_cleanup_only", "5")
	r.clearCalls()

	done := r.waitOp(r.rollbackToA())
	if done.State != "failed" {
		t.Fatalf("rollback = %s, want failed: nothing was ever running", done.State)
	}
	if n := r.upCalls(); n != 2 {
		t.Errorf("`compose up` ran %d times, want exactly 2 (one retry, then stop)", n)
	}
	if files := r.journalFiles(); len(files) == 0 {
		t.Error("the interrupted record was retired although the rollback failed")
	}
}

// psCalls counts the `compose ps` reads the agent made.
func (r *crashRig) psCalls() int {
	n := 0
	for _, line := range strings.Split(r.read("calls.log"), "\n") {
		if f := strings.Fields(line); len(f) > 3 && f[0] == "compose" && f[3] == "ps" {
			n++
		}
	}
	return n
}

// TestUpRetry_OrdinaryUpgradeIsUnchanged: with nothing interrupted on record,
// an upgrade makes exactly the docker calls it always made: one `up`, and no
// extra read after it. (Even when that `up` starts nothing: outside a recovery
// the health gate alone decides, as before.)
func TestUpRetry_OrdinaryUpgradeIsUnchanged(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	r.clearCalls()
	if d := r.waitOp(r.applyUpgrade()); d.State != "succeeded" {
		t.Fatalf("upgrade = %s(%s)", d.State, d.FailureReason)
	}
	if n := r.upCalls(); n != 1 {
		t.Errorf("`compose up` ran %d times on a healthy upgrade, want 1", n)
	}
	// capture_before, the capture after `up`, verify.
	if n := r.psCalls(); n != 3 {
		t.Errorf("`compose ps` ran %d times on a healthy upgrade, want 3 (no read was added)", n)
	}
}
