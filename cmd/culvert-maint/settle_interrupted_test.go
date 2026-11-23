package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rollbackToA submits an image rollback to the prior image and returns the op id.
func (r *crashRig) rollbackToA() string {
	r.t.Helper()
	var op opView
	if code := r.post("/v1/rollbacks", map[string]interface{}{"mode": "image", "image_ref": refA}, &op); code != http.StatusAccepted {
		r.t.Fatalf("rollback: HTTP %d", code)
	}
	return op.OpID
}

// tagOrUpCalls returns the docker calls that move the fixed tag or recreate the
// proxy. A pull is not one of them: it changes neither, and the rollback pulls
// before it waits.
func (r *crashRig) tagOrUpCalls() []string {
	var out []string
	for _, c := range r.mutatingCalls() {
		if !strings.HasPrefix(c, "pull ") {
			out = append(out, c)
		}
	}
	return out
}

// opLogs returns the operation's log as text.
func (r *crashRig) opLogs(opID string) string {
	r.t.Helper()
	req, err := http.NewRequestWithContext(r.t.Context(), http.MethodGet, "http://agent/v1/operations/"+opID+"/logs", http.NoBody)
	if err != nil {
		r.t.Fatal(err)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		r.t.Fatalf("op logs: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		r.t.Fatalf("op logs: %v", err)
	}
	return string(b)
}

// TestSettle_RollbackWaitsOutAnInterruptedRecreate: after an agent death
// inside the tag+recreate window, dockerd may still be stopping the old proxy
// container for the dead operation. The next operation must not tag or
// recreate until that request can no longer be pending (agent start +
// interrupted_settle), so that its `up` and health gate judge a container
// nothing outstanding can touch.
func TestSettle_RollbackWaitsOutAnInterruptedRecreate(t *testing.T) {
	const settle = 6 * time.Second
	r := newCrashRig(t)
	r.setSettle(settle.String())
	r.start()
	r.crashAt("up_before:1")  // past the barrier: the dead agent was inside `compose up`
	beforeStart := time.Now() // no later than the new process's start
	r.start()
	r.clearCalls()

	op := r.rollbackToA()

	// Negative control on the wait: well inside the window nothing has been
	// moved, although the operation was admitted at once.
	time.Sleep(time.Second)
	if calls := r.tagOrUpCalls(); len(calls) != 0 {
		t.Fatalf("the rollback tagged or recreated %v after the restart, inside the %v settle window: %v",
			time.Since(beforeStart).Round(time.Millisecond), settle, calls)
	}

	done := r.waitOp(op)
	if done.State != "succeeded" {
		t.Fatalf("rollback = %s(%s); agent output:\n%s", done.State, done.FailureReason, r.logs.String())
	}
	if waited := time.Since(beforeStart); waited < settle {
		t.Errorf("the rollback finished %v after the restart; it must not act before %v", waited, settle)
	}
	if calls := r.tagOrUpCalls(); len(calls) == 0 {
		t.Error("the rollback never tagged or recreated: the wait swallowed the operation")
	}
	if r.read("pinned") != imgA || r.read("running") != imgA {
		t.Errorf("after rollback: tag %.8s container %.8s, want both on the prior image", r.read("pinned"), r.read("running"))
	}
	if files := r.waitJournal(); len(files) != 0 {
		t.Errorf("journal still holds %v after the rollback succeeded", files)
	}
	if logs := r.opLogs(op); !strings.Contains(logs, "settle: waited") {
		t.Errorf("the operation log does not say it waited:\n%s", logs)
	}

	// The window is counted from the agent's start, not from each operation:
	// the next operation finds it over and its log records no wait.
	second := r.rollbackToA()
	if d := r.waitOp(second); d.State != "succeeded" {
		t.Fatalf("second rollback = %s(%s)", d.State, d.FailureReason)
	}
	if logs := r.opLogs(second); strings.Contains(logs, "settle: waited") {
		t.Errorf("an operation after the window waited again:\n%s", logs)
	}
}

// TestSettle_FirstStartOnAStateDirWaits: the wait does not depend on a journal
// record. On the first start that keeps mutation markers, their absence proves
// nothing (an earlier agent version wrote none, and a stop can be left behind
// by something that records nothing in the journal, such as a restore's
// `compose down`), so the first tag+recreate waits out the window.
func TestSettle_FirstStartOnAStateDirWaits(t *testing.T) {
	const settle = 6 * time.Second
	r := newCrashRig(t)
	r.setSettle(settle.String())
	beforeStart := time.Now()
	r.start() // a clean start: empty journal
	if files := r.journalFiles(); len(files) != 0 {
		t.Fatalf("the journal is not empty at a clean start: %v", files)
	}

	op := r.applyUpgrade()
	time.Sleep(time.Second)
	if calls := r.tagOrUpCalls(); len(calls) != 0 {
		t.Fatalf("an upgrade tagged or recreated %v after a clean start, inside the %v settle window: %v",
			time.Since(beforeStart).Round(time.Millisecond), settle, calls)
	}
	if d := r.waitOp(op); d.State != "succeeded" {
		t.Fatalf("upgrade = %s(%s); agent output:\n%s", d.State, d.FailureReason, r.logs.String())
	}
	if waited := time.Since(beforeStart); waited < settle {
		t.Errorf("the upgrade finished %v after the start; it must not act before %v", waited, settle)
	}
	if r.read("pinned") != imgB || r.read("running") != imgB {
		t.Errorf("after upgrade: tag %.8s container %.8s, want both on the target", r.read("pinned"), r.read("running"))
	}
}

// TestSettle_AlreadyCurrentIsNotReportedInsideTheWindow: an upgrade to the image
// that is already running skips the restart and the health gate. It must still
// not report success on a container the predecessor's stop may be about to
// kill: the capture it is judged on is taken only after the window.
func TestSettle_AlreadyCurrentIsNotReportedInsideTheWindow(t *testing.T) {
	const settle = 6 * time.Second
	r := newCrashRig(t)
	r.setSettle(settle.String())
	beforeStart := time.Now()
	r.start()

	var op opView
	if code := r.post("/v1/upgrades/apply", map[string]interface{}{"image_ref": refA}, &op); code != http.StatusAccepted {
		t.Fatalf("apply: HTTP %d", code)
	}
	done := r.waitOp(op.OpID)
	if done.State != "succeeded" {
		t.Fatalf("upgrade = %s(%s); agent output:\n%s", done.State, done.FailureReason, r.logs.String())
	}
	if logs := r.opLogs(op.OpID); !strings.Contains(logs, "already_current=true") {
		t.Fatalf("precondition: the upgrade was not already_current:\n%s", logs)
	}
	if waited := time.Since(beforeStart); waited < settle {
		t.Errorf("an already_current upgrade reported success %v after the start, inside the %v settle window", waited, settle)
	}
}

// TestSettle_NoWaitAfterAnIdlePredecessor: the previous agent process ended,
// here even by SIGKILL, with no compose up/down in flight. No marker is left,
// so dockerd has nothing of its to finish and the first operation of the new
// process acts at once. This is the ordinary restart: package upgrade, reboot.
func TestSettle_NoWaitAfterAnIdlePredecessor(t *testing.T) {
	const settle = 30 * time.Second
	r := newCrashRig(t)
	r.setSettle(settle.String())
	r.start() // first start on this state dir
	r.kill()  // idle: nothing in flight
	began := time.Now()
	r.start()

	op := r.applyUpgrade()
	if d := r.waitOp(op); d.State != "succeeded" {
		t.Fatalf("upgrade = %s(%s); agent output:\n%s", d.State, d.FailureReason, r.logs.String())
	}
	if took := time.Since(began); took >= settle {
		t.Errorf("the upgrade took %v after the restart: it waited out the %v window although nothing was in flight", took, settle)
	}
	if logs := r.opLogs(op); strings.Contains(logs, "settle:") {
		t.Errorf("the operation log records a settle wait:\n%s", logs)
	}
	if r.read("pinned") != imgB || r.read("running") != imgB {
		t.Errorf("after upgrade: tag %.8s container %.8s, want both on the target", r.read("pinned"), r.read("running"))
	}
}

// TestSettle_EndsEarlyWhenTheProxyIsDown: the agent died inside `compose up`
// and the proxy is not running. No container stop can be pending on a
// container that is not running, so the rollback goes on as soon as two reads
// of Docker show that, instead of keeping the proxy down for the rest of the
// window.
func TestSettle_EndsEarlyWhenTheProxyIsDown(t *testing.T) {
	const settle = 60 * time.Second
	r := newCrashRig(t)
	r.setSettle(settle.String())
	r.start() // first start on this state dir: would wait; get past it
	r.kill()
	r.start() // an idle predecessor: no wait, so the upgrade reaches `up` at once
	r.crashAt("up_before:1")
	if err := os.Remove(filepath.Join(r.model, "running")); err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	r.start()
	r.clearCalls()

	op := r.rollbackToA()
	done := r.waitOp(op)
	if done.State != "succeeded" {
		t.Fatalf("rollback = %s(%s); agent output:\n%s\nop log:\n%s", done.State, done.FailureReason, r.logs.String(), r.opLogs(op))
	}
	if took := time.Since(began); took >= settle/2 {
		t.Errorf("the rollback took %v with the proxy down; the %v window should have been ended early", took, settle)
	}
	if logs := r.opLogs(op); !strings.Contains(logs, "no proxy container is running") {
		t.Errorf("the operation log does not record why the wait ended early:\n%s", logs)
	}
	if r.read("pinned") != imgA || r.read("running") != imgA {
		t.Errorf("after rollback: tag %.8s container %.8s, want both on the prior image", r.read("pinned"), r.read("running"))
	}
}

// TestSettle_TheMarkerAloneOpensTheWindow: the interrupted `up` left no journal
// record, only its marker. The next start must still wait out the window while
// a proxy container is running (it may be the one being stopped).
func TestSettle_TheMarkerAloneOpensTheWindow(t *testing.T) {
	const settle = 6 * time.Second
	r := newCrashRig(t)
	r.setSettle(settle.String())
	r.start() // first start on this state dir: would wait; get past it
	r.kill()
	r.start()
	crashed := r.crashAt("up_before:1")
	if err := os.Remove(filepath.Join(r.state, "reconcile", crashed+".json")); err != nil {
		t.Fatalf("removing the interrupted record: %v", err)
	}
	beforeStart := time.Now()
	r.start()
	r.clearCalls()

	op := r.rollbackToA()
	time.Sleep(time.Second)
	if calls := r.tagOrUpCalls(); len(calls) != 0 {
		t.Fatalf("the rollback tagged or recreated inside the window, with only the marker to go on: %v", calls)
	}
	if d := r.waitOp(op); d.State != "succeeded" {
		t.Fatalf("rollback = %s(%s); op log:\n%s", d.State, d.FailureReason, r.opLogs(op))
	}
	if waited := time.Since(beforeStart); waited < settle {
		t.Errorf("the rollback finished %v after the restart; it must not act before %v", waited, settle)
	}
}
