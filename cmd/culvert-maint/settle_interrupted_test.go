package main

import (
	"io"
	"net/http"
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

// TestSettle_AppliesAfterAnyStart: the wait does not depend on a journal
// record. A stop can be left behind by something that records nothing (a
// restore's `compose down`) or records another class (a data rollback), so the
// first tag+recreate after ANY agent start waits out the window.
func TestSettle_AppliesAfterAnyStart(t *testing.T) {
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
