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
// recreate until that request can no longer be pending
// (InterruptedAt + interrupted_settle), so that its `up` and health gate judge
// a container nothing outstanding can touch.
func TestSettle_RollbackWaitsOutAnInterruptedRecreate(t *testing.T) {
	const settle = 3 * time.Second
	r := newCrashRig(t)
	r.setSettle(settle.String())
	r.start()
	r.crashAt("up_before:1") // past the barrier: the dead agent was inside `compose up`
	restarted := time.Now()  // no later than the record's InterruptedAt
	r.start()
	r.clearCalls()

	op := r.rollbackToA()

	// Negative control on the wait: well inside the window nothing has been
	// moved, although the operation was admitted at once.
	time.Sleep(settle / 3)
	if calls := r.tagOrUpCalls(); len(calls) != 0 {
		t.Fatalf("the rollback tagged or recreated %v after the restart, inside the %v settle window: %v",
			time.Since(restarted).Round(time.Millisecond), settle, calls)
	}

	done := r.waitOp(op)
	if done.State != "succeeded" {
		t.Fatalf("rollback = %s(%s); agent output:\n%s", done.State, done.FailureReason, r.logs.String())
	}
	if waited := time.Since(restarted); waited < settle {
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

	// The window is counted from the interruption, not from each operation:
	// with the record retired, the next operation does not wait.
	again := time.Now()
	if d := r.waitOp(r.rollbackToA()); d.State != "succeeded" {
		t.Fatalf("second rollback = %s(%s)", d.State, d.FailureReason)
	}
	if took := time.Since(again); took >= settle {
		t.Errorf("a rollback with no interrupted record took %v: it waited for nothing", took)
	}
}

// TestSettle_NoWaitBeforeTheBarrier: an operation that died before the
// write-ahead barrier never reached `compose up`, so it cannot have left a
// container stop behind. Waiting there would only delay recovery.
func TestSettle_NoWaitBeforeTheBarrier(t *testing.T) {
	const settle = 20 * time.Second
	r := newCrashRig(t)
	r.setSettle(settle.String())
	r.start()
	r.crashAt("pull:1")
	r.start()

	began := time.Now()
	if d := r.waitOp(r.rollbackToA()); d.State != "succeeded" {
		t.Fatalf("rollback = %s(%s); agent output:\n%s", d.State, d.FailureReason, r.logs.String())
	}
	if took := time.Since(began); took >= settle/2 {
		t.Errorf("rollback after a pre-barrier interruption took %v with interrupted_settle=%v: it waited", took, settle)
	}
}
