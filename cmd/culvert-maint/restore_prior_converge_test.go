package main

// restore_prior_converge_test.go — restore_prior (ADR-0062 slice 4) on the
// REAL agent binary, SIGKILLed at chosen points of a real upgrade, against the
// process-level Docker model of startup_crash_recovery_test.go, with
// reconcile_on_startup = "converge". The sequences are the acceptance cases of
// ADR-0062 slice 3 (the ones on which reviews of the earlier, marker-based
// design found a wrong restore) plus the positive cases.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// killAgentAt arms the Docker model to block at point, starts the agent, and
// SIGKILLs it once it is blocked there.
func (r *crashRig) killAgentAt(point string) {
	r.t.Helper()
	r.put("block_on", point)
	r.start()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(r.model, "blocked")); err == nil {
			r.kill()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.t.Fatalf("the agent never reached %q; output:\n%s\ncalls:\n%s", point, r.logs.String(), r.read("calls.log"))
}

// diedInsideUpWithProxyDown runs a real upgrade, kills the agent inside its
// `compose up`, and leaves no proxy container (the recreate got as far as
// stopping the old one). The next agent start will run with converge on.
func diedInsideUpWithProxyDown(t *testing.T, settle string) (r *crashRig, opID string) {
	t.Helper()
	r = newCrashRig(t)
	r.pastFirstUse(settle)
	r.start()
	opID = r.crashAt("up_before:1")
	if err := os.Remove(filepath.Join(r.model, "running")); err != nil {
		t.Fatal(err)
	}
	r.converge("")
	r.clearCalls()
	return r, opID
}

// TestRestorePrior_TheAgentDiedInsideItsOwnUp: positive case. The next start
// puts the tag back on the image that was serving, starts it, gates and
// verifies it, and retires the record: no operator action. With and without a
// settle window.
func TestRestorePrior_TheAgentDiedInsideItsOwnUp(t *testing.T) {
	for _, settle := range []string{"0s", "20s"} {
		t.Run("settle "+settle, func(t *testing.T) {
			r, opID := diedInsideUpWithProxyDown(t, settle)
			r.start()
			assertConverge(t, r, opID, convergeCase{[]string{"tag:" + refA, "up"}, true, "stack_down_up_interrupted", imgA, imgA, false})
		})
	}
}

// TestRestorePrior_NoIntentNoRestore: the same state, but the record holds no
// command intent (it could not be written when the command began). Nothing can
// be put down to the agent: the stack is reported and nothing is started.
func TestRestorePrior_NoIntentNoRestore(t *testing.T) {
	r, opID := diedInsideUpWithProxyDown(t, "0s")
	path := filepath.Join(r.state, "reconcile", opID+".json")
	raw, err := os.ReadFile(path) // #nosec G304 -- rig-owned temp dir
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["intent"]; !ok {
		t.Fatalf("test setup: no intent in the record of an agent killed inside `up`:\n%s", raw)
	}
	delete(m, "intent")
	out, _ := json.Marshal(m)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	r.start()
	assertConverge(t, r, opID, convergeCase{nil, false, "stack_down", imgB, "", true})
}

// TestRestorePrior_CaseA_AStartHasLooked: the agent died inside `up` after the
// target came up. The next start finds the target running and only reports.
// Later the operator takes the stack down and the agent restarts: nothing may
// be started, whatever the record once said.
func TestRestorePrior_CaseA_AStartHasLooked(t *testing.T) {
	r := newCrashRig(t)
	r.pastFirstUse("0s")
	r.start()
	opID := r.crashAt("up_after:1") // killed inside `compose up`; the target is running
	r.converge("")
	r.clearCalls()
	r.start()
	assertConverge(t, r, opID, convergeCase{nil, false, "target_live_ungated", imgB, imgB, true})
	r.kill() // an ordinary agent restart, later
	if err := os.Remove(filepath.Join(r.model, "running")); err != nil {
		t.Fatal(err) // the operator took the stack down
	}
	r.clearCalls()
	r.start()
	assertConverge(t, r, opID, convergeCase{nil, false, "stack_down", imgB, "", true})
}

// TestRestorePrior_CaseE_TheFirstStartWasInModeOff: the first start after the
// death ran with reconcile_on_startup off. It found the death and reported it;
// switching converge on later does not turn an outage of unknown age into a
// restore.
func TestRestorePrior_CaseE_TheFirstStartWasInModeOff(t *testing.T) {
	r := newCrashRig(t)
	r.pastFirstUse("0s")
	r.start()
	opID := r.crashAt("up_before:1")
	if err := os.Remove(filepath.Join(r.model, "running")); err != nil {
		t.Fatal(err)
	}
	r.start() // off: reports, changes nothing
	r.kill()
	r.converge("")
	r.clearCalls()
	r.start()
	assertConverge(t, r, opID, convergeCase{nil, false, "stack_down", imgB, "", true})
}

// TestRestorePrior_CaseC_ARestoreWhoseUpReturnedIsNotACrash: the restore's own
// `up` FAILS and the agent stays up. The operator then brings the stack up by
// hand (on the prior or on the target), and later takes it down on purpose.
// The agent restarts: nothing may be started.
func TestRestorePrior_CaseC_ARestoreWhoseUpReturnedIsNotACrash(t *testing.T) {
	for name, handImage := range map[string]string{"operator ran the prior image": imgA, "operator ran the target image": imgB} {
		t.Run(name, func(t *testing.T) {
			r, opID := diedInsideUpWithProxyDown(t, "3s")
			r.put("block_on", "up_before:2") // the restore's own `up`
			r.start()
			deadline := time.Now().Add(60 * time.Second)
			for {
				if pid, err := strconv.Atoi(strings.TrimSpace(r.read("blocked"))); err == nil && pid > 1 {
					_ = os.Remove(filepath.Join(r.model, "block_on"))
					_ = syscall.Kill(pid, syscall.SIGKILL) // the CLI dies; the agent lives
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("the restore never reached its `up`; agent output:\n%s", r.logs.String())
				}
				time.Sleep(20 * time.Millisecond)
			}
			if v := r.waitReconcile(); len(v.Reconcile.Records) != 1 || v.Reconcile.Records[0].Reason != "up_failed" {
				t.Fatalf("start 1 = %+v, want one record with up_failed", v.Reconcile.Records)
			}
			_ = os.Remove(filepath.Join(r.model, "blocked"))
			r.put("pinned", handImage)
			r.put("running", handImage) // the operator brings the stack up by hand
			_ = os.Remove(filepath.Join(r.model, "leftover"))
			r.kill() // ... days pass; then:
			if err := os.Remove(filepath.Join(r.model, "running")); err != nil {
				t.Fatal(err) // the operator takes it down on purpose
			}
			r.clearCalls()
			r.start()
			assertConverge(t, r, opID, convergeCase{nil, false, "stack_down", handImage, "", true})
		})
	}
}

// TestRestorePrior_ARestoreThatDiesInItsOwnUpIsRetriedOnce: the agent dies
// inside the restore's own `up` as well. That `up` ran under the record's
// operation, so the next start is told, and one attempt is left: the prior is
// restored. The attempt cap (2) ends it there.
func TestRestorePrior_ARestoreThatDiesInItsOwnUpIsRetriedOnce(t *testing.T) {
	r, opID := diedInsideUpWithProxyDown(t, "0s")
	r.killAgentAt("up_before:2") // the restore got as far as its own `compose up`
	if got := r.read("running"); got != "" {
		t.Fatalf("a container (%.8s) runs after the cut restore; the test needs the proxy down", got)
	}
	r.clearCalls()
	r.start()
	assertConverge(t, r, opID, convergeCase{[]string{"tag:" + refA, "up"}, true, "stack_down_up_interrupted", imgA, imgA, false})
}

// TestRestorePrior_TheOperatorsComposeDownIsNotUndone: the agent died inside
// its `up` with the proxy down, and before the next start the operator ran
// `compose down` on purpose. The journal still attributes the outage to the
// death; Docker shows no "created" container any more (ADR-0062 slice 4, B1):
// nothing is started.
func TestRestorePrior_TheOperatorsComposeDownIsNotUndone(t *testing.T) {
	r, opID := diedInsideUpWithProxyDown(t, "0s")
	if err := os.Remove(filepath.Join(r.model, "leftover")); err != nil {
		t.Fatalf("test setup: a death inside `up` must leave the created container: %v", err)
	}
	r.start()
	assertConverge(t, r, opID, convergeCase{nil, false, "stack_down_no_up_evidence", imgB, "", true})
}

// TestRestorePrior_WithoutTheSudoersRuleNothingIsRestored: an install whose
// sudoers file predates `compose ps -a`. The evidence cannot be read, and the
// journal's attribution is not enough on its own: nothing is started.
func TestRestorePrior_WithoutTheSudoersRuleNothingIsRestored(t *testing.T) {
	r, opID := diedInsideUpWithProxyDown(t, "0s")
	r.put("psa_denied", "1")
	r.start()
	assertConverge(t, r, opID, convergeCase{nil, false, "up_evidence_unreadable", imgB, "", true})
}

// editRecord rewrites the on-disk record of opID through fn (a test stand-in
// for states a real sequence reaches only with a second operation or a wrong
// clock).
func (r *crashRig) editRecord(opID string, fn func(m map[string]any)) {
	r.t.Helper()
	path := filepath.Join(r.state, "reconcile", opID+".json")
	raw, err := os.ReadFile(path) // #nosec G304 -- rig-owned temp dir
	if err != nil {
		r.t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		r.t.Fatal(err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		r.t.Fatal(err)
	}
}

// TestRestorePrior_CaseB_TwoRecordsTheOlderDoesNothing: two upgrade records
// for the same stack; the agent died inside the NEWER operation's `up`. The
// attribution belongs to that operation only: the older record, whose own
// commands all returned, is reported and changes nothing; only the newer one
// restores, and Docker is changed exactly once.
func TestRestorePrior_CaseB_TwoRecordsTheOlderDoesNothing(t *testing.T) {
	r, newer := diedInsideUpWithProxyDown(t, "0s")
	const older = "01ARZ3NDEKTSV4RRFFQ69G5FAV" // a ULID from long before newer
	src := filepath.Join(r.state, "reconcile", newer+".json")
	raw, err := os.ReadFile(src) // #nosec G304 -- rig-owned temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.state, "reconcile", older+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	r.editRecord(older, func(m map[string]any) { delete(m, "intent"); m["op_id"] = older })
	r.start()
	v := r.waitReconcile()
	reasons := map[string]string{}
	for _, rec := range v.Reconcile.Records {
		reasons[rec.OpID] = rec.Reason
	}
	if reasons[newer] != "stack_down_up_interrupted" {
		t.Errorf("newer record: reason %q, want stack_down_up_interrupted (records %+v)", reasons[newer], v.Reconcile.Records)
	}
	if got := reasons[older]; got == "stack_down_up_interrupted" || got == "" {
		t.Errorf("older record: reason %q, want a report that is not a restore (records %+v)", got, v.Reconcile.Records)
	}
	if got, want := strings.Join(normMutating(r.mutatingCalls()), ","), "tag:"+refA+",up"; got != want {
		t.Errorf("state-changing docker commands = [%s], want exactly [%s] (one restore)", got, want)
	}
}

// TestRestorePrior_CaseD_ClockBehindBeganChangesNothing: the agent died inside
// `up` after the target came up, and at the next start the clock is behind the
// intent's `began` (power loss, a corrected clock). The start still takes the
// intent (the epoch decides, never the clock) and only reports the live
// target. The operator then takes the stack down and the agent restarts with
// the clock back in range: nothing is started.
func TestRestorePrior_CaseD_ClockBehindBeganChangesNothing(t *testing.T) {
	r := newCrashRig(t)
	r.pastFirstUse("0s")
	r.start()
	opID := r.crashAt("up_after:1")
	r.editRecord(opID, func(m map[string]any) {
		in, ok := m["intent"].(map[string]any)
		if !ok {
			t.Fatalf("test setup: no intent in the record of an agent killed inside `up`: %v", m)
		}
		in["began"] = time.Now().Add(240 * time.Hour).UTC().Format(time.RFC3339Nano)
	})
	r.converge("")
	r.clearCalls()
	r.start()
	assertConverge(t, r, opID, convergeCase{nil, false, "target_live_ungated", imgB, imgB, true})
	r.kill()
	if err := os.Remove(filepath.Join(r.model, "running")); err != nil {
		t.Fatal(err) // the operator took the stack down
	}
	r.clearCalls()
	r.start()
	assertConverge(t, r, opID, convergeCase{nil, false, "stack_down", imgB, "", true})
}
