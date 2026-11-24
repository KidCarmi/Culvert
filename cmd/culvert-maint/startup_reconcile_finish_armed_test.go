package main

// startup_reconcile_finish_armed_test.go — owner Decision 1 (2026-11-23) on
// AGT-900, on the REAL agent binary and the shell Docker model of
// startup_crash_recovery_test.go: with reconcile_on_startup = "converge" the
// next start finishes an inline rollback the journal proves was armed although
// the agent was killed before the rollback's own `docker tag` ("T/T armed",
// real-Docker e2e finding 2). Every step of that finish is then killed in turn,
// and the start after it must converge or report recovery_required without
// repeating an unsafe step.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func (r *crashRig) setHealth(hang, down bool) {
	r.healthMu.Lock()
	r.healthHang, r.healthDown = hang, down
	r.healthMu.Unlock()
}

// waitBlockedFor waits, up to budget, until the Docker model is blocked at its block_on point.
func (r *crashRig) waitBlockedFor(budget time.Duration) {
	r.t.Helper()
	deadline := time.Now().Add(budget)
	for {
		if _, err := os.Stat(filepath.Join(r.model, "blocked")); err == nil {
			return
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("never reached %q; agent output:\n%s\ncalls:\n%s", r.read("block_on"), r.logs.String(), r.read("calls.log"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type armedRecord struct {
	Phase         string `json:"phase"`
	RollbackArmed bool   `json:"rollback_armed"`
	Attempts      int    `json:"reconcile_attempts"`
	TargetImageID string `json:"target_image_id"`
}

func (r *crashRig) record(opID string) armedRecord {
	r.t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.state, "reconcile", opID+".json")) // #nosec G304 -- test-owned temp dir
	if err != nil {
		r.t.Fatalf("journal record: %v", err)
	}
	var rec armedRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		r.t.Fatal(err)
	}
	return rec
}

// reconciledAuditsOffline counts the reconcile's `:reconciled` entries for
// opID straight from the audit log, while no agent runs.
func (r *crashRig) reconciledAuditsOffline(opID string) int {
	r.t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.state, "audit.jsonl")) // #nosec G304 -- test-owned temp dir
	if err != nil {
		r.t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(string(raw), "\n") {
		var e struct {
			OpID  string `json:"op_id"`
			Kind  string `json:"kind"`
			Actor string `json:"actor"`
		}
		if json.Unmarshal([]byte(line), &e) == nil && e.OpID == opID && strings.HasSuffix(e.Kind, ":reconciled") && e.Actor == "agent:reconcile" {
			n++
		}
	}
	return n
}

// crashArmedTT leaves the T/T-armed state the e2e found: the upgrade to B was
// killed in its health gate (container and tag on B, phase restarted), and the
// record then carries rollback_armed exactly as armRollbackInJournal writes it
// right before the rollback's `docker tag`. (TestConvergeRecovery_ArmedRollback
// TagNeverMoved reaches the same state through a real failed gate.)
func (r *crashRig) crashArmedTT() string {
	r.t.Helper()
	opID := r.crashAt("health")
	path := filepath.Join(r.state, "reconcile", opID+".json")
	raw, err := os.ReadFile(path) // #nosec G304 -- test-owned temp dir
	if err != nil {
		r.t.Fatal(err)
	}
	out := strings.Replace(string(raw), `"phase": "restarted"`, `"phase": "restarted", "rollback_armed": true`, 1)
	if out == string(raw) {
		r.t.Fatalf("record not at phase restarted:\n%s", raw)
	}
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil { // #nosec G703 -- test-owned temp dir
		r.t.Fatal(err)
	}
	if r.read("pinned") != imgB || r.read("running") != imgB {
		r.t.Fatalf("not T/T: tag %.8s container %.8s", r.read("pinned"), r.read("running"))
	}
	return opID
}

// TestConvergeRecovery_ArmedRollbackTagNeverMoved: the e2e finding, reproduced
// end to end. The target fails its health gate, the inline rollback arms the
// record and is killed in its own `docker tag`. With the default "off" the
// next start changes nothing (AGT-004). With "converge" it runs exactly
// `docker tag <prior ref>` and `compose up`, gates and verifies the prior
// image, audits once and retires the record; the upgrade stays failed.
func TestConvergeRecovery_ArmedRollbackTagNeverMoved(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	r.setHealth(false, true)          // the target never answers ready
	r.put("block_on", "tag_before:2") // the inline rollback's retag; the forward tag is the first
	opID := r.applyUpgrade()
	r.waitBlockedFor(120 * time.Second) // the failing gate polls for its full 30s budget
	r.kill()
	r.setHealth(false, false) // the prior image is healthy
	if r.read("pinned") != imgB || r.read("running") != imgB {
		t.Fatalf("not T/T after the kill: tag %.8s container %.8s", r.read("pinned"), r.read("running"))
	}
	if rec := r.record(opID); !rec.RollbackArmed || rec.Phase != "restarted" {
		t.Fatalf("record = %+v, want armed at restarted", rec)
	}

	// Default "off": reported, nothing changed.
	r.clearCalls()
	r.start()
	if m := r.mutatingCalls(); len(m) != 0 {
		t.Errorf("reconcile_on_startup off changed Docker: %v", m)
	}
	r.kill()

	r.converge("")
	r.clearCalls()
	r.start()
	assertConverge(t, r, opID, convergeCase{[]string{"tag:" + refA, "up"}, true, "rollback_armed_tag_not_moved", imgA, imgA, false})
}

// armFinishKill sets up where the next start's finish is frozen: a block_on
// point, "gate" (the health probe hangs) or "verify" (the verify's compose ps).
func (r *crashRig) armFinishKill(block string) {
	r.t.Helper()
	switch block {
	case "gate":
		for len(r.healthHit) > 0 {
			<-r.healthHit
		}
		r.setHealth(true, false)
	case "verify":
		// The verify's `compose ps` is the 5th of this start: the Docker
		// readiness wait, the decision's read, the recheck before the retag,
		// the recheck before `up`, then the verify.
		n, err := strconv.Atoi(r.read("count.ps"))
		if err != nil {
			r.t.Fatal(err)
		}
		r.put("block_on", "ps:"+strconv.Itoa(n+5))
	default:
		r.put("block_on", block)
	}
}

// awaitFinishKill waits until the finish is frozen there and, for the gate
// and the verify, checks the freeze is after this start's `up` applied.
func (r *crashRig) awaitFinishKill(block string) {
	r.t.Helper()
	if block == "gate" {
		select {
		case <-r.healthHit:
		case <-time.After(30 * time.Second):
			r.t.Fatalf("the finish never reached its gate; agent output:\n%s", r.logs.String())
		}
	} else {
		r.waitBlockedFor(30 * time.Second)
	}
	if block != "gate" && block != "verify" {
		return
	}
	calls := strings.Split(strings.TrimSpace(r.read("calls.log")), "\n")
	if r.read("running") != imgA || r.read("pinned") != imgA || !strings.Contains(strings.Join(calls, "\n"), " up ") {
		r.t.Fatalf("kill point is not after the finish's `up`: tag %.8s container %.8s calls:\n%s",
			r.read("pinned"), r.read("running"), strings.Join(calls, "\n"))
	}
	if block == "verify" && !strings.Contains(calls[len(calls)-1], " ps ") {
		r.t.Fatalf("blocked in %q, want the verify's compose ps", calls[len(calls)-1])
	}
}

// TestConvergeRecovery_KillDuringArmedFinish kills the T/T finish at each of
// its steps and restarts. The write-ahead attempt is durable before any
// step; the next start decides again from Docker truth and the record:
//
//   - before the retag: T/T armed again, attempt 2 of 2 redoes retag + up;
//   - after the retag, before `up` applied: T/P armed, `up` only;
//   - after `up`, during the gate, or during the verify (before the audit):
//     container and tag on the prior, armed: no Docker change; retired on a
//     fresh ready probe, audited once.
func TestConvergeRecovery_KillDuringArmedFinish(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block string // block_on point in the second start; "gate" hangs the health probe
		want  convergeCase
	}{
		{"after_write_ahead_before_retag", "tag_before:2",
			convergeCase{[]string{"tag:" + refA, "up"}, true, "rollback_armed_tag_not_moved", imgA, imgA, false}},
		{"after_retag_before_up", "up_before:2",
			convergeCase{[]string{"up"}, true, "rollback_interrupted", imgA, imgA, false}},
		{"after_up_before_gate", "up_after:2",
			convergeCase{nil, true, "armed_rollback_prior_ready", imgA, imgA, false}},
		{"during_gate", "gate",
			convergeCase{nil, true, "armed_rollback_prior_ready", imgA, imgA, false}},
		{"during_verify_before_audit", "verify",
			convergeCase{nil, true, "armed_rollback_prior_ready", imgA, imgA, false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newCrashRig(t)
			r.start()
			opID := r.crashArmedTT()
			r.converge("")
			r.armFinishKill(tc.block)
			r.start()
			r.awaitFinishKill(tc.block)
			r.kill()
			r.setHealth(false, false)
			if rec := r.record(opID); rec.Attempts != 1 || !rec.RollbackArmed {
				t.Fatalf("record after the kill = %+v, want armed with the write-ahead attempt 1", rec)
			}
			if n := r.reconciledAuditsOffline(opID); n != 0 {
				t.Fatalf("%d :reconciled entries before the restart, want none (killed before the audit)", n)
			}
			r.clearCalls()
			r.start()
			assertConverge(t, r, opID, tc.want)
		})
	}
}
