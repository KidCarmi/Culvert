package main

// startup_reconcile_converge_test.go — the opt-in startup reconcile
// (reconcile_on_startup = "converge", contract AGT-900), on the REAL agent
// binary and the same process-level Docker model as
// startup_crash_recovery_test.go. That file's tests run with the default "off"
// and are unchanged: they keep asserting zero state-changing Docker commands.
// Here each kill point is replayed with "converge" and the EXACT state-changing
// commands the restart may issue are asserted.

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// converge rewrites the rig's config to reconcile_on_startup = "converge",
// optionally with another stage_timeout (which also bounds the wait for a
// readable Docker daemon).
func (r *crashRig) converge(stageTimeout string) {
	r.t.Helper()
	raw, err := os.ReadFile(r.cfgPath)
	if err != nil {
		r.t.Fatal(err)
	}
	cfg := string(raw)
	if stageTimeout != "" {
		cfg = strings.Replace(cfg, `stage_timeout = "1m"`, `stage_timeout = "`+stageTimeout+`"`, 1)
	}
	cfg += "reconcile_on_startup = \"converge\"\n"
	if err := os.WriteFile(r.cfgPath, []byte(cfg), 0o600); err != nil { // #nosec G703 -- test-owned temp dir
		r.t.Fatal(err)
	}
}

type reconcileView struct {
	RecoveryRequired *bool `json:"recovery_required"`
	Reconcile        *struct {
		State   string `json:"state"`
		OpID    string `json:"op_id"`
		Records []struct {
			OpID             string   `json:"source_op_id"`
			Decision         string   `json:"decision"`
			Reason           string   `json:"reason"`
			Outcome          string   `json:"outcome"`
			Actions          []string `json:"actions"`
			DockerReconciled bool     `json:"docker_reconciled"`
		} `json:"records"`
	} `json:"reconcile"`
	Interrupted []struct {
		OpID             string `json:"op_id"`
		ReconcileOutcome string `json:"reconcile_outcome"`
		DockerReconciled bool   `json:"docker_reconciled"`
	} `json:"interrupted_operations"`
}

// waitReconcile polls GET /v1/status until the startup reconcile has finished.
func (r *crashRig) waitReconcile() reconcileView {
	r.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var v reconcileView
	for time.Now().Before(deadline) {
		v = reconcileView{}
		if code, _ := r.tryGet("/v1/status", &v); code == http.StatusOK && v.Reconcile != nil &&
			v.Reconcile.State != "in_progress" && v.Reconcile.State != "not_started" {
			return v
		}
		time.Sleep(50 * time.Millisecond)
	}
	r.t.Fatalf("startup reconcile did not finish (last %+v); agent output:\n%s", v.Reconcile, r.logs.String())
	return v
}

// reconciledAudits counts `<kind>:reconciled` audit entries for opID.
func (r *crashRig) reconciledAudits(opID string) int {
	r.t.Helper()
	var av struct {
		Events []struct {
			OpID  string `json:"op_id"`
			Kind  string `json:"kind"`
			Actor string `json:"actor"`
		} `json:"events"`
	}
	r.get("/v1/audit?limit=1000", &av)
	n := 0
	for _, e := range av.Events {
		if e.OpID == opID && strings.HasSuffix(e.Kind, ":reconciled") && e.Actor == "agent:reconcile" {
			n++
		}
	}
	return n
}

// convergeCase is what "converge" must do at one kill point.
type convergeCase struct {
	mutating          []string // exact state-changing commands of the restart ("tag:<image>" or "up")
	retired           bool     // the record is removed (verified convergence)
	reason            string
	pinned, running   string // Docker afterwards
	reconcileOpFailed bool
}

// convergeExpect extends killPoints() (unchanged) with the converge outcome.
var convergeExpect = map[string]convergeCase{
	"admitted_at_capture":      {nil, true, "safe_boundary_unchanged", imgA, imgA, false},
	"captured_at_resolve":      {nil, true, "safe_boundary_unchanged", imgA, imgA, false},
	"resolved_at_pull":         {nil, true, "safe_boundary_unchanged", imgA, imgA, false},
	"barrier_before_tag":       {nil, true, "already_on_prior", imgA, imgA, false},
	"tag_moved_before_up":      {[]string{"tag:" + refA}, true, "tag_ahead_container_on_prior", imgA, imgA, false},
	"up_done_unrecorded":       {nil, false, "target_live_ungated", imgB, imgB, true},
	"restarted_at_health_gate": {nil, false, "target_live_ungated", imgB, imgB, true},
	"restarted_at_verify":      {nil, false, "target_live_ungated", imgB, imgB, true},
}

// normMutating renders the model's mutating call lines as "tag:<ref>" / "up".
func normMutating(lines []string) []string {
	out := []string{}
	for _, l := range lines {
		f := strings.Fields(l)
		switch {
		case len(f) >= 2 && f[0] == "tag":
			out = append(out, "tag:"+f[1])
		case len(f) > 3 && f[0] == "compose":
			out = append(out, f[3])
		default:
			out = append(out, l)
		}
	}
	return out
}

// assertConverge checks the restart against tc.
func assertConverge(t *testing.T, r *crashRig, opID string, tc convergeCase) {
	t.Helper()
	v := r.waitReconcile()
	if got, want := strings.Join(normMutating(r.mutatingCalls()), ","), strings.Join(tc.mutating, ","); got != want {
		t.Errorf("state-changing docker commands = [%s], want exactly [%s]", got, want)
	}
	if r.read("pinned") != tc.pinned || r.read("running") != tc.running {
		t.Errorf("Docker after reconcile: tag %.8s container %.8s, want %.8s / %.8s", r.read("pinned"), r.read("running"), tc.pinned, tc.running)
	}
	if len(v.Reconcile.Records) != 1 || v.Reconcile.Records[0].OpID != opID || v.Reconcile.Records[0].Reason != tc.reason {
		t.Errorf("reconcile records = %+v, want one for %s with reason %s", v.Reconcile.Records, opID, tc.reason)
	}
	var files []string
	if tc.retired {
		files = r.waitJournal()
	} else {
		files = r.waitJournal(opID)
	}
	if retired := len(files) == 0; retired != tc.retired {
		t.Errorf("journal = %v, want retired=%v", files, tc.retired)
	}
	// The interrupted op is never flipped: it stays failed(agent_restart_interrupted).
	var op opView
	if code := r.get("/v1/operations/"+opID, &op); code != http.StatusOK || op.State != "failed" || op.FailureReason != "agent_restart_interrupted" {
		t.Errorf("original op = HTTP %d %s(%s), want failed(agent_restart_interrupted)", code, op.State, op.FailureReason)
	}
	var rop opView
	if code := r.get("/v1/operations/"+v.Reconcile.OpID, &rop); code != http.StatusOK || rop.Kind != "reconcile.startup" {
		t.Fatalf("reconcile op = HTTP %d %+v", code, rop)
	}
	if failed := rop.State == "failed" && rop.FailureReason == "recovery_required"; failed != tc.reconcileOpFailed || (!failed && rop.State != "succeeded") {
		t.Errorf("reconcile op = %s(%s), want failed=%v", rop.State, rop.FailureReason, tc.reconcileOpFailed)
	}
	if v.RecoveryRequired == nil || *v.RecoveryRequired != tc.reconcileOpFailed {
		t.Errorf("status.recovery_required = %v, want %v", v.RecoveryRequired, tc.reconcileOpFailed)
	}
	// Retirement is audited first; a kept record is listed with its outcome.
	if n := r.reconciledAudits(opID); tc.retired && n != 1 {
		t.Errorf("%d `:reconciled` audit entries for a retired record, want 1", n)
	}
	if !tc.retired && (len(v.Interrupted) != 1 || v.Interrupted[0].ReconcileOutcome != "recovery_required" || v.Interrupted[0].DockerReconciled) {
		t.Errorf("kept record in status = %+v, want reconcile_outcome recovery_required, docker_reconciled false", v.Interrupted)
	}
}

// TestConvergeRecovery_EveryKillPoint replays every kill point of
// TestCrashRecovery_EveryKillPoint with reconcile_on_startup = "converge".
func TestConvergeRecovery_EveryKillPoint(t *testing.T) {
	for _, kp := range killPoints() {
		tc, ok := convergeExpect[kp.name]
		if !ok {
			t.Fatalf("kill point %q has no converge expectation", kp.name)
		}
		t.Run(kp.name, func(t *testing.T) {
			r := newCrashRig(t)
			r.start()
			opID := r.crashAt(kp.point)
			r.converge("")
			r.clearCalls()
			r.start()
			assertConverge(t, r, opID, tc)
		})
	}
}

// TestConvergeRecovery_VerifiedPhaseAdopts: A10. A record at `verified` with
// the target live under the tag and answering ready is adopted with no Docker
// change; the original op still says failed(agent_restart_interrupted).
func TestConvergeRecovery_VerifiedPhaseAdopts(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	opID := r.crashAt("ps:3")
	r.rewritePhase(opID, "restarted", "verified")
	r.converge("")
	r.clearCalls()
	r.start()
	assertConverge(t, r, opID, convergeCase{nil, true, "verified_target_live", imgB, imgB, false})
}

// TestConvergeRecovery_FinishesAnArmedRollback: R2. The inline rollback had
// moved the tag back to the previous image and was killed before `up`; the
// record carries rollback_armed. Converge runs exactly one `compose up`,
// gates and verifies the previous image, and retires the record. Without the
// marker the same Docker state is reported only.
func TestConvergeRecovery_FinishesAnArmedRollback(t *testing.T) {
	for _, armed := range []bool{true, false} {
		name := map[bool]string{true: "armed", false: "not_armed"}[armed]
		t.Run(name, func(t *testing.T) {
			r := newCrashRig(t)
			r.start()
			opID := r.crashAt("up_after:1") // restarting, container and tag on the target
			r.put("pinned", imgA)           // the rollback's retag landed
			if armed {
				path := filepath.Join(r.state, "reconcile", opID+".json")
				raw, err := os.ReadFile(path) // #nosec G304 -- test-owned temp dir
				if err != nil {
					t.Fatal(err)
				}
				out := strings.Replace(string(raw), `"phase": "restarting"`, `"phase": "restarting", "rollback_armed": true`, 1)
				if err := os.WriteFile(path, []byte(out), 0o600); err != nil { // #nosec G703 -- test-owned temp dir
					t.Fatal(err)
				}
			}
			r.converge("")
			r.clearCalls()
			r.start()
			if armed {
				assertConverge(t, r, opID, convergeCase{[]string{"up"}, true, "rollback_interrupted", imgA, imgA, false})
			} else {
				assertConverge(t, r, opID, convergeCase{nil, false, "tag_on_prior_rollback_unproven", imgA, imgB, true})
			}
		})
	}
}

// TestConvergeRecovery_KillDuringReconcile: the agent dies inside the
// reconcile's own `docker tag`. While it runs, a state-changing request is
// refused 409 naming the reconcile and reads are served. The write-ahead
// attempt is durable, and the next start converges (attempt 2 of 2).
func TestConvergeRecovery_KillDuringReconcile(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	opID := r.crashAt("up_before:1") // tag on B, container on A
	r.converge("")
	r.put("block_on", "tag_before:2") // the reconcile's retag
	r.start()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(r.model, "blocked")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("reconcile never reached its retag; agent output:\n%s", r.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	var conflict struct {
		Error  string `json:"error"`
		Holder struct {
			Kind string `json:"kind"`
		} `json:"holder_op"`
	}
	if code := r.post("/v1/upgrades/apply", map[string]interface{}{"image_ref": refB}, &conflict); code != http.StatusConflict ||
		conflict.Holder.Kind != "reconcile.startup" {
		t.Errorf("apply during reconcile: HTTP %d %+v, want 409 held by reconcile.startup", code, conflict)
	}
	var v reconcileView
	if code := r.get("/v1/status", &v); code != http.StatusOK || v.Reconcile == nil || v.Reconcile.State != "in_progress" {
		t.Errorf("status during reconcile: HTTP %d %+v", code, v.Reconcile)
	}
	r.kill()
	raw, err := os.ReadFile(filepath.Join(r.state, "reconcile", opID+".json")) // #nosec G304 -- test-owned temp dir
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		Attempts int `json:"reconcile_attempts"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil || rec.Attempts != 1 {
		t.Fatalf("record after a kill in the reconcile: attempts=%d err=%v, want the write-ahead attempt 1", rec.Attempts, err)
	}
	r.clearCalls()
	r.start()
	assertConverge(t, r, opID, convergeCase{[]string{"tag:" + refA}, true, "tag_ahead_container_on_prior", imgA, imgA, false})
}

// TestConvergeRecovery_DockerUnavailableDefers: Docker unreadable at start:
// deferred, nothing changed, no attempt counted, the record kept; once Docker
// is back the next start converges.
func TestConvergeRecovery_DockerUnavailableDefers(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	opID := r.crashAt("up_before:1")
	r.converge("2s")
	r.put("docker_down", "1")
	r.clearCalls()
	r.start()
	v := r.waitReconcile()
	if v.Reconcile.State != "deferred" || len(v.Reconcile.Records) != 1 || v.Reconcile.Records[0].Outcome != "deferred" {
		t.Errorf("reconcile = %+v, want deferred", v.Reconcile)
	}
	if m := r.mutatingCalls(); len(m) != 0 {
		t.Errorf("state-changing docker commands with Docker down: %v", m)
	}
	raw, err := os.ReadFile(filepath.Join(r.state, "reconcile", opID+".json")) // #nosec G304 -- test-owned temp dir
	if err != nil {
		t.Fatalf("record not kept: %v", err)
	}
	if strings.Contains(string(raw), "reconcile_attempts") {
		t.Errorf("a deferral counted an attempt:\n%s", raw)
	}
	r.kill()
	_ = os.Remove(filepath.Join(r.model, "docker_down"))
	r.clearCalls()
	r.start()
	assertConverge(t, r, opID, convergeCase{[]string{"tag:" + refA}, true, "tag_ahead_container_on_prior", imgA, imgA, false})
}

// TestConvergeRecovery_SecondInstanceSkips: a second agent process on the
// same state_dir (here on another socket) cannot take the instance lock the
// first one holds for its lifetime, so it reconciles nothing.
func TestConvergeRecovery_SecondInstanceSkips(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	opID := r.crashAt("up_before:1")
	r.converge("2s")
	r.put("docker_down", "1") // the first instance defers and keeps the record
	r.start()
	if v := r.waitReconcile(); v.Reconcile.State != "deferred" {
		t.Fatalf("first instance: %+v", v.Reconcile)
	}
	_ = os.Remove(filepath.Join(r.model, "docker_down"))
	r.clearCalls()

	raw, err := os.ReadFile(r.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	sock2 := filepath.Join(r.dir, "b.sock")
	cfg2 := filepath.Join(r.dir, "config2.toml")
	if err := os.WriteFile(cfg2, []byte(strings.Replace(string(raw), r.sock, sock2, 1)), 0o600); err != nil { // #nosec G703 -- test-owned temp dir
		t.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(), agentBinary(t), "--config", cfg2) // #nosec G204 -- test-built binary, test-owned config
	cmd.Env = append(os.Environ(), "PATH="+r.shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock2)
		}}}
	var v reconcileView
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://agent/v1/status", http.NoBody)
		if resp, derr := client.Do(req); derr == nil {
			_ = json.NewDecoder(resp.Body).Decode(&v)
			_ = resp.Body.Close()
			if v.Reconcile != nil {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if v.Reconcile == nil || v.Reconcile.State != "skipped_second_instance" {
		t.Fatalf("second instance reconcile = %+v, want skipped_second_instance", v.Reconcile)
	}
	time.Sleep(500 * time.Millisecond)
	if m := r.mutatingCalls(); len(m) != 0 {
		t.Errorf("the second instance changed Docker: %v", m)
	}
	if files := r.journalFiles(); len(files) != 1 || files[0] != opID {
		t.Errorf("journal = %v, want the record kept", files)
	}
}

// TestConvergeRecovery_CorruptRecordStillRefusesToServe: converge does not
// change the fail-closed posture on an unreadable record (ADR-0061 decision 2).
func TestConvergeRecovery_CorruptRecordStillRefusesToServe(t *testing.T) {
	r := newCrashRig(t)
	r.converge("")
	if err := os.MkdirAll(filepath.Join(r.state, "reconcile"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.state, "reconcile", "01HZZZZZZZZZZZZZZZZZZZZZZZ.json"), []byte(`{"op_id":`), 0o600); err != nil {
		t.Fatal(err)
	}
	r.launch()
	done := make(chan error, 1)
	go func() { done <- r.cmd.Wait() }()
	select {
	case err := <-done:
		r.cmd = nil
		if err == nil {
			t.Fatalf("agent exited 0 on a corrupt record; output:\n%s", r.logs.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("agent kept running on a corrupt record; output:\n%s", r.logs.String())
	}
	if !strings.Contains(r.logs.String(), "refusing to serve") {
		t.Errorf("refusal not reported:\n%s", r.logs.String())
	}
	if m := r.mutatingCalls(); len(m) != 0 {
		t.Errorf("a refused start issued docker commands: %v", m)
	}
}

// TestOffMode_StatusAndStateUnchanged: with the default "off" the status
// payload carries no reconcile keys and no instance lock file is created.
func TestOffMode_StatusAndStateUnchanged(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	r.crashAt("up_before:1")
	r.start()
	raw := map[string]json.RawMessage{}
	r.get("/v1/status", &raw)
	for _, k := range []string{"reconcile", "recovery_required"} {
		if _, ok := raw[k]; ok {
			t.Errorf("status carries %q with reconcile_on_startup off", k)
		}
	}
	if _, err := os.Stat(filepath.Join(r.state, "reconcile", ".lock")); !os.IsNotExist(err) {
		t.Errorf("instance lock file exists in off mode (err=%v)", err)
	}
}

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

// TestConvergeRecovery_AMarkerIsEvidenceForOneStartOnly: the upgrade's `compose
// up` was cut AFTER the target came up. The start that follows finds the target
// running and, rightly, only reports; record and marker stay. Later the stack
// is taken down by hand and the agent restarts. The marker is still there and
// still names only that `compose up`, but it describes nothing about THIS
// outage: starting the prior image now would undo an operator's action (and
// start a version that was not the one serving). The second start must only
// report.
func TestConvergeRecovery_AMarkerIsEvidenceForOneStartOnly(t *testing.T) {
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

// TestConvergeRecovery_ACutRestoreIsRetriedOnceAndNoMore: the restore's own
// `compose up` is cut as well. The next start is the first to find THAT cut,
// it is still this operation's, and one attempt is left: the prior image is
// restored. The attempt cap (2) bounds it: a third start would only report.
func TestConvergeRecovery_ACutRestoreIsRetriedOnceAndNoMore(t *testing.T) {
	r := newCrashRig(t)
	r.pastFirstUse("0s")
	r.start()
	opID := r.crashAt("up_before:1")
	if err := os.Remove(filepath.Join(r.model, "running")); err != nil {
		t.Fatal(err)
	}
	r.converge("")
	r.killAgentAt("up_before:2") // the restore got as far as its own `compose up`
	if got := r.read("running"); got != "" {
		t.Fatalf("a container (%.8s) runs after the cut restore; the test needs the proxy down", got)
	}
	r.clearCalls()
	r.start()
	assertConverge(t, r, opID, convergeCase{[]string{"tag:" + refA, "up"}, true, "stack_down_up_interrupted", imgA, imgA, false})
}

// TestConvergeRecovery_RestoresThePriorImageWhenTheProxyIsDown: the agent died
// inside `compose up` and the proxy is not running. With the marker of that
// unfinished `up` on disk, the next start (converge) puts the tag back on the
// image that was serving, starts it, gates and verifies it, and retires the
// record: no operator action. Without the marker the same state is only
// reported, and nothing is started.
func TestConvergeRecovery_RestoresThePriorImageWhenTheProxyIsDown(t *testing.T) {
	for _, tc := range []struct {
		name       string
		withMarker bool
		settle     string
	}{
		{"own_up_cut", true, "0s"},
		// With a settle window: no proxy container is listed, so the wait ends
		// on the two quiet reads and the restore follows. It must not need the
		// window to be switched off.
		{"own_up_cut_settle_window", true, "20s"},
		{"no_marker", false, "0s"},
	} {
		withMarker := tc.withMarker
		t.Run(tc.name, func(t *testing.T) {
			r := newCrashRig(t)
			r.pastFirstUse(tc.settle)
			r.start()
			opID := r.crashAt("up_before:1") // tag on B, the agent inside `compose up`
			if err := os.Remove(filepath.Join(r.model, "running")); err != nil {
				t.Fatal(err) // the recreate got as far as stopping the old proxy
			}
			if !withMarker {
				if err := os.Remove(filepath.Join(r.state, "mutation", "pending.json")); err != nil {
					t.Fatalf("removing the marker: %v", err)
				}
			}
			r.converge("")
			r.clearCalls()
			r.start()
			if withMarker {
				assertConverge(t, r, opID, convergeCase{[]string{"tag:" + refA, "up"}, true, "stack_down_up_interrupted", imgA, imgA, false})
			} else {
				assertConverge(t, r, opID, convergeCase{nil, false, "stack_down", imgB, "", true})
			}
		})
	}
}
