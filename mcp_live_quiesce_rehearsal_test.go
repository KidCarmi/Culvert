package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// CANARY-ROLLBACK-LIVE-QUIESCE-REHEARSAL — the executable, controlled live-armed rehearsal (§15).
//
// It drives the FULL sequence on the REAL composed live tier with a SYNTHETIC recording upstream and
// NO real credential (§19), asserting every required proof, and records durable build-bound evidence
// only when they all hold. This is the drill that closes the prerequisite for a build.

func TestLiveQuiesceRehearsal_FullSequence(t *testing.T) {
	// A blocking upstream so an execution can be held "in flight" deterministically during quiesce.
	up := &recordingUpstream{block: make(chan struct{}, 4)}
	cfg := armCanaryLiveTier(t, up, true, 100)
	ex := cfg.Deps.Executor
	lt := mcpLiveTierFor(rollout.CapabilityGateway)
	capb := rollout.CapabilityGateway
	now := time.Unix(0, 1)
	var proofs []string

	// ── PROOF 1: arm → execute. A trusted, in-budget, read-first request crosses the boundary. ──
	up.block <- struct{}{} // let this one through immediately
	in := liveExecInput(policy.OpRead, "t1", "p1")
	if out := ex.Execute(context.Background(), in, ex.Resolve(in)); !out.Executed || up.callCount() != 1 {
		t.Fatalf("arm→execute: want executed with 1 upstream call, got executed=%v calls=%d", out.Executed, up.callCount())
	}
	genBefore := globalCanaryRuntime.currentGeneration(capb)
	if genBefore == 0 || !globalCanaryRuntime.armed(capb) {
		t.Fatalf("Canary runtime must be armed with a non-zero generation, gen=%d", genBefore)
	}
	proofs = append(proofs, "armed_live_execution_crossed_boundary")

	// ── PROOF 2: quiesce → no new admitted, in-flight drains, live goes OFF. ──
	// Hold ONE execution in flight (upstream blocks), then quiesce concurrently.
	inflightStarted := make(chan struct{})
	inflightDone := make(chan runtimeExecResult, 1)
	go func() {
		close(inflightStarted)
		o := ex.Execute(context.Background(), in, ex.Resolve(in))
		inflightDone <- runtimeExecResult{executed: o.Executed}
	}()
	<-inflightStarted
	// Wait until the in-flight execution has been admitted (in-flight count == 1) — deterministic via
	// the observable count, not a sleep.
	for i := 0; i < 5_000_000 && lt.inFlightCount() == 0; i++ {
	}
	if lt.inFlightCount() != 1 {
		t.Fatalf("one execution must be in flight before quiesce, got %d", lt.inFlightCount())
	}
	// Quiesce on a goroutine — it un-arms immediately, then drains the one in-flight execution.
	quiesceDone := make(chan int, 1)
	go func() { quiesceDone <- quiesceLiveTier(capb, 5*time.Second) }()
	for i := 0; i < 5_000_000 && lt.armed(); i++ {
	}
	// Live is now OFF — the demote precondition (§15 "quiesce the live tier before the demotion").
	if liveExecDepsConfigured(false) {
		t.Fatal("quiesce must clear the armed bit before draining (live OFF is the demote precondition)")
	}
	// A NEW execution during quiesce is rejected at the gate (§6) — upstream count unchanged.
	callsBefore := up.callCount()
	rej := ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != callsBefore || rej.Executed {
		t.Fatalf("a quiescing tier must reject a new execution (no upstream call), calls delta=%d", up.callCount()-callsBefore)
	}
	// Release the in-flight execution → drain completes cleanly.
	up.block <- struct{}{}
	<-inflightDone
	if rem := <-quiesceDone; rem != 0 {
		t.Fatalf("the in-flight execution must drain cleanly, residual=%d", rem)
	}
	proofs = append(proofs, "quiesce_rejected_new_and_drained_inflight")

	// ── PROOF 3: kill terminates the side-effect eligibility window. ──
	// Re-arm, engage the emergency kill, and prove a subsequent execution is refused at the boundary
	// (upstream not reached) with the emergency reason.
	if err := lt.arm(true, "armed"); err != nil {
		t.Fatalf("re-arm for kill proof: %v", err)
	}
	getMCPRollout().gateway.EngageKillSwitch("rehearsal", now.UnixNano())
	callsBeforeKill := up.callCount()
	up.block <- struct{}{} // would let it through — but the kill must stop it first
	killOut := ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != callsBeforeKill {
		t.Fatalf("an engaged emergency kill must terminate the side-effect window (Upstream.Call == 0), calls delta=%d", up.callCount()-callsBeforeKill)
	}
	if killOut.Executed {
		t.Fatal("no execution may occur while the emergency kill is engaged")
	}
	// drain the token we pushed (the call never consumed it because kill stopped it at admission).
	select {
	case <-up.block:
	default:
	}
	proofs = append(proofs, "emergency_kill_terminated_side_effect_window")

	// ── PROOF 4: demotion uses the REAL coordinator; the Canary generation is invalidated. ──
	// Quiesce (live already effectively unusable under kill), then drive a REAL Canary→Observe
	// demotion through commitRolloutTransitionAt (the single authoritative coordinator), which fires
	// demoteCanary via the runtime-reconcile path. Clear the kill first so the transition to a
	// non-executing mode is not conflated with the kill (a demotion to Observe requires no exec deps).
	_ = quiesceLiveTier(capb, time.Second)
	getMCPRollout().gateway.ClearKillSwitch()
	if err := getMCPRollout().commitRolloutTransitionAt(gwObserveCfg(), "rehearsal", now, rollout.OriginSynthetic); err != nil {
		t.Fatalf("coordinator Canary→Observe demotion failed: %v", err)
	}
	if globalCanaryRuntime.armed(capb) {
		t.Fatal("the coordinator demotion must invalidate the Canary runtime (demoteCanary): still armed")
	}
	if globalCanaryRuntime.executionEligible(capb, now) {
		t.Fatal("a demoted Canary runtime must not be execution-eligible")
	}
	proofs = append(proofs, "coordinator_demotion_invalidated_generation")

	// ── PROOF 5: persist/recover — a restart does NOT re-arm. ──
	// The lifecycle re-composes on restart but never re-arms (§17); the canary runtime restore does
	// not restore a demoted generation as armed.
	lt.disarmForRestart()
	globalCanaryRuntime.restore() // re-read durable canary-runtime state (the demotion removed/disarmed it)
	if lt.State() != liveTierComposed || lt.armed() {
		t.Fatalf("restart posture must be composed+unarmed, got %s", lt.State())
	}
	if globalCanaryRuntime.armed(capb) {
		t.Fatal("a restart must not re-arm a demoted Canary runtime (§17)")
	}
	proofs = append(proofs, "restart_does_not_re_arm")

	// ── PROOF 6: live trust is not resurrected / evidence preserved. The tier is composed (executor
	// still installed) but unarmed, and admits no new execution. ──
	if !lt.composed() {
		t.Fatal("the executor stays composed across the rehearsal (evidence/trust preserved)")
	}
	if _, ok := lt.admitExecution(); ok {
		t.Fatal("an unarmed tier admits no execution (trust cannot be resurrected into a live grant)")
	}
	proofs = append(proofs, "live_trust_not_resurrected")

	// ── Record durable build-bound evidence; the drill's proofs all held. ──
	if err := recordLiveQuiesceRehearsal(capb, proofs, now); err != nil {
		t.Fatalf("record rehearsal evidence: %v", err)
	}
	if !liveQuiesceRehearsed(capb) {
		t.Fatal("a successful drill must produce a valid current-build rehearsal record")
	}
}

// runtimeExecResult is a tiny channel payload for the in-flight goroutine.
type runtimeExecResult struct{ executed bool }

// TestLiveQuiesceRehearsal_EvidenceIsBuildBound proves the record is fail-closed against a build
// change and corruption — a prior build's (or tampered) rehearsal never counts as CLOSED.
func TestLiveQuiesceRehearsal_EvidenceIsBuildBound(t *testing.T) {
	setDataDirForTest(t, t.TempDir())
	pinTestBuildVersion(t) // a valid rehearsal record requires a non-placeholder build stamp
	capb := rollout.CapabilityGateway
	if liveQuiesceRehearsed(capb) {
		t.Fatal("no record ⇒ not rehearsed (fail-closed)")
	}
	if err := recordLiveQuiesceRehearsal(capb, append([]string(nil), liveQuiesceRehearsalRequiredProofs...), time.Unix(0, 1)); err != nil {
		t.Fatalf("record: %v", err)
	}
	if !liveQuiesceRehearsed(capb) {
		t.Fatal("a fresh current-build record must read rehearsed")
	}
	// A build change must invalidate it (a materially changed build does not inherit a prior
	// build's rehearsal). Change the process version stamp and re-read.
	prev := version
	version = "v-canary-test-DIFFERENT"
	t.Cleanup(func() { version = prev })
	if liveQuiesceRehearsed(capb) {
		t.Fatal("a record from a DIFFERENT build must not count as rehearsed (fail-closed)")
	}
}

// TestLiveQuiesceRehearsal_RequiresCompleteProofRoster proves the record must carry the EXACT required
// proof roster, not merely a non-empty slice — a partial record is refused on write AND reads as not
// rehearsed (Codex P2 round-7, PR #1290).
func TestLiveQuiesceRehearsal_RequiresCompleteProofRoster(t *testing.T) {
	setDataDirForTest(t, t.TempDir())
	pinTestBuildVersion(t)
	capb := rollout.CapabilityGateway

	// A write with a partial roster is refused fail-closed and leaves no consumable record.
	if err := recordLiveQuiesceRehearsal(capb, []string{"armed_live_execution_crossed_boundary"}, time.Unix(0, 1)); !errors.Is(err, errLiveQuiesceRehearsalIncompleteProofs) {
		t.Fatalf("a partial proof roster must be refused on write, got %v", err)
	}
	if liveQuiesceRehearsed(capb) {
		t.Fatal("a refused write must leave no consumable record")
	}

	// A record written to disk with a partial roster (bypassing the write guard) must READ as not
	// rehearsed — the read path validates the exact roster independently.
	partial := liveQuiesceRehearsalRecord{
		SchemaVersion: liveQuiesceRehearsalSchemaVersion,
		Capability:    capb.String(),
		BuildVersion:  currentRuntimeIdentity().BuildVersion,
		Proofs:        append([]string(nil), liveQuiesceRehearsalRequiredProofs[:3]...), // only the first 3
		RehearsedAt:   1,
	}
	raw, err := json.Marshal(partial)
	if err != nil {
		t.Fatalf("marshal partial: %v", err)
	}
	if werr := fileutil.AtomicWrite(liveQuiesceRehearsalPath(capb), raw, 0o600); werr != nil {
		t.Fatalf("write partial: %v", werr)
	}
	if liveQuiesceRehearsed(capb) {
		t.Fatal("a record missing required proofs must not count as rehearsed (fail-closed)")
	}

	// The EXACT complete roster reads rehearsed.
	if err := recordLiveQuiesceRehearsal(capb, append([]string(nil), liveQuiesceRehearsalRequiredProofs...), time.Unix(0, 2)); err != nil {
		t.Fatalf("full-roster record: %v", err)
	}
	if !liveQuiesceRehearsed(capb) {
		t.Fatal("the exact complete roster must read rehearsed")
	}
}

// TestLiveQuiesceRehearsal_RejectsTrailingDelimiter proves the strict decoder rejects a valid record
// followed by any trailing token — including a "}" or "]" that dec.More() alone would let slip past
// (Codex P2 round-7, PR #1290).
func TestLiveQuiesceRehearsal_RejectsTrailingDelimiter(t *testing.T) {
	valid := `{"schema_version":1,"capability":"gateway","build_version":"x","proofs":["a"],"rehearsed_at_unix":1}`
	for _, tc := range []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"clean", valid, false},
		{"trailing_brace", valid + "}", true},
		{"trailing_bracket", valid + "]", true},
		{"trailing_value", valid + " 5", true},
		{"trailing_object", valid + " {}", true},
	} {
		var rec liveQuiesceRehearsalRecord
		err := strictDecodeLiveQuiesceRehearsalJSON([]byte(tc.raw), &rec)
		if tc.wantErr && err == nil {
			t.Fatalf("%s: trailing data must be rejected (fail-closed)", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("%s: a single valid value must decode, got %v", tc.name, err)
		}
	}
}
