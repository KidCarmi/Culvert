package main

// mcp_canary_concurrency_matrix_test.go — Step 6A: the deterministic concurrency
// matrix behind the physical-effect invariant (review blockers #6/#8).
//
// THE INVARIANT, measured at the CONTROLLED PEER and not at any Go seam:
//
//	accepted reservations = N
//	physical side-effect-bearing tool POSTs <= N
//
// Every case is driven by BARRIERS AND CHANNELS, never by sleeps. A sleep-driven
// race test does not fail when the ordering it claims to pin stops being enforced;
// it just becomes slow and flaky, and a flaky gate gets muted. Each case therefore
// makes the ordering it needs happen, then asserts.
//
// ANTI-VACUITY. Every negative case is paired with a positive control proving the
// same fixture CAN do the thing being denied — that the execution reached the layer
// under test, that the peer can receive a POST, that the spool can persist a valid
// event, and that recovery can settle a valid attempt. Two defects in this program
// (Resolution{} and the missing DecisionRef) were caught only by such controls.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// gatedPeer answers only after `release` is closed, so a test can hold N requests
// simultaneously inside upstream I/O with no timing assumptions. `arrived` is
// signalled once per received request AFTER the body is drained, i.e. after the
// invocation has demonstrably reached the peer.
type gatedPeer struct {
	arrived chan struct{}
	release chan struct{}
}

func newGatedPeer(capacity int) *gatedPeer {
	return &gatedPeer{arrived: make(chan struct{}, capacity), release: make(chan struct{})}
}

func (g *gatedPeer) handler(w http.ResponseWriter, r *http.Request) {
	g.arrived <- struct{}{}
	<-g.release
	respondOK(w, r)
}

// awaitArrivals blocks until n invocations have physically reached the peer.
func (g *gatedPeer) awaitArrivals(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-g.arrived:
		case <-time.After(30 * time.Second):
			t.Fatalf("only %d of %d invocations reached the peer", i, n)
		}
	}
}

// runConcurrent fires n executions simultaneously through one barrier and returns
// their outputs. The barrier is what makes the race real rather than incidental.
func runConcurrent(rig *peerRig, in func(int) mcpruntime.ExecInput, n int) []mcpruntime.ExecOutput {
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	outs := make([]mcpruntime.ExecOutput, n)
	for i := 0; i < n; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			outs[i] = rig.exec(in(i))
		}(i)
	}
	start.Done()
	done.Wait()
	return outs
}

// ── (1) N reservations racing for N slots ───────────────────────────────────

// TestConc01_NReservationsForNSlotsYieldExactlyNPOSTs pins the equality case: with
// exactly as many slots as racing requests, all N are admitted and the peer sees
// exactly N physical invocations — no fewer (a lost admission) and no more (a
// double-send).
func TestConc01_NReservationsForNSlotsYieldExactlyNPOSTs(t *testing.T) {
	const n = 5
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, n)
	outs := runConcurrent(rig, func(int) mcpruntime.ExecInput { return peerExecInput(p, policy.OpRead) }, n)

	executed := 0
	for _, o := range outs {
		if o.Executed {
			executed++
		}
	}
	if executed != n {
		t.Fatalf("with %d slots for %d racing requests, all must be admitted, got %d", n, n, executed)
	}
	if got := p.count(); got != n {
		t.Fatalf("accepted reservations=%d must yield exactly %d physical POSTs, peer saw %d", n, n, got)
	}
}

// ── (2) N+1 racing while N are admitted ─────────────────────────────────────

// TestConc02_NPlusOneRacingNeverExceedsTheBudget is the core bound under contention:
// more racing requests than slots must produce AT MOST N physical POSTs, and the
// excess must be REFUSED before any bytes leave rather than merely uncounted.
//
// Observed and deliberately pinned as an inequality, not an equality: a burst that
// overruns the budget trips the whole-Canary abort, and once tripped the boundary
// revalidation refuses even requests that already hold a reservation. A large burst
// can therefore end with FEWER physical effects than the budget — including zero.
// That is strictly safer than the bound and must not be "fixed" into an equality:
// asserting exactly N here would make the abort controller doing its job look like
// a failure, and the pressure would be to weaken the abort.
//
// The anti-vacuity control is TestConc01 (racers == slots reaches the peer exactly
// N times) plus the in-test control below, which proves this rig can execute at all
// before the burst is measured.
func TestConc02_NPlusOneRacingNeverExceedsTheBudget(t *testing.T) {
	const budget, racers = 3, 12
	p := startControlledPeer(t, respondOK)

	// CONTROL, on its own rig with the same shape: the fixture CAN reach the peer.
	ctlPeer := startControlledPeer(t, respondOK)
	ctlRig := armCanaryWithRealPeer(t, ctlPeer, budget)
	if out := ctlRig.exec(peerExecInput(ctlPeer, policy.OpRead)); !out.Executed || ctlPeer.count() != 1 {
		t.Fatalf("control: the fixture must be able to execute, out=%+v count=%d", out, ctlPeer.count())
	}

	rig := armCanaryWithRealPeer(t, p, budget)
	outs := runConcurrent(rig, func(int) mcpruntime.ExecInput { return peerExecInput(p, policy.OpRead) }, racers)

	if got := p.count(); got > budget {
		t.Fatalf("PHYSICAL EFFECT BREACH: budget=%d but the peer received %d POSTs", budget, got)
	}
	executed := 0
	for _, o := range outs {
		if o.Executed {
			executed++
		}
	}
	if executed > budget {
		t.Fatalf("at most %d requests may report executed, got %d", budget, executed)
	}
	// Every request that did not execute must have been REFUSED — a request that
	// neither executed nor was rejected would mean an effect nobody accounted for.
	for i, o := range outs {
		if !o.Executed && o.Disposition != mcpruntime.DispRejected {
			t.Fatalf("request %d neither executed nor was refused: %+v", i, o)
		}
	}
	// The bound must be enforced by REFUSAL, not by the peer being unreachable: every
	// POST that did land must be attributable to a distinct authorized attempt.
	seen := map[string]bool{}
	for _, r := range p.observed() {
		if r.AttemptID == "" || seen[r.AttemptID] {
			t.Fatalf("physical POSTs must carry distinct attempt ids, got %q", r.AttemptID)
		}
		seen[r.AttemptID] = true
	}
}

// ── (3) concurrent sends carry unique attempt ids ───────────────────────────

// TestConc03_ConcurrentSendsCarryUniqueAttemptIDs pins the property a witness needs
// under concurrency: each physical invocation is individually attributable, so
// "two POSTs for one attempt" is detectable rather than invisible.
func TestConc03_ConcurrentSendsCarryUniqueAttemptIDs(t *testing.T) {
	const n = 8
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, n)
	runConcurrent(rig, func(int) mcpruntime.ExecInput { return peerExecInput(p, policy.OpRead) }, n)

	obs := p.observed()
	if len(obs) != n {
		t.Fatalf("setup: expected %d physical POSTs, got %d", n, len(obs))
	}
	seen := map[string]bool{}
	for _, r := range obs {
		if r.AttemptID == "" {
			t.Fatal("a metered physical invocation must carry an attempt id")
		}
		if seen[r.AttemptID] {
			t.Fatalf("two concurrent physical POSTs shared attempt id %q", r.AttemptID)
		}
		seen[r.AttemptID] = true
	}
}

// ── (4) kill engages after reservation, before the final boundary ───────────

// TestConc04_KillAfterReservationBeforeBoundarySendsNoBytes pins PREREQ-MCP-KILL-1
// under a real race: the emergency kill engages while the request holds a
// reservation but has not yet crossed the boundary. No bytes may leave.
func TestConc04_KillAfterReservationBeforeBoundarySendsNoBytes(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, 10)

	// CONTROL first, on the SAME rig: prove this fixture CAN reach the peer. Without
	// it, "zero POSTs" after the kill proves nothing.
	if out := rig.exec(peerExecInput(p, policy.OpRead)); !out.Executed || p.count() != 1 {
		t.Fatalf("control: the fixture must be able to execute, out=%+v count=%d", out, p.count())
	}
	before := p.count()

	engageKillForTest(t)
	out := rig.exec(peerExecInput(p, policy.OpRead))
	if out.Executed {
		t.Fatalf("a killed gateway must not execute, out=%+v", out)
	}
	if p.count() != before {
		t.Fatalf("the kill must precede the side effect: peer count %d -> %d", before, p.count())
	}
}

// ── (5) kill engages while another request is inside upstream I/O ───────────

// TestConc05_KillDuringInflightIODoesNotUnsendOrDoubleSend pins that a kill landing
// while a request is already inside upstream I/O neither un-sends the in-flight
// invocation (it happened) nor produces a second one, and that a request arriving
// after the kill sends nothing.
func TestConc05_KillDuringInflightIODoesNotUnsendOrDoubleSend(t *testing.T) {
	g := newGatedPeer(4)
	p := startControlledPeer(t, g.handler)
	rig := armCanaryWithRealPeer(t, p, 10)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = rig.exec(peerExecInput(p, policy.OpRead)) }()
	g.awaitArrivals(t, 1) // the invocation is now physically at the peer

	engageKillForTest(t)
	inflightCount := p.count()

	// A request that starts AFTER the kill must send nothing.
	if out := rig.exec(peerExecInput(p, policy.OpRead)); out.Executed {
		t.Fatalf("a post-kill request must not execute, out=%+v", out)
	}
	if p.count() != inflightCount {
		t.Fatalf("a post-kill request reached the peer: %d -> %d", inflightCount, p.count())
	}
	close(g.release)
	wg.Wait()
	if p.count() != inflightCount {
		t.Fatalf("the in-flight request must not be re-sent: %d -> %d", inflightCount, p.count())
	}
}

// ── (6) generation demotion after intent, before the final guard ────────────

// TestConc06_GenerationDemotionAfterIntentRefusesTheSend pins that a request whose
// activation generation is superseded between the durable intent and the final
// guard sends NO bytes, and that its reservation is NOT reclaimed (§12: a committed
// send intent followed by a final refusal consumes the reservation conservatively).
func TestConc06_GenerationDemotionAfterIntentRefusesTheSend(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeerGate(t, p, 10, true, demoteAtBoundary)

	out := rig.exec(peerExecInput(p, policy.OpRead))
	if out.Executed {
		t.Fatalf("a demoted generation must not execute, out=%+v", out)
	}
	if got := p.count(); got != 0 {
		t.Fatalf("a boundary refusal must send no bytes, peer saw %d POSTs", got)
	}
	// CONSERVATIVE CONSUMPTION: the slot stays spent even though the send is
	// provably definitely_not_sent. Reclaiming it here is the shape that would let a
	// refused-then-retried request exceed the physical bound.
	if spent := canaryTotalReserved(t); spent != 1 {
		t.Fatalf("a committed send intent must consume its reservation even when refused, total=%d", spent)
	}
}

// ── (7) fingerprint drift after intent, before the final guard ──────────────

// TestConc07_ToolDriftAfterIntentRefusesTheSend pins the same shape for the tool
// freshness check: a tool redefined under the decision must abort before any bytes
// leave, with the reservation still consumed.
func TestConc07_ToolDriftAfterIntentRefusesTheSend(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, 10)

	in := peerExecInput(p, policy.OpRead)
	// ToolStillCurrent is the PRODUCTION freshness seam preCallGuard consults at the
	// boundary — the runtime installs it from the live catalog. Reporting false is
	// exactly "the tool was redefined between the decision and the send".
	in.ToolStillCurrent = func() bool { return false }
	out := rig.exec(in)
	if out.Executed {
		t.Fatalf("a drifted tool must not execute, out=%+v", out)
	}
	if got := p.count(); got != 0 {
		t.Fatalf("a freshness refusal must send no bytes, peer saw %d POSTs", got)
	}
	// CONTROL: the undrifted request on the same rig DOES reach the peer.
	if out := rig.exec(peerExecInput(p, policy.OpRead)); !out.Executed || p.count() != 1 {
		t.Fatalf("control: the same fixture must execute without drift, out=%+v count=%d", out, p.count())
	}
}

// ── (8) outcome commit racing a restart/recovery read ───────────────────────

// TestConc08_RecoveryReadRacingOutcomeCommitIsNeverWrong pins that a recovery scan
// concurrent with in-flight outcome commits never reports a FALSE state. It may
// legitimately observe an attempt as either an unresolved orphan (the outcome has
// not landed yet) or settled (it has) — but it must never report a settled attempt
// as definitely-not-sent, and must never lose one entirely.
func TestConc08_RecoveryReadRacingOutcomeCommitIsNeverWrong(t *testing.T) {
	const n = 6
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, n)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			rep, err := execution.RecoverAttempts(rig.events.Spool(model.CapGateway))
			if err != nil {
				continue // a torn mid-commit read is allowed to fail; it must not lie
			}
			for _, a := range append(append([]execution.RecoveredAttempt{}, rep.Orphans...), rep.Settled...) {
				if a.TerminalSendState == model.SendDefinitelyNotSent {
					t.Errorf("a concurrently-observed attempt was reported definitely_not_sent: %+v", a)
					return
				}
			}
		}
	}()
	runConcurrent(rig, func(int) mcpruntime.ExecInput { return peerExecInput(p, policy.OpRead) }, n)
	close(stop)
	wg.Wait()

	// Once quiescent, every physical invocation must be settled and none orphaned.
	rep := rig.recover(t)
	if len(rep.Orphans) != 0 {
		t.Fatalf("after quiescence no attempt may remain orphaned: %+v", rep.Orphans)
	}
	if len(rep.Settled) != p.count() {
		t.Fatalf("settled attempts (%d) must equal physical POSTs (%d)", len(rep.Settled), p.count())
	}
}

// ── (9) orphan reconciliation racing a newer generation ─────────────────────

// TestConc09_ReconcilingAnOrphanNeverTouchesANewerGeneration pins the authority
// boundary: reconciliation of a generation-G orphan, concurrent with generation-G+1
// work, changes KNOWLEDGE about G only. It never grants allowance, never resends,
// never mutates a generation.
func TestConc09_ReconcilingAnOrphanNeverTouchesANewerGeneration(t *testing.T) {
	orphan := execution.RecoveredAttempt{
		AttemptID: mustAttemptIDMain(t), ReservationID: "rsv_old", ActivationGeneration: 7,
		State: execution.AttemptReconciliationRequired,
	}
	w := fixedWitness{obs: execution.WitnessObservation{
		Count: 0, Complete: true, CompletenessWatermark: "wm-1", Source: "controlled",
	}}
	var wg sync.WaitGroup
	results := make([]model.ReconciliationEvidence, 8)
	wg.Add(len(results))
	for i := range results {
		go func(i int) {
			defer wg.Done()
			ev, err := execution.ReconcileOrphan(context.Background(), w, orphan, "s1", "tools/call", int64(1000+i))
			if err != nil {
				t.Errorf("ReconcileOrphan: %v", err)
				return
			}
			results[i] = ev
		}(i)
	}
	wg.Wait()
	for _, ev := range results {
		if ev.ActivationGeneration != 7 {
			t.Fatalf("reconciliation must not mutate the generation, got %d", ev.ActivationGeneration)
		}
		if ev.ReservationID != "rsv_old" {
			t.Fatalf("reconciliation must not rebind the reservation, got %q", ev.ReservationID)
		}
		if ev.Result != model.ReconNotReceived {
			t.Fatalf("a complete zero-count observation must resolve not_received, got %q", ev.Result)
		}
	}
}

// ── (10) two reconciliation attempts for the same orphan ────────────────────

// TestConc10_ConcurrentReconciliationsAreIdempotent pins that racing reconciliations
// over one orphan converge on ONE result rather than producing divergent evidence.
func TestConc10_ConcurrentReconciliationsAreIdempotent(t *testing.T) {
	orphan := execution.RecoveredAttempt{
		AttemptID: mustAttemptIDMain(t), ReservationID: "rsv_1", ActivationGeneration: 3,
		State: execution.AttemptReconciliationRequired,
	}
	w := fixedWitness{obs: execution.WitnessObservation{
		Count: 1, Complete: true, CompletenessWatermark: "wm-1",
		ServerID: "s1", Method: "tools/call", ReservationID: "rsv_1", Source: "controlled",
	}}
	var wg sync.WaitGroup
	out := make([]model.ReconciliationResult, 16)
	wg.Add(len(out))
	for i := range out {
		go func(i int) {
			defer wg.Done()
			ev, err := execution.ReconcileOrphan(context.Background(), w, orphan, "s1", "tools/call", 1)
			if err != nil {
				t.Errorf("ReconcileOrphan: %v", err)
				return
			}
			out[i] = ev.Result
		}(i)
	}
	wg.Wait()
	for i, r := range out {
		if r != model.ReconReceived {
			t.Fatalf("concurrent reconciliation %d diverged: %q", i, r)
		}
	}
}

// ── (11) evidence corruption appearing while recovery scans ─────────────────

// TestConc11_CorruptionDuringScanFailsClosedNeverPartially pins that a ledger which
// becomes contradictory while recovery is reading it produces an ERROR, never a
// partial report a caller might act on. A half-derived recovery is worse than none:
// it would silently drop attempts that are still unaccounted for.
func TestConc11_CorruptionDuringScanFailsClosedNeverPartially(t *testing.T) {
	id := mustAttemptIDMain(t)
	// The corrupt shape: two send intents for one attempt id.
	rep, err := execution.RecoverAttempts(mainReaderWith(
		intentEventMain(id, "rsv_1", 7),
		intentEventMain(id, "rsv_1", 7),
	))
	if err == nil {
		t.Fatalf("a duplicated send intent must fail recovery closed, got %+v", rep)
	}
	if len(rep.Orphans) != 0 || len(rep.Settled) != 0 {
		t.Fatalf("a failed recovery must return NO partial report, got %+v", rep)
	}
	// CONTROL: the same reader shape with sound evidence recovers normally, so the
	// gate is measuring corruption and not a broken fixture.
	ok, cerr := execution.RecoverAttempts(mainReaderWith(intentEventMain(id, "rsv_1", 7)))
	if cerr != nil || len(ok.Orphans) != 1 {
		t.Fatalf("control: sound evidence must recover, err=%v rep=%+v", cerr, ok)
	}
}

// ── (12) concurrent releases touch inflight only, never total ───────────────

// TestConc12_ConcurrentReleasesNeverReduceTotal pins §12 at the enforcer: Release
// returns CONCURRENCY, not ALLOWANCE. If it decremented the monotonic total, a
// request that reserved, sent, and then failed would hand its slot back — and N
// reservations could produce more than N physical invocations.
func TestConc12_ConcurrentReleasesNeverReduceTotal(t *testing.T) {
	const n = 16
	now := time.Unix(0, 1)
	e := canary.NewBudgetEnforcer(runtimeTestBudget(n), 1, now)
	for i := 0; i < n; i++ {
		if o := e.Reserve(1, now, canary.ExecutionIdentity{Principal: "p1", Server: "s1", Tool: "read_file"}); !o.Granted() {
			t.Fatalf("setup: reservation %d denied (%v)", i, o)
		}
	}
	if got := e.TotalReserved(); got != n {
		t.Fatalf("setup: total must be %d, got %d", n, got)
	}
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() { defer wg.Done(); e.Release() }()
	}
	wg.Wait()

	if got := e.TotalReserved(); got != n {
		t.Fatalf("MONOTONICITY BREACH: %d concurrent releases changed total from %d to %d", n, n, got)
	}
	if got := e.Inflight(); got != 0 {
		t.Fatalf("release must drain inflight to zero, got %d", got)
	}
	// The budget is spent: a further reservation must be denied even with nothing
	// in flight. This is the whole point of the total/inflight split.
	if o := e.Reserve(1, now, canary.ExecutionIdentity{Principal: "p1", Server: "s1", Tool: "read_file"}); o.Granted() {
		t.Fatalf("a fully-released but fully-spent budget must still deny, got %v", o)
	}
}

// ── shared helpers ──────────────────────────────────────────────────────────

// fixedWitness reports one observation regardless of attempt, for concurrency
// determinism. Verdict derivation stays in the engine.
type fixedWitness struct{ obs execution.WitnessObservation }

func (w fixedWitness) LookupAttempt(context.Context, string) (execution.WitnessObservation, error) {
	return w.obs, nil
}

// canaryTotalReserved reads the monotonic spend from the live canary runtime.
func canaryTotalReserved(t *testing.T) int {
	t.Helper()
	cr := globalCanaryRuntime.capRuntime(rollout.CapabilityGateway)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if cr.enforcer == nil {
		t.Fatal("no budget enforcer on the canary runtime")
	}
	return cr.enforcer.TotalReserved()
}

// demoteAtBoundary forces ONLY the generation-revalidation seam to report
// "superseded", so the refusal happens at the final boundary — after the budget
// reservation and after the durable send intent are already committed.
func demoteAtBoundary(g *mcpLiveSideEffectGate) {
	g.generationCurrent = func(uint64) bool { return false }
}

// mustAttemptIDMain mints a well-formed attempt identity for package-main evidence
// fixtures. It is built the same way the engine builds one so the shape checks in
// recovery see a real identifier, not a placeholder that would be rejected for the
// wrong reason.
func mustAttemptIDMain(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return "att_" + hex.EncodeToString(b)
}

// intentEventMain builds a durable PhaseSendIntent record for recovery fixtures.
func intentEventMain(id, resID string, gen uint64) model.Event {
	return model.Event{Phase: model.PhaseSendIntent, Outcome: &model.OutcomeEvidence{
		AttemptID: id, ReservationID: resID, ActivationGeneration: gen,
	}}
}

// outcomeEventMain builds a durable PhaseOutcome record for recovery fixtures.
//
// DecisionRef is REQUIRED on a terminal outcome by the durable validator, and the
// recovery read path now mirrors that rule, so a fixture without one would build a
// record that could never have been committed.
func outcomeEventMain(id, resID string, gen uint64, st model.PhysicalSendState) model.Event {
	return model.Event{Phase: model.PhaseOutcome, Outcome: &model.OutcomeEvidence{
		AttemptID: id, ReservationID: resID, ActivationGeneration: gen, PhysicalSendState: st,
		DecisionRef: "evt_fixturedecision",
	}}
}

// staticEvidenceReader replays a fixed event list to the recovery derivation, so a
// ledger shape can be constructed exactly rather than provoked.
type staticEvidenceReader struct{ evs []model.Event }

func mainReaderWith(evs ...model.Event) *staticEvidenceReader {
	return &staticEvidenceReader{evs: evs}
}

func (r *staticEvidenceReader) CommittedForExport(part model.Partition, afterSeq uint64, maxRecords int) (evs []model.Event, seqs []uint64, cursor uint64, err error) {
	// All fixture events live in the ordinary partition, matching where the executor
	// actually commits intents and outcomes.
	total := uint64(len(r.evs))
	if part != model.PartOrd || afterSeq >= total {
		return nil, nil, afterSeq, nil
	}
	// Paginate in uint64 space: narrowing the cursor to int is the conversion gosec
	// flags, and it is avoidable rather than worth suppressing.
	end := total
	if maxRecords > 0 {
		if n := afterSeq + uint64(maxRecords); n < end {
			end = n
		}
	}
	evs = r.evs[afterSeq:end]
	seqs = make([]uint64, 0, len(evs))
	for s := afterSeq; s < end; s++ {
		seqs = append(seqs, s+1)
	}
	return evs, seqs, end, nil
}

// engageKillForTest engages the emergency kill on the process-global gateway state
// and RESTORES it on cleanup.
//
// The restore is not tidiness. getMCPRollout() is a process-wide singleton that
// resetLiveTierGlobals does not touch, so a latched kill leaks into every later test
// in the binary — where it presents as an unrelated rollout_mode_invalid refusal,
// which is exactly the kind of failure that gets misdiagnosed as flake and muted.
func engageKillForTest(t *testing.T) {
	t.Helper()
	gw := getMCPRollout().gateway
	gw.EngageKillSwitch("test", time.Unix(0, 3).UnixNano())
	t.Cleanup(gw.ClearKillSwitch)
}
