package main

// ha_lease_recovery_chaos_test.go — CHAOS-55 reproduction gates.
//
// Every test in this file was verified FAILING against the pre-fix tree before
// the fix landed. They pin the recovery half of ADR-0005: a node that loses (or
// cannot take) the fencing lease must find its own way back once the backend
// returns, without an operator.

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// outageProvider wraps a Provider with an operator-controlled "backend
// unreachable" switch: every RPC returns a transport error while it is armed.
// That is the etcd-is-down shape — distinct from a DENIAL, which the real
// backend reports as (false, status, nil).
type outageProvider struct {
	halease.Provider
	down atomic.Bool

	acquires atomic.Int64
	reads    atomic.Int64
}

var errBackendDown = errors.New("halease: connection refused (simulated etcd outage)")

func (o *outageProvider) Acquire(ctx context.Context, candidateID string) (bool, halease.Status, error) {
	o.acquires.Add(1)
	if o.down.Load() {
		return false, halease.Status{}, errBackendDown
	}
	return o.Provider.Acquire(ctx, candidateID)
}

func (o *outageProvider) Renew(ctx context.Context, holderID string, epoch int64) (bool, time.Duration, error) {
	if o.down.Load() {
		return false, 0, errBackendDown
	}
	return o.Provider.Renew(ctx, holderID, epoch)
}

func (o *outageProvider) Read(ctx context.Context) (halease.Status, error) {
	o.reads.Add(1)
	if o.down.Load() {
		return halease.Status{}, errBackendDown
	}
	return o.Provider.Read(ctx)
}

// resumingLeader builds the state a leader restart reconstitutes: HA enabled,
// persisted role=leader, a lease provider armed, nothing acquired yet.
func resumingLeader(t *testing.T, p halease.Provider, id string) (*HAState, *haConfig) {
	t.Helper()
	h := &HAState{}
	h.SetLeaseProvider(p, id)
	cfg := &haConfig{
		Enabled:  true,
		Token:    "ha-token",
		PeerAddr: "cp-peer:50051",
		Role:     "leader",
		Term:     11,
	}
	return h, cfg
}

// haWaitFor polls cond until it holds or the budget elapses.
func haWaitFor(budget time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// ── HA-7a: a transient backend outage during a leader restart ───────────────

// The registered HA-7 gate: resume denied (backend unreachable) → the backend
// comes back → write authority must return with NO operator action.
//
// Pre-fix: acquireLeaseForResume returns false on the FIRST transport error
// (never spending its 45 s budget on the one fault that actually happens at
// boot), ResumeAsLeader then asserts role=leader with leaseEpoch=0, and
// startLeaseKeepalive no-ops because the epoch is 0 — so nothing in the process
// ever calls Acquire again. WriteAllowed() stays false until an operator acts.
func TestChaos55_ResumeDuringBackendOutage_RegainsWriteAuthority(t *testing.T) {
	tempHADir(t)
	o := &outageProvider{Provider: halease.NewFake(4 * time.Second)}
	o.down.Store(true)

	h, cfg := resumingLeader(t, o, "cp-a")
	h.ResumeAsLeader(cfg)
	defer h.Stop()

	if h.WriteAllowed() {
		t.Fatal("a leader that could not reach the fencing backend must have NO write authority")
	}
	if got := h.Status().Role; got != "leader" {
		t.Fatalf("role = %q, want leader (the persisted role is honoured)", got)
	}

	// etcd comes back. No operator, no restart.
	o.down.Store(false)

	if !haWaitFor(20*time.Second, h.WriteAllowed) {
		t.Fatal("HA-7: write authority never returned after the fencing backend recovered — " +
			"the node is a permanently read-only leader until an operator intervenes")
	}
	if h.CurrentEpoch() == 0 {
		t.Error("recovered leader must carry a live fencing epoch")
	}
	if got := h.Status().Term; got != termFromEpoch(h.CurrentEpoch()) {
		t.Errorf("term = %d, want the fencing epoch %d (ADR-0005 Finding 6 collapse)", got, h.CurrentEpoch())
	}
}

// The recovery must be driven by the keepalive contract, not a one-shot: once
// re-acquired, the lease has to keep being renewed or the node self-fences one
// TTL later and we are back where we started.
func TestChaos55_RecoveredLeaderKeepsRenewing(t *testing.T) {
	tempHADir(t)
	o := &outageProvider{Provider: halease.NewFake(3 * time.Second)}
	o.down.Store(true)

	h, cfg := resumingLeader(t, o, "cp-a")
	h.ResumeAsLeader(cfg)
	defer h.Stop()

	o.down.Store(false)
	if !haWaitFor(20*time.Second, h.WriteAllowed) {
		t.Fatal("write authority never returned")
	}
	// Hold well past a full TTL: a recovered leader that never started its
	// keepalive would lose authority again after one lease period.
	time.Sleep(4 * time.Second)
	if !h.WriteAllowed() {
		t.Fatal("recovered leader lost write authority — the keepalive loop was not started after re-acquisition")
	}
}

// ── The safety half: recovery must never override the fence ─────────────────

// While this node was unfenced, another node legitimately took the lease. With
// a recorded ex-standby it must re-enter standby against the new leader — the
// same disposition the shipped S4 path takes for a resume denied by a live
// holder.
func TestChaos55_ForeignHolderSeenDuringRecovery_EntersStandby(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(30 * time.Second)
	o := &outageProvider{Provider: f}
	o.down.Store(true)

	h, cfg := resumingLeader(t, o, "cp-a")
	cfg.StandbyAddr = "cp-b:50051"
	h.SetResyncMaterial(context.Background(), "cp-a:50051", "", "", "")
	h.ResumeAsLeader(cfg)
	defer h.Stop()

	// The peer promoted while we were blind.
	if granted, _, _ := f.Acquire(context.Background(), "cp-b"); !granted {
		t.Fatal("seed: peer acquire")
	}
	o.down.Store(false)

	if !haWaitFor(20*time.Second, func() bool { return h.Status().Role == "standby" }) {
		t.Fatalf("node stayed %q while another node held the fence — an unfenced leader must stand down once it can see the fence again",
			h.Status().Role)
	}
	if h.WriteAllowed() {
		t.Error("a demoted node must have no write authority")
	}
	if h.CurrentEpoch() != 0 {
		t.Error("a demoted node must carry no fencing epoch")
	}
}

// The same observation with NO resync target keeps the shipped ADR-0005 S2
// stance — read-only leader role, CRITICAL alert — and LATCHES: once another
// node has demonstrably led, this node's state may be arbitrarily stale, so it
// must not silently take over when that holder later disappears. That decision
// belongs to the standby machinery's freshness gate, or to an operator.
func TestChaos55_ForeignHolderWithoutTarget_LatchesAndStopsRetrying(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(2 * time.Second)
	o := &outageProvider{Provider: f}
	o.down.Store(true)

	h, cfg := resumingLeader(t, o, "cp-a") // no StandbyAddr, no resync material
	h.ResumeAsLeader(cfg)
	defer h.Stop()

	if granted, _, _ := f.Acquire(context.Background(), "cp-b"); !granted {
		t.Fatal("seed: peer acquire")
	}
	o.down.Store(false)

	// The loop must stop of its own accord once it sees the foreign holder.
	if !haWaitFor(20*time.Second, func() bool { return !h.leaseRecoveryActive() }) {
		t.Fatal("recovery loop kept running after observing a foreign fence holder")
	}
	if got := h.Status().Role; got != "leader" {
		t.Errorf("role = %q, want leader (the shipped S2 stance: role kept, no write authority)", got)
	}
	if h.WriteAllowed() {
		t.Fatal("must have no write authority while another node holds the fence")
	}

	// The foreign holder goes away entirely. A latched node must NOT take over.
	f.ExpireForTest()
	time.Sleep(2 * time.Second)
	if h.WriteAllowed() {
		t.Fatal("a node that observed another leader must not silently re-acquire when that leader vanishes — " +
			"its state may be arbitrarily stale, and that decision belongs to the freshness gate or an operator")
	}
}

// A denial by another holder on the resume itself is a REAL fence decision, not
// an unknown: it must not be retried into leadership.
func TestChaos55_RealDenialIsNotRetriedIntoLeadership(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(30 * time.Second)
	if granted, _, _ := f.Acquire(context.Background(), "cp-b"); !granted {
		t.Fatal("seed: peer acquire")
	}
	o := &outageProvider{Provider: f}

	h, cfg := resumingLeader(t, o, "cp-a")
	start := time.Now()
	h.ResumeAsLeader(cfg)
	defer h.Stop()

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("a denial by a live foreign holder must return promptly, took %s", elapsed)
	}
	// Give any recovery loop a chance to misbehave.
	time.Sleep(500 * time.Millisecond)
	if h.WriteAllowed() {
		t.Fatal("node took write authority while another node demonstrably holds the fence")
	}
}

// ── The other half of the budget: the ghost-lease path still works ──────────

// A fast leader restart finds its OWN previous process's lease still live. That
// must still be waited out (the pre-existing S5 behaviour), not treated as a
// foreign holder.
func TestChaos55_OwnGhostLeaseStillWaitedOut(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(3 * time.Second)
	if granted, _, _ := f.Acquire(context.Background(), "cp-a"); !granted {
		t.Fatal("seed: our own previous process")
	}
	o := &outageProvider{Provider: f}

	h, cfg := resumingLeader(t, o, "cp-a")
	h.ResumeAsLeader(cfg)
	defer h.Stop()

	if !haWaitFor(20*time.Second, h.WriteAllowed) {
		t.Fatal("a restarting leader must wait out its own ghost lease and resume with write authority")
	}
	if h.Status().Role != "leader" {
		t.Errorf("role = %q, want leader", h.Status().Role)
	}
}

// ── Legacy mode is untouched ────────────────────────────────────────────────

func TestChaos55_LegacyModeUnchanged(t *testing.T) {
	tempHADir(t)
	h := &HAState{} // nil provider
	cfg := &haConfig{Enabled: true, Role: "leader", Term: 3, Token: "t"}
	h.ResumeAsLeader(cfg)
	defer h.Stop()

	if !h.WriteAllowed() {
		t.Error("legacy mode must always report write authority at the lease layer")
	}
	if got := h.Status().Term; got != 3 {
		t.Errorf("term = %d, want the persisted 3 (legacy resume never bumps)", got)
	}
	if h.leaseRecoveryActive() {
		t.Error("legacy mode must never arm a lease-recovery loop")
	}
}

// ── The resume budget itself ────────────────────────────────────────────────

// A backend that is a few seconds behind us at boot is the common case, and it
// must be absorbed by the resume acquire — no read-only window, no recovery
// loop, no alert. Pre-fix this returned false on the first transport error and
// the node came up unfenced.
func TestChaos55_ResumeAbsorbsAShortBackendOutage(t *testing.T) {
	tempHADir(t)
	o := &outageProvider{Provider: halease.NewFake(10 * time.Second)}
	o.down.Store(true)
	go func() {
		time.Sleep(3 * time.Second)
		o.down.Store(false)
	}()

	h, cfg := resumingLeader(t, o, "cp-a")
	h.ResumeAsLeader(cfg)
	defer h.Stop()

	if !h.WriteAllowed() {
		t.Fatal("the resume acquire must spend its haResumeGhostWait budget on a transport error — " +
			"a backend seconds behind us at boot must not produce an unfenced leader")
	}
	if h.leaseRecoveryActive() {
		t.Error("no background recovery should be needed when the resume acquire succeeded")
	}
	if o.acquires.Load() < 2 {
		t.Errorf("resume made %d acquire attempts, want ≥2 (the first was the one that failed)", o.acquires.Load())
	}
}

// ── Shutdown must never wait out a backoff ──────────────────────────────────

// CHAOS-54's rule, applied to this loop: Stop() closes the recovery channel and
// the sleep selects on it. A non-interruptible sleep would put up to
// haLeaseRecoveryMaxBackoff (30 s) between SIGTERM and process exit.
//
// Many trials, deliberately: where Stop lands inside a sleep is uniform, so a
// single trial passes a broken build most of the time.
func TestChaos55_StopIsPromptDuringRecoveryBackoff(t *testing.T) {
	tempHADir(t)
	for trial := 0; trial < 8; trial++ {
		o := &outageProvider{Provider: halease.NewFake(10 * time.Second)}
		o.down.Store(true)
		h, cfg := resumingLeader(t, o, "cp-a")
		h.ResumeAsLeader(cfg)
		if !h.leaseRecoveryActive() {
			t.Fatal("recovery loop must be armed for an unfenced leader")
		}
		// Land inside a backoff sleep rather than inside an RPC.
		time.Sleep(time.Duration(20+trial*7) * time.Millisecond)
		start := time.Now()
		h.Stop()
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("trial %d: Stop took %s — the recovery backoff is not interruptible", trial, elapsed)
		}
		if h.leaseRecoveryActive() {
			t.Fatalf("trial %d: recovery loop still armed after Stop", trial)
		}
	}
}

// ── The loop's arming conditions ────────────────────────────────────────────

// A standby without the fence is the NORMAL steady state, not a fault. Arming
// recovery there would turn every standby into a candidate racing for
// leadership on every tick, bypassing the freshness and hysteresis gates that
// ha_failover.go exists to apply.
func TestChaos55_RecoveryNeverArmsForAStandby(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(10 * time.Second)
	h := leaseStandby(f, "cp-me")
	defer h.Stop()

	h.startLeaseRecovery()
	if h.leaseRecoveryActive() {
		t.Fatal("a standby must never arm the lease-recovery loop — promotion is the standby loop's decision, gated on freshness and hysteresis")
	}
}

// A leader that HOLDS the fence has nothing to recover; arming would spend RPCs
// forever on a healthy node.
func TestChaos55_RecoveryNeverArmsForAHealthyLeader(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(10 * time.Second)
	h := leaseStandby(f, "cp-me")
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("PromoteManually: %v", err)
	}
	defer h.Stop()

	h.startLeaseRecovery()
	if h.leaseRecoveryActive() {
		t.Fatal("a leader holding the fence must never arm the recovery loop")
	}
}

// ── Observability: an unfenced leader must not look like a healthy one ──────

// Pre-fix, /metrics carried culvert_ha_role=1 and nothing else, so a node that
// could not issue a certificate, accept a revocation, or publish a config
// snapshot was byte-identical on the operator's paging surface to a fully
// healthy leader.
func TestChaos55_UnfencedLeaderIsVisibleOnMetrics(t *testing.T) {
	tempHADir(t)
	restore := swapGlobalHA(t)
	defer restore()
	resetHALeaseRecoveryStatsForTest()
	t.Cleanup(resetHALeaseRecoveryStatsForTest)

	// No fence armed at all: every lease series must be ABSENT. `0` on a node
	// that never had a lease is indistinguishable from a fenced-out one, and
	// the documented paging rule is `== 0`.
	var plain strings.Builder
	writeHALeaseMetrics(&plain)
	if plain.Len() != 0 {
		t.Errorf("lease metrics emitted on a node with no fencing backend:\n%s", plain.String())
	}

	o := &outageProvider{Provider: halease.NewFake(10 * time.Second)}
	o.down.Store(true)
	globalHA.SetLeaseProvider(o, "cp-a")
	globalHA.ResumeAsLeader(&haConfig{Enabled: true, Role: "leader", Term: 5, Token: "t"})
	defer globalHA.Stop()

	var out strings.Builder
	writeHALeaseMetrics(&out)
	got := out.String()
	for _, want := range []string{
		"culvert_ha_unfenced 1",
		"culvert_ha_write_authority 0",
		"culvert_ha_lease_recovering 1",
		"culvert_ha_lease_epoch 0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}

	o.down.Store(false)
	// Wait for the SETTLED state, not just for write authority: the grant is
	// installed (making WriteAllowed true) a beat before the loop exits and
	// clears the recovering flag, so a scrape landing between the two would see
	// write_authority=1 with recovering=1. That transient is harmless — no
	// alert rule keys on it, and unfenced is already 0 — but asserting on a
	// mid-commit snapshot is not a real contract.
	if !haWaitFor(20*time.Second, func() bool {
		return globalHA.WriteAllowed() && !globalHA.leaseRecoveryActive()
	}) {
		t.Fatalf("recovery did not settle: write_authority=%v recovering=%v",
			globalHA.WriteAllowed(), globalHA.leaseRecoveryActive())
	}
	var after strings.Builder
	writeHALeaseMetrics(&after)
	recovered := after.String()
	for _, want := range []string{
		"culvert_ha_unfenced 0",
		"culvert_ha_write_authority 1",
		"culvert_ha_lease_recovering 0",
		"culvert_ha_lease_reacquired_total 1",
	} {
		if !strings.Contains(recovered, want) {
			t.Errorf("missing %q after recovery in:\n%s", want, recovered)
		}
	}
}

// A standby has no write authority and that is HEALTHY — culvert_ha_unfenced
// must not fire on it, or the paging rule is useless.
func TestChaos55_StandbyIsNotReportedUnfenced(t *testing.T) {
	tempHADir(t)
	restore := swapGlobalHA(t)
	defer restore()

	f := halease.NewFake(10 * time.Second)
	if granted, _, _ := f.Acquire(context.Background(), "cp-other"); !granted {
		t.Fatal("seed acquire")
	}
	globalHA.SetLeaseProvider(f, "cp-me")
	globalHA.mu.Lock()
	globalHA.role = "standby"
	globalHA.mu.Unlock()
	defer globalHA.Stop()

	var out strings.Builder
	writeHALeaseMetrics(&out)
	if got := out.String(); !strings.Contains(got, "culvert_ha_unfenced 0") {
		t.Errorf("a standby must not be reported as an unfenced leader:\n%s", got)
	}
}

// ── The JSON surfaces ───────────────────────────────────────────────────────

func TestChaos55_LeaseHealthReportsRecovering(t *testing.T) {
	tempHADir(t)
	o := &outageProvider{Provider: halease.NewFake(10 * time.Second)}
	o.down.Store(true)
	h, cfg := resumingLeader(t, o, "cp-a")
	h.ResumeAsLeader(cfg)
	defer h.Stop()

	resp := map[string]any{}
	addLeaseHealth(resp, h)
	if resp["lease_mode"] != "lease" {
		t.Errorf("lease_mode = %v, want lease", resp["lease_mode"])
	}
	if resp["lease_valid"] != false {
		t.Errorf("lease_valid = %v, want false", resp["lease_valid"])
	}
	if resp["lease_recovering"] != true {
		t.Errorf("lease_recovering = %v, want true — an operator must be able to tell "+
			"'read-only and working on it' from 'read-only and stuck'", resp["lease_recovering"])
	}

	// Legacy mode carries neither field.
	legacy := map[string]any{}
	addLeaseHealth(legacy, &HAState{})
	if _, ok := legacy["lease_recovering"]; ok {
		t.Error("legacy mode must not carry lease_recovering")
	}
}

// ── Jitter ──────────────────────────────────────────────────────────────────

// Every CP in a fleet restarts together after a site-wide power event. A fixed
// backoff would have them all hit the recovering backend on the same tick.
func TestChaos55_RecoveryBackoffIsJittered(t *testing.T) {
	const base = time.Second
	seen := map[time.Duration]int{}
	lo := time.Duration(float64(base) * (1 - haLeaseRecoveryJitter))
	hi := time.Duration(float64(base) * (1 + haLeaseRecoveryJitter))
	for i := 0; i < 200; i++ {
		d := jitterDuration(base, haLeaseRecoveryJitter)
		if d < lo || d > hi {
			t.Fatalf("jittered %s outside [%s,%s]", d, lo, hi)
		}
		seen[d]++
	}
	if len(seen) < 100 {
		t.Errorf("only %d distinct backoffs in 200 draws — the jitter is not spreading the fleet", len(seen))
	}
	if got := jitterDuration(0, haLeaseRecoveryJitter); got != 0 {
		t.Errorf("jitterDuration(0) = %s, want 0", got)
	}
}

// ── Unknown fence state is not a fence decision ─────────────────────────────

// The whole-site-restart deadlock, reduced to one node. The ex-standby's
// address IS recorded and resync material IS available — everything the shipped
// S4 path needs to demote — but the reason the resume failed is that the
// fencing backend is unreachable, which tells us nothing about who leads.
//
// Pre-fix the node demoted anyway. In a real two-node cluster the peer does the
// same thing in mirror image: both stand by against each other, neither ever
// syncs (a lease-configured puller rejects a bundle carrying no live holder,
// ha_fencing.go), so lastSyncOK stays zero and leaseAutoPromote's freshness gate
// refuses every promotion — permanently leaderless, from a few seconds of etcd
// being slow to boot.
func TestChaos55_UnknownFenceStateDoesNotDemoteToStandby(t *testing.T) {
	tempHADir(t)
	o := &outageProvider{Provider: halease.NewFake(10 * time.Second)}
	o.down.Store(true)

	h, cfg := resumingLeader(t, o, "cp-a")
	cfg.StandbyAddr = "cp-b:50051" // S0 target recorded — demotion is fully available
	h.SetResyncMaterial(context.Background(), "cp-a:50051", "", "", "")

	h.ResumeAsLeader(cfg)
	defer h.Stop()

	if got := h.Status().Role; got != "leader" {
		t.Fatalf("role = %q, want leader — an UNREACHABLE fence is an absence of information, "+
			"not a decision that another node leads", got)
	}
	if h.WriteAllowed() {
		t.Fatal("an unfenced leader must still have no write authority")
	}
	if !h.leaseRecoveryActive() {
		t.Fatal("recovery must be armed so the fence decides once it is visible again")
	}

	o.down.Store(false)
	if !haWaitFor(20*time.Second, h.WriteAllowed) {
		t.Fatal("write authority never returned after the backend recovered")
	}
	if got := h.Status().Role; got != "leader" {
		t.Errorf("role = %q, want leader after recovery", got)
	}
}

// The counterpart, and the shipped ADR-0005 S4 behaviour that must not
// regress: a resume denied by a LIVE FOREIGN HOLDER is an affirmative fence
// decision, so the node demotes and resyncs from the recorded ex-standby.
func TestChaos55_ForeignHolderOnResumeStillEntersStandby(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(30 * time.Second)
	if granted, _, _ := f.Acquire(context.Background(), "cp-b"); !granted {
		t.Fatal("seed: peer promoted while we were down")
	}

	h, cfg := resumingLeader(t, f, "cp-a")
	cfg.StandbyAddr = "cp-b:50051"
	h.SetResyncMaterial(context.Background(), "cp-a:50051", "", "", "")

	h.ResumeAsLeader(cfg)
	defer h.Stop()

	if got := h.Status().Role; got != "standby" {
		t.Fatalf("role = %q, want standby — the fence affirmatively reported another holder", got)
	}
	if h.leaseRecoveryActive() {
		t.Error("a demoted node must not arm the leader recovery loop")
	}
}

// ── The resume must not hold up the data plane ──────────────────────────────

// ResumeAsLeader runs inside initCluster, which main.go orders BEFORE the root
// CA, the policy engine, the proxy listener and the admin UI. Time spent
// blocking on an unreachable fencing backend is time the secure web gateway is
// not serving — and the fence governs control-plane writes, nothing on the data
// path. So the resume absorbs the short boot race and hands anything longer to
// the background loop.
//
// This is the counterweight to TestChaos55_ResumeAbsorbsAShortBackendOutage:
// together they pin both ends of the budget.
func TestChaos55_ResumeDoesNotBlockBootOnALongOutage(t *testing.T) {
	tempHADir(t)
	o := &outageProvider{Provider: halease.NewFake(10 * time.Second)}
	o.down.Store(true) // never recovers during this test

	h, cfg := resumingLeader(t, o, "cp-a")
	start := time.Now()
	h.ResumeAsLeader(cfg)
	elapsed := time.Since(start)
	defer h.Stop()

	// Budget + one retry cadence + RPC slack. Emphatically NOT haResumeGhostWait.
	bound := haResumeUnreachableWait + haLeaseResumeRetryBackoff + 3*time.Second
	if elapsed > bound {
		t.Fatalf("ResumeAsLeader blocked for %s (bound %s) — an etcd outage must not delay the proxy data plane's startup", elapsed, bound)
	}
	if elapsed >= haResumeGhostWait {
		t.Fatalf("the unreachable path spent the GHOST budget (%s); the two must stay separate", haResumeGhostWait)
	}
	if !h.leaseRecoveryActive() {
		t.Fatal("the boot must hand off to the background recovery loop, not give up")
	}
	if haResumeUnreachableWait >= haResumeGhostWait {
		t.Fatal("haResumeUnreachableWait must stay well below haResumeGhostWait — it sits on the boot path")
	}
}
