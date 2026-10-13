package main

// controlplane_client_cadence_chaos_test.go — CHAOS-71: the DP→CP retry cadence
// under a Control Plane outage.
//
// The Control Plane is the one dependency every data plane shares, so its
// recovery is the moment a fleet is most able to prevent it. Three defects made
// that worse rather than better, and each test below pins the one contract that
// was violated:
//
//  1. the failure streak advanced TWICE per failed poll (the caller and
//     backoff() both incremented it), so the documented 2s/4s/8s/…/60s ladder
//     was really 4s/16s/60s and the documented "3 consecutive failures"
//     failover gate tripped on the second;
//  2. a successful redial cleared the streak, so a reachable-but-not-serving
//     CP pair made the client flap between CPs every few seconds forever and
//     the ladder never advanced past its second rung;
//  3. nothing was jittered or phase-offset, so a fleet that failed together
//     retried together and reconnected in one instant.
//
// These assert cadence ARITHMETIC and loop ORDERING, so none of them sleep for
// a backoff: an already-cancelled context makes backoff() return immediately
// while still performing every state transition under test.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// cpDownClient builds a DataPlaneClient whose every RPC fails, as a CP that is
// down (or up but not serving) presents to a data plane. jitter is left nil so
// the ladder is the exact documented one — see jitterDelay.
func cpDownClient(t *testing.T, addrs ...string) (*DataPlaneClient, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	return &DataPlaneClient{
		nodeID: "dp-chaos71",
		addrs:  addrs,
		callForTest: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
			calls.Add(1)
			return nil, errors.New("chaos71: control plane unreachable")
		},
	}, &calls
}

// cancelledCtx is a context whose Done channel is already closed, so every
// backoff in these tests returns without waiting out its delay.
func cancelledCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// TestChaos71_BackoffLadderIsTheDocumentedOne pins the ladder that the doubled
// increment silently replaced. Before the fix the observed delays for the first
// three failed polls were 4s, 16s and 60s: the ceiling on the THIRD poll
// instead of the sixth, costing a data plane up to a minute of config
// convergence after a blip barely long enough to notice.
func TestChaos71_BackoffLadderIsTheDocumentedOne(t *testing.T) {
	want := []time.Duration{
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		32 * time.Second,
		dpBackoffCeiling,
		dpBackoffCeiling,
		dpBackoffCeiling,
	}
	for i, w := range want {
		streak := i + 1
		if got := dpBackoffDelay(streak); got != w {
			t.Errorf("dpBackoffDelay(%d) = %s, want %s — the retry ladder no longer matches the contract backoff() documents", streak, got, w)
		}
	}
	if got := dpBackoffDelay(0); got != 2*time.Second {
		t.Errorf("dpBackoffDelay(0) = %s, want the first rung 2s (clamped, never a shorter floor)", got)
	}
	if dpBackoffDelay(1<<20) != dpBackoffCeiling {
		t.Error("an enormous streak must clamp to the ceiling, not overflow the shift")
	}
}

// TestChaos71_StreakAdvancesOncePerFailedPoll is the direct regression test for
// the double increment: the streak is the input to BOTH the ladder and the
// failover gate, so an extra increment per poll corrupted both at once.
func TestChaos71_StreakAdvancesOncePerFailedPoll(t *testing.T) {
	ctx := cancelledCtx(t)
	c, calls := cpDownClient(t, "cp1:50051") // single CP: failover is impossible

	for poll := 1; poll <= 5; poll++ {
		if _, ok := c.pollConfig(ctx); ok {
			t.Fatalf("poll %d reported success against an unreachable CP", poll)
		}
		if c.failCount != poll {
			t.Fatalf("after %d failed polls failCount = %d, want %d — the consecutive-failure streak has more than one writer again", poll, c.failCount, poll)
		}
	}
	if got := calls.Load(); got != 5 {
		t.Errorf("single-CP client issued %d RPCs for 5 polls, want 5 (no hidden retry)", got)
	}
}

// TestChaos71_FailoverTripsOnTheThirdFailureNotTheSecond pins the gate that the
// doubled increment moved. Redialling a peer one failure early is not a safe
// direction to err in: it is extra connection churn aimed at a CP that may be
// merely blipping, which is exactly what the snapshot-scaled call deadline
// (dpConfigMaxDeadline) was introduced to avoid causing.
func TestChaos71_FailoverTripsOnTheThirdFailureNotTheSecond(t *testing.T) {
	ctx := cancelledCtx(t)
	c, _ := cpDownClient(t, "cp1:50051", "cp2:50051")
	startIdx := c.activeIdx

	for poll := 1; poll <= 2; poll++ {
		if _, ok := c.pollConfig(ctx); ok {
			t.Fatalf("poll %d reported success against an unreachable CP", poll)
		}
		if c.activeIdx != startIdx {
			t.Fatalf("failed over after only %d consecutive failures; dpFailoverAfterFailures is %d", poll, dpFailoverAfterFailures)
		}
	}
	if _, ok := c.pollConfig(ctx); ok {
		t.Fatal("poll 3 reported success against an unreachable CP")
	}
	if c.activeIdx == startIdx {
		t.Errorf("no failover after %d consecutive failures — the peer CP is never probed during an outage", dpFailoverAfterFailures)
	}
}

// TestChaos71_SustainedOutageConvergesOnTheCeiling is the regression test for
// the failover streak reset, and the most consequential of the three: because
// failover() cleared failCount on a successful DIAL, an HA pair that answered
// TCP while failing GetConfig held every data plane on the low rungs of the
// ladder indefinitely. The streak must grow monotonically across failovers so
// the ladder actually reaches its ceiling.
func TestChaos71_SustainedOutageConvergesOnTheCeiling(t *testing.T) {
	ctx := cancelledCtx(t)
	c, _ := cpDownClient(t, "cp1:50051", "cp2:50051")

	const polls = 12
	var failovers int
	prevIdx := c.activeIdx
	for poll := 1; poll <= polls; poll++ {
		if _, ok := c.pollConfig(ctx); ok {
			t.Fatalf("poll %d reported success against an unreachable CP pair", poll)
		}
		if c.failCount != poll {
			t.Fatalf("after %d failed polls failCount = %d, want %d — a redial is clearing the streak again, so the backoff ladder never advances", poll, c.failCount, poll)
		}
		if c.activeIdx != prevIdx {
			failovers++
			prevIdx = c.activeIdx
		}
	}
	if got := dpBackoffDelay(c.failCount); got != dpBackoffCeiling {
		t.Errorf("after %d failed polls the retry delay is %s, want the %s ceiling", polls, got, dpBackoffCeiling)
	}
	// Both CPs stay under observation, but at the gate's cadence rather than
	// on every poll: a dead pair must not mean a fresh gRPC connection per tick.
	if wantFailovers := polls / dpFailoverAfterFailures; failovers != wantFailovers {
		t.Errorf("%d failovers over %d failed polls, want %d (one per %d failures)", failovers, polls, wantFailovers, dpFailoverAfterFailures)
	}
}

// TestChaos71_SuccessfulPollClearsTheStreak is the negative control for the two
// tests above: the fix removes the reset from the redial path, so the only
// remaining reset — an actually successful poll — must still work. Without this
// a "fix" that never cleared the streak would pin every other assertion here
// while leaving a recovered CP permanently on the 60s ceiling.
func TestChaos71_SuccessfulPollClearsTheStreak(t *testing.T) {
	ctx := cancelledCtx(t)
	var healthy atomic.Bool
	c := &DataPlaneClient{
		nodeID: "dp-chaos71",
		addrs:  []string{"cp1:50051", "cp2:50051"},
		callForTest: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
			if healthy.Load() {
				return json.RawMessage(`{}`), nil
			}
			return nil, errors.New("chaos71: control plane unreachable")
		},
	}
	for poll := 1; poll <= 4; poll++ {
		if _, ok := c.pollConfig(ctx); ok {
			t.Fatalf("poll %d reported success while the CP was down", poll)
		}
	}
	if c.failCount == 0 {
		t.Fatal("the streak did not accumulate during the outage")
	}
	healthy.Store(true)
	if _, ok := c.pollConfig(ctx); !ok {
		t.Fatal("pollConfig failed against a recovered CP")
	}
	if c.failCount != 0 {
		t.Errorf("failCount = %d after a successful poll, want 0 — a recovered CP would stay on the backoff ceiling", c.failCount)
	}
}

// TestChaos71_JitterDecorrelatesTheRetryInstant asserts the property that makes
// a fleet's recovery survivable: two nodes handed the same ladder rung must not
// retry at the same instant. The CP outage that starts every node's streak is a
// single shared event, so without this the ladder is a schedule the whole fleet
// agrees on.
func TestChaos71_JitterDecorrelatesTheRetryInstant(t *testing.T) {
	const (
		fleet = 200
		base  = 30 * time.Second
	)
	jitter := dpRetryJitter(dpRetryJitterFrac)
	seen := make(map[time.Duration]int, fleet)
	for i := 0; i < fleet; i++ {
		d := jitter(base)
		// The spread must not reshape the ladder it is spreading.
		lo := base - time.Duration(float64(base)*dpRetryJitterFrac)
		hi := base + time.Duration(float64(base)*dpRetryJitterFrac)
		if d < lo || d > hi {
			t.Fatalf("jittered delay %s outside ±%.0f%% of %s — the jitter is reshaping the ladder, not decorrelating it", d, dpRetryJitterFrac*100, base)
		}
		seen[d]++
	}
	// 200 draws over a 6-second window at nanosecond resolution: a handful of
	// collisions is unremarkable, a fleet landing on one value is the defect.
	if len(seen) < fleet/2 {
		t.Errorf("%d distinct retry instants across %d nodes — the fleet is still correlated", len(seen), fleet)
	}
	if worst := mostCommonCount(seen); worst > fleet/4 {
		t.Errorf("%d of %d nodes drew the SAME retry instant", worst, fleet)
	}

	// A client with no jitter installed must stay exactly on the ladder, which
	// is what every cadence assertion in this file depends on.
	var plain DataPlaneClient
	if got := plain.jitterDelay(base); got != base {
		t.Errorf("jitterDelay with no jitter function = %s, want %s unchanged", got, base)
	}
}

func mostCommonCount(m map[time.Duration]int) int {
	worst := 0
	for _, n := range m {
		if n > worst {
			worst = n
		}
	}
	return worst
}

// TestChaos71_StartupStaggerIsBoundedAndSpread pins the phase offset that keeps
// a fleet's tickers out of lockstep: bounded above by dpStartupStaggerMax so it
// can never approach the 90s heartbeat timeout, bounded by the loop's own
// interval so a sub-second loop is not delayed past its first tick, and
// actually spread rather than constant.
func TestChaos71_StartupStaggerIsBoundedAndSpread(t *testing.T) {
	for _, interval := range []time.Duration{
		500 * time.Millisecond, 3 * time.Second, 10 * time.Second, 30 * time.Second, time.Hour,
	} {
		bound := min(interval, dpStartupStaggerMax)
		distinct := make(map[time.Duration]struct{})
		for i := 0; i < 500; i++ {
			d := dpStartupStagger(interval)
			if d < 0 || d >= bound {
				t.Fatalf("stagger %s for interval %s outside [0, %s)", d, interval, bound)
			}
			distinct[d] = struct{}{}
		}
		if len(distinct) < 2 {
			t.Errorf("interval %s: stagger is constant — the fleet stays in phase", interval)
		}
	}
	if got := dpStartupStagger(0); got != 0 {
		t.Errorf("dpStartupStagger(0) = %s, want 0 (no interval, nothing to spread)", got)
	}
	if got := dpStartupStagger(-time.Second); got != 0 {
		t.Errorf("dpStartupStagger(negative) = %s, want 0", got)
	}
}

// TestChaos71_StaggerYieldsToShutdown asserts the stagger is a cancellation
// point, not a sleep: a SIGTERM arriving in the offset window must not be held
// for it, and the caller must learn that so it can run its own teardown.
func TestChaos71_StaggerYieldsToShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if staggerLoopStart(ctx, time.Hour) {
		t.Error("staggerLoopStart reported success on a cancelled context — the caller would skip its teardown")
	}
	if el := time.Since(start); el > time.Second {
		t.Errorf("staggerLoopStart waited %s on a cancelled context; shutdown must not be held for the offset", el)
	}
	if !staggerLoopStart(context.Background(), time.Millisecond) {
		t.Error("staggerLoopStart reported failure on a live context")
	}
}

// TestChaos71_GossipLoopDisarmsWhenCancelledDuringTheStagger covers the one
// teardown the stagger could have swallowed: rateLimitGossipLoop arms
// cluster-aware rate limiting BEFORE waiting out its offset, so a cancellation
// inside that window must disarm it exactly as the loop's own ctx.Done() branch
// does. Leaving it armed would hold the limiter in cluster mode with no gossip
// ever arriving behind it.
func TestChaos71_GossipLoopDisarmsWhenCancelledDuringTheStagger(t *testing.T) {
	limiter := newRateLimiter()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c, _ := cpDownClient(t, "cp1:50051")
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.rateLimitGossipLoop(ctx, time.Hour, limiter)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("rateLimitGossipLoop did not return promptly on a cancelled context")
	}
	if limiter.ClusterEnabled() {
		t.Error("the limiter is still armed for cluster-aware counting after the loop returned — a cancellation during the startup stagger skipped the disarm")
	}
}

// TestChaos71_ColdStartPollIsNeverStaggered is the guard on the one ordering
// the stagger must not change. A node with no last-known-good snapshot
// enforces nothing until its first poll lands, so delaying that poll to smooth
// a boot burst would trade a security property for load. Every SUBSEQUENT poll
// is staggered; the first must not be.
func TestChaos71_ColdStartPollIsNeverStaggered(t *testing.T) {
	polled := make(chan struct{}, 1)
	c := &DataPlaneClient{
		nodeID: "dp-chaos71",
		addrs:  []string{"cp1:50051"},
		callForTest: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
			select {
			case polled <- struct{}{}:
			default:
			}
			return nil, errors.New("chaos71: control plane unreachable")
		},
	}
	// An interval far longer than the stagger bound: if the first fetch were
	// behind the offset, it could not possibly land inside the window below.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.pollLoop(ctx, time.Hour)

	select {
	case <-polled:
	case <-time.After(dpStartupStaggerMax):
		t.Fatalf("no config poll within %s of start — the cold-start fetch is behind the startup stagger, so a node with no last-known-good snapshot enforces nothing for that whole window", dpStartupStaggerMax)
	}
}

// TestChaos71_BackoffDoesNotOutliveShutdown pins the backoff as a cancellation
// point. The ceiling is a minute; a drain that waited one out would blow any
// shutdown budget in the process.
func TestChaos71_BackoffDoesNotOutliveShutdown(t *testing.T) {
	c, _ := cpDownClient(t, "cp1:50051")
	c.failCount = 6 // the ceiling rung
	ctx, cancel := context.WithCancel(context.Background())

	returned := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		c.backoff(ctx)
		returned <- time.Since(start)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case el := <-returned:
		if el > 10*time.Second {
			t.Errorf("backoff took %s to observe cancellation (ceiling is %s)", el, dpBackoffCeiling)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("backoff did not return after cancellation — shutdown would wait out the %s ceiling", dpBackoffCeiling)
	}
}

// TestChaos71_BackoffLogLineReportsTheRealDelay keeps the operator-facing
// evidence honest. The doubled increment also made the log line itself
// misleading ("backing off 4s (failure #2)" on the FIRST failed poll), so an
// operator reading it could not have reconstructed the real cadence.
func TestChaos71_BackoffLogLineReportsTheRealDelay(t *testing.T) {
	ctx := cancelledCtx(t)
	c, _ := cpDownClient(t, "cp1:50051")

	sink := captureLoggerForTest(t)

	if _, ok := c.pollConfig(ctx); ok {
		t.Fatal("poll reported success against an unreachable CP")
	}
	got := sink.String()
	if !strings.Contains(got, "backing off 2s (failure #1)") {
		t.Errorf("first failed poll logged %q; want the real first rung %q", got, "backing off 2s (failure #1)")
	}
}

// TestChaos71_ProductionClientHasJitterInstalled is the wiring guard. Every
// assertion above about jitter is about the FUNCTION; this one is about the
// constructor, because the whole fleet-decorrelation property is one struct
// field away from being silently absent in production while every other test
// in this file still passes.
func TestChaos71_ProductionClientHasJitterInstalled(t *testing.T) {
	c, err := NewDataPlaneClient("dp-chaos71", "127.0.0.1:1", "", "", "")
	if err != nil {
		t.Fatalf("NewDataPlaneClient: %v", err)
	}
	t.Cleanup(func() {
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
	if c.jitter == nil {
		t.Fatal("a production DataPlaneClient has no jitter function — the whole fleet retries in lockstep")
	}
	const base = 30 * time.Second
	allSame := true
	for i := 0; i < 50; i++ {
		if c.jitterDelay(base) != base {
			allSame = false
			break
		}
	}
	if allSame {
		t.Error("the installed jitter is an identity function — retry instants stay correlated across the fleet")
	}
}
