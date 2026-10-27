package main

// release_dispatch_apply_backoff_chaos93_test.go — CHAOS-93 RT-3.
//
// applyWithRetry's three attempts used to run back to back with no sleep, no
// backoff and no jitter. The retry budget existed for exactly one fault — a
// maintenance agent that is briefly unreachable, typically because it is
// restarting — and that fault refuses the connection in microseconds, so all
// three attempts burned in well under a millisecond and the dispatch landed
// TerminalFailedNeedsAttn (operator-visible, manually re-dispatched) for an
// agent that was serving again a second later.
//
// These gates pin the schedule rather than the wall-clock cost: the delay is
// taken through the applyWait seam, so the assertions are exact and the test
// spends no time.

import (
	"context"
	"strings"
	"testing"
	"time"
)

// transientAgentErr is a 5xx, which isTransientAgentErr classifies as retryable.
func transientAgentErr() error {
	return &agentHTTPError{Status: 503, Method: "POST", Path: "/v1/upgrades/apply"}
}

// TestExec_ApplyRetryBacksOffBetweenAttempts is the RT-3 gate: the retries are
// SPREAD. Pre-fix the recorded schedule was empty — three attempts, zero waits.
func TestExec_ApplyRetryBacksOffBetweenAttempts(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, []string{dispatchRepo + "@" + digB})

	// Transient on every attempt: the full budget is spent.
	agent := &fakeAgent{applyErrs: []error{transientAgentErr(), transientAgentErr(), transientAgentErr()}}
	e := NewDispatchExecutor(agent, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	e.newOpID = func() string { return "OP01" }

	var waits []time.Duration
	e.applyWait = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}

	if _, err := e.Execute(context.Background(), plan); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// applyRetries = 2 ⇒ 3 attempts ⇒ 2 waits, doubling from the base.
	want := []time.Duration{dispatchApplyBackoffBase, 2 * dispatchApplyBackoffBase}
	if len(waits) != len(want) {
		t.Fatalf("retries were not spaced: got %d waits %v, want %d %v", len(waits), waits, len(want), want)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Errorf("wait %d = %v, want %v (bounded exponential from the base)", i+1, waits[i], want[i])
		}
	}
}

// A retry that succeeds waits only before the attempt that needed it — the
// backoff must not be charged to a dispatch that worked first time.
func TestExec_ApplyBackoffNotSpentWhenFirstAttemptSucceeds(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, []string{dispatchRepo + "@" + digB})

	agent := &fakeAgent{applyOpID: "op-ok", waitState: agentStateSucceeded,
		runningSeq: [][]string{{dispatchRepo + "@" + digB}, {dispatchRepo + "@" + digA}}}
	e := NewDispatchExecutor(agent, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	e.newOpID = func() string { return "OP01" }

	waits := 0
	e.applyWait = func(context.Context, time.Duration) error { waits++; return nil }

	if _, err := e.Execute(context.Background(), plan); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if waits != 0 {
		t.Errorf("a first-attempt success waited %d times; want 0", waits)
	}
}

// The backoff is interruptible: a cancelled context aborts the wait and the
// cancellation — not the agent's transient error — is what surfaces, so a
// shutdown is never reported to an operator as an agent fault.
func TestExec_ApplyBackoffIsInterruptible(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, []string{dispatchRepo + "@" + digB})

	agent := &fakeAgent{applyErrs: []error{transientAgentErr(), transientAgentErr(), transientAgentErr()}}
	e := NewDispatchExecutor(agent, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	e.newOpID = func() string { return "OP01" }

	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	e.applyWait = func(ctx context.Context, _ time.Duration) error {
		calls++
		cancel() // the lifecycle ends while the dispatch is backing off
		return ctx.Err()
	}

	res, err := e.Execute(ctx, plan)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if calls != 1 {
		t.Errorf("backoff was entered %d times after cancellation; want 1", calls)
	}
	if res.Terminal != TerminalFailedNeedsAttn {
		t.Errorf("terminal = %s; want %s", res.Terminal, TerminalFailedNeedsAttn)
	}
	if res.Detail == "" {
		t.Error("a cancelled dispatch must carry a detail an operator can read")
	}
	if !strings.Contains(res.Detail, context.Canceled.Error()) {
		t.Errorf("detail %q does not name the cancellation; a shutdown must not read as an agent fault", res.Detail)
	}
}

// waitInterruptible itself: it returns on cancellation rather than sleeping out
// the delay, which is what keeps a shutdown from waiting on a doomed dispatch.
func TestWaitInterruptible_ReturnsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := waitInterruptible(ctx, time.Hour); err == nil {
		t.Fatal("want the context error from a cancelled wait")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("cancelled wait took %v; it must return at once", elapsed)
	}
	if err := waitInterruptible(context.Background(), time.Millisecond); err != nil {
		t.Errorf("an uncancelled wait must complete: %v", err)
	}
}
