package main

import (
	"context"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Tests for P1.4 / S4.SIGHUP — SIGHUP reloader shutdown ownership.
//
// The shutdown invariant under test is:
//
//   "the SIGHUP reload goroutine cannot remain detached after lifecycle
//    cancellation."
//
// Done closes after run() returns. The implementation defers close(r.done)
// first and signal.Stop second; defers run LIFO, so signal.Stop runs before
// close(done) — the signal handler is detached before Done closes. The
// tests treat Done as the black-box exit signal — they do not assert
// directly on signal-handler state.
//
// Tests pass an unregistered chan os.Signal — signal.Stop is documented as
// a no-op for channels that were never registered with signal.Notify, so
// the production teardown path is safe to exercise from tests without
// affecting the running process's actual SIGHUP handler.

// TestSighupReloader_InvokesReloadOnSignal verifies the production behaviour
// preserved by P1.4: each signal received on the channel triggers exactly
// one invocation of the reload callback. Uses a buffered `called` channel
// as the observation mechanism — bounded select, no sleeps.
func TestSighupReloader_InvokesReloadOnSignal(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	called := make(chan struct{}, 1)
	r := newSighupReloader(sigCh, func() {
		select {
		case called <- struct{}{}:
		default:
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	go r.run(ctx)
	// Phase 1 ownership pattern: every goroutine started by a test must be
	// joined before test exit. t.Cleanup survives early t.Fatal returns.
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.Done():
		case <-time.After(time.Second):
			t.Error("reloader did not exit during test cleanup")
		}
	})

	sigCh <- syscall.SIGHUP

	select {
	case <-called:
		// Pass — reload callback invoked.
	case <-time.After(time.Second):
		t.Fatal("reload callback was not invoked within 1s of fake SIGHUP")
	}
}

// TestSighupReloader_ExitsOnContextCancel is the core shutdown-invariant
// test: cancel the context, require Done to close inside a generous bound.
func TestSighupReloader_ExitsOnContextCancel(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	r := newSighupReloader(sigCh, func() {})

	ctx, cancel := context.WithCancel(context.Background())
	go r.run(ctx)

	cancel()

	select {
	case <-r.Done():
		// Pass — run returned.
	case <-time.After(time.Second):
		t.Fatal("sighupReloader did not exit within 1s of context cancellation; goroutine is detached")
	}
}

// TestSighupReloader_PreCancelledCtx_ExitsImmediately covers the case where
// the lifecycle context is already cancelled before run starts. The select
// must take the ctx.Done() branch on its first iteration without waiting
// for a signal.
func TestSighupReloader_PreCancelledCtx_ExitsImmediately(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	r := newSighupReloader(sigCh, func() {
		t.Error("reload callback must NOT be invoked when ctx is pre-cancelled and no signal is sent")
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	go r.run(ctx)

	select {
	case <-r.Done():
		// Pass.
	case <-time.After(200 * time.Millisecond):
		t.Fatal("sighupReloader did not exit promptly when ctx was already cancelled; the loop is waiting on the signal channel instead of ctx.Done()")
	}
}

// TestSighupReloader_ClosedSigChan_ExitsWithoutReload pins two contracts at
// once: closing the injected signal channel must (1) make the reloader
// exit and (2) NOT cause the reload callback to be invoked. A buggy
// implementation that did `case <-r.sigCh:` (without checking the ok flag)
// would spin on receives from a closed channel and call reload repeatedly.
func TestSighupReloader_ClosedSigChan_ExitsWithoutReload(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	var reloadCount atomic.Int32
	r := newSighupReloader(sigCh, func() {
		reloadCount.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.run(ctx)

	close(sigCh)

	select {
	case <-r.Done():
		// Pass — reloader observed the closed channel and exited.
	case <-time.After(time.Second):
		t.Fatal("sighupReloader did not exit within 1s of its signal channel being closed")
	}

	if n := reloadCount.Load(); n != 0 {
		t.Errorf("reload callback was invoked %d time(s) on a closed signal channel; want 0", n)
	}
}

// TestApplyHotReload_ExplicitCanonicalZeroDisablesRateLimit is the
// CodeRabbit review regression (PR #1504): fc.Security.RateLimit is already
// reconciled by the time applyHotReload sees it (loadFileConfig ->
// reconcileDeprecatedRateLimitKey), but the old "> 0" guard around
// rl.Configure meant a reload could only ever RAISE the rate limit, never
// use that resolved value to disable an already-running limiter — an
// explicit "rate_limit_rpm: 0" in the reloaded file was silently ignored.
func TestApplyHotReload_ExplicitCanonicalZeroDisablesRateLimit(t *testing.T) {
	snapshotConnAndRateLimitGlobals(t)

	rl.Configure(60, time.Minute)
	if !rl.Enabled() {
		t.Fatal("test setup invalid: rl should be enabled after Configure(60, ...)")
	}

	zero := 0
	fc := &FileConfig{}
	fc.Security.RateLimitRPM = &zero // explicit "rate_limit_rpm: 0" in the reloaded file

	applyHotReload(fc)

	if rl.Enabled() {
		t.Error("applyHotReload left the rate limiter enabled after an explicit canonical rate_limit_rpm: 0 reload")
	}
}

// TestApplyHotReload_AbsentRateLimitSettingLeavesLimiterUntouched is the
// companion control: a reloaded file that does not mention rate limiting at
// all (RateLimitRPM nil, legacy RateLimit zero-valued) must NOT disable an
// already-running limiter — applyHotReload's existing contract is to only
// reapply settings the reloaded file actually specifies, same as every
// other block in the function.
func TestApplyHotReload_AbsentRateLimitSettingLeavesLimiterUntouched(t *testing.T) {
	snapshotConnAndRateLimitGlobals(t)

	rl.Configure(60, time.Minute)
	if !rl.Enabled() {
		t.Fatal("test setup invalid: rl should be enabled after Configure(60, ...)")
	}

	fc := &FileConfig{} // no security section at all: RateLimitRPM nil, RateLimit 0

	applyHotReload(fc)

	if !rl.Enabled() {
		t.Error("applyHotReload disabled the rate limiter on a reload that never mentioned rate limiting")
	}
	if got := rl.Limit(); got != 60 {
		t.Errorf("rl.Limit() = %d, want unchanged 60", got)
	}
}
