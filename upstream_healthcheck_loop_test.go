package main

import (
	"context"
	"testing"
	"time"
)

// Tests for P1.3 / S4.UpstreamHealth — upstream health-check loop ownership.
//
// The shutdown invariant under test is:
//
//   "the upstream health-check goroutine cannot remain detached after
//    lifecycle cancellation."
//
// Each test wraps runUpstreamHealthCheckLoop in a goroutine guarded by a
// `done` channel that is closed only after the function returns. Receiving
// from `done` proves the function returned, which means the deferred
// ticker.Stop ran. The tests treat `done` as the black-box exit signal —
// they do not assert directly on ticker state.
//
// We use a fresh, empty *UpstreamPool so HealthCheck (if it ever fires) is
// a no-op: the proxies slice is empty, so the per-iteration HTTP probe loop
// runs zero times and never touches the network.

// TestRunUpstreamHealthCheckLoop_ExitsOnContextCancel is the core
// shutdown-invariant test: cancel the context, require `done` to close
// inside a generous bound. The interval is short to make any latent
// "wait for next tick" path quick to surface, but the invariant is
// "ctx cancel → loop exits" regardless of where the goroutine is in its
// loop.
func TestRunUpstreamHealthCheckLoop_ExitsOnContextCancel(t *testing.T) {
	pool := &UpstreamPool{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runUpstreamHealthCheckLoop(ctx, pool, 10*time.Millisecond)
	}()

	cancel()

	select {
	case <-done:
		// Pass — loop returned.
	case <-time.After(time.Second):
		t.Fatal("runUpstreamHealthCheckLoop did not exit within 1s of context cancellation; goroutine is detached")
	}
}

// TestRunUpstreamHealthCheckLoop_PreCancelledCtx_ExitsImmediately covers
// the case where the lifecycle context is already cancelled before the
// loop starts. The select must take the ctx.Done() branch on its first
// iteration without waiting for any ticks.
func TestRunUpstreamHealthCheckLoop_PreCancelledCtx_ExitsImmediately(t *testing.T) {
	pool := &UpstreamPool{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		runUpstreamHealthCheckLoop(ctx, pool, time.Hour) // long interval — ticks must NOT be required
	}()

	select {
	case <-done:
		// Pass.
	case <-time.After(200 * time.Millisecond):
		t.Fatal("runUpstreamHealthCheckLoop did not exit promptly when ctx was already cancelled; the loop is waiting on the ticker instead of ctx.Done()")
	}
}
