package main

import (
	"context"
	"testing"
	"time"
)

// Tests for P1.2 / S4.SSE — SSE broadcaster shutdown ownership.
//
// The shutdown invariant under test is:
//
//   "the SSE broadcaster cannot remain detached after lifecycle cancellation."
//
// Done closes after run() returns. Because ticker.Stop is deferred before
// close(done), the implementation stops the ticker before Done closes. The
// tests treat Done as the black-box exit signal — they do not assert
// directly on ticker state. No goroutine leak detection or
// runtime.NumGoroutine snapshot is therefore needed: the channel close is
// the contract.

// TestSSEBroadcaster_ExitsOnContextCancel is the core shutdown-invariant
// test: cancel the broadcaster's context, require Done to close inside a
// generous bound. We do not sleep to "wait for a tick" — the invariant is
// "ctx cancel → Done closes", regardless of where the goroutine is in its
// loop. The pre-cancelled-ctx test below covers the other ordering edge.
func TestSSEBroadcaster_ExitsOnContextCancel(t *testing.T) {
	b := newSSEBroadcaster(10 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	go b.run(ctx)
	cancel()

	select {
	case <-b.Done():
		// Pass — run returned.
	case <-time.After(time.Second):
		t.Fatal("sseBroadcaster did not exit within 1s of context cancellation; goroutine is detached")
	}
}

// TestSSEBroadcaster_PreCancelledCtx_ExitsImmediately covers the case where
// the lifecycle context is already cancelled before run starts (e.g. fast
// shutdown path during a degraded-startup scenario). The select must take
// the ctx.Done() branch on its first iteration without waiting for any
// ticks.
func TestSSEBroadcaster_PreCancelledCtx_ExitsImmediately(t *testing.T) {
	b := newSSEBroadcaster(time.Hour) // intentionally long; ticks must NOT be required

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	go b.run(ctx)

	select {
	case <-b.Done():
		// Pass.
	case <-time.After(200 * time.Millisecond):
		t.Fatal("sseBroadcaster did not exit promptly when ctx was already cancelled; the loop is waiting on the ticker instead of ctx.Done()")
	}
}

// TestStartSSEBroadcaster_ReturnsLiveHandle covers the production entry
// point: startSSEBroadcaster(ctx) must spawn the goroutine and return a
// handle whose Done() closes when ctx is cancelled. Mirrors the production
// call shape from initBackgroundServices.
func TestStartSSEBroadcaster_ReturnsLiveHandle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	b := startSSEBroadcaster(ctx)
	if b == nil {
		t.Fatal("startSSEBroadcaster returned nil")
	}

	cancel()

	select {
	case <-b.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("broadcaster spawned by startSSEBroadcaster did not exit within 2s of ctx cancel")
	}
}
