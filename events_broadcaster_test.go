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
// Receiving from b.Done() proves the run goroutine fully returned. Because
// run is structured as:
//
//   defer close(b.done)      // outer-defer  — runs LAST
//   defer ticker.Stop()      // inner-defer — runs FIRST
//
// any reception on Done() is also proof that ticker.Stop() ran (defers fire
// in LIFO order). No goroutine leak detection or runtime.NumGoroutine
// snapshot is therefore needed: the channel close is the contract.

// TestSSEBroadcaster_ExitsOnContextCancel is the core shutdown-invariant
// test. We start the broadcaster with a short interval (so any latent
// "wait for next tick" path would be quick to surface), let it run, cancel
// its context, and require Done to close inside a generous bound.
func TestSSEBroadcaster_ExitsOnContextCancel(t *testing.T) {
	b := newSSEBroadcaster(10 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	go b.run(ctx)

	// Let at least one tick fire so the goroutine is genuinely inside the
	// select loop (not still racing toward the first iteration).
	time.Sleep(30 * time.Millisecond)

	cancel()

	select {
	case <-b.Done():
		// Pass — goroutine returned, ticker was stopped.
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

// TestSSEBroadcaster_Done_ReturnsSameChannel is a sanity check that Done()
// returns the same channel on repeated calls — i.e. callers (Phase 2
// registry, tests) can hold a handle to the close signal without surprises.
func TestSSEBroadcaster_Done_ReturnsSameChannel(t *testing.T) {
	b := newSSEBroadcaster(time.Second)
	if b.Done() != b.Done() {
		t.Error("Done() returned different channels on successive calls")
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
