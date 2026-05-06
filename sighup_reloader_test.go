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
