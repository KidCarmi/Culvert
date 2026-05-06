package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// Tests for P2.1 — shutdownRegistry contract.
//
// Each test exercises one row of the contract from runtime_shutdown.go. No
// production code is wired into the registry by this PR; these tests
// stand alone with synthetic hooks (closures recording into local state).

// TestShutdownRegistry_HooksRunInOrder pins the ascending-order rule.
func TestShutdownRegistry_HooksRunInOrder(t *testing.T) {
	var r shutdownRegistry
	var seq []string
	r.Register("c", 30, func(context.Context) error { seq = append(seq, "c"); return nil })
	r.Register("a", 10, func(context.Context) error { seq = append(seq, "a"); return nil })
	r.Register("b", 20, func(context.Context) error { seq = append(seq, "b"); return nil })

	if err := r.RunAll(context.Background()); err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	want := []string{"a", "b", "c"}
	if !slices.Equal(seq, want) {
		t.Errorf("execution order = %v; want %v", seq, want)
	}
}

// TestShutdownRegistry_SameOrderPreservesRegistration pins the
// stable-sort tie-break: hooks with the same order run in the order they
// were Register'd.
func TestShutdownRegistry_SameOrderPreservesRegistration(t *testing.T) {
	var r shutdownRegistry
	var seq []string
	r.Register("first", 5, func(context.Context) error { seq = append(seq, "first"); return nil })
	r.Register("second", 5, func(context.Context) error { seq = append(seq, "second"); return nil })
	r.Register("third", 5, func(context.Context) error { seq = append(seq, "third"); return nil })

	if err := r.RunAll(context.Background()); err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	want := []string{"first", "second", "third"}
	if !slices.Equal(seq, want) {
		t.Errorf("execution order = %v; want %v", seq, want)
	}
}

// TestShutdownRegistry_ErrorsDoNotStopLaterHooks asserts the
// run-everything-collect-errors contract: a failing hook does not abort
// the batch, and the returned error names each failing hook (and only
// failing hooks) and wraps the underlying errors.
func TestShutdownRegistry_ErrorsDoNotStopLaterHooks(t *testing.T) {
	var r shutdownRegistry
	var ranCount int
	bang1 := errors.New("hook1 boom")
	bang3 := errors.New("hook3 boom")

	r.Register("hook1", 1, func(context.Context) error { ranCount++; return bang1 })
	r.Register("hook2", 2, func(context.Context) error { ranCount++; return nil })
	r.Register("hook3", 3, func(context.Context) error { ranCount++; return bang3 })

	err := r.RunAll(context.Background())
	if err == nil {
		t.Fatal("RunAll returned nil; want aggregated error")
	}
	if ranCount != 3 {
		t.Errorf("only %d/3 hooks ran; expected all hooks to run despite errors", ranCount)
	}
	msg := err.Error()
	if !strings.Contains(msg, "hook1") || !strings.Contains(msg, "hook3") {
		t.Errorf("error %q must name each failing hook (hook1, hook3)", msg)
	}
	if strings.Contains(msg, "hook2") {
		t.Errorf("error %q must NOT include hook2 (which succeeded)", msg)
	}
	if !errors.Is(err, bang1) {
		t.Errorf("error %v does not wrap bang1", err)
	}
	if !errors.Is(err, bang3) {
		t.Errorf("error %v does not wrap bang3", err)
	}
}

// TestShutdownRegistry_RunAllIdempotent pins the second-call-is-a-no-op
// contract.
func TestShutdownRegistry_RunAllIdempotent(t *testing.T) {
	var r shutdownRegistry
	var ranCount int
	r.Register("once", 0, func(context.Context) error { ranCount++; return nil })

	if err := r.RunAll(context.Background()); err != nil {
		t.Fatalf("first RunAll: %v", err)
	}
	if err := r.RunAll(context.Background()); err != nil {
		t.Errorf("second RunAll returned %v; want nil", err)
	}
	if ranCount != 1 {
		t.Errorf("hook ran %d times; want 1 (idempotent contract)", ranCount)
	}
}

// TestShutdownRegistry_CtxIsPassedToHooks asserts that the ctx supplied
// to RunAll is forwarded to each hook unchanged.
func TestShutdownRegistry_CtxIsPassedToHooks(t *testing.T) {
	var r shutdownRegistry
	var seenCtx context.Context
	r.Register("capture", 0, func(ctx context.Context) error {
		seenCtx = ctx
		return nil
	})

	parentCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := r.RunAll(parentCtx); err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	if seenCtx == nil {
		t.Fatal("hook did not see a ctx")
	}
	if seenCtx.Err() == nil {
		t.Errorf("hook saw ctx with nil Err; expected ctx.Err() to reflect parent cancellation")
	}
}

// TestShutdownRegistry_NilStopPanics pins the nil-stop fail-fast contract:
// Register panics rather than silently accepting a no-op hook. This makes
// wiring mistakes (forgotten initialiser, dropped assignment) loud at
// startup time instead of silently skipping shutdown logic.
func TestShutdownRegistry_NilStopPanics(t *testing.T) {
	var reg shutdownRegistry
	defer func() {
		if rec := recover(); rec == nil {
			t.Fatal("Register(nil stop) did not panic")
		}
	}()
	reg.Register("bad", 0, nil)
}

// TestShutdownRegistry_EmptyRunAllReturnsNil confirms that calling RunAll
// on an empty registry is a no-op (no hooks → no errors).
func TestShutdownRegistry_EmptyRunAllReturnsNil(t *testing.T) {
	var r shutdownRegistry
	if err := r.RunAll(context.Background()); err != nil {
		t.Errorf("empty RunAll returned %v; want nil", err)
	}
}
