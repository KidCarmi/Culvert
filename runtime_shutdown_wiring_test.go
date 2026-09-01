package main

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// Tests for P2.2 / S5 — shutdown sequence wired through two shutdownRegistry
// instances (early + late) so that the 30s shutdown budget covers only the
// late phase, byte-equivalent to the original hand-ordered body.
//
// These tests inspect the wired hook lists (via shutdownRegistry.hooksSnapshot)
// without invoking RunAll. Hook closures are inspected by name + order only
// and never called, so no production global is touched at run-time.

// testInertHTTPServer returns an *http.Server that satisfies gosec G112
// (Slowloris) by setting ReadHeaderTimeout. It is passed to
// registerLateShutdownHooks but the Shutdown closure is never invoked in
// these tests, so the timeout value is purely cosmetic — any non-zero
// value works.
func testInertHTTPServer() *http.Server {
	return &http.Server{ReadHeaderTimeout: time.Second}
}

// canonicalEarlyShutdownHooks pins the exact early-phase sequence. These
// hooks ran BEFORE the 30s ctx was created in the original body, so they
// continue to run with context.Background().
var canonicalEarlyShutdownHooks = []struct {
	name  string
	order int
}{
	{"ha-stop", shutdownOrderHAStop},
	{"control-plane-grpc-stop", shutdownOrderControlPlaneGRPCStop},
	{"cdr-client-shutdown", shutdownOrderCDRClientShutdown},
	{"app-lifecycle-cancel", shutdownOrderAppLifecycleCancel},
	{"rate-limit-cleanup-cancel", shutdownOrderRateLimitCleanupCancel},
}

// canonicalLateShutdownHooks pins the exact late-phase sequence. These
// hooks run under the 30s ctx that runShutdownSequence creates after the
// early phase completes.
var canonicalLateShutdownHooks = []struct {
	name  string
	order int
}{
	{"cluster-store-flush", shutdownOrderClusterStoreFlush},
	{"scan-svc-shutdown", shutdownOrderScanSvcShutdown},
	{"mcp-runtime-stop", shutdownOrderMCPRuntimeStop},
	{"mcp-telemetry-drain", shutdownOrderMCPTelemetryDrain},
	{"policy-learning-flush", shutdownOrderPolicyLearnFlush},
	{"admin-ui-shutdown", shutdownOrderAdminUIShutdown},
	{"socks5-listener-stop", shutdownOrderSOCKS5ListenerStop},
	{"proxy-server-shutdown", shutdownOrderProxyServerShutdown},
	{"tunnel-establish-fence", shutdownOrderTunnelEstablishFence},
	{"h2-inspect-goaway", shutdownOrderH2InspectGOAWAY},
	{"tunnel-drain", shutdownOrderTunnelDrain},
	{"syslog-close", shutdownOrderSyslogClose},
	{"community-db-close", shutdownOrderCommunityDBClose},
	{"log-store-close", shutdownOrderLogStoreClose},
	{"request-log-close", shutdownOrderRequestLogClose},
	{"audit-log-close", shutdownOrderAuditLogClose},
	{"log-closer", shutdownOrderLogCloser},
}

// TestRegisterEarlyShutdownHooks_OrderMatchesCanonical pins each early-
// phase hook by name and order. Synthetic startupState — hook bodies are
// closures and are never invoked.
func TestRegisterEarlyShutdownHooks_OrderMatchesCanonical(t *testing.T) {
	var reg shutdownRegistry
	registerEarlyShutdownHooks(&reg, &startupState{})

	hooks := reg.hooksSnapshot()
	if len(hooks) != len(canonicalEarlyShutdownHooks) {
		t.Fatalf("got %d early hooks; want %d", len(hooks), len(canonicalEarlyShutdownHooks))
	}
	for i, want := range canonicalEarlyShutdownHooks {
		if hooks[i].name != want.name {
			t.Errorf("early hook[%d] name = %q; want %q", i, hooks[i].name, want.name)
		}
		if hooks[i].order != want.order {
			t.Errorf("early hook[%d] (%s) order = %d; want %d", i, hooks[i].name, hooks[i].order, want.order)
		}
	}
}

// TestRegisterLateShutdownHooks_OrderMatchesCanonical pins each late-phase
// hook by name and order.
func TestRegisterLateShutdownHooks_OrderMatchesCanonical(t *testing.T) {
	var reg shutdownRegistry
	registerLateShutdownHooks(&reg, &startupState{}, testInertHTTPServer())

	hooks := reg.hooksSnapshot()
	if len(hooks) != len(canonicalLateShutdownHooks) {
		t.Fatalf("got %d late hooks; want %d", len(hooks), len(canonicalLateShutdownHooks))
	}
	for i, want := range canonicalLateShutdownHooks {
		if hooks[i].name != want.name {
			t.Errorf("late hook[%d] name = %q; want %q", i, hooks[i].name, want.name)
		}
		if hooks[i].order != want.order {
			t.Errorf("late hook[%d] (%s) order = %d; want %d", i, hooks[i].name, hooks[i].order, want.order)
		}
	}
}

// TestEarlyAndLateShutdownHooks_OrdersDoNotOverlap pins the structural
// invariant that early-phase orders are all ≤ shutdownEarlyLateBoundary
// and late-phase orders are all > shutdownEarlyLateBoundary. If a future
// PR moves a hook between phases without updating the canonical lists,
// this and the canonical tests above fail loudly.
func TestEarlyAndLateShutdownHooks_OrdersDoNotOverlap(t *testing.T) {
	var early, late shutdownRegistry
	registerEarlyShutdownHooks(&early, &startupState{})
	registerLateShutdownHooks(&late, &startupState{}, testInertHTTPServer())

	for _, h := range early.hooksSnapshot() {
		if h.order > shutdownEarlyLateBoundary {
			t.Errorf("early hook %q has order %d > boundary %d (must be in late phase)", h.name, h.order, shutdownEarlyLateBoundary)
		}
	}
	for _, h := range late.hooksSnapshot() {
		if h.order <= shutdownEarlyLateBoundary {
			t.Errorf("late hook %q has order %d ≤ boundary %d (must be in early phase)", h.name, h.order, shutdownEarlyLateBoundary)
		}
	}
}

// TestRegisterShutdownHooks_OrdersAreStrictlyAscending pins the
// strict-monotonic-increase invariant within each phase.
func TestRegisterShutdownHooks_OrdersAreStrictlyAscending(t *testing.T) {
	var early, late shutdownRegistry
	registerEarlyShutdownHooks(&early, &startupState{})
	registerLateShutdownHooks(&late, &startupState{}, testInertHTTPServer())

	for _, phase := range []struct {
		label string
		hooks []shutdownHook
	}{
		{"early", early.hooksSnapshot()},
		{"late", late.hooksSnapshot()},
	} {
		for i := 1; i < len(phase.hooks); i++ {
			if phase.hooks[i].order <= phase.hooks[i-1].order {
				t.Errorf("%s hook[%d] (%s, order=%d) is not strictly greater than hook[%d] (%s, order=%d)",
					phase.label, i, phase.hooks[i].name, phase.hooks[i].order,
					i-1, phase.hooks[i-1].name, phase.hooks[i-1].order)
			}
		}
	}
}

// TestRegisterShutdownHooks_NoNilStops is belt-and-suspenders against
// shutdownRegistry.Register's panic-on-nil contract: every hook produced
// by both wiring functions must have a non-nil stop.
func TestRegisterShutdownHooks_NoNilStops(t *testing.T) {
	var early, late shutdownRegistry
	registerEarlyShutdownHooks(&early, &startupState{})
	registerLateShutdownHooks(&late, &startupState{}, testInertHTTPServer())

	for _, h := range early.hooksSnapshot() {
		if h.stop == nil {
			t.Errorf("early hook %q has nil stop function", h.name)
		}
	}
	for _, h := range late.hooksSnapshot() {
		if h.stop == nil {
			t.Errorf("late hook %q has nil stop function", h.name)
		}
	}
}

// TestRegisterShutdownHooks_NamesAreUniqueAcrossPhases pins the
// global-name-uniqueness invariant: even though the two registries are
// run separately, hook names are used in aggregated error messages and
// duplicates would be ambiguous. (The shutdownRegistry type itself does
// not enforce this — the contract is at the application layer.)
func TestRegisterShutdownHooks_NamesAreUniqueAcrossPhases(t *testing.T) {
	var early, late shutdownRegistry
	registerEarlyShutdownHooks(&early, &startupState{})
	registerLateShutdownHooks(&late, &startupState{}, testInertHTTPServer())

	seen := make(map[string]string) // name → phase
	check := func(phase string, hooks []shutdownHook) {
		for _, h := range hooks {
			if other, dup := seen[h.name]; dup {
				t.Errorf("duplicate hook name %q (in %s and %s)", h.name, other, phase)
			}
			seen[h.name] = phase
		}
	}
	check("early", early.hooksSnapshot())
	check("late", late.hooksSnapshot())
}

// TestRunShutdownSequence_EveryPhaseCarriesADeadline is the budget-scoping
// contract test. Synthetic hooks record the deadline status of the ctx they
// receive; the assertion fails if any phase runs unbounded.
//
// CHAOS-56 INVERTED THIS TEST. It previously asserted the OPPOSITE for the
// early phase — that the early ctx must NOT carry a deadline, pinning the
// P2.2 decision to run HA stop / gRPC GracefulStop / CDR shutdown under
// context.Background(). That is the defect: GracefulStop waits for every
// client transport to close, and a half-open DP never acks the GOAWAY ping,
// so the early phase could hold SIGTERM open for the TCP retransmit budget
// (~15 min) while the container's 60s stop_grace_period ticked down to a
// SIGKILL that skipped every durable flush behind it. The early phase now
// carries its own bound; the budget-SCOPING intent the old test protected —
// that the early phase does not share the late phase's clock — is preserved
// and asserted below.
func TestRunShutdownSequence_EveryPhaseCarriesADeadline(t *testing.T) {
	var early, late shutdownRegistry
	var earlyRemaining, drainRemaining, flushRemaining time.Duration
	var earlyRan, drainRan, flushRan atomic.Bool

	budget := shutdownBudget{Total: 30 * time.Second, Early: 6 * time.Second, Flush: 8 * time.Second}

	early.Register("test-early-probe", 1, func(ctx context.Context) error {
		earlyRemaining = remainingOf(t, ctx)
		earlyRan.Store(true)
		return nil
	})
	late.Register("test-drain-probe", shutdownFlushBoundary, func(ctx context.Context) error {
		drainRemaining = remainingOf(t, ctx)
		drainRan.Store(true)
		return nil
	})
	late.Register("test-flush-probe", shutdownFlushBoundary+1, func(ctx context.Context) error {
		flushRemaining = remainingOf(t, ctx)
		flushRan.Store(true)
		return nil
	})

	runShutdownSequence(&early, &late, budget)

	for _, c := range []struct {
		name string
		ran  *atomic.Bool
	}{{"early", &earlyRan}, {"drain", &drainRan}, {"flush", &flushRan}} {
		if !c.ran.Load() {
			t.Fatalf("%s probe hook did not run", c.name)
		}
	}

	// Early is bounded by its OWN share, not by the whole envelope — the
	// budget-scoping property the pre-CHAOS-56 test protected with
	// "no deadline at all".
	assertRemaining(t, "early", earlyRemaining, budget.Early)
	// The drain phase gets the envelope MINUS the flush reserve, so a stuck
	// drain cannot spend the durability budget.
	assertRemaining(t, "drain", drainRemaining, budget.Total-budget.Flush)
	// The flush reserve is measured from the start of the flush phase, so it
	// is the full reserve regardless of what the drain phase did.
	assertRemaining(t, "flush", flushRemaining, budget.Flush)
}

// remainingOf reports how long ctx has left, failing the test if it carries
// no deadline at all.
func remainingOf(t *testing.T, ctx context.Context) time.Duration {
	t.Helper()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Error("phase ctx has no deadline — the shutdown envelope is not being enforced")
		return 0
	}
	return time.Until(dl)
}

// assertRemaining pins an observed phase budget to its expected share, with
// generous slack for goroutine scheduling. The deadline is set before the
// hook runs, so the observed remaining time should be just under `want`.
func assertRemaining(t *testing.T, phase string, got, want time.Duration) {
	t.Helper()
	if got > want {
		t.Errorf("%s phase remaining = %v; must be ≤ its share %v", phase, got, want)
	}
	if got < want-time.Second {
		t.Errorf("%s phase remaining = %v; must be ≥ share − 1s = %v", phase, got, want-time.Second)
	}
}

// TestRunShutdownSequence_ZeroBudgetRunsUnbounded pins the escape hatch: a
// zero Total reproduces the pre-CHAOS-56 un-budgeted shape, so a caller (or a
// test) can still run the sequence with no envelope at all.
func TestRunShutdownSequence_ZeroBudgetRunsUnbounded(t *testing.T) {
	var early, late shutdownRegistry
	var earlyHasDeadline, lateHasDeadline atomic.Bool

	early.Register("test-early-probe", 1, func(ctx context.Context) error {
		_, has := ctx.Deadline()
		earlyHasDeadline.Store(has)
		return nil
	})
	late.Register("test-late-probe", 1, func(ctx context.Context) error {
		_, has := ctx.Deadline()
		lateHasDeadline.Store(has)
		return nil
	})

	runShutdownSequence(&early, &late, shutdownBudget{})

	if earlyHasDeadline.Load() || lateHasDeadline.Load() {
		t.Errorf("zero budget must run unbounded; early deadline=%v late deadline=%v",
			earlyHasDeadline.Load(), lateHasDeadline.Load())
	}
}
