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

// TestRunShutdownSequence_EarlyCtxHasNoDeadline_LateCtxDoes is the
// budget-scoping contract test: the entire reason this PR splits into two
// registries. Synthetic hooks record the deadline status of the ctx they
// receive; the assertion fails if the 30s budget leaks into the early
// phase.
//
// This is the test the user explicitly asked for — "would fail if the 30s
// ctx is created before hooks 1–5".
func TestRunShutdownSequence_EarlyCtxHasNoDeadline_LateCtxDoes(t *testing.T) {
	var early, late shutdownRegistry
	var earlyHasDeadline, lateHasDeadline atomic.Bool
	var earlyRan, lateRan atomic.Bool

	early.Register("test-early-probe", 1, func(ctx context.Context) error {
		_, has := ctx.Deadline()
		earlyHasDeadline.Store(has)
		earlyRan.Store(true)
		return nil
	})
	late.Register("test-late-probe", 1, func(ctx context.Context) error {
		_, has := ctx.Deadline()
		lateHasDeadline.Store(has)
		lateRan.Store(true)
		return nil
	})

	runShutdownSequence(&early, &late, 30*time.Second)

	if !earlyRan.Load() {
		t.Fatal("early probe hook did not run")
	}
	if !lateRan.Load() {
		t.Fatal("late probe hook did not run")
	}
	if earlyHasDeadline.Load() {
		t.Error("early phase ctx must NOT carry a deadline; got one — the 30s shutdown budget is leaking into the early phase")
	}
	if !lateHasDeadline.Load() {
		t.Error("late phase ctx must carry the 30s shutdown deadline; got none — the budget is missing")
	}
}

// TestRunShutdownSequence_LateCtxBudgetMatchesArgument confirms that the
// budget passed to runShutdownSequence is the budget the late ctx
// actually carries (within a generous tolerance for scheduling).
func TestRunShutdownSequence_LateCtxBudgetMatchesArgument(t *testing.T) {
	const want = 7 * time.Second
	var early, late shutdownRegistry
	var observedRemaining time.Duration

	late.Register("test-late-probe", 1, func(ctx context.Context) error {
		dl, ok := ctx.Deadline()
		if !ok {
			t.Error("late ctx has no deadline")
			return nil
		}
		observedRemaining = time.Until(dl)
		return nil
	})

	runShutdownSequence(&early, &late, want)

	// Allow generous slack for goroutine scheduling. The deadline is set
	// before the hook runs; the observed remaining time should be very
	// close to (but no more than) `want`.
	if observedRemaining > want {
		t.Errorf("late ctx remaining = %v; must be ≤ budget %v", observedRemaining, want)
	}
	if observedRemaining < want-time.Second {
		t.Errorf("late ctx remaining = %v; must be ≥ budget − 1s = %v", observedRemaining, want-time.Second)
	}
}
