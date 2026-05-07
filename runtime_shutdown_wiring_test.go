package main

import (
	"net/http"
	"testing"
)

// Tests for P2.2 / S5 — runProxyUntilShutdown wired through shutdownRegistry.
//
// These tests inspect the wired hook list (via shutdownRegistry.hooksSnapshot)
// without invoking RunAll. No production global is touched at run-time —
// hook bodies are closures; they're only inspected by name + order, never
// called.
//
// The registry semantics (run-everything, ascending order, idempotency,
// nil-stop panic, register-after-RunAll panic) are pinned by the existing
// runtime_shutdown_test.go (P2.1).

// canonicalShutdownHookOrder is the byte-equivalent canonical sequence of
// shutdown hooks as they were laid out before P2.2 in runProxyUntilShutdown.
// Must stay aligned with registerProxyShutdownHooks; this list is the test's
// independent source of truth (renaming a hook or shuffling its order in
// the production code without updating this list will fail
// TestRegisterProxyShutdownHooks_OrderMatchesCanonical).
var canonicalShutdownHookOrder = []struct {
	name  string
	order int
}{
	{"ha-stop", shutdownOrderHAStop},
	{"control-plane-grpc-stop", shutdownOrderControlPlaneGRPCStop},
	{"cdr-client-shutdown", shutdownOrderCDRClientShutdown},
	{"app-lifecycle-cancel", shutdownOrderAppLifecycleCancel},
	{"rate-limit-cleanup-cancel", shutdownOrderRateLimitCleanupCancel},
	{"scan-svc-shutdown", shutdownOrderScanSvcShutdown},
	{"admin-ui-shutdown", shutdownOrderAdminUIShutdown},
	{"socks5-listener-stop", shutdownOrderSOCKS5ListenerStop},
	{"proxy-server-shutdown", shutdownOrderProxyServerShutdown},
	{"tunnel-drain", shutdownOrderTunnelDrain},
	{"syslog-close", shutdownOrderSyslogClose},
	{"community-db-close", shutdownOrderCommunityDBClose},
	{"request-log-close", shutdownOrderRequestLogClose},
	{"log-closer", shutdownOrderLogCloser},
}

// TestRegisterProxyShutdownHooks_OrderMatchesCanonical pins the exact
// hook name and order for every shutdown step. The wiring code in
// registerProxyShutdownHooks must register hooks in this exact sequence
// to preserve byte-equivalent shutdown behaviour. Synthetic startupState
// + empty proxySrv — no production code is invoked at run-time.
func TestRegisterProxyShutdownHooks_OrderMatchesCanonical(t *testing.T) {
	var reg shutdownRegistry
	registerProxyShutdownHooks(&reg, &startupState{}, &http.Server{})

	hooks := reg.hooksSnapshot()
	if len(hooks) != len(canonicalShutdownHookOrder) {
		t.Fatalf("got %d hooks; want %d (canonical sequence drifted)", len(hooks), len(canonicalShutdownHookOrder))
	}

	for i, want := range canonicalShutdownHookOrder {
		got := hooks[i]
		if got.name != want.name {
			t.Errorf("hook[%d] name = %q; want %q", i, got.name, want.name)
		}
		if got.order != want.order {
			t.Errorf("hook[%d] (%s) order = %d; want %d", i, got.name, got.order, want.order)
		}
	}
}

// TestRegisterProxyShutdownHooks_OrdersAreStrictlyAscending pins the
// invariant that order numbers are unique and monotonically increasing.
// A duplicate order would still be deterministic (stable sort breaks ties
// in registration order), but unique gaps make the contract self-evident
// and leave room for future inserts without renumbering.
func TestRegisterProxyShutdownHooks_OrdersAreStrictlyAscending(t *testing.T) {
	var reg shutdownRegistry
	registerProxyShutdownHooks(&reg, &startupState{}, &http.Server{})

	hooks := reg.hooksSnapshot()
	for i := 1; i < len(hooks); i++ {
		if hooks[i].order <= hooks[i-1].order {
			t.Errorf("hook[%d] (%s, order=%d) is not strictly greater than hook[%d] (%s, order=%d)",
				i, hooks[i].name, hooks[i].order,
				i-1, hooks[i-1].name, hooks[i-1].order)
		}
	}
}

// TestRegisterProxyShutdownHooks_NoNilStops is belt-and-suspenders against
// P2.1's panic-on-nil contract: every hook produced by the wiring code
// must have a non-nil stop function. (P2.1's Register would panic during
// registerProxyShutdownHooks if a nil slipped through, which would also
// fail this test — but a direct snapshot assertion gives a clearer error
// message.)
func TestRegisterProxyShutdownHooks_NoNilStops(t *testing.T) {
	var reg shutdownRegistry
	registerProxyShutdownHooks(&reg, &startupState{}, &http.Server{})

	for _, h := range reg.hooksSnapshot() {
		if h.stop == nil {
			t.Errorf("hook %q has nil stop function", h.name)
		}
	}
}

// TestRegisterProxyShutdownHooks_NamesAreUnique pins the name-uniqueness
// invariant — an aggregated error from RunAll labels each failing hook by
// name, so duplicate names would produce ambiguous diagnostics.
func TestRegisterProxyShutdownHooks_NamesAreUnique(t *testing.T) {
	var reg shutdownRegistry
	registerProxyShutdownHooks(&reg, &startupState{}, &http.Server{})

	seen := make(map[string]struct{})
	for _, h := range reg.hooksSnapshot() {
		if _, dup := seen[h.name]; dup {
			t.Errorf("duplicate hook name %q", h.name)
		}
		seen[h.name] = struct{}{}
	}
}
