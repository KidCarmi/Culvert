package connlimit

// chaos112_setmaxperip_test.go — CHAOS-112, the owner's half of the contract.
//
// The root gates (connlimit_cluster_apply_chaos112_test.go) drive the CP→DP
// apply, and they can only reach SetMaxPerIP through the caller's
// `if snap.MaxConnsPerIP > 0` guard — so the primitive's own refusal of a
// non-positive cap is unreachable from there. That is not a hypothetical gap:
// mutating the guard to reset-to-default instead of return went UNCAUGHT by
// every root gate, which is why these live here.
//
// What this file pins is the whole reason the primitive exists: a caller may
// hand this limiter a CAP without handing it an ENABLEMENT DECISION, and must
// get exactly that and nothing more.

import "testing"

// TestCHAOS112_SetMaxPerIPNeverTouchesEnablement is the primitive's defining
// property. `conn_limit_enabled` has no ConfigSnapshot binding in the root
// config-surface registry — it is node-local — so the one caller that applies
// a cluster-synced cap must not be able to move it in either direction.
func TestCHAOS112_SetMaxPerIPNeverTouchesEnablement(t *testing.T) {
	t.Run("a disabled limiter stays disabled", func(t *testing.T) {
		cl := New()
		if cl.Enabled() {
			t.Fatal("fixture: New() must return a disabled limiter")
		}
		cl.SetMaxPerIP(5)
		if cl.Enabled() {
			t.Error("SetMaxPerIP enabled a disabled limiter — this is the CHAOS-112 defect")
		}
		if got := cl.MaxPerIP(); got != 5 {
			t.Errorf("MaxPerIP() = %d, want 5", got)
		}
	})

	t.Run("an enabled limiter stays enabled", func(t *testing.T) {
		cl := New()
		cl.Enable(3)
		cl.SetMaxPerIP(9)
		if !cl.Enabled() {
			t.Error("SetMaxPerIP disabled an enabled limiter")
		}
		if got := cl.MaxPerIP(); got != 9 {
			t.Errorf("MaxPerIP() = %d, want 9", got)
		}
	})
}

// TestCHAOS112_SetMaxPerIPIgnoresANonPositiveCap pins the semantics the root
// config-surface registry records for the wire field this primitive serves:
// semSkipIfZero, "zero value keeps live state". An older Control Plane, or a
// snapshot with the field absent, decodes as 0 and must leave the node alone.
//
// This is the control the mutation run proved no root gate could reach.
func TestCHAOS112_SetMaxPerIPIgnoresANonPositiveCap(t *testing.T) {
	for _, cap := range []int{0, -1, -1024} {
		cl := New()
		cl.Enable(17)
		cl.SetMaxPerIP(cap)
		if got := cl.MaxPerIP(); got != 17 {
			t.Errorf("SetMaxPerIP(%d): MaxPerIP() = %d, want 17 — a non-positive cap "+
				"overwrote live state instead of keeping it", cap, got)
		}
		if !cl.Enabled() {
			t.Errorf("SetMaxPerIP(%d) disabled the limiter", cap)
		}
	}
}

// TestCHAOS112_SetMaxPerIPIsTheCapAcquireEnforces is the control against a
// primitive that stores a number nothing reads. A cluster-synced cap that does
// not actually govern admission would pass every assertion about enablement
// while silently un-syncing the surface the registry does declare synced.
func TestCHAOS112_SetMaxPerIPIsTheCapAcquireEnforces(t *testing.T) {
	cl := New()
	cl.Enable(4)
	cl.SetMaxPerIP(2)

	const ip = "198.51.100.9"
	if !cl.Acquire(ip) || !cl.Acquire(ip) {
		t.Fatal("the first two connections must be admitted at a cap of 2")
	}
	if cl.Acquire(ip) {
		t.Error("a third connection was admitted at a cap of 2 — SetMaxPerIP's value does " +
			"not reach the admission decision")
	}
	cl.Release(ip)
	cl.Release(ip)
}

// TestCHAOS112_SetMaxPerIPOnADisabledLimiterEnforcesNothing is the other side
// of that control, and it is the one that matters operationally: recording the
// fleet's cap on a node whose operator has not enabled limiting must not start
// enforcing it. If this ever fails, the CHAOS-112 defect is back by a
// different road.
func TestCHAOS112_SetMaxPerIPOnADisabledLimiterEnforcesNothing(t *testing.T) {
	cl := New()
	cl.SetMaxPerIP(1)

	const ip = "198.51.100.10"
	for i := 0; i < 50; i++ {
		if !cl.Acquire(ip) {
			t.Fatalf("connection %d refused by a DISABLED limiter holding a cap of 1", i+1)
		}
	}
	if got := cl.Rejected(); got != 0 {
		t.Errorf("Rejected() = %d, want 0 — a disabled limiter counted refusals", got)
	}
	for i := 0; i < 50; i++ {
		cl.Release(ip)
	}
}

// TestCHAOS112_DisablePreservesTheConfiguredCap pins the property that makes
// the whole finding possible, so that a later change to it is a deliberate
// decision rather than a surprise.
//
// Disable clears the flag and keeps the cap, which is correct on its own terms
// — an operator who toggles limiting off and on again must get their own
// configured value back, and GET /api/connlimit must render it meanwhile
// rather than a misleading 0. The consequence is that MaxPerIP can NEVER
// answer 0, so a publisher that derives a wire field from it cannot express
// "off", and any caller that infers enablement from the cap is wrong. That
// inference was the defect.
//
// If a future change makes MaxPerIP report 0 while disabled, this test fails —
// and the CP→DP apply, the admin API's rendering and the admin-settings
// round-trip all have to be revisited together.
func TestCHAOS112_DisablePreservesTheConfiguredCap(t *testing.T) {
	cl := New()
	cl.Enable(42)
	cl.Disable()

	if cl.Enabled() {
		t.Fatal("Disable did not clear the flag")
	}
	if got := cl.MaxPerIP(); got != 42 {
		t.Errorf("MaxPerIP() = %d after Disable, want the configured 42 — the operator's "+
			"value must survive an off/on cycle", got)
	}
	cl.Enable(0) // "enable, keep whatever cap you have" — the admin API's shape
	if got := cl.MaxPerIP(); got != defaultMaxConnsPerIP {
		t.Logf("Enable(0) resets to the default (%d), not the retained cap — recorded, not asserted", got)
	}

	fresh := New()
	if got := fresh.MaxPerIP(); got <= 0 {
		t.Errorf("a fresh, never-configured limiter reports MaxPerIP() = %d; CHAOS-112's "+
			"root cause is that this is non-zero, so a wire field derived from it cannot "+
			"signal \"off\"", got)
	}
}
