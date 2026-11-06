package main

// connlimit_cluster_apply_chaos112_test.go — CHAOS-112, first half.
//
// The CP→DP snapshot apply ENABLED the per-IP connection limiter on every Data
// Plane, at the default cap, on a fleet where no operator configured it.
// `conn_limit_max_per_ip` is ClusterSynced in config_surfaces.go;
// `conn_limit_enabled` has no ConfigSnapshot binding there at all — enablement
// is node-local, owned by the startup resolver, the persisted admin settings,
// the admin API and config import — and the apply's only primitive was
// `Enable`, which writes BOTH.
//
// The controls matter as much as the primary gate. The cheapest way to pass it
// is to ignore the snapshot field, which would silently un-sync a surface the
// registry DOES declare synced; the next cheapest is to skip the field on a
// disabled node, which would freeze that node's cap at its boot value forever.
//
// The refusal's observability — the half that made this undiagnosable on a
// live fleet — is gated in connlimit_refusal_observability_chaos112_test.go.
// The primitive's own contract, including the non-positive refusal no root
// gate can reach, is in internal/connlimit/chaos112_setmaxperip_test.go.

import (
	"bytes"
	"log"
	"testing"
)

// chaos112Isolate installs a fresh connection limiter and restores the
// previous one. The limiter is a package-global whose enabled flag and cap are
// exactly what these tests assert on, and `Enable`/`Disable` mutate it in
// place, so saving the POINTER alone would hand back the same mutated object —
// the connlimit_startup_test.go / proxy_host_bounds_test.go pattern.
func chaos112Isolate(t *testing.T) {
	t.Helper()
	setupProxyTest(t)
	// The apply mutates ipf and rl IN PLACE (RISK-030), so saving the pointers
	// would restore the mutated objects and leak a cleared filter or a zeroed
	// rate limiter into whatever runs next. Required of every root test that
	// reaches the apply path, and enforced structurally by
	// TestSnapshotApplyFixture_Wall_EveryApplyCallerBindsFreshOwners — which is
	// what caught this sweep's first draft.
	bindFreshAdmissionOwners(t)
	prev := connLimiter
	t.Cleanup(func() { connLimiter = prev })
	connLimiter = newConnLimiter()
}

// chaos112CaptureLog swaps the process logger for a buffer and restores it.
func chaos112CaptureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = prev })
	return &buf
}

// chaos112Snapshot builds the snapshot a real Control Plane publishes. The cap
// is taken the way CurrentConfigSnapshot takes it — `connLimiter.MaxPerIP()`
// (controlplane_snapshot.go) — because the whole finding is that that accessor
// answers with a cap whether or not limiting is on.
func chaos112Snapshot(version int64, maxPerIP int) ConfigSnapshot {
	return ConfigSnapshot{Version: version, MaxConnsPerIP: maxPerIP}
}

// ───────────────────────── DEFECT GATES ─────────────────────────

// TestCHAOS112_SnapshotDoesNotEnableADisabledLimiter is the primary gate.
//
// Pre-fix: a Data Plane whose operator never configured the per-IP connection
// limiter applies its first snapshot and starts enforcing a cap nobody asked
// for, while the Control Plane's own GET /api/connlimit reports
// `enabled:false`. The direction of the error is fail-CLOSED, which is why it
// survived — but it is an enforcement divergence between CP and DP on an
// admission surface, and (see the observability gates below) it was invisible
// from every surface except that one node's own API.
func TestCHAOS112_SnapshotDoesNotEnableADisabledLimiter(t *testing.T) {
	chaos112Isolate(t)

	if connLimiter.Enabled() {
		t.Fatal("fixture: a fresh limiter must start disabled")
	}
	// The root cause, asserted here so the gate's premise is explicit rather
	// than assumed: a DISABLED limiter still answers MaxPerIP() with a cap, so
	// the publisher cannot emit 0 and the field can never mean "off".
	if got := connLimiter.MaxPerIP(); got <= 0 {
		t.Fatalf("fixture: MaxPerIP() = %d on a disabled limiter; this gate's premise "+
			"is that it answers non-zero, making the wire field unable to signal off", got)
	}

	applyConfigSnapshot(chaos112Snapshot(101, connLimiter.MaxPerIP()))

	if connLimiter.Enabled() {
		t.Errorf("applying a config snapshot ENABLED per-IP connection limiting on a node "+
			"that never configured it (cap now %d). conn_limit_enabled has no ConfigSnapshot "+
			"binding in config_surfaces.go — enablement is node-local — so the apply must not "+
			"write it", connLimiter.MaxPerIP())
	}
}

// TestCHAOS112_ControlSnapshotUpdatesTheCapOfAnEnabledLimiter is the control
// that forbids the cheap fix. `conn_limit_max_per_ip` IS declared
// ClusterSynced, so a node that HAS the limiter on must adopt the cluster cap;
// an apply that simply dropped the field would pass the gate above while
// silently un-syncing a surface the registry says is synced.
func TestCHAOS112_ControlSnapshotUpdatesTheCapOfAnEnabledLimiter(t *testing.T) {
	chaos112Isolate(t)

	connLimiter.Enable(7)
	applyConfigSnapshot(chaos112Snapshot(102, 64))

	if !connLimiter.Enabled() {
		t.Error("the apply DISABLED a limiter the node had enabled — enablement is node-local " +
			"in both directions, not just the off one")
	}
	if got := connLimiter.MaxPerIP(); got != 64 {
		t.Errorf("MaxPerIP() = %d, want 64 — the cluster-synced cap did not reach the node", got)
	}
}

// TestCHAOS112_SnapshotNeverFlipsEnablementInEitherDirection is the structural
// statement of the contract, over both starting states and a cap that differs
// from the live one in each. It is deliberately redundant with the two gates
// above: those pin the two cases that matter operationally, this one pins the
// INVARIANT, so a later apply that grows a new enablement branch fails here.
func TestCHAOS112_SnapshotNeverFlipsEnablementInEitherDirection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		enable   bool
		maxPerIP int
		wantCap  int
	}{
		{"off stays off", false, 32, 32},
		{"on stays on", true, 32, 32},
		{"off stays off at the default cap", false, 1024, 1024},
		{"on stays on at a tighter cap", true, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chaos112Isolate(t)
			if tc.enable {
				connLimiter.Enable(4096)
			}
			before := connLimiter.Enabled()

			applyConfigSnapshot(chaos112Snapshot(103, tc.maxPerIP))

			if got := connLimiter.Enabled(); got != before {
				t.Errorf("Enabled() = %v, want %v — the apply moved node-local enablement", got, before)
			}
			if got := connLimiter.MaxPerIP(); got != tc.wantCap {
				t.Errorf("MaxPerIP() = %d, want %d", got, tc.wantCap)
			}
		})
	}
}

// TestCHAOS112_ControlZeroCapKeepsLiveState pins the semantics
// config_surfaces.go records for this binding — `semSkipIfZero`, "zero value
// keeps live state". The finding is that no real publisher can emit zero, not
// that zero should start meaning something new: an older Control Plane, or a
// snapshot with the field absent, must still leave the node's cap alone.
func TestCHAOS112_ControlZeroCapKeepsLiveState(t *testing.T) {
	chaos112Isolate(t)

	connLimiter.Enable(11)
	applyConfigSnapshot(chaos112Snapshot(104, 0))

	if !connLimiter.Enabled() {
		t.Error("a zero cap disabled the limiter — semSkipIfZero means keep live state")
	}
	if got := connLimiter.MaxPerIP(); got != 11 {
		t.Errorf("MaxPerIP() = %d, want 11 — a zero cap overwrote live state", got)
	}
}

// TestCHAOS112_ControlDisabledLimiterKeepsItsCapThroughAnApply is the
// negative control for the fix's shape. The fix must update the cap WITHOUT
// touching enablement, which means a disabled node's cap moves too — that is
// correct (it is the cluster's cap, ready for whenever the operator enables
// locally) and it must not be mistaken for enforcement. Asserted so a future
// "just skip the whole field when disabled" cannot land silently: that would
// leave a node's cap frozen at its boot value forever.
func TestCHAOS112_ControlDisabledLimiterKeepsItsCapThroughAnApply(t *testing.T) {
	chaos112Isolate(t)

	applyConfigSnapshot(chaos112Snapshot(105, 77))

	if connLimiter.Enabled() {
		t.Fatal("the apply enabled a disabled limiter")
	}
	if got := connLimiter.MaxPerIP(); got != 77 {
		t.Errorf("MaxPerIP() = %d, want 77 — the cluster cap must still be recorded on a "+
			"node whose limiter is off, so enabling locally adopts the fleet's value", got)
	}
	// And the recorded cap must not start enforcing anything by itself.
	if !connLimiter.Acquire("198.51.100.77") {
		t.Error("Acquire refused on a DISABLED limiter — recording a cap must not enforce it")
	}
	connLimiter.Release("198.51.100.77")
}
