package main

// CHAOS-130 — the OTLP export PAIR. Metrics and traces are configured and
// stopped together by every caller, but never atomically, and the CP snapshot
// apply decided for both halves from the METRICS exporter's state. A plane
// left half enabled was therefore permanent AND invisible in one direction,
// and fail-OPEN in the other.

import (
	"strings"
	"sync"
	"testing"
)

const chaos130Endpoint = "http://collector.invalid:4318"

// Reproduction: a traces exporter stopped on its own stayed dark through every
// later snapshot carrying the right endpoint, because the apply compared the
// snapshot's endpoint against globalOTLP's and skipped both when it matched.
func TestChaos130_SnapshotRestoresATracesExporterStoppedAlone(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)

	globalOTLP.Configure(chaos130Endpoint, nil)
	globalOTLPTraces.Stop()
	if globalOTLPTraces.Enabled() {
		t.Fatal("fixture: traces must start stopped")
	}

	applySnapshotExtendedState(ConfigSnapshot{OTLPEndpoint: chaos130Endpoint})

	if !globalOTLPTraces.Enabled() {
		t.Error("traces export is still off after a snapshot carrying the endpoint; spans stop being exported and no later apply recovers it")
	}
	if got := globalOTLPTraces.Endpoint(); got != chaos130Endpoint {
		t.Errorf("traces endpoint = %q; want %q", got, chaos130Endpoint)
	}
	if !globalOTLP.Enabled() {
		t.Error("metrics export was turned off by the reconcile; it was already correct")
	}
}

// The fail-OPEN direction: a snapshot that DISABLES export stopped neither
// half when metrics was already off, because the guard was
// `else if globalOTLP.Enabled()`. A fleet-wide instruction to stop shipping
// telemetry left spans — client IPs, target hosts, enforcement decisions —
// going to the collector, and the control plane believed it had complied.
func TestChaos130_SnapshotDisableStopsTracesEvenWhenMetricsIsAlreadyOff(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)

	globalOTLP.Stop()
	globalOTLPTraces.Configure(chaos130Endpoint, nil)
	if !globalOTLPTraces.Enabled() {
		t.Fatal("fixture: traces must start enabled")
	}

	applySnapshotExtendedState(ConfigSnapshot{OTLPEndpoint: ""})

	if globalOTLPTraces.Enabled() {
		t.Error("traces export survived a snapshot that disabled OTLP export: the gateway is still shipping request spans the control plane told it to stop shipping")
	}
	if globalOTLP.Enabled() {
		t.Error("metrics export survived a snapshot that disabled OTLP export")
	}
}

// An exporter already at the snapshot's endpoint is left alone: reconciling
// must not cancel a healthy push loop, or — for traces — throw away the
// buffered spans, on every apply.
func TestChaos130_SnapshotLeavesACoherentPlaneAlone(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)

	configureOTLPPair(chaos130Endpoint, nil)
	globalOTLPTraces.RecordSpan(SpanRecord{TraceID: "t", SpanID: "s", Name: "proxy_request"})
	before := globalOTLPTraces.Health().DroppedSpans

	for i := 0; i < 5; i++ {
		applySnapshotExtendedState(ConfigSnapshot{OTLPEndpoint: chaos130Endpoint})
	}

	if !globalOTLP.Enabled() || !globalOTLPTraces.Enabled() {
		t.Errorf("reconcile turned a correct plane off: metrics=%v traces=%v", globalOTLP.Enabled(), globalOTLPTraces.Enabled())
	}
	if got := globalOTLPTraces.Health().DroppedSpans; got != before {
		t.Errorf("DroppedSpans moved from %d to %d across five no-op applies; a buffered span must not be discarded by a reconcile that changes nothing", before, got)
	}
}

// A repoint through the snapshot must move BOTH halves.
func TestChaos130_SnapshotRepointMovesBothHalves(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)

	configureOTLPPair(chaos130Endpoint, nil)
	const next = "http://collector2.invalid:4318"
	applySnapshotExtendedState(ConfigSnapshot{OTLPEndpoint: next})

	if got := globalOTLP.Endpoint(); got != next {
		t.Errorf("metrics endpoint = %q; want %q", got, next)
	}
	if got := globalOTLPTraces.Endpoint(); got != next {
		t.Errorf("traces endpoint = %q; want %q", got, next)
	}
}

// The admin handler's shape: concurrent enable and disable transitions must
// never settle with the plane half on. Pre-fix each handler called the two
// exporters in sequence with nothing serialising the pair.
func TestChaos130_ConcurrentPairTransitionsNeverSettleHalfEnabled(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)

	for round := 0; round < 200; round++ {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); configureOTLPPair(chaos130Endpoint, nil) }()
		go func() { defer wg.Done(); stopOTLPPair() }()
		wg.Wait()

		m, tr := globalOTLP.Enabled(), globalOTLPTraces.Enabled()
		if m != tr {
			t.Fatalf("round %d: metrics enabled=%v but traces enabled=%v — the pair settled half on, which is not a state an operator can ask for", round, m, tr)
		}
	}
}

// The silence this round removes: an export plane with one half running used
// to produce NO diagnostic row at all, because the only row reports a half
// that is FAILING and has nothing to say about one that is OFF.
func TestChaos130_HalfEnabledExportIsReported(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)

	t.Run("metrics on, traces off", func(t *testing.T) {
		globalOTLP.Configure(chaos130Endpoint, nil)
		globalOTLPTraces.Stop()
		assertPartialRow(t, "traces")
	})
	t.Run("traces on, metrics off", func(t *testing.T) {
		globalOTLP.Stop()
		globalOTLPTraces.Configure(chaos130Endpoint, nil)
		assertPartialRow(t, "metrics")
	})
	t.Run("both on is not a divergence", func(t *testing.T) {
		configureOTLPPair(chaos130Endpoint, nil)
		if row := findDiagRow(checkOTLPExport(), "otlp_export_partial"); row != nil {
			t.Errorf("a fully enabled export plane reported %q: %s", row.Code, row.Message)
		}
	})
	t.Run("both off is not a divergence", func(t *testing.T) {
		stopOTLPPair()
		if row := findDiagRow(checkOTLPExport(), "otlp_export_partial"); row != nil {
			t.Errorf("a fully disabled export plane reported %q: %s", row.Code, row.Message)
		}
	})
}

func assertPartialRow(t *testing.T, wantOffHalf string) {
	t.Helper()
	row := findDiagRow(checkOTLPExport(), "otlp_export_partial")
	if row == nil {
		t.Fatalf("no otlp_export_partial row for a plane with %s off; the state was silent", wantOffHalf)
	}
	if row.Status != diagWarn {
		t.Errorf("row status = %q; want %q", row.Status, diagWarn)
	}
	if row.OperatorAction == "" {
		t.Error("row carries no operator action")
	}
	if !strings.Contains(row.Message, wantOffHalf) {
		t.Errorf("row message does not name the half that is off (%s): %s", wantOffHalf, row.Message)
	}
}

func findDiagRow(rows []OperatorContractCheck, code string) *OperatorContractCheck {
	for i := range rows {
		if rows[i].Code == code {
			return &rows[i]
		}
	}
	return nil
}
