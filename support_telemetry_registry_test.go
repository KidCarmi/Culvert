package main

// support_telemetry_registry_test.go — Slice 1 tests for the wired
// supportMetricRegistry (package-main Read closures over live process
// state), the exact §7 eligible set, and the pure builder wrapper. See
// internal/supportmetrics/*_test.go for the schema/hash/sample engine tests;
// these tests cover main's wiring of that engine.

import (
	"testing"
	"time"
)

// TestSupportTelemetryRegistryValid proves the wired production registry
// itself passes every structural invariant the engine enforces (default-deny
// justification, label-free ids, telemetry_eligible ⊆ in_bundle).
func TestSupportTelemetryRegistryValid(t *testing.T) {
	if err := supportMetricRegistry.Validate(); err != nil {
		t.Fatalf("supportMetricRegistry failed validation: %v", err)
	}
}

// TestSupportTelemetryExactEligibleSet is the golden test for §7: the wired
// registry's eligible set must be EXACTLY the 8 approved v1 metrics — no
// more, no less. Adding any other culvert_* metric here (traffic, scale,
// policy, detection, security-posture) must fail this test until §7 of the
// merged design is amended.
func TestSupportTelemetryExactEligibleSet(t *testing.T) {
	want := map[string]bool{
		"support_health_ca_ready":              true,
		"support_health_clamav_ready":          true,
		"support_health_yara_ready":            true,
		"support_health_policy_loaded":         true,
		"support_health_session_ready":         true,
		"support_health_config_snapshot_valid": true,
		"support_health_ca_expiry_bucket":      true,
		"support_uptime_bucket":                true,
	}
	got := map[string]bool{}
	for _, d := range supportMetricRegistry.Eligible() {
		got[d.ID] = true
	}
	if len(got) != len(want) {
		t.Fatalf("eligible set has %d metrics, want exactly %d: got=%v", len(got), len(want), got)
	}
	for id := range want {
		if !got[id] {
			t.Errorf("expected eligible metric %q missing from wired registry", id)
		}
	}
	for id := range got {
		if !want[id] {
			t.Errorf("unexpected eligible metric %q — v1 eligibility set is fixed by §7; broadening it needs a design amendment", id)
		}
	}
}

// TestSupportTelemetryRegistryAllInSupportBundle proves every wired
// descriptor (not just the eligible ones) is marked InSupportBundle — this
// slice's registry contains only support-health metrics, all of which are
// support-bundle health-section material.
func TestSupportTelemetryRegistryAllInSupportBundle(t *testing.T) {
	for _, d := range supportMetricRegistry {
		if !d.InSupportBundle {
			t.Errorf("metric %q is in the scoped support-metric registry but not marked InSupportBundle", d.ID)
		}
	}
}

func TestBuildSupportTelemetrySample_EmitsExactlyEligibleIDs(t *testing.T) {
	sample, err := buildSupportTelemetrySample(time.Now())
	if err != nil {
		t.Fatalf("buildSupportTelemetrySample: %v", err)
	}
	if len(sample.Metrics()) != len(supportMetricRegistry.Eligible()) {
		t.Fatalf("sample has %d metrics, want %d", len(sample.Metrics()), len(supportMetricRegistry.Eligible()))
	}
	for _, d := range supportMetricRegistry.Eligible() {
		if _, ok := sample.Metrics()[d.ID]; !ok {
			t.Errorf("sample missing eligible metric %q", d.ID)
		}
	}
}

func TestBuildSupportTelemetrySample_SchemaAndHashPresent(t *testing.T) {
	sample, err := buildSupportTelemetrySample(time.Now())
	if err != nil {
		t.Fatalf("buildSupportTelemetrySample: %v", err)
	}
	if sample.SchemaVersion() == 0 {
		t.Error("sample missing schema_version")
	}
	if sample.RegistryHash() == "" {
		t.Error("sample missing registry_hash")
	}
	if sample.RegistryHash() != supportMetricRegistry.Hash() {
		t.Errorf("sample registry_hash %q does not match live registry hash %q", sample.RegistryHash(), supportMetricRegistry.Hash())
	}
	if sample.GeneratedAt().IsZero() {
		t.Error("sample missing generated_at")
	}
	if sample.SampleEpoch() == "" {
		t.Error("sample missing sample_epoch")
	}
}

// TestSupportHealthReadCallbacks_ReturnBinaryOrBucketValues sanity-checks
// each wired Read closure returns a value in its documented range, without
// asserting a specific live value (which depends on process state the test
// doesn't control).
func TestSupportHealthReadCallbacks_ReturnBinaryOrBucketValues(t *testing.T) {
	binary := []func() float64{
		readSupportHealthCAReady,
		readSupportHealthClamAVReady,
		readSupportHealthYARAReady,
		readSupportHealthPolicyLoaded,
		readSupportHealthSessionReady,
		readSupportHealthConfigSnapshotValid,
	}
	for i, fn := range binary {
		v := fn()
		if v != 0 && v != 1 {
			t.Errorf("binary read closure #%d returned %v, want 0 or 1", i, v)
		}
	}
	bucketed := []func() float64{readSupportHealthCAExpiryBucket, readSupportUptimeBucket}
	for i, fn := range bucketed {
		v := fn()
		if v < 0 || v > 3 {
			t.Errorf("bucketed read closure #%d returned %v, want 0..3", i, v)
		}
	}
}

// TestSupportHealthCAReady_HonorsLoadFailure — a CA that failed to
// load/persist (sslInspectionLoadError, CHAOS-06) must report NOT ready even
// when certMgr.Ready() still returns true in that window, matching
// computeReadiness's "ca" check (healthcheck.go). Without this, the
// telemetry sample would tell an admin/TAC the CA is usable while the
// appliance is actually degraded to tunnel-only bypass.
func TestSupportHealthCAReady_HonorsLoadFailure(t *testing.T) {
	prev := sslInspectionLoadFailure()
	t.Cleanup(func() { sslInspectionLoadError.Store(prev) })

	sslInspectionLoadError.Store("Root CA load/init failed: boom")
	if got := readSupportHealthCAReady(); got != 0 {
		t.Errorf("readSupportHealthCAReady() = %v during a recorded load failure, want 0", got)
	}
	if got := readSupportHealthCAExpiryBucket(); got != 3 {
		t.Errorf("readSupportHealthCAExpiryBucket() = %v during a recorded load failure, want 3 (most urgent)", got)
	}

	sslInspectionLoadError.Store("")
	// With no recorded failure, both reads fall back to their normal
	// certMgr-derived posture (not asserted further here — process CA state
	// is exercised by TestSupportHealthReadCallbacks_ReturnBinaryOrBucketValues).
}
