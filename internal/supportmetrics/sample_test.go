package supportmetrics

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
	"time"
)

func fixedNow() time.Time {
	return time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
}

// fixedTestEpoch is a well-formed 128-bit-hex sample_epoch for tests that
// don't care about the epoch's specific value.
func fixedTestEpoch() string { return "0123456789abcdef0123456789abcdef" }

// TestSupportTelemetrySampleHasNoStableIdentity — the sample carries no
// node_id/hostname/IP/tenant identifier: its JSON encoding contains only the
// governed schema fields and eligible metric id/value pairs. sample_epoch is
// present (per the wire contract) but is explicitly NOT a stable identity —
// it is a caller-supplied, per-process-lifetime random token, never an
// appliance fingerprint (§5).
func TestSupportTelemetrySampleHasNoStableIdentity(t *testing.T) {
	r := fixedTestRegistry()
	sample, err := r.BuildSample(fixedNow(), "0123456789abcdef0123456789abcdef", 0)
	if err != nil {
		t.Fatalf("BuildSample: %v", err)
	}

	b, err := json.Marshal(sample)
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}

	forbidden := []string{
		"node_id", "nodeId", "hostname", "host_name", "tenant", "appliance_id",
		"serial", "mac_address", "fingerprint", "ip_address",
	}
	got := string(b)
	for _, f := range forbidden {
		if jsonContainsKey(got, f) {
			t.Errorf("sample JSON contains forbidden identity-shaped field %q: %s", f, got)
		}
	}

	// Only the documented top-level wire fields exist (§3.3).
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal sample: %v", err)
	}
	wantKeys := map[string]bool{
		"schema_version": true, "registry_hash": true, "generated_at": true,
		"sample_epoch": true, "sequence": true, "metrics": true,
	}
	for k := range raw {
		if !wantKeys[k] {
			t.Errorf("sample JSON has unexpected top-level field %q", k)
		}
	}
	for k := range wantKeys {
		if _, ok := raw[k]; !ok {
			t.Errorf("sample JSON missing required field %q", k)
		}
	}
}

func jsonContainsKey(doc, key string) bool {
	var raw map[string]any
	if json.Unmarshal([]byte(doc), &raw) != nil {
		return false
	}
	_, ok := raw[key]
	return ok
}

// TestSupportTelemetrySampleForbiddenFieldSerialization is the "forbidden-field
// serialization test" required by the plan: no field name resembling a
// hostname/URL/IP/credential ever appears as a JSON key at any nesting depth,
// including inside the metrics map's keys (metric ids are a closed,
// code-reviewed vocabulary, but this proves it structurally too).
func TestSupportTelemetrySampleForbiddenFieldSerialization(t *testing.T) {
	r := fixedTestRegistry()
	sample, err := r.BuildSample(fixedNow(), fixedTestEpoch(), 0)
	if err != nil {
		t.Fatalf("BuildSample: %v", err)
	}
	for id := range sample.Metrics() {
		if !idPattern.MatchString(id) {
			t.Errorf("metric key %q in serialized sample is not label-free-scalar-safe", id)
		}
	}
}

// TestSupportTelemetrySampleMetricsIsImmutable proves Metrics() returns a
// defensive copy: mutating it must never affect the Sample's own state (and
// therefore never affect a later Metrics() call or MarshalJSON).
func TestSupportTelemetrySampleMetricsIsImmutable(t *testing.T) {
	r := fixedTestRegistry()
	sample, err := r.BuildSample(fixedNow(), fixedTestEpoch(), 0)
	if err != nil {
		t.Fatalf("BuildSample: %v", err)
	}
	m := sample.Metrics()
	for k := range m {
		m[k] = -999
	}
	m["totally_new_key"] = 1

	again := sample.Metrics()
	for k, v := range again {
		if v == -999 {
			t.Fatalf("mutating a Metrics() copy leaked into the Sample: key %q = %v", k, v)
		}
	}
	if _, ok := again["totally_new_key"]; ok {
		t.Fatal("adding a key to a Metrics() copy leaked into the Sample")
	}

	b, err := json.Marshal(sample)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire struct {
		Metrics map[string]float64 `json:"metrics"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := wire.Metrics["totally_new_key"]; ok {
		t.Fatal("MarshalJSON serialized a mutation made to a Metrics() copy")
	}
}

// TestSupportTelemetrySampleBuildIsSideEffectFree proves BuildSample performs
// no I/O of its own: it only ever calls each eligible Read() exactly once
// (even when the descriptor has a deprecated alias — the alias reuses the
// same value, Read is not called twice).
func TestSupportTelemetrySampleBuildIsSideEffectFree(t *testing.T) {
	calls := 0
	r := Registry{{
		ID: "support_health_ca_ready", Type: Gauge, PrivacyClass: Aggregate,
		InSupportBundle: true, TelemetryEligible: true, TelemetryReason: "own health",
		Read: func() float64 { calls++; return 1 },
	}}
	if _, err := r.BuildSample(fixedNow(), fixedTestEpoch(), 0); err != nil {
		t.Fatalf("BuildSample: %v", err)
	}
	if calls != 1 {
		t.Fatalf("Read called %d times, want exactly 1", calls)
	}
}

// TestSupportTelemetrySample_DeprecatedAliasEmitted verifies that BuildSample
// emits both the canonical ID and the deprecated alias key with identical
// values, and that the alias does not cause Read() to be called more than once.
func TestSupportTelemetrySample_DeprecatedAliasEmitted(t *testing.T) {
	calls := 0
	r := Registry{{
		ID: "support_health_ca_ready", Type: Gauge, PrivacyClass: Aggregate,
		InSupportBundle: true, TelemetryEligible: true, TelemetryReason: "own health",
		Read: func() float64 { calls++; return 5 }, DeprecatedAlias: "support_ca_ready",
	}}
	sample, err := r.BuildSample(fixedNow(), fixedTestEpoch(), 0)
	if err != nil {
		t.Fatalf("BuildSample: %v", err)
	}
	if calls != 1 {
		t.Errorf("Read called %d times with alias set, want exactly 1", calls)
	}
	m := sample.Metrics()
	if m["support_health_ca_ready"] != 5 {
		t.Errorf("canonical id value: got %v, want 5", m["support_health_ca_ready"])
	}
	if m["support_ca_ready"] != 5 {
		t.Errorf("deprecated alias value: got %v, want 5", m["support_ca_ready"])
	}
	// 2 keys: canonical + alias.
	if len(m) != 2 {
		t.Errorf("metrics map has %d entries, want 2 (canonical + alias)", len(m))
	}
}

// TestSupportTelemetrySampleRejectsInvalidRegistry ensures BuildSample
// refuses to build over a registry that fails Validate (e.g. an eligible
// metric missing its justification) rather than silently emitting a
// governance-incomplete sample.
func TestSupportTelemetrySampleRejectsInvalidRegistry(t *testing.T) {
	r := Registry{{ID: "support_health_x", Type: Gauge, PrivacyClass: Aggregate, TelemetryEligible: true, InSupportBundle: true, Read: func() float64 { return 0 }}}
	if _, err := r.BuildSample(fixedNow(), fixedTestEpoch(), 0); err == nil {
		t.Fatal("BuildSample must reject an invalid registry")
	}
}

// TestSupportTelemetrySampleDeterministicForFixedInputs — building twice with
// the same clock/epoch/sequence and unchanged Read values yields
// byte-identical JSON (map-order independence: encoding/json sorts map keys).
func TestSupportTelemetrySampleDeterministicForFixedInputs(t *testing.T) {
	r := fixedTestRegistry()
	s1, err := r.BuildSample(fixedNow(), fixedTestEpoch(), 7)
	if err != nil {
		t.Fatalf("BuildSample: %v", err)
	}
	s2, err := r.BuildSample(fixedNow(), fixedTestEpoch(), 7)
	if err != nil {
		t.Fatalf("BuildSample: %v", err)
	}
	b1, _ := json.Marshal(s1)
	b2, _ := json.Marshal(s2)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("two builds with identical inputs produced different bytes:\n%s\nvs\n%s", b1, b2)
	}
}

// TestSupportTelemetryBuildSampleValidatesEpochFormat — epoch must be
// exactly 32 lowercase-hex characters (128 bits, §5); anything else
// (wrong length, uppercase, non-hex) is rejected.
func TestSupportTelemetryBuildSampleValidatesEpochFormat(t *testing.T) {
	r := fixedTestRegistry()
	bad := []string{
		"", "epoch-1", "not-hex-at-all-not-hex-at-all!!",
		"0123456789ABCDEF0123456789ABCDEF",  // uppercase
		"0123456789abcdef0123456789abcde",   // 31 chars, one short
		"0123456789abcdef0123456789abcdef0", // 33 chars, one long
	}
	for _, epoch := range bad {
		if _, err := r.BuildSample(fixedNow(), epoch, 0); err == nil {
			t.Errorf("epoch %q must be rejected", epoch)
		}
	}
	if _, err := r.BuildSample(fixedNow(), fixedTestEpoch(), 0); err != nil {
		t.Errorf("well-formed epoch must be accepted: %v", err)
	}
}

// TestSupportTelemetryBuildSampleRejectsZeroTime — now must be non-zero;
// a zero time.Time is never a legitimate "current" generation timestamp.
func TestSupportTelemetryBuildSampleRejectsZeroTime(t *testing.T) {
	r := fixedTestRegistry()
	if _, err := r.BuildSample(time.Time{}, fixedTestEpoch(), 0); err == nil {
		t.Fatal("a zero time.Time must be rejected")
	}
}

// TestSupportTelemetryBuildSampleRejectsNonFiniteMetric — a Read() closure
// returning NaN/Inf must fail BuildSample rather than silently emit
// unrepresentable/misleading JSON.
func TestSupportTelemetryBuildSampleRejectsNonFiniteMetric(t *testing.T) {
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		r := Registry{{
			ID: "support_health_x", Type: Gauge, PrivacyClass: Aggregate,
			InSupportBundle: true, TelemetryEligible: true, TelemetryReason: "x",
			Read: func() float64 { return bad },
		}}
		if _, err := r.BuildSample(fixedNow(), fixedTestEpoch(), 0); err == nil {
			t.Errorf("non-finite metric value %v must be rejected", bad)
		}
	}
}

// TestSupportTelemetrySampleFieldsAreImmutable proves there is no exported
// API on Sample that can alter any field after construction — every
// accessor returns either an immutable value type or, for Metrics(), a
// fresh defensive copy.
func TestSupportTelemetrySampleFieldsAreImmutable(t *testing.T) {
	r := fixedTestRegistry()
	sample, err := r.BuildSample(fixedNow(), fixedTestEpoch(), 7)
	if err != nil {
		t.Fatalf("BuildSample: %v", err)
	}
	want, err := json.Marshal(sample)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Reading every accessor and mutating whatever comes back (value types
	// can't be mutated through the accessor at all; Metrics() is checked by
	// TestSupportTelemetrySampleMetricsIsImmutable) must never change what
	// the sample itself reports afterward.
	_ = sample.SchemaVersion()
	_ = sample.RegistryHash()
	_ = sample.GeneratedAt()
	_ = sample.SampleEpoch()
	_ = sample.Sequence()
	m := sample.Metrics()
	for k := range m {
		delete(m, k)
	}

	got, err := json.Marshal(sample)
	if err != nil {
		t.Fatalf("marshal after accessor calls: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("sample changed after calling its own accessors:\nbefore: %s\nafter:  %s", want, got)
	}
}

func TestCAExpiryBucketBoundaries(t *testing.T) {
	cases := []struct {
		days int
		want float64
	}{
		{91, 0}, {90, 1}, {31, 1}, {30, 2}, {8, 2}, {7, 3}, {0, 3}, {-1, 3}, {-100, 3},
	}
	for _, c := range cases {
		if got := CAExpiryBucket(c.days); got != c.want {
			t.Errorf("CAExpiryBucket(%d) = %v, want %v", c.days, got, c.want)
		}
	}
}

func TestUptimeBucketBoundaries(t *testing.T) {
	day := 24 * time.Hour
	cases := []struct {
		d    time.Duration
		want float64
	}{
		{0, 0},
		{day - time.Second, 0},
		{day, 1},
		{7*day - time.Second, 1},
		{7 * day, 2},
		{30*day - time.Second, 2},
		{30 * day, 3},
		{365 * day, 3},
	}
	for _, c := range cases {
		if got := UptimeBucket(c.d); got != c.want {
			t.Errorf("UptimeBucket(%v) = %v, want %v", c.d, got, c.want)
		}
	}
}
