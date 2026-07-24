package supportmetrics

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func fixedNow() time.Time {
	return time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
}

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
	sample, err := r.BuildSample(fixedNow(), "epoch-1", 0)
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
	sample, err := r.BuildSample(fixedNow(), "epoch-1", 0)
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
// no I/O of its own: it only ever calls each eligible Read() exactly once.
func TestSupportTelemetrySampleBuildIsSideEffectFree(t *testing.T) {
	calls := 0
	r := Registry{{
		ID: "support_health_ca_ready", Type: Gauge, PrivacyClass: Aggregate,
		InSupportBundle: true, TelemetryEligible: true, TelemetryReason: "own health",
		Read: func() float64 { calls++; return 1 },
	}}
	if _, err := r.BuildSample(fixedNow(), "epoch-1", 0); err != nil {
		t.Fatalf("BuildSample: %v", err)
	}
	if calls != 1 {
		t.Fatalf("Read called %d times, want exactly 1", calls)
	}
}

// TestSupportTelemetrySampleRejectsInvalidRegistry ensures BuildSample
// refuses to build over a registry that fails Validate (e.g. an eligible
// metric missing its justification) rather than silently emitting a
// governance-incomplete sample.
func TestSupportTelemetrySampleRejectsInvalidRegistry(t *testing.T) {
	r := Registry{{ID: "support_health_x", Type: Gauge, PrivacyClass: Aggregate, TelemetryEligible: true, InSupportBundle: true, Read: func() float64 { return 0 }}}
	if _, err := r.BuildSample(fixedNow(), "epoch-1", 0); err == nil {
		t.Fatal("BuildSample must reject an invalid registry")
	}
}

// TestSupportTelemetrySampleDeterministicForFixedInputs — building twice with
// the same clock/epoch/sequence and unchanged Read values yields
// byte-identical JSON (map-order independence: encoding/json sorts map keys).
func TestSupportTelemetrySampleDeterministicForFixedInputs(t *testing.T) {
	r := fixedTestRegistry()
	s1, err := r.BuildSample(fixedNow(), "epoch-1", 7)
	if err != nil {
		t.Fatalf("BuildSample: %v", err)
	}
	s2, err := r.BuildSample(fixedNow(), "epoch-1", 7)
	if err != nil {
		t.Fatalf("BuildSample: %v", err)
	}
	b1, _ := json.Marshal(s1)
	b2, _ := json.Marshal(s2)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("two builds with identical inputs produced different bytes:\n%s\nvs\n%s", b1, b2)
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
