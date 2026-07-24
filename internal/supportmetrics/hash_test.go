package supportmetrics

import "testing"

var testCAExpiryLadder = &BucketLadder{
	Labels:     []string{"gt90d", "le90d", "le30d", "le7d"},
	Thresholds: []float64{7, 30, 90},
	Descending: true,
}

func fixedTestRegistry() Registry {
	return Registry{
		{ID: "support_health_ca_ready", Type: Gauge, PrivacyClass: Aggregate, InSupportBundle: true, TelemetryEligible: true, TelemetryReason: "own health", Read: func() float64 { return 1 }},
		{ID: "support_health_clamav_ready", Type: Gauge, PrivacyClass: Aggregate, InSupportBundle: true, TelemetryEligible: true, TelemetryReason: "own health", Read: func() float64 { return 0 }},
		{ID: "support_health_ca_expiry_bucket", Type: Gauge, PrivacyClass: Aggregate, InSupportBundle: true, TelemetryEligible: true, TelemetryReason: "renewal signal", Buckets: testCAExpiryLadder, Read: func() float64 { return 0 }},
	}
}

// TestSupportTelemetryRegistryHashStable — deterministic across repeated
// calls/process "restarts" (no hidden mutable state), and independent of
// registry construction/iteration order (map-order independence stand-in:
// here, slice order).
func TestSupportTelemetryRegistryHashStable(t *testing.T) {
	r1 := fixedTestRegistry()
	r2 := fixedTestRegistry()

	h1a := r1.Hash()
	h1b := r1.Hash()
	if h1a != h1b {
		t.Fatalf("hash not stable across repeated calls: %s vs %s", h1a, h1b)
	}
	if h1a != r2.Hash() {
		t.Fatalf("hash not stable across independently-constructed identical registries: %s vs %s", h1a, r2.Hash())
	}

	// Reordered (simulates a different construction/iteration order).
	reordered := Registry{r1[2], r1[0], r1[1]}
	if got := reordered.Hash(); got != h1a {
		t.Fatalf("hash depends on registry order: %s vs %s", got, h1a)
	}

	if len(h1a) != 64 {
		t.Fatalf("expected 64 lowercase-hex chars (sha256), got %d: %q", len(h1a), h1a)
	}
	for _, c := range h1a {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("hash is not lowercase hex: %q", h1a)
		}
	}
}

// TestSupportTelemetryRegistryHashIndependentOfValues — Hash() never calls
// Read(), so it cannot depend on runtime metric values.
func TestSupportTelemetryRegistryHashIndependentOfValues(t *testing.T) {
	calls := 0
	r := Registry{{
		ID: "support_health_ca_ready", Type: Gauge, PrivacyClass: Aggregate,
		InSupportBundle: true, TelemetryEligible: true, TelemetryReason: "own health",
		Read: func() float64 { calls++; return 1 },
	}}
	_ = r.Hash()
	_ = r.Hash()
	if calls != 0 {
		t.Fatalf("Hash() invoked Read() %d time(s); it must be pure over schema facts only", calls)
	}

	same := fixedTestRegistry()
	same[0].Read = func() float64 { return 999 } // different runtime value
	if same.Hash() != fixedTestRegistry().Hash() {
		t.Fatal("hash changed when only a Read closure's return value changed")
	}
}

// TestSupportTelemetryRegistryHashChangesOnSchemaChange — the hash changes
// when the eligible schema or a governed bucket definition changes, and only
// then.
func TestSupportTelemetryRegistryHashChangesOnSchemaChange(t *testing.T) {
	base := fixedTestRegistry()
	baseHash := base.Hash()

	t.Run("toggle eligibility", func(t *testing.T) {
		r := fixedTestRegistry()
		r[1].TelemetryEligible = false
		r[1].TelemetryReason = ""
		if r.Hash() == baseHash {
			t.Fatal("hash unchanged after flipping TelemetryEligible")
		}
	})

	t.Run("change privacy class", func(t *testing.T) {
		r := fixedTestRegistry()
		r[0].PrivacyClass = Public
		if r.Hash() == baseHash {
			t.Fatal("hash unchanged after changing PrivacyClass")
		}
	})

	t.Run("change metric type", func(t *testing.T) {
		r := fixedTestRegistry()
		r[0].Type = Counter
		if r.Hash() == baseHash {
			t.Fatal("hash unchanged after changing Type")
		}
	})

	t.Run("change bucket label", func(t *testing.T) {
		r := fixedTestRegistry()
		r[2].Buckets = &BucketLadder{
			Labels:     []string{"gt90d", "le90d", "le45d", "le7d"},
			Thresholds: []float64{7, 30, 90},
			Descending: true,
		}
		if r.Hash() == baseHash {
			t.Fatal("hash unchanged after changing a governed bucket boundary label")
		}
	})

	// The review-mandated test: changing an EXECUTABLE threshold (not just a
	// label string) must change the hash, since Buckets is the same
	// BucketLadder value Read evaluates against.
	t.Run("change bucket threshold (90 -> 120)", func(t *testing.T) {
		r := fixedTestRegistry()
		r[2].Buckets = &BucketLadder{
			Labels:     []string{"gt90d", "le90d", "le30d", "le7d"},
			Thresholds: []float64{7, 30, 120},
			Descending: true,
		}
		if r.Hash() == baseHash {
			t.Fatal("hash unchanged after changing a governed bucket threshold")
		}
		// And the new threshold is genuinely live: a value between the old
		// and new boundary now evaluates differently.
		if got := r[2].Buckets.Index(100); got != 1 {
			t.Fatalf("Index(100) with threshold 120 = %v, want 1 (le90d)", got)
		}
		if got := testCAExpiryLadder.Index(100); got != 0 {
			t.Fatalf("Index(100) with threshold 90 = %v, want 0 (gt90d)", got)
		}
	})

	t.Run("bucket label vs comma collision is not ambiguous", func(t *testing.T) {
		a := fixedTestRegistry()
		a[2].Buckets = &BucketLadder{Labels: []string{"a,b"}, Descending: true}
		b := fixedTestRegistry()
		b[2].Buckets = &BucketLadder{Labels: []string{"a", "b"}, Descending: true}
		if a.Hash() == b.Hash() {
			t.Fatal("[\"a,b\"] and [\"a\",\"b\"] must not hash identically")
		}
	})

	t.Run("add a new descriptor", func(t *testing.T) {
		r := append(fixedTestRegistry(), Descriptor{
			ID: "support_health_yara_ready", Type: Gauge, PrivacyClass: Aggregate,
			InSupportBundle: true, TelemetryEligible: true, TelemetryReason: "own health",
			Read: func() float64 { return 1 },
		})
		if r.Hash() == baseHash {
			t.Fatal("hash unchanged after adding a new eligible descriptor")
		}
	})

	t.Run("rename a metric id", func(t *testing.T) {
		r := fixedTestRegistry()
		r[0].ID = "support_health_ca_usable"
		if r.Hash() == baseHash {
			t.Fatal("hash unchanged after renaming a metric id")
		}
	})
}

// TestSupportTelemetryPayloadNoDrift — the eligible set the hash covers is
// exactly the same set BuildSample emits (both are derived from
// Registry.Eligible()), so there is exactly one source of truth for "what is
// eligible."
func TestSupportTelemetryPayloadNoDrift(t *testing.T) {
	r := fixedTestRegistry()
	eligible := r.Eligible()
	if len(eligible) != len(r) {
		t.Fatalf("fixture expected all-eligible; got %d/%d", len(eligible), len(r))
	}

	sample, err := r.BuildSample(fixedNow(), fixedTestEpoch(), 0)
	if err != nil {
		t.Fatalf("BuildSample: %v", err)
	}
	metrics := sample.Metrics()
	if len(metrics) != len(eligible) {
		t.Fatalf("sample has %d metrics, want exactly %d eligible", len(metrics), len(eligible))
	}
	for _, d := range eligible {
		if _, ok := metrics[d.ID]; !ok {
			t.Errorf("sample missing eligible metric %q", d.ID)
		}
	}
	for id := range metrics {
		found := false
		for _, d := range eligible {
			if d.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("sample contains metric %q that is not in the eligible set", id)
		}
	}
}
