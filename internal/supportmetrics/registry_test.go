package supportmetrics

import "testing"

// TestSupportTelemetryRegistryDefaultDeny — eligibility defaults false. The
// zero-value Descriptor (a metric someone forgot to classify) must be
// telemetry-INeligible by construction; a developer has to opt in
// explicitly and, per Validate, justify it.
func TestSupportTelemetryRegistryDefaultDeny(t *testing.T) {
	var d Descriptor
	if d.TelemetryEligible {
		t.Fatal("zero-value Descriptor must default to TelemetryEligible=false (default-deny)")
	}

	// A registry containing an unclassified-for-eligibility (but properly
	// typed) metric must validate cleanly (it's simply not eligible) —
	// default-deny never blocks an ineligible entry.
	r := Registry{{ID: "support_health_example", Type: Gauge, PrivacyClass: Aggregate, Read: func() float64 { return 0 }}}
	if err := r.Validate(); err != nil {
		t.Fatalf("a non-eligible descriptor with no justification must validate: %v", err)
	}
	if len(r.Eligible()) != 0 {
		t.Fatal("non-eligible descriptor leaked into Eligible()")
	}
}

// TestSupportTelemetryRegistryHasJustification — every eligible metric has a
// TelemetryReason; marking TelemetryEligible=true without one is rejected.
func TestSupportTelemetryRegistryHasJustification(t *testing.T) {
	r := Registry{{
		ID:                "support_health_example",
		Type:              Gauge,
		PrivacyClass:      Aggregate,
		InSupportBundle:   true,
		TelemetryEligible: true,
		Read:              func() float64 { return 1 },
	}}
	if err := r.Validate(); err == nil {
		t.Fatal("eligible descriptor with empty TelemetryReason must fail validation")
	}

	r[0].TelemetryReason = "   "
	if err := r.Validate(); err == nil {
		t.Fatal("eligible descriptor with whitespace-only TelemetryReason must fail validation")
	}

	r[0].TelemetryReason = "own health; no customer data"
	if err := r.Validate(); err != nil {
		t.Fatalf("eligible descriptor with a real justification must validate: %v", err)
	}
}

// TestSupportTelemetrySubset — telemetry_eligible ⊆ in_bundle: an eligible
// metric not marked InSupportBundle is rejected.
func TestSupportTelemetrySubset(t *testing.T) {
	r := Registry{{
		ID:                "support_health_example",
		Type:              Gauge,
		PrivacyClass:      Aggregate,
		InSupportBundle:   false,
		TelemetryEligible: true,
		TelemetryReason:   "justified",
		Read:              func() float64 { return 1 },
	}}
	if err := r.Validate(); err == nil {
		t.Fatal("telemetry-eligible descriptor not in the support bundle must fail validation")
	}
}

// TestSupportTelemetryLabelFree — no eligible (or any) metric carries a
// label: IDs are constrained to a closed, delimiter-safe scalar vocabulary
// (no braces, commas, or per-entity/label-shaped suffixes), and Read always
// returns a single float64 — the type signature itself rules out a labelled
// vector.
func TestSupportTelemetryLabelFree(t *testing.T) {
	badIDs := []string{
		"", "Support_Health_CA", "support-health-ca", "support_health_ca{host=x}",
		"support_health_ca,other", "support health ca", "1support_health",
	}
	for _, id := range badIDs {
		r := Registry{{ID: id, Type: Gauge, PrivacyClass: Aggregate, Read: func() float64 { return 0 }}}
		if err := r.Validate(); err == nil {
			t.Errorf("label-shaped/invalid id %q must fail validation", id)
		}
	}

	if err := (Registry{{ID: "support_health_ca_ready", Type: Gauge, PrivacyClass: Aggregate, Read: func() float64 { return 0 }}}).Validate(); err != nil {
		t.Fatalf("well-formed scalar id must validate: %v", err)
	}
}

func TestSupportTelemetryRegistryRejectsDuplicateID(t *testing.T) {
	r := Registry{
		{ID: "support_health_ca_ready", Type: Gauge, PrivacyClass: Aggregate, Read: func() float64 { return 1 }},
		{ID: "support_health_ca_ready", Type: Gauge, PrivacyClass: Aggregate, Read: func() float64 { return 0 }},
	}
	if err := r.Validate(); err == nil {
		t.Fatal("duplicate metric id must fail validation")
	}
}

func TestSupportTelemetryRegistryRejectsNilRead(t *testing.T) {
	r := Registry{{ID: "support_health_ca_ready", Type: Gauge, PrivacyClass: Aggregate}}
	if err := r.Validate(); err == nil {
		t.Fatal("descriptor with nil Read must fail validation")
	}
}

// TestSupportTelemetryRegistryRejectsUnclassifiedType — an omitted/unknown
// MetricType fails closed rather than silently behaving like Gauge.
func TestSupportTelemetryRegistryRejectsUnclassifiedType(t *testing.T) {
	r := Registry{{ID: "support_health_ca_ready", PrivacyClass: Aggregate, Read: func() float64 { return 0 }}}
	if err := r.Validate(); err == nil {
		t.Fatal("descriptor with unset (Unknown) MetricType must fail validation")
	}
}

// TestSupportTelemetryRegistryRejectsUnclassifiedPrivacy — an
// omitted/unknown PrivacyClass fails closed rather than silently behaving
// like Public (the most permissive class).
func TestSupportTelemetryRegistryRejectsUnclassifiedPrivacy(t *testing.T) {
	r := Registry{{ID: "support_health_ca_ready", Type: Gauge, Read: func() float64 { return 0 }}}
	if err := r.Validate(); err == nil {
		t.Fatal("descriptor with unset (Unknown) PrivacyClass must fail validation")
	}
}

// TestSupportTelemetryRegistryRejectsOutOfRangeEnums — a MetricType or
// PrivacyClass value outside the declared enum (e.g. from a bad cast or a
// future migration bug) must fail closed rather than fall through to the
// String() method's "unknown" default and validate anyway.
func TestSupportTelemetryRegistryRejectsOutOfRangeEnums(t *testing.T) {
	r := Registry{{ID: "support_health_ca_ready", Type: MetricType(99), PrivacyClass: Aggregate, Read: func() float64 { return 0 }}}
	if err := r.Validate(); err == nil {
		t.Fatal("out-of-range MetricType must fail validation")
	}
	r2 := Registry{{ID: "support_health_ca_ready", Type: Gauge, PrivacyClass: PrivacyClass(99), Read: func() float64 { return 0 }}}
	if err := r2.Validate(); err == nil {
		t.Fatal("out-of-range PrivacyClass must fail validation")
	}
}

// TestSupportTelemetryRegistryRejectsLocalOnlyEligible — PrivacyClass
// LocalOnly is a positive declaration that a value must never leave the
// box; TelemetryEligible on such an entry is a contradiction and must fail
// closed even if it otherwise carries a justification and InSupportBundle.
func TestSupportTelemetryRegistryRejectsLocalOnlyEligible(t *testing.T) {
	r := Registry{{
		ID: "support_health_example", Type: Gauge, PrivacyClass: LocalOnly,
		InSupportBundle: true, TelemetryEligible: true, TelemetryReason: "justified",
		Read: func() float64 { return 0 },
	}}
	if err := r.Validate(); err == nil {
		t.Fatal("telemetry-eligible descriptor classified LocalOnly must fail validation")
	}
}

// TestSupportTelemetryRegistryBundleSnapshot — BundleSnapshot reads exactly
// the InSupportBundle descriptors (a superset can exist that is NOT
// telemetry-eligible: a bundle-only, LocalOnly metric), using their live
// Read closures.
func TestSupportTelemetryRegistryBundleSnapshot(t *testing.T) {
	r := Registry{
		{ID: "support_health_a", Type: Gauge, PrivacyClass: Aggregate, InSupportBundle: true, TelemetryEligible: true, TelemetryReason: "x", Read: func() float64 { return 1 }},
		{ID: "support_health_b", Type: Gauge, PrivacyClass: LocalOnly, InSupportBundle: true, TelemetryEligible: false, Read: func() float64 { return 2 }},
		{ID: "support_health_c", Type: Gauge, PrivacyClass: Aggregate, InSupportBundle: false, TelemetryEligible: false, Read: func() float64 { return 3 }},
	}
	snap, err := r.BundleSnapshot()
	if err != nil {
		t.Fatalf("BundleSnapshot: %v", err)
	}
	if len(snap) != 2 {
		t.Fatalf("snapshot has %d entries, want 2 (in-bundle only): %v", len(snap), snap)
	}
	if snap["support_health_a"] != 1 || snap["support_health_b"] != 2 {
		t.Errorf("unexpected snapshot values: %v", snap)
	}
	if _, ok := snap["support_health_c"]; ok {
		t.Error("BundleSnapshot leaked a non-InSupportBundle metric")
	}
}

func TestSupportTelemetryRegistryBundleSnapshotRejectsInvalidRegistry(t *testing.T) {
	r := Registry{{ID: "support_health_x", TelemetryEligible: true, InSupportBundle: true, Read: func() float64 { return 0 }}}
	if _, err := r.BundleSnapshot(); err == nil {
		t.Fatal("BundleSnapshot must reject an invalid registry")
	}
}

// TestSupportTelemetryRegistryDeprecatedAlias_Validate covers the structural
// invariants of DeprecatedAlias: valid idPattern, not same as canonical ID,
// and no collision with other canonical IDs or aliases.
func TestSupportTelemetryRegistryDeprecatedAlias_Validate(t *testing.T) {
	good := func() Descriptor {
		return Descriptor{
			ID: "support_health_ca_ready", Type: Gauge, PrivacyClass: Aggregate,
			InSupportBundle: true, TelemetryEligible: true, TelemetryReason: "own health",
			Read: func() float64 { return 1 },
		}
	}

	t.Run("valid alias accepted", func(t *testing.T) {
		d := good()
		d.DeprecatedAlias = "support_ca_ready"
		r := Registry{d}
		if err := r.Validate(); err != nil {
			t.Fatalf("valid deprecated_alias must be accepted: %v", err)
		}
	})

	t.Run("alias same as canonical id rejected", func(t *testing.T) {
		d := good()
		d.DeprecatedAlias = d.ID
		r := Registry{d}
		if err := r.Validate(); err == nil {
			t.Fatal("deprecated_alias same as canonical id must fail validation")
		}
	})

	t.Run("alias with invalid pattern rejected", func(t *testing.T) {
		for _, bad := range []string{"UPPER", "has-dash", "has space", "1start"} {
			d := good()
			d.DeprecatedAlias = bad
			r := Registry{d}
			if err := r.Validate(); err == nil {
				t.Errorf("invalid alias %q must fail validation", bad)
			}
		}
	})

	t.Run("alias collides with canonical id of another descriptor", func(t *testing.T) {
		d1 := good()
		d1.DeprecatedAlias = "support_health_clamav_ready"
		d2 := Descriptor{
			ID: "support_health_clamav_ready", Type: Gauge, PrivacyClass: Aggregate,
			Read: func() float64 { return 0 },
		}
		if err := (Registry{d1, d2}).Validate(); err == nil {
			t.Fatal("alias colliding with another canonical id must fail validation")
		}
	})

	t.Run("alias collides with alias of another descriptor", func(t *testing.T) {
		d1 := good()
		d1.DeprecatedAlias = "support_old_name"
		d2 := Descriptor{
			ID: "support_health_clamav_ready", Type: Gauge, PrivacyClass: Aggregate,
			Read:            func() float64 { return 0 },
			DeprecatedAlias: "support_old_name",
		}
		if err := (Registry{d1, d2}).Validate(); err == nil {
			t.Fatal("two descriptors sharing the same deprecated_alias must fail validation")
		}
	})
}

// TestSupportTelemetryRegistryDeprecatedAlias_BundleSnapshot verifies that
// BundleSnapshot emits both the canonical ID and the deprecated alias key with
// the same value, while a descriptor without an alias emits only its canonical
// ID.
func TestSupportTelemetryRegistryDeprecatedAlias_BundleSnapshot(t *testing.T) {
	r := Registry{
		{
			ID: "support_health_a", Type: Gauge, PrivacyClass: Aggregate,
			InSupportBundle: true, TelemetryEligible: true, TelemetryReason: "x",
			Read: func() float64 { return 42 }, DeprecatedAlias: "support_a_old",
		},
		{
			ID: "support_health_b", Type: Gauge, PrivacyClass: Aggregate,
			InSupportBundle: true, TelemetryEligible: false,
			Read: func() float64 { return 7 },
		},
	}
	snap, err := r.BundleSnapshot()
	if err != nil {
		t.Fatalf("BundleSnapshot: %v", err)
	}
	if snap["support_health_a"] != 42 {
		t.Errorf("canonical id value: got %v, want 42", snap["support_health_a"])
	}
	if snap["support_a_old"] != 42 {
		t.Errorf("deprecated alias value: got %v, want 42", snap["support_a_old"])
	}
	if snap["support_health_b"] != 7 {
		t.Errorf("non-aliased id value: got %v, want 7", snap["support_health_b"])
	}
	// 3 keys: canonical A, alias A, canonical B.
	if len(snap) != 3 {
		t.Errorf("snapshot has %d entries, want 3", len(snap))
	}
}

