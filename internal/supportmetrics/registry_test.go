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

	// A registry containing an unclassified metric with no eligibility set
	// must validate cleanly (it's simply not eligible) — default-deny never
	// blocks an ineligible entry.
	r := Registry{{ID: "support_health_example", Read: func() float64 { return 0 }}}
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
		r := Registry{{ID: id, Read: func() float64 { return 0 }}}
		if err := r.Validate(); err == nil {
			t.Errorf("label-shaped/invalid id %q must fail validation", id)
		}
	}

	if err := (Registry{{ID: "support_health_ca_ready", Read: func() float64 { return 0 }}}).Validate(); err != nil {
		t.Fatalf("well-formed scalar id must validate: %v", err)
	}
}

func TestSupportTelemetryRegistryRejectsDuplicateID(t *testing.T) {
	r := Registry{
		{ID: "support_health_ca_ready", Read: func() float64 { return 1 }},
		{ID: "support_health_ca_ready", Read: func() float64 { return 0 }},
	}
	if err := r.Validate(); err == nil {
		t.Fatal("duplicate metric id must fail validation")
	}
}

func TestSupportTelemetryRegistryRejectsNilRead(t *testing.T) {
	r := Registry{{ID: "support_health_ca_ready"}}
	if err := r.Validate(); err == nil {
		t.Fatal("descriptor with nil Read must fail validation")
	}
}
