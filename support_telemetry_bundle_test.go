package main

import (
	"encoding/json"
	"testing"

	"github.com/KidCarmi/Culvert/internal/redaction"
	"github.com/KidCarmi/Culvert/internal/supportmetrics"
)

// TestSupportMetricsCollector_PresentAndMatchesRegistry is the integration
// test the design review demanded: it builds a REAL support bundle (over
// the actual registered collectors, not a mock) and proves the
// sections/support_metrics.json section contains EXACTLY the registry's
// InSupportBundle entries — the same ids the telemetry preview would show —
// with the same registry_hash. This is what makes §6's "shared source"
// claim provable rather than just a metadata assertion (InSupportBundle
// bool alone does not prove a metric actually reaches the bundle).
func TestSupportMetricsCollector_PresentAndMatchesRegistry(t *testing.T) {
	res := buildRealBundle(t)
	files := extractTarGz(t, res.TarGz)
	raw, ok := files["sections/support_metrics.json"]
	if !ok {
		t.Fatal("bundle missing sections/support_metrics.json")
	}
	var sec supportMetricsSection
	if err := json.Unmarshal(raw, &sec); err != nil {
		t.Fatalf("unmarshal support_metrics section: %v", err)
	}

	if sec.RegistryHash != supportMetricRegistry.Hash() {
		t.Errorf("bundle section registry_hash %q != live registry hash %q", sec.RegistryHash, supportMetricRegistry.Hash())
	}

	inBundle := supportMetricRegistry.InBundle()
	if len(sec.Metrics) != len(inBundle) {
		t.Fatalf("bundle section has %d metrics, want exactly %d InSupportBundle entries: %v", len(sec.Metrics), len(inBundle), sec.Metrics)
	}
	for _, d := range inBundle {
		if _, ok := sec.Metrics[d.ID]; !ok {
			t.Errorf("bundle section missing InSupportBundle metric %q", d.ID)
		}
	}
	for id := range sec.Metrics {
		found := false
		for _, d := range inBundle {
			if d.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("bundle section contains metric %q that is not InSupportBundle", id)
		}
	}

	// Every telemetry-eligible metric is, by the registry's own subset
	// invariant, also InSupportBundle — so it must appear here too.
	for _, d := range supportMetricRegistry.Eligible() {
		if _, ok := sec.Metrics[d.ID]; !ok {
			t.Errorf("telemetry-eligible metric %q does not appear in the support bundle", d.ID)
		}
	}

	// Declared class reflects that these are subsystem posture verdicts
	// (policy/session/CA/config-snapshot health), not unrestricted-public
	// data — INTERNAL, not PUBLIC.
	for _, s := range res.Manifest.Sections {
		if s.ID == "support_metrics" && s.ClassMax != "INTERNAL" {
			t.Errorf("support_metrics class_max=%q, want INTERNAL", s.ClassMax)
		}
	}
}

// minRedactionClassForPrivacyClass is the fail-closed floor a bundle
// collector's declared MaxClass/Sensitivity must never fall below for a
// descriptor of the given supportmetrics.PrivacyClass. It exists ONLY in
// this test so a future descriptor added with PrivacyClass=Aggregate or
// PrivacyClass=LocalOnly cannot be silently exposed at ClassPublic by a
// collector's hardcoded metadata — the two taxonomies (why a value is safe
// to leave the box vs. how sensitive it is to read in a bundle) are
// maintained independently, and this mapping is the wall that keeps them
// from drifting apart.
func minRedactionClassForPrivacyClass(pc supportmetrics.PrivacyClass) redaction.DataClass {
	switch pc {
	case supportmetrics.Public:
		return redaction.ClassPublic
	case supportmetrics.Aggregate:
		return redaction.ClassInternal
	case supportmetrics.LocalOnly:
		// LocalOnly is a positive declaration that a value must never leave
		// the box (supportmetrics.Registry.Validate doc comment) — strictly
		// more restrictive than an Aggregate health verdict, so it floors at
		// SENSITIVE rather than INTERNAL.
		return redaction.ClassSensitive
	default:
		// PrivacyClassUnknown (or any future value this mapping doesn't
		// know about yet) fails closed to the most restrictive class this
		// package defines short of NEVER_EXPORT, rather than defaulting to
		// PUBLIC.
		return redaction.ClassSecret
	}
}

// TestSupportMetricsCollector_PrivacyClassNeverExceedsDeclaredRedactionClass
// is the fail-closed parity wall the review asked for: it walks every
// InSupportBundle descriptor in the LIVE registry and proves the
// support_metrics collector's declared MaxClass and Sensitivity are each at
// least as restrictive as that descriptor's own PrivacyClass demands. A
// future descriptor classified Aggregate or LocalOnly would fail this test
// immediately if the collector metadata in support_telemetry_bundle.go were
// left at (or reverted to) ClassPublic — the bug this whole test file's
// review round exists to catch.
func TestSupportMetricsCollector_PrivacyClassNeverExceedsDeclaredRedactionClass(t *testing.T) {
	if err := supportMetricRegistry.Validate(); err != nil {
		t.Fatalf("registry invalid: %v", err)
	}
	meta := (supportMetricsCollector{}).Meta()
	for _, d := range supportMetricRegistry.InBundle() {
		want := minRedactionClassForPrivacyClass(d.PrivacyClass)
		if meta.MaxClass < want {
			t.Errorf("support_metrics MaxClass=%v is more permissive than descriptor %q's PrivacyClass=%v demands (want >= %v)",
				meta.MaxClass, d.ID, d.PrivacyClass, want)
		}
		if meta.Sensitivity < want {
			t.Errorf("support_metrics Sensitivity=%v is more permissive than descriptor %q's PrivacyClass=%v demands (want >= %v)",
				meta.Sensitivity, d.ID, d.PrivacyClass, want)
		}
	}
}
