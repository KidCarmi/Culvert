package main

import (
	"encoding/json"
	"testing"
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

	// Declared class stays within the shareable PUBLIC ceiling.
	for _, s := range res.Manifest.Sections {
		if s.ID == "support_metrics" && s.ClassMax != "PUBLIC" {
			t.Errorf("support_metrics class_max=%q, want PUBLIC", s.ClassMax)
		}
	}
}
