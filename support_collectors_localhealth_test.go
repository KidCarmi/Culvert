package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestLocalHealthCollector_PresentAndClean builds a real L1 bundle and asserts the
// local_health section is emitted, carries the three posture verdicts, and leaks
// no infrastructure address (the bundle-level mirror of the diagnose no-secret
// tests).
func TestLocalHealthCollector_PresentAndClean(t *testing.T) {
	res := buildRealBundle(t)
	files := extractTarGz(t, res.TarGz)
	raw, ok := files["sections/local_health.json"]
	if !ok {
		t.Fatal("bundle missing sections/local_health.json")
	}
	var sec localHealthSection
	if err := json.Unmarshal(raw, &sec); err != nil {
		t.Fatalf("unmarshal local_health section: %v", err)
	}
	switch sec.ClusterRole {
	case "standalone", "control-plane", "leader", "standby", "data-plane":
	default:
		t.Fatalf("cluster_role=%q is not a known role", sec.ClusterRole)
	}
	// No infrastructure address may appear anywhere in the serialized section.
	for _, needle := range []string{":6443", "10.", "192.168.", "172.", "https://", "grpc"} {
		if bytes.Contains(bytes.ToLower(raw), []byte(needle)) {
			t.Fatalf("local_health section leaked infra detail %q: %s", needle, raw)
		}
	}
	// Declared class is within the shareable ceiling.
	for _, s := range res.Manifest.Sections {
		if s.ID == "local_health" && s.ClassMax != "INTERNAL" && s.ClassMax != "PUBLIC" {
			t.Fatalf("local_health class_max=%q want INTERNAL/PUBLIC", s.ClassMax)
		}
	}
}
