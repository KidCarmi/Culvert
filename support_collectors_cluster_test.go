package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestClusterCollector_SectionPresentAndClean builds a real L1 bundle and asserts
// the cluster section is emitted, carries a valid role, and never leaks a CP
// peer/standby address — the bundle-level mirror of TestDiagnoseCluster_NoSecrets.
func TestClusterCollector_SectionPresentAndClean(t *testing.T) {
	res := buildRealBundle(t)
	files := extractTarGz(t, res.TarGz)
	raw, ok := files["sections/cluster.json"]
	if !ok {
		t.Fatal("bundle missing sections/cluster.json")
	}
	var sec clusterSection
	if err := json.Unmarshal(raw, &sec); err != nil {
		t.Fatalf("unmarshal cluster section: %v", err)
	}
	// A standalone test node must report a known role, never an empty/unknown one.
	switch sec.Role {
	case "standalone", "control-plane", "leader", "standby", "data-plane":
	default:
		t.Fatalf("cluster section role=%q is not a known role", sec.Role)
	}
	// No infrastructure address may appear anywhere in the serialized section.
	for _, needle := range []string{":6443", "10.", "192.168.", "172.", "https://", "grpc"} {
		if bytes.Contains(bytes.ToLower(raw), []byte(needle)) {
			t.Fatalf("cluster section leaked infra detail %q: %s", needle, raw)
		}
	}
	// The section's declared class is INTERNAL at most.
	for _, s := range res.Manifest.Sections {
		if s.ID == "cluster" && s.ClassMax != "INTERNAL" && s.ClassMax != "PUBLIC" {
			t.Fatalf("cluster class_max=%q want INTERNAL/PUBLIC", s.ClassMax)
		}
	}
}
