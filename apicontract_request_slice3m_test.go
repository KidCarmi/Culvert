package main

// Slice 3 tranche 13 — request conformance for the yara/validate write (PEM GETs
// are non-JSON; node-group/recipient bodies are rich/open and not asserted).

import "testing"

func TestConformance_Request_Slice3m(t *testing.T) {
	spec := loadContract(t)
	good := `{"source":"rule x { condition: true }"}`
	bad := `{"source":5}`
	if err := spec.ValidateJSONRequest("POST", "/api/security-scan/yara/validate", []byte(good)); err != nil {
		t.Fatalf("valid body rejected: %v", err)
	}
	if err := spec.ValidateJSONRequest("POST", "/api/security-scan/yara/validate", []byte(bad)); err == nil {
		t.Fatal("contract accepted invalid body")
	}
}
