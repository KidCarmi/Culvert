package main

// Slice 3.1 (batch 2) — response/request conformance for newly-tightened schemas.

import (
	"net/http"
	"testing"
)

func TestConformance_Tighten2_Response(t *testing.T) {
	cases := []struct {
		name, path string
		h          http.HandlerFunc
	}{
		{"idp", "/api/idp", apiIdPList},
		{"alerts-history", "/api/alerts/webhooks/history", apiAlertsDeliveryHist},
		{"pac-exceptions", "/api/pac/posture/exceptions", apiPACExceptions},
		{"content-scan", "/api/content-scan", apiContentScan},
		{"content-scan-bypass", "/api/content-scan/bypass", apiContentScanBypass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertResponseConformsAdmin(t, http.MethodGet, c.path, c.h)
		})
	}
}

func TestConformance_Tighten2_Request(t *testing.T) {
	spec := loadContract(t)
	good := `{"category":"social","host":"x.com"}`
	bad := `{"category":"social"}`
	if err := spec.ValidateJSONRequest("POST", "/api/urlcat/host", []byte(good)); err != nil {
		t.Fatalf("valid body rejected: %v", err)
	}
	if err := spec.ValidateJSONRequest("POST", "/api/urlcat/host", []byte(bad)); err == nil {
		t.Fatal("contract accepted a body missing required host")
	}
}
