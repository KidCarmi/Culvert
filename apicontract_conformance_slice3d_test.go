package main

// Slice 3 tranche 4 — response conformance for scan/pac/decryption/release reads.

import (
	"net/http"
	"testing"
)

func TestConformance_Response_Slice3d(t *testing.T) {
	cases := []struct {
		name, path string
		h          http.HandlerFunc
	}{
		{"scan-svc", "/api/security-scan/svc", apiScanSvcConfig},
		{"scan-cache", "/api/security-scan/cache", apiScanCache},
		{"domain-allowlist", "/api/security-scan/feeds/domain-allowlist", apiDomainAllowlist},
		{"yara-settings", "/api/security-scan/yara/settings", apiSecYARASettings},
		{"decryption-redaction", "/api/decryption/redaction", apiDecryptionRedaction},
		{"pac-pools", "/api/pac/pools", apiPACPools},
		{"pac-profiles", "/api/pac/profiles", apiPACProfiles},
		{"pac-posture-inventory", "/api/pac/posture/inventory", apiPACPostureInventory},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertResponseConforms(t, http.MethodGet, c.path, c.h)
		})
	}
}
