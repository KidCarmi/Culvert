package main

// Slice 3 tranche 7 — response conformance for the remaining node-group/support/
// scan read endpoints (the param-required config/diff and membership are
// documented but not live-200-tested since they require query params).

import (
	"net/http"
	"testing"
)

func TestConformance_Response_Slice3g(t *testing.T) {
	cases := []struct {
		name, path string
		h          http.HandlerFunc
	}{
		{"support-bundles", "/api/support/bundles", apiSupportBundles},
		{"support-debug-level", "/api/support/debug-level", apiSupportDebugLevel},
		{"support-recipients", "/api/support/recipients", apiSupportRecipients},
		{"scan-exclusions", "/api/security-scan/exclusions", apiSecScanExclusions},
		{"yara-rules", "/api/security-scan/yara/rules", apiSecYARARules},
		{"autoexclude-tunables", "/api/decryption-exclusions/tunables", apiDecryptionExclusionTunables},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertResponseConforms(t, http.MethodGet, c.path, c.h)
		})
	}
}
