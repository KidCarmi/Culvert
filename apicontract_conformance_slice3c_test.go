package main

// Slice 3 tranche 3 — response conformance for blocklist/urlcat/fileblock/DPI/
// scan read endpoints, through the real handlers.

import (
	"net/http"
	"testing"
)

func TestConformance_Response_Slice3c(t *testing.T) {
	cases := []struct {
		name, path string
		h          http.HandlerFunc
	}{
		{"blocklist-exceptions", "/api/blocklist/exceptions", apiBlocklistExceptions},
		{"blocklist-feed", "/api/blocklist/feed", apiBlocklistFeed},
		{"urlcat", "/api/urlcat", apiURLCat},
		{"fileblock", "/api/fileblock", apiFileblock},
		{"fileblock-profiles", "/api/fileblock/profiles", apiFileblockProfiles},
		{"config-versions", "/api/config/versions", apiConfigVersions},
		{"decryption-profiles", "/api/decryption-profiles", apiDecryptionProfiles},
		{"dpi", "/api/dpi", apiContentScan},
		{"dpi-bypass", "/api/dpi/bypass", apiContentScanBypass},
		{"security-scan-status", "/api/security-scan/status", apiSecScanStatus},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertResponseConforms(t, http.MethodGet, c.path, c.h)
		})
	}
}
