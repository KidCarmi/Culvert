package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// assertResponseConformsAdmin drives the handler with an admin role (which also
// satisfies viewer-gated routes), for response-shape validation of admin GETs.
func assertResponseConformsAdmin(t *testing.T, method, path string, h http.HandlerFunc) {
	t.Helper()
	spec := loadContract(t)
	rec := httptest.NewRecorder()
	req := withRole(httptest.NewRequestWithContext(context.Background(), method, path, http.NoBody), RoleAdmin)
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %s: status = %d, want 200 (body: %s)", method, path, rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("%s %s: content-type = %q", method, path, ct)
	}
	if err := spec.ValidateJSONResponse(method, path, 200, rec.Body.Bytes()); err != nil {
		t.Fatalf("%s %s response violates contract: %v\nbody: %s", method, path, err, rec.Body.String())
	}
}

func TestConformance_Response_Slice3o(t *testing.T) {
	cases := []struct {
		name, path string
		h          http.HandlerFunc
	}{
		{"syslog", "/api/syslog", apiSyslogConfig},
		{"otlp", "/api/otlp", apiOTLPConfig},
		{"ui-allow-ips", "/api/ui-allow-ips", apiUIAllowIPs},
		{"geoip", "/api/geoip", apiGeoIPConfig},
		{"idp", "/api/idp", apiIdPList},
		{"blocklist", "/api/blocklist", apiBlocklist},
		{"alerts-history", "/api/alerts/webhooks/history", apiAlertsDeliveryHist},
		{"pac-exceptions", "/api/pac/posture/exceptions", apiPACExceptions},
		{"content-scan", "/api/content-scan", apiContentScan},
		{"content-scan-bypass", "/api/content-scan/bypass", apiContentScanBypass},
		{"lockouts", "/api/auth/lockouts", apiAuthLockouts},
		{"blockpage", "/api/blockpage", apiBlockPage},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertResponseConformsAdmin(t, http.MethodGet, c.path, c.h)
		})
	}
}
