package main

import (
	"net/http"
	"testing"

	"github.com/KidCarmi/Culvert/internal/apicontract"
)

// assertResponseConformsAdmin drives the handler with an admin role (which also
// satisfies viewer-gated routes), for response-shape validation of admin GETs.
// The spec is the caller's per-invocation fixture, as for assertResponseConforms.
func assertResponseConformsAdmin(t *testing.T, spec *apicontract.Spec, method, path string, h http.HandlerFunc) {
	t.Helper()
	if err := checkResponseConforms(spec, method, path, RoleAdmin, h); err != nil {
		t.Fatal(err)
	}
}

func TestConformance_Response_Slice3o(t *testing.T) {
	spec := loadContract(t)
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
			assertResponseConformsAdmin(t, spec, http.MethodGet, c.path, c.h)
		})
	}
}
