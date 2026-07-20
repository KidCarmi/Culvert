package main

// Slice 3 tranche 9 — request conformance for more write endpoints.

import "testing"

func TestConformance_Request_Slice3i(t *testing.T) {
	spec := loadContract(t)
	cases := []struct {
		method, path, good, bad string
	}{
		{"POST", "/api/security", `{"ipFilterMode":"block","rateLimitRPM":100}`, `{"rateLimitRPM":"lots"}`},
		{"POST", "/api/upstream", `{"proxies":[{"url":"http://p:8080"}]}`, `{"proxies":"none"}`},
		{"POST", "/api/fileblock", `{"extensions":["exe","dll"]}`, `{"extension":42}`},
		{"PUT", "/api/security-scan/exclusions", `{"hashes":["abc"],"hosts":["h.com"]}`, `{"hashes":"abc"}`},
		{"PUT", "/api/security-scan/feeds/domain-allowlist", `{"domains":["a.com"]}`, `{"domains":1}`},
		{"PUT", "/api/security-scan/yara/settings", `{"enabled":true,"timeout_secs":5}`, `{"enabled":"yes"}`},
		{"PUT", "/api/logs/retention", `{"enabled":true,"retentionDays":30}`, `{"retentionDays":"lots"}`},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			if err := spec.ValidateJSONRequest(c.method, c.path, []byte(c.good)); err != nil {
				t.Fatalf("valid body rejected: %v", err)
			}
			if err := spec.ValidateJSONRequest(c.method, c.path, []byte(c.bad)); err == nil {
				t.Fatalf("contract accepted invalid body %s", c.bad)
			}
		})
	}
}
