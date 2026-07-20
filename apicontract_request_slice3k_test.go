package main

// Slice 3 tranche 11 — request conformance for the precisely-schema'd writes
// (the rich-struct bodies — decryption profiles, rewrite rules, support
// retention — are documented with open schemas and not asserted here).

import "testing"

func TestConformance_Request_Slice3k(t *testing.T) {
	spec := loadContract(t)
	cases := []struct {
		method, path, good, bad string
	}{
		{"POST", "/api/blocklist/feed", `{"url":"https://f.com/list","interval":"24h"}`, `{"url":"https://f.com/list"}`},
		{"POST", "/api/pac-config", `{"proxyHost":"proxy","proxyPort":8080}`, `{"proxyPort":"8080"}`},
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
