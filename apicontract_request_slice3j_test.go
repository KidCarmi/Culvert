package main

// Slice 3 tranche 10 — request conformance for category-group/settings/
// session-secret/blocklist-exception writes (DELETEs are query-param, no body).

import "testing"

func TestConformance_Request_Slice3j(t *testing.T) {
	spec := loadContract(t)
	cases := []struct {
		method, path, good, bad string
	}{
		{"POST", "/api/category-groups", `{"name":"social","categories":["fb","tw"]}`, `{"name":"social"}`},
		{"PUT", "/api/category-groups", `{"name":"social","categories":["fb"]}`, `{"categories":["fb"]}`},
		{"POST", "/api/settings", `{"user":"admin","pass":"longpass8"}`, `{"user":"admin"}`},
		{"POST", "/api/settings/network", `{"base_url":"https://x","trust_forwarded_headers":true}`, `{"trust_forwarded_headers":"yes"}`},
		{"POST", "/api/session-secret", `{"secret":"0123456789012345678901234567890123456789012345678901234567890123"}`, `{"secret":"short"}`},
		{"POST", "/api/blocklist/exceptions", `{"host":"a.com"}`, `{"host":123}`},
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
