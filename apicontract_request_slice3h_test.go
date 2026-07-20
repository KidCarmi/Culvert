package main

// Slice 3 tranche 8 — request conformance for write endpoints. Validates that a
// well-formed request body satisfies the documented schema and that a malformed
// one is rejected — WITHOUT executing the (state-mutating) handlers.

import "testing"

func TestConformance_Request_Slice3h(t *testing.T) {
	spec := loadContract(t)
	cases := []struct {
		method, path, good, bad string
	}{
		{"POST", "/api/blocklist/mode", `{"mode":"block"}`, `{"mode":123}`},
		{"POST", "/api/default-action", `{"action":"deny"}`, `{"action":true}`},
		{"PUT", "/api/settings/log-level", `{"level":"info"}`, `{"nope":"x"}`},
		{"POST", "/api/ssl-bypass", `{"pattern":"*.example.com"}`, `{"pattern":5}`},
		{"POST", "/api/session-timeout", `{"hours":8}`, `{"hours":"eight"}`},
		{"PUT", "/api/decryption/redaction", `{"redact_hosts":true}`, `{"redact_hosts":"yes"}`},
		{"POST", "/api/ocsp", `{"enabled":true}`, `{"enabled":"true"}`},
		{"POST", "/api/connlimit", `{"enabled":true,"maxPerIP":10}`, `{"maxPerIP":"ten"}`},
		{"PUT", "/api/dpi/bypass", `{"hosts":["a.com","b.com"]}`, `{"hosts":"a.com"}`},
		{"POST", "/api/metrics-config", `{"token":"secret"}`, `{"token":123}`},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			if err := spec.ValidateJSONRequest(c.method, c.path, []byte(c.good)); err != nil {
				t.Fatalf("valid body rejected by contract: %v", err)
			}
			if err := spec.ValidateJSONRequest(c.method, c.path, []byte(c.bad)); err == nil {
				t.Fatalf("contract accepted an invalid body %s", c.bad)
			}
		})
	}
}
