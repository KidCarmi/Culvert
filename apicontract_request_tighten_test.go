package main

// Slice 3.1 — request conformance for tightened write schemas (previously the
// open GenericWriteInput). These now reject unknown fields and wrong types.

import "testing"

func TestConformance_Request_Tightened(t *testing.T) {
	spec := loadContract(t)
	cases := []struct {
		method, path, good, bad string
	}{
		{"POST", "/api/syslog", `{"addr":"10.0.0.1:514","format":"rfc5424"}`, `{"addr":"x","format":"y","extra":1}`},
		{"POST", "/api/otlp", `{"endpoint":"https://c","authHeaderName":"X","authHeaderValue":"v"}`, `{"endpoint":5}`},
		{"POST", "/api/ui-allow-ips", `{"ips":["10.0.0.0/8"]}`, `{"ips":"10.0.0.0/8"}`},
		{"PUT", "/api/settings/default-auth-outcome", `{"defaultAuthOutcome":"Exempt"}`, `{"defaultAuthOutcome":"Maybe"}`},
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
