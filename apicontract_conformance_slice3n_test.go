package main

// Slice 3 tranche 15 — response conformance for cdr reads (release reads return
// 503 when unconfigured; actions are not live-executed).

import (
	"net/http"
	"testing"
)

func TestConformance_Response_Slice3n(t *testing.T) {
	cases := []struct {
		name, path string
		h          http.HandlerFunc
	}{
		{"cdr-config", "/api/cdr/config", apiCDRConfig},
		{"cdr-instances", "/api/cdr/instances", apiCDRInstances},
		{"cdr-policies", "/api/cdr/policies", apiCDRPolicies},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertResponseConforms(t, http.MethodGet, c.path, c.h)
		})
	}
}
