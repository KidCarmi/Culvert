package main

// Slice 3.1 (batch 3) — response/request conformance for tightened schemas.

import (
	"net/http"
	"testing"
)

func TestConformance_Tighten3_Response(t *testing.T) {
	assertResponseConformsAdmin(t, http.MethodGet, "/api/blockpage", apiBlockPage)
	assertResponseConformsAdmin(t, http.MethodGet, "/api/auth/lockouts", apiAuthLockouts)
}

func TestConformance_Tighten3_Request(t *testing.T) {
	spec := loadContract(t)
	cases := []struct {
		method, path, good, bad string
	}{
		{"PUT", "/api/blockpage", `{"html":"<h1>blocked</h1>"}`, `{"html":5}`},
		{"POST", "/api/auth/lockouts", `{"username":"alice"}`, `{"user":"alice"}`},
		{"POST", "/api/cluster/labels", `{"node_id":"n1","labels":{"geo":"us"}}`, `{"node_id":5}`},
		{"POST", "/api/cluster/mode", `{"grpc_addr":":9443"}`, `{"grpc_addr":true}`},
		{"POST", "/api/policy/move", `{"priority":10,"position":"before","targetName":"r2"}`, `{"priority":"ten"}`},
		{"POST", "/api/policy/reorder", `{"priorities":[3,1,2]}`, `{"priorities":"3,1,2"}`},
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
