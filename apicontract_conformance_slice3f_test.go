package main

// Slice 3 tranche 6 — response conformance for cluster/support/diagnostics reads.

import (
	"net/http"
	"testing"
)

func TestConformance_Response_Slice3f(t *testing.T) {
	cases := []struct {
		name, path string
		h          http.HandlerFunc
	}{
		{"cluster-ca", "/api/cluster/ca", apiClusterCA},
		{"cluster-tokens", "/api/cluster/tokens", apiClusterTokens},
		{"cluster-audit", "/api/cluster/audit", apiClusterAudit},
		{"cluster-rate-limits", "/api/cluster/rate-limits", apiClusterRateLimits},
		{"cluster-revocations", "/api/cluster/revocations", apiClusterRevocations},
		{"cluster-rotation", "/api/cluster/rotation", apiClusterRotation},
		{"support-retention", "/api/support/retention", apiSupportRetention},
		{"diagnostics", "/api/diagnostics", apiDiagnostics},
		{"health-explain", "/api/health/explain", apiHealthExplain},
		{"upstream-settings", "/api/upstream/settings", apiUpstreamSettings},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertResponseConforms(t, http.MethodGet, c.path, c.h)
		})
	}
}
