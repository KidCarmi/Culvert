package main

// Slice 3 tranche 5 — response conformance for dashboard/cluster/support reads.

import (
	"net/http"
	"testing"
)

func TestConformance_Response_Slice3e(t *testing.T) {
	cases := []struct {
		name, path string
		h          http.HandlerFunc
	}{
		{"audit", "/api/audit", apiAudit},
		{"country-traffic", "/api/country-traffic", apiCountryTraffic},
		{"dashboard-health", "/api/dashboard/health", apiDashboardHealth},
		{"dashboard-threats", "/api/dashboard/threats", apiDashboardThreats},
		{"dashboard-top-rules", "/api/dashboard/top-rules", apiDashboardTopRules},
		{"timeseries", "/api/timeseries", apiTimeseries},
		{"cluster-status", "/api/cluster/status", apiClusterStatus},
		{"cluster-nodes", "/api/cluster/nodes", apiClusterNodes},
		{"cluster-metrics", "/api/cluster/metrics", apiClusterMetrics},
		{"cluster-ha", "/api/cluster/ha", apiClusterHA},
		{"support-status", "/api/support/status", apiSupportStatus},
		{"upstream", "/api/upstream", apiUpstream},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertResponseConforms(t, http.MethodGet, c.path, c.h)
		})
	}
}
