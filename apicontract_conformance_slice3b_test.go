package main

// Slice 3 tranche 2 — response conformance for settings/policy read endpoints.
// Same pattern as slice3: real handler via httptest, viewer role injected,
// body validated against the documented schema.

import (
	"net/http"
	"testing"
)

func TestConformance_Response_Slice3b(t *testing.T) {
	cases := []struct {
		name, path string
		h          http.HandlerFunc
	}{
		{"settings", "/api/settings", apiSettings},
		{"log-level", "/api/settings/log-level", apiLogLevel},
		{"network", "/api/settings/network", apiNetworkSettings},
		{"rewrite", "/api/rewrite", apiRewrite},
		{"category-groups", "/api/category-groups", apiCategoryGroups},
		{"metrics-config", "/api/metrics-config", apiMetricsConfig},
		{"logs-retention", "/api/logs/retention", apiLogsRetention},
		{"ca-key-provider", "/api/ca/key-provider", apiCAKeyProvider},
		{"policy-draft", "/api/policy/draft", apiPolicyDraft},
		{"session-secret", "/api/session-secret", apiSessionSecret},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertResponseConforms(t, http.MethodGet, c.path, c.h)
		})
	}
}
