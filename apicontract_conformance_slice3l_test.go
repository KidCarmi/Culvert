package main

// Slice 3 tranche 12 — response conformance for the alerts/webhooks GET added
// alongside its CRUD operations.

import (
	"net/http"
	"testing"
)

func TestConformance_Response_Slice3l(t *testing.T) {
	spec := loadContract(t)
	assertResponseConforms(t, spec, http.MethodGet, "/api/alerts/webhooks", apiAlertsWebhooks)
}
