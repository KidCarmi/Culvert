package main

// alerts_webhook_url_viewer_exposure_test.go — a webhook URL is a credential.
//
// Slack, Teams, Discord and PagerDuty-style receivers authenticate the caller
// by the URL alone (a token in the path or query), so whoever can read the URL
// can post forged alerts into the channel the SOC trusts. Managing webhooks
// needs RoleOperator; these tests pin that a VIEWER cannot read the URL back
// through any of the three viewer-readable surfaces it reaches.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	webhookPathMarker  = "PATHTOKENa1b2c3d4e5"
	webhookQueryMarker = "QUERYTOKENf6g7h8i9"
	webhookUserMarker  = "USERINFOj0k1l2"
	// 127.0.0.1 so the SSRF-guarded dialer refuses the delivery without any
	// DNS or network I/O; the refusal is what lands in the delivery history.
	webhookSecretURL = "http://u:" + webhookUserMarker + "@127.0.0.1:1/services/T000/" +
		webhookPathMarker + "?key=" + webhookQueryMarker
)

func serveAs(role UIRole, h http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h(w, roleRequest(method, path, body, role))
	return w
}

func assertNoWebhookMarker(t *testing.T, surface, body string) {
	t.Helper()
	for _, tok := range []string{webhookPathMarker, webhookQueryMarker, webhookUserMarker} {
		if strings.Contains(body, tok) {
			t.Errorf("%s discloses webhook URL credential %q to a viewer:\n%s", surface, tok, body)
		}
	}
}

func TestAlertWebhookURL_NotReadableBelowOperator(t *testing.T) {
	orig := alertStore()
	t.Cleanup(func() { alertStoreRef.Store(orig) })
	as := &AlertStore{}
	as.Init("")
	alertStoreRef.Store(as)

	create := serveAs(RoleOperator, apiAlertsWebhooks, http.MethodPost, "/api/alerts/webhooks",
		`{"name":"soc","url":"`+webhookSecretURL+`","events":["policy_block"]}`)
	if create.Code != http.StatusOK {
		t.Fatalf("operator create = %d: %s", create.Code, create.Body.String())
	}
	hooks := as.List()
	if len(hooks) != 1 {
		t.Fatalf("want 1 webhook, got %d", len(hooks))
	}
	// A failed test delivery puts the transport error in the delivery history.
	if w := serveAs(RoleOperator, apiAlertsWebhookTest, http.MethodPost,
		"/api/alerts/webhooks/test?id="+hooks[0].ID, ""); w.Code != http.StatusOK {
		t.Fatalf("operator test delivery = %d: %s", w.Code, w.Body.String())
	}

	// Control: the role that manages webhooks still reads the full URL (the
	// edit form prefills from this listing).
	opList := serveAs(RoleOperator, apiAlertsWebhooks, http.MethodGet, "/api/alerts/webhooks", "")
	if !strings.Contains(opList.Body.String(), webhookPathMarker) {
		t.Fatalf("operator listing lost the webhook URL: %s", opList.Body.String())
	}

	list := serveAs(RoleViewer, apiAlertsWebhooks, http.MethodGet, "/api/alerts/webhooks", "")
	if list.Code != http.StatusOK {
		t.Fatalf("viewer list = %d", list.Code)
	}
	assertNoWebhookMarker(t, "GET /api/alerts/webhooks", list.Body.String())
	// The viewer still learns WHERE alerts go, just not the capability.
	if !strings.Contains(list.Body.String(), `"url":"http://127.0.0.1:1"`) {
		t.Errorf("viewer listing should keep scheme and host: %s", list.Body.String())
	}

	hist := serveAs(RoleViewer, apiAlertsDeliveryHist, http.MethodGet, "/api/alerts/webhooks/history", "")
	if !strings.Contains(hist.Body.String(), hooks[0].ID) {
		t.Fatalf("delivery history has no record for the test delivery: %s", hist.Body.String())
	}
	assertNoWebhookMarker(t, "GET /api/alerts/webhooks/history", hist.Body.String())

	audit := serveAs(RoleViewer, apiAudit, http.MethodGet, "/api/audit", "")
	if !strings.Contains(audit.Body.String(), hooks[0].ID) {
		t.Fatalf("audit log has no alert.webhook.create entry for %s", hooks[0].ID)
	}
	assertNoWebhookMarker(t, "GET /api/audit", audit.Body.String())
}
