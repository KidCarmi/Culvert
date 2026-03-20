package main

// ui_alerts_unauth_test.go — HTTP handler tests for apiAlertsWebhooks
// and apiUnauthMode, which were previously at 0% coverage.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// adminRequest creates a test request with the admin role injected into context.
func adminRequest(method, path, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r, _ = http.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r, _ = http.NewRequest(method, path, nil)
	}
	ctx := context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin)
	return r.WithContext(ctx)
}

// ── apiAlertsWebhooks ─────────────────────────────────────────────────────────

func TestAPIAlertsWebhooks_GET(t *testing.T) {
	orig := globalAlertStore
	defer func() { globalAlertStore = orig }()
	as := &AlertStore{}
	as.Init("")
	globalAlertStore = as

	req := adminRequest(http.MethodGet, "/api/alerts/webhooks", "")
	w := httptest.NewRecorder()
	apiAlertsWebhooks(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := resp["webhooks"]; !ok {
		t.Error("response should have 'webhooks' key")
	}
}

func TestAPIAlertsWebhooks_POST(t *testing.T) {
	orig := globalAlertStore
	defer func() { globalAlertStore = orig }()
	as := &AlertStore{}
	as.Init("")
	globalAlertStore = as

	body := `{"name":"test","url":"http://example.com/hook","events":["threat_detected"]}`
	req := adminRequest(http.MethodPost, "/api/alerts/webhooks", body)
	w := httptest.NewRecorder()
	apiAlertsWebhooks(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(as.hooks) != 1 {
		t.Errorf("expected 1 webhook stored, got %d", len(as.hooks))
	}
}

func TestAPIAlertsWebhooks_POST_MissingURL(t *testing.T) {
	orig := globalAlertStore
	defer func() { globalAlertStore = orig }()
	as := &AlertStore{}
	as.Init("")
	globalAlertStore = as

	req := adminRequest(http.MethodPost, "/api/alerts/webhooks", `{"name":"no-url"}`)
	w := httptest.NewRecorder()
	apiAlertsWebhooks(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing URL, got %d", w.Code)
	}
}

func TestAPIAlertsWebhooks_PUT(t *testing.T) {
	orig := globalAlertStore
	defer func() { globalAlertStore = orig }()
	as := &AlertStore{}
	as.Init("")
	globalAlertStore = as

	// Create a webhook first.
	created := as.Add(AlertWebhook{Name: "orig", URL: "http://a.com", Events: []string{"*"}, Enabled: true})

	body := `{"name":"updated","url":"http://b.com","events":["policy_block"]}`
	req := adminRequest(http.MethodPut, "/api/alerts/webhooks?id="+created.ID, body)
	w := httptest.NewRecorder()
	apiAlertsWebhooks(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIAlertsWebhooks_PUT_MissingID(t *testing.T) {
	orig := globalAlertStore
	defer func() { globalAlertStore = orig }()
	globalAlertStore = &AlertStore{}
	globalAlertStore.Init("")

	req := adminRequest(http.MethodPut, "/api/alerts/webhooks", `{"name":"x","url":"http://x.com"}`)
	w := httptest.NewRecorder()
	apiAlertsWebhooks(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing ID, got %d", w.Code)
	}
}

func TestAPIAlertsWebhooks_DELETE(t *testing.T) {
	orig := globalAlertStore
	defer func() { globalAlertStore = orig }()
	as := &AlertStore{}
	as.Init("")
	globalAlertStore = as

	created := as.Add(AlertWebhook{Name: "del", URL: "http://del.com", Events: []string{"*"}, Enabled: true})

	body := bytes.NewBufferString(`{"id":"` + created.ID + `"}`)
	req, _ := http.NewRequest(http.MethodDelete, "/api/alerts/webhooks?id="+created.ID, body)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiAlertsWebhooks(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(as.hooks) != 0 {
		t.Error("webhook should have been deleted")
	}
}

// ── apiUnauthMode ─────────────────────────────────────────────────────────────

func TestAPIUnauthMode_EnableDisable(t *testing.T) {
	// Enable.
	req := adminRequest(http.MethodPut, "/api/settings/unauth-mode", `{"enabled":true}`)
	w := httptest.NewRecorder()
	apiUnauthMode(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("enable: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !cfg.UnauthMode() {
		t.Error("unauth mode should be enabled")
	}

	// Disable.
	req = adminRequest(http.MethodPut, "/api/settings/unauth-mode", `{"enabled":false}`)
	w = httptest.NewRecorder()
	apiUnauthMode(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("disable: expected 200, got %d", w.Code)
	}
	if cfg.UnauthMode() {
		t.Error("unauth mode should be disabled")
	}
}

func TestAPIUnauthMode_WrongMethod(t *testing.T) {
	req := adminRequest(http.MethodGet, "/api/settings/unauth-mode", "")
	w := httptest.NewRecorder()
	apiUnauthMode(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestAPIUnauthMode_BadJSON(t *testing.T) {
	req := adminRequest(http.MethodPut, "/api/settings/unauth-mode", "not-json")
	w := httptest.NewRecorder()
	apiUnauthMode(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
