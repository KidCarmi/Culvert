package main

// alerts_webhook_eventname_injection_test.go — SEC-ALERTS-EVENTNAME-1.
//
// A webhook's subscribed event names were accepted unvalidated from the admin
// API (only RoleOperator is required), persisted verbatim, and then rendered
// into the Alerts panel's webhook table through innerHTML with no escaping —
// while the name and url cells beside them were escaped. An operator could
// therefore store markup that executed in the session of every viewer,
// operator and ADMIN who opened that panel: a privilege escalation out of the
// operator role, since an admin session carries full configuration and RBAC
// authority.
//
// Both halves are pinned here: the ingress refuses the value, and the render
// sink escapes whatever is already on disk from before the fix.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// roleRequest builds an admin-API request carrying an explicit role, so the
// authorization arm can drive a non-admin caller.
func roleRequest(method, path, body string, role UIRole) *http.Request {
	ctx := context.WithValue(context.Background(), uiRoleKey{}, role)
	var rdr io.Reader = http.NoBody
	if body != "" {
		rdr = strings.NewReader(body)
	}
	r, _ := http.NewRequestWithContext(ctx, method, path, rdr)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

func withEmptyAlertStore(t *testing.T) *AlertStore {
	t.Helper()
	orig := globalAlertStore
	t.Cleanup(func() { globalAlertStore = orig })
	as := &AlertStore{}
	as.Init("")
	globalAlertStore = as
	return as
}

// injectionPayloads are the shapes that matter at the HTML sink this fix
// closes, plus the control bytes that would break a log or wire line.
var injectionPayloads = map[string]string{
	"img onerror":        `<img src=x onerror=alert(1)>`,
	"script tag":         `<script>alert(document.cookie)</script>`,
	"attribute breakout": `" onmouseover="alert(1)`,
	"newline":            "policy_block\nthreat_detected",
	"nul byte":           "policy_block\x00",
	"uppercase":          "Policy_Block",
	"space":              "policy block",
}

// TestWebhookEventNames_POSTRejectsInjection — the create ingress refuses a
// malformed name with 400 and stores NOTHING. A 400 that still persisted the
// hook would leave the payload on disk for every later reader.
func TestWebhookEventNames_POSTRejectsInjection(t *testing.T) {
	for name, payload := range injectionPayloads {
		t.Run(name, func(t *testing.T) {
			as := withEmptyAlertStore(t)
			body, err := json.Marshal(map[string]any{
				"name":   "hook",
				"url":    "http://example.com/hook",
				"events": []string{payload},
			})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			w := httptest.NewRecorder()
			apiAlertsWebhooks(w, roleRequest(http.MethodPost, "/api/alerts/webhooks", string(body), RoleAdmin))

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for event name %q, got %d: %s", payload, w.Code, w.Body.String())
			}
			if got := len(as.List()); got != 0 {
				t.Errorf("a refused create must store nothing, got %d webhook(s)", got)
			}
		})
	}
}

// TestWebhookEventNames_PUTRejectsInjection — an update re-supplies the whole
// event list, so it is the same ingress; a hook created clean must not be
// editable into a poisoned one.
func TestWebhookEventNames_PUTRejectsInjection(t *testing.T) {
	as := withEmptyAlertStore(t)
	created := as.Add(AlertWebhook{Name: "hook", URL: "http://example.com/hook", Events: []string{"policy_block"}})

	body := `{"name":"hook","url":"http://example.com/hook","events":["<img src=x onerror=alert(1)>"]}`
	w := httptest.NewRecorder()
	apiAlertsWebhooks(w, roleRequest(http.MethodPut, "/api/alerts/webhooks?id="+created.ID, body, RoleAdmin))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on update, got %d: %s", w.Code, w.Body.String())
	}
	hooks := as.List()
	if len(hooks) != 1 {
		t.Fatalf("expected the original webhook to survive, got %d", len(hooks))
	}
	if len(hooks[0].Events) != 1 || hooks[0].Events[0] != "policy_block" {
		t.Errorf("a refused update must leave the stored events unchanged, got %v", hooks[0].Events)
	}
}

// TestWebhookEventNames_POSTAcceptsCatalogName is the positive control: the
// validation must not have broken ordinary subscription.
func TestWebhookEventNames_POSTAcceptsCatalogName(t *testing.T) {
	as := withEmptyAlertStore(t)
	body := `{"name":"hook","url":"http://example.com/hook","events":["panic_contained","threat_detected"]}`
	w := httptest.NewRecorder()
	apiAlertsWebhooks(w, roleRequest(http.MethodPost, "/api/alerts/webhooks", body, RoleAdmin))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	hooks := as.List()
	if len(hooks) != 1 {
		t.Fatalf("expected 1 webhook, got %d", len(hooks))
	}
	if len(hooks[0].Events) != 2 {
		t.Errorf("expected both events subscribed, got %v", hooks[0].Events)
	}
}

// TestWebhookEventNames_AuthorizationStillEnforced — the new check must not
// have become the FIRST gate: a viewer is refused by role (403) before any
// input shape is considered, whether the payload is clean or poisoned.
func TestWebhookEventNames_AuthorizationStillEnforced(t *testing.T) {
	for _, tc := range []struct{ name, events string }{
		{"clean payload", `["policy_block"]`},
		{"poisoned payload", `["<img src=x onerror=alert(1)>"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			as := withEmptyAlertStore(t)
			body := `{"name":"hook","url":"http://example.com/hook","events":` + tc.events + `}`
			w := httptest.NewRecorder()
			apiAlertsWebhooks(w, roleRequest(http.MethodPost, "/api/alerts/webhooks", body, RoleViewer))

			if w.Code != http.StatusForbidden {
				t.Errorf("a viewer must be refused with 403, got %d: %s", w.Code, w.Body.String())
			}
			if got := len(as.List()); got != 0 {
				t.Errorf("a viewer must store nothing, got %d", got)
			}
		})
	}
}

// TestWebhookEventNames_ConcurrentCreatesRefuseEveryPoisonedOne — the check
// sits in the handler, which runs on many admin goroutines at once; no
// interleaving may let one poisoned create through.
func TestWebhookEventNames_ConcurrentCreatesRefuseEveryPoisonedOne(t *testing.T) {
	as := withEmptyAlertStore(t)
	const n = 24
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			events := `["policy_block"]`
			if i%2 == 1 {
				events = `["<img src=x onerror=alert(1)>"]`
			}
			body := `{"name":"hook","url":"http://example.com/hook","events":` + events + `}`
			w := httptest.NewRecorder()
			apiAlertsWebhooks(w, roleRequest(http.MethodPost, "/api/alerts/webhooks", body, RoleAdmin))
			codes[i] = w.Code
		}(i)
	}
	wg.Wait()

	for i, code := range codes {
		want := http.StatusOK
		if i%2 == 1 {
			want = http.StatusBadRequest
		}
		if code != want {
			t.Errorf("create %d: expected %d, got %d", i, want, code)
		}
	}
	for _, h := range as.List() {
		for _, ev := range h.Events {
			if ev != "policy_block" {
				t.Errorf("a poisoned event name reached the store: %q", ev)
			}
		}
	}
}

// TestWebhookEventsCell_IsEscapedInAdminUI is the render-sink half. Validation
// at ingress does not help a name already persisted before this fix, so the
// cell must escape. Pinned against the source because the panel has no test
// harness: the sibling cells use escHtml and this one did not, which is the
// inconsistency that made the hole.
func TestWebhookEventsCell_IsEscapedInAdminUI(t *testing.T) {
	// staticIndexHTMLPath() anchors the read to the package source dir: a plain
	// relative read is CWD-relative and flakes when a concurrent test chdirs
	// (TestTestFileReadsAreCWDIndependent is the wall that enforces this).
	b, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read admin UI: %v", err)
	}
	ui := string(b)

	const unescaped = `${(h.events||[]).join(', ')}`
	if strings.Contains(ui, unescaped) {
		t.Errorf("the webhook events cell interpolates %s into innerHTML without escaping — "+
			"a stored event name containing markup executes in every viewer's and admin's session (CWE-79)", unescaped)
	}
	const escaped = `${escHtml((h.events||[]).join(', '))}`
	if !strings.Contains(ui, escaped) {
		t.Errorf("expected the webhook events cell to render through escHtml; looked for %s", escaped)
	}
}
