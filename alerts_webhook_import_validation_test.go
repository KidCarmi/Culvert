package main

// alerts_webhook_import_validation_test.go — SEC-ALERTS-EVENTNAME-1 at the
// SECOND write ingress.
//
// The admin API's create and update arms share one definition of an acceptable
// webhook payload (webhookPayloadRejected), whose comment credits it with
// keeping an unvalidated value "from reaching the webhook file, a support
// bundle or any other consumer at all". POST /api/config/import reconstructs
// every webhook through the same store and ran neither the URL nor the
// event-name check, so a backup carrying an arbitrary event name or a
// non-http(s) URL was installed with a 200.
//
// The downstream sinks do hold — the Alerts panel escapes (pinned by
// TestWebhookEventsCell_IsEscapedInAdminUI) and a bad URL is refused at egress
// by the scheme barrier plus ssrf.SafeDialContext — so this is defence in
// depth, not a live XSS or SSRF. It is still the gap that matters: the
// character class and the 64-byte bound exist precisely so the value never
// reaches the webhook file, and a control enforced at one of two ingresses is
// the shape of defect that produced the original finding.

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// importBackupExpecting posts a backup and asserts the status code, returning
// the body so a refusal's reason can be checked.
func importBackupExpecting(t *testing.T, backup map[string]any, wantStatus int) string {
	t.Helper()
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import?mode=merge", backup))
	if w.Code != wantStatus {
		t.Fatalf("import status = %d, want %d; body: %s", w.Code, wantStatus, w.Body.String())
	}
	return w.Body.String()
}

// webhookBackup is a v1 backup carrying one webhook with the given URL and
// event names.
func webhookBackup(url string, events []string) map[string]any {
	return map[string]any{
		"version":    1,
		"exportedAt": "2026-11-17T00:00:00Z",
		"alertWebhooks": []map[string]any{{
			"name":    "imported",
			"url":     url,
			"events":  events,
			"enabled": true,
		}},
	}
}

// TestConfigImport_RefusesHostileEventNames is the negative case. Each payload
// is one the admin API's POST/PUT arms already refuse; the import must refuse
// it too, and must install NOTHING (the whole import is rejected, never
// partially applied — the posture the URL-category and PAC gates beside it
// already take).
func TestConfigImport_RefusesHostileEventNames(t *testing.T) {
	for _, tc := range []struct {
		name  string
		event string
	}{
		{"html_breakout", `<img src=x onerror=alert(1)>`},
		{"attribute_breakout", `a" onmouseover="alert(1)`},
		{"crlf", "threat_detected\r\nX-Injected: 1"},
		{"newline", "threat_detected\nthreat_detected"},
		{"nul", "threat\x00detected"},
		{"uppercase", "Threat_Detected"},
		{"space", "threat detected"},
		{"empty", ""},
		{"over_max_len", strings.Repeat("a", 65)},
		{"json_breakout", `threat","x":"y`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshotConfigVersionsDir(t)
			as := swapAlertStoreForImport(t)

			body := importBackupExpecting(t, webhookBackup("https://siem.example.invalid/c", []string{tc.event}), 400)
			if !strings.Contains(strings.ToLower(body), "event") {
				t.Errorf("refusal body %q does not name the events field", strings.TrimSpace(body))
			}
			if hooks := as.List(); len(hooks) != 0 {
				t.Errorf("the import installed %d webhook(s) despite the refusal: %+v — the whole import "+
					"must be refused, never partially applied", len(hooks), hooks)
			}
		})
	}
}

// TestConfigImport_RefusesNonHTTPWebhookURL covers the other half of the
// shared payload definition. validateWebhookURL is a shape gate (absolute,
// http/https, non-empty host); the import skipped it entirely.
func TestConfigImport_RefusesNonHTTPWebhookURL(t *testing.T) {
	for _, tc := range []struct {
		name, url string
	}{
		{"javascript_scheme", "javascript:alert(1)"},
		{"file_scheme", "file:///etc/shadow"},
		{"data_scheme", "data:text/html,<script>alert(1)</script>"},
		{"relative", "/not/absolute"},
		{"no_host", "https://"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshotConfigVersionsDir(t)
			as := swapAlertStoreForImport(t)

			body := importBackupExpecting(t, webhookBackup(tc.url, []string{"threat_detected"}), 400)
			if !strings.Contains(strings.ToLower(body), "webhook") {
				t.Errorf("refusal body %q does not name the webhook", strings.TrimSpace(body))
			}
			if hooks := as.List(); len(hooks) != 0 {
				t.Errorf("the import installed %d webhook(s) despite the refusal: %+v", len(hooks), hooks)
			}
		})
	}
}

// TestConfigImport_AcceptsAValidWebhook is the positive control: the gate must
// not false-positive on a legitimate backup. `*` is included because it is the
// one name admitted outside the [a-z0-9_] class, and a gate that rejected it
// would silently unsubscribe catch-all webhooks on every restore.
func TestConfigImport_AcceptsAValidWebhook(t *testing.T) {
	for _, events := range [][]string{
		{"threat_detected"},
		{"threat_detected", "policy_block"},
		{"*"},
		{"a1_b2"},
		{strings.Repeat("a", 64)}, // exactly at the bound
		{},
	} {
		t.Run(strings.Join(events, ","), func(t *testing.T) {
			snapshotConfigVersionsDir(t)
			as := swapAlertStoreForImport(t)

			importBackupExpecting(t, webhookBackup("https://siem.example.invalid/c", events), 200)
			if hooks := as.List(); len(hooks) != 1 {
				t.Fatalf("installed %d webhooks, want 1: %+v", len(hooks), hooks)
			}
		})
	}
}

// TestConfigImport_RefusalIsWholeNotPartial pins the all-or-nothing property
// across MULTIPLE webhooks: a bad entry anywhere in the list must prevent the
// good ones from being installed too, so an operator never ends up with a
// half-restored alert plane they believe is complete.
func TestConfigImport_RefusalIsWholeNotPartial(t *testing.T) {
	snapshotConfigVersionsDir(t)
	as := swapAlertStoreForImport(t)

	backup := map[string]any{
		"version":    1,
		"exportedAt": "2026-11-17T00:00:00Z",
		"alertWebhooks": []map[string]any{
			{"name": "good-1", "url": "https://a.example.invalid/c", "events": []string{"threat_detected"}, "enabled": true},
			{"name": "bad", "url": "https://b.example.invalid/c", "events": []string{"<script>"}, "enabled": true},
			{"name": "good-2", "url": "https://c.example.invalid/c", "events": []string{"policy_block"}, "enabled": true},
		},
	}
	body := importBackupExpecting(t, backup, 400)
	if !strings.Contains(body, "2") {
		t.Errorf("refusal %q should identify WHICH webhook failed so the operator can fix the backup", strings.TrimSpace(body))
	}
	if hooks := as.List(); len(hooks) != 0 {
		t.Errorf("installed %d webhook(s) from a backup containing one bad entry: %+v", len(hooks), hooks)
	}
}
