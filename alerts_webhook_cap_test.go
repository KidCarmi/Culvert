package main

// alerts_webhook_cap_test.go — maxAlertWebhooks (alerts.MaxWebhooks) at both
// write ingresses: the admin API create arm and POST /api/config/import.
//
// Import used to accept an unbounded list, and every Add rewrites and fsyncs the
// whole webhook file, so one request cost O(N²) fsync'd I/O (CWE-770). Both
// ingresses now refuse past the same limit with a 400, before any mutation, and
// a refusal is neither audited nor versioned.
//
// Assertions are on unique content (each test's URLs, IDs and exportedAt
// discriminator), never on audit-ring length deltas. Every global touched is
// restored: the alert store (swapAlertStoreForImport) and the config-version
// directory (snapshotConfigVersionsDir).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/alerts"
)

// seedCapHooks adds n webhooks with URLs unique to this test.
func seedCapHooks(t *testing.T, as *alerts.Store, tag string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		as.Add(alerts.Webhook{
			Name:    fmt.Sprintf("%s-seed-%03d", tag, i),
			URL:     fmt.Sprintf("https://seed.example.invalid/%s/%03d", tag, i),
			Events:  []string{"threat_detected"},
			Enabled: true,
		})
	}
}

// storeFingerprint is the set of ID+URL pairs the store holds, so "no state
// change" is asserted on content rather than on a count alone. Keyed by the
// pair, not the ID: Add mints IDs from the clock, so a collision between two
// seeds must not hide a webhook.
func storeFingerprint(as *alerts.Store) map[string]bool {
	out := map[string]bool{}
	for _, h := range as.List() {
		out[h.ID+" "+h.URL] = true
	}
	return out
}

func storeHasURL(as *alerts.Store, url string) bool {
	for _, h := range as.List() {
		if h.URL == url {
			return true
		}
	}
	return false
}

func assertSameStore(t *testing.T, as *alerts.Store, before map[string]bool) {
	t.Helper()
	after := storeFingerprint(as)
	if len(after) != len(before) {
		t.Fatalf("store changed on refusal: %d webhooks before, %d after", len(before), len(after))
	}
	for k := range before {
		if !after[k] {
			t.Fatalf("store changed on refusal: webhook %q is gone", k)
		}
	}
}

func auditHas(action, detail string) bool {
	entries := auditGet()
	for i := range entries {
		if entries[i].Action == action && entries[i].Detail == detail {
			return true
		}
	}
	return false
}

func configVersionSaved(action string) bool {
	for _, m := range configVersions.List() {
		if m.Action == action {
			return true
		}
	}
	return false
}

// ── API create arm ─────────────────────────────────────────────────────────

func createWebhookViaAPI(t *testing.T, url string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"name": "cap-api", "url": url, "events": []string{"threat_detected"}})
	w := httptest.NewRecorder()
	apiAlertsWebhooks(w, roleRequest(http.MethodPost, "/api/alerts/webhooks", string(body), RoleAdmin))
	return w
}

func TestAlertWebhookCreate_AcceptedBelowCap(t *testing.T) {
	as := swapAlertStoreForImport(t)
	seedCapHooks(t, as, "api-below", maxAlertWebhooks-1)

	url := "https://new.example.invalid/api-below/last"
	w := createWebhookViaAPI(t, url)
	if w.Code != http.StatusOK {
		t.Fatalf("create at %d existing = %d, want 200; body %s", maxAlertWebhooks-1, w.Code, w.Body.String())
	}
	var created AlertWebhook
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("create response %q did not carry the new webhook: %v", w.Body.String(), err)
	}
	if !storeFingerprint(as)[created.ID+" "+url] {
		t.Errorf("created webhook %s with URL %q is not in the store", created.ID, url)
	}
	if !auditHas("alert.webhook.create", url) {
		t.Error("an accepted create was not audited")
	}
}

func TestAlertWebhookCreate_RefusedAtCap(t *testing.T) {
	as := swapAlertStoreForImport(t)
	seedCapHooks(t, as, "api-at", maxAlertWebhooks)
	before := storeFingerprint(as)

	url := "https://new.example.invalid/api-at/refused"
	w := createWebhookViaAPI(t, url)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("create at %d existing = %d, want 400; body %s", maxAlertWebhooks, w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, fmt.Sprint(maxAlertWebhooks)) {
		t.Errorf("refusal %q should name the limit", strings.TrimSpace(body))
	}
	assertSameStore(t, as, before)
	if storeHasURL(as, url) {
		t.Fatal("the refused webhook was installed")
	}
	if auditHas("alert.webhook.create", url) {
		t.Error("a refused create was audited")
	}
}

// ── config import ──────────────────────────────────────────────────────────

// capBackup is a backup carrying n webhooks; exportedAt is the test's unique
// discriminator in the config.import audit detail.
func capBackup(tag, exportedAt string, n int) map[string]any {
	hooks := make([]map[string]any, n)
	for i := range hooks {
		hooks[i] = map[string]any{
			"name":    fmt.Sprintf("%s-import-%03d", tag, i),
			"url":     fmt.Sprintf("https://import.example.invalid/%s/%03d", tag, i),
			"events":  []string{"threat_detected"},
			"enabled": true,
		}
	}
	return map[string]any{"version": 1, "exportedAt": exportedAt, "alertWebhooks": hooks}
}

func importCap(t *testing.T, mode string, backup map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import?mode="+mode, backup))
	return w
}

func countImported(as *alerts.Store, tag string) int {
	n := 0
	prefix := "https://import.example.invalid/" + tag + "/"
	for _, h := range as.List() {
		if strings.HasPrefix(h.URL, prefix) {
			n++
		}
	}
	return n
}

// webhookCapCase is one import against a store seeded with existing webhooks.
type webhookCapCase struct {
	name     string
	mode     string
	existing int
	incoming int
	accept   bool
}

func TestConfigImport_WebhookCap(t *testing.T) {
	for _, tc := range []webhookCapCase{
		{"replace_at_cap", "replace", 60, maxAlertWebhooks, true},
		{"replace_over_cap", "replace", 60, maxAlertWebhooks + 1, false},
		{"merge_at_cap", "merge", 60, maxAlertWebhooks - 60, true},
		{"merge_over_cap", "merge", 60, maxAlertWebhooks - 60 + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) { runWebhookCapCase(t, tc) })
	}
}

func runWebhookCapCase(t *testing.T, tc webhookCapCase) {
	snapshotConfigVersionsDir(t)
	as := swapAlertStoreForImport(t)
	tag := "cap-" + tc.name
	seedCapHooks(t, as, tag, tc.existing)
	before := storeFingerprint(as)
	exportedAt := "2026-11-20T00:00:00Z/" + tag
	detail := "from config exported " + exportedAt

	w := importCap(t, tc.mode, capBackup(tag, exportedAt, tc.incoming))
	if tc.accept {
		assertCapImportAccepted(t, as, tc, w, tag, detail)
		return
	}
	assertCapImportRefused(t, as, tc, w, tag, detail, before)
}

func assertCapImportRefused(t *testing.T, as *alerts.Store, tc webhookCapCase, w *httptest.ResponseRecorder, tag, detail string, before map[string]bool) {
	t.Helper()
	if w.Code != http.StatusBadRequest {
		t.Fatalf("%s import of %d onto %d = %d, want 400; body %s", tc.mode, tc.incoming, tc.existing, w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, fmt.Sprint(maxAlertWebhooks)) {
		t.Errorf("refusal %q should name the limit", strings.TrimSpace(body))
	}
	assertSameStore(t, as, before)
	if n := countImported(as, tag); n != 0 {
		t.Errorf("a refused import installed %d webhook(s) — never partially applied", n)
	}
	if auditHas("config.import", detail) {
		t.Error("a refused import was audited")
	}
	if configVersionSaved("config.import") {
		t.Error("a refused import saved a config version")
	}
}

func assertCapImportAccepted(t *testing.T, as *alerts.Store, tc webhookCapCase, w *httptest.ResponseRecorder, tag, detail string) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("%s import of %d onto %d = %d, want 200; body %s", tc.mode, tc.incoming, tc.existing, w.Code, w.Body.String())
	}
	if n := countImported(as, tag); n != tc.incoming {
		t.Errorf("installed %d imported webhooks, want %d", n, tc.incoming)
	}
	if got := as.Len(); got != maxAlertWebhooks {
		t.Errorf("store holds %d webhooks, want exactly the limit %d", got, maxAlertWebhooks)
	}
	// The refusal-side negative controls are live: an accepted import IS
	// audited and versioned.
	if !auditHas("config.import", detail) {
		t.Error("an accepted import was not audited")
	}
	if !configVersionSaved("config.import") {
		t.Error("an accepted import saved no config version")
	}
}
