package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/decryptobs"
)

// decryption_redaction_test.go — ADR-0011 §4 host/SNI redaction toggle: the flag drives
// the projection, persists node-locally, and the admin surface gates + audits.

// swapDecRedact sets the flag for a test and restores it after.
func swapDecRedact(t *testing.T, v bool) {
	t.Helper()
	prev := decRedactHosts()
	setDecRedactHosts(v)
	t.Cleanup(func() { setDecRedactHosts(prev) })
}

// TestDecRedaction_DrivesProjection proves toBlock hashes host/SNI iff the flag is on.
// (The projection sites pass decRedactHosts() as the redact arg.)
func TestDecRedaction_DrivesProjection(t *testing.T) {
	o := &DecryptionOutcome{
		Outcome: decryptobs.OutcomeInspected, DecisionSource: decryptobs.DecisionPolicyInspect,
		Host: "secret.example", SNI: "secret.example",
	}
	if b := o.toBlock(false); b.Host != "secret.example" {
		t.Fatalf("redact=false must keep plaintext host, got %q", b.Host)
	}
	if b := o.toBlock(true); b.Host == "secret.example" || !strings.HasPrefix(b.Host, "h_") {
		t.Fatalf("redact=true must hash host, got %q", b.Host)
	} else if b.SNI == "secret.example" || !strings.HasPrefix(b.SNI, "h_") {
		t.Fatalf("redact=true must hash SNI, got %q", b.SNI)
	}
}

// TestDecRedaction_PersistenceRoundTrip — Save writes the flag; a simulated restart
// (reset flag) + Load restores it. Node-local (admin_settings) durability.
func TestDecRedaction_PersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)
	swapDecRedact(t, false)

	setDecRedactHosts(true)
	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("save: %v", err)
	}
	var s AdminSettings
	data, _ := os.ReadFile(path)
	if json.Unmarshal(data, &s) != nil || !s.DecryptionRedactHosts {
		t.Fatalf("persisted flag wrong: %+v", s)
	}

	// Simulated restart: flag back to default, then Load restores true.
	setDecRedactHosts(false)
	LoadAdminSettings(path)
	if !decRedactHosts() {
		t.Fatal("Load did not restore the persisted redaction flag")
	}
}

func decRedactReq(t *testing.T, role UIRole, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	r := httptest.NewRequest(method, "/api/decryption/redaction", rdr)
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
	w := httptest.NewRecorder()
	apiDecryptionRedaction(w, r)
	return w
}

func TestApiDecryptionRedaction_GetPutAndRBAC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)
	swapDecRedact(t, false)

	// GET viewer reflects the current (false) state.
	w := decRedactReq(t, RoleViewer, http.MethodGet, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"redact_hosts":false`) {
		t.Fatalf("GET viewer: code=%d body=%s", w.Code, w.Body.String())
	}

	// PUT viewer is denied (admin-only).
	if w := decRedactReq(t, RoleViewer, http.MethodPut, `{"redact_hosts":true}`); w.Code == http.StatusOK {
		t.Fatalf("PUT viewer returned 200, want a deny")
	}
	if decRedactHosts() {
		t.Fatal("denied PUT still flipped the flag")
	}

	// PUT admin enables it + persists.
	w = decRedactReq(t, RoleAdmin, http.MethodPut, `{"redact_hosts":true}`)
	if w.Code != http.StatusOK || !decRedactHosts() {
		t.Fatalf("PUT admin: code=%d flag=%v", w.Code, decRedactHosts())
	}
	var s AdminSettings
	data, _ := os.ReadFile(path)
	if json.Unmarshal(data, &s) != nil || !s.DecryptionRedactHosts {
		t.Fatal("PUT admin did not persist the flag")
	}

	// GET viewer now reflects true.
	if w := decRedactReq(t, RoleViewer, http.MethodGet, ""); !strings.Contains(w.Body.String(), `"redact_hosts":true`) {
		t.Fatalf("GET after enable: %s", w.Body.String())
	}
	// Non-GET/PUT → 405.
	if w := decRedactReq(t, RoleAdmin, http.MethodDelete, ""); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE code=%d, want 405", w.Code)
	}
}

// TestDecRedaction_APISurfacesHonestScope pins the PR3 B0 honesty fix: the GET
// response advertises the TRUTHFUL scope (decryption-metadata-only) and warns that
// top-level host/URI remain plaintext — so the toggle no longer claims privacy it does
// not deliver. This is the mission red line ("do not claim 'host/SNI is redacted' if
// another field in the same record reveals it").
func TestDecRedaction_APISurfacesHonestScope(t *testing.T) {
	swapDecRedact(t, true)
	req := httptest.NewRequest(http.MethodGet, "/api/decryption/redaction", http.NoBody)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleViewer))
	rw := httptest.NewRecorder()
	apiDecryptionRedaction(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", rw.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["scope"] != "decryption_metadata_only" {
		t.Fatalf("scope = %v, want decryption_metadata_only", resp["scope"])
	}
	warn, _ := resp["warning"].(string)
	for _, want := range []string{"host", "URI", "plaintext"} {
		if !strings.Contains(warn, want) {
			t.Fatalf("warning must mention %q; got %q", want, warn)
		}
	}
	// The scope_fields must name exactly the two nested fields it actually redacts.
	fields, _ := resp["scope_fields"].([]any)
	if len(fields) != 2 || fields[0] != "dec.host" || fields[1] != "dec.sni" {
		t.Fatalf("scope_fields = %v, want [dec.host dec.sni]", fields)
	}
}
