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

// swapTrafficKey installs a fixed node-local pseudonym key for a test and restores the
// prior key on cleanup. Use alongside swapDecRedact for any test that asserts on the
// redacted TOKEN (PR3 Option B: redaction is keyed HMAC, so a key must be present).
func swapTrafficKey(t *testing.T, key []byte) {
	t.Helper()
	prev := getTrafficPseudonymKey()
	setTrafficPseudonymKey(key)
	t.Cleanup(func() { setTrafficPseudonymKey(prev) })
}

// TestDecRedaction_DrivesProjection proves toBlock pseudonymizes host/SNI iff the flag
// is on. Option B: the token is a keyed HMAC, so a key is installed.
func TestDecRedaction_DrivesProjection(t *testing.T) {
	swapTrafficKey(t, []byte("0123456789abcdef0123456789abcdef"))
	o := &DecryptionOutcome{
		Outcome: decryptobs.OutcomeInspected, DecisionSource: decryptobs.DecisionPolicyInspect,
		Host: "secret.example", SNI: "secret.example",
	}
	if b := o.toBlock(false); b.Host != "secret.example" {
		t.Fatalf("redact=false must keep plaintext host, got %q", b.Host)
	}
	if b := o.toBlock(true); b.Host == "secret.example" || !strings.HasPrefix(b.Host, "h_") {
		t.Fatalf("redact=true must pseudonymize host, got %q", b.Host)
	} else if b.SNI == "secret.example" || !strings.HasPrefix(b.SNI, "h_") {
		t.Fatalf("redact=true must pseudonymize SNI, got %q", b.SNI)
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

// TestApiDecryptionRedaction_RotatePreservesPosture — a rotation is its own
// action (2E-B correction, exactly-one-action contract: rotate_key:true +
// operation_id + ifRevision, no posture field), so it must NOT disable an
// enabled posture: the posture is preserved across a rotation, only the key
// changes. Regression for the Codex P1 "rotation turns plaintext logging
// back on" finding.
func TestApiDecryptionRedaction_RotatePreservesPosture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)
	swapDecRedact(t, false)
	swapTrafficKey(t, nil)

	// Enable the posture (mints a key).
	if w := decRedactReq(t, RoleAdmin, http.MethodPut, `{"redact_hosts":true}`); w.Code != http.StatusOK || !decRedactHosts() {
		t.Fatalf("enable: code=%d flag=%v", w.Code, decRedactHosts())
	}
	before := redactDestinationHost("host.example.com")
	if !strings.HasPrefix(before, "h_") {
		t.Fatalf("posture-on token wrong: %q", before)
	}
	var g struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(decRedactReq(t, RoleViewer, http.MethodGet, "").Body.Bytes(), &g); err != nil || g.Revision == "" {
		t.Fatalf("cannot read the reviewed revision: %v", err)
	}

	// Rotate the key; the posture MUST stay enabled.
	w := decRedactReq(t, RoleAdmin, http.MethodPut,
		`{"rotate_key":true,"operation_id":"op-preserve-posture","ifRevision":"`+g.Revision+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("rotate: code=%d body=%s", w.Code, w.Body.String())
	}
	if !decRedactHosts() {
		t.Fatal("rotation silently DISABLED the posture (would re-enable plaintext logging)")
	}
	if !strings.Contains(w.Body.String(), `"redact_hosts":true`) {
		t.Fatalf("rotate response must report the preserved posture, got %s", w.Body.String())
	}
	after := redactDestinationHost("host.example.com")
	if after == before {
		t.Fatal("rotation must change the token for the same host")
	}
	if !strings.HasPrefix(after, "h_") {
		t.Fatalf("post-rotation token wrong: %q", after)
	}
	// Persisted posture is still on.
	var s AdminSettings
	data, _ := os.ReadFile(path)
	if json.Unmarshal(data, &s) != nil || !s.DecryptionRedactHosts {
		t.Fatalf("rotation must persist the preserved posture, got %+v", s)
	}
}

// TestDecRedaction_APISurfacesScope pins the PR3 Option B GET contract: the posture is
// now a GLOBAL destination-privacy posture — the API advertises the traffic_destination
// scope covering host, uri, and the dec.* fields, and reports whether a node-local key
// is provisioned (never the key value).
func TestDecRedaction_APISurfacesScope(t *testing.T) {
	swapDecRedact(t, true)
	swapTrafficKey(t, []byte("0123456789abcdef0123456789abcdef"))
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
	if resp["scope"] != "traffic_destination" {
		t.Fatalf("scope = %v, want traffic_destination", resp["scope"])
	}
	fields, _ := resp["scope_fields"].([]any)
	if len(fields) != 5 || fields[0] != "host" || fields[1] != "uri" || fields[2] != "dec.host" || fields[3] != "dec.sni" || fields[4] != "top_hosts" {
		t.Fatalf("scope_fields = %v, want [host uri dec.host dec.sni top_hosts]", fields)
	}
	if resp["key_provisioned"] != true {
		t.Fatalf("key_provisioned = %v, want true", resp["key_provisioned"])
	}
	// The response must NEVER carry the key material itself. key_id is the
	// 2E-B §B NON-SECRET generation identifier (random, never derived from the
	// key); its non-secrecy is separately pinned by
	// TestDec2EB_RedactionResponsesNeverCarryKeyMaterial.
	for k := range resp {
		if strings.Contains(strings.ToLower(k), "key") && k != "key_provisioned" && k != "key_id" {
			t.Fatalf("GET response exposes a key-ish field %q", k)
		}
	}
	if id, _ := resp["key_id"].(string); id == "" || strings.Contains(id, "0123456789abcdef0123456789abcdef") {
		t.Fatalf("key_id must be a non-empty identifier independent of the key bytes, got %q", id)
	}
}
