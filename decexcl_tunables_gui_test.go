package main

// decexcl_tunables_gui_test.go — F10 PR4: the Decryption Exclusions "Cache Tuning"
// GUI section. Proves the panel renders with its wiring, that the read endpoint
// exposes defaults+bounds (NOT current values — those stay on the Stats surface),
// and that admin enforcement holds through the FULL middleware chain (viewer PUT is
// rejected, admin PUT applies). Mirrors release_gui_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ─── panel + nav render (the GUI deliverable) ───────────────────────────────

func TestDecTunablesGUI_PanelAndWiringRender(t *testing.T) {
	fx := newE2EFixture(t)
	resp := mustGet(t, fx.anonClient(), fx.srv.URL+"/") // SPA shell is public
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d; want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)

	for _, marker := range []string{
		`id="dectun-panel"`,                   // the tuning panel
		`id="dectun-form"`,                    // where the fields are injected
		`id="dectun-error"`,                   // client-side validation error slot
		`data-click="saveDecTunables"`,        // wired save
		`data-click="resetDecTunables"`,       // wired reset-to-defaults
		`renderDecTunables`,                   // pre-fill from the Stats snapshot
		`loadDecTunablesMeta`,                 // defaults+bounds loader
		`/api/decryption-exclusions/tunables`, // the endpoint the JS calls
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("rendered SPA missing cache-tuning marker %q", marker)
		}
	}

	// The tuning panel must be admin-gated in markup (data-min-role="admin" hides it
	// for lower roles; the server PUT is the real backstop, asserted below).
	if i := strings.Index(html, `id="dectun-panel"`); i >= 0 {
		seg := html[i:min(i+120, len(html))]
		if !strings.Contains(seg, `data-min-role="admin"`) {
			t.Errorf("dectun-panel must carry data-min-role=\"admin\"; got %q", seg)
		}
	}
}

// ─── read endpoint: defaults + bounds only, NOT current values ──────────────

func TestDecTunablesGUI_GetExposesDefaultsAndBoundsOnly(t *testing.T) {
	fx := newE2EFixture(t)
	viewer := fx.loginAs(e2eViewUser, e2eViewPass)
	doc := decodeJSONMap(t, mustGet(t, viewer, fx.srv.URL+"/api/decryption-exclusions/tunables")) //nolint:bodyclose // decodeJSONMap closes resp.Body

	if _, ok := doc["defaults"]; !ok {
		t.Error("GET tunables must expose defaults (for the form's default hints)")
	}
	if _, ok := doc["bounds"]; !ok {
		t.Error("GET tunables must expose bounds (for the input min/max)")
	}
	// Current values are the Stats surface's job — the tuning endpoint must not
	// duplicate them (single source of truth; matches the F10 locked decision).
	for _, k := range []string{"current", "stats", "active", "pending"} {
		if _, ok := doc[k]; ok {
			t.Errorf("GET tunables must not duplicate current values (found key %q)", k)
		}
	}
}

// ─── admin enforcement through the FULL middleware chain ────────────────────

func TestDecTunablesGUI_ViewerCannotPut(t *testing.T) {
	fx := newE2EFixture(t)
	viewer := fx.loginAs(e2eViewUser, e2eViewPass)
	code, _ := putJSON(t, viewer, fx.srv.URL+"/api/decryption-exclusions/tunables",
		map[string]any{"confirm_n": 3, "ttl_secs": 3600, "pinned_ttl_secs": 600, "window_secs": 300, "max_entries": 1000})
	if code != http.StatusForbidden {
		t.Fatalf("viewer PUT tunables = %d; want 403", code)
	}
}

func TestDecTunablesGUI_OperatorCannotPut(t *testing.T) {
	fx := newE2EFixture(t)
	op := fx.loginAs(e2eOpUser, e2eOpPass)
	code, _ := putJSON(t, op, fx.srv.URL+"/api/decryption-exclusions/tunables",
		map[string]any{"confirm_n": 3, "ttl_secs": 3600, "pinned_ttl_secs": 600, "window_secs": 300, "max_entries": 1000})
	if code != http.StatusForbidden {
		t.Fatalf("operator PUT tunables = %d; want 403 (admin-only)", code)
	}
}

func TestDecTunablesGUI_AdminCanPut(t *testing.T) {
	fx := newE2EFixture(t)
	admin := fx.loginAs(e2eAdminUser, e2eAdminPass)
	code, body := putJSON(t, admin, fx.srv.URL+"/api/decryption-exclusions/tunables",
		map[string]any{"confirm_n": 3, "ttl_secs": 7200, "pinned_ttl_secs": 900, "window_secs": 300, "max_entries": 2048})
	if code != http.StatusOK {
		t.Fatalf("admin PUT tunables = %d; want 200 (%v)", code, body)
	}
	if got := body["confirm_n"]; got != float64(3) {
		t.Fatalf("PUT echoed confirm_n = %v; want 3", got)
	}
}

// putJSON PUTs a JSON body via the authenticated client and returns the status
// code + decoded JSON body (mirrors postJSON in release_gui_test.go).
func putJSON(t *testing.T, c *http.Client, url string, payload any) (status int, body map[string]any) {
	t.Helper()
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", url, err)
	}
	defer resp.Body.Close()
	var m map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}
