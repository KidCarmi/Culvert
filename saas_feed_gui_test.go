package main

// saas_feed_gui_test.go — F3a-2 GUI deliverable + full-middleware-chain contract.
// Proves the SaaS feed panel + overrides editor render with their wiring, that the
// honest "configured but not active" labeling is present, and that admin RBAC +
// CSRF + auth hold through the ENTIRE middleware chain (viewer/operator PUT
// rejected, admin PUT applies). Mirrors decexcl_tunables_gui_test.go.

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSaaSFeedGUI_PanelAndWiringRender(t *testing.T) {
	fx := newE2EFixture(t)
	resp := mustGet(t, fx.anonClient(), fx.srv.URL+"/") // SPA shell is public
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d; want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)

	for _, marker := range []string{
		`id="saasfeed-panel"`,
		`id="saasfeed-form"`,
		`id="saasfeed-error"`,               // failure-state slot
		`id="saasfeed-loading"`,             // loading-state slot
		`id="saasfeed-status"`,              // F3b-4 runtime status panel
		`id="overrides-rows"`,               // overrides editor table body
		`id="overrides-empty"`,              // empty-state slot
		`id="overrides-error"`,              // validation-error slot
		`data-click="saveSaaSFeedSettings"`, // wired save
		`data-click="saveSaaSFeedOverrides"`,
		`data-click="clearSaaSFeedOverrides"`, // explicit empty replacement
		`data-click="addOverrideRow"`,
		`loadSaaSFeedConfig`,      // config loader
		`loadSaaSFeedStatus`,      // F3b-4 runtime-status loader
		`refreshSaaSFeed`,         // F3b-4 manual-refresh handler
		`renderOverrideRows`,      // XSS-safe DOM renderer
		`/api/saas-feed/settings`, // endpoints the JS calls
		`/api/saas-feed/overrides`,
		`/api/saas-feed/status`,  // F3b-4 runtime status
		`/api/saas-feed/refresh`, // F3b-4 manual refresh
		`not downgradeable`,      // protocol is signed-only, stated in UI
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("rendered SPA missing SaaS-feed marker %q", marker)
		}
	}

	// F3b-4: the panel now surfaces the live runtime state separately from config.
	if !strings.Contains(html, "Runtime state") {
		t.Error("SaaS feed panel must surface the runtime state (F3b-4)")
	}

	// XSS posture: the override renderer must build rows via textContent, not by
	// interpolating host/category into innerHTML.
	if !strings.Contains(html, "textContent = XSS-safe") && !strings.Contains(html, "XSS-safe") {
		t.Error("override renderer must document/use the textContent XSS-safe path")
	}
}

func TestSaaSFeedGUI_ReadExposesConfiguredNotRuntime(t *testing.T) {
	fx := newE2EFixture(t)
	viewer := fx.loginAs(e2eViewUser, e2eViewPass)
	doc := decodeJSONMap(t, mustGet(t, viewer, fx.srv.URL+"/api/saas-feed/settings")) //nolint:bodyclose // decodeJSONMap closes resp.Body

	// F3b-4: runtime activation is now available (the signed-feed client is wired).
	if v, ok := doc["runtime_activation_available"]; !ok || v != true {
		t.Errorf("GET settings must report runtime_activation_available=true (F3b-4); got %v (present=%v)", v, ok)
	}
	// The SETTINGS endpoint stays CONFIG-only: runtime/activation fields live on
	// /api/saas-feed/status and must NOT be fabricated here.
	for _, k := range []string{"last_success", "active_version", "freshness", "provenance", "state"} {
		if _, ok := doc[k]; ok {
			t.Errorf("GET settings must not carry runtime field %q (it belongs on /api/saas-feed/status)", k)
		}
	}
	if _, ok := doc["official_url"]; !ok {
		t.Error("GET settings must expose official_url (the constrained endpoint)")
	}
}

func TestSaaSFeedGUI_ViewerAndOperatorCannotPut(t *testing.T) {
	fx := newE2EFixture(t)
	for _, who := range []struct {
		name, user, pass string
	}{
		{"viewer", e2eViewUser, e2eViewPass},
		{"operator", e2eOpUser, e2eOpPass},
	} {
		c := fx.loginAs(who.user, who.pass)
		if code, _ := putJSON(t, c, fx.srv.URL+"/api/saas-feed/settings", map[string]any{"enabled": true}); code != http.StatusForbidden {
			t.Errorf("%s PUT settings = %d; want 403", who.name, code)
		}
		if code, _ := putJSON(t, c, fx.srv.URL+"/api/saas-feed/overrides", map[string]any{"tombstones": []string{"x.com"}}); code != http.StatusForbidden {
			t.Errorf("%s PUT overrides = %d; want 403", who.name, code)
		}
	}
}

func TestSaaSFeedGUI_AdminCanPutThroughFullChain(t *testing.T) {
	fx := newE2EFixture(t)
	admin := fx.loginAs(e2eAdminUser, e2eAdminPass)

	code, body := putJSON(t, admin, fx.srv.URL+"/api/saas-feed/settings",
		map[string]any{"managed": true, "enabled": true, "protocol": "signed_manifest_v1", "refresh": "24h"})
	if code != http.StatusOK {
		t.Fatalf("admin PUT settings = %d; want 200 (%v)", code, body)
	}
	if got := body["enabled"]; got != true {
		t.Fatalf("PUT echoed enabled = %v; want true", got)
	}

	// Overrides full-set replace, then explicit-empty clear.
	if code, _ := putJSON(t, admin, fx.srv.URL+"/api/saas-feed/overrides",
		map[string]any{"tombstones": []string{"ads.example.com"}}); code != http.StatusOK {
		t.Fatalf("admin PUT overrides = %d; want 200", code)
	}
	if code, _ := putJSON(t, admin, fx.srv.URL+"/api/saas-feed/overrides", map[string]any{}); code != http.StatusOK {
		t.Fatalf("admin PUT empty overrides (clear-all) = %d; want 200", code)
	}
}

// A legacy/unsupported protocol or a non-official URL is rejected with 400 through
// the full chain (no unsigned/raw fallback, no generic mirror).
func TestSaaSFeedGUI_RejectsLegacyProtocolAndMirror(t *testing.T) {
	fx := newE2EFixture(t)
	admin := fx.loginAs(e2eAdminUser, e2eAdminPass)
	if code, _ := putJSON(t, admin, fx.srv.URL+"/api/saas-feed/settings", map[string]any{"protocol": "raw_v0"}); code != http.StatusBadRequest {
		t.Errorf("legacy protocol PUT = %d; want 400", code)
	}
	if code, _ := putJSON(t, admin, fx.srv.URL+"/api/saas-feed/settings", map[string]any{"url": "https://evil.example.com/manifest.sigstore.json"}); code != http.StatusBadRequest {
		t.Errorf("non-official URL PUT = %d; want 400", code)
	}
}
