package main

// setup_token_test.go — gates for the per-instance first-admin setup token
// (setup_token.go; owner review round 3, PR #1528: the one-time setup
// window on the published admin port needs protection on its actual traffic
// path, not a firewall note).

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupTokenTestConfig(t *testing.T) {
	t.Helper()
	orig := cfg
	setupProxyTest(t)
	cfg.SetUIUsersFile(filepath.Join(t.TempDir(), "ui_users.json"))
	_ = cfg.SetAuth("", "")
	t.Cleanup(func() {
		loadSetupToken("")
		cfg = orig // never leave the global pointing at a removed temp dir
	})
}

func postSetup(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/setup/complete", strings.NewReader(`{"user":"admin","pass":"Str0ngPassw0rd!"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.77:4000"
	if token != "" {
		req.Header.Set(headerSetupToken, token)
	}
	rec := httptest.NewRecorder()
	apiSetupComplete(rec, req)
	return rec
}

func TestSetupToken_RequiredAndMissingRefusesWithoutConfiguring(t *testing.T) {
	setupTokenTestConfig(t)
	loadSetupToken("per-instance-token-0123456789abcdef")
	if !setupTokenRequired() {
		t.Fatal("token must be reported as required")
	}
	rec := postSetup(t, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing token: want 403, got %d %s", rec.Code, rec.Body.String())
	}
	if cfg.IsConfigured() {
		t.Fatal("a refused setup must not configure the appliance")
	}
	rec = postSetup(t, "per-instance-token-0123456789abcdeX")
	if rec.Code != http.StatusForbidden || cfg.IsConfigured() {
		t.Fatalf("wrong token: want 403 and unconfigured, got %d configured=%v", rec.Code, cfg.IsConfigured())
	}
}

func TestSetupToken_RightTokenCompletesSetup(t *testing.T) {
	setupTokenTestConfig(t)
	loadSetupToken("  per-instance-token-0123456789abcdef\n")
	rec := postSetup(t, "per-instance-token-0123456789abcdef")
	if rec.Code != http.StatusOK {
		t.Fatalf("right token: want 200, got %d %s", rec.Code, rec.Body.String())
	}
	if !cfg.IsConfigured() {
		t.Fatal("setup must complete")
	}
	// Once configured the token is irrelevant: the endpoint is closed.
	if rec := postSetup(t, "per-instance-token-0123456789abcdef"); rec.Code != http.StatusForbidden {
		t.Fatalf("second setup must be refused as already complete, got %d", rec.Code)
	}
}

// CONTROL: a deployment without a token keeps the historical open bootstrap
// window byte for byte (no header needed, status reports false).
func TestSetupToken_UnsetKeepsOpenBootstrap(t *testing.T) {
	setupTokenTestConfig(t)
	loadSetupToken("   ")
	if setupTokenRequired() {
		t.Fatal("a blank token must not be required")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/setup/status", http.NoBody)
	rec := httptest.NewRecorder()
	apiSetupStatus(rec, req)
	if !strings.Contains(rec.Body.String(), `"setupTokenRequired":false`) {
		t.Fatalf("status must report the token as not required: %s", rec.Body.String())
	}
	if rec := postSetup(t, ""); rec.Code != http.StatusOK {
		t.Fatalf("setup without a configured token must still work: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSetupToken_StatusReportsRequirement(t *testing.T) {
	setupTokenTestConfig(t)
	loadSetupToken("per-instance-token-0123456789abcdef")
	req := httptest.NewRequest(http.MethodGet, "/api/setup/status", http.NoBody)
	rec := httptest.NewRecorder()
	apiSetupStatus(rec, req)
	if !strings.Contains(rec.Body.String(), `"setupTokenRequired":true`) {
		t.Fatalf("status must report the token requirement so the wizard asks for it: %s", rec.Body.String())
	}
}

// The bootstrap credential must protect every route that receives the
// temporary administrator role, not just /api/setup/complete. Otherwise a
// caller can bypass setup and persist its own administrator through users.
func TestSetupToken_ProtectsBootstrapAdminRoutes(t *testing.T) {
	origLogger := logger
	logger = log.New(io.Discard, "", 0)
	t.Cleanup(func() { logger = origLogger })
	for _, tc := range []struct {
		name, configured, presented string
		want                        int
	}{
		{"missing", "instance-token", "", http.StatusForbidden},
		{"wrong", "instance-token", "wrong-token", http.StatusForbidden},
		{"valid", "instance-token", "instance-token", http.StatusOK},
		{"legacy-unset", "", "", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupTokenTestConfig(t)
			loadSetupToken(tc.configured)
			req := httptest.NewRequest(http.MethodPost, "/api/auth/users", strings.NewReader(`{"username":"bootstrap-admin","password":"Str0ngPassw0rd!","role":"admin"}`))
			req.RemoteAddr = "198.51.100.78:4000"
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(headerSetupToken, tc.presented)
			rec := httptest.NewRecorder()
			uiAuthMiddleware(http.HandlerFunc(apiAuthUsers)).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("want %d, got %d: %s", tc.want, rec.Code, rec.Body.String())
			}
			if got := cfg.UIUserExists("bootstrap-admin"); got != (tc.want == http.StatusOK) {
				t.Fatalf("administrator persisted = %v; HTTP result %d", got, rec.Code)
			}
		})
	}
}

func TestSetupToken_BootstrapRoutingAndPostSetup(t *testing.T) {
	setupTokenTestConfig(t)
	loadSetupToken("instance-token")
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/api/auth/users", http.StatusForbidden}, // reads also need bootstrap authority
		{"/", http.StatusNoContent},
		{"/api/setup/status", http.StatusNoContent},
		{"/api/setup/complete", http.StatusNoContent}, // the handler owns its token gate
	} {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, http.NoBody))
			if rec.Code != tc.want {
				t.Fatalf("want %d, got %d", tc.want, rec.Code)
			}
		})
	}
	if err := cfg.SetAuth("admin", "Str0ngPassw0rd!"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/users", http.NoBody)
	req.Header.Set(headerSetupToken, "instance-token")
	rec := httptest.NewRecorder()
	uiAuthMiddleware(http.HandlerFunc(apiAuthUsers)).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("setup token must not authenticate after setup: got %d", rec.Code)
	}
}

// The comparison is over digests in constant time, so the token's bytes and
// length never influence timing; pinned structurally (a timing gate would
// flake) by requiring subtle.ConstantTimeCompare on the hashes.
func TestSetupToken_ComparisonIsConstantTime(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(pkgSourceDir(), "setup_token.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if !strings.Contains(src, "subtle.ConstantTimeCompare(got[:], setupTokenState.hash[:])") {
		t.Fatal("setupTokenAccepts must compare SHA-256 digests with subtle.ConstantTimeCompare")
	}
	if strings.Contains(src, "== presented") || strings.Contains(src, "presented ==") {
		t.Fatal("the raw token must never be compared as a string")
	}
}
