package main

// setup_token_test.go — gates for the per-instance first-admin setup token
// (setup_token.go; owner review round 3, PR #1528: the one-time setup
// window on the published admin port needs protection on its actual traffic
// path, not a firewall note).

import (
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
	req := httptest.NewRequest(http.MethodGet, "/api/setup/status", nil)
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
	req := httptest.NewRequest(http.MethodGet, "/api/setup/status", nil)
	rec := httptest.NewRecorder()
	apiSetupStatus(rec, req)
	if !strings.Contains(rec.Body.String(), `"setupTokenRequired":true`) {
		t.Fatalf("status must report the token requirement so the wizard asks for it: %s", rec.Body.String())
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
