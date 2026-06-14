package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveReleaseStartupConfig_Defaults(t *testing.T) {
	t.Setenv(envReleaseProxyRepo, "")
	t.Setenv(envMaintAgentURL, "")
	cfg := resolveReleaseStartupConfig()
	if cfg.proxyRepo != defaultReleaseProxyRepo {
		t.Errorf("proxyRepo = %q; want default %q", cfg.proxyRepo, defaultReleaseProxyRepo)
	}
	if cfg.maintURL != defaultMaintAgentSocket {
		t.Errorf("maintURL = %q; want default socket %q", cfg.maintURL, defaultMaintAgentSocket)
	}
	if cfg.catalogDir == "" {
		t.Error("catalogDir should be derived from dataDir, got empty")
	}
}

func TestResolveReleaseStartupConfig_EnvOverride(t *testing.T) {
	t.Setenv(envReleaseProxyRepo, "registry.local/culvert")
	t.Setenv(envMaintAgentURL, "http://127.0.0.1:9999")
	cfg := resolveReleaseStartupConfig()
	if cfg.proxyRepo != "registry.local/culvert" || cfg.maintURL != "http://127.0.0.1:9999" {
		t.Fatalf("env override not honored: %+v", cfg)
	}
}

func TestLocalAgentEndpoint(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantOK  bool
		wantURL string
	}{
		{"empty", "", false, ""},
		{"bare socket", "/run/culvert-maint.sock", true, "http://unix"},
		{"unix scheme", "unix:///run/culvert-maint.sock", true, "http://unix"},
		{"http url", "http://127.0.0.1:8888", true, "http://127.0.0.1:8888"},
		{"https url", "https://maint.local:443", true, "https://maint.local:443"},
		{"bad scheme", "ftp://maint", false, ""},
		{"no scheme non-abs", "maint:8888", false, ""},
		{"unix empty", "unix:", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep, ok := localAgentEndpoint(tc.raw)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v; want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if ep.Key != localAgentKey {
				t.Errorf("key = %q; want %q", ep.Key, localAgentKey)
			}
			if ep.BaseURL != tc.wantURL {
				t.Errorf("baseURL = %q; want %q", ep.BaseURL, tc.wantURL)
			}
			if ep.Client == nil {
				t.Error("client must be non-nil")
			}
		})
	}
}

func TestReleaseAgentResolver(t *testing.T) {
	// Configured local agent resolves only the "local" key.
	resolve, note := releaseAgentResolver("/run/culvert-maint.sock")
	if note == "none" {
		t.Fatal("note should describe the configured endpoint")
	}
	if _, ok := resolve(localAgentKey); !ok {
		t.Fatal("local key should resolve")
	}
	if _, ok := resolve("other"); ok {
		t.Fatal("non-local key must not resolve")
	}
	// Blank endpoint ⇒ resolver knows no agents.
	resolveNone, noteNone := releaseAgentResolver("")
	if noteNone != "none" {
		t.Fatalf("note = %q; want none", noteNone)
	}
	if _, ok := resolveNone(localAgentKey); ok {
		t.Fatal("blank endpoint must resolve no agents")
	}
}

func TestLoadReleaseManagement_PublishesAndGraceful(t *testing.T) {
	t.Cleanup(func() { setReleaseManager(nil) })

	// A valid config publishes a usable backend (routes leave the 503 state).
	setReleaseManager(nil)
	loadReleaseManagement(releaseStartupConfig{
		proxyRepo: defaultReleaseProxyRepo, catalogDir: "/tmp/nonexistent-catalog", maintURL: "",
	})
	if currentReleaseManager() == nil {
		t.Fatal("valid config must publish a release manager")
	}
	// With an empty holder the read route is live and reports available:false.
	rec := httptest.NewRecorder()
	apiReleases(rec, releaseReq(http.MethodGet, "/api/releases", nil, RoleViewer))
	if rec.Code != http.StatusOK || decodeBody(t, rec)["available"] != false {
		t.Fatalf("GET /api/releases after wiring = %d %s; want 200 available:false", rec.Code, rec.Body.String())
	}

	// An invalid proxy_repo fails construction gracefully: manager stays nil
	// (routes report 503), never a panic.
	setReleaseManager(nil)
	loadReleaseManagement(releaseStartupConfig{proxyRepo: "", catalogDir: "/tmp/x", maintURL: ""})
	if currentReleaseManager() != nil {
		t.Fatal("invalid proxy_repo must leave the manager unpublished (503), not panic")
	}
}
