package runtime

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewProtectedResourceMetadata_DerivesPaths(t *testing.T) {
	m, err := NewProtectedResourceMetadata("https://gw.example.com/mcp/gateway", []string{"https://idp.example/issuer"}, "Culvert Gateway")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if m.Resource != "https://gw.example.com/mcp/gateway" {
		t.Fatalf("resource = %q", m.Resource)
	}
	if m.WellKnownPath != "/.well-known/oauth-protected-resource/mcp/gateway" {
		t.Fatalf("well-known path = %q", m.WellKnownPath)
	}
	if m.MetadataURL != "https://gw.example.com/.well-known/oauth-protected-resource/mcp/gateway" {
		t.Fatalf("metadata url = %q", m.MetadataURL)
	}
}

func TestNewProtectedResourceMetadata_RejectsNonHTTPS(t *testing.T) {
	for _, res := range []string{"http://gw.example.com/mcp/gateway", "gw.example.com/mcp/gateway", "/mcp/gateway", "://bad"} {
		if _, err := NewProtectedResourceMetadata(res, nil, ""); err == nil {
			t.Fatalf("expected rejection of non-https resource %q", res)
		}
	}
}

func TestProtectedResourceMetadata_DocumentIsBoundedAndSecretFree(t *testing.T) {
	m, err := NewProtectedResourceMetadata("https://gw.example.com/mcp/gateway", []string{"https://idp.example/issuer"}, "Culvert Gateway")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	body := m.documentJSON()
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("doc not valid JSON: %v", err)
	}
	if doc["resource"] != "https://gw.example.com/mcp/gateway" {
		t.Fatalf("resource field = %v", doc["resource"])
	}
	if _, ok := doc["bearer_methods_supported"]; !ok {
		t.Fatal("bearer_methods_supported missing")
	}
	// The document may carry ONLY the four bounded public RFC 9728 keys — anything
	// else is an unexpected (potentially secret-bearing) field.
	allowed := map[string]struct{}{
		"resource": {}, "authorization_servers": {}, "bearer_methods_supported": {}, "resource_name": {},
	}
	for k := range doc {
		if _, ok := allowed[k]; !ok {
			t.Fatalf("public metadata document carried unexpected field %q: %s", k, body)
		}
	}
	// A raw credential/key must never appear as a VALUE.
	for _, forbidden := range []string{"access_token", "client_secret", "password", "private", "-----BEGIN"} {
		if strings.Contains(strings.ToLower(string(body)), forbidden) {
			t.Fatalf("public metadata document leaked %q: %s", forbidden, body)
		}
	}
}

func TestProtectedResourceMetadata_ChallengeFormat(t *testing.T) {
	m, _ := NewProtectedResourceMetadata("https://gw.example.com/mcp/gateway", nil, "")
	got := m.challenge()
	want := `Bearer resource_metadata="https://gw.example.com/.well-known/oauth-protected-resource/mcp/gateway"`
	if got != want {
		t.Fatalf("challenge = %q want %q", got, want)
	}
	// A nil metadata never produces a challenge (byte-identical pre-metadata behavior).
	var nilm *ProtectedResourceMetadata
	if nilm.challenge() != "" {
		t.Fatal("nil metadata must yield empty challenge")
	}
}

// gwListenerConfigWithMetadata returns the gateway listener config plus published
// metadata, reusing the shared testkit fixtures.
func gwListenerConfigWithMetadata(t testing.TB) ListenerConfig {
	t.Helper()
	cfg := gwListenerConfig(t)
	m, err := NewProtectedResourceMetadata("https://"+gwHost+gwResource, []string{testIssuer}, "Culvert Gateway")
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	cfg.Metadata = m
	return cfg
}

func TestListener_ServesWellKnownMetadata(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, NewBoundedSink(8))
	l, err := newListener(gwListenerConfigWithMetadata(t), deps, "gw", 1)
	if err != nil {
		t.Fatalf("newListener: %v", err)
	}
	req := httptest.NewRequest("GET", "https://"+gwHost+"/.well-known/oauth-protected-resource"+gwResource, http.NoBody)
	req.Host = gwHost
	rec := httptest.NewRecorder()
	l.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("well-known GET status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if doc["resource"] == "" || doc["resource"] == nil {
		t.Fatal("metadata resource empty")
	}
}

func TestListener_Emits401ChallengeOnMissingCredential(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, NewBoundedSink(8))
	l, err := newListener(gwListenerConfigWithMetadata(t), deps, "gw", 1)
	if err != nil {
		t.Fatalf("newListener: %v", err)
	}
	// An initialize POST with no Authorization header reaches the auth step and is
	// rejected 401 with a challenge that points at the metadata document.
	req := httptest.NewRequest("POST", "https://"+gwHost+gwResource, strings.NewReader(string(initializeBody(1))))
	req.Host = gwHost
	rec := httptest.NewRecorder()
	l.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	ch := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(ch, "Bearer resource_metadata=") {
		t.Fatalf("WWW-Authenticate = %q", ch)
	}
	if !strings.Contains(ch, gwResource) {
		t.Fatalf("challenge does not reference the resource path: %q", ch)
	}
}

func TestListener_NoChallengeWhenMetadataAbsent(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, NewBoundedSink(8))
	l, err := newListener(gwListenerConfig(t), deps, "gw", 1) // no Metadata
	if err != nil {
		t.Fatalf("newListener: %v", err)
	}
	req := httptest.NewRequest("POST", "https://"+gwHost+gwResource, strings.NewReader(string(initializeBody(1))))
	req.Host = gwHost
	rec := httptest.NewRecorder()
	l.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if ch := rec.Header().Get("WWW-Authenticate"); ch != "" {
		t.Fatalf("no challenge expected without metadata, got %q", ch)
	}
}
