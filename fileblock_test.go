package main

// Proxy-integration tests for file blocking. The FileBlocker/FileProfileStore
// ENGINE and its unit tests moved to internal/fileblock (ADR-0002); these tests
// stay here because they exercise the proxy (handleRequest) integration with the
// file-block engine. They use only the exported engine API via the package main
// singletons (fileBlocker / globalProfileStore).

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestProxy_FileBlockURL verifies that the proxy serves a 403 block page when
// a request URL ends with a blocked extension.
func TestProxy_FileBlockURL(t *testing.T) {
	setupProxyTest(t)
	fileBlocker.Add(".exe")
	t.Cleanup(func() { fileBlocker.Remove(".exe") })

	ts := httptest.NewServer(http.HandlerFunc(handleRequest))
	defer ts.Close()

	req := makeRequest("http://example.com/setup.exe", nil)
	rec := httptest.NewRecorder()
	handleRequest(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

// ── ActionAllow + file profile blocks plain HTTP ─────────────────────────────

func TestProxy_FileBlockPolicyProfile(t *testing.T) {
	setupProxyTest(t)

	// Ensure the built-in "Executables" profile is available (includes .ps1).
	// Seeded via the exported API now that FileProfileStore lives in
	// internal/fileblock (its fields are no longer reachable from main).
	if globalProfileStore.GetByName("Executables") == nil {
		if _, err := globalProfileStore.Create("Executables", []string{".ps1", ".exe", ".bat"}); err != nil {
			t.Fatalf("seed Executables profile: %v", err)
		}
	}

	// Add a policy rule that allows example.com with the Executables profile.
	policyStore.mu.Lock()
	oldRules := policyStore.rules
	policyStore.rules = []*PolicyRule{{
		Name:          "allow-with-profile",
		Priority:      1,
		Action:        ActionAllow,
		DestFQDN:      "example.com",
		FileFiltering: true,
		FileProfile:   "Executables",
	}}
	policyStore.mu.Unlock()
	t.Cleanup(func() {
		policyStore.mu.Lock()
		policyStore.rules = oldRules
		policyStore.mu.Unlock()
	})

	req := makeRequest("http://example.com/tools/script.ps1", nil)
	rec := httptest.NewRecorder()
	handleRequest(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for .ps1 via policy profile, got %d", rec.Code)
	}
}

// Verify that the same rule allows a non-blocked extension.
func TestProxy_FileBlockPolicyProfile_AllowsClean(t *testing.T) {
	setupProxyTest(t)

	// Ensure the built-in "Executables" profile is available.
	if globalProfileStore.GetByName("Executables") == nil {
		if _, err := globalProfileStore.Create("Executables", []string{".ps1", ".exe"}); err != nil {
			t.Fatalf("seed Executables profile: %v", err)
		}
	}

	// Spin up a local upstream that always returns 200 so handleHTTP has
	// somewhere reachable to dial.  Without this, client.Do(r) tries to
	// resolve/dial example.com and can receive environment-dependent
	// responses (CI sandboxes return a 403 "Host not in allowlist" which
	// the proxy then echoes, causing a false-positive test failure).
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	policyStore.mu.Lock()
	oldRules := policyStore.rules
	policyStore.rules = []*PolicyRule{{
		Name:          "allow-with-profile",
		Priority:      1,
		Action:        ActionAllow,
		DestFQDN:      "127.0.0.1",
		FileFiltering: true,
		FileProfile:   "Executables",
	}}
	policyStore.mu.Unlock()
	t.Cleanup(func() {
		policyStore.mu.Lock()
		policyStore.rules = oldRules
		policyStore.mu.Unlock()
	})

	// Request routes to the local upstream; the policy rule matches on
	// 127.0.0.1 (the Host header carries host+port but matchFQDN strips
	// the port before comparing).  A .txt path must NOT trip the
	// Executables profile (.ps1 / .exe only).
	req := makeRequest(upstream.URL+"/readme.txt", nil)
	rec := httptest.NewRecorder()
	handleRequest(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Errorf("expected non-403 for .txt, got %d (body=%q)", rec.Code, rec.Body.String())
	}
}
