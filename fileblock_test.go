package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func freshFB() *FileBlocker {
	return &FileBlocker{extensions: map[string]bool{}}
}

func TestFileBlocker_AddRemoveCount(t *testing.T) {
	fb := freshFB()
	fb.Add(".exe")
	fb.Add("dll")  // without leading dot — should normalise to ".dll"
	fb.Add(".EXE") // duplicate, case-insensitive — should not increase count

	if fb.Count() != 2 {
		t.Errorf("expected 2 extensions, got %d", fb.Count())
	}

	fb.Remove(".exe")
	if fb.Count() != 1 {
		t.Errorf("expected 1 after remove, got %d", fb.Count())
	}
	if fb.CheckPath("/file.exe") != "" {
		t.Error("expected .exe allowed after remove")
	}
}

func TestFileBlocker_CheckPath(t *testing.T) {
	fb := freshFB()
	fb.Add(".exe")
	fb.Add(".ps1")

	cases := []struct {
		path    string
		blocked bool
	}{
		{"/download/malware.exe", true},
		{"/scripts/run.ps1", true},
		{"/docs/report.pdf", false},
		{"/page/", false},        // no extension
		{"/file.EXE", true},      // case-insensitive
		{"/file.exe.txt", false}, // extension is .txt, not .exe
	}
	for _, c := range cases {
		got := fb.CheckPath(c.path) != ""
		if got != c.blocked {
			t.Errorf("CheckPath(%q) blocked=%v, want %v", c.path, got, c.blocked)
		}
	}
}

func TestFileBlocker_CheckContentDisposition(t *testing.T) {
	fb := freshFB()
	fb.Add(".exe")

	cases := []struct {
		header  string
		blocked bool
	}{
		{`attachment; filename="setup.exe"`, true},
		{`attachment; filename="report.pdf"`, false},
		{`attachment; filename="SETUP.EXE"`, true}, // case-insensitive
		{`inline`, false}, // no filename param
		{``, false},       // empty header
		{`attachment; filename="archive.tar.gz"`, false}, // .gz not blocked
	}
	for _, c := range cases {
		got := fb.CheckContentDisposition(c.header) != ""
		if got != c.blocked {
			t.Errorf("CheckContentDisposition(%q) blocked=%v, want %v", c.header, got, c.blocked)
		}
	}
}

func TestFileBlocker_CheckContentType(t *testing.T) {
	fb := freshFB()
	fb.Add(".exe")
	fb.Add(".msi")

	cases := []struct {
		ct      string
		blocked bool
		ext     string
	}{
		// Exact dangerous MIME — should block
		{"application/x-msdownload", true, ".exe"},
		{"application/x-dosexec", true, ".exe"},
		{"application/vnd.microsoft.portable-executable", true, ".exe"},
		{"application/x-msi", true, ".msi"},

		// MIME with parameters — should still block
		{"application/x-msdownload; charset=utf-8", true, ".exe"},
		{"application/x-msi; name=setup.msi", true, ".msi"},

		// Dangerous MIME but extension not in block list
		{"application/x-powershell", false, ""},
		{"application/x-bat", false, ""},

		// Safe MIME types — should not block
		{"text/html", false, ""},
		{"application/json", false, ""},
		{"image/png", false, ""},
		{"application/pdf", false, ""},

		// Empty / invalid
		{"", false, ""},
		{";;;invalid", false, ""},
	}
	for _, c := range cases {
		got := fb.CheckContentType(c.ct)
		if c.blocked && got == "" {
			t.Errorf("CheckContentType(%q) expected block (ext=%s), got allowed", c.ct, c.ext)
		} else if !c.blocked && got != "" {
			t.Errorf("CheckContentType(%q) expected allowed, got blocked (ext=%s)", c.ct, got)
		} else if c.blocked && got != c.ext {
			t.Errorf("CheckContentType(%q) expected ext=%s, got %s", c.ct, c.ext, got)
		}
	}
}

func TestFileBlocker_List(t *testing.T) {
	fb := freshFB()
	fb.Add(".exe")
	fb.Add(".dll")
	list := fb.List()
	if len(list) != 2 {
		t.Errorf("expected 2 in list, got %d", len(list))
	}
}

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

// ── fileBlockConn helper ────────────────────────────────────────────────────

// closableBuffer wraps bytes.Buffer with a no-op Close for fileBlockConn.
type closableBuffer struct{ bytes.Buffer }

func (cb *closableBuffer) Close() error { return nil }

func TestFileBlockConn(t *testing.T) {
	var buf closableBuffer
	fileBlockConn(&buf, "example.com", "/download/script.ps1", ".ps1", "global ext")

	resp := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("HTTP/1.1 403")) {
		t.Errorf("expected HTTP/1.1 403 in response, got:\n%s", resp)
	}
	if !bytes.Contains(buf.Bytes(), []byte(".ps1")) {
		t.Errorf("expected .ps1 in body, got:\n%s", resp)
	}
	if !bytes.Contains(buf.Bytes(), []byte("Connection: close")) {
		t.Errorf("expected Connection: close header, got:\n%s", resp)
	}
}

// ── Fix 1: ActionAllow + file profile blocks plain HTTP ──────────────────────

func TestProxy_FileBlockPolicyProfile(t *testing.T) {
	setupProxyTest(t)

	// Ensure the built-in "Executables" profile is available (includes .ps1).
	globalProfileStore.mu.Lock()
	found := false
	for _, p := range globalProfileStore.profiles {
		if p.Name == "Executables" {
			found = true
			break
		}
	}
	if !found {
		globalProfileStore.profiles = append(globalProfileStore.profiles, &FileExtProfile{
			ID: "test-exec", Name: "Executables", Extensions: []string{".ps1", ".exe", ".bat"},
		})
	}
	globalProfileStore.mu.Unlock()

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
	globalProfileStore.mu.Lock()
	found := false
	for _, p := range globalProfileStore.profiles {
		if p.Name == "Executables" {
			found = true
			break
		}
	}
	if !found {
		globalProfileStore.profiles = append(globalProfileStore.profiles, &FileExtProfile{
			ID: "test-exec", Name: "Executables", Extensions: []string{".ps1", ".exe"},
		})
	}
	globalProfileStore.mu.Unlock()

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

// TestFileBlocker_Save_NoTmpLeak verifies the converted writer does not
// leave orphaned *.tmp.* files. fb.Add triggers fb.save internally.
func TestFileBlocker_Save_NoTmpLeak(t *testing.T) {
	dir := t.TempDir()
	fb := &FileBlocker{
		path:       filepath.Join(dir, "fileblock.json"),
		extensions: map[string]bool{},
	}
	fb.Add(".exe")
	assertNoTmpLeak(t, dir)
}
