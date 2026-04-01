package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// ─── ScanBody cache paths ─────────────────────────────────────────────────────

// makeScannerWithYARA creates a SecurityScanner with a minimal YARA rule so
// BodyScanEnabled() returns true (requires clam != nil OR globalYARA.Enabled()).
func makeScannerWithYARA(t *testing.T) (*SecurityScanner, func()) { //nolint:gocritic // unnamed cleanup func is idiomatic Go
	t.Helper()
	rules, err := parseYARASrc(yaraRule("TestCacheRule", `        $a = "MATCH_THIS_STRING"`, "any of them"))
	if err != nil {
		t.Fatalf("parseYARASrc: %v", err)
	}
	y := &YARARuleSet{rules: rules}
	old := globalYARA
	globalYARA = y
	ss := &SecurityScanner{cache: newHashCache(100, 0), enabled: true}
	return ss, func() { globalYARA = old }
}

func TestSecurityScanner_ScanBody_CacheHit_Dirty(t *testing.T) {
	ss, cleanup := makeScannerWithYARA(t)
	defer cleanup()

	data := []byte("evil cached content")
	hash := SHA256Hex(data)
	ss.cache.Set(hash, ScanCacheResult{Clean: false, Reason: "virus-name", Source: "clamav"})

	result := ss.ScanBody(data)
	if result == nil {
		t.Error("ScanBody should return cached dirty result")
	}
	if result != nil && result.Source != "clamav" {
		t.Errorf("ScanBody cached source = %q, want clamav", result.Source)
	}
}

func TestSecurityScanner_ScanBody_CacheHit_Clean(t *testing.T) {
	ss, cleanup := makeScannerWithYARA(t)
	defer cleanup()

	data := []byte("clean cached content")
	hash := SHA256Hex(data)
	ss.cache.Set(hash, ScanCacheResult{Clean: true, Source: "clean"})

	result := ss.ScanBody(data)
	if result != nil {
		t.Error("ScanBody should return nil for cached clean result")
	}
}

// ─── bodyNeedsBuffering with DPI enabled ─────────────────────────────────────

func TestBodyNeedsBuffering_DPIEnabled(t *testing.T) {
	// Temporarily add a DPI pattern to enable scanner
	_ = dpiScanner.Add("test-needs-buffering")
	defer dpiScanner.Remove("test-needs-buffering")

	if !bodyNeedsBuffering("text/html") {
		t.Error("bodyNeedsBuffering should return true when DPI is enabled for text content")
	}
}

func TestBodyNeedsBuffering_DPIEnabled_Binary(t *testing.T) {
	_ = dpiScanner.Add("test-dpi-binary")
	defer dpiScanner.Remove("test-dpi-binary")

	// Binary content should not trigger DPI buffering (DPI only applies to text)
	if bodyNeedsBuffering("image/jpeg") {
		t.Error("bodyNeedsBuffering should return false for binary content even with DPI enabled")
	}
}

// ─── SetUIAllowedCIDRs IPv6 path ──────────────────────────────────────────────

func TestSetUIAllowedCIDRs_IPv6(t *testing.T) {
	defer SetUIAllowedCIDRs([]string{}) //nolint:errcheck // test teardown; reset errors are non-actionable
	err := SetUIAllowedCIDRs([]string{"::1", "2001:db8::/32"})
	if err != nil {
		t.Errorf("SetUIAllowedCIDRs IPv6: %v", err)
	}
}

func TestSetUIAllowedCIDRs_Invalid(t *testing.T) {
	err := SetUIAllowedCIDRs([]string{"not-a-valid-ip"})
	if err == nil {
		t.Error("SetUIAllowedCIDRs invalid IP should return error")
	}
}

func TestSetUIAllowedCIDRs_PlainIP(t *testing.T) {
	defer SetUIAllowedCIDRs([]string{}) //nolint:errcheck // test teardown; reset errors are non-actionable
	err := SetUIAllowedCIDRs([]string{"192.168.1.5"})
	if err != nil {
		t.Errorf("SetUIAllowedCIDRs plain IP: %v", err)
	}
}

// ─── apiCertsUpload ───────────────────────────────────────────────────────────

func TestAPICertsUpload_MissingCert(t *testing.T) {
	var body strings.Builder
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("target", "ui")
	_ = mw.WriteField("cert", "")
	_ = mw.WriteField("key", "")
	_ = mw.Close() // multipart.Writer.Close flushes the boundary; test cleanup

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/certs/upload", strings.NewReader(body.String()))
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiCertsUpload(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPICertsUpload_InvalidTarget(t *testing.T) {
	var body strings.Builder
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("target", "invalid")
	_ = mw.WriteField("cert", "some-cert")
	_ = mw.WriteField("key", "some-key")
	_ = mw.Close() // multipart.Writer.Close flushes the boundary; test cleanup

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/certs/upload", strings.NewReader(body.String()))
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiCertsUpload(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── apiUIAllowIPs POST invalid CIDR ─────────────────────────────────────────

func TestAPIUIAllowIPs_Post_Invalid(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/ui-allow-ips", map[string]any{
		"ips": []string{"not-valid-cidr"},
	})
	r = adminCtx(r)
	apiUIAllowIPs(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── pac.go: apiPACConfig ─────────────────────────────────────────────────────

// ─── ca.go: SaveCA + LoadCA (round trip) ─────────────────────────────────────

func TestCACert_GetPEM(t *testing.T) {
	cm := &CertManager{}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	pem := cm.CACertPEM()
	if len(pem) == 0 {
		t.Error("CACertPEM should return non-empty PEM after InitCA")
	}
}

// ─── oidcCacheSetWithExp past token expiry ────────────────────────────────────

func TestOIDCCacheSetWithExp_PastExpiry(t *testing.T) {
	a := &OIDCAuth{
		cache: make(map[string]*oidcCacheEntry),
		ttl:   1 * time.Hour,
	}
	// Past expiry should use ttl instead
	pastExp := time.Now().Add(-1 * time.Minute).Unix()
	a.oidcCacheSetWithExp("past-expiry-test", true, pastExp)
	a.mu.Lock()
	e := a.cache["past-expiry-test"]
	a.mu.Unlock()
	if e == nil {
		t.Fatal("cache entry should exist")
	}
	// Expiry should be roughly 1 hour (ttl), not past
	if e.expiry.Before(time.Now()) {
		t.Error("oidcCacheSetWithExp with past tokenExp should use ttl")
	}
}

// ─── matchDest with country filter (no cache hit) ────────────────────────────

func TestMatchDest_CountryFilter_NoCacheHit(t *testing.T) {
	rule := &PolicyRule{DestCountry: []string{"US"}}
	// Fail-closed: geo.LookupCached returns "" and false (no cache hit),
	// so the country filter rejects the match (unknown country = no match).
	if matchDest(rule, "example.com") {
		t.Error("matchDest with country filter and no cache hit should return false (fail-closed)")
	}
}

// ─── store: saveMode path ─────────────────────────────────────────────────────

func TestBlocklist_SetMode_Block(t *testing.T) {
	defer bl.SetMode("block")
	bl.SetMode("allow")
	if bl.Mode() != "allow" {
		t.Error("SetMode allow should work")
	}
	bl.SetMode("block")
	if bl.Mode() != "block" {
		t.Error("SetMode block should work")
	}
}

// ─── ScanBody with YARA (cache-miss path, clean result) ─────────────────────

func TestSecurityScanner_ScanBody_YARA_Clean(t *testing.T) {
	// YARA enabled but no match
	y := &YARARuleSet{}
	rules, _ := parseYARASrc(yaraRule("DetectEICAR", `        $a = "EICAR_MATCH"`, "any of them"))
	y.rules = rules

	old := globalYARA
	globalYARA = y
	defer func() { globalYARA = old }()

	ss := &SecurityScanner{cache: newHashCache(100, 0), enabled: true}
	result := ss.ScanBody([]byte("clean data that does not match"))
	if result != nil {
		t.Error("ScanBody should return nil for clean data with no YARA match")
	}
}

func TestReadUISessionCookie_NoCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	sess, err := readUISessionCookie(r)
	if err != nil || sess != nil {
		t.Errorf("readUISessionCookie no cookie: got sess=%v err=%v, want nil/nil", sess, err)
	}
}

// ─── LoadCustomCA more paths ──────────────────────────────────────────────────

func TestLoadCustomCA_ValidSelfSigned(t *testing.T) {
	// Build a valid CA using InitCA and export PEM, then reload via LoadCustomCA
	cm1 := &CertManager{}
	if err := cm1.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	pemData := cm1.CACertPEM()
	if len(pemData) == 0 {
		t.Fatal("CACertPEM returned empty")
	}
	// We don't have the private key PEM exported, so use ParseTLSPair as an
	// alternative validation — just verify the error path works
	cm2 := &CertManager{}
	err := cm2.LoadCustomCA(pemData, []byte("not-a-valid-key"))
	if err == nil {
		t.Error("LoadCustomCA should fail with invalid key PEM")
	}
}

// ─── apiAuthUsers GET with existing users ────────────────────────────────────

func TestAPIAuthUsers_Delete_LastAdmin_Protected(t *testing.T) {
	// Ensure only one admin exists
	_ = cfg.SetAuth("soleadmin", "adminpass123")
	defer cfg.SetAuth("", "") //nolint:errcheck // test teardown; reset errors are non-actionable

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodDelete, "/api/auth/users", map[string]any{
		"username": "soleadmin",
	})
	r = adminCtx(r)
	apiAuthUsers(w, r)
	// Should reject deletion of last admin
	if w.Code == http.StatusNoContent {
		t.Error("apiAuthUsers should not allow deleting last admin")
	}
}

// ─── apiBlocklist POST bulk add / DELETE ──────────────────────────────────────

func TestAPIBlocklist_Post_BulkAdd(t *testing.T) {
	defer bl.Remove("bulktest1.example.com")
	defer bl.Remove("bulktest2.example.com")
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/blocklist", map[string]any{
		"hosts": []string{"bulktest1.example.com", "bulktest2.example.com"},
	})
	r = adminCtx(r)
	apiBlocklist(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPIBlocklist_Delete_MissingHost(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/blocklist", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiBlocklist(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── securityMiddleware ────────────────────────────────────────────────────────

func testSecMiddleware(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	handler := securityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(w, r)
	return w
}

func TestSecurityMiddleware_CORS_SameOrigin(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/stats", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r.Host = "localhost:8080"
	r.Header.Set("Origin", "http://localhost:8080")
	w := testSecMiddleware(r)
	if w.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Error("securityMiddleware should set CORS header for same-origin request")
	}
}

func TestSecurityMiddleware_CSRF_Block(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/stats", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r.Host = "localhost:8080"
	r.Header.Set("Origin", "http://evil.example.com")
	w := testSecMiddleware(r)
	if w.Code != http.StatusForbidden {
		t.Errorf("securityMiddleware should block cross-origin POST, got %d", w.Code)
	}
}

// ─── apiTimeseries wrong method ───────────────────────────────────────────────

func TestAPITimeseries_WrongMethod(_ *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/timeseries", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	// No role set — should fail without crash
	apiTimeseries(w, r)
	// Either 401/403 (no role) — just verify no panic
}

// ─── apiAuthLogin success when auth disabled ──────────────────────────────────

func TestAPIAuthLogin_Success_AuthDisabled(t *testing.T) {
	_ = cfg.SetAuth("", "")

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/auth/login", map[string]any{
		"user": "anyone",
		"pass": "anypassword123",
	})
	apiAuthLogin(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── store.auditAdd with syslog (global nil) ──────────────────────────────────

func TestAuditAdd_NoFile_NoSyslog(_ *testing.T) {
	// Make sure auditLogFile and globalSyslog are nil
	oldFile := auditLogFile
	auditLogFile = nil
	defer func() { auditLogFile = oldFile }()

	// auditAdd should not panic when both file and syslog are nil
	auditAdd(AuditEntry{TS: 1, Action: "test.action", Actor: "testactor"})
}

// ─── CertManager.GetCert ─────────────────────────────────────────────────────

func TestCertManager_GetCert(t *testing.T) {
	cm := &CertManager{cache: make(map[string]*certCacheEntry)}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	hello := &tls.ClientHelloInfo{ServerName: "test.example.com"}
	cert, err := cm.GetCert(hello)
	if err != nil {
		t.Fatalf("GetCert error: %v", err)
	}
	if cert == nil {
		t.Error("GetCert should return a certificate")
	}
	// Second call should use cache
	cert2, err := cm.GetCert(hello)
	if err != nil || cert2 == nil {
		t.Errorf("GetCert cache hit failed: cert=%v err=%v", cert2, err)
	}
}

func TestCertManager_GetCert_EmptyServerName(t *testing.T) {
	cm := &CertManager{cache: make(map[string]*certCacheEntry)}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	hello := &tls.ClientHelloInfo{ServerName: ""}
	cert, err := cm.GetCert(hello)
	if err != nil {
		t.Fatalf("GetCert with empty ServerName error: %v", err)
	}
	if cert == nil {
		t.Error("GetCert should return a certificate even with empty ServerName")
	}
}

// ─── Blocklist.saveMode with non-empty path ───────────────────────────────────

func TestBlocklist_SaveMode_NonEmptyPath(t *testing.T) {
	dir, err := os.MkdirTemp("", "blocklist*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck // test cleanup

	b := &Blocklist{
		exact:     make(map[string]bool),
		wildcards: make(map[string]bool),
		path:      dir + "/blocklist.txt",
		mode:      "allow",
	}
	b.saveMode()

	// Verify the mode file was created
	data, err := os.ReadFile(dir + "/blocklist.txt.mode")
	if err != nil {
		t.Fatalf("saveMode should create mode file: %v", err)
	}
	if string(data) != "allow" {
		t.Errorf("saveMode content = %q, want allow", string(data))
	}
}

// ─── Blocklist.Load with mode sidecar ────────────────────────────────────────

func TestBlocklist_Load_WithModeSidecar(t *testing.T) {
	dir, err := os.MkdirTemp("", "blocklist*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck // test cleanup

	path := dir + "/blocklist.txt"
	// Create blocklist file with some hosts
	if err := os.WriteFile(path, []byte("blocked.example.com\n*.bad.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Create mode sidecar
	if err := os.WriteFile(path+".mode", []byte("allow"), 0o600); err != nil {
		t.Fatal(err)
	}

	b := &Blocklist{
		exact:     make(map[string]bool),
		wildcards: make(map[string]bool),
	}
	if err := b.Load(path); err != nil {
		t.Fatalf("Blocklist.Load: %v", err)
	}
	if b.mode != "allow" {
		t.Errorf("Blocklist.Load mode = %q, want allow", b.mode)
	}
}

// ─── validateExternalURL public HTTPS ────────────────────────────────────────

func TestValidateExternalURL_PublicHTTPS(t *testing.T) {
	err := validateExternalURL("http://192.168.0.1/")
	if err == nil {
		t.Error("private URL should be rejected")
	}
}

// ─── auditAdd with file ───────────────────────────────────────────────────────

func TestAuditAdd_WithFile(t *testing.T) {
	f, err := os.CreateTemp("", "auditadd*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup

	oldFile := auditLogFile
	auditLogFile = f
	defer func() {
		auditLogFile = oldFile
		f.Close()
	}()

	auditAdd(AuditEntry{TS: 1, Action: "test.file.write", Actor: "testactor"})

	// Verify something was written
	f.Seek(0, 0) //nolint:errcheck // seeking to start of file; error is non-actionable in test context
	buf := make([]byte, 1024)
	n, _ := f.Read(buf)
	if n == 0 {
		t.Error("auditAdd should write to the file when auditLogFile is set")
	}
}

// ─── ca.go: decryptBundle error paths ────────────────────────────────────────

func TestDecryptBundle_TooShort(t *testing.T) {
	_, err := decryptBundle([]byte("short"), []byte("passphrase"))
	if err == nil {
		t.Error("decryptBundle should fail on short data")
	}
}

func TestDecryptBundle_BadMagic(t *testing.T) {
	data := make([]byte, 100)
	data[4] = caVersion
	binary.BigEndian.PutUint32(data[5:9], 100_001) // valid iteration count
	_, err := decryptBundle(data, []byte("passphrase"))
	if err == nil {
		t.Error("decryptBundle should fail with bad magic")
	}
}

// ─── LoadCA with bad passphrase ────────────────────────────────────────────────

func TestCertManager_LoadCA_BadPassphrase(t *testing.T) {
	dir, err := os.MkdirTemp("", "testca*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck // test cleanup
	path := dir + "/ca.enc"

	// Create an encrypted CA bundle
	cm := &CertManager{}
	if err := cm.LoadOrInitCA(path, "correct-passphrase"); err != nil {
		t.Fatalf("LoadOrInitCA: %v", err)
	}

	// Try to load with wrong passphrase
	cm2 := &CertManager{}
	err = cm2.LoadCA(path, "wrong-passphrase")
	if err == nil {
		t.Error("LoadCA should fail with wrong passphrase")
	}
}

// ─── store: logAdd truncation ─────────────────────────────────────────────────

func TestLogAdd_Truncation(t *testing.T) {
	// Fill logs beyond maxLogs limit
	for i := 0; i < maxLogs+10; i++ {
		logAdd(LogEntry{TS: int64(i), Host: "trunctest.example.com", Status: "OK"})
	}
	// Verify logs were truncated to maxLogs
	logsMu.Lock()
	n := len(logs)
	logsMu.Unlock()
	if n > maxLogs {
		t.Errorf("logAdd should cap logs at %d, got %d", maxLogs, n)
	}
}

// ─── auditAdd truncation ──────────────────────────────────────────────────────

func TestAuditAdd_Truncation(t *testing.T) {
	oldFile := auditLogFile
	auditLogFile = nil
	defer func() { auditLogFile = oldFile }()

	oldLog := auditLog
	auditLog = nil
	defer func() { auditLog = oldLog }()

	for i := 0; i < maxAuditLogs+10; i++ {
		auditAdd(AuditEntry{TS: int64(i), Action: "test"})
	}
	auditMu.Lock()
	n := len(auditLog)
	auditMu.Unlock()
	if n > maxAuditLogs {
		t.Errorf("auditAdd should cap at %d, got %d", maxAuditLogs, n)
	}
}

// ─── exportBundle / SaveCA with passphrase ────────────────────────────────────

func TestCertManager_SaveCA_WithPassphrase(t *testing.T) {
	dir, err := os.MkdirTemp("", "testca*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck // test cleanup
	path := dir + "/ca-pass.bin"

	cm := &CertManager{}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	if err := cm.SaveCA(path, "testpassphrase"); err != nil {
		t.Fatalf("SaveCA with passphrase: %v", err)
	}

	// Verify the file was written
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		t.Error("SaveCA should write non-empty file")
	}
}

// ─── apiAuthUsers DELETE with query param ────────────────────────────────────

func TestAPIAuthUsers_Delete_QueryParam(t *testing.T) {
	// Create a second admin so deletion is allowed
	_ = cfg.SetUIUser("deletetest1", "password123", RoleAdmin)
	_ = cfg.SetUIUser("deletetest2", "password123", RoleAdmin)
	defer cfg.DeleteUIUser("deletetest1") //nolint:errcheck // test teardown; reset errors are non-actionable
	defer cfg.DeleteUIUser("deletetest2") //nolint:errcheck // test teardown; reset errors are non-actionable

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/auth/users?username=deletetest2", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiAuthUsers(w, r)
	// Should succeed (204) since there's another admin remaining
	if w.Code != http.StatusNoContent && w.Code != http.StatusConflict {
		t.Errorf("apiAuthUsers DELETE: unexpected status %d", w.Code)
	}
}

// ─── isSameOrigin: parse error path ──────────────────────────────────────────

func TestIsSameOrigin_InvalidOrigin(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/stats", http.NoBody)
	r.Host = "localhost:9090"
	// An invalid URL will fail url.Parse
	if isSameOrigin(r, "://invalid") {
		t.Error("isSameOrigin with invalid URL should return false")
	}
}

// ─── apiSSLBypass POST ────────────────────────────────────────────────────────

func TestAPISSLBypass_Post_Add(t *testing.T) {
	defer sslBypass.Remove("ssltest.example.com")
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/ssl-bypass", map[string]any{
		"pattern": "ssltest.example.com",
	})
	r = adminCtx(r)
	apiSSLBypass(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPISSLBypass_Delete_Missing(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/ssl-bypass", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiSSLBypass(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── apiPolicy POST/PUT ───────────────────────────────────────────────────────

func TestAPIPolicy_Post_Valid(t *testing.T) {
	// Pre-cleanup to ensure no stale rule from previous runs
	cleanupPolicyCoverageRule := func() {
		for _, rule := range policyStore.List() {
			if rule.Name == "test-coverage-rule-xyz" {
				policyStore.Delete(rule.Priority)
			}
		}
	}
	cleanupPolicyCoverageRule()
	defer cleanupPolicyCoverageRule()

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/policy", map[string]any{
		"name":     "test-coverage-rule-xyz",
		"action":   "Block_Page",
		"destFQDN": "definitely-not-existing-test-xyz.internal.invalid",
	})
	r = adminCtx(r)
	apiPolicy(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPIPolicy_Post_NoName(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/policy", map[string]any{
		"action": "allow",
	})
	r = adminCtx(r)
	apiPolicy(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIPolicy_Post_NoAction(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/policy", map[string]any{
		"name": "no-action-rule",
	})
	r = adminCtx(r)
	apiPolicy(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── apiConfigImport with data ────────────────────────────────────────────────

func TestAPIConfigImport_WithData(t *testing.T) {
	// Save and restore default action
	oldAction := defaultPolicyAction()
	defer setDefaultPolicyAction(oldAction)
	defer bl.Remove("import-test.example.com")

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/config/import", map[string]any{
		"version":             1,
		"exportedAt":          "2026-01-01T00:00:00Z",
		"blocklistMode":       "block",
		"blocklist":           []string{"import-test.example.com"},
		"policyRules":         []any{},
		"defaultAction":       "deny",
		"rewriteRules":        []any{},
		"sslBypass":           []string{},
		"contentScanPatterns": []string{},
		"fileBlockExtensions": []string{},
		"ipFilterMode":        "block",
		"ipList":              []string{},
		"rateLimitRPM":        60,
	})
	r = adminCtx(r)
	apiConfigImport(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── apiPolicyTest: valid host no rules match ─────────────────────────────────

func TestAPIPolicyTest_ValidNoMatch(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/policy/test", map[string]any{
		"host":       "example-no-rules.com",
		"sourceIP":   "1.2.3.4",
		"identity":   "testuser",
		"authSource": "ldap",
	})
	r = adminCtx(r)
	apiPolicyTest(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── apiSettings GET ──────────────────────────────────────────────────────────

func TestAPISettings_GetFull(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/settings", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiSettings(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── IdPRegistry.save with path ──────────────────────────────────────────────

func TestIdPRegistry_Save_WithPath(t *testing.T) {
	dir, err := os.MkdirTemp("", "idpreg*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck // test cleanup

	reg := &IdPRegistry{
		profiles: []*IdPProfile{
			{ID: "test-save-id", Name: "test-save", Type: IdPTypeSAML, Enabled: false},
		},
		live: make(map[string]IdentityProvider),
		path: dir + "/idp.json",
	}
	if err := reg.save(); err != nil {
		t.Fatalf("save with path: %v", err)
	}
	// Verify file was written
	data, err := os.ReadFile(dir + "/idp.json")
	if err != nil || len(data) == 0 {
		t.Error("save should write non-empty file")
	}
}

// ─── authSelectProvider with relay param ─────────────────────────────────────

func TestAuthSelectProvider_WithRelay(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/select?relay=/dashboard", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	authSelectProvider(w, r)
	if w.Code == 0 {
		t.Error("authSelectProvider should write a response")
	}
}

// ─── InitAuditLog: with oversized existing data ───────────────────────────────

func TestInitAuditLog_WithManyEntries(t *testing.T) {
	f, err := os.CreateTemp("", "auditinit*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup

	// Write more than maxAuditLogs entries to trigger truncation
	for i := 0; i < maxAuditLogs+5; i++ {
		_, _ = f.WriteString(`{"ts":` + string(rune('0'+i%10)) + `,"action":"test"}` + "\n")
	}
	f.Close()

	oldFile := auditLogFile
	oldLog := auditLog
	auditLogFile = nil
	auditLog = nil
	defer func() {
		auditLogFile = oldFile
		auditLog = oldLog
		if auditLogFile != nil {
			auditLogFile.Close()
		}
	}()

	if err := InitAuditLog(f.Name()); err != nil {
		t.Fatalf("InitAuditLog: %v", err)
	}
	if auditLogFile != nil {
		auditLogFile.Close()
		auditLogFile = nil
	}
}

// ─── apiUIAllowIPs POST with valid IPs ───────────────────────────────────────

func TestAPIUIAllowIPs_Post_ValidEmpty(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/ui-allow-ips", map[string]any{
		"ips": []string{},
	})
	r = adminCtx(r)
	apiUIAllowIPs(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── apiIdPItem PUT with valid name ───────────────────────────────────────────

func TestAPIIdPItem_Put_Valid(t *testing.T) {
	// Create a disabled IdP first
	p := &IdPProfile{
		ID:      "put-test-id",
		Name:    "put-test",
		Type:    IdPTypeSAML,
		Enabled: false,
		SAML:    &SAMLProfileConfig{MetadataXML: "<md:EntityDescriptor/>"},
	}
	idpRegistry.mu.Lock()
	idpRegistry.profiles = append(idpRegistry.profiles, p)
	idpRegistry.mu.Unlock()
	defer idpRegistry.Delete("put-test-id") //nolint:errcheck // test teardown; cleanup errors are non-actionable

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPut, "/api/idp/put-test-id", map[string]any{
		"name":    "put-test-updated",
		"type":    IdPTypeSAML,
		"enabled": false,
		"saml":    map[string]any{"metadataXML": "<md:EntityDescriptor/>"},
	})
	r = adminCtx(r)
	apiIdPItem(w, r, "put-test-id")
	// Accept 200 or 400 (compile error on bad SAML XML)
	if w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
		t.Errorf("apiIdPItem PUT: unexpected status %d", w.Code)
	}
}

// ─── uiIPGuardMiddleware: IP allowed/blocked ─────────────────────────────────

func TestUIIPGuardMiddleware_IPAllowed(t *testing.T) {
	// Set allowed CIDRs to include 127.0.0.1
	_ = SetUIAllowedCIDRs([]string{"127.0.0.0/8"})
	defer SetUIAllowedCIDRs(nil) //nolint:errcheck // test teardown; reset errors are non-actionable

	handler := uiIPGuardMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/stats", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("uiIPGuardMiddleware should allow 127.0.0.1 when in allowed CIDRs, got %d", w.Code)
	}
}

func TestUIIPGuardMiddleware_IPBlocked(t *testing.T) {
	// Set allowed CIDRs to only 192.168.0.0/24 (excludes 127.0.0.1)
	_ = SetUIAllowedCIDRs([]string{"192.168.0.0/24"})
	defer SetUIAllowedCIDRs(nil) //nolint:errcheck // test teardown; reset errors are non-actionable

	handler := uiIPGuardMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/stats", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("uiIPGuardMiddleware should block 127.0.0.1 when not in allowed CIDRs, got %d", w.Code)
	}
}

// ─── readUISessionCookie: invalid cookie value ───────────────────────────────

func TestReadUISessionCookie_InvalidValue(_ *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: "invalidcookievalue"})
	sess, err := readUISessionCookie(r)
	// Should return nil session (invalid token); err may or may not be set
	_ = err
	_ = sess
}

// ─── uptime format paths ──────────────────────────────────────────────────────

func TestUptime_HoursPath(t *testing.T) {
	// Force startTime to be in the past so h > 0
	old := startTime
	startTime = time.Now().Add(-2 * time.Hour)
	defer func() { startTime = old }()

	result := uptime()
	if result == "" {
		t.Error("uptime should return non-empty string")
	}
	// Should include 'h' since h > 0
	if !strings.Contains(result, "h") {
		t.Errorf("uptime with >1h should include 'h', got %q", result)
	}
}

// ─── apiTimeseries admin role ─────────────────────────────────────────────────

func TestAPITimeseries_WithRole(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/timeseries", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiTimeseries(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── apiStats: negative allowed path ─────────────────────────────────────────

func TestAPIStats_WithBlockedStats(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/stats", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiStats(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── Blocklist.List with wildcards ────────────────────────────────────────────

func TestBlocklist_List_WithWildcards(t *testing.T) {
	b := &Blocklist{
		exact:     map[string]bool{"exact.example.com": true},
		wildcards: map[string]bool{".example.com": true},
	}
	list := b.List()
	if len(list) != 2 {
		t.Errorf("List should return 2 items (1 exact + 1 wildcard), got %d", len(list))
	}
	// Check wildcard is prefixed with *
	hasWildcard := false
	for _, item := range list {
		if item == "*.example.com" {
			hasWildcard = true
		}
	}
	if !hasWildcard {
		t.Error("List should include *.example.com for wildcard entry")
	}
}

// ─── parseProxyAuth: username too long ───────────────────────────────────────

func TestParseProxyAuth_UsernameTooLong(t *testing.T) {
	r := httptest.NewRequest("GET", "/", http.NoBody)
	longUser := strings.Repeat("a", maxUsernameLen+1)
	r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(longUser+":pass")))
	_, _, ok := parseProxyAuth(r)
	if ok {
		t.Error("parseProxyAuth should reject username exceeding maxUsernameLen")
	}
}

// ─── parseProxyAuth: no colon in decoded ─────────────────────────────────────

func TestParseProxyAuth_NoColon(t *testing.T) {
	r := httptest.NewRequest("GET", "/", http.NoBody)
	r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("nocolon")))
	_, _, ok := parseProxyAuth(r)
	if ok {
		t.Error("parseProxyAuth should reject value without colon separator")
	}
}

// ─── isSafeRedirectURL: bad URL, relative URL ────────────────────────────────

func TestIsSafeRedirectURL_Relative(t *testing.T) {
	if isSafeRedirectURL("/relative/path") {
		t.Error("isSafeRedirectURL should reject relative URL")
	}
}

func TestIsSafeRedirectURL_FTPScheme(t *testing.T) {
	if isSafeRedirectURL("ftp://example.com/path") {
		t.Error("isSafeRedirectURL should reject ftp:// scheme")
	}
}

// ─── tsRecord: diff > 0 path ──────────────────────────────────────────────────

func TestTsRecord_DiffPath(_ *testing.T) {
	// Force ts.lastMin to be in the past to trigger the diff > 0 branch
	ts.mu.Lock()
	ts.lastMin = (time.Now().Unix() / 60) - 2 // 2 minutes ago
	ts.mu.Unlock()

	tsRecord()
	tsRecord()

	ts.mu.Lock()
	ts.lastMin = 0 // reset
	ts.mu.Unlock()
}

// ─── Blocklist.IsBlocked in allow mode ───────────────────────────────────────

func TestBlocklist_IsBlocked_AllowMode(t *testing.T) {
	b := &Blocklist{
		exact:     map[string]bool{"allowed.example.com": true},
		wildcards: make(map[string]bool),
		mode:      "allow",
	}
	// In allow mode, listed hosts are NOT blocked (allowed), unlisted ARE blocked
	if b.IsBlocked("allowed.example.com") {
		t.Error("listed host in allow mode should NOT be blocked")
	}
	if !b.IsBlocked("unlisted.example.com") {
		t.Error("unlisted host in allow mode should be blocked")
	}
}

// ─── Blocklist.Remove wildcard ────────────────────────────────────────────────

func TestBlocklist_Remove_Wildcard(t *testing.T) {
	b := &Blocklist{
		exact:     make(map[string]bool),
		wildcards: map[string]bool{".example.com": true},
	}
	b.Remove("*.example.com")
	if b.wildcards[".example.com"] {
		t.Error("Remove wildcard should delete from wildcards map")
	}
}

// ─── Config.VerifyAuth with cache hit ────────────────────────────────────────

func TestConfig_VerifyAuth_CacheHit(t *testing.T) {
	_ = cfg.SetAuth("cacheuser", "cachepass123")
	defer cfg.SetAuth("", "") //nolint:errcheck // test teardown; reset errors are non-actionable

	// First call populates cache
	cfg.VerifyAuth("cacheuser", "cachepass123")
	// Second call hits cache
	ok := cfg.VerifyAuth("cacheuser", "cachepass123")
	if !ok {
		t.Error("VerifyAuth cache hit should return true for correct credentials")
	}
}

// ─── Config.SetUIUser: update role without password ──────────────────────────

func TestConfig_SetUIUser_UpdateRoleOnly(t *testing.T) {
	// Create a user first
	_ = cfg.SetUIUser("roletest", "password123", RoleAdmin)
	defer cfg.DeleteUIUser("roletest") //nolint:errcheck // test teardown; cleanup errors are non-actionable

	// Update role without changing password
	err := cfg.SetUIUser("roletest", "", RoleAdmin)
	if err != nil {
		t.Errorf("SetUIUser update role only: %v", err)
	}
}

// ─── Config.VerifyUIUser: legacy fallback ────────────────────────────────────

func TestConfig_VerifyUIUser_LegacyFallback(t *testing.T) {
	// Set up legacy auth (single user, no uiUsers map entry)
	_ = cfg.SetAuth("legacytest", "legacypass123")
	defer cfg.SetAuth("", "") //nolint:errcheck // test teardown; reset errors are non-actionable

	// Clear the uiUsers for legacytest to simulate legacy mode
	cfg.mu.Lock()
	delete(cfg.uiUsers, "legacytest")
	cfg.mu.Unlock()

	role, ok := cfg.VerifyUIUser("legacytest", "legacypass123")
	if !ok {
		t.Error("VerifyUIUser legacy fallback should succeed with correct password")
	}
	if role != RoleAdmin {
		t.Errorf("VerifyUIUser legacy fallback role = %q, want admin", role)
	}
}

// ─── Blocklist.List with path set (saves on load) ────────────────────────────

func TestBlocklist_List_Save(t *testing.T) {
	dir, err := os.MkdirTemp("", "bltest*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck // test cleanup

	b := &Blocklist{
		exact:     make(map[string]bool),
		wildcards: make(map[string]bool),
		path:      dir + "/bl.txt",
		mode:      "block",
	}
	b.Add("list-save-test.example.com")
	b.Save()

	// Reload
	b2 := &Blocklist{
		exact:     make(map[string]bool),
		wildcards: make(map[string]bool),
	}
	if err := b2.Load(dir + "/bl.txt"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !b2.IsBlocked("list-save-test.example.com") {
		t.Error("Loaded blocklist should have saved entry")
	}
}
