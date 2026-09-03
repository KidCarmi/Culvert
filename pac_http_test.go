package main

// pac_http_test.go — HTTP delivery + validation contract for the PAC
// foundation (PR "pac: add validated deterministic PAC compilation
// foundation"): strong ETag + conditional GET, the two cache modes
// (configured host vs request-Host fallback), the version header, strict
// validation of POST /api/pac-config, and the config-import PAC
// pre-validation gate.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
)

// resetPACHTTPGlobals snapshots/restores the process-wide pacStore so these
// tests stay hermetic under -shuffle -count=2.
func resetPACHTTPGlobals(t *testing.T) {
	t.Helper()
	orig := pacStore.Snapshot()
	t.Cleanup(func() { pacStore.Restore(orig) })
}

func pacGET(host, ifNoneMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/proxy.pac", http.NoBody)
	req.Host = host
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	rec := httptest.NewRecorder()
	servePACFile(rec, req)
	return rec
}

// ─── ETag + conditional GET (configured-host mode) ────────────────────────────

func TestServePACFile_ETagAnd304_ConfiguredHost(t *testing.T) {
	resetPACHTTPGlobals(t)
	if err := pacStore.Set(PACConfig{ProxyHost: "proxy.corp.example", ProxyPort: 3128}); err != nil {
		t.Fatal(err)
	}

	first := pacGET("ui.corp.example:9090", "")
	if first.Code != http.StatusOK {
		t.Fatalf("GET: got %d", first.Code)
	}
	etag := first.Header().Get("ETag")
	if !regexp.MustCompile(`^"[0-9a-f]{64}"$`).MatchString(etag) {
		t.Fatalf("ETag not a quoted sha256: %q", etag)
	}
	if cc := first.Header().Get("Cache-Control"); cc != "max-age=0, must-revalidate" {
		t.Errorf("configured-host Cache-Control = %q, want revalidation caching", cc)
	}
	if lm := first.Header().Get("Last-Modified"); lm == "" {
		t.Error("configured-host mode should send Last-Modified")
	}

	// Conditional revalidation: matching If-None-Match → 304, empty body.
	second := pacGET("ui.corp.example:9090", etag)
	if second.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match match: got %d, want 304", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Error("304 must not carry a body")
	}
	if second.Header().Get("ETag") != etag {
		t.Error("304 must repeat the ETag")
	}

	// Weak-validator and list forms must also match.
	if rec := pacGET("ui.corp.example:9090", `W/`+etag); rec.Code != http.StatusNotModified {
		t.Errorf("weak If-None-Match: got %d, want 304", rec.Code)
	}
	if rec := pacGET("ui.corp.example:9090", `"nope", `+etag); rec.Code != http.StatusNotModified {
		t.Errorf("list If-None-Match: got %d, want 304", rec.Code)
	}

	// Stale ETag → full 200 body.
	if rec := pacGET("ui.corp.example:9090", `"deadbeef"`); rec.Code != http.StatusOK {
		t.Errorf("stale If-None-Match: got %d, want 200", rec.Code)
	}

	// Config change → new ETag.
	if err := pacStore.Set(PACConfig{ProxyHost: "proxy.corp.example", ProxyPort: 3129}); err != nil {
		t.Fatal(err)
	}
	if rec := pacGET("ui.corp.example:9090", etag); rec.Code != http.StatusOK {
		t.Errorf("changed config must invalidate the old ETag; got %d", rec.Code)
	}
}

// ─── Fallback mode: per-Host body ⇒ no shared caching ─────────────────────────

func TestServePACFile_FallbackMode_NoStoreAndPerHostETag(t *testing.T) {
	resetPACHTTPGlobals(t)
	if err := pacStore.Set(PACConfig{ProxyPort: 8080}); err != nil { // no ProxyHost
		t.Fatal(err)
	}

	a := pacGET("host-a.example:9090", "")
	b := pacGET("host-b.example:9090", "")
	if cc := a.Header().Get("Cache-Control"); cc != "no-cache, no-store" {
		t.Errorf("fallback-mode Cache-Control = %q, want no-store (body varies per Host)", cc)
	}
	if a.Header().Get("Last-Modified") != "" {
		t.Error("fallback mode must not advertise Last-Modified")
	}
	if a.Header().Get("ETag") == b.Header().Get("ETag") {
		t.Error("fallback-mode ETag must differ per request host (digest of actual bytes)")
	}
	if !strings.Contains(a.Body.String(), "PROXY host-a.example:8080") {
		t.Errorf("fallback body must embed the request host:\n%s", a.Body.String())
	}
}

// ─── Version header ───────────────────────────────────────────────────────────

func TestServePACFile_VersionHeader(t *testing.T) {
	resetPACHTTPGlobals(t)
	if err := pacStore.Set(PACConfig{ProxyHost: "proxy.example", ProxyPort: 8080}); err != nil {
		t.Fatal(err)
	}
	rec := pacGET("ui.example:9090", "")
	v := rec.Header().Get("X-Culvert-PAC-Version")
	if !regexp.MustCompile(`^` + pac.CompilerVersion + `-[0-9a-f]{16}$`).MatchString(v) {
		t.Errorf("X-Culvert-PAC-Version = %q, want <compiler>-<digest16>", v)
	}
}

// ─── POST /api/pac-config: strict validation at the API boundary ──────────────

func pacAdminPost(t *testing.T, body string, remoteIP string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, pacTestWithTokens(http.MethodPost, "/api/pac-config", body), bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteIP
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rec := httptest.NewRecorder()
	apiPACConfig(rec, req)
	return rec
}

func TestAPIPACConfig_POST_RejectsInvalidWithIssues(t *testing.T) {
	resetPACHTTPGlobals(t)
	before := pacStore.Get()

	rec := pacAdminPost(t, `{"proxyHost":"proxy.example","proxyPort":8080,`+
		`"exclusions":["good.example","192.168.0.0/33","corp.*.bad"]}`, "198.51.100.60:0")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid config: got %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Error  string                `json:"error"`
		Issues []pac.ValidationIssue `json:"issues"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("400 body not structured JSON: %v", err)
	}
	codes := map[string]bool{}
	for _, is := range resp.Issues {
		codes[is.Code] = true
		if is.Message == "" {
			t.Error("issue without actionable message")
		}
	}
	if !codes[pac.IssueInvalidCIDR] || !codes[pac.IssueInvalidWildcard] {
		t.Errorf("expected invalid_cidr + invalid_wildcard, got %+v", resp.Issues)
	}
	if got := pacStore.Get(); len(got.Exclusions) != len(before.Exclusions) {
		t.Error("rejected POST must not mutate the store")
	}
}

func TestAPIPACConfig_POST_CanonicalizesAndWarns(t *testing.T) {
	resetPACHTTPGlobals(t)

	rec := pacAdminPost(t, `{"proxyHost":"Proxy.Example","proxyPort":3128,`+
		`"exclusions":["Corp.Local.","corp.local","192.168.1.55/24"]}`, "198.51.100.61:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("valid config: got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		PACConfig
		Warnings []pac.ValidationIssue `json:"warnings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Exclusions) != 2 {
		t.Errorf("expected deduped canonical exclusions, got %v", resp.Exclusions)
	}
	if resp.Exclusions[0] != "corp.local" || resp.Exclusions[1] != "192.168.1.0/24" {
		t.Errorf("canonicalization mismatch: %v", resp.Exclusions)
	}
	warnCodes := map[string]bool{}
	for _, w := range resp.Warnings {
		warnCodes[w.Code] = true
	}
	if !warnCodes[pac.IssueDuplicateEntry] || !warnCodes[pac.IssueCIDRNormalized] {
		t.Errorf("expected duplicate + cidr_normalized warnings, got %+v", resp.Warnings)
	}
	stored := pacStore.Get()
	if len(stored.Exclusions) != 2 || stored.Exclusions[0] != "corp.local" {
		t.Errorf("store must hold the canonical form: %v", stored.Exclusions)
	}
}

// ─── Config import: PAC pre-validation gate ───────────────────────────────────

func TestConfigImport_RejectsInvalidPACBeforeMutation(t *testing.T) {
	resetPACHTTPGlobals(t)
	if err := pacStore.Set(PACConfig{ProxyHost: "keep.example", ProxyPort: 8080}); err != nil {
		t.Fatal(err)
	}

	body := `{"version":1,"pacProxyHost":"import.example","pacExclusions":["ok.example","999.999.0.0/8"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/import", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.62:0"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rec := httptest.NewRecorder()
	apiConfigImport(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("import with junk PAC: got %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_cidr") {
		t.Errorf("400 body must carry structured issues: %s", rec.Body.String())
	}
	if got := pacStore.Get(); got.ProxyHost != "keep.example" {
		t.Errorf("rejected import must not touch the PAC store, got %+v", got)
	}
}

func TestConfigImport_ValidPACStillApplies(t *testing.T) {
	resetPACHTTPGlobals(t)
	if err := pacStore.Set(PACConfig{ProxyHost: "old.example", ProxyPort: 8080}); err != nil {
		t.Fatal(err)
	}

	body := `{"version":1,"pacProxyHost":"new.example","pacExclusions":["ok.example"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/import", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.63:0"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rec := httptest.NewRecorder()
	apiConfigImport(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("valid import: got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if got := pacStore.Get(); got.ProxyHost != "new.example" {
		t.Errorf("import did not apply PAC host: %+v", got)
	}
}

// ─── Replay-path tolerance wall ───────────────────────────────────────────────

// TestConfigRollback_JunkPACEntriesStillApply walls the reviewed strictness
// boundary: config-version rollback replays historical PACConfig data through
// the TOLERANT Store.Set (which discards nothing and whose error is ignored
// by applyConfigBackup), so a snapshot holding junk entries that predate
// strict validation must still apply and still serve a working PAC file
// (junk dropped from the generated script only). Anyone re-adding validation
// to Store.Set breaks this test — that strictness belongs at the API
// boundary only.
func TestConfigRollback_JunkPACEntriesStillApply(t *testing.T) {
	resetPACHTTPGlobals(t)

	junk := PACConfig{
		ProxyHost:  "proxy.example",
		ProxyPort:  8080,
		Exclusions: []string{"good.example", "999.999.0.0/99", "corp.*.bad", ""},
	}
	if err := pacStore.Set(junk); err != nil {
		t.Fatalf("tolerant Set must accept historical junk: %v", err)
	}
	if got := pacStore.Get(); len(got.Exclusions) != 4 {
		t.Fatalf("Set must store data verbatim (no silent filtering): %v", got.Exclusions)
	}

	rec := pacGET("ui.example:9090", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("PAC must keep serving with junk in store: %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"good.example"`) {
		t.Error("valid entry must survive junk neighbors in generated PAC")
	}
	if strings.Contains(body, "999.999") || strings.Contains(body, "corp.*.bad") {
		t.Error("junk entries must be dropped from the generated PAC, not emitted")
	}
}
