package main

// upstream_v2_red_test.go — the 2F-C Upstream v2 RED matrix (approved 2F
// contract C4/C6/C9/C10/C11 + binding clarifications 1–2,
// docs/design/FRONTEND-MIGRATION-PLAN.md): R15–R23, R25–R26, R30–R31,
// R35–R39, R41–R42.
//
// RED-before evidence: every test was committed against the frozen 2F-B
// baseline (1e3578d9) BEFORE the implementation and fails there, because the
// baseline (a) persists raw credential-bearing URLs in admin_settings.json
// and logs a raw URL on a parse failure, (b) lets a redacted (xxxxx) import
// or a legacy re-POST overwrite/destroy a credential, (c) has no entry
// identity, revision fence, credential state or durable-before-respond
// mutation, (d) marks a new parent healthy without a probe and classifies a
// 407 as healthy, (e) exposes no effective mode and admits duplicate
// authorities, and (f) logs raw transport errors. Fault injection is
// deterministic (upstream.ProbeTransport / upstream.FallbackAlertHook seams,
// an unwritable settings path); no sleeps, no probabilistic concurrency.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

const (
	upRedIP   = "198.51.100.77"
	upRedPW   = "S3cr3t-Parent-PW-9f2a" // #nosec G101 -- test-only fake parent-proxy password
	upRedHost = "parent-a.test"
)

// upEnv isolates the process-global upstream pool, the admin-settings path and
// the data dir (credential key) for one test.
func upEnv(t *testing.T) {
	t.Helper()
	snapshotUpstreamPool(t)
	dir := t.TempDir()
	swapAdminSettingsPath(t, filepath.Join(dir, "admin_settings.json"))
	prevData := dataDir
	dataDir = dir
	pt, fh := upstream.ProbeTransport, upstream.FallbackAlertHook
	t.Cleanup(func() {
		dataDir = prevData
		upstream.ProbeTransport, upstream.FallbackAlertHook = pt, fh
	})
	upstream.ProbeTransport, upstream.FallbackAlertHook = nil, nil
	upstreamPool.Configure(nil, 5, 60*time.Second)
	applyUpstreamProxy()
}

func upReq(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader = http.NoBody
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = upRedIP + ":40011"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	registerClusterRoutes(mux)
	mux.ServeHTTP(rec, req)
	return rec
}

func upJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not JSON (%d): %q", rec.Code, rec.Body.String())
	}
	return m
}

func upGet(t *testing.T) map[string]any {
	t.Helper()
	rec := upReq(t, "GET", "/api/upstream", "")
	if rec.Code != 200 {
		t.Fatalf("GET /api/upstream: %d %s", rec.Code, rec.Body.String())
	}
	return upJSON(t, rec)
}

func upSettingsFile(t *testing.T) string {
	t.Helper()
	adminSettingsSaveWG.Wait() // the baseline saves asynchronously
	b, err := os.ReadFile(adminSettingsPath)
	if err != nil {
		return ""
	}
	return string(b)
}

func upDocRevision(t *testing.T) int64 {
	t.Helper()
	rev, _ := upGet(t)["revision"].(float64)
	return int64(rev)
}

// upV1Post is the legacy bulk POST. The revision fence is echoed only when
// the GET exposes one (the baseline has no fence and its strict decoder
// would otherwise refuse the field before reaching the defect under test).
func upV1Post(t *testing.T, proxiesJSON string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"proxies":` + proxiesJSON + `}`
	if rev, ok := upGet(t)["revision"].(float64); ok {
		body = fmt.Sprintf(`{"proxies":%s,"revision":%d}`, proxiesJSON, int64(rev))
	}
	return upReq(t, "POST", "/api/upstream", body)
}

// upSeedCredentialed configures one parent with a credential through the v2
// endpoints; on the baseline (no v2 routes) it falls back to the legacy
// credential-bearing URL POST, which is exactly the surface the matrix
// retires. Returns the entry id ("" on the baseline).
func upSeedCredentialed(t *testing.T, host, user, pw string) string {
	t.Helper()
	rec := upReq(t, "POST", "/api/upstream/entries",
		fmt.Sprintf(`{"scheme":"http","host":%q,"port":3128,"username":%q,"revision":%d}`, host, user, upDocRevision(t)))
	if rec.Code == http.StatusNotFound {
		legacy := upReq(t, "POST", "/api/upstream", fmt.Sprintf(`{"proxies":[{"url":"http://%s:%s@%s:3128"}]}`, user, pw, host))
		if legacy.Code != 200 {
			t.Fatalf("legacy seed: %d %s", legacy.Code, legacy.Body.String())
		}
		return ""
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("create entry: %d %s", rec.Code, rec.Body.String())
	}
	e, _ := upJSON(t, rec)["entry"].(map[string]any)
	id, _ := e["id"].(string)
	rev, _ := e["revision"].(float64)
	cred := upReq(t, "POST", "/api/upstream/entries/"+id+"/credential",
		fmt.Sprintf(`{"action":"replace","password":%q,"revision":%d}`, pw, int64(rev)))
	if cred.Code != 200 {
		t.Fatalf("replace credential: %d %s", cred.Code, cred.Body.String())
	}
	return id
}

func upEntry(t *testing.T, id string) map[string]any {
	t.Helper()
	entries, _ := upGet(t)["entries"].([]any)
	for _, e := range entries {
		em, _ := e.(map[string]any)
		if em["id"] == id {
			return em
		}
	}
	return nil
}

// upProxyURL is what the transport would use for the next request.
func upProxyURL(t *testing.T) *url.URL {
	t.Helper()
	req := httptest.NewRequest("GET", "http://origin.example/", http.NoBody)
	u, err := upstreamPool.ProxyFunc()(req)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

type upProbeRT struct {
	status int
	err    error
}

func (r upProbeRT) RoundTrip(req *http.Request) (*http.Response, error) {
	if r.err != nil {
		return nil, r.err
	}
	return &http.Response{StatusCode: r.status, Status: fmt.Sprintf("%d", r.status), Body: io.NopCloser(strings.NewReader("x")), Header: http.Header{}, Request: req}, nil
}

func upProbe(status int, err error) {
	upstream.ProbeTransport = func(*url.URL) http.RoundTripper { return upProbeRT{status: status, err: err} }
}

// ── R15 / R26: no plaintext credential in any stored or logged representation ──

func TestUpstreamV2_R15_R26_NoPlaintextCredentialAtRestOrInLogs(t *testing.T) {
	upEnv(t)
	upSeedCredentialed(t, upRedHost, "svc", upRedPW)
	if f := upSettingsFile(t); strings.Contains(f, upRedPW) {
		t.Fatal("admin_settings.json must never carry a plaintext parent-proxy password (legacy key must be credential-free, v2 key sealed)")
	}
	// A malformed credential-bearing URL must not be echoed into the log.
	out := captureLogger(t, func() {
		upReq(t, "POST", "/api/upstream", `{"proxies":[{"url":"http://svc:`+upRedPW+`@[bad host:3128"}]}`)
	})
	if strings.Contains(out, upRedPW) {
		t.Fatalf("log must not carry the password: %q", out)
	}
	for _, body := range []string{upReq(t, "GET", "/api/upstream", "").Body.String(), upReq(t, "GET", "/api/upstream/settings", "").Body.String()} {
		if strings.Contains(body, upRedPW) {
			t.Fatal("API body must not carry the password")
		}
	}
}

// ── R16: a redacted import preserves the credential instead of overwriting it ──

func TestUpstreamV2_R16_RedactedImportPreservesCredential(t *testing.T) {
	upEnv(t)
	upSeedCredentialed(t, upRedHost, "svc", upRedPW)
	body := `{"version":1,"upstreamProxies":[{"url":"http://svc:xxxxx@` + upRedHost + `:3128"}]}`
	req := httptest.NewRequest("POST", "/api/config/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = upRedIP + ":40012"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rec := httptest.NewRecorder()
	apiConfigImport(rec, req)
	if rec.Code != 200 {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	u := upProxyURL(t)
	if u == nil {
		t.Fatal("the parent must still be selectable after a redacted import")
	}
	if pw, _ := u.User.Password(); pw != upRedPW {
		t.Fatalf("a redacted import must preserve the real credential, got password %q", pw)
	}
}

// ── R17 / R31: a legacy re-POST never destroys or removes a credentialed entry ──

func TestUpstreamV2_R17_LegacyRepostOfRedactedListIsRefused(t *testing.T) {
	upEnv(t)
	upSeedCredentialed(t, upRedHost, "svc", upRedPW)
	proxies, _ := upGet(t)["proxies"].([]any)
	if len(proxies) != 1 {
		t.Fatalf("want one proxy, got %v", proxies)
	}
	shown, _ := proxies[0].(map[string]any)["url"].(string)
	rec := upV1Post(t, fmt.Sprintf(`[{"url":%q}]`, shown))
	if rec.Code == 200 {
		t.Fatalf("a legacy bulk POST of the listed URLs must be refused while a credential exists (got 200; the credential would be replaced by %q)", shown)
	}
	if rec.Code != http.StatusConflict || upJSON(t, rec)["code"] != "credentialed_entries_present" {
		t.Fatalf("want 409 credentialed_entries_present, got %d %s", rec.Code, rec.Body.String())
	}
	if pw, _ := upProxyURL(t).User.Password(); pw != upRedPW {
		t.Fatal("the credential must be intact after the refused re-POST")
	}
}

func TestUpstreamV2_R31_LegacyBulkOmissionCannotRemoveCredentialedEntry(t *testing.T) {
	upEnv(t)
	upSeedCredentialed(t, upRedHost, "svc", upRedPW)
	rec := upV1Post(t, `[{"url":"http://parent-b.test:3128"}]`)
	if rec.Code == 200 {
		t.Fatal("omitting a credentialed entry from a legacy bulk POST must not remove it (got 200)")
	}
	if rec.Code != http.StatusConflict || upJSON(t, rec)["code"] != "credentialed_entries_present" {
		t.Fatalf("want 409 credentialed_entries_present, got %d %s", rec.Code, rec.Body.String())
	}
	if u := upProxyURL(t); u == nil || u.Hostname() != upRedHost {
		t.Fatal("the credentialed entry must still be in the pool")
	}
}

// ── R18: an authority change never retains or rebinds a credential ──

func TestUpstreamV2_R18_AuthorityChangeWhileCredentialBoundIsRefused(t *testing.T) {
	upEnv(t)
	id := upSeedCredentialed(t, upRedHost, "svc", upRedPW)
	e := upEntry(t, id)
	if e == nil {
		t.Fatalf("entry %q not listed (v2 entries absent)", id)
	}
	rev, _ := e["revision"].(float64)
	rec := upReq(t, "PUT", "/api/upstream/entries/"+id, fmt.Sprintf(`{"scheme":"http","host":"parent-b.test","port":3128,"username":"svc","revision":%d}`, int64(rev)))
	if rec.Code != http.StatusConflict || upJSON(t, rec)["code"] != "credential_bound" {
		t.Fatalf("authority change with a bound credential must be 409 credential_bound, got %d %s", rec.Code, rec.Body.String())
	}
	if e := upEntry(t, id); e["host"] != upRedHost || e["credentialState"] != "configured" {
		t.Fatalf("entry must be unchanged and still configured: %v", e)
	}
	if u := upProxyURL(t); u == nil || u.Hostname() != upRedHost {
		t.Fatal("the credential must still bind to the original authority")
	}
}

// ── R19: derived state is never accepted from a client ──

func TestUpstreamV2_R19_ClientSuppliedCredentialStateIsRejected(t *testing.T) {
	upEnv(t)
	for _, body := range []string{
		fmt.Sprintf(`{"scheme":"http","host":%q,"port":3128,"username":"svc","credentialState":"configured","revision":%d}`, upRedHost, upDocRevision(t)),
		fmt.Sprintf(`{"scheme":"http","host":%q,"port":3128,"username":"svc","credential_configured":true,"revision":%d}`, upRedHost, upDocRevision(t)),
	} {
		rec := upReq(t, "POST", "/api/upstream/entries", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("client-supplied derived state must be 400, got %d %s", rec.Code, rec.Body.String())
		}
	}
	if entries, _ := upGet(t)["entries"].([]any); len(entries) != 0 {
		t.Fatal("nothing may be created")
	}
}

// ── R20: invalid entries are refused, never silently dropped ──

func TestUpstreamV2_R20_InvalidEntryIsRefusedNotDropped(t *testing.T) {
	upEnv(t)
	rec := upV1Post(t, `[{"url":"http://parent-b.test:3128"},{"url":"nonsense-without-scheme"}]`)
	if rec.Code == 200 {
		t.Fatalf("an invalid entry must fail the whole request, got 200: %s", rec.Body.String())
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d %s", rec.Code, rec.Body.String())
	}
	if upstreamPool.Enabled() {
		t.Fatal("a refused request must leave the pool untouched")
	}
}

// ── R21: a persistence failure is a failure with zero visible mutation ──

func TestUpstreamV2_R21_PersistFailureIsNonSuccessWithZeroMutation(t *testing.T) {
	upEnv(t)
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "missing", "deeper", "admin_settings.json"))
	rec := upV1Post(t, `[{"url":"http://parent-b.test:3128"}]`)
	if rec.Code >= 200 && rec.Code < 300 {
		t.Fatalf("a failed durable write must not be reported as success: %d", rec.Code)
	}
	if upstreamPool.Enabled() {
		t.Fatal("a failed durable write must leave the running pool unchanged")
	}
	rec = upReq(t, "POST", "/api/upstream/entries", fmt.Sprintf(`{"scheme":"http","host":"parent-b.test","port":3128,"revision":%d}`, 0))
	if rec.Code >= 200 && rec.Code < 300 {
		t.Fatalf("v2 create must not succeed on a failed durable write: %d", rec.Code)
	}
	if upstreamPool.Enabled() {
		t.Fatal("v2 create on a failed durable write must leave the running pool unchanged")
	}
}

// ── R22: concurrent edits — the loser cannot overwrite the winner ──

func TestUpstreamV2_R22_StaleRevisionLoses(t *testing.T) {
	upEnv(t)
	rec := upReq(t, "POST", "/api/upstream/entries", fmt.Sprintf(`{"scheme":"http","host":%q,"port":3128,"revision":%d}`, upRedHost, upDocRevision(t)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	e, _ := upJSON(t, rec)["entry"].(map[string]any)
	id, _ := e["id"].(string)
	rev := int64(e["revision"].(float64))
	// Two admins loaded the same revision; the first edit wins.
	win := upReq(t, "PUT", "/api/upstream/entries/"+id, fmt.Sprintf(`{"scheme":"http","host":%q,"port":3129,"revision":%d}`, upRedHost, rev))
	if win.Code != 200 {
		t.Fatalf("first edit: %d %s", win.Code, win.Body.String())
	}
	lose := upReq(t, "PUT", "/api/upstream/entries/"+id, fmt.Sprintf(`{"scheme":"http","host":%q,"port":3130,"revision":%d}`, upRedHost, rev))
	if lose.Code != http.StatusConflict {
		t.Fatalf("the stale edit must be refused 409, got %d %s", lose.Code, lose.Body.String())
	}
	m := upJSON(t, lose)
	cur, _ := m["current"].(map[string]any)
	if m["code"] != "stale" || cur == nil || cur["revision"] == nil {
		t.Fatalf("409 must be structured with the current revision: %s", lose.Body.String())
	}
	if e := upEntry(t, id); e["port"] != float64(3129) {
		t.Fatalf("the winner's edit must stand: %v", e)
	}
	none := upReq(t, "PUT", "/api/upstream/entries/"+id, fmt.Sprintf(`{"scheme":"http","host":%q,"port":3131}`, upRedHost))
	if none.Code != http.StatusPreconditionRequired {
		t.Fatalf("a missing revision must be 428, got %d", none.Code)
	}
	gone := upReq(t, "PUT", "/api/upstream/entries/01ARZ3NDEKTSV4RRFFQ69G5FAV", fmt.Sprintf(`{"scheme":"http","host":%q,"port":3131,"revision":1}`, upRedHost))
	if gone.Code != http.StatusNotFound {
		t.Fatalf("a vanished identity must be 404, got %d", gone.Code)
	}
}

// ── R23: a new entry is unprobed, never healthy by assumption ──

func TestUpstreamV2_R23_NewEntryIsUnprobed(t *testing.T) {
	upEnv(t)
	rec := upV1Post(t, `[{"url":"http://parent-b.test:3128"}]`)
	if rec.Code != 200 {
		t.Fatalf("add: %d %s", rec.Code, rec.Body.String())
	}
	entries, _ := upGet(t)["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("want one entry, got %v", entries)
	}
	probe, _ := entries[0].(map[string]any)["probe"].(map[string]any)
	if probe == nil || probe["status"] != "unprobed" {
		t.Fatalf("a new entry must be unprobed, got %v", entries[0])
	}
}

// ── R25 / R36: a missing key is unusable, never configured, never selected ──

func upSeedSealedWithoutKey(t *testing.T) string {
	t.Helper()
	id := upSeedCredentialed(t, upRedHost, "svc", upRedPW)
	if id == "" {
		t.Fatal("v2 entries absent")
	}
	// Restart the node with the credential key gone.
	if err := os.Remove(filepath.Join(dataDir, ".upstream_cred_key")); err != nil {
		t.Fatalf("remove key: %v", err)
	}
	upstreamPool.Configure(nil, 5, 60*time.Second)
	LoadAdminSettings(adminSettingsPath)
	return id
}

func TestUpstreamV2_R25_R36_MissingKeyIsUnusableAndNeverSelected(t *testing.T) {
	upEnv(t)
	id := upSeedSealedWithoutKey(t)
	e := upEntry(t, id)
	if e == nil || e["credentialState"] != "unusable" {
		t.Fatalf("a sealed credential without its key must be unusable, got %v", e)
	}
	if u := upProxyURL(t); u != nil {
		t.Fatalf("an unusable entry must never be selected or build a URL, got %v", u.Redacted())
	}
	if mode := upGet(t)["mode"]; mode != "no_eligible_parent" && mode != "direct_fallback" {
		t.Fatalf("with no eligible parent the mode must say so, got %v", mode)
	}
	if _, err := os.Stat(filepath.Join(dataDir, ".upstream_cred_key")); err == nil {
		t.Fatal("a failed key read must never mint a new key while ciphertext exists")
	}
}

// ── R30: a credentialed entry cannot be deleted ──

func TestUpstreamV2_R30_CredentialedDeleteIsRefused(t *testing.T) {
	upEnv(t)
	id := upSeedCredentialed(t, upRedHost, "svc", upRedPW)
	e := upEntry(t, id)
	if e == nil {
		t.Fatal("v2 entries absent")
	}
	rev := int64(e["revision"].(float64))
	rec := upReq(t, "DELETE", fmt.Sprintf("/api/upstream/entries/%s?revision=%d", id, rev), "")
	if rec.Code != http.StatusConflict || upJSON(t, rec)["code"] != "credential_present" {
		t.Fatalf("delete of a configured entry must be 409 credential_present, got %d %s", rec.Code, rec.Body.String())
	}
	if upEntry(t, id) == nil {
		t.Fatal("the entry must still exist")
	}
}

// ── R35: HTTP 407 is unhealthy/proxy_auth_failed, never healthy ──

func TestUpstreamV2_R35_ProxyAuth407IsUnhealthy(t *testing.T) {
	upEnv(t)
	if rec := upV1Post(t, `[{"url":"http://parent-b.test:3128"}]`); rec.Code != 200 {
		t.Fatalf("add: %d %s", rec.Code, rec.Body.String())
	}
	upProbe(http.StatusProxyAuthRequired, nil)
	upstreamPool.HealthCheck(upstream.ProbeManual)
	proxies, _ := upGet(t)["proxies"].([]any)
	if len(proxies) != 1 || proxies[0].(map[string]any)["healthy"] != false {
		t.Fatalf("a 407 must classify the parent unhealthy, got %v", proxies)
	}
	entries, _ := upGet(t)["entries"].([]any)
	probe, _ := entries[0].(map[string]any)["probe"].(map[string]any)
	if probe["status"] != "unhealthy" || probe["reason"] != "proxy_auth_failed" {
		t.Fatalf("want unhealthy/proxy_auth_failed, got %v", probe)
	}
}

// ── R37: an authority-mismatched credential is never selected ──

func TestUpstreamV2_R37_AuthorityMismatchNeverSelected(t *testing.T) {
	upEnv(t)
	id := upSeedCredentialed(t, upRedHost, "svc", upRedPW)
	if id == "" {
		t.Fatal("v2 entries absent")
	}
	// Tamper the stored document: the sealed credential now claims a
	// different authority than its entry.
	raw, _ := os.ReadFile(adminSettingsPath)
	doc := string(raw)
	if !strings.Contains(doc, `"authorityHash"`) {
		t.Fatalf("sealed credential must carry an authorityHash: %s", doc)
	}
	doc = strings.Replace(doc, `"authorityHash": "`, `"authorityHash": "deadbeef`, 1)
	if err := os.WriteFile(adminSettingsPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	upstreamPool.Configure(nil, 5, 60*time.Second)
	LoadAdminSettings(adminSettingsPath)
	if e := upEntry(t, id); e == nil || e["credentialState"] != "mismatch" {
		t.Fatalf("want credentialState mismatch, got %v", e)
	}
	if u := upProxyURL(t); u != nil {
		t.Fatalf("a mismatched entry must never be selected, got %v", u.Redacted())
	}
}

// ── R38 / R39: effective mode truth ──

func TestUpstreamV2_R38_R39_NoEligibleParentThenDirectFallbackOnce(t *testing.T) {
	upEnv(t)
	alerts := 0
	upstream.FallbackAlertHook = func(string) { alerts++ }
	if rec := upV1Post(t, `[{"url":"http://parent-b.test:3128"}]`); rec.Code != 200 {
		t.Fatalf("add: %d %s", rec.Code, rec.Body.String())
	}
	upProbe(0, errors.New("dial tcp 192.0.2.1:3128: connect: connection refused"))
	upstreamPool.HealthCheck(upstream.ProbeManual)
	if mode := upGet(t)["mode"]; mode != "no_eligible_parent" {
		t.Fatalf("zero eligible parents with no request yet must be no_eligible_parent, got %v", mode)
	}
	if alerts != 0 {
		t.Fatal("no alert before any request falls back")
	}
	if u := upProxyURL(t); u != nil {
		t.Fatal("the request must fall back to direct")
	}
	if mode := upGet(t)["mode"]; mode != "direct_fallback" {
		t.Fatalf("the first real fallback must transition to direct_fallback, got %v", mode)
	}
	upProxyURL(t)
	if alerts != 1 {
		t.Fatalf("exactly one alert per transition, got %d", alerts)
	}
	if cov, _ := upGet(t)["coverage"].(map[string]any); cov == nil || cov["summary"] != "plain_http_only" {
		t.Fatal("coverage must state plain_http_only")
	}
}

// ── R41: duplicate canonical authorities never enter the effective pool ──

func TestUpstreamV2_R41_DuplicateAuthorityIsRefused(t *testing.T) {
	upEnv(t)
	rec := upV1Post(t, `[{"url":"http://parent-b.test:3128"},{"url":"HTTP://PARENT-B.TEST:3128/"}]`)
	if rec.Code == 200 {
		t.Fatalf("two spellings of one canonical authority must be refused, got 200: %s", rec.Body.String())
	}
	m := upJSON(t, rec)
	if m["code"] != "duplicate_authority" || m["count"] != float64(1) {
		t.Fatalf("want duplicate_authority with a count, got %s", rec.Body.String())
	}
	if upstreamPool.Enabled() {
		t.Fatal("runtime must be unchanged")
	}
	// YAML-owned vs managed.
	upstreamPool.Configure([]UpstreamEntry{{URL: "http://parent-y.test:3128"}}, 5, 60*time.Second)
	rec = upReq(t, "POST", "/api/upstream/entries", fmt.Sprintf(`{"scheme":"http","host":"PARENT-Y.TEST","port":3128,"revision":%d}`, upDocRevision(t)))
	if rec.Code != http.StatusConflict || upJSON(t, rec)["code"] != "duplicate_authority" {
		t.Fatalf("a managed entry duplicating a YAML authority must be refused, got %d %s", rec.Code, rec.Body.String())
	}
}

// ── R42: an injected password-bearing transport error reaches no sink ──

func TestUpstreamV2_R42_PasswordBearingTransportErrorReachesNoSink(t *testing.T) {
	upEnv(t)
	upSeedCredentialed(t, upRedHost, "svc", upRedPW)
	upProbe(0, fmt.Errorf("proxyconnect tcp: dial http://svc:%s@%s:3128: connection refused", upRedPW, upRedHost))
	since := time.Now().UnixMilli()
	out := captureLogger(t, func() {
		upstreamPool.HealthCheck(upstream.ProbeManual)
		_ = upReq(t, "POST", "/api/upstream/health", "")
	})
	if strings.Contains(out, upRedPW) {
		t.Fatalf("the process log must not carry the password: %q", out)
	}
	for _, body := range []string{upReq(t, "GET", "/api/upstream", "").Body.String(), upReq(t, "POST", "/api/upstream/health", "").Body.String()} {
		if strings.Contains(body, upRedPW) {
			t.Fatal("an API body must not carry the password")
		}
	}
	d := diagnoseUpstream(time.Now())
	if b := fmt.Sprintf("%+v", d); strings.Contains(b, upRedPW) {
		t.Fatal("diagnose must not carry the password")
	}
	for _, e := range auditGet() {
		if e.TS >= since && (strings.Contains(e.Detail, upRedPW) || strings.Contains(e.Object, upRedPW)) {
			t.Fatal("the audit ring must not carry the password")
		}
	}
}
