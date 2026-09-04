package main

// upstream_v2_correction_red_test.go — the 2F-C correction RED matrix,
// written against the exact rejected candidate (02b97716) BEFORE any product
// change. Each test names the external-review blocker it pins and fails on
// the candidate for the reason the review states; every helper it uses
// exists on the candidate so the file compiles there unchanged.
//
//   C-R1  credential binding must include the immutable entry ID (transplant ⇒ mismatch)
//   C-R2  YAML inline credentials are retained in memory, read-only, never persisted
//   C-R3  a rejected v2 document freezes every managed mutation and key minting
//   C-R3b a failed YAML validation stays visible after the managed document loads
//   C-R4  the authority grammar is http|https only (socks5 refused everywhere)
//   C-R5  the read model carries coverage, top-level probe, per-entry health, effective.since
//   C-R6  the probe transport selector never sees a password; GET url carries no userinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

const upCorrPW = "corr-Secret-Delta-4k" // #nosec G101 -- test fixture

// upCaptureProbe installs a probe seam that records every URL the pool hands
// the transport factory and answers 200.
func upCaptureProbe(t *testing.T) *[]string {
	t.Helper()
	var mu sync.Mutex
	seen := &[]string{}
	upstream.ProbeTransport = func(u *url.URL) http.RoundTripper {
		mu.Lock()
		*seen = append(*seen, u.String())
		mu.Unlock()
		return upProbeRT{status: 200}
	}
	return seen
}

func upCorrEntryHealthCheck(t *testing.T) map[string]any {
	t.Helper()
	rec := upReq(t, "POST", "/api/upstream/health", "")
	if rec.Code != 200 {
		t.Fatalf("health: %d %s", rec.Code, rec.Body.String())
	}
	return upJSON(t, rec)
}

// ── C-R1: transplanted ciphertext must be mismatch, never configured/selected ──

func TestUpstreamV2C_R1_TransplantedCiphertextIsMismatchNeverSelected(t *testing.T) {
	upEnv(t)
	seen := upCaptureProbe(t)
	idA := upSeedCredentialed(t, upRedHost, "svc", upCorrPW)
	docA := upstreamPool.Document()
	if len(docA.Entries) != 1 || docA.Entries[0].Credential == nil {
		t.Fatal("seed did not produce a sealed credential")
	}
	credA := *docA.Entries[0].Credential

	// Clear (T3) and delete A, then create B with the SAME authority.
	e := upEntry(t, idA)
	rec := upReq(t, "POST", "/api/upstream/entries/"+idA+"/credential",
		fmt.Sprintf(`{"action":"clear","confirm":%q,"revision":%d}`, idA, int64(e["revision"].(float64))))
	if rec.Code != 200 {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body.String())
	}
	e = upEntry(t, idA)
	rec = upReq(t, "DELETE", fmt.Sprintf("/api/upstream/entries/%s?revision=%d", idA, int64(e["revision"].(float64))), "")
	if rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	rec = upReq(t, "POST", "/api/upstream/entries", fmt.Sprintf(`{"scheme":"http","host":%q,"port":3128,"username":"svc","revision":%d}`, upRedHost, upDocRevision(t)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create B: %d %s", rec.Code, rec.Body.String())
	}
	idB, _ := upJSON(t, rec)["entry"].(map[string]any)["id"].(string)
	if idB == idA {
		t.Fatal("B must be a new identity")
	}

	// Transplant A's ciphertext onto B through the engine (same authority hash).
	docB := upstreamPool.Document()
	c := credA
	docB.Entries[0].Credential = &c
	if err := upstreamPool.SetDocument(docB); err != nil {
		t.Fatalf("SetDocument: %v", err)
	}
	if st := upEntry(t, idB)["credentialState"]; st != upstream.CredentialMismatch {
		t.Fatalf("a credential sealed for entry %s transplanted onto %s must be mismatch, got %v", idA, idB, st)
	}
	if u := upProxyURL(t); u != nil {
		t.Fatalf("a mismatched credential must never be selected, got %v", u.Redacted())
	}
	upCorrEntryHealthCheck(t)
	if len(*seen) != 0 {
		t.Fatalf("a mismatched credential must never be probed, parent contacted %d time(s)", len(*seen))
	}

	// The same transplant through the durable file must land identically.
	path := filepath.Join(dataDir, "admin_settings.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var s AdminSettings
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	if s.UpstreamProxiesV2 == nil || len(s.UpstreamProxiesV2.Entries) != 1 {
		t.Fatalf("unexpected persisted document: %+v", s.UpstreamProxiesV2)
	}
	c2 := credA
	s.UpstreamProxiesV2.Entries[0].Credential = &c2
	out, _ := json.Marshal(s)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	LoadAdminSettings(path)
	if st := upEntry(t, idB)["credentialState"]; st != upstream.CredentialMismatch {
		t.Fatalf("after reload the transplanted credential must be mismatch, got %v", st)
	}
	if u := upProxyURL(t); u != nil {
		t.Fatalf("after reload a mismatched credential must never be selected, got %v", u.Redacted())
	}
}

// ── C-R2: YAML inline credentials retained in memory, read-only, never persisted ──

func TestUpstreamV2C_R2_YAMLInlineCredentialIsRetainedReadOnlyAndNeverPersisted(t *testing.T) {
	upEnv(t)
	seen := upCaptureProbe(t)
	err := upstreamPool.Configure([]UpstreamEntry{{URL: "http://svc:" + upCorrPW + "@parent-y.test:3128"}}, 5, 60*time.Second)
	if err != nil {
		t.Fatalf("an existing config.yaml parent with an inline credential must stay usable, got refusal: %v", err)
	}
	applyUpstreamProxy()
	list := upstreamPool.List()
	if len(list) != 1 || list[0].Source != string(upstream.SourceYAML) || !strings.HasPrefix(list[0].ID, "yaml-") {
		t.Fatalf("want one read-only yaml entry, got %+v", list)
	}
	if list[0].CredentialState != upstream.CredentialConfigured {
		t.Fatalf("the inline credential must be usable (configured), got %s", list[0].CredentialState)
	}
	u := upProxyURL(t)
	if u == nil {
		t.Fatal("the YAML parent must be selectable")
	}
	if pw, _ := u.User.Password(); pw != upCorrPW {
		t.Fatalf("chaining must present the inline credential, got %q", pw)
	}
	// Never persisted, never returned, never logged.
	body, _ := json.Marshal(upGet(t))
	if strings.Contains(string(body), upCorrPW) {
		t.Fatal("GET must never carry the YAML password")
	}
	for _, st := range upstreamPool.List() {
		if strings.Contains(st.URL, upCorrPW) || strings.Contains(st.Authority, upCorrPW) {
			t.Fatal("List must never carry the YAML password")
		}
	}
	if len(upstreamPool.Document().Entries) != 0 {
		t.Fatal("a YAML entry must never enter the managed document")
	}
	SaveAdminSettings()
	if strings.Contains(upSettingsFile(t), upCorrPW) {
		t.Fatal("admin_settings.json must never carry the YAML password")
	}
	logs := captureLogger(t, func() { upCorrEntryHealthCheck(t) })
	if strings.Contains(logs, upCorrPW) {
		t.Fatal("the process log must never carry the YAML password")
	}
	for _, s := range *seen {
		if strings.Contains(s, upCorrPW) {
			t.Fatal("the probe transport factory must never see the password")
		}
	}
	// Still read-only through the API.
	rec := upReq(t, "PUT", "/api/upstream/entries/"+list[0].ID, `{"scheme":"http","host":"parent-y.test","port":3129,"revision":1}`)
	if rec.Code != http.StatusConflict || upJSON(t, rec)["code"] != "yaml_owned" {
		t.Fatalf("a YAML entry must stay read-only (409 yaml_owned), got %d %s", rec.Code, rec.Body.String())
	}
	rec = upReq(t, "POST", "/api/upstream/entries/"+list[0].ID+"/credential", `{"action":"clear","confirm":"`+list[0].ID+`","revision":1}`)
	if rec.Code != http.StatusConflict || upJSON(t, rec)["code"] != "yaml_owned" {
		t.Fatalf("a YAML credential must not be clearable through the API, got %d %s", rec.Code, rec.Body.String())
	}
}

// ── C-R3: a rejected v2 document freezes every managed mutation and key minting ──

func upCorrRejectedDocument() string {
	cred := `{"authorityHash":"deadbeef","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","keyId":"0123456789abcdef","setAt":"2026-09-04T00:00:00Z"}`
	return `{"upstream_proxies_saved":true,"upstream_proxies":[{"url":"http://parent-a.test:3128"},{"url":"http://parent-a.test:3128"}],` +
		`"upstream_proxies_v2":{"schema":1,"revision":7,"entries":[` +
		`{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","scheme":"http","host":"parent-a.test","port":3128,"revision":1,"source":"managed","credential":` + cred + `},` +
		`{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","scheme":"http","host":"parent-a.test","port":3128,"revision":1,"source":"managed"}]}}`
}

func TestUpstreamV2C_R3_RejectedDocumentFreezesMutationsAndKeyMinting(t *testing.T) {
	upEnv(t)
	path := filepath.Join(dataDir, "admin_settings.json")
	keyPath := filepath.Join(dataDir, upstream.KeyFileName)
	before := upCorrRejectedDocument()
	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	LoadAdminSettings(path)
	if _, err := os.Stat(keyPath); err == nil {
		t.Fatal("loading a rejected document must not mint a key")
	}
	v := upGet(t)
	deg, _ := v["degraded"].(map[string]any)
	if deg == nil || deg["reason"] != "duplicate_authority" {
		t.Fatalf("the rejected document must be visible as degraded, got %v", v["degraded"])
	}
	if upstreamPool.Enabled() {
		t.Fatal("a rejected document must publish nothing")
	}
	sections := func() (any, any) {
		var s map[string]any
		data, _ := os.ReadFile(path)
		_ = json.Unmarshal(data, &s)
		return s["upstream_proxies_v2"], s["upstream_proxies"]
	}
	v2Before, legacyBefore := sections()

	rec := upReq(t, "POST", "/api/upstream/entries", fmt.Sprintf(`{"scheme":"http","host":"parent-b.test","port":3128,"revision":%d}`, upDocRevision(t)))
	if rec.Code < 400 {
		t.Fatalf("a create while the stored document is rejected must be refused, got %d %s", rec.Code, rec.Body.String())
	}
	rec = upV1Post(t, `[{"url":"http://parent-b.test:3128"}]`)
	if rec.Code < 400 {
		t.Fatalf("a v1 replace while the stored document is rejected must be refused, got %d %s", rec.Code, rec.Body.String())
	}
	rec = upImport(t, `{"version":1,"upstreamProxies":[{"url":"http://parent-b.test:3128"}]}`, "")
	if rec.Code < 400 {
		t.Fatalf("an import while the stored document is rejected must be refused, got %d %s", rec.Code, rec.Body.String())
	}
	// A save triggered by an unrelated admin section must carry the stored
	// upstream sections forward verbatim, never the empty live pool.
	SaveAdminSettings()
	v2After, legacyAfter := sections()
	if fmt.Sprint(v2After) != fmt.Sprint(v2Before) || fmt.Sprint(legacyAfter) != fmt.Sprint(legacyBefore) {
		t.Fatalf("the rejected upstream sections must be preserved on disk\nbefore v2=%v legacy=%v\nafter  v2=%v legacy=%v", v2Before, legacyBefore, v2After, legacyAfter)
	}
	if _, err := os.Stat(keyPath); err == nil {
		t.Fatal("no key may be minted while ciphertext exists in a rejected document")
	}
	if upstreamPool.Enabled() {
		t.Fatal("the live pool must stay unchanged")
	}
	if deg, _ := upGet(t)["degraded"].(map[string]any); deg == nil {
		t.Fatal("the degraded condition must stay visible until operator repair")
	}
}

func TestUpstreamV2C_R3b_YAMLDegradedStaysVisibleAfterManagedLoad(t *testing.T) {
	upEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loadUpstreamPool(upstreamPoolStartupConfig{
		Proxies:     []UpstreamEntry{{URL: "http://parent-y.test:3128"}, {URL: "HTTP://PARENT-Y.TEST:3128/"}},
		CBThreshold: 5, CBTimeout: 60 * time.Second,
	}, ctx)
	if upstreamPool.Enabled() {
		t.Fatal("a duplicate YAML seed must be refused whole")
	}
	valid := upstream.Document{Schema: upstream.DocumentSchema, Revision: 3, Entries: []upstream.ManagedEntry{{
		ID: upstream.NewManagedID(), Scheme: "http", Host: "parent-b.test", Port: 3128, Revision: 1, Source: upstream.SourceManaged}}}
	applyUpstreamV2(&AdminSettings{UpstreamProxiesSaved: true, UpstreamProxiesV2: &valid})
	v := upGet(t)
	yd, _ := v["yamlDegraded"].(map[string]any)
	if yd == nil || yd["reason"] != "duplicate_authority" {
		t.Fatalf("the YAML validation failure must remain visible after the managed document loads, got yamlDegraded=%v degraded=%v", v["yamlDegraded"], v["degraded"])
	}
	if len(upstreamPool.List()) != 1 {
		t.Fatalf("the managed entry must still load, got %+v", upstreamPool.List())
	}
}

// ── C-R4: the authority grammar is http|https only ──

func TestUpstreamV2C_R4_SOCKS5IsRefusedEverywhere(t *testing.T) {
	upEnv(t)
	rec := upReq(t, "POST", "/api/upstream/entries", fmt.Sprintf(`{"scheme":"socks5","host":"parent-s.test","port":1080,"revision":%d}`, upDocRevision(t)))
	if rec.Code != http.StatusBadRequest || upJSON(t, rec)["code"] != "invalid_entry" {
		t.Fatalf("v2 create with socks5 must be 400 invalid_entry, got %d %s", rec.Code, rec.Body.String())
	}
	rec = upV1Post(t, `[{"url":"socks5://parent-s.test:1080"}]`)
	if rec.Code != http.StatusBadRequest || upJSON(t, rec)["code"] != "invalid_entry" {
		t.Fatalf("v1 with socks5 must be 400 invalid_entry, got %d %s", rec.Code, rec.Body.String())
	}
	if err := upstreamPool.Configure([]UpstreamEntry{{URL: "socks5://parent-s.test:1080"}}, 5, time.Minute); err == nil {
		t.Fatal("a socks5 YAML seed must be refused")
	}
	rec = upImport(t, `{"version":1,"upstreamProxies":[{"url":"socks5://parent-s.test:1080"}]}`, "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_entry") {
		t.Fatalf("import with socks5 must be 400 invalid_entry, got %d %s", rec.Code, rec.Body.String())
	}
	if upstreamPool.Enabled() {
		t.Fatal("nothing may be published")
	}
	path := filepath.Join(dataDir, "admin_settings.json")
	legacy := `{"upstream_proxies_saved":true,"upstream_proxies":[{"url":"socks5://svc:pw@parent-s.test:1080"}]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	LoadAdminSettings(path)
	if st := getUpstreamState(); st.Migration.State != "degraded" || st.Migration.Reason != "parse_failed" {
		t.Fatalf("a legacy socks5 URL must degrade the migration as parse_failed, got %+v", st.Migration)
	}
	if _, err := os.Stat(filepath.Join(dataDir, upstream.KeyFileName)); err == nil {
		t.Fatal("no key may be minted for a refused migration")
	}
}

// ── C-R5: the read model carries the full contracted truth ──

func TestUpstreamV2C_R5_ReadModelCoverageProbeHealthSince(t *testing.T) {
	upEnv(t)
	upCaptureProbe(t)
	v := upGet(t)
	cov, _ := v["coverage"].(map[string]any)
	if cov["plainHttp"] != "chained" || cov["connect"] != "direct" || cov["websocket"] != "direct" || cov["socks5"] != "direct" || cov["summary"] != "plain_http_only" {
		t.Fatalf("coverage must be {plainHttp:chained, connect:direct, websocket:direct, socks5:direct, summary:plain_http_only}, got %v", v["coverage"])
	}
	probe, _ := v["probe"].(map[string]any)
	if _, ok := probe["configured"].(bool); !ok {
		t.Fatalf("top-level probe.configured must be a boolean, got %v", v["probe"])
	}
	if _, ok := probe["interval"].(string); !ok {
		t.Fatalf("top-level probe.interval must be a duration string, got %v", v["probe"])
	}
	eff, _ := v["effective"].(map[string]any)
	since, _ := eff["since"].(string)
	if _, err := time.Parse(time.RFC3339, since); err != nil {
		t.Fatalf("effective.since must be an RFC3339 transition time, got %v", eff["since"])
	}
	rec := upReq(t, "POST", "/api/upstream/entries", fmt.Sprintf(`{"scheme":"http","host":"parent-b.test","port":3128,"revision":%d}`, upDocRevision(t)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	entries, _ := upGet(t)["entries"].([]any)
	h, _ := entries[0].(map[string]any)["health"].(map[string]any)
	if h["status"] != "unprobed" || h["reason"] != "none" {
		t.Fatalf("a new entry's health must be unprobed/none, got %v", entries[0].(map[string]any)["health"])
	}
	r := upCorrEntryHealthCheck(t)
	entries, _ = r["entries"].([]any)
	h, _ = entries[0].(map[string]any)["health"].(map[string]any)
	if h["status"] != "healthy" || h["reason"] != "none" || h["source"] != "manual" {
		t.Fatalf("after a manual check health must be healthy/none with source manual, got %v", entries[0].(map[string]any)["health"])
	}
	if at, _ := h["lastProbeAt"].(string); at == "" {
		t.Fatalf("health.lastProbeAt must be set after a probe, got %v", h)
	}
}

// ── C-R6: the probe selector never sees a password; GET url carries no userinfo ──

func TestUpstreamV2C_R6_ProbeSelectorNeverSeesPasswordAndURLHasNoUserinfo(t *testing.T) {
	upEnv(t)
	seen := upCaptureProbe(t)
	upSeedCredentialed(t, upRedHost, "svc", upCorrPW)
	logs := captureLogger(t, func() { upCorrEntryHealthCheck(t) })
	if len(*seen) == 0 {
		t.Fatal("a configured entry must be probed")
	}
	for _, s := range *seen {
		if strings.Contains(s, upCorrPW) || strings.Contains(s, "@") {
			t.Fatalf("the probe transport factory must receive the credential-free authority only, got %s", (&url.URL{}).String()+strings.ReplaceAll(s, upCorrPW, "<pw>"))
		}
	}
	if strings.Contains(logs, upCorrPW) {
		t.Fatal("the process log must never carry the password")
	}
	entries, _ := upGet(t)["entries"].([]any)
	u, _ := entries[0].(map[string]any)["url"].(string)
	if strings.Contains(u, "@") {
		t.Fatalf("GET url must carry no userinfo (username is a separate field), got %q", u)
	}
	if entries[0].(map[string]any)["username"] != "svc" {
		t.Fatalf("username must stay a separate field, got %v", entries[0])
	}
}
