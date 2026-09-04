package main

// admin_settings_upstream_test.go — persistence contracts for the
// GUI-configured upstream pool (the "upstream runtime durability gap" logged
// as an out-of-scope observation in
// roadmap/CATEGORY-B-PRIME-FINDING-10.3-SPEC.md §5).
//
// Engine-level pool contracts (SetProxies keeps CB params, Entries() raw vs
// List() redacted, hostless-URL rejection) moved to internal/upstream with
// the ADR-0002 extraction. This file keeps the MAIN-side contracts:
//
//  1. (2F-C) SaveAdminSettings writes the SEALED v2 document beside a
//     credential-free legacy list with the UpstreamProxiesSaved sentinel;
//     LoadAdminSettings restores it (restart simulation), the credential
//     unseals again, and the startup-configured circuit-breaker params
//     (YAML-owned) are kept.
//  2. Sentinel semantics: unset → YAML seed kept; set → authoritative for the
//     MANAGED entries only — YAML entries are read-only and always coexist
//     (2F-C retires the pre-v2 "saved empty list wipes the seed" contract).
//  3. A pre-v2 file with userinfo URLs is migrated once (sealed, plaintext
//     removed); an unparseable legacy URL degrades without rewriting.
//  4. POST /api/upstream (credential-free v1 adapter) keeps CB params and
//     persists before responding.
//
// CB params are asserted through the exported surface: Pool.Next() returns
// the sole *upstream.Proxy, whose CB exposes Params().

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

// snapshotUpstreamPool captures the global pool's entries and circuit-breaker
// parameters and restores them on cleanup, so tests that mutate the global
// pool stay order-independent under -count=N / -shuffle=on.
func snapshotUpstreamPool(t *testing.T) {
	t.Helper()
	prev := upstreamPool.Snapshot()
	t.Cleanup(func() { upstreamPool.Restore(prev) })
}

// soleProxyCBParams returns the CB params of the pool's single healthy proxy.
func soleProxyCBParams(t *testing.T) (int, time.Duration) {
	t.Helper()
	up := upstreamPool.Next()
	if up == nil {
		t.Fatal("pool has no available proxy")
	}
	return up.CB.Params()
}

// upTestReq builds an admin request against the cluster mux for the tests below.
func upTestReq(t *testing.T, method, path string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	r := jsonReq(method, path, body)
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	registerClusterRoutes(mux)
	mux.ServeHTTP(w, r)
	return w
}

// upTestRevision reads the current document revision the fence expects.
func upTestRevision(t *testing.T) int64 {
	t.Helper()
	return upstreamPool.Document().Revision
}

// TestAdminSettings_UpstreamRoundTrip (2F-C): a managed entry with a sealed
// credential survives SaveAdminSettings → LoadAdminSettings with the
// plaintext never on disk, the credential usable again after the restart,
// and the startup-configured circuit-breaker params kept.
func TestAdminSettings_UpstreamRoundTrip(t *testing.T) {
	snapshotUpstreamPool(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "admin_settings.json")
	swapAdminSettingsPath(t, path)
	prevData := dataDir
	dataDir = dir
	t.Cleanup(func() { dataDir = prevData })
	upstreamPool.Configure(nil, 7, 90*time.Second)
	applyUpstreamProxy()

	const pw = "rt-sealed-secret" // #nosec G101 -- test fixture
	w := upTestReq(t, "POST", "/api/upstream/entries", map[string]any{
		"scheme": "http", "host": "parent-a.test", "port": 3128, "username": "svc", "revision": upTestRevision(t)})
	assertStatus(t, w, 201)
	var created struct {
		Entry struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
		} `json:"entry"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	w = upTestReq(t, "POST", "/api/upstream/entries/"+created.Entry.ID+"/credential", map[string]any{
		"action": "replace", "password": pw, "revision": created.Entry.Revision})
	assertStatus(t, w, 200)
	w = upTestReq(t, "POST", "/api/upstream/entries", map[string]any{
		"scheme": "http", "host": "parent-b.test", "port": 3128, "revision": upTestRevision(t)})
	assertStatus(t, w, 201)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("settings file not written: %v", err)
	}
	if strings.Contains(string(data), pw) {
		t.Fatal("the plaintext password must never reach admin_settings.json")
	}
	var s AdminSettings
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	if !s.UpstreamProxiesSaved {
		t.Error("upstream_proxies_saved = false; want true (sentinel must be set on save)")
	}
	if s.UpstreamProxiesV2 == nil || len(s.UpstreamProxiesV2.Entries) != 2 || s.UpstreamProxiesV2.Entries[0].Credential == nil {
		t.Fatalf("persisted v2 document = %+v; want 2 entries, the first with a sealed credential", s.UpstreamProxiesV2)
	}
	if len(s.UpstreamProxies) != 2 || strings.Contains(s.UpstreamProxies[0].URL, "@") && strings.Contains(s.UpstreamProxies[0].URL, ":"+pw) {
		t.Fatalf("legacy list = %+v; want 2 credential-free authorities", s.UpstreamProxies)
	}

	// Restart simulation: wipe the pool and its key, then load the file.
	upstreamPool.Restore(upstream.PoolState{CBThreshold: 7, CBTimeout: 90 * time.Second})
	if upstreamPool.Enabled() {
		t.Fatal("pool should be empty before restore")
	}
	LoadAdminSettings(path)
	list := upstreamPool.List()
	if len(list) != 2 || list[0].CredentialState != upstream.CredentialConfigured {
		t.Fatalf("restored list = %+v; want 2 entries, the first credential configured", list)
	}
	// Round-robin over two eligible parents: one of the next two selections
	// is the credentialed one, and it must unseal to the original password.
	var got string
	for i := 0; i < 2; i++ {
		u, err := upstreamPool.ProxyFunc()(httptest.NewRequest("GET", "http://origin.example/", http.NoBody))
		if err != nil || u == nil {
			t.Fatalf("ProxyFunc after restore: %v %v", u, err)
		}
		if p, ok := u.User.Password(); ok {
			got = p
		}
	}
	if got != pw {
		t.Fatalf("restored credential must unseal to the original password, got %q", got)
	}
	if th, to := soleProxyCBParams(t); th != 7 || to != 90*time.Second {
		t.Errorf("restored CB params = %d/%v, want 7/90s (YAML-owned, not persisted)", th, to)
	}
}

func TestAdminSettings_UpstreamSentinelUnsetKeepsSeed(t *testing.T) {
	snapshotUpstreamPool(t)
	upstreamPool.Configure([]UpstreamEntry{{URL: "http://yaml-seed.test:3128"}}, 5, time.Minute)

	// Pre-feature settings file: no sentinel, no list → seed untouched.
	applyAdminNetwork(&AdminSettings{})

	entries := upstreamPool.Entries()
	if len(entries) != 1 || entries[0].URL != "http://yaml-seed.test:3128" {
		t.Fatalf("entries = %+v; want the YAML seed untouched (upgrade safety)", entries)
	}
}

// TestAdminSettings_UpstreamSavedListCoexistsWithYAML (2F-C): the saved
// managed list is authoritative for MANAGED entries only — YAML entries are
// read-only and always present, so a saved empty managed list no longer
// wipes the YAML seed (the pre-2F-C "saved wipe beats the seed" contract is
// retired; YAML ownership is the documented replacement).
func TestAdminSettings_UpstreamSavedListCoexistsWithYAML(t *testing.T) {
	snapshotUpstreamPool(t)
	upstreamPool.Configure([]UpstreamEntry{{URL: "http://yaml-seed.test:3128"}}, 5, time.Minute)

	applyAdminNetwork(&AdminSettings{UpstreamProxiesSaved: true})
	list := upstreamPool.List()
	if len(list) != 1 || list[0].Source != string(upstream.SourceYAML) {
		t.Fatalf("list = %+v; want exactly the read-only YAML entry", list)
	}

	applyAdminNetwork(&AdminSettings{UpstreamProxiesSaved: true, UpstreamProxies: []UpstreamEntry{{URL: "http://managed.test:3128"}}})
	list = upstreamPool.List()
	if len(list) != 2 {
		t.Fatalf("list = %+v; want YAML + managed", list)
	}
	// A saved managed entry duplicating a YAML authority is YAML-owned and
	// never adopted into the managed set.
	applyAdminNetwork(&AdminSettings{UpstreamProxiesSaved: true, UpstreamProxies: []UpstreamEntry{{URL: "HTTP://YAML-SEED.TEST:3128"}}})
	list = upstreamPool.List()
	if len(list) != 1 || list[0].Source != string(upstream.SourceYAML) {
		t.Fatalf("list = %+v; want the YAML entry alone (managed duplicate skipped)", list)
	}
}

// TestAdminSettings_LegacyMigrationSealsUserinfo (2F-C): a pre-v2 settings
// file carrying a userinfo URL is migrated ONCE at load — the credential is
// sealed into upstream_proxies_v2 under a freshly minted key, the legacy list
// is rewritten credential-free, the plaintext leaves the disk, and the
// runtime keeps working with the same credential.
func TestAdminSettings_LegacyMigrationSealsUserinfo(t *testing.T) {
	snapshotUpstreamPool(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "admin_settings.json")
	swapAdminSettingsPath(t, path)
	prevData := dataDir
	dataDir = dir
	t.Cleanup(func() { dataDir = prevData })
	upstreamPool.Configure(nil, 5, time.Minute)
	applyUpstreamProxy()

	const pw = "legacy-plain-secret" // #nosec G101 -- test fixture
	legacy := `{"upstream_proxies_saved":true,"upstream_proxies":[{"url":"http://svc:` + pw + `@parent-a.test:3128"},{"url":"http://parent-b.test:3128"}]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	LoadAdminSettings(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), pw) {
		t.Fatal("migration must remove the plaintext password from admin_settings.json")
	}
	var s AdminSettings
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	if s.UpstreamProxiesV2 == nil || len(s.UpstreamProxiesV2.Entries) != 2 || s.UpstreamProxiesV2.Entries[0].Credential == nil {
		t.Fatalf("migrated document = %+v; want 2 entries with the first sealed", s.UpstreamProxiesV2)
	}
	if _, err := os.Stat(filepath.Join(dir, upstream.KeyFileName)); err != nil {
		t.Fatalf("migration must mint the credential key: %v", err)
	}
	st := getUpstreamState()
	if st.Migration.State != "ok" || st.Migration.Sealed != 1 {
		t.Fatalf("migration state = %+v; want ok with 1 sealed", st.Migration)
	}
	var got string
	for i := 0; i < 2; i++ {
		u, err := upstreamPool.ProxyFunc()(httptest.NewRequest("GET", "http://origin.example/", http.NoBody))
		if err != nil || u == nil {
			t.Fatalf("ProxyFunc after migration: %v %v", u, err)
		}
		if p, ok := u.User.Password(); ok {
			got = p
		}
	}
	if got != pw {
		t.Fatalf("migrated credential must unseal to the original password, got %q", got)
	}
}

// TestAdminSettings_LegacyMigrationParseFailureIsDegradedNotDestructive
// (2F-C): a legacy file with an unparseable URL is NOT migrated (nothing
// rewritten, runtime unchanged) and the outcome is a bounded degraded reason.
func TestAdminSettings_LegacyMigrationParseFailureIsDegradedNotDestructive(t *testing.T) {
	snapshotUpstreamPool(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "admin_settings.json")
	swapAdminSettingsPath(t, path)
	prevData := dataDir
	dataDir = dir
	t.Cleanup(func() { dataDir = prevData })
	upstreamPool.Configure(nil, 5, time.Minute)

	legacy := `{"upstream_proxies_saved":true,"upstream_proxies":[{"url":"http://svc:secret@parent-a.test:3128"},{"url":"://not a url"}]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	LoadAdminSettings(path)
	// The unrelated SaaS-feed schema migration may stamp the file, so the
	// upstream SECTIONS are what must be untouched: the legacy list (with its
	// plaintext URL — nothing was sealed) and no v2 document.
	after, _ := os.ReadFile(path)
	var s AdminSettings
	if err := json.Unmarshal(after, &s); err != nil {
		t.Fatal(err)
	}
	if s.UpstreamProxiesV2 != nil || len(s.UpstreamProxies) != 2 || s.UpstreamProxies[0].URL != "http://svc:secret@parent-a.test:3128" {
		t.Fatalf("a failed migration must leave the legacy upstream sections untouched, got v2=%v legacy=%+v", s.UpstreamProxiesV2, s.UpstreamProxies)
	}
	if upstreamPool.Enabled() {
		t.Fatal("a failed migration must leave the runtime unchanged (no partial pool)")
	}
	if st := getUpstreamState(); st.Migration.State != "degraded" || st.Migration.Reason != "parse_failed" {
		t.Fatalf("migration state = %+v; want degraded/parse_failed", st.Migration)
	}
	if _, err := os.Stat(filepath.Join(dir, upstream.KeyFileName)); err == nil {
		t.Fatal("a failed migration must not mint a key")
	}
}

// TestAPIUpstream_PostKeepsCBParamsAndPersists: the credential-free v1 bulk
// adapter keeps the startup CB params and persists BEFORE responding (2F-C
// durable-before-respond: the file is complete when the 200 is written).
func TestAPIUpstream_PostKeepsCBParamsAndPersists(t *testing.T) {
	snapshotUpstreamPool(t)
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)

	// Startup-configured CB params the handler must not clobber.
	upstreamPool.Configure(nil, 9, 45*time.Second)

	w := upTestReq(t, "POST", "/api/upstream", map[string]any{
		"proxies":  []map[string]string{{"url": "http://api-added.test:3128"}},
		"revision": upTestRevision(t),
	})
	assertStatus(t, w, 200)

	if got := len(upstreamPool.List()); got != 1 {
		t.Fatalf("pool has %d proxies, want 1", got)
	}
	if th, to := soleProxyCBParams(t); th != 9 || to != 45*time.Second {
		t.Errorf("CB params after POST = %d/%v, want 9/45s (handler must not hardcode 5/60s)", th, to)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("settings file must be written before the response: %v", err)
	}
	var s AdminSettings
	if err := json.Unmarshal(data, &s); err != nil || !s.UpstreamProxiesSaved ||
		len(s.UpstreamProxies) != 1 || s.UpstreamProxies[0].URL != "http://api-added.test:3128" {
		t.Fatalf("settings file did not persist the POSTed upstream: %+v (err=%v)", s, err)
	}
}
