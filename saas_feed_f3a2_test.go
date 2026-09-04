package main

// saas_feed_f3a2_test.go — F3a-2 surface tests: CP→DP ConfigSnapshot propagation
// (the *bool nil/false/true matrix + override wipe), DP-side validation +
// atomic rejection, the API handlers (auth/authz/strict-JSON/managed-DP denial),
// export/import + rollback, persistence-failure atomicity, and the CRITICAL
// SEPARATION proof that feed-config mutation performs zero downloader/network
// activity and never touches the live category store or the legacy syncer.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catoverride"
)

// ─── isolation helpers ──────────────────────────────────────────────────────────

func f3a2ResetFeedDurable(t *testing.T) {
	t.Helper()
	prev := getSaaSFeedDurable()
	t.Cleanup(func() { setSaaSFeedDurable(prev) })
	setSaaSFeedDurable(saasFeedDurable{SchemaVersion: saasStoreSchemaVersion})
}

func f3a2SwapOverrides(t *testing.T) *catoverride.Store {
	t.Helper()
	prev := globalCategoryOverrides
	s := catoverride.New()
	s.SetPathForTest(filepath.Join(t.TempDir(), "overrides.json"))
	globalCategoryOverrides = s
	t.Cleanup(func() { globalCategoryOverrides = prev })
	return s
}

func f3a2SwapRole(t *testing.T, role string) {
	t.Helper()
	clusterRoleMu.Lock()
	prev := clusterRole.role
	clusterRole.role = role
	clusterRoleMu.Unlock()
	t.Cleanup(func() {
		clusterRoleMu.Lock()
		clusterRole.role = prev
		clusterRoleMu.Unlock()
	})
}

func boolPtr(b bool) *bool { return &b }

// f3a2IsolateConfigWriters isolates the two PROCESS-GLOBAL writers a settings/
// overrides PUT drives — the config-version store (saveConfigVersion advances its
// Seq + writes numbered files) and the cluster config store (publishCurrentConfigSnapshot
// advances its version). Without this, a handler test leaks global state into
// shuffled sibling tests (the determinism gate). Mirrors the standard pattern in
// auth_password_change_no_versioning_test.go + cluster_benchgate_test.go.
func f3a2IsolateConfigWriters(t *testing.T) {
	t.Helper()
	origDir, origSeq := configVersions.Dir(), configVersions.Seq()
	configVersions.SetDirForTest(t.TempDir())
	configVersions.SetSeqForTest(0)
	origStore := globalConfigStore
	globalConfigStore = &ConfigStore{}
	t.Cleanup(func() {
		configVersions.SetDirForTest(origDir)
		configVersions.SetSeqForTest(origSeq)
		globalConfigStore = origStore
	})
}

// ─── 1. CP snapshot encode/decode round-trip ────────────────────────────────────

func TestF3a2_SnapshotRoundTrip(t *testing.T) {
	orig := ConfigSnapshot{
		SaaSFeedManaged:        boolPtr(true),
		SaaSFeedEnabled:        boolPtr(false),
		SaaSFeedURL:            builtinSaaSFeedURL,
		SaaSFeedProtocol:       saasFeedProtocolV1,
		SaaSFeedRefreshSeconds: 7200,
		CategoryOverrides: &CategoryOverrides{
			Added:      map[string]string{"a.example.com": "social"},
			Tombstones: []string{"bad.example.com"},
		},
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ConfigSnapshot
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SaaSFeedManaged == nil || *got.SaaSFeedManaged != true {
		t.Errorf("managed lost: %v", got.SaaSFeedManaged)
	}
	if got.SaaSFeedEnabled == nil || *got.SaaSFeedEnabled != false {
		t.Errorf("enabled lost: %v", got.SaaSFeedEnabled)
	}
	if got.SaaSFeedURL != builtinSaaSFeedURL || got.SaaSFeedProtocol != saasFeedProtocolV1 || got.SaaSFeedRefreshSeconds != 7200 {
		t.Errorf("scalar round-trip mismatch: %+v", got)
	}
	if got.CategoryOverrides == nil || got.CategoryOverrides.Added["a.example.com"] != "social" ||
		len(got.CategoryOverrides.Tombstones) != 1 {
		t.Errorf("overrides round-trip mismatch: %+v", got.CategoryOverrides)
	}
}

// ─── 2. *bool absent / false / true propagation matrix ───────────────────────────

func TestF3a2_BoolPresenceMatrix(t *testing.T) {
	cases := []struct {
		name        string
		snapManaged *bool
		snapEnabled *bool
		startMgd    bool
		startEn     bool
		wantMgd     bool
		wantEn      bool
	}{
		// nil ⇒ keep the DP's local state (a rolled-back CP must NOT re-enable).
		{"nil keeps durable disable", nil, nil, true, false, true, false},
		// explicit false ⇒ apply false (even though false is the zero value).
		{"explicit false applies", boolPtr(false), boolPtr(false), true, true, false, false},
		// explicit true ⇒ apply true.
		{"explicit true applies", boolPtr(true), boolPtr(true), false, false, true, true},
		// mixed: managed set, enabled nil ⇒ only managed changes.
		{"mixed nil-skip", boolPtr(true), nil, false, false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f3a2ResetFeedDurable(t)
			f3a2SwapOverrides(t)
			setSaaSFeedDurable(saasFeedDurable{Managed: tc.startMgd, Enabled: tc.startEn, SchemaVersion: saasStoreSchemaVersion})
			applySnapshotSaaSFeed(ConfigSnapshot{SaaSFeedManaged: tc.snapManaged, SaaSFeedEnabled: tc.snapEnabled})
			got := getSaaSFeedDurable()
			if got.Managed != tc.wantMgd || got.Enabled != tc.wantEn {
				t.Errorf("managed=%v enabled=%v; want %v/%v", got.Managed, got.Enabled, tc.wantMgd, tc.wantEn)
			}
		})
	}
}

// ─── 3. non-empty overrides → explicit empty wipe ───────────────────────────────

func TestF3a2_OverridesWipePropagation(t *testing.T) {
	f3a2ResetFeedDurable(t)
	s := f3a2SwapOverrides(t)
	if err := s.ReplaceAll(CategoryOverrides{Tombstones: []string{"x.example.com"}}); err != nil {
		t.Fatal(err)
	}
	// A non-nil EMPTY override set on the wire ⇒ authoritative wipe.
	applySnapshotSaaSFeed(ConfigSnapshot{CategoryOverrides: &CategoryOverrides{}})
	if got := s.Get(); len(got.Tombstones) != 0 || len(got.Added) != 0 {
		t.Errorf("empty override set did not wipe: %+v", got)
	}
	// nil ⇒ keep-local (absence is not deletion).
	if err := s.ReplaceAll(CategoryOverrides{Tombstones: []string{"y.example.com"}}); err != nil {
		t.Fatal(err)
	}
	applySnapshotSaaSFeed(ConfigSnapshot{CategoryOverrides: nil})
	if got := s.Get(); len(got.Tombstones) != 1 {
		t.Errorf("nil override set wrongly mutated live state: %+v", got)
	}
}

// ─── 4/8. DP-side validation + atomic rejection of one invalid field ─────────────

func TestF3a2_ValidateSnapshot_RejectsInvalid(t *testing.T) {
	base := func() ConfigSnapshot {
		return ConfigSnapshot{
			BlockedHosts: []string{}, IPList: []string{},
			SaaSFeedProtocol: saasFeedProtocolV1, SaaSFeedURL: builtinSaaSFeedURL,
		}
	}
	if err := validateConfigSnapshot(base()); err != nil {
		t.Fatalf("valid snapshot rejected: %v", err)
	}
	bad := []struct {
		name  string
		mutfn func(*ConfigSnapshot)
	}{
		{"bad protocol", func(s *ConfigSnapshot) { s.SaaSFeedProtocol = "raw_v1" }},
		{"non-official url", func(s *ConfigSnapshot) { s.SaaSFeedURL = "https://evil.example.com/manifest.sigstore.json" }},
		{"negative refresh", func(s *ConfigSnapshot) { s.SaaSFeedRefreshSeconds = -5 }},
		{"invalid override host", func(s *ConfigSnapshot) {
			s.CategoryOverrides = &CategoryOverrides{Added: map[string]string{"*.wild": "x"}}
		}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			tc.mutfn(&s)
			if err := validateConfigSnapshot(s); err == nil {
				t.Errorf("invalid field %q accepted — whole snapshot must be rejected", tc.name)
			}
		})
	}
}

// applyConfigSnapshot must reject a snapshot with one invalid feed field WITHOUT
// applying any of its (otherwise valid) fields — no partial application.
func TestF3a2_ApplyConfigSnapshot_AtomicRejection(t *testing.T) {
	f3a2ResetFeedDurable(t)
	s := f3a2SwapOverrides(t)
	_ = s.ReplaceAll(CategoryOverrides{Tombstones: []string{"keep.example.com"}})
	before := getSaaSFeedDurable()

	snap := ConfigSnapshot{
		BlockedHosts: []string{}, IPList: []string{},
		SaaSFeedManaged:  boolPtr(true),
		SaaSFeedProtocol: "unsigned_v1", // invalid ⇒ whole snapshot rejected
	}
	if err := applyConfigSnapshot(snap); err == nil {
		t.Fatal("snapshot with invalid protocol was accepted")
	}
	if getSaaSFeedDurable() != before {
		t.Errorf("feed durable mutated despite rejection: %+v", getSaaSFeedDurable())
	}
	if got := s.Get(); len(got.Tombstones) != 1 {
		t.Errorf("overrides mutated despite rejection: %+v", got)
	}
}

// ─── 6. stale epoch rejection ────────────────────────────────────────────────────

func TestF3a2_StaleEpochRejection(t *testing.T) {
	f3a2ResetFeedDurable(t)
	f3a2SwapOverrides(t)
	// Ratchet the DP's last-seen epoch high, then push a stale-epoch snapshot.
	// dpLastSeenEpoch is a PROCESS-GLOBAL ratchet — save/restore it so this test
	// does not leak a high epoch into shuffled sibling tests (determinism gate).
	origEpoch := dpLastSeenEpoch.Load()
	t.Cleanup(func() { dpLastSeenEpoch.Store(origEpoch) })
	dpObserveEpoch("test seed", 50)
	before := getSaaSFeedDurable()
	err := applyConfigSnapshot(ConfigSnapshot{
		Epoch: 3, SaaSFeedManaged: boolPtr(true), SaaSFeedEnabled: boolPtr(true),
		SaaSFeedProtocol: saasFeedProtocolV1,
	})
	if err == nil {
		t.Fatal("stale-epoch snapshot accepted")
	}
	if getSaaSFeedDurable() != before {
		t.Errorf("feed config applied from a stale-epoch snapshot: %+v", getSaaSFeedDurable())
	}
}

// ─── 5/7/9. API: settings handler auth/authz/validation/managed-DP denial ────────

func dispatchSettings(role UIRole, method, body string) *httptest.ResponseRecorder {
	ctx := context.WithValue(context.Background(), uiRoleKey{}, role)
	r := httptest.NewRequestWithContext(ctx, method, "/api/saas-feed/settings", strings.NewReader(body))
	w := httptest.NewRecorder()
	apiSaaSFeedSettings(w, r)
	return w
}

func TestF3a2_SettingsHandler(t *testing.T) {
	f3a2ResetFeedDurable(t)
	f3a2SwapOverrides(t)
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))
	f3a2IsolateConfigWriters(t)
	f3a2SwapRole(t, "standalone")

	// GET viewer OK.
	if w := dispatchSettings(RoleViewer, http.MethodGet, ""); w.Code != http.StatusOK {
		t.Fatalf("GET viewer: got %d", w.Code)
	}
	// PUT viewer forbidden.
	if w := dispatchSettings(RoleViewer, http.MethodPut, `{"enabled":true}`); w.Code != http.StatusForbidden {
		t.Errorf("PUT viewer: got %d, want 403", w.Code)
	}
	// PUT admin valid (empty url ⇒ built-in official).
	if w := dispatchSettings(RoleAdmin, http.MethodPut, `{"managed":true,"enabled":true,"protocol":"signed_manifest_v1","refresh":"24h"}`); w.Code != http.StatusOK {
		t.Fatalf("PUT admin valid: got %d (%s)", w.Code, w.Body.String())
	}
	if d := getSaaSFeedDurable(); !d.Managed || !d.Enabled || d.URL != builtinSaaSFeedURL || d.Protocol != saasFeedProtocolV1 {
		t.Errorf("settings not applied: %+v", d)
	}
	// PUT admin invalid protocol ⇒ 400, no mutation.
	before := getSaaSFeedDurable()
	if w := dispatchSettings(RoleAdmin, http.MethodPut, `{"protocol":"raw"}`); w.Code != http.StatusBadRequest {
		t.Errorf("PUT bad protocol: got %d, want 400", w.Code)
	}
	if getSaaSFeedDurable() != before {
		t.Error("invalid protocol PUT mutated state")
	}
	// PUT admin non-official URL ⇒ 400.
	if w := dispatchSettings(RoleAdmin, http.MethodPut, `{"url":"https://evil.example.com/x"}`); w.Code != http.StatusBadRequest {
		t.Errorf("PUT bad url: got %d, want 400", w.Code)
	}
	// Unknown field ⇒ 400 (strict JSON).
	if w := dispatchSettings(RoleAdmin, http.MethodPut, `{"bogus":1}`); w.Code != http.StatusBadRequest {
		t.Errorf("PUT unknown field: got %d, want 400", w.Code)
	}
}

// managed data-plane node: every PUT is denied 409; GET still allowed.
func TestF3a2_ManagedDPDenial(t *testing.T) {
	f3a2ResetFeedDurable(t)
	f3a2SwapOverrides(t)
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))
	f3a2IsolateConfigWriters(t)
	f3a2SwapRole(t, "data-plane")

	if w := dispatchSettings(RoleAdmin, http.MethodPut, `{"enabled":true}`); w.Code != http.StatusConflict {
		t.Errorf("managed-DP settings PUT: got %d, want 409", w.Code)
	}
	if w := dispatchSettings(RoleViewer, http.MethodGet, ""); w.Code != http.StatusOK {
		t.Errorf("managed-DP settings GET: got %d, want 200", w.Code)
	}
	// Overrides PUT denied too.
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	r := httptest.NewRequestWithContext(ctx, http.MethodPut, "/api/saas-feed/overrides", strings.NewReader(`{"tombstones":["x.com"]}`))
	w := httptest.NewRecorder()
	apiSaaSFeedOverrides(w, r)
	if w.Code != http.StatusConflict {
		t.Errorf("managed-DP overrides PUT: got %d, want 409", w.Code)
	}
	// CP node IS authoritative: same PUT succeeds.
	f3a2SwapRole(t, "control-plane")
	if w := dispatchSettings(RoleAdmin, http.MethodPut, `{"enabled":true}`); w.Code != http.StatusOK {
		t.Errorf("control-plane settings PUT: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
}

// ─── overrides handler: full-set replace + explicit empty clear ─────────────────

func dispatchOverrides(role UIRole, method, body string) *httptest.ResponseRecorder {
	ctx := context.WithValue(context.Background(), uiRoleKey{}, role)
	r := httptest.NewRequestWithContext(ctx, method, "/api/saas-feed/overrides", strings.NewReader(body))
	w := httptest.NewRecorder()
	apiSaaSFeedOverrides(w, r)
	return w
}

func TestF3a2_OverridesHandler(t *testing.T) {
	f3a2ResetFeedDurable(t)
	s := f3a2SwapOverrides(t)
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))
	f3a2IsolateConfigWriters(t)
	f3a2SwapRole(t, "standalone")

	// PUT full set.
	if w := dispatchOverrides(RoleAdmin, http.MethodPut, `{"tombstones":["ads.example.com"],"added":{"work.example.com":"business"}}`); w.Code != http.StatusOK {
		t.Fatalf("PUT overrides: got %d (%s)", w.Code, w.Body.String())
	}
	if got := s.Get(); len(got.Tombstones) != 1 || got.Added["work.example.com"] != "business" {
		t.Errorf("overrides not applied: %+v", got)
	}
	// Explicit empty replacement clears everything.
	if w := dispatchOverrides(RoleAdmin, http.MethodPut, `{}`); w.Code != http.StatusOK {
		t.Fatalf("PUT empty overrides: got %d", w.Code)
	}
	if got := s.Get(); len(got.Tombstones) != 0 || len(got.Added) != 0 {
		t.Errorf("empty PUT did not clear overrides: %+v", got)
	}
	// Invalid override ⇒ 400, no mutation.
	_ = s.ReplaceAll(CategoryOverrides{Tombstones: []string{"keep.example.com"}})
	if w := dispatchOverrides(RoleAdmin, http.MethodPut, `{"added":{"*.wild":"x"}}`); w.Code != http.StatusBadRequest {
		t.Errorf("PUT invalid override: got %d, want 400", w.Code)
	}
	if got := s.Get(); len(got.Tombstones) != 1 {
		t.Errorf("invalid override PUT mutated state: %+v", got)
	}
	// Viewer PUT forbidden.
	if w := dispatchOverrides(RoleViewer, http.MethodPut, `{}`); w.Code != http.StatusForbidden {
		t.Errorf("viewer overrides PUT: got %d, want 403", w.Code)
	}
}

// ─── 11/12. export/import round-trip + legacy protocol rejection ─────────────────

func TestF3a2_ImportValidation(t *testing.T) {
	// Legacy/unsupported protocol in an import payload is rejected whole.
	b := &configBackup{SaaSFeedProtocol: "raw_feed_v0", SaaSFeedURL: builtinSaaSFeedURL}
	if err := validateSaaSFeedImport(b); err == nil {
		t.Error("legacy protocol import accepted")
	}
	// Non-official URL rejected.
	b = &configBackup{SaaSFeedProtocol: saasFeedProtocolV1, SaaSFeedURL: "https://raw.githubusercontent.com/x/y/z.json"}
	if err := validateSaaSFeedImport(b); err == nil {
		t.Error("non-official import URL accepted")
	}
	// Historical GitHub URL resolves (accepted, rewritten to official).
	b = &configBackup{SaaSFeedProtocol: saasFeedProtocolV1, SaaSFeedURL: historicalSaaSFeedURLs[0]}
	if err := validateSaaSFeedImport(b); err != nil {
		t.Errorf("historical URL rejected: %v", err)
	}
	// Valid.
	b = &configBackup{SaaSFeedProtocol: saasFeedProtocolV1, SaaSFeedURL: "", CategoryOverrides: &CategoryOverrides{Tombstones: []string{"x.example.com"}}}
	if err := validateSaaSFeedImport(b); err != nil {
		t.Errorf("valid import rejected: %v", err)
	}
}

func TestF3a2_ImportApply_NeverWipeAndManaged(t *testing.T) {
	f3a2ResetFeedDurable(t)
	s := f3a2SwapOverrides(t)
	_ = s.ReplaceAll(CategoryOverrides{Tombstones: []string{"pre.example.com"}})

	// A backup with NO feed fields (protocol empty) must never wipe existing config.
	setSaaSFeedDurable(saasFeedDurable{Managed: true, Enabled: false, URL: builtinSaaSFeedURL, Protocol: saasFeedProtocolV1, SchemaVersion: saasStoreSchemaVersion})
	before := getSaaSFeedDurable()
	importSaaSFeedConfig(&configBackup{}) // protocol empty ⇒ skip
	if getSaaSFeedDurable() != before {
		t.Error("empty import wiped feed config (must be never-wipe)")
	}
	// An empty override set never wipes on import.
	importCategoryOverrides(&configBackup{CategoryOverrides: &CategoryOverrides{}}, true)
	if got := s.Get(); len(got.Tombstones) != 1 {
		t.Errorf("empty override import wiped live overrides: %+v", got)
	}
	// A populated import applies.
	importSaaSFeedConfig(&configBackup{SaaSFeedProtocol: saasFeedProtocolV1, SaaSFeedEnabled: true, SaaSFeedURL: builtinSaaSFeedURL})
	if d := getSaaSFeedDurable(); !d.Enabled {
		t.Errorf("populated import not applied: %+v", d)
	}
}

// ─── 13. rollback round-trip excludes node-local operational state ───────────────
// (Node-local floor/generation/activation state has NO configBackup binding by
// construction, so capture/apply can't touch it. Here we prove the CONFIG half
// round-trips through capture→apply.)

func TestF3a2_RollbackConfigRoundTrip(t *testing.T) {
	f3a2ResetFeedDurable(t)
	f3a2SwapOverrides(t)
	setSaaSFeedDurable(saasFeedDurable{Managed: true, Enabled: false, URL: builtinSaaSFeedURL, Protocol: saasFeedProtocolV1, RefreshSeconds: 3600, SchemaVersion: saasStoreSchemaVersion})
	_ = globalCategoryOverrides.ReplaceAll(CategoryOverrides{Added: map[string]string{"a.example.com": "social"}})

	capA := captureConfigBackup()
	if capA.SaaSFeedProtocol != saasFeedProtocolV1 || !capA.SaaSFeedManaged || capA.SaaSFeedEnabled {
		t.Fatalf("capture wrong: %+v", capA)
	}
	if capA.CategoryOverrides == nil || capA.CategoryOverrides.Added["a.example.com"] != "social" {
		t.Fatalf("override capture wrong: %+v", capA.CategoryOverrides)
	}

	// Diverge, then roll back.
	setSaaSFeedDurable(saasFeedDurable{Managed: false, Enabled: true, SchemaVersion: saasStoreSchemaVersion})
	_ = globalCategoryOverrides.ReplaceAll(CategoryOverrides{Tombstones: []string{"z.example.com"}})
	applyConfigBackup(capA)

	if d := getSaaSFeedDurable(); !d.Managed || d.Enabled || d.URL != builtinSaaSFeedURL {
		t.Errorf("feed config not restored: %+v", d)
	}
	if got := globalCategoryOverrides.Get(); got.Added["a.example.com"] != "social" || len(got.Tombstones) != 0 {
		t.Errorf("overrides not restored: %+v", got)
	}
}

// ─── 13b. rollback persists feed config to admin_settings.json (Codex P2) ───────
//
// applyConfigBackup restores feed scalars in-memory only; the versioned stores
// (blocklist/overrides) persist themselves, but feed scalars live in
// admin_settings.json. Without the rollback-path SaveAdminSettings, a restart
// would reload the pre-rollback values. This proves the rolled-back state is
// actually written to disk.
func TestF3a2_RollbackPersistsFeedConfig(t *testing.T) {
	f3a2ResetFeedDurable(t)
	f3a2SwapOverrides(t)
	settingsPath := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, settingsPath)
	f3a2IsolateConfigWriters(t)

	// State A: managed, disabled — captured as version 1.
	setSaaSFeedDurable(saasFeedDurable{Managed: true, Enabled: false, URL: builtinSaaSFeedURL, Protocol: saasFeedProtocolV1, RefreshSeconds: 3600, SchemaVersion: saasStoreSchemaVersion})
	saveConfigVersion("tester", "seed feed A")
	ver := configVersions.Seq()

	// Diverge to state B (unmanaged, enabled) and persist B so the file starts at B.
	setSaaSFeedDurable(saasFeedDurable{Managed: false, Enabled: true, URL: builtinSaaSFeedURL, Protocol: saasFeedProtocolV1, RefreshSeconds: 60, SchemaVersion: saasStoreSchemaVersion})
	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("seed B persist: %v", err)
	}

	// Roll back to A via the real handler.
	body, _ := json.Marshal(map[string]any{"version": ver})
	r := httptest.NewRequest(http.MethodPost, "/api/config/rollback", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	rollbackConfigVersion(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("rollback status = %d, want 200 (%s)", w.Code, w.Body.String())
	}

	// The on-disk admin_settings.json must reflect the rolled-back (A) feed state.
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read admin settings: %v", err)
	}
	var got AdminSettings
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal admin settings: %v", err)
	}
	if !got.SaaSFeedManaged || got.SaaSFeedEnabled || got.SaaSFeedRefreshSeconds != 3600 {
		t.Errorf("rollback not persisted: managed=%v enabled=%v refresh=%d (want true/false/3600)",
			got.SaaSFeedManaged, got.SaaSFeedEnabled, got.SaaSFeedRefreshSeconds)
	}
}

// ─── 13c. import preview surfaces feed + override changes (Codex P3) ─────────────
func TestF3a2_ImportPreviewShowsFeedAndOverrides(t *testing.T) {
	f3a2SwapOverrides(t) // clean current override set so "current" count is 0

	b := configBackup{
		SaaSFeedProtocol:       saasFeedProtocolV1,
		SaaSFeedManaged:        true,
		SaaSFeedEnabled:        true,
		SaaSFeedURL:            builtinSaaSFeedURL,
		SaaSFeedRefreshSeconds: 7200,
		CategoryOverrides:      &CategoryOverrides{Added: map[string]string{"h.example.com": "social"}},
	}
	sections, settings := buildImportPreview(&b, false, nil)

	var ovSection *importPreviewSection
	for i := range sections {
		if sections[i].Section == "Category Overrides" {
			ovSection = &sections[i]
		}
	}
	if ovSection == nil {
		t.Fatalf("Category Overrides section missing from preview: %+v", sections)
	}
	if ovSection.Incoming != 1 {
		t.Errorf("override incoming = %d, want 1", ovSection.Incoming)
	}

	want := map[string]bool{"SaaS Feed": false, "SaaS Feed URL": false, "SaaS Feed Refresh": false}
	for _, s := range settings {
		if _, ok := want[s.Setting]; ok {
			want[s.Setting] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("import preview missing setting %q: %+v", name, settings)
		}
	}

	// A pre-extension backup (no protocol) must surface no feed rows.
	empty := configBackup{}
	_, emptySettings := buildImportPreview(&empty, false, nil)
	for _, s := range emptySettings {
		if strings.HasPrefix(s.Setting, "SaaS Feed") {
			t.Errorf("pre-extension backup leaked feed setting %q", s.Setting)
		}
	}
}

// ─── 14. persistence failure ⇒ no partial mutation ──────────────────────────────

func TestF3a2_PersistFailure_NoPartialMutation(t *testing.T) {
	f3a2ResetFeedDurable(t)
	f3a2SwapOverrides(t)
	f3a2SwapRole(t, "standalone")
	// Point admin_settings at an unwritable path (missing parent dir) so
	// SaveAdminSettings fails and the handler must revert the runtime.
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "no-such-dir", "admin_settings.json"))
	before := getSaaSFeedDurable()

	w := dispatchSettings(RoleAdmin, http.MethodPut, `{"managed":true,"enabled":true,"protocol":"signed_manifest_v1"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("persist-fail PUT: got %d, want 500 (%s)", w.Code, w.Body.String())
	}
	if getSaaSFeedDurable() != before {
		t.Errorf("runtime not reverted after persist failure: %+v", getSaaSFeedDurable())
	}
}

// ─── 17. CRITICAL SEPARATION: no downloader / network / live-store side effects ──

func TestF3a2_NoLegacySyncerOrLiveStoreSideEffects(t *testing.T) {
	f3a2ResetFeedDurable(t)
	f3a2SwapOverrides(t)
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))
	f3a2IsolateConfigWriters(t)
	f3a2SwapRole(t, "standalone")

	// Snapshot the legacy syncer's configured URL + the live category store.
	legacyURLBefore := globalSaaSFeed.FeedURL()
	catCountBefore := len(catStore.All())

	// Configure the SIGNED feed to the official manifest URL via the new API.
	if w := dispatchSettings(RoleAdmin, http.MethodPut, `{"managed":true,"enabled":true,"url":"`+builtinSaaSFeedURL+`","protocol":"signed_manifest_v1","refresh":"24h"}`); w.Code != http.StatusOK {
		t.Fatalf("settings PUT: got %d (%s)", w.Code, w.Body.String())
	}
	// Add overrides too.
	if w := dispatchOverrides(RoleAdmin, http.MethodPut, `{"tombstones":["ads.example.com"]}`); w.Code != http.StatusOK {
		t.Fatalf("overrides PUT: got %d", w.Code)
	}

	// The legacy additive syncer must NOT have been pointed at the signed manifest
	// URL — its configured URL is unchanged (no reinterpretation as a raw feed).
	if got := globalSaaSFeed.FeedURL(); got != legacyURLBefore {
		t.Errorf("legacy syncer URL changed to %q (was %q) — signed URL leaked into the raw syncer", got, legacyURLBefore)
	}
	if globalSaaSFeed.FeedURL() == builtinSaaSFeedURL {
		t.Error("legacy syncer pointed at the signed manifest URL")
	}
	// The live category store must be untouched (no fetch/merge/activation).
	if got := len(catStore.All()); got != catCountBefore {
		t.Errorf("live category store mutated by feed-config change: %d → %d", catCountBefore, got)
	}
	// The durable holder DID record the signed config (plumbing worked).
	if d := getSaaSFeedDurable(); d.URL != builtinSaaSFeedURL {
		t.Errorf("signed URL not recorded in durable holder: %+v", d)
	}
}
