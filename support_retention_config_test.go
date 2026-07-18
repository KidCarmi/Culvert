package main

// support_retention_config_test.go — Slice B: admin-configurable support-bundle
// retention. Covers the runtime accessors, validate-before-convert bounds, the
// pointer-patch (omitted=unchanged) PUT semantics, the persist-before-apply +
// omnibus-save durability wiring, the typed-confirm destructive-tightening guard,
// RBAC, and the janitor boot-order contract.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// swapSupportRetention isolates the global retention config per test (mirrors
// swapAutoExclude): it stores cfg and restores the previous pointer on cleanup.
func swapSupportRetention(t *testing.T, cfg supportRetentionConfig) {
	t.Helper()
	prev := supportRetentionCfg.Load()
	setSupportRetention(cfg)
	t.Cleanup(func() { supportRetentionCfg.Store(prev) })
}

func callRetention(role UIRole, method string, body any) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	apiSupportRetention(w, roleReq(role, method, "/api/support/retention", body))
	return w
}

// TestSupportRetention_DefaultAccessors — with nothing applied, the accessors
// return the compiled defaults (feature-off is byte-identical to the old consts).
func TestSupportRetention_DefaultAccessors(t *testing.T) {
	prev := supportRetentionCfg.Load()
	supportRetentionCfg.Store(nil)
	t.Cleanup(func() { supportRetentionCfg.Store(prev) })

	if got := supportRetentionKeepVal(); got != defaultSupportRetentionKeep {
		t.Errorf("keep default = %d, want %d", got, defaultSupportRetentionKeep)
	}
	if got := supportRetentionMaxAgeVal(); got != time.Duration(defaultSupportRetentionMaxAgeDays)*24*time.Hour {
		t.Errorf("max-age default = %v, want %dd", got, defaultSupportRetentionMaxAgeDays)
	}
}

// TestSupportRetention_ValidateBounds — REJECT (never clamp) out-of-range values,
// including the overflow-prone upper edge (validate runs before days→duration).
func TestSupportRetention_ValidateBounds(t *testing.T) {
	ok := []supportRetentionConfig{
		{Keep: supportRetentionKeepMin, MaxAgeDays: supportRetentionDaysMin},
		{Keep: supportRetentionKeepMax, MaxAgeDays: supportRetentionDaysMax},
		{Keep: 10, MaxAgeDays: 30},
	}
	for _, c := range ok {
		if err := validateSupportRetention(c); err != nil {
			t.Errorf("validate(%+v) = %v, want nil", c, err)
		}
	}
	bad := []supportRetentionConfig{
		{Keep: 0, MaxAgeDays: 30},                           // keep below min (a corrupt 0 must not wipe all)
		{Keep: -1, MaxAgeDays: 30},                          // negative keep
		{Keep: supportRetentionKeepMax + 1, MaxAgeDays: 30}, // keep above max
		{Keep: 10, MaxAgeDays: 0},                           // age below min
		{Keep: 10, MaxAgeDays: supportRetentionDaysMax + 1}, // age above max
		{Keep: 10, MaxAgeDays: 1 << 30},                     // absurd age (overflow guard)
	}
	for _, c := range bad {
		if err := validateSupportRetention(c); err == nil {
			t.Errorf("validate(%+v) = nil, want rejection", c)
		}
	}
}

// TestSupportRetention_PatchResolvePartial — an omitted (nil) patch field leaves
// that cap unchanged; only an explicit value mutates.
func TestSupportRetention_PatchResolvePartial(t *testing.T) {
	cur := supportRetentionConfig{Keep: 10, MaxAgeDays: 30}
	keep := 3
	got := supportRetentionPatch{Keep: &keep}.resolve(cur)
	if got.Keep != 3 || got.MaxAgeDays != 30 {
		t.Errorf("keep-only patch = %+v, want {3,30} (max_age unchanged)", got)
	}
	age := 7
	got = supportRetentionPatch{MaxAgeDays: &age}.resolve(cur)
	if got.Keep != 10 || got.MaxAgeDays != 7 {
		t.Errorf("age-only patch = %+v, want {10,7} (keep unchanged)", got)
	}
	if got := (supportRetentionPatch{}).resolve(cur); got != cur {
		t.Errorf("empty patch = %+v, want unchanged %+v", got, cur)
	}
}

// TestSupportRetention_SnapshotApplyRoundTrip — snapshot into AdminSettings, apply
// back; the sentinel gates application (unsaved ⇒ defaults, not a zero-wipe).
func TestSupportRetention_SnapshotApplyRoundTrip(t *testing.T) {
	swapSupportRetention(t, supportRetentionConfig{Keep: 5, MaxAgeDays: 14})

	var s AdminSettings
	snapshotSupportRetention(&s, nil)
	if !s.SupportRetentionSaved || s.SupportRetentionKeep != 5 || s.SupportRetentionMaxAgeDays != 14 {
		t.Fatalf("snapshot = %+v, want saved{5,14}", s)
	}

	// Apply from a DIFFERENT starting point restores the persisted values.
	setSupportRetention(supportRetentionConfig{Keep: 10, MaxAgeDays: 30})
	applyAdminSupportRetention(&s)
	if got := currentSupportRetention(); got.Keep != 5 || got.MaxAgeDays != 14 {
		t.Fatalf("apply = %+v, want {5,14}", got)
	}

	// Sentinel false ⇒ apply is a no-op (leaves the live config as-is).
	setSupportRetention(supportRetentionConfig{Keep: 9, MaxAgeDays: 21})
	applyAdminSupportRetention(&AdminSettings{SupportRetentionSaved: false, SupportRetentionKeep: 1})
	if got := currentSupportRetention(); got.Keep != 9 {
		t.Fatalf("unsaved apply mutated live config: %+v", got)
	}
}

// TestSupportRetention_ApplyRejectsCorrupt — a hand-edited out-of-range persisted
// value (e.g. keep=0) is refused on load; the live config keeps its prior value
// rather than adopting a config that would delete every bundle.
func TestSupportRetention_ApplyRejectsCorrupt(t *testing.T) {
	swapSupportRetention(t, supportRetentionConfig{Keep: 10, MaxAgeDays: 30})
	applyAdminSupportRetention(&AdminSettings{
		SupportRetentionSaved: true, SupportRetentionKeep: 0, SupportRetentionMaxAgeDays: 30,
	})
	if got := currentSupportRetention(); got.Keep != 10 {
		t.Fatalf("corrupt keep=0 was applied (%+v) — must fail closed to prior/defaults", got)
	}
}

// TestSupportRetention_ProjectionExemptions — the eviction projection honors the
// Slice A exemptions: case-bound evidence is exempt from both caps; pending from
// the count cap.
func TestSupportRetention_ProjectionExemptions(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	now := time.Unix(1_800_000_000, 0).UTC()
	ts := func(dAgo int) string { return now.Add(-time.Duration(dAgo) * time.Hour).Format(time.RFC3339) }

	// 4 ready+unbound (evictable) + 1 case-bound + 1 pending.
	writeFakeBundle(t, "csb_projnewaaaaaaaaaa234567abc", ts(1))
	writeFakeBundle(t, "csb_projtwoaaaaaaaaaa234567abc", ts(2))
	writeFakeBundle(t, "csb_projthreeaaaaaaa2234567abc", ts(3))
	writeFakeBundle(t, "csb_projfouraaaaaaaaa234567abc", ts(4))
	writeFakeBundle(t, "csb_projboundaaaaaaaa234567abc", ts(99))
	writeBundleStateFile(t, "csb_projboundaaaaaaaa234567abc", bundleStateReady, "SR-9")
	writeFakeBundle(t, "csb_projpendaaaaaaaaa234567abc", ts(99))
	writeBundleStateFile(t, "csb_projpendaaaaaaaaa234567abc", bundleStatePending, "")

	// keep=2 over 4 evictable ⇒ 2 overflow; evidence + pending exempt from count.
	set := projectRetentionEvictionSet(supportRetentionConfig{Keep: 2, MaxAgeDays: 3650}, now)
	if len(set) != 2 {
		t.Fatalf("count-cap projection = %d bundles, want 2 (evidence+pending exempt)", len(set))
	}
	if set["csb_projboundaaaaaaaa234567abc"] || set["csb_projpendaaaaaaaaa234567abc"] {
		t.Error("projection must never include case-bound or pending bundles under the count cap")
	}

	// Tight age cap (1h) ⇒ every non-evidence bundle older than 1h, but NOT the
	// case-bound one (evidence exempt from age too).
	ageSet := projectRetentionEvictionSet(supportRetentionConfig{Keep: 10000, MaxAgeDays: supportRetentionDaysMin}, now)
	if ageSet["csb_projboundaaaaaaaa234567abc"] {
		t.Error("age projection must never include case-bound evidence")
	}
}

// TestSupportRetention_IncrementalOnlyCountsNewLoss — a loosening returns 0
// incremental evictions; a tightening returns only the ADDITIONAL bundles it dooms.
func TestSupportRetention_IncrementalOnlyCountsNewLoss(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	now := time.Unix(1_800_000_000, 0).UTC()
	ts := func(dAgo int) string { return now.Add(-time.Duration(dAgo) * time.Hour).Format(time.RFC3339) }
	for i, seed := range []string{"incone", "inctwo", "incthree", "incfour"} {
		writeFakeBundle(t, "csb_"+seed+strings.Repeat("a", 26-len(seed)), ts(i+1))
	}

	cur := supportRetentionConfig{Keep: 4, MaxAgeDays: 3650}
	// Loosen keep 4→10: no new loss.
	if n := incrementalRetentionEvictions(supportRetentionConfig{Keep: 10, MaxAgeDays: 3650}, cur, now); n != 0 {
		t.Errorf("loosening incremental = %d, want 0", n)
	}
	// Tighten keep 4→2: 2 more doomed.
	if n := incrementalRetentionEvictions(supportRetentionConfig{Keep: 2, MaxAgeDays: 3650}, cur, now); n != 2 {
		t.Errorf("tightening keep 4→2 incremental = %d, want 2", n)
	}
}

// TestRetentionAPI_RBAC — GET=viewer, PUT=admin; lower roles are 403 on PUT.
func TestRetentionAPI_RBAC(t *testing.T) {
	swapSupportRetention(t, supportRetentionConfig{Keep: 10, MaxAgeDays: 30})
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))

	if w := callRetention(RoleViewer, http.MethodGet, nil); w.Code != http.StatusOK {
		t.Errorf("GET viewer: got %d, want 200", w.Code)
	}
	keep := 8
	body := supportRetentionPatch{Keep: &keep}
	for _, role := range []UIRole{RoleViewer, RoleOperator} {
		if w := callRetention(role, http.MethodPut, body); w.Code != http.StatusForbidden {
			t.Errorf("PUT as %v: got %d, want 403", role, w.Code)
		}
	}
	if w := callRetention(RoleAdmin, http.MethodPut, body); w.Code != http.StatusOK {
		t.Errorf("PUT admin: got %d, want 200 (%s)", w.Code, w.Body)
	}
}

// TestRetentionAPI_GET_Shape — GET returns current values, defaults, bounds, and a
// pending-eviction projection.
func TestRetentionAPI_GET_Shape(t *testing.T) {
	swapSupportRetention(t, supportRetentionConfig{Keep: 7, MaxAgeDays: 12})
	w := callRetention(RoleViewer, http.MethodGet, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: got %d", w.Code)
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"keep", "max_age_days", "defaults", "bounds", "pending_evictions"} {
		if _, ok := resp[k]; !ok {
			t.Errorf("GET missing key %q", k)
		}
	}
}

// TestRetentionAPI_PUT_EmptyAndOutOfRange — an empty/no-op body and an out-of-range
// value are both 400 and leave the live config unchanged.
func TestRetentionAPI_PUT_EmptyAndOutOfRange(t *testing.T) {
	swapSupportRetention(t, supportRetentionConfig{Keep: 10, MaxAgeDays: 30})
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))

	if w := callRetention(RoleAdmin, http.MethodPut, map[string]any{}); w.Code != http.StatusBadRequest {
		t.Errorf("empty body: got %d, want 400", w.Code)
	}
	zero := 0
	if w := callRetention(RoleAdmin, http.MethodPut, supportRetentionPatch{Keep: &zero}); w.Code != http.StatusBadRequest {
		t.Errorf("keep=0: got %d, want 400", w.Code)
	}
	if got := currentSupportRetention(); got.Keep != 10 || got.MaxAgeDays != 30 {
		t.Errorf("rejected PUT changed live config: %+v", got)
	}
}

// TestRetentionAPI_PUT_TighteningRequiresConfirm — a tightening that would evict
// bundles returns 409 with an evict_count; resubmitting with the matching
// confirm_evict succeeds.
func TestRetentionAPI_PUT_TighteningRequiresConfirm(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })
	swapSupportRetention(t, supportRetentionConfig{Keep: 10, MaxAgeDays: 3650})
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))

	now := time.Now()
	for i, seed := range []string{"cfone", "cftwo", "cfthree", "cffour"} {
		writeFakeBundle(t, "csb_"+seed+strings.Repeat("a", 26-len(seed)), now.Add(-time.Duration(i+1)*time.Hour).Format(time.RFC3339))
	}

	keep2 := 2 // 4 evictable, keep 2 ⇒ 2 doomed
	w := callRetention(RoleAdmin, http.MethodPut, supportRetentionPatch{Keep: &keep2})
	if w.Code != http.StatusConflict {
		t.Fatalf("tightening without confirm: got %d, want 409 (%s)", w.Code, w.Body)
	}
	var resp struct {
		EvictCount int `json:"evict_count"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.EvictCount != 2 {
		t.Fatalf("evict_count = %d, want 2", resp.EvictCount)
	}
	if got := currentSupportRetention(); got.Keep != 10 {
		t.Fatalf("409 must not apply the change: live keep=%d, want 10", got.Keep)
	}

	// A wrong confirm count is still refused (the store may have changed).
	wrong := 1
	if w := callRetention(RoleAdmin, http.MethodPut, supportRetentionPatch{Keep: &keep2, ConfirmEvict: &wrong}); w.Code != http.StatusConflict {
		t.Fatalf("mismatched confirm: got %d, want 409", w.Code)
	}
	// The exact confirm applies.
	right := 2
	if w := callRetention(RoleAdmin, http.MethodPut, supportRetentionPatch{Keep: &keep2, ConfirmEvict: &right}); w.Code != http.StatusOK {
		t.Fatalf("confirmed tightening: got %d, want 200 (%s)", w.Code, w.Body)
	}
	if got := currentSupportRetention(); got.Keep != 2 {
		t.Fatalf("confirmed PUT not applied: live keep=%d, want 2", got.Keep)
	}
}

// TestRetentionAPI_PUT_PersistFailureLeavesRuntimeUnchanged — persist-before-apply:
// a broken settings path 500s and never mutates the live config.
func TestRetentionAPI_PUT_PersistFailureLeavesRuntimeUnchanged(t *testing.T) {
	swapSupportRetention(t, supportRetentionConfig{Keep: 10, MaxAgeDays: 30})
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "missing-dir", "admin_settings.json"))

	keep := 5
	w := callRetention(RoleAdmin, http.MethodPut, supportRetentionPatch{Keep: &keep})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("persist failure: got %d, want 500", w.Code)
	}
	if got := currentSupportRetention(); got.Keep != 10 {
		t.Fatalf("runtime changed despite persist failure: %+v", got)
	}
}

// TestRetention_OmnibusSaveKeepsRetention is the silent-loss guard (§6 P0): after a
// retention PUT, an UNRELATED omnibus SaveAdminSettings must still carry the
// retention fields to disk (snapshotSupportRetention is wired into the rebuild),
// so changing any other admin setting can't drop retention back to defaults on the
// next restart.
func TestRetention_OmnibusSaveKeepsRetention(t *testing.T) {
	swapSupportRetention(t, supportRetentionConfig{Keep: 6, MaxAgeDays: 15})
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)

	// An omnibus save (as fired by any other admin mutation) with no retention override.
	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("SaveAdminSettings: %v", err)
	}
	var s AdminSettings
	data, _ := os.ReadFile(path)
	if json.Unmarshal(data, &s) != nil || !s.SupportRetentionSaved ||
		s.SupportRetentionKeep != 6 || s.SupportRetentionMaxAgeDays != 15 {
		t.Fatalf("omnibus save dropped retention: %+v", s)
	}
}

// TestRetention_JanitorBootOrder pins the §8 ordering contract by source-scan: the
// retention janitor is started from the persistent-admin-state loader AFTER
// LoadAdminSettings (so its boot sweep sees the configured caps), and is NOT started
// in the background-services slice (which runs before settings load).
func TestRetention_JanitorBootOrder(t *testing.T) {
	pa, err := os.ReadFile(filepath.Join(pkgSourceDir(), "persistent_admin_state_startup.go"))
	if err != nil {
		t.Fatalf("read persistent_admin_state_startup.go: %v", err)
	}
	src := string(pa)
	loadIdx := strings.Index(src, "LoadAdminSettings(")
	janIdx := strings.Index(src, "startSupportRetentionJanitor(")
	if loadIdx < 0 || janIdx < 0 {
		t.Fatalf("expected both LoadAdminSettings and startSupportRetentionJanitor in the persistent-admin loader")
	}
	if janIdx < loadIdx {
		t.Errorf("janitor must start AFTER LoadAdminSettings (jan@%d, load@%d)", janIdx, loadIdx)
	}
	bg, err := os.ReadFile(filepath.Join(pkgSourceDir(), "background_services_startup.go"))
	if err != nil {
		t.Fatalf("read background_services_startup.go: %v", err)
	}
	if strings.Contains(string(bg), "startSupportRetentionJanitor(") {
		t.Error("janitor must NOT be started in the background-services slice (it runs before LoadAdminSettings)")
	}
}
