package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

func uiPolicyFixture(t *testing.T) {
	t.Helper()
	resetUIAccessPolicyGlobals(t)
	ensureUIAccessPolicyTestLogger(t)
	if err := SetUIAllowedCIDRs(nil); err != nil {
		t.Fatal(err)
	}
}

func uiPolicyResponse(t *testing.T, peer string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/setup/status", nil)
	r.RemoteAddr = peer
	w := httptest.NewRecorder()
	uiIPGuardMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(w, r)
	return w
}

func TestUIAllowIPsStrictValidationPreservesPolicy(t *testing.T) {
	uiPolicyFixture(t)
	seed := []string{"192.0.2.0/24", "2001:db8::/32"}
	if err := SetUIAllowedCIDRs(seed); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{""}, {" \t"}, {"192.0.2.1", "invalid"}, {"2001:db8::1", ""}, {"::ffff:invalid"}} {
		if err := SetUIAllowedCIDRs(bad); err == nil {
			t.Fatalf("accepted malformed list %q", bad)
		}
		if !reflect.DeepEqual(ListUIAllowedCIDRs(), seed) {
			t.Fatal("refused mutation changed policy")
		}
	}
	for _, peer := range []string{"192.0.2.4:1234", "[2001:db8::4]:1234"} {
		if got := uiPolicyResponse(t, peer).Code; got != http.StatusNoContent {
			t.Fatalf("allowed peer status %d", got)
		}
	}
	if got := uiPolicyResponse(t, "198.51.100.4:1234").Code; got != http.StatusForbidden {
		t.Fatalf("disallowed peer status %d", got)
	}
	if err := SetUIAllowedCIDRs([]string{}); err != nil {
		t.Fatal(err)
	}
	if got := uiPolicyResponse(t, "198.51.100.4:1234").Code; got != http.StatusNoContent {
		t.Fatalf("explicit empty status %d", got)
	}
}

func TestUIAllowIPsMalformedSavedPolicyStaysRefusedAcrossSave(t *testing.T) {
	uiPolicyFixture(t)
	path := filepath.Join(t.TempDir(), "settings.json")
	setUISettingsTestPath(t, path)
	bad := []string{"192.0.2.0/24", " "}
	applyAdminUIAccessPolicy(&AdminSettings{UIAllowIPs: bad})
	if got := uiPolicyResponse(t, "192.0.2.1:10"); got.Code != 503 || !strings.Contains(got.Body.String(), "ui_access_policy_unavailable") {
		t.Fatal("malformed loaded policy did not refuse management")
	}
	checks := map[string]*readinessCheck{}
	appendUIAccessReadinessCheck(checks)
	if checks["ui_access_policy"] == nil || checks["ui_access_policy"].Status != "fail" {
		t.Fatal("missing readiness refusal")
	}
	if err := SaveAdminSettings(); err != nil && (runtime.GOOS != "windows" || !errors.Is(err, fileutil.ErrReplacedNotSynced)) {
		t.Fatal(err)
	}
	var saved AdminSettings
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if !saved.UIAllowIPsSaved || !reflect.DeepEqual(saved.UIAllowIPs, bad) {
		t.Fatal("unrelated save erased refused policy")
	}
	if err := SetUIAllowedCIDRs(nil); err != nil {
		t.Fatal(err)
	}
	applyAdminUIAccessPolicy(&saved)
	if !uiAccessPolicyRefused() {
		t.Fatal("restart silently reopened management")
	}
}

func uiPolicyPOST(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.WithValue(t.Context(), uiRoleKey{}, RoleAdmin), http.MethodPost, "/api/ui-allow-ips", strings.NewReader(body))
	apiUIAllowIPs(w, r)
	return w
}

func TestUIAllowIPsAPIInvalidOrFailedSavePreservesPolicy(t *testing.T) {
	uiPolicyFixture(t)
	seed := []string{"192.0.2.0/24"}
	if err := SetUIAllowedCIDRs(seed); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{}`, `{"ips":null}`, `{"ips":[""]}`, `{"ips":["192.0.2.1","bad"]}`, `{"ips":"192.0.2.1"}`} {
		w := uiPolicyPOST(t, body)
		if w.Code != 400 || !strings.Contains(w.Body.String(), `"code":"invalid_ui_allow_ips"`) {
			t.Fatalf("invalid body response: %d %s", w.Code, w.Body.String())
		}
		if !reflect.DeepEqual(ListUIAllowedCIDRs(), seed) {
			t.Fatal("invalid body changed runtime")
		}
	}
	// Atomic replacement of a directory fails on Linux and Windows, including root.
	path := filepath.Join(t.TempDir(), "not-a-file")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	setUISettingsTestPath(t, path)
	w := uiPolicyPOST(t, `{"ips":[]}`)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "ui_allow_ips_not_saved") {
		t.Fatalf("failed persistence claimed success: %d %s", w.Code, w.Body.String())
	}
	if !reflect.DeepEqual(ListUIAllowedCIDRs(), seed) {
		t.Fatal("failed save changed runtime")
	}
}

func TestUIAllowIPsAPIDurableEmptyOverridesStartupSeed(t *testing.T) {
	uiPolicyFixture(t)
	path := filepath.Join(t.TempDir(), "settings.json")
	setUISettingsTestPath(t, path)
	if err := SetUIAllowedCIDRs([]string{"192.0.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	w := uiPolicyPOST(t, `{"ips":[]}`)
	wantStatus := http.StatusOK
	if runtime.GOOS == "windows" {
		// Windows cannot fsync this directory handle; exercise the explicit
		// landed-but-uncertain branch without pretending it proves durability.
		wantStatus = http.StatusServiceUnavailable
		if !strings.Contains(w.Body.String(), "ui_allow_ips_persistence_uncertain") {
			t.Fatal("post-rename uncertainty was not distinguished from refusal")
		}
	}
	if w.Code != wantStatus {
		t.Fatalf("explicit empty failed: %d %s", w.Code, w.Body.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved AdminSettings
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if !saved.UIAllowIPsSaved || len(saved.UIAllowIPs) != 0 {
		t.Fatal("empty intent not durably authoritative")
	}
	if err := SetUIAllowedCIDRs([]string{"192.0.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	applyAdminUIAccessPolicy(&saved)
	if got := uiPolicyResponse(t, "198.51.100.8:10").Code; got != 204 {
		t.Fatalf("saved empty did not override seed: %d", got)
	}
}

func TestUIAllowIPsUnknownStateRefusesSaveAndSurvivesResidualQuarantine(t *testing.T) {
	uiPolicyFixture(t)
	path := filepath.Join(t.TempDir(), "settings.json")
	setUISettingsTestPath(t, path)
	before := []byte(`{"ui_allow_ips":["192.0.2.0/24"]}`)
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	refuseLoadedUIAccessPolicy(nil)
	if err := SaveAdminSettings(); err == nil {
		t.Fatal("unknown policy allowed an omnibus save")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("unknown stored state overwritten")
	}
	if err := SetUIAllowedCIDRs(nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".corrupt.1", []byte("synthetic corrupt fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	noteUIAccessQuarantine(path)
	applyAdminUIAccessPolicy(&AdminSettings{})
	if !uiAccessPolicyRefused() {
		t.Fatal("defaults after quarantine reopened management")
	}
	applyAdminUIAccessPolicy(&AdminSettings{UIAllowIPsSaved: true, UIAllowIPs: []string{"192.0.2.0/24"}})
	if uiAccessPolicyRefused() {
		t.Fatal("explicit locally repaired policy did not recover")
	}
}

func TestUIAllowIPsUnreadableSettingsRefusesManagement(t *testing.T) {
	uiPolicyFixture(t)
	t.Cleanup(rewriter.Snapshot())
	publishRewriteRules(nil)
	path := t.TempDir() // A directory is not a readable settings document, even as root.
	setUISettingsTestPath(t, path)
	LoadAdminSettings(path)
	if got := uiPolicyResponse(t, "192.0.2.1:10").Code; got != 503 {
		t.Fatalf("unreadable settings exposed management: %d", got)
	}
	if err := SaveAdminSettings(); err == nil {
		t.Fatal("unreadable policy accepted an omnibus save")
	}
}

func TestUIAllowIPsNullSettingsIsNotFirstBoot(t *testing.T) {
	var settings AdminSettings
	if err := decodeAdminSettingsObject([]byte(" null\n"), &settings); err == nil {
		t.Fatal("null settings document accepted as unrestricted first boot")
	}
	for _, valid := range []string{`{}`, `{"ui_allow_ips":[]}`} {
		if err := decodeAdminSettingsObject([]byte(valid), &settings); err != nil {
			t.Fatal(err)
		}
	}
}

func setUISettingsTestPath(t *testing.T, path string) {
	t.Helper()
	adminSettingsMu.Lock()
	prev := adminSettingsPath
	adminSettingsPath = path
	adminSettingsMu.Unlock()
	prevSurfaces := adminSettingsOverriddenSurfaces.Load()
	t.Cleanup(func() {
		adminSettingsMu.Lock()
		adminSettingsPath = prev
		adminSettingsMu.Unlock()
		adminSettingsOverriddenSurfaces.Store(prevSurfaces)
	})
}
