package main

// av_unavailable_posture_test.go — the admin/boot surface of the scanner's
// av_unavailable posture: the GET/PUT API (RBAC, validation, stale-writer
// fence, persist-before-apply), admin_settings.json durability, the
// CULVERT_AV_UNAVAILABLE boot default and its precedence, the status/metrics
// surfaces, and the deployment artifacts (compose, installer, appliance first
// boot) that ship the appliance default of closed.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// withAVPostureState snapshots the live posture + provenance and restores both.
func withAVPostureState(t *testing.T) {
	t.Helper()
	prev := secscan.AVUnavailablePosture()
	prevSaved := avPostureSaved.Load()
	t.Cleanup(func() {
		_ = secscan.SetAVUnavailablePosture(prev)
		avPostureSaved.Store(prevSaved)
	})
}

type avSettingsResp struct {
	AVUnavailable string `json:"av_unavailable"`
	Source        string `json:"source"`
	Revision      string `json:"revision"`
}

func getAVSettings(t *testing.T) avSettingsResp {
	t.Helper()
	w := httptest.NewRecorder()
	apiSecAVSettings(w, newViewerRequest("/api/security-scan/av-settings"))
	if w.Code != http.StatusOK {
		t.Fatalf("viewer GET: %d %s", w.Code, w.Body.String())
	}
	var r avSettingsResp
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatalf("decode: %v; %s", err, w.Body.String())
	}
	return r
}

func putAVSettings(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	apiSecAVSettings(w, newAdminRequest(http.MethodPut, "/api/security-scan/av-settings", []byte(body)))
	return w
}

func TestAVSettingsAPI_RBACValidationAndApply(t *testing.T) {
	withAVPostureState(t)
	swapAdminSettingsPath(t, "") // no persistence: the trivially-successful write path
	_ = secscan.SetAVUnavailablePosture(secscan.AVUnavailableOpen)
	avPostureSaved.Store(false)

	g := getAVSettings(t)
	if g.AVUnavailable != "open" || g.Source != "boot" || g.Revision == "" {
		t.Fatalf("default GET = %+v, want open/boot/revision", g)
	}

	// Viewer PUT is forbidden and changes nothing.
	r := httptest.NewRequestWithContext(context.WithValue(context.Background(), uiRoleKey{}, RoleViewer),
		http.MethodPut, "/api/security-scan/av-settings", bytes.NewReader([]byte(`{"av_unavailable":"closed"}`)))
	w := httptest.NewRecorder()
	apiSecAVSettings(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer PUT: want 403, got %d", w.Code)
	}
	if secscan.AVUnavailablePosture() != "open" {
		t.Fatal("a forbidden PUT changed the posture")
	}

	// Invalid values are 400 and change nothing.
	for _, body := range []string{`{"av_unavailable":""}`, `{"av_unavailable":"deny"}`, `{"av_unavailable":"fail_closed"}`, `{}`, `not json`} {
		if w := putAVSettings(t, body); w.Code != http.StatusBadRequest {
			t.Errorf("PUT %s: want 400, got %d %s", body, w.Code, w.Body.String())
		}
	}
	if secscan.AVUnavailablePosture() != "open" || avPostureSaved.Load() {
		t.Fatal("a rejected PUT changed the posture or its provenance")
	}

	// Admin PUT applies and takes ownership.
	w = putAVSettings(t, `{"av_unavailable":"CLOSED"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("admin PUT: %d %s", w.Code, w.Body.String())
	}
	var put avSettingsResp
	_ = json.Unmarshal(w.Body.Bytes(), &put)
	if put.AVUnavailable != "closed" || put.Source != "admin" {
		t.Fatalf("PUT response = %+v", put)
	}
	if secscan.AVUnavailablePosture() != "closed" || !avPostureSaved.Load() {
		t.Fatal("admin PUT did not install closed as an admin-owned posture")
	}
	if g := getAVSettings(t); g != put {
		t.Fatalf("GET after PUT = %+v, PUT returned %+v (coherent pair)", g, put)
	}
}

func TestAVSettingsAPI_StaleRevisionIsRefused(t *testing.T) {
	withAVPostureState(t)
	swapAdminSettingsPath(t, "")
	_ = secscan.SetAVUnavailablePosture(secscan.AVUnavailableOpen)
	stale := getAVSettings(t).Revision
	if w := putAVSettings(t, `{"av_unavailable":"closed","ifRevision":"`+stale+`"}`); w.Code != http.StatusOK {
		t.Fatalf("fresh fenced PUT: %d %s", w.Code, w.Body.String())
	}
	w := putAVSettings(t, `{"av_unavailable":"open","ifRevision":"`+stale+`"}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "currentRevision") {
		t.Fatalf("stale fenced PUT: want structured 409, got %d %s", w.Code, w.Body.String())
	}
	if secscan.AVUnavailablePosture() != "closed" {
		t.Fatal("a refused stale write changed the posture")
	}
}

// TestAVSettings_PersistRoundTrip: PUT → admin_settings.json → restart
// (LoadAdminSettings) restores the admin-owned posture.
func TestAVSettings_PersistRoundTrip(t *testing.T) {
	withAVPostureState(t)
	resetYARASettings(t)
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)
	_ = secscan.SetAVUnavailablePosture(secscan.AVUnavailableOpen)
	avPostureSaved.Store(false)

	if w := putAVSettings(t, `{"av_unavailable":"closed"}`); w.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", w.Code, w.Body.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk AdminSettings
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	if !onDisk.AVUnavailableSaved || onDisk.AVUnavailable != "closed" {
		t.Fatalf("file must record the admin-owned posture, got saved=%v value=%q", onDisk.AVUnavailableSaved, onDisk.AVUnavailable)
	}

	// Simulated restart: boot posture open, nothing owned yet, then load.
	_ = secscan.SetAVUnavailablePosture(secscan.AVUnavailableOpen)
	avPostureSaved.Store(false)
	LoadAdminSettings(path)
	if secscan.AVUnavailablePosture() != "closed" || !avPostureSaved.Load() {
		t.Fatalf("reload: posture %q saved=%v, want closed/true", secscan.AVUnavailablePosture(), avPostureSaved.Load())
	}

	// An unrelated omnibus save carries the admin-owned posture forward.
	if err := SaveAdminSettings(); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(path)
	if !strings.Contains(string(raw), `"av_unavailable": "closed"`) {
		t.Fatal("an unrelated save dropped the admin-owned posture")
	}
}

// TestAVSettings_PersistFailureLeavesPostureUnchanged: persist-before-apply.
func TestAVSettings_PersistFailureLeavesPostureUnchanged(t *testing.T) {
	withAVPostureState(t)
	resetYARASettings(t)
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "missing-dir", "admin_settings.json"))
	_ = secscan.SetAVUnavailablePosture(secscan.AVUnavailableOpen)
	avPostureSaved.Store(false)
	w := putAVSettings(t, `{"av_unavailable":"closed"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("unwritable settings: want 500, got %d %s", w.Code, w.Body.String())
	}
	if secscan.AVUnavailablePosture() != "open" || avPostureSaved.Load() {
		t.Fatal("a failed persist must leave the live posture untouched")
	}
}

// TestAVSettings_EnvBootPostureAndPrecedence: CULVERT_AV_UNAVAILABLE applies at
// boot, junk is ignored (open stays), and an explicitly saved admin choice
// wins at load — while an unrelated save never freezes the env value.
func TestAVSettings_EnvBootPostureAndPrecedence(t *testing.T) {
	withAVPostureState(t)
	resetYARASettings(t)
	cases := []struct{ env, want string }{
		{"closed", "closed"}, // the appliance case
		{" OPEN ", "open"},   // case/space tolerant
		{"", "open"},         // unset ⇒ unchanged (open)
		{"bogus", "open"},    // junk ignored ⇒ unchanged (open)
	}
	for _, tc := range cases {
		_ = secscan.SetAVUnavailablePosture(secscan.AVUnavailableOpen)
		applyAVUnavailableBootPosture(tc.env)
		if got := secscan.AVUnavailablePosture(); got != tc.want {
			t.Errorf("env %q: posture %q, want %q", tc.env, got, tc.want)
		}
	}

	// The scanning resolver carries the shim-read env through untouched.
	cfg := resolveScanningStartupConfig(&FileConfig{}, scanningCLIFlags{AVUnavailableEnv: "closed"}, "")
	if cfg.AVUnavailableEnv != "closed" {
		t.Fatalf("resolver dropped the env: %+v", cfg.AVUnavailableEnv)
	}

	// Without a saved setting, the env posture survives load AND an
	// unrelated omnibus save does not freeze it into the file.
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)
	avPostureSaved.Store(false)
	applyAVUnavailableBootPosture("closed")
	if err := SaveAdminSettings(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "av_unavailable") {
		t.Fatalf("an unrelated save froze the boot posture into the file:\n%s", raw)
	}
	_ = secscan.SetAVUnavailablePosture(secscan.AVUnavailableOpen)
	applyAVUnavailableBootPosture("closed")
	LoadAdminSettings(path)
	if secscan.AVUnavailablePosture() != "closed" {
		t.Fatal("a file without the sentinel must leave the boot posture standing")
	}

	// A saved admin choice wins over the env.
	saved, _ := json.Marshal(AdminSettings{AVUnavailableSaved: true, AVUnavailable: "open", YARASettingsSaved: true,
		YARAEnabled: yaraGetEnabled(), YARATimeoutSecs: yaraGetTimeoutSecs(), YARAMaxInflight: yaraGetMaxInflight(),
		YARAOnTimeout: yaraGetOnTimeout(), YARAOnSaturation: yaraGetOnSaturation(), YARAAlertDegraded: yaraGetAlertDegraded()})
	savedPath := filepath.Join(t.TempDir(), "saved.json")
	if err := os.WriteFile(savedPath, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	applyAVUnavailableBootPosture("closed")
	LoadAdminSettings(savedPath)
	if secscan.AVUnavailablePosture() != "open" || !avPostureSaved.Load() {
		t.Fatalf("saved admin open must win over env closed, got %q", secscan.AVUnavailablePosture())
	}

	// A saved but corrupt value is refused; the boot posture stands.
	bad, _ := json.Marshal(AdminSettings{AVUnavailableSaved: true, AVUnavailable: "sideways"})
	badPath := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(badPath, bad, 0o600)
	avPostureSaved.Store(false)
	applyAVUnavailableBootPosture("closed")
	LoadAdminSettings(badPath)
	if secscan.AVUnavailablePosture() != "closed" || avPostureSaved.Load() {
		t.Fatalf("a corrupt saved value must be refused (boot posture closed stands), got %q saved=%v",
			secscan.AVUnavailablePosture(), avPostureSaved.Load())
	}
}

// TestAVSettings_StatusAndMetricsSurfaces: an operator can see which posture
// is active and how many bodies it refused.
func TestAVSettings_StatusAndMetricsSurfaces(t *testing.T) {
	withAVPostureState(t)
	_ = secscan.SetAVUnavailablePosture(secscan.AVUnavailableClosed)
	m := secScanStatusMap()
	if m["av_unavailable"] != "closed" {
		t.Fatalf("status av_unavailable = %v, want closed", m["av_unavailable"])
	}
	if _, ok := m["stat_av_unavailable_refused"]; !ok {
		t.Fatal("status is missing stat_av_unavailable_refused")
	}
	w := httptest.NewRecorder()
	handleMetrics(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	body := w.Body.String()
	for _, want := range []string{
		"# TYPE culvert_scan_av_unavailable_refused_total counter",
		"culvert_scan_av_unavailable_refused_total ",
		"culvert_scan_av_unavailable_closed 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
}

// TestAVSettings_ScanBlockSaysAVUnavailable: the 403 body names the cause
// instead of reading like a detection, and every other source is unchanged.
func TestAVSettings_ScanBlockSaysAVUnavailable(t *testing.T) {
	w := httptest.NewRecorder()
	scanBlock(w, "files.example", secscan.AVUnavailableReason, secscan.SourceAVUnavailable)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "antivirus scanning is currently unavailable") {
		t.Fatalf("av_unavailable block: %d %q", w.Code, w.Body.String())
	}
	if got := scanBlockBody("EICAR", "clamav"); got != "Blocked by CLAMAV scan: EICAR" {
		t.Fatalf("detection body changed: %q", got)
	}
	if got := scanBlockBody("scan timeout", "timeout"); got != "Blocked by TIMEOUT scan: scan timeout" {
		t.Fatalf("timeout body changed: %q", got)
	}
}

// ── Deployment artifacts: the appliance ships closed ────────────────────────

func TestDockerComposeForwardsAVUnavailableEnv(t *testing.T) {
	compose, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(compose)
	loc := regexp.MustCompile(`(?m)^ {2}proxy:`).FindStringIndex(s)
	if loc == nil {
		t.Fatal("docker-compose.yml has no proxy service")
	}
	rest := s[loc[1]:]
	if end := regexp.MustCompile(`(?m)^ {2}[a-zA-Z0-9_-]+:`).FindStringIndex(rest); end != nil {
		rest = rest[:end[0]]
	}
	if !regexp.MustCompile(`(?m)^\s*-\s*CULVERT_AV_UNAVAILABLE=\$\{CULVERT_AV_UNAVAILABLE:-\}\s*$`).MatchString(rest) {
		t.Fatal("proxy service must actively forward CULVERT_AV_UNAVAILABLE (as it does CULVERT_DEFAULT_ACTION)")
	}
}

func TestInstallScript_ForwardsAVUnavailablePosture(t *testing.T) {
	installSH := filepath.Join(pkgSourceDir(), "scripts", "install.sh")
	raw, err := os.ReadFile(installSH)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, `case "${CULVERT_INSTALL_AV_UNAVAILABLE:-}" in`)
	if start < 0 {
		t.Fatal("install.sh no longer handles CULVERT_INSTALL_AV_UNAVAILABLE")
	}
	end := strings.Index(src[start:], "\nesac\n")
	block := src[start : start+end+6]
	envPut := extractShellFunction(t, installSH, "env_put")
	run := func(t *testing.T, value string) (string, string) {
		t.Helper()
		envFile := filepath.Join(t.TempDir(), ".env")
		script := "set -euo pipefail\ninfo(){ :; }; warn(){ echo \"WARN: $*\"; }\n" + envPut +
			"\nINSTALL_DIR=\"$(dirname \"$1\")\"\nexport CULVERT_INSTALL_AV_UNAVAILABLE=\"$2\"\n" + block
		cmd := exec.CommandContext(t.Context(), "bash", "-c", script, "av_test", envFile, value) // #nosec G204 -- fixed test script content
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("script failed: %v\n%s", err, out)
		}
		got, _ := os.ReadFile(envFile)
		return string(got), string(out)
	}
	if env, _ := run(t, "closed"); !strings.Contains(env, "CULVERT_AV_UNAVAILABLE=closed\n") {
		t.Fatalf("closed not forwarded into .env:\n%s", env)
	}
	if env, _ := run(t, ""); strings.Contains(env, "CULVERT_AV_UNAVAILABLE") {
		t.Fatalf("unset must write nothing (historical open):\n%s", env)
	}
	if env, out := run(t, "sideways"); strings.Contains(env, "CULVERT_AV_UNAVAILABLE") || !strings.Contains(out, "Ignoring CULVERT_INSTALL_AV_UNAVAILABLE") {
		t.Fatalf("junk must be refused with a warning: env=%q out=%q", env, out)
	}
}

func TestApplianceFirstBoot_PassesAVUnavailableClosed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(pkgSourceDir(), "appliance", "provision", "culvert-firstboot.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^\s*export CULVERT_INSTALL_AV_UNAVAILABLE=closed\s*$`).Match(raw) {
		t.Fatal("appliance first boot must export CULVERT_INSTALL_AV_UNAVAILABLE=closed beside CULVERT_INSTALL_DEFAULT_ACTION=deny")
	}
}
