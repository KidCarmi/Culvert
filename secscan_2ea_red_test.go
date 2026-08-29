package main

// secscan_2ea_red_test.go — 2E-A Content Security backend hardening:
// red-before proofs against ac0e16f2, written to compile at both trees.
//
// Defect families (each demonstrated RED at the candidate):
//
//	§1 LOST UPDATE — the whole-set/config-style PUTs (threat-feed domain
//	   allowlist, YARA engine settings, scan exclusions, DPI bypass) and the
//	   per-file YARA rule writes accept a stale write unconditionally: two
//	   admins read A, edit independently, and the second silently overwrites
//	   the first. The new contract: GETs carry a content-derived `revision`;
//	   writes may assert `ifRevision` and a mismatch is the ONE structured
//	   409 {error, currentRevision, yourRevision} with no mutation. Absent
//	   fence keeps the legacy last-writer-wins contract (compat).
//	§2 DURABILITY TRUTH — dpiScanner.Save() swallows the AtomicWrite error,
//	   so DPI pattern add/remove and DPI bypass replace return 200 when the
//	   configuration never reached disk; scan-exclusions PUT logs its Save
//	   error and still 200s; YARA settings PUT applies live values and
//	   detaches the settings save, returning 200 before (and regardless of)
//	   persistence. New contract: a persist failure is a truthful 500 —
//	   fail-safe surfaces stay applied in memory with a distinct
//	   *_unpersisted audit action (the domain-allowlist precedent), and the
//	   YARA settings PUT persists the target BEFORE applying (a failure
//	   leaves the live engine untouched).
//	§3 SECRET BOUNDARY — the scan-service base URL is echoed verbatim on
//	   viewer read surfaces; an operator URL carrying embedded credentials
//	   (http://user:secret@host) leaks them to every viewer. New contract:
//	   userinfo is redacted on every read surface.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/scanexcl"
	"github.com/KidCarmi/Culvert/internal/threatfeed"
	"github.com/KidCarmi/Culvert/internal/yara"
)

// sec2eaSwapThreatFeed installs a fresh, path-less threat feed (no
// persistence — the fence semantics are what is under test).
func sec2eaSwapThreatFeed(t *testing.T) {
	t.Helper()
	orig := globalThreatFeed
	globalThreatFeed = threatfeed.New()
	t.Cleanup(func() { globalThreatFeed = orig })
}

// sec2eaSwapExclusions installs a fresh exclusion store rooted at the given
// path (Load on a missing file records the path without error).
func sec2eaSwapExclusions(t *testing.T, path string) {
	t.Helper()
	orig := globalScanExclusions
	fresh := scanexcl.New()
	if err := fresh.Load(path); err != nil {
		t.Fatalf("seed exclusions path: %v", err)
	}
	globalScanExclusions = fresh
	t.Cleanup(func() { globalScanExclusions = orig })
}

// sec2eaSwapYARA installs a fresh YARA rule set rooted at a temp dir.
func sec2eaSwapYARA(t *testing.T) string {
	t.Helper()
	orig := globalYARA
	dir := t.TempDir()
	fresh := yara.NewRuleSet()
	fresh.SetDir(dir)
	globalYARA = fresh
	t.Cleanup(func() { globalYARA = orig })
	return dir
}

// sec2eaYARASettingsGuard snapshots the live YARA engine settings and
// restores them at cleanup (they are process-global atomics).
func sec2eaYARASettingsGuard(t *testing.T) {
	t.Helper()
	pe, pt, pm := yaraGetEnabled(), yaraGetTimeoutSecs(), yaraGetMaxInflight()
	pot, pos, pa := yaraGetOnTimeout(), yaraGetOnSaturation(), yaraGetAlertDegraded()
	t.Cleanup(func() {
		yaraSetEnabled(pe)
		yaraSetTimeoutSecs(pt)
		yaraSetMaxInflight(pm)
		yaraSetOnTimeout(pot)
		yaraSetOnSaturation(pos)
		yaraSetAlertDegraded(pa)
	})
}

const sec2eaMinimalRule = "rule sec2ea_min { strings: $a = \"sec2ea-token\" condition: $a }"

// ─── §1: lost update / stale-writer fences ──────────────────────────────────

// TestSec2EA_DomainAllowlistStaleWriteRefused: a PUT asserting a stale
// ifRevision must be the structured 409 and must not mutate. At ac0e16f2 the
// unknown field is ignored and the stale write silently replaces the list.
func TestSec2EA_DomainAllowlistStaleWriteRefused(t *testing.T) {
	sec2eaSwapThreatFeed(t)
	if err := globalThreatFeed.SetDomainAllowlist([]string{"keep.example"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := httptest.NewRecorder()
	apiDomainAllowlist(w, jsonReq("PUT", "/api/security-scan/feeds/domain-allowlist",
		map[string]any{"domains": []string{"stale-writer.example"}, "ifRevision": "sha256:not-the-current-revision"}))
	if w.Code != 409 {
		t.Fatalf("stale allowlist PUT = %d body=%s — the second admin silently overwrote the first (want the structured 409)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "currentRevision") || !strings.Contains(w.Body.String(), "yourRevision") {
		t.Fatalf("fence conflict must use the ONE structured dialect, got %s", w.Body.String())
	}
	if got := globalThreatFeed.DomainAllowlist(); len(got) != 1 || got[0] != "keep.example" {
		t.Fatalf("a refused stale write mutated the allowlist: %v", got)
	}
}

// TestSec2EA_YARASettingsStaleWriteRefused: same fence contract on the YARA
// engine settings PUT.
func TestSec2EA_YARASettingsStaleWriteRefused(t *testing.T) {
	sec2eaYARASettingsGuard(t)
	settingsPath := dcFinYAMLBootEnv(t)
	_ = settingsPath
	yaraSetTimeoutSecs(5)

	w := httptest.NewRecorder()
	apiSecYARASettings(w, jsonReq("PUT", "/api/security-scan/yara/settings", map[string]any{
		"enabled": true, "timeout_secs": 9, "max_inflight": 32,
		"on_timeout": yaraFailClosed, "on_saturation": yaraFailClosed,
		"alert_degraded": false, "ifRevision": "sha256:stale",
	}))
	if w.Code != 409 {
		t.Fatalf("stale YARA settings PUT = %d body=%s, want the structured 409", w.Code, w.Body.String())
	}
	if yaraGetTimeoutSecs() == 9 {
		t.Fatal("a refused stale write changed the live YARA engine settings")
	}
}

// TestSec2EA_ExclusionsStaleWriteRefused: same fence contract on the scan
// exclusion replace.
func TestSec2EA_ExclusionsStaleWriteRefused(t *testing.T) {
	dir := t.TempDir()
	sec2eaSwapExclusions(t, filepath.Join(dir, "exclusions.json"))
	globalScanExclusions.Replace([]string{"aa11"}, []string{"keep.example"})

	w := httptest.NewRecorder()
	apiSecScanExclusions(w, jsonReq("PUT", "/api/security-scan/exclusions",
		map[string]any{"hashes": []string{}, "hosts": []string{"stale.example"}, "ifRevision": "sha256:stale"}))
	if w.Code != 409 {
		t.Fatalf("stale exclusions PUT = %d body=%s, want the structured 409", w.Code, w.Body.String())
	}
	_, hosts := globalScanExclusions.Lists()
	if len(hosts) != 1 || hosts[0] != "keep.example" {
		t.Fatalf("a refused stale write mutated the exclusions: %v", hosts)
	}
}

// TestSec2EA_DPIBypassStaleWriteRefused: same fence contract on the DPI
// bypass replace (canonical /api/dpi/bypass).
func TestSec2EA_DPIBypassStaleWriteRefused(t *testing.T) {
	snapshotDPIScanner(t)
	dpiScanner.SetBypassHosts([]string{"keep.example"})

	w := httptest.NewRecorder()
	apiContentScanBypass(w, jsonReq("PUT", "/api/dpi/bypass",
		map[string]any{"hosts": []string{"stale.example"}, "ifRevision": "sha256:stale"}))
	if w.Code != 409 {
		t.Fatalf("stale DPI bypass PUT = %d body=%s, want the structured 409", w.Code, w.Body.String())
	}
	if got := dpiScanner.BypassHosts(); len(got) != 1 || got[0] != "keep.example" {
		t.Fatalf("a refused stale write mutated the bypass list: %v", got)
	}
}

// TestSec2EA_YARACreateFenceRefusesSilentOverwrite: a create asserting
// ifRevision "new" against an EXISTING rule file must refuse (409), never
// silently replace another admin's rule; a PUT asserting a stale content
// revision must refuse identically. At ac0e16f2 both writes overwrite.
func TestSec2EA_YARACreateFenceRefusesSilentOverwrite(t *testing.T) {
	sec2eaSwapYARA(t)
	// Admin A creates the rule (legacy unfenced create keeps working).
	w := httptest.NewRecorder()
	apiSecYARARules(w, jsonReq("POST", "/api/security-scan/yara/rules",
		map[string]any{"name": "shared", "source": sec2eaMinimalRule}))
	if w.Code != 200 {
		t.Fatalf("seed create: %d %s", w.Code, w.Body.String())
	}

	// Admin B "creates" the same name with the create fence → must refuse.
	w = httptest.NewRecorder()
	apiSecYARARules(w, jsonReq("POST", "/api/security-scan/yara/rules",
		map[string]any{"name": "shared", "source": "rule sec2ea_b { condition: true }", "ifRevision": "new"}))
	if w.Code != 409 {
		t.Fatalf("fenced create over an existing rule file = %d body=%s — admin B silently replaced admin A's rule (want 409)", w.Code, w.Body.String())
	}
	src, err := globalYARA.ReadRule("shared")
	if err != nil || !strings.Contains(src, "sec2ea-token") {
		t.Fatalf("a refused create overwrote the rule file: %q err=%v", src, err)
	}

	// Admin B updates with a STALE content revision → must refuse.
	w = httptest.NewRecorder()
	apiSecYARARules(w, jsonReq("PUT", "/api/security-scan/yara/rules/shared",
		map[string]any{"source": "rule sec2ea_c { condition: true }", "ifRevision": "sha256:stale"}))
	if w.Code != 409 {
		t.Fatalf("stale fenced rule update = %d body=%s, want 409", w.Code, w.Body.String())
	}
}

// TestSec2EA_FencedRoundTripsSucceed (new-contract green): each fenced
// surface serves its revision on GET, accepts a write asserting that exact
// revision, and serves a NEW revision afterwards.
func TestSec2EA_FencedRoundTripsSucceed(t *testing.T) {
	sec2eaSwapThreatFeed(t)
	dir := t.TempDir()
	sec2eaSwapExclusions(t, filepath.Join(dir, "exclusions.json"))
	snapshotDPIScanner(t)
	sec2eaYARASettingsGuard(t)
	dcFinYAMLBootEnv(t)

	fetchRev := func(handler func(http.ResponseWriter, *http.Request), target string) string {
		t.Helper()
		w := httptest.NewRecorder()
		handler(w, jsonReq("GET", target, nil))
		if w.Code != 200 {
			t.Fatalf("GET %s = %d", target, w.Code)
		}
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatalf("decode %s: %v", target, err)
		}
		rev, _ := m["revision"].(string)
		if rev == "" {
			t.Fatalf("GET %s carries no revision — the fence contract is unimplemented: %s", target, w.Body.String())
		}
		return rev
	}

	// Allowlist.
	rev := fetchRev(apiDomainAllowlist, "/api/security-scan/feeds/domain-allowlist")
	w := httptest.NewRecorder()
	apiDomainAllowlist(w, jsonReq("PUT", "/api/security-scan/feeds/domain-allowlist",
		map[string]any{"domains": []string{"fenced.example"}, "ifRevision": rev}))
	if w.Code != 200 {
		t.Fatalf("fenced allowlist PUT with the current revision = %d %s", w.Code, w.Body.String())
	}
	if rev2 := fetchRev(apiDomainAllowlist, "/api/security-scan/feeds/domain-allowlist"); rev2 == rev {
		t.Fatal("allowlist revision must advance after a successful write")
	}

	// Exclusions.
	rev = fetchRev(apiSecScanExclusions, "/api/security-scan/exclusions")
	w = httptest.NewRecorder()
	apiSecScanExclusions(w, jsonReq("PUT", "/api/security-scan/exclusions",
		map[string]any{"hashes": []string{"bb22"}, "hosts": []string{"fenced.example"}, "ifRevision": rev}))
	if w.Code != 200 {
		t.Fatalf("fenced exclusions PUT = %d %s", w.Code, w.Body.String())
	}

	// DPI bypass.
	rev = fetchRev(apiContentScanBypass, "/api/dpi/bypass")
	w = httptest.NewRecorder()
	apiContentScanBypass(w, jsonReq("PUT", "/api/dpi/bypass",
		map[string]any{"hosts": []string{"fenced.example"}, "ifRevision": rev}))
	if w.Code != 200 {
		t.Fatalf("fenced bypass PUT = %d %s", w.Code, w.Body.String())
	}

	// YARA settings.
	rev = fetchRev(apiSecYARASettings, "/api/security-scan/yara/settings")
	w = httptest.NewRecorder()
	apiSecYARASettings(w, jsonReq("PUT", "/api/security-scan/yara/settings", map[string]any{
		"enabled": yaraGetEnabled(), "timeout_secs": 7, "max_inflight": yaraGetMaxInflight(),
		"on_timeout": yaraGetOnTimeout(), "on_saturation": yaraGetOnSaturation(),
		"alert_degraded": yaraGetAlertDegraded(), "ifRevision": rev,
	}))
	if w.Code != 200 {
		t.Fatalf("fenced YARA settings PUT = %d %s", w.Code, w.Body.String())
	}
	if yaraGetTimeoutSecs() != 7 {
		t.Fatal("fenced settings write must apply")
	}
}

// TestSec2EA_UnfencedLegacyWritesStillReplace (CONTROL — green at both
// trees): a PUT without ifRevision keeps the pre-fence last-writer-wins
// contract on every surface.
func TestSec2EA_UnfencedLegacyWritesStillReplace(t *testing.T) {
	sec2eaSwapThreatFeed(t)
	snapshotDPIScanner(t)
	w := httptest.NewRecorder()
	apiDomainAllowlist(w, jsonReq("PUT", "/api/security-scan/feeds/domain-allowlist",
		map[string]any{"domains": []string{"legacy.example"}}))
	if w.Code != 200 {
		t.Fatalf("unfenced allowlist PUT = %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	apiContentScanBypass(w, jsonReq("PUT", "/api/dpi/bypass",
		map[string]any{"hosts": []string{"legacy.example"}}))
	if w.Code != 200 {
		t.Fatalf("unfenced bypass PUT = %d %s", w.Code, w.Body.String())
	}
}

// ─── §2: durability truth ───────────────────────────────────────────────────

// TestSec2EA_DPIBypassPersistFailureIs500: with a broken persistence path a
// bypass replace must be a truthful 500 (applied in memory, fail-safe) with
// the distinct *_unpersisted audit action. At ac0e16f2 Save() swallows the
// error and the client sees 200.
func TestSec2EA_DPIBypassPersistFailureIs500(t *testing.T) {
	orig := dpiScanner
	fresh := newContentScanner(1 << 20)
	fresh.SetPath(filepath.Join(t.TempDir(), "no-such-dir", "content_scan.json"))
	dpiScanner = fresh
	t.Cleanup(func() { dpiScanner = orig })

	baseline := len(auditGet())
	_ = baseline
	w := httptest.NewRecorder()
	apiContentScanBypass(w, jsonReq("PUT", "/api/dpi/bypass",
		map[string]any{"hosts": []string{"pf.example"}}))
	if w.Code != 500 {
		t.Fatalf("bypass PUT with failing persistence = %d body=%s — the 200 records a configuration that will silently revert on restart (want a truthful 500)", w.Code, w.Body.String())
	}
	found := false
	for _, e := range auditGet() {
		if e.Action == "security.dpi_bypass.update_unpersisted" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("the transient in-memory-only bypass state must stay attributable via the distinct unpersisted audit action")
	}
}

// TestSec2EA_DPIPatternPersistFailureIs500: same truth for the DPI pattern
// add (canonical /api/dpi POST).
func TestSec2EA_DPIPatternPersistFailureIs500(t *testing.T) {
	orig := dpiScanner
	fresh := newContentScanner(1 << 20)
	fresh.SetPath(filepath.Join(t.TempDir(), "no-such-dir", "content_scan.json"))
	dpiScanner = fresh
	t.Cleanup(func() { dpiScanner = orig })
	snapshotConfigVersionsDir(t)

	w := httptest.NewRecorder()
	apiContentScan(w, jsonReq("POST", "/api/dpi", map[string]any{"pattern": "sec2ea-pf-[0-9]+"}))
	if w.Code != 500 {
		t.Fatalf("DPI pattern add with failing persistence = %d body=%s, want a truthful 500", w.Code, w.Body.String())
	}
}

// TestSec2EA_ExclusionsPersistFailureIs500: the exclusion replace must not
// 200 over a failed Save (the transient trust-elevation state stays applied
// and attributable).
func TestSec2EA_ExclusionsPersistFailureIs500(t *testing.T) {
	sec2eaSwapExclusions(t, filepath.Join(t.TempDir(), "no-such-dir", "exclusions.json"))

	w := httptest.NewRecorder()
	apiSecScanExclusions(w, jsonReq("PUT", "/api/security-scan/exclusions",
		map[string]any{"hashes": []string{"cc33"}, "hosts": []string{"pf.example"}}))
	if w.Code != 500 {
		t.Fatalf("exclusions PUT with failing persistence = %d body=%s, want a truthful 500", w.Code, w.Body.String())
	}
	found := false
	for _, e := range auditGet() {
		if e.Action == "security.scan_exclusions.update_unpersisted" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("unpersisted exclusion state must stay attributable via the distinct audit action")
	}
}

// TestSec2EA_YARASettingsPersistFailureLeavesLiveUntouched: the settings PUT
// persists the TARGET before applying — a persist failure is a 500 and the
// live engine keeps its previous posture. At ac0e16f2 the handler applies
// live values, detaches the save, and returns 200 regardless.
func TestSec2EA_YARASettingsPersistFailureLeavesLiveUntouched(t *testing.T) {
	sec2eaYARASettingsGuard(t)
	dcFinYAMLBootEnv(t)
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "no-such-dir", "admin_settings.json"))
	yaraSetTimeoutSecs(5)
	yaraSetOnTimeout(yaraFailClosed)

	w := httptest.NewRecorder()
	apiSecYARASettings(w, jsonReq("PUT", "/api/security-scan/yara/settings", map[string]any{
		"enabled": true, "timeout_secs": 11, "max_inflight": 32,
		"on_timeout": yaraFailOpenWithAlert, "on_saturation": yaraFailClosed,
		"alert_degraded": false,
	}))
	adminSettingsSaveWG.Wait()
	if w.Code != 500 {
		t.Fatalf("YARA settings PUT with failing persistence = %d body=%s — the 200 reports a durable posture change that will silently revert on restart (want 500)", w.Code, w.Body.String())
	}
	if yaraGetTimeoutSecs() == 11 || yaraGetOnTimeout() == yaraFailOpenWithAlert {
		t.Fatal("a failed persist must leave the live YARA engine posture untouched (persist-before-apply)")
	}
}

// TestSec2EA_DurableWritesSurviveRestart (new-contract green): a successful
// fenced write reaches disk — a fresh store loading the same path serves it.
func TestSec2EA_DurableWritesSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	exclPath := filepath.Join(dir, "exclusions.json")
	sec2eaSwapExclusions(t, exclPath)

	w := httptest.NewRecorder()
	apiSecScanExclusions(w, jsonReq("PUT", "/api/security-scan/exclusions",
		map[string]any{"hashes": []string{"dd44"}, "hosts": []string{"durable.example"}}))
	if w.Code != 200 {
		t.Fatalf("exclusions PUT = %d %s", w.Code, w.Body.String())
	}
	reload := scanexcl.New()
	if err := reload.Load(exclPath); err != nil {
		t.Fatalf("reload: %v", err)
	}
	hashes, hosts := reload.Lists()
	if len(hashes) != 1 || hashes[0] != "dd44" || len(hosts) != 1 || hosts[0] != "durable.example" {
		t.Fatalf("a 200 exclusions write must be on disk: %v %v", hashes, hosts)
	}
}

// ─── §3: secret boundary ────────────────────────────────────────────────────

// TestSec2EA_ScanSvcURLRedactsCredentials: a scan-service URL carrying
// embedded credentials must never reach a viewer read surface verbatim.
func TestSec2EA_ScanSvcURLRedactsCredentials(t *testing.T) {
	orig := globalRemoteScanner
	globalRemoteScanner = &RemoteScanner{}
	globalRemoteScanner.Init("http://svcuser:sec2ea-secret@127.0.0.1:1")
	t.Cleanup(func() { globalRemoteScanner = orig })

	w := httptest.NewRecorder()
	apiScanSvcConfig(w, jsonReq("GET", "/api/security-scan/svc", nil))
	if w.Code != 200 {
		t.Fatalf("svc GET = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "sec2ea-secret") {
		t.Fatalf("the viewer svc surface leaked embedded scan-service credentials: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "127.0.0.1:1") {
		t.Fatalf("redaction must keep the host identifiable: %s", w.Body.String())
	}

	// The status map carries the same URL.
	w = httptest.NewRecorder()
	apiSecScanStatus(w, jsonReq("GET", "/api/security-scan/status", nil))
	if w.Code != 200 {
		t.Fatalf("status GET = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "sec2ea-secret") {
		t.Fatalf("the status surface leaked embedded scan-service credentials")
	}
}
