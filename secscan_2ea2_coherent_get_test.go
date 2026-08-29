package main

// secscan_2ea2_coherent_get_test.go — 2E-A-2 §1: every fenced content-security
// GET must return {state, revision(state)} from ONE coherent committed
// snapshot. At b60d4ed6 the four GETs (threat-feed domain allowlist, scan
// exclusions, DPI bypass, YARA engine settings) assemble the state and the
// revision from SEPARATE store reads, so a writer landing between the two
// reads makes the GET emit data=A with revision(B) — and a later fenced write
// carrying that token passes the fence while overwriting B (a stale write with
// a "valid" fence).
//
// Each test drives the interleaving DETERMINISTICALLY: the handler runs
// synchronously in the test goroutine and contentSecGETPauseHook performs the
// concurrent writer's mutation inline at the exact read boundary (no
// goroutines, no sleeps). Two assertions per surface:
//
//  1. COHERENCE: the returned revision equals the content-derived revision of
//     the returned state (mirror derivation via contentSecRevision).
//  2. FENCE TRUTH: a fenced write asserting the GET's returned token against
//     the moved store must be the structured 409 with no mutation.
//
// RED at b60d4ed6(+seams): the GET emits {A, revision(B)} (assertion 1 fails)
// and the stale write passes the fence and destroys the concurrent writer's
// state (assertion 2 fails).

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
)

// sec2ea2PauseOnce installs a one-shot GET-interleave writer for one surface.
func sec2ea2PauseOnce(t *testing.T, surface string, writer func()) {
	t.Helper()
	prev := contentSecGETPauseHook
	var once sync.Once
	contentSecGETPauseHook = func(s string) {
		if s == surface {
			once.Do(writer)
		}
	}
	t.Cleanup(func() { contentSecGETPauseHook = prev })
}

// ─── §1-A: threat-feed domain allowlist ─────────────────────────────────────

func TestSec2EA2_AllowlistGETCoherentUnderConcurrentWriter(t *testing.T) {
	sec2eaSwapThreatFeed(t)
	if err := globalThreatFeed.SetDomainAllowlist([]string{"a-coherent.example"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// The concurrent writer is the surface's real writer domain — the DP
	// snapshot apply (controlplane_snapshot.go) and every admin PUT both land
	// through SetDomainAllowlist.
	sec2ea2PauseOnce(t, "allowlist", func() {
		if err := globalThreatFeed.SetDomainAllowlist([]string{"b-writer.example"}); err != nil {
			t.Errorf("interleaved writer: %v", err)
		}
	})

	w := httptest.NewRecorder()
	apiDomainAllowlist(w, getReq("/api/security-scan/feeds/domain-allowlist"))
	if w.Code != 200 {
		t.Fatalf("GET = %d, want 200", w.Code)
	}
	var resp struct {
		Domains  []string `json:"domains"`
		Revision string   `json:"revision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Coherence: the revision must fingerprint EXACTLY the returned state.
	wantRev := contentSecRevision(append([]string{"allowlist"}, resp.Domains...)...)
	if resp.Revision != wantRev {
		t.Fatalf("GET emitted a torn pair: domains=%v but revision fingerprints a different state (got %s, revision-of-returned-state %s)",
			resp.Domains, resp.Revision, wantRev)
	}
	// Fence truth: the returned token now names a superseded state, so a write
	// asserting it must be the structured 409 with no mutation.
	w2 := httptest.NewRecorder()
	apiDomainAllowlist(w2, jsonReq("PUT", "/api/security-scan/feeds/domain-allowlist",
		map[string]any{"domains": []string{}, "ifRevision": resp.Revision}))
	if w2.Code != 409 {
		t.Fatalf("stale fenced PUT = %d, want 409 (a token minted for superseded state passed the fence)", w2.Code)
	}
	cur := globalThreatFeed.DomainAllowlist()
	if len(cur) != 1 || cur[0] != "b-writer.example" {
		t.Fatalf("concurrent writer's state was destroyed by a stale fenced write: allowlist = %v", cur)
	}
}

// ─── §1-B: scan exclusions ──────────────────────────────────────────────────

func TestSec2EA2_ExclusionsGETCoherentUnderConcurrentWriter(t *testing.T) {
	sec2eaSwapExclusions(t, filepath.Join(t.TempDir(), "scan_exclusions.json"))
	globalScanExclusions.Replace([]string{"aaaa"}, []string{"a-host.example"})
	sec2ea2PauseOnce(t, "exclusions", func() {
		globalScanExclusions.Replace([]string{"bbbb"}, []string{"b-host.example"})
	})

	w := httptest.NewRecorder()
	apiSecScanExclusions(w, getReq("/api/security-scan/exclusions"))
	if w.Code != 200 {
		t.Fatalf("GET = %d, want 200", w.Code)
	}
	var resp struct {
		Hashes   []string `json:"hashes"`
		Hosts    []string `json:"hosts"`
		Revision string   `json:"revision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	parts := append([]string{"hashes"}, resp.Hashes...)
	parts = append(parts, "hosts")
	parts = append(parts, resp.Hosts...)
	if wantRev := contentSecRevision(parts...); resp.Revision != wantRev {
		t.Fatalf("GET emitted a torn pair: hashes=%v hosts=%v revision=%s (revision-of-returned-state %s)",
			resp.Hashes, resp.Hosts, resp.Revision, wantRev)
	}
	w2 := httptest.NewRecorder()
	apiSecScanExclusions(w2, jsonReq("PUT", "/api/security-scan/exclusions",
		map[string]any{"hashes": []string{}, "hosts": []string{}, "ifRevision": resp.Revision}))
	if w2.Code != 409 {
		t.Fatalf("stale fenced PUT = %d, want 409", w2.Code)
	}
	hashes, hosts := globalScanExclusions.Lists()
	if len(hashes) != 1 || hashes[0] != "bbbb" || len(hosts) != 1 || hosts[0] != "b-host.example" {
		t.Fatalf("concurrent writer's state destroyed by a stale fenced write: hashes=%v hosts=%v", hashes, hosts)
	}
}

// ─── §1-C: DPI bypass hosts ─────────────────────────────────────────────────

func TestSec2EA2_DPIBypassGETCoherentUnderConcurrentWriter(t *testing.T) {
	snapshotDPIScanner(t)
	dpiScanner.SetBypassHosts([]string{"a-bypass.example"})
	sec2ea2PauseOnce(t, "dpi-bypass", func() {
		dpiScanner.SetBypassHosts([]string{"b-bypass.example"})
	})

	w := httptest.NewRecorder()
	apiContentScanBypass(w, getReq("/api/dpi/bypass"))
	if w.Code != 200 {
		t.Fatalf("GET = %d, want 200", w.Code)
	}
	var resp struct {
		Hosts    []string `json:"hosts"`
		Revision string   `json:"revision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if wantRev := contentSecRevision(append([]string{"dpi-bypass"}, resp.Hosts...)...); resp.Revision != wantRev {
		t.Fatalf("GET emitted a torn pair: hosts=%v revision=%s (revision-of-returned-state %s)",
			resp.Hosts, resp.Revision, wantRev)
	}
	w2 := httptest.NewRecorder()
	apiContentScanBypass(w2, jsonReq("PUT", "/api/dpi/bypass",
		map[string]any{"hosts": []string{}, "ifRevision": resp.Revision}))
	if w2.Code != 409 {
		t.Fatalf("stale fenced PUT = %d, want 409", w2.Code)
	}
	if hosts := dpiScanner.BypassHosts(); len(hosts) != 1 || hosts[0] != "b-bypass.example" {
		t.Fatalf("concurrent writer's state destroyed by a stale fenced write: hosts=%v", hosts)
	}
}

// ─── §1-D: YARA engine settings ─────────────────────────────────────────────

func sec2ea2YARARevisionOfResponse(enabled bool, timeoutSecs, maxInflight int64, onTimeout, onSaturation string, alertDegraded bool) string {
	return contentSecRevision("yara-settings",
		fmt.Sprintf("%t", enabled),
		fmt.Sprintf("%d", timeoutSecs),
		fmt.Sprintf("%d", maxInflight),
		onTimeout,
		onSaturation,
		fmt.Sprintf("%t", alertDegraded),
	)
}

func TestSec2EA2_YARASettingsGETCoherentUnderConcurrentWriter(t *testing.T) {
	sec2eaYARASettingsGuard(t)
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))
	yaraSetEnabled(false)
	yaraSetTimeoutSecs(10)
	yaraSetMaxInflight(8)
	yaraSetOnTimeout(yaraFailClosed)
	yaraSetOnSaturation(yaraFailClosed)
	yaraSetAlertDegraded(false)
	// The interleaved writer flips the same values the settings PUT's
	// applyOnSuccess installs (the runtime writer domain applies all six under
	// adminSettingsMu; a reader off that domain can observe a torn mix).
	sec2ea2PauseOnce(t, "yara-settings", func() {
		yaraSetEnabled(true)
		yaraSetOnTimeout(yaraFailOpenWithAlert)
	})

	w := httptest.NewRecorder()
	apiSecYARASettings(w, getReq("/api/security-scan/yara/settings"))
	if w.Code != 200 {
		t.Fatalf("GET = %d, want 200", w.Code)
	}
	var resp struct {
		Enabled       bool   `json:"enabled"`
		TimeoutSecs   int64  `json:"timeout_secs"`
		MaxInflight   int64  `json:"max_inflight"`
		OnTimeout     string `json:"on_timeout"`
		OnSaturation  string `json:"on_saturation"`
		AlertDegraded bool   `json:"alert_degraded"`
		Revision      string `json:"revision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantRev := sec2ea2YARARevisionOfResponse(resp.Enabled, resp.TimeoutSecs, resp.MaxInflight,
		resp.OnTimeout, resp.OnSaturation, resp.AlertDegraded)
	if resp.Revision != wantRev {
		t.Fatalf("GET emitted a torn pair: returned settings do not match the returned revision (got %s, revision-of-returned-state %s)",
			resp.Revision, wantRev)
	}
	// Fence truth: the returned token names superseded state; a full-body PUT
	// asserting it must 409 and leave the live posture (the writer's) intact.
	w2 := httptest.NewRecorder()
	apiSecYARASettings(w2, jsonReq("PUT", "/api/security-scan/yara/settings", map[string]any{
		"enabled": false, "timeout_secs": 10, "max_inflight": 8,
		"on_timeout": yaraFailClosed, "on_saturation": yaraFailClosed,
		"alert_degraded": false, "ifRevision": resp.Revision,
	}))
	if w2.Code != 409 {
		t.Fatalf("stale fenced PUT = %d, want 409", w2.Code)
	}
	if !yaraGetEnabled() || yaraGetOnTimeout() != yaraFailOpenWithAlert {
		t.Fatalf("concurrent writer's posture destroyed by a stale fenced write: enabled=%v on_timeout=%q",
			yaraGetEnabled(), yaraGetOnTimeout())
	}
}

// ─── §1-D writer-domain pin (green control at the fixed tree) ───────────────

// TestSec2EA2_YARASettingsSnapshotSerializedWithWriterDomain: the settings
// PUT's applyOnSuccess installs all six values while HOLDING adminSettingsMu;
// the GET snapshot must be serialized against that domain, so a reader that
// arrives while an apply is mid-flight returns only a complete posture (all
// old or all new), never a half-applied mix. The writer here holds the real
// mutex across a deliberately split apply; the reader is spawned mid-hold and
// can therefore only acquire the lock after the apply completes.
func TestSec2EA2_YARASettingsSnapshotSerializedWithWriterDomain(t *testing.T) {
	sec2eaYARASettingsGuard(t)
	yaraSetEnabled(false)
	yaraSetOnTimeout(yaraFailClosed)
	yaraSetOnSaturation(yaraFailClosed)
	yaraSetTimeoutSecs(10)
	yaraSetMaxInflight(8)
	yaraSetAlertDegraded(false)

	half := make(chan struct{})
	spawned := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		adminSettingsMu.Lock()
		defer adminSettingsMu.Unlock()
		yaraSetEnabled(true) // half-applied posture, only visible off-domain
		close(half)
		<-spawned
		<-release
		yaraSetOnTimeout(yaraFailOpenWithAlert) // apply completes
	}()
	<-half
	type snap struct {
		enabled   bool
		onTimeout string
	}
	got := make(chan snap, 1)
	go func() {
		w := httptest.NewRecorder()
		apiSecYARASettings(w, getReq("/api/security-scan/yara/settings"))
		var resp struct {
			Enabled   bool   `json:"enabled"`
			OnTimeout string `json:"on_timeout"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		got <- snap{enabled: resp.Enabled, onTimeout: resp.OnTimeout}
	}()
	close(spawned)
	close(release)
	<-done
	g := <-got
	// Complete-old or complete-new — never the half-applied (true, fail_closed)
	// tear the writer exposed mid-hold.
	if g.enabled && g.onTimeout == yaraFailClosed {
		t.Fatalf("GET observed a half-applied posture (enabled=true, on_timeout=%q) — the snapshot is not serialized with the settings writer domain", g.onTimeout)
	}
}
