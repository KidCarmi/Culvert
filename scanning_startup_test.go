package main

// scanning_startup_test.go — per-slice tests for the security-scanning
// startup slice (resolver mode split, gates, duration/size normalisation).
// The loader's collaborators (scanner, YARA, threat feed, sidecar) are owned
// and tested by their own suites.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/scanexcl"
)

func TestResolveScanning_DisabledByDefault(t *testing.T) {
	got := resolveScanningStartupConfig(&FileConfig{}, scanningCLIFlags{}, "")
	if got.RemoteScanURL != "" || got.LocalEnabled || got.ThreatFeedEnabled {
		t.Errorf("zero config must resolve fully disabled: %+v", got)
	}
	if got.CacheTTL != time.Hour || got.SyncInterval != 6*time.Hour || got.CacheSize != 10_000 {
		t.Errorf("defaults = (%v, %v, %d), want (1h, 6h, 10000)", got.CacheTTL, got.SyncInterval, got.CacheSize)
	}
	if got.ScanExclusionsPath != "" {
		t.Errorf("no data dir must skip exclusions path, got %q", got.ScanExclusionsPath)
	}
}

func TestResolveScanning_AnyBackendEnablesLocal(t *testing.T) {
	// Each backend alone flips LocalEnabled (verbatim pre-slice gate).
	cases := []scanningCLIFlags{
		{ClamAVAddr: "clam:3310"},
		{YARARulesDir: "/rules"},
		{ThreatFeedDB: "/data/feeds.db"},
	}
	for i, fl := range cases {
		if got := resolveScanningStartupConfig(&FileConfig{}, fl, "/data"); !got.LocalEnabled {
			t.Errorf("case %d: backend %+v must enable local scanning", i, fl)
		}
	}
	// ThreatFeedEnabled needs a feed DB or enabled=true — a lone ClamAV does not.
	if got := resolveScanningStartupConfig(&FileConfig{}, scanningCLIFlags{ClamAVAddr: "clam:3310"}, ""); got.ThreatFeedEnabled {
		t.Error("ClamAV alone must not enable the threat feed")
	}
}

func TestResolveScanning_RemoteModeAndCLIPrecedence(t *testing.T) {
	fc := &FileConfig{}
	fc.SecurityScan.ScanSvcURL = "http://config-svc:8484"
	fc.SecurityScan.ClamAVAddr = "config-clam:3310"

	dir := t.TempDir()
	got := resolveScanningStartupConfig(fc, scanningCLIFlags{ScanSvcURL: "http://cli-svc:8484"}, dir)
	if got.RemoteScanURL != "http://cli-svc:8484" {
		t.Errorf("RemoteScanURL = %q, want the CLI value", got.RemoteScanURL)
	}
	if got.ClamAddr != "config-clam:3310" {
		t.Errorf("ClamAddr = %q, want the config fallback", got.ClamAddr)
	}
	if want := filepath.Join(dir, "scan_exclusions.json"); got.ScanExclusionsPath != want {
		t.Errorf("ScanExclusionsPath = %q, want %q", got.ScanExclusionsPath, want)
	}
}

func TestResolveScanning_SizesAndDurations(t *testing.T) {
	fc := &FileConfig{}
	fc.SecurityScan.Enabled = true
	fc.SecurityScan.CacheTTL = "30m"
	fc.SecurityScan.SyncInterval = "2h"
	fc.SecurityScan.CacheSize = 500
	fc.SecurityScan.MaxScanMB = 25

	got := resolveScanningStartupConfig(fc, scanningCLIFlags{}, "")
	if got.CacheTTL != 30*time.Minute || got.SyncInterval != 2*time.Hour {
		t.Errorf("durations = (%v, %v)", got.CacheTTL, got.SyncInterval)
	}
	if got.CacheSize != 500 {
		t.Errorf("CacheSize = %d, want 500", got.CacheSize)
	}
	if got.MaxScanBytes != 25<<20 {
		t.Errorf("MaxScanBytes = %d, want %d", got.MaxScanBytes, 25<<20)
	}
	if !got.LocalEnabled || !got.ThreatFeedEnabled {
		t.Error("Enabled=true must flip both gates")
	}
	// Unparseable durations fall back (verbatim parse-ok-wins semantics).
	fc.SecurityScan.CacheTTL = "garbage"
	if got := resolveScanningStartupConfig(fc, scanningCLIFlags{}, ""); got.CacheTTL != time.Hour {
		t.Errorf("unparseable CacheTTL = %v, want 1h fallback", got.CacheTTL)
	}
}

// ── CHAOS-53: scan exclusions in remote mode ────────────────────────────────

// TestChaos53_RemoteModeLoadsScanExclusions proves the admin allowlist is read
// from disk in remote mode, and that saves reach disk afterwards.
//
// The exclusion load used to sit on the LOCAL branch only, so a sidecar
// deployment never read the file. That is worse than it sounds, because
// scanexcl.Store learns its persistence path FROM Load: with no path, Save() is
// a documented no-op, so every admin edit to the exclusion lists returned 200,
// wrote an audit entry and took a config-version snapshot while persisting
// nothing — the lists reverted to empty on the next restart, silently. The HOST
// list is consulted on the request path in remote mode too (proxy_tunnel.go,
// proxy_http.go), so the setting was being ignored outright as well.
func TestChaos53_RemoteModeLoadsScanExclusions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan_exclusions.json")
	const hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.WriteFile(path, []byte(`{"hashes":["`+hash+`"],"hosts":["excluded.example"]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := globalScanExclusions
	globalScanExclusions = scanexcl.New()
	t.Cleanup(func() { globalScanExclusions = prev })

	loadScanExclusions(path)

	if !globalScanExclusions.IsHashExcluded(hash) {
		t.Error("hash allowlist not loaded in remote mode")
	}
	if !globalScanExclusions.IsHostExcluded("excluded.example") {
		t.Error("host allowlist not loaded in remote mode — the request path consults it in remote mode too")
	}

	// The load is also what gives the store a path to save to. Without it the
	// admin API's Save() succeeds and writes nothing.
	globalScanExclusions.Replace([]string{hash}, []string{"another.example"})
	if err := globalScanExclusions.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(raw), "another.example") {
		t.Fatalf("admin edits did not reach disk: %s", raw)
	}
}
