package main

// cluster_apply_persist_test.go — P3.4 / CL-1 regression guards for
// applyConfigSnapshot's persistence claim on the four fsync-safe
// stores.
//
// Background
// ==========
// roadmap/CLUSTER-RUNTIME-DISCOVERY.md §8.1 CL-1 listed every store
// mutated by applyConfigSnapshot and marked the following four as
// "memory only / P3.4 gap = YES":
//
//	• globalProfileStore (FileProfileStore.ReplaceAll)
//	• globalBandwidth    (BandwidthManager.ReplaceAll)
//	• fileBlocker        (FileBlocker.Add per extension)
//	• globalNodeGroups   (NodeGroupStore.ReplaceAll)
//
// Direct source inspection while drafting the P3.4 PR found that
// each of these mutators **already calls its store's saveLocked() /
// save() method, which already routes through atomicWriteFile**:
//
//	• fileprofile.go:132 — ReplaceAll calls saveLocked()
//	• bandwidth.go:292   — ReplaceAll calls m.saveLocked()
//	• fileblock.go:87    — Add calls fb.save()
//	• nodegroup.go:155   — ReplaceAll calls s.saveLocked()
//
// So the P6.4 doc claim was wrong: these four stores already persist
// across DP restart/reload via their mutator path. The TestPolicy*
// case (PR #225, P3.2b) is the ONLY store in applyConfigSnapshot
// that needs an explicit caller-side Save() — every other fsync-safe
// store auto-persists via its mutator.
//
// What these tests verify
// =======================
// For each of the four stores:
//
//	(1) Set up the store with a tempdir-scoped persistence path.
//	(2) Build a ConfigSnapshot with that store's field populated.
//	(3) Call applyConfigSnapshot(snap).
//	(4) Construct a FRESH store instance and Load from the path.
//	(5) Assert the data round-tripped — i.e. survives DP restart.
//
// These act as regression guards: any future change that removes
// the mutator-side Save (whether intentional or accidental) will
// fail the test immediately. They also serve as the evidence base
// for the P6.4 doc correction in this same PR.
//
// Why no caller-side Save() calls were added in this PR
// ======================================================
// The user-supplied CL-1 brief said "Do NOT add Save calls to
// stores whose Save path is not fsync-safe unless the durable
// primitive is already fixed." The remaining memory-only stores
// in applyConfigSnapshot (bl, sslBypass, catStore, dpiScanner,
// globalThreatFeed, globalCategoryGroups, pacStore) all have
// non-fsync-safe Save methods — see roadmap/CLUSTER-RUNTIME-
// DISCOVERY.md §13 CL-1 (updated in this same PR) for the
// per-store breakdown and the dependency chain on P6.1 UC-1 /
// P6.2 SC-4 / P6.3 CA-3.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catgroup"
	"github.com/KidCarmi/Culvert/internal/fileblock"
)

// ─── globalProfileStore ─────────────────────────────────────────────

// TestApplyConfigSnapshot_FileProfilesPersist exercises the
// FileProfileStore.ReplaceAll → saveLocked → atomicWriteFile chain
// triggered by applyConfigSnapshot's snap.FileProfiles branch
// (controlplane.go:1521–1523).
func TestApplyConfigSnapshot_FileProfilesPersist(t *testing.T) {
	origProfiles := globalProfileStore.List()
	t.Cleanup(func() {
		globalProfileStore.SetPath("") // drop the test's temp persistence path
		restored := make([]FileExtProfile, 0, len(origProfiles))
		for _, p := range origProfiles {
			restored = append(restored, *p)
		}
		globalProfileStore.ReplaceAll(restored)
	})

	dir := t.TempDir()
	path := filepath.Join(dir, "fileprofiles.json")
	globalProfileStore.SetPath(path)

	snap := ConfigSnapshot{
		Version: 1,
		FileProfiles: []FileExtProfile{
			{
				Name:       "p34-test-profile",
				Extensions: []string{".test", ".p34"},
			},
		},
	}
	applyConfigSnapshot(snap)

	// On-disk evidence: the file must exist (mutator persists).
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat %q: %v (mutator did not persist)", path, err)
	}

	// Fresh-reader evidence: a brand-new store must load the data.
	fresh := &FileProfileStore{}
	if err := fresh.Load(path); err != nil {
		t.Fatalf("fresh.Load: %v", err)
	}
	loaded := fresh.List()
	if len(loaded) != 1 {
		t.Fatalf("loaded %d profiles, want 1", len(loaded))
	}
	if loaded[0].Name != "p34-test-profile" {
		t.Errorf("loaded[0].Name = %q, want p34-test-profile", loaded[0].Name)
	}
	if len(loaded[0].Extensions) != 2 {
		t.Errorf("loaded[0].Extensions len = %d, want 2", len(loaded[0].Extensions))
	}
}

// ─── globalBandwidth ────────────────────────────────────────────────

// TestApplyConfigSnapshot_BandwidthPoliciesPersist exercises the
// BandwidthManager.ReplaceAll → saveLocked → atomicWriteFile chain
// triggered by applyConfigSnapshot's snap.BandwidthPolicies branch
// (controlplane.go:1591–1593).
//
// globalBandwidth is declared as `var globalBandwidth *BandwidthManager`
// (bandwidth.go:52) — nil by default in tests; constructed at startup
// in main.go:1113. The test installs a tempdir-scoped instance for
// the duration of the test.
//
// TestApplyConfigSnapshot_NodeGroupsPersist — each test exercises a
// heterogeneous store type (BandwidthManager vs NodeGroupStore) with
// distinct constructors, field shapes, and assertions. A shared
// helper would require type-switch or generics for marginal benefit.
//
//nolint:dupl // Intentional structural symmetry with
func TestApplyConfigSnapshot_BandwidthPoliciesPersist(t *testing.T) {
	origMgr := globalBandwidth
	t.Cleanup(func() { globalBandwidth = origMgr })

	dir := t.TempDir()
	path := filepath.Join(dir, "bandwidth.json")
	globalBandwidth = NewBandwidthManager(path)

	snap := ConfigSnapshot{
		Version: 1,
		BandwidthPolicies: []BandwidthPolicy{
			{
				Name:           "p34-test-policy",
				LabelSelector:  map[string]string{"env": "p34-test"},
				MaxBytesPerSec: 1024,
			},
		},
	}
	applyConfigSnapshot(snap)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat %q: %v (mutator did not persist)", path, err)
	}

	fresh := NewBandwidthManager(path)
	loaded := fresh.List()
	if len(loaded) != 1 {
		t.Fatalf("loaded %d policies, want 1", len(loaded))
	}
	if loaded[0].Name != "p34-test-policy" {
		t.Errorf("loaded[0].Name = %q, want p34-test-policy", loaded[0].Name)
	}
	if loaded[0].MaxBytesPerSec != 1024 {
		t.Errorf("loaded[0].MaxBytesPerSec = %d, want 1024", loaded[0].MaxBytesPerSec)
	}
}

// ─── fileBlocker ────────────────────────────────────────────────────

// TestApplyConfigSnapshot_FileBlockExtensionsPersist exercises the
// FileBlocker.Add → save → atomicWriteFile chain triggered by
// applyConfigSnapshot's snap.FileBlockExtensions branch
// (controlplane.go:1601–1606).
//
// Note: applyConfigSnapshot calls ClearAll() then a per-extension
// Add() loop. Each Add calls save() (fileblock.go:87) and rewrites
// the file. The test only asserts the FINAL on-disk state matches
// the snapshot; the per-extension intermediate writes are an
// efficiency observation (out of P3.4 scope per the brief's
// "no broad persistence framework rewrite" constraint).
func TestApplyConfigSnapshot_FileBlockExtensionsPersist(t *testing.T) {
	origExts := fileBlocker.List()
	t.Cleanup(func() {
		fileBlocker.SetPath("") // drop the test's temp persistence path
		fileBlocker.ClearAll()
		for _, ext := range origExts {
			fileBlocker.Add(ext)
		}
	})

	dir := t.TempDir()
	path := filepath.Join(dir, "fileblock.json")
	fileBlocker.SetPath(path)
	// SetPath may load from disk; clear so this test starts clean.
	fileBlocker.ClearAll()

	snap := ConfigSnapshot{
		Version:             1,
		FileBlockExtensions: []string{".p34", ".test", ".guard"},
	}
	applyConfigSnapshot(snap)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat %q: %v (mutator did not persist)", path, err)
	}

	// Read the file directly and unmarshal — FileBlocker's on-disk
	// shape is `[]string` per fileblock.go save() body.
	raw, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	var diskExts []string
	if err := json.Unmarshal(raw, &diskExts); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	wantSet := map[string]bool{".p34": true, ".test": true, ".guard": true}
	if len(diskExts) != len(wantSet) {
		t.Fatalf("on-disk extensions len = %d, want %d (got %v)", len(diskExts), len(wantSet), diskExts)
	}
	for _, ext := range diskExts {
		if !wantSet[ext] {
			t.Errorf("unexpected on-disk extension %q", ext)
		}
		delete(wantSet, ext)
	}
	if len(wantSet) > 0 {
		t.Errorf("missing on-disk extensions: %v", wantSet)
	}

	// Fresh-reader evidence: SetPath() on a brand-new FileBlocker
	// should load the same extensions.
	fresh := fileblock.NewBlocker()
	fresh.SetPath(path)
	freshExts := fresh.List()
	if len(freshExts) != 3 {
		t.Fatalf("fresh.List() len = %d, want 3", len(freshExts))
	}
}

// ─── globalNodeGroups ───────────────────────────────────────────────

// TestApplyConfigSnapshot_NodeGroupsPersist exercises the
// NodeGroupStore.ReplaceAll → saveLocked → atomicWriteFile chain
// triggered by applyConfigSnapshot's snap.NodeGroups branch
// (controlplane.go:1620–1622).
//
// globalNodeGroups is declared as `var globalNodeGroups *NodeGroupStore`
// (nodegroup.go:40) — nil by default in tests; constructed at startup
// in main.go:1110. The test installs a tempdir-scoped instance for
// the duration of the test.
//
// TestApplyConfigSnapshot_BandwidthPoliciesPersist — see the rationale
// on that test.
//
//nolint:dupl // Intentional structural symmetry with
func TestApplyConfigSnapshot_NodeGroupsPersist(t *testing.T) {
	origStore := globalNodeGroups
	t.Cleanup(func() { globalNodeGroups = origStore })

	dir := t.TempDir()
	path := filepath.Join(dir, "node_groups.json")
	globalNodeGroups = NewNodeGroupStore(path)

	snap := ConfigSnapshot{
		Version: 1,
		NodeGroups: []NodeGroup{
			{
				Name:          "p34-test-group",
				LabelSelector: map[string]string{"env": "p34-test"},
				Priority:      10,
			},
		},
	}
	applyConfigSnapshot(snap)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat %q: %v (mutator did not persist)", path, err)
	}

	fresh := NewNodeGroupStore(path)
	loaded := fresh.List()
	if len(loaded) != 1 {
		t.Fatalf("loaded %d groups, want 1", len(loaded))
	}
	if loaded[0].Name != "p34-test-group" {
		t.Errorf("loaded[0].Name = %q, want p34-test-group", loaded[0].Name)
	}
	if loaded[0].Priority != 10 {
		t.Errorf("loaded[0].Priority = %d, want 10", loaded[0].Priority)
	}
}

// ─── P3.4 caller-side Save hooks (PR after #246) ────────────────────
//
// The five tests below verify the caller-side .Save() hooks installed
// in applyConfigSnapshot for the Bucket-4 stores whose Save methods
// were hardened to atomicWriteFile in PR #246. Mirror of the
// _FileProfilesPersist / _NodeGroupsPersist pattern above.

// TestApplyConfigSnapshot_SSLBypassPatternsPersist exercises the
// caller-side sslBypass.Save() hook after sslBypass.Set() in
// applyConfigSnapshot's snap.SSLBypassPatterns branch.
func TestApplyConfigSnapshot_SSLBypassPatternsPersist(t *testing.T) {
	origPath := sslBypass.Path()
	origPatterns := sslBypass.List()
	t.Cleanup(func() {
		sslBypass.SetPathForTest(origPath)
		_ = sslBypass.Set(origPatterns)
	})

	dir := t.TempDir()
	path := filepath.Join(dir, "ssl_bypass.json")
	sslBypass.SetPathForTest(path)

	snap := ConfigSnapshot{
		Version:           1,
		SSLBypassPatterns: []string{"*.p34-test-bank.example", "*.p34-test-pay.example"},
	}
	applyConfigSnapshot(snap)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat %q: %v (caller-side Save hook did not persist)", path, err)
	}

	fresh := &SSLBypassMatcher{}
	if err := fresh.Load(path); err != nil {
		t.Fatalf("fresh.Load: %v", err)
	}
	patterns := fresh.List()
	if len(patterns) != 2 {
		t.Fatalf("loaded %d patterns, want 2", len(patterns))
	}
}

// TestApplyConfigSnapshot_URLCategoriesPersist exercises the
// caller-side catStore.Save() hook after catStore.ReplaceAll() in
// applyConfigSnapshot's snap.URLCategories branch (P6.1 UC-2 closure).
func TestApplyConfigSnapshot_URLCategoriesPersist(t *testing.T) {
	origPath := catStore.Path()
	origEntries := catStore.All()
	t.Cleanup(func() {
		catStore.SetPathForTest(origPath)
		catStore.ReplaceAll(origEntries)
	})

	dir := t.TempDir()
	path := filepath.Join(dir, "categories.json")
	catStore.SetPathForTest(path)

	snap := ConfigSnapshot{
		Version: 1,
		URLCategories: []CategoryEntry{
			{Name: "p34-test-cat", Hosts: []string{"p34.example", "test.example"}},
		},
	}
	applyConfigSnapshot(snap)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat %q: %v (caller-side Save hook did not persist)", path, err)
	}

	fresh := newCategoryStore(nil)
	if err := fresh.Load(path); err != nil {
		t.Fatalf("fresh.Load: %v", err)
	}
	entries := fresh.All()
	if len(entries) != 1 {
		t.Fatalf("loaded %d entries, want 1", len(entries))
	}
	if entries[0].Name != "p34-test-cat" {
		t.Errorf("entries[0].Name = %q, want p34-test-cat", entries[0].Name)
	}
}

// TestApplyConfigSnapshot_DPIPatternsPersist exercises the
// caller-side dpiScanner.Save() hook after dpiScanner.Set() in
// applyConfigSnapshot's snap.DPIPatterns branch (P6.2 SC-3 closure).
func TestApplyConfigSnapshot_DPIPatternsPersist(t *testing.T) {
	origPath := dpiScanner.Path()
	origPatterns := append([]string(nil), dpiScanner.List()...)
	t.Cleanup(func() {
		dpiScanner.SetPath(origPath)
		_ = dpiScanner.Set(origPatterns)
	})

	dir := t.TempDir()
	path := filepath.Join(dir, "dpi_patterns.json")
	dpiScanner.SetPath(path)

	snap := ConfigSnapshot{
		Version:     1,
		DPIPatterns: []string{`p34-test-dpi-pattern`},
	}
	applyConfigSnapshot(snap)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat %q: %v (caller-side Save hook did not persist)", path, err)
	}

	fresh := newContentScanner(0)
	if err := fresh.Load(path); err != nil {
		t.Fatalf("fresh.Load: %v", err)
	}
	if len(fresh.List()) != 1 {
		t.Fatalf("loaded %d patterns, want 1", len(fresh.List()))
	}
	if fresh.List()[0] != "p34-test-dpi-pattern" {
		t.Errorf("fresh.List()[0] = %q, want p34-test-dpi-pattern", fresh.List()[0])
	}
}

// TestApplyConfigSnapshot_ThreatFeedPersist exercises the
// caller-side globalThreatFeed.Save() hook after ImportFeedData in
// applyConfigSnapshot's threat-feed branch (P6.2 SC-3 / SC-4 closure).
//
// SetDomainAllowlist already auto-persists internally
// (threatfeed.go:266); ImportFeedData does NOT — this test verifies
// the latter branch becomes durable after the caller-side hook.
func TestApplyConfigSnapshot_ThreatFeedPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "threatfeed.json")
	origDbPath := globalThreatFeed.SetDBPathForTest(path)
	t.Cleanup(func() {
		globalThreatFeed.SetDBPathForTest(origDbPath)
		globalThreatFeed.ImportFeedData(nil, nil) // clear seeded feed data
	})

	snap := ConfigSnapshot{
		Version: 1,
		ThreatFeedURLs: map[string]int64{
			"http://p34-threat.example/x": 1700000000,
		},
		ThreatFeedDomains: map[string]int64{
			"p34-threat.example": 1700000000,
		},
	}
	applyConfigSnapshot(snap)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat %q: %v (caller-side Save hook did not persist)", path, err)
	}

	// Round-trip via partial JSON decode (feedDB is unexported; tags
	// are snake_case per threatfeed.go:42–47).
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	urls, ok := decoded["urls"].(map[string]any)
	if !ok {
		t.Fatalf("on-disk feedDB urls map missing or wrong type")
	}
	if _, ok := urls["http://p34-threat.example/x"]; !ok {
		t.Errorf("on-disk urls missing seeded entry; got keys: %v", keysOf(urls))
	}
}

func TestApplyConfigSnapshot_ThreatFeedAllowlistAppliedBeforeImport(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "threatfeed.json")
	origDbPath := globalThreatFeed.SetDBPathForTest(dbPath)
	origAllowlist := globalThreatFeed.DomainAllowlist()
	// CheckURL/CheckDomain return early when the feed is disabled; enable it
	// explicitly so the positive-verdict assertions below don't depend on
	// whether an earlier test happened to run Init (shuffle determinism).
	origEnabled := globalThreatFeed.SetEnabledForTest(true)
	globalThreatFeed.ImportFeedData(nil, nil)
	_ = globalThreatFeed.SetDomainAllowlist(nil)
	t.Cleanup(func() {
		globalThreatFeed.ImportFeedData(nil, nil)
		_ = globalThreatFeed.SetDomainAllowlist(origAllowlist)
		globalThreatFeed.SetEnabledForTest(origEnabled)
		globalThreatFeed.SetDBPathForTest(origDbPath)
	})

	const (
		badURL  = "https://allowlisted-snap.example/malware"
		badHost = "allowlisted-snap.example"
	)
	applyConfigSnapshot(ConfigSnapshot{
		Version: 1,
		ThreatFeedURLs: map[string]int64{
			badURL: 1700000000,
		},
		ThreatFeedDomains: map[string]int64{
			badHost: 1700000001,
		},
		ThreatDomainAllowlist: []string{badHost},
	})

	if hit, _ := globalThreatFeed.CheckDomain(badHost); hit {
		t.Fatal("allowlisted snapshot domain should not block while the exception is active")
	}
	if hit, src := globalThreatFeed.CheckURL(badURL); !hit || src != "cluster-sync" {
		t.Fatalf("exact malicious URL must stay blocked despite the domain allowlist; hit=%v src=%q", hit, src)
	}
	// Legacy-compat surfaces exclude masked hosts: ExportDomains feeds the
	// CP→DP wire field and the on-disk `domains` key feeds old binaries on
	// rollback — both keep the pre-masking meaning "hosts a lookup may
	// block", so allowlisted hosts must NOT appear there (an old binary has
	// no lookup-time mask and would hard-block them).
	if _, ok := globalThreatFeed.ExportDomains()[badHost]; ok {
		t.Fatal("ExportDomains must exclude allowlisted hosts (mixed-version rolling-upgrade safety)")
	}
	if _, ok := globalThreatFeed.ExportURLs()[badURL]; !ok {
		t.Fatal("exact malicious URL should remain present after snapshot allowlist")
	}

	// Read the DB BEFORE removing the exemption — removal auto-persists
	// again and legitimately re-adds the (now unmasked) host.
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read threatfeed DB: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal threatfeed DB: %v", err)
	}
	domains, ok := decoded["domains"].(map[string]any)
	if !ok {
		t.Fatalf("on-disk feedDB domains map missing or wrong type")
	}
	if _, ok := domains[badHost]; ok {
		t.Fatal("on-disk domains must exclude allowlisted hosts (binary-rollback safety)")
	}
	urls, ok := decoded["urls"].(map[string]any)
	if !ok {
		t.Fatalf("on-disk feedDB urls map missing or wrong type")
	}
	if _, ok := urls[badURL]; !ok {
		t.Fatal("applyConfigSnapshot should persist exact malicious URL entries")
	}

	// In-memory retention: removing the exemption re-blocks IMMEDIATELY —
	// no waiting for the next feed sync to repopulate the domain map — and
	// the host returns to the legacy-compat surfaces.
	if err := globalThreatFeed.RemoveDomainAllowlist(badHost); err != nil {
		t.Fatalf("RemoveDomainAllowlist: %v", err)
	}
	if hit, src := globalThreatFeed.CheckDomain(badHost); !hit || src != "cluster-sync" {
		t.Fatalf("removing snapshot allowlist should immediately re-enable domain block; hit=%v src=%q", hit, src)
	}
	if _, ok := globalThreatFeed.ExportDomains()[badHost]; !ok {
		t.Fatal("ExportDomains should include the host again after allowlist removal")
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestApplyConfigSnapshot_CategoryGroupsPersist exercises the
// caller-side globalCategoryGroups.Save() hook after ReplaceAll in
// applyConfigSnapshot's snap.CategoryGroups branch (P6.1 UC-2 closure).
func TestApplyConfigSnapshot_CategoryGroupsPersist(t *testing.T) {
	origPath := globalCategoryGroups.Path()
	origGroups := globalCategoryGroups.List()
	t.Cleanup(func() {
		globalCategoryGroups.SetPathForTest(origPath)
		globalCategoryGroups.ReplaceAll(origGroups)
	})

	dir := t.TempDir()
	path := filepath.Join(dir, "category_groups.json")
	globalCategoryGroups.SetPathForTest(path)

	snap := ConfigSnapshot{
		Version: 1,
		CategoryGroups: []CategoryGroup{
			{Name: "p34-test-group", Categories: []string{"Adult", "Gambling"}},
		},
	}
	applyConfigSnapshot(snap)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat %q: %v (caller-side Save hook did not persist)", path, err)
	}

	fresh := catgroup.New()
	if err := fresh.Load(path); err != nil {
		t.Fatalf("fresh.Load: %v", err)
	}
	groups := fresh.List()
	if len(groups) != 1 {
		t.Fatalf("loaded %d groups, want 1", len(groups))
	}
	if groups[0].Name != "p34-test-group" {
		t.Errorf("groups[0].Name = %q, want p34-test-group", groups[0].Name)
	}
}
