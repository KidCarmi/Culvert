package main

// configversion_dpi_bypass_test.go — regression coverage for the
// dpiScanner.bypassHosts rollback-surface extension. Per spec at
// roadmap/SCANNER-ROLLBACK-EXTENSION-SPEC.md.
//
// dpiScanner persists patterns AND bypass hosts in a single
// content_scan.json envelope (scanner.go Save). This extension adds
// the bypass-host half to the rollback surface; patterns were already
// covered by configBackup.ContentScanPatterns. The apply path merges
// both into one Save() call.
//
// Tests:
//   1. RoundTrip — capture, mutate, apply prior snapshot, assert
//      bypass hosts restored.
//   2. NilSnapshotIsNoOp — backward compat (absent field → nil → skip).
//   3. EmptySnapshotWipes — explicit [] wipes live bypass list.
//   4. EmptyMarshalsAsArray — zero-bypass serializes as [], not null.
//   5. HandlerPUT_CreatesConfigVersion — apiContentScanBypass PUT
//      produces a "security.dpi-bypass" envelope.
//   6. SingleEnvelopeAfterApply — on-disk content_scan.json contains
//      BOTH patterns and bypass_hosts after a combined apply (single
//      Save, no intermediate state).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// snapshotDPIScanner captures and restores the package-global
// dpiScanner pointer with a fresh in-test instance rooted at a
// t.TempDir path so Save() doesn't pollute /data. Mirrors
// snapshotCatStore from PR #269. Returns the tmp file path so the
// SingleEnvelope test can read it back.
func snapshotDPIScanner(t *testing.T) string {
	t.Helper()
	orig := dpiScanner
	dir := t.TempDir()
	path := filepath.Join(dir, "content_scan.json")
	fresh := newContentScanner(1 << 20)
	// Configure the persistence path via Load on a non-existent file
	// (sets s.path, leaves store empty — scanner.go Load).
	_ = fresh.Load(path)
	dpiScanner = fresh
	t.Cleanup(func() { dpiScanner = orig })
	return path
}

func listBypassHosts(t *testing.T) []string {
	t.Helper()
	hosts := dpiScanner.BypassHosts()
	sort.Strings(hosts)
	return hosts
}

// ─── Test 1: round-trip ───────────────────────────────────────────────

func TestConfigVersion_DPIBypassHosts_RoundTrip(t *testing.T) {
	snapshotDPIScanner(t)
	tmp := snapshotConfigVersionsDir(t)

	// Seed v1: two bypass hosts + one pattern.
	dpiScanner.SetBypassHosts([]string{"ci.internal.example", "mirror.internal.example"})
	if err := dpiScanner.Set([]string{"secret-pattern"}); err != nil {
		t.Fatalf("seed pattern: %v", err)
	}

	saveConfigVersion("dpi-bypass-round-trip", "v1")

	// Mutate v2: change bypass hosts + pattern.
	dpiScanner.SetBypassHosts([]string{"different.example"})
	if err := dpiScanner.Set([]string{"other-pattern"}); err != nil {
		t.Fatalf("mutate pattern: %v", err)
	}

	loadAndApplyV1Envelope(t, tmp)

	// Bypass hosts restored to v1.
	got := listBypassHosts(t)
	want := []string{"ci.internal.example", "mirror.internal.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("bypass hosts after rollback = %v; want %v", got, want)
	}
	// Patterns also restored to v1 (already covered by
	// ContentScanPatterns; verify the merged apply didn't break it).
	if gotPats := dpiScanner.List(); !reflect.DeepEqual(gotPats, []string{"secret-pattern"}) {
		t.Errorf("patterns after rollback = %v; want [secret-pattern]", gotPats)
	}
}

// ─── Test 2: nil snapshot is no-op ────────────────────────────────────

func TestConfigVersion_DPIBypassHosts_NilSnapshotIsNoOp(t *testing.T) {
	snapshotDPIScanner(t)

	dpiScanner.SetBypassHosts([]string{"live.example"})
	pre := listBypassHosts(t)

	backup := configBackup{
		Version:    1,
		ExportedAt: "test",
		// ContentScanBypassHosts: nil — pre-extension shape.
	}
	applyConfigBackup(&backup)

	post := listBypassHosts(t)
	if !reflect.DeepEqual(pre, post) {
		t.Errorf("nil-snapshot apply mutated bypass hosts: pre=%v post=%v", pre, post)
	}
}

// ─── Test 3: empty snapshot wipes ─────────────────────────────────────

func TestConfigVersion_DPIBypassHosts_EmptySnapshotWipes(t *testing.T) {
	snapshotDPIScanner(t)

	dpiScanner.SetBypassHosts([]string{"will.be.wiped.example"})

	backup := configBackup{
		Version:                1,
		ExportedAt:             "test",
		ContentScanBypassHosts: []string{}, // explicit empty
	}
	applyConfigBackup(&backup)

	if hosts := listBypassHosts(t); len(hosts) != 0 {
		t.Errorf("empty-snapshot apply did NOT wipe bypass hosts: got %v", hosts)
	}
}

// ─── Test 4: empty marshals as [] not null ────────────────────────────

func TestConfigVersion_DPIBypassHosts_EmptyMarshalsAsArray(t *testing.T) {
	snapshotDPIScanner(t)

	backup := captureConfigBackup()
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(data)
	if !strings.Contains(js, `"contentScanBypassHosts":[]`) {
		t.Errorf("expected `\"contentScanBypassHosts\":[]` in marshaled snapshot; got: %s", js)
	}
	if strings.Contains(js, `"contentScanBypassHosts":null`) {
		t.Errorf("marshaled snapshot has `\"contentScanBypassHosts\":null` — omitempty must be absent AND BypassHosts() must return non-nil empty: %s", js)
	}
}

// ─── Test 5: handler PUT creates config version ───────────────────────

func TestAPIContentScanBypass_PUT_CreatesConfigVersion(t *testing.T) {
	snapshotDPIScanner(t)
	tmp := snapshotConfigVersionsDir(t)

	body, _ := json.Marshal(map[string]any{"hosts": []string{"bypass-test.example"}})
	w := httptest.NewRecorder()
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	r := httptest.NewRequestWithContext(ctx, http.MethodPut, "/api/content-scan/bypass", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	apiContentScanBypass(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body: %s)", w.Code, w.Body.String())
	}
	assertConfigVersionWithAction(t, tmp, "security.dpi-bypass")
}

// assertConfigVersionWithAction fails the test unless some envelope in
// dir has Meta.Action matching. Positive counterpart to
// assertNoConfigVersionWithAction (from PR #263).
func assertConfigVersionWithAction(t *testing.T, dir, action string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read tmp dir: %v", err)
	}
	type envelope struct {
		Meta struct {
			Action string `json:"action"`
		} `json:"meta"`
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var env envelope
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatalf("unmarshal %s: %v", e.Name(), err)
		}
		if env.Meta.Action == action {
			return
		}
	}
	t.Errorf("no config-version envelope with Meta.Action=%q found — handler did not call saveConfigVersion", action)
}

// ─── Test 7: invalid-pattern snapshot does not produce mixed state ────

// TestConfigVersion_DPIBypassHosts_InvalidPatternNoMixedState pins the
// Codex P2 fix: a snapshot carrying an invalid regex must leave BOTH
// patterns and bypass hosts at their pre-apply runtime values — never
// a mixed state where bypass hosts are replaced but patterns are not.
func TestConfigVersion_DPIBypassHosts_InvalidPatternNoMixedState(t *testing.T) {
	snapshotDPIScanner(t)

	// Establish a known-good runtime state.
	if err := dpiScanner.Set([]string{"good-pattern"}); err != nil {
		t.Fatalf("seed pattern: %v", err)
	}
	dpiScanner.SetBypassHosts([]string{"runtime.example"})

	// Snapshot carries an INVALID regex (unbalanced paren) plus a
	// different bypass-host set.
	backup := configBackup{
		Version:                1,
		ExportedAt:             "test",
		ContentScanPatterns:    []string{"valid", "in(valid"},
		ContentScanBypassHosts: []string{"snapshot.example"},
	}
	applyConfigBackup(&backup)

	// Patterns must be UNCHANGED (Set rejected the bad regex).
	if pats := dpiScanner.List(); !reflect.DeepEqual(pats, []string{"good-pattern"}) {
		t.Errorf("patterns after invalid-snapshot apply = %v; want [good-pattern] (unchanged)", pats)
	}
	// Bypass hosts must ALSO be unchanged — no mixed state.
	if got := listBypassHosts(t); !reflect.DeepEqual(got, []string{"runtime.example"}) {
		t.Errorf("bypass hosts after invalid-snapshot apply = %v; want [runtime.example] (unchanged — mixed state regression)", got)
	}
}

// ─── Test 8: diffConfigs reports bypass-host changes ──────────────────

// TestConfigVersion_DPIBypassHosts_DiffReportsChanges pins the Codex P2
// fix: diffConfigs must include content_scan_bypass_hosts so rollback
// dry-run preflight reflects the actual impact. Without it, dry-run
// claims "no changes" even when apply would mutate bypass hosts.
func TestConfigVersion_DPIBypassHosts_DiffReportsChanges(t *testing.T) {
	a := &configBackup{ContentScanBypassHosts: []string{"keep.example", "removed.example"}}
	b := &configBackup{ContentScanBypassHosts: []string{"keep.example", "added.example"}}

	changes := diffConfigs(a, b)

	var sawField bool
	for _, c := range changes {
		if c.Field == "content_scan_bypass_hosts" {
			sawField = true
		}
	}
	if !sawField {
		t.Errorf("diffConfigs did not report content_scan_bypass_hosts changes; got %d change(s): %+v — dry-run preflight would be inaccurate", len(changes), changes)
	}
}

// TestConfigVersion_DPIBypassHosts_SingleEnvelopeAfterApply verifies
// the spec §8 single-Save contract: after a combined apply, the
// on-disk content_scan.json contains BOTH the restored patterns and
// the restored bypass_hosts (envelope format), proving the merged
// apply wrote the file once with both halves consistent.
func TestConfigVersion_DPIBypassHosts_SingleEnvelopeAfterApply(t *testing.T) {
	path := snapshotDPIScanner(t)

	backup := configBackup{
		Version:                1,
		ExportedAt:             "test",
		ContentScanPatterns:    []string{"pat-a", "pat-b"},
		ContentScanBypassHosts: []string{"bypass-a.example"},
	}
	applyConfigBackup(&backup)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read content_scan.json: %v", err)
	}
	// Envelope format because bypass hosts are present (scanner.go Save).
	var env struct {
		Patterns    []string `json:"patterns"`
		BypassHosts []string `json:"bypass_hosts"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v (raw: %s)", err, data)
	}
	sort.Strings(env.Patterns)
	if !reflect.DeepEqual(env.Patterns, []string{"pat-a", "pat-b"}) {
		t.Errorf("on-disk patterns = %v; want [pat-a pat-b]", env.Patterns)
	}
	if !reflect.DeepEqual(env.BypassHosts, []string{"bypass-a.example"}) {
		t.Errorf("on-disk bypass_hosts = %v; want [bypass-a.example]", env.BypassHosts)
	}
}
