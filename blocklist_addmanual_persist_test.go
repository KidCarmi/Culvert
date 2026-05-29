package main

// blocklist_addmanual_persist_test.go — regression coverage for the
// "manual blocklist entries lost across restart" gap: AddManual must
// persist its entry to the MAIN blocklist file (not just the .manual
// sidecar), because Load reads the main file into b.exact / b.wildcards
// — the only maps IsBlocked consults. The .manual sidecar restores
// attribution metadata (b.manual) but is NOT re-injected into the
// enforcement maps by Load, so an entry that only made it to .manual
// will not be enforced after restart.
//
// The realistic failure mode is the apiBlocklist POST handler
// (ui_policy.go) processing a bulk add: it calls AddManual per host
// inside a loop and bl.Save() once after the loop, but it `return`s
// early on an invalid wildcard mid-loop — skipping the post-loop Save
// for the valid entries that already ran through AddManual.

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBlocklist_AddManual_PersistsMainFile pins the durability contract:
// after AddManual returns, a fresh Blocklist instance loading from the
// same path must enforce the entry. Without the production fix (Save()
// in AddManual), the main file is empty / stale, Load reads no exact
// entries, and IsBlocked returns false — the test fails with the
// intended "did not survive reload" diagnostic.
func TestBlocklist_AddManual_PersistsMainFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")

	// First instance: create the main file (empty) so the reload's Load
	// call doesn't fail on os.Open. Real production flow starts from an
	// existing file (initial Save at startup); we mirror that.
	b1 := freshBLWithSidecars(path)
	b1.Save()

	const host = "manual-persist.example"
	b1.AddManual(host)

	// Fresh instance reads the same path. Mirrors process restart.
	b2 := freshBLWithSidecars(path)
	if err := b2.Load(path); err != nil {
		t.Fatalf("reload Load(%q): %v", path, err)
	}
	if !b2.IsBlocked(host) {
		t.Fatalf("AddManual entry %q did not survive reload — main blocklist file was not persisted (IsBlocked checks b.exact/wildcards, not the .manual sidecar)", host)
	}
}

// TestBlocklist_AddManual_WildcardPersistsMainFile is the wildcard arm of
// the same contract — wildcards go into b.wildcards and travel through
// the same main-file save/load cycle, so the durability requirement is
// symmetric with the exact-host case.
func TestBlocklist_AddManual_WildcardPersistsMainFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")

	b1 := freshBLWithSidecars(path)
	b1.Save()

	const wildcard = "*.manual-persist.example"
	const matched = "child.manual-persist.example"
	b1.AddManual(wildcard)

	b2 := freshBLWithSidecars(path)
	if err := b2.Load(path); err != nil {
		t.Fatalf("reload Load: %v", err)
	}
	if !b2.IsBlocked(matched) {
		t.Fatalf("wildcard AddManual entry %q did not survive reload — main blocklist file was not persisted", wildcard)
	}
}

// TestBlocklist_AddManual_DuplicateNoCorruption guards the "preserve
// existing behavior for duplicates" non-regression: calling AddManual
// twice for the same host must leave a single entry on disk and remain
// idempotent on reload. The added Save() must not corrupt the main file
// or duplicate lines.
func TestBlocklist_AddManual_DuplicateNoCorruption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")

	b := freshBLWithSidecars(path)
	b.Save()

	const host = "dup.example"
	b.AddManual(host)
	b.AddManual(host)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read main file: %v", err)
	}
	// Count occurrences of the host on its own line. Save() writes one
	// line per map key, so duplicates collapse via the map — there must
	// be exactly one.
	got := 0
	for _, line := range splitLines(string(data)) {
		if line == host {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("AddManual duplicate produced %d %q lines in main file; want 1 (map keys must dedupe; data=%q)", got, host, string(data))
	}
}

// splitLines is a tiny strings.Split wrapper kept local to avoid
// importing strings just for this file.
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
