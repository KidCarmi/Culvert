package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── sanitizeYARAName ─────────────────────────────────────────────────────────

func TestSanitizeYARAName_Valid(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"rule1", "rule1"},
		{"Rule_1-foo", "Rule_1-foo"},
		{"  trim  ", "trim"},
		{"name.yar", "name"},
		{"name.yara", "name"},
		{"A", "A"},
	}
	for _, c := range cases {
		got, err := sanitizeYARAName(c.in)
		if err != nil {
			t.Errorf("sanitizeYARAName(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("sanitizeYARAName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeYARAName_Invalid(t *testing.T) {
	bad := []string{
		"",
		"   ",
		"..",
		"../etc/passwd",
		"foo/bar",
		"foo bar",
		"foo\\bar",
		"foo;rm",
		"foo$bar",
		strings.Repeat("a", 65),
	}
	for _, in := range bad {
		if _, err := sanitizeYARAName(in); err == nil {
			t.Errorf("sanitizeYARAName(%q) expected error, got nil", in)
		}
	}
}

// ─── resolveRulePath ──────────────────────────────────────────────────────────

func TestResolveRulePath_Basic(t *testing.T) {
	dir := t.TempDir()
	y := &YARARuleSet{dir: dir}

	path, got, err := y.resolveRulePath("myrule")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != filepath.Clean(dir) {
		t.Errorf("dir = %q, want %q", got, dir)
	}
	want := filepath.Join(dir, "myrule.yar")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}

func TestResolveRulePath_NoDirConfigured(t *testing.T) {
	y := &YARARuleSet{}
	if _, _, err := y.resolveRulePath("rule"); err == nil {
		t.Fatal("expected error when dir is empty")
	}
}

func TestResolveRulePath_InvalidName(t *testing.T) {
	y := &YARARuleSet{dir: t.TempDir()}
	if _, _, err := y.resolveRulePath("../escape"); err == nil {
		t.Fatal("expected error for traversal attempt")
	}
}

// ─── ReadRule / WriteRule / DeleteRule ────────────────────────────────────────

func TestYARARuleSet_WriteReadDelete(t *testing.T) {
	dir := t.TempDir()
	y := &YARARuleSet{}
	y.SetDir(dir)
	if y.Dir() != dir {
		t.Fatalf("Dir() = %q, want %q", y.Dir(), dir)
	}

	src := yaraRule("TestRule", `        $a = "HELLO"`, "any of them")

	warnings, err := y.WriteRule("myrule", src)
	if err != nil {
		t.Fatalf("WriteRule error: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}

	// File should now exist on disk.
	if _, err := os.Stat(filepath.Join(dir, "myrule.yar")); err != nil {
		t.Fatalf("expected rule file on disk: %v", err)
	}

	// LoadDir should have been called by WriteRule — Names() should include it.
	names := y.Names()
	found := false
	for _, n := range names {
		if n == "TestRule" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TestRule in Names(), got %v", names)
	}

	// Read it back.
	got, err := y.ReadRule("myrule")
	if err != nil {
		t.Fatalf("ReadRule error: %v", err)
	}
	if got != src {
		t.Errorf("ReadRule returned %q, want %q", got, src)
	}

	// Delete it.
	if err := y.DeleteRule("myrule"); err != nil {
		t.Fatalf("DeleteRule error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "myrule.yar")); !os.IsNotExist(err) {
		t.Errorf("expected file removed, stat err = %v", err)
	}
}

func TestYARARuleSet_WriteRule_InvalidSource(t *testing.T) {
	y := &YARARuleSet{}
	y.SetDir(t.TempDir())
	if _, err := y.WriteRule("bad", "not a rule"); err == nil {
		t.Fatal("expected parse error on garbage source")
	}
}

func TestYARARuleSet_WriteRule_InvalidName(t *testing.T) {
	y := &YARARuleSet{}
	y.SetDir(t.TempDir())
	src := yaraRule("OK", `        $a = "x"`, "any of them")
	if _, err := y.WriteRule("../evil", src); err == nil {
		t.Fatal("expected error on traversal name")
	}
}

func TestYARARuleSet_ReadRule_NotFound(t *testing.T) {
	y := &YARARuleSet{}
	y.SetDir(t.TempDir())
	if _, err := y.ReadRule("missing"); err == nil {
		t.Fatal("expected read error on missing file")
	}
}

func TestYARARuleSet_DeleteRule_NotFound(t *testing.T) {
	y := &YARARuleSet{}
	y.SetDir(t.TempDir())
	if err := y.DeleteRule("missing"); err == nil {
		t.Fatal("expected delete error on missing file")
	}
}

// ─── Names / Warnings / Dir ───────────────────────────────────────────────────

func TestYARARuleSet_Names_Warnings_Dir_Empty(t *testing.T) {
	y := &YARARuleSet{}
	if names := y.Names(); len(names) != 0 {
		t.Errorf("empty set Names() = %v", names)
	}
	if w := y.Warnings(); w != nil {
		t.Errorf("empty set Warnings() = %v", w)
	}
	if d := y.Dir(); d != "" {
		t.Errorf("empty set Dir() = %q", d)
	}
}

// ─── ValidateYARASource ───────────────────────────────────────────────────────

func TestValidateYARASource_Good(t *testing.T) {
	src := yaraRule("R1", `        $a = "abc"`, "any of them")
	names, warnings, err := ValidateYARASource(src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(names) != 1 || names[0] != "R1" {
		t.Errorf("names = %v, want [R1]", names)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestValidateYARASource_Empty(t *testing.T) {
	if _, _, err := ValidateYARASource(""); err == nil {
		t.Fatal("expected error on empty source")
	}
	if _, _, err := ValidateYARASource("// just a comment"); err == nil {
		t.Fatal("expected error on comment-only source")
	}
}

func TestValidateYARASource_PartialSkip(t *testing.T) {
	// Two rules, one broken. Parser should recover and return the valid one
	// plus a warning for the broken one.
	good := yaraRule("Good", `        $a = "ok"`, "any of them")
	// "rule {" — parser sees "rule " prefix but name resolves to empty,
	// triggering "empty rule name" that becomes a warning.
	bad := "rule {\n  condition:\n    any of them\n}\n"
	names, warnings, err := ValidateYARASource(good + bad)
	if err != nil {
		t.Fatalf("expected success with warnings, got %v", err)
	}
	if len(names) != 1 || names[0] != "Good" {
		t.Errorf("names = %v, want [Good]", names)
	}
	if len(warnings) == 0 {
		t.Error("expected at least one warning for the broken rule")
	}
}

// ─── ContentScanner DPI bypass hosts (Tier 3.4) ───────────────────────────────

func TestContentScanner_BypassHosts_SetGetIs(t *testing.T) {
	s := &ContentScanner{maxBytes: 1 << 20}
	s.SetBypassHosts([]string{"Example.com", "  internal.local  ", ""})

	list := s.BypassHosts()
	if len(list) != 2 {
		t.Fatalf("expected 2 hosts, got %v", list)
	}
	// Sorted output.
	if list[0] != "example.com" || list[1] != "internal.local" {
		t.Errorf("unexpected sorted list: %v", list)
	}

	if !s.IsBypassHost("example.com") {
		t.Error("IsBypassHost should match exact host")
	}
	if !s.IsBypassHost("EXAMPLE.COM") {
		t.Error("IsBypassHost should be case-insensitive")
	}
	if !s.IsBypassHost("example.com:8080") {
		t.Error("IsBypassHost should strip port suffix")
	}
	if s.IsBypassHost("other.com") {
		t.Error("IsBypassHost false positive")
	}
	if s.IsBypassHost("") {
		t.Error("empty host should not match")
	}
}

func TestContentScanner_BypassHosts_NilReceiver(t *testing.T) {
	var s *ContentScanner
	if s.IsBypassHost("anything.com") {
		t.Error("nil receiver should return false")
	}
}

func TestContentScanner_BypassHosts_LoadSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dpi.json")

	s := &ContentScanner{maxBytes: 1 << 20}
	if err := s.Load(path); err != nil {
		t.Fatalf("Load missing file: %v", err)
	}
	if err := s.Set([]string{"foo"}); err != nil {
		t.Fatal(err)
	}
	s.SetBypassHosts([]string{"a.example"})
	s.Save()

	// Re-load in a fresh scanner.
	s2 := &ContentScanner{maxBytes: 1 << 20}
	if err := s2.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if patterns := s2.List(); len(patterns) != 1 || patterns[0] != "foo" {
		t.Errorf("patterns = %v", patterns)
	}
	if !s2.IsBypassHost("a.example") {
		t.Error("bypass host not restored")
	}
}

// ─── ScanExclusionStore (Tier 3.3) ────────────────────────────────────────────

func TestScanExclusionStore_ReplaceAndIsHashExcluded(t *testing.T) {
	s := &ScanExclusionStore{hashes: map[string]bool{}, hosts: map[string]bool{}}
	s.Replace([]string{"ABCDEF123", "  "}, []string{"Example.com", ""})

	if !s.IsHashExcluded("abcdef123") {
		t.Error("hash should be excluded (lowercased)")
	}
	if !s.IsHashExcluded("ABCDEF123") {
		t.Error("hash should be excluded regardless of input case")
	}
	if s.IsHashExcluded("deadbeef") {
		t.Error("unknown hash should not match")
	}

	if !s.IsHostExcluded("example.com") {
		t.Error("host should be excluded")
	}
	if !s.IsHostExcluded("EXAMPLE.COM:443") {
		t.Error("host with port should be excluded (case-insensitive)")
	}
	if s.IsHostExcluded("other.com") {
		t.Error("false positive on host")
	}
	if s.IsHostExcluded("") {
		t.Error("empty host should not match")
	}
}

func TestScanExclusionStore_NilReceiver(t *testing.T) {
	var s *ScanExclusionStore
	if s.IsHashExcluded("x") {
		t.Error("nil receiver hash")
	}
	if s.IsHostExcluded("example.com") {
		t.Error("nil receiver host")
	}
}

func TestScanExclusionStore_Lists_Sorted(t *testing.T) {
	s := &ScanExclusionStore{hashes: map[string]bool{}, hosts: map[string]bool{}}
	s.Replace([]string{"beef", "dead", "cafe"}, []string{"c.com", "a.com", "b.com"})
	hashes, hosts := s.Lists()
	if len(hashes) != 3 || hashes[0] != "beef" || hashes[1] != "cafe" || hashes[2] != "dead" {
		t.Errorf("hashes not sorted: %v", hashes)
	}
	if len(hosts) != 3 || hosts[0] != "a.com" || hosts[1] != "b.com" || hosts[2] != "c.com" {
		t.Errorf("hosts not sorted: %v", hosts)
	}
}

func TestScanExclusionStore_LoadSave_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "excl.json")

	s1 := &ScanExclusionStore{hashes: map[string]bool{}, hosts: map[string]bool{}}
	// Load missing file is not an error.
	if err := s1.Load(path); err != nil {
		t.Fatalf("load missing: %v", err)
	}

	s1.Replace([]string{"h1", "h2"}, []string{"host1.example", "host2.example"})
	if err := s1.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Fresh store reloads from disk.
	s2 := &ScanExclusionStore{hashes: map[string]bool{}, hosts: map[string]bool{}}
	if err := s2.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !s2.IsHashExcluded("h1") || !s2.IsHashExcluded("h2") {
		t.Error("hashes not roundtripped")
	}
	if !s2.IsHostExcluded("host1.example") || !s2.IsHostExcluded("host2.example") {
		t.Error("hosts not roundtripped")
	}
}

func TestScanExclusionStore_Load_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "excl.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &ScanExclusionStore{hashes: map[string]bool{}, hosts: map[string]bool{}}
	if err := s.Load(path); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestScanExclusionStore_Save_NoPath(t *testing.T) {
	s := &ScanExclusionStore{hashes: map[string]bool{}, hosts: map[string]bool{}}
	s.Replace([]string{"x"}, []string{"y"})
	// No path configured → Save is a no-op, no error.
	if err := s.Save(); err != nil {
		t.Errorf("Save without path should be no-op: %v", err)
	}
}

func TestScanExclusionStore_Load_ValidEnvelope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "excl.json")
	env := scanExclusionsFile{
		Hashes: []string{"AAA", "BBB"},
		Hosts:  []string{"Foo.Example"},
	}
	data, _ := json.Marshal(env)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &ScanExclusionStore{hashes: map[string]bool{}, hosts: map[string]bool{}}
	if err := s.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !s.IsHashExcluded("aaa") || !s.IsHashExcluded("bbb") {
		t.Error("hashes not loaded/lowercased")
	}
	if !s.IsHostExcluded("foo.example") {
		t.Error("host not loaded/lowercased")
	}
}

// ─── sortStrings helper ───────────────────────────────────────────────────────

func TestSortStrings(t *testing.T) {
	in := []string{"c", "a", "b", "a"}
	sortStrings(in)
	if in[0] != "a" || in[1] != "a" || in[2] != "b" || in[3] != "c" {
		t.Errorf("sortStrings = %v", in)
	}

	sortStrings(nil) // should not panic
	sortStrings([]string{"only"})
}
