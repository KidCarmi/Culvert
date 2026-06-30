package main

import (
	"os"
	"path/filepath"
	"testing"
)

// sanitizeYARAName + resolveRulePath tests moved to internal/yara (ADR-0002) —
// they exercise the unexported helpers + the dir field.

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

// ─── Files / FileRules (Tier 3.2) ─────────────────────────────────────────────

func TestYARARuleSet_Files_And_FileRules(t *testing.T) {
	dir := t.TempDir()
	// Write a .yar file containing two rules.
	src1 := yaraRule("RuleOne", `        $a = "x"`, "any of them") +
		yaraRule("RuleTwo", `        $a = "y"`, "any of them")
	if err := os.WriteFile(filepath.Join(dir, "bundle.yar"), []byte(src1), 0o600); err != nil {
		t.Fatal(err)
	}
	// Write a .yara file with a single rule.
	src2 := yaraRule("LegacyRule", `        $a = "z"`, "any of them")
	if err := os.WriteFile(filepath.Join(dir, "legacy.yara"), []byte(src2), 0o600); err != nil {
		t.Fatal(err)
	}

	y := &YARARuleSet{}
	if err := y.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	files := y.Files()
	if len(files) != 2 || files[0] != "bundle" || files[1] != "legacy" {
		t.Errorf("Files() = %v, want [bundle legacy]", files)
	}

	fr := y.FileRules()
	bundleRules := fr["bundle"]
	if len(bundleRules) != 2 {
		t.Errorf("bundle should contain 2 rules, got %v", bundleRules)
	}
	legacyRules := fr["legacy"]
	if len(legacyRules) != 1 || legacyRules[0] != "LegacyRule" {
		t.Errorf("legacy should contain [LegacyRule], got %v", legacyRules)
	}
}

func TestYARARuleSet_Files_Empty(t *testing.T) {
	y := &YARARuleSet{}
	if f := y.Files(); f != nil {
		t.Errorf("Files() on empty set = %v, want nil", f)
	}
	if fr := y.FileRules(); fr != nil {
		t.Errorf("FileRules() on empty set = %v, want nil", fr)
	}
}

// ─── .yara extension fallback (Tier 3.2) ──────────────────────────────────────

func TestYARARuleSet_ReadRule_YaraExtension(t *testing.T) {
	dir := t.TempDir()
	src := yaraRule("LegacyRule", `        $a = "legacy"`, "any of them")
	if err := os.WriteFile(filepath.Join(dir, "legacy.yara"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	y := &YARARuleSet{}
	y.SetDir(dir)

	got, err := y.ReadRule("legacy")
	if err != nil {
		t.Fatalf("ReadRule should find .yara file: %v", err)
	}
	if got != src {
		t.Errorf("unexpected content: %q", got)
	}

	// Delete should also find the .yara file.
	if err := y.DeleteRule("legacy"); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "legacy.yara")); !os.IsNotExist(err) {
		t.Errorf(".yara file not removed: %v", err)
	}
}

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
	s := newContentScanner(1 << 20)
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

	s := newContentScanner(1 << 20)
	if err := s.Load(path); err != nil {
		t.Fatalf("Load missing file: %v", err)
	}
	if err := s.Set([]string{"foo"}); err != nil {
		t.Fatal(err)
	}
	s.SetBypassHosts([]string{"a.example"})
	s.Save()

	// Re-load in a fresh scanner.
	s2 := newContentScanner(1 << 20)
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

// ScanExclusionStore + sortStrings tests moved to internal/scanexcl (ADR-0002)
// — they exercise the unexported fields / helper, now in package scanexcl.
