package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Helper: build YARA source with { on its own line (required by parser).
func yaraRule(name, strings_, cond string) string {
	s := "rule " + name + "\n{\n"
	if strings_ != "" {
		s += "    strings:\n" + strings_ + "\n"
	}
	s += "    condition:\n        " + cond + "\n}\n"
	return s
}

// ─── parseYARASrc / parseYARARule ─────────────────────────────────────────────

func TestParseYARASrc_LiteralMatch(t *testing.T) {
	src := yaraRule("TestLiteral", `        $a = "EICAR"`, "any of them")
	rules, err := parseYARASrc(src)
	if err != nil {
		t.Fatalf("parseYARASrc error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].name != "TestLiteral" {
		t.Errorf("rule name = %q, want TestLiteral", rules[0].name)
	}
	if rules[0].condKind != yaraAnyOfThem {
		t.Errorf("condKind = %v, want yaraAnyOfThem", rules[0].condKind)
	}
}

func TestParseYARASrc_AllOfThem(t *testing.T) {
	src := yaraRule("TestAll", "        $a = \"hello\"\n        $b = \"world\"", "all of them")
	rules, err := parseYARASrc(src)
	if err != nil {
		t.Fatalf("parseYARASrc error: %v", err)
	}
	if rules[0].condKind != yaraAllOfThem {
		t.Errorf("condKind = %v, want yaraAllOfThem", rules[0].condKind)
	}
}

func TestParseYARASrc_BoolExpr(t *testing.T) {
	src := yaraRule("TestBool", "        $a = \"foo\"\n        $b = \"bar\"", "$a and $b")
	rules, err := parseYARASrc(src)
	if err != nil {
		t.Fatalf("parseYARASrc error: %v", err)
	}
	if rules[0].condKind != yaraBoolExpr {
		t.Errorf("condKind = %v, want yaraBoolExpr", rules[0].condKind)
	}
}

func TestParseYARASrc_Comment(t *testing.T) {
	src := "// A comment\n" + yaraRule("TestComment", "        $a = \"test\" // inline comment", "any of them")
	rules, err := parseYARASrc(src)
	if err != nil {
		t.Fatalf("parseYARASrc error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
}

func TestParseYARASrc_MultipleRules(t *testing.T) {
	src := yaraRule("Rule1", `        $a = "abc"`, "any of them") +
		yaraRule("Rule2", `        $b = "xyz"`, "any of them")
	rules, err := parseYARASrc(src)
	if err != nil {
		t.Fatalf("parseYARASrc error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}

func TestParseYARASrc_NoCase(t *testing.T) {
	src := yaraRule("TestNoCase", `        $a = "MaLwArE" nocase`, "any of them")
	rules, err := parseYARASrc(src)
	if err != nil {
		t.Fatalf("parseYARASrc error: %v", err)
	}
	if len(rules[0].strings) == 0 || !rules[0].strings[0].noCase {
		t.Error("nocase flag should be parsed")
	}
}

func TestParseYARASrc_Regex(t *testing.T) {
	src := yaraRule("TestRegex", `        $re = /malware_\w+/i`, "any of them")
	rules, err := parseYARASrc(src)
	if err != nil {
		t.Fatalf("parseYARASrc error: %v", err)
	}
	if rules[0].strings[0].re == nil {
		t.Error("regex string def should have a compiled regexp")
	}
}

func TestParseYARASrc_HexPattern(t *testing.T) {
	src := yaraRule("TestHex", `        $hex = { 4D 5A 90 00 }`, "any of them")
	rules, err := parseYARASrc(src)
	if err != nil {
		t.Fatalf("parseYARASrc error: %v", err)
	}
	if len(rules[0].strings[0].literal) == 0 {
		t.Error("hex pattern should produce a non-empty literal")
	}
}

func TestParseYARASrc_Empty(t *testing.T) {
	rules, err := parseYARASrc("")
	if err != nil {
		t.Fatalf("parseYARASrc('') error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules from empty input, got %d", len(rules))
	}
}

// ─── YARARuleSet.Match ────────────────────────────────────────────────────────

func newYARASet(t *testing.T, src string) *YARARuleSet {
	t.Helper()
	rules, err := parseYARASrc(src)
	if err != nil {
		t.Fatalf("parseYARASrc: %v", err)
	}
	y := &YARARuleSet{}
	y.rules = rules
	return y
}

func TestYARARuleSet_Match_AnyOfThem(t *testing.T) {
	y := newYARASet(t, yaraRule("Detect", "        $a = \"EICAR\"\n        $b = \"malware\"", "any of them"))
	if matched := y.Match([]byte("This file contains EICAR test string")); len(matched) == 0 {
		t.Error("should match when $a is present")
	}
	if matched := y.Match([]byte("clean content")); len(matched) != 0 {
		t.Errorf("should not match clean content, got %v", matched)
	}
}

func TestYARARuleSet_Match_AllOfThem(t *testing.T) {
	y := newYARASet(t, yaraRule("NeedsBoth", "        $a = \"hello\"\n        $b = \"world\"", "all of them"))
	if matched := y.Match([]byte("hello world")); len(matched) == 0 {
		t.Error("should match when both strings present")
	}
	if matched := y.Match([]byte("hello only")); len(matched) != 0 {
		t.Errorf("should not match when only one string present, got %v", matched)
	}
}

func TestYARARuleSet_Match_BoolExprAnd(t *testing.T) {
	y := newYARASet(t, yaraRule("BoolAnd", "        $a = \"foo\"\n        $b = \"bar\"", "$a and $b"))
	if matched := y.Match([]byte("foo and bar together")); len(matched) == 0 {
		t.Error("should match when both strings present")
	}
	if matched := y.Match([]byte("only foo here")); len(matched) != 0 {
		t.Errorf("should not match with only $a, got %v", matched)
	}
}

func TestYARARuleSet_Match_BoolExprOr(t *testing.T) {
	y := newYARASet(t, yaraRule("BoolOr", "        $a = \"foo\"\n        $b = \"bar\"", "$a or $b"))
	if matched := y.Match([]byte("just foo")); len(matched) == 0 {
		t.Error("should match when $a present with OR condition")
	}
}

func TestYARARuleSet_Match_Not(t *testing.T) {
	y := newYARASet(t, yaraRule("NotRule", `        $a = "danger"`, "not $a"))
	if matched := y.Match([]byte("safe content")); len(matched) == 0 {
		t.Error("should match when $a is NOT present")
	}
	if matched := y.Match([]byte("danger zone")); len(matched) != 0 {
		t.Errorf("should not match when $a IS present, got %v", matched)
	}
}

func TestYARARuleSet_Match_Regex(t *testing.T) {
	y := newYARASet(t, yaraRule("RegexRule", `        $re = /virus_[a-z]+/i`, "any of them"))
	if matched := y.Match([]byte("found VIRUS_abc in file")); len(matched) == 0 {
		t.Error("regex with 'i' flag should match case-insensitively")
	}
	if matched := y.Match([]byte("nothing suspicious")); len(matched) != 0 {
		t.Errorf("should not match clean content, got %v", matched)
	}
}

func TestYARARuleSet_Match_NoCase(t *testing.T) {
	y := newYARASet(t, yaraRule("NoCaseRule", `        $a = "MALWARE" nocase`, "any of them"))
	if matched := y.Match([]byte("contains malware string")); len(matched) == 0 {
		t.Error("nocase should match lowercase variant")
	}
	if matched := y.Match([]byte("MaLwArE here")); len(matched) == 0 {
		t.Error("nocase should match mixed-case variant")
	}
}

func TestYARARuleSet_Match_HexPattern(t *testing.T) {
	y := newYARASet(t, yaraRule("HexRule", `        $mz = { 4D 5A }`, "any of them"))
	if matched := y.Match([]byte{0x4D, 0x5A, 0x90, 0x00}); len(matched) == 0 {
		t.Error("should match MZ header hex pattern")
	}
	if matched := y.Match([]byte{0x00, 0x01, 0x02}); len(matched) != 0 {
		t.Errorf("should not match non-MZ bytes, got %v", matched)
	}
}

func TestYARARuleSet_Enabled(t *testing.T) {
	y := &YARARuleSet{}
	if y.Enabled() {
		t.Error("empty YARARuleSet should not be enabled")
	}
	y.rules = []yaraCompiledRule{{name: "test"}}
	if !y.Enabled() {
		t.Error("YARARuleSet with rules should be enabled")
	}
}

func TestYARARuleSet_LoadDir(t *testing.T) {
	dir := t.TempDir()
	content := yaraRule("TestFile", `        $a = "test"`, "any of them")
	if err := os.WriteFile(filepath.Join(dir, "test.yar"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	y := &YARARuleSet{}
	if err := y.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir error: %v", err)
	}
	if y.Count() != 1 {
		t.Errorf("Count() = %d, want 1", y.Count())
	}
	if !y.Enabled() {
		t.Error("should be enabled after loading rules")
	}
}

func TestYARARuleSet_LoadDir_Empty(t *testing.T) {
	dir := t.TempDir()
	y := &YARARuleSet{}
	if err := y.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir error on empty dir: %v", err)
	}
	if y.Count() != 0 {
		t.Errorf("Count() = %d, want 0", y.Count())
	}
}

// ─── evalBoolCondition ────────────────────────────────────────────────────────

func TestEvalBoolCondition_AnyOfThem(t *testing.T) {
	hit := map[string]bool{"$a": true, "$b": false}
	if !evalBoolCondition("any of them", hit) {
		t.Error("any of them: should be true when at least one matches")
	}
	if evalBoolCondition("any of them", map[string]bool{"$a": false}) {
		t.Error("any of them: should be false when none match")
	}
}

func TestEvalBoolCondition_AllOfThem(t *testing.T) {
	if !evalBoolCondition("all of them", map[string]bool{"$a": true, "$b": true}) {
		t.Error("all of them: should be true when all match")
	}
	if evalBoolCondition("all of them", map[string]bool{"$a": true, "$b": false}) {
		t.Error("all of them: should be false when any miss")
	}
	if evalBoolCondition("all of them", map[string]bool{}) {
		t.Error("all of them: empty map should return false")
	}
}

func TestEvalBoolCondition_Parentheses(t *testing.T) {
	hit := map[string]bool{"$a": true, "$b": false, "$c": true}
	// ($a or $b) and $c
	if !evalBoolCondition("( $a or $b ) and $c", hit) {
		t.Error("(true or false) and true should be true")
	}
}

func TestEvalBoolCondition_TrueFalse(t *testing.T) {
	if !evalBoolCondition("true", map[string]bool{}) {
		t.Error("'true' literal should evaluate to true")
	}
	if evalBoolCondition("false", map[string]bool{}) {
		t.Error("'false' literal should evaluate to false")
	}
}

// ─── stripYARAComment ────────────────────────────────────────────────────────

func TestStripYARAComment(t *testing.T) {
	if got := stripYARAComment("code // comment"); got != "code " {
		t.Errorf("stripYARAComment = %q, want 'code '", got)
	}
	if got := stripYARAComment("no comment"); got != "no comment" {
		t.Errorf("stripYARAComment = %q, want 'no comment'", got)
	}
	if got := stripYARAComment("// full comment"); got != "" {
		t.Errorf("stripYARAComment = %q, want ''", got)
	}
}

// ─── parseYARAStringDef ───────────────────────────────────────────────────────

func TestParseYARAStringDef_Literal(t *testing.T) {
	sd, err := parseYARAStringDef(`$s1 = "hello world"`)
	if err != nil {
		t.Fatalf("parseYARAStringDef error: %v", err)
	}
	if sd.id != "$s1" {
		t.Errorf("id = %q, want $s1", sd.id)
	}
	if string(sd.literal) != "hello world" {
		t.Errorf("literal = %q, want 'hello world'", sd.literal)
	}
}

func TestParseYARAStringDef_Hex(t *testing.T) {
	sd, err := parseYARAStringDef(`$hex = { DE AD BE EF }`)
	if err != nil {
		t.Fatalf("parseYARAStringDef hex error: %v", err)
	}
	if len(sd.literal) != 4 {
		t.Errorf("hex literal len = %d, want 4", len(sd.literal))
	}
}

func TestParseYARAStringDef_Regex(t *testing.T) {
	sd, err := parseYARAStringDef(`$re = /test_\w+/`)
	if err != nil {
		t.Fatalf("parseYARAStringDef regex error: %v", err)
	}
	if sd.re == nil {
		t.Error("regex string def should have non-nil re")
	}
}

func TestParseYARAStringDef_NoID(t *testing.T) {
	_, err := parseYARAStringDef(`notanid = "value"`)
	if err == nil {
		t.Error("should fail when identifier doesn't start with $")
	}
}

func TestParseYARAStringDef_NoEquals(t *testing.T) {
	_, err := parseYARAStringDef(`$a "no equals"`)
	if err == nil {
		t.Error("should fail with no '=' sign")
	}
}

// ─── parseYARAHexPattern ─────────────────────────────────────────────────────

func TestParseYARAHexPattern_Valid(t *testing.T) {
	b, err := parseYARAHexPattern("{ 4D 5A 90 00 03 }")
	if err != nil {
		t.Fatalf("parseYARAHexPattern error: %v", err)
	}
	if len(b) != 5 || b[0] != 0x4D || b[1] != 0x5A {
		t.Errorf("hex bytes = %v, want [4D 5A 90 00 03]", b)
	}
}

func TestParseYARAHexPattern_Wildcard(t *testing.T) {
	_, err := parseYARAHexPattern("{ DE ?? BE EF }")
	if err == nil {
		t.Error("wildcard hex pattern should return an error")
	}
}

func TestParseYARAHexPattern_Invalid(t *testing.T) {
	_, err := parseYARAHexPattern("not a hex block")
	if err == nil {
		t.Error("invalid hex block should return an error")
	}
}

// ─── parseYARARegex ───────────────────────────────────────────────────────────

func TestParseYARARegex_CaseInsensitive(t *testing.T) {
	re, err := parseYARARegex(`/hello/i`)
	if err != nil {
		t.Fatalf("parseYARARegex error: %v", err)
	}
	if !re.MatchString("HELLO") {
		t.Error("case-insensitive regex should match uppercase")
	}
}

func TestParseYARARegex_Invalid(t *testing.T) {
	_, err := parseYARARegex(`/[invalid/`)
	if err == nil {
		t.Error("invalid regex should return an error")
	}
}

func TestParseYARARegex_Unterminated(t *testing.T) {
	_, err := parseYARARegex(`/unterminated`)
	if err == nil {
		t.Error("unterminated regex should return an error")
	}
}

// ─── parseYARALiteralString ───────────────────────────────────────────────────

func TestParseYARALiteralString_Escapes(t *testing.T) {
	val, _, err := parseYARALiteralString(`"hello\nworld"`)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if val != "hello\nworld" {
		t.Errorf("got %q, want unescaped newline", val)
	}
}

func TestParseYARALiteralString_Unterminated(t *testing.T) {
	_, _, err := parseYARALiteralString(`"unterminated`)
	if err == nil {
		t.Error("unterminated string should return an error")
	}
}
