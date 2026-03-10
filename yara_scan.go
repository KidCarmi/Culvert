package main

// Pure-Go YARA rule engine.
//
// Implements a subset of the YARA rule language without requiring cgo or
// libyara, so the proxy binary compiles and runs on any Go-supported platform
// without additional system dependencies.
//
// Supported:
//   - String types: literal ("…"), case-insensitive ("…" nocase),
//     regex (/pattern/[flags]), hex pattern ({ DE AD BE EF })
//   - Conditions: any of them, all of them, $id references, boolean
//     and / or / not expressions, parentheses
//
// Not supported: YARA modules (pe/elf/etc.), filesize, entrypoint,
//   offset operators (@, !), count operators (#), nested rules,
//   include directives, hex wildcards (??), jump patterns.

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// ── Data types ────────────────────────────────────────────────────────────────

type yaraStringDef struct {
	id      string         // variable identifier, e.g. "$a"
	literal []byte         // non-nil for literal / hex patterns
	re      *regexp.Regexp // non-nil for regex patterns
	noCase  bool           // case-insensitive match for literal strings
}

type yaraCondKind int

const (
	yaraAnyOfThem yaraCondKind = iota
	yaraAllOfThem
	yaraBoolExpr
)

type yaraCompiledRule struct {
	name     string
	strings  []yaraStringDef
	condKind yaraCondKind
	condExpr string // lower-cased raw expression for yaraBoolExpr
}

// ── YARARuleSet ───────────────────────────────────────────────────────────────

// YARARuleSet holds compiled YARA rules loaded from a directory.
// All methods are safe for concurrent use.
type YARARuleSet struct {
	mu    sync.RWMutex
	rules []yaraCompiledRule
	dir   string
}

// globalYARA is the process-wide YARA rule set.
var globalYARA = &YARARuleSet{}

// LoadDir loads all *.yar and *.yara files from dir, replacing current rules
// atomically. Errors in individual rule files are logged and skipped; the
// remaining rules are still loaded.
func (y *YARARuleSet) LoadDir(dir string) error {
	var files []string
	for _, pat := range []string{"*.yar", "*.yara"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		files = append(files, m...)
	}

	var loaded []yaraCompiledRule
	for _, f := range files {
		rules, err := loadYARAFile(f)
		if err != nil {
			logger.Printf("YARA: skipping %s: %v", f, err)
			continue
		}
		loaded = append(loaded, rules...)
	}

	y.mu.Lock()
	y.dir = dir
	y.rules = loaded
	y.mu.Unlock()

	logger.Printf("YARA: %d rule(s) loaded from %d file(s) in %s", len(loaded), len(files), dir)
	return nil
}

// Enabled reports whether any rules are currently loaded.
func (y *YARARuleSet) Enabled() bool {
	y.mu.RLock()
	defer y.mu.RUnlock()
	return len(y.rules) > 0
}

// Count returns the number of loaded rules.
func (y *YARARuleSet) Count() int {
	y.mu.RLock()
	defer y.mu.RUnlock()
	return len(y.rules)
}

// Match returns the names of every rule that matches data.
func (y *YARARuleSet) Match(data []byte) []string {
	y.mu.RLock()
	rules := y.rules
	y.mu.RUnlock()

	var matched []string
	for i := range rules {
		if evalYARARule(&rules[i], data) {
			matched = append(matched, rules[i].name)
		}
	}
	return matched
}

// ── Rule evaluation ───────────────────────────────────────────────────────────

func evalYARARule(r *yaraCompiledRule, data []byte) bool {
	hit := make(map[string]bool, len(r.strings))
	for _, s := range r.strings {
		hit[s.id] = matchYARAString(&s, data)
	}
	switch r.condKind {
	case yaraAnyOfThem:
		for _, v := range hit {
			if v {
				return true
			}
		}
		return false
	case yaraAllOfThem:
		if len(hit) == 0 {
			return false
		}
		for _, v := range hit {
			if !v {
				return false
			}
		}
		return true
	default: // yaraBoolExpr
		return evalBoolCondition(r.condExpr, hit)
	}
}

func matchYARAString(s *yaraStringDef, data []byte) bool {
	if s.re != nil {
		return s.re.Match(data)
	}
	if s.noCase {
		return bytes.Contains(bytes.ToLower(data), bytes.ToLower(s.literal))
	}
	return bytes.Contains(data, s.literal)
}

// ── Boolean condition evaluator ───────────────────────────────────────────────
//
// Grammar:
//
//	expr   = term  ('or'  term)*
//	term   = factor ('and' factor)*
//	factor = 'not' factor | '(' expr ')' | '$id' | 'true' | 'false'

func evalBoolCondition(expr string, hit map[string]bool) bool {
	// Fast paths for the two most common conditions.
	if strings.Contains(expr, "any of them") {
		for _, v := range hit {
			if v {
				return true
			}
		}
		return false
	}
	if strings.Contains(expr, "all of them") {
		if len(hit) == 0 {
			return false
		}
		for _, v := range hit {
			if !v {
				return false
			}
		}
		return true
	}
	ts := newYARATokenStream(tokeniseYARAExpr(expr))
	return parseYARAOr(ts, hit)
}

func tokeniseYARAExpr(s string) []string {
	s = strings.ReplaceAll(s, "(", " ( ")
	s = strings.ReplaceAll(s, ")", " ) ")
	return strings.Fields(s)
}

type yaraTokenStream struct {
	tokens []string
	pos    int
}

func newYARATokenStream(t []string) *yaraTokenStream { return &yaraTokenStream{tokens: t} }
func (ts *yaraTokenStream) peek() string {
	if ts.pos >= len(ts.tokens) {
		return ""
	}
	return ts.tokens[ts.pos]
}
func (ts *yaraTokenStream) next() string { t := ts.peek(); ts.pos++; return t }

func parseYARAOr(ts *yaraTokenStream, hit map[string]bool) bool {
	v := parseYARAAnd(ts, hit)
	for ts.peek() == "or" {
		ts.next()
		v = parseYARAAnd(ts, hit) || v
	}
	return v
}

func parseYARAAnd(ts *yaraTokenStream, hit map[string]bool) bool {
	v := parseYARANot(ts, hit)
	for ts.peek() == "and" {
		ts.next()
		v = parseYARANot(ts, hit) && v
	}
	return v
}

func parseYARANot(ts *yaraTokenStream, hit map[string]bool) bool {
	if ts.peek() == "not" {
		ts.next()
		return !parseYARANot(ts, hit)
	}
	return parseYARAAtom(ts, hit)
}

func parseYARAAtom(ts *yaraTokenStream, hit map[string]bool) bool {
	tok := ts.next()
	switch tok {
	case "(":
		v := parseYARAOr(ts, hit)
		if ts.peek() == ")" {
			ts.next()
		}
		return v
	case "true":
		return true
	case "false", "":
		return false
	default:
		if strings.HasPrefix(tok, "$") {
			return hit[tok]
		}
		return false
	}
}

// ── YARA file / source parser ─────────────────────────────────────────────────

func loadYARAFile(path string) ([]yaraCompiledRule, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- admin-configured rules directory
	if err != nil {
		return nil, err
	}
	return parseYARASrc(string(data))
}

func parseYARASrc(src string) ([]yaraCompiledRule, error) {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(src))
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}

	var rules []yaraCompiledRule
	i := 0
	for i < len(lines) {
		line := strings.TrimSpace(stripYARAComment(lines[i]))
		if strings.HasPrefix(line, "rule ") {
			rule, end, err := parseYARARule(lines, i)
			if err != nil {
				logger.Printf("YARA: parse error near line %d: %v (skipping rule)", i+1, err)
				// Skip to the closing brace of this broken rule.
				i++
				for i < len(lines) && strings.TrimSpace(lines[i]) != "}" {
					i++
				}
				i++
				continue
			}
			rules = append(rules, rule)
			i = end
			continue
		}
		i++
	}
	return rules, nil
}

// stripYARAComment removes a trailing // comment from a line.
func stripYARAComment(s string) string {
	if idx := strings.Index(s, "//"); idx >= 0 {
		return s[:idx]
	}
	return s
}

func parseYARARule(lines []string, start int) (yaraCompiledRule, int, error) {
	header := strings.TrimSpace(lines[start])
	parts := strings.Fields(header)
	if len(parts) < 2 {
		return yaraCompiledRule{}, start + 1, fmt.Errorf("missing rule name on line %d", start+1)
	}
	// Strip trailing colon-separated tags or opening brace from the name.
	name := parts[1]
	if idx := strings.IndexAny(name, ":{}"); idx >= 0 {
		name = name[:idx]
	}
	if name == "" {
		return yaraCompiledRule{}, start + 1, fmt.Errorf("empty rule name on line %d", start+1)
	}

	rule := yaraCompiledRule{name: name}

	// Advance past the opening '{'.
	i := start + 1
	for i < len(lines) {
		if strings.Contains(lines[i], "{") {
			i++
			break
		}
		i++
	}

	section := ""
	var condParts []string

	for i < len(lines) {
		raw := strings.TrimSpace(stripYARAComment(lines[i]))
		if raw == "}" {
			i++
			break
		}
		if raw == "" {
			i++
			continue
		}
		switch {
		case raw == "meta:" || strings.HasSuffix(raw, " meta:"):
			section = "meta"
		case raw == "strings:" || strings.HasSuffix(raw, " strings:"):
			section = "strings"
		case raw == "condition:" || strings.HasSuffix(raw, " condition:"):
			section = "condition"
		default:
			switch section {
			case "strings":
				if sd, err := parseYARAStringDef(raw); err == nil {
					rule.strings = append(rule.strings, sd)
				} else {
					logger.Printf("YARA: rule %s: string parse error: %v", name, err)
				}
			case "condition":
				condParts = append(condParts, raw)
			}
		}
		i++
	}

	// Compile condition.
	condText := strings.ToLower(strings.TrimSpace(strings.Join(condParts, " ")))
	switch {
	case strings.Contains(condText, "any of them"):
		rule.condKind = yaraAnyOfThem
	case strings.Contains(condText, "all of them"):
		rule.condKind = yaraAllOfThem
	default:
		rule.condKind = yaraBoolExpr
		rule.condExpr = condText
	}

	return rule, i, nil
}

// parseYARAStringDef parses a single YARA string definition line.
//
//	$s1 = "literal"
//	$s2 = "Case Insensitive" nocase
//	$re = /malware_\w+/i
//	$hex = { 4D 5A 90 00 }
func parseYARAStringDef(line string) (yaraStringDef, error) {
	eqIdx := strings.Index(line, "=")
	if eqIdx < 0 {
		return yaraStringDef{}, fmt.Errorf("no '=' in string definition: %s", line)
	}
	id := strings.TrimSpace(line[:eqIdx])
	rest := strings.TrimSpace(line[eqIdx+1:])

	if !strings.HasPrefix(id, "$") {
		return yaraStringDef{}, fmt.Errorf("string identifier must start with '$': %q", id)
	}

	sd := yaraStringDef{id: id}
	switch {
	case strings.HasPrefix(rest, "\""):
		val, mods, err := parseYARALiteralString(rest)
		if err != nil {
			return yaraStringDef{}, err
		}
		sd.literal = []byte(val)
		sd.noCase = strings.Contains(mods, "nocase")

	case strings.HasPrefix(rest, "/"):
		re, err := parseYARARegex(rest)
		if err != nil {
			return yaraStringDef{}, fmt.Errorf("regex compile error in %s: %w", id, err)
		}
		sd.re = re

	case strings.HasPrefix(rest, "{"):
		b, err := parseYARAHexPattern(rest)
		if err != nil {
			return yaraStringDef{}, fmt.Errorf("hex pattern error in %s: %w", id, err)
		}
		sd.literal = b

	default:
		return yaraStringDef{}, fmt.Errorf("unknown string type in: %s", rest)
	}
	return sd, nil
}

// parseYARALiteralString extracts the string value and modifier keywords.
// Input:  `"hello world" nocase`
// Output: ("hello world", "nocase", nil)
func parseYARALiteralString(s string) (string, string, error) {
	if !strings.HasPrefix(s, "\"") {
		return "", "", fmt.Errorf("expected opening quote")
	}
	// Scan for the closing unescaped double-quote.
	i := 1
	for i < len(s) {
		if s[i] == '\\' {
			i += 2
			continue
		}
		if s[i] == '"' {
			break
		}
		i++
	}
	if i >= len(s) {
		return "", "", fmt.Errorf("unterminated string literal")
	}
	raw := s[1:i]
	mods := strings.ToLower(strings.TrimSpace(s[i+1:]))

	// Unescape common escape sequences.
	raw = strings.ReplaceAll(raw, `\n`, "\n")
	raw = strings.ReplaceAll(raw, `\t`, "\t")
	raw = strings.ReplaceAll(raw, `\r`, "\r")
	raw = strings.ReplaceAll(raw, `\\`, "\\")
	raw = strings.ReplaceAll(raw, `\"`, "\"")
	return raw, mods, nil
}

// parseYARARegex compiles a YARA regex definition.
// Input:  `/pattern/i`
func parseYARARegex(s string) (*regexp.Regexp, error) {
	if !strings.HasPrefix(s, "/") {
		return nil, fmt.Errorf("expected opening '/'")
	}
	// Locate the closing slash after position 0.
	end := strings.LastIndex(s[1:], "/")
	if end < 0 {
		return nil, fmt.Errorf("unterminated regex")
	}
	end++ // adjust for the skipped leading character

	pattern := s[1:end]
	flagStr := s[end+1:]

	// Extract alphabetic flag characters (e.g. "i", "is", "nocase").
	var flagChars strings.Builder
	for _, ch := range flagStr {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			flagChars.WriteRune(ch)
		} else {
			break
		}
	}
	flags := strings.ToLower(flagChars.String())

	prefix := ""
	if strings.ContainsRune(flags, 'i') {
		prefix += "(?i)"
	}
	if strings.ContainsRune(flags, 's') {
		prefix += "(?s)"
	}
	return regexp.Compile(prefix + pattern)
}

// parseYARAHexPattern converts a YARA hex pattern { DE AD BE EF } to bytes.
// Hex wildcards (??) are not supported and return an error so the string is
// gracefully skipped rather than causing a compile error.
func parseYARAHexPattern(s string) ([]byte, error) {
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("invalid hex block: %s", s)
	}
	inner := s[start+1 : end]
	// Strip block comments /* … */ within hex definitions.
	inner = regexp.MustCompile(`/\*[^*]*\*/`).ReplaceAllString(inner, "")
	inner = strings.TrimSpace(inner)

	if strings.ContainsAny(inner, "?") {
		return nil, fmt.Errorf("wildcard hex patterns (??) not supported in this implementation")
	}

	tokens := strings.Fields(inner)
	var result []byte
	for _, t := range tokens {
		b, err := hex.DecodeString(t)
		if err != nil {
			return nil, fmt.Errorf("invalid hex token %q: %w", t, err)
		}
		result = append(result, b...)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("empty hex pattern")
	}
	return result, nil
}
