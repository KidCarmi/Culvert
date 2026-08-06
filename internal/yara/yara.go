package yara

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
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// ── Data types ────────────────────────────────────────────────────────────────

type yaraStringDef struct {
	id           string         // variable identifier, e.g. "$a"
	literal      []byte         // non-nil for literal / hex patterns
	literalLower []byte         // bytes.ToLower(literal), precomputed when noCase
	re           *regexp.Regexp // non-nil for regex patterns
	noCase       bool           // case-insensitive match for literal strings
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

// ── RuleSet ───────────────────────────────────────────────────────────────

// RuleSet holds compiled YARA rules loaded from a directory.
// All methods are safe for concurrent use.
type RuleSet struct {
	mu       sync.RWMutex
	rules    []yaraCompiledRule
	dir      string
	warnings []string // parse/load warnings from the most recent LoadDir call
}

// NewRuleSet returns an empty RuleSet.
func NewRuleSet() *RuleSet { return &RuleSet{} }

// LoadSource compiles rules from a literal source string and installs them,
// replacing the current rule set; it returns any parser warnings. It is the
// directory-free counterpart to LoadDir, used for programmatic/test rule
// loading (the package-main test suite builds rule sets this way).
func (y *RuleSet) LoadSource(src string) ([]string, error) {
	rules, warnings, err := parseYARASrcWithWarnings(src)
	if err != nil {
		return warnings, err
	}
	y.mu.Lock()
	y.rules = rules
	y.warnings = warnings
	y.mu.Unlock()
	return warnings, nil
}

// Inflight returns the current count of in-flight regex-match goroutines
// (observability; surfaced in the security-scan stats map).
func Inflight() int64 { return yaraInflight.Load() }

// LoadDir loads all *.yar and *.yara files from dir, replacing current rules
// atomically. Errors in individual rule files are logged and captured in
// y.warnings so admins can see which files failed to parse; the remaining
// rules are still loaded.
func (y *RuleSet) LoadDir(dir string) error {
	var files []string
	for _, pat := range []string{"*.yar", "*.yara"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		files = append(files, m...)
	}

	var loaded []yaraCompiledRule
	var warnings []string
	for _, f := range files {
		rules, err := loadYARAFile(f)
		if err != nil {
			msg := fmt.Sprintf("%s: %v", filepath.Base(f), err)
			obs.Printf("YARA: skipping %s", msg)
			warnings = append(warnings, msg)
			continue
		}
		loaded = append(loaded, rules...)
	}

	y.mu.Lock()
	y.dir = dir
	y.rules = loaded
	y.warnings = warnings
	y.mu.Unlock()

	// Reset in-flight counter so stale timeouts from previous rules don't
	// suppress matching after a reload (P8).
	yaraInflight.Store(0)

	obs.Printf("YARA: %d rule(s) loaded from %d file(s) in %s (%d warnings)",
		len(loaded), len(files), dir, len(warnings))
	return nil
}

// Names returns the names of all currently loaded rules.
// Tier 2.1: exposes the rule set so admins can verify which rules are active.
func (y *RuleSet) Names() []string {
	y.mu.RLock()
	defer y.mu.RUnlock()
	out := make([]string, len(y.rules))
	for i := range y.rules {
		out[i] = y.rules[i].name
	}
	return out
}

// Files returns the basenames (without extension) of every *.yar / *.yara file
// in the configured rules directory. Tier 3.2: the GUI rule editor lists
// *files*, not the rule names inside them — otherwise ReadRule fails whenever
// a single file bundles multiple rules (the common case for starter kits). The
// returned list is sorted and de-duplicated across the two extensions.
func (y *RuleSet) Files() []string {
	y.mu.RLock()
	dir := y.dir
	y.mu.RUnlock()
	if dir == "" {
		return nil
	}
	seen := map[string]bool{}
	for _, pat := range []string{"*.yar", "*.yara"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		for _, f := range m {
			base := filepath.Base(f)
			stem := strings.TrimSuffix(base, filepath.Ext(base))
			if stem != "" {
				seen[stem] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	// tiny insertion sort — directory listings are short
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// FileRules returns a map from file stem to the list of rule names defined in
// that file. Tier 3.2: lets the GUI show "sample_rules.yar → [EICAR_Test_File,
// WebShell_…]" without a second round trip. File stems with no parsable rules
// (parse failures, empty files) map to an empty slice.
func (y *RuleSet) FileRules() map[string][]string {
	y.mu.RLock()
	dir := y.dir
	y.mu.RUnlock()
	if dir == "" {
		return nil
	}
	out := map[string][]string{}
	for _, pat := range []string{"*.yar", "*.yara"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		for _, f := range m {
			base := filepath.Base(f)
			stem := strings.TrimSuffix(base, filepath.Ext(base))
			if stem == "" {
				continue
			}
			rules, err := loadYARAFile(f)
			if err != nil {
				if _, ok := out[stem]; !ok {
					out[stem] = []string{}
				}
				continue
			}
			names := make([]string, len(rules))
			for i := range rules {
				names[i] = rules[i].name
			}
			out[stem] = names
		}
	}
	return out
}

// Warnings returns a copy of any parse/load warnings from the most recent
// LoadDir call. Empty when all rule files loaded cleanly.
// Tier 2.1: lets admins surface silently-skipped rules in the UI.
func (y *RuleSet) Warnings() []string {
	y.mu.RLock()
	defer y.mu.RUnlock()
	if len(y.warnings) == 0 {
		return nil
	}
	out := make([]string, len(y.warnings))
	copy(out, y.warnings)
	return out
}

// Dir returns the directory the rule set was loaded from.
func (y *RuleSet) Dir() string {
	y.mu.RLock()
	defer y.mu.RUnlock()
	return y.dir
}

// Enabled reports whether any rules are currently loaded.
func (y *RuleSet) Enabled() bool {
	y.mu.RLock()
	defer y.mu.RUnlock()
	return len(y.rules) > 0
}

// Count returns the number of loaded rules.
func (y *RuleSet) Count() int {
	y.mu.RLock()
	defer y.mu.RUnlock()
	return len(y.rules)
}

// yaraFileNameRe constrains admin-supplied rule file names. Tier 3.2.
// Rejects path traversal, slashes, dots, and anything other than
// [A-Za-z0-9_-]. The ".yar" suffix is always appended by the caller.
var yaraFileNameRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_-]{0,63}$`)

// sanitizeYARAName validates a rule filename (without extension) supplied
// over the admin API and returns an error for any invalid / unsafe input.
// Tier 3.2: defense against path traversal during WriteRule / DeleteRule.
func sanitizeYARAName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("rule name is empty")
	}
	if strings.HasSuffix(name, ".yar") {
		name = strings.TrimSuffix(name, ".yar")
	} else if strings.HasSuffix(name, ".yara") {
		name = strings.TrimSuffix(name, ".yara")
	}
	if !yaraFileNameRe.MatchString(name) {
		return "", fmt.Errorf("rule name must match [A-Za-z0-9_-]{1,64}")
	}
	return name, nil
}

// resolveRulePath builds a cleaned, absolute path for the given rule name and
// verifies the result is still inside the configured rules directory. It is
// the single choke-point for every file operation on YARA rule files so the
// taint analyser (gosec G703) and any future auditor can see a defence-in-
// depth path traversal guard, even though sanitizeYARAName already rejects
// anything outside [A-Za-z0-9_-]{1,64}. Tier 3.2.
//
// New files are always created with the .yar extension. If an existing
// .yara file matches the name, that path is returned instead so Read/Delete
// find the existing file.
func (y *RuleSet) resolveRulePath(name string) (path, dir string, err error) {
	clean, err := sanitizeYARAName(name)
	if err != nil {
		return "", "", err
	}
	y.mu.RLock()
	rawDir := y.dir
	y.mu.RUnlock()
	if rawDir == "" {
		return "", "", fmt.Errorf("no YARA rules directory configured")
	}
	dir = filepath.Clean(rawDir)
	path = filepath.Clean(filepath.Join(dir, clean+".yar"))
	// Reject any path that does not live directly inside dir. This cannot
	// happen given sanitizeYARAName, but the explicit check makes the
	// sanitisation legible to static analysers and is cheap to run.
	if filepath.Dir(path) != dir {
		return "", "", fmt.Errorf("resolved path escapes rules directory")
	}
	// If the .yar variant does not exist but a .yara variant does, prefer
	// the existing file so Read/Delete operate on the real file on disk.
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		altPath := filepath.Clean(filepath.Join(dir, clean+".yara"))
		if filepath.Dir(altPath) != dir {
			return "", "", fmt.Errorf("resolved alt path escapes rules directory")
		}
		if _, altErr := os.Stat(altPath); altErr == nil {
			path = altPath
		}
	}
	return path, dir, nil
}

// ReadRule returns the raw source of the named rule file. Tier 3.2.
func (y *RuleSet) ReadRule(name string) (string, error) {
	path, _, err := y.resolveRulePath(name)
	if err != nil {
		return "", err
	}
	// #nosec G304,G703 -- name is regex-validated by sanitizeYARAName and
	// the resolved path is verified to live inside the admin-configured
	// rules directory by resolveRulePath.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// WriteRule validates and persists a YARA rule file, then reloads the rule
// set atomically. Tier 3.2. Uses tmp+rename for crash-safety. Returns the
// parser warnings (if any) so the admin can see what was skipped inside the
// rule file even on success.
func (y *RuleSet) WriteRule(name, src string) ([]string, error) {
	names, warnings, err := ValidateSource(src)
	if err != nil {
		return warnings, err
	}
	if len(names) == 0 {
		return warnings, fmt.Errorf("rule source parsed without errors but defines no rules")
	}
	path, dir, err := y.resolveRulePath(name)
	if err != nil {
		return warnings, err
	}
	// Ensure the directory exists (first-time write in /data/yara).
	// #nosec G703 -- dir is the cleaned, admin-configured rules directory
	// returned by resolveRulePath; no user-controlled component.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return warnings, fmt.Errorf("create rules dir: %w", err)
	}
	// #nosec G304,G703 -- path is validated by resolveRulePath; no
	// user-controlled component.
	if err := fileutil.AtomicWrite(path, []byte(src), 0o600); err != nil {
		return warnings, err
	}

	// Reload the whole directory so the new rule takes effect immediately.
	if err := y.LoadDir(dir); err != nil {
		return warnings, fmt.Errorf("reload: %w", err)
	}
	return warnings, nil
}

// DeleteRule removes the named rule file from disk and reloads. Tier 3.2.
func (y *RuleSet) DeleteRule(name string) error {
	path, dir, err := y.resolveRulePath(name)
	if err != nil {
		return err
	}
	// #nosec G304,G703 -- path validated by resolveRulePath.
	if err := os.Remove(path); err != nil {
		return err
	}
	return y.LoadDir(dir)
}

// SetDir updates the rules directory without loading. Used on first-time
// startup when /data/yara/ does not yet exist and the admin wants to create
// rules via the API. Tier 3.2.
func (y *RuleSet) SetDir(dir string) {
	y.mu.Lock()
	y.dir = dir
	y.mu.Unlock()
}

// scanCtx carries the per-scan body plus a lazily-computed ASCII/Unicode
// lowercased copy of it, so a nocase-heavy ruleset lowercases the body at most
// ONCE per Match instead of once per nocase string (perf). It is built once in
// Match and threaded by POINTER — passing it by value would drop the lowerSet
// memoization at every call boundary and re-lower the body per string.
type scanCtx struct {
	data     []byte
	lower    []byte
	lowerSet bool
}

// lowerData returns bytes.ToLower(data), computing it at most once. bytes.ToLower
// is Unicode-aware; it is used deliberately to stay byte-for-byte identical to
// the pre-refactor nocase match — do NOT swap it for an ASCII-only fold.
func (c *scanCtx) lowerData() []byte {
	if !c.lowerSet {
		c.lower = bytes.ToLower(c.data)
		c.lowerSet = true
	}
	return c.lower
}

// Match returns the names of every rule that matches data.
func (y *RuleSet) Match(data []byte) []string {
	y.mu.RLock()
	rules := y.rules
	y.mu.RUnlock()

	ctx := &scanCtx{data: data}
	var matched []string
	for i := range rules {
		if evalYARARule(&rules[i], ctx) {
			matched = append(matched, rules[i].name)
		}
	}
	return matched
}

// ── Rule evaluation ───────────────────────────────────────────────────────────

func evalYARARule(r *yaraCompiledRule, ctx *scanCtx) bool {
	switch r.condKind {
	case yaraAnyOfThem:
		// True iff ANY string matches — short-circuit, no per-rule map alloc.
		for i := range r.strings {
			if matchYARAString(&r.strings[i], ctx) {
				return true
			}
		}
		return false
	case yaraAllOfThem:
		// True iff EVERY string matches (and there is at least one).
		if len(r.strings) == 0 {
			return false
		}
		for i := range r.strings {
			if !matchYARAString(&r.strings[i], ctx) {
				return false
			}
		}
		return true
	default: // yaraBoolExpr — needs id→bool lookup, so build the hit map here only
		hit := make(map[string]bool, len(r.strings))
		for i := range r.strings {
			hit[r.strings[i].id] = matchYARAString(&r.strings[i], ctx)
		}
		return evalBoolCondition(r.condExpr, hit)
	}
}

// FailClosed / FailOpenWithAlert are the two posture strings for the
// on_timeout and on_saturation policies.
const (
	FailClosed        = "fail_closed"
	FailOpenWithAlert = "fail_open_with_alert"
)

// Runtime-configurable YARA engine parameters. Defaults match the original
// hardcoded constants; all access goes through the typed getters below.
// Set via Admin GUI under Security Scanning → YARA Engine Settings.
var (
	yaraEngineEnabledVar atomic.Bool  // admin on/off toggle; default true
	yaraMaxInflightVar   atomic.Int64 // default 50
	yaraTimeoutSecsVar   atomic.Int64 // default 5 seconds
	yaraOnTimeoutVar     atomic.Value // "fail_closed" | "fail_open_with_alert"
	yaraOnSaturationVar  atomic.Value // "fail_closed" | "fail_open_with_alert"
	yaraAlertDegradedVar atomic.Bool  // default true
)

func init() {
	yaraEngineEnabledVar.Store(true)
	yaraMaxInflightVar.Store(int64(50))
	yaraTimeoutSecsVar.Store(int64(5))
	yaraOnTimeoutVar.Store(FailClosed)
	yaraOnSaturationVar.Store(FailClosed)
	yaraAlertDegradedVar.Store(true)
}

// Getters — called from the scan hot-path; must not block.

// GetEnabled reports whether the YARA engine is enabled.
func GetEnabled() bool { return yaraEngineEnabledVar.Load() }

// GetMaxInflight returns the in-flight regex-goroutine cap.
func GetMaxInflight() int64 { return yaraMaxInflightVar.Load() }

// GetTimeoutSecs returns the per-regex match timeout in seconds.
func GetTimeoutSecs() int64 { return yaraTimeoutSecsVar.Load() }

// GetAlertDegraded reports whether degraded-mode alerts are enabled.
func GetAlertDegraded() bool { return yaraAlertDegradedVar.Load() }

// GetOnTimeout returns the on-timeout posture (FailClosed | FailOpenWithAlert).
func GetOnTimeout() string {
	if v, ok := yaraOnTimeoutVar.Load().(string); ok && v != "" {
		return v
	}
	return FailClosed
}

// GetOnSaturation returns the on-saturation posture (FailClosed | FailOpenWithAlert).
func GetOnSaturation() string {
	if v, ok := yaraOnSaturationVar.Load().(string); ok && v != "" {
		return v
	}
	return FailClosed
}

// Setters — called from the Admin API handler and LoadAdminSettings.

// SetEnabled toggles the YARA engine on/off.
func SetEnabled(v bool) { yaraEngineEnabledVar.Store(v) }

// SetMaxInflight sets the in-flight regex-goroutine cap.
func SetMaxInflight(n int64) { yaraMaxInflightVar.Store(n) }

// SetTimeoutSecs sets the per-regex match timeout in seconds.
func SetTimeoutSecs(n int64) { yaraTimeoutSecsVar.Store(n) }

// SetOnTimeout sets the on-timeout posture (FailClosed | FailOpenWithAlert).
func SetOnTimeout(v string) { yaraOnTimeoutVar.Store(v) }

// SetOnSaturation sets the on-saturation posture (FailClosed | FailOpenWithAlert).
func SetOnSaturation(v string) { yaraOnSaturationVar.Store(v) }

// SetAlertDegraded toggles degraded-mode alerting.
func SetAlertDegraded(v bool) { yaraAlertDegradedVar.Store(v) }

// yaraStringIDExists reports whether defs already contains a string with id.
// Used to skip duplicate ids at parse time so evaluation is deterministic.
func yaraStringIDExists(defs []yaraStringDef, id string) bool {
	for i := range defs {
		if defs[i].id == id {
			return true
		}
	}
	return false
}

func matchYARAString(s *yaraStringDef, ctx *scanCtx) bool {
	if s.re != nil {
		timeout := time.Duration(GetTimeoutSecs()) * time.Second
		return matchRegexWithTimeout(s.re, ctx.data, timeout)
	}
	if s.noCase {
		// Body lowercased at most once per scan (ctx.lowerData); literalLower
		// precomputed at parse time. Equivalent to the former
		// bytes.Contains(bytes.ToLower(data), bytes.ToLower(literal)).
		return bytes.Contains(ctx.lowerData(), s.literalLower)
	}
	return bytes.Contains(ctx.data, s.literal)
}

// yaraInflight tracks abandoned regex goroutines to prevent unbounded accumulation.
var yaraInflight atomic.Int64

// yaraMatchComponent labels contained per-match panics in the crash plane;
// yaraMatchPanics is the local counter (MatchPanics()).
const yaraMatchComponent = "yara-match"

var yaraMatchPanics atomic.Int64

// yaraMatchFn is the regex-match call itself, indirected so the CHAOS-25
// fault-injection test can make a match panic — a real *regexp.Regexp cannot be
// coerced into panicking, so without this seam the guard below would be
// unpinnable. Production never replaces it.
var yaraMatchFn = func(re *regexp.Regexp, data []byte) bool { return re.Match(data) }

// MatchPanics reports how many regex-match rounds were contained by the
// CHAOS-25 guard. Non-zero means some scan verdicts were decided by the
// on-timeout posture rather than by the rule itself, so it is a correctness
// signal, not only a liveness one.
func MatchPanics() int64 { return yaraMatchPanics.Load() }

// yaraSaturationCheck returns (saturated, result). When saturated is true, the
// caller must return result immediately without attempting the regex match.
// Posture is controlled by yaraOnSaturationVar: fail_closed returns true (block),
// fail_open_with_alert returns false (allow) and fires a degraded alert.
func yaraSaturationCheck(inflight int64) (saturated, result bool) {
	limit := GetMaxInflight()
	if inflight < limit {
		return false, false
	}
	obs.Warnf("YARA: regex skipped: too many in-flight goroutines (%d)", inflight)
	if GetAlertDegraded() {
		go alerts.Fire("yara_degraded", alerts.Payload{
			Source: "yara",
			Detail: fmt.Sprintf("regex skipped: inflight=%d max=%d — YARA engine saturated", inflight, limit),
		})
	}
	return true, GetOnSaturation() != FailOpenWithAlert
}

// yaraDegradedCheck fires a degraded alert when inflight is approaching the cap.
// Tier 1.3: visibility into approaching saturation before matches start dropping.
func yaraDegradedCheck(inflight int64) {
	if !GetAlertDegraded() {
		return
	}
	limit := GetMaxInflight()
	if inflight >= (limit*80)/100 {
		go alerts.Fire("yara_degraded", alerts.Payload{
			Source: "yara",
			Detail: fmt.Sprintf("inflight=%d/%d — approaching YARA saturation", inflight, limit),
		})
	}
}

// yaraTimeoutResult logs the timeout and returns the posture-controlled decision.
// Posture is controlled by yaraOnTimeoutVar: fail_closed returns true (block),
// fail_open_with_alert returns false (allow).
func yaraTimeoutResult(timeout time.Duration, pattern string) bool {
	obs.Warnf("YARA: regex timeout after %s on pattern %q (inflight: %d)",
		timeout, obs.Sanitize(pattern), yaraInflight.Load())
	return GetOnTimeout() != FailOpenWithAlert
}

// matchRegexWithTimeout runs re.Match(data) in a goroutine. Returns true
// (fail-closed / suspicious) when the match does not complete within timeout
// or when the inflight cap is reached, unless the admin has explicitly chosen
// fail_open_with_alert for that posture.
// Abandoned goroutines are tracked via yaraInflight to prevent unbounded leaks.
func matchRegexWithTimeout(re *regexp.Regexp, data []byte, timeout time.Duration) bool {
	inflight := yaraInflight.Load()
	if saturated, result := yaraSaturationCheck(inflight); saturated {
		return result
	}
	yaraDegradedCheck(inflight)
	ch := make(chan bool, 1)
	yaraInflight.Add(1)
	go func() {
		defer yaraInflight.Add(-1)
		// CHAOS-25: this goroutine runs attacker-supplied bytes through a
		// compiled regexp on the response-scanning path. A panic here would
		// terminate an in-line gateway, and unlike a worker loop there is no
		// "next round" to keep alive — so the guard is on the whole (one-shot)
		// body. A contained panic yields NO scan verdict, which is exactly the
		// epistemic state a timeout leaves, so it resolves through the SAME
		// admin-selectable posture (fail_closed ⇒ block, fail_open_with_alert
		// ⇒ allow) instead of defaulting to "clean". It answers immediately
		// rather than leaving the parent to wait out the full timeout: the
		// panic already proved the match will never complete.
		var matched bool
		if obs.SafeCall(yaraMatchComponent, func() { matched = yaraMatchFn(re, data) }) {
			yaraMatchPanics.Add(1)
			ch <- GetOnTimeout() != FailOpenWithAlert
			return
		}
		ch <- matched
	}()
	select {
	case matched := <-ch:
		return matched
	case <-time.After(timeout):
		return yaraTimeoutResult(timeout, re.String())
	}
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
	// #nosec G304,G703 -- path comes from filepath.Glob over the admin-
	// configured rules directory (see LoadDir) or from resolveRulePath which
	// validates containment; no user-controlled component reaches this call.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseYARASrc(string(data))
}

func parseYARASrc(src string) ([]yaraCompiledRule, error) {
	rules, warnings, err := parseYARASrcWithWarnings(src)
	for _, w := range warnings {
		obs.Printf("YARA: %s", w)
	}
	return rules, err
}

// parseYARASrcWithWarnings is the internal parser used by both parseYARASrc
// (which forwards warnings to the logger) and ValidateSource (which
// returns them to the caller so the admin UI can display them).
//
//nolint:unparam // error is always nil today but is part of the parser's forward-compatible contract (ValidateSource / parseYARASrc propagate it)
func parseYARASrcWithWarnings(src string) ([]yaraCompiledRule, []string, error) {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(src))
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}

	var rules []yaraCompiledRule
	var warnings []string
	i := 0
	for i < len(lines) {
		line := strings.TrimSpace(stripYARAComment(lines[i]))
		if strings.HasPrefix(line, "rule ") {
			rule, end, err := parseYARARule(lines, i)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("parse error near line %d: %v (skipping rule)", i+1, err))
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
	return rules, warnings, nil
}

// ValidateSource parses a YARA rule source string without loading it into
// the global rule set. Used by the admin UI's "validate" feature so operators
// can check a rule before persisting it. Tier 3.1.
//
// Returns the list of rule names successfully parsed and any parser warnings.
// Returns an error only when the source contains no valid rules at all; a
// non-empty warnings slice with a non-empty names slice indicates a source
// that loaded some rules but skipped others.
func ValidateSource(src string) (names []string, warnings []string, err error) {
	rules, warnings, perr := parseYARASrcWithWarnings(src)
	if perr != nil {
		return nil, warnings, perr
	}
	names = make([]string, len(rules))
	for i := range rules {
		names[i] = rules[i].name
	}
	if len(rules) == 0 {
		if len(warnings) > 0 {
			return nil, warnings, fmt.Errorf("no valid rules parsed (%d warning(s))", len(warnings))
		}
		return nil, warnings, fmt.Errorf("no rules defined in source")
	}
	return names, warnings, nil
}

// stripYARAComment removes a trailing // comment from a line.
func stripYARAComment(s string) string {
	if idx := strings.Index(s, "//"); idx >= 0 {
		return s[:idx]
	}
	return s
}

//nolint:cyclop,funlen // pre-existing single-pass YARA rule parser moved verbatim during the internal/yara split (ADR-0002); decomposition is a separate, out-of-scope change
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
					if yaraStringIDExists(rule.strings, sd.id) {
						// Real YARA rejects duplicate string identifiers; this
						// lenient parser skips the dup (first wins) so evaluation
						// is deterministic and identical across all condition
						// kinds. CWE-117: sanitize admin-supplied name/id inline.
						safeName := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(name, "\n", "_"), "\r", "_"), "\t", "_")
						safeID := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(sd.id, "\n", "_"), "\r", "_"), "\t", "_")
						obs.Printf("YARA: rule %q: duplicate string id %q ignored", safeName, safeID)
					} else {
						rule.strings = append(rule.strings, sd)
					}
				} else {
					// CWE-117: rule name and error text may contain admin-
					// supplied content via WriteRule; strip CR/LF/TAB and
					// quote with %q so CodeQL sees the sanitiser inline.
					safeName := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(name, "\n", "_"), "\r", "_"), "\t", "_")
					safeErr := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(err.Error(), "\n", "_"), "\r", "_"), "\t", "_")
					obs.Printf("YARA: rule %q: string parse error: %q", safeName, safeErr)
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
		if sd.noCase {
			sd.literalLower = bytes.ToLower(sd.literal)
		}

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
//
//nolint:gocritic // results are (value, mods, error) as documented above
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
