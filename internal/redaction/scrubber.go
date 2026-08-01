package redaction

import (
	"regexp"
	"strings"
	"unicode"
)

// Scrubber is the free-form secret backstop (REDACTION-MODEL: "Regexes are a
// later backstop"). Structural DataClass redaction masks/drops whole classified
// FIELDS; the scrubber is the second layer that catches a secret EMBEDDED inside
// a field that is legitimately KEPT — e.g. an INTERNAL diagnostic message
// "dial tcp: bad auth Bearer ghp_…", an audit Detail, a config value, a log URI.
//
// Design (adversarially reviewed twice, M2 PR1): precision over recall. Every
// pattern is a fixed, self-identifying credential SHAPE; there is deliberately NO
// bare length/entropy rule, so git SHAs, SHA-256 hashes, base64 cert fingerprints,
// ULIDs, UUIDs, and X-Request-IDs pass through verbatim and bundles stay useful.
// Bare context-free secrets are left to the structural SECRET class (dropped).
//
// The engine is bounded and deterministic (bundle hashing depends on it): Go
// regexp is RE2 (linear, no catastrophic backtracking); the clean path is at most
// two scans (format-rune check + one detector match) with no output allocation; a
// leaf over maxScanBytes or with more than maxReplacements matches is replaced
// WHOLE (fail-closed). The replacement token contains no trigger substring, so
// Scrub is idempotent: Scrub(Scrub(s))==Scrub(s).
type Scrubber struct {
	detect     *regexp.Regexp // fast "does anything match" guard (no output build)
	tokenRE    *regexp.Regexp // whole-match, self-identifying shapes (named groups)
	tokenNames []string       // tokenRE.SubexpNames(), cached
	valueRules []valueRule    // keyword-gated value-capture rules (keep key, redact value)
}

// valueRule redacts only capture group `group` of each match, keeping the rest
// (so "password=…" keeps the key name and "scheme://u:p@host" keeps scheme+host).
// An optional skip predicate suppresses redaction of a captured value that is
// provably not a secret (RE2 has no lookahead, so this guard lives in Go).
type valueRule struct {
	name  string
	re    *regexp.Regexp
	group int
	skip  func(captured string) bool
}

const (
	maxScanBytes    = 16 << 10 // a leaf larger than this is replaced whole (a secret could hide past the cap)
	maxReplacements = 256      // a leaf with more matches than this is maximal doubt → replaced whole
)

// isFormatRune reports whether r is a zero-width / format codepoint an evader can
// splice into a secret to defeat the shape patterns. We match the whole Unicode
// Cf (format) category — ZWSP/ZWNJ/ZWJ/BOM/soft-hyphen/word-joiner/invisible
// separators/LRM-RLM — plus the variation selectors, and strip them before
// matching. Cc/Zs (tab, newline, space) are NOT format runes, so ordinary
// whitespace in a bundle is untouched.
func isFormatRune(r rune) bool {
	return unicode.Is(unicode.Cf, r) || (r >= 0xFE00 && r <= 0xFE0F)
}

// trivialValue matches non-secret literals so a credential-shaped assignment of a
// boolean/toggle (use_api_key=true, is_secret=false) is not destroyed. No real
// credential equals one of these, so skipping them is leak-safe.
var trivialValue = regexp.MustCompile(`(?i)^(?:true|false|yes|no|on|off|0|1|none|null|nil|default|enabled|disabled)$`)

// tokenPatterns are whole-match, self-identifying credential shapes. Each becomes
// a named alternative; a match is replaced by "[redacted:<name>]".
var tokenPatterns = []struct{ name, re string }{
	{"github_token", `gh[oprsu]_[0-9A-Za-z]{36,}`},
	{"github_pat", `github_pat_[0-9A-Za-z_]{22,}`},
	{"gitlab_pat", `glpat-[0-9A-Za-z_-]{20,}`},
	{"gcp_api_key", `AIza[0-9A-Za-z_-]{35}`},
	{"slack_token", `xox[baprs]-[0-9A-Za-z-]{10,}`},
	{"slack_app_token", `xapp-[0-9]-[0-9A-Za-z-]{8,}`},
	{"slack_webhook", `hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]{24}`},
	{"sendgrid_key", `SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}`},
	// Body floor raised to 40 so real OpenAI keys (48-char bodies) match but
	// hyphen-free internal names (sk-prod_us_east_replica_0001) do not.
	{"openai_key", `sk-(?:proj-|svcacct-)?[0-9A-Za-z_]{40,}`},
	{"stripe_key", `(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}`},
	{"stripe_webhook_secret", `whsec_[0-9A-Za-z]{24,}`},
	{"npm_token", `npm_[0-9A-Za-z]{36}`},
	{"databricks_pat", `dapi[0-9a-f]{32}`},
	{"vault_token", `hvs\.[0-9A-Za-z_-]{24,}`},
	{"twilio_key", `SK[0-9a-f]{32}`},
	{"aws_access_key_id", `(?:AKIA|ASIA)[0-9A-Z]{16}`},
	{"pem_private_key", `(?s:-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----)`},
	{"jwt", `eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{6,}\.[0-9A-Za-z_-]*`},
}

// valuePatterns are keyword-gated rules that redact only the secret VALUE and
// keep the surrounding context. The value charclasses exclude '[' so an
// already-inserted "[redacted:…]" token is never re-matched (idempotence).
var valuePatterns = []struct {
	name  string
	re    string
	group int
}{
	// scheme://user:pass@host — redact the user:pass userinfo, keep scheme+host.
	// Password sub-class anchors on the terminating '@' (lazy) so a '/' or other
	// reserved byte in the password no longer breaks the match and leaks the tail.
	{"basic_auth_url", `([a-zA-Z][a-zA-Z0-9+.-]*://)([^\s@\[/]+:[^@\s\[]+?)@`, 2},
	// aws_secret[...]=<40 base64> — keyword-gated; redact the 40-char secret only.
	{"aws_secret", `(?i)(aws_?secret[a-z_]*\s*['"=: ]+\s*)([A-Za-z0-9/+]{40})`, 2},
	// "bearer <token>" — space-separated (not =/:), so it needs its own rule. A
	// digit-bearing guard (skip predicate) keeps prose ("bearer authentication
	// required") intact; JWTs are caught by the jwt tokenPattern separately.
	{"bearer_token", `(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{8,})`, 1},
	// <credential-word>[=:]VALUE — allowlisted key, redact the value only. Optional
	// quotes on BOTH sides of the separator catch JSON/.env/YAML quoted forms
	// (password="…", {"api_key":"…"}). Bare 'pwd' is intentionally dropped (it
	// collided with PWD/OLDPWD env vars); passwd/password still match.
	{"credential_assignment", `(?i)(password|passwd|secret|client_secret|api[_-]?key|access[_-]?token|auth[_-]?token|account_?key|shared_?access_?key)["']?(\s*[=:]\s*)["']?([^\s;,'"\[]+)`, 3},
}

// defaultScrubber is the process-wide compiled scrubber (patterns are constant).
var defaultScrubber = compileScrubber()

func compileScrubber() *Scrubber {
	var tokenAlts, allBodies []string
	for _, p := range tokenPatterns {
		tokenAlts = append(tokenAlts, `(?P<`+p.name+`>`+p.re+`)`)
		allBodies = append(allBodies, `(?:`+p.re+`)`)
	}
	sc := &Scrubber{tokenRE: regexp.MustCompile(strings.Join(tokenAlts, "|"))}
	sc.tokenNames = sc.tokenRE.SubexpNames()
	for _, v := range valuePatterns {
		vr := valueRule{name: v.name, re: regexp.MustCompile(v.re), group: v.group}
		switch v.name {
		case "bearer_token":
			// Real bearer tokens carry a digit; a bare dictionary word does not.
			vr.skip = func(s string) bool { return !strings.ContainsFunc(s, unicode.IsDigit) }
		case "credential_assignment":
			vr.skip = trivialValue.MatchString
		}
		sc.valueRules = append(sc.valueRules, vr)
		allBodies = append(allBodies, `(?:`+v.re+`)`)
	}
	sc.detect = regexp.MustCompile(strings.Join(allBodies, "|"))
	return sc
}

// Scrub returns s with every recognized secret shape replaced by an
// "[redacted:<kind>]" token, plus the number of redactions. The clean path (no
// format runes, no match) returns s unchanged with no output allocation.
func (sc *Scrubber) Scrub(s string) (out string, n int) {
	if s == "" {
		return "", 0
	}
	// Enforce the scan cap FIRST so it is truly fail-closed: an over-cap leaf is
	// replaced whole regardless of whether the (precision-first) patterns happen
	// to match, and the resource bound holds before any full scan of a huge leaf.
	if len(s) > maxScanBytes {
		return "[redacted:oversized]", 1
	}
	zw := strings.IndexFunc(s, isFormatRune) >= 0
	if !zw && !sc.detect.MatchString(s) {
		return s, 0 // clean path: format-rune check + one detector scan, no build
	}
	if zw {
		s = strings.Map(func(r rune) rune {
			if isFormatRune(r) {
				return -1
			}
			return r
		}, s)
		if len(s) > maxScanBytes { // re-check: stripping only shrinks, but be explicit
			return "[redacted:oversized]", 1
		}
	}
	count := 0
	s = sc.applyTokenPass(s, &count, nil)
	for i := range sc.valueRules {
		s = sc.valueRules[i].apply(s, &count, nil)
	}
	if count > maxReplacements {
		return "[redacted:overflow]", 1 // maximal doubt → replace whole
	}
	return s, count
}

// applyTokenPass replaces each whole-match secret shape with its named token in a
// single left-to-right pass. When names != nil, every replaced shape's detector
// name is appended (the classification companion for the MCP DLP layer); when
// nil the pass is byte-identical to the historical scrubber behavior.
func (sc *Scrubber) applyTokenPass(s string, count *int, names *[]string) string {
	locs := sc.tokenRE.FindAllStringSubmatchIndex(s, -1)
	if len(locs) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, idx := range locs {
		name := "secret"
		for gi := 1; gi*2+1 < len(idx); gi++ {
			if idx[2*gi] >= 0 && gi < len(sc.tokenNames) && sc.tokenNames[gi] != "" {
				name = sc.tokenNames[gi]
				break
			}
		}
		b.WriteString(s[last:idx[0]])
		b.WriteString("[redacted:" + name + "]")
		last = idx[1]
		*count++
		if names != nil {
			*names = append(*names, name)
		}
	}
	b.WriteString(s[last:])
	return b.String()
}

// apply redacts only the rule's secret capture group, keeping all other bytes. A
// match whose captured value fails the skip predicate is left untouched. When
// names != nil the rule name is appended for each redacted value.
func (v valueRule) apply(s string, count *int, names *[]string) string {
	locs := v.re.FindAllStringSubmatchIndex(s, -1)
	if len(locs) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, idx := range locs {
		gs, ge := idx[2*v.group], idx[2*v.group+1]
		if gs < 0 {
			continue
		}
		if v.skip != nil && v.skip(s[gs:ge]) {
			continue // not a secret (boolean toggle, prose word) — keep it verbatim
		}
		b.WriteString(s[last:gs])
		b.WriteString("[redacted:" + v.name + "]")
		last = ge
		*count++
		if names != nil {
			*names = append(*names, v.name)
		}
	}
	b.WriteString(s[last:])
	return b.String()
}
