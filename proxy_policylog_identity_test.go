package main

// Byte-identity proofs for the directly-built policy-decision lines
// (proxy_policylog.go).
//
// These lines are consumed by SIEM forwarders and log parsers, so replacing
// fmt with a hand-rolled builder is acceptable ONLY if the emitted bytes are
// unchanged. Nothing here argues that from the shape of the code; every test
// renders the production emitter and a FROZEN fmt-based copy of the exact
// pre-change body and compares the two, the convention
// TestIPFilterView_DifferentialAgainstLegacy already follows.
//
// The frozen copies below are the baseline and are never the thing under test.
// They must not be "kept in sync" with proxy.go — that would defeat the whole
// point. If a future change alters what a decision line says, these fail, and
// the right response is to update the frozen copy DELIBERATELY, in the same
// commit that changes the contract.

import (
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

// ── Frozen pre-change emitters (fmt-based) ──────────────────────────────────

func plFmtAllow(rule string, priority int, clientIP, method, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf("POLICY_ALLOW rule=%q pri=%d %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}",
		safeRule, priority, clientIP, method, sanitizeLog(host), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plFmtDrop(rule string, priority int, clientIP, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf("POLICY_DROP rule=%q pri=%d %s -> %q [%s] {req_id=%s identity=%s rule=%s action=drop}",
		safeRule, priority, clientIP, sanitizeLog(host), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plFmtBlock(rule string, priority int, clientIP, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf("POLICY_BLOCK rule=%q pri=%d %s -> %q [%s] {req_id=%s identity=%s rule=%s action=block}",
		safeRule, priority, clientIP, sanitizeLog(host), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plFmtRedirect(rule string, priority int, clientIP, host, redirectURL, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf("POLICY_REDIRECT rule=%q pri=%d %s -> %q => %q [%s] {req_id=%s identity=%s rule=%s action=redirect}",
		safeRule, priority, clientIP, sanitizeLog(host), sanitizeLog(redirectURL), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

// plLineInputs is one complete argument set for every emitter.
type plLineInputs struct {
	rule                                                    string
	priority                                                int
	clientIP, method, host, redirect, cond, reqID, identity string
}

// plRenderPair renders the same inputs through the production emitter and the
// frozen fmt copy, for all four decision branches.
func plRenderPair(in plLineInputs) (production, frozen [4]string) {
	prod := [4]func(){
		func() {
			logPolicyAllow(in.rule, in.priority, in.clientIP, in.method, in.host, in.cond, in.reqID, in.identity)
		},
		func() { logPolicyBlock(in.rule, in.priority, in.clientIP, in.host, in.cond, in.reqID, in.identity) },
		func() { logPolicyDrop(in.rule, in.priority, in.clientIP, in.host, in.cond, in.reqID, in.identity) },
		func() {
			logPolicyRedirect(in.rule, in.priority, in.clientIP, in.host, in.redirect, in.cond, in.reqID, in.identity)
		},
	}
	froz := [4]func(){
		func() {
			plFmtAllow(in.rule, in.priority, in.clientIP, in.method, in.host, in.cond, in.reqID, in.identity)
		},
		func() { plFmtBlock(in.rule, in.priority, in.clientIP, in.host, in.cond, in.reqID, in.identity) },
		func() { plFmtDrop(in.rule, in.priority, in.clientIP, in.host, in.cond, in.reqID, in.identity) },
		func() {
			plFmtRedirect(in.rule, in.priority, in.clientIP, in.host, in.redirect, in.cond, in.reqID, in.identity)
		},
	}
	for i := range prod {
		production[i] = plCapture(prod[i])
		frozen[i] = plCapture(froz[i])
	}
	return production, frozen
}

var plBranchNames = [4]string{"allow", "block", "drop", "redirect"}

// plDivergenceShapes are the inputs most likely to separate a hand-rolled
// builder from fmt: the escape triggers %q handles, the boundary bytes of the
// printable-ASCII fast path, invalid UTF-8, and the control characters
// sanitizeLog is supposed to have removed before the quoting ever runs.
var plDivergenceShapes = []string{
	"",
	"corp-saas-allow",
	"files.example.com",
	`has"one`,
	`has\one`,
	`both"and\`,
	`"`,
	`\`,
	`\\`,
	`""`,
	"\x1f", // just below the fast path's low bound
	"\x20", // the low bound itself (space)
	"\x7e", // the high bound itself (~)
	"\x7f", // DEL, just above
	"\x80", // first non-ASCII byte: invalid UTF-8 on its own
	"\xff",
	"\xed\xa0\x80",     // UTF-16 surrogate half, invalid UTF-8
	"\xf4\x90\x80\x80", // beyond MaxRune, invalid UTF-8
	"ünïcode-rule-名前",
	"emoji-🔥-rule",
	"mixed \"quote\" and ünïcode",
	"tab\there",
	"nl\nhere",
	"cr\rhere",
	"nul\x00here",
	"esc\x1bhere",
	strings.Repeat("a", 300), // overruns the size hint
	strings.Repeat(`"`, 120), // every byte escapes: worst case for the hint
	strings.Repeat("\xff", 90),
}

// TestPolicyDecisionLine_AllBranchesMatchFmt is the spine of this change: for
// every branch and every adversarial input, the built line must equal the line
// fmt produced.
func TestPolicyDecisionLine_AllBranchesMatchFmt(t *testing.T) {
	priorities := []int{0, 1, 9, 10, 100, 999, -1, -999, 2147483647, -2147483648}
	for _, shape := range plDivergenceShapes {
		for _, pri := range priorities {
			in := plLineInputs{
				rule: shape, priority: pri, clientIP: plClientIP, method: plMethod,
				host: shape, redirect: shape, cond: shape, reqID: plReqID, identity: shape,
			}
			production, frozen := plRenderPair(in)
			for i := range production {
				if production[i] != frozen[i] {
					t.Fatalf("%s branch diverged for input %q pri=%d:\n  fmt: %q\nbuilt: %q",
						plBranchNames[i], shape, pri, frozen[i], production[i])
				}
			}
		}
	}
}

// TestPolicyDecisionLine_RandomizedDifferential covers the combinations the
// hand-picked list cannot reach: every field carrying a DIFFERENT adversarial
// value at once, so a builder that wrote the right bytes into the wrong slot
// is caught as well as one that escaped a byte wrongly.
func TestPolicyDecisionLine_RandomizedDifferential(t *testing.T) {
	// #nosec G404 -- deterministic seeded generator for reproducible test data
	rng := rand.New(rand.NewSource(20260919))
	pick := func() string { return plDivergenceShapes[rng.Intn(len(plDivergenceShapes))] }
	randomBytes := func() string {
		b := make([]byte, rng.Intn(24))
		for i := range b {
			b[i] = byte(rng.Intn(256))
		}
		return string(b)
	}
	for i := 0; i < 2000; i++ {
		field := func() string {
			if rng.Intn(2) == 0 {
				return pick()
			}
			return randomBytes()
		}
		in := plLineInputs{
			rule: field(), priority: rng.Intn(1<<31) - (1 << 30), clientIP: field(),
			method: field(), host: field(), redirect: field(), cond: field(),
			reqID: field(), identity: field(),
		}
		production, frozen := plRenderPair(in)
		for j := range production {
			if production[j] != frozen[j] {
				t.Fatalf("%s branch diverged on randomized case %d (%#v):\n  fmt: %q\nbuilt: %q",
					plBranchNames[j], i, in, frozen[j], production[j])
			}
		}
	}
}

// FuzzPolicyDecisionLine drives the same differential from the fuzzer, which
// reaches byte sequences neither list above enumerates.
func FuzzPolicyDecisionLine(f *testing.F) {
	for _, s := range plDivergenceShapes {
		f.Add(s, 100, s, s)
	}
	f.Fuzz(func(t *testing.T, rule string, priority int, host string, identity string) {
		in := plLineInputs{
			rule: rule, priority: priority, clientIP: plClientIP, method: plMethod,
			host: host, redirect: host, cond: identity, reqID: plReqID, identity: identity,
		}
		production, frozen := plRenderPair(in)
		for j := range production {
			if production[j] != frozen[j] {
				t.Fatalf("%s branch diverged:\n  fmt: %q\nbuilt: %q", plBranchNames[j], frozen[j], production[j])
			}
		}
	})
}

// ── The quoting fast path ───────────────────────────────────────────────────

func plQuoted(s string) string {
	var b strings.Builder
	writeQuoted(&b, s)
	return b.String()
}

// TestPolicyDecisionLine_QuotingMatchesFmt walks EVERY byte value through
// writeQuoted, in isolation and in company, and requires it to agree with the
// %q verb it replaces. The fast path's whole risk is a byte it wrongly claims
// needs no escaping, and a per-byte sweep is the only way to rule that out
// exhaustively rather than probabilistically.
func TestPolicyDecisionLine_QuotingMatchesFmt(t *testing.T) {
	for i := 0; i < 256; i++ {
		c := string([]byte{byte(i)})
		for _, s := range []string{c, "a" + c, c + "a", "pre" + c + "post", c + c} {
			if got, want := plQuoted(s), fmt.Sprintf("%q", s); got != want {
				t.Errorf("writeQuoted(%q) = %s, fmt %%q = %s (byte 0x%02x)", s, got, want, i)
			}
		}
	}
}

// TestPolicyDecisionLine_QuotableAsIsIsSound pins the predicate the fast path
// rests on, stated as the property it must have rather than as its
// implementation: whenever it says yes, the quoted form really is the input
// wrapped in quotes.
func TestPolicyDecisionLine_QuotableAsIsIsSound(t *testing.T) {
	check := func(s string) {
		if !quotableAsIs(s) {
			return
		}
		if want := strconv.Quote(s); want != `"`+s+`"` {
			t.Errorf("quotableAsIs(%q) said yes but strconv.Quote gives %s", s, want)
		}
	}
	for i := 0; i < 256; i++ {
		check(string([]byte{byte(i)}))
	}
	for _, s := range plDivergenceShapes {
		check(s)
	}
	// #nosec G404 -- deterministic seeded generator for reproducible test data
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 20000; i++ {
		b := make([]byte, rng.Intn(16))
		for j := range b {
			b[j] = byte(rng.Intn(256))
		}
		check(string(b))
	}
}

// TestPolicyDecisionLine_QuotingFastPathIsReachable is the CONTROL for the two
// tests above. Both would pass if quotableAsIs simply always answered no — the
// fast path would be dead code and the optimisation silently gone — so pin
// that the ordinary values a decision line carries DO take it, and that the
// values it must not take it for do not.
func TestPolicyDecisionLine_QuotingFastPathIsReachable(t *testing.T) {
	for _, s := range []string{plRule, plHost, plIdentity, plCond, "", "a.b-c_d/e:1234"} {
		if !quotableAsIs(s) {
			t.Errorf("quotableAsIs(%q) = false, want true — the fast path is not reachable for ordinary input", s)
		}
	}
	for _, s := range []string{`q"uote`, `back\slash`, "hi\x00", "ünïcode", "\x7f", "\x80"} {
		if quotableAsIs(s) {
			t.Errorf("quotableAsIs(%q) = true, want false — the fast path would emit wrong bytes", s)
		}
	}
}

func FuzzPolicyDecisionLineQuoting(f *testing.F) {
	for _, s := range plDivergenceShapes {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := plQuoted(s), fmt.Sprintf("%q", s); got != want {
			t.Fatalf("writeQuoted(%q) = %s, fmt %%q = %s", s, got, want)
		}
	})
}

// ── Emission contract ───────────────────────────────────────────────────────

// TestPolicyDecisionLine_LoggerCarriesNoCallerPositionFlag pins the assumption
// emitPolicyLine rests on.
//
// logger.Output takes a calldepth, but Output consults it ONLY for Lshortfile
// and Llongfile. setupLogger builds the logger with log.LstdFlags (or 0 in JSON
// mode), so the value is inert and these four lines cannot be mislabelled.
// Adding a caller-position flag would silently start attributing every decision
// line to whichever frame the depth happens to land on, so it must fail here
// and be resolved deliberately.
func TestPolicyDecisionLine_LoggerCarriesNoCallerPositionFlag(t *testing.T) {
	for _, format := range []string{"", "text", "json"} {
		lg, closer, err := setupLogger("", 0, format)
		if err != nil {
			t.Fatalf("setupLogger(format=%q): %v", format, err)
		}
		flags := lg.Flags()
		if closer != nil {
			_ = closer.Close()
		}
		if flags&(log.Lshortfile|log.Llongfile) != 0 {
			t.Errorf("the production logger (format=%q) carries a caller-position flag (%d): "+
				"emitPolicyLine's calldepth is no longer inert, so the four policy decision lines "+
				"would be attributed to the wrong source position. Either pass a deliberate depth "+
				"or drop the flag.", format, flags)
		}
	}
}
