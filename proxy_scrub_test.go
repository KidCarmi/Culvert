package main

import (
	"net"
	"net/http"
	"strings"
	"testing"
)

// scrubForwardedHeaders was rewritten for allocation cost (netip parsing, no
// intermediate []string, no Join, and a leave-untouched fast path when the
// header is already in sanitized form). It sits on the security boundary — it is
// what stops a client injecting identity claims and leaking internal topology
// upstream — so the rewrite is proven differentially against the previous
// implementation, reproduced verbatim below, rather than argued.

// legacyScrubForwardedHeaders is the verbatim pre-change implementation.
func legacyScrubForwardedHeaders(r *http.Request) {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		var public []string
		for _, raw := range strings.Split(xff, ",") {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip != nil && !isPrivateIP(ip) {
				public = append(public, ip.String())
			}
		}
		if len(public) == 0 {
			r.Header.Del("X-Forwarded-For")
		} else {
			r.Header.Set("X-Forwarded-For", strings.Join(public, ", "))
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := net.ParseIP(strings.TrimSpace(xri))
		if ip == nil || isPrivateIP(ip) {
			r.Header.Del("X-Real-IP")
		}
	}
	r.Header.Del("X-User-Identity")
}

// scrubCorpus covers the shapes a forwarded header actually takes plus the
// adversarial ones: private/public mixes, whitespace and separator variants,
// empty and malformed hops, IPv6 in every notation, IPv4-mapped forms, zoned
// addresses, and hostile tokens.
var scrubCorpus = []string{
	// Ordinary chains.
	"203.0.113.9",
	"203.0.113.9, 198.51.100.4",
	"203.0.113.9, 198.51.100.4, 192.0.2.33",
	"10.0.0.1",
	"10.0.0.1, 203.0.113.9",
	"203.0.113.9, 10.0.0.1",
	"10.0.0.1, 203.0.113.9, 192.168.1.1",
	"10.0.0.1, 192.168.1.1, 172.16.0.1",
	"127.0.0.1",
	"169.254.169.254, 203.0.113.9",
	// Separator and whitespace variants — canonicalization must be preserved.
	"203.0.113.9,198.51.100.4",
	"203.0.113.9 , 198.51.100.4",
	"  203.0.113.9  ,  198.51.100.4  ",
	"203.0.113.9,   198.51.100.4,192.0.2.33",
	"\t203.0.113.9\t",
	"203.0.113.9,",
	",203.0.113.9",
	"203.0.113.9,,198.51.100.4",
	",",
	",,",
	" ",
	// Malformed / hostile hops.
	"not-an-ip",
	"not-an-ip, 203.0.113.9",
	"203.0.113.9, not-an-ip",
	"203.0.113.999",
	"203.0.113.9:8080",
	"010.0.0.1",
	"0x7f000001",
	"2130706433",
	"203.0.113.9/24",
	"[203.0.113.9]",
	"unknown",
	"_hidden",
	"for=203.0.113.9",
	"203.0.113.9 203.0.113.10",
	// IPv6 notations.
	"2001:db8::1",
	"2001:DB8::1",
	"2001:0db8:0000:0000:0000:0000:0000:0001",
	"2001:db8::1, 203.0.113.9",
	"fe80::1",
	"fe80::1, 2001:db8::1",
	"::1",
	"::",
	"fc00::1",
	"ff02::1",
	"2606:4700:4700::1111, 2001:db8::1",
	// IPv4-mapped and IPv4-compatible IPv6 — the rendering must not change form.
	"::ffff:203.0.113.9",
	"::ffff:10.0.0.1",
	"::ffff:127.0.0.1",
	"::ffff:203.0.113.9, 198.51.100.4",
	"::203.0.113.9",
	// Zoned addresses: rejected by net.ParseIP, so they must stay dropped.
	"fe80::1%eth0",
	"2001:db8::1%eth0",
	"2001:db8::1%eth0, 203.0.113.9",
	// Long chain (past the stack scratch buffer).
	"203.0.113.1, 203.0.113.2, 203.0.113.3, 203.0.113.4, 203.0.113.5, 203.0.113.6, " +
		"203.0.113.7, 203.0.113.8, 203.0.113.9, 203.0.113.10, 203.0.113.11, 203.0.113.12",
	"2001:db8::1, 2001:db8::2, 2001:db8::3, 2001:db8::4, 2001:db8::5, 2001:db8::6, " +
		"2001:db8::7, 2001:db8::8, 2001:db8::9, 2001:db8::a",
}

// TestScrubForwardedHeaders_MatchesLegacyImplementation is the equivalence
// proof: for every corpus value, in both header positions, the rewritten scrub
// must leave the header set byte-identical to what the previous implementation
// produced.
func TestScrubForwardedHeaders_MatchesLegacyImplementation(t *testing.T) {
	for _, xff := range scrubCorpus {
		for _, xri := range []string{"", "203.0.113.9", "10.0.0.1", "not-an-ip", " 203.0.113.9 ", "::ffff:10.0.0.1", "fe80::1%eth0"} {
			build := func() *http.Request {
				r, err := http.NewRequest(http.MethodGet, "http://target.example.com/", nil)
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("X-Forwarded-For", xff)
				if xri != "" {
					r.Header.Set("X-Real-IP", xri)
				}
				r.Header.Set("X-User-Identity", "spoofed@evil.example")
				r.Header.Set("X-Unrelated", "keep-me")
				return r
			}
			want, got := build(), build()
			legacyScrubForwardedHeaders(want)
			scrubForwardedHeaders(got)

			for _, h := range []string{"X-Forwarded-For", "X-Real-IP", "X-User-Identity", "X-Unrelated"} {
				w, g := want.Header[h], got.Header[h]
				if len(w) != len(g) {
					t.Errorf("xff=%q xri=%q: %s value count = %d %q, legacy = %d %q", xff, xri, h, len(g), g, len(w), w)
					continue
				}
				for i := range w {
					if w[i] != g[i] {
						t.Errorf("xff=%q xri=%q: %s[%d] = %q, legacy = %q", xff, xri, h, i, g[i], w[i])
					}
				}
			}
		}
	}
}

// TestScrubForwardedHeaders_NeverLeaksPrivateHop is the invariant stated
// independently of the legacy implementation: whatever survives the scrub must
// contain no private/internal address. A differential test alone would happily
// reproduce a shared bug.
func TestScrubForwardedHeaders_NeverLeaksPrivateHop(t *testing.T) {
	for _, xff := range scrubCorpus {
		r, err := http.NewRequest(http.MethodGet, "http://target.example.com/", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("X-Forwarded-For", xff)
		scrubForwardedHeaders(r)
		out := r.Header.Get("X-Forwarded-For")
		if out == "" {
			continue
		}
		for _, tok := range strings.Split(out, ",") {
			tok = strings.TrimSpace(tok)
			ip := net.ParseIP(tok)
			if ip == nil {
				t.Errorf("xff=%q: surviving hop %q does not parse as an IP — an unvalidated token reached the forwarded header", xff, tok)
				continue
			}
			if isPrivateIP(ip) {
				t.Errorf("xff=%q: private hop %q survived the scrub", xff, tok)
			}
		}
	}
}

// TestScrubForwardedHeaders_AlwaysStripsIdentity pins the unconditional half:
// the internally-set identity header must never survive, whatever else the
// request carries.
func TestScrubForwardedHeaders_AlwaysStripsIdentity(t *testing.T) {
	for _, xff := range []string{"", "203.0.113.9", "10.0.0.1", "garbage"} {
		r, err := http.NewRequest(http.MethodGet, "http://target.example.com/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		r.Header["X-User-Identity"] = []string{"a@evil.example", "b@evil.example"}
		scrubForwardedHeaders(r)
		if v := r.Header["X-User-Identity"]; len(v) != 0 {
			t.Errorf("xff=%q: X-User-Identity survived: %q", xff, v)
		}
	}
}

// TestScrubForwardedHeaders_MultiLineForwardedForCollapses pins the reason the
// fast path reads the header slice instead of Get. A request carrying several
// X-Forwarded-For lines must be collapsed to the sanitized FIRST line — exactly
// what the previous unconditional Set did. Skipping the Set because line one
// happened to be canonical would forward the remaining lines untouched, which is
// precisely the private-hop leak the scrub exists to prevent.
func TestScrubForwardedHeaders_MultiLineForwardedForCollapses(t *testing.T) {
	cases := [][]string{
		{"203.0.113.9", "10.0.0.1"},                // line 1 already canonical
		{"203.0.113.9", "192.168.1.1, 172.16.0.1"}, // multiple private hops behind it
		{"203.0.113.9,198.51.100.4", "10.0.0.1"},   // line 1 needs canonicalizing
		{"10.0.0.1", "203.0.113.9"},                // line 1 fully private
		{"203.0.113.9", "203.0.113.10"},            // both public — still collapses
		{"203.0.113.9", "10.0.0.1", "192.168.1.1"}, // three lines
	}
	for _, lines := range cases {
		want, _ := http.NewRequest(http.MethodGet, "http://target.example.com/", nil)
		got, _ := http.NewRequest(http.MethodGet, "http://target.example.com/", nil)
		want.Header["X-Forwarded-For"] = append([]string(nil), lines...)
		got.Header["X-Forwarded-For"] = append([]string(nil), lines...)
		legacyScrubForwardedHeaders(want)
		scrubForwardedHeaders(got)
		w, g := want.Header["X-Forwarded-For"], got.Header["X-Forwarded-For"]
		if len(g) != len(w) {
			t.Fatalf("lines=%q: got %d values %q, legacy %d values %q", lines, len(g), g, len(w), w)
		}
		for i := range w {
			if w[i] != g[i] {
				t.Errorf("lines=%q: value[%d] = %q, legacy = %q", lines, i, g[i], w[i])
			}
		}
		// Independent of the legacy comparison: nothing private may remain.
		for _, v := range g {
			for _, tok := range strings.Split(v, ",") {
				if ip := net.ParseIP(strings.TrimSpace(tok)); ip != nil && isPrivateIP(ip) {
					t.Errorf("lines=%q: private hop %q survived a multi-line header", lines, tok)
				}
			}
		}
	}
}

// TestSanitizeForwardedFor_ChangedContract pins the fast-path signal itself:
// changed=false is only ever legal when the value is already byte-identical to
// the sanitized form, because the caller skips the header write on it.
func TestSanitizeForwardedFor_ChangedContract(t *testing.T) {
	for _, in := range scrubCorpus {
		out, changed := sanitizeForwardedFor(in)
		if !changed {
			if out != in {
				t.Errorf("sanitizeForwardedFor(%q) reported unchanged but returned %q", in, out)
			}
			// Re-running must be a no-op, i.e. the value really is a fixed point.
			if again, changedAgain := sanitizeForwardedFor(out); changedAgain || again != out {
				t.Errorf("sanitizeForwardedFor(%q) is not idempotent: second pass gave %q changed=%v", in, again, changedAgain)
			}
			continue
		}
		if out == in {
			t.Errorf("sanitizeForwardedFor(%q) reported changed but returned the input verbatim", in)
		}
		// The rewritten value must itself be a fixed point.
		if again, changedAgain := sanitizeForwardedFor(out); out != "" && (changedAgain || again != out) {
			t.Errorf("sanitizeForwardedFor(%q) → %q is not a fixed point: %q changed=%v", in, out, again, changedAgain)
		}
	}
}

// TestParsePublicAddr_RejectsZonedAddresses pins the deliberate narrowing of
// netip.ParseAddr's acceptance back to net.ParseIP's: a scoped address must be
// treated as unparseable so an attacker-supplied zone string can never be
// re-emitted into a header forwarded upstream.
func TestParsePublicAddr_RejectsZonedAddresses(t *testing.T) {
	for _, s := range []string{"fe80::1%eth0", "2001:db8::1%eth0", "::1%lo", "2001:db8::1%25eth0"} {
		if _, ok := parsePublicAddr(s); ok {
			t.Errorf("parsePublicAddr(%q) accepted a zoned address; net.ParseIP rejected it", s)
		}
		if ip := net.ParseIP(s); ip != nil {
			t.Errorf("premise broken: net.ParseIP(%q) now succeeds — revisit parsePublicAddr's narrowing", s)
		}
	}
}

// TestParsePublicAddr_AcceptanceMatchesParseIP is the broader half of the same
// contract, over every token shape in the corpus.
func TestParsePublicAddr_AcceptanceMatchesParseIP(t *testing.T) {
	for _, in := range scrubCorpus {
		for _, tok := range strings.Split(in, ",") {
			addr, ok := parsePublicAddr(tok)
			ip := net.ParseIP(strings.TrimSpace(tok))
			if ok != (ip != nil) {
				t.Errorf("parsePublicAddr(%q) ok=%v, net.ParseIP non-nil=%v", tok, ok, ip != nil)
				continue
			}
			if ok && addr.String() != ip.String() {
				t.Errorf("parsePublicAddr(%q).String() = %q, net.ParseIP(...).String() = %q — the rendered hop changed",
					tok, addr.String(), ip.String())
			}
		}
	}
}
