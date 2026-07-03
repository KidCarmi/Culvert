package main

// fuzz_test.go — Go fuzz targets for security-critical input-parsing paths.
//
// Run locally:
//   go test -fuzz=FuzzIsPrivateHost      -fuzztime=30s
//   go test -fuzz=FuzzIsSafeRedirectURL  -fuzztime=30s
//   go test -fuzz=FuzzParseClamResponse  -fuzztime=30s
//   go test -fuzz=FuzzNormaliseFeedURL   -fuzztime=30s
//   go test -fuzz=FuzzMatchDest          -fuzztime=30s
//   go test -fuzz=FuzzParseYARALiteral   -fuzztime=30s
//   go test -fuzz=FuzzRemoveHopHeaders   -fuzztime=30s
//
// In CI these run nightly (Mon/Wed/Fri) with a 15m coverage-guided budget each
// (fuzz-nightly.yml); any crash input is uploaded so it can be committed as a
// permanent regression seed.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/threatfeed"
)

// FuzzIsPrivateHost ensures the private-host classifier never panics on
// arbitrary hostport strings (includes IPv6 brackets, no port, Unicode, etc.)
func FuzzIsPrivateHost(f *testing.F) {
	// Seed corpus: representative edge cases.
	seeds := []string{
		"localhost", "localhost:8080",
		"127.0.0.1", "127.0.0.1:80",
		"10.0.0.1:443", "172.16.0.1:3128",
		"192.168.1.1", "192.168.1.1:8080",
		"[::1]:80", "[::1]", "::1",
		"[fe80::1%eth0]:443",
		"example.com:443", "example.com",
		"", ":", ":0", "999.999.999.999:99999",
		"0.0.0.0", "255.255.255.255",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, hostport string) {
		// Must not panic; return value and error are intentionally ignored.
		_ = isPrivateHost(hostport)
	})
}

// FuzzIsSafeRedirectURL ensures the redirect-URL validator never panics on
// attacker-controlled input and never returns true for javascript:/data: URLs.
func FuzzIsSafeRedirectURL(f *testing.F) {
	seeds := []string{
		"https://example.com/path",
		"http://example.com",
		"javascript:alert(1)",
		"data:text/html,<script>",
		"ftp://example.com",
		"//example.com",
		"", "/", "/?foo=bar",
		"\x00", "http://\x00evil.com",
		"https://[::1]/path",
		"http://user:pass@host/",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		safe := isSafeRedirectURL(raw)
		// Safety invariant: javascript: and data: URIs must never be safe.
		if safe {
			for _, bad := range []string{"javascript:", "data:", "vbscript:"} {
				if len(raw) >= len(bad) && raw[:len(bad)] == bad {
					t.Errorf("isSafeRedirectURL(%q) = true for dangerous scheme", raw)
				}
			}
		}
	})
}

// FuzzParseClamResponse moved to internal/clamav (ADR-0002) — it fuzzes the
// unexported parseClamResponse, now in package clamav.

// FuzzNormaliseFeedURL ensures the feed-URL normaliser never panics on
// arbitrary URLs from untrusted operator input.
func FuzzNormaliseFeedURL(f *testing.F) {
	seeds := []string{
		"https://example.com/feed.txt",
		"http://example.com/list.gz",
		"example.com/feed",
		"ftp://feeds.example.org/block.txt",
		"",
		"//example.com/feed",
		"https://[::1]/feed",
		"\x00",
		"http://user:pass@host/feed?q=1#frag",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = threatfeed.NormaliseURL(raw)
	})
}

// FuzzMatchDest exercises the policy destination matcher against arbitrary
// hostname strings, ensuring it never panics on malformed input.
func FuzzMatchDest(f *testing.F) {
	rule := &PolicyRule{
		DestFQDN: "*.example.com",
	}
	seeds := []string{
		"example.com", "sub.example.com",
		"blocked.org", "safe.com",
		"", ".", "..", "*.com",
		"EXAMPLE.COM", "Sub.Example.Com",
		"xn--nxasmq6b.com", // punycode
		"10.0.0.1", "192.168.1.1",
		"very-long-subdomain-that-exceeds-normal-limits.example.com",
		"\x00evil.com",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, host string) {
		_ = matchDest(rule, host)
	})
}

// FuzzParseYARALiteral moved to internal/yara (ADR-0002) — it fuzzes the
// unexported parseYARALiteralString, now in package yara.

// FuzzRemoveHopHeaders fuzzes the custom RFC 7230 §6.1 Connection-token parser in
// removeHopHeaders (proxy.go): the header the proxy uses to strip attacker- or
// origin-supplied hop-by-hop headers before forwarding. It feeds an arbitrary
// Connection header value (a comma-separated token list) plus an arbitrary extra
// header, pre-populates a header entry for every listed token, and asserts the
// parser never panics, always removes the Connection header itself, and removes
// every non-empty token the Connection header names. It deliberately does NOT
// assert any header survives — a fuzzed Connection value may legitimately name
// (and thus strip) any header, including the extra one.
func FuzzRemoveHopHeaders(f *testing.F) {
	seeds := []struct {
		connVal, name, val string
	}{
		{"close", "X-Keep", "1"},
		{"keep-alive, Foo-Bar", "Foo-Bar", "leak"},
		{"X-Custom-Hop", "X-Custom-Hop", "secret"},
		{"", "X-Present", "v"},
		{" , , ", "X-Edge", "v"},
		{"Upgrade,Connection", "Upgrade", "websocket"},
		{"a,b,c,d,e", "b", "v"},
		{"X-Token\x00", "X-Token", "v"},
		{"UPPER,lower,MiXeD", "MiXeD", "v"},
		// Regression seeds: fuzzed extra-header name canonicalizes to "Connection"
		// and must NOT clobber the token list under assertion.
		{"X-Custom-Hop,close", "Connection", "close"},
		{"A,B", "connection", "override"},
		{"A", "CONNECTION", ""},
	}
	for _, s := range seeds {
		f.Add(s.connVal, s.name, s.val)
	}
	f.Fuzz(func(t *testing.T, connVal, name, val string) {
		h := http.Header{}
		// Set the arbitrary extra header FIRST, then Connection LAST: if the fuzzed
		// name canonicalizes to "Connection" it must not clobber the token list we
		// are about to assert on (that would make the test fail on a non-bug).
		h.Set(name, val)
		h.Set("Connection", connVal)
		// Pre-populate a header for every token the Connection value names, so a
		// successful removal is observable.
		tokens := strings.Split(connVal, ",")
		for _, tok := range tokens {
			if tok = strings.TrimSpace(tok); tok != "" {
				h.Add(tok, "populated")
			}
		}

		removeHopHeaders(h) // must not panic

		if len(h["Connection"]) != 0 {
			t.Errorf("Connection header not stripped: %#v", h["Connection"])
		}
		for _, tok := range tokens {
			if tok = strings.TrimSpace(tok); tok == "" {
				continue
			}
			if h.Get(tok) != "" {
				t.Errorf("Connection-listed hop-by-hop token %q not removed", tok)
			}
		}
	})
}
