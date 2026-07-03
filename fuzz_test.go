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
//
// In CI the targets run for a short duration (5 s each) as a regression
// check; the corpus/ directories capture any panics found during local runs.

import (
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
