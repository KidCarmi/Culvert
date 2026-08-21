package pac

import (
	"fmt"
	"strings"
	"testing"
)

// ─── ValidateConfig: strict table ─────────────────────────────────────────────

func TestValidateConfig_Table(t *testing.T) {
	cases := []struct {
		name     string
		cfg      Config
		wantCode string // "" = valid
	}{
		{"valid full", Config{ProxyHost: "proxy.corp.com", ProxyPort: 3128,
			Exclusions: []string{"corp.local", "*.internal.corp", "10.0.0.0/8", "192.0.2.7"}}, ""},
		{"valid empty", Config{}, ""},
		{"valid ipv4 proxy host", Config{ProxyHost: "192.0.2.1", ProxyPort: 8080}, ""},
		{"ipv6 proxy host rejected (unportable)", Config{ProxyHost: "[2001:db8::1]", ProxyPort: 8080}, IssueInvalidProxyHost},
		{"valid idn exclusion", Config{Exclusions: []string{"münchen.example"}}, ""},

		{"port negative", Config{ProxyPort: -1}, IssueInvalidPort},
		{"port too high", Config{ProxyPort: 65536}, IssueInvalidPort},
		{"proxy host with scheme", Config{ProxyHost: "http://proxy"}, IssueInvalidProxyHost},
		{"proxy host with port", Config{ProxyHost: "proxy:8080"}, IssueInvalidProxyHost},
		{"proxy host with space", Config{ProxyHost: "pro xy"}, IssueInvalidProxyHost},
		{"empty exclusion", Config{Exclusions: []string{""}}, IssueEmptyEntry},
		{"whitespace exclusion", Config{Exclusions: []string{"   "}}, IssueEmptyEntry},
		{"control chars", Config{Exclusions: []string{"corp\x00.local"}}, IssueControlChars},
		{"newline injection", Config{Exclusions: []string{"a.com\nreturn"}}, IssueControlChars},
		{"too long entry", Config{Exclusions: []string{strings.Repeat("a", 254)}}, IssueEntryTooLong},
		{"bad cidr", Config{Exclusions: []string{"192.168.0.0/33"}}, IssueInvalidCIDR},
		{"not a cidr", Config{Exclusions: []string{"junk/entry"}}, IssueInvalidCIDR},
		{"ipv6 cidr", Config{Exclusions: []string{"2001:db8::/32"}}, IssueInvalidCIDR},
		{"mid wildcard", Config{Exclusions: []string{"corp.*.com"}}, IssueInvalidWildcard},
		{"trailing wildcard", Config{Exclusions: []string{"corp.com.*"}}, IssueInvalidWildcard},
		{"bare star", Config{Exclusions: []string{"*"}}, IssueInvalidWildcard},
		{"double star", Config{Exclusions: []string{"*.*.corp.com"}}, IssueInvalidWildcard},
		{"invalid host", Config{Exclusions: []string{"exa mple.com"}}, IssueControlChars},

		// Punctuation the permissive IDNA conversion passes through must be
		// rejected by the hostname-label check (Codex P2 finding on PR #799).
		{"proxy host with hash", Config{ProxyHost: "bad#host"}, IssueInvalidProxyHost},
		{"proxy host with query", Config{ProxyHost: "bad?host"}, IssueInvalidProxyHost},
		{"exclusion with hash", Config{Exclusions: []string{"bad#host.example"}}, IssueInvalidHost},
		{"wildcard with hash", Config{Exclusions: []string{"*.bad#host.example"}}, IssueInvalidHost},
		{"label leading hyphen", Config{Exclusions: []string{"-bad.example"}}, IssueInvalidHost},
		{"label trailing hyphen", Config{Exclusions: []string{"bad-.example"}}, IssueInvalidHost},
		{"label too long", Config{Exclusions: []string{strings.Repeat("a", 64) + ".example"}}, IssueInvalidHost},
		{"empty label", Config{Exclusions: []string{"bad..example"}}, IssueInvalidHost},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, issues := ValidateConfig(c.cfg)
			if c.wantCode == "" {
				if len(issues) != 0 {
					t.Fatalf("expected valid, got issues: %+v", issues)
				}
				return
			}
			if len(issues) == 0 {
				t.Fatalf("expected issue %s, got none", c.wantCode)
			}
			found := false
			for _, is := range issues {
				if is.Code == c.wantCode {
					found = true
					if is.Message == "" {
						t.Error("issue message must be actionable, got empty")
					}
				}
			}
			if !found {
				t.Errorf("expected issue code %s, got %+v", c.wantCode, issues)
			}
		})
	}
}

func TestValidateConfig_TooManyEntries(t *testing.T) {
	excl := make([]string, MaxExclusionEntries+1)
	for i := range excl {
		excl[i] = fmt.Sprintf("host%d.example", i)
	}
	_, issues := ValidateConfig(Config{Exclusions: excl})
	if len(issues) == 0 || issues[0].Code != IssueTooManyEntries {
		t.Fatalf("expected too_many_exclusions, got %+v", issues)
	}
}

func TestValidateConfig_DuplicatesDedupedWithWarning(t *testing.T) {
	n, issues := ValidateConfig(Config{Exclusions: []string{"corp.local", "CORP.LOCAL.", "corp.local"}})
	if len(issues) != 0 {
		t.Fatalf("duplicates must warn, not reject: %+v", issues)
	}
	if len(n.Exclusions) != 1 {
		t.Fatalf("expected 1 deduped exclusion, got %d", len(n.Exclusions))
	}
	dups := 0
	for _, w := range n.Warnings {
		if w.Code == IssueDuplicateEntry {
			dups++
		}
	}
	if dups != 2 {
		t.Errorf("expected 2 duplicate warnings, got %d (%+v)", dups, n.Warnings)
	}
}

func TestValidateConfig_IDNAPunycoded(t *testing.T) {
	n, issues := ValidateConfig(Config{Exclusions: []string{"münchen.example", "*.bücher.example"}})
	if len(issues) != 0 {
		t.Fatalf("unexpected issues: %+v", issues)
	}
	if n.Exclusions[0].Host != "xn--mnchen-3ya.example" {
		t.Errorf("IDN not punycoded: %q", n.Exclusions[0].Host)
	}
	if n.Exclusions[1].Kind != KindWildcard || n.Exclusions[1].Host != "xn--bcher-kva.example" {
		t.Errorf("wildcard IDN not punycoded: %+v", n.Exclusions[1])
	}
}

func TestValidateConfig_HostFallbackWarning(t *testing.T) {
	n, issues := ValidateConfig(Config{ProxyPort: 8080})
	if len(issues) != 0 {
		t.Fatalf("empty proxyHost must be valid (fallback mode): %+v", issues)
	}
	found := false
	for _, w := range n.Warnings {
		if w.Code == IssueHostFallback {
			found = true
		}
	}
	if !found {
		t.Errorf("expected proxy_host_fallback warning, got %+v", n.Warnings)
	}
}

// ─── NormalizeLenient: tolerant replay path ───────────────────────────────────

func TestNormalizeLenient_DropsJunkKeepsValid(t *testing.T) {
	n := NormalizeLenient(Config{
		ProxyHost: "proxy.corp.com",
		Exclusions: []string{
			"corp.local",      // valid
			"192.168.0.0/33",  // junk CIDR — dropped with warning
			"",                // blank — silently dropped (legacy behavior)
			"corp.*.wildcard", // junk wildcard — dropped with warning
			"*.ok.example",    // valid
			"172.16.0.0/12",   // valid
		},
	})
	if len(n.Exclusions) != 3 {
		t.Fatalf("expected 3 surviving exclusions, got %d: %+v", len(n.Exclusions), n.Exclusions)
	}
	warnCodes := map[string]bool{}
	for _, w := range n.Warnings {
		warnCodes[w.Code] = true
	}
	if !warnCodes[IssueInvalidCIDR] || !warnCodes[IssueInvalidWildcard] {
		t.Errorf("expected junk warnings, got %+v", n.Warnings)
	}
	if warnCodes[IssueEmptyEntry] {
		t.Error("blank entries must stay warning-free in lenient mode (legacy noise)")
	}
}

func TestNormalizeLenient_NeverRejects(t *testing.T) {
	n := NormalizeLenient(Config{
		ProxyHost:  "http://bad host",
		ProxyPort:  99999,
		Exclusions: []string{"\x01", strings.Repeat("x", 500)},
	})
	if n.ProxyHost != "" || n.ProxyPort != 0 {
		t.Errorf("lenient mode must zero unusable host/port, got %q/%d", n.ProxyHost, n.ProxyPort)
	}
	if len(n.Exclusions) != 0 {
		t.Errorf("junk exclusions must be dropped, got %+v", n.Exclusions)
	}
	if len(n.Warnings) == 0 {
		t.Error("dropped junk must be surfaced as warnings")
	}
}

// ─── Canonical form ───────────────────────────────────────────────────────────

func TestNormalizedExclusion_Canonical(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Corp.Local.", "corp.local"},
		{"*.Corp.Com", "*.corp.com"},
		{"10.1.2.3/32", "10.1.2.3/32"},
		{"192.168.1.55/24", "192.168.1.0/24"},
		{"192.0.2.9", "192.0.2.9"},
	}
	for _, c := range cases {
		entry, _, errIssue := normalizeExclusion(c.in)
		if errIssue != nil {
			t.Fatalf("normalizeExclusion(%q): %v", c.in, errIssue)
		}
		if got := entry.Canonical(); got != c.want {
			t.Errorf("Canonical(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
