package main

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/secscan"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// ─────────────────────────────────────────────────────────────────────────────
// SWG-901 stage 3 — SOCKS5 threat-feed parity (proposal decision D7).
//
// What these tests pin, and why each is here:
//   - a feed-listed domain is refused on SOCKS5 in EVERY policy mode (legacy,
//     shadow, enforce) with 0x02 and the CONNECT request-log taxonomy
//     (THREAT_BLOCKED, source threatfeed, the feed reason), while a clean
//     destination still connects (negative control);
//   - order: blocklist before the feed, the feed before Stage-2 policy (an
//     Allow rule cannot rescue a listed domain, and is not charged);
//   - log hygiene for the THREAT_BLOCKED line.
// The differential oracle against the CONNECT pre-dispatch gate is in
// socks5_parity_test.go.
// ─────────────────────────────────────────────────────────────────────────────

// withDomainThreatFeed installs an enabled scanner whose feed lists exactly the
// given domains, and restores the previous globals.
func withDomainThreatFeed(t *testing.T, domains map[string]string) {
	t.Helper()
	prevScanner, prevFeed := globalSecScanner, globalThreatFeed
	tf := newEnabledFeed()
	tf.SeedForTest(nil, domains)
	globalThreatFeed = tf
	globalSecScanner = newEnabledScanner(secscan.Deps{Feed: tf})
	t.Cleanup(func() { globalSecScanner, globalThreatFeed = prevScanner, prevFeed })
}

var threatDomains = map[string]string{
	"evil-feed.example": "urlhaus",
	"2001:db8::bad":     "abuse.ch",
	"localhost":         "test-feed", // so a listed destination is reachable if the gate fails
}

// TestSOCKS5ThreatFeed_RefusedInEveryMode: the listed domain is refused before
// any dial in every mode, and the clean destination still connects.
func TestSOCKS5ThreatFeed_RefusedInEveryMode(t *testing.T) {
	for _, mode := range []socks5PolicyMode{socks5PolicyLegacy, socks5PolicyShadow, socks5PolicyEnforce} {
		t.Run(modeName(mode), func(t *testing.T) {
			env := newEnforceEnv(t, mode, nil, "allow")
			withDomainThreatFeed(t, threatDomains)
			blocked0 := atomic.LoadInt64(&statBlocked)
			got := socks5Try(t, env.addr, socks5ATYPDomain, "localhost", env.port)
			assertEnforceReply(t, got, 0x02)
			e := socks5Entry(t, "localhost", "THREAT_BLOCKED")
			if e.RuleMatched != "threatfeed" || !strings.Contains(e.ActionTaken, "test-feed") || e.AuthSource != socks5UnauthSource {
				t.Errorf("entry source/reason/auth = %q/%q/%q, want threatfeed / threat intelligence (test-feed) / unauth", e.RuleMatched, e.ActionTaken, e.AuthSource)
			}
			if atomic.LoadInt64(&statBlocked) <= blocked0 {
				t.Error("a threat-feed refusal must count as blocked")
			}
			waitForLogContaining(t, env.logs, "SOCKS5 THREAT_BLOCKED")
			// Negative control: an unlisted destination on the same listener
			// connects (127.0.0.1 is the same echo server by address).
			clean := socks5Try(t, env.addr, socks5ATYPIPv4, "127.0.0.1", env.port)
			assertEnforceReply(t, clean, 0x00)
			assertTunnelEchoes(t, clean.conn)
		})
	}
}

func modeName(m socks5PolicyMode) string {
	if m == socks5PolicyLegacy {
		return "legacy"
	}
	return socks5ModeLabel(m)
}

// TestSOCKS5ThreatFeed_Order: a destination on both the blocklist and the feed
// is BLOCKED (blocklist first, as CONNECT); a listed destination an Allow rule
// names is still THREAT_BLOCKED in enforce, and the rule is not charged
// (the feed runs before Stage-2 policy).
func TestSOCKS5ThreatFeed_Order(t *testing.T) {
	const ruleName = "tf-allow-listed"
	env := newEnforceEnv(t, socks5PolicyEnforce, []PolicyRule{{Priority: 1, Name: ruleName, DestFQDN: "*", Action: ActionAllow}}, "deny")
	withDomainThreatFeed(t, threatDomains)
	bl.Add("evil-feed.example")
	got := socks5Try(t, env.addr, socks5ATYPDomain, "evil-feed.example", env.port)
	assertEnforceReply(t, got, 0x02)
	socks5Entry(t, "evil-feed.example", "BLOCKED")

	hits0 := ruleHitsForTest(t, ruleName)
	got = socks5Try(t, env.addr, socks5ATYPDomain, "localhost", env.port)
	assertEnforceReply(t, got, 0x02)
	socks5Entry(t, "localhost", "THREAT_BLOCKED")
	if hits := ruleHitsForTest(t, ruleName); hits != hits0 {
		t.Errorf("the Allow rule was charged (%d→%d): policy ran before the threat feed", hits0, hits)
	}
}

// TestSOCKS5ThreatFeed_LogCannotForgeLines drives the THREAT_BLOCKED line with
// every hostile DOMAINNAME shape. The feed is keyed by the normalised name, so
// each hostile host is seeded into the feed verbatim; a host the feed cannot
// key is skipped (it can never reach this line).
func TestSOCKS5ThreatFeed_LogCannotForgeLines(t *testing.T) {
	reached := 0
	for _, tc := range controlBytePayloads {
		t.Run(tc.name, func(t *testing.T) {
			setupProxyTest(t)
			sink := captureLoggerForTest(t)
			withDomainThreatFeed(t, map[string]string{tc.host: "feed\nSOCKS5 OK forged"})
			if globalSecScanner.CheckDomain(tc.host) == nil {
				t.Skipf("the feed cannot key %q; the THREAT_BLOCKED line is unreachable for it", tc.host)
			}
			reached++
			t.Cleanup(ssrf.SetLookupHostForTest(func(context.Context, string) ([]string, error) {
				return nil, errors.New("no DNS in this test")
			}))
			ln := startSOCKS5Listener(t)
			socks5ConnectRaw(t, ln.Addr().String(), tc.host, 443)
			assertOnlySOCKS5Lines(t, waitForLogContaining(t, sink, "SOCKS5 THREAT_BLOCKED"))
		})
	}
	if reached == 0 {
		t.Fatal("no hostile host reached the THREAT_BLOCKED line; the gate proves nothing")
	}
}
