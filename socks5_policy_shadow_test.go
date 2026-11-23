package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// ─────────────────────────────────────────────────────────────────────────────
// SWG-901 stage 2 — SOCKS5 shadow policy evaluation.
//
// What these tests pin, and why each is here:
//   - shadow NEVER changes a connection's outcome (table over a real handshake,
//     run in both modes and compared);
//   - the shadow verdict is the CONNECT verdict (differential against the real
//     CONNECT dispatcher, with a negative control that a different matcher fails);
//   - shadow charges no policy accounting (hit counters, ruleMet, request log);
//   - legacy evaluates nothing, counts nothing, logs nothing new, emits no series;
//   - the config key: absent → legacy, shadow accepted, enforce/garbage rejected;
//   - ATYP counting; log hygiene for hostile DOMAINNAME bytes.
// ─────────────────────────────────────────────────────────────────────────────

// useSOCKS5PolicyModeForTest installs mode and restores the previous one.
// Call it BEFORE startSOCKS5Listener: cleanups are LIFO, so the listener's
// handler drain runs first and no handler can read the mode after the restore.
func useSOCKS5PolicyModeForTest(t *testing.T, mode socks5PolicyMode) {
	t.Helper()
	prev := loadSOCKS5PolicyMode()
	setSOCKS5PolicyMode(mode)
	t.Cleanup(func() { setSOCKS5PolicyMode(prev) })
}

// openSOCKS5WouldBlockLogForTest disables the log rate gate so every
// would-block in the test logs. Same LIFO ordering note as above.
func openSOCKS5WouldBlockLogForTest(t *testing.T) {
	t.Helper()
	prevWindow := socks5WouldBlockLogWindowNanos.Load()
	prevLast := socks5WouldBlockLogLast.Load()
	socks5WouldBlockLogWindowNanos.Store(0)
	socks5WouldBlockLogLast.Store(0)
	t.Cleanup(func() {
		socks5WouldBlockLogWindowNanos.Store(prevWindow)
		socks5WouldBlockLogLast.Store(prevLast)
	})
}

// installPolicyForTest replaces the rulebase and the default action, restoring
// both (conventions: rules and default action together).
func installPolicyForTest(t *testing.T, rules []PolicyRule, defaultAction string) {
	t.Helper()
	snapshotPolicyStoreForTest(t)
	prev := defaultPolicyAction()
	t.Cleanup(func() { setDefaultPolicyAction(prev) })
	policyStore.ReplaceAll(rules)
	setDefaultPolicyAction(defaultAction)
}

// shadowCounters is a point-in-time copy of the evidence counters, for deltas.
type shadowCounters struct {
	decisions [2][2]int64
	atyp      [3]int64
}

func readShadowCounters() shadowCounters {
	var c shadowCounters
	for v := range socks5ShadowDecisions {
		for r := range socks5ShadowDecisions[v] {
			c.decisions[v][r] = socks5ShadowDecisions[v][r].Load()
		}
	}
	for i := range socks5ShadowATYP {
		c.atyp[i] = socks5ShadowATYP[i].Load()
	}
	return c
}

func (c shadowCounters) minus(o shadowCounters) shadowCounters {
	var d shadowCounters
	for v := range c.decisions {
		for r := range c.decisions[v] {
			d.decisions[v][r] = c.decisions[v][r] - o.decisions[v][r]
		}
	}
	for i := range c.atyp {
		d.atyp[i] = c.atyp[i] - o.atyp[i]
	}
	return d
}

func decisionIndex(verdict, reason string) (v, r int) {
	if verdict == socks5VerdictWouldBlock {
		v = 1
	}
	if reason == socks5ReasonDefault {
		r = 1
	}
	return v, r
}

// startEchoServerForTest serves an echo on 127.0.0.1 and returns its port.
func startEchoServerForTest(t *testing.T) uint16 {
	t.Helper()
	ln, err := ctxListen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return uint16(port) // #nosec G115 -- ephemeral port < 65536
}

// allowLoopbackSOCKS5ForTest lets the SOCKS5 SSRF guard admit the loopback echo
// server: loopback is dropped from the guard table and the guard's resolver
// answers 127.0.0.1 for any name (the dial itself still uses the OS resolver,
// which is why domain destinations in these tests are "localhost").
func allowLoopbackSOCKS5ForTest(t *testing.T) {
	t.Helper()
	t.Cleanup(ssrf.AllowLoopbackForTest())
	t.Cleanup(ssrf.SetLookupHostForTest(func(context.Context, string) ([]string, error) {
		return []string{"127.0.0.1"}, nil
	}))
}

// socks5RequestFrame encodes a no-auth CONNECT for host with the given ATYP.
func socks5RequestFrame(t *testing.T, atyp byte, host string, port uint16) []byte {
	t.Helper()
	req := []byte{0x05, 0x01, 0x00, atyp}
	switch atyp {
	case socks5ATYPIPv4:
		ip := net.ParseIP(host).To4()
		if ip == nil {
			t.Fatalf("%q is not an IPv4 literal", host)
		}
		req = append(req, ip...)
	case socks5ATYPIPv6:
		ip := net.ParseIP(strings.Trim(host, "[]")).To16()
		if ip == nil {
			t.Fatalf("%q is not an IPv6 literal", host)
		}
		req = append(req, ip...)
	default:
		req = append(req, byte(len(host))) // #nosec G115 -- test hosts are short
		req = append(req, host...)
	}
	return append(req, byte(port>>8), byte(port&0xff))
}

// socks5ConnectATYP performs the no-auth greeting and a CONNECT, returning the
// reply code and the open client connection (closed at test end).
func socks5ConnectATYP(t *testing.T, addr string, atyp byte, host string, port uint16) (byte, net.Conn) {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		t.Fatalf("greeting read: %v", err)
	}
	if _, err := conn.Write(socks5RequestFrame(t, atyp, host, port)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reply read: %v", err)
	}
	return reply[1], conn
}

// assertTunnelEchoes proves the tunnel carries bytes end to end.
func assertTunnelEchoes(t *testing.T, conn net.Conn) {
	t.Helper()
	const payload = "swg-901-shadow-payload"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("tunnel write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("tunnel read: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("tunnel echoed %q, want %q", got, payload)
	}
}

// socks5OKEntry waits for the SOCKS5 "OK" request-log entry for host.
func socks5OKEntry(t *testing.T, host string) *LogEntry {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries := logGet()
		for i := range entries {
			if entries[i].Method == "SOCKS5" && entries[i].Host == host && entries[i].Status == "OK" {
				return &entries[i]
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no SOCKS5 OK request-log entry for %q", host)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// socks5Outcome is everything a client or operator observes about one
// connection other than the shadow evidence itself.
type socks5Outcome struct {
	reply       byte
	status      string
	ruleMatched string
	actionTaken string
	ruleID      string
}

// runSOCKS5Once drives one real SOCKS5 CONNECT in mode and returns the
// observable outcome, the evidence-counter delta and the captured log.
func runSOCKS5Once(t *testing.T, mode socks5PolicyMode, rules []PolicyRule, defaultAction string, atyp byte, host string) (socks5Outcome, shadowCounters, string) {
	t.Helper()
	setupProxyTest(t)
	sink := captureLoggerForTest(t)
	useSOCKS5PolicyModeForTest(t, mode)
	openSOCKS5WouldBlockLogForTest(t)
	installPolicyForTest(t, rules, defaultAction)
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackSOCKS5ForTest(t)
	port := startEchoServerForTest(t)
	ln := startSOCKS5Listener(t)

	before := readShadowCounters()
	reply, conn := socks5ConnectATYP(t, ln.Addr().String(), atyp, host, port)
	delta := readShadowCounters().minus(before)
	out := socks5Outcome{reply: reply}
	if reply != 0x00 {
		return out, delta, sink.String()
	}
	assertTunnelEchoes(t, conn)
	e := socks5OKEntry(t, host)
	out.status, out.ruleMatched, out.actionTaken, out.ruleID = e.Status, e.RuleMatched, e.ActionTaken, e.RuleID
	return out, delta, sink.String()
}

// shadowTableCases are destinations whose policy verdict spans every shadow
// outcome. Domain destinations are "localhost" and IPv4 ones 127.0.0.1 so the
// real dial reaches the loopback echo server.
var shadowTableCases = []struct {
	name          string
	rules         []PolicyRule
	defaultAction string
	atyp          byte
	host          string
	wantVerdict   string
	wantReason    string
}{
	{"drop_rule_domain", []PolicyRule{{Priority: 1, Name: "shadow-drop", DestFQDN: "localhost", Action: ActionDrop}},
		"allow", socks5ATYPDomain, "localhost", socks5VerdictWouldBlock, socks5ReasonRule},
	{"block_page_rule_wildcard", []PolicyRule{{Priority: 1, Name: "shadow-block", DestFQDN: "*", Action: ActionBlockPage}},
		"allow", socks5ATYPDomain, "localhost", socks5VerdictWouldBlock, socks5ReasonRule},
	{"block_page_rule_ipv4", []PolicyRule{{Priority: 1, Name: "shadow-block-ip", DestFQDN: "127.0.0.1", Action: ActionBlockPage}},
		"allow", socks5ATYPIPv4, "127.0.0.1", socks5VerdictWouldBlock, socks5ReasonRule},
	{"redirect_rule", []PolicyRule{{Priority: 1, Name: "shadow-redirect", DestFQDN: "localhost", Action: ActionRedirect, RedirectURL: "https://portal.example.com/"}},
		"allow", socks5ATYPDomain, "localhost", socks5VerdictWouldBlock, socks5ReasonRule},
	{"default_deny_with_rules", []PolicyRule{{Priority: 1, Name: "shadow-other", DestFQDN: "other.example.com", Action: ActionAllow}},
		"deny", socks5ATYPDomain, "localhost", socks5VerdictWouldBlock, socks5ReasonDefault},
	{"default_deny_ipv4", []PolicyRule{{Priority: 1, Name: "shadow-other", DestFQDN: "other.example.com", Action: ActionAllow}},
		"deny", socks5ATYPIPv4, "127.0.0.1", socks5VerdictWouldBlock, socks5ReasonDefault},
	{"allow_rule", []PolicyRule{{Priority: 1, Name: "shadow-allow", DestFQDN: "localhost", Action: ActionAllow}},
		"deny", socks5ATYPDomain, "localhost", socks5VerdictAllow, socks5ReasonRule},
	{"default_allow_no_rules", nil, "allow", socks5ATYPIPv4, "127.0.0.1", socks5VerdictAllow, socks5ReasonDefault},
}

// TestSOCKS5Shadow_NeverRefusesAndRecordsVerdict is the core stage-2 gate. Each
// destination is connected twice over a real handshake — once in legacy, once
// in shadow — and must be served IDENTICALLY (reply 0x00, bytes relayed, the
// same request-log entry with no policy attribution). Only shadow records the
// verdict, and the would_block cases log POLICY_WOULD_BLOCK.
func TestSOCKS5Shadow_NeverRefusesAndRecordsVerdict(t *testing.T) {
	for _, tc := range shadowTableCases {
		t.Run(tc.name, func(t *testing.T) {
			var legacy socks5Outcome
			t.Run("legacy", func(t *testing.T) {
				out, delta, logs := runSOCKS5Once(t, socks5PolicyLegacy, tc.rules, tc.defaultAction, tc.atyp, tc.host)
				legacy = out
				if delta != (shadowCounters{}) {
					t.Errorf("legacy mode moved the shadow counters: %+v", delta)
				}
				if strings.Contains(logs, "POLICY_WOULD_BLOCK") {
					t.Errorf("legacy mode logged a would-block line:\n%s", logs)
				}
			})
			t.Run("shadow", func(t *testing.T) {
				out, delta, logs := runSOCKS5Once(t, socks5PolicyShadow, tc.rules, tc.defaultAction, tc.atyp, tc.host)
				if out != legacy {
					t.Fatalf("shadow changed the connection outcome: shadow=%+v legacy=%+v", out, legacy)
				}
				if out.reply != 0x00 {
					t.Fatalf("SOCKS5 reply = 0x%02x, want 0x00: shadow must never refuse", out.reply)
				}
				assertSOCKS5ShadowDelta(t, delta, tc.wantVerdict, tc.wantReason, tc.atyp)
				var ruleName string
				if len(tc.rules) > 0 {
					ruleName = tc.rules[0].Name
				}
				assertWouldBlockLog(t, logs, tc.wantVerdict, tc.wantReason, ruleName)
			})
		})
	}
}

// assertWouldBlockLog requires a POLICY_WOULD_BLOCK line iff the verdict is
// would_block, naming the rule (when a rule decided) and the identity the
// evaluation ran as.
func assertWouldBlockLog(t *testing.T, logs, verdict, reason, ruleName string) {
	t.Helper()
	wantLog := verdict == socks5VerdictWouldBlock
	if got := strings.Contains(logs, "SOCKS5 POLICY_WOULD_BLOCK"); got != wantLog {
		t.Errorf("POLICY_WOULD_BLOCK logged = %v, want %v; logs:\n%s", got, wantLog, logs)
	}
	if !wantLog {
		return
	}
	if reason == socks5ReasonRule && !strings.Contains(logs, `rule="`+ruleName+`"`) {
		t.Errorf("the would-block line must name the rule %q; logs:\n%s", ruleName, logs)
	}
	if !strings.Contains(logs, "auth_source=unauth") {
		t.Errorf("the would-block line must state the identity it was evaluated as; logs:\n%s", logs)
	}
}

// assertSOCKS5ShadowDelta requires exactly one decision in (verdict, reason), none
// elsewhere, and exactly one request for atyp.
func assertSOCKS5ShadowDelta(t *testing.T, delta shadowCounters, verdict, reason string, atyp byte) {
	t.Helper()
	var want shadowCounters
	v, r := decisionIndex(verdict, reason)
	want.decisions[v][r] = 1
	switch atyp {
	case socks5ATYPIPv4:
		want.atyp[0] = 1
	case socks5ATYPIPv6:
		want.atyp[1] = 1
	case socks5ATYPDomain:
		want.atyp[2] = 1
	}
	if delta != want {
		t.Errorf("shadow counter delta = %+v, want %+v (verdict=%s reason=%s atyp=0x%02x)", delta, want, verdict, reason, atyp)
	}
}

// ── Differential: shadow verdict == CONNECT verdict ─────────────────────────

// differentialRules is one rulebase exercising wildcard/case/IP/IPv6/source/
// auth-source/unknown-action/empty-action matching. Installed directly (not via
// ReplaceAll) because the unknown-action row is exactly the shape ReplaceAll
// refuses, and the runtime still has to fail closed on one that got in.
func differentialRules() []*PolicyRule {
	return []*PolicyRule{
		{Priority: 1, Name: "d-drop-gambling", DestFQDN: "*.gambling.example", Action: ActionDrop},
		{Priority: 2, Name: "d-block-exact", DestFQDN: "blocked.example.com", Action: ActionBlockPage},
		{Priority: 3, Name: "d-allow-corp-src", SourceIP: "10.1.0.0/16", DestFQDN: "*.corp.example", Action: ActionAllow},
		{Priority: 4, Name: "d-drop-corp", DestFQDN: "*.corp.example", Action: ActionDrop},
		{Priority: 5, Name: "d-redirect", DestFQDN: "redirect.example", Action: ActionRedirect, RedirectURL: "https://portal.example.com/"},
		{Priority: 6, Name: "d-allow-okta", AuthSource: "okta", DestFQDN: "*.okta-only.example", Action: ActionAllow},
		{Priority: 7, Name: "d-unknown", DestFQDN: "weird.example", Action: PolicyAction("Quarantine")},
		{Priority: 8, Name: "d-empty-action", DestFQDN: "legacy-empty.example", Action: ""},
		{Priority: 9, Name: "d-drop-v6", DestFQDN: "2001:db8::66", Action: ActionDrop},
		{Priority: 10, Name: "d-allow-ip", DestFQDN: "198.51.100.7", Action: ActionAllow},
		{Priority: 11, Name: "d-allow-org", DestFQDN: "*.example.org", Action: ActionAllow},
		{Priority: 12, Name: "d-block-v4", DestFQDN: "203.0.113.50", Action: ActionBlockPage},
	}
}

// differentialCorpus is (client, SOCKS5 wire host, CONNECT host). The two host
// forms differ only for IPv6, where SOCKS5 carries brackets and CONNECT does not.
var differentialCorpus = []struct{ clientIP, socksHost, connectHost string }{
	{"192.0.2.10", "casino.gambling.example", "casino.gambling.example"},
	{"192.0.2.10", "CASINO.Gambling.Example", "CASINO.Gambling.Example"},
	{"192.0.2.10", "blocked.example.com", "blocked.example.com"},
	{"192.0.2.10", "BLOCKED.EXAMPLE.COM", "BLOCKED.EXAMPLE.COM"},
	{"10.1.2.3", "app.corp.example", "app.corp.example"},
	{"192.0.2.10", "app.corp.example", "app.corp.example"},
	{"192.0.2.10", "redirect.example", "redirect.example"},
	{"192.0.2.10", "sso.okta-only.example", "sso.okta-only.example"},
	{"192.0.2.10", "weird.example", "weird.example"},
	{"192.0.2.10", "legacy-empty.example", "legacy-empty.example"},
	{"192.0.2.10", "[2001:db8::66]", "2001:db8::66"},
	{"192.0.2.10", "[2001:db8::67]", "2001:db8::67"},
	{"192.0.2.10", "198.51.100.7", "198.51.100.7"},
	{"192.0.2.10", "203.0.113.50", "203.0.113.50"},
	{"192.0.2.10", "www.example.org", "www.example.org"},
	{"192.0.2.10", "unmatched.example.net", "unmatched.example.net"},
}

// connectPathVerdict runs the REAL CONNECT decision — policyStore.Evaluate (the
// exact call handleRequest makes, with the unauthenticated identity) and then
// applyPolicyDecision on a CONNECT request — and reports would_block iff the
// dispatcher wrote a terminal refusal.
func connectPathVerdict(t *testing.T, clientIP, host string) string {
	t.Helper()
	match := policyStore.Evaluate(clientIP, "", "unauth", host, nil)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "http://"+net.JoinHostPort(host, "443"), http.NoBody)
	r.Host = net.JoinHostPort(host, "443")
	w := httptest.NewRecorder() // not a Hijacker, so Drop returns instead of hijacking
	if _, terminal := applyPolicyDecision(w, r, clientIP, host, "req-swg901-diff", "", AuthLogFields{}, match); terminal {
		return socks5VerdictWouldBlock
	}
	return socks5VerdictAllow
}

// shadowMismatches evaluates the corpus under every default action and returns
// the rows where shadow disagrees with CONNECT, plus the verdict tally.
func shadowMismatches(t *testing.T, shadow func(clientIP, host string) socks5ShadowResult) (mismatches []string, allow, block int) {
	t.Helper()
	for _, def := range []string{"deny", "allow"} {
		setDefaultPolicyAction(def)
		for _, c := range differentialCorpus {
			want := connectPathVerdict(t, c.clientIP, c.connectHost)
			got := shadow(c.clientIP, c.socksHost).verdict
			if got != want {
				mismatches = append(mismatches, def+" "+c.clientIP+" "+c.socksHost+": shadow="+got+" connect="+want)
			}
			if want == socks5VerdictAllow {
				allow++
			} else {
				block++
			}
		}
	}
	return mismatches, allow, block
}

func setupDifferentialPolicy(t *testing.T) {
	t.Helper()
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)
	prev := defaultPolicyAction()
	t.Cleanup(func() { setDefaultPolicyAction(prev) })
	t.Cleanup(reqlog.SwapRingForTest())
	policyStore.mu.Lock()
	policyStore.rules = differentialRules()
	policyStore.mu.Unlock()
}

// TestSOCKS5Shadow_VerdictEqualsCONNECTVerdict is the differential oracle: for
// every corpus row and both default actions, the shadow verdict equals what the
// CONNECT path actually dispatches for the same client, host and rulebase.
func TestSOCKS5Shadow_VerdictEqualsCONNECTVerdict(t *testing.T) {
	setupDifferentialPolicy(t)
	mismatches, allow, block := shadowMismatches(t, socks5ShadowEvaluate)
	for _, m := range mismatches {
		t.Errorf("shadow/CONNECT divergence: %s", m)
	}
	// Non-vacuous: the corpus must exercise both verdicts substantially.
	if allow < 5 || block < 10 {
		t.Fatalf("corpus too one-sided to prove agreement: allow=%d would_block=%d", allow, block)
	}
}

// TestSOCKS5Shadow_DifferentialCatchesADifferentMatcher is the NEGATIVE
// CONTROL. A shadow path with its own matcher — exact, case-sensitive FQDN
// compare, no wildcards, no source/auth conditions — classified by the same
// verdict mapping must be caught by the oracle above, or the oracle proves
// nothing about which matcher shadow uses.
func TestSOCKS5Shadow_DifferentialCatchesADifferentMatcher(t *testing.T) {
	setupDifferentialPolicy(t)
	naive := func(_ string, host string) socks5ShadowResult {
		var hit *PolicyRule
		rules := policyStore.List()
		for i := range rules {
			if rules[i].DestFQDN == host {
				hit = &rules[i]
				break
			}
		}
		return classifySOCKS5Shadow(hit, defaultPolicyAction() == "allow")
	}
	mismatches, _, _ := shadowMismatches(t, naive)
	if len(mismatches) == 0 {
		t.Fatal("the differential oracle did not detect a shadow path using a different matcher; it cannot prove shadow uses the CONNECT evaluator")
	}
}

// ── Non-accounting ─────────────────────────────────────────────────────────

// ruleMetHitsForTest reads ruleMet's hit cell for name (0 when unregistered).
func ruleMetHitsForTest(name string) int64 {
	ruleMet.mu.RLock()
	defer ruleMet.mu.RUnlock()
	if p := ruleMet.hits[name]; p != nil {
		return *p
	}
	return 0
}

// TestSOCKS5Shadow_DoesNotChargePolicyAccounting proves the shadow path is
// non-accounting: after several matched shadow evaluations over real
// handshakes, the matched rule's hit counter, last-hit stamp and Prometheus hit
// cell are unchanged and no POLICY_* request-log entry exists. The positive
// control then charges one CONNECT evaluation and requires the counter to move,
// so "unchanged" cannot be an artefact of reading a dead cell.
func TestSOCKS5Shadow_DoesNotChargePolicyAccounting(t *testing.T) {
	const ruleName = "swg901-accounting-probe"
	setupProxyTest(t)
	captureLoggerForTest(t)
	useSOCKS5PolicyModeForTest(t, socks5PolicyShadow)
	installPolicyForTest(t, []PolicyRule{{Priority: 1, Name: ruleName, DestFQDN: "localhost", Action: ActionDrop}}, "deny")
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackSOCKS5ForTest(t)
	port := startEchoServerForTest(t)
	ln := startSOCKS5Listener(t)

	hitsOf := func() (int64, string) {
		for _, r := range policyStore.List() {
			if r.Name == ruleName {
				return r.HitCount, r.LastHit
			}
		}
		t.Fatalf("rule %q missing", ruleName)
		return 0, ""
	}
	hits0, last0 := hitsOf()
	met0 := ruleMetHitsForTest(ruleName)
	before := readShadowCounters()

	for i := 0; i < 3; i++ {
		reply, conn := socks5ConnectATYP(t, ln.Addr().String(), socks5ATYPDomain, "localhost", port)
		if reply != 0x00 {
			t.Fatalf("connection %d refused (0x%02x); shadow must never refuse", i, reply)
		}
		assertTunnelEchoes(t, conn)
	}
	if d := readShadowCounters().minus(before); d.decisions[1][0] != 3 {
		t.Fatalf("precondition: expected 3 rule would_block shadow decisions, got %+v", d)
	}

	if hits, last := hitsOf(); hits != hits0 || last != last0 {
		t.Errorf("shadow charged rule accounting: hitCount %d→%d lastHit %q→%q", hits0, hits, last0, last)
	}
	if met := ruleMetHitsForTest(ruleName); met != met0 {
		t.Errorf("shadow charged ruleMet (Prometheus rule hits): %d→%d", met0, met)
	}
	socks5OKEntry(t, "localhost") // the legacy OK entry is still written…
	for _, e := range logGet() {
		if strings.HasPrefix(e.Status, "POLICY_") || e.RuleMatched == ruleName {
			t.Errorf("shadow wrote a policy request-log entry: %+v", e) // …but nothing policy-shaped
		}
	}

	// Positive control: the CONNECT evaluator DOES charge the same cell.
	if m := policyStore.Evaluate("127.0.0.1", "", "unauth", "localhost", nil); m == nil {
		t.Fatal("positive control: the rule must match via Evaluate")
	}
	if hits, _ := hitsOf(); hits != hits0+1 {
		t.Fatalf("positive control: Evaluate must charge the hit counter (%d→%d); the non-accounting assertion above read a dead cell", hits0, hits)
	}
}

// ── Legacy ─────────────────────────────────────────────────────────────────

// TestSOCKS5Shadow_LegacyEvaluatesNothing pins the default: with rules that
// would block every destination, a legacy connection is served, no evaluation
// is counted (the decision counter is charged by EVERY evaluation, so an
// unchanged counter proves none ran), the rule's hit counter is untouched, no
// would-block line is logged and the metric families are absent from /metrics.
func TestSOCKS5Shadow_LegacyEvaluatesNothing(t *testing.T) {
	setupProxyTest(t)
	sink := captureLoggerForTest(t)
	useSOCKS5PolicyModeForTest(t, socks5PolicyLegacy)
	openSOCKS5WouldBlockLogForTest(t)
	installPolicyForTest(t, []PolicyRule{{Priority: 1, Name: "legacy-drop-all", DestFQDN: "*", Action: ActionDrop}}, "deny")
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackSOCKS5ForTest(t)
	port := startEchoServerForTest(t)
	ln := startSOCKS5Listener(t)

	before := readShadowCounters()
	for _, d := range []struct {
		atyp byte
		host string
	}{{socks5ATYPDomain, "localhost"}, {socks5ATYPIPv4, "127.0.0.1"}} {
		reply, conn := socks5ConnectATYP(t, ln.Addr().String(), d.atyp, d.host, port)
		if reply != 0x00 {
			t.Fatalf("legacy refused %s (0x%02x)", d.host, reply)
		}
		assertTunnelEchoes(t, conn)
	}
	if d := readShadowCounters().minus(before); d != (shadowCounters{}) {
		t.Errorf("legacy mode evaluated or counted: %+v", d)
	}
	for _, r := range policyStore.List() {
		if r.HitCount != 0 {
			t.Errorf("legacy mode charged rule %q (%d hits)", r.Name, r.HitCount)
		}
	}
	if strings.Contains(sink.String(), "POLICY_WOULD_BLOCK") || strings.Contains(sink.String(), "policy mode") {
		t.Errorf("legacy mode logged something new:\n%s", sink.String())
	}
	body := scrapeMetricsNoToken(t)
	for _, fam := range []string{"culvert_socks5_policy_decisions_total", "culvert_socks5_requests_total"} {
		if strings.Contains(body, fam) {
			t.Errorf("legacy /metrics exposes %s; the series must be absent outside shadow mode", fam)
		}
	}
}

// scrapeMetricsNoToken renders /metrics with the bearer token cleared.
func scrapeMetricsNoToken(t *testing.T) string {
	t.Helper()
	prev := metricsToken
	metricsToken = ""
	t.Cleanup(func() { metricsToken = prev })
	w := httptest.NewRecorder()
	handleMetrics(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	if w.Code != http.StatusOK {
		t.Fatalf("handleMetrics status = %d", w.Code)
	}
	return w.Body.String()
}

// TestSOCKS5Shadow_MetricsExposition pins the shadow series: present in shadow
// mode through the real /metrics handler, with exactly the bounded label set,
// and carrying the counter values.
func TestSOCKS5Shadow_MetricsExposition(t *testing.T) {
	useSOCKS5PolicyModeForTest(t, socks5PolicyShadow)
	body := scrapeMetricsNoToken(t)
	c := readShadowCounters()
	for _, line := range []string{
		"# TYPE culvert_socks5_policy_decisions_total counter",
		`culvert_socks5_policy_decisions_total{mode="shadow",verdict="allow",reason="rule"} ` + strconv.FormatInt(c.decisions[0][0], 10),
		`culvert_socks5_policy_decisions_total{mode="shadow",verdict="allow",reason="default"} ` + strconv.FormatInt(c.decisions[0][1], 10),
		`culvert_socks5_policy_decisions_total{mode="shadow",verdict="would_block",reason="rule"} ` + strconv.FormatInt(c.decisions[1][0], 10),
		`culvert_socks5_policy_decisions_total{mode="shadow",verdict="would_block",reason="default"} ` + strconv.FormatInt(c.decisions[1][1], 10),
		"# TYPE culvert_socks5_requests_total counter",
		`culvert_socks5_requests_total{atyp="ipv4"} ` + strconv.FormatInt(c.atyp[0], 10),
		`culvert_socks5_requests_total{atyp="ipv6"} ` + strconv.FormatInt(c.atyp[1], 10),
		`culvert_socks5_requests_total{atyp="domain"} ` + strconv.FormatInt(c.atyp[2], 10),
	} {
		if !strings.Contains(body, line+"\n") {
			t.Errorf("/metrics missing %q", line)
		}
	}
	if n := strings.Count(body, "culvert_socks5_policy_decisions_total{"); n != 4 {
		t.Errorf("decisions series = %d, want exactly 4 (bounded labels)", n)
	}
	if n := strings.Count(body, "culvert_socks5_requests_total{"); n != 3 {
		t.Errorf("requests series = %d, want exactly 3 (bounded labels)", n)
	}
}

// ── ATYP ───────────────────────────────────────────────────────────────────

// TestSOCKS5Shadow_CountsATYP sends one CONNECT per address type and requires
// one count per type. The IPv6 destination may fail to dial on a runner without
// IPv6 loopback; it is counted at the policy stage, before the dial, and the
// test asserts only that it was not refused by policy (no 0x02).
func TestSOCKS5Shadow_CountsATYP(t *testing.T) {
	setupProxyTest(t)
	captureLoggerForTest(t)
	useSOCKS5PolicyModeForTest(t, socks5PolicyShadow)
	installPolicyForTest(t, nil, "allow")
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackSOCKS5ForTest(t)
	port := startEchoServerForTest(t)
	ln := startSOCKS5Listener(t)

	for _, d := range []struct {
		atyp byte
		host string
		idx  int
	}{{socks5ATYPIPv4, "127.0.0.1", 0}, {socks5ATYPIPv6, "[::1]", 1}, {socks5ATYPDomain, "localhost", 2}} {
		before := readShadowCounters()
		reply, _ := socks5ConnectATYP(t, ln.Addr().String(), d.atyp, d.host, port)
		if reply == 0x02 {
			t.Errorf("%s refused with 0x02 (ruleset) — shadow must not refuse", d.host)
		}
		delta := readShadowCounters().minus(before)
		var want [3]int64
		want[d.idx] = 1
		if delta.atyp != want {
			t.Errorf("ATYP 0x%02x (%s): atyp delta = %v, want %v", d.atyp, d.host, delta.atyp, want)
		}
		if delta.decisions[0][1] != 1 {
			t.Errorf("ATYP 0x%02x (%s): expected one allow/default decision, got %+v", d.atyp, d.host, delta.decisions)
		}
	}
}

// TestSOCKS5Shadow_EvaluatorPanicDoesNotChangeOutcome forces the evaluator to
// panic (a nil store) and requires the connection to be served exactly as in
// legacy mode, with the panic recorded rather than propagated into
// handleSOCKS5's goroutine guard, which would close the connection.
func TestSOCKS5Shadow_EvaluatorPanicDoesNotChangeOutcome(t *testing.T) {
	setupProxyTest(t)
	captureLoggerForTest(t)
	useSOCKS5PolicyModeForTest(t, socks5PolicyShadow)
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackSOCKS5ForTest(t)
	prevStore := policyStore
	policyStore = nil // matchAccessRule dereferences it: a guaranteed panic
	t.Cleanup(func() { policyStore = prevStore })
	crashes0 := atomic.LoadInt64(&statCrashRecords)
	port := startEchoServerForTest(t)
	ln := startSOCKS5Listener(t) // registered last: its drain runs before the store is restored

	reply, conn := socks5ConnectATYP(t, ln.Addr().String(), socks5ATYPDomain, "localhost", port)
	if reply != 0x00 {
		t.Fatalf("SOCKS5 reply = 0x%02x after an evaluator panic, want 0x00", reply)
	}
	assertTunnelEchoes(t, conn)
	if atomic.LoadInt64(&statCrashRecords) == crashes0 {
		t.Fatal("the evaluator panic was not recorded")
	}
}

// TestSOCKS5PolicyHost_StripsIPv6Brackets pins the evaluator input form.
func TestSOCKS5PolicyHost_StripsIPv6Brackets(t *testing.T) {
	for in, want := range map[string]string{
		"[2001:db8::1]": "2001:db8::1",
		"[::1]":         "::1",
		"192.0.2.1":     "192.0.2.1",
		"example.com":   "example.com",
		"[":             "[",
		"[]":            "",
		"":              "",
	} {
		if got := socks5PolicyHost(in); got != want {
			t.Errorf("socks5PolicyHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestClassifySOCKS5Shadow pins the verdict mapping, including the fail-closed
// unknown action and the empty action that canonicalizes to Allow.
func TestClassifySOCKS5Shadow(t *testing.T) {
	cases := []struct {
		rule         *PolicyRule
		defaultAllow bool
		verdict      string
		reason       string
	}{
		{nil, true, socks5VerdictAllow, socks5ReasonDefault},
		{nil, false, socks5VerdictWouldBlock, socks5ReasonDefault},
		{&PolicyRule{Action: ActionAllow}, false, socks5VerdictAllow, socks5ReasonRule},
		{&PolicyRule{Action: "allow"}, false, socks5VerdictAllow, socks5ReasonRule},
		{&PolicyRule{Action: ""}, false, socks5VerdictAllow, socks5ReasonRule},
		{&PolicyRule{Action: ActionDrop}, true, socks5VerdictWouldBlock, socks5ReasonRule},
		{&PolicyRule{Action: ActionBlockPage}, true, socks5VerdictWouldBlock, socks5ReasonRule},
		{&PolicyRule{Action: ActionRedirect}, true, socks5VerdictWouldBlock, socks5ReasonRule},
		{&PolicyRule{Action: "Quarantine"}, true, socks5VerdictWouldBlock, socks5ReasonRule},
	}
	for _, c := range cases {
		got := classifySOCKS5Shadow(c.rule, c.defaultAllow)
		if got.verdict != c.verdict || got.reason != c.reason {
			t.Errorf("classify(%+v, defaultAllow=%v) = %s/%s, want %s/%s", c.rule, c.defaultAllow, got.verdict, got.reason, c.verdict, c.reason)
		}
	}
}

// TestSOCKS5Shadow_WouldBlockLogIsRateLimited pins the sampling: with the
// production window, a burst of would-blocks emits one line while the counter
// takes every one.
func TestSOCKS5Shadow_WouldBlockLogIsRateLimited(t *testing.T) {
	prevLast := socks5WouldBlockLogLast.Load()
	prevWindow := socks5WouldBlockLogWindowNanos.Load()
	t.Cleanup(func() {
		socks5WouldBlockLogLast.Store(prevLast)
		socks5WouldBlockLogWindowNanos.Store(prevWindow)
	})
	socks5WouldBlockLogWindowNanos.Store(int64(time.Hour))
	socks5WouldBlockLogLast.Store(0)
	allowed := 0
	for i := 0; i < 50; i++ {
		if socks5WouldBlockLogAllowed() {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("a burst inside one window logged %d lines, want 1", allowed)
	}
	// A clock that went backwards re-arms rather than silencing.
	socks5WouldBlockLogLast.Store(time.Now().Add(time.Hour).UnixNano())
	if !socks5WouldBlockLogAllowed() {
		t.Fatal("a last-log stamp in the future must re-arm, not suppress")
	}
}

// ── Log hygiene (SEC-SOCKS5-LOG-1 extended to the shadow line) ──────────────

// TestSOCKS5Shadow_WouldBlockLogCannotForgeLines drives the shadow would-block
// line with every hostile DOMAINNAME shape and a hostile rule name, and
// requires no raw control byte and no line the proxy did not emit.
func TestSOCKS5Shadow_WouldBlockLogCannotForgeLines(t *testing.T) {
	for _, tc := range controlBytePayloads {
		t.Run(tc.name, func(t *testing.T) {
			setupProxyTest(t)
			sink := captureLoggerForTest(t) // BEFORE the listener: see captureLoggerForTest
			useSOCKS5PolicyModeForTest(t, socks5PolicyShadow)
			openSOCKS5WouldBlockLogForTest(t)
			installPolicyForTest(t, []PolicyRule{{
				Priority: 1, Name: "forge\nSOCKS5 OK 10.0.0.9 -> bank.example.com:443", DestFQDN: "*", Action: ActionDrop,
			}}, "deny")
			// The SSRF guard after the shadow hook must not reach real DNS.
			t.Cleanup(ssrf.SetLookupHostForTest(func(context.Context, string) ([]string, error) {
				return nil, errors.New("no DNS in this test")
			}))

			ln := startSOCKS5Listener(t)
			socks5ConnectRaw(t, ln.Addr().String(), tc.host, 443)

			got := waitForLogContaining(t, sink, "SOCKS5 POLICY_WOULD_BLOCK")
			assertNoRawControlBytes(t, got)
			wouldBlock := 0
			for _, line := range strings.Split(got, "\n") {
				if strings.TrimSpace(line) == "" {
					continue
				}
				if !strings.HasPrefix(line, "SOCKS5 ") {
					t.Errorf("forged log record %q", line)
				}
				if strings.HasPrefix(line, "SOCKS5 POLICY_WOULD_BLOCK") {
					wouldBlock++
				}
			}
			if wouldBlock != 1 {
				t.Errorf("want exactly one POLICY_WOULD_BLOCK record, got %d:\n%q", wouldBlock, got)
			}
		})
	}
}

// TestSOCKS5Shadow_WouldBlockLogStillNamesTheHost is the control for the gate
// above: an ordinary destination must still be identifiable.
func TestSOCKS5Shadow_WouldBlockLogStillNamesTheHost(t *testing.T) {
	setupProxyTest(t)
	sink := captureLoggerForTest(t)
	useSOCKS5PolicyModeForTest(t, socks5PolicyShadow)
	openSOCKS5WouldBlockLogForTest(t)
	installPolicyForTest(t, nil, "deny")
	t.Cleanup(ssrf.SetLookupHostForTest(func(context.Context, string) ([]string, error) {
		return nil, errors.New("no DNS in this test")
	}))
	ln := startSOCKS5Listener(t)
	socks5ConnectRaw(t, ln.Addr().String(), "shadow-named.example.com", 443)
	got := waitForLogContaining(t, sink, "SOCKS5 POLICY_WOULD_BLOCK")
	if !strings.Contains(got, `"shadow-named.example.com"`) || !strings.Contains(got, "reason=default") {
		t.Errorf("the would-block line must name the destination and the reason; got %q", got)
	}
}

// ── Configuration ──────────────────────────────────────────────────────────

func loadConfigForTest(t *testing.T, yaml string) (*FileConfig, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return loadFileConfig(path)
}

// TestSOCKS5PolicyMode_ConfigKey pins the YAML contract: absent → legacy,
// legacy/shadow accepted, enforce rejected by name, anything else rejected.
func TestSOCKS5PolicyMode_ConfigKey(t *testing.T) {
	cases := []struct {
		name, yaml string
		want       socks5PolicyMode
		wantErr    string
	}{
		{"absent", "proxy:\n  socks5_port: 1080\n", socks5PolicyLegacy, ""},
		{"legacy", "proxy:\n  socks5_policy_mode: legacy\n", socks5PolicyLegacy, ""},
		{"shadow", "proxy:\n  socks5_policy_mode: shadow\n", socks5PolicyShadow, ""},
		{"enforce_not_available", "proxy:\n  socks5_policy_mode: enforce\n", 0, "not available"},
		{"garbage", "proxy:\n  socks5_policy_mode: observe\n", 0, `got "observe"`},
		{"case_sensitive", "proxy:\n  socks5_policy_mode: Shadow\n", 0, `got "Shadow"`},
		{"empty_string_is_absent", "proxy:\n  socks5_policy_mode: \"\"\n", socks5PolicyLegacy, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fc, err := loadConfigForTest(t, c.yaml)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) || !strings.Contains(err.Error(), socks5PolicyModeKey) {
					t.Fatalf("load error = %v, want one naming %s and containing %q", err, socks5PolicyModeKey, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			got, perr := parseSOCKS5PolicyMode(fc.Proxy.SOCKS5PolicyMode)
			if perr != nil || got != c.want {
				t.Fatalf("mode = %v (%v), want %v", got, perr, c.want)
			}
		})
	}
}

// TestInstallSOCKS5PolicyMode pins the startup install: legacy logs nothing
// (byte-identical startup output), shadow installs and announces itself, and
// shadow without a listener says it has no effect.
func TestInstallSOCKS5PolicyMode(t *testing.T) {
	cases := []struct {
		raw        string
		listener   bool
		want       socks5PolicyMode
		wantLogSub string
	}{
		{"", true, socks5PolicyLegacy, ""},
		{"legacy", true, socks5PolicyLegacy, ""},
		{"shadow", true, socks5PolicyShadow, "NEVER refused"},
		{"shadow", false, socks5PolicyShadow, "listener is disabled"},
	}
	for _, c := range cases {
		t.Run(c.raw+"/"+strconv.FormatBool(c.listener), func(t *testing.T) {
			sink := captureLoggerForTest(t)
			useSOCKS5PolicyModeForTest(t, socks5PolicyLegacy)
			installSOCKS5PolicyMode(c.raw, c.listener)
			if got := loadSOCKS5PolicyMode(); got != c.want {
				t.Fatalf("installed %v, want %v", got, c.want)
			}
			logs := sink.String()
			if c.wantLogSub == "" && logs != "" {
				t.Fatalf("legacy install logged %q; startup output must be unchanged", logs)
			}
			if c.wantLogSub != "" && !strings.Contains(logs, c.wantLogSub) {
				t.Fatalf("install log %q missing %q", logs, c.wantLogSub)
			}
		})
	}
}

// TestSOCKS5Shadow_HandlerCannotBranchOnVerdict is the structural half of
// "shadow never blocks": the hook returns nothing, so no future edit can make
// handleSOCKS5 act on the verdict without changing this signature first.
func TestSOCKS5Shadow_HandlerCannotBranchOnVerdict(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "socks5.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(src, []byte("\tsocks5ShadowPolicy(clientIP, host, atyp)\n")) {
		t.Fatal("handleSOCKS5 must call socks5ShadowPolicy as a bare statement (its result, if any, unused)")
	}
	// Compile-time: assigning to a func type with no results fails to build if
	// the hook ever grows a return value.
	if !acceptsResultlessHook(socks5ShadowPolicy) {
		t.Fatal("socks5ShadowPolicy is nil")
	}
}

// acceptsResultlessHook only type-checks its argument: a hook with a result
// does not convert to this parameter type.
func acceptsResultlessHook(h func(clientIP, host string, atyp byte)) bool { return h != nil }
