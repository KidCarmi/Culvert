package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// ─────────────────────────────────────────────────────────────────────────────
// SWG-901 — proxy.socks5_policy_mode: enforce.
//
// What these tests pin, and why each is here:
//   - the per-action table over a REAL handshake: Drop is an RST with no reply,
//     Block_Page/Redirect/unknown action/default deny reply 0x02, zero rules
//     with the startup-derived default allows, Allow connects, and an Allow
//     rule that requires TLS inspection is refused (inspection_unsupported)
//     unless the GENERIC SSL bypass list names the host;
//   - enforce charges what CONNECT charges (rule hit counter, ruleMet,
//     statBlocked, one request-log entry with rule/ID/identity/auth source);
//   - shadow predicts the inspection refusal and still serves the connection;
//   - ATYP IPv4 vs domain, IPv6 brackets;
//   - log hygiene for every enforce refusal line.
// The differential oracle against the CONNECT dispatcher (with its negative
// controls) is in socks5_parity_test.go.
// ─────────────────────────────────────────────────────────────────────────────

// socks5Attempt is what one client observes and what the operator records.
type socks5Attempt struct {
	reply   byte  // SOCKS5 REP, valid when readErr == nil
	readErr error // non-nil when no reply arrived (Drop's RST)
	conn    net.Conn
}

// socks5Try performs the no-auth greeting and a CONNECT, returning the reply or
// the read error (a Drop answers with an RST, not a reply).
func socks5Try(t *testing.T, addr string, atyp byte, host string, port uint16) socks5Attempt {
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
	return socks5SendRequest(t, conn, atyp, host, port)
}

// socks5SendRequest sends the CONNECT frame on an already-negotiated conn.
func socks5SendRequest(t *testing.T, conn net.Conn, atyp byte, host string, port uint16) socks5Attempt {
	t.Helper()
	if _, err := conn.Write(socks5RequestFrame(t, atyp, host, port)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return socks5Attempt{readErr: err, conn: conn}
	}
	return socks5Attempt{reply: reply[1], conn: conn}
}

// socks5Entry waits for the SOCKS5 request-log entry for (host, status).
func socks5Entry(t *testing.T, host, status string) *LogEntry {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries := logGet()
		for i := range entries {
			if entries[i].Method == "SOCKS5" && entries[i].Host == host && entries[i].Status == status {
				return &entries[i]
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no SOCKS5 %s request-log entry for %q", status, host)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// enforceEnv is one enforce-mode listener over a rulebase, with the loopback
// echo server as the reachable destination.
type enforceEnv struct {
	addr string
	port uint16
	logs *syncBuf
}

func newEnforceEnv(t *testing.T, mode socks5PolicyMode, rules []PolicyRule, defaultAction string) enforceEnv {
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
	return enforceEnv{addr: ln.Addr().String(), port: port, logs: sink}
}

// enforceCase is one row of the action table. Every row's destination is the
// loopback echo server, so an allowed row really connects.
type enforceCase struct {
	name          string
	rules         []PolicyRule
	defaultAction string
	atyp          byte
	host          string
	bypass        []string // SSL bypass patterns installed for the row
	wantReply     byte     // 0xFF = no reply (RST)
	wantStatus    string   // request-log status
	wantRule      string
	wantAction    string
	wantReason    string // counter reason
}

const socks5NoReply byte = 0xFF

func socks5InspectRule(name, host string) PolicyRule {
	return PolicyRule{Priority: 1, Name: name, DestFQDN: host, Action: ActionAllow, SSLAction: SSLInspect}
}

var enforceTableCases = []enforceCase{
	{"drop_rst", []PolicyRule{{Priority: 1, Name: "e-drop", DestFQDN: "localhost", Action: ActionDrop}},
		"allow", socks5ATYPDomain, "localhost", nil, socks5NoReply, "POLICY_DROP", "e-drop", "Drop", socks5ReasonRule},
	{"block_page", []PolicyRule{{Priority: 1, Name: "e-block", DestFQDN: "*", Action: ActionBlockPage}},
		"allow", socks5ATYPDomain, "localhost", nil, 0x02, "POLICY_BLOCK", "e-block", "Block_Page", socks5ReasonRule},
	{"redirect", []PolicyRule{{Priority: 1, Name: "e-redirect", DestFQDN: "localhost", Action: ActionRedirect, RedirectURL: "https://portal.example.com/"}},
		"allow", socks5ATYPDomain, "localhost", nil, 0x02, "POLICY_REDIRECT", "e-redirect", "Redirect", socks5ReasonRule},
	{"default_deny_with_rules", []PolicyRule{{Priority: 1, Name: "e-other", DestFQDN: "other.example.com", Action: ActionAllow}},
		"deny", socks5ATYPDomain, "localhost", nil, 0x02, "POLICY_DEFAULT_DENY", "", "", socks5ReasonDefault},
	{"allow_rule_connects", []PolicyRule{{Priority: 1, Name: "e-allow", DestFQDN: "localhost", Action: ActionAllow}},
		"deny", socks5ATYPDomain, "localhost", nil, 0x00, "OK", "e-allow", "Allow", socks5ReasonRule},
	{"allow_inspect_refused", []PolicyRule{socks5InspectRule("e-inspect", "localhost")},
		"deny", socks5ATYPDomain, "localhost", nil, 0x02, "POLICY_BLOCK", "e-inspect", "inspection_unsupported", socks5ReasonInspection},
	{"allow_inspect_on_generic_bypass_list", []PolicyRule{socks5InspectRule("e-inspect-bypassed", "localhost")},
		"deny", socks5ATYPDomain, "localhost", []string{"localhost"}, 0x00, "OK", "e-inspect-bypassed", "Allow", socks5ReasonRule},
	{"allow_bypass_ssl_connects", []PolicyRule{{Priority: 1, Name: "e-bypass", DestFQDN: "localhost", Action: ActionAllow, SSLAction: SSLBypass}},
		"deny", socks5ATYPDomain, "localhost", nil, 0x00, "OK", "e-bypass", "Allow", socks5ReasonRule},
	{"ipv4_atyp_rule", []PolicyRule{{Priority: 1, Name: "e-block-ip", DestFQDN: "127.0.0.1", Action: ActionBlockPage}},
		"allow", socks5ATYPIPv4, "127.0.0.1", nil, 0x02, "POLICY_BLOCK", "e-block-ip", "Block_Page", socks5ReasonRule},
	// The same destination by name is not the IP-literal rule's destination
	// (FQDN rules match the text the client sent, as for a CONNECT).
	{"domain_atyp_misses_ip_rule", []PolicyRule{{Priority: 1, Name: "e-block-ip", DestFQDN: "127.0.0.1", Action: ActionBlockPage}},
		"allow", socks5ATYPDomain, "localhost", nil, 0x00, "OK", "default-allow", "Allow", socks5ReasonDefault},
}

// TestSOCKS5Enforce_ActionTable drives every enforce outcome over a real
// handshake and checks the client's view, the request log and the counters.
func TestSOCKS5Enforce_ActionTable(t *testing.T) {
	for _, tc := range enforceTableCases {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnforceEnv(t, socks5PolicyEnforce, tc.rules, tc.defaultAction)
			withSSLBypassForTest(t, tc.bypass)
			blocked0 := atomic.LoadInt64(&statBlocked)
			before := readShadowCounters()
			got := socks5Try(t, env.addr, tc.atyp, tc.host, env.port)
			assertEnforceReply(t, got, tc.wantReply)
			if tc.wantReply == 0x00 {
				assertTunnelEchoes(t, got.conn)
			}
			e := socks5Entry(t, tc.host, tc.wantStatus)
			assertEnforceEntry(t, e, tc)
			assertEnforceCounters(t, readShadowCounters().minus(before), tc)
			if refused := tc.wantReply != 0x00; refused != (atomic.LoadInt64(&statBlocked) > blocked0) {
				t.Errorf("statBlocked moved=%v, want %v", !refused, refused)
			}
		})
	}
}

func withSSLBypassForTest(t *testing.T, patterns []string) {
	t.Helper()
	prev := sslBypass.List()
	if err := sslBypass.Set(patterns); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sslBypass.Set(prev) })
}

func assertEnforceReply(t *testing.T, got socks5Attempt, want byte) {
	t.Helper()
	if want == socks5NoReply {
		if got.readErr == nil {
			t.Fatalf("Drop must not reply; got REP 0x%02x", got.reply)
		}
		if !errors.Is(got.readErr, syscall.ECONNRESET) {
			t.Fatalf("Drop must reset the connection (RST); read error = %v", got.readErr)
		}
		return
	}
	if got.readErr != nil {
		t.Fatalf("no reply: %v", got.readErr)
	}
	if got.reply != want {
		t.Fatalf("SOCKS5 REP = 0x%02x, want 0x%02x", got.reply, want)
	}
}

func assertEnforceEntry(t *testing.T, e *LogEntry, tc enforceCase) {
	t.Helper()
	if e.RuleMatched != tc.wantRule || e.ActionTaken != tc.wantAction {
		t.Errorf("entry rule/action = %q/%q, want %q/%q", e.RuleMatched, e.ActionTaken, tc.wantRule, tc.wantAction)
	}
	wantID := tc.wantRule != "" && tc.wantRule != "default-allow"
	if (e.RuleID != "") != wantID {
		t.Errorf("entry ruleId = %q, want present=%v", e.RuleID, wantID)
	}
	if e.AuthSource != socks5UnauthSource || e.Identity != "" {
		t.Errorf("entry identity/auth_source = %q/%q, want \"\"/unauth for a NO-AUTH client", e.Identity, e.AuthSource)
	}
}

func assertEnforceCounters(t *testing.T, d shadowCounters, tc enforceCase) {
	t.Helper()
	var want shadowCounters
	v := 0
	if tc.wantReply != 0x00 {
		v = 1
	}
	want.enforce[v][socks5ReasonIndex(tc.wantReason)] = 1
	switch tc.atyp {
	case socks5ATYPIPv4:
		want.atyp[0] = 1
	case socks5ATYPIPv6:
		want.atyp[1] = 1
	default:
		want.atyp[2] = 1
	}
	if d != want {
		t.Errorf("counter delta = %+v, want %+v", d, want)
	}
}

// TestSOCKS5Enforce_ZeroRulesFollowsStartupDefault pins the default-action
// errata through the startup derivation itself: an empty default_action with
// zero rules allows, and with one rule denies (it is not SOCKS5-specific).
func TestSOCKS5Enforce_ZeroRulesFollowsStartupDefault(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []PolicyRule
		want  byte
	}{
		{"zero_rules_allow", nil, 0x00},
		{"one_rule_deny", []PolicyRule{{Priority: 1, Name: "z-other", DestFQDN: "other.example.com", Action: ActionAllow}}, 0x02},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnforceEnv(t, socks5PolicyEnforce, tc.rules, "deny")
			loadRewriteAndDefaultAction(rewriteDefaultActionStartupConfig{}, len(tc.rules))
			got := socks5Try(t, env.addr, socks5ATYPDomain, "localhost", env.port)
			assertEnforceReply(t, got, tc.want)
		})
	}
}

// TestSOCKS5Enforce_UnknownActionFailsClosed installs a rule whose action this
// build does not recognise (ReplaceAll refuses one; a restored backup or a
// newer Control Plane can still deliver it) and requires a 0x02 refusal with
// the stored action recorded — and that the lower-priority Allow is NOT reached.
func TestSOCKS5Enforce_UnknownActionFailsClosed(t *testing.T) {
	env := newEnforceEnv(t, socks5PolicyEnforce, nil, "allow")
	policyStore.mu.Lock()
	policyStore.rules = []*PolicyRule{
		{Priority: 1, Name: "e-unknown", DestFQDN: "localhost", Action: PolicyAction("Quarantine")},
		{Priority: 2, Name: "e-allow-below", DestFQDN: "*", Action: ActionAllow},
	}
	policyStore.mu.Unlock()
	got := socks5Try(t, env.addr, socks5ATYPDomain, "localhost", env.port)
	assertEnforceReply(t, got, 0x02)
	e := socks5Entry(t, "localhost", "POLICY_BLOCK")
	if e.RuleMatched != "e-unknown" || e.ActionTaken != "Quarantine" {
		t.Errorf("entry = %q/%q, want e-unknown/Quarantine", e.RuleMatched, e.ActionTaken)
	}
}

// TestSOCKS5Enforce_ChargesRuleAccounting is the inverse of shadow's
// non-accounting test: enforce IS the decision path, so a matched rule's hit
// counter, last-hit stamp and ruleMet cell move once per connection — for an
// allowed and for a refused connection alike.
func TestSOCKS5Enforce_ChargesRuleAccounting(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action PolicyAction
		reply  byte
	}{{"allow", ActionAllow, 0x00}, {"block", ActionBlockPage, 0x02}} {
		t.Run(tc.name, func(t *testing.T) {
			ruleName := "e-accounting-" + tc.name
			env := newEnforceEnv(t, socks5PolicyEnforce, []PolicyRule{{Priority: 1, Name: ruleName, DestFQDN: "localhost", Action: tc.action}}, "deny")
			hits0, met0 := ruleHitsForTest(t, ruleName), ruleMetHitsForTest(ruleName)
			for i := 0; i < 2; i++ {
				got := socks5Try(t, env.addr, socks5ATYPDomain, "localhost", env.port)
				assertEnforceReply(t, got, tc.reply)
			}
			if hits := ruleHitsForTest(t, ruleName); hits != hits0+2 {
				t.Errorf("rule hit counter %d→%d, want +2", hits0, hits)
			}
			if met := ruleMetHitsForTest(ruleName); met != met0+2 {
				t.Errorf("ruleMet %d→%d, want +2", met0, met)
			}
		})
	}
}

func ruleHitsForTest(t *testing.T, name string) int64 {
	t.Helper()
	rules := policyStore.List()
	for i := range rules {
		if rules[i].Name == name {
			return rules[i].HitCount
		}
	}
	t.Fatalf("rule %q missing", name)
	return 0
}

// TestSOCKS5Enforce_IPv6BracketsStripped proves an ATYP 0x04 destination meets
// the rule written as CONNECT sees it (no brackets).
func TestSOCKS5Enforce_IPv6BracketsStripped(t *testing.T) {
	env := newEnforceEnv(t, socks5PolicyEnforce, []PolicyRule{{Priority: 1, Name: "e-block-v6", DestFQDN: "::1", Action: ActionBlockPage}}, "allow")
	got := socks5Try(t, env.addr, socks5ATYPIPv6, "[::1]", env.port)
	assertEnforceReply(t, got, 0x02)
	if e := socks5Entry(t, "[::1]", "POLICY_BLOCK"); e.RuleMatched != "e-block-v6" {
		t.Errorf("rule = %q, want e-block-v6", e.RuleMatched)
	}
}

// TestSOCKS5Enforce_EvaluatorPanicFailsClosed is the enforce twin of the shadow
// panic test: here a panic must NOT be absorbed — the connection is closed
// without a success reply (handleSOCKS5's recoverGoroutine), never relayed.
func TestSOCKS5Enforce_EvaluatorPanicFailsClosed(t *testing.T) {
	setupProxyTest(t)
	captureLoggerForTest(t)
	useSOCKS5PolicyModeForTest(t, socks5PolicyEnforce)
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackSOCKS5ForTest(t)
	prevStore := policyStore
	policyStore = nil
	t.Cleanup(func() { policyStore = prevStore })
	port := startEchoServerForTest(t)
	ln := startSOCKS5Listener(t)
	got := socks5Try(t, ln.Addr().String(), socks5ATYPDomain, "localhost", port)
	if got.readErr == nil && got.reply == 0x00 {
		t.Fatal("enforce served a connection after an evaluator panic; it must fail closed")
	}
}

// TestSOCKS5Shadow_InspectRuleNeverRefuses: shadow predicts the
// inspection_unsupported refusal but still serves the connection.
func TestSOCKS5Shadow_InspectRuleNeverRefuses(t *testing.T) {
	env := newEnforceEnv(t, socks5PolicyShadow, []PolicyRule{socks5InspectRule("s-inspect", "localhost")}, "deny")
	withSSLBypassForTest(t, nil)
	before := readShadowCounters()
	got := socks5Try(t, env.addr, socks5ATYPDomain, "localhost", env.port)
	assertEnforceReply(t, got, 0x00)
	assertTunnelEchoes(t, got.conn)
	if d := readShadowCounters().minus(before); d.decisions[1][2] != 1 || d.enforce != ([2][3]int64{}) {
		t.Errorf("shadow must record one would_block/inspection_unsupported and no enforce decision: %+v", d)
	}
	logs := waitForLogContaining(t, env.logs, "SOCKS5 POLICY_WOULD_BLOCK")
	if !strings.Contains(logs, "reason=inspection_unsupported") {
		t.Errorf("would-block line must name the reason; got %q", logs)
	}
}

// ── Log hygiene (SEC-SOCKS5-LOG-1 extended to the enforce lines) ────────────

// TestSOCKS5Enforce_RefusalLogsCannotForgeLines drives each enforce refusal
// line (default deny, a rule refusal with a hostile rule name, the inspection
// refusal) with every hostile DOMAINNAME shape.
func TestSOCKS5Enforce_RefusalLogsCannotForgeLines(t *testing.T) {
	hostile := "forge\nSOCKS5 OK 10.0.0.9 -> bank.example.com:443"
	for _, rc := range []struct {
		name  string
		rules []PolicyRule
		def   string
		want  string
	}{
		{"default_deny", nil, "deny", "SOCKS5 POLICY_DEFAULT_DENY"},
		{"rule_block", []PolicyRule{{Priority: 1, Name: hostile, DestFQDN: "*", Action: ActionBlockPage}}, "allow", "SOCKS5 POLICY_BLOCK"},
		{"rule_drop", []PolicyRule{{Priority: 1, Name: hostile, DestFQDN: "*", Action: ActionDrop}}, "allow", "SOCKS5 POLICY_DROP"},
		{"inspection", []PolicyRule{{Priority: 1, Name: hostile, DestFQDN: "*", Action: ActionAllow, SSLAction: SSLInspect}}, "deny", "inspection_unsupported"},
	} {
		for _, tc := range controlBytePayloads {
			t.Run(rc.name+"/"+tc.name, func(t *testing.T) {
				setupProxyTest(t)
				sink := captureLoggerForTest(t)
				useSOCKS5PolicyModeForTest(t, socks5PolicyEnforce)
				installPolicyForTest(t, rc.rules, rc.def)
				withSSLBypassForTest(t, nil)
				t.Cleanup(ssrf.SetLookupHostForTest(func(context.Context, string) ([]string, error) {
					return nil, errors.New("no DNS in this test")
				}))
				ln := startSOCKS5Listener(t)
				socks5ConnectRaw(t, ln.Addr().String(), tc.host, 443)
				assertOnlySOCKS5Lines(t, waitForLogContaining(t, sink, rc.want))
			})
		}
	}
}

// assertOnlySOCKS5Lines requires no raw control byte and no line the proxy did
// not emit (every SOCKS5 decision line starts with "SOCKS5 ").
func assertOnlySOCKS5Lines(t *testing.T, got string) {
	t.Helper()
	assertNoRawControlBytes(t, got)
	for _, line := range strings.Split(got, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, "SOCKS5 ") {
			t.Errorf("forged log record %q", line)
		}
	}
}
