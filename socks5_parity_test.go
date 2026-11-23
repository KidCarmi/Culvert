package main

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// ─────────────────────────────────────────────────────────────────────────────
// SWG-901 — SOCKS5 parity harness: differential oracles against the shared
// engines, each with a corpus and a NEGATIVE CONTROL that proves the oracle can
// fail. Kept apart from the behaviour tests (socks5_policy_enforce_test.go,
// socks5_identity_test.go, socks5_threatfeed_test.go) so verification and
// production changes are reviewable independently.
//
//   - Stage-2 policy: the enforce (and shadow) verdict equals the REAL CONNECT
//     dispatcher's verdict — Evaluate + applyPolicyDecision + the SSL decision —
//     for every (principal, host, default action). Controls: an evaluator
//     bypass, and a path that drops the resolved identity.
//   - Threat feed: SOCKS5's content gate refuses exactly where CONNECT's
//     pre-dispatch gate does. Control: a gate that skips the feed.
//   - Identity: every credential SOCKS5 accepts resolves to the principal HTTP
//     proxy Basic resolves for it, and SOCKS5 refuses exactly HTTP's refusals
//     plus the credentials RFC 1929 must not accept (the admin-console pair,
//     an OIDC token). Control: the removed SOCKS5-only check disagrees.
// ─────────────────────────────────────────────────────────────────────────────

// ── Differential: enforce verdict == CONNECT verdict ────────────────────────

// identityDiffRules extends differentialRules with identity-, group-, auth
// source- and inspection-scoped rules, the conditions stage 3 makes reachable.
func identityDiffRules() []*PolicyRule {
	rules := []*PolicyRule{
		{Priority: 1, Name: "i-allow-alice", SourceIdentity: "alice", DestFQDN: "*.id.example", Action: ActionAllow},
		{Priority: 2, Name: "i-allow-eng", SourceGroup: "engineering", DestFQDN: "*.id.example", Action: ActionAllow},
		{Priority: 3, Name: "i-drop-unauth", AuthSource: "unauth", DestFQDN: "*.id.example", Action: ActionDrop},
		{Priority: 4, Name: "i-block-id-rest", DestFQDN: "*.id.example", Action: ActionBlockPage},
		{Priority: 5, Name: "i-inspect-ldap", AuthSource: "corp-ad", DestFQDN: "*.tls.example", Action: ActionAllow, SSLAction: SSLInspect},
		{Priority: 6, Name: "i-allow-tls", DestFQDN: "*.tls.example", Action: ActionAllow},
	}
	for i, r := range differentialRules() {
		r.Priority = 100 + i
		rules = append(rules, r)
	}
	return rules
}

// identityPrincipals are the principals of the policy corpus: NO-AUTH, a
// directory user matched by name, a directory user with the group, a directory
// user without it, and a principal from another directory profile.
var identityPrincipals = []ProxyIdentity{
	{ClientIP: "192.0.2.10", AuthSource: socks5UnauthSource},
	{ClientIP: "192.0.2.11", Identity: "alice", AuthSource: "corp-ad"},
	{ClientIP: "10.1.2.3", Identity: "CN=Bob,DC=corp", AuthSource: "corp-ad", Groups: []string{"engineering"}},
	{ClientIP: "192.0.2.12", Identity: "CN=Carol,DC=corp", AuthSource: "corp-ad", Groups: []string{"finance"}},
	{ClientIP: "192.0.2.13", Identity: "dave", AuthSource: "branch-ad"},
}

var identityHosts = []struct{ socksHost, connectHost string }{
	{"app.id.example", "app.id.example"},
	{"web.tls.example", "web.tls.example"},
	{"casino.gambling.example", "casino.gambling.example"},
	{"app.corp.example", "app.corp.example"},
	{"redirect.example", "redirect.example"},
	{"weird.example", "weird.example"},
	{"[2001:db8::66]", "2001:db8::66"},
	{"198.51.100.7", "198.51.100.7"},
	{"unmatched.example.net", "unmatched.example.net"},
}

// connectDecision is the REAL CONNECT decision for one principal and host:
// Evaluate with the principal, applyPolicyDecision on a CONNECT, then the SSL
// decision handleRequest takes for an allowed tunnel.
func connectDecision(t *testing.T, who ProxyIdentity, host string) string {
	t.Helper()
	match := policyStore.Evaluate(who.ClientIP, who.Identity, who.AuthSource, host, who.Groups)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "http://"+net.JoinHostPort(host, "443"), http.NoBody)
	r.Host = net.JoinHostPort(host, "443")
	w := httptest.NewRecorder()
	if _, terminal := applyPolicyDecision(w, r, who.ClientIP, host, "req-swg901-enforce", who.Identity, AuthLogFields{AuthSource: who.AuthSource}, match); terminal {
		return "block"
	}
	if resolveSSLDecision(match, host, who.ClientIP).Action == SSLInspect {
		return "inspect"
	}
	return "allow"
}

// discardConn is the conn the SOCKS5 gates reply on in the differentials:
// replies are discarded (the verdict is read from the return value).
type discardConn struct{ net.Conn }

func (discardConn) Write(p []byte) (int, error) { return len(p), nil }

// enforceDecision runs the REAL enforce dispatcher and maps its outcome onto
// the CONNECT labels: allowed → allow; refused for inspection → inspect;
// otherwise → block.
func enforceDecision(who ProxyIdentity, host string) string {
	before := socks5PolicyDecisions[1][1][2].Load()
	if _, ok := socks5EnforcePolicy(discardConn{}, who, host, socks5ATYPDomain); ok {
		return "allow"
	}
	if socks5PolicyDecisions[1][1][2].Load() > before {
		return "inspect"
	}
	return "block"
}

// shadowDecision maps the shadow verdict onto the same labels.
func shadowDecision(who ProxyIdentity, host string) string {
	v := socks5ShadowEvaluate(who, host)
	switch {
	case !v.refuse:
		return "allow"
	case v.reason == socks5ReasonInspection:
		return "inspect"
	}
	return "block"
}

type decisionFn func(who ProxyIdentity, host string) string

// enforceMismatches compares decide against CONNECT over the policy corpus
// under both default actions.
func enforceMismatches(t *testing.T, decide decisionFn) (mismatches []string, tally map[string]int) {
	t.Helper()
	tally = map[string]int{}
	for _, def := range []string{"deny", "allow"} {
		setDefaultPolicyAction(def)
		for _, who := range identityPrincipals {
			for _, h := range identityHosts {
				want := connectDecision(t, who, h.connectHost)
				got := decide(who, h.socksHost)
				tally[want]++
				if got != want {
					mismatches = append(mismatches, def+" "+who.Identity+"/"+who.AuthSource+" "+h.socksHost+": socks5="+got+" connect="+want)
				}
			}
		}
	}
	return mismatches, tally
}

func setupIdentityDifferential(t *testing.T) {
	t.Helper()
	setupProxyTest(t)
	captureLoggerForTest(t)
	snapshotPolicyStoreForTest(t)
	prev := defaultPolicyAction()
	t.Cleanup(func() { setDefaultPolicyAction(prev) })
	t.Cleanup(reqlog.SwapRingForTest())
	withSSLBypassForTest(t, nil)
	policyStore.mu.Lock()
	policyStore.rules = identityDiffRules()
	policyStore.mu.Unlock()
}

// TestSOCKS5Enforce_VerdictEqualsCONNECTVerdict is the differential oracle for
// enforce (and, on the same corpus, for shadow): for every principal, host and
// default action, SOCKS5 decides what CONNECT decides.
func TestSOCKS5Enforce_VerdictEqualsCONNECTVerdict(t *testing.T) {
	setupIdentityDifferential(t)
	for name, decide := range map[string]decisionFn{"enforce": enforceDecision, "shadow": shadowDecision} {
		mismatches, tally := enforceMismatches(t, decide)
		for _, m := range mismatches {
			t.Errorf("%s/CONNECT divergence: %s", name, m)
		}
		// Non-vacuous: every outcome must be exercised substantially.
		if tally["allow"] < 10 || tally["block"] < 20 || tally["inspect"] < 2 {
			t.Fatalf("%s: corpus too one-sided to prove agreement: %v", name, tally)
		}
	}
}

// TestSOCKS5Enforce_DifferentialCatchesBypassAndIdentityLoss is the NEGATIVE
// CONTROL: a SOCKS5 path that skips the evaluator (default action only), and
// one that evaluates every client as unauth (the pre-stage-3 behaviour), must
// both be caught by the oracle above.
func TestSOCKS5Enforce_DifferentialCatchesBypassAndIdentityLoss(t *testing.T) {
	setupIdentityDifferential(t)
	controls := map[string]decisionFn{
		"evaluator_bypassed": func(ProxyIdentity, string) string {
			if defaultPolicyAllows() {
				return "allow"
			}
			return "block"
		},
		"identity_dropped": func(who ProxyIdentity, host string) string {
			return enforceDecision(ProxyIdentity{ClientIP: who.ClientIP, AuthSource: socks5UnauthSource}, host)
		},
	}
	for name, decide := range controls {
		if mismatches, _ := enforceMismatches(t, decide); len(mismatches) == 0 {
			t.Errorf("the differential oracle did not detect the %s control; it cannot prove SOCKS5 uses the CONNECT evaluator with the resolved principal", name)
		}
	}
}

// ── Differential: threat feed ───────────────────────────────────────────────

// threatCorpus is (SOCKS5 wire host, CONNECT host).
var threatCorpus = []struct{ socksHost, connectHost string }{
	{"evil-feed.example", "evil-feed.example"},
	{"EVIL-FEED.example", "EVIL-FEED.example"},
	{"evil-feed.example.", "evil-feed.example."},
	{"sub.evil-feed.example", "sub.evil-feed.example"},
	{"[2001:db8::bad]", "2001:db8::bad"},
	{"[2001:db8::bae]", "2001:db8::bae"},
	{"clean.example", "clean.example"},
	{"198.51.100.9", "198.51.100.9"},
}

// connectThreatBlocked runs the REAL CONNECT pre-dispatch gate.
func connectThreatBlocked(t *testing.T, host string) bool {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "http://"+host+":443", http.NoBody)
	r.Host = host + ":443"
	status, _ := preDispatchBlocked(httptest.NewRecorder(), r, "192.0.2.10", host, "req-swg901-threat", "", AuthLogFields{})
	return status == "THREAT_BLOCKED"
}

// socks5ThreatBlocked runs the REAL SOCKS5 content gate and reports whether the
// refusal it recorded was the threat feed's. The verdict is read from the
// request log, the operator-visible record.
func socks5ThreatBlocked(host string) bool {
	return socks5ContentBlocked(discardConn{}, ProxyIdentity{ClientIP: "192.0.2.10", AuthSource: socks5UnauthSource}, host) &&
		lastSOCKS5Status(host) == "THREAT_BLOCKED"
}

func lastSOCKS5Status(host string) string {
	entries := logGet()
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].Method == "SOCKS5" && entries[i].Host == host {
			return entries[i].Status
		}
	}
	return ""
}

func threatMismatches(t *testing.T, socks func(host string) bool) (mismatches []string, blocked int) {
	t.Helper()
	for _, c := range threatCorpus {
		want := connectThreatBlocked(t, c.connectHost)
		if got := socks(c.socksHost); got != want {
			mismatches = append(mismatches, c.socksHost+": socks5="+boolWord(got)+" connect="+boolWord(want))
		}
		if want {
			blocked++
		}
	}
	return mismatches, blocked
}

func boolWord(b bool) string {
	if b {
		return "blocked"
	}
	return "passed"
}

func setupThreatDifferential(t *testing.T) {
	t.Helper()
	setupProxyTest(t)
	captureLoggerForTest(t)
	withDomainThreatFeed(t, threatDomains)
	t.Cleanup(reqlog.SwapRingForTest())
}

// TestSOCKS5ThreatFeed_VerdictEqualsCONNECT is the differential oracle: SOCKS5
// refuses on the feed exactly where CONNECT's pre-dispatch gate does.
func TestSOCKS5ThreatFeed_VerdictEqualsCONNECT(t *testing.T) {
	setupThreatDifferential(t)
	mismatches, blocked := threatMismatches(t, socks5ThreatBlocked)
	for _, m := range mismatches {
		t.Errorf("SOCKS5/CONNECT threat divergence: %s", m)
	}
	if blocked < 3 || blocked == len(threatCorpus) {
		t.Fatalf("corpus must exercise both outcomes: %d of %d blocked", blocked, len(threatCorpus))
	}
}

// TestSOCKS5ThreatFeed_DifferentialCatchesASkippedFeed is the NEGATIVE CONTROL:
// a SOCKS5 gate without the feed (the pre-stage-3 behaviour) is caught.
//
// (Handing the feed the bracketed IPv6 wire form is NOT a divergence today —
// the feed's own normalisation strips brackets — so it is no control; the
// gate strips them anyway so the feed sees CONNECT's exact input.)
func TestSOCKS5ThreatFeed_DifferentialCatchesASkippedFeed(t *testing.T) {
	setupThreatDifferential(t)
	if mismatches, _ := threatMismatches(t, func(string) bool { return false }); len(mismatches) == 0 {
		t.Error("the threat differential did not detect a SOCKS5 gate that skips the feed")
	}
}

// ── Differential: shared credential resolver ────────────────────────────────

// socks5NegotiateInProcess runs the real socks5Negotiate over an in-memory pipe
// with a USER/PASS client and returns what the server resolved and the RFC
// 1929 status the client read.
func socks5NegotiateInProcess(t *testing.T, user, pass string) (who ProxyIdentity, ok bool, status byte) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	type result struct {
		who ProxyIdentity
		ok  bool
	}
	done := make(chan result, 1)
	go func() {
		w, k := socks5Negotiate(server, "198.51.100.40")
		done <- result{w, k}
	}()
	status = socks5HandshakeAuth(t, client, user, pass)
	r := <-done
	return r.who, r.ok, status
}

// httpBasicOutcome runs the real HTTP Stage-1 pipeline with Basic credentials.
func httpBasicOutcome(t *testing.T, user, pass string) (out authOutcome, proceed bool, code int) {
	t.Helper()
	r := makeRequest("http://basic.example.test/", nil)
	r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	w := httptest.NewRecorder()
	out, proceed = resolveRequestAuth(w, r, "127.0.0.1", "swg901-identity")
	return out, proceed, w.Code
}

// credentialCase is one credential and whether RFC 1929 must refuse it even
// when HTTP Basic accepts it (socks5Excluded).
type credentialCase struct {
	user, pass     string
	socks5Excluded bool
}

var credentialCorpus = []credentialCase{
	{"admin", "admin-pass", true},         // admin-console pair: HTTP accepts, SOCKS5 never
	{"admin", "wrong", false},             // admin-console, bad password
	{"alice", "ldap-pass", false},         // registry LDAP
	{"alice", "wrong", false},             // registry LDAP, bad password
	{"carol@corp.example", "tok-1", true}, // OIDC token: HTTP accepts, SOCKS5 never
	{"mallory", "ldap-pass", false},       // unknown user
	{"", "", false},                       // empty
	{"alice", "admin-pass", false},        // cross-backend password
	{"ADMIN", "admin-pass", false},        // case variant
}

// TestSOCKS5Identity_SharedResolverEqualsHTTPBasic is the differential oracle
// for identity, over a deployment with a local admin, a registry LDAP profile
// and a registry OIDC profile: SOCKS5 accepts a credential iff HTTP Basic does
// and it is not excluded from RFC 1929, and then resolves the same principal.
func TestSOCKS5Identity_SharedResolverEqualsHTTPBasic(t *testing.T) {
	setupMixedCredentialBackends(t)
	accepted := 0
	for _, c := range credentialCorpus {
		out, proceed, _ := httpBasicOutcome(t, c.user, c.pass)
		who, ok, status := socks5NegotiateInProcess(t, c.user, c.pass)
		want := proceed && !c.socks5Excluded
		if ok != want || (status == 0x00) != want {
			t.Errorf("%q: SOCKS5 ok=%v status=0x%02x, want %v (HTTP proceed=%v, excluded=%v)", c.user, ok, status, want, proceed, c.socks5Excluded)
			continue
		}
		if c.socks5Excluded && !proceed {
			t.Errorf("%q: precondition: HTTP must accept the excluded credential, or the exclusion is untested", c.user)
		}
		if !want {
			continue
		}
		accepted++
		if who.Identity != out.identity || who.AuthSource != out.source || !slices.Equal(who.Groups, out.groups) {
			t.Errorf("%q: SOCKS5 principal %q/%q/%v, HTTP %q/%q/%v", c.user,
				who.Identity, who.AuthSource, who.Groups, out.identity, out.source, out.groups)
		}
	}
	if accepted != 1 {
		t.Fatalf("expected exactly the LDAP credential to authenticate SOCKS5, got %d", accepted)
	}
}

// TestSOCKS5Identity_RemovedLegacyCheckDisagrees is the NEGATIVE CONTROL: the
// SOCKS5-only check this stage removed (cfg.VerifyAuthFrom: legacy provider or
// the admin pair, a bool) disagrees with the oracle on both sides — it rejects
// the directory user and accepts the admin-console pair — so the differential
// above can tell the two paths apart.
func TestSOCKS5Identity_RemovedLegacyCheckDisagrees(t *testing.T) {
	setupMixedCredentialBackends(t)
	if cfg.VerifyAuthFrom("198.51.100.40", "alice", "ldap-pass") {
		t.Error("the removed SOCKS5-only check accepts the LDAP user, so it is no control for that row")
	}
	if !cfg.VerifyAuthFrom("198.51.100.40", "admin", "admin-pass") {
		t.Error("the removed SOCKS5-only check rejects the admin pair, so it is no control for that row")
	}
}
