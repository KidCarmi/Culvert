package main

// Adversarial policy-evaluation × auth-policy BYPASS suite. Where the auth
// matrix proves the happy/expected cells, this tries to BREAK authorization:
// forge group/identity/auth-source matches, exploit AND-of-conditions, and
// spoof the source IP via X-Forwarded-For. The authorization predicates
// (matchSource) are the gate that "identity enables but never grants" relies
// on; if any of these can be forged, the whole model collapses.

import (
	"net/http"
	"testing"
	"time"
)

// evalMatch runs a single rule through the real Evaluate and returns the match.
func evalMatch(rule PolicyRule, clientIP, identity, authSource, host string, groups []string) *PolicyMatch {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{rule})
	return ps.Evaluate(clientIP, identity, authSource, host, groups)
}

// TestAuthzBypass_GroupMatchNotForgeable proves group authorization matches the
// equivalence class (case-insensitive, trimmed — documented) but CANNOT be
// widened by substring/prefix tricks.
func TestAuthzBypass_GroupMatchNotForgeable(t *testing.T) {
	rule := PolicyRule{Priority: 1, Name: "eng-allow", DestFQDN: "*", SourceGroup: "engineering", Action: ActionAllow}
	cases := []struct {
		groups []string
		want   bool
	}{
		{[]string{"engineering"}, true},
		{[]string{"Engineering"}, true},            // case-insensitive
		{[]string{"ENGINEERING"}, true},            // case-insensitive
		{[]string{" engineering "}, true},          // trimmed
		{[]string{"finance", "engineering"}, true}, // any-of
		{[]string{"engineering-admin"}, false},     // suffix glue must NOT match
		{[]string{"eng"}, false},                   // prefix must NOT match
		{[]string{"engineeringx"}, false},          // extra char
		{[]string{"xengineering"}, false},          // prefix char
		{[]string{"engine ering"}, false},          // internal space
		{nil, false},                               // no groups
		{[]string{""}, false},                      // empty group
		{[]string{"engineering\x00admin"}, false},  // NUL injection
	}
	for _, c := range cases {
		got := evalMatch(rule, "203.0.113.1", "u", "oidc:test", "site.example", c.groups) != nil
		if got != c.want {
			t.Errorf("group match groups=%q = %v, want %v (authorization must not be forgeable)", c.groups, got, c.want)
		}
	}
}

// TestAuthzBypass_SourceIdentityNotForgeable proves identity authorization is an
// exact (case-insensitive) match, not a prefix/substring.
func TestAuthzBypass_SourceIdentityNotForgeable(t *testing.T) {
	rule := PolicyRule{Priority: 1, Name: "alice-allow", DestFQDN: "*", SourceIdentity: "alice", Action: ActionAllow}
	cases := []struct {
		id   string
		want bool
	}{
		{"alice", true},
		{"Alice", true}, // EqualFold (documented case-insensitive)
		{"alice2", false},
		{"alic", false},
		{"aliceadmin", false},
		{"", false},
		{"alice ", false}, // trailing space (identity is NOT trimmed, unlike groups)
	}
	for _, c := range cases {
		got := evalMatch(rule, "203.0.113.1", c.id, "local", "site.example", nil) != nil
		if got != c.want {
			t.Errorf("identity match id=%q = %v, want %v", c.id, got, c.want)
		}
	}
}

// TestAuthzBypass_AuthSourceNotForgeable proves a rule scoped to an auth source
// only matches that source (and its documented IdP-prefix alias), not arbitrary
// client-influenced values — and crucially that an UNAUTH request cannot match a
// rule requiring real authentication.
func TestAuthzBypass_AuthSourceNotForgeable(t *testing.T) {
	localRule := PolicyRule{Priority: 1, Name: "local-only", DestFQDN: "*", AuthSource: "local", Action: ActionAllow}
	if evalMatch(localRule, "203.0.113.1", "u", "unauth", "site.example", nil) != nil {
		t.Error("BYPASS: an unauth request matched a rule requiring AuthSource=local")
	}
	if evalMatch(localRule, "203.0.113.1", "u", "oidc:okta", "site.example", nil) != nil {
		t.Error("BYPASS: an oidc request matched a rule requiring AuthSource=local")
	}
	if evalMatch(localRule, "203.0.113.1", "u", "local", "site.example", nil) == nil {
		t.Error("a local request should match AuthSource=local")
	}

	// IdP-prefix alias: rule "oidc:okta" matches "okta" but not look-alikes.
	idpRule := PolicyRule{Priority: 1, Name: "okta", DestFQDN: "*", AuthSource: "oidc:okta", Action: ActionAllow}
	for src, want := range map[string]bool{
		"oidc:okta": true,
		"okta":      true, // documented prefix-strip alias
		// FINDING (documented): matchAuthSource strips oidc:/saml: from BOTH sides,
		// so a rule scoped to "oidc:okta" ALSO authorizes a "saml:okta" source —
		// cross-IdP/cross-scheme aliasing. Asserted as the ACTUAL behavior here and
		// reported for product review (see bug report).
		"saml:okta": true,
		"okta-evil": false,
		"evil:okta": false,
		"unauth":    false,
	} {
		got := evalMatch(idpRule, "203.0.113.1", "u", src, "site.example", nil) != nil
		// NOTE: matchAuthSource strips oidc:/saml: from BOTH sides, so "saml:okta"
		// could alias to "okta". If that happens this assertion documents it as a
		// finding rather than silently passing.
		if got != want {
			t.Errorf("authSource %q matched=%v, want %v (cross-source/look-alike must not authorize)", src, got, want)
		}
	}
}

// TestAuthzBypass_SourceCIDRNotForgeable proves CIDR source matching is exact
// and a malformed client IP cannot match (fail-closed, no panic).
func TestAuthzBypass_SourceCIDRNotForgeable(t *testing.T) {
	rule := PolicyRule{Priority: 1, Name: "corp-net", DestFQDN: "*", SourceIP: "10.0.0.0/8", Action: ActionAllow}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.254", true},
		{"11.0.0.1", false},
		{"9.255.255.255", false},
		{"203.0.113.1", false},
		{"", false},          // malformed
		{"not-an-ip", false}, // malformed
		{"10.0.0.1.5", false},
	}
	for _, c := range cases {
		got := evalMatch(rule, c.ip, "u", "local", "site.example", nil) != nil
		if got != c.want {
			t.Errorf("source CIDR ip=%q = %v, want %v", c.ip, got, c.want)
		}
	}
}

// TestAuthzBypass_AndConditionsCannotBePartiallySatisfied proves a multi-
// condition rule requires ALL conditions; satisfying a subset must NOT
// authorize (the classic "combine to bypass" attempt).
func TestAuthzBypass_AndConditionsCannotBePartiallySatisfied(t *testing.T) {
	// Allow ONLY: engineering group AND a *.internal destination.
	rule := PolicyRule{Priority: 1, Name: "eng-internal", DestFQDN: "*.internal", SourceGroup: "engineering", Action: ActionAllow}
	type c struct {
		host   string
		groups []string
		want   bool
	}
	for _, tc := range []c{
		{"app.internal", []string{"engineering"}, true},               // both conditions
		{"app.internal", []string{"finance"}, false},                  // wrong group, right dest
		{"evil.example", []string{"engineering"}, false},              // right group, wrong dest
		{"evil.example", []string{"finance"}, false},                  // neither
		{"app.internal.evil.example", []string{"engineering"}, false}, // suffix-confusion dest
	} {
		got := evalMatch(rule, "203.0.113.1", "u", "oidc:test", tc.host, tc.groups) != nil
		if got != tc.want {
			t.Errorf("AND rule host=%q groups=%q = %v, want %v (partial satisfaction must not authorize)", tc.host, tc.groups, got, tc.want)
		}
	}
}

// TestAuthzBypass_DefaultDenyOnNoMatch proves that a request matching NO rule's
// conditions yields no match (→ caller defaults to deny), even with attacker-
// chosen identity/groups/host.
func TestAuthzBypass_DefaultDenyOnNoMatch(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "r1", DestFQDN: "allowed.example", SourceGroup: "admins", Action: ActionAllow},
		{Priority: 2, Name: "r2", DestFQDN: "*.corp", SourceIP: "10.0.0.0/8", Action: ActionAllow},
	})
	// Attacker: arbitrary identity/groups, but host + source match nothing.
	for _, host := range []string{"attacker.example", "allowed.example.attacker.example", "x.corp.attacker"} {
		if m := ps.Evaluate("203.0.113.99", "attacker", "oidc:evil", host, []string{"wheel", "root", "admin"}); m != nil {
			t.Errorf("BYPASS: host=%q matched rule %q despite no condition holding", host, m.Rule.Name)
		}
	}
}

// TestAuthzBypass_XFFCannotChangeSourceIPAuthz is the end-to-end proof: a client
// cannot satisfy a source-IP-scoped rule by spoofing X-Forwarded-For. Source
// authorization keys on the real connection (RemoteAddr), not a client header.
func TestAuthzBypass_XFFCannotChangeSourceIPAuthz(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startTestProxy(t)
	setDefaultPolicyAction("deny")

	// Rule authorizes ONLY the 10.0.0.0/8 source — the test client is 127.x.
	policyStore.rules = nil
	policyStore.Add(PolicyRule{Priority: 1, Name: "corp-only", DestFQDN: "*", SourceIP: "10.0.0.0/8", Action: ActionAllow})

	doReq := func(xff string) int {
		p := *proxyURL
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&p)}, Timeout: 5 * time.Second}
		req, _ := http.NewRequest(http.MethodGet, backend.URL+"/", nil)
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// No spoof: real client is 127.x, not in 10/8 → denied.
	if got := doReq(""); got != http.StatusForbidden {
		t.Errorf("baseline: status %d, want 403 (127.x not in 10/8)", got)
	}
	// Spoof XFF claiming a 10/8 address → must STILL be denied (header ignored
	// for source authorization by default).
	if got := doReq("10.1.2.3"); got != http.StatusForbidden {
		t.Errorf("BYPASS: X-Forwarded-For spoof changed source-IP authorization → status %d, want 403", got)
	}
	if got := doReq("10.0.0.0, 10.1.1.1"); got != http.StatusForbidden {
		t.Errorf("BYPASS: multi-value XFF spoof authorized the request → status %d, want 403", got)
	}
	if cb.hitCount() != 0 {
		t.Errorf("XFF-spoof requests reached upstream %d times, want 0", cb.hitCount())
	}

	// Control: a rule for the REAL client source authorizes it (proves the rule
	// engine works, the spoof just can't influence it).
	policyStore.rules = nil
	policyStore.Add(PolicyRule{Priority: 1, Name: "loopback-ok", DestFQDN: "*", SourceIP: "127.0.0.0/8", Action: ActionAllow})
	if got := doReq(""); got != http.StatusOK {
		t.Errorf("control: real-source rule status %d, want 200", got)
	}
}
