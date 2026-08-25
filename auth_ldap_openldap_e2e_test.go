package main

// auth_ldap_openldap_e2e_test.go — additional END-TO-END coverage for the
// ADR-0027 LDAP IdP, run against a REAL OpenLDAP directory over the real
// go-ldap protocol stack. These complement auth_ldap_openldap_integration_test.go
// with edge cases that suite does not exercise:
//
//   1. custom identity-attribute mapping resolved from a live entry,
//   2. an authoritative deny when the user filter matches more than one entry,
//   3. the LDAP-injection escape guard proven against a real filter parser,
//   4. the full HTTP POST /api/idp/test handler (decode → validate → staged
//      directory test → JSON), not just the runLDAPDirectoryTest helper.
//
// Env-gated exactly like the interop suite: skips without CULVERT_OPENLDAP_URL,
// so it is a no-op locally and in CI lanes without a directory, and runs in the
// "OpenLDAP" job of .github/workflows/auth-idp-interop.yml. Fixtures are the
// shared .github/idp/openldap/bootstrap.ldif DIT (alice/bob under
// dc=corp,dc=example; alice ∈ cn=engineering via the memberof overlay).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 1. Custom attribute mapping is honored against a live directory entry.
// alice's cn is "Alice" while her displayName is "Alice Example"; pointing
// NameAttribute at cn must resolve the cn value, proving searchAttributes()
// requested it and buildIdentity() mapped it from the real server response.
func TestOpenLDAPInteropE2E_CustomAttributeMapping(t *testing.T) {
	p := openLDAPInteropProfile(t)
	p.LDAP.NameAttribute = "cn"
	p.LDAP.EmailAttribute = "mail"
	p.LDAP.GroupAttribute = "memberOf"
	prov, err := NewLDAPIdPProvider(p)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	id, ok := prov.ResolveIdentity("alice", "alice-password")
	if !ok || id == nil {
		t.Fatal("ResolveIdentity(alice) failed against the live directory")
	}
	if id.Name != "Alice" {
		t.Errorf("Name = %q, want the cn value \"Alice\" (custom NameAttribute mapping)", id.Name)
	}
	if id.Email != "alice@corp.example" {
		t.Errorf("Email = %q, want alice@corp.example", id.Email)
	}
	if id.Sub != "uid=alice,ou=people,dc=corp,dc=example" {
		t.Errorf("Sub = %q, want the full user DN", id.Sub)
	}
}

// 2. A user filter that selects more than one entry is an authoritative deny
// (verify() rejects len(entries) != 1 before any user bind). "(objectClass=%s)"
// with the value "inetOrgPerson" matches both alice and bob.
func TestOpenLDAPInteropE2E_FilterMatchingMultipleEntriesDenies(t *testing.T) {
	p := openLDAPInteropProfile(t)
	p.LDAP.UserFilter = "(objectClass=%s)"
	prov, err := NewLDAPIdPProvider(p)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// The correct password is irrelevant: the ambiguous-match deny happens at
	// the search stage, before the credential is ever checked.
	if id, ok := prov.ResolveIdentity("inetOrgPerson", "alice-password"); ok || id != nil {
		t.Errorf("a filter matching multiple entries must deny, got (%+v, %v)", id, ok)
	}
}

// 3. LDAP-injection guard, proven end to end — and proven to DISCRIMINATE the
// regression it claims to catch (Codex review on PR #1225).
//
// The discriminating payload is "alice*" combined with alice's REAL password:
//   - Escaped (the correct code path): fmt.Sprintf("(uid=%s)", EscapeFilter("alice*"))
//     = (uid=alice\2a), which matches the literal uid "alice*" — nobody — so the
//     search returns 0 entries and authentication is DENIED.
//   - Unescaped (the regression): (uid=alice*) is an initial-substring filter
//     that selects EXACTLY alice, whose password we supply, so the user bind
//     SUCCEEDS and the attacker authenticates as alice.
//
// The unescaped form therefore selects exactly one authenticatable entry, so a
// dropped EscapeFilter flips this assertion from deny to allow — the earlier
// "*" / breakout payloads did not, because unescaped they select two entries or
// an invalid filter and are denied by len(entries)!=1 regardless of escaping.
func TestOpenLDAPInteropE2E_InjectionAttemptIsEscaped(t *testing.T) {
	p := openLDAPInteropProfile(t)
	prov, err := NewLDAPIdPProvider(p)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Sanity floor: the genuine login works and a genuinely wrong login is
	// denied, so the directory + credentials are sound before we test escaping.
	if _, ok := prov.ResolveIdentity("alice", "alice-password"); !ok {
		t.Fatal("control login for alice failed — fixture/directory problem, not the guard")
	}
	if _, ok := prov.ResolveIdentity("alice", "wrong-password"); ok {
		t.Fatal("control: a wrong password authenticated — fixture/directory problem")
	}

	// The discriminating case: unescaped this selects exactly alice and binds
	// with her real password (=> auth would succeed); escaped it matches nobody
	// (=> deny). A dropped EscapeFilter makes this authenticate, failing here.
	if id, ok := prov.ResolveIdentity("alice*", "alice-password"); ok || id != nil {
		t.Errorf("injection payload %q authenticated (id=%+v) — a targeted wildcard "+
			"selected exactly alice and bound with her password; EscapeFilter guard failed", "alice*", id)
	}

	// Additional breakout shapes must also be denied (non-discriminating on their
	// own — unescaped they yield multi-match or an invalid filter — but they pin
	// that a hostile username never produces an accepted bind).
	for _, payload := range []string{
		"*",               // wildcard — unescaped matches all users
		"alice)(uid=bob",  // filter breakout — unescaped rewrites the filter
		`alice))(|(uid=*`, // parenthesis/OR injection
	} {
		if id, ok := prov.ResolveIdentity(payload, "alice-password"); ok || id != nil {
			t.Errorf("injection payload %q authenticated (id=%+v)", payload, id)
		}
	}
}

// 4. The full admin HTTP surface: POST /api/idp/test with a user auth test runs
// the whole handler (strict decode → validateLDAPProfileConfig →
// resolveTestBindCredential → runLDAPDirectoryTest → audit → JSON report)
// against the live directory and returns a passing staged report with a mapped
// identity — the browser-facing path the interop suite exercises only at the
// runLDAPDirectoryTest level.
func TestOpenLDAPInteropE2E_TestEndpointHTTPHandler(t *testing.T) {
	p := openLDAPInteropProfile(t)
	body := apiIdPTestRequest{Profile: p, TestUsername: "alice", TestPassword: "alice-password"}
	r := jsonReq(http.MethodPost, "/api/idp/test", body) // jsonReq attaches admin context
	w := httptest.NewRecorder()
	apiIdPTest(w, r)
	assertStatus(t, w, http.StatusOK)

	var rep ldapTestReport
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode report: %v (body=%s)", err, w.Body.String())
	}
	if !rep.OK {
		t.Fatalf("staged test report not OK: %+v", rep.Steps)
	}
	if rep.Identity == nil || rep.Identity.Sub != "uid=alice,ou=people,dc=corp,dc=example" {
		t.Fatalf("report identity = %+v, want alice's DN", rep.Identity)
	}
	// The user-auth stage must have actually run and passed (not skipped).
	var sawUserAuth bool
	for _, s := range rep.Steps {
		if s.Name == "user_auth" {
			sawUserAuth = true
			if !s.OK || s.Skipped {
				t.Errorf("user_auth step = %+v, want OK and not skipped", s)
			}
		}
	}
	if !sawUserAuth {
		t.Error("report is missing the user_auth stage")
	}
}
