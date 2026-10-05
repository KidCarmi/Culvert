package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// CHAOS-71 — deleting or disabling an identity provider must revoke the
// sessions it already minted.
//
// Every DEFECT gate below was verified failing against the pre-fix tree (the
// gate in `resolveRequestAuth` arm 1 removed), and every CONTROL was verified
// failing against the cheapest wrong fix — refusing every session cookie —
// which passes all nine defect gates while deleting browser SSO through the
// gateway and locking the admin UI out of its own cookie.
// ---------------------------------------------------------------------------

// c71Setup installs a registry in one of three postures and a local admin
// account, so credCapable keeps authRequired true after the provider is gone.
// That is the realistic shape: an appliance always has a local admin, so
// removing one federation never drops the whole Stage-1 gate.
//
// It also isolates the process-global refusal counter and log gate — a leaked
// gate suppresses the line for every later test in the package.
func c71Setup(t *testing.T, posture string) {
	t.Helper()
	prevReg := idpRegistry
	prof := &IdPProfile{ID: "corp", Type: IdPTypeSAML, Enabled: true, Name: "Corp SSO"}
	reg := &IdPRegistry{live: map[string]IdentityProvider{}}
	switch posture {
	case "live":
		reg.profiles = []*IdPProfile{prof}
		reg.live["corp"] = &SAMLProvider{profile: prof}
	case "disabled":
		// The profile is still STORED — the admin toggled Enabled off rather
		// than deleting. `live` holds only enabled+compiled providers, so the
		// two postures converge here by construction, which is why disable is
		// covered without a second code path.
		disabled := *prof
		disabled.Enabled = false
		reg.profiles = []*IdPProfile{&disabled}
	case "deleted":
		// Nothing stored, nothing live.
	default:
		t.Fatalf("unknown posture %q", posture)
	}
	idpRegistry = reg

	cfg.mu.Lock()
	oldUser, oldHash, oldRev := cfg.user, cfg.passHash, cfg.authRevision
	cfg.user, cfg.passHash = "c71-admin", []byte("$2a$10$c71PlaceholderHashNotUsedByAnyAssertionInThisFile0000000")
	cfg.authRevision++
	cfg.mu.Unlock()

	resetSessionProviderBoundsForTest()
	t.Cleanup(func() {
		idpRegistry = prevReg
		cfg.mu.Lock()
		cfg.user, cfg.passHash, cfg.authRevision = oldUser, oldHash, oldRev
		cfg.mu.Unlock()
		cfg.cache.clear()
		resetSessionProviderBoundsForTest()
	})
}

// c71Request mints a cookie this appliance would really have issued: signed
// with the live key, carrying the asserting profile's id in `pvd` and the
// groups that provider asserted.
func c71Request(t *testing.T, provider string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), "GET", "http://example.com/", http.NoBody)
	if provider == "<none>" {
		return r
	}
	tok, err := encodeSession(&Session{
		Sub:      "alice@corp.example",
		Email:    "alice@corp.example",
		Groups:   []string{"engineering", "vpn-users"},
		Provider: provider,
		Exp:      time.Now().Add(8 * time.Hour).Unix(),
		Jti:      newSessionJti(),
	})
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tok}) // #nosec G124 -- request-side session-cookie fixture sent TO the handler; Secure/HttpOnly/SameSite are response attributes and AddCookie serialises only name=value
	return r
}

func c71Resolve(t *testing.T, provider string) (authOutcome, bool, int) {
	t.Helper()
	w := httptest.NewRecorder()
	outcome, proceed := resolveRequestAuth(w, c71Request(t, provider), "192.0.2.10", "chaos-71")
	return outcome, proceed, w.Code
}

// ── DEFECT GATES ────────────────────────────────────────────────────────────

// A deleted provider's session must stop being an identity. Pre-fix this
// returned proceed=true with identity "alice@corp.example".
func TestChaos71_DefectDeletedProviderSessionIsNotAnIdentity(t *testing.T) {
	c71Setup(t, "deleted")
	outcome, proceed, code := c71Resolve(t, "corp")
	if proceed || outcome.identity != "" {
		t.Fatalf("deleted provider still authenticated: proceed=%v identity=%q status=%d",
			proceed, outcome.identity, code)
	}
}

// Disabling is the same revocation intent with the profile left in place.
func TestChaos71_DefectDisabledProviderSessionIsNotAnIdentity(t *testing.T) {
	c71Setup(t, "disabled")
	outcome, proceed, code := c71Resolve(t, "corp")
	if proceed || outcome.identity != "" {
		t.Fatalf("disabled provider still authenticated: proceed=%v identity=%q status=%d",
			proceed, outcome.identity, code)
	}
}

// THE SEVERITY HALF. The identity alone is not what makes this High: the
// groups the removed provider asserted go straight into
// `policyStore.Evaluate(clientIP, identity, source, host, groups)`, so a
// group-scoped allow rule kept matching for a federation the operator had
// just cut off. Asserting on the identity alone would leave that reachable
// through any future change that cleared the subject and kept the groups.
func TestChaos71_DefectRemovedProviderGroupsNeverReachPolicy(t *testing.T) {
	for _, posture := range []string{"deleted", "disabled"} {
		t.Run(posture, func(t *testing.T) {
			c71Setup(t, posture)
			outcome, _, _ := c71Resolve(t, "corp")
			if len(outcome.groups) != 0 {
				t.Fatalf("groups from a %s provider reached policy evaluation: %v",
					posture, outcome.groups)
			}
			if outcome.source == "corp" {
				t.Fatalf("auth source still names the %s provider: %q", posture, outcome.source)
			}
		})
	}
}

// THE REASON THE FIX IS DERIVED STATE AND NOT A REVOCATION EVENT. The admin
// DELETE handler is only one writer of the registry: `ReplaceAll` is also
// reached from config import, config-version rollback and the CP→DP
// `syncSnapshotIdPProfiles` path, none of which run that handler. A
// `RevokeProvider` entry emitted from the handler would cover none of them;
// probing the live set covers all of them with one predicate.
func TestChaos71_DefectProviderRemovedByReplaceAllIsAlsoRevoked(t *testing.T) {
	c71Setup(t, "live")
	if _, proceed, _ := c71Resolve(t, "corp"); !proceed {
		t.Fatal("precondition: the live provider's session must authenticate first")
	}
	// The shape a CP snapshot / config import / rollback produces: the whole
	// profile set is replaced and this provider is simply not in it.
	if err := idpRegistry.ReplaceAll(nil); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	outcome, proceed, code := c71Resolve(t, "corp")
	if proceed || outcome.identity != "" {
		t.Fatalf("provider removed by ReplaceAll still authenticated: proceed=%v identity=%q status=%d",
			proceed, outcome.identity, code)
	}
}

// The refusal is otherwise invisible — it looks exactly like a user with no
// cookie, which is the point of the fix and the reason it needs its own
// counter. An operator with no metrics scraper has no other way to tell
// whether the revocation reached live traffic.
func TestChaos71_DefectRefusalIsCounted(t *testing.T) {
	c71Setup(t, "deleted")
	if got := sessionProviderRevokedCount(); got != 0 {
		t.Fatalf("counter = %d before any request, want 0", got)
	}
	for i := 0; i < 3; i++ {
		c71Resolve(t, "corp")
	}
	if got := sessionProviderRevokedCount(); got != 3 {
		t.Fatalf("counter = %d after 3 refused requests, want 3", got)
	}
}

// The refusal must degrade to EXACTLY "no cookie" and not invent a posture of
// its own: the client is re-challenged through the existing no-credential
// dispatch, so there is no second code path to keep in step with arm 3.
func TestChaos71_DefectRefusalIsIndistinguishableFromNoCookie(t *testing.T) {
	c71Setup(t, "deleted")
	revoked, revokedProceed, revokedCode := c71Resolve(t, "corp")
	none, noneProceed, noneCode := c71Resolve(t, "<none>")
	if revokedProceed != noneProceed || revokedCode != noneCode {
		t.Fatalf("refused session (proceed=%v status=%d) differs from no cookie (proceed=%v status=%d)",
			revokedProceed, revokedCode, noneProceed, noneCode)
	}
	if revoked.identity != none.identity || revoked.source != none.source {
		t.Fatalf("refused session resolved (identity=%q source=%q), no cookie resolved (identity=%q source=%q)",
			revoked.identity, revoked.source, none.identity, none.source)
	}
}

// ── CONTROLS ────────────────────────────────────────────────────────────────
// The cheapest way to pass every defect gate above is to stop honouring
// session cookies at all. These four fail against that shape and pass against
// BOTH the pre-fix and the fixed tree, which is what makes them controls
// rather than second defect gates.

// Browser SSO through the gateway must keep working, groups included.
func TestChaos71_ControlLiveProviderStillAuthenticatesWithGroups(t *testing.T) {
	c71Setup(t, "live")
	outcome, proceed, code := c71Resolve(t, "corp")
	if !proceed || outcome.identity != "alice@corp.example" {
		t.Fatalf("live provider session rejected: proceed=%v identity=%q status=%d",
			proceed, outcome.identity, code)
	}
	if len(outcome.groups) != 2 {
		t.Fatalf("groups = %v, want the two the provider asserted", outcome.groups)
	}
	if got := sessionProviderRevokedCount(); got != 0 {
		t.Fatalf("counter = %d for a live provider, want 0", got)
	}
}

// `setUISessionCookie` stamps "local", which names no registry profile. The
// admin UI owns its own backstop (uiAuthMiddleware's cfg.UIUserExists check);
// refusing "local" here would lock every administrator out of the appliance
// the moment no IdP is configured, which is the default posture.
func TestChaos71_ControlLocalProviderIsNeverRefused(t *testing.T) {
	c71Setup(t, "deleted")
	if !sessionProviderLive(sessionProviderLocal) {
		t.Fatal("the local admin-UI provider must never be refused")
	}
	if got := sessionProviderRevokedCount(); got != 0 {
		t.Fatalf("counter = %d, want 0", got)
	}
}

// A cookie minted before the `pvd` field existed carries "". Refusing those
// would log out every pre-upgrade session on the deploy that adds this check,
// for no security gain: such a cookie names no federation, so there is no
// federation to have been cut off.
func TestChaos71_ControlLegacyEmptyProviderIsNeverRefused(t *testing.T) {
	c71Setup(t, "deleted")
	if !sessionProviderLive("") {
		t.Fatal("a pre-pvd legacy session must not be refused")
	}
	if _, _, _ = c71Resolve(t, ""); sessionProviderRevokedCount() != 0 {
		t.Fatalf("counter = %d for a legacy session, want 0", sessionProviderRevokedCount())
	}
}

// Ordinary anonymous traffic must never charge the counter, or the metric
// stops meaning "a removed provider's session was cut" and starts meaning
// "somebody browsed".
func TestChaos71_ControlAbsentCookieChargesNothing(t *testing.T) {
	c71Setup(t, "deleted")
	for i := 0; i < 5; i++ {
		c71Resolve(t, "<none>")
	}
	if got := sessionProviderRevokedCount(); got != 0 {
		t.Fatalf("counter = %d for anonymous traffic, want 0", got)
	}
}

// ── REPRESENTATION ──────────────────────────────────────────────────────────

// This codebase carries TWO representations of one provider identity on
// purpose: the interactive providers stamp the BARE profile id into
// `Identity.Provider` (`ExchangeCode`, `extractSAMLIdentity`) while `Name()`
// returns `oidc:<id>` / `saml:<id>` — which is why `stripIdPPrefix` exists at
// all. A fail-closed bound applied to the wrong representation is a
// customer-visible outage rather than a tightening (CHAOS-69's round-1 IDN
// regression), so both forms must resolve while a removed provider is refused
// in EITHER spelling.
func TestChaos71_BothProviderRepresentationsResolve(t *testing.T) {
	c71Setup(t, "live")
	for _, spelling := range []string{"corp", "saml:corp", "oidc:corp", "ldap:corp"} {
		if !sessionProviderLive(spelling) {
			t.Errorf("live provider spelled %q was refused", spelling)
		}
	}
	c71Setup(t, "deleted")
	for _, spelling := range []string{"corp", "saml:corp", "oidc:corp"} {
		if sessionProviderLive(spelling) {
			t.Errorf("removed provider spelled %q was admitted", spelling)
		}
	}
}

// Probing both spellings must never WIDEN: a bare id that names nothing live
// stays refused however it is prefixed, and a prefix alone is not a provider.
func TestChaos71_ControlPrefixAloneIsNotAProvider(t *testing.T) {
	c71Setup(t, "live")
	for _, spelling := range []string{"saml:", "oidc:", "other", "saml:other", "  ", "CORP"} {
		if sessionProviderLive(spelling) {
			t.Errorf("%q was admitted as a live provider", spelling)
		}
	}
}

// ── STRUCTURAL WALL ─────────────────────────────────────────────────────────

// The predicate is only safe because the set of `pvd` values a legitimately
// minted cookie can carry is CLOSED: `setSessionCookie` has exactly two
// callers, both interactive IdP callbacks stamping the bare profile id, and
// `setUISessionCookie` always stamps "local". Behavioural coverage cannot
// reach a future third minter, and the failure mode is an availability one —
// every user of the new path locked out — so the inventory is walled.
//
// Enumerated from the PRIMITIVE, not from the file being edited: CHAOS-70's
// own note records that its wall AST-walked one file while the mutator that
// escaped it lived in another.
func TestChaos71_WallSessionCookieMintersAreEnumerated(t *testing.T) {
	// callSite → why the pvd value it stamps is one sessionProviderLive admits.
	known := map[string]string{
		"ui_auth.go:authOIDCCallback": "OIDCFlowProvider.ExchangeCode stamps the BARE profile id",
		"ui_auth.go:authSAMLCallback": "extractSAMLIdentity is handed p.profile.ID — the BARE profile id",
	}
	src := readSourceForC71Wall(t, "ui_auth.go")
	var found []string
	for _, line := range strings.Split(src, "\n") {
		if strings.Contains(line, "setSessionCookie(w, r,") {
			found = append(found, strings.TrimSpace(line))
		}
	}
	if len(found) != len(known) {
		t.Fatalf("setSessionCookie call sites in ui_auth.go = %d, inventory has %d.\n"+
			"A new minter must record which pvd shape it stamps and confirm "+
			"sessionProviderLive admits it for a LIVE provider — a value outside "+
			"that set locks every user of the new path out of the proxy.\nfound: %v",
			len(found), len(known), found)
	}
	// Not vacuous: the selector must really be matching.
	if len(found) == 0 {
		t.Fatal("wall is vacuous: no setSessionCookie call sites matched")
	}
	// And no OTHER root file may mint the proxy cookie.
	for _, f := range []string{"proxy.go", "proxy_portal.go", "ui_session.go", "session.go"} {
		body := readSourceForC71Wall(t, f)
		if strings.Contains(body, "setSessionCookie(w, r,") {
			t.Errorf("%s mints the proxy session cookie; add it to the inventory above", f)
		}
	}
}

// ── RATE GATE ───────────────────────────────────────────────────────────────

// A mitigation for a revocation gap must not become a log-volume problem: a
// browser re-sends a dead cookie on every request until it re-authenticates,
// so the rate is set by traffic. The LINE is suppressed within the window;
// the COUNT never is, and rides every line that does get emitted.
//
// This is a CONTROL, not a defect gate, and the distinction is the CHAOS-70
// round-1 lesson: a TOCTOU on an atomic is invisible to `-race` and was
// measured unreachable behaviourally, so the claim mechanism is asserted
// structurally below instead.
func TestChaos71_ControlLogIsSuppressedButTheCountNeverIs(t *testing.T) {
	c71Setup(t, "deleted")
	frozen := time.Now()
	prev := timeNowSessionProvider
	timeNowSessionProvider = func() time.Time { return frozen }
	t.Cleanup(func() { timeNowSessionProvider = prev })

	for i := 0; i < 50; i++ {
		noteSessionProviderRevoked("corp", "alice", "192.0.2.10")
	}
	if got := sessionProviderRevokedCount(); got != 50 {
		t.Fatalf("counter = %d, want 50 — the count must never be rate-limited", got)
	}
}

// A clock rollback must RE-ARM the gate rather than silence the line until
// wall-clock catches up (CHAOS-61: a negative age is STALE, not fresh).
func TestChaos71_LogGateReArmsOnClockRollback(t *testing.T) {
	c71Setup(t, "deleted")
	now := time.Now()
	prev := timeNowSessionProvider
	timeNowSessionProvider = func() time.Time { return now }
	t.Cleanup(func() { timeNowSessionProvider = prev })

	noteSessionProviderRevoked("corp", "alice", "192.0.2.10")
	armed := sessionProviderLogGate.Load()
	if armed == 0 {
		t.Fatal("first refusal did not arm the log gate")
	}
	// Roll the clock back an hour: the stored stamp is now in the future.
	now = now.Add(-time.Hour)
	noteSessionProviderRevoked("corp", "alice", "192.0.2.10")
	if got := sessionProviderLogGate.Load(); got == armed {
		t.Fatal("a clock rollback left the gate latched at a future stamp")
	}
}

// The gate must CLAIM its window with a compare-and-swap rather than
// read-compare-store. Asserted structurally because the race is invisible to
// `-race` (atomics are race-free by definition) and, measured on the CHAOS-70
// precedent, a behavioural gate passes against the defect — which is worse
// than no gate.
func TestChaos71_WallLogGateIsClaimedNotRead(t *testing.T) {
	src := readSourceForC71Wall(t, "session_provider_bounds.go")
	if !strings.Contains(src, "sessionProviderLogGate.CompareAndSwap(") {
		t.Fatal("the log rate gate must claim its window with CompareAndSwap: " +
			"a read-compare-store lets every request in a flood observe the same " +
			"expired stamp and all emit, making the mitigation a log-volume problem")
	}
}

// ── CONCURRENCY ─────────────────────────────────────────────────────────────

// The accounting must be exact under the concurrency a real refusal arrives
// with: a whole fleet's browsers re-send their dead cookies at once when a
// provider is removed.
func TestChaos71_RefusalAccountingIsExactUnderConcurrency(t *testing.T) {
	c71Setup(t, "deleted")
	const workers, each = 16, 25
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				rec := httptest.NewRecorder()
				resolveRequestAuth(rec, c71Request(t, "corp"),
					fmt.Sprintf("192.0.2.%d", id+1), "chaos-71-conc")
			}
		}(w)
	}
	wg.Wait()
	if got := sessionProviderRevokedCount(); got != int64(workers*each) {
		t.Fatalf("counter = %d, want %d", got, workers*each)
	}
}

// readSourceForC71Wall reads a root source file for the structural walls.
func readSourceForC71Wall(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// THE AGREEMENT GATE. `sessionProviderLive` and `identityAuthSource` both
// decide "does this session name a federation?", and they must decide it the
// same way. `identityAuthSource` tests the RAW `id.Provider` against "", so
// trimming inside the predicate would make a whitespace-only `pvd` "no
// federation" to the predicate while still being stamped into
// `authenticatedSource` and carried into the policy decision as a federation
// name — a value exempt from revocation that is nevertheless used for
// authorization.
//
// It asserts the AGREEMENT rather than either spelling of the rule, so it
// fails against drift introduced from EITHER side (the
// TestTOTPSameKey_AgreesWithTheVerifier / LoginNameConfiguredMatchesVerifyUIUser
// precedent). Verified failing against the trimming shape this sweep shipped
// first.
func TestChaos71_ProviderEmptinessAgreesWithIdentityAuthSource(t *testing.T) {
	c71Setup(t, "deleted")
	for _, pvd := range []string{"", " ", "  ", "\t", "\n", " corp ", "corp", "local", " local"} {
		// What identityAuthSource considers "no provider at all".
		namesNoFederation := identityAuthSource(&Identity{Provider: pvd}, "sentinel") == "sentinel"
		// What the predicate exempts from revocation for the same reason.
		exemptAsFederationless := pvd == ""
		if namesNoFederation != exemptAsFederationless {
			t.Errorf("pvd %q: identityAuthSource says namesNoFederation=%v but the "+
				"predicate's federationless exemption is %v — the two layers disagree "+
				"about which values mean 'no provider'",
				pvd, namesNoFederation, exemptAsFederationless)
		}
		// And a value that DOES name a federation must be refused while that
		// federation is not live (the "local" admin-UI value excepted: it
		// names no registry profile and the UI owns its own backstop).
		if !namesNoFederation && pvd != sessionProviderLocal && sessionProviderLive(pvd) {
			t.Errorf("pvd %q names a federation that is not live, yet was admitted", pvd)
		}
	}
}

// THE ADMIN-UI COOKIE IS OUT OF SCOPE ONLY BECAUSE IT IS ALWAYS "local", and
// that is worth a wall rather than a sentence.
//
// `uiAuthMiddleware`'s deleted-user backstop is keyed on
// `sess.Provider == "local"`, and `sessionProviderLive` exempts "local"
// because the middleware owns that check. So a future change that minted an
// SSO-backed ADMIN session would skip BOTH backstops at once: the middleware
// would not consult the roster (not local) and this predicate would not be
// consulted at all (the admin UI does not call it). The two exemptions are
// safe only as a pair, and only while `setUISessionCookie` hardcodes "local".
//
// If this gate fails, the admin-UI path needs its own provider check before
// the new minter ships — do not simply widen the inventory.
func TestChaos71_WallAdminUISessionIsAlwaysLocal(t *testing.T) {
	src := readSourceForC71Wall(t, "ui_session.go")
	if !strings.Contains(src, `Provider: "local",`) {
		t.Fatal("setUISessionCookie no longer hardcodes Provider: \"local\" — " +
			"uiAuthMiddleware's roster backstop is keyed on it and " +
			"sessionProviderLive exempts it on that basis, so an SSO-backed " +
			"admin session would skip both checks")
	}
	// And the middleware's backstop must still be the local-only one the
	// exemption assumes.
	mw := readSourceForC71Wall(t, "ui_middleware.go")
	if !strings.Contains(mw, `sess.Provider == "local" && !cfg.UIUserExists(sess.Sub)`) {
		t.Fatal("uiAuthMiddleware's deleted-user backstop changed shape; " +
			"re-derive whether sessionProviderLive may still exempt \"local\"")
	}
}
