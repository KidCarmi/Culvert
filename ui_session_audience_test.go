package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// SEC-UISESSION-AUD-1 — the admin-UI cookie must not honour a portal token.
//
// ps_ui_session and the proxy-user ps_session are the same signed token type
// under the same HMAC key, and the MAC covers the payload, not the cookie
// name. The payload has no audience claim, so Provider is the only field that
// tells them apart: setUISessionCookie stamps uiSessionProvider on every
// admin-UI session, while setSessionCookie copies the IdP profile id out of the
// asserted Identity and sets NO Role.
//
// The pre-fix gate was `Provider == "local" && !UIUserExists(Sub)`, which made
// the roster-existence requirement conditional on exactly that field. A
// replayed portal token skipped the check, and the empty-role pre-RBAC branch
// in sessionRoleOrReject then resolved it to RoleAdmin — full control-plane
// admin for any directory user who could complete captive-portal SSO, with no
// forgery, and bypassing admin TOTP and admin lockout along the way.
//
// Every test below that asserts a REFUSAL is a defect gate: each one passes
// against the fixed tree and fails against the verbatim pre-fix predicate.

// portalProviders are IdP profile ids of the shape setSessionCookie stamps
// (auth_oidc_flow.go `Provider: p.profile.ID`, auth_saml.go `providerID`).
var portalProviders = []string{"oidc-profile-01", "saml-corp", "ldap-01", "okta", "entra-id"}

// audienceEnv installs the signing key and a configured cfg, AND isolates the
// process-wide revocation list.
//
// The swap is load-bearing, not hygiene theatre. apiAuthUsers' DELETE branch
// calls sessionRevoked.RevokeUser, and that list is a package singleton — so
// when the roster-endpoint gate below runs against a PRE-FIX tree the portal
// token is admitted, the delete succeeds, and "bob" stays user-revoked for the
// session TTL. Every later test minting a session for bob then fails inside
// Decode with "user revoked" rather than for the reason it is testing, which
// made one of the positive controls look like a defect gate.
func audienceEnv(t *testing.T) {
	t.Helper()
	withSessionKey(t)
	configuredCfg(t)
	t.Cleanup(session.Revoked.SwapForTest())
}

// uiSessionCookieValue mints a signed cookie value for an arbitrary payload.
// It deliberately does NOT go through setUISessionCookie: the whole point is to
// produce the shapes only the portal minter produces.
func uiSessionCookieValue(t *testing.T, sub, provider, role string) string {
	t.Helper()
	value, err := encodeSession(&Session{
		Sub: sub, Provider: provider, Role: role,
		Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(),
	})
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	return value
}

// driveUISession runs one GET /api request carrying the given cookie value
// through uiAuthMiddleware and reports the status, the injected role, and
// whether the inner handler was reached at all.
func driveUISession(t *testing.T, value string) (code int, role UIRole, reached bool) {
	t.Helper()
	h := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached, role = true, uiRole(r)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/stats", http.NoBody)
	req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: value}) // #nosec G124 -- request-side test cookie, never sent to a browser
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, role, reached
}

// ─── 1. DEFECT GATE: the escalation itself ───────────────────────────────────

// TestSECUISESSIONAUD1_PortalTokenReplayedAsUICookieIsRefused is the headline
// gate. Pre-fix, every `role=""` row returned 200 with the injected role
// "admin"; the non-empty rows are included so a portal token cannot smuggle an
// explicit role either.
func TestSECUISESSIONAUD1_PortalTokenReplayedAsUICookieIsRefused(t *testing.T) {
	audienceEnv(t)

	for _, provider := range portalProviders {
		// "" is what setSessionCookie actually produces (it sets no Role);
		// the rest prove an explicit role does not rescue a portal token.
		for _, role := range []string{"", "admin", "operator", "viewer"} {
			// Both an identity absent from the roster (the ordinary portal
			// user) and one that COLLIDES with a real admin's name: a
			// directory user called "root" must not inherit root's authority
			// just because the names match.
			for _, sub := range []string{"mallory@corp.example", "root", "bob"} {
				name := fmt.Sprintf("%s/role=%q/sub=%s", provider, role, sub)
				t.Run(name, func(t *testing.T) {
					code, got, reached := driveUISession(t, uiSessionCookieValue(t, sub, provider, role))
					if reached {
						t.Fatalf("DEFECT: handler reached with injected role %q for a %s portal token (sub=%q role=%q)",
							got, provider, sub, role)
					}
					if code != http.StatusUnauthorized {
						t.Errorf("status = %d, want %d", code, http.StatusUnauthorized)
					}
				})
			}
		}
	}
}

// TestSECUISESSIONAUD1_PortalTokenIsRefusedByTheAdminRosterEndpoint carries the
// gate past the middleware to a real admin-only handler, so the assertion is
// "the roster was not readable or writable", not merely "the middleware said
// 401". apiAuthUsers is the most sensitive shape available: it reads every
// account and, on DELETE, removes one.
func TestSECUISESSIONAUD1_PortalTokenIsRefusedByTheAdminRosterEndpoint(t *testing.T) {
	audienceEnv(t)
	value := uiSessionCookieValue(t, "mallory@corp.example", "oidc-profile-01", "")

	before := len(cfg.ListUIUsers())
	if before == 0 {
		t.Fatalf("precondition: roster must be non-empty")
	}

	h := uiAuthMiddleware(http.HandlerFunc(apiAuthUsers))
	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/api/auth/users"},
		{http.MethodDelete, "/api/auth/users?username=bob"},
	} {
		req := httptest.NewRequest(tc.method, tc.target, http.NoBody)
		req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: value}) // #nosec G124 -- request-side test cookie
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: status = %d, want %d; body=%s",
				tc.method, tc.target, rec.Code, http.StatusUnauthorized, strings.TrimSpace(rec.Body.String()))
		}
		if strings.Contains(rec.Body.String(), "\"users\"") {
			t.Errorf("DEFECT: %s %s disclosed the roster to a replayed portal token", tc.method, tc.target)
		}
	}
	if after := len(cfg.ListUIUsers()); after != before {
		t.Errorf("DEFECT: roster changed from %d to %d accounts via a replayed portal token", before, after)
	}
}

// ─── 2. CONTROLS: the fix must not narrow a legitimate admin session ────────

// TestSECUISESSIONAUD1_LocalRosterSessionStillPassesAtItsExactRole is the
// not-vacuous control. If this regressed, the gate above would "pass" simply by
// refusing everything.
func TestSECUISESSIONAUD1_LocalRosterSessionStillPassesAtItsExactRole(t *testing.T) {
	audienceEnv(t)

	for _, tc := range []struct {
		sub, role string
		want      UIRole
		note      string
	}{
		{"bob", string(RoleViewer), RoleViewer, "enrolled role passes through unchanged"},
		{"root", string(RoleAdmin), RoleAdmin, "admin session keeps admin"},
		// The documented pre-RBAC compatibility case: a session minted before
		// the Role field existed carries "" and must STILL resolve to admin.
		// The fix must not take this away — it only requires the provider and
		// the roster entry, both of which a real pre-RBAC session has.
		{"bob", "", RoleAdmin, "pre-RBAC empty role still resolves to admin"},
	} {
		t.Run(tc.note, func(t *testing.T) {
			code, got, reached := driveUISession(t, uiSessionCookieValue(t, tc.sub, uiSessionProvider, tc.role))
			if !reached {
				t.Fatalf("legitimate local session refused (status %d) — the fix narrowed admin access", code)
			}
			if got != tc.want {
				t.Errorf("injected role = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSECUISESSIONAUD1_LocalSessionForAbsentUserStillRefused pins the
// pre-existing half of the predicate (Finding 5.2, deleted users), so a future
// edit cannot drop it while keeping the provider half.
func TestSECUISESSIONAUD1_LocalSessionForAbsentUserStillRefused(t *testing.T) {
	audienceEnv(t)
	code, role, reached := driveUISession(t, uiSessionCookieValue(t, "deleted-admin", uiSessionProvider, string(RoleAdmin)))
	if reached {
		t.Fatalf("handler reached with role %q for a local session naming no roster account", role)
	}
	if code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", code, http.StatusUnauthorized)
	}
}

// ─── 3. BOUNDARY / MALFORMED provider values ────────────────────────────────

// TestSECUISESSIONAUD1_ProviderComparisonIsExact pins the comparison as a byte
// equality against uiSessionProvider. A case-folded or trimmed comparison would
// let an operator name an IdP profile "Local" and re-open the escalation.
func TestSECUISESSIONAUD1_ProviderComparisonIsExact(t *testing.T) {
	audienceEnv(t)
	for _, provider := range []string{
		"",        // absent Provider — the zero value, and what a hand-built token carries
		"Local",   // case
		"LOCAL",   // case
		" local",  // leading space
		"local ",  // trailing space
		"local\t", // tab
		"locale",  // prefix of a longer value
		"loca",    // truncation
		"local\x00",
		"local\n",
	} {
		t.Run(fmt.Sprintf("%q", provider), func(t *testing.T) {
			code, role, reached := driveUISession(t, uiSessionCookieValue(t, "bob", provider, ""))
			if reached {
				t.Fatalf("DEFECT: provider %q accepted as an admin-UI session (injected role %q)", provider, role)
			}
			if code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", code, http.StatusUnauthorized)
			}
		})
	}
}

// TestSECUISESSIONAUD1_AdmissiblePredicateDirectly exercises the predicate at
// its own boundary, including the nil and empty-subject shapes its callers rely
// on it to absorb.
func TestSECUISESSIONAUD1_AdmissiblePredicateDirectly(t *testing.T) {
	audienceEnv(t)
	for _, tc := range []struct {
		name string
		sess *Session
		want bool
	}{
		{"nil session", nil, false},
		{"local + roster user", &Session{Sub: "bob", Provider: uiSessionProvider}, true},
		{"local + empty subject", &Session{Sub: "", Provider: uiSessionProvider}, false},
		{"local + absent user", &Session{Sub: "nobody", Provider: uiSessionProvider}, false},
		{"portal + roster user", &Session{Sub: "bob", Provider: "oidc-profile-01"}, false},
		{"portal + empty subject", &Session{Sub: "", Provider: "oidc-profile-01"}, false},
		{"empty provider + roster user", &Session{Sub: "bob"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := uiSessionAdmissible(tc.sess); got != tc.want {
				t.Errorf("uiSessionAdmissible = %v, want %v", got, tc.want)
			}
		})
	}

	// uiSessionAudience is the audience half ALONE: it must not consult the
	// roster, and it must still refuse every portal provider.
	for _, tc := range []struct {
		name string
		sess *Session
		want bool
	}{
		{"nil session", nil, false},
		{"local + roster user", &Session{Sub: "bob", Provider: uiSessionProvider}, true},
		{"local + absent user", &Session{Sub: "nobody", Provider: uiSessionProvider}, true},
		{"local + empty subject", &Session{Sub: "", Provider: uiSessionProvider}, true},
		{"portal + roster user", &Session{Sub: "bob", Provider: "oidc-profile-01"}, false},
		{"empty provider", &Session{Sub: "bob"}, false},
	} {
		t.Run("audience/"+tc.name, func(t *testing.T) {
			if got := uiSessionAudience(tc.sess); got != tc.want {
				t.Errorf("uiSessionAudience = %v, want %v", got, tc.want)
			}
		})
	}
}

// ─── 4. The sibling surfaces that shared the same predicate ─────────────────

// TestSECUISESSIONAUD1_AuthStatusDoesNotReportAPortalTokenAsAdmin covers the
// PUBLIC allowlisted endpoint. Pre-fix it had no provider or existence check at
// all, so it answered {"loggedIn":true,"role":"admin"} and the console rendered
// the whole admin surface for an ordinary proxy user.
func TestSECUISESSIONAUD1_AuthStatusDoesNotReportAPortalTokenAsAdmin(t *testing.T) {
	audienceEnv(t)

	status := func(value string) map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
		req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: value}) // #nosec G124 -- request-side test cookie
		rec := httptest.NewRecorder()
		apiAuthStatus(rec, req)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %q: %v", rec.Body.String(), err)
		}
		return out
	}

	got := status(uiSessionCookieValue(t, "mallory@corp.example", "oidc-profile-01", ""))
	if got["loggedIn"] == true {
		t.Errorf("DEFECT: /api/auth/status reports a replayed portal token as logged in: %v", got)
	}
	if got["role"] == string(RoleAdmin) {
		t.Errorf("DEFECT: /api/auth/status reports role=admin for a replayed portal token: %v", got)
	}

	// CONTROL: a real admin session is still reported, at its real role.
	ok := status(uiSessionCookieValue(t, "root", uiSessionProvider, string(RoleAdmin)))
	if ok["loggedIn"] != true || ok["role"] != string(RoleAdmin) {
		t.Errorf("legitimate admin session no longer reported: %v", ok)
	}
}

// TestSECUISESSIONAUD1_SSERevalidationRejectsAPortalToken covers the mid-stream
// re-check: an SSE stream outlives its connect-time check, so this predicate is
// what terminates a stream whose session stopped being admissible.
func TestSECUISESSIONAUD1_SSERevalidationRejectsAPortalToken(t *testing.T) {
	audienceEnv(t)

	req := func(value string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/events", http.NoBody)
		r.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: value}) // #nosec G124 -- request-side test cookie
		return r
	}

	if sseAuthStillValid(req(uiSessionCookieValue(t, "mallory@corp.example", "oidc-profile-01", ""))) {
		t.Error("DEFECT: sseAuthStillValid accepted a replayed portal token")
	}
	// CONTROL: a real admin session keeps its stream.
	if !sseAuthStillValid(req(uiSessionCookieValue(t, "bob", uiSessionProvider, string(RoleViewer)))) {
		t.Error("sseAuthStillValid refused a legitimate local session — the fix broke live telemetry")
	}
}

// TestSECUISESSIONAUD1_MCPLivePrincipalRejectsAPortalToken covers the four-eyes
// principal: live-execution trust may not be attributed to a portal identity.
func TestSECUISESSIONAUD1_MCPLivePrincipalRejectsAPortalToken(t *testing.T) {
	audienceEnv(t)

	req := func(value string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/mcp/tool-trust/decision", http.NoBody)
		r.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: value}) // #nosec G124 -- request-side test cookie
		return r
	}

	if principal, err := mcpLivePrincipal(req(uiSessionCookieValue(t, "mallory@corp.example", "oidc-profile-01", ""))); err == nil {
		t.Errorf("DEFECT: mcpLivePrincipal accepted a replayed portal token as principal %q", principal)
	}
	// CONTROL: a real admin session is still a valid principal.
	principal, err := mcpLivePrincipal(req(uiSessionCookieValue(t, "root", uiSessionProvider, string(RoleAdmin))))
	if err != nil || principal != "root" {
		t.Errorf("mcpLivePrincipal(local admin) = %q, %v; want \"root\", nil", principal, err)
	}

	// CONTROL, and a deliberate boundary: this surface is AUDIENCE-only. It runs
	// behind uiAuthMiddleware, which has already applied the roster half, so a
	// local session whose subject is not in this test's roster must still be
	// accepted here. Folding uiSessionAdmissible in would refuse a principal the
	// gate admitted and break the four-eyes flow — which is exactly what
	// TestLiveTrustHTTP_FourEyesAndRBAC caught.
	principal, err = mcpLivePrincipal(req(uiSessionCookieValue(t, "operator-not-in-test-roster", uiSessionProvider, string(RoleOperator))))
	if err != nil || principal != "operator-not-in-test-roster" {
		t.Errorf("mcpLivePrincipal(local, non-roster subject) = %q, %v; want the subject and nil — this surface must not re-apply the roster check",
			principal, err)
	}

	// An empty subject is still refused: four-eyes over an anonymous actor is
	// not a separation of duties.
	if p, perr := mcpLivePrincipal(req(uiSessionCookieValue(t, "", uiSessionProvider, string(RoleAdmin)))); perr == nil {
		t.Errorf("mcpLivePrincipal accepted an empty subject as principal %q", p)
	}
}

// ─── 5. Concurrency ─────────────────────────────────────────────────────────

// TestSECUISESSIONAUD1_ConcurrentMixedSessionsDoNotCrossTalk runs admissible and
// replayed tokens through the middleware in parallel. The predicate reads cfg
// under its RWMutex while other requests read it too, and the per-request role
// travels in the request context — this asserts no outcome leaks between
// goroutines. Meaningful under -race.
func TestSECUISESSIONAUD1_ConcurrentMixedSessionsDoNotCrossTalk(t *testing.T) {
	audienceEnv(t)

	legit := uiSessionCookieValue(t, "bob", uiSessionProvider, string(RoleViewer))
	portal := uiSessionCookieValue(t, "mallory@corp.example", "oidc-profile-01", "")

	const iterations = 200
	var wg sync.WaitGroup
	var escalations, refusedLegit int64
	var mu sync.Mutex

	for i := 0; i < iterations; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, role, reached := driveUISession(t, portal)
			if reached {
				mu.Lock()
				escalations++
				mu.Unlock()
				_ = role
			}
		}()
		go func() {
			defer wg.Done()
			_, role, reached := driveUISession(t, legit)
			if !reached || role != RoleViewer {
				mu.Lock()
				refusedLegit++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if escalations != 0 {
		t.Errorf("DEFECT: %d/%d concurrent portal tokens reached the handler", escalations, iterations)
	}
	if refusedLegit != 0 {
		t.Errorf("%d/%d concurrent legitimate sessions were refused or got the wrong role", refusedLegit, iterations)
	}
}

// ─── 6. Structural wall ─────────────────────────────────────────────────────

// TestSECUISESSIONAUD1_EveryUISessionConsumerIsAccountedFor is the wall. The
// defect was not one wrong line: it was FOUR independent consumers of
// readUISessionCookie, three carrying their own copy of the predicate (one of
// them missing it entirely). Behavioural tests can only cover the consumers
// that exist today, so this fails the build when a FIFTH appears, forcing
// whoever adds it to decide — in this list — whether it gates or merely
// attributes.
func TestSECUISESSIONAUD1_EveryUISessionConsumerIsAccountedFor(t *testing.T) {
	// Gating consumers MUST route the session through one of the two
	// predicates. Anything that resolves a ROLE needs the full
	// uiSessionAdmissible; a surface that only needs the audience, and that runs
	// behind the gate which already applied the roster half, may use
	// uiSessionAudience.
	gating := map[string]string{
		"uiAuthMiddleware":  "THE admin-plane gate; injects the role every requireRole check reads (admissible)",
		"apiAuthStatus":     "PUBLIC allowlist; its answer decides what the console renders (admissible)",
		"sseAuthStillValid": "mid-stream SSE re-check; a stream outlives its connect-time check (admissible)",
		// Logout decides whether to write into the persisted, cluster-gossiped
		// revocation list, so it is a trust decision too (SEC-REVOKE-1).
		"apiAuthLogout": "decides whether to insert into the revocation list; PUBLIC allowlist (admissible)",
		// Runs behind the gate, so it needs the audience and nothing more.
		"mcpLivePrincipal": "supplies one of the two eyes for live-execution trust (audience)",
	}
	// Attribution-only consumers gate NOTHING. Recording the identity a
	// refused session claimed is more useful than recording "unknown", and
	// with the gate fixed a non-admissible session never reaches a handler
	// that audits. Routing these through the predicate would be churn.
	attribution := map[string]string{
		"sessionAdmin": "audit/config-version actor attribution only (ui_rbac.go)",
		"auditActor":   "audit-ring actor attribution only (ui_helpers.go)",
	}

	callers := uiSessionCookieConsumers(t)
	if len(callers) < len(gating)+len(attribution) {
		t.Fatalf("wall found only %d readUISessionCookie consumer(s), expected at least %d — the selector has drifted and the wall proves nothing",
			len(callers), len(gating)+len(attribution))
	}

	var unknown, ungated []string
	for fn, where := range callers {
		_, isGating := gating[fn]
		_, isAttribution := attribution[fn]
		switch {
		case !isGating && !isAttribution:
			unknown = append(unknown, fmt.Sprintf("  %s (%s)", fn, where))
		case isGating && !fnCalls(t, fn, "uiSessionAdmissible") && !fnCalls(t, fn, "uiSessionAudience"):
			ungated = append(ungated, fmt.Sprintf("  %s (%s)", fn, where))
		}
	}
	if len(unknown) > 0 {
		t.Errorf("readUISessionCookie has %d consumer(s) this wall does not know about:\n%s\n\n"+
			"ps_ui_session and the proxy-user ps_session are the same signed token under the same key, and the MAC "+
			"does not cover the cookie NAME (SEC-UISESSION-AUD-1). A consumer that makes a trust decision must call "+
			"uiSessionAdmissible; add it to `gating` here. One that only names an actor belongs in `attribution`.",
			len(unknown), strings.Join(unknown, "\n"))
	}
	if len(ungated) > 0 {
		t.Errorf("%d gating consumer(s) of readUISessionCookie call neither uiSessionAdmissible nor uiSessionAudience:\n%s",
			len(ungated), strings.Join(ungated, "\n"))
	}
}

// TestSECUISESSIONAUD1_ExactlyTwoSessionMintersOnePerAudience pins the premise
// the whole fix rests on: uiSessionAdmissible trusts that Provider identifies
// the audience, which holds only while each cookie has exactly one minter and
// each minter stamps its own Provider. encodeSession is the chokepoint both go
// through, so counting its callers counts the minters.
func TestSECUISESSIONAUD1_ExactlyTwoSessionMintersOnePerAudience(t *testing.T) {
	minters := map[string]string{
		"setUISessionCookie": "the admin-UI cookie (ps_ui_session); must stamp uiSessionProvider",
		"setSessionCookie":   "the proxy-user portal cookie (ps_session); stamps the IdP profile id",
	}
	found := fnsCalling(t, "encodeSession")
	if len(found) < len(minters) {
		t.Fatalf("wall found only %d encodeSession caller(s) %v, expected at least %d — the selector has drifted and the wall proves nothing",
			len(found), found, len(minters))
	}
	for fn, where := range found {
		if _, ok := minters[fn]; !ok {
			t.Errorf("%s (%s) mints a session token outside the two known minters.\n\n"+
				"SEC-UISESSION-AUD-1: ps_ui_session and ps_session are the same signed type under the same key, "+
				"and the MAC does not cover the cookie NAME — uiSessionAdmissible can only tell them apart by Provider. "+
				"A third minter breaks that. Add it here and state which audience it stamps.", fn, where)
		}
	}
	// And the admin-UI minter must actually stamp the provider the gate tests.
	if !fnReferences(t, "setUISessionCookie", "uiSessionProvider") {
		t.Error("setUISessionCookie no longer sets Provider from uiSessionProvider — uiSessionAdmissible would refuse every admin session")
	}
}

// ─── wall-test machinery (AST over this package's non-test sources) ─────────

// forEachPkgFunc parses every non-test .go file in this package and calls visit
// for each top-level function/method body.
func forEachPkgFunc(t *testing.T, visit func(file string, fn *ast.FuncDecl, fset *token.FileSet)) {
	t.Helper()
	fset := token.NewFileSet()
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				visit(name, fn, fset)
			}
		}
	}
}

// uiSessionCookieConsumers maps each function that calls readUISessionCookie to
// "file:line".
func uiSessionCookieConsumers(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	forEachPkgFunc(t, func(file string, fn *ast.FuncDecl, fset *token.FileSet) {
		if fn.Name.Name == "readUISessionCookie" {
			return
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "readUISessionCookie" {
				out[fn.Name.Name] = fmt.Sprintf("%s:%d", file, fset.Position(n.Pos()).Line)
			}
			return true
		})
	})
	return out
}

// fnsReferencing maps each function whose body mentions ident (and for which
// keep returns true) to "file:line".
func fnsReferencing(t *testing.T, ident string, keep func(fn string) bool) map[string]string {
	t.Helper()
	out := map[string]string{}
	forEachPkgFunc(t, func(file string, fn *ast.FuncDecl, fset *token.FileSet) {
		if !keep(fn.Name.Name) {
			return
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == ident {
				out[fn.Name.Name] = fmt.Sprintf("%s:%d", file, fset.Position(n.Pos()).Line)
			}
			return true
		})
	})
	return out
}

// fnReferences reports whether the named function's body mentions ident.
func fnReferences(t *testing.T, fnName, ident string) bool {
	t.Helper()
	found := false
	forEachPkgFunc(t, func(_ string, fn *ast.FuncDecl, _ *token.FileSet) {
		if fn.Name.Name != fnName {
			return
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == ident {
				found = true
			}
			return true
		})
	})
	return found
}

// fnCalls reports whether the named function's body calls callee.
func fnCalls(t *testing.T, fnName, callee string) bool {
	t.Helper()
	return fnReferences(t, fnName, callee)
}

// fnsCalling maps each function that calls callee to "file:line".
func fnsCalling(t *testing.T, callee string) map[string]string {
	t.Helper()
	out := map[string]string{}
	forEachPkgFunc(t, func(file string, fn *ast.FuncDecl, fset *token.FileSet) {
		if fn.Name.Name == callee {
			return
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == callee {
				out[fn.Name.Name] = fmt.Sprintf("%s:%d", file, fset.Position(n.Pos()).Line)
			}
			return true
		})
	})
	return out
}
