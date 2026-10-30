package main

// session_provider_availability_test.go — CHAOS-88 narrowed by the owner
// decision on #1485/#1564: an unreachable IdP is degraded AVAILABILITY, not
// revocation. Only an explicit delete, disable or removal by ReplaceAll revokes
// the sessions a provider minted; a compile failure and the CHAOS-87
// staleness-ceiling retirement must not.
//
// Keyed on `LiveProvider` (enabled AND compiled), restarting a node while an
// IdP was unreachable logged out every session of that IdP — and sent those
// users to an IdP that was down. These gates fail against that shape.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func c72AssertAuthenticates(t *testing.T, why string) {
	t.Helper()
	outcome, proceed, code := c72Resolve(t, "corp")
	if !proceed || outcome.identity != "alice@corp.example" || len(outcome.groups) != 2 {
		t.Fatalf("%s must NOT revoke the session: proceed=%v identity=%q groups=%v status=%d",
			why, proceed, outcome.identity, outcome.groups, code)
	}
	if got := sessionProviderRevokedCount(); got != 0 {
		t.Fatalf("%s: revocation counter = %d, want 0", why, got)
	}
}

func c72AssertRevoked(t *testing.T, why string) {
	t.Helper()
	outcome, proceed, code := c72Resolve(t, "corp")
	if proceed || outcome.identity != "" || len(outcome.groups) != 0 {
		t.Fatalf("%s must revoke the session: proceed=%v identity=%q groups=%v status=%d",
			why, proceed, outcome.identity, outcome.groups, code)
	}
	if got := sessionProviderRevokedCount(); got == 0 {
		t.Fatalf("%s: the refusal must be counted", why)
	}
}

// A dark profile (stored + enabled, nothing compiled) keeps its sessions.
func TestChaos88_DarkEnabledProfileDoesNotRevoke(t *testing.T) {
	c72Setup(t, "dark")
	c72AssertAuthenticates(t, "a stored, enabled profile with no live provider")
}

// END TO END: the boot path with the IdP unreachable and nothing cached. Load
// logs the compile error and leaves the profile enabled-but-dark; a session
// that profile minted before the restart must keep authenticating.
func TestChaos88_CompileFailureDoesNotRevokeSessions(t *testing.T) {
	c72Setup(t, "deleted") // local admin + counter isolation; registry replaced below
	chaos87Env(t)
	idp := newChaos87IdP(t)
	idp.down.Store(true) // 503 with nothing cached: the compile fails

	path := filepath.Join(t.TempDir(), "idp_profiles.json")
	seed := `[{"id":"corp","name":"corp","type":"saml","enabled":true,"saml":{"metadataUrl":"` + idp.URL() + `"}}]`
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := idpRegistry.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, live := idpRegistry.LiveProvider("corp"); live {
		t.Fatal("setup: the provider must have failed to compile")
	}
	if !idpRegistry.ProfileEnabled("corp") {
		t.Fatal("setup: a compile failure must leave the profile stored and enabled")
	}
	c72AssertAuthenticates(t, "a compile failure (IdP unreachable at boot)")
}

// END TO END: a provider retired at the CHAOS-87 staleness ceiling (#1485's
// retireStaleProvider) goes dark but stays enabled; its sessions survive. The
// seven-day expiry by itself must never become a mass logout.
func TestChaos88_StaleExpiryRetirementDoesNotRevokeSessions(t *testing.T) {
	c72Setup(t, "deleted")
	chaos87Env(t)
	idp := newChaos87IdP(t)
	if err := idpRegistry.Upsert(chaos87Profile("corp", idp.URL())); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	c72AssertAuthenticates(t, "a live provider (precondition)")

	src := idpRemoteDocumentSource(chaos87Profile("corp", idp.URL()))
	served := chaos87SeedStaleServe("corp", src)
	if !idpRegistry.retireStaleProvider("corp", src, served) {
		t.Fatal("setup: the stale provider must be retired")
	}
	if _, live := idpRegistry.LiveProvider("corp"); live {
		t.Fatal("setup: retirement must leave the provider dark")
	}
	c72AssertAuthenticates(t, "a staleness-ceiling retirement")
}

// The CONTROLS on a REAL registry that has gone dark: an explicit delete,
// disable or ReplaceAll removal still revokes. A dark provider must not mask
// the operator's revocation lever.
func TestChaos88_ExplicitRemovalStillRevokesADarkProvider(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remove func(t *testing.T, url string)
	}{
		{"delete", func(t *testing.T, _ string) {
			if err := idpRegistry.Delete("corp"); err != nil {
				t.Fatalf("Delete: %v", err)
			}
		}},
		{"disable", func(t *testing.T, url string) {
			p := chaos87Profile("corp", url)
			p.Enabled = false
			if err := idpRegistry.Upsert(p); err != nil {
				t.Fatalf("disable upsert: %v", err)
			}
		}},
		{"replaceall-removal", func(t *testing.T, _ string) {
			if err := idpRegistry.ReplaceAll(nil); err != nil {
				t.Fatalf("ReplaceAll: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c72Setup(t, "deleted")
			chaos87Env(t)
			idp := newChaos87IdP(t)
			if err := idpRegistry.Upsert(chaos87Profile("corp", idp.URL())); err != nil {
				t.Fatalf("upsert: %v", err)
			}
			src := idpRemoteDocumentSource(chaos87Profile("corp", idp.URL()))
			if !idpRegistry.retireStaleProvider("corp", src, chaos87SeedStaleServe("corp", src)) {
				t.Fatal("setup: the provider must be dark before removal")
			}
			c72AssertAuthenticates(t, "the dark provider (precondition)")

			tc.remove(t, idp.URL())
			if idpRegistry.ProfileEnabled("corp") {
				t.Fatalf("%s must leave no enabled profile", tc.name)
			}
			c72AssertRevoked(t, tc.name)
		})
	}
}

// ProfileEnabled answers "stored and enabled" and nothing else, and it is on
// the proxy request path, so it must not allocate.
func TestChaos88_ProfileEnabledSemanticsAndAllocations(t *testing.T) {
	reg := &IdPRegistry{
		live: map[string]IdentityProvider{},
		profiles: []*IdPProfile{
			{ID: "on", Type: IdPTypeSAML, Enabled: true},
			{ID: "off", Type: IdPTypeSAML, Enabled: false},
			nil,
		},
	}
	for id, want := range map[string]bool{"on": true, "off": false, "absent": false, "": false} {
		if got := reg.ProfileEnabled(id); got != want {
			t.Errorf("ProfileEnabled(%q) = %v, want %v", id, got, want)
		}
	}
	if allocs := testing.AllocsPerRun(100, func() { _ = reg.ProfileEnabled("on") }); allocs != 0 {
		t.Fatalf("ProfileEnabled allocates %.0f per call; it runs on every proxied request", allocs)
	}
}

// ---------------------------------------------------------------------------
// The SAML-ONLY deployment: no local account, no legacy provider, no
// credential-capable profile. Codex P2 on #1564.
//
// Every gate above installs a local admin (c72Setup does, deliberately), which
// keeps `credCapable` true and therefore keeps resolveRequestAuth's
// `authRequired` gate OPEN after the provider goes dark. That is the shape of
// an appliance that has one. It is not the only shape: `cfg.user` empty with
// no legacy provider is a state the same function contemplates by name ("when
// no user is set"), and `authRequired` exists precisely to go false in it.
//
// In that deployment the two predicates that decide a session's fate disagree
// about what "the provider is still there" means:
//
//   - sessionProviderLive (arm 1, CHAOS-88) asks ProfileEnabled — ENABLED.
//   - ssoCapable asks HasEnabledInteractiveProvider — enabled AND LIVE.
//
// A staleness-ceiling retirement darkens an ENABLED profile, so arm 1 would
// keep the session (the decision this file exists to pin) while the gate above
// it closes and arm 1 never runs. The session is not revoked; it is never
// read. That is worse than the revocation these tests forbid: a revocation is
// counted and logged, and this is silent.
// ---------------------------------------------------------------------------

// c72NoCredentialBackend strips the local admin c72Setup installed, leaving a
// deployment whose ONLY identity backend is the browser-only SAML profile.
// c72Setup's cleanup restores the real values.
//
// It also empties the roster for the test's duration (restored on cleanup).
// These fixtures share the global cfg, so an account an earlier test left in
// cfg.uiUsers would survive the strip — and a roster with accounts but no
// verifier is not "no backend": the HTTP proxy fails it closed
// (SEC-AUTHENABLED-1). The premise is asserted, not assumed.
func c72NoCredentialBackend(t *testing.T) {
	t.Helper()
	cfg.mu.Lock()
	cfg.user, cfg.passHash = "", nil
	prevUsers := cfg.uiUsers
	cfg.uiUsers = nil
	cfg.authRevision++
	cfg.mu.Unlock()
	cfg.cache.clear()
	t.Cleanup(func() {
		cfg.mu.Lock()
		cfg.uiUsers = prevUsers
		cfg.mu.Unlock()
	})
	if hasCredentialCapableProvider() {
		t.Fatal("setup: the deployment must have no credential-capable validator")
	}
	if cfg.AuthEnabled() {
		t.Fatal("setup: the deployment must have no roster account and no provider")
	}
}

// DEFECT GATE: a dark-but-enabled SAML profile in a SAML-only deployment must
// still have its sessions read. Pre-fix this returned identity "" with no
// revocation counted — the cookie was never looked at.
func TestChaos88_DefectSAMLOnlyDarkProfileStillReadsItsSessions(t *testing.T) {
	c72Setup(t, "dark")
	c72NoCredentialBackend(t)
	c72AssertAuthenticates(t, "a dark enabled profile in a SAML-only deployment")
}

// CONTROL: the operator's revocation lever still works in this deployment.
// Opening the gate for an enabled-but-dark profile must not reopen it for a
// provider that was deleted or disabled — that is the whole lever this sweep
// delivers, and widening the predicate is the obvious way to break it.
//
// `proceed` is deliberately NOT asserted false here. With no credential
// backend and no live SSO, a 407 or captive redirect is unfulfillable, so the
// frozen spec's no-backend row says the request falls through to Stage-2
// unauthenticated and default-deny does the work. What must hold is that the
// cookie buys NOTHING: no identity, no groups.
func TestChaos88_ControlSAMLOnlyRemovalStillRevokes(t *testing.T) {
	for _, posture := range []string{"deleted", "disabled"} {
		t.Run(posture, func(t *testing.T) {
			c72Setup(t, posture)
			c72NoCredentialBackend(t)
			if idpRegistry.HasEnabledInteractiveProfile() {
				t.Fatalf("setup: %s must leave no ENABLED interactive profile", posture)
			}
			outcome, proceed, code := c72Resolve(t, "corp")
			if outcome.identity != "" || len(outcome.groups) != 0 {
				t.Fatalf("a %s provider must not authenticate in a SAML-only deployment: "+
					"proceed=%v identity=%q groups=%v status=%d", posture, proceed, outcome.identity, outcome.groups, code)
			}
		})
	}
}

// CONTROL: the gate must key on an enabled interactive PROFILE, not on "a
// cookie was presented". An appliance that deliberately runs without any
// identity backend must stay inert — otherwise any client could reopen Stage-1
// on it by attaching a cookie.
func TestChaos88_ControlNoIdentityBackendStaysInert(t *testing.T) {
	c72Setup(t, "deleted")
	c72NoCredentialBackend(t)
	outcome, proceed, _ := c72Resolve(t, "corp")
	if !proceed || outcome.identity != "" || outcome.source != "unauth" {
		t.Fatalf("a no-backend deployment must stay inert: proceed=%v identity=%q source=%q",
			proceed, outcome.identity, outcome.source)
	}
	// The cookie must not even be READ here, which is what separates the fix
	// from the cheapest wrong one — opening arm 1 unconditionally. That shape
	// satisfies every assertion above and still charges a refusal on an
	// appliance that federates nothing, so the counter is the discriminator.
	if got := sessionProviderRevokedCount(); got != 0 {
		t.Fatalf("no stored profile: the cookie must not be read at all, refusals = %d", got)
	}
}

// CONTROL: the fix must not make an unfulfillable challenge reachable. In the
// SAML-only dark deployment WITHOUT a cookie, arms 2 and 3 must still be
// skipped — the request falls through exactly as it did before, with no 407,
// no redirect and no per-request inert log on the proxy hot path.
func TestChaos88_ControlSAMLOnlyDarkWithoutACookieIsUnchanged(t *testing.T) {
	c72Setup(t, "dark")
	c72NoCredentialBackend(t)
	w := httptest.NewRecorder()
	outcome, proceed := resolveRequestAuth(w, c72Request(t, "<none>"), "192.0.2.10", "chaos-88")
	if !proceed || outcome.identity != "" || outcome.source != "unauth" {
		t.Fatalf("no cookie must fall through untouched: proceed=%v identity=%q source=%q",
			proceed, outcome.identity, outcome.source)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("no cookie must not be challenged: status=%d", w.Code)
	}
}
