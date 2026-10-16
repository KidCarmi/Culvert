package main

// session_provider_availability_test.go — CHAOS-72 narrowed by the owner
// decision on #1485/#1564: an unreachable IdP is degraded AVAILABILITY, not
// revocation. Only an explicit delete, disable or removal by ReplaceAll revokes
// the sessions a provider minted; a compile failure and the CHAOS-71
// staleness-ceiling retirement must not.
//
// Keyed on `LiveProvider` (enabled AND compiled), restarting a node while an
// IdP was unreachable logged out every session of that IdP — and sent those
// users to an IdP that was down. These gates fail against that shape.

import (
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
func TestChaos72_DarkEnabledProfileDoesNotRevoke(t *testing.T) {
	c72Setup(t, "dark")
	c72AssertAuthenticates(t, "a stored, enabled profile with no live provider")
}

// END TO END: the boot path with the IdP unreachable and nothing cached. Load
// logs the compile error and leaves the profile enabled-but-dark; a session
// that profile minted before the restart must keep authenticating.
func TestChaos72_CompileFailureDoesNotRevokeSessions(t *testing.T) {
	c72Setup(t, "deleted") // local admin + counter isolation; registry replaced below
	chaos71Env(t)
	idp := newChaos71IdP(t)
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

// END TO END: a provider retired at the CHAOS-71 staleness ceiling (#1485's
// retireStaleProvider) goes dark but stays enabled; its sessions survive. The
// seven-day expiry by itself must never become a mass logout.
func TestChaos72_StaleExpiryRetirementDoesNotRevokeSessions(t *testing.T) {
	c72Setup(t, "deleted")
	chaos71Env(t)
	idp := newChaos71IdP(t)
	if err := idpRegistry.Upsert(chaos71Profile("corp", idp.URL())); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	c72AssertAuthenticates(t, "a live provider (precondition)")

	src := idpRemoteDocumentSource(chaos71Profile("corp", idp.URL()))
	served := chaos71SeedStaleServe("corp", src)
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
func TestChaos72_ExplicitRemovalStillRevokesADarkProvider(t *testing.T) {
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
			p := chaos71Profile("corp", url)
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
			chaos71Env(t)
			idp := newChaos71IdP(t)
			if err := idpRegistry.Upsert(chaos71Profile("corp", idp.URL())); err != nil {
				t.Fatalf("upsert: %v", err)
			}
			src := idpRemoteDocumentSource(chaos71Profile("corp", idp.URL()))
			if !idpRegistry.retireStaleProvider("corp", src, chaos71SeedStaleServe("corp", src)) {
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
func TestChaos72_ProfileEnabledSemanticsAndAllocations(t *testing.T) {
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
