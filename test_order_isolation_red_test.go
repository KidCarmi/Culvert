package main

// test_order_isolation_red_test.go — PR-C7 RED proofs for two order
// dependencies the seeded determinism run (-shuffle=1788866999688368609,
// -count=2) exposed once PR-C2 cleared the latch that used to fail first.
//
// Each test rebuilds, deterministically and in-process, the state a
// predecessor leaves behind in that order and then runs the victim test
// unchanged, so the dependency is pinned without the shuffle.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"testing"
)

// A predecessor left rules in the global rewriter. After the corrupt
// admin_settings.json is quarantined, the seed-identity finalizer writes a
// fresh minimal ledger at the settings path — by design — so the victim's
// "file absent after quarantine" assertion only holds with an EMPTY
// rewriter, which it must establish itself.
func TestOrder_CorruptSettingsQuarantineWithSeededRewriter(t *testing.T) {
	saved := rewriter.List()
	t.Cleanup(func() { publishRewriteRules(saved) })
	publishRewriteRules([]RewriteRule{{Host: "seed.example", ReqSet: map[string]string{"X-Seed": "1"}}})

	TestLoadAdminSettings_CorruptFileQuarantinedNotOverwritten(t)
}

// A predecessor left an access rule in the global policy store. The reorder
// contract (2E-C) refuses a list that does not cover the whole access set
// with 409, so the victim's two-rule list is a state conflict unless it
// starts from a store it owns.
func TestOrder_PolicyReorderWithForeignAccessRule(t *testing.T) {
	extra := policyStore.Add(PolicyRule{Priority: 7790, Name: "reorder-foreign", Action: "allow"})
	t.Cleanup(func() { policyStore.Delete(extra.Priority) })

	TestAPIPolicyReorder_Post_Success(t)
}

// PR-C7b (the same seeded run, once PR-C7's two were isolated): a
// predecessor's best-effort admin-settings save (adminSettingsSave spawns a
// goroutine every admin mutation makes) was still in flight when the legacy
// LDAP sentinel test pinned and rewrote its fixture file, so the stale save
// landed on the fixture with the flag already reset and the load read
// `legacy_ldap_retired: false`. The fixture helper must drain pending saves
// BEFORE it hands the settings path to the test: with one held open here, a
// helper that drains cannot return until it is released.
func TestOrder_LegacyLDAPFixtureDrainsPendingSaves(t *testing.T) {
	release := make(chan struct{})
	adminSettingsSaveWG.Add(1)
	go func() {
		defer adminSettingsSaveWG.Done()
		<-release
	}()
	released := false
	unblock := func() {
		if !released {
			released = true
			close(release)
		}
	}
	t.Cleanup(unblock)

	done := make(chan struct{})
	go func() {
		defer close(done)
		withLegacyLDAPAuthorityReset(t)
	}()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	select {
	case <-done:
		t.Fatal("the LDAP fixture helper returned while a best-effort save was still pending; that save can land on the fixture file")
	default:
	}
	unblock()
	<-done
}

// PR-C7b: the R3 premise arms the process-global rejected-document latch.
// upEnv resets it at ENTRY (PR-C2), which protects the next UPSTREAM test
// only; a non-upstream successor's save carried the rejected sections
// forward verbatim and its load logged `duplicate_authority` (the LDAP
// sentinel test above). The latch must not outlive the test that armed it.
func TestOrder_RejectedDocumentLatchDoesNotOutliveItsTest(t *testing.T) {
	t.Run("r3", TestUpstreamV2C_R3_RejectedDocumentFreezesMutationsAndKeyMinting)
	if _, _, ok := upstreamRetainedSections(); ok {
		t.Fatal("the rejected-document latch armed by R3 is still set after R3 finished")
	}
	if st := getUpstreamState(); st.Degraded != nil {
		t.Fatalf("the managed degradation surface armed by R3 is still set after R3 finished: %+v", st.Degraded)
	}
}

// PR-C16 RED — the CI-shaped seeded shuffle (`-shuffle=1788873409540952482
// ./... -count=2`, read-only /data) failed TestIdentityIngress_NoBackendSpoofDenied
// with "log entry for 127.0.0.1:43439 attributed to identity \"alice\"" while
// the test's OWN request was logged with an EMPTY identity: the assertion
// judged every ring entry whose host matched the backend's ephemeral port,
// and an earlier test that authenticated alice against a backend on the
// same recycled port had left its entry in the ring. Reproduced
// deterministically: a stale alice entry for the backend's host is recorded
// before the spoofed request, and the snapshot-scoped assertion must judge
// only what THIS request produced.
func TestOrder_IdentityIngressAttributionIsScopedToOwnRequest(t *testing.T) {
	backend, cb := startCountingBackend(t)
	setupProxyTest(t)

	origReg := idpRegistry
	idpRegistry = &IdPRegistry{}
	t.Cleanup(func() { idpRegistry = origReg })

	policyStore.Add(PolicyRule{
		Priority: 1, Name: "alice-allow", DestFQDN: "*", SourceIdentity: "alice", Action: ActionAllow,
	})
	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	// The stale entry: an earlier test's authenticated request to a backend
	// that sat on the same ephemeral port.
	recordRequest("127.0.0.1", "GET", u.Host, "OK", "alice-allow", "allow", "alice", "")

	srv := httptest.NewServer(http.HandlerFunc(handleRequest))
	t.Cleanup(srv.Close)
	proxyURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	prev := logGet()
	if got := spoofedGet(t, proxyURL, backend.URL+"/", "alice"); got != http.StatusForbidden {
		t.Fatalf("spoofed request: status %d, want 403", got)
	}
	if cb.hitCount() != 0 {
		t.Fatalf("spoofed request reached upstream %d times, want 0", cb.hitCount())
	}
	assertNoIdentityAttributionSince(t, u.Host, prev)
}

// #1527 (seed 1792141333146841338): TestAPISyslogConfig_Post_EmptyAddr's
// best-effort save was still in flight when
// TestAdminSettings_LegacyMigrationSealsUserinfo swapped the settings path to
// its fixture. The detached SaveAdminSettings read the NEW path and wrote a
// full snapshot (current SaaS schema, the live pool's empty v2 document) over
// the legacy fixture before the load, so no migration ran and the file held
// "Entries:[]". swapAdminSettingsPath must drain pending saves before it hands
// the path over: with one held open here, a draining helper cannot return.
func TestOrder_SwapAdminSettingsPathDrainsPendingSaves(t *testing.T) {
	release := make(chan struct{})
	adminSettingsSaveWG.Add(1)
	go func() {
		defer adminSettingsSaveWG.Done()
		<-release
	}()
	released := false
	unblock := func() {
		if !released {
			released = true
			close(release)
		}
	}
	t.Cleanup(unblock)

	done := make(chan struct{})
	go func() {
		defer close(done)
		swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))
	}()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	select {
	case <-done:
		// Release the held save BEFORE failing: t.Fatal runs cleanups LIFO, so
		// the helper's own draining cleanup would otherwise wait on it forever
		// and a regression would hang instead of failing.
		unblock()
		t.Fatal("swapAdminSettingsPath returned while a best-effort save was still pending; that save reads the new path and can overwrite the test's fixture")
	default:
	}
	unblock()
	<-done
}
