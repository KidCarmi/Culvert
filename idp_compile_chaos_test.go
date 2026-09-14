package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// CHAOS-66 — the IdP registry's compile step.
//
// Gate inventory. Every DEFECT gate below was verified failing against the
// pre-fix shape (recorded per gate); the CONTROLS exist because the cheapest
// way to pass several of the defect gates is to stop compiling altogether,
// which would freeze the identity set permanently and is far worse than the
// defect.
//
// The locking and reuse gates drive the compile through compileIdPProfileFn,
// so they are deterministic: no network, no DNS, no timing thresholds. The one
// gate that does touch a socket is the permanent DEFECT PROOF — the premise
// that a real compile blocks on a third party. If a future change makes the
// compile network-free, that gate fails and whoever made it true updates the
// claim in the same change (the CHAOS-56 BareGracefulStop role).

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

// stubIdPProvider is a live provider that does nothing. Identity (the pointer)
// is the observable the reuse gates read.
type stubIdPProvider struct{ id string }

func (s *stubIdPProvider) Name() string                                     { return "stub:" + s.id }
func (s *stubIdPProvider) DisplayName() string                              { return s.Name() }
func (s *stubIdPProvider) Verify(_, _ string) bool                          { return false }
func (s *stubIdPProvider) ResolveIdentity(_, _ string) (*Identity, bool)    { return nil, false }
func (s *stubIdPProvider) CaptiveLoginURL(_ string, _ *http.Request) string { return "" }

// withCompileSeam installs a fresh registry and a compile function the test
// controls, and restores both afterwards. It returns a counter of compiles.
func withCompileSeam(t *testing.T, fn func(context.Context, *IdPProfile) (IdentityProvider, error)) *int32Counter {
	t.Helper()
	origRegistry := idpRegistry
	origCompile := compileIdPProfileFn
	origBase := cfg.ProxyBaseURL()
	idpRegistry = &IdPRegistry{live: make(map[string]*liveIdP)}
	resetIdPCompileCountersForTest()
	var n int32Counter
	compileIdPProfileFn = func(ctx context.Context, p *IdPProfile) (IdentityProvider, error) {
		n.add(1)
		return fn(ctx, p)
	}
	t.Cleanup(func() {
		idpRegistry = origRegistry
		compileIdPProfileFn = origCompile
		SetProxyBaseURL(origBase)
		resetIdPCompileCountersForTest()
	})
	return &n
}

type int32Counter struct {
	mu sync.Mutex
	n  int
}

func (c *int32Counter) add(d int) { c.mu.Lock(); c.n += d; c.mu.Unlock() }
func (c *int32Counter) get() int  { c.mu.Lock(); defer c.mu.Unlock(); return c.n }

func chaos66Profile(id string) *IdPProfile {
	return &IdPProfile{
		ID: id, Name: "Profile " + id, Type: IdPTypeSAML, Enabled: true,
		SAML: &SAMLProfileConfig{MetadataXML: "<EntityDescriptor/>", GroupsAttribute: "groups"},
	}
}

func okCompile(_ context.Context, p *IdPProfile) (IdentityProvider, error) {
	return &stubIdPProvider{id: p.ID}, nil
}

// ---------------------------------------------------------------------------
// DEFECT GATES
// ---------------------------------------------------------------------------

// TestChaos66_UpsertDoesNotHoldTheRegistryLockAcrossCompile is the sharpest
// gate. resolveRequestAuth (proxy.go) calls HasEnabledInteractiveProvider() on
// EVERY proxied request, and sync.RWMutex is writer-preferring, so a writer
// blocked inside the compile also blocks every subsequent reader.
//
// Verified failing against the pre-fix shape (compile under r.mu.Lock), where
// the probe never returned while the compile was in flight. Against the real
// binary the same defect was measured with a real wedged origin: the probe was
// still blocked after 3 s and Upsert ran the full 10 s discovery timeout.
//
// STRUCTURAL, not timing-based: the compile blocks until this test releases it,
// so a regression fails on any hardware, at any load, with or without -race.
func TestChaos66_UpsertDoesNotHoldTheRegistryLockAcrossCompile(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()

	entered := make(chan struct{})
	var enteredOnce sync.Once
	withCompileSeam(t, func(_ context.Context, p *IdPProfile) (IdentityProvider, error) {
		enteredOnce.Do(func() { close(entered) })
		<-release
		return &stubIdPProvider{id: p.ID}, nil
	})

	upsertDone := make(chan error, 1)
	go func() { upsertDone <- idpRegistry.Upsert(chaos66Profile("slow")) }()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("compile never started")
	}

	probed := make(chan struct{})
	go func() {
		defer close(probed)
		_ = idpRegistry.HasEnabledInteractiveProvider() // proxy.go:349, per request
		_ = idpRegistry.HasEnabledCredentialProvider()
		_ = idpRegistry.EnabledCredentialProviders()
	}()
	select {
	case <-probed:
	case <-time.After(5 * time.Second):
		t.Fatal("the per-request registry probes blocked behind an in-flight IdP compile " +
			"— a wedged IdP origin stalls every proxied request")
	}

	unblock()
	if err := <-upsertDone; err != nil {
		t.Fatalf("Upsert: %v", err)
	}
}

// TestChaos66_PersistDoesNotHoldTheRegistryLock is the same finding reached by
// the other route: r.persist is an atomicWriteFile (temp + fsync + rename), and
// under r.mu a wedged or full volume stalled the same per-request probes.
//
// Verified failing against the pre-fix shape (persist under r.mu.Lock).
func TestChaos66_PersistDoesNotHoldTheRegistryLock(t *testing.T) {
	withCompileSeam(t, okCompile)

	// Making a real atomicWriteFile block is platform-dependent and fragile, so
	// the gate asserts the property that makes the stall impossible rather than
	// the stall itself: a mutation in progress — which is exactly the window the
	// persist occupies — holds writeMu and NOT r.mu, so the read path answers
	// throughout. Under the pre-fix shape the persist ran under r.mu.Lock, and
	// that is the lock the readers would have queued behind.
	//
	// reg is captured deliberately: withCompileSeam restores the package global
	// on cleanup, so a goroutine that re-read idpRegistry would release a
	// different registry's mutex.
	reg := idpRegistry

	held := make(chan struct{})
	releaseHold := make(chan struct{})
	holderDone := make(chan struct{})
	go func() {
		defer close(holderDone)
		reg.writeMu.Lock()
		defer reg.writeMu.Unlock()
		close(held)
		<-releaseHold
	}()
	<-held
	// Join the holder before the test returns, so the lock is never held across
	// the seam's cleanup.
	defer func() { close(releaseHold); <-holderDone }()

	probed := make(chan struct{})
	go func() {
		defer close(probed)
		_ = reg.HasEnabledInteractiveProvider()
		_ = reg.All()
	}()
	select {
	case <-probed:
	case <-time.After(5 * time.Second):
		t.Fatal("a registry mutation in progress blocked the read path")
	}
}

// TestChaos66_UnchangedProfilesAreNotRecompiledOnSnapshotApply is the fix for
// the amplifier. A control-plane snapshot is published for ANY config mutation
// anywhere in the fleet, so without this every policy-rule edit made every node
// re-fetch every SAML metadata document and every OIDC discovery document.
//
// Verified failing against the pre-fix shape: measured against the real
// registry, five byte-identical ReplaceAll calls rebuilt the live provider five
// times.
func TestChaos66_UnchangedProfilesAreNotRecompiledOnSnapshotApply(t *testing.T) {
	compiles := withCompileSeam(t, okCompile)

	set := func() []*IdPProfile { return []*IdPProfile{chaos66Profile("corp")} }
	if err := idpRegistry.ReplaceAll(set()); err != nil {
		t.Fatalf("first ReplaceAll: %v", err)
	}
	if compiles.get() != 1 {
		t.Fatalf("first apply compiled %d times, want 1", compiles.get())
	}
	first, _ := idpRegistry.LiveProvider("corp")

	for i := 0; i < 5; i++ {
		if err := idpRegistry.ReplaceAll(set()); err != nil {
			t.Fatalf("ReplaceAll %d: %v", i, err)
		}
	}
	if got := compiles.get(); got != 1 {
		t.Fatalf("five byte-identical snapshot applies performed %d compiles, want 1 "+
			"— each one is an outbound fetch at the IdP", got)
	}
	if cur, _ := idpRegistry.LiveProvider("corp"); cur != first {
		t.Fatal("the live provider was rebuilt despite an unchanged profile")
	}
	if _, _, reused := idpCompileCounters(); reused != 5 {
		t.Fatalf("culvert_idp_compile_reused_total = %d, want 5", reused)
	}
}

// TestChaos66_UnreachableIdPOriginDoesNotFreezeAnUnchangedSnapshot is the
// headline consequence, expressed as a gate. On the Data Plane poll path
// (fetchAndApply) syncSnapshotIdPProfiles runs BEFORE applyConfigSnapshot and
// a failure returns, so a failed IdP compile means no blocklist, no policy
// rules, no rate limits — and lastVersion is not advanced, so the next poll
// re-attempts the same fetch every 30 s, forever.
//
// This change does not relitigate that abort posture (recorded as IDP-3); it
// removes the reason it triggers. Once a profile is live, an origin that stops
// answering can no longer fail an apply that did not ask for it.
//
// Verified failing against the pre-fix shape, where the second apply recompiled
// and therefore inherited the unreachable origin's error.
func TestChaos66_UnreachableIdPOriginDoesNotFreezeAnUnchangedSnapshot(t *testing.T) {
	reachable := true
	withCompileSeam(t, func(_ context.Context, p *IdPProfile) (IdentityProvider, error) {
		if !reachable {
			return nil, errors.New("dial tcp: connect: connection refused")
		}
		return &stubIdPProvider{id: p.ID}, nil
	})

	set := func() []*IdPProfile { return []*IdPProfile{chaos66Profile("corp")} }
	if err := idpRegistry.ReplaceAll(set()); err != nil {
		t.Fatalf("first ReplaceAll: %v", err)
	}

	// The IdP's metadata tier goes down. Nothing about this node's identity
	// configuration changed; the control plane publishes a new snapshot because
	// somebody edited a policy rule.
	reachable = false
	if err := idpRegistry.ReplaceAll(set()); err != nil {
		t.Fatalf("an unreachable IdP origin rejected a snapshot whose IdP profiles "+
			"were unchanged — the node's whole config sync is frozen on a third "+
			"party it did not need to ask: %v", err)
	}
	if _, ok := idpRegistry.LiveProvider("corp"); !ok {
		t.Fatal("the live provider was dropped")
	}
}

// TestChaos66_CompilesShareOneEnvelope pins the CHAOS-58/CHAOS-65 rule: the
// budget is for the whole operation, not a fresh allowance per profile. Before
// this change N SAML profiles could serialise into N x 15 s on the Data Plane's
// poll goroutine and on the boot path.
func TestChaos66_CompilesShareOneEnvelope(t *testing.T) {
	var deadlines []time.Time
	var mu sync.Mutex
	withCompileSeam(t, func(ctx context.Context, p *IdPProfile) (IdentityProvider, error) {
		d, ok := ctx.Deadline()
		if !ok {
			return nil, errors.New("compile ran with no deadline")
		}
		mu.Lock()
		deadlines = append(deadlines, d)
		mu.Unlock()
		return &stubIdPProvider{id: p.ID}, nil
	})

	profiles := []*IdPProfile{chaos66Profile("a"), chaos66Profile("b"), chaos66Profile("c")}
	if err := idpRegistry.ReplaceAll(profiles); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	if len(deadlines) != 3 {
		t.Fatalf("compiled %d profiles, want 3", len(deadlines))
	}
	for i := 1; i < len(deadlines); i++ {
		if !deadlines[i].Equal(deadlines[0]) {
			t.Fatalf("profile %d got its own deadline (%v) instead of sharing the "+
				"operation envelope (%v) — N profiles can serialise into N x the budget",
				i, deadlines[i], deadlines[0])
		}
	}
}

// TestChaos66_ProxyBaseURLChangeForcesRecompile is the ambient-input trap the
// reuse rule had to avoid. NewSAMLProvider reads proxyBaseURL(nil) and turns it
// into the SP EntityID and ACS URL, and applyExternalAuthSnapshotSettings sets
// that value immediately before the IdP sync precisely because the two are
// coupled. A fingerprint over the profile bytes alone would have reused a
// provider carrying the wrong EntityID — a defect the fix would have
// INTRODUCED.
func TestChaos66_ProxyBaseURLChangeForcesRecompile(t *testing.T) {
	compiles := withCompileSeam(t, okCompile)

	SetProxyBaseURL("https://proxy-a.example.com")
	set := func() []*IdPProfile { return []*IdPProfile{chaos66Profile("corp")} }
	if err := idpRegistry.ReplaceAll(set()); err != nil {
		t.Fatalf("first ReplaceAll: %v", err)
	}
	if compiles.get() != 1 {
		t.Fatalf("compiles = %d, want 1", compiles.get())
	}

	SetProxyBaseURL("https://proxy-b.example.com")
	if err := idpRegistry.ReplaceAll(set()); err != nil {
		t.Fatalf("second ReplaceAll: %v", err)
	}
	if compiles.get() != 2 {
		t.Fatal("a changed proxy base URL reused the old provider — its SAML SP " +
			"EntityID and ACS URL are derived from that value")
	}
}

// ---------------------------------------------------------------------------
// PERMANENT DEFECT PROOF
// ---------------------------------------------------------------------------

// TestChaos66_CompilingAMetadataURLProfileBlocksOnTheThirdParty pins the
// premise the whole sweep rests on: compiling a SAML profile that carries a
// metadata_url performs a blocking outbound fetch to an operator-named third
// party. Every gate above is about containing that fact.
//
// If a future change makes the compile network-free (a cached, refreshing
// metadata resolver — register row AU-6), this fails, and whoever made it true
// updates the claim in the same change rather than leaving gates that guard
// nothing.
func TestChaos66_CompilingAMetadataURLProfileBlocksOnTheThirdParty(t *testing.T) {
	// An origin that completes the TCP handshake and then never answers: the
	// ordinary wedged-web-tier fault, and the one CHAOS-58 bounded for LDAP.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { <-stop; c.Close() }()
		}
	}()

	origDial := ssrfSafeDialContext
	ssrfSafeDialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}
	t.Cleanup(func() { ssrfSafeDialContext = origDial })

	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := fetchSAMLMetadata(ctx, &SAMLProfileConfig{
			MetadataURL: "https://idp.example.com/saml/metadata",
		})
		done <- err
	}()

	select {
	case err := <-done:
		// It must not have returned INSTANTLY: a network-free compile would.
		// It must have returned by the envelope: that is the bound this change
		// gives it.
		if err == nil {
			t.Fatal("a silent origin produced a successful metadata fetch")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the metadata fetch outlived the caller's envelope — the compile " +
			"budget does not bound it")
	}
}

// TestChaos66_CompileEnvelopeBoundsTheFetch proves the envelope is what ends
// the fetch, not the client's own Timeout: a context cancelled well inside the
// 15 s client timeout must end the fetch.
func TestChaos66_CompileEnvelopeBoundsTheFetch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { <-stop; c.Close() }()
		}
	}()
	origDial := ssrfSafeDialContext
	ssrfSafeDialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}
	t.Cleanup(func() { ssrfSafeDialContext = origDial })

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = fetchSAMLMetadata(ctx, &SAMLProfileConfig{
		MetadataURL: "https://idp.example.com/saml/metadata",
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("want an error from a silent origin")
	}
	// idpCompileBudget is 15 s; if the envelope were ignored the fetch would run
	// to that. Generous bound so this can never flake on a loaded runner.
	if elapsed > 5*time.Second {
		t.Fatalf("fetch took %v — the caller's envelope did not bound it", elapsed)
	}
}

// ---------------------------------------------------------------------------
// CONTROLS
// ---------------------------------------------------------------------------

// TestChaos66_Control_ChangedProfileIsStillRecompiled. The cheapest way to pass
// every reuse gate is to stop compiling, which would freeze the identity set at
// whatever was first loaded and silently ignore every later IdP change.
func TestChaos66_Control_ChangedProfileIsStillRecompiled(t *testing.T) {
	compiles := withCompileSeam(t, okCompile)

	if err := idpRegistry.ReplaceAll([]*IdPProfile{chaos66Profile("corp")}); err != nil {
		t.Fatalf("first ReplaceAll: %v", err)
	}
	changed := chaos66Profile("corp")
	changed.SAML.MetadataXML = "<EntityDescriptor id=\"rotated\"/>"
	if err := idpRegistry.ReplaceAll([]*IdPProfile{changed}); err != nil {
		t.Fatalf("second ReplaceAll: %v", err)
	}
	if compiles.get() != 2 {
		t.Fatalf("a CHANGED profile was not recompiled (compiles=%d) — the registry "+
			"would ignore every IdP change the control plane pushes", compiles.get())
	}
}

// TestChaos66_Control_AdminUpsertAlwaysRecompiles pins the deliberate asymmetry.
// Re-saving an unchanged profile is the documented remedy for register row AU-6
// (SAML metadata and OIDC discovery are fetched once and never refreshed, so an
// IdP signing-certificate rollover breaks assertion validation until the profile
// is re-saved or the process restarts). Extending the reuse rule to Upsert would
// delete the only recovery path this appliance has for a rotated IdP
// certificate.
func TestChaos66_Control_AdminUpsertAlwaysRecompiles(t *testing.T) {
	compiles := withCompileSeam(t, okCompile)

	p := chaos66Profile("corp")
	if err := idpRegistry.Upsert(p); err != nil {
		t.Fatalf("first Upsert: %v", err)
	}
	same := chaos66Profile("corp")
	if err := idpRegistry.Upsert(same); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	if compiles.get() != 2 {
		t.Fatalf("an unchanged admin re-save skipped the compile (compiles=%d) — that "+
			"re-save is the only way an operator can pick up a rotated IdP signing "+
			"certificate (AU-6)", compiles.get())
	}
}

// TestChaos66_Control_FailedCompileStillRejectsTheReplacement. Reuse must not
// weaken ReplaceAll's all-or-nothing staging: a profile that is genuinely NEW
// or CHANGED and cannot be compiled still rejects the whole replacement, and
// the previous live set stays authoritative.
func TestChaos66_Control_FailedCompileStillRejectsTheReplacement(t *testing.T) {
	withCompileSeam(t, func(_ context.Context, p *IdPProfile) (IdentityProvider, error) {
		if p.ID == "broken" {
			return nil, errors.New("metadata: fetch failed")
		}
		return &stubIdPProvider{id: p.ID}, nil
	})

	if err := idpRegistry.ReplaceAll([]*IdPProfile{chaos66Profile("good")}); err != nil {
		t.Fatalf("first ReplaceAll: %v", err)
	}
	good, _ := idpRegistry.LiveProvider("good")

	err := idpRegistry.ReplaceAll([]*IdPProfile{chaos66Profile("good"), chaos66Profile("broken")})
	if err == nil {
		t.Fatal("a replacement containing an uncompilable NEW profile was accepted")
	}
	if !strings.Contains(err.Error(), "broken") {
		t.Fatalf("error does not name the offending profile: %v", err)
	}
	if cur, ok := idpRegistry.LiveProvider("good"); !ok || cur != good {
		t.Fatal("the previously working provider did not stay authoritative")
	}
	if _, ok := idpRegistry.LiveProvider("broken"); ok {
		t.Fatal("the uncompilable profile became live")
	}
}

// TestChaos66_Control_DisableThenEnableRecompiles. A disabled profile has no
// live entry, so re-enabling must compile — this is the other operator-visible
// path to a fresh metadata fetch and it must survive the reuse rule.
func TestChaos66_Control_DisableThenEnableRecompiles(t *testing.T) {
	compiles := withCompileSeam(t, okCompile)

	if err := idpRegistry.ReplaceAll([]*IdPProfile{chaos66Profile("corp")}); err != nil {
		t.Fatalf("enable: %v", err)
	}
	off := chaos66Profile("corp")
	off.Enabled = false
	if err := idpRegistry.ReplaceAll([]*IdPProfile{off}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := idpRegistry.ReplaceAll([]*IdPProfile{chaos66Profile("corp")}); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if compiles.get() != 2 {
		t.Fatalf("compiles = %d, want 2 (a disable/enable cycle must refetch)", compiles.get())
	}
}

// ---------------------------------------------------------------------------
// FINGERPRINT contract
// ---------------------------------------------------------------------------

// TestChaos66_FingerprintIgnoresDiscoveredEndpoints. The five OIDC endpoint
// fields are written back by NewOIDCFlowProvider from the discovery document,
// so they are OUTPUTS of a compile. If the fingerprint counted them, a
// freshly-compiled profile would never match the identical admin input and
// every reuse would be defeated — the fix would silently do nothing.
func TestChaos66_FingerprintIgnoresDiscoveredEndpoints(t *testing.T) {
	bare := &IdPProfile{
		ID: "o", Name: "O", Type: IdPTypeOIDC, Enabled: true,
		OIDC: &OIDCProfileConfig{Issuer: "https://idp.example.com", ClientID: "c"},
	}
	discovered := &IdPProfile{
		ID: "o", Name: "O", Type: IdPTypeOIDC, Enabled: true,
		OIDC: &OIDCProfileConfig{
			Issuer: "https://idp.example.com", ClientID: "c",
			AuthorizationEndpoint: "https://idp.example.com/authorize",
			TokenEndpoint:         "https://idp.example.com/token",
			JWKsURI:               "https://idp.example.com/jwks",
		},
	}
	if idpCompileFingerprint(bare) != idpCompileFingerprint(discovered) {
		t.Fatal("the discovery-derived endpoints changed the fingerprint — every " +
			"reuse would be defeated and the fix would be a no-op")
	}
}

// TestChaos66_FingerprintSeparatesCompileRelevantChanges. Every field an
// operator can change that affects what a compile produces must change the
// fingerprint. A miss here is a STALE PROVIDER, which is the one direction the
// reuse rule may not err in.
func TestChaos66_FingerprintSeparatesCompileRelevantChanges(t *testing.T) {
	base := chaos66Profile("corp")
	fp := idpCompileFingerprint(base)

	mutations := map[string]func(*IdPProfile){
		"metadata xml":     func(p *IdPProfile) { p.SAML.MetadataXML = "<other/>" },
		"metadata url":     func(p *IdPProfile) { p.SAML.MetadataURL = "https://x.example/m" },
		"name id format":   func(p *IdPProfile) { p.SAML.NameIDFormat = "urn:x" },
		"groups attribute": func(p *IdPProfile) { p.SAML.GroupsAttribute = "memberOf" },
		"email attribute":  func(p *IdPProfile) { p.SAML.EmailAttribute = "mail" },
		"name attribute":   func(p *IdPProfile) { p.SAML.NameAttribute = "cn" },
		"type":             func(p *IdPProfile) { p.Type = IdPTypeOIDC },
		"id":               func(p *IdPProfile) { p.ID = "other" },
		"enabled":          func(p *IdPProfile) { p.Enabled = false },
		"email domains":    func(p *IdPProfile) { p.EmailDomains = []string{"corp.example"} },
		"priority":         func(p *IdPProfile) { p.Priority = 5 },
		"display name":     func(p *IdPProfile) { p.Name = "Renamed" },
	}
	for label, mutate := range mutations {
		p := chaos66Profile("corp")
		mutate(p)
		if idpCompileFingerprint(p) == fp {
			t.Errorf("changing %s did not change the compile fingerprint — a stale "+
				"provider would be reused", label)
		}
	}
}

// TestChaos66_FingerprintFailsSafeOnAnUncharacterisableProfile. A nil profile
// yields "", which can never equal a stored fingerprint, so the fallback is
// RECOMPILE — the pre-change behaviour. Never worse.
func TestChaos66_FingerprintFailsSafeOnAnUncharacterisableProfile(t *testing.T) {
	if got := idpCompileFingerprint(nil); got != "" {
		t.Fatalf("idpCompileFingerprint(nil) = %q, want \"\"", got)
	}
	if fp := idpCompileFingerprint(chaos66Profile("corp")); fp == "" {
		t.Fatal("a well-formed profile produced the never-matching sentinel")
	}
}

// TestChaos66_ReuseRequiresANonEmptyFingerprint. Defense in depth for the rule
// above: even with a live entry whose fingerprint is the zero value (the shape
// tests build by hand, and the shape Load stores if a profile ever becomes
// uncharacterisable), reuse must not fire.
func TestChaos66_ReuseRequiresANonEmptyFingerprint(t *testing.T) {
	compiles := withCompileSeam(t, okCompile)
	idpRegistry.publish(
		[]*IdPProfile{chaos66Profile("corp")},
		map[string]*liveIdP{"corp": {provider: &stubIdPProvider{id: "corp"}}}, // fingerprint ""
	)
	if err := idpRegistry.ReplaceAll([]*IdPProfile{chaos66Profile("corp")}); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	if compiles.get() != 1 {
		t.Fatalf("compiles = %d, want 1 — an empty stored fingerprint must not "+
			"satisfy the reuse check", compiles.get())
	}
}

// ---------------------------------------------------------------------------
// Metrics emission rule
// ---------------------------------------------------------------------------

// TestChaos66_CompileMetricsEmitOnlyWhenConfigured pins the standing emission
// rule (socks5 / cluster_ca / dns): a flat zero exported by every appliance
// that never configured an identity provider is indistinguishable from one
// whose registry has stopped compiling, and the paging rule for the failure
// series is "> 0".
func TestChaos66_CompileMetricsEmitOnlyWhenConfigured(t *testing.T) {
	withCompileSeam(t, okCompile)

	var empty strings.Builder
	writeIdPCompileMetrics(&empty)
	if empty.Len() != 0 {
		t.Fatalf("a node with no IdP profiles exported compile metrics:\n%s", empty.String())
	}

	if err := idpRegistry.ReplaceAll([]*IdPProfile{chaos66Profile("corp")}); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	var configured strings.Builder
	writeIdPCompileMetrics(&configured)
	for _, want := range []string{
		"culvert_idp_compile_total 1",
		"culvert_idp_compile_failures_total 0",
		"culvert_idp_compile_reused_total 0",
	} {
		if !strings.Contains(configured.String(), want) {
			t.Errorf("missing %q in:\n%s", want, configured.String())
		}
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// TestChaos66_ConcurrentMutatorsAndReaders runs every mutation path against the
// per-request read path under -race. writeMu is what makes the liveSnapshot a
// mutation takes still authoritative when it publishes.
func TestChaos66_ConcurrentMutatorsAndReaders(t *testing.T) {
	withCompileSeam(t, okCompile)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = idpRegistry.HasEnabledInteractiveProvider()
				_ = idpRegistry.HasEnabledCredentialProvider()
				_ = idpRegistry.EnabledProviders()
				_ = idpRegistry.All()
				_ = idpRegistry.RouteByDomain("corp.example")
			}
		}()
	}
	for i := 0; i < 50; i++ {
		_ = idpRegistry.Upsert(chaos66Profile("a"))
		_ = idpRegistry.ReplaceAll([]*IdPProfile{chaos66Profile("a"), chaos66Profile("b")})
		_ = idpRegistry.Delete("b")
	}
	close(stop)
	wg.Wait()
}
