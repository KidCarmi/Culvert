package main

// idp_metadata_chaos_test.go — CHAOS-71 gates.
//
// Every DEFECT gate here was verified FAILING against the pre-fix tree before
// the fix was written (the reproduction is recorded in the PR and in
// roadmap/CHAOS-ENGINEERING-REVIEW.md §41). The CONTROLS matter as much: the
// cheapest way to pass every defect gate is to always prefer the cached
// document, which would silently stop this appliance from ever noticing an
// IdP-side signing-key rotation — strictly worse than the defect being fixed.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/idpmeta"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// ── fixtures ────────────────────────────────────────────────────────────────

// chaos71IdP is a real SAML IdP metadata endpoint that can be taken down on
// demand and counts every request it receives.
type chaos71IdP struct {
	srv  *httptest.Server
	down atomic.Bool
	hits atomic.Int64
	doc  atomic.Value // string
}

func newChaos71IdP(t *testing.T) *chaos71IdP {
	t.Helper()
	m := &chaos71IdP{}
	m.doc.Store(chaos71MetadataXML(t, "cert-A"))
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		m.hits.Add(1)
		if m.down.Load() {
			http.Error(w, "maintenance", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(m.doc.Load().(string)))
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *chaos71IdP) URL() string { return m.srv.URL + "/metadata" }

// rotateSigningKey replaces the published signing certificate, the way an IdP
// does on an automatic key rollover.
func (m *chaos71IdP) rotateSigningKey(t *testing.T) { m.doc.Store(chaos71MetadataXML(t, "cert-B")) }

func chaos71MetadataXML(t *testing.T, cn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/%s">
 <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
  <KeyDescriptor use="signing">
   <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo>
  </KeyDescriptor>
  <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>
 </IDPSSODescriptor>
</EntityDescriptor>`, cn, base64.StdEncoding.EncodeToString(der))
}

// chaos71Env isolates every process-global this sweep touches: the document
// store singleton, the metadata health record, the SSRF posture, the dialer
// AND the global IdP registry.
//
// The registry is the one that bites, and it is not hypothetical — it was
// caught by the full suite after these gates passed on their own. Tests that
// drive syncSnapshotIdPProfiles go through the GLOBAL idpRegistry, so a gate
// that compiles a SAML provider and does not restore it leaves that provider
// live for the rest of the package. `resolveRequestAuth` then reads
// `ssoCapable = idpRegistry.HasEnabledInteractiveProvider()` as true, flips
// `authRequired` on, and every later test that proxies a request without
// credentials gets 407 instead of 200 — which surfaced as twenty unrelated
// MITM/H2 failures in a package that had passed. That is the PR3d
// fence-pollution class, and under -shuffle it is order-dependent, so it must
// be isolated here rather than per test.
func chaos71Env(t *testing.T) *idpmeta.Store {
	t.Helper()
	prevRegistry := idpRegistry
	idpRegistry = &IdPRegistry{live: make(map[string]IdentityProvider)}
	t.Cleanup(func() { idpRegistry = prevRegistry })

	store := idpmeta.New(t.TempDir())
	t.Cleanup(swapIdPMetadataStore(store))
	resetIdPMetadataHealthForTest()
	t.Cleanup(resetIdPMetadataHealthForTest)
	t.Cleanup(ssrf.AllowLoopbackForTest())
	ssrf.CacheReset()
	t.Cleanup(ssrf.CacheReset)
	orig := ssrfSafeDialContext
	ssrfSafeDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	}
	t.Cleanup(func() { ssrfSafeDialContext = orig })
	return store
}

func chaos71Profile(id, metadataURL string) *IdPProfile {
	return &IdPProfile{
		ID: id, Name: id, Type: IdPTypeSAML, Enabled: true,
		SAML: &SAMLProfileConfig{MetadataURL: metadataURL},
	}
}

// chaos71DeadTLSEndpoint is an https URL on loopback whose connections are
// accepted and immediately closed — a metadata endpoint that is reachable but
// not answering — counting every connection.
func chaos71DeadTLSEndpoint(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	hits := &atomic.Int64{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			_ = c.Close()
		}
	}()
	return "https://" + ln.Addr().String() + "/metadata", hits
}

// ── DEFECT GATES ────────────────────────────────────────────────────────────

// D1 (defect): a provider that compiled successfully cannot be compiled again
// once its metadata endpoint stops answering. Pre-fix there was no
// last-known-good at all, so the second compile failed outright.
func TestChaos71_CompileSurvivesAnIdPOutageFromLastKnownGood(t *testing.T) {
	chaos71Env(t)
	idp := newChaos71IdP(t)

	if _, err := NewSAMLProvider(chaos71Profile("corp", idp.URL())); err != nil {
		t.Fatalf("healthy compile: %v", err)
	}
	idp.down.Store(true)

	prov, err := NewSAMLProvider(chaos71Profile("corp", idp.URL()))
	if err != nil {
		t.Fatalf("compile must survive the outage from the cached document: %v", err)
	}
	if prov == nil || prov.sp == nil || prov.sp.IDPMetadata == nil {
		t.Fatal("the degraded provider must carry real IdP metadata")
	}
	if snap := idpMetadataState(); snap.StaleServed != 1 {
		t.Fatalf("StaleServed = %d, want exactly 1 — the degradation must be counted, not silent", snap.StaleServed)
	}
}

// D1b (defect): the cache must survive a PROCESS RESTART — a boot during an
// IdP outage is the case that turned a transient blip into a permanent dark
// provider, and an in-memory cache would not have helped it at all.
func TestChaos71_CachedDocumentSurvivesRestart(t *testing.T) {
	store := chaos71Env(t)
	idp := newChaos71IdP(t)
	if _, err := NewSAMLProvider(chaos71Profile("corp", idp.URL())); err != nil {
		t.Fatalf("healthy compile: %v", err)
	}
	idp.down.Store(true)

	// A brand-new Store over the same directory is what the next boot builds.
	restore := swapIdPMetadataStore(idpmeta.New(storeDirOf(t, store)))
	t.Cleanup(restore)
	if _, err := NewSAMLProvider(chaos71Profile("corp", idp.URL())); err != nil {
		t.Fatalf("a boot during an IdP outage must compile from the persisted document: %v", err)
	}
}

// D3 (defect): one unreachable IdP rejected the ENTIRE profile set, including
// a profile whose metadata is pasted inline and needs no network at all.
// With a cached document the healthy set now applies.
func TestChaos71_OneRecoverableIdPNoLongerRejectsTheWholeSet(t *testing.T) {
	chaos71Env(t)
	idp := newChaos71IdP(t)

	reg := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := reg.ReplaceAll([]*IdPProfile{
		{ID: "inline-idp", Name: "inline-idp", Type: IdPTypeSAML, Enabled: true,
			SAML: &SAMLProfileConfig{MetadataXML: chaos71MetadataXML(t, "inline")}},
		chaos71Profile("remote-idp", idp.URL()),
	}); err != nil {
		t.Fatalf("healthy ReplaceAll: %v", err)
	}
	idp.down.Store(true)

	if err := reg.ReplaceAll([]*IdPProfile{
		{ID: "inline-idp", Name: "inline-idp", Type: IdPTypeSAML, Enabled: true,
			SAML: &SAMLProfileConfig{MetadataXML: chaos71MetadataXML(t, "inline")}},
		chaos71Profile("remote-idp", idp.URL()),
	}); err != nil {
		t.Fatalf("an IdP outage must not reject the profile set once a document is cached: %v", err)
	}
	if n := len(reg.EnabledInteractiveProviders()); n != 2 {
		t.Fatalf("%d live providers, want 2", n)
	}
}

// D4 (defect, the sharpest): a failed IdP metadata fetch ABORTED the config
// snapshot apply, so an IdP maintenance window stopped POLICY, blocklist and
// threat-feed distribution to every data plane in the fleet — a failure in the
// identity plane taking out the config plane.
func TestChaos71_IdPOutageNoLongerAbortsTheConfigSnapshot(t *testing.T) {
	chaos71Env(t)
	idp := newChaos71IdP(t)
	snap := ConfigSnapshot{Version: 42, IdPProfiles: []*IdPProfile{chaos71Profile("corp", idp.URL())}}

	if err := syncSnapshotIdPProfiles(snap); err != nil {
		t.Fatalf("healthy sync: %v", err)
	}
	idp.down.Store(true)

	snap.Version = 43
	if err := syncSnapshotIdPProfiles(snap); err != nil {
		t.Fatalf("an unreachable IdP must not veto the operator's config push: %v", err)
	}
}

// D6 (defect): amplification. Because the version never advanced, every DP
// retried the whole apply — fetch included — every 30 s, indefinitely.
// Measured 1:1 pre-fix. With a cached document the compile succeeds, so a
// failed fetch costs ONE connection per apply instead of blocking the version
// and repeating forever.
func TestChaos71_OutageDoesNotBlockTheVersionAndSoDoesNotAmplify(t *testing.T) {
	chaos71Env(t)
	idp := newChaos71IdP(t)
	if err := syncSnapshotIdPProfiles(ConfigSnapshot{Version: 1, IdPProfiles: []*IdPProfile{chaos71Profile("corp", idp.URL())}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	idp.down.Store(true)

	// The DP applies the new version once and MOVES ON — the pre-fix tree
	// could not advance past it, which is what made the retry unbounded.
	for v := 2; v <= 4; v++ {
		if err := syncSnapshotIdPProfiles(ConfigSnapshot{Version: int64(v), IdPProfiles: []*IdPProfile{chaos71Profile("corp", idp.URL())}}); err != nil {
			t.Fatalf("apply v%d during outage: %v", v, err)
		}
	}
}

// D2/D5 (defect): a boot-time compile failure was PERMANENT. Nothing in the
// process retried, so an IdP that came back thirty seconds later stayed dark
// until a restart or an admin re-save. The recovery loop closes it, and
// recovery is declared on OBSERVED evidence — a provider that actually
// compiled — never on elapsed time.
func TestChaos71_DarkProviderRecoversWithoutARestart(t *testing.T) {
	chaos71Env(t)
	idp := newChaos71IdP(t)
	idp.down.Store(true)

	dir := t.TempDir()
	path := filepath.Join(dir, "idp_profiles.json")
	seed := `[{"id":"corp","name":"corp","type":"saml","enabled":true,"saml":{"metadataUrl":"` + idp.URL() + `"}}]`
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	reg := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := reg.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if reg.HasEnabledInteractiveProvider() {
		t.Fatal("precondition: the provider must start dark")
	}
	if enabled, live := reg.enabledInteractiveCounts(); enabled != 1 || live != 0 {
		t.Fatalf("enabled=%d live=%d, want 1/0 — the divergence must be observable", enabled, live)
	}

	// Drive the loop's recovery step directly rather than sleeping out a
	// backoff: the gate is about the RECOVERY, not about the cadence (which
	// has its own gate below).
	idp.down.Store(false)
	for _, p := range reg.darkEnabledProfiles() {
		prov, err := compileIdPProfile(p)
		if err != nil {
			t.Fatalf("recompile after the IdP recovered: %v", err)
		}
		if !reg.publishRecompiled(p.ID, p, prov) {
			t.Fatal("publishRecompiled refused a legitimately recovered provider")
		}
	}
	if !reg.HasEnabledInteractiveProvider() {
		t.Fatal("the provider must be live after recovery, with no restart")
	}
	if enabled, live := reg.enabledInteractiveCounts(); enabled != live {
		t.Fatalf("enabled=%d live=%d, want them equal after recovery", enabled, live)
	}
}

// The recovery loop must return immediately on a healthy appliance — it must
// not be a goroutine that lives for the process lifetime doing nothing.
func TestChaos71_RecoveryLoopExitsWhenNothingIsDark(t *testing.T) {
	chaos71Env(t)
	done := make(chan struct{})
	go func() { defer close(done); runIdPRecoveryLoop(context.Background()) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the loop must return at once when every enabled profile is live")
	}
}

// The loop's wait must be INTERRUPTIBLE, so shutdown never sits out a backoff.
func TestChaos71_RecoveryLoopStopsPromptlyOnShutdown(t *testing.T) {
	chaos71Env(t)
	deadURL, _ := chaos71DeadTLSEndpoint(t)
	prev := idpRegistry
	idpRegistry = &IdPRegistry{
		live:     map[string]IdentityProvider{},
		profiles: []*IdPProfile{chaos71Profile("corp", deadURL)},
	}
	t.Cleanup(func() { idpRegistry = prev })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); runIdPRecoveryLoop(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancel must interrupt the backoff, not be waited out")
	}
}

// publishRecompiled must re-check EVERYTHING under the lock. The compile ran
// without it, so the profile may have been deleted, disabled or replaced in
// the meantime — publishing then would resurrect a deleted IdP or overwrite a
// newer provider with one built from older config.
func TestChaos71_RecompiledProviderIsNotPublishedOverANewerDecision(t *testing.T) {
	chaos71Env(t)
	idp := newChaos71IdP(t)
	p := chaos71Profile("corp", idp.URL())
	prov, err := compileIdPProfile(p)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	t.Run("deleted while compiling", func(t *testing.T) {
		reg := &IdPRegistry{live: map[string]IdentityProvider{}}
		if reg.publishRecompiled("corp", p, prov) {
			t.Fatal("a profile deleted while we compiled must not be resurrected")
		}
	})
	t.Run("disabled while compiling", func(t *testing.T) {
		disabled := chaos71Profile("corp", idp.URL())
		disabled.Enabled = false
		reg := &IdPRegistry{live: map[string]IdentityProvider{}, profiles: []*IdPProfile{disabled}}
		if reg.publishRecompiled("corp", disabled, prov) {
			t.Fatal("a profile disabled while we compiled must not go live")
		}
	})
	t.Run("replaced by a newer generation", func(t *testing.T) {
		newer := chaos71Profile("corp", idp.URL())
		reg := &IdPRegistry{live: map[string]IdentityProvider{}, profiles: []*IdPProfile{newer}}
		if reg.publishRecompiled("corp", p, prov) {
			t.Fatal("a stale generation must not overwrite a newer profile")
		}
	})
	t.Run("already live", func(t *testing.T) {
		reg := &IdPRegistry{live: map[string]IdentityProvider{"corp": prov}, profiles: []*IdPProfile{p}}
		if reg.publishRecompiled("corp", p, prov) {
			t.Fatal("an admin write or snapshot that got there first must win")
		}
	})
}

// ── SECURITY GATES ──────────────────────────────────────────────────────────

// The staleness ceiling is the security half of this change: past it, a
// withdrawn IdP signing key must stop being trusted and the compile must fail
// exactly as it did before CHAOS-71.
func TestChaos71_CompileFailsOncePastTheStalenessCeiling(t *testing.T) {
	store := chaos71Env(t)
	idp := newChaos71IdP(t)
	if _, err := NewSAMLProvider(chaos71Profile("corp", idp.URL())); err != nil {
		t.Fatalf("healthy compile: %v", err)
	}
	idp.down.Store(true)
	store.SetClockForTest(func() time.Time { return time.Now().Add(idpmeta.StaleMaxAge + time.Hour) })

	if _, err := NewSAMLProvider(chaos71Profile("corp", idp.URL())); err == nil {
		t.Fatal("a cached document past the ceiling must be refused — it would keep trusting a key the IdP may have withdrawn")
	}
	if snap := idpMetadataState(); snap.Unavailable != 1 {
		t.Fatalf("Unavailable = %d, want 1", snap.Unavailable)
	}
}

// Re-pointing a profile at a DIFFERENT IdP must get no cache. Otherwise a
// deliberate migration could be answered by the provider being migrated away
// from, which is a trust decision rather than a caching one.
func TestChaos71_RepointingAProfileGetsNoCachedDocument(t *testing.T) {
	chaos71Env(t)
	oldIdP := newChaos71IdP(t)
	newIdP := newChaos71IdP(t)
	if _, err := NewSAMLProvider(chaos71Profile("corp", oldIdP.URL())); err != nil {
		t.Fatalf("seed: %v", err)
	}
	newIdP.down.Store(true)

	if _, err := NewSAMLProvider(chaos71Profile("corp", newIdP.URL())); err == nil {
		t.Fatal("a re-pointed profile must NOT be served the previous IdP's document")
	}
}

// Cached bytes go through the IDENTICAL parser as network bytes. A cache file
// edited on disk must be refused by the same validation, never trusted because
// "we fetched it once".
func TestChaos71_CachedBytesAreParsedByTheSameValidator(t *testing.T) {
	store := chaos71Env(t)
	idp := newChaos71IdP(t)
	if _, err := NewSAMLProvider(chaos71Profile("corp", idp.URL())); err != nil {
		t.Fatalf("seed: %v", err)
	}
	idp.down.Store(true)

	dir := storeDirOf(t, store)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	tampered := false
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".doc" {
			continue
		}
		// Same byte length so the index's length check cannot be what refuses
		// it — the PARSER must.
		orig, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), []byte(strings.Repeat("Z", len(orig))), 0o600); err != nil {
			t.Fatalf("tamper: %v", err)
		}
		tampered = true
	}
	if !tampered {
		t.Fatal("no cached document found to tamper with")
	}
	if _, err := NewSAMLProvider(chaos71Profile("corp", idp.URL())); err == nil {
		t.Fatal("a tampered cached document must be refused by the same parser as network bytes")
	}
}

// ── CONTROLS ────────────────────────────────────────────────────────────────

// CONTROL. The cheapest way to pass every defect gate above is to always serve
// the cached document. That would silently stop this appliance from ever
// picking up an IdP-side signing-key rotation — the standard SAML/OIDC
// operational event — which is strictly worse than the outage being fixed.
// The network must always WIN when it answers.
func TestChaos71Control_FreshDocumentAlwaysBeatsTheCache(t *testing.T) {
	chaos71Env(t)
	idp := newChaos71IdP(t)
	first, err := NewSAMLProvider(chaos71Profile("corp", idp.URL()))
	if err != nil {
		t.Fatalf("first compile: %v", err)
	}
	before := first.sp.IDPMetadata.EntityID

	idp.rotateSigningKey(t)
	second, err := NewSAMLProvider(chaos71Profile("corp", idp.URL()))
	if err != nil {
		t.Fatalf("second compile: %v", err)
	}
	if got := certCNOf(t, second); got != "cert-B" {
		t.Fatalf("the rotated signing certificate must be picked up, got %q (entityID before=%q)", got, before)
	}
	if snap := idpMetadataState(); snap.StaleServed != 0 {
		t.Fatalf("StaleServed = %d, want 0 — a healthy fetch must never be answered from cache", snap.StaleServed)
	}
}

// CONTROL. A healthy appliance must be observably unchanged: every acquisition
// fresh, nothing degraded, no page.
func TestChaos71Control_HealthyApplianceReportsHealthy(t *testing.T) {
	chaos71Env(t)
	idp := newChaos71IdP(t)
	if _, err := NewSAMLProvider(chaos71Profile("corp", idp.URL())); err != nil {
		t.Fatalf("compile: %v", err)
	}
	snap := idpMetadataState()
	if snap.FetchFailures != 0 || snap.Degraded || snap.StaleServed != 0 {
		t.Fatalf("healthy appliance reported failures=%d degraded=%v stale=%d", snap.FetchFailures, snap.Degraded, snap.StaleServed)
	}
	if row := checkIdPMetadata(); row.Status != diagOK {
		t.Fatalf("contract row = %s (%s), want ok", row.Status, row.Message)
	}
}

// CONTROL + emission rule. An appliance that never configured a remote IdP
// must emit NOTHING on this plane. A flat `0` from every such appliance is
// indistinguishable from one whose IdP is dead, and the paging rule is `> 0`.
func TestChaos71Control_NodeWithNoRemoteIdPEmitsNothing(t *testing.T) {
	chaos71Env(t)
	prev := idpRegistry
	idpRegistry = &IdPRegistry{live: map[string]IdentityProvider{}}
	t.Cleanup(func() { idpRegistry = prev })

	if snap := idpMetadataState(); snap.Used {
		t.Fatal("an unused plane must report Used=false so /metrics emits nothing")
	}
	row := checkIdPMetadata()
	if row.Status != diagOK || !strings.Contains(row.Message, "No remote IdP") {
		t.Fatalf("row = %s %q, want a no-claim ok row", row.Status, row.Message)
	}
}

// An inline metadata_xml profile involves no network and must not touch this
// plane at all — counting it would make a node with no remote IdP look healthy
// for a reason that says nothing about any IdP.
func TestChaos71_InlineMetadataDoesNotTouchTheMetadataPlane(t *testing.T) {
	chaos71Env(t)
	if _, err := NewSAMLProvider(&IdPProfile{
		ID: "inline", Name: "inline", Type: IdPTypeSAML, Enabled: true,
		SAML: &SAMLProfileConfig{MetadataXML: chaos71MetadataXML(t, "inline")},
	}); err != nil {
		t.Fatalf("inline compile: %v", err)
	}
	if snap := idpMetadataState(); snap.Used || snap.RemoteAttempts != 0 {
		t.Fatalf("inline metadata must not register on the remote-document plane (used=%v attempts=%d)", snap.Used, snap.RemoteAttempts)
	}
}

// The contract row must report the enabled-but-dark state — the state that had
// NO surface at all before CHAOS-71 — and must warn, never fail: an IdP outage
// is fleet-wide, so failing readiness would eject every node at once over a
// dependency none of them can fix by restarting.
func TestChaos71_ContractRowReportsDarkProvidersAsWarnNotFail(t *testing.T) {
	chaos71Env(t)
	deadURL, _ := chaos71DeadTLSEndpoint(t)
	prev := idpRegistry
	idpRegistry = &IdPRegistry{
		live:     map[string]IdentityProvider{},
		profiles: []*IdPProfile{chaos71Profile("corp", deadURL)},
	}
	t.Cleanup(func() { idpRegistry = prev })

	row := checkIdPMetadata()
	if row.Status != diagWarn {
		t.Fatalf("row status = %s, want warn (a fail row would eject a serving fleet)", row.Status)
	}
	if !strings.Contains(row.Message, "NO live provider") {
		t.Fatalf("row message must name the dark state, got %q", row.Message)
	}
	if row.OperatorAction == "" {
		t.Fatal("the row must tell the operator what to do")
	}
}

// The alert Detail must be BOUNDED. Store.Dispatch dedups on
// `event + ":" + Detail`, so an unbounded Detail yields one dedup key per
// failure, which the window cannot suppress and which evicts real threat
// alerts from the 500-entry retry queue (the WK-12/RS-5 defect). The raw error
// embeds the configured IdP URL and must never reach it.
func TestChaos71_AlertDetailIsBoundedAndCarriesNoURL(t *testing.T) {
	chaos71Env(t)
	var details []string
	prev := fireIdPMetadataAlert
	fireIdPMetadataAlert = func(d string) { details = append(details, d) }
	t.Cleanup(func() { fireIdPMetadataAlert = prev })

	// A URL, not a credential — but it is exactly the kind of value that must
	// never reach an alert Detail, because Dispatch dedups on it.
	privateURL := "https://idp.internal.example/private-metadata-path"
	idpMetadata.mu.Lock()
	idpMetadataEpisodeLocked("corp").firstFailure = time.Now().Add(-2 * idpMetadataDegradedAfter)
	idpMetadata.mu.Unlock()
	idpMetadataEverUsed.Store(true)
	noteIdPMetadataOutcome("corp", idpMetaUnavailable, fmt.Errorf("fetch %s: connection refused", privateURL))

	if len(details) != 1 {
		t.Fatalf("want exactly one page per degradation episode, got %d", len(details))
	}
	if strings.Contains(details[0], privateURL) || strings.Contains(details[0], "idp.internal.example") {
		t.Fatalf("alert Detail leaked the IdP URL: %q", details[0])
	}

	// Fire-once per episode: a second failure must not page again.
	noteIdPMetadataOutcome("corp", idpMetaUnavailable, fmt.Errorf("again"))
	if len(details) != 1 {
		t.Fatalf("the latch must fire once per episode, got %d pages", len(details))
	}

	// Recovery is on OBSERVED evidence — a document actually fetched — and it
	// re-arms the latch so a second incident pages again.
	noteIdPMetadataOutcome("corp", idpMetaFresh, nil)
	idpMetadata.mu.Lock()
	idpMetadataEpisodeLocked("corp").firstFailure = time.Now().Add(-2 * idpMetadataDegradedAfter)
	idpMetadata.mu.Unlock()
	noteIdPMetadataOutcome("corp", idpMetaUnavailable, fmt.Errorf("second incident"))
	if len(details) != 2 {
		t.Fatalf("a second incident must page again, got %d pages", len(details))
	}
}

// Recovery must never be declared by ELAPSED TIME. A node whose fetch failures
// stop because nothing is compiling any more has not recovered, and reporting
// that as recovery is the mistake ca_health.go and storage_health.go both name.
func TestChaos71_RecoveryRequiresObservedEvidence(t *testing.T) {
	chaos71Env(t)
	idpMetadataEverUsed.Store(true)
	noteIdPMetadataOutcome("corp", idpMetaUnavailable, fmt.Errorf("down"))
	if !idpMetadataState().Failing {
		t.Fatal("precondition: must be failing")
	}
	time.Sleep(50 * time.Millisecond)
	if !idpMetadataState().Failing {
		t.Fatal("elapsed time alone must NEVER clear a failing state")
	}
	noteIdPMetadataOutcome("corp", idpMetaFresh, nil)
	if idpMetadataState().Failing {
		t.Fatal("an observed successful fetch must clear it")
	}
}

// The admin "test this issuer" probe must never consult or populate the cache:
// a diagnostic that answers from cache reports a dead IdP as healthy, and a
// cache keyed on a caller-supplied issuer is a seeding surface.
func TestChaos71_AdminDiscoveryProbeIsCacheFree(t *testing.T) {
	store := chaos71Env(t)
	if _, err := probeOIDCDiscovery("https://issuer.invalid.example"); err == nil {
		t.Fatal("probe against an unreachable issuer must fail")
	}
	if store.Len() != 0 {
		t.Fatalf("the admin probe must not populate the cache, %d entries", store.Len())
	}
	if idpMetadataState().Used {
		t.Fatal("the admin probe must not register on the compile-path health plane")
	}
}

// Codex review (P1): a document the IdP served with HTTP 200 but that the
// compile's own parser rejects must NOT replace the last-known-good copy.
// Pre-fix the bytes were persisted BEFORE parsing, so one malformed answer
// overwrote the valid cache and a later outage fell back to the broken bytes —
// the provider could no longer recover from the cache at all.
func TestChaos71_InvalidFetchedDocumentDoesNotReplaceLastKnownGood(t *testing.T) {
	chaos71Env(t)
	idp := newChaos71IdP(t)

	if _, err := NewSAMLProvider(chaos71Profile("corp", idp.URL())); err != nil {
		t.Fatalf("healthy compile: %v", err)
	}
	idp.doc.Store("<html>edge error page, not SAML metadata</html>")
	if _, err := NewSAMLProvider(chaos71Profile("corp", idp.URL())); err != nil {
		t.Fatalf("an invalid 200 answer must fall back to the last-known-good document: %v", err)
	}
	if snap := idpMetadataState(); snap.StaleServed != 1 || !snap.Failing {
		t.Fatalf("an invalid document must be accounted as a failed acquisition served from cache: %+v", snap)
	}

	idp.down.Store(true)
	if _, err := NewSAMLProvider(chaos71Profile("corp", idp.URL())); err != nil {
		t.Fatalf("after an invalid answer the cache must still hold the VALID document: %v", err)
	}
}

// Codex review (P2): failure episodes are PER PROFILE. With one
// process-global episode, a healthy sibling's successful fetch cleared the
// dead profile's episode, so it never reached the degradation threshold and
// never paged.
func TestChaos71_HealthySiblingDoesNotClearAnotherProfilesEpisode(t *testing.T) {
	chaos71Env(t)
	var details []string
	prev := fireIdPMetadataAlert
	fireIdPMetadataAlert = func(d string) { details = append(details, d) }
	t.Cleanup(func() { fireIdPMetadataAlert = prev })

	noteIdPMetadataOutcome("dead", idpMetaStale, fmt.Errorf("down"))
	idpMetadata.mu.Lock()
	idpMetadataEpisodeLocked("dead").firstFailure = time.Now().Add(-2 * idpMetadataDegradedAfter)
	idpMetadata.mu.Unlock()

	noteIdPMetadataOutcome("healthy", idpMetaFresh, nil)
	if snap := idpMetadataState(); !snap.Failing || !snap.Degraded {
		t.Fatalf("a sibling's success must not clear the dead profile's episode: %+v", snap)
	}
	noteIdPMetadataOutcome("dead", idpMetaStale, fmt.Errorf("still down"))
	if len(details) != 1 {
		t.Fatalf("the dead profile must page once it crosses the threshold, got %d pages", len(details))
	}
	noteIdPMetadataOutcome("dead", idpMetaFresh, nil)
	if idpMetadataState().Failing {
		t.Fatal("the profile's OWN success must clear its episode")
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func storeDirOf(t *testing.T, s *idpmeta.Store) string {
	t.Helper()
	// The store's directory is not exported; recover it from the singleton the
	// env installed by writing a probe and locating it. Simpler: the env
	// created the store over a TempDir, so ask the store to persist and scan.
	if err := s.Put("__probe__", idpmeta.KindSAMLMetadata, "probe", []byte("x")); err != nil {
		t.Fatalf("probe put: %v", err)
	}
	return s.Dir()
}

func certCNOf(t *testing.T, p *SAMLProvider) string {
	t.Helper()
	md := p.sp.IDPMetadata
	if md == nil || len(md.IDPSSODescriptors) == 0 {
		t.Fatal("no IdP descriptors")
	}
	kds := md.IDPSSODescriptors[0].KeyDescriptors
	for i := range kds {
		for _, c := range kds[i].KeyInfo.X509Data.X509Certificates {
			der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(c.Data))
			if err != nil {
				continue
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				continue
			}
			return cert.Subject.CommonName
		}
	}
	t.Fatal("no certificate in IdP metadata")
	return ""
}

// ── Codex review round (2026-09-25) ─────────────────────────────────────────

// P1. A RESOLUTION failure must route to the cache, not be reported as a
// configuration error before the cache can be consulted. validateExternalURL
// resolves the host, so using it as the OIDC admission gate made "DNS is down"
// return early — leaving the OIDC half of this sweep's headline defect open
// after the SAML half was closed.
func TestChaos71_StructuralValidatorDecidesWithoutAResolver(t *testing.T) {
	// A name that cannot resolve is a RESOLUTION question: structural
	// validation must accept it and leave the verdict to the fetch, which is
	// what lets the cached document answer during a DNS outage.
	unresolvable := "https://idp-that-does-not-resolve.invalid/.well-known/openid-configuration"
	if err := validateExternalURLStructure(unresolvable); err != nil {
		t.Fatalf("an unresolvable HOST is not a configuration error: %v", err)
	}
	// The DNS-backed form is what must refuse it — the two are not
	// interchangeable, which is the whole point of the split.
	if err := validateExternalURL(unresolvable); err == nil {
		t.Fatal("validateExternalURL must still fail closed on an unresolvable host")
	}

	// CONFIGURATION errors still fail fast, from the string alone.
	for _, bad := range []string{
		"",                    // empty
		"not-a-url",           // not absolute
		"ftp://idp.example/x", // wrong scheme
		"https://127.0.0.1/x", // private IP literal
		"https://10.0.0.1/x",  // private IP literal
		"https://[::1]/x",     // private IP literal, v6
	} {
		if err := validateExternalURLStructure(bad); err == nil {
			t.Errorf("structural validation must refuse %q", bad)
		}
	}
	// ...and a public literal is still fine.
	if err := validateExternalURLStructure("https://93.184.216.34/x"); err != nil {
		t.Fatalf("a public IP literal must pass structurally: %v", err)
	}
}

// P2. The pre-flight host check must not outlive the operation it guards.
// isPrivateHost resolves under context.Background(), so on a wedged resolver
// it blocked for the OS budget BEFORE the request context existed.
func TestChaos71_SAMLPreflightIsBoundedByTheRequestBudget(t *testing.T) {
	if samlMetadataFetchBudget <= 0 {
		t.Fatal("the shared budget must be positive")
	}
	// The guard and the request must share ONE budget: a guard with its own
	// (or no) deadline is how an unbounded step re-enters a bounded operation.
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "auth_saml.go"))
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	// Slice the function out by hand rather than with a bare strings.Index:
	// Index returns -1 when the anchor is absent, which slices from the END of
	// the file and silently makes every assertion below vacuous — a wall that
	// passes because it stopped looking is worse than no wall (gocritic
	// offBy1 flags exactly this).
	body := string(src)
	start := strings.Index(body, "func fetchSAMLMetadataOverNetwork")
	if start < 0 {
		t.Fatal("fetchSAMLMetadataOverNetwork not found — this wall is pinning nothing")
	}
	fn := body[start:]
	end := strings.Index(fn, "\n}\n")
	if end < 0 {
		t.Fatal("could not find the end of fetchSAMLMetadataOverNetwork")
	}
	fn = fn[:end]
	if strings.Contains(fn, "isPrivateHost(") && !strings.Contains(fn, "isPrivateHostContext(") {
		t.Fatal("the SAML pre-flight must use the ctx-bounded form, not the Background() one")
	}
	if !strings.Contains(fn, "isPrivateHostContext(ctx,") {
		t.Fatal("the pre-flight must be bounded by the SAME ctx the request uses")
	}
	if strings.Count(fn, "context.WithTimeout") != 1 {
		t.Fatal("guard and request must share ONE deadline, not one each")
	}
}

// P2. An inline transition is the resolution of a remote-fetch episode: with
// no remote fetch left, nothing else can ever clear it, so the episode would
// hold the degraded gauge and the contract row at a permanent outage for a
// dependency that no longer exists.
func TestChaos71_InlineTransitionClearsAStaleEpisode(t *testing.T) {
	chaos71Env(t)
	idpMetadataEverUsed.Store(true)

	noteIdPMetadataOutcome("switching", idpMetaUnavailable, fmt.Errorf("down"))
	if !idpMetadataState().Failing {
		t.Fatal("precondition: the profile must have an open episode")
	}
	// The admin switches that profile to inline metadata_xml.
	noteIdPMetadataOutcome("switching", idpMetaInline, nil)
	if idpMetadataState().Failing {
		t.Fatal("an inline transition must clear the profile's now-unresolvable episode")
	}
	// It must clear ONLY that episode, and must not fabricate an attempt.
	before := idpMetadataState().RemoteAttempts
	noteIdPMetadataOutcome("other", idpMetaUnavailable, fmt.Errorf("down"))
	noteIdPMetadataOutcome("switching", idpMetaInline, nil)
	if !idpMetadataState().Failing {
		t.Fatal("one profile going inline must not clear another profile's episode")
	}
	if got := idpMetadataState().RemoteAttempts; got != before+1 {
		t.Fatalf("RemoteAttempts = %d, want %d — inline must count no attempt", got, before+1)
	}
}

// P1, behavioural. The structural check above is worth nothing unless the OIDC
// compile path actually consults it: a DNS outage must reach the cache. This is
// the gate that fails against the pre-fix shape, where validateExternalURL —
// which resolves — was the admission gate and returned before the cache.
func TestChaos71_OIDCDNSOutageIsAnsweredFromCache(t *testing.T) {
	store := chaos71Env(t)

	const issuer = "https://idp-that-does-not-resolve.invalid"
	wellKnown := issuer + "/.well-known/openid-configuration"
	doc := []byte(`{"issuer":"` + issuer + `",` +
		`"authorization_endpoint":"https://idp-that-does-not-resolve.invalid/authorize",` +
		`"token_endpoint":"https://idp-that-does-not-resolve.invalid/token"}`)
	if err := store.Put("dns-out", idpmeta.KindOIDCDiscovery, wellKnown, doc); err != nil {
		t.Fatalf("seed last-known-good: %v", err)
	}

	got, err := fetchOIDCDiscovery("dns-out", issuer)
	if err != nil {
		t.Fatalf("a resolvable-yesterday issuer must still compile from cache: %v", err)
	}
	if got.TokenEndpoint != "https://idp-that-does-not-resolve.invalid/token" {
		t.Fatalf("token endpoint = %q, want the cached one", got.TokenEndpoint)
	}
	if st := idpMetadataState(); !st.Failing || st.StaleServed == 0 {
		t.Fatalf("a cache-served compile must be reported stale, got %+v", st)
	}
}

// The structural validator's ONLY security-relevant job is classifying an IP
// LITERAL without a resolver, and the direction it must not get wrong is
// admitting a private one. IPv4-mapped IPv6 is the form that gets this wrong in
// the fail-open direction (the same class the shared prefixSet normaliser in
// security.go carries a differential test for), so it is pinned explicitly
// rather than left to the reader of ssrf.PrivateIP.
//
// A non-literal host is deliberately NOT this function's problem and is pinned
// as such: obfuscated forms (decimal, octal, abbreviated) are resolved by the
// guards downstream, whose refusal is based on the RESOLVED address and is
// therefore robust to spelling in a way no string check can be. Go's pure
// resolver rejects them outright; cgo's getaddrinfo accepts them and the
// pre-flight then refuses them by resolved address. Both are closed, which is
// why this gate asserts only that they are passed ON rather than misclassified.
func TestChaos71_StructuralValidatorClassifiesOnlyLiterals(t *testing.T) {
	private := []string{
		"https://[::ffff:10.0.0.1]/x",            // IPv4-mapped, RFC1918
		"https://[::ffff:127.0.0.1]/x",           // IPv4-mapped, loopback
		"https://[0:0:0:0:0:ffff:192.168.1.1]/x", // IPv4-mapped, long form
		"https://[::ffff:a00:1]/x",               // IPv4-mapped, hex spelling
		"https://[fc00::1]/x",                    // IPv6 unique-local
		"https://[fe80::1]/x",                    // IPv6 link-local
		"https://[::1]/x",                        // IPv6 loopback
		"https://169.254.169.254/x",              // cloud metadata
	}
	for _, u := range private {
		if err := validateExternalURLStructure(u); err == nil {
			t.Errorf("a private IP literal must be refused without a resolver: %q", u)
		}
	}

	// Public literals must still pass — refusing them would break an operator
	// who addresses their IdP by address.
	for _, u := range []string{"https://93.184.216.34/x", "https://[2606:2800:220:1::1]/x"} {
		if err := validateExternalURLStructure(u); err != nil {
			t.Errorf("a public IP literal must pass structurally: %q: %v", u, err)
		}
	}

	// Non-literals are passed on, whatever they are spelled like. The verdict
	// belongs to the resolving guards, not to this function.
	for _, u := range []string{
		"https://2130706433/x", // decimal 127.0.0.1
		"https://0177.0.0.1/x", // octal
		"https://127.1/x",      // abbreviated
		"https://localhost/x",
		"https://idp.example.com/x",
	} {
		if err := validateExternalURLStructure(u); err != nil {
			t.Errorf("a NAME is not this function's verdict to make: %q: %v", u, err)
		}
	}
}

// CodeQL go/request-forgery (PR #1485): the SAML metadata fetch carries a
// Regexp.MatchString barrier on the raw URL, ahead of url.Parse, and that
// barrier admits exactly the shapes the scheme check admits.
func TestChaos71_SAMLMetadataURLShapeBarrier(t *testing.T) {
	for _, ok := range []string{
		"https://idp.example.com/metadata",
		"http://idp.example.com:8080/saml/metadata",
		"HTTPS://IDP.example.com/metadata",
	} {
		if !samlMetadataURLShape.MatchString(ok) {
			t.Errorf("barrier refused a valid metadata URL %q", ok)
		}
	}
	for _, bad := range []string{
		"", "ftp://idp.example.com/m", "file:///etc/passwd", "https:///path-only",
		"//idp.example.com/m", "idp.example.com/metadata", "gopher://x",
	} {
		if samlMetadataURLShape.MatchString(bad) {
			t.Errorf("barrier admitted %q", bad)
		}
		if _, err := fetchSAMLMetadataOverNetwork(bad); err == nil {
			t.Errorf("fetch accepted %q", bad)
		}
	}
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "auth_saml.go"))
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func fetchSAMLMetadataOverNetwork")
	if start < 0 {
		t.Fatal("fetchSAMLMetadataOverNetwork not found")
	}
	fn := body[start:]
	guard := strings.Index(fn, "samlMetadataURLShape.MatchString(raw)")
	parse := strings.Index(fn, "url.Parse(raw)")
	if guard < 0 || parse < 0 || guard > parse {
		t.Fatal("the regexp barrier must run on raw BEFORE url.Parse, in the same function as the request")
	}
}

// ── Codex review round 2 (2026-09-25) ───────────────────────────────────────

// P1. The headline defect, on the path it was actually about. The previous
// gate called fetchOIDCDiscovery DIRECTLY, so it proved the cache fallback
// works BELOW the registry's admission gates and proved nothing about whether
// those gates are reachable during a resolver outage — and they were not:
// both called the RESOLVING validateExternalURL on the issuer before
// compilation, so a DNS outage refused the admin write and aborted the whole
// CP->DP snapshot exactly as before the sweep.
//
// This drives ReplaceAll, which is the fleet-wide path.
func TestChaos71_ReplaceAllSurvivesAnUnresolvableIssuer(t *testing.T) {
	store := chaos71Env(t)

	const issuer = "https://idp-that-does-not-resolve.invalid"
	wellKnown := issuer + "/.well-known/openid-configuration"
	doc := []byte(`{"issuer":"` + issuer + `",` +
		`"authorization_endpoint":"https://idp-that-does-not-resolve.invalid/authorize",` +
		`"token_endpoint":"https://idp-that-does-not-resolve.invalid/token"}`)
	if err := store.Put("dp-sync", idpmeta.KindOIDCDiscovery, wellKnown, doc); err != nil {
		t.Fatalf("seed last-known-good: %v", err)
	}

	reg := &IdPRegistry{live: make(map[string]IdentityProvider)}
	profile := &IdPProfile{
		ID: "dp-sync", Name: "dp-sync", Type: IdPTypeOIDC, Enabled: true,
		OIDC: &OIDCProfileConfig{
			Issuer: issuer, ClientID: "cid", ClientSecret: "sec",
		},
	}
	if err := reg.ReplaceAll([]*IdPProfile{profile}); err != nil {
		t.Fatalf("an unresolvable issuer with a valid cached document must not "+
			"abort the config snapshot: %v", err)
	}
	if _, ok := reg.live["dp-sync"]; !ok {
		t.Fatal("the profile should have compiled from the cached document")
	}
}

// P1, the configuration half: the gates must still fail FAST on a genuine
// configuration error, which is the whole reason the two questions were split.
func TestChaos71_AdmissionGatesStillRefuseBadConfiguration(t *testing.T) {
	// Deliberately NOT chaos71Env: that helper calls ssrf.AllowLoopbackForTest,
	// which makes 127.0.0.1 non-private and would let this gate pass against a
	// validator that had stopped refusing private literals. This case is pure
	// validation and needs no environment, so it runs under the real posture.
	for _, bad := range []string{"", "not-a-url", "ftp://idp.example", "https://127.0.0.1", "https://10.0.0.1"} {
		p := &IdPProfile{
			ID: "x", Name: "x", Type: IdPTypeOIDC, Enabled: true,
			OIDC: &OIDCProfileConfig{
				Issuer: bad, ClientID: "cid", ClientSecret: "sec",
			},
		}
		if err := validateIdPProfile(p); err == nil {
			t.Errorf("a configuration error must still fail fast: issuer %q", bad)
		}
	}
}

// P2, security. The authorization endpoint is handed to the user's BROWSER, so
// no dialer of ours is ever consulted and isSafeCaptiveRedirect checks only
// the SHAPE. Dropping the resolving validator from the discovery parser
// therefore opened a redirect-to-internal path; this pins that a discovery
// document naming a private authorization endpoint is refused.
func TestChaos71_PrivateAuthorizationEndpointIsRefused(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "10.0.0.1", "[::1]"} {
		doc := []byte(`{"issuer":"https://idp.example",` +
			`"authorization_endpoint":"https://` + host + `/authorize",` +
			`"token_endpoint":"https://idp.example/token"}`)
		if _, err := parseAndValidateOIDCDiscovery(doc); err == nil {
			t.Errorf("a private authorization_endpoint must be refused: %q", host)
		}
	}
	// A public one still passes — the guard must not refuse everything.
	ok := []byte(`{"issuer":"https://idp.example",` +
		`"authorization_endpoint":"https://idp.example/authorize",` +
		`"token_endpoint":"https://idp.example/token"}`)
	if _, err := parseAndValidateOIDCDiscovery(ok); err != nil {
		t.Fatalf("a public authorization_endpoint must pass: %v", err)
	}
}

// P2, security — the CONTROL that keeps the guard from becoming the defect it
// replaces. An UNRESOLVABLE host is "unknown", not "private": refusing it
// would hand a resolver outage the power to reject a cached document, which is
// this sweep's headline defect in miniature.
func TestChaos71_UnresolvableAuthorizationEndpointIsNotRefused(t *testing.T) {
	doc := []byte(`{"issuer":"https://idp.example",` +
		`"authorization_endpoint":"https://idp-that-does-not-resolve.invalid/authorize",` +
		`"token_endpoint":"https://idp-that-does-not-resolve.invalid/token"}`)
	if _, err := parseAndValidateOIDCDiscovery(doc); err != nil {
		t.Fatalf("an unresolvable host is unknown, not private, and must not be "+
			"refused — that would break the cache fallback: %v", err)
	}
}

// P2. An episode recorded while compiling a candidate whose mutation is then
// REJECTED has no owner: the profile never entered the registry, degradation
// is derived from elapsed time, and only a fetch or an inline transition
// cleared one — so it would report an indefinite outage for a dependency
// nobody configured.
func TestChaos71_RejectedCandidateLeavesNoEpisode(t *testing.T) {
	chaos71Env(t)
	idpMetadataEverUsed.Store(true)

	noteIdPMetadataOutcome("ghost", idpMetaUnavailable, fmt.Errorf("down"))
	if !idpMetadataState().Failing {
		t.Fatal("precondition: the candidate must have an open episode")
	}

	reg := &IdPRegistry{live: make(map[string]IdentityProvider)}
	// An enabled profile whose issuer cannot be compiled: never registered.
	bad := &IdPProfile{
		ID: "ghost", Name: "ghost", Type: IdPTypeOIDC, Enabled: true,
		OIDC: &OIDCProfileConfig{Issuer: "ftp://nope", ClientID: "c", ClientSecret: "s"},
	}
	if err := reg.ReplaceAll([]*IdPProfile{bad}); err == nil {
		t.Fatal("precondition: this snapshot must be rejected")
	}
	if idpMetadataState().Failing {
		t.Fatal("a rejected candidate must not leave an episode nothing can clear")
	}
}

// P2, the other direction: a profile that IS registered keeps its episode when
// an EDIT of it is refused — the existing provider is still authoritative and
// still down, so deleting that signal would hide a real outage.
//
// NOTE ON WHAT THIS ACTUALLY COVERS (corrected in round 3). The candidate here
// carries `ftp://nope`, so `validateUpsertProfile` refuses it BEFORE the lock
// and before any episode logic runs — this gate therefore pins the
// VALIDATION-refusal path, on which no forget is reachable at all. That is a
// real path worth pinning, but it is NOT the compile-refusal path the comment
// above describes, and reading it as such is how a gate comes to pass for a
// reason other than the one it claims. The compile-refusal path — where the
// forget decision actually lives — is covered by
// TestChaos71_RejectedEditOnTheSameSourceKeepsTheEpisode and
// TestChaos71_RejectedReusedIDWithADifferentSourceLeavesNoEpisode, which use a
// structurally valid but unresolvable issuer so admission passes.
func TestChaos71_RejectedEditKeepsTheLiveProfilesEpisode(t *testing.T) {
	chaos71Env(t)
	idpMetadataEverUsed.Store(true)

	reg := &IdPRegistry{
		live:     make(map[string]IdentityProvider),
		profiles: []*IdPProfile{{ID: "live-one", Name: "live-one", Type: IdPTypeOIDC}},
	}
	noteIdPMetadataOutcome("live-one", idpMetaUnavailable, fmt.Errorf("down"))
	if !idpMetadataState().Failing {
		t.Fatal("precondition: the registered profile must have an open episode")
	}

	bad := &IdPProfile{
		ID: "live-one", Name: "live-one", Type: IdPTypeOIDC, Enabled: true,
		OIDC: &OIDCProfileConfig{Issuer: "ftp://nope", ClientID: "c", ClientSecret: "s"},
	}
	_ = reg.Upsert(bad)
	if !idpMetadataState().Failing {
		t.Fatal("a refused EDIT must not delete the live profile's episode")
	}
}

// ---------------------------------------------------------------------------
// Codex review round 3. Four findings, each verified against its pre-fix shape.
// ---------------------------------------------------------------------------

// ROUND 3 P1. The headline defect a THIRD time, on the SAML half: round 2
// converted the OIDC issuer gates to the structural validator and left
// validateSAMLProfileConfig resolving, so one unresolvable metadata host still
// refused an admin write and aborted the whole CP->DP snapshot. Driven through
// ReplaceAll — the outermost caller — because that is the lesson of round 2: a
// gate entering below the layer that refuses cannot observe a refusal.
func TestChaos71_SAMLAdmissionSurvivesAnUnresolvableMetadataHost(t *testing.T) {
	store := chaos71Env(t)

	const metaURL = "https://saml-idp-that-does-not-resolve.invalid/metadata"
	xml := chaos71MetadataXML(t, "round3-saml")
	if err := store.Put("dp-saml", idpmeta.KindSAMLMetadata, metaURL, []byte(xml)); err != nil {
		t.Fatalf("seed last-known-good: %v", err)
	}

	reg := &IdPRegistry{live: make(map[string]IdentityProvider)}
	profile := &IdPProfile{
		ID: "dp-saml", Name: "dp-saml", Type: IdPTypeSAML, Enabled: true,
		SAML: &SAMLProfileConfig{MetadataURL: metaURL},
	}
	if err := reg.ReplaceAll([]*IdPProfile{profile}); err != nil {
		t.Fatalf("an unresolvable SAML metadata host with a valid cached document "+
			"must not abort the config snapshot: %v", err)
	}
	if _, ok := reg.live["dp-saml"]; !ok {
		t.Fatal("the SAML profile should have compiled from the cached document")
	}
}

// The configuration half of the same split: a genuine SAML misconfiguration
// must still fail FAST. Deliberately NOT chaos71Env — that helper allows
// loopback, which would let a private literal through.
func TestChaos71_SAMLAdmissionStillRefusesBadConfiguration(t *testing.T) {
	for _, bad := range []string{"not-a-url", "ftp://idp.example", "https://127.0.0.1", "https://10.0.0.1"} {
		cfg := &SAMLProfileConfig{MetadataURL: bad}
		if err := validateSAMLProfileConfig(cfg); err == nil {
			t.Errorf("a SAML configuration error must still fail fast: metadata_url %q", bad)
		}
	}
}

// ROUND 3 P2. Episode ownership is decided by SOURCE, not by id alone. An edit
// that REUSES a registered id and repoints it at a different unreachable source
// leaves an episode opened by the CANDIDATE's fetch; the profile that stays
// authoritative never had that dependency, so inheriting it reports an
// indefinite outage against the published configuration.
//
// Both halves use a structurally VALID but unresolvable issuer, so admission
// passes and the failure happens in COMPILE — which is where the episode is
// opened and where the forget decision lives.
func TestChaos71_RejectedReusedIDWithADifferentSourceLeavesNoEpisode(t *testing.T) {
	chaos71Env(t)
	idpMetadataEverUsed.Store(true)

	reg := &IdPRegistry{
		live: make(map[string]IdentityProvider),
		profiles: []*IdPProfile{{
			ID: "shared-id", Name: "shared-id", Type: IdPTypeOIDC, Enabled: true,
			OIDC: &OIDCProfileConfig{
				Issuer: "https://idp-a-live.invalid", ClientID: "c", ClientSecret: "s",
			},
		}},
	}

	// The candidate repoints the SAME id at a DIFFERENT unreachable issuer.
	candidate := &IdPProfile{
		ID: "shared-id", Name: "shared-id", Type: IdPTypeOIDC, Enabled: true,
		OIDC: &OIDCProfileConfig{
			Issuer: "https://idp-b-candidate.invalid", ClientID: "c", ClientSecret: "s",
		},
	}
	if err := reg.Upsert(candidate); err == nil {
		t.Fatal("precondition: an unreachable issuer with nothing cached must be refused")
	}
	if idpMetadataState().Failing {
		t.Fatal("an episode opened against the CANDIDATE's source must not be " +
			"inherited by the profile that stays live on a different source")
	}
}

// The CONTROL, and the one that makes the rule non-vacuous: when the candidate
// keeps the SAME source as the live profile, the episode describes a dependency
// the live provider really does have, so it must SURVIVE the refusal. The
// cheapest way to pass the gate above is to forget unconditionally, which would
// delete a real outage signal.
func TestChaos71_RejectedEditOnTheSameSourceKeepsTheEpisode(t *testing.T) {
	chaos71Env(t)
	idpMetadataEverUsed.Store(true)

	const issuer = "https://idp-shared-source.invalid"
	reg := &IdPRegistry{
		live: make(map[string]IdentityProvider),
		profiles: []*IdPProfile{{
			ID: "shared-id", Name: "shared-id", Type: IdPTypeOIDC, Enabled: true,
			OIDC: &OIDCProfileConfig{Issuer: issuer, ClientID: "c", ClientSecret: "s"},
		}},
	}

	candidate := &IdPProfile{
		ID: "shared-id", Name: "shared-id", Type: IdPTypeOIDC, Enabled: true,
		OIDC: &OIDCProfileConfig{Issuer: issuer, ClientID: "c", ClientSecret: "other"},
	}
	if err := reg.Upsert(candidate); err == nil {
		t.Fatal("precondition: an unreachable issuer with nothing cached must be refused")
	}
	if !idpMetadataState().Failing {
		t.Fatal("a refused edit on the SAME source must keep the live profile's " +
			"episode — that outage is real and deleting it hides it")
	}
}

// ROUND 3 P2. The cached bytes go through the caller's validator BEFORE the
// stale outcome is recorded. Validating only the FETCHED bytes let the stale
// path claim a compile that never happened: the counter moved, the log said
// compilation was continuing, and the caller then rejected the document.
func TestChaos71_UnusableCachedDocumentIsNotReportedAsServed(t *testing.T) {
	store := chaos71Env(t)
	idpMetadataEverUsed.Store(true)

	const src = "https://idp.example/.well-known/openid-configuration"
	if err := store.Put("corrupt", idpmeta.KindOIDCDiscovery, src, []byte("{not-usable}")); err != nil {
		t.Fatalf("seed: %v", err)
	}

	fetchErr := fmt.Errorf("dial tcp: no such host")
	reject := func([]byte) error { return fmt.Errorf("cannot parse") }

	got, err := resolveIdPDocument("corrupt", idpmeta.KindOIDCDiscovery, src, nil, fetchErr, reject)
	if err == nil {
		t.Fatal("a cached document the caller cannot use is not a fallback — " +
			"resolveIdPDocument must return the fetch error")
	}
	if got != nil {
		t.Fatalf("no document should be handed back, got %d bytes", len(got))
	}
	st := idpMetadataState()
	if st.StaleServed != 0 {
		t.Errorf("an unusable cached document must not be counted as stale-SERVED, got %d", st.StaleServed)
	}
	if !st.Failing {
		t.Error("the profile is dark, so the episode must stay open")
	}
}

// The CONTROL: a cached document the caller CAN use is still served stale. The
// cheapest way to pass the gate above is to stop trusting the cache at all,
// which would delete the entire last-known-good mechanism this sweep exists for.
func TestChaos71_UsableCachedDocumentIsStillServedStale(t *testing.T) {
	store := chaos71Env(t)
	idpMetadataEverUsed.Store(true)

	const src = "https://idp.example/.well-known/openid-configuration"
	doc := []byte(`{"issuer":"https://idp.example"}`)
	if err := store.Put("good", idpmeta.KindOIDCDiscovery, src, doc); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := resolveIdPDocument("good", idpmeta.KindOIDCDiscovery, src, nil,
		fmt.Errorf("dial tcp: no such host"), func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("a usable cached document must still be served: %v", err)
	}
	if string(got) != string(doc) {
		t.Fatalf("the cached document should come back verbatim, got %q", got)
	}
	if idpMetadataState().StaleServed == 0 {
		t.Error("serving from cache must be counted as stale-served")
	}
}

// ROUND 3 P2. Clearing a disabled profile's episode is a DURABLE transition, so
// it happens only after the write lands. On a persist failure the OLD enabled
// profile and its live provider stay authoritative, so clearing there erases a
// genuine outage signal and suppresses its alert.
func TestChaos71_DisableClearsTheEpisodeOnlyAfterPersistSucceeds(t *testing.T) {
	chaos71Env(t)
	idpMetadataEverUsed.Store(true)

	// A path that cannot be written: the parent is a FILE, not a directory.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	reg := &IdPRegistry{
		live: make(map[string]IdentityProvider),
		path: filepath.Join(blocker, "profiles.json"),
		profiles: []*IdPProfile{{
			ID: "going-dark", Name: "going-dark", Type: IdPTypeOIDC, Enabled: true,
			OIDC: &OIDCProfileConfig{
				Issuer: "https://idp-live.invalid", ClientID: "c", ClientSecret: "s",
			},
		}},
	}
	noteIdPMetadataOutcome("going-dark", idpMetaUnavailable, fmt.Errorf("down"))
	if !idpMetadataState().Failing {
		t.Fatal("precondition: the live profile must have an open episode")
	}

	disabled := &IdPProfile{
		ID: "going-dark", Name: "going-dark", Type: IdPTypeOIDC, Enabled: false,
		OIDC: &OIDCProfileConfig{
			Issuer: "https://idp-live.invalid", ClientID: "c", ClientSecret: "s",
		},
	}
	if err := reg.Upsert(disabled); err == nil {
		t.Fatal("precondition: the persist must fail for this gate to mean anything")
	}
	if !idpMetadataState().Failing {
		t.Fatal("a FAILED disable leaves the enabled profile authoritative and " +
			"still down — its episode must not be erased")
	}
}

// The CONTROL: a disable that PERSISTS does clear the episode, because the
// profile then really has no remote fetch left to produce evidence.
func TestChaos71_PersistedDisableClearsTheEpisode(t *testing.T) {
	chaos71Env(t)
	idpMetadataEverUsed.Store(true)

	reg := &IdPRegistry{
		live: make(map[string]IdentityProvider),
		path: filepath.Join(t.TempDir(), "profiles.json"),
		profiles: []*IdPProfile{{
			ID: "going-dark", Name: "going-dark", Type: IdPTypeOIDC, Enabled: true,
			OIDC: &OIDCProfileConfig{
				Issuer: "https://idp-live.invalid", ClientID: "c", ClientSecret: "s",
			},
		}},
	}
	noteIdPMetadataOutcome("going-dark", idpMetaUnavailable, fmt.Errorf("down"))

	disabled := &IdPProfile{
		ID: "going-dark", Name: "going-dark", Type: IdPTypeOIDC, Enabled: false,
		OIDC: &OIDCProfileConfig{
			Issuer: "https://idp-live.invalid", ClientID: "c", ClientSecret: "s",
		},
	}
	if err := reg.Upsert(disabled); err != nil {
		t.Fatalf("a disable with a writable path must succeed: %v", err)
	}
	if idpMetadataState().Failing {
		t.Fatal("a PERSISTED disable leaves no remote fetch, so the episode must be cleared")
	}
}
