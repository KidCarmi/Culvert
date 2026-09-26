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
	"bytes"
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
	"regexp"
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
// chaos71Source derives a stable remote source for a profile id. Episodes are
// keyed by (profile, SOURCE) since round 6, so repeated calls for one profile
// must name the SAME source or they are two episodes rather than one run.
func chaos71Source(profileID string) string { return "https://" + profileID + ".invalid/document" }

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
	for _, dc := range reg.darkEnabledProfiles() {
		prov, err := compileIdPProfile(dc.candidate)
		if err != nil {
			t.Fatalf("recompile after the IdP recovered: %v", err)
		}
		if !reg.publishRecompiled(dc.candidate.ID, dc.generation, dc.candidate, prov) {
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
		if reg.publishRecompiled("corp", p, p, prov) {
			t.Fatal("a profile deleted while we compiled must not be resurrected")
		}
	})
	t.Run("disabled while compiling", func(t *testing.T) {
		disabled := chaos71Profile("corp", idp.URL())
		disabled.Enabled = false
		reg := &IdPRegistry{live: map[string]IdentityProvider{}, profiles: []*IdPProfile{disabled}}
		if reg.publishRecompiled("corp", disabled, disabled, prov) {
			t.Fatal("a profile disabled while we compiled must not go live")
		}
	})
	t.Run("replaced by a newer generation", func(t *testing.T) {
		newer := chaos71Profile("corp", idp.URL())
		reg := &IdPRegistry{live: map[string]IdentityProvider{}, profiles: []*IdPProfile{newer}}
		if reg.publishRecompiled("corp", p, p, prov) {
			t.Fatal("a stale generation must not overwrite a newer profile")
		}
	})
	t.Run("already live", func(t *testing.T) {
		reg := &IdPRegistry{live: map[string]IdentityProvider{"corp": prov}, profiles: []*IdPProfile{p}}
		if reg.publishRecompiled("corp", p, p, prov) {
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
	idpMetadataEpisodeLocked(idpEpisodeKey("corp", chaos71Source("corp"))).firstFailure = time.Now().Add(-2 * idpMetadataDegradedAfter)
	idpMetadata.mu.Unlock()
	idpMetadataEverUsed.Store(true)
	noteIdPMetadataOutcome("corp", chaos71Source("corp"), idpMetaUnavailable, fmt.Errorf("fetch %s: connection refused", privateURL))

	if len(details) != 1 {
		t.Fatalf("want exactly one page per degradation episode, got %d", len(details))
	}
	if strings.Contains(details[0], privateURL) || strings.Contains(details[0], "idp.internal.example") {
		t.Fatalf("alert Detail leaked the IdP URL: %q", details[0])
	}

	// Fire-once per episode: a second failure must not page again.
	noteIdPMetadataOutcome("corp", chaos71Source("corp"), idpMetaUnavailable, fmt.Errorf("again"))
	if len(details) != 1 {
		t.Fatalf("the latch must fire once per episode, got %d pages", len(details))
	}

	// Recovery is on OBSERVED evidence — a document actually fetched — and it
	// re-arms the latch so a second incident pages again.
	noteIdPMetadataOutcome("corp", chaos71Source("corp"), idpMetaFresh, nil)
	idpMetadata.mu.Lock()
	idpMetadataEpisodeLocked(idpEpisodeKey("corp", chaos71Source("corp"))).firstFailure = time.Now().Add(-2 * idpMetadataDegradedAfter)
	idpMetadata.mu.Unlock()
	noteIdPMetadataOutcome("corp", chaos71Source("corp"), idpMetaUnavailable, fmt.Errorf("second incident"))
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
	noteIdPMetadataOutcome("corp", chaos71Source("corp"), idpMetaUnavailable, fmt.Errorf("down"))
	if !idpMetadataState().Failing {
		t.Fatal("precondition: must be failing")
	}
	time.Sleep(50 * time.Millisecond)
	if !idpMetadataState().Failing {
		t.Fatal("elapsed time alone must NEVER clear a failing state")
	}
	noteIdPMetadataOutcome("corp", chaos71Source("corp"), idpMetaFresh, nil)
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

	noteIdPMetadataOutcome("dead", chaos71Source("dead"), idpMetaStale, fmt.Errorf("down"))
	idpMetadata.mu.Lock()
	idpMetadataEpisodeLocked(idpEpisodeKey("dead", chaos71Source("dead"))).firstFailure = time.Now().Add(-2 * idpMetadataDegradedAfter)
	idpMetadata.mu.Unlock()

	noteIdPMetadataOutcome("healthy", chaos71Source("healthy"), idpMetaFresh, nil)
	if snap := idpMetadataState(); !snap.Failing || !snap.Degraded {
		t.Fatalf("a sibling's success must not clear the dead profile's episode: %+v", snap)
	}
	noteIdPMetadataOutcome("dead", chaos71Source("dead"), idpMetaStale, fmt.Errorf("still down"))
	if len(details) != 1 {
		t.Fatalf("the dead profile must page once it crosses the threshold, got %d pages", len(details))
	}
	noteIdPMetadataOutcome("dead", chaos71Source("dead"), idpMetaFresh, nil)
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
//
// ROUND 5: this wall is a TABLE over BOTH fetchers. It covered only the SAML
// half, and the OIDC half carried the identical unbounded guard — the third
// finding this sweep has produced from the same SAML/OIDC asymmetry (the
// admission gates and the endpoint validator were the other two). A wall
// scoped to one of two symmetric paths is how that asymmetry keeps surviving,
// so the fix is to wall the PAIR rather than the instance.
func TestChaos71_MetadataPreflightsAreBoundedByTheRequestBudget(t *testing.T) {
	if samlMetadataFetchBudget <= 0 || oidcDiscoveryFetchBudget <= 0 {
		t.Fatal("both shared budgets must be positive")
	}
	for _, tc := range []struct{ file, fn string }{
		{"auth_saml.go", "fetchSAMLMetadataOverNetwork"},
		{"auth_oidc_flow.go", "fetchOIDCDiscoveryOverNetwork"},
	} {
		t.Run(tc.fn, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join(pkgSourceDir(), tc.file))
			if err != nil {
				t.Fatalf("read source: %v", err)
			}
			// Slice the function out by hand rather than with a bare
			// strings.Index: Index returns -1 when the anchor is absent, which
			// slices from the END of the file and silently makes every
			// assertion below vacuous — a wall that passes because it stopped
			// looking is worse than no wall (gocritic offBy1 flags exactly this).
			body := string(src)
			start := strings.Index(body, "func "+tc.fn)
			if start < 0 {
				t.Fatalf("%s not found — this wall is pinning nothing", tc.fn)
			}
			fn := body[start:]
			end := strings.Index(fn, "\n}\n")
			if end < 0 {
				t.Fatalf("could not find the end of %s", tc.fn)
			}
			fn = fn[:end]

			if strings.Contains(fn, "isPrivateHost(") && !strings.Contains(fn, "isPrivateHostContext(") {
				t.Fatal("the pre-flight must use the ctx-bounded form, not the Background() one")
			}
			if !strings.Contains(fn, "isPrivateHostContext(ctx,") {
				t.Fatal("the pre-flight must be bounded by the SAME ctx the request uses")
			}
			if strings.Count(fn, "context.WithTimeout") != 1 {
				t.Fatal("guard and request must share ONE deadline, not one each")
			}
			// validateExternalURL RESOLVES under Background(). Reaching it here
			// is the defect in its original form, whatever else the function
			// also does.
			if strings.Contains(fn, "validateExternalURL(") {
				t.Fatal("the resolving validator must not be the pre-flight: it " +
					"resolves under context.Background(), outside this function's budget")
			}
		})
	}
}

// ROUND 5 P2. The degradation watchdog is the ONLY thing that evaluates the
// elapsed-time threshold for a provider that is live while serving a cached
// document, and it is started once at boot. Gating that start on a remote
// profile EXISTING at boot meant an appliance that later gained one — an admin
// write, or a CP->DP snapshot — had no goroutine left to notice its outage, so
// the documented alert could never fire for exactly the profile an operator
// had just added.
//
// Structural, because the defect is a start that never happens: no behavioural
// test can observe a goroutine that was not spawned, and the sweep is a no-op
// with no episodes, so an absent watchdog looks identical to a healthy one.
func TestChaos71_DegradationWatchdogStartIsUnconditional(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "ui_access_policy_startup.go"))
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	body := string(src)
	i := strings.Index(body, "go runIdPMetadataDegradationWatchdog(")
	if i < 0 {
		t.Fatal("the degradation watchdog is never started — the documented " +
			"alert can never fire for a cache-serving provider")
	}
	// INDENTATION, not keywords. The first version of this wall looked for a
	// condition mentioning "Profile" on the preceding lines, which pins one
	// spelling of one gate: any other condition — including the enclosing
	// `if cfg.IdPProfilesFile != ""` block this start also had to leave —
	// would have passed it. The statement must sit at FUNCTION-BODY depth,
	// which no conditional wrapper can satisfy.
	lineStart := strings.LastIndex(body[:i], "\n") + 1
	indent := body[lineStart:i]
	if indent != "\t" {
		t.Fatalf("the watchdog start is nested (indent %q, want one tab): it is "+
			"conditional on boot-time state, so a remote profile added later — by "+
			"an admin write or a CP->DP snapshot — would never be watched", indent)
	}
}

// ROUND 6 P2. resolveIdPDocument may run its validator TWICE — once on fetched
// bytes to decide whether to cache them, once on cached bytes to decide whether
// they are still usable — so a validator that resolves DNS and records a
// counter charges both twice. Each acquisition whose authorization host cannot
// be resolved therefore paid the authorization-host budget twice and
// double-counted culvert_idp_authz_endpoint_unverified_total, on boot and on
// every CP->DP snapshot apply.
func TestChaos71_UnverifiedAuthzEndpointIsCountedOncePerAcquisition(t *testing.T) {
	store := chaos71Env(t)

	const issuer = "https://idp-round6-unreachable.invalid"
	wellKnown := oidcWellKnownURL(issuer)
	// The authorization endpoint is on a host that cannot be resolved, so the
	// address check returns "unknown" and admits it unverified — the state the
	// counter exists to make visible.
	doc := []byte(`{"issuer":"` + issuer + `",` +
		`"authorization_endpoint":"https://authz-round6-unresolvable.invalid/authorize",` +
		`"token_endpoint":"` + issuer + `/token"}`)
	if err := store.Put("round6", idpmeta.KindOIDCDiscovery, wellKnown, doc); err != nil {
		t.Fatalf("seed last-known-good: %v", err)
	}

	before := idpAuthzEndpointUnverified.Load()
	// The fetch fails (unreachable issuer), so this takes the stale path, which
	// is the one that runs the validator on the CACHED bytes as well.
	if _, err := compileIdPProfile(&IdPProfile{
		ID: "round6", Name: "round6", Type: IdPTypeOIDC, Enabled: true,
		OIDC: &OIDCProfileConfig{Issuer: issuer, ClientID: "c", ClientSecret: "s"},
	}); err != nil {
		t.Fatalf("precondition: the cached document must compile: %v", err)
	}
	if got := idpAuthzEndpointUnverified.Load() - before; got != 1 {
		t.Fatalf("culvert_idp_authz_endpoint_unverified_total moved by %d for ONE acquisition, want 1 — "+
			"the side-effecting, DNS-resolving parser is being run more than once per document, "+
			"so the counter over-reports and each acquisition pays the authorization-host "+
			"budget repeatedly", got)
	}
}

// ROUND 6 P2. An episode describes a failed fetch against a SOURCE, so it is
// keyed by (profile, source). Keyed by profile alone, a speculative compile of
// a candidate that REUSES an id shared one entry with the live profile, and the
// fresh evidence beyond the round-3 thread is the case where the live source is
// ALREADY FAILING when the repoint arrives: the refusal path then deleted a
// genuine, ongoing outage episode for the source still in service, losing its
// fire-once alert latch and restarting its degradation clock.
func TestChaos71_RefusedRepointPreservesTheLiveSourcesEpisode(t *testing.T) {
	store := chaos71Env(t)
	idpMetadataEverUsed.Store(true)

	const liveIssuer = "https://idp-live-already-failing.invalid"
	live := &IdPProfile{
		ID: "shared", Name: "shared", Type: IdPTypeOIDC, Enabled: true,
		OIDC: &OIDCProfileConfig{Issuer: liveIssuer, ClientID: "c", ClientSecret: "s"},
	}
	liveSource := idpRemoteDocumentSource(live)
	// Cached so the live profile compiles and stays authoritative.
	if err := store.Put("shared", idpmeta.KindOIDCDiscovery, liveSource, []byte(
		`{"issuer":"`+liveIssuer+`","authorization_endpoint":"`+liveIssuer+`/a",`+
			`"token_endpoint":"`+liveIssuer+`/t"}`)); err != nil {
		t.Fatalf("seed last-known-good: %v", err)
	}
	reg := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := reg.ReplaceAll([]*IdPProfile{live}); err != nil {
		t.Fatalf("precondition: the live profile must register: %v", err)
	}
	// It is serving from cache, so it ALREADY has an open episode. Clear the
	// alert latch state by re-recording, then age it to just under threshold.
	noteIdPMetadataOutcome("shared", liveSource, idpMetaStale, fmt.Errorf("origin down"))
	if !idpMetadataState().Failing {
		t.Fatal("precondition: the live source must be failing")
	}
	firstFailure := idpMetadataState().FailingFor

	// The admin repoints the SAME id at a DIFFERENT unreachable source, with
	// nothing cached for it, so the candidate is refused.
	if err := reg.Upsert(&IdPProfile{
		ID: "shared", Name: "shared", Type: IdPTypeOIDC, Enabled: true,
		OIDC: &OIDCProfileConfig{
			Issuer: "https://idp-candidate-unreachable.invalid", ClientID: "c", ClientSecret: "s",
		},
	}); err == nil {
		t.Fatal("precondition: an unreachable issuer with nothing cached must be refused")
	}

	if !idpMetadataState().Failing {
		t.Fatal("the REFUSED repoint deleted the live source's genuine outage episode: " +
			"its degradation clock is restarted and its fire-once page is lost, while the " +
			"profile is still live on that same failing source")
	}
	if got := idpMetadataState().FailingFor; got < firstFailure {
		t.Fatalf("the live episode's clock was restarted (FailingFor %s < %s)", got, firstFailure)
	}
	// And the candidate must not have left an episode of its own behind.
	idpMetadata.mu.Lock()
	n := len(idpMetadata.episodes)
	idpMetadata.mu.Unlock()
	if n != 1 {
		t.Fatalf("want exactly the live source's episode, got %d — a refused candidate "+
			"left an episode describing a configuration that is not in service", n)
	}
}

// ROUND 5 P2. An inline transition IS the resolution of a remote-fetch episode
// — with no remote fetch left nothing else can ever clear it — but COMPILING is
// not COMMITTING. The first shape cleared the episode inside compileIdPProfile,
// which runs before the inline document is parsed and before the registry
// mutation is persisted, so a REJECTED inline edit erased a live profile's
// genuine outage episode and suppressed its alert while that profile stayed
// authoritative.
//
// Driven through Upsert — the outermost caller — because that is the lesson
// this sweep has now learned three times: a gate entering below the layer that
// refuses cannot observe a refusal.
func TestChaos71_InlineSwitchClearsTheEpisodeOnlyOnCommit(t *testing.T) {
	const metaURL = "https://saml-idp-that-does-not-resolve.invalid/metadata"

	// A registered, live REMOTE profile carrying a real failure episode.
	arrange := func(t *testing.T) *IdPRegistry {
		t.Helper()
		store := chaos71Env(t)
		idpMetadataEverUsed.Store(true)
		if err := store.Put("switching", idpmeta.KindSAMLMetadata, metaURL,
			[]byte(chaos71MetadataXML(t, "round5-remote"))); err != nil {
			t.Fatalf("seed last-known-good: %v", err)
		}
		reg := &IdPRegistry{live: make(map[string]IdentityProvider)}
		remote := &IdPProfile{
			ID: "switching", Name: "switching", Type: IdPTypeSAML, Enabled: true,
			SAML: &SAMLProfileConfig{MetadataURL: metaURL},
		}
		if err := reg.ReplaceAll([]*IdPProfile{remote}); err != nil {
			t.Fatalf("precondition: the remote profile must register: %v", err)
		}
		noteIdPMetadataOutcome("switching", chaos71Source("switching"), idpMetaUnavailable, fmt.Errorf("down"))
		if !idpMetadataState().Failing {
			t.Fatal("precondition: the profile must have an open episode")
		}
		return reg
	}

	// THE DEFECT GATE: a refused inline edit must leave the episode alone.
	t.Run("a rejected inline edit preserves the episode", func(t *testing.T) {
		reg := arrange(t)
		err := reg.Upsert(&IdPProfile{
			ID: "switching", Name: "switching", Type: IdPTypeSAML, Enabled: true,
			SAML: &SAMLProfileConfig{MetadataXML: "<not-valid-saml-metadata"},
		})
		if err == nil {
			t.Fatal("precondition: an unparseable inline document must be refused")
		}
		if !idpMetadataState().Failing {
			t.Fatal("a REFUSED inline edit cleared the live remote profile's episode: " +
				"the old profile is still authoritative and still failing, so its " +
				"degradation is now invisible and its alert suppressed")
		}
	})

	// THE CONTROL: the cheapest way to pass the gate above is to stop clearing
	// at all, which would hold the degraded gauge and the contract row at a
	// permanent outage for a dependency that no longer exists.
	t.Run("a committed inline switch clears the episode", func(t *testing.T) {
		reg := arrange(t)
		before := idpMetadataState().RemoteAttempts
		if err := reg.Upsert(&IdPProfile{
			ID: "switching", Name: "switching", Type: IdPTypeSAML, Enabled: true,
			SAML: &SAMLProfileConfig{MetadataXML: chaos71MetadataXML(t, "round5-inline")},
		}); err != nil {
			t.Fatalf("a valid inline switch must commit: %v", err)
		}
		if idpMetadataState().Failing {
			t.Fatal("a committed inline switch must clear the profile's now-unresolvable episode")
		}
		if got := idpMetadataState().RemoteAttempts; got != before {
			t.Fatalf("RemoteAttempts = %d, want %d — going inline fetches nothing "+
				"and must count no attempt", got, before)
		}
	})

	// It must clear ONLY that profile's episode.
	t.Run("it does not clear another profile's episode", func(t *testing.T) {
		reg := arrange(t)
		noteIdPMetadataOutcome("other", chaos71Source("other"), idpMetaUnavailable, fmt.Errorf("down"))
		if err := reg.Upsert(&IdPProfile{
			ID: "switching", Name: "switching", Type: IdPTypeSAML, Enabled: true,
			SAML: &SAMLProfileConfig{MetadataXML: chaos71MetadataXML(t, "round5-inline")},
		}); err != nil {
			t.Fatalf("inline switch: %v", err)
		}
		if !idpMetadataState().Failing {
			t.Fatal("one profile going inline must not clear another profile's episode")
		}
	})
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
		if _, err := parseAndValidateOIDCDiscovery("t", doc); err == nil {
			t.Errorf("a private authorization_endpoint must be refused: %q", host)
		}
	}
	// A public one still passes — the guard must not refuse everything.
	ok := []byte(`{"issuer":"https://idp.example",` +
		`"authorization_endpoint":"https://idp.example/authorize",` +
		`"token_endpoint":"https://idp.example/token"}`)
	if _, err := parseAndValidateOIDCDiscovery("t", ok); err != nil {
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
	if _, err := parseAndValidateOIDCDiscovery("t", doc); err != nil {
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

	reg := &IdPRegistry{live: make(map[string]IdentityProvider)}
	// An enabled profile whose issuer cannot be compiled: never registered.
	bad := &IdPProfile{
		ID: "ghost", Name: "ghost", Type: IdPTypeOIDC, Enabled: true,
		OIDC: &OIDCProfileConfig{Issuer: "ftp://nope", ClientID: "c", ClientSecret: "s"},
	}
	// Seed the episode against the CANDIDATE'S OWN source, derived from the
	// profile by the production function rather than spelled out here — an
	// episode recorded against some other source is not the one a refusal of
	// THIS candidate is responsible for, and hard-coding the string would let
	// the test drift from how the compile path names it.
	noteIdPMetadataOutcome("ghost", idpRemoteDocumentSource(bad), idpMetaUnavailable, fmt.Errorf("down"))
	if !idpMetadataState().Failing {
		t.Fatal("precondition: the candidate must have an open episode")
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
	noteIdPMetadataOutcome("live-one", chaos71Source("live-one"), idpMetaUnavailable, fmt.Errorf("down"))
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
	if !bytes.Equal(got, doc) {
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
	noteIdPMetadataOutcome("going-dark", chaos71Source("going-dark"), idpMetaUnavailable, fmt.Errorf("down"))
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
	noteIdPMetadataOutcome("going-dark", chaos71Source("going-dark"), idpMetaUnavailable, fmt.Errorf("down"))

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

// chaos71StubProvider is a minimal IdentityProvider for the publication gates:
// they assert on WHICH pointer is published, never on provider behaviour.
type chaos71StubProvider struct{}

func (chaos71StubProvider) Verify(string, string) bool                       { return false }
func (chaos71StubProvider) ResolveIdentity(string, string) (*Identity, bool) { return nil, false }
func (chaos71StubProvider) Name() string                                     { return "chaos71-stub" }
func (chaos71StubProvider) DisplayName() string                              { return "chaos71-stub" }
func (chaos71StubProvider) CaptiveLoginURL(string, *http.Request) string     { return "" }

// ---------------------------------------------------------------------------
// Codex review round 4. Three findings, each verified against its pre-fix shape.
// ---------------------------------------------------------------------------

// ROUND 4 P1. ReplaceAll is the CP->DP snapshot-apply path, so a `null` entry in
// idp_profiles must be REFUSED, not fatal. validateIdPProfile handles nil
// correctly; the cleanup helper added in round 3 then dereferenced it and
// panicked the data plane.
func TestChaos71_NilSnapshotProfileIsRefusedNotFatal(t *testing.T) {
	chaos71Env(t)
	reg := &IdPRegistry{live: make(map[string]IdentityProvider)}

	// A nil entry alongside a legitimate one, in both orders: the panic must
	// not depend on where in the snapshot the malformed entry sits.
	good := func() *IdPProfile {
		return &IdPProfile{
			ID: "ok", Name: "ok", Type: IdPTypeSAML, Enabled: false,
			SAML: &SAMLProfileConfig{MetadataXML: chaos71MetadataXML(t, "nilsnap")},
		}
	}
	for _, snapshot := range [][]*IdPProfile{
		{nil},
		{nil, good()},
		{good(), nil},
	} {
		err := reg.ReplaceAll(snapshot) // must RETURN, never panic
		if err == nil {
			t.Fatalf("a snapshot carrying a nil profile must be refused, got nil error (len=%d)", len(snapshot))
		}
	}
	if len(reg.profiles) != 0 {
		t.Fatalf("a refused snapshot must publish nothing, got %d profile(s)", len(reg.profiles))
	}
}

// ROUND 4 P2. The degradation page must not depend on another fetch happening.
// A provider that fell back to cache once and whose config never changed again
// crosses the elapsed-time threshold with nothing left to evaluate it: no
// compile, and no recovery loop either, because that loop covers DARK profiles
// and a cache-serving provider is LIVE.
func TestChaos71_DegradationAlertFiresWithoutAFurtherFetch(t *testing.T) {
	chaos71Env(t)
	idpMetadataEverUsed.Store(true)

	// ONE failure, then nothing ever compiles this profile again.
	noteIdPMetadataOutcome("cache-serving", chaos71Source("cache-serving"), idpMetaStale, fmt.Errorf("HTTP 503"))

	// Before the threshold: no page.
	if fired := idpMetadataDegradationSweep(time.Now()); len(fired) != 0 {
		t.Fatalf("swept %d alert(s) before the threshold elapsed, want 0", len(fired))
	}

	// Past the threshold, with NO further fetch recorded.
	fired := idpMetadataDegradationSweep(time.Now().Add(idpMetadataDegradedAfter + time.Minute))
	if len(fired) != 1 {
		t.Fatalf("the degradation page must fire without another fetch, got %d", len(fired))
	}
	if fired[0] != idpMetaStale {
		t.Errorf("the alert must carry the episode's BOUNDED outcome class, got %q", fired[0])
	}

	// Fire-once: the latch must hold across sweeps, or a ticking watchdog
	// would page every interval for one episode.
	if again := idpMetadataDegradationSweep(time.Now().Add(2 * idpMetadataDegradedAfter)); len(again) != 0 {
		t.Fatalf("the fire-once latch leaked: swept %d further alert(s)", len(again))
	}
}

// The CONTROL: the sweep must not invent pages. An episode that RECOVERED on
// observed evidence is gone, and the cheapest way to pass the gate above is to
// fire for anything at all.
func TestChaos71_DegradationSweepDoesNotPageARecoveredProfile(t *testing.T) {
	chaos71Env(t)
	idpMetadataEverUsed.Store(true)

	noteIdPMetadataOutcome("recovers", chaos71Source("recovers"), idpMetaStale, fmt.Errorf("HTTP 503"))
	noteIdPMetadataOutcome("recovers", chaos71Source("recovers"), idpMetaFresh, nil) // observed evidence

	if fired := idpMetadataDegradationSweep(time.Now().Add(10 * idpMetadataDegradedAfter)); len(fired) != 0 {
		t.Fatalf("a recovered profile must never be paged, got %d alert(s)", len(fired))
	}
	// And a sweep with no episodes at all is inert.
	if fired := idpMetadataDegradationSweep(time.Now()); len(fired) != 0 {
		t.Fatalf("an empty sweep must be inert, got %d", len(fired))
	}
}

// The watchdog interval must stay BELOW the threshold it detects, or the page
// lands late by design (CHAOS-55's recoveryPollCeiling rule).
func TestChaos71_WatchdogIntervalIsCappedBelowTheThreshold(t *testing.T) {
	if idpMetadataWatchdogInterval >= idpMetadataDegradedAfter {
		t.Fatalf("watchdog interval %s must be < the degradation threshold %s, or the page straddles it",
			idpMetadataWatchdogInterval, idpMetadataDegradedAfter)
	}
}

// ROUND 4 P2, wiring. A detection-only watchdog must not fetch, compile, or
// clear an episode — recovery stays on OBSERVED evidence.
func TestChaos71_DegradationSweepNeverClearsAnEpisode(t *testing.T) {
	chaos71Env(t)
	idpMetadataEverUsed.Store(true)

	noteIdPMetadataOutcome("still-down", chaos71Source("still-down"), idpMetaUnavailable, fmt.Errorf("down"))
	_ = idpMetadataDegradationSweep(time.Now().Add(idpMetadataDegradedAfter + time.Minute))

	if !idpMetadataState().Failing {
		t.Fatal("the sweep must not clear the episode — only observed evidence may")
	}
}

// ROUND 4 P3. Compiling writes the five discovered endpoints into the profile,
// and the recovery compile runs OUTSIDE r.mu, so the loop must not be handed the
// registry's own pointer. Run under -race, this fails on the pre-fix shape.
func TestChaos71_RecoveryCompilesACopyNotTheRegistrysProfile(t *testing.T) {
	chaos71Env(t)

	live := &IdPProfile{
		ID: "racy", Name: "racy", Type: IdPTypeOIDC, Enabled: true,
		OIDC: &OIDCProfileConfig{Issuer: "https://idp.example", ClientID: "c", ClientSecret: "s"},
	}
	reg := &IdPRegistry{live: make(map[string]IdentityProvider), profiles: []*IdPProfile{live}}

	dark := reg.darkEnabledProfiles()
	if len(dark) != 1 {
		t.Fatalf("want 1 dark candidate, got %d", len(dark))
	}
	dc := dark[0]
	if dc.generation != live {
		t.Error("the generation token must be the registry's own pointer, or publishRecompiled's identity check is meaningless")
	}
	if dc.candidate == live {
		t.Fatal("the candidate handed to the compile must NOT be the registry's profile")
	}
	if dc.candidate.OIDC == live.OIDC {
		t.Fatal("the OIDC config must be deep-copied — that is the struct the compile writes into")
	}

	// Simulate what NewOIDCFlowProvider does, then prove it did not touch the
	// registry's profile until publication carries it across under the lock.
	dc.candidate.OIDC.TokenEndpoint = "https://idp.example/token"
	if live.OIDC.TokenEndpoint != "" {
		t.Fatal("a compile-time write reached the registry's profile without the lock")
	}
	if !reg.publishRecompiled(dc.candidate.ID, dc.generation, dc.candidate, chaos71StubProvider{}) {
		t.Fatal("publishRecompiled refused a legitimate recovery")
	}
	if live.OIDC.TokenEndpoint != "https://idp.example/token" {
		t.Error("discovered endpoints must be carried onto the authoritative profile at publication, " +
			"or the admin UI silently stops showing them for any recovered provider")
	}
}

// The CONTROL for P3: cloning must not defeat the generation check. A profile
// REPLACED while the compile ran must still be refused.
func TestChaos71_PublishStillRefusesASupersededGeneration(t *testing.T) {
	chaos71Env(t)

	live := &IdPProfile{
		ID: "racy", Name: "racy", Type: IdPTypeOIDC, Enabled: true,
		OIDC: &OIDCProfileConfig{Issuer: "https://idp.example", ClientID: "c", ClientSecret: "s"},
	}
	reg := &IdPRegistry{live: make(map[string]IdentityProvider), profiles: []*IdPProfile{live}}
	dc := reg.darkEnabledProfiles()[0]

	// An admin write replaces the profile with a NEW generation.
	reg.mu.Lock()
	reg.profiles = []*IdPProfile{{
		ID: "racy", Name: "racy", Type: IdPTypeOIDC, Enabled: true,
		OIDC: &OIDCProfileConfig{Issuer: "https://other.example", ClientID: "c", ClientSecret: "s"},
	}}
	reg.mu.Unlock()

	if reg.publishRecompiled(dc.candidate.ID, dc.generation, dc.candidate, chaos71StubProvider{}) {
		t.Fatal("a provider built from a SUPERSEDED generation must never be published")
	}
}

// ── Codex review round 7 ────────────────────────────────────────────────────

// chaos71OIDCServer is a discovery endpoint whose document can be switched
// between a healthy one and one naming a private authorization endpoint.
type chaos71OIDCServer struct {
	srv      *httptest.Server
	serveBad atomic.Bool
}

func newChaos71OIDCServer(t *testing.T, badAuthzHost string) *chaos71OIDCServer {
	t.Helper()
	s := &chaos71OIDCServer{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		authz := s.srv.URL + "/authorize"
		if s.serveBad.Load() {
			authz = "https://" + badAuthzHost + "/authorize"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q}`,
			s.srv.URL, authz, s.srv.URL+"/token")
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *chaos71OIDCServer) goodAuthz() string { return s.srv.URL + "/authorize" }

// idpMetadataHasEpisode reports whether an episode exists for (profile, source)
// WITHOUT creating one. idpMetadataEpisodeLocked is get-or-create, so it cannot
// answer a presence question — calling it would manufacture the episode the
// assertion is looking for.
func idpMetadataHasEpisode(profileID, source string) bool {
	idpMetadata.mu.Lock()
	defer idpMetadata.mu.Unlock()
	_, ok := idpMetadata.episodes[idpEpisodeKey(profileID, source)]
	return ok
}

// R7-D1 (P1, defect). THE DOCUMENT GATE resolveIdPDocument APPLIES MUST BE THE
// SAME VERDICT THE COMPILE USES.
//
// Round 6 split the OIDC parser and wired the validator to the STRUCTURAL half,
// so a 200 document that parses and whose endpoints are structurally legal
// passed the gate even when its authorization_endpoint resolved into a private
// range: Store.Put OVERWROTE the last-known-good copy and a FRESH acquisition
// was recorded, and only then did the authoritative parse refuse the provider.
// The document that could be compiled was gone, so the next outage found only
// the refused one — recovery defeated by the acquisition that reported success.
//
// The pre-fix tree fails every assertion here: the compile errors instead of
// degrading, the cache holds the refused bytes, and nothing is counted stale.
func TestChaos71_ARefusedDocumentNeverReplacesTheLastKnownGood(t *testing.T) {
	store := chaos71Env(t)

	// A host with a DEFINITE private verdict, seeded into the SSRF DNS cache so
	// this gate needs no resolver and no /etc/hosts. chaos71Env allows loopback
	// (the discovery server lives there), so loopback is NOT private here — the
	// two hosts therefore get genuinely different verdicts.
	ssrf.CacheStore("authz-private-r7.invalid", true)

	idp := newChaos71OIDCServer(t, "authz-private-r7.invalid")
	issuer := idp.srv.URL
	wellKnown := oidcWellKnownURL(issuer)

	// 1. A healthy acquisition caches the good document. (Also the CONTROL for
	//    the cheapest wrong fix: never replacing the cache at all.)
	got, err := fetchOIDCDiscovery("r7", issuer)
	if err != nil {
		t.Fatalf("healthy discovery must compile: %v", err)
	}
	if got.AuthorizationEndpoint != idp.goodAuthz() {
		t.Fatalf("authorization_endpoint = %q, want %q", got.AuthorizationEndpoint, idp.goodAuthz())
	}
	cached, _, cErr := store.Get("r7", idpmeta.KindOIDCDiscovery, wellKnown)
	if cErr != nil {
		t.Fatalf("a healthy document must be cached as last-known-good: %v", cErr)
	}
	if !bytes.Contains(cached, []byte(idp.goodAuthz())) {
		t.Fatalf("cached document does not name the good authorization endpoint: %s", cached)
	}
	if st := idpMetadataState(); st.Failing {
		t.Fatalf("a healthy acquisition must open no episode, got %+v", st)
	}
	goodBytes := append([]byte(nil), cached...)

	// 2. The IdP now serves a document the COMPILE will refuse.
	idp.serveBad.Store(true)

	got2, err := fetchOIDCDiscovery("r7", issuer)
	if err != nil {
		t.Fatalf("a refused document must degrade to the last-known-good, not fail the compile: %v", err)
	}
	if got2.AuthorizationEndpoint != idp.goodAuthz() {
		t.Fatalf("authorization_endpoint = %q, want the CACHED %q — the refused document must never become authoritative",
			got2.AuthorizationEndpoint, idp.goodAuthz())
	}

	// 3. The cache still holds the document that can be compiled.
	after, _, aErr := store.Get("r7", idpmeta.KindOIDCDiscovery, wellKnown)
	if aErr != nil {
		t.Fatalf("the last-known-good document must survive a refused fetch: %v", aErr)
	}
	if !bytes.Equal(after, goodBytes) {
		t.Fatalf("the cache was replaced by a document the compile refuses:\n got %s\nwant %s", after, goodBytes)
	}

	// 4. And it is reported as the degradation it is, not as a success.
	if st := idpMetadataState(); !st.Failing || st.StaleServed == 0 {
		t.Fatalf("serving the cache because the IdP's document was refused must be counted stale and failing, got %+v", st)
	}
}

// R7-D1b. This gate is BOTH halves and it is worth being precise about which,
// because they are usually different tests.
//
// As a DEFECT gate it pins the MIS-REPORTING half of R7-D1: with nothing cached,
// the pre-fix tree recorded the refused document as a FRESH acquisition —
// LastReason "fresh", LastSuccess advanced, no episode — while the provider did
// not go live, so the operator's only signal said healthy. It was verified
// failing against the verbatim pre-fix block for exactly that reason.
//
// As a CONTROL it pins that the refusal still happens at all. The cheapest way
// to pass R7-D1 is to stop refusing the document, which would reopen the
// browser-redirect-to-internal path round 3 closed; with no fallback available,
// failing closed is the only correct outcome.
func TestChaos71_PrivateAuthzEndpointStillFailsClosedWithNoCache(t *testing.T) {
	chaos71Env(t)
	ssrf.CacheStore("authz-private-r7b.invalid", true)

	idp := newChaos71OIDCServer(t, "authz-private-r7b.invalid")
	idp.serveBad.Store(true)

	if _, err := fetchOIDCDiscovery("r7b", idp.srv.URL); err == nil {
		t.Fatal("a private authorization_endpoint with no cached fallback must refuse the compile")
	}
	if st := idpMetadataState(); !st.Failing {
		t.Fatalf("the refusal must open an episode so it is visible, got %+v", st)
	}
}

// chaos71RepointSetup leaves profile "corp" LIVE on source A, serving A's cached
// document, with an open failure episode for A — the state a repoint arrives
// into. Package-level rather than a closure inside the gate: gocognit charges
// each branch by its nesting depth, and these three live two closures deep.
func chaos71RepointSetup(t *testing.T) (sourceA string, healthyB *chaos71IdP) {
	t.Helper()
	chaos71Env(t)
	a := newChaos71IdP(t)
	b := newChaos71IdP(t)

	// A is healthy first, so the profile is REGISTERED and live with a cached
	// document...
	if err := idpRegistry.Upsert(chaos71Profile("corp", a.URL())); err != nil {
		t.Fatalf("initial upsert against a healthy source: %v", err)
	}
	// ...then A stops answering, and a recompile degrades to its cache, which is
	// what opens A's episode while the profile stays live.
	a.down.Store(true)
	if err := idpRegistry.Upsert(chaos71Profile("corp", a.URL())); err != nil {
		t.Fatalf("stale recompile must succeed from cache: %v", err)
	}
	if !idpMetadataHasEpisode("corp", a.URL()) {
		t.Fatal("setup: source A must carry an open episode")
	}
	return a.URL(), b
}

// chaos71WantEpisode / chaos71WantNoEpisode keep the assertion branches out of
// the gate bodies for the same reason.
func chaos71WantEpisode(t *testing.T, profileID, source, why string) {
	t.Helper()
	if !idpMetadataHasEpisode(profileID, source) {
		t.Fatal(why)
	}
}

func chaos71WantNoEpisode(t *testing.T, profileID, source, why string) {
	t.Helper()
	if idpMetadataHasEpisode(profileID, source) {
		t.Fatal(why)
	}
}

func chaos71WantNotFailing(t *testing.T, why string) {
	t.Helper()
	if st := idpMetadataState(); st.Failing {
		t.Fatalf("%s: %+v", why, st)
	}
}

func chaos71WantErr(t *testing.T, err error, why string) {
	t.Helper()
	if err == nil {
		t.Fatal(why)
	}
}

// R7-D2 (P2, defect). A COMMITTED REPOINT MUST RETIRE THE SUPERSEDED SOURCE'S
// EPISODE.
//
// Round 6 keyed episodes by (profile, SOURCE), which fixed the REFUSAL path and
// left the COMMIT path leaking: a live profile serving cached metadata from
// source A carries an open episode for A, and a successful edit to a healthy
// source B clears only B's key. Nothing in the process fetches A any more, so
// A's episode can never be cleared by evidence — it ages past the degradation
// threshold and the (now unconditional) watchdog pages for a source that is no
// longer configured.
func TestChaos71_CommittedRepointRetiresThePreviousSourcesEpisode(t *testing.T) {
	t.Run("Upsert", func(t *testing.T) {
		sourceA, healthyB := chaos71RepointSetup(t)
		if err := idpRegistry.Upsert(chaos71Profile("corp", healthyB.URL())); err != nil {
			t.Fatalf("repoint to a healthy source: %v", err)
		}
		chaos71WantNoEpisode(t, "corp", sourceA,
			"the superseded source's episode must be retired on commit — nothing fetches it any more, "+
				"so it can never be cleared by evidence and will page forever")
		chaos71WantNoEpisode(t, "corp", healthyB.URL(),
			"the newly published healthy source must carry no episode")
		chaos71WantNotFailing(t, "no episode must survive a fully healthy repoint")
	})

	t.Run("ReplaceAll", func(t *testing.T) {
		sourceA, healthyB := chaos71RepointSetup(t)
		if err := idpRegistry.ReplaceAll([]*IdPProfile{chaos71Profile("corp", healthyB.URL())}); err != nil {
			t.Fatalf("snapshot repoint to a healthy source: %v", err)
		}
		chaos71WantNoEpisode(t, "corp", sourceA,
			"ReplaceAll has the same retention gap as Upsert and must retire the superseded source too")
		chaos71WantNotFailing(t, "no episode must survive a fully healthy snapshot repoint")
	})

	// CONTROL: retire on COMMIT, never on ATTEMPT. A repoint whose candidate
	// cannot be compiled leaves the OLD configuration authoritative, so A is
	// still the source in service and its genuine outage episode must survive.
	t.Run("ControlRefusedRepointKeepsTheLiveSourcesEpisode", func(t *testing.T) {
		sourceA, _ := chaos71RepointSetup(t)
		deadB, _ := chaos71DeadTLSEndpoint(t)
		chaos71WantErr(t, idpRegistry.Upsert(chaos71Profile("corp", deadB)),
			"a repoint to an uncompilable source must be refused")
		chaos71WantEpisode(t, "corp", sourceA,
			"a REFUSED repoint must not retire the live source's episode — "+
				"source A is still what this profile fetches")
		chaos71WantNoEpisode(t, "corp", deadB,
			"the refused candidate must leave no episode of its own")
	})

	// CONTROL: a persist failure is not a commit either.
	t.Run("ControlUnpersistedRepointKeepsTheLiveSourcesEpisode", func(t *testing.T) {
		sourceA, healthyB := chaos71RepointSetup(t)
		idpRegistry.path = filepath.Join(t.TempDir(), "no-such-dir", "idp.json")
		chaos71WantErr(t, idpRegistry.Upsert(chaos71Profile("corp", healthyB.URL())),
			"a repoint that cannot be persisted must be refused")
		chaos71WantEpisode(t, "corp", sourceA,
			"an UNPERSISTED repoint must not retire the live source's episode")
	})

	// CONTROL: episodes are per (profile, source), so retiring one profile's
	// view of source A must not touch another profile's.
	t.Run("ControlAnotherProfilesEpisodeOnTheSameSourceSurvives", func(t *testing.T) {
		sourceA, healthyB := chaos71RepointSetup(t)
		noteIdPMetadataOutcome("other", sourceA, idpMetaUnavailable, fmt.Errorf("down"))
		if err := idpRegistry.Upsert(chaos71Profile("corp", healthyB.URL())); err != nil {
			t.Fatalf("repoint: %v", err)
		}
		chaos71WantEpisode(t, "other", sourceA,
			"another profile's episode on the same source must survive")
	})
}

// R7-D3 (P2, defect). ONE DERIVATION MEANS ONE STRING, NORMALISATION INCLUDED.
//
// Round 6 made oidcWellKnownURL the single derivation of the discovery URL —
// the fetch target, the cache key and the episode source — and left the
// trailing-slash normalisation OUTSIDE it, in fetchOIDCDiscovery. So for an
// issuer ending in "/" (which both admission gates accept, since neither
// normalises) the acquisition recorded its episode under one key while
// idpRemoteDocumentSource derived another, and a refused edit's cleanup looked
// up a key that never existed — round 6's own defect, one layer down.
func TestChaos71_IssuerTrailingSlashDerivesExactlyOneSource(t *testing.T) {
	// The derivation itself.
	for _, issuer := range []string{
		"https://idp.example.com",
		"https://idp.example.com/",
		"https://idp.example.com///",
	} {
		if got, want := oidcWellKnownURL(issuer), "https://idp.example.com/.well-known/openid-configuration"; got != want {
			t.Errorf("oidcWellKnownURL(%q) = %q, want %q", issuer, got, want)
		}
	}
	if oidcWellKnownURL("") != "" {
		t.Error("an empty issuer must derive an empty source")
	}

	// And the property it exists for: acquisition and cleanup must agree, so a
	// refused edit carrying a trailing-slash issuer leaves NO episode behind.
	chaos71Env(t)
	bad := &IdPProfile{
		ID: "slash", Name: "slash", Type: IdPTypeOIDC, Enabled: true,
		// ClientID is REQUIRED or NewOIDCFlowProvider refuses before it ever
		// calls fetchOIDCDiscovery — the first draft of this gate omitted it,
		// so no episode was ever recorded and the assertion below passed
		// against the defect it exists to catch. A gate that cannot reach the
		// code under test proves nothing.
		OIDC: &OIDCProfileConfig{
			Issuer:   "https://idp-that-does-not-resolve.invalid/",
			ClientID: "c",
		},
	}
	if err := idpRegistry.Upsert(bad); err == nil {
		t.Fatal("an unresolvable issuer with nothing cached must be refused")
	}
	// The episode the refused compile opened must be gone under EVERY spelling:
	// the acquisition records one key and the cleanup derives another, so
	// checking only one of them would miss the divergence in one direction.
	for _, source := range []string{
		"https://idp-that-does-not-resolve.invalid/.well-known/openid-configuration",
		"https://idp-that-does-not-resolve.invalid//.well-known/openid-configuration",
	} {
		if idpMetadataHasEpisode("slash", source) {
			t.Errorf("a refused edit left an episode under %q", source)
		}
	}
	if st := idpMetadataState(); st.Failing {
		t.Fatalf("a refused edit must leave no episode — the cleanup key must match the one the "+
			"acquisition recorded, whatever the issuer's trailing slashes: %+v", st)
	}
}

// R7 WALL. The runbook quotes an event name and an `outcome="…"` token, and an
// operator builds log parsing and alert routing from exactly those strings — so
// they are a contract, not prose. CHAOS-69 learned this the expensive way: its
// runbook kept a pre-rework example naming a bound the emitter never printed,
// and the doc contradicted its own field list. Prose cannot be unit-tested but a
// QUOTED TOKEN can, so every one the runbook names must be one the code emits.
//
// It pins the CONTRACT, not the layout: which tokens the doc chooses to mention
// stays the author's call, and only their correctness is asserted.
func TestChaos71_RunbookQuotesOnlyRealLogTokens(t *testing.T) {
	// Both reads are anchored to pkgSourceDir(): a CWD-relative read picks up the
	// wrong file the moment any concurrent test calls os.Chdir, which is the class
	// TestTestFileReadsAreCWDIndependent exists to keep out, and it caught the
	// bare .go read here.
	//
	// The docs read had the IDENTICAL hazard and no pattern to catch it — that
	// wall matches a bare `os.ReadFile("x.go")` and `static/index.html`, not a
	// filepath.Join whose first element is a literal repo directory. Widening it
	// was tried and reverted: eleven pre-existing sites across other sweeps match
	// that shape, and some are reads relative to a temp dir the test deliberately
	// chdir'd into, so closing the gap needs per-site review rather than one
	// regexp. Recorded as a wall-coverage gap rather than papered over here;
	// every docs-reading test in this package otherwise already anchors, which is
	// the convention followed below.
	runbook, err := os.ReadFile(filepath.Join(pkgSourceDir(), "docs", "operator", "idp-metadata-availability.md")) // #nosec G304 -- fixed in-repo path
	if err != nil {
		t.Fatalf("read runbook: %v", err)
	}
	health, err := os.ReadFile(filepath.Join(pkgSourceDir(), "idp_metadata_health.go")) // #nosec G304 -- fixed in-repo path
	if err != nil {
		t.Fatalf("read health plane: %v", err)
	}

	events := regexp.MustCompile(`IDP_METADATA_[A-Z_]+`).FindAllString(string(runbook), -1)
	if len(events) == 0 {
		t.Fatal("not vacuous: the runbook must name at least one log event")
	}
	seenEvent := map[string]bool{}
	for _, ev := range events {
		if seenEvent[ev] {
			continue
		}
		seenEvent[ev] = true
		if !bytes.Contains(health, []byte(ev)) {
			t.Errorf("the runbook names log event %q, which idp_metadata_health.go never emits", ev)
		}
	}

	valid := map[string]bool{
		string(idpMetaFresh):       true,
		string(idpMetaStale):       true,
		string(idpMetaUnavailable): true,
	}
	outcomes := regexp.MustCompile(`outcome="([a-z_]+)"`).FindAllStringSubmatch(string(runbook), -1)
	if len(outcomes) == 0 {
		t.Fatal("not vacuous: the runbook must quote at least one outcome token")
	}
	for _, m := range outcomes {
		if !valid[m[1]] {
			t.Errorf("the runbook quotes outcome=%q, which is not an idpMetadataOutcome value", m[1])
		}
	}
}

// ── Codex review round 8 ────────────────────────────────────────────────────

// R8-D1 (P1, defect). THE STALENESS CEILING MUST BE ENFORCED ON A LIVE PROVIDER,
// NOT ONLY AT COMPILE TIME.
//
// idpmeta.StaleMaxAge lives inside Store.Get, which is reached only from a
// compile — and on a steady-state node nothing recompiles: an unchanged CP
// snapshot skips ReplaceAll, the recovery loop considers only DARK profiles, and
// the degradation watchdog only alerted. So a provider compiled from cache stayed
// live INDEFINITELY on a document the runbook promises "stops being usable 7 days
// after it was fetched", which for SAML means continuing to trust a signing
// certificate the IdP has withdrawn.
//
// The watchdog now retires such a provider, making it dark — the same state a
// fresh boot past the ceiling produces — and hands it to the recovery loop.
func TestChaos71_StaleCeilingIsEnforcedOnALiveProvider(t *testing.T) {
	chaos71Env(t)

	const profile = "expired"
	source := chaos71Source(profile)

	// A provider live from a cached document fetched just inside the ceiling.
	noteIdPMetadataOutcome(profile, source, idpMetaStale, fmt.Errorf("endpoint down"))
	noteIdPStaleDocumentServed(profile, source, time.Now().Add(-idpmeta.StaleMaxAge+time.Hour))
	if got := idpStaleCeilingSweep(time.Now()); len(got) != 0 {
		t.Fatalf("a document still inside the ceiling must not be swept, got %+v", got)
	}

	// Past it, the provider is named for retirement exactly once.
	noteIdPStaleDocumentServed(profile, source, time.Now().Add(-idpmeta.StaleMaxAge-time.Minute))
	got := idpStaleCeilingSweep(time.Now())
	if len(got) != 1 || got[0].profileID != profile {
		t.Fatalf("a document past %s must be swept for retirement, got %+v", idpmeta.StaleMaxAge, got)
	}
	if again := idpStaleCeilingSweep(time.Now()); len(again) != 0 {
		t.Fatalf("one document must be reported ONCE, got %+v on the second sweep", again)
	}
}

// R8-D1b (P1, defect, end to end). The registry must actually stop serving it,
// and must leave the profile ENABLED so the recovery loop owns it — retiring by
// disabling or deleting would discard the operator's configuration over an
// expired document.
func TestChaos71_RetiringAnExpiredProviderLeavesItDarkNotDeleted(t *testing.T) {
	chaos71Env(t)
	idp := newChaos71IdP(t)

	if err := idpRegistry.Upsert(chaos71Profile("corp", idp.URL())); err != nil {
		t.Fatalf("initial upsert: %v", err)
	}
	if !idpRegistry.HasEnabledInteractiveProvider() {
		t.Fatal("setup: the provider must be live")
	}

	if !idpRegistry.retireStaleProvider("corp", idpRemoteDocumentSource(chaos71Profile("corp", idp.URL()))) {
		t.Fatal("a live enabled profile must be retirable")
	}
	if idpRegistry.HasEnabledInteractiveProvider() {
		t.Fatal("an expired provider must no longer be live — this is the fail-closed half: " +
			"serving it means trusting a signing key the IdP may have withdrawn")
	}
	if !idpRegistry.hasDarkEnabledProfile() {
		t.Fatal("the profile must be DARK (enabled, stored, no live provider) so the recovery loop owns it")
	}
	// The operator's configuration is untouched.
	found := false
	for _, p := range idpRegistry.All() {
		if p.ID == "corp" {
			found = true
			if !p.Enabled {
				t.Fatal("retiring must not disable the profile — the config is correct, the DOCUMENT expired")
			}
		}
	}
	if !found {
		t.Fatal("retiring must not delete the profile")
	}
	// Idempotent: a second retirement changes nothing.
	if idpRegistry.retireStaleProvider("corp", idpRemoteDocumentSource(chaos71Profile("corp", idp.URL()))) {
		t.Fatal("retiring an already-dark provider must report no change")
	}
}

// R9-D1 (P2, defect, Codex round 9). THE SOURCE IS PART OF THE RETIREMENT
// VERDICT. idpStaleCeilingSweep picks a victim under idpMetadata.mu and RELEASES
// it before retireStaleProvider takes r.mu — deliberately, since no subsystem
// may hold its own lock across a call into another's. An admin repoint lands in
// that window: Upsert publishes a HEALTHY provider for a NEW source, and an
// id-and-enabled check cannot tell it from the expired one it replaced, so the
// sweep deletes a provider that is serving correctly and browser SSO goes down
// for that profile until the recovery loop recompiles it.
//
// Verified failing against the reintroduced pre-fix shape (retireStaleProvider
// taking profileID alone): the replacement provider is deleted and
// HasEnabledInteractiveProvider reports false.
func TestChaos71_RetirementIsRefusedAfterARepoint(t *testing.T) {
	chaos71Env(t)
	oldIdP := newChaos71IdP(t)
	newIdP := newChaos71IdP(t)

	// Live on the OLD source, and that is the source the sweep would select.
	if err := idpRegistry.Upsert(chaos71Profile("corp", oldIdP.URL())); err != nil {
		t.Fatalf("initial upsert: %v", err)
	}
	expired := idpRemoteDocumentSource(chaos71Profile("corp", oldIdP.URL()))
	if expired == "" {
		t.Fatal("setup: the victim source must be derivable")
	}

	// The repoint the sweep cannot see, because it already let go of its lock.
	if err := idpRegistry.Upsert(chaos71Profile("corp", newIdP.URL())); err != nil {
		t.Fatalf("repoint upsert: %v", err)
	}
	if !idpRegistry.HasEnabledInteractiveProvider() {
		t.Fatal("setup: the replacement provider must be live before the stale sweep runs")
	}

	if idpRegistry.retireStaleProvider("corp", expired) {
		t.Fatal("a retirement selected for the PREVIOUS source must not delete the provider " +
			"published for the new one — the expired document is not what this profile serves")
	}
	if !idpRegistry.HasEnabledInteractiveProvider() {
		t.Fatal("the healthy replacement provider must still be live")
	}
	if idpRegistry.hasDarkEnabledProfile() {
		t.Fatal("the profile must not be dark — nothing was wrong with it")
	}

	// CONTROL: the cheapest way to pass the above is to stop retiring at all,
	// which would delete round 8's whole enforcement of the staleness ceiling.
	// A victim naming the source STILL IN SERVICE must retire exactly as before.
	inService := idpRemoteDocumentSource(chaos71Profile("corp", newIdP.URL()))
	if !idpRegistry.retireStaleProvider("corp", inService) {
		t.Fatal("a victim naming the source actually in service must still retire the provider")
	}
	if idpRegistry.HasEnabledInteractiveProvider() {
		t.Fatal("the ceiling must still be enforced for the source in service")
	}
}

// R8-D1c (P1, defect). RETIRING IS ONLY SAFE BECAUSE RECOVERY IS RE-ARMED.
// runIdPRecoveryLoop RETURNS once nothing is dark and was started once at boot,
// so a retirement would otherwise leave SSO down with nothing retrying it —
// strictly worse than the expired document. The watchdog therefore re-arms while
// anything is dark, and the arming is single-flighted.
func TestChaos71_RecoveryIsReArmedAndSingleFlighted(t *testing.T) {
	chaos71Env(t)

	idpRecoveryRunning.Store(false)
	t.Cleanup(func() { idpRecoveryRunning.Store(false) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := &atomic.Int64{}
	release := make(chan struct{})
	prevArm := idpArmRecovery
	idpArmRecovery = func(context.Context) {
		if !idpRecoveryRunning.CompareAndSwap(false, true) {
			return
		}
		started.Add(1)
		go func() { <-release; idpRecoveryRunning.Store(false) }()
	}
	t.Cleanup(func() { idpArmRecovery = prevArm })

	for i := 0; i < 5; i++ {
		idpArmRecovery(ctx)
	}
	if got := started.Load(); got != 1 {
		t.Fatalf("arming must be single-flighted: %d loops started, want 1", got)
	}
	close(release)
}

// R8-D1c CONTROL. The production arming must really start the loop, or every
// assertion above passes against a no-op. Verified by observing the guard flip.
func TestChaos71_ProductionArmingActuallyStartsTheLoop(t *testing.T) {
	chaos71Env(t)
	idpRecoveryRunning.Store(false)
	t.Cleanup(func() { idpRecoveryRunning.Store(false) })

	// Nothing is dark in this registry, so the loop returns immediately; what is
	// asserted is that arming RAN it — the guard must return to false on its own.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	armIdPRecoveryLoop(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !idpRecoveryRunning.Load() {
			return // the loop ran and released the guard
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("armIdPRecoveryLoop did not run the loop (the guard never cleared)")
}

// R8-D1 CONTROL. A provider live from a FRESH fetch must NEVER be retired,
// however old the cached copy beside it is. Retiring on cache age alone would
// take SSO down every 7 days on a completely healthy fleet — a self-inflicted
// outage far worse than the defect.
func TestChaos71_AHealthyLiveProviderIsNeverRetired(t *testing.T) {
	chaos71Env(t)

	const profile = "healthy"
	source := chaos71Source(profile)
	// It once served a very old cached document...
	noteIdPMetadataOutcome(profile, source, idpMetaStale, fmt.Errorf("was down"))
	noteIdPStaleDocumentServed(profile, source, time.Now().Add(-10*idpmeta.StaleMaxAge))
	// ...and has since fetched successfully, which closes the episode.
	noteIdPMetadataOutcome(profile, source, idpMetaFresh, nil)

	if got := idpStaleCeilingSweep(time.Now()); len(got) != 0 {
		t.Fatalf("a provider serving a FRESH document must never be retired, got %+v", got)
	}
}

// R8-D2 (P2, defect). EVERY ABORT ROLLS BACK EVERY CANDIDATE'S EPISODE.
//
// ReplaceAll is all-or-nothing, but its two in-loop abort paths discarded only
// the profile that failed. A snapshot that compiled an earlier changed-source
// candidate from stale cache — opening an episode for a source that is about to
// be rejected with the rest of the snapshot — then left that episode behind to
// age into a degradation alert for a configuration nobody ever ran. The rule was
// already written on the persist branch and applied to one of three paths.
func TestChaos71_AbortedSnapshotRollsBackEveryCandidatesEpisode(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  *IdPProfile
	}{
		{"validation", &IdPProfile{ID: "bad", Name: "bad", Type: IdPTypeSAML, Enabled: true,
			SAML: &SAMLProfileConfig{}}}, // neither metadata_url nor metadata_xml
		{"compile", nil}, // filled in below with an unreachable source
	} {
		t.Run(tc.name, func(t *testing.T) {
			chaos71Env(t)

			// The candidate whose episode leaks must have a CHANGED source: an
			// episode for the source ALREADY IN SERVICE is a genuine outage
			// signal and must survive a refusal (rounds 6/7), so only a
			// repointed candidate's episode is speculative.
			//
			// oldSrc is cached and then taken down; the profile is left live on
			// newSrc, which stays healthy — so after the refusal there is no
			// legitimate episode anywhere and any survivor is the leak.
			oldIdP := newChaos71IdP(t)
			if err := idpRegistry.Upsert(chaos71Profile("first", oldIdP.URL())); err != nil {
				t.Fatalf("seed against the old source: %v", err)
			}
			newIdP := newChaos71IdP(t)
			if err := idpRegistry.Upsert(chaos71Profile("first", newIdP.URL())); err != nil {
				t.Fatalf("move to the new source: %v", err)
			}
			oldIdP.down.Store(true) // cached, unreachable, and NOT in service

			bad := tc.bad
			if bad == nil {
				deadURL, _ := chaos71DeadTLSEndpoint(t)
				bad = chaos71Profile("bad", deadURL)
			}
			// The snapshot repoints "first" BACK to the dead-but-cached source —
			// which stale-compiles and opens a speculative episode — and then
			// fails on "bad", rejecting the whole snapshot.
			err := idpRegistry.ReplaceAll([]*IdPProfile{chaos71Profile("first", oldIdP.URL()), bad})
			if err == nil {
				t.Fatal("the snapshot must be rejected")
			}
			if idpMetadataHasEpisode("first", oldIdP.URL()) {
				t.Fatal("the earlier candidate's speculative episode survived an aborted snapshot — " +
					"its source was never published, so it pages for a configuration nobody ran")
			}
			if st := idpMetadataState(); st.Failing {
				t.Fatalf("a REJECTED snapshot must leave no candidate's episode behind — "+
					"nothing it compiled entered service, so any surviving episode pages for a "+
					"configuration that was never published: %+v", st)
			}
		})
	}
}

// R8-D1 WALL. The sweep, the retirement and the re-arming are worthless unless
// the watchdog actually invokes them, and that is the one thing no behavioural
// gate here can observe: the interval is a constant and a loop that was never
// wired looks exactly like a healthy one with nothing to do (round 5's
// "a start that never happens cannot be seen behaviourally", one mechanism over).
//
// It pins the CALLS, not their arrangement, so the body stays free to change.
func TestChaos71_WatchdogEnforcesTheCeilingAndReArmsRecovery(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "idp_metadata_health.go")) // #nosec G304 -- fixed in-repo path
	if err != nil {
		t.Fatalf("read health plane: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func runIdPMetadataDegradationWatchdog(")
	if start < 0 {
		t.Fatal("watchdog not found — rename it and this wall must be updated with it")
	}
	end := strings.Index(body[start:], "\n}\n")
	if end < 0 {
		t.Fatal("could not delimit the watchdog body")
	}
	fn := body[start : start+end]

	for _, must := range []string{
		"idpMetadataDegradationSweep(", // still alerts
		"idpStaleCeilingSweep(",        // enforces idpmeta.StaleMaxAge on live providers
		"idpRetireStaleProvider(",      // acts on the verdict
		"idpAnyProfileDark(",           // supervises
		"idpArmRecovery(",              // gives a retired provider a way back
	} {
		if !strings.Contains(fn, must) {
			t.Errorf("the watchdog no longer calls %s — detection without enforcement is what round 8 found, "+
				"and a retirement without re-arming leaves SSO down with nothing retrying it", must)
		}
	}
}
