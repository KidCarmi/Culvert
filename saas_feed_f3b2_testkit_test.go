package main

// saas_feed_f3b2_testkit_test.go — shared F3b-2 test harness.
//
// Design note on the verifier seam. The trust kernel (internal/urlcatfeed) is
// verify-before-parse and its identity/tamper rejections are proven GENUINELY there
// with an offline VirtualSigstore (verify_test.go: wrong SAN/issuer/workflow/tag,
// tampered payload/artifact → no object). A VirtualSigstore *Sign* entity's Rekor
// tlog proto is intentionally INCOMPLETE for re-serialization (no KindVersion, no
// serializable inclusion promise/proof), so a valid ACCEPT-path wire bundle cannot be
// reconstructed from it. F3b-2 therefore proves crypto behavior two ways:
//
//   - REAL kernel, rejection path: a forged/garbage envelope needs no valid
//     signature, so the production *urlcatfeed.Verifier rejects it and the pipeline is
//     driven with genuine crypto (verify-before-parse ⇒ zero artifact fetches).
//   - Faithful fakeFeedVerifier for the deterministic pipeline/persistence matrix
//     (valid accept, tampered-artifact reject, freshness, floor, idempotency,
//     conflict, concurrency, failure injection). It models the kernel CONTRACT
//     exactly (return a complete object or ErrVerify) so the pipeline logic is tested
//     without depending on sigstore-internal serialization.
//
// No production trust root, signing key, or bundle fixture enters non-test code.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// Compile-time proof that the production verifier satisfies the F3b-2 seam.
var _ feedVerifier = (*urlcatfeed.Verifier)(nil)

// feedMatchingSAN satisfies urlcatfeed.OfficialSANRegex (a tagged release run of the
// feed signing workflow).
const feedMatchingSAN = "https://github.com/KidCarmi/Culvert/.github/workflows/publish-feeds.yml@refs/tags/feeds-v1.0.0"

// ─── generated wire bytes (real generator, real manifest) ────────────────────────

// feedGen is a real generated feed: canonical manifest+artifact bytes + the verified
// manifest/artifact payloads. The bytes are exactly what the producer emits; the fake
// verifier returns these payloads for the matching bytes.
type feedGen struct {
	ManifestBytes []byte
	ArtifactBytes []byte
	Manifest      urlcatfeed.ManifestPayload
	Artifact      urlcatfeed.ArtifactPayload
	// EnvelopeBytes is a wire envelope wrapping the manifest bytes with an OPAQUE
	// (test-only) bundle marker. The fake verifier maps EnvelopeBytes → Manifest; the
	// real verifier rejects it (the bundle is not a genuine cosign bundle).
	EnvelopeBytes []byte
	// BundleBytes is an opaque artifact-bundle marker the fake verifier binds.
	BundleBytes []byte
}

type feedGenOpts struct {
	feedVersion int64
	generatedAt time.Time
	validity    time.Duration
}

func (o feedGenOpts) withDefaults() feedGenOpts {
	if o.feedVersion == 0 {
		o.feedVersion = 42
	}
	if o.generatedAt.IsZero() {
		o.generatedAt = time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	}
	if o.validity == 0 {
		o.validity = 14 * 24 * time.Hour
	}
	return o
}

func buildFeedGen(t *testing.T, o feedGenOpts) feedGen {
	t.Helper()
	o = o.withDefaults()
	gen, err := urlcatfeed.Generate(urlcatfeed.GenerateInput{
		Source:      feedSampleDataset(),
		FeedVersion: o.feedVersion,
		GeneratedAt: o.generatedAt,
		ExpiresAt:   o.generatedAt.Add(o.validity),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// An opaque envelope wrapping the real manifest bytes (payload_b64) plus a
	// test-only bundle marker. Shape-compatible with the wire Envelope so the download
	// path sees realistic bytes; the fake verifier keys on the exact bytes.
	envObj := map[string]any{
		"payload_b64": base64.StdEncoding.EncodeToString(gen.ManifestBytes),
		"bundle":      map[string]any{"test": "opaque-manifest-bundle"},
	}
	envBytes, _ := json.Marshal(envObj)
	bundleBytes := []byte(`{"test":"opaque-artifact-bundle"}`)
	return feedGen{
		ManifestBytes: gen.ManifestBytes,
		ArtifactBytes: gen.ArtifactBytes,
		Manifest:      gen.Manifest,
		EnvelopeBytes: envBytes,
		BundleBytes:   bundleBytes,
	}
}

func feedSampleDataset() urlcatfeed.SourceDataset {
	return urlcatfeed.SourceDataset{Categories: []urlcatfeed.SourceCategory{
		{Name: "ai", Hosts: []string{"chat.example", "api.example.ai"}},
		{Name: "storage", Hosts: []string{"files.example.net"}},
	}}
}

// ─── fake verifier (faithful to the kernel contract) ─────────────────────────────

// fakeFeedVerifier returns a COMPLETE verified object or ErrVerify/ErrBinding — never
// (nil,nil) — exactly like the kernel. It counts calls so tests can assert
// verify-before-parse ordering.
type fakeFeedVerifier struct {
	gen feedGen

	envelopeErr error // if set, VerifyEnvelope returns it
	artifactErr error // if set, VerifyArtifact returns it

	envelopeCalls atomic.Int64
	artifactCalls atomic.Int64
}

func newFakeVerifier(g feedGen) *fakeFeedVerifier { return &fakeFeedVerifier{gen: g} }

func (f *fakeFeedVerifier) VerifyEnvelope(b []byte) (*urlcatfeed.ManifestPayload, error) {
	f.envelopeCalls.Add(1)
	if f.envelopeErr != nil {
		return nil, f.envelopeErr
	}
	if string(b) != string(f.gen.EnvelopeBytes) {
		return nil, urlcatfeed.ErrVerify
	}
	m := f.gen.Manifest
	return &m, nil
}

func (f *fakeFeedVerifier) VerifyArtifact(artifactBytes, bundleJSON []byte, manifest *urlcatfeed.ManifestPayload) (*urlcatfeed.ArtifactPayload, error) {
	f.artifactCalls.Add(1)
	if f.artifactErr != nil {
		return nil, f.artifactErr
	}
	if manifest == nil {
		return nil, urlcatfeed.ErrBinding
	}
	// Bind exactly as the kernel does: size + digest against the manifest.
	if int64(len(artifactBytes)) != manifest.ArtifactSize || sha256Hex(artifactBytes) != manifest.ArtifactSHA256 {
		return nil, urlcatfeed.ErrBinding
	}
	if string(bundleJSON) != string(f.gen.BundleBytes) {
		return nil, urlcatfeed.ErrVerify
	}
	return &urlcatfeed.ArtifactPayload{
		SchemaVersion: urlcatfeed.SchemaVersion,
		Protocol:      urlcatfeed.Protocol,
		Feed:          urlcatfeed.FeedID,
		FeedVersion:   manifest.FeedVersion,
		GeneratedAt:   manifest.GeneratedAt,
	}, nil
}

// realFeedVerifier builds a genuine kernel verifier bound to an offline
// VirtualSigstore — used for the REJECTION-path tests (a forged/garbage envelope is
// rejected with real crypto, needing no valid signature).
func realFeedVerifier(t *testing.T) *urlcatfeed.Verifier {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	v, err := urlcatfeed.NewVerifierFromMaterial(vs, urlcatfeed.OfficialIdentity())
	if err != nil {
		t.Fatalf("NewVerifierFromMaterial: %v", err)
	}
	return v
}

// forgedEnvelope is a structurally-plausible envelope whose bundle is NOT a genuine
// cosign bundle, so the real kernel rejects it (verify-before-parse) without ever
// exposing a manifest field.
func forgedEnvelope(t *testing.T, manifestBytes []byte) []byte {
	t.Helper()
	envObj := map[string]any{
		"payload_b64": base64.StdEncoding.EncodeToString(manifestBytes),
		"bundle":      map[string]any{"not": "a-real-bundle"},
	}
	b, err := json.Marshal(envObj)
	if err != nil {
		t.Fatalf("marshal forged envelope: %v", err)
	}
	return b
}

// ─── in-process TLS origin ───────────────────────────────────────────────────────

// feedOrigin is an httptest TLS server standing in for feeds.culvertlabs.com, plus a
// fetcher wired to reach it (loopback resolver + a cert bearing the official SAN).
type feedOrigin struct {
	srv        *httptest.Server
	fetcher    *feedFetcher
	dialedAddr string // the addr the transport asked the dialer to reach (the resolved IP:443)
	sniName    string // the TLS ServerName the origin observed
	rootPool   *x509.CertPool
	certSANs   []string
}

// newFeedOrigin serves handler over TLS with a cert whose SAN is the official feed
// host, and returns a fetcher that resolves that host to loopback and trusts the cert.
func newFeedOrigin(t *testing.T, handler http.Handler) *feedOrigin {
	return newFeedOriginCert(t, handler, []string{saasFeedOfficialHost}, true)
}

// newFeedOriginCert allows overriding the cert SANs (for the TLS-hostname-failure
// test) and whether the fetcher trusts the cert.
func newFeedOriginCert(t *testing.T, handler http.Handler, certSANs []string, trust bool) *feedOrigin {
	t.Helper()
	cert, pool := feedTestCert(t, certSANs...)

	fo := &feedOrigin{rootPool: pool, certSANs: certSANs}
	fo.srv = httptest.NewUnstartedServer(handler)
	fo.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			fo.sniName = hello.ServerName
			return nil, nil
		},
	}
	fo.srv.StartTLS()
	t.Cleanup(fo.srv.Close)

	serverAddr := fo.srv.Listener.Addr().String()
	clientTLS := &tls.Config{ServerName: saasFeedOfficialHost, MinVersion: tls.VersionTLS12}
	if trust {
		clientTLS.RootCAs = pool
	}
	fo.fetcher = newFeedFetcher(feedFetcherOpts{
		resolve: func(_ context.Context, host string) ([]net.IP, error) {
			if host == saasFeedOfficialHost {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}
			return nil, net.UnknownNetworkError("unexpected host in test: " + host)
		},
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			fo.dialedAddr = addr // capture what the transport tried to dial (the resolved IP:443)
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, serverAddr)
		},
		tlsConfig:    clientTLS,
		allowPrivate: true, // loopback is "private"; permit it in tests only
	})
	return fo
}

// feedTestCert mints a short-lived self-signed cert whose SANs include dnsNames, and
// returns it plus a RootCAs pool trusting it.
func feedTestCert(t *testing.T, dnsNames ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	cn := "test"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return cert, pool
}

// ─── feed HTTP handler ───────────────────────────────────────────────────────────

// feedMux serves the approved manifest + artifact + bundle paths from a feedGen. It
// records per-path hit counts so tests can assert "zero artifact fetches" on a
// rejected manifest.
type feedMux struct {
	gen           feedGen
	manifestHits  atomic.Int64
	artifactHits  atomic.Int64
	bundleHits    atomic.Int64
	manifestETag  string
	artifactExtra func(w http.ResponseWriter, r *http.Request) bool // optional override; return true if handled
}

func newFeedMux(g feedGen) *feedMux { return &feedMux{gen: g} }

func (m *feedMux) artifactPath() string { return saasFeedArtifactPrefix + m.gen.Manifest.ArtifactPath }
func (m *feedMux) bundlePath() string   { return saasFeedArtifactPrefix + m.gen.Manifest.ArtifactSigPath }

func (m *feedMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case saasFeedManifestPath:
		m.manifestHits.Add(1)
		if m.manifestETag != "" {
			if inm := r.Header.Get("If-None-Match"); inm == m.manifestETag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", m.manifestETag)
		}
		_, _ = w.Write(m.gen.EnvelopeBytes)
	case m.artifactPath():
		m.artifactHits.Add(1)
		if m.artifactExtra != nil && m.artifactExtra(w, r) {
			return
		}
		_, _ = w.Write(m.gen.ArtifactBytes)
	case m.bundlePath():
		m.bundleHits.Add(1)
		_, _ = w.Write(m.gen.BundleBytes)
	default:
		http.NotFound(w, r)
	}
}

// baseAcquireInput returns a ready standalone AcquireInput for gen, with a fixed
// clock inside the manifest's validity window and a floor below the version.
func baseAcquireInput(g feedGen) AcquireInput {
	return AcquireInput{
		Config: SaaSFeedConfig{
			Managed:  false,
			Enabled:  true,
			URL:      builtinSaaSFeedURL,
			Protocol: saasFeedProtocolV1,
			Refresh:  saasFeedDefaultRefresh,
		},
		Authority:      authorityStandalone,
		RecoveredFloor: g.Manifest.FeedVersion - 1,
		Now:            func() time.Time { return time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC) },
	}
}
