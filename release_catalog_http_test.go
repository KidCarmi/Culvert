package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ─── fake catalog origin ─────────────────────────────────────────────────────

type fakeCatalogServer struct {
	files       map[string][]byte // "/index.json", "/index.json.sig", "/manifests/<ref>"
	etag        string            // when set, supports conditional 304
	partial     map[string]bool   // paths served truncated (declared Content-Length > body)
	slow        map[string]bool   // paths served after a delay (slow origin)
	delay       time.Duration
	manifestGET atomic.Int32 // count of /manifests/ requests
}

func (f *fakeCatalogServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/manifests/") {
			f.manifestGET.Add(1)
		}
		if f.slow[p] {
			time.Sleep(f.delay)
		}
		b, ok := f.files[p]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if p == "/index.json" && f.etag != "" {
			w.Header().Set("ETag", f.etag)
			if r.Header.Get("If-None-Match") == f.etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		if f.partial[p] {
			// Declare more than we write, then return → client sees a short read.
			w.Header().Set("Content-Length", strconv.Itoa(len(b)+512))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b[:len(b)/2])
			return
		}
		_, _ = w.Write(b)
	}
}

func signedCatalogFiles(t *testing.T, priv ed25519.PrivateKey, ms *memSource) map[string][]byte {
	t.Helper()
	files := map[string][]byte{
		"/index.json":     ms.index,
		"/index.json.sig": sigEnvelopeBytes(t, catalogSigAlg, holderTestKeyID, ed25519.Sign(priv, ms.index)),
	}
	for ref, b := range ms.manifests {
		files["/manifests/"+ref] = b
	}
	return files
}

// newHTTPProvider starts a fake origin and returns a provider wired to it (SSRF
// guard disabled for loopback; staging under a temp dir for cleanup assertions).
func newHTTPProvider(t *testing.T, f *fakeCatalogServer, trust TrustStore) (*HTTPCatalogProvider, string) {
	t.Helper()
	ts := httptest.NewServer(f.handler())
	t.Cleanup(ts.Close)
	p, err := NewHTTPCatalogProvider(ts.URL, trust)
	if err != nil {
		t.Fatal(err)
	}
	p.guard = nil // allow loopback in tests
	stageBase := t.TempDir()
	p.stageBase = stageBase
	return p, stageBase
}

func stageEmpty(t *testing.T, stageBase string) bool {
	t.Helper()
	entries, err := os.ReadDir(stageBase)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries) == 0
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestHTTPProvider_HappyPath(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCatalogServer{files: signedCatalogFiles(t, priv, validSource())}
	p, _ := newHTTPProvider(t, f, holderTrust(t, pub))

	dir, err := p.Stage(context.Background())
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// The staged dir hands off to the existing trust boundary unchanged.
	c, err := LoadVerifiedCatalog(&dirCatalogSource{dir: dir}, holderTrust(t, pub))
	if err != nil {
		t.Fatalf("LoadVerifiedCatalog over staged dir: %v", err)
	}
	if len(c.byReleaseID) != 2 {
		t.Fatalf("staged catalog has %d releases; want 2", len(c.byReleaseID))
	}
}

// A bad index signature is rejected in Phase 1 — BEFORE any manifest is fetched
// (the §5.1 guarantee) — and the staging dir is cleaned up.
func TestHTTPProvider_BadSignatureFetchesNoManifests(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil) // the trusted key
	if err != nil {
		t.Fatal(err)
	}
	_, attackerPriv, err := ed25519.GenerateKey(nil) // signs the index (untrusted)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCatalogServer{files: signedCatalogFiles(t, attackerPriv, validSource())}
	p, stageBase := newHTTPProvider(t, f, holderTrust(t, pub))

	if _, err := p.Stage(context.Background()); err == nil {
		t.Fatal("Stage must reject an index signed by an untrusted key")
	}
	if n := f.manifestGET.Load(); n != 0 {
		t.Fatalf("a bad index must trigger ZERO manifest fetches; got %d (§5.1)", n)
	}
	if !stageEmpty(t, stageBase) {
		t.Fatal("staging dir must be cleaned up on failure")
	}
}

// A tampered manifest passes the provider (index is authentic) but is caught by
// the hand-off to LoadVerifiedCatalog (manifest_sha256 mismatch).
func TestHTTPProvider_TamperedManifestCaughtOnLoad(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	files := signedCatalogFiles(t, priv, validSource())
	files["/manifests/a.json"] = append(append([]byte(nil), files["/manifests/a.json"]...), ' ') // tamper
	f := &fakeCatalogServer{files: files}
	p, _ := newHTTPProvider(t, f, holderTrust(t, pub))

	dir, err := p.Stage(context.Background())
	if err != nil {
		t.Fatalf("Stage should succeed (index authentic, manifests fetched): %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if _, err := LoadVerifiedCatalog(&dirCatalogSource{dir: dir}, holderTrust(t, pub)); err == nil {
		t.Fatal("LoadVerifiedCatalog must reject the tampered manifest (hash mismatch)")
	}
}

func TestHTTPProvider_PartialDownloadFailsAndCleans(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCatalogServer{
		files:   signedCatalogFiles(t, priv, validSource()),
		partial: map[string]bool{"/manifests/a.json": true},
	}
	p, stageBase := newHTTPProvider(t, f, holderTrust(t, pub))

	if _, err := p.Stage(context.Background()); err == nil {
		t.Fatal("a truncated manifest download must fail")
	}
	if !stageEmpty(t, stageBase) {
		t.Fatal("staging dir must be cleaned up after a partial download")
	}
}

func TestHTTPProvider_TimeoutFailsAndCleans(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCatalogServer{
		files: signedCatalogFiles(t, priv, validSource()),
		slow:  map[string]bool{"/index.json": true},
		delay: 500 * time.Millisecond,
	}
	p, stageBase := newHTTPProvider(t, f, holderTrust(t, pub))
	p.client = &http.Client{Timeout: 50 * time.Millisecond} // shorter than the delay

	if _, err := p.Stage(context.Background()); err == nil {
		t.Fatal("a slow origin must trip the client timeout")
	}
	if !stageEmpty(t, stageBase) {
		t.Fatal("staging dir must be cleaned up after a timeout")
	}
}

// The SSRF guard is enforced at DIAL time on the resolved address (closing the
// DNS-rebind window), not as a racy preflight host check.
func TestHTTPProvider_DialGuardRejectsPrivate(t *testing.T) {
	ts, err := NewTrustStore(nil, VerifyDisabled)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewHTTPCatalogProvider("https://releases.example.com/catalog/", ts) // production guard wired
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.safeDialContext(context.Background(), "tcp", "127.0.0.1:9"); err == nil {
		t.Fatal("safeDialContext must refuse a private/loopback address")
	}
}

// Redirects are re-guarded (private target refused) and capped.
func TestHTTPProvider_RedirectGuard(t *testing.T) {
	ts, err := NewTrustStore(nil, VerifyDisabled)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewHTTPCatalogProvider("https://releases.example.com/catalog/", ts)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1/evil", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.checkRedirect(priv, nil); err == nil {
		t.Fatal("checkRedirect must refuse a redirect to a private host")
	}
	pub, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://cdn.example.com/x", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.checkRedirect(pub, make([]*http.Request, 5)); err == nil {
		t.Fatal("checkRedirect must cap the redirect chain")
	}
}

func TestHTTPProvider_UnchangedCatalog304(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCatalogServer{files: signedCatalogFiles(t, priv, validSource()), etag: `"v1"`}
	p, _ := newHTTPProvider(t, f, holderTrust(t, pub))

	// First fetch succeeds and captures the ETag.
	dir, err := p.Stage(context.Background())
	if err != nil {
		t.Fatalf("first Stage: %v", err)
	}
	_ = os.RemoveAll(dir)
	manifestsAfterFirst := f.manifestGET.Load()

	// Second fetch sends If-None-Match → 304 → unchanged sentinel, no new work.
	if _, err := p.Stage(context.Background()); !errors.Is(err, errCatalogUnchanged) {
		t.Fatalf("second Stage: err = %v; want errCatalogUnchanged", err)
	}
	if got := f.manifestGET.Load(); got != manifestsAfterFirst {
		t.Fatalf("a 304 must not refetch manifests; got %d, was %d", got, manifestsAfterFirst)
	}
}
