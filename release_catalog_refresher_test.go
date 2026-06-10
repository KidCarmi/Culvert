package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// newSignedSourceRefresher wires a refresher over a freshly-signed source dir and
// an (initially empty) cache dir, returning the refresher plus the dirs.
func newSignedSourceRefresher(t *testing.T) (r *Refresher, src, cache string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	src = t.TempDir()
	cache = filepath.Join(t.TempDir(), "cache") // must not exist yet
	writeSignedCatalogDir(t, src, priv, validSource())
	return NewRefresher(src, cache, holderTrust(t, pub)), src, cache
}

// A successful refresh publishes the catalog, records metadata, and persists the
// last-good cache.
func TestRefresher_SuccessfulRefreshPublishes(t *testing.T) {
	r, _, cache := newSignedSourceRefresher(t)
	if err := r.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	c := r.GetCatalog()
	if c == nil || len(c.byReleaseID) != 2 {
		t.Fatalf("expected a published 2-release catalog; got %+v", c)
	}
	m := r.Meta()
	if !m.HasCatalog || m.LastError != "" || m.LastSuccess.IsZero() || m.LastAttempt.IsZero() {
		t.Fatalf("unexpected meta after success: %+v", m)
	}
	if _, err := os.Stat(filepath.Join(cache, "index.json")); err != nil {
		t.Fatalf("last-good cache not persisted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cache, "index.json.sig")); err != nil {
		t.Fatalf("cache signature not persisted: %v", err)
	}
}

// A failed refresh (source tampered after signing) keeps the current catalog and
// records the error.
func TestRefresher_FailedRefreshKeepsCurrent(t *testing.T) {
	r, src, _ := newSignedSourceRefresher(t)
	if err := r.Refresh(); err != nil {
		t.Fatal(err)
	}
	prev := r.GetCatalog()
	if prev == nil {
		t.Fatal("precondition: a catalog must be published")
	}

	// Tamper the source index so its signature no longer matches.
	tampered := append(append([]byte(nil), validSource().index...), ' ')
	if err := os.WriteFile(filepath.Join(src, "index.json"), tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := r.Refresh(); err == nil {
		t.Fatal("refresh of a tampered source must fail")
	}
	if r.GetCatalog() != prev {
		t.Fatal("a failed refresh must keep the exact previous catalog")
	}
	if m := r.Meta(); m.LastError == "" {
		t.Fatal("a failed refresh must record LastError")
	}
}

// Startup re-verifies the cache: a cache signed by an UNTRUSTED key is rejected
// and the (trusted) source is published instead.
func TestRefresher_CacheReVerifiedBeforePublish(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil) // trusted/source key
	if err != nil {
		t.Fatal(err)
	}
	_, untrustedPriv, err := ed25519.GenerateKey(nil) // cache signed by this (untrusted) key
	if err != nil {
		t.Fatal(err)
	}
	src, cache := t.TempDir(), t.TempDir()
	writeSignedCatalogDir(t, src, priv, validSource())            // source: trusted
	writeSignedCatalogDir(t, cache, untrustedPriv, validSource()) // cache: untrusted signer

	r := NewRefresher(src, cache, holderTrust(t, pub))
	if err := r.Start(); err != nil {
		t.Fatalf("Start should publish from the source: %v", err)
	}
	c := r.GetCatalog()
	if c == nil || len(c.byReleaseID) != 2 {
		t.Fatalf("expected the source catalog to be published; got %+v", c)
	}
}

// A corrupt cache is rejected (never published); the source is used instead, and
// with no usable source the holder stays in the no-catalog state.
func TestRefresher_CorruptCacheRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	src, cache := t.TempDir(), t.TempDir()
	writeSignedCatalogDir(t, src, priv, validSource())
	// Corrupt cache: present but unparseable index + garbage signature.
	if err := os.MkdirAll(filepath.Join(cache, "manifests"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "index.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "index.json.sig"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewRefresher(src, cache, holderTrust(t, pub))
	if err := r.Start(); err != nil {
		t.Fatalf("Start should publish from the source despite a corrupt cache: %v", err)
	}
	if c := r.GetCatalog(); c == nil || len(c.byReleaseID) != 2 {
		t.Fatalf("corrupt cache must be rejected and the source published; got %+v", c)
	}

	// Corrupt cache AND no usable source ⇒ no catalog (fail-closed, boots empty).
	// Use a FRESH corrupt cache (the first Start persisted a valid catalog over
	// the original cache dir).
	cache2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(cache2, "index.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache2, "index.json.sig"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	r2 := NewRefresher(t.TempDir(), cache2, holderTrust(t, pub)) // empty source dir
	if err := r2.Start(); err == nil {
		t.Fatal("Start with a corrupt cache and no source should error")
	}
	if r2.GetCatalog() != nil {
		t.Fatal("nothing may be published when neither cache nor source verifies")
	}
}

// Single-flight: while a refresh is in flight, concurrent triggers are rejected
// with errRefreshInFlight rather than starting a second refresh.
func TestRefresher_SingleFlight(t *testing.T) {
	r, _, _ := newSignedSourceRefresher(t)

	// Deterministic: simulate an in-flight refresh by holding the guard.
	if !r.begin() {
		t.Fatal("begin should succeed on a fresh refresher")
	}
	if err := r.Refresh(); !errors.Is(err, errRefreshInFlight) {
		t.Fatalf("Refresh while in flight: err = %v; want errRefreshInFlight", err)
	}
	if err := r.Start(); !errors.Is(err, errRefreshInFlight) {
		t.Fatalf("Start while in flight: err = %v; want errRefreshInFlight", err)
	}
	r.end()
	if err := r.Refresh(); err != nil {
		t.Fatalf("Refresh after the guard is released: %v", err)
	}

	// Concurrent stress (run under -race): every call is nil or in-flight; the
	// published catalog is always valid.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.Refresh(); err != nil && !errors.Is(err, errRefreshInFlight) {
				t.Errorf("unexpected refresh error: %v", err)
			}
		}()
	}
	wg.Wait()
	if r.GetCatalog() == nil {
		t.Fatal("a catalog must remain published after the concurrent refreshes")
	}
}

// Staleness is computed from the catalog's GeneratedAt and the last successful
// refresh, against an injectable clock; it is unavailable in the no-catalog state.
func TestRefresher_StalenessMetadata(t *testing.T) {
	r, _, _ := newSignedSourceRefresher(t)
	fixedNow := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC) // 2 days after the fixture's generated_at
	r.now = func() time.Time { return fixedNow }

	if err := r.Refresh(); err != nil {
		t.Fatal(err)
	}
	catAge, sinceRefresh, ok := r.Staleness()
	if !ok {
		t.Fatal("Staleness ok should be true with a published catalog")
	}
	genAt := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC) // validSource() generated_at
	if want := fixedNow.Sub(genAt); catAge != want {
		t.Fatalf("catalogAge = %v; want %v", catAge, want)
	}
	if sinceRefresh != 0 {
		t.Fatalf("sinceRefresh = %v; want 0 (refresh happened at fixedNow)", sinceRefresh)
	}

	// No-catalog state ⇒ staleness unavailable.
	empty := NewRefresher(t.TempDir(), t.TempDir(), r.trust)
	if _, _, ok := empty.Staleness(); ok {
		t.Fatal("Staleness ok should be false in the no-catalog state")
	}
}

// The optional ticker is disabled by default: RunTicker returns immediately when
// no interval is configured (it must not block or refresh).
func TestRefresher_TickerDisabledByDefault(t *testing.T) {
	r, _, _ := newSignedSourceRefresher(t)
	done := make(chan struct{})
	go func() {
		r.RunTicker(context.Background()) // interval == 0 ⇒ immediate return
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunTicker must return immediately when the ticker is disabled")
	}
	if m := r.Meta(); !m.LastAttempt.IsZero() {
		t.Fatal("a disabled ticker must not attempt any refresh")
	}
}
