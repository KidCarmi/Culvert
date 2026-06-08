package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// holderTestKeyID is the fixed key_id used across the holder fixtures.
const holderTestKeyID = "k1"

// writeSignedCatalogDir materializes a memSource's index + manifests on disk and
// signs the exact index bytes with priv (under holderTestKeyID), producing a
// directory that LoadVerifiedCatalog (via dirCatalogSource) can load.
func writeSignedCatalogDir(t *testing.T, dir string, priv ed25519.PrivateKey, ms *memSource) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "manifests"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), ms.index, 0o600); err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, ms.index)
	if err := os.WriteFile(filepath.Join(dir, "index.json.sig"), sigEnvelopeBytes(t, catalogSigAlg, holderTestKeyID, sig), 0o600); err != nil {
		t.Fatal(err)
	}
	for ref, b := range ms.manifests {
		if err := os.WriteFile(filepath.Join(dir, "manifests", ref), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// holderTrust returns an enforce-mode TrustStore trusting pub under holderTestKeyID.
func holderTrust(t *testing.T, pub ed25519.PublicKey) TrustStore {
	t.Helper()
	ts, err := NewTrustStore([]TrustKey{{KeyID: holderTestKeyID, Alg: catalogSigAlg, PublicKey: pub}}, VerifyEnforce)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// ─── tests ───────────────────────────────────────────────────────────────────

// Before any successful reload the holder is in the explicit no-catalog state.
func TestHolder_NoCatalogState(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewCatalogHolder(t.TempDir(), holderTrust(t, pub))
	if h.GetCatalog() != nil {
		t.Fatal("GetCatalog must be nil before any reload (no-catalog state)")
	}
	if h.HasCatalog() {
		t.Fatal("HasCatalog must be false in the no-catalog state")
	}
	// An empty dir cannot be loaded → Reload errors and the holder stays empty.
	if err := h.Reload(); err == nil {
		t.Fatal("Reload on an empty dir should error")
	}
	if h.GetCatalog() != nil {
		t.Fatal("a failed reload must not publish a catalog")
	}
}

// A valid signed dir loads, verifies, and publishes.
func TestHolder_SuccessfulVerifiedPublish(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeSignedCatalogDir(t, dir, priv, validSource())
	h := NewCatalogHolder(dir, holderTrust(t, pub))
	if err := h.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	c := h.GetCatalog()
	if c == nil || len(c.byReleaseID) != 2 {
		t.Fatalf("expected a published 2-release catalog; got %+v", c)
	}
	if !h.HasCatalog() {
		t.Fatal("HasCatalog must be true after a successful publish")
	}
}

// A failed reload (here: the on-disk index tampered after signing) returns an
// error and leaves the previously-published catalog live and unchanged.
func TestHolder_FailedReloadKeepsCurrent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeSignedCatalogDir(t, dir, priv, validSource())
	h := NewCatalogHolder(dir, holderTrust(t, pub))
	if err := h.Reload(); err != nil {
		t.Fatal(err)
	}
	prev := h.GetCatalog()
	if prev == nil {
		t.Fatal("precondition: a catalog must be published")
	}

	// Corrupt the index on disk so its signature no longer matches.
	idxPath := filepath.Join(dir, "index.json")
	b, err := os.ReadFile(idxPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idxPath, append(b, ' '), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := h.Reload(); err == nil {
		t.Fatal("reload of a tampered index must fail")
	}
	if h.GetCatalog() != prev {
		t.Fatal("a failed reload must keep the exact previous catalog (pointer unchanged)")
	}
}

// Re-verification gates every publish: a catalog signed by a key NOT in the
// trust ring is rejected and nothing is published.
func TestHolder_ReVerifiesBeforePublish(t *testing.T) {
	_, signingPriv, err := ed25519.GenerateKey(nil) // signs the catalog
	if err != nil {
		t.Fatal(err)
	}
	trustedPub, _, err := ed25519.GenerateKey(nil) // a DIFFERENT key the holder trusts
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeSignedCatalogDir(t, dir, signingPriv, validSource()) // signed by the untrusted key
	h := NewCatalogHolder(dir, holderTrust(t, trustedPub))

	if err := h.Reload(); err == nil {
		t.Fatal("reload must reject a catalog signed by an untrusted key")
	}
	if h.GetCatalog() != nil {
		t.Fatal("nothing may be published when verification fails")
	}
}

// Concurrent readers always observe a COMPLETE catalog (old or new) or nil —
// never a partially-built one — while the writer reloads, alternating between a
// 2-release and a 1-release catalog. Run under -race.
func TestHolder_ConcurrentReadersNeverPartial(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()

	msA := validSource()       // 2 releases (a.json 1.10.0, b.json 1.9.0)
	msB := buildCatalogSource( // 1 release (c.json)
		map[string]string{"recommended": "rel_c"}, 1, "2026-04-18T00:00:00Z",
		[]relSpec{{ref: "c.json", releaseID: "rel_c", versionID: "2.0.0", raw: manifestJSON("rel_c", "2.0.0", "normal", repo, digA)}},
	)

	writeSignedCatalogDir(t, dir, priv, msA)
	h := NewCatalogHolder(dir, holderTrust(t, pub))
	if err := h.Reload(); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if c := h.GetCatalog(); c != nil {
					if n := len(c.byReleaseID); n != 1 && n != 2 {
						t.Errorf("partial catalog observed: byReleaseID=%d (want 1 or 2)", n)
						return
					}
				}
			}
		}()
	}

	for i := 0; i < 150; i++ {
		if i%2 == 0 {
			writeSignedCatalogDir(t, dir, priv, msB)
		} else {
			writeSignedCatalogDir(t, dir, priv, msA)
		}
		if err := h.Reload(); err != nil {
			t.Errorf("reload %d: %v", i, err)
			break
		}
	}
	close(stop)
	wg.Wait()

	if !h.HasCatalog() {
		t.Fatal("a catalog must remain published after the reload loop")
	}
}
