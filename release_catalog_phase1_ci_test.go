package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Phase 1 CI gate: through the PRODUCTION enforce-mode holder (signature trust +
// freshness + rollback), every untrusted/stale/replayed catalog FAILS CLOSED —
// the holder returns the matching error kind and publishes NOTHING. This is the
// regression wall behind the "unsigned official catalogs are never accepted"
// invariant and the freshness/rollback additions.

// enforceHolder builds an enforce-mode holder over dir that trusts trustPub and
// enforces freshness/rollback at the fixed instant `now`, persisting the version
// floor under statePath.
func enforceHolder(t *testing.T, dir string, trustPub ed25519.PublicKey, now time.Time, statePath string) *CatalogHolder {
	t.Helper()
	ts, err := NewTrustStore([]TrustKey{{KeyID: holderTestKeyID, Alg: catalogSigAlg, PublicKey: trustPub}}, VerifyEnforce)
	if err != nil {
		t.Fatal(err)
	}
	return NewCatalogHolder(dir, ts, WithFreshnessEnforcement(func() time.Time { return now }, catalogClockSkew, statePath))
}

const ciFixedNow = "2026-05-01T00:00:00Z" // after freshValidSource generated_at

func TestPhase1CI_EnforceHappyPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	writeSignedCatalogDir(t, dir, priv, freshValidSource("2099-01-01T00:00:00Z", 1))
	h := enforceHolder(t, dir, pub, mustTime(t, ciFixedNow), filepath.Join(t.TempDir(), "s.json"))
	if err := h.Reload(); err != nil {
		t.Fatalf("a valid signed+fresh catalog must load under enforce: %v", err)
	}
	if !h.HasCatalog() {
		t.Fatal("happy path must publish a catalog")
	}
}

func TestPhase1CI_FailClosedMatrix(t *testing.T) {
	now := mustTime(t, ciFixedNow)

	cases := []struct {
		name    string
		setup   func(t *testing.T, dir string, signPriv ed25519.PrivateKey) // materialize the catalog dir
		trusted func(signPub ed25519.PublicKey) ed25519.PublicKey           // which key the holder trusts
		wantErr error
	}{
		{
			name: "unsigned: no signature file (enforce rejects)",
			setup: func(t *testing.T, dir string, priv ed25519.PrivateKey) {
				writeSignedCatalogDir(t, dir, priv, freshValidSource("2099-01-01T00:00:00Z", 1))
				if err := os.Remove(filepath.Join(dir, "index.json.sig")); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: errSigMissing,
		},
		{
			name: "sig-stripped/tampered: index altered after signing",
			setup: func(t *testing.T, dir string, priv ed25519.PrivateKey) {
				ms := freshValidSource("2099-01-01T00:00:00Z", 1)
				writeSignedCatalogDir(t, dir, priv, ms)
				tampered := append(append([]byte(nil), ms.index...), ' ')
				if err := os.WriteFile(filepath.Join(dir, "index.json"), tampered, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: errSigVerify,
		},
		{
			// The envelope's key_id ("k1") is trusted, but the signature was made
			// by a DIFFERENT private key, so verification fails — a forged catalog
			// claiming a trusted key_id cannot pass.
			name: "wrong key: trusted key_id but signature from another key",
			setup: func(t *testing.T, dir string, _ ed25519.PrivateKey) {
				_, otherPriv, _ := ed25519.GenerateKey(nil)
				writeSignedCatalogDir(t, dir, otherPriv, freshValidSource("2099-01-01T00:00:00Z", 1))
			},
			wantErr: errSigVerify,
		},
		{
			name: "expired: signed but past expires_at + skew",
			setup: func(t *testing.T, dir string, priv ed25519.PrivateKey) {
				writeSignedCatalogDir(t, dir, priv, freshValidSource("2026-04-19T00:00:00Z", 1)) // before now
			},
			wantErr: errCatalogExpired,
		},
		{
			name: "missing expires_at: signed but no freshness floor",
			setup: func(t *testing.T, dir string, priv ed25519.PrivateKey) {
				writeSignedCatalogDir(t, dir, priv, freshValidSource("", 1)) // no expires_at
			},
			wantErr: errCatalogExpiryMissing,
		},
		{
			name: "missing catalog_version: signed+fresh but no rollback counter",
			setup: func(t *testing.T, dir string, priv ed25519.PrivateKey) {
				writeSignedCatalogDir(t, dir, priv, freshValidSource("2099-01-01T00:00:00Z", 0)) // no catalog_version
			},
			wantErr: errCatalogVersionMissing,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, _ := ed25519.GenerateKey(nil)
			dir := t.TempDir()
			tc.setup(t, dir, priv)
			h := enforceHolder(t, dir, pub, now, filepath.Join(t.TempDir(), "s.json"))
			err := h.Reload()
			if err == nil {
				t.Fatalf("%s: Reload must fail closed; got a published catalog", tc.name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s: err = %v; want errors.Is(%v)", tc.name, err, tc.wantErr)
			}
			if h.HasCatalog() {
				t.Fatalf("%s: nothing may be published on a fail-closed reload", tc.name)
			}
		})
	}
}

// A captured older signed catalog (lower catalog_version) is refused after a
// newer one has been accepted — through the real holder + persisted floor.
func TestPhase1CI_RollbackReplayRefused(t *testing.T) {
	now := mustTime(t, ciFixedNow)
	statePath := filepath.Join(t.TempDir(), "state.json")
	pub, priv, _ := ed25519.GenerateKey(nil)

	// Accept v5.
	dirNew := t.TempDir()
	writeSignedCatalogDir(t, dirNew, priv, freshValidSource("2099-01-01T00:00:00Z", 5))
	if err := enforceHolder(t, dirNew, pub, now, statePath).Reload(); err != nil {
		t.Fatalf("accept v5: %v", err)
	}

	// A separately-served, validly-signed v4 (replay/downgrade) is refused, even
	// though its signature and freshness are perfectly valid.
	dirOld := t.TempDir()
	writeSignedCatalogDir(t, dirOld, priv, freshValidSource("2099-01-01T00:00:00Z", 4))
	h := enforceHolder(t, dirOld, pub, now, statePath)
	err := h.Reload()
	if !errors.Is(err, errCatalogRollback) {
		t.Fatalf("downgrade replay: err = %v; want errCatalogRollback", err)
	}
	if h.HasCatalog() {
		t.Fatal("a refused rollback must publish nothing")
	}
}
