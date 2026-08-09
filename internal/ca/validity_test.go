package ca

// validity_test.go — CHAOS-28 regression gates for the Root-CA usability guard.
//
// Every test here fails against the pre-fix engine:
//   - signLeaf returned a well-formed leaf for an expired CA (no guard existed);
//   - leaf NotAfter was an unconditional now+24h, so it outlived the issuer;
//   - RotateIfNeeded logged a save failure and returned true regardless.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mkCA builds a self-signed CA with an explicit validity window.
func mkCA(t *testing.T, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return cert, key
}

func TestCAUsable_ValidityWindow(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	cert, _ := mkCA(t, now.Add(-24*time.Hour), now.Add(24*time.Hour))

	cases := []struct {
		name    string
		cert    *x509.Certificate
		at      time.Time
		wantErr bool
	}{
		{"inside window", cert, now, false},
		{"one second before expiry", cert, cert.NotAfter.Add(-time.Second), false},
		{"one second after expiry", cert, cert.NotAfter.Add(time.Second), true},
		{"long expired", cert, cert.NotAfter.Add(365 * 24 * time.Hour), true},
		{"no CA loaded", nil, now, true},
		// Clock rollback: the node's clock is now BEFORE the CA was issued.
		// Inside the tolerance this must stay usable — a peer with a slightly
		// faster clock must not be able to take the gateway down.
		{"rolled back within tolerance", cert, cert.NotBefore.Add(-caClockSkewTolerance + time.Minute), false},
		{"rolled back past tolerance", cert, cert.NotBefore.Add(-caClockSkewTolerance - time.Minute), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := caUsable(tc.cert, tc.at)
			if tc.wantErr {
				if err == nil {
					t.Fatal("caUsable = nil, want an error")
				}
				if !errors.Is(err, ErrCAUnusable) {
					t.Fatalf("caUsable error %v does not wrap ErrCAUnusable", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("caUsable = %v, want nil", err)
			}
		})
	}
}

// TestSignLeaf_RefusesExpiredCA is the core regression gate. Pre-fix, an expired
// Root CA still produced a leaf — x509.CreateCertificate never checks the
// parent's validity — so the engine handed clients certificates that every one
// of them rejects, silently, forever.
func TestSignLeaf_RefusesExpiredCA(t *testing.T) {
	cm := New()
	cert, key := mkCA(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	cm.SetCAForTest(cert, key)

	// Guard the publish-once observer so the assertion is deterministic under
	// -shuffle: package main is not linked here, so the hook starts nil.
	var seen []string
	UnusableObserver = func(reason string) { seen = append(seen, reason) }
	t.Cleanup(func() { UnusableObserver = nil })

	leaf, err := cm.signLeaf("example.com")
	if err == nil {
		t.Fatal("signLeaf succeeded with an EXPIRED Root CA — every client would reject this leaf")
	}
	if leaf != nil {
		t.Fatal("signLeaf returned a certificate alongside its error")
	}
	if !errors.Is(err, ErrCAUnusable) {
		t.Fatalf("signLeaf error %v does not wrap ErrCAUnusable", err)
	}
	if got := cm.SignRefusals(); got != 1 {
		t.Fatalf("SignRefusals = %d, want 1", got)
	}
	if len(seen) != 1 {
		t.Fatalf("UnusableObserver fired %d times, want 1", len(seen))
	}
	if !strings.Contains(seen[0], "expired at") {
		t.Fatalf("observer reason %q does not name the violated bound", seen[0])
	}
}

// TestGetCert_ExpiredCADoesNotServeOrCache proves the refusal reaches the
// tls.Config.GetCertificate callback and that nothing poisons the leaf cache: a
// failed sign must not leave an entry that a later, recovered CA would keep
// serving from.
func TestGetCert_ExpiredCADoesNotServeOrCache(t *testing.T) {
	cm := New()
	cert, key := mkCA(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	cm.SetCAForTest(cert, key)

	if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "example.com"}); err == nil {
		t.Fatal("GetCert served a leaf signed by an expired Root CA")
	}
	if n := cm.CertCacheLen(); n != 0 {
		t.Fatalf("leaf cache holds %d entries after a refused sign, want 0", n)
	}
	if cm.Usable() == nil {
		t.Fatal("Usable() = nil for an expired CA")
	}
}

// TestSignLeaf_ClampsLeafValidityToIssuer pins that a leaf can never outlive its
// issuer. Pre-fix the leaf carried an unconditional now+24h NotAfter, so every
// leaf minted in the CA's final day claimed validity past the CA's own — the
// state that makes an expiry incident hardest to diagnose, because the leaf
// looks fine and only the chain fails.
func TestSignLeaf_ClampsLeafValidityToIssuer(t *testing.T) {
	cm := New()
	// CA expires in one hour — well inside the leaf's natural 24h lifetime.
	caNotAfter := time.Now().Add(time.Hour)
	cert, key := mkCA(t, time.Now().Add(-time.Hour), caNotAfter)
	cm.SetCAForTest(cert, key)

	leaf, err := cm.signLeaf("clamp.example.com")
	if err != nil {
		t.Fatalf("signLeaf: %v", err)
	}
	if leaf.Leaf.NotAfter.After(cert.NotAfter) {
		t.Fatalf("leaf NotAfter %s outlives issuer NotAfter %s", leaf.Leaf.NotAfter, cert.NotAfter)
	}
	if leaf.Leaf.NotBefore.Before(cert.NotBefore) {
		t.Fatalf("leaf NotBefore %s predates issuer NotBefore %s", leaf.Leaf.NotBefore, cert.NotBefore)
	}
	// The clamp must never produce an already-dead leaf.
	if !leaf.Leaf.NotAfter.After(time.Now()) {
		t.Fatalf("clamped leaf NotAfter %s is not in the future", leaf.Leaf.NotAfter)
	}
}

// TestSignLeaf_ClampsNotBeforeUpToFreshIssuer covers the other clamp direction:
// a CA generated seconds ago (rotation just ran) versus the leaf's 5-minute
// backdate. The leaf must start no earlier than its issuer.
func TestSignLeaf_ClampsNotBeforeUpToFreshIssuer(t *testing.T) {
	cm := New()
	cert, key := mkCA(t, time.Now(), time.Now().Add(365*24*time.Hour))
	cm.SetCAForTest(cert, key)

	leaf, err := cm.signLeaf("fresh.example.com")
	if err != nil {
		t.Fatalf("signLeaf: %v", err)
	}
	if leaf.Leaf.NotBefore.Before(cert.NotBefore) {
		t.Fatalf("leaf NotBefore %s predates a freshly-issued CA's NotBefore %s",
			leaf.Leaf.NotBefore, cert.NotBefore)
	}
}

// TestGetCert_CacheOrderDoesNotGrowOnRefresh is the resource-exhaustion gate.
//
// Pre-fix, every TTL-expired re-sign appended the host to cacheOrder again while
// the map entry was overwritten — so the map stayed bounded at 10k, the eviction
// branch (which keys on map length) never fired, and the slice grew by one
// string per refresh, forever. The leak scaled with UPTIME on a perfectly
// ordinary steady-state workload.
func TestGetCert_CacheOrderDoesNotGrowOnRefresh(t *testing.T) {
	cm := New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	const host = "steady.example.com"

	for i := 0; i < 25; i++ {
		if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: host}); err != nil {
			t.Fatalf("GetCert %d: %v", i, err)
		}
		// Force the next call to miss, exactly as the 1h TTL does in production.
		if !cm.AgeCacheEntryForTest(host, time.Now().Add(-2*CacheTTL)) {
			t.Fatal("AgeCacheEntryForTest: entry missing")
		}
	}

	cm.mu.RLock()
	order := len(cm.cacheOrder)
	entries := len(cm.cache)
	cm.mu.RUnlock()
	if entries != 1 {
		t.Fatalf("cache holds %d entries for one host, want 1", entries)
	}
	if order != 1 {
		t.Fatalf("cacheOrder holds %d entries after 25 refreshes of ONE host, want 1 — "+
			"the slice grows per refresh while the map stays bounded, so eviction never reclaims it", order)
	}
}

// TestGetCert_CacheOrderTracksDistinctHosts is the negative control: the
// no-duplicate rule must not stop genuinely new hosts from being tracked, or
// LRU eviction would lose its input.
func TestGetCert_CacheOrderTracksDistinctHosts(t *testing.T) {
	cm := New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: fmt.Sprintf("h%d.example.com", i)}); err != nil {
			t.Fatalf("GetCert %d: %v", i, err)
		}
	}
	cm.mu.RLock()
	order := len(cm.cacheOrder)
	cm.mu.RUnlock()
	if order != 8 {
		t.Fatalf("cacheOrder = %d for 8 distinct hosts, want 8", order)
	}
}

// TestRotateIfNeeded_PersistFailureIsReported is the CA-2 gate: a rotation whose
// bundle write fails is NOT a successful rotation. Pre-fix the failure was
// logged and swallowed, so the operator was told the CA had rotated while the
// replacement existed only in RAM — and the next restart silently rotated to a
// different root again.
func TestRotateIfNeeded_PersistFailureIsReported(t *testing.T) {
	cm := New()
	// Near-expiry CA (inside the 30-day overlap) so rotation triggers.
	cert, key := mkCA(t, time.Now().Add(-24*time.Hour), time.Now().Add(5*24*time.Hour))
	cm.SetCAForTest(cert, key)

	var persistErrs []string
	RotationPersistFailureObserver = func(reason string) { persistErrs = append(persistErrs, reason) }
	t.Cleanup(func() { RotationPersistFailureObserver = nil })

	// A path whose PARENT is a regular file — every write to it fails ENOTDIR.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	badPath := filepath.Join(blocker, "ca.bundle")

	if !cm.RotateIfNeeded(badPath, "passphrase") {
		t.Fatal("near-expiry CA should still rotate in memory")
	}
	if len(persistErrs) != 1 {
		t.Fatalf("RotationPersistFailureObserver fired %d times, want 1 — a swallowed save failure "+
			"reports a rotation that will not survive restart", len(persistErrs))
	}
}

// TestRotateIfNeeded_SuccessfulPersistIsSilent is the negative control: a clean
// rotation must NOT fire the persist-failure observer, or the alert would cry
// wolf on every healthy renewal.
func TestRotateIfNeeded_SuccessfulPersistIsSilent(t *testing.T) {
	cm := New()
	cert, key := mkCA(t, time.Now().Add(-24*time.Hour), time.Now().Add(5*24*time.Hour))
	cm.SetCAForTest(cert, key)

	fired := 0
	RotationPersistFailureObserver = func(string) { fired++ }
	t.Cleanup(func() { RotationPersistFailureObserver = nil })

	if !cm.RotateIfNeeded(filepath.Join(t.TempDir(), "ca.bundle"), "passphrase") {
		t.Fatal("near-expiry CA should rotate")
	}
	if fired != 0 {
		t.Fatalf("persist-failure observer fired %d times on a successful save", fired)
	}
}

// TestRotateIfNeeded_SuccessSignalIsGatedOnPersistence pins the Codex review
// finding: a rotation whose bundle write failed must not fire the SUCCESS
// observer. Package main wires that observer to a "Root CA rotated (dual-CA
// overlap active)" alert and to culvert_ca_rotations_total, so firing it
// alongside the persist-failure signal sends two contradictory pages for one
// event and advances a counter documented as counting successful rotations for
// a CA the next restart will discard.
func TestRotateIfNeeded_SuccessSignalIsGatedOnPersistence(t *testing.T) {
	cm := New()
	cert, key := mkCA(t, time.Now().Add(-24*time.Hour), time.Now().Add(5*24*time.Hour))
	cm.SetCAForTest(cert, key)

	success, failure := 0, 0
	RotationObserver = func(time.Time, time.Time) { success++ }
	RotationPersistFailureObserver = func(string) { failure++ }
	t.Cleanup(func() { RotationObserver = nil; RotationPersistFailureObserver = nil })

	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	if !cm.RotateIfNeeded(filepath.Join(blocker, "ca.bundle"), "passphrase") {
		t.Fatal("rotation should still happen in memory")
	}
	if failure != 1 {
		t.Fatalf("persist-failure observer fired %d times, want 1", failure)
	}
	if success != 0 {
		t.Fatalf("success observer fired %d times for a rotation that did not persist — "+
			"that is a contradictory alert plus a false culvert_ca_rotations_total increment", success)
	}
}

// TestRotateIfNeeded_PersistSuccessIsObserved is the other half: a clean save
// must fire the success-persist observer, because that is the ONLY thing that
// clears the "may be memory-only" warning. Without it the warning latches for
// the life of the process even after the operator fixes the volume.
func TestRotateIfNeeded_PersistSuccessIsObserved(t *testing.T) {
	cm := New()
	cert, key := mkCA(t, time.Now().Add(-24*time.Hour), time.Now().Add(5*24*time.Hour))
	cm.SetCAForTest(cert, key)

	persisted, success := 0, 0
	RotationPersistSuccessObserver = func() { persisted++ }
	RotationObserver = func(time.Time, time.Time) { success++ }
	t.Cleanup(func() { RotationPersistSuccessObserver = nil; RotationObserver = nil })

	if !cm.RotateIfNeeded(filepath.Join(t.TempDir(), "ca.bundle"), "passphrase") {
		t.Fatal("near-expiry CA should rotate")
	}
	if persisted != 1 {
		t.Fatalf("persist-success observer fired %d times on a clean save, want 1", persisted)
	}
	if success != 1 {
		t.Fatalf("success observer fired %d times on a fully successful rotation, want 1", success)
	}
}

// TestRotateIfNeeded_NoBundlePathFiresNeitherPersistObserver: with no bundle
// path configured nothing is written, so there is nothing to be degraded — or
// recovered — about. Firing either observer would invent a state.
func TestRotateIfNeeded_NoBundlePathFiresNeitherPersistObserver(t *testing.T) {
	cm := New()
	cert, key := mkCA(t, time.Now().Add(-24*time.Hour), time.Now().Add(5*24*time.Hour))
	cm.SetCAForTest(cert, key)

	fail, ok, success := 0, 0, 0
	RotationPersistFailureObserver = func(string) { fail++ }
	RotationPersistSuccessObserver = func() { ok++ }
	RotationObserver = func(time.Time, time.Time) { success++ }
	t.Cleanup(func() {
		RotationPersistFailureObserver, RotationPersistSuccessObserver, RotationObserver = nil, nil, nil
	})

	if !cm.RotateIfNeeded("", "") {
		t.Fatal("rotation should happen with no bundle path")
	}
	if fail != 0 || ok != 0 {
		t.Fatalf("persist observers fired (fail=%d ok=%d) with no bundle path configured", fail, ok)
	}
	if success != 1 {
		t.Fatalf("success observer fired %d times, want 1 — no save was attempted, so nothing was withheld", success)
	}
}
