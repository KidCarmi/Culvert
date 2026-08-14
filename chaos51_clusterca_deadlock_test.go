package main

// CHAOS-51 — the cluster CA install path must never hold ca.mu across a call
// that re-enters the cluster CA.
//
// Pre-fix, ImportCA held ca.mu.Lock() while calling onRotate (→ rebuildCPCertPool
// → AllCACertsPEM → ca.mu.RLock) and CurrentConfigSnapshot (→ CACertFingerprint
// → ca.mu.RLock). sync.RWMutex is not reentrant, so both self-deadlocked and left
// the write lock held for the life of the process — a total Control-Plane stall.
//
// The reason this was invisible to the existing suite is important enough to
// restate in code: every prior ImportCA test called the method on a LOCAL
// clusterCA value, while the re-entrant reads go through the globalClusterCA
// package variable — a different mutex. These tests install the object under test
// AS the global and wire onRotate the way controlplane_tls.go does, which is the
// only configuration in which the defect exists.
//
// Each test drives the call on a child goroutine and fails on a timeout rather
// than hanging the whole binary: a regression here would otherwise wedge CI with
// no attributable failure.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// chaos51Deadline bounds every call under test. Generous relative to the work
// (a few file writes) and tiny relative to a deadlock, which is unbounded.
const chaos51Deadline = 20 * time.Second

// newClusterCAPair mints a self-signed ECDSA cluster-CA cert/key PEM pair.
func newClusterCAPair(t *testing.T, cn string, validFor time.Duration) (certPEM, keyPEM []byte, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Culvert"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		parsed
}

// installGlobalClusterCA makes a fresh clusterCA THE process global and wires
// onRotate exactly as controlplane_tls.go does on a running CP, including a
// non-nil cpTLSConfig.cfg so rebuildCPCertPool actually reaches AllCACertsPEM
// (with a nil cfg it returns early and the re-entrancy never happens — which is
// precisely how a less faithful test would miss the defect).
func installGlobalClusterCA(t *testing.T) *clusterCA {
	t.Helper()
	prevCA := globalClusterCA
	cca := &clusterCA{dir: t.TempDir(), onRotate: rebuildCPCertPool}
	globalClusterCA = cca

	cpTLSConfig.mu.Lock()
	prevCfg := cpTLSConfig.cfg
	cpTLSConfig.cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	cpTLSConfig.mu.Unlock()

	t.Cleanup(func() {
		globalClusterCA = prevCA
		// TryLock, not Lock. The pre-fix deadlock left cpTLSConfig.mu held too —
		// rebuildCPCertPool takes it and THEN blocks on ca.mu.RLock, so the CP TLS
		// config mutex is also unrecoverable (every subsequent ClientHello, which
		// goes through getCPTLSConfigForClient, blocks forever as well). A cleanup
		// that used Lock would inherit that and wedge the whole test binary, hiding
		// the reported failure behind a package-level timeout.
		if cpTLSConfig.mu.TryLock() {
			cpTLSConfig.cfg = prevCfg
			cpTLSConfig.mu.Unlock()
			return
		}
		t.Log("cpTLSConfig.mu is held — a rebuild is stuck; leaving the CP TLS config as-is")
	})
	return cca
}

// runBounded executes fn on a child goroutine and fails with `what` if it has
// not returned within chaos51Deadline. A leaked goroutine on failure is
// deliberate: it is deadlocked, so there is nothing to cancel.
func runBounded(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(chaos51Deadline):
		t.Fatalf("DEADLOCK: %s did not return within %s — ca.mu is held across a call that re-enters the cluster CA", what, chaos51Deadline)
	}
}

// TestChaos51_ImportCAOnGlobalDoesNotDeadlock is the primary gate: the manual
// admin import path (POST /api/cluster/ca) and the auto-rotation path both funnel
// through ImportCA on the global.
func TestChaos51_ImportCAOnGlobalDoesNotDeadlock(t *testing.T) {
	cca := installGlobalClusterCA(t)

	// Seed an existing CA so the import is a REPLACEMENT (the dual-CA overlap
	// branch, which is what StartCARotation and the secondary fingerprint need).
	firstCert, firstKey, _ := newClusterCAPair(t, "Culvert Cluster CA (old)", 365*24*time.Hour)
	runBounded(t, "first ImportCA", func() {
		if err := cca.ImportCA(firstCert, firstKey); err != nil {
			t.Errorf("first ImportCA: %v", err)
		}
	})

	nextCert, nextKey, parsed := newClusterCAPair(t, "Culvert Cluster CA (new)", 10*365*24*time.Hour)
	runBounded(t, "replacement ImportCA", func() {
		if err := cca.ImportCA(nextCert, nextKey); err != nil {
			t.Errorf("replacement ImportCA: %v", err)
		}
	})

	// The lock must be free afterwards, and the new CA actually installed.
	runBounded(t, "CACertFingerprint after import", func() {
		if fp := globalClusterCA.CACertFingerprint(); fp == "" {
			t.Error("cluster CA fingerprint empty after import")
		}
	})
	if !cca.SecondaryActive() {
		t.Error("dual-CA overlap should be active after a replacement import")
	}
	info := cca.Info()
	if info["initialized"] != true {
		t.Errorf("Info() should report an initialised CA: %v", info)
	}
	if got, want := info["expires"], parsed.NotAfter.Format(time.RFC3339); got != want {
		t.Errorf("Info() expires = %v, want the newly imported CA %v", got, want)
	}
	if info["dualCAActive"] != true {
		t.Error("Info() should report the dual-CA overlap after a replacement import")
	}
}

// TestChaos51_FirstImportWithNoPriorCADoesNotPanic covers the other defect on the
// same lines: the old code dereferenced ca.secondaryCert unconditionally, but the
// secondary is only set when a previous CA existed. A first import on a node whose
// cluster CA was never initialised nil-panicked.
func TestChaos51_FirstImportWithNoPriorCADoesNotPanic(t *testing.T) {
	cca := installGlobalClusterCA(t)
	certPEM, keyPEM, _ := newClusterCAPair(t, "Culvert Cluster CA", 10*365*24*time.Hour)

	runBounded(t, "first ImportCA with no prior CA", func() {
		defer func() {
			if v := recover(); v != nil {
				t.Errorf("PANIC on first import (nil secondaryCert): %v", v)
			}
		}()
		if err := cca.ImportCA(certPEM, keyPEM); err != nil {
			t.Errorf("ImportCA: %v", err)
		}
	})
	if cca.SecondaryActive() {
		t.Error("a first import has nothing to overlap with — secondary must stay unset")
	}
}

// TestChaos51_CleanupSecondaryDoesNotDeadlock covers the unattended half: this one
// is driven by the 24h auto-rotation loop, with no operator present to notice the
// gateway stopped answering.
func TestChaos51_CleanupSecondaryDoesNotDeadlock(t *testing.T) {
	cca := installGlobalClusterCA(t)

	certPEM, _, cert := newClusterCAPair(t, "Culvert Cluster CA", 10*365*24*time.Hour)
	expiredPEM, _, expired := newClusterCAPair(t, "Culvert Cluster CA (old)", time.Hour)

	cca.mu.Lock()
	cca.cert = cert
	cca.certPEM = certPEM
	cca.secondaryCert = expired
	cca.secondaryPEM = expiredPEM
	cca.secondaryExp = time.Now().Add(-time.Minute) // overlap window already over
	cca.mu.Unlock()

	runBounded(t, "CleanupSecondary", cca.CleanupSecondary)

	if cca.SecondaryActive() {
		t.Error("expired secondary should have been removed")
	}
	runBounded(t, "AllCACertsPEM after cleanup", func() {
		if len(globalClusterCA.AllCACertsPEM()) == 0 {
			t.Error("primary CA PEM should still be served after cleanup")
		}
	})
}

// TestChaos51_CleanupSecondaryNoOpWhenOverlapLive proves the restructured
// CleanupSecondary kept its guard: an overlap that has NOT expired is untouched
// and fires no rebuild.
func TestChaos51_CleanupSecondaryNoOpWhenOverlapLive(t *testing.T) {
	cca := installGlobalClusterCA(t)

	certPEM, _, cert := newClusterCAPair(t, "Culvert Cluster CA", 10*365*24*time.Hour)
	oldPEM, _, old := newClusterCAPair(t, "Culvert Cluster CA (old)", 48*time.Hour)

	cca.mu.Lock()
	cca.cert = cert
	cca.certPEM = certPEM
	cca.secondaryCert = old
	cca.secondaryPEM = oldPEM
	cca.secondaryExp = time.Now().Add(24 * time.Hour) // still overlapping
	cca.mu.Unlock()

	runBounded(t, "CleanupSecondary (live overlap)", cca.CleanupSecondary)

	if !cca.SecondaryActive() {
		t.Error("a live overlap must not be cleaned up")
	}
}

// TestChaos51_ConcurrentReadersProgressDuringImport is the blast-radius assertion.
// The pre-fix failure was not merely "the caller hangs" — it left ca.mu write-held
// forever, so every reader of the cluster CA blocked too: CACertFingerprint (and
// therefore every CP→DP ConfigSnapshot), Ready, Info, AllCACertsPEM.
func TestChaos51_ConcurrentReadersProgressDuringImport(t *testing.T) {
	cca := installGlobalClusterCA(t)
	firstCert, firstKey, _ := newClusterCAPair(t, "Culvert Cluster CA", 365*24*time.Hour)
	runBounded(t, "seed ImportCA", func() {
		if err := cca.ImportCA(firstCert, firstKey); err != nil {
			t.Errorf("seed ImportCA: %v", err)
		}
	})

	nextCert, nextKey, _ := newClusterCAPair(t, "Culvert Cluster CA (new)", 10*365*24*time.Hour)
	runBounded(t, "import then read", func() {
		if err := cca.ImportCA(nextCert, nextKey); err != nil {
			t.Errorf("ImportCA: %v", err)
		}
		// Any of these blocking forever is the pre-fix symptom.
		_ = globalClusterCA.CACertFingerprint()
		_ = globalClusterCA.Ready()
		_ = globalClusterCA.AllCACertsPEM()
		_ = globalClusterCA.Info()
	})
}
