package main

// cluster_ca_chaos_test.go — CHAOS-50 (register row CA-13) regression gates for
// the cluster CA: the enrollment trust root.
//
// Every test here corresponds to a defect that was reproduced against the
// pre-fix engine. The deadlock gates in particular are the reason this file
// exists at all: the pre-fix suite exercised ImportCA only on LOCAL clusterCA
// instances, while the deadlock was caused by side effects that re-enter the
// process-global singleton. The production path was, in effect, untested.
// Tests here therefore drive globalClusterCA deliberately.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// chaos50CA builds a cluster-CA-shaped self-signed cert/key pair with an
// explicit validity window.
func chaos50CA(t *testing.T, notBefore, notAfter time.Time) (certPEM, keyPEM []byte, key *ecdsa.PrivateKey, cert *x509.Certificate) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Culvert Cluster CA", Organization: []string{"Culvert"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), k, parsed
}

func chaos50CSR(t *testing.T, cn string) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// useGlobalClusterCA swaps in a fresh singleton bound to a temp dir and
// restores the original, so a test that drives the production path cannot leak
// state (or a held lock) into the rest of the binary.
func useGlobalClusterCA(t *testing.T) {
	t.Helper()
	orig := globalClusterCA
	t.Cleanup(func() { globalClusterCA = orig })
	globalClusterCA = &clusterCA{}
	if err := globalClusterCA.InitOrLoad(t.TempDir()); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
}

// quietClusterCAAlerts isolates the process-global health record and captures
// alert payloads synchronously.
func quietClusterCAAlerts(t *testing.T) *[]string {
	t.Helper()
	origFire := fireClusterCAAlert
	var mu sync.Mutex
	var got []string
	fireClusterCAAlert = func(detail string) {
		mu.Lock()
		got = append(got, detail)
		mu.Unlock()
	}
	resetClusterCAHealthForTest()
	t.Cleanup(func() {
		fireClusterCAAlert = origFire
		resetClusterCAHealthForTest()
	})
	return &got
}

// ── FS-1: the self-deadlock ─────────────────────────────────────────────────

// TestChaos50_ImportCADoesNotDeadlock drives the PRODUCTION singleton. Pre-fix
// this never returned: ImportCA held ca.mu for writing while
// CurrentConfigSnapshot re-entered CACertFingerprint for reading.
func TestChaos50_ImportCADoesNotDeadlock(t *testing.T) {
	useGlobalClusterCA(t)
	quietClusterCAAlerts(t)

	certPEM, keyPEM, _, _ := chaos50CA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	done := make(chan error, 1)
	go func() { done <- globalClusterCA.ImportCA(certPEM, keyPEM) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ImportCA: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("ImportCA deadlocked: the post-install side effects must run with ca.mu released")
	}
}

// TestChaos50_ImportCADoesNotFreezeReaders is the blast-radius half. The
// pre-fix deadlock hung while HOLDING the write lock, so every reader —
// enrollment (SignCSR), the DP config poll (CACertFingerprint), and the admin
// API (Info) — blocked for the life of the process.
func TestChaos50_ImportCADoesNotFreezeReaders(t *testing.T) {
	useGlobalClusterCA(t)
	quietClusterCAAlerts(t)

	certPEM, keyPEM, _, _ := chaos50CA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	imported := make(chan error, 1)
	go func() { imported <- globalClusterCA.ImportCA(certPEM, keyPEM) }()

	readers := make(chan string, 3)
	go func() {
		_, _, _, err := globalClusterCA.SignCSR(chaos50CSR(t, "node-1"), "node-1")
		if err != nil {
			readers <- "SignCSR: " + err.Error()
			return
		}
		readers <- ""
	}()
	go func() { _ = globalClusterCA.CACertFingerprint(); readers <- "" }()
	go func() { _ = globalClusterCA.Info(); readers <- "" }()

	deadline := time.After(20 * time.Second)
	for i := 0; i < 3; i++ {
		select {
		case msg := <-readers:
			if msg != "" {
				t.Fatalf("reader failed: %s", msg)
			}
		case <-deadline:
			t.Fatal("cluster CA readers blocked behind ImportCA — enrollment and config sync would be frozen")
		}
	}
	if err := <-imported; err != nil {
		t.Fatalf("ImportCA: %v", err)
	}
}

// TestChaos50_CleanupSecondaryDoesNotDeadlock covers the delayed twin: the same
// re-entrant callback, reached 30 days after a rotation when the overlap ends.
// The onRotate installed here reproduces what rebuildCPCertPool does — read the
// CA back through AllCACertsPEM.
func TestChaos50_CleanupSecondaryDoesNotDeadlock(t *testing.T) {
	useGlobalClusterCA(t)

	// An already-expired secondary, so CleanupSecondary takes the removal path.
	_, _, _, oldCert := chaos50CA(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	globalClusterCA.mu.Lock()
	globalClusterCA.secondaryCert = oldCert
	globalClusterCA.secondaryPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: oldCert.Raw})
	globalClusterCA.secondaryExp = oldCert.NotAfter
	globalClusterCA.onRotate = func() {
		// Exactly the re-entrancy rebuildCPCertPool performs.
		_ = globalClusterCA.AllCACertsPEM()
	}
	globalClusterCA.mu.Unlock()

	done := make(chan struct{})
	go func() { globalClusterCA.CleanupSecondary(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("CleanupSecondary deadlocked against its own onRotate callback")
	}
}

// ── FS-2: an expired CA must not issue certificates ─────────────────────────

// TestChaos50_ExpiredClusterCARefusesToSign pins the fail-closed posture. An
// expired CA used to sign happily; the node then failed every mTLS handshake
// with nothing on the CP side to explain it.
func TestChaos50_ExpiredClusterCARefusesToSign(t *testing.T) {
	alerts := quietClusterCAAlerts(t)

	certPEM, _, key, cert := chaos50CA(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	ca := &clusterCA{cert: cert, key: key, certPEM: certPEM, dir: t.TempDir()}

	if err := ca.Usable(); err == nil {
		t.Fatal("Usable() reported an expired CA as usable")
	}
	_, _, _, err := ca.SignCSR(chaos50CSR(t, "node-1"), "node-1")
	if err == nil {
		t.Fatal("expired cluster CA signed a node certificate — every mTLS peer would reject it")
	}
	if !errors.Is(err, errClusterCAUnusable) {
		t.Fatalf("want errClusterCAUnusable, got %v", err)
	}
	if got := statClusterCASignRefused.Load(); got != 1 {
		t.Errorf("sign refusals = %d, want 1", got)
	}
	degraded, reason, _ := clusterCADegraded()
	if !degraded || reason == "" {
		t.Errorf("refusal did not mark the cluster CA degraded (reason=%q)", reason)
	}
	if len(*alerts) != 1 {
		t.Errorf("alerts fired = %d, want 1", len(*alerts))
	}
}

// TestChaos50_NotYetValidCAToleratesClockSkew is the other end of the window: a
// CA generated seconds ago on a peer with a slightly fast clock must not brick
// enrollment. Beyond the tolerance it is refused.
func TestChaos50_NotYetValidCAToleratesClockSkew(t *testing.T) {
	quietClusterCAAlerts(t)

	certPEM, _, key, cert := chaos50CA(t, time.Now().Add(2*time.Minute), time.Now().Add(365*24*time.Hour))
	ca := &clusterCA{cert: cert, key: key, certPEM: certPEM, dir: t.TempDir()}
	if err := ca.Usable(); err != nil {
		t.Fatalf("a CA 2 min in the future must be tolerated (skew window is %v): %v", clusterCAClockSkewTolerance, err)
	}

	certPEM2, _, key2, cert2 := chaos50CA(t, time.Now().Add(time.Hour), time.Now().Add(365*24*time.Hour))
	ca2 := &clusterCA{cert: cert2, key: key2, certPEM: certPEM2, dir: t.TempDir()}
	if err := ca2.Usable(); err == nil {
		t.Fatal("a CA 1 h in the future must be refused")
	}
}

// ── FS-3: node certs must not outlive their issuer ──────────────────────────

// TestChaos50_NodeCertClampedToCAWindow pins the clamp. Unclamped, a CA with 10
// days left issued 1-year node certs, so the DP renewal loop (which fires at 30
// days remaining on the NODE cert) slept straight through the CA expiry.
func TestChaos50_NodeCertClampedToCAWindow(t *testing.T) {
	quietClusterCAAlerts(t)

	certPEM, _, key, cert := chaos50CA(t, time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour))
	ca := &clusterCA{cert: cert, key: key, certPEM: certPEM, dir: t.TempDir()}

	nodeCertPEM, _, expiry, err := ca.SignCSR(chaos50CSR(t, "node-1"), "node-1")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	blk, _ := pem.Decode(nodeCertPEM)
	nc, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if nc.NotAfter.After(cert.NotAfter) {
		t.Errorf("node cert NotAfter=%s outlives CA NotAfter=%s", nc.NotAfter, cert.NotAfter)
	}
	if nc.NotBefore.Before(cert.NotBefore) {
		t.Errorf("node cert NotBefore=%s precedes CA NotBefore=%s", nc.NotBefore, cert.NotBefore)
	}
	if !expiry.Equal(nc.NotAfter) {
		t.Errorf("returned expiry %s disagrees with the issued cert %s", expiry, nc.NotAfter)
	}

	// It must still verify against its own issuer — the clamp cannot be a
	// cure that breaks the ordinary case.
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if _, err := nc.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("clamped node cert does not verify: %v", err)
	}
}

// TestChaos50_HealthyCAStillIssuesFullYear guards against the clamp silently
// shortening certificates on a healthy cluster.
func TestChaos50_HealthyCAStillIssuesFullYear(t *testing.T) {
	quietClusterCAAlerts(t)

	certPEM, _, key, cert := chaos50CA(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	ca := &clusterCA{cert: cert, key: key, certPEM: certPEM, dir: t.TempDir()}

	nodeCertPEM, _, _, err := ca.SignCSR(chaos50CSR(t, "node-1"), "node-1")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	blk, _ := pem.Decode(nodeCertPEM)
	nc, _ := x509.ParseCertificate(blk.Bytes)
	if days := time.Until(nc.NotAfter).Hours() / 24; days < 364 {
		t.Errorf("node cert on a healthy CA lasts %.0f days, want ~365", days)
	}
}

// ── FS-4 / FS-5: partial-failure state ──────────────────────────────────────

// TestChaos50_ImportCAOnUninitializedDoesNotPanic covers the first install: no
// current CA meant no secondary, and the rotation-tracking call dereferenced
// it. Reachable whenever InitOrLoad failed closed and the operator uploads a CA
// through the admin API to recover.
func TestChaos50_ImportCAOnUninitializedDoesNotPanic(t *testing.T) {
	quietClusterCAAlerts(t)

	orig := globalClusterCA
	t.Cleanup(func() { globalClusterCA = orig })
	globalClusterCA = &clusterCA{dir: t.TempDir()}

	certPEM, keyPEM, _, _ := chaos50CA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if err := globalClusterCA.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("first ImportCA: %v", err)
	}
	if !globalClusterCA.Ready() {
		t.Fatal("CA not installed after first import")
	}
	if globalClusterCA.SecondaryActive() {
		t.Error("a first install must not report a dual-CA overlap")
	}
}

// TestChaos50_FailedPersistLeavesCAUnchanged pins the ordering: durable write
// first, in-memory swap second. Pre-fix the old CA was promoted to secondary
// BEFORE the write, so a failed write left a live CA listed as its own
// secondary — a dual-CA state that never existed.
func TestChaos50_FailedPersistLeavesCAUnchanged(t *testing.T) {
	quietClusterCAAlerts(t)

	certPEM, _, key, cert := chaos50CA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	ca := &clusterCA{cert: cert, key: key, certPEM: certPEM, dir: "/proc/culvert-chaos50-nonexistent"}

	newCertPEM, newKeyPEM, _, _ := chaos50CA(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	if err := ca.ImportCA(newCertPEM, newKeyPEM); err == nil {
		t.Fatal("ImportCA must fail when the CA directory is not writable")
	}

	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.cert != cert {
		t.Error("a failed persist replaced the in-memory CA")
	}
	if ca.secondaryCert != nil {
		t.Error("a failed persist left a phantom secondary CA")
	}
}

// TestChaos50_RotationFailureIsCountedAlertedAndRecovers is the CA-13 core:
// a stuck auto-rotation must be visible before the CA expires, and the degraded
// state must clear on EVIDENCE (a rotation that actually installed a CA).
func TestChaos50_RotationFailureIsCountedAlertedAndRecovers(t *testing.T) {
	alerts := quietClusterCAAlerts(t)
	useGlobalClusterCA(t)

	// A CA inside the 30-day rotation window, with an unwritable directory.
	certPEM, _, key, cert := chaos50CA(t, time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour))
	globalClusterCA.mu.Lock()
	globalClusterCA.cert = cert
	globalClusterCA.key = key
	globalClusterCA.certPEM = certPEM
	goodDir := globalClusterCA.dir
	globalClusterCA.dir = "/proc/culvert-chaos50-nonexistent"
	globalClusterCA.mu.Unlock()

	globalClusterCA.RotateIfNeeded()

	if got := statClusterCARotationFailures.Load(); got != 1 {
		t.Fatalf("rotation failures = %d, want 1", got)
	}
	if len(*alerts) != 1 {
		t.Errorf("alerts fired = %d, want 1", len(*alerts))
	}
	if degraded, _, _ := clusterCADegraded(); !degraded {
		t.Error("a failed rotation must mark the cluster CA degraded")
	}
	if info := globalClusterCA.Info(); info["lastRotationError"] == nil {
		t.Error("Info() lost the rotation error")
	}

	// Operator fixes the volume; the next rotation succeeds and clears the state.
	globalClusterCA.mu.Lock()
	globalClusterCA.dir = goodDir
	globalClusterCA.mu.Unlock()
	globalClusterCA.RotateIfNeeded()

	if degraded, _, _ := clusterCADegraded(); degraded {
		t.Error("degraded state must clear once a rotation succeeds")
	}
	if info := globalClusterCA.Info(); info["lastRotationError"] != nil {
		t.Error("Info() still reports a rotation error after a successful rotation")
	}
}

// TestChaos50_MetricsExposeClusterCAHealth pins the scrapeable surface. Before
// this, culvert_cluster_ca_rotations_total counted only successes — a CP that
// could no longer renew its own trust root moved nothing at all.
func TestChaos50_MetricsExposeClusterCAHealth(t *testing.T) {
	quietClusterCAAlerts(t)
	useGlobalClusterCA(t)

	var sb strings.Builder
	clusterCAWritePrometheus(&sb)
	out := sb.String()
	for _, want := range []string{
		"culvert_cluster_ca_rotation_failures_total",
		"culvert_cluster_ca_sign_refused_total",
		"culvert_cluster_ca_usable 1",
		"culvert_cluster_ca_expires_in_seconds",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}

	// A node with no cluster CA must not emit a usable=0 gauge that would page
	// an operator for a CA it is not supposed to have.
	orig := globalClusterCA
	globalClusterCA = &clusterCA{}
	var empty strings.Builder
	clusterCAWritePrometheus(&empty)
	globalClusterCA = orig
	if strings.Contains(empty.String(), "culvert_cluster_ca_usable") {
		t.Error("cluster_ca_usable emitted on a node with no cluster CA")
	}
}

// TestChaos50_ConcurrentImportsAreSerialized checks importMu still gives the
// side effects a stable order while readers stay unblocked.
func TestChaos50_ConcurrentImportsAreSerialized(t *testing.T) {
	quietClusterCAAlerts(t)
	useGlobalClusterCA(t)

	// Bind the singleton once: the goroutines below must not read the package
	// variable itself, which the cleanup hook restores.
	ca := globalClusterCA

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		certPEM, keyPEM, _, _ := chaos50CA(t, time.Now().Add(-time.Hour), time.Now().Add(time.Duration(365+i)*24*time.Hour))
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ca.ImportCA(certPEM, keyPEM); err != nil {
				t.Errorf("ImportCA: %v", err)
			}
		}()
	}
	// Readers hammer the CA throughout.
	stop := make(chan struct{})
	readersDone := make(chan struct{})
	go func() {
		defer close(readersDone)
		for {
			select {
			case <-stop:
				return
			default:
				_ = ca.CACertFingerprint()
				_ = ca.AllCACertsPEM()
			}
		}
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent imports did not complete")
	}
	close(stop)
	<-readersDone

	if !ca.Ready() {
		t.Fatal("cluster CA not ready after concurrent imports")
	}
	if err := ca.Usable(); err != nil {
		t.Fatalf("cluster CA unusable after concurrent imports: %v", err)
	}
}
