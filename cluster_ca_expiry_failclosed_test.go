package main

// cluster_ca_expiry_failclosed_test.go — CHAOS-29 gates (register row CA-13).
//
// Every gate here was executed against the pre-fix code and observed to FAIL.
// The two that matter most:
//
//	TestSignCSR_RefusesExpiredClusterCA          — pre-fix: signed, err = <nil>
//	TestSignCSR_ClampsNodeCertValidityToIssuer   — pre-fix: leaf NotAfter was
//	                                               366 days past the issuer's
//	TestImportCA_BootstrapWithNoExistingCA       — pre-fix: nil-pointer PANIC
//
// The negative controls are as load-bearing as the positives: a healthy cluster
// CA must be byte-identically unaffected, and the refusal must not become a
// reason to admit an unauthenticated peer.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ── fixtures ────────────────────────────────────────────────────────────────

// newClusterCAWithWindow builds a cluster CA whose OWN certificate has the
// given validity window, so the expiry paths are reachable without waiting ten
// years. Persisted nowhere: these tests exercise the in-memory sign path.
func newClusterCAWithWindow(t *testing.T, notBefore, notAfter time.Time) *clusterCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(20260812),
		Subject:               pkix.Name{CommonName: "Culvert Cluster CA", Organization: []string{"Culvert"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &clusterCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		dir:     t.TempDir(),
	}
}

// clusterCAPEMPair returns the cert+key PEM of a CA fixture, for ImportCA.
func clusterCAPEMPair(t *testing.T, ca *clusterCA) (certPEM, keyPEM []byte) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return ca.certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func nodeCSR(t *testing.T, nodeID string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: nodeID}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// isolateClusterCA installs a fixture as the process-global cluster CA and
// resets the process-global health record, restoring both afterwards. The health
// record is separate state from the CA, so a test that only swapped the CA would
// leak refusal counts into the next test under -count=2 -shuffle=on — the
// determinism class the CI gate exists to catch.
func isolateClusterCA(t *testing.T, ca *clusterCA) {
	t.Helper()
	prev := globalClusterCA
	globalClusterCA = ca
	resetClusterCAHealthForTest()
	t.Cleanup(func() {
		globalClusterCA = prev
		resetClusterCAHealthForTest()
	})
}

// ── FS-1: the sign path ─────────────────────────────────────────────────────

// TestClusterCAUsable_ValidityWindow pins the pure predicate, including the
// clock-rollback tolerance that keeps an HA CA handover from a slightly-fast
// peer from taking enrollment down.
func TestClusterCAUsable_ValidityWindow(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	ca := newClusterCAWithWindow(t, now.Add(-24*time.Hour), now.Add(24*time.Hour))

	cases := []struct {
		name    string
		cert    *x509.Certificate
		at      time.Time
		wantErr bool
	}{
		{"inside window", ca.cert, now, false},
		{"one second before expiry", ca.cert, ca.cert.NotAfter.Add(-time.Second), false},
		{"one second after expiry", ca.cert, ca.cert.NotAfter.Add(time.Second), true},
		{"long expired", ca.cert, ca.cert.NotAfter.Add(90 * 24 * time.Hour), true},
		{"no CA loaded", nil, now, true},
		{"clock rolled back within tolerance", ca.cert,
			ca.cert.NotBefore.Add(-clusterCAClockSkewTolerance + time.Minute), false},
		{"clock rolled back past tolerance", ca.cert,
			ca.cert.NotBefore.Add(-clusterCAClockSkewTolerance - time.Minute), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := clusterCAUsable(tc.cert, tc.at)
			if (err != nil) != tc.wantErr {
				t.Fatalf("clusterCAUsable = %v, wantErr = %v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrClusterCAUnusable) {
				t.Fatalf("error does not wrap ErrClusterCAUnusable: %v", err)
			}
		})
	}
}

// TestSignCSR_RefusesExpiredClusterCA is THE gate. Pre-fix this signed happily
// and returned a nil error, so the CP reported a successful enrollment while
// handing the node a certificate no peer would ever validate.
func TestSignCSR_RefusesExpiredClusterCA(t *testing.T) {
	ca := newClusterCAWithWindow(t, time.Now().Add(-400*24*time.Hour), time.Now().Add(-24*time.Hour))
	isolateClusterCA(t, ca)

	certPEM, serial, expiry, err := ca.SignCSR(nodeCSR(t, "dp-1"), "dp-1")
	if err == nil {
		t.Fatal("expired cluster CA SIGNED a node certificate — the CP would report a successful enrollment for material no peer can validate")
	}
	if !errors.Is(err, ErrClusterCAUnusable) {
		t.Fatalf("error does not wrap ErrClusterCAUnusable: %v", err)
	}
	if certPEM != nil || serial != "" || !expiry.IsZero() {
		t.Fatalf("refusal returned material: cert=%d serial=%q expiry=%v", len(certPEM), serial, expiry)
	}
	if got := ca.SignRefusals(); got != 1 {
		t.Fatalf("SignRefusals = %d, want 1", got)
	}
	if snap := clusterCAUsabilityFailures(); snap.Refusals != 1 {
		t.Fatalf("health record refusals = %d, want 1", snap.Refusals)
	}
}

// TestSignCSR_RefusesNotYetValidClusterCA covers the other bound — a CA handed
// over by an HA peer whose clock runs far ahead.
func TestSignCSR_RefusesNotYetValidClusterCA(t *testing.T) {
	ca := newClusterCAWithWindow(t, time.Now().Add(2*time.Hour), time.Now().Add(24*time.Hour))
	isolateClusterCA(t, ca)

	if _, _, _, err := ca.SignCSR(nodeCSR(t, "dp-1"), "dp-1"); !errors.Is(err, ErrClusterCAUnusable) {
		t.Fatalf("not-yet-valid cluster CA signed or returned the wrong error: %v", err)
	}
}

// TestSignCSR_HealthyClusterCAIsUnaffected is the negative control: the guard
// must not cost a healthy Control Plane anything.
func TestSignCSR_HealthyClusterCAIsUnaffected(t *testing.T) {
	ca := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	isolateClusterCA(t, ca)

	certPEM, serial, expiry, err := ca.SignCSR(nodeCSR(t, "dp-1"), "dp-1")
	if err != nil {
		t.Fatalf("healthy cluster CA refused to sign: %v", err)
	}
	if len(certPEM) == 0 || serial == "" || expiry.IsZero() {
		t.Fatal("healthy sign returned incomplete material")
	}
	if got := ca.SignRefusals(); got != 0 {
		t.Fatalf("SignRefusals = %d on a healthy CA, want 0", got)
	}
	if snap := clusterCAUsabilityFailures(); snap.Refusals != 0 {
		t.Fatalf("health record moved on a healthy sign: %+v", snap)
	}
	// And the issued cert must actually chain to the CA — the guard must not
	// have changed what a good sign produces.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.certPEM) {
		t.Fatal("could not build verification pool")
	}
	blk, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("issued node cert does not validate against its own CA: %v", err)
	}
}

// TestSignCSR_ClampsNodeCertValidityToIssuer pins the CA-1b analogue. Node certs
// are issued for a fixed year and the CA rotates with 30 days left, so pre-fix
// EVERY cert signed in a CA's final month outlived its issuer — by up to eleven.
func TestSignCSR_ClampsNodeCertValidityToIssuer(t *testing.T) {
	// A CA with 10 days left: the unclamped year-long node cert would run 355
	// days past it.
	ca := newClusterCAWithWindow(t, time.Now().Add(-30*24*time.Hour), time.Now().Add(10*24*time.Hour))
	isolateClusterCA(t, ca)

	certPEM, _, expiry, err := ca.SignCSR(nodeCSR(t, "dp-1"), "dp-1")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if expiry.After(ca.cert.NotAfter) {
		t.Fatalf("returned expiry %s outlives the issuer's %s", expiry, ca.cert.NotAfter)
	}
	blk, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	if leaf.NotAfter.After(ca.cert.NotAfter) {
		t.Fatalf("issued node cert NotAfter %s outlives the cluster CA's %s (by %s)",
			leaf.NotAfter, ca.cert.NotAfter, leaf.NotAfter.Sub(ca.cert.NotAfter))
	}
	if leaf.NotBefore.Before(ca.cert.NotBefore) {
		t.Fatalf("issued node cert NotBefore %s predates the cluster CA's %s",
			leaf.NotBefore, ca.cert.NotBefore)
	}
	// The reported expiry must match the certificate — the DP renewal loop keys
	// on the file, the cluster store keys on the returned value, and the two
	// disagreeing is how a node ends up considered live past its real expiry.
	if !leaf.NotAfter.Equal(expiry) {
		t.Fatalf("returned expiry %s != certificate NotAfter %s", expiry, leaf.NotAfter)
	}
}

// TestClampNodeCertValidity_LeavesRoomyIssuerAlone: the clamp must be a no-op in
// the normal case (a fresh 10-year CA), or it would silently shorten every node
// cert in the fleet.
func TestClampNodeCertValidity_LeavesRoomyIssuerAlone(t *testing.T) {
	ca := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	nb := time.Now().Add(-5 * time.Minute)
	na := time.Now().Add(365 * 24 * time.Hour)
	gotNB, gotNA := clampNodeCertValidity(nb, na, ca.cert)
	if !gotNB.Equal(nb) || !gotNA.Equal(na) {
		t.Fatalf("clamp altered a window that fits inside the issuer: (%s,%s) → (%s,%s)", nb, na, gotNB, gotNA)
	}
	// nil issuer must pass through rather than zero the window.
	gotNB, gotNA = clampNodeCertValidity(nb, na, nil)
	if !gotNB.Equal(nb) || !gotNA.Equal(na) {
		t.Fatal("clamp altered the window when the issuer was nil")
	}
}

// ── FS-2: rotation-failure observability (the recorded CA-13) ───────────────

// TestRecordRotationFailure_IsCountedAndAlerted pins the substance of CA-13: a
// failing auto-rotation must reach a counter and an alert, not only a log line
// and a field on an admin page.
func TestRecordRotationFailure_IsCountedAndAlerted(t *testing.T) {
	ca := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	isolateClusterCA(t, ca)

	// Observe through the delivery seam, NOT by swapping globalAlertStore: the
	// producer hands off to a goroutine, so a test that restored the store in
	// t.Cleanup would race that goroutine's read of it. The race detector
	// catches exactly this, and it is a test bug, not a product one — the seam
	// exists so the transition can be observed synchronously.
	var alerted []string
	prevFire := fireClusterCAAlert
	fireClusterCAAlert = func(detail string) { alerted = append(alerted, detail) }
	t.Cleanup(func() { fireClusterCAAlert = prevFire })

	ca.recordRotationFailure(errors.New("write cluster CA cert: read-only file system"))

	if len(alerted) != 1 {
		t.Fatalf("rotation failure fired %d alerts, want 1", len(alerted))
	}
	if !strings.Contains(alerted[0], "auto-rotation failed") ||
		!strings.Contains(alerted[0], "read-only file system") {
		t.Fatalf("alert does not carry the failure and its cause: %q", alerted[0])
	}
	if !strings.Contains(alerted[0], "mTLS trust") {
		t.Fatalf("alert does not state the consequence an operator is being paged about: %q", alerted[0])
	}

	snap := clusterCAUsabilityFailures()
	if snap.RotationFailures != 1 {
		t.Fatalf("rotation failures = %d, want 1", snap.RotationFailures)
	}
	if !snap.RotationDegraded {
		t.Fatal("rotation is not reported as degraded after a failure")
	}
	if !strings.Contains(snap.RotationErr, "read-only file system") {
		t.Fatalf("recorded reason lost the cause: %q", snap.RotationErr)
	}
	// Info() keeps the pre-existing pull-only field working.
	if info := ca.Info(); info["lastRotationError"] == nil {
		t.Fatal("Info() no longer surfaces lastRotationError")
	}
}

// TestClusterCARotationDegraded_ClearsOnEvidence: an operator who fixes the
// volume and completes a rotation must stop being told it is broken — and the
// cumulative counter must never go backwards while that happens.
func TestClusterCARotationDegraded_ClearsOnEvidence(t *testing.T) {
	ca := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	isolateClusterCA(t, ca)
	prevStore := globalClusterStore
	globalClusterStore = newTestClusterStore(t)
	t.Cleanup(func() { globalClusterStore = prevStore })

	ca.recordRotationFailure(errors.New("no space left on device"))
	if !clusterCARotationDegraded() {
		t.Fatal("not degraded after a failure")
	}

	replacement := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	certPEM, keyPEM := clusterCAPEMPair(t, replacement)
	if err := ca.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("import replacement: %v", err)
	}
	if clusterCARotationDegraded() {
		t.Fatal("rotation still reported as degraded after an observed successful import — the warning latched")
	}
	if snap := clusterCAUsabilityFailures(); snap.RotationFailures != 1 {
		t.Fatalf("cumulative counter = %d after recovery, want 1 (counters must not go backwards)", snap.RotationFailures)
	}
	// And it must re-arm on a later failure.
	ca.recordRotationFailure(errors.New("permission denied"))
	if !clusterCARotationDegraded() {
		t.Fatal("did not re-arm on a later failure")
	}
}

// TestClusterCAAlert_IsRateLimitedButFullyCounted: a fleet that has lost mTLS
// trust retries from every node at once. The magnitude must survive; the paging
// must not.
func TestClusterCAAlert_IsRateLimitedButFullyCounted(t *testing.T) {
	ca := newClusterCAWithWindow(t, time.Now().Add(-400*24*time.Hour), time.Now().Add(-24*time.Hour))
	isolateClusterCA(t, ca)

	var alerts int
	prevFire := fireClusterCAAlert
	fireClusterCAAlert = func(string) { alerts++ }
	t.Cleanup(func() { fireClusterCAAlert = prevFire })

	const storm = 500
	for i := 0; i < storm; i++ {
		if _, _, _, err := ca.SignCSR(nodeCSR(t, "dp-1"), "dp-1"); err == nil {
			t.Fatal("expired CA signed during the storm")
		}
	}
	if alerts != 1 {
		t.Fatalf("%d alerts fired for %d refusals — the rate gate is not holding", alerts, storm)
	}
	if got := clusterCAUsabilityFailures().Refusals; got != storm {
		t.Fatalf("refusals = %d, want %d — rate limiting must not cost magnitude", got, storm)
	}
	if got := ca.SignRefusals(); got != storm {
		t.Fatalf("engine counter = %d, want %d", got, storm)
	}
}

// TestClusterCAAlert_NoSubscriberSpawnsNoGoroutine pins the per-request
// alert-producer contract on the default posture (no webhooks configured).
func TestClusterCAAlert_NoSubscriberSpawnsNoGoroutine(t *testing.T) {
	ca := newClusterCAWithWindow(t, time.Now().Add(-400*24*time.Hour), time.Now().Add(-24*time.Hour))
	isolateClusterCA(t, ca)

	prevStore := globalAlertStore
	globalAlertStore = &AlertStore{}
	t.Cleanup(func() { globalAlertStore = prevStore })

	before := runtime.NumGoroutine()
	if _, _, _, err := ca.SignCSR(nodeCSR(t, "dp-1"), "dp-1"); err == nil {
		t.Fatal("expired CA signed")
	}
	time.Sleep(50 * time.Millisecond) // let anything spawned get scheduled
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("a refused signing spawned %d goroutine(s) with no webhook subscribed", after-before)
	}
}

// ── FS-3: the bootstrap-import panic ────────────────────────────────────────

// TestImportCA_BootstrapWithNoExistingCA: pre-fix this nil-derefed on
// ca.secondaryCert.Raw and panicked mid-handler — AFTER the new CA had been
// written to disk and installed in memory, so the operator saw the request fail
// while the import had in fact happened.
func TestImportCA_BootstrapWithNoExistingCA(t *testing.T) {
	prevStore := globalClusterStore
	globalClusterStore = newTestClusterStore(t)
	t.Cleanup(func() { globalClusterStore = prevStore })

	src := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	certPEM, keyPEM := clusterCAPEMPair(t, src)

	empty := &clusterCA{dir: t.TempDir()}
	isolateClusterCA(t, empty)

	if err := empty.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("bootstrap import failed: %v", err)
	}
	if !empty.Ready() {
		t.Fatal("bootstrap import did not install the CA")
	}
	if empty.Usable() != nil {
		t.Fatalf("bootstrap-imported CA is not usable: %v", empty.Usable())
	}
	// No predecessor ⇒ no overlap to track and no secondary in the trust pool.
	if empty.SecondaryActive() {
		t.Fatal("bootstrap import invented a secondary CA to overlap with")
	}
}

// TestImportCA_RotationStillTracksOverlap is the negative control for the guard
// above: when there IS a predecessor, the dual-CA overlap must still be
// recorded, or enrolled nodes lose trust the instant a CA is replaced.
func TestImportCA_RotationStillTracksOverlap(t *testing.T) {
	prevStore := globalClusterStore
	globalClusterStore = newTestClusterStore(t)
	t.Cleanup(func() { globalClusterStore = prevStore })

	old := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(20*24*time.Hour))
	isolateClusterCA(t, old)

	replacement := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	certPEM, keyPEM := clusterCAPEMPair(t, replacement)
	if err := old.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("rotation import failed: %v", err)
	}
	if !old.SecondaryActive() {
		t.Fatal("rotation did not preserve the old CA as an active secondary")
	}
	if st := globalClusterStore.CARotationStatus(); st == nil {
		t.Fatal("rotation tracking was not started for a real rotation")
	}
	if !strings.Contains(string(old.AllCACertsPEM()), "CERTIFICATE") {
		t.Fatal("trust pool lost its contents across the rotation")
	}
}

// ── FS-4: the re-entrant-callback deadlock ──────────────────────────────────

// withDeadlineGuard runs fn and fails the test if it has not returned within
// the budget. A deadlock cannot be caught any other way: the goroutine does not
// panic, does not error and does not exit — it simply never comes back, which
// is exactly why this class survived in main.
func withDeadlineGuard(t *testing.T, what string, budget time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(budget):
		buf := make([]byte, 1<<16)
		buf = buf[:runtime.Stack(buf, true)]
		t.Fatalf("DEADLOCK: %s did not return within %s — it holds the cluster CA write lock, "+
			"so enrollment, renewal, Info() and the TLS pool rebuild are all blocked behind it.\n%s",
			what, budget, buf)
	}
}

// TestImportCA_DoesNotDeadlockOnPublication is the regression gate for the
// critical finding. Reproduced against unmodified main: ImportCA held ca.mu
// while CurrentConfigSnapshot re-entered through CACertFingerprint's RLock.
//
// The fixture is the PRODUCTION shape — ImportCA invoked on globalClusterCA —
// because that identity is the whole bug. Existing tests missed it by calling
// ImportCA on a CA object that was not the global one.
func TestImportCA_DoesNotDeadlockOnPublication(t *testing.T) {
	prevStore := globalClusterStore
	globalClusterStore = newTestClusterStore(t)
	t.Cleanup(func() { globalClusterStore = prevStore })

	ca := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(20*24*time.Hour))
	isolateClusterCA(t, ca)

	replacement := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	certPEM, keyPEM := clusterCAPEMPair(t, replacement)

	withDeadlineGuard(t, "ImportCA", 20*time.Second, func() {
		if err := ca.ImportCA(certPEM, keyPEM); err != nil {
			t.Errorf("ImportCA: %v", err)
		}
	})
	// And the CA must still be readable afterwards — a lock leaked on the
	// success path would show up here rather than in the guard above.
	withDeadlineGuard(t, "post-import reads", 10*time.Second, func() {
		_ = ca.Info()
		_ = ca.CACertFingerprint()
		_ = ca.AllCACertsPEM()
		_ = ca.Ready()
	})
}

// TestImportCA_DoesNotDeadlockWithRotationCallbackWired covers the OTHER
// re-entry, the one a unit test without a Control Plane never wires: onRotate →
// rebuildCPCertPool → AllCACertsPEM → ca.mu.RLock. On a real CP this deadlocks
// EARLIER than the config-snapshot path.
func TestImportCA_DoesNotDeadlockWithRotationCallbackWired(t *testing.T) {
	prevStore := globalClusterStore
	globalClusterStore = newTestClusterStore(t)
	t.Cleanup(func() { globalClusterStore = prevStore })

	ca := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(20*24*time.Hour))
	isolateClusterCA(t, ca)

	// Stand in for rebuildCPCertPool: re-enter the cluster CA under RLock,
	// exactly as the real callback does.
	var rebuilt int
	ca.mu.Lock()
	ca.onRotate = func() {
		rebuilt++
		if len(ca.AllCACertsPEM()) == 0 {
			t.Error("rotation callback saw an empty trust pool")
		}
		_ = ca.CACertFingerprint()
	}
	ca.mu.Unlock()

	replacement := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	certPEM, keyPEM := clusterCAPEMPair(t, replacement)
	withDeadlineGuard(t, "ImportCA with onRotate wired", 20*time.Second, func() {
		if err := ca.ImportCA(certPEM, keyPEM); err != nil {
			t.Errorf("ImportCA: %v", err)
		}
	})
	if rebuilt != 1 {
		t.Fatalf("rotation callback ran %d times, want exactly 1", rebuilt)
	}
}

// TestCleanupSecondary_DoesNotDeadlock is the same class in the more dangerous
// place: CleanupSecondary runs on the shared CA rotation tick, so a deadlock
// there is silently un-contained (runGuarded catches panics, not deadlocks) and
// strands the rotation goroutine holding the write lock.
func TestCleanupSecondary_DoesNotDeadlock(t *testing.T) {
	prevStore := globalClusterStore
	globalClusterStore = newTestClusterStore(t)
	t.Cleanup(func() { globalClusterStore = prevStore })

	ca := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	isolateClusterCA(t, ca)

	// An overlap whose window has already closed, with the callback wired.
	expiredSecondary := newClusterCAWithWindow(t, time.Now().Add(-400*24*time.Hour), time.Now().Add(-time.Hour))
	var rebuilt int
	ca.mu.Lock()
	ca.secondaryCert = expiredSecondary.cert
	ca.secondaryPEM = expiredSecondary.certPEM
	ca.secondaryExp = expiredSecondary.cert.NotAfter
	ca.onRotate = func() { rebuilt++; _ = ca.AllCACertsPEM() }
	ca.mu.Unlock()

	withDeadlineGuard(t, "CleanupSecondary", 20*time.Second, func() { ca.CleanupSecondary() })
	if rebuilt != 1 {
		t.Fatalf("rotation callback ran %d times, want exactly 1", rebuilt)
	}
	if ca.SecondaryActive() {
		t.Fatal("expired secondary was not removed")
	}
	// A no-op cleanup (nothing expired) must not fire the callback or block.
	withDeadlineGuard(t, "CleanupSecondary no-op", 10*time.Second, func() { ca.CleanupSecondary() })
	if rebuilt != 1 {
		t.Fatalf("no-op cleanup fired the rotation callback (%d runs)", rebuilt)
	}
}

// TestClusterCA_ConcurrentImportsAndReadsStayLive is the stress form: the admin
// import path and the rotation tick are independent goroutines, and readers run
// on every enrollment. Nothing here may block indefinitely.
func TestClusterCA_ConcurrentImportsAndReadsStayLive(t *testing.T) {
	prevStore := globalClusterStore
	globalClusterStore = newTestClusterStore(t)
	t.Cleanup(func() { globalClusterStore = prevStore })

	ca := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	isolateClusterCA(t, ca)
	ca.mu.Lock()
	ca.onRotate = func() { _ = ca.AllCACertsPEM() }
	ca.mu.Unlock()

	pairs := make([][2][]byte, 4)
	for i := range pairs {
		r := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
		c, k := clusterCAPEMPair(t, r)
		pairs[i] = [2][]byte{c, k}
	}

	// One CSR is reused across the read loop: generating a fresh P-256 key per
	// iteration would dominate the test's runtime under -race and measure key
	// generation rather than the lock discipline this is here to exercise.
	csr := nodeCSR(t, "dp-1")

	withDeadlineGuard(t, "concurrent imports + reads", 90*time.Second, func() {
		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := range pairs {
				if err := ca.ImportCA(pairs[i][0], pairs[i][1]); err != nil {
					t.Errorf("concurrent import %d: %v", i, err)
				}
				ca.CleanupSecondary()
			}
		}()
		// Yield between rounds rather than spinning: a hot loop starves the
		// writer on a small runner and turns a lock-discipline test into a
		// scheduling test.
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = ca.Info()
			_ = ca.Usable()
			_ = ca.AllCACertsPEM()
			_, _, _, _ = ca.SignCSR(csr, "dp-1")
			time.Sleep(time.Millisecond)
		}
	})
}

// ── Observability surfaces ──────────────────────────────────────────────────

func TestClusterCAMetrics_SurfaceUsabilityAndOmitWhenAbsent(t *testing.T) {
	// No cluster CA (standalone / DP node): the GAUGES must be absent — a
	// culvert_cluster_ca_usable 0 there would page most of a fleet for a CA they
	// are not supposed to have. The counters stay, so rate() works from boot.
	isolateClusterCA(t, &clusterCA{})
	var sb strings.Builder
	clusterCAWriteUsabilityPrometheus(&sb)
	out := sb.String()
	if strings.Contains(out, "culvert_cluster_ca_usable ") {
		t.Error("culvert_cluster_ca_usable published on a node with no cluster CA")
	}
	if strings.Contains(out, "culvert_cluster_ca_expires_in_seconds ") {
		t.Error("culvert_cluster_ca_expires_in_seconds published on a node with no cluster CA")
	}
	for _, want := range []string{
		"culvert_cluster_ca_sign_refused_total 0",
		"culvert_cluster_ca_rotation_failures_total 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q from:\n%s", want, out)
		}
	}

	// Expired cluster CA: usable 0, expiry negative, refusals counted.
	ca := newClusterCAWithWindow(t, time.Now().Add(-400*24*time.Hour), time.Now().Add(-24*time.Hour))
	isolateClusterCA(t, ca)
	if _, _, _, err := ca.SignCSR(nodeCSR(t, "dp-1"), "dp-1"); err == nil {
		t.Fatal("expired CA signed")
	}
	sb.Reset()
	clusterCAWriteUsabilityPrometheus(&sb)
	out = sb.String()
	if !strings.Contains(out, "culvert_cluster_ca_usable 0") {
		t.Errorf("expired CA does not report culvert_cluster_ca_usable 0:\n%s", out)
	}
	if !strings.Contains(out, "culvert_cluster_ca_expires_in_seconds -") {
		t.Errorf("expired CA does not report a negative expiry:\n%s", out)
	}
	if !strings.Contains(out, "culvert_cluster_ca_sign_refused_total 1") {
		t.Errorf("refusal not counted:\n%s", out)
	}

	// Healthy cluster CA: usable 1.
	healthy := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	isolateClusterCA(t, healthy)
	sb.Reset()
	clusterCAWriteUsabilityPrometheus(&sb)
	if !strings.Contains(sb.String(), "culvert_cluster_ca_usable 1") {
		t.Errorf("healthy CA does not report culvert_cluster_ca_usable 1:\n%s", sb.String())
	}
}

// TestClusterCAMetrics_AreLabelFree pins the CA-2 metrics contract: no node ID,
// serial, fingerprint or subject may reach /metrics.
func TestClusterCAMetrics_AreLabelFree(t *testing.T) {
	ca := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	isolateClusterCA(t, ca)
	var sb strings.Builder
	clusterCAWriteUsabilityPrometheus(&sb)
	for _, line := range strings.Split(sb.String(), "\n") {
		if strings.HasPrefix(line, "culvert_cluster_ca") && strings.Contains(line, "{") {
			t.Errorf("cluster CA metric carries labels: %q", line)
		}
	}
	if strings.Contains(sb.String(), ca.cert.SerialNumber.Text(16)) {
		t.Error("cluster CA serial leaked into /metrics")
	}
}

func TestHealthz_ClusterCAPosture(t *testing.T) {
	read := func() string {
		rec := httptest.NewRecorder()
		handleHealth(rec, httptest.NewRequest("GET", "/healthz", nil))
		var h struct {
			ClusterCA string `json:"cluster_ca"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &h); err != nil {
			t.Fatalf("decode /healthz: %v", err)
		}
		return h.ClusterCA
	}

	isolateClusterCA(t, &clusterCA{})
	if got := read(); got != "not_initialized" {
		t.Fatalf("cluster_ca = %q with no CA, want not_initialized", got)
	}

	isolateClusterCA(t, newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour)))
	if got := read(); got != "ready" {
		t.Fatalf("cluster_ca = %q with a healthy CA, want ready", got)
	}

	isolateClusterCA(t, newClusterCAWithWindow(t, time.Now().Add(-400*24*time.Hour), time.Now().Add(-24*time.Hour)))
	if got := read(); got != "expired" {
		t.Fatalf("cluster_ca = %q with an expired CA, want expired — the probe stayed silent through a cluster-wide enrollment outage", got)
	}
}

func TestOperatorContract_ClusterCARow(t *testing.T) {
	// Absent on a node with no cluster CA: a permanent row saying "you have no
	// cluster CA" would be noise on every standalone and DP node.
	isolateClusterCA(t, &clusterCA{})
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "cluster_ca" {
			t.Fatal("cluster_ca row emitted on a node that holds no cluster CA")
		}
	}

	// Expired ⇒ fail, with the impact stated and an operator action.
	ca := newClusterCAWithWindow(t, time.Now().Add(-400*24*time.Hour), time.Now().Add(-24*time.Hour))
	isolateClusterCA(t, ca)
	if _, _, _, err := ca.SignCSR(nodeCSR(t, "dp-1"), "dp-1"); err == nil {
		t.Fatal("expired CA signed")
	}
	row := checkClusterCA()
	if row.Status != diagFail {
		t.Fatalf("cluster_ca status = %q with an expired CA, want %q", row.Status, diagFail)
	}
	if !strings.Contains(row.Message, "BLOCKED") {
		t.Fatalf("cluster_ca message does not state the impact: %q", row.Message)
	}
	if row.OperatorAction == "" {
		t.Fatal("cluster_ca row carries no operator action for a blocking fault")
	}
	// Viewer-role surface: no timestamp or path may appear in the message.
	if strings.Contains(row.Message, "expired at") || strings.Contains(row.Message, "/") {
		t.Fatalf("cluster_ca message leaks the raw cause to a viewer: %q", row.Message)
	}

	// Healthy ⇒ ok.
	isolateClusterCA(t, newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour)))
	if got := checkClusterCA(); got.Status != diagOK {
		t.Fatalf("cluster_ca status = %q with a healthy CA, want %q", got.Status, diagOK)
	}
}

func TestClusterCAInfo_ReportsUsability(t *testing.T) {
	healthy := newClusterCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	if info := healthy.Info(); info["usable"] != true {
		t.Fatalf("healthy CA Info() usable = %v, want true", info["usable"])
	}

	expired := newClusterCAWithWindow(t, time.Now().Add(-400*24*time.Hour), time.Now().Add(-24*time.Hour))
	info := expired.Info()
	if info["usable"] != false {
		t.Fatalf("expired CA Info() usable = %v, want false", info["usable"])
	}
	if info["initialized"] != true {
		t.Fatal("expired CA should still report initialized — usable and initialized are different questions")
	}
	reason, _ := info["unusableReason"].(string)
	if !strings.Contains(reason, "expired") {
		t.Fatalf("unusableReason does not name the violated bound: %q", reason)
	}
}
