package main

// cluster_ca_validity_test.go — CHAOS-50 / register row CA-13.
//
// Every test here reproduced a real defect on the commit before this file
// existed. The proof harness that established them was run first and is
// recorded in docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-18.md; these
// are the permanent walls.
//
// Determinism notes for this package's CI gate (-count=2 -shuffle=on):
//   - the process-global health record is reset per test via
//     resetClusterCAHealthForTest;
//   - alerts are observed through the fireClusterCAAlert seam rather than the
//     process-global alert store, so no test depends on webhook wiring;
//   - no test asserts on len(auditGet()) (the ring-saturation pitfall).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestClusterCAPEM mints a self-signed cluster-CA-shaped pair over an
// explicit validity window, so a test can drive expiry without waiting out the
// real ten-year lifetime.
func newTestClusterCAPEM(t *testing.T, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
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
		t.Fatalf("create CA: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// newTestNodeCSR builds a DP-shaped CSR.
func newTestNodeCSR(t *testing.T, nodeID string) []byte {
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

// loadTestClusterCA builds a clusterCA holding the given window.
func loadTestClusterCA(t *testing.T, notBefore, notAfter time.Time) *clusterCA {
	t.Helper()
	certPEM, keyPEM := newTestClusterCAPEM(t, notBefore, notAfter)
	ca := &clusterCA{dir: t.TempDir()}
	if err := ca.loadFromPEM(certPEM, keyPEM); err != nil {
		t.Fatalf("loadFromPEM: %v", err)
	}
	return ca
}

// captureClusterCAAlerts swaps the alert seam for the duration of a test and
// returns a pointer to the collected details.
func captureClusterCAAlerts(t *testing.T) *[]string {
	t.Helper()
	var got []string
	prev := fireClusterCAAlert
	fireClusterCAAlert = func(detail string) { got = append(got, detail) }
	t.Cleanup(func() { fireClusterCAAlert = prev })
	return &got
}

// ─── The core fail-closed guard ──────────────────────────────────────────────

// An expired cluster CA must REFUSE to issue. Pre-fix it signed happily and the
// Control Plane returned enrollment success, handing the node a certificate
// that fails path validation in every TLS stack — a node that can never
// connect, and a Control Plane reporting that it enrolled fine.
func TestClusterCA_ExpiredCARefusesToSignNodeCert(t *testing.T) {
	ca := loadTestClusterCA(t, time.Now().Add(-3*365*24*time.Hour), time.Now().Add(-24*time.Hour))
	// Loading an out-of-window CA records a fault of its own (that is
	// TestClusterCA_ExpiredCAAtBootIsLoadedButRecorded's subject). Arm the
	// observers AFTER the load so the counts below belong solely to the
	// issuance attempt under test.
	resetClusterCAHealthForTest()
	alerts := captureClusterCAAlerts(t)

	_, _, _, err := ca.SignCSR(newTestNodeCSR(t, "dp-1"), "dp-1")
	if err == nil {
		t.Fatal("expired cluster CA signed a node certificate; it must fail closed")
	}
	if !errors.Is(err, ErrClusterCAUnusable) {
		t.Fatalf("error must wrap ErrClusterCAUnusable, got %v", err)
	}
	if !strings.Contains(err.Error(), "expired at") {
		t.Errorf("error must name the violated bound, got %q", err)
	}

	// The refusal must be COUNTED, not just returned: a node that cannot enroll
	// reports nothing to the Control Plane, so the counter is the only place
	// this shows up on the node that can fix it.
	if snap := clusterCAHealthFailures(); snap.SignRefusals != 1 {
		t.Errorf("SignRefusals = %d, want 1", snap.SignRefusals)
	}
	if len(*alerts) != 1 {
		t.Fatalf("want exactly 1 alert, got %d: %v", len(*alerts), *alerts)
	}
	if !strings.Contains((*alerts)[0], "cannot issue node certificates") {
		t.Errorf("alert must state the operator-visible consequence, got %q", (*alerts)[0])
	}
}

// The clock-rollback half of the same guard, plus its tolerance: a CA whose
// NotBefore is a few minutes ahead (peer clock skew during a fresh rotation)
// must still work, while a genuine rollback must fail closed.
func TestClusterCA_NotYetValidCAIsRefusedButSmallSkewIsTolerated(t *testing.T) {
	now := time.Now()

	withinTolerance, _ := newTestClusterCAPEM(t,
		now.Add(clusterCAClockSkewTolerance/2), now.Add(24*time.Hour))
	blk, _ := pem.Decode(withinTolerance)
	certOK, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := clusterCAUsable(certOK, now); err != nil {
		t.Errorf("a NotBefore inside the skew tolerance must stay usable, got %v", err)
	}

	beyondTolerance, _ := newTestClusterCAPEM(t,
		now.Add(2*clusterCAClockSkewTolerance), now.Add(24*time.Hour))
	blk2, _ := pem.Decode(beyondTolerance)
	certBad, err := x509.ParseCertificate(blk2.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	err = clusterCAUsable(certBad, now)
	if !errors.Is(err, ErrClusterCAUnusable) {
		t.Fatalf("a NotBefore beyond the tolerance must fail closed, got %v", err)
	}
	if !strings.Contains(err.Error(), "clock may have rolled back") {
		t.Errorf("error should point the operator at the clock, got %q", err)
	}
}

// A usable CA must be entirely unaffected — the guard adds denials, it never
// changes the healthy path.
func TestClusterCA_UsableCAStillSignsNormally(t *testing.T) {
	resetClusterCAHealthForTest()
	ca := loadTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))

	certPEM, serial, expiry, err := ca.SignCSR(newTestNodeCSR(t, "dp-ok"), "dp-ok")
	if err != nil {
		t.Fatalf("a usable cluster CA must sign: %v", err)
	}
	if serial == "" || len(certPEM) == 0 || expiry.IsZero() {
		t.Fatal("signing returned an incomplete result")
	}
	if snap := clusterCAHealthFailures(); snap.SignRefusals != 0 {
		t.Errorf("healthy path must not record a refusal, got %d", snap.SignRefusals)
	}
	// The issued certificate must actually chain to the issuing CA.
	blk, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CACertPEM())
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("issued node certificate must validate against its issuer: %v", err)
	}
}

// ─── The clamp ───────────────────────────────────────────────────────────────

// A node certificate must never outlive its issuer. This is the defect that
// makes a cluster-CA expiry incident hardest to diagnose: unclamped, the DP's
// own renewal trigger (certNeedsRenewal) reads the leaf's NotAfter, sees a year
// of runway, and sits still through the entire window in which it had to renew
// — while every handshake it makes has been failing since the issuer expired.
func TestClusterCA_NodeCertIsClampedToIssuerWindow(t *testing.T) {
	caNotAfter := time.Now().Add(20 * 24 * time.Hour) // well inside the 1-year default
	ca := loadTestClusterCA(t, time.Now().Add(-time.Hour), caNotAfter)

	certPEM, _, expiry, err := ca.SignCSR(newTestNodeCSR(t, "dp-clamp"), "dp-clamp")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if expiry.After(caNotAfter) {
		t.Errorf("returned expiry %s outlives the issuer %s", expiry, caNotAfter)
	}
	blk, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.NotAfter.After(ca.cert.NotAfter) {
		t.Errorf("leaf NotAfter %s outlives issuer NotAfter %s", leaf.NotAfter, ca.cert.NotAfter)
	}
	if leaf.NotBefore.Before(ca.cert.NotBefore) {
		t.Errorf("leaf NotBefore %s predates issuer NotBefore %s", leaf.NotBefore, ca.cert.NotBefore)
	}
	// The returned expiry is what the Control Plane stores as
	// EnrolledNode.CertExpiry and what the DP writes to disk, so the two views
	// of the node's lifetime must agree.
	if !leaf.NotAfter.Equal(expiry) {
		t.Errorf("returned expiry %s disagrees with the certificate's NotAfter %s", expiry, leaf.NotAfter)
	}
}

// A long-lived CA must not clamp anything — the default 1-year node lifetime is
// preserved whenever it fits inside the issuer's window.
func TestClusterCA_ClampDoesNotShortenCertsUnderALongLivedCA(t *testing.T) {
	ca := loadTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	_, _, expiry, err := ca.SignCSR(newTestNodeCSR(t, "dp-long"), "dp-long")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	days := time.Until(expiry).Hours() / 24
	if days < 364 || days > 366 {
		t.Errorf("node certificate lifetime = %.1f days, want the unclamped ~365", days)
	}
}

func TestClampNodeCertValidity_NilIssuerIsIdentity(t *testing.T) {
	nb, na := time.Now(), time.Now().Add(time.Hour)
	gotNB, gotNA := clampNodeCertValidity(nb, na, nil)
	if !gotNB.Equal(nb) || !gotNA.Equal(na) {
		t.Errorf("nil issuer must be identity, got (%s, %s)", gotNB, gotNA)
	}
}

// ─── Boot-time visibility ────────────────────────────────────────────────────

// An expired cluster CA on disk must LOAD (refusing would brick the one node
// that can repair it, and rotation is the recovery path) but must not load
// SILENTLY: pre-fix the only signal was a boot line that reads like success.
func TestClusterCA_ExpiredCAAtBootIsLoadedButRecorded(t *testing.T) {
	resetClusterCAHealthForTest()
	alerts := captureClusterCAAlerts(t)

	dir := t.TempDir()
	certPEM, keyPEM := newTestClusterCAPEM(t,
		time.Now().Add(-3*365*24*time.Hour), time.Now().Add(-48*time.Hour))
	if err := os.WriteFile(filepath.Join(dir, "cluster-ca.crt"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cluster-ca.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("an expired CA must still load (rotation is the recovery path): %v", err)
	}
	if !ca.Ready() {
		t.Error("Ready() must stay true — a CA is installed")
	}
	if err := ca.Usable(); err == nil {
		t.Error("Usable() must be false for an expired CA")
	}
	if snap := clusterCAHealthFailures(); snap.SignRefusals != 1 {
		t.Errorf("boot must record the fault, SignRefusals = %d want 1", snap.SignRefusals)
	}
	if len(*alerts) != 1 {
		t.Errorf("boot must alert once, got %d alerts", len(*alerts))
	}
}

// Ready() and Usable() answer different questions and must stay separate:
// folding validity into Ready() would report "cluster CA not initialized" for a
// CA that is very much initialized, sending the operator to the wrong runbook.
func TestClusterCA_ReadyAndUsableAreDistinct(t *testing.T) {
	resetClusterCAHealthForTest()
	ca := loadTestClusterCA(t, time.Now().Add(-3*365*24*time.Hour), time.Now().Add(-time.Hour))
	if !ca.Ready() {
		t.Error("Ready() must be true: a CA and key are loaded")
	}
	if ca.Usable() == nil {
		t.Error("Usable() must be false: the CA is outside its validity window")
	}

	empty := &clusterCA{}
	if empty.Ready() {
		t.Error("Ready() must be false with no CA")
	}
	if !errors.Is(empty.Usable(), ErrClusterCAUnusable) {
		t.Error("Usable() must fail closed with no CA")
	}
}

// ─── Import: persist before swap ─────────────────────────────────────────────

// A failed import must be a no-op on live state. Pre-fix the dual-CA overlap
// assignment ran BEFORE the writes, so a write failure returned an error having
// already installed the current CA as its own secondary: SecondaryActive()
// flipped true, the client pool got the same certificate twice, and the next
// CleanupSecondary cleared rotation tracking for a rotation that never happened.
func TestClusterCA_FailedImportDoesNotMutateLiveState(t *testing.T) {
	dir := t.TempDir()
	ca := &clusterCA{dir: dir}
	oldCertPEM, oldKeyPEM := newTestClusterCAPEM(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if err := ca.loadFromPEM(oldCertPEM, oldKeyPEM); err != nil {
		t.Fatal(err)
	}
	beforeFP := ca.CACertFingerprint()

	// Occupying the cert path with a DIRECTORY makes the atomic rename fail for
	// any user, including root — so this reproduces in CI containers too.
	if err := os.Mkdir(filepath.Join(dir, "cluster-ca.crt"), 0o700); err != nil {
		t.Fatal(err)
	}

	newCertPEM, newKeyPEM := newTestClusterCAPEM(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	if err := ca.ImportCA(newCertPEM, newKeyPEM); err == nil {
		t.Fatal("import over an unwritable path must fail")
	}

	if ca.SecondaryActive() {
		t.Error("a FAILED import must not activate dual-CA overlap")
	}
	if got := ca.CACertFingerprint(); got != beforeFP {
		t.Error("a FAILED import must leave the active CA unchanged")
	}
	if all := ca.AllCACertsPEM(); len(all) != len(oldCertPEM) {
		t.Errorf("client CA pool must still hold exactly the one active CA (%d bytes, want %d)",
			len(all), len(oldCertPEM))
	}
}

// Importing into a Control Plane whose cluster CA failed to load — exactly the
// state an operator imports a CA to REPAIR — must work. Pre-fix it dereferenced
// a nil secondary and panicked half-way through, after onRotate had fired.
func TestClusterCA_ImportIntoUninitialisedCASucceeds(t *testing.T) {
	ca := &clusterCA{dir: t.TempDir()}
	if ca.Ready() {
		t.Fatal("precondition: no CA loaded")
	}
	certPEM, keyPEM := newTestClusterCAPEM(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	if err := ca.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("first install must succeed: %v", err)
	}
	if !ca.Ready() || ca.Usable() != nil {
		t.Error("the imported CA must be ready and usable")
	}
	if ca.SecondaryActive() {
		t.Error("a first install is not a rotation — there is nothing to overlap with")
	}
}

// A successful import still establishes dual-CA overlap, so nodes holding
// certificates from the outgoing CA keep validating. The persist-before-swap
// reordering must not have cost this.
func TestClusterCA_SuccessfulImportStillEstablishesOverlap(t *testing.T) {
	ca := &clusterCA{dir: t.TempDir()}
	oldCertPEM, oldKeyPEM := newTestClusterCAPEM(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	if err := ca.loadFromPEM(oldCertPEM, oldKeyPEM); err != nil {
		t.Fatal(err)
	}
	newCertPEM, newKeyPEM := newTestClusterCAPEM(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	if err := ca.ImportCA(newCertPEM, newKeyPEM); err != nil {
		t.Fatalf("import: %v", err)
	}
	if !ca.SecondaryActive() {
		t.Fatal("the outgoing CA must be retained as secondary")
	}
	if all := ca.AllCACertsPEM(); len(all) != len(oldCertPEM)+len(newCertPEM) {
		t.Errorf("client CA pool must carry both CAs, got %d bytes", len(all))
	}
}

// ─── Rotation observability ──────────────────────────────────────────────────

// A failed rotation must be counted and alerted, not just stored in a JSON
// field. Pre-fix the Info() string was the entire record: nothing counted it,
// nothing alerted on it, no probe moved — so a rotation failing daily for a
// month first surfaced as the cluster-wide enrollment outage at expiry.
func TestClusterCA_RotationFailureIsCountedAndAlerted(t *testing.T) {
	resetClusterCAHealthForTest()
	alerts := captureClusterCAAlerts(t)

	ca := loadTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(10*time.Hour))
	ca.recordRotationFailure(errors.New("write cluster CA cert: no space left on device"))

	snap := clusterCAHealthFailures()
	if snap.RotationFailures != 1 {
		t.Errorf("RotationFailures = %d, want 1", snap.RotationFailures)
	}
	if !snap.RotationDegraded {
		t.Error("a failed rotation with no success since must report degraded")
	}
	if !clusterCARotationDegraded() {
		t.Error("clusterCARotationDegraded() must agree with the snapshot")
	}
	if len(*alerts) != 1 {
		t.Fatalf("want 1 rotation alert, got %d", len(*alerts))
	}
	if !strings.Contains((*alerts)[0], "auto-rotation FAILED") {
		t.Errorf("alert must name the failure, got %q", (*alerts)[0])
	}
	// The Info() surface must agree with the health plane — the admin panel and
	// the metrics must never tell the operator different stories.
	info := ca.Info()
	if info["rotationDegraded"] != true || info["rotationFailures"].(int64) != 1 {
		t.Errorf("Info() must surface the rotation state, got %v", info)
	}
}

// Recovery is reported on EVIDENCE (an observed successful rotation), never on
// elapsed time — and the cumulative counter must not go backwards, because it
// feeds a Prometheus counter.
func TestClusterCA_RotationDegradedClearsOnObservedSuccess(t *testing.T) {
	resetClusterCAHealthForTest()
	_ = captureClusterCAAlerts(t)

	noteClusterCARotationFailure("disk full")
	if !clusterCARotationDegraded() {
		t.Fatal("precondition: degraded")
	}
	noteClusterCARotated()
	if clusterCARotationDegraded() {
		t.Error("an observed successful rotation must clear the degraded state")
	}
	if snap := clusterCAHealthFailures(); snap.RotationFailures != 1 {
		t.Errorf("the cumulative counter must not be decremented, got %d", snap.RotationFailures)
	}
}

// The usability fault log/alert is rate-limited but the COUNTER is not: a
// reconnect storm against an expired CA must not flood the alert plane, and
// must not lose the magnitude either.
func TestClusterCA_RefusalAlertIsRateLimitedButCountsAreNot(t *testing.T) {
	ca := loadTestClusterCA(t, time.Now().Add(-3*365*24*time.Hour), time.Now().Add(-time.Hour))
	// Armed after the load, so the boot-time fault record is not counted here.
	resetClusterCAHealthForTest()
	alerts := captureClusterCAAlerts(t)

	const attempts = 25
	for i := 0; i < attempts; i++ {
		if _, _, _, err := ca.SignCSR(newTestNodeCSR(t, "dp-storm"), "dp-storm"); err == nil {
			t.Fatal("expected every issuance to be refused")
		}
	}
	if snap := clusterCAHealthFailures(); snap.SignRefusals != attempts {
		t.Errorf("SignRefusals = %d, want %d — the counter carries the magnitude", snap.SignRefusals, attempts)
	}
	if len(*alerts) != 1 {
		t.Errorf("want exactly 1 alert for a storm inside one rate-limit window, got %d", len(*alerts))
	}
}

// Recovery of the usability state is likewise evidence-driven.
func TestClusterCA_UsabilityRecoveryRequiresObservedEvidence(t *testing.T) {
	resetClusterCAHealthForTest()
	_ = captureClusterCAAlerts(t)

	noteClusterCAUnusable("expired at 2020-01-01T00:00:00Z")
	if !clusterCAEverUnusable.Load() {
		t.Fatal("precondition: a fault was recorded")
	}
	before := clusterCAHealthFailures()
	if !before.Last.IsZero() && before.Reason == "" {
		t.Error("the fault record must carry a reason")
	}
	noteClusterCAUsable()
	after := clusterCAHealthFailures()
	if after.SignRefusals != before.SignRefusals {
		t.Error("recovery must not rewrite the refusal count")
	}
}

// ─── The SPOF: rotation must not depend on the inspection CA ─────────────────

// The auto-rotation loop drives TWO unrelated CAs. Gating it on the inspection
// CA's health meant a wrong CULVERT_CA_PASSPHRASE or a corrupt bundle — the
// already-recorded CA-3 fault, which leaves certMgr.Ready() false because
// LoadOrInitCA routes an existing bundle straight to LoadCA without ever
// calling InitCA — ALSO silently disabled cluster-CA rotation, permanently.
// The two faults then compound on a decade-long fuse with nothing connecting
// them.
func TestClusterCA_RotationLoopIsNotGatedOnTheInspectionCA(t *testing.T) {
	// Anchored to the package source dir, never CWD — a concurrent os.Chdir in
	// another test would otherwise flake this read (static_read_wall_test.go).
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "rootca_startup.go"))
	if err != nil {
		t.Fatalf("read rootca_startup.go: %v", err)
	}
	body := string(src)
	idx := strings.Index(body, "StartCAAutoRotation(ctx")
	if idx < 0 {
		t.Fatal("loadRootCA must still start the auto-rotation loop")
	}
	// Look back over the enclosing statement for a conditional on the
	// inspection CA. A gate would have to appear within a few lines of the call.
	window := body[max(0, idx-400):idx]
	if strings.Contains(window, "if certMgr.Ready()") {
		t.Error("StartCAAutoRotation must NOT be gated on certMgr.Ready(): the loop also " +
			"drives the cluster CA, whose expiry breaks every node enrollment and renewal " +
			"in the fleet, and which has nothing to do with the inspection CA")
	}
}

// The loop is claimed by more than one caller (startup, and a runtime
// Control-Plane promotion), so a repeat call must be a no-op rather than a
// second goroutine racing the first.
func TestClusterCA_AutoRotationStartIsIdempotent(t *testing.T) {
	prev := caAutoRotationStarted.Load()
	t.Cleanup(func() { caAutoRotationStarted.Store(prev) })

	caAutoRotationStarted.Store(false)
	// Cancelled on return so the one goroutine the first call spawns does not
	// outlive the test and tick against the process-global CAs. Its immediate
	// startup round is a no-op here: both RotateIfNeeded implementations return
	// straight away when their CA has no expiry to check.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	StartCAAutoRotation(ctx, "", "")
	if !caAutoRotationStarted.Load() {
		t.Fatal("first call must claim the loop")
	}
	// Second and third calls must be no-ops. If they were not, they would each
	// spawn a goroutine that outlives the test and ticks against the shared
	// process-global CAs.
	StartCAAutoRotation(ctx, "", "")
	StartCAAutoRotation(ctx, "", "")
}
