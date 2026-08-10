package main

// cluster_ca_validity_test.go — CHAOS-29 regression gates (register row CA-13).
//
// Every test here was run against the PRE-FIX tree and observed to fail. That
// matters more than usual for this defect class: the pre-fix code did not error,
// did not panic (except one case, which panicked in the wrong place), and did
// not move a counter — it produced well-formed certificates that no peer would
// accept. A gate that cannot be shown to fail against the original code proves
// nothing about a failure mode whose whole signature is "looks fine".

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
	"testing"
	"time"
)

// newTestClusterCAPEM mints a self-signed cluster-CA-shaped cert with an
// explicit validity window, so the expiry cases do not require waiting a decade.
func newTestClusterCAPEM(t *testing.T, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
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
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// loadTestClusterCA builds an in-memory clusterCA around a given window,
// bypassing InitOrLoad so an already-expired CA can be installed (which
// ImportCA correctly refuses to do).
func loadTestClusterCA(t *testing.T, notBefore, notAfter time.Time) *clusterCA {
	t.Helper()
	certPEM, keyPEM := newTestClusterCAPEM(t, notBefore, notAfter)
	blk, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	kblk, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(kblk.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	return &clusterCA{cert: cert, key: key, certPEM: certPEM, dir: t.TempDir()}
}

func newTestNodeCSR(t *testing.T, nodeID string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: nodeID},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// TestClusterCA_ExpiredCARefusesToSign is the headline gate.
//
// PRE-FIX: SignCSR returned a valid-looking 1-year node certificate from a CA
// that expired an hour earlier — proven by running this test against the
// original enrollment.go, where the sign SUCCEEDED.
func TestClusterCA_ExpiredCARefusesToSign(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	ca := loadTestClusterCA(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))

	_, _, _, err := ca.SignCSR(newTestNodeCSR(t, "dp-node-1"), "dp-node-1")
	if err == nil {
		t.Fatal("expired cluster CA signed a node certificate — every mTLS peer would reject it")
	}
	if !errors.Is(err, ErrClusterCAUnusable) {
		t.Errorf("error does not wrap ErrClusterCAUnusable: %v", err)
	}
	if got := statClusterCASignRefused.Load(); got != 1 {
		t.Errorf("culvert_cluster_ca_sign_refused_total = %d, want 1", got)
	}
	// The refusal must be observable, not just returned: the enrolling node
	// sees the error, but the OPERATOR only ever sees the health plane.
	if snap := clusterCAHealthFailures(); snap.Reason == "" || snap.Last.IsZero() {
		t.Errorf("refusal not recorded on the health plane: %+v", snap)
	}
}

// TestClusterCA_ClockRollbackRefusesToSign covers the other end of the window.
// A CA whose NotBefore is in the future signs certs that fail path validation
// exactly like an expired one, while every status surface reports it healthy.
func TestClusterCA_ClockRollbackRefusesToSign(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	ca := loadTestClusterCA(t, time.Now().Add(72*time.Hour), time.Now().Add(10*365*24*time.Hour))
	if _, _, _, err := ca.SignCSR(newTestNodeCSR(t, "dp-node-1"), "dp-node-1"); !errors.Is(err, ErrClusterCAUnusable) {
		t.Fatalf("not-yet-valid cluster CA signed a node certificate (err=%v)", err)
	}
}

// TestClusterCA_SkewToleranceDoesNotBreakFreshCA is the other half of the
// contract: the guard must not take enrollment down over ordinary clock skew.
// A CA minted seconds ago on a peer whose clock runs slightly fast is healthy.
func TestClusterCA_SkewToleranceDoesNotBreakFreshCA(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	ca := loadTestClusterCA(t,
		time.Now().Add(clusterCAClockSkewTolerance-time.Minute),
		time.Now().Add(10*365*24*time.Hour))
	if _, _, _, err := ca.SignCSR(newTestNodeCSR(t, "dp-node-1"), "dp-node-1"); err != nil {
		t.Fatalf("CA within the skew tolerance was refused — the guard is too tight: %v", err)
	}
	if got := statClusterCASignRefused.Load(); got != 0 {
		t.Errorf("healthy sign counted a refusal: %d", got)
	}
}

// TestClusterCA_NodeCertClampedToIssuer proves the renewal-clock defect is
// closed. The node cert is the clock certNeedsRenewal runs on, so a cert that
// outlives its issuer leaves the DP quiet while its trust anchor dies.
//
// PRE-FIX: the node cert expired 320 days after its issuer.
func TestClusterCA_NodeCertClampedToIssuer(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	caExpiry := time.Now().Add(45 * 24 * time.Hour) // inside its own rotation window
	ca := loadTestClusterCA(t, time.Now().Add(-time.Hour), caExpiry)

	certPEM, _, expiry, err := ca.SignCSR(newTestNodeCSR(t, "dp-node-1"), "dp-node-1")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if expiry.After(caExpiry) {
		t.Errorf("returned expiry %s outlives the issuer %s by %.0f days",
			expiry.Format(time.RFC3339), caExpiry.Format(time.RFC3339),
			expiry.Sub(caExpiry).Hours()/24)
	}
	// The returned expiry is what the ClusterStore records; the certificate
	// itself is what peers validate. Both must be clamped.
	blk, _ := pem.Decode(certPEM)
	nodeCert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse node cert: %v", err)
	}
	if nodeCert.NotAfter.After(caExpiry) {
		t.Errorf("node certificate NotAfter %s outlives its issuer %s",
			nodeCert.NotAfter.Format(time.RFC3339), caExpiry.Format(time.RFC3339))
	}
	// The clamp must pull the cert inside the DP's 30-day renewal window ahead
	// of the CA's expiry — that is the whole point, not a side effect.
	if time.Until(nodeCert.NotAfter) > time.Until(caExpiry) {
		t.Error("clamp did not bring the node cert's renewal clock in front of the CA expiry")
	}
}

// TestClusterCA_HealthyCAStillIssuesFullYear guards against over-clamping: a
// normal 10-year cluster CA must keep issuing the full 1-year node cert.
func TestClusterCA_HealthyCAStillIssuesFullYear(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	ca := loadTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	_, _, expiry, err := ca.SignCSR(newTestNodeCSR(t, "dp-node-1"), "dp-node-1")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if d := time.Until(expiry); d < 364*24*time.Hour {
		t.Errorf("node cert lifetime shortened to %v — the clamp fired against a healthy CA", d)
	}
}

// TestClusterCA_ImportWithNoPriorCADoesNotPanic covers the reachable nil
// dereference. initClusterCA LOGS AND CONTINUES when InitOrLoad fails, so a
// read-only or permission-denied CA directory leaves a running node with
// cert == nil — and the admin's recovery action (import a CA) hit the panic.
//
// PRE-FIX: panicked with "invalid memory address or nil pointer dereference",
// AFTER writing the CA to disk and publishing it in memory, and BEFORE the
// config-store bump that tells DP nodes about it.
func TestClusterCA_ImportWithNoPriorCADoesNotPanic(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	ca := &clusterCA{dir: t.TempDir()} // InitOrLoad never ran / failed
	certPEM, keyPEM := newTestClusterCAPEM(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))

	before := statClusterCARotations.Load()
	if err := ca.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("ImportCA into an uninitialised cluster CA: %v", err)
	}
	// Reaching the end of ImportCA is the actual assertion — the counter is the
	// cheapest proof that the tail of the function ran rather than unwinding.
	if got := statClusterCARotations.Load(); got != before+1 {
		t.Errorf("ImportCA did not complete: rotations counter %d, want %d", got, before+1)
	}
	if !ca.Ready() {
		t.Error("CA not installed after a successful import")
	}
	// A first install has no predecessor, so there is no overlap to track.
	if ca.SecondaryActive() {
		t.Error("first install invented a dual-CA overlap with a non-existent old CA")
	}
}

// TestParseAndValidateCACert_RejectsNotYetValid keeps a future-dated CA out at
// the import boundary instead of letting the sign gate discover it later.
//
// PRE-FIX: accepted.
func TestParseAndValidateCACert_RejectsNotYetValid(t *testing.T) {
	certPEM, _ := newTestClusterCAPEM(t, time.Now().Add(72*time.Hour), time.Now().Add(10*365*24*time.Hour))
	if _, err := parseAndValidateCACert(certPEM); err == nil {
		t.Fatal("accepted a cluster CA whose NotBefore is 72h in the future")
	}
}

// TestParseAndValidateCACert_AcceptsWithinSkew is the paired usability check:
// import must not reject a CA generated moments ago on a slightly fast peer.
func TestParseAndValidateCACert_AcceptsWithinSkew(t *testing.T) {
	certPEM, _ := newTestClusterCAPEM(t,
		time.Now().Add(clusterCAClockSkewTolerance-time.Minute),
		time.Now().Add(10*365*24*time.Hour))
	if _, err := parseAndValidateCACert(certPEM); err != nil {
		t.Fatalf("rejected a CA inside the skew tolerance: %v", err)
	}
}

// TestClusterCA_RotationFailureIsCountedAndDegraded closes register row CA-13
// proper: rotation failures were log-only plus a pull-only Info() field.
func TestClusterCA_RotationFailureIsCountedAndDegraded(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	ca := loadTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour))
	ca.recordRotationFailure(errors.New("write cluster CA cert: read-only file system"))

	if got := statClusterCARotationFailure.Load(); got != 1 {
		t.Errorf("culvert_cluster_ca_rotation_failures_total = %d, want 1", got)
	}
	if !clusterCARotationDegraded() {
		t.Error("rotation not reported degraded after a failure")
	}
	if snap := clusterCAHealthFailures(); !snap.RotationDegraded || snap.RotationFailures != 1 {
		t.Errorf("snapshot did not carry the failure: %+v", snap)
	}
}

// TestClusterCA_RotationRecoveryOnEvidence pins the recovery rule: the degraded
// row clears on an OBSERVED successful rotation/import, never on elapsed time —
// and the cumulative counter must not go backwards when it does.
func TestClusterCA_RotationRecoveryOnEvidence(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	ca := &clusterCA{dir: t.TempDir()}
	if err := ca.InitOrLoad(t.TempDir()); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	ca.recordRotationFailure(errors.New("write cluster CA cert: no space left on device"))
	if !clusterCARotationDegraded() {
		t.Fatal("precondition: expected degraded after failure")
	}

	certPEM, keyPEM := newTestClusterCAPEM(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	if err := ca.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("ImportCA (operator recovery): %v", err)
	}
	if clusterCARotationDegraded() {
		t.Error("degraded row still latched after a successful import — the operator fixed it and is still being told otherwise")
	}
	if got := statClusterCARotationFailure.Load(); got != 1 {
		t.Errorf("cumulative failure counter moved backwards on recovery: %d, want 1", got)
	}
}

// TestClusterCA_MetricsOmittedWithoutCA proves the standalone-node posture: a
// node with no cluster CA emits neither gauge, so an alerting rule written
// against culvert_cluster_ca_usable is safe to deploy fleet-wide.
func TestClusterCA_MetricsOmittedWithoutCA(t *testing.T) {
	resetClusterCAHealthForTest()
	orig := globalClusterCA
	t.Cleanup(func() {
		globalClusterCA = orig
		resetClusterCAHealthForTest()
	})
	globalClusterCA = &clusterCA{}

	var sb strings.Builder
	clusterCAWriteUsabilityPrometheus(&sb)
	out := sb.String()
	for _, series := range []string{"culvert_cluster_ca_usable", "culvert_cluster_ca_expires_in_seconds"} {
		if strings.Contains(out, series+" ") {
			t.Errorf("%s emitted on a node with no cluster CA — reads as a CA outage on every standalone proxy", series)
		}
	}
	// The counters are process-wide and always meaningful.
	if !strings.Contains(out, "culvert_cluster_ca_sign_refused_total") {
		t.Error("refusal counter missing")
	}
}

// TestClusterCA_MetricsReportUnusable is the paired positive case.
func TestClusterCA_MetricsReportUnusable(t *testing.T) {
	resetClusterCAHealthForTest()
	orig := globalClusterCA
	t.Cleanup(func() {
		globalClusterCA = orig
		resetClusterCAHealthForTest()
	})
	globalClusterCA = loadTestClusterCA(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))

	var sb strings.Builder
	clusterCAWriteUsabilityPrometheus(&sb)
	out := sb.String()
	if !strings.Contains(out, "culvert_cluster_ca_usable 0") {
		t.Errorf("expired cluster CA did not report culvert_cluster_ca_usable 0:\n%s", out)
	}
	if !strings.Contains(out, "culvert_cluster_ca_expires_in_seconds -") {
		t.Errorf("expired cluster CA did not report a negative expiry:\n%s", out)
	}
}

// TestClusterCA_DiagnosticsRowFailsClosed pins the operator-contract row, and
// with it the viewer-role guardrail: the row states impact and a count, and
// must never carry the raw cause (which names the appliance's exact cert state).
func TestClusterCA_DiagnosticsRowFailsClosed(t *testing.T) {
	resetClusterCAHealthForTest()
	orig := globalClusterCA
	t.Cleanup(func() {
		globalClusterCA = orig
		resetClusterCAHealthForTest()
	})
	globalClusterCA = loadTestClusterCA(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))

	row := checkClusterCA()
	if row.Status != diagFail {
		t.Errorf("cluster_ca row = %q, want %q for an expired CA", row.Status, diagFail)
	}
	if row.OperatorAction == "" {
		t.Error("failing row carries no operator action")
	}
	if strings.Contains(row.Message, "expired at") {
		t.Errorf("viewer-role row leaked the raw cause: %q", row.Message)
	}
}

// TestClusterCA_DiagnosticsRowSilentOnStandalone: a proxy with no cluster CA is
// the majority deployment and must not carry a standing warning.
func TestClusterCA_DiagnosticsRowSilentOnStandalone(t *testing.T) {
	orig := globalClusterCA
	t.Cleanup(func() { globalClusterCA = orig })
	globalClusterCA = &clusterCA{}

	if row := checkClusterCA(); row.Status != diagOK {
		t.Errorf("standalone node reports cluster_ca = %q, want %q", row.Status, diagOK)
	}
}

// TestClusterCA_InfoSurfacesUsability: "initialized" was the only health signal
// on the admin API, and an expired CA is initialized.
func TestClusterCA_InfoSurfacesUsability(t *testing.T) {
	ca := loadTestClusterCA(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	info := ca.Info()
	if usable, ok := info["usable"].(bool); !ok || usable {
		t.Errorf("Info() reports usable=%v for an expired CA", info["usable"])
	}
	if info["unusableReason"] == "" || info["unusableReason"] == nil {
		t.Error("Info() carries no reason for an unusable CA")
	}

	healthy := loadTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	hinfo := healthy.Info()
	if usable, ok := hinfo["usable"].(bool); !ok || !usable {
		t.Errorf("Info() reports usable=%v for a healthy CA", hinfo["usable"])
	}
	if days, ok := hinfo["expiresInDays"].(int); !ok || days < 3000 {
		t.Errorf("Info() expiresInDays = %v, want ~3650", hinfo["expiresInDays"])
	}
}
