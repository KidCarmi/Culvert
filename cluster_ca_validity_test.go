package main

// cluster_ca_validity_test.go — CHAOS-50 / CA-13 regression gates.
//
// Every test here was verified to FAIL against the pre-fix code:
//   · the expired/rolled-back issuer signed happily (no refusal, no counter)
//   · node certs outlived their issuer by up to a year
//   · the first import panicked on a nil secondary CA
//   · a re-import opened a phantom overlap with newFP == oldFP
//   · a failed persist left the live CA installed as its own secondary
//
// Fixture CAs are built with explicit validity windows rather than by waiting
// for a ten-year CA to expire, so the clock is an input, not a dependency.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// newTestClusterCAPair mints a self-signed cluster-CA cert+key with an explicit
// validity window.
func newTestClusterCAPair(t *testing.T, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
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
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// loadTestClusterCA builds an isolated clusterCA holding the given window.
func loadTestClusterCA(t *testing.T, notBefore, notAfter time.Time) *clusterCA {
	t.Helper()
	certPEM, keyPEM := newTestClusterCAPair(t, notBefore, notAfter)
	ca := &clusterCA{}
	if err := ca.loadFromPEM(certPEM, keyPEM); err != nil {
		t.Fatalf("loadFromPEM: %v", err)
	}
	return ca
}

func newTestCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("csr keygen: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// captureClusterCAAlerts swaps the alert seam so the transition is observed
// synchronously rather than racing the process-global alerts sink.
func captureClusterCAAlerts(t *testing.T) *[]string {
	t.Helper()
	resetClusterCAUsabilityHealthForTest()
	t.Cleanup(resetClusterCAUsabilityHealthForTest)
	got := &[]string{}
	prev := fireClusterCAUnusableAlert
	fireClusterCAUnusableAlert = func(detail string) { *got = append(*got, detail) }
	t.Cleanup(func() { fireClusterCAUnusableAlert = prev })
	return got
}

// ─── The usability predicate ────────────────────────────────────────────────

func TestClusterCAUsable_Windows(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	certPEM, _ := newTestClusterCAPair(t, now.Add(-time.Hour), now.Add(time.Hour))
	blk, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if err := clusterCAUsable(nil, now); !errors.Is(err, errClusterCAUnusable) {
		t.Errorf("nil cert: want errClusterCAUnusable, got %v", err)
	}
	if err := clusterCAUsable(cert, now); err != nil {
		t.Errorf("inside window: want usable, got %v", err)
	}
	if err := clusterCAUsable(cert, now.Add(2*time.Hour)); !errors.Is(err, errClusterCAUnusable) {
		t.Errorf("past NotAfter: want unusable, got %v", err)
	}
	// Clock rolled back beyond tolerance → unusable.
	if err := clusterCAUsable(cert, now.Add(-2*time.Hour)); !errors.Is(err, errClusterCAUnusable) {
		t.Errorf("before NotBefore: want unusable, got %v", err)
	}
	// Clock rolled back WITHIN tolerance → still usable. A node whose RTC is a
	// couple of minutes slow, or one that just took a small NTP step backwards,
	// must not refuse to enroll the whole fleet.
	skewed := cert.NotBefore.Add(-clusterCAClockSkewTolerance + time.Minute)
	if err := clusterCAUsable(cert, skewed); err != nil {
		t.Errorf("within skew tolerance: want usable, got %v", err)
	}
}

// ─── Fail closed on an unusable issuer ──────────────────────────────────────

func TestClusterCA_ExpiredIssuerRefusesToSign(t *testing.T) {
	alerts := captureClusterCAAlerts(t)
	ca := loadTestClusterCA(t, time.Now().Add(-2*365*24*time.Hour), time.Now().Add(-24*time.Hour))

	// Ready() must STAY true: it answers "is a CA installed", and folding
	// validity into it would silently change what every existing caller means.
	if !ca.Ready() {
		t.Fatal("Ready() must remain true for an installed-but-expired CA")
	}
	if err := ca.Usable(); !errors.Is(err, errClusterCAUnusable) {
		t.Fatalf("Usable(): want errClusterCAUnusable, got %v", err)
	}

	_, _, _, err := ca.SignCSR(newTestCSR(t, "dp-1"), "dp-1")
	if !errors.Is(err, errClusterCAUnusable) {
		t.Fatalf("SignCSR with an expired cluster CA must fail closed; got err=%v", err)
	}
	if snap := clusterCAUsabilityFailures(); snap.Refusals != 1 {
		t.Errorf("sign refusals = %d, want 1", snap.Refusals)
	}
	if len(*alerts) != 1 {
		t.Fatalf("want exactly 1 cert_expiry alert, got %d", len(*alerts))
	}
	if !strings.Contains((*alerts)[0], "enrollment") {
		t.Errorf("alert does not name the impacted capability: %q", (*alerts)[0])
	}
	if !clusterCAUsabilityDegraded() {
		t.Error("clusterCAUsabilityDegraded() = false after a refusal")
	}
}

func TestClusterCA_NotYetValidIssuerRefusesToSign(t *testing.T) {
	captureClusterCAAlerts(t)
	// Clock rollback: the CA is legitimately in the future relative to this node.
	ca := loadTestClusterCA(t, time.Now().Add(48*time.Hour), time.Now().Add(365*24*time.Hour))
	_, _, _, err := ca.SignCSR(newTestCSR(t, "dp-1"), "dp-1")
	if !errors.Is(err, errClusterCAUnusable) {
		t.Fatalf("SignCSR with a not-yet-valid cluster CA must fail closed; got %v", err)
	}
	if !strings.Contains(err.Error(), "clock") {
		t.Errorf("error should name the clock as the likely cause: %v", err)
	}
	// A clock fault and an expiry are NOT the same operator action. Reporting
	// both as "expired" steers the operator into rotating a trust root that is
	// perfectly fine — a fleet-wide operation that does not fix the fault.
	if kind := clusterCAUnusableKind(err); kind != "not_yet_valid" {
		t.Errorf("unusable kind = %q, want not_yet_valid", kind)
	}
	if errors.Is(err, errClusterCAExpired) {
		t.Error("a not-yet-valid CA must not classify as expired")
	}
	fix := clusterCAUnusableRemediation(clusterCAUnusableKind(err))
	if !strings.Contains(fix, "clock") || strings.Contains(fix, "Rotate or import") {
		t.Errorf("remediation for a clock fault must point at the clock, not a rotation: %q", fix)
	}
}

// The two unusable states are classified distinctly everywhere they surface.
func TestClusterCA_UnusableKindsAreDistinct(t *testing.T) {
	orig := globalClusterCA
	t.Cleanup(func() { globalClusterCA = orig })

	expired := loadTestClusterCA(t, time.Now().Add(-2*365*24*time.Hour), time.Now().Add(-24*time.Hour))
	notYet := loadTestClusterCA(t, time.Now().Add(48*time.Hour), time.Now().Add(365*24*time.Hour))

	if kind := clusterCAUnusableKind(expired.Usable()); kind != "expired" {
		t.Errorf("expired CA kind = %q, want expired", kind)
	}
	if !errors.Is(expired.Usable(), errClusterCAExpired) {
		t.Error("expired CA must wrap errClusterCAExpired")
	}

	globalClusterCA = notYet
	if got := clusterCAHealthState(); got != "not_yet_valid" {
		t.Errorf("/healthz cluster_ca = %q for a clock rollback, want not_yet_valid — "+
			"reporting it as \"expired\" points the operator at an unnecessary CA rotation", got)
	}
	info := notYet.Info()
	if info["unusableKind"] != "not_yet_valid" {
		t.Errorf("Info() unusableKind = %v, want not_yet_valid", info["unusableKind"])
	}
	rem, _ := info["unusableRemediation"].(string)
	if !strings.Contains(rem, "clock") {
		t.Errorf("Info() remediation = %q, want it to name the clock", rem)
	}

	globalClusterCA = expired
	if got := clusterCAHealthState(); got != "expired" {
		t.Errorf("/healthz cluster_ca = %q, want expired", got)
	}
	if rem := expired.Info()["unusableRemediation"]; !strings.Contains(rem.(string), "Rotate or import") {
		t.Errorf("expired remediation = %v, want a rotate/import instruction", rem)
	}
}

// The alert producer is rate-limited: an outage drives every node at the
// enrollment RPC at once, and one webhook per node per attempt would drop the
// alerts the operator actually needs.
func TestClusterCA_UnusableAlertIsRateLimited(t *testing.T) {
	alerts := captureClusterCAAlerts(t)
	ca := loadTestClusterCA(t, time.Now().Add(-2*365*24*time.Hour), time.Now().Add(-24*time.Hour))
	for i := 0; i < 25; i++ {
		_, _, _, _ = ca.SignCSR(newTestCSR(t, "dp-storm"), "dp-storm")
	}
	if len(*alerts) != 1 {
		t.Errorf("25 refusals produced %d alerts, want 1 (rate-limited)", len(*alerts))
	}
	if snap := clusterCAUsabilityFailures(); snap.Refusals != 25 {
		t.Errorf("refusals = %d, want 25 — the COUNTER must carry the magnitude", snap.Refusals)
	}
}

// Recovery is reported on OBSERVED evidence (a sign that actually succeeded),
// never on elapsed time — a still-expired CA looks exactly like a healthy one
// if nothing happens to need a certificate.
func TestClusterCA_RecoveryReportedOnEvidenceOnly(t *testing.T) {
	captureClusterCAAlerts(t)
	dead := loadTestClusterCA(t, time.Now().Add(-2*365*24*time.Hour), time.Now().Add(-24*time.Hour))
	if _, _, _, err := dead.SignCSR(newTestCSR(t, "dp-1"), "dp-1"); err == nil {
		t.Fatal("expected refusal")
	}
	if !clusterCAUsabilityDegraded() {
		t.Fatal("want degraded after refusal")
	}

	// Elapsed time alone must not clear it. Only a successful issuance does.
	healthy := loadTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if _, _, _, err := healthy.SignCSR(newTestCSR(t, "dp-1"), "dp-1"); err != nil {
		t.Fatalf("healthy CA must sign: %v", err)
	}
	if clusterCAUsabilityDegraded() {
		t.Error("degraded flag should clear on an observed successful issuance")
	}
}

// ─── Node certs never outlive their issuer ──────────────────────────────────

func TestClusterCA_NodeCertNeverOutlivesIssuer(t *testing.T) {
	resetClusterCAUsabilityHealthForTest()
	t.Cleanup(resetClusterCAUsabilityHealthForTest)

	for _, tc := range []struct {
		name       string
		caLifeLeft time.Duration
		wantClamp  bool
	}{
		{"ca inside its rotation window", 10 * 24 * time.Hour, true},
		{"ca shorter than a node cert", 100 * 24 * time.Hour, true},
		{"ca longer than a node cert", 10 * 365 * 24 * time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := loadTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(tc.caLifeLeft))
			leafPEM, _, expiry, err := ca.SignCSR(newTestCSR(t, "dp-1"), "dp-1")
			if err != nil {
				t.Fatalf("SignCSR: %v", err)
			}
			blk, _ := pem.Decode(leafPEM)
			leaf, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if leaf.NotAfter.After(ca.cert.NotAfter) {
				t.Errorf("node cert NotAfter %s outlives issuer %s",
					leaf.NotAfter.Format(time.RFC3339), ca.cert.NotAfter.Format(time.RFC3339))
			}
			if leaf.NotBefore.Before(ca.cert.NotBefore) {
				t.Errorf("node cert NotBefore %s predates issuer %s",
					leaf.NotBefore.Format(time.RFC3339), ca.cert.NotBefore.Format(time.RFC3339))
			}
			// The RETURNED expiry is what lands in EnrolledNode.CertExpiry and
			// drives every operator view of when this node must renew. It must
			// be the clamped value, not the value that was asked for.
			// (x509 encodes to second precision, so compare with a 1s tolerance.)
			if d := expiry.Sub(leaf.NotAfter); d > time.Second || d < -time.Second {
				t.Errorf("returned expiry %s != actual cert NotAfter %s — the node record would lie",
					expiry.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
			}
			if got := leaf.NotAfter.Equal(ca.cert.NotAfter); got != tc.wantClamp {
				t.Errorf("clamped = %v, want %v", got, tc.wantClamp)
			}
		})
	}

	// A clamped issuance is countable — it is the leading indicator that the
	// cluster CA is inside its rotation window.
	if snap := clusterCAUsabilityFailures(); snap.Clamped != 2 {
		t.Errorf("clamped count = %d, want 2", snap.Clamped)
	}
}

// The chain must actually verify — the whole point is that the artifact works.
func TestClusterCA_ClampedNodeCertStillChains(t *testing.T) {
	ca := loadTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour))
	leafPEM, _, _, err := ca.SignCSR(newTestCSR(t, "dp-1"), "dp-1")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	blk, _ := pem.Decode(leafPEM)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("clamped node cert must still verify against its issuer: %v", err)
	}
}

// ─── ImportCA: first import, re-import, failed persist ──────────────────────

func withTestClusterStore(t *testing.T) {
	t.Helper()
	orig := globalClusterStore
	t.Cleanup(func() { globalClusterStore = orig })
	globalClusterStore = newTestClusterStore(t)
}

func TestClusterCA_FirstImportDoesNotPanicOrOpenRotation(t *testing.T) {
	withTestClusterStore(t)
	dir := t.TempDir()
	// The documented recovery path: InitOrLoad failed (partial pair, permission
	// denied, corrupt PEM, wrong KEK), initClusterCA logged "enrollment
	// disabled", and the operator imports a CA from the admin UI. Pre-fix this
	// dereferenced a nil secondary CA and panicked — after the new CA had
	// already been written and swapped in, so the operator saw a failed request
	// against a CA that was actually live.
	ca := &clusterCA{dir: dir}
	certPEM, keyPEM := newTestClusterCAPair(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	if err := ca.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("first import must succeed: %v", err)
	}
	if !ca.Ready() || ca.Usable() != nil {
		t.Fatal("CA should be installed and usable after a first import")
	}
	if ca.SecondaryActive() {
		t.Error("a first import has no outgoing CA — there must be no dual-CA overlap")
	}
	if rot := globalClusterStore.CARotationStatus(); rot != nil {
		t.Errorf("a first import is not a rotation; got rotation state %+v", rot)
	}
}

func TestClusterCA_ReimportOfSameCAIsNotARotation(t *testing.T) {
	withTestClusterStore(t)
	dir := t.TempDir()
	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	certPEM := append([]byte(nil), ca.certPEM...)
	keyPEM := ca.CAKeyPEM()

	if err := ca.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("re-import of the identical CA: %v", err)
	}
	if ca.SecondaryActive() {
		t.Error("re-importing the same CA must not install it as its own secondary")
	}
	if rot := globalClusterStore.CARotationStatus(); rot != nil {
		t.Errorf("re-importing the same CA opened a phantom rotation (%d nodes would be "+
			"marked pending renewal): %+v", rot.TotalNodes, rot)
	}
}

func TestClusterCA_RealRotationStillOpensOverlap(t *testing.T) {
	withTestClusterStore(t)
	dir := t.TempDir()
	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	oldFP := ca.CACertFingerprint()

	certPEM, keyPEM := newTestClusterCAPair(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if err := ca.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("ImportCA: %v", err)
	}
	if !ca.SecondaryActive() {
		t.Fatal("a real rotation must preserve the outgoing CA as secondary")
	}
	rot := globalClusterStore.CARotationStatus()
	if rot == nil {
		t.Fatal("a real rotation must open rotation tracking")
	}
	if rot.OldFingerprint != oldFP {
		t.Errorf("old fingerprint = %q, want %q", rot.OldFingerprint, oldFP)
	}
	if rot.NewFingerprint == rot.OldFingerprint {
		t.Error("rotation recorded with identical old/new fingerprints")
	}
	// Both CAs must be offered to the TLS layer during the overlap, so nodes
	// holding certs from either one keep authenticating.
	if n := strings.Count(string(ca.AllCACertsPEM()), "BEGIN CERTIFICATE"); n != 2 {
		t.Errorf("AllCACertsPEM has %d certs during overlap, want 2", n)
	}
}

func TestClusterCA_FailedPersistLeavesRunningCAUnchanged(t *testing.T) {
	withTestClusterStore(t)
	dir := t.TempDir()
	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	origCert, origFP := ca.cert, ca.CACertFingerprint()

	// Simulate an unwritable CA directory (read-only volume, ENOSPC, a bad
	// dataDir). The import must fail with the RUNNING CA untouched.
	ca.mu.Lock()
	ca.dir = dir + "/definitely-not-a-directory"
	ca.mu.Unlock()

	certPEM, keyPEM := newTestClusterCAPair(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if err := ca.ImportCA(certPEM, keyPEM); err == nil {
		t.Fatal("import onto an unwritable directory must fail")
	}

	if ca.cert != origCert || ca.CACertFingerprint() != origFP {
		t.Error("a failed persist swapped the live CA")
	}
	if ca.SecondaryActive() {
		t.Error("a failed persist left a phantom dual-CA overlap — the live CA " +
			"was installed as its own secondary and only a restart cleared it")
	}
	if rot := globalClusterStore.CARotationStatus(); rot != nil {
		t.Errorf("a failed persist opened rotation tracking: %+v", rot)
	}
	if info := ca.Info(); info["dualCAActive"] == true {
		t.Error("Info() reports dualCAActive after a failed import")
	}
}

func TestStartCARotation_RejectsSelfRotation(t *testing.T) {
	cs := newTestClusterStore(t)
	cs.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected"})

	cs.StartCARotation("same-fp", "same-fp", time.Now().Add(24*time.Hour))
	if rot := cs.CARotationStatus(); rot != nil {
		t.Errorf("self-rotation accepted — every node would be marked pending renewal: %+v", rot)
	}
	cs.StartCARotation("", "old-fp", time.Now().Add(24*time.Hour))
	if rot := cs.CARotationStatus(); rot != nil {
		t.Errorf("empty new fingerprint accepted: %+v", rot)
	}

	cs.StartCARotation("new-fp", "old-fp", time.Now().Add(24*time.Hour))
	if rot := cs.CARotationStatus(); rot == nil {
		t.Fatal("a genuine rotation must still be recorded")
	}
}

// ─── Observability surfaces ─────────────────────────────────────────────────

func TestClusterCA_InfoSurfacesUsability(t *testing.T) {
	resetClusterCAUsabilityHealthForTest()
	t.Cleanup(resetClusterCAUsabilityHealthForTest)

	healthy := loadTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(400*24*time.Hour))
	info := healthy.Info()
	if info["usable"] != true {
		t.Errorf("healthy CA: usable = %v, want true", info["usable"])
	}
	if _, ok := info["unusableReason"]; ok {
		t.Error("healthy CA must not carry an unusableReason")
	}
	if d, _ := info["expiresInDays"].(int); d < 395 || d > 400 {
		t.Errorf("expiresInDays = %v, want ~399", info["expiresInDays"])
	}

	expired := loadTestClusterCA(t, time.Now().Add(-2*365*24*time.Hour), time.Now().Add(-24*time.Hour))
	info = expired.Info()
	if info["usable"] != false {
		t.Errorf("expired CA: usable = %v, want false", info["usable"])
	}
	reason, _ := info["unusableReason"].(string)
	if !strings.Contains(reason, "expired") {
		t.Errorf("unusableReason = %q, want it to name the expiry", reason)
	}
	if d, _ := info["expiresInDays"].(int); d > 0 {
		t.Errorf("expiresInDays = %v, want negative for an expired CA", info["expiresInDays"])
	}
}

func TestClusterCA_MetricsSurfaceUsabilityAndExpiry(t *testing.T) {
	resetClusterCAUsabilityHealthForTest()
	t.Cleanup(resetClusterCAUsabilityHealthForTest)
	orig := globalClusterCA
	t.Cleanup(func() { globalClusterCA = orig })

	// No cluster CA (the normal state on a data-plane node): the expiry series
	// must be OMITTED, not reported as 0 — 0 reads as "expires now" and would
	// page on every node that has no cluster CA at all.
	globalClusterCA = &clusterCA{}
	var w strings.Builder
	clusterCAWriteUsabilityPrometheus(&w)
	if out := w.String(); strings.Contains(out, "culvert_cluster_ca_expires_in_seconds ") {
		t.Error("expiry series emitted with no cluster CA loaded")
	} else if !strings.Contains(out, "culvert_cluster_ca_usable 0") {
		t.Errorf("want culvert_cluster_ca_usable 0, got:\n%s", out)
	}

	globalClusterCA = loadTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	w.Reset()
	clusterCAWriteUsabilityPrometheus(&w)
	for _, want := range []string{
		"culvert_cluster_ca_usable 1",
		"culvert_cluster_ca_expires_in_seconds ",
		"culvert_cluster_ca_sign_refused_total 0",
		"culvert_cluster_ca_node_cert_clamped_total 0",
	} {
		if !strings.Contains(w.String(), want) {
			t.Errorf("missing metric %q in:\n%s", want, w.String())
		}
	}

	globalClusterCA = loadTestClusterCA(t, time.Now().Add(-2*365*24*time.Hour), time.Now().Add(-24*time.Hour))
	w.Reset()
	clusterCAWriteUsabilityPrometheus(&w)
	if !strings.Contains(w.String(), "culvert_cluster_ca_usable 0") {
		t.Errorf("expired cluster CA must report usable 0:\n%s", w.String())
	}
}

func TestClusterCA_HealthzRowTracksUsability(t *testing.T) {
	orig := globalClusterCA
	t.Cleanup(func() { globalClusterCA = orig })

	globalClusterCA = &clusterCA{}
	if got := clusterCAHealthState(); got != "absent" {
		t.Errorf("no CA: cluster_ca = %q, want absent", got)
	}
	globalClusterCA = loadTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if got := clusterCAHealthState(); got != "ready" {
		t.Errorf("healthy CA: cluster_ca = %q, want ready", got)
	}
	globalClusterCA = loadTestClusterCA(t, time.Now().Add(-2*365*24*time.Hour), time.Now().Add(-24*time.Hour))
	if got := clusterCAHealthState(); got != "expired" {
		t.Errorf("expired CA: cluster_ca = %q, want expired — the probe stayed "+
			"green through a fleet-wide enrollment outage before this row existed", got)
	}
}

// ─── Token preservation on an unusable-CA refusal ───────────────────────────

// An enrollment token is single-use and its consumption is PERSISTED. A
// precondition failure that is not the caller's fault must therefore not spend
// it: burning a token on a CA that cannot sign leaves the node unable to retry
// once the CA is repaired, and an admin has to mint and distribute a
// replacement. Found in review of the CHAOS-50 fail-closed gate — the guard was
// correct but sat downstream of ValidateAndConsumeToken.
func TestEnroll_UnusableCADoesNotConsumeToken(t *testing.T) {
	captureClusterCAAlerts(t)
	origStore, origCA := globalClusterStore, globalClusterCA
	t.Cleanup(func() {
		globalClusterStore = origStore
		globalClusterCA = origCA
	})
	globalClusterStore = newTestClusterStore(t)
	globalClusterCA = loadTestClusterCA(t,
		time.Now().Add(-2*365*24*time.Hour), time.Now().Add(-24*time.Hour))

	token, err := globalClusterStore.GenerateToken("", "", "admin", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	reqJSON, _ := json.Marshal(EnrollRequest{
		Token: token, NodeID: "dp-1", CSR: string(newTestCSR(t, "dp-1")),
	})

	srv := &controlPlaneServer{}
	if _, err := srv.Enroll(context.Background(), reqJSON); err == nil {
		t.Fatal("enrollment against an expired cluster CA must be refused")
	} else if !strings.Contains(err.Error(), "cannot issue") {
		t.Errorf("refusal should name the cause: %v", err)
	}

	if !globalClusterStore.TokenExists(token) {
		t.Fatal("the enrollment token was CONSUMED by a refusal that was not the " +
			"caller's fault — after the CA is repaired the node cannot retry and an " +
			"admin must mint and distribute a replacement")
	}
	if _, registered := globalClusterStore.GetNode("dp-1"); registered {
		t.Error("a refused enrollment must not register the node")
	}
	if snap := clusterCAUsabilityFailures(); snap.Refusals != 1 {
		t.Errorf("refusals = %d, want exactly 1 (the precondition returns before "+
			"SignCSR, so the refusal must not be double-counted)", snap.Refusals)
	}

	// And the token still works once the CA is usable again — the whole point.
	globalClusterCA = loadTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if _, err := srv.Enroll(context.Background(), reqJSON); err != nil {
		t.Fatalf("the preserved token must enroll once the CA is repaired: %v", err)
	}
	if _, registered := globalClusterStore.GetNode("dp-1"); !registered {
		t.Error("node should be registered after the successful retry")
	}
}

// The same rule for the pre-existing "not initialized" precondition, which had
// the identical shape.
func TestEnroll_UninitializedCADoesNotConsumeToken(t *testing.T) {
	origStore, origCA := globalClusterStore, globalClusterCA
	t.Cleanup(func() {
		globalClusterStore = origStore
		globalClusterCA = origCA
	})
	globalClusterStore = newTestClusterStore(t)
	globalClusterCA = &clusterCA{} // never initialized

	token, err := globalClusterStore.GenerateToken("", "", "admin", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	reqJSON, _ := json.Marshal(EnrollRequest{
		Token: token, NodeID: "dp-2", CSR: string(newTestCSR(t, "dp-2")),
	})

	srv := &controlPlaneServer{}
	if _, err := srv.Enroll(context.Background(), reqJSON); err == nil {
		t.Fatal("enrollment with no cluster CA must be refused")
	}
	if !globalClusterStore.TokenExists(token) {
		t.Error("an uninitialized cluster CA consumed the enrollment token")
	}
}
