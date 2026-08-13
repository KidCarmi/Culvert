package main

// cluster_ca_validity_test.go — CHAOS-50 / register row CA-13.
//
// Each test here corresponds to a defect reproduced against main before the fix
// was written. The bar is the CHAOS-28 one: assert the OUTCOME an operator or a
// data-plane node would observe, not the shape of the code that produces it.

import (
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

// ── helpers ──────────────────────────────────────────────────────────────────

// newTestClusterCA builds a self-signed cluster CA with an explicit validity
// window and a writable persistence directory.
func newTestClusterCA(t *testing.T, notBefore, notAfter time.Time) *clusterCA {
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

func newTestCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "dp-node-1"}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func parseLeafPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		t.Fatal("no PEM block in signed certificate")
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

// ── fail-closed signing ──────────────────────────────────────────────────────

// TestClusterCA_ExpiredCARefusesToSign is the core CA-13 assertion. Before the
// fix an expired cluster CA signed happily and the RPC reported success; the
// certificate was rejected by every peer that tried to use it.
func TestClusterCA_ExpiredCARefusesToSign(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	ca := newTestClusterCA(t, time.Now().Add(-10*365*24*time.Hour), time.Now().Add(-24*time.Hour))

	if _, _, _, err := ca.SignCSR(newTestCSR(t), "dp-node-1"); err == nil {
		t.Fatal("expired cluster CA signed a node certificate; must fail closed")
	} else if !errors.Is(err, errClusterCAUnusable) {
		t.Fatalf("error must be errClusterCAUnusable so callers can classify it; got %v", err)
	}

	if got := clusterCAUsabilityFailures().SignRefusals; got != 1 {
		t.Fatalf("SignRefusals = %d, want 1 — the refusal must be counted, not just returned", got)
	}
	if !clusterCAUsabilityDegraded() {
		t.Fatal("a refusal with no successful verification since must read as degraded")
	}
}

// TestClusterCA_NotYetValidRefusesToSign covers the other end of the window —
// the clock-rollback / restored-VM case.
func TestClusterCA_NotYetValidRefusesToSign(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	ca := newTestClusterCA(t, time.Now().Add(24*time.Hour), time.Now().Add(365*24*time.Hour))
	if _, _, _, err := ca.SignCSR(newTestCSR(t), "dp-node-1"); !errors.Is(err, errClusterCAUnusable) {
		t.Fatalf("not-yet-valid cluster CA must fail closed; got %v", err)
	}
}

// TestClusterCA_ClockSkewToleranceKeepsMarginalCAUsable pins the other half of
// the same contract: a few minutes of skew must not brick the cluster PKI.
func TestClusterCA_ClockSkewToleranceKeepsMarginalCAUsable(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	// Expired one minute ago — inside the 5-minute tolerance.
	ca := newTestClusterCA(t, time.Now().Add(-365*24*time.Hour), time.Now().Add(-1*time.Minute))
	if err := ca.Usable(); err != nil {
		t.Fatalf("a CA one minute past NotAfter is within tolerance and must stay usable; got %v", err)
	}

	// Not valid for another minute — also inside the tolerance.
	ca2 := newTestClusterCA(t, time.Now().Add(1*time.Minute), time.Now().Add(365*24*time.Hour))
	if err := ca2.Usable(); err != nil {
		t.Fatalf("a CA one minute before NotBefore is within tolerance and must stay usable; got %v", err)
	}
}

// TestClusterCA_UsableIsDistinctFromReady pins the separation deliberately drawn
// in usableLocked's comment. Folding validity into Ready() would switch the
// enrollment surface off entirely at expiry, which reads as a misconfiguration
// rather than as the expiry it is.
func TestClusterCA_UsableIsDistinctFromReady(t *testing.T) {
	ca := newTestClusterCA(t, time.Now().Add(-10*365*24*time.Hour), time.Now().Add(-24*time.Hour))
	if !ca.Ready() {
		t.Fatal("Ready() must stay true for a loaded-but-expired CA")
	}
	if ca.Usable() == nil {
		t.Fatal("Usable() must report the expired window")
	}
}

// ── issuer clamp ─────────────────────────────────────────────────────────────

// TestClusterCA_NodeCertClampedToIssuer proves a node certificate can never
// outlive the CA that signed it.
func TestClusterCA_NodeCertClampedToIssuer(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	caExpiry := time.Now().Add(20 * 24 * time.Hour) // CA dies well inside a 1-year leaf
	ca := newTestClusterCA(t, time.Now().Add(-time.Hour), caExpiry)

	certPEM, _, expiry, err := ca.SignCSR(newTestCSR(t), "dp-node-1")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if expiry.After(caExpiry) {
		t.Fatalf("returned expiry %s outlives the issuer's %s", expiry, caExpiry)
	}
	leaf := parseLeafPEM(t, certPEM)
	if leaf.NotAfter.After(ca.cert.NotAfter) {
		t.Fatalf("leaf NotAfter %s outlives issuer NotAfter %s", leaf.NotAfter, ca.cert.NotAfter)
	}
	if leaf.NotBefore.Before(ca.cert.NotBefore) {
		t.Fatalf("leaf NotBefore %s precedes issuer NotBefore %s", leaf.NotBefore, ca.cert.NotBefore)
	}
	// The returned expiry is what the CP records on the node roster, so it must
	// agree with the certificate actually issued.
	if !expiry.Equal(leaf.NotAfter) {
		t.Fatalf("returned expiry %s disagrees with the issued leaf %s", expiry, leaf.NotAfter)
	}
	if got := clusterCAUsabilityFailures().Clamps; got != 1 {
		t.Fatalf("Clamps = %d, want 1 — the clamp is the early-warning signal and must be counted", got)
	}
}

// TestClusterCA_UnclampedLeafIsLeftAloneWhenIssuerOutlivesIt is the
// no-op half: on a healthy CA nothing changes and nothing is counted.
func TestClusterCA_UnclampedLeafIsLeftAloneWhenIssuerOutlivesIt(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	ca := newTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	_, _, expiry, err := ca.SignCSR(newTestCSR(t), "dp-node-1")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	// Still the ordinary 1-year node-certificate lifetime.
	if d := time.Until(expiry); d < 364*24*time.Hour || d > 366*24*time.Hour {
		t.Fatalf("healthy CA must issue the standard ~1y node cert; got %v", d)
	}
	if got := clusterCAUsabilityFailures().Clamps; got != 0 {
		t.Fatalf("Clamps = %d, want 0 on a CA that outlives its leaves", got)
	}
}

// TestClusterCA_ClampMakesRenewalFireInsideTheOverlapWindow is the recovery
// assertion, and the reason the clamp matters more here than it did for the
// inspection CA.
//
// The DP renewal loop reads the LEAF's NotAfter (certNeedsRenewal, 30 days).
// Unclamped, a leaf minted in the CA's final year reported ~365 days of life,
// so a node stayed quiet straight through the 30-day dual-CA overlap — the one
// window in which it could still have re-keyed itself — and came out the other
// side unable to reach the RPC that would have fixed it. Clamped, the leaf's
// renewal threshold and the CA's rotation threshold are the same moment.
func TestClusterCA_ClampMakesRenewalFireInsideTheOverlapWindow(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	// A CA inside its own rotation window: RotateIfNeeded fires at 30 days.
	ca := newTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(20*24*time.Hour))
	certPEM, _, _, err := ca.SignCSR(newTestCSR(t), "dp-node-1")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}

	certFile := filepath.Join(t.TempDir(), "node.crt")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	days, needs := certNeedsRenewal(certFile)
	if !needs {
		t.Fatalf("node cert reports %d days left and does NOT need renewal, but its issuer expires in 20 days — "+
			"the node would sleep through the overlap window and require manual re-enrollment", days)
	}
	if days > 30 {
		t.Fatalf("clamped leaf should be inside the 30-day renewal threshold; got %d days", days)
	}
}

// ── import / rotation state integrity ────────────────────────────────────────

// TestClusterCA_ImportFailureLeavesNoPhantomOverlap: a persist failure must not
// publish a dual-CA overlap that never happened.
func TestClusterCA_ImportFailureLeavesNoPhantomOverlap(t *testing.T) {
	ca := newTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	origCert, origPEM := ca.cert, ca.certPEM
	ca.dir = filepath.Join(t.TempDir(), "does-not-exist") // writes fail

	replacement := newTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	keyDER, err := x509.MarshalECPrivateKey(replacement.key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := ca.ImportCA(replacement.certPEM, newKeyPEM); err == nil {
		t.Skip("persist unexpectedly succeeded — cannot exercise the failure path here")
	}

	if ca.SecondaryActive() {
		t.Fatal("a FAILED import reported an active dual-CA overlap; Info() and the admin panel would show " +
			"a rotation in flight that never started")
	}
	if ca.cert != origCert {
		t.Fatal("a failed import must leave the active CA untouched")
	}
	if string(ca.certPEM) != string(origPEM) {
		t.Fatal("a failed import must leave the active CA PEM untouched")
	}
}

// TestClusterCA_FirstImportWithNoPriorCADoesNotPanic: POST /api/cluster/ca has
// no Ready() precondition, so the first import onto a node with no cluster CA
// used to dereference a nil secondary.
func TestClusterCA_FirstImportWithNoPriorCADoesNotPanic(t *testing.T) {
	empty := &clusterCA{dir: t.TempDir()}

	fresh := newTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	keyDER, err := x509.MarshalECPrivateKey(fresh.key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := empty.ImportCA(fresh.certPEM, keyPEM); err != nil {
		t.Fatalf("first import onto an empty cluster CA: %v", err)
	}
	if !empty.Ready() {
		t.Fatal("cluster CA should be ready after a first import")
	}
	if empty.SecondaryActive() {
		t.Fatal("a first import has no predecessor and must not report a dual-CA overlap")
	}
}

// TestClusterCA_RotationFailureIsCountedAndSurfaced: the CA-13 observability
// gap. A rotation that keeps failing had no counter, no alert and no health
// signal — only a log line, in the 30-day window that is the last chance to fix
// it before a fleet-wide mTLS outage.
func TestClusterCA_RotationFailureIsCountedAndSurfaced(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	// A CA inside its rotation window whose directory cannot be written.
	ca := newTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour))
	ca.dir = filepath.Join(t.TempDir(), "read-only-does-not-exist")

	ca.RotateIfNeeded()

	snap := clusterCAUsabilityFailures()
	if snap.RotationFailures == 0 {
		t.Fatal("a failed auto-rotation must increment culvert_cluster_ca_rotation_failures_total")
	}
	info := ca.Info()
	if info["lastRotationError"] == nil {
		t.Fatal("the failure must be surfaced on the admin API, not only in the log")
	}
	if got, ok := info["rotationFailures"].(int64); !ok || got == 0 {
		t.Fatalf("Info() must carry the rotation-failure count; got %v", info["rotationFailures"])
	}
}

// ── health plane ─────────────────────────────────────────────────────────────

// TestClusterCA_RecoveryRequiresObservedEvidence: silence is not recovery. A
// still-expired cluster CA looks exactly like a healthy one on a quiet cluster.
func TestClusterCA_RecoveryRequiresObservedEvidence(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	noteClusterCASignRefused("expired 2026-01-01T00:00:00Z")
	if !clusterCAUsabilityDegraded() {
		t.Fatal("degraded after an observed refusal")
	}

	// Time passing changes nothing.
	if !clusterCAUsabilityDegraded() {
		t.Fatal("degraded state must not clear on its own")
	}

	// An OBSERVED usable verification is what clears it.
	noteClusterCAUsable()
	if clusterCAUsabilityDegraded() {
		t.Fatal("an observed usable verification must clear the degraded state")
	}
}

// TestClusterCA_UnusableAlertIsRateLimitedButTheCounterIsNot: the alert-producer
// contract. An expired cluster CA drives the whole fleet into a retry loop at
// once, so the signal must be gated while the magnitude must not be lost.
func TestClusterCA_UnusableAlertIsRateLimitedButTheCounterIsNot(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	var alerts int
	orig := fireClusterCAAlert
	fireClusterCAAlert = func(string) { alerts++ }
	t.Cleanup(func() { fireClusterCAAlert = orig })

	const n = 50
	for i := 0; i < n; i++ {
		noteClusterCASignRefused("expired 2026-01-01T00:00:00Z")
	}

	if got := clusterCAUsabilityFailures().SignRefusals; got != n {
		t.Fatalf("SignRefusals = %d, want %d — rate limiting must never cost magnitude", got, n)
	}
	if alerts != 1 {
		t.Fatalf("alerts = %d, want 1 — %d refusals inside one interval must produce one alert", alerts, n)
	}
}

// TestClusterCA_AlertCarriesNoKeyMaterial pins the metrics/alert contract: the
// detail names the condition and the count, never a fingerprint, serial, subject
// or node ID.
func TestClusterCA_AlertCarriesNoKeyMaterial(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	var detail string
	orig := fireClusterCAAlert
	fireClusterCAAlert = func(d string) { detail = d }
	t.Cleanup(func() { fireClusterCAAlert = orig })

	noteClusterCASignRefused("expired 2026-01-01T00:00:00Z")
	for _, banned := range []string{"BEGIN", "PRIVATE KEY", "CERTIFICATE"} {
		if strings.Contains(detail, banned) {
			t.Fatalf("alert detail leaked %q: %s", banned, detail)
		}
	}
	if !strings.Contains(detail, "cluster CA") {
		t.Fatalf("alert detail must name the subsystem; got %q", detail)
	}
}

// ── observability surfaces ───────────────────────────────────────────────────

// TestClusterCA_MetricsExposeUsabilitySeries pins the scrapeable contract.
// culvert_cluster_ca_rotations_total counts only successes, so before these an
// operator could not distinguish "not due for rotation" from "failing daily".
func TestClusterCA_MetricsExposeUsabilitySeries(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	origCA := globalClusterCA
	t.Cleanup(func() { globalClusterCA = origCA })
	globalClusterCA = newTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour))

	var sb strings.Builder
	clusterCAWriteUsabilityPrometheus(&sb)
	out := sb.String()

	for _, want := range []string{
		"culvert_cluster_ca_usable 1",
		"culvert_cluster_ca_expires_in_seconds",
		"culvert_cluster_ca_sign_refused_total 0",
		"culvert_cluster_ca_rotation_failures_total 0",
		"culvert_cluster_ca_cert_clamped_total 0",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics missing %q\n%s", want, out)
		}
	}
}

// TestClusterCA_ExpirySeriesOmittedWhenNoCA: exporting 0 would read as "expires
// now" and page on every standalone node that has no cluster CA at all.
func TestClusterCA_ExpirySeriesOmittedWhenNoCA(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	origCA := globalClusterCA
	t.Cleanup(func() { globalClusterCA = origCA })
	globalClusterCA = &clusterCA{}

	var sb strings.Builder
	clusterCAWriteUsabilityPrometheus(&sb)
	out := sb.String()

	if strings.Contains(out, "culvert_cluster_ca_expires_in_seconds") {
		t.Fatalf("expiry series must be omitted when no cluster CA is loaded:\n%s", out)
	}
	if !strings.Contains(out, "culvert_cluster_ca_usable 0") {
		t.Fatalf("usable gauge must still report 0:\n%s", out)
	}
}

// TestClusterCA_HealthzReportsExpiredNotReady: /healthz used to say nothing at
// all about the cluster CA, so the probe stayed green through a total
// cluster-PKI outage.
func TestClusterCA_HealthzReportsExpiredNotReady(t *testing.T) {
	origCA := globalClusterCA
	t.Cleanup(func() { globalClusterCA = origCA })

	globalClusterCA = newTestClusterCA(t, time.Now().Add(-10*365*24*time.Hour), time.Now().Add(-24*time.Hour))
	if got := computeHealth().ClusterCA; got != "expired" {
		t.Fatalf("healthz cluster_ca = %q, want \"expired\"", got)
	}

	globalClusterCA = newTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if got := computeHealth().ClusterCA; got != "ready" {
		t.Fatalf("healthz cluster_ca = %q, want \"ready\"", got)
	}

	globalClusterCA = &clusterCA{}
	if got := computeHealth().ClusterCA; got != "not_configured" {
		t.Fatalf("healthz cluster_ca = %q, want \"not_configured\"", got)
	}
}

// TestClusterCA_ReadyzRowIsReportOnly pins both halves: the row appears and
// fails, and it never gates the verdict — a control plane must stay reachable
// so an operator can import a replacement CA through its own admin UI.
func TestClusterCA_ReadyzRowIsReportOnly(t *testing.T) {
	origCA := globalClusterCA
	t.Cleanup(func() { globalClusterCA = origCA })
	globalClusterCA = newTestClusterCA(t, time.Now().Add(-10*365*24*time.Hour), time.Now().Add(-24*time.Hour))

	checks := map[string]*readinessCheck{}
	appendClusterCAReadinessCheck(checks)

	row, ok := checks["cluster_ca"]
	if !ok {
		t.Fatal("expired cluster CA must produce a cluster_ca readiness row")
	}
	if row.Status != "fail" {
		t.Fatalf("cluster_ca row status = %q, want \"fail\"", row.Status)
	}
	// Unauthenticated surface: fixed detail, no expiry date or path.
	if strings.Contains(row.Detail, "20") {
		t.Fatalf("cluster_ca detail must not carry dates on an unauthenticated surface: %q", row.Detail)
	}

	// No cluster CA at all → no row (matches the `ca` row's behaviour).
	globalClusterCA = &clusterCA{}
	checks2 := map[string]*readinessCheck{}
	appendClusterCAReadinessCheck(checks2)
	if _, ok := checks2["cluster_ca"]; ok {
		t.Fatal("a node with no cluster CA must not get a cluster_ca row")
	}
}

// TestClusterCA_InfoSurfacesUsability pins the admin-API contract the GUI banner
// renders from.
func TestClusterCA_InfoSurfacesUsability(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	ca := newTestClusterCA(t, time.Now().Add(-10*365*24*time.Hour), time.Now().Add(-24*time.Hour))
	info := ca.Info()

	if usable, ok := info["usable"].(bool); !ok || usable {
		t.Fatalf("Info().usable = %v, want false for an expired CA", info["usable"])
	}
	if reason, _ := info["unusableReason"].(string); reason == "" {
		t.Fatal("Info() must name why the CA is unusable")
	}
	if days, ok := info["expiresInDays"].(int); !ok || days > 0 {
		t.Fatalf("Info().expiresInDays = %v, want negative for an expired CA", info["expiresInDays"])
	}
}

// TestClusterCA_DiagnosticsRowReportsTheOutage pins the operator-contract row.
// It is a viewer-role surface, so it carries impact and a count — never the
// validity window itself, which names the appliance's exact certificate state.
func TestClusterCA_DiagnosticsRowReportsTheOutage(t *testing.T) {
	resetClusterCAHealthForTest()
	t.Cleanup(resetClusterCAHealthForTest)

	origCA := globalClusterCA
	t.Cleanup(func() { globalClusterCA = origCA })

	globalClusterCA = newTestClusterCA(t, time.Now().Add(-10*365*24*time.Hour), time.Now().Add(-24*time.Hour))
	row := checkClusterCA()
	if row.Code != "cluster_ca" || row.Status != diagFail {
		t.Fatalf("expired cluster CA: code=%q status=%q, want cluster_ca/fail", row.Code, row.Status)
	}
	if row.OperatorAction == "" {
		t.Fatal("a failing row must name the remedy")
	}
	if strings.Contains(row.Message, "20") {
		t.Fatalf("viewer-role row must not carry the validity window: %q", row.Message)
	}

	// Healthy CA, but auto-rotation has been failing: warn while there is still
	// time to act, because that is what makes the fail row above inevitable.
	globalClusterCA = newTestClusterCA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if got := checkClusterCA(); got.Status != diagOK {
		t.Fatalf("healthy cluster CA: status=%q, want ok", got.Status)
	}
	noteClusterCARotationFailure("import", errors.New("read-only file system"))
	if got := checkClusterCA(); got.Status != diagWarn {
		t.Fatalf("failing rotation on a still-valid CA: status=%q, want warn", got.Status)
	}

	// No cluster CA at all is the ordinary standalone case, not a degradation.
	globalClusterCA = &clusterCA{}
	if got := checkClusterCA(); got.Status != diagOK {
		t.Fatalf("standalone node with no cluster CA: status=%q, want ok", got.Status)
	}
}

// ── startup wiring ───────────────────────────────────────────────────────────

// TestClusterCA_RotationLoopNotGatedOnInspectionCA pins the decoupling.
//
// StartCAAutoRotation drives BOTH CAs. Gating it on certMgr.Ready() meant an
// inspection-CA load failure — a corrupt bundle, a wrong CULVERT_CA_PASSPHRASE,
// an unwritable directory, all of which are ALREADY an accepted fail-open
// degradation for inspection (register row CA-3) — also switched off cluster-CA
// auto-rotation on a control plane, whose only symptom appears years later as a
// fleet-wide mTLS outage with no rotation ever attempted.
//
// Asserted at the source, because the coupling IS the wiring: the two
// subsystems share nothing but a ticker, and the defect is a guard around one
// call, not a behaviour reachable from a single unit under test.
func TestClusterCA_RotationLoopNotGatedOnInspectionCA(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "rootca_startup.go"))
	if err != nil {
		t.Fatalf("read rootca_startup.go: %v", err)
	}
	// Strip line comments first: this file DOCUMENTS the removed guard, and a
	// naive scan would match the explanation instead of the code.
	var stripped []string
	for _, line := range strings.Split(string(src), "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "//") {
			continue
		}
		stripped = append(stripped, line)
	}
	body := strings.Join(stripped, "\n")

	idx := strings.Index(body, "StartCAAutoRotation(ctx")
	if idx < 0 {
		t.Fatal("loadRootCA no longer starts the CA auto-rotation loop")
	}
	// Scan back to the start of the statement's enclosing block and reject a
	// certMgr.Ready() condition guarding the call.
	head := body[:idx]
	if lastIf := strings.LastIndex(head, "\tif "); lastIf >= 0 {
		guard := head[lastIf:]
		if strings.Contains(guard, "certMgr.Ready()") {
			t.Fatal("StartCAAutoRotation is gated on certMgr.Ready() again — an inspection-CA load failure " +
				"would silently disable CLUSTER-CA auto-rotation too (CHAOS-50 / CA-13)")
		}
	}
}
