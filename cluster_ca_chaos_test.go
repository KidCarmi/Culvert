package main

// cluster_ca_chaos_test.go — CHAOS-50 regression gates for the cluster
// (enrollment) CA across its lifecycle. Register row CA-13.
//
// Every gate here was verified to FAIL against the pre-fix tree before the fix
// landed. They are the executable half of
// docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-19.md.
//
// The tests drive validity with an explicit clock or a purpose-built CA rather
// than waiting ten years for the real one to expire.

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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ca"
)

// ── helpers ─────────────────────────────────────────────────────────────────

// newClusterCAWithWindow builds a persisted cluster CA whose own validity is
// exactly the requested window, so a test can put the CA anywhere in its
// lifecycle without a clock injection seam.
func newClusterCAWithWindow(t *testing.T, dir string, notBefore, notAfter time.Time) *clusterCA {
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
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return &clusterCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		dir:     dir,
	}
}

func newTestCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// installClusterCA swaps the process-global cluster CA for the duration of the
// test and restores it afterwards, mirroring the swapAutoExclude convention
// (the fence-pollution class: a global left mutated makes an unrelated test
// fail under -shuffle).
func installClusterCA(t *testing.T, c *clusterCA) {
	t.Helper()
	prev := globalClusterCA
	globalClusterCA = c
	resetClusterCAHealthForTest()
	t.Cleanup(func() {
		globalClusterCA = prev
		resetClusterCAHealthForTest()
	})
}

// captureClusterCAAlerts replaces the alert seam so a test observes the
// transition synchronously instead of racing the process-global sink.
func captureClusterCAAlerts(t *testing.T) *[]string {
	t.Helper()
	var got []string
	prev := fireClusterCAAlert
	fireClusterCAAlert = func(detail string) { got = append(got, detail) }
	t.Cleanup(func() { fireClusterCAAlert = prev })
	return &got
}

// ── 1. The sign path fails closed ───────────────────────────────────────────

// TestChaos50_ExpiredClusterCARefusesToSign is the core gate. Pre-fix this
// SUCCEEDED: x509.CreateCertificate does not check the parent's validity, so the
// control plane minted a node identity that no peer could ever verify — and
// because Enroll needs no client cert, the operator's recovery action reported
// success while handing back a dead certificate.
func TestChaos50_ExpiredClusterCARefusesToSign(t *testing.T) {
	c := newClusterCAWithWindow(t, t.TempDir(),
		time.Now().Add(-400*24*time.Hour), time.Now().Add(-24*time.Hour))
	installClusterCA(t, c)
	alerts := captureClusterCAAlerts(t)

	// Ready() must stay TRUE: an expired CA is installed, and reporting it as
	// "not configured" would hide a trust outage behind a setup message.
	if !c.Ready() {
		t.Fatal("Ready() must still report an installed CA")
	}
	if err := c.Usable(); err == nil {
		t.Fatal("Usable() reported an expired CA as usable")
	}

	certPEM, serial, expiry, err := c.SignCSR(newTestCSR(t, "node-1"), "node-1")
	if err == nil {
		t.Fatalf("DEFECT: expired cluster CA signed a node cert (%d bytes, serial %s, expiry %s)",
			len(certPEM), serial, expiry)
	}
	if !errors.Is(err, errClusterCAUnusable) {
		t.Fatalf("error does not wrap errClusterCAUnusable: %v", err)
	}
	if certPEM != nil || serial != "" || !expiry.IsZero() {
		t.Fatalf("refusal returned partial output: cert=%d serial=%q expiry=%v", len(certPEM), serial, expiry)
	}

	snap := clusterCAFailures()
	if snap.SignRefusals != 1 {
		t.Fatalf("SignRefusals = %d, want 1", snap.SignRefusals)
	}
	if !clusterCAUsabilityDegraded() {
		t.Fatal("usability not reported degraded after a refusal")
	}
	if len(*alerts) != 1 {
		t.Fatalf("alerts fired = %d, want 1", len(*alerts))
	}
	if !strings.Contains((*alerts)[0], "UNUSABLE") {
		t.Fatalf("alert does not state the condition: %q", (*alerts)[0])
	}
}

// TestChaos50_ClockRollbackRefusesButSkewToleranceHolds pins both ends of the
// NotBefore guard. A CP that boots with a bad RTC must not fence its own fleet
// out over a few seconds of skew (the tolerance), but a genuine rollback past
// the CA's start must fail closed.
func TestChaos50_ClockRollbackRefusesButSkewToleranceHolds(t *testing.T) {
	now := time.Now()

	// Inside tolerance: NotBefore 1 minute in the future → still usable.
	near := newClusterCAWithWindow(t, t.TempDir(), now.Add(1*time.Minute), now.Add(3650*24*time.Hour))
	installClusterCA(t, near)
	if err := near.Usable(); err != nil {
		t.Fatalf("CA within the %s skew tolerance reported unusable: %v", clusterCAClockSkewTolerance, err)
	}
	if _, _, _, err := near.SignCSR(newTestCSR(t, "node-ok"), "node-ok"); err != nil {
		t.Fatalf("sign refused inside the skew tolerance: %v", err)
	}

	// Beyond tolerance: a real rollback → refuse, and say why.
	far := newClusterCAWithWindow(t, t.TempDir(),
		now.Add(clusterCAClockSkewTolerance+time.Hour), now.Add(3650*24*time.Hour))
	installClusterCA(t, far)
	err := far.Usable()
	if err == nil {
		t.Fatal("a not-yet-valid CA beyond the skew tolerance reported usable")
	}
	if !strings.Contains(err.Error(), "clock") {
		t.Fatalf("reason does not point at the clock: %v", err)
	}
	if _, _, _, err := far.SignCSR(newTestCSR(t, "node-bad"), "node-bad"); !errors.Is(err, errClusterCAUnusable) {
		t.Fatalf("sign not refused beyond the skew tolerance: %v", err)
	}
}

// ── 2. The clamp ────────────────────────────────────────────────────────────

// TestChaos50_NodeCertNeverOutlivesIssuer proves the clamp. Pre-fix a node cert
// signed by a CA with 10 days left claimed a FULL YEAR — so the nodes API, and
// the node's own expiry check, both reported ~355 days of validity that did not
// exist. The cert must also actually verify against its issuer, which is the
// property the clamp exists to keep true for the whole of its stated life.
func TestChaos50_NodeCertNeverOutlivesIssuer(t *testing.T) {
	caExp := time.Now().Add(10 * 24 * time.Hour)
	c := newClusterCAWithWindow(t, t.TempDir(), time.Now().Add(-100*24*time.Hour), caExp)
	installClusterCA(t, c)

	certPEM, _, expiry, err := c.SignCSR(newTestCSR(t, "node-1"), "node-1")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if expiry.After(caExp) {
		t.Fatalf("DEFECT: node cert expiry %s outlives issuer %s by %s",
			expiry.Format(time.RFC3339), caExp.Format(time.RFC3339), expiry.Sub(caExp).Round(time.Hour))
	}
	// x509 encodes validity at second granularity, so compare truncated.
	if !expiry.Equal(caExp.Truncate(time.Second)) {
		t.Fatalf("expiry = %s, want the issuer's %s", expiry, caExp.Truncate(time.Second))
	}

	// The returned expiry must match what is actually inside the certificate —
	// the CP persists this value onto the EnrolledNode record, and a mismatch
	// would make the fleet view lie in a different way.
	blk, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	if !leaf.NotAfter.Equal(expiry) {
		t.Fatalf("cert NotAfter %s != reported expiry %s", leaf.NotAfter, expiry)
	}
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("clamped cert does not verify against its own issuer: %v", err)
	}

	if snap := clusterCAFailures(); snap.ClampedIssuances != 1 {
		t.Fatalf("ClampedIssuances = %d, want 1", snap.ClampedIssuances)
	}
}

// TestChaos50_HealthyCAIssuesUnchangedOneYearCert is the negative half: on a
// healthy CA (which is what every node in a correctly-rotating fleet signs
// against) issuance must be byte-for-byte the pre-fix behaviour — a full year,
// no clamp, no refusal, no counter movement.
func TestChaos50_HealthyCAIssuesUnchangedOneYearCert(t *testing.T) {
	c := newClusterCAWithWindow(t, t.TempDir(),
		time.Now().Add(-1*time.Hour), time.Now().Add(10*365*24*time.Hour))
	installClusterCA(t, c)

	before := time.Now()
	_, _, expiry, err := c.SignCSR(newTestCSR(t, "node-1"), "node-1")
	if err != nil {
		t.Fatalf("SignCSR on a healthy CA: %v", err)
	}
	want := before.Add(365 * 24 * time.Hour)
	if expiry.Sub(want) > time.Minute || want.Sub(expiry) > time.Minute {
		t.Fatalf("expiry = %s, want ~%s (the unchanged 1-year window)", expiry, want)
	}
	snap := clusterCAFailures()
	if snap.ClampedIssuances != 0 || snap.SignRefusals != 0 {
		t.Fatalf("healthy issuance moved a fault counter: clamped=%d refused=%d",
			snap.ClampedIssuances, snap.SignRefusals)
	}
	if clusterCAUsabilityDegraded() {
		t.Fatal("healthy CA reported degraded")
	}
}

// ── 3. Rotation observability + recovery on evidence ────────────────────────

// TestChaos50_RotationFailureIsCountedAndAlerted closes the CA-13 silent-failure
// half: pre-fix a rotation failure reached Info() and nothing else, so a CP with
// a read-only CA directory looked identical to a healthy one on /metrics,
// /healthz, /readyz, /api/diagnostics and every alerting rule.
func TestChaos50_RotationFailureIsCountedAndAlerted(t *testing.T) {
	c := newClusterCAWithWindow(t, t.TempDir(),
		time.Now().Add(-1*time.Hour), time.Now().Add(10*365*24*time.Hour))
	installClusterCA(t, c)

	c.recordRotationFailure(errors.New("open /data/cluster-ca.crt: read-only file system"))

	snap := clusterCAFailures()
	if snap.RotationFailures != 1 {
		t.Fatalf("RotationFailures = %d, want 1", snap.RotationFailures)
	}
	if !snap.RotationDegraded {
		t.Fatal("RotationDegraded false immediately after a failure")
	}
	if !clusterCARotationDegraded() {
		t.Fatal("clusterCARotationDegraded() false immediately after a failure")
	}
	if snap.RotationErr == "" {
		t.Fatal("no rotation error recorded")
	}
}

// TestChaos50_RotationDegradedClearsOnEvidenceOnly is the storage_health.go
// contract: an operator who fixes the volume and imports a replacement has
// resolved this, and the warning must clear — but ONLY on an observed successful
// rotation, never because time passed. Also pins that the CUMULATIVE counter
// does not go backwards (it feeds a Prometheus counter).
func TestChaos50_RotationDegradedClearsOnEvidenceOnly(t *testing.T) {
	dir := t.TempDir()
	c := newClusterCAWithWindow(t, dir, time.Now().Add(-1*time.Hour), time.Now().Add(10*365*24*time.Hour))
	installClusterCA(t, c)

	c.recordRotationFailure(errors.New("disk full"))
	if !clusterCARotationDegraded() {
		t.Fatal("not degraded after a failure")
	}

	// Elapsed time alone must not clear it.
	time.Sleep(5 * time.Millisecond)
	if !clusterCARotationDegraded() {
		t.Fatal("degraded state cleared without evidence — silence is not recovery")
	}

	// A real, landed rotation is the evidence.
	replacement := newClusterCAWithWindow(t, dir, time.Now().Add(-1*time.Hour), time.Now().Add(10*365*24*time.Hour))
	keyDER, err := x509.MarshalECPrivateKey(replacement.key)
	if err != nil {
		t.Fatalf("marshal replacement key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := c.ImportCA(replacement.certPEM, keyPEM); err != nil {
		t.Fatalf("ImportCA: %v", err)
	}
	if clusterCARotationDegraded() {
		t.Fatal("degraded state latched after a successful rotation")
	}
	if snap := clusterCAFailures(); snap.RotationFailures != 1 {
		t.Fatalf("cumulative RotationFailures = %d, want it to stay at 1 (counters never go backwards)",
			snap.RotationFailures)
	}
}

// TestChaos50_UsabilityRecoveryRequiresObservedIssuance is the same contract for
// the refusal path. A CA that is still expired looks exactly like a healthy one
// if nothing needs a certificate, and on a settled fleet nothing does for weeks
// — so an elapsed-time heuristic would report recovery almost immediately and
// always be wrong.
func TestChaos50_UsabilityRecoveryRequiresObservedIssuance(t *testing.T) {
	dir := t.TempDir()
	expired := newClusterCAWithWindow(t, dir, time.Now().Add(-400*24*time.Hour), time.Now().Add(-time.Hour))
	installClusterCA(t, expired)

	if _, _, _, err := expired.SignCSR(newTestCSR(t, "n"), "n"); err == nil {
		t.Fatal("expired CA signed")
	}
	if !clusterCAUsabilityDegraded() {
		t.Fatal("not degraded after a refusal")
	}
	// Asking the question while still broken must not clear it.
	if clusterCAUsableNow() {
		t.Fatal("clusterCAUsableNow() true for an expired CA")
	}
	if !clusterCAUsabilityDegraded() {
		t.Fatal("degraded cleared by a FAILED verification")
	}

	// Import a good CA → the next observation is the evidence.
	good := newClusterCAWithWindow(t, dir, time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	keyDER, err := x509.MarshalECPrivateKey(good.key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := expired.ImportCA(good.certPEM,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
		t.Fatalf("ImportCA: %v", err)
	}
	if !clusterCAUsableNow() {
		t.Fatal("clusterCAUsableNow() false after importing a valid CA")
	}
	if clusterCAUsabilityDegraded() {
		t.Fatal("degraded latched after observed recovery")
	}
}

// TestChaos50_RefusalAlertIsGatedAndRateLimited pins the two producer contracts:
// no goroutine when nothing subscribes, and one signal per interval however many
// refusals occur (a fleet in a renewal storm retries every node every 6h).
func TestChaos50_RefusalAlertIsGatedAndRateLimited(t *testing.T) {
	c := newClusterCAWithWindow(t, t.TempDir(),
		time.Now().Add(-400*24*time.Hour), time.Now().Add(-time.Hour))
	installClusterCA(t, c)
	alerts := captureClusterCAAlerts(t)

	for i := 0; i < 25; i++ {
		if _, _, _, err := c.SignCSR(newTestCSR(t, "n"), "n"); err == nil {
			t.Fatal("expired CA signed")
		}
	}
	if got := clusterCAFailures().SignRefusals; got != 25 {
		t.Fatalf("SignRefusals = %d, want 25 — every refusal must be counted", got)
	}
	if len(*alerts) != 1 {
		t.Fatalf("alerts = %d, want exactly 1 inside the %s window", len(*alerts), clusterCAUnusableAlertInterval)
	}
}

// ── 4. Surfaces ─────────────────────────────────────────────────────────────

// TestChaos50_HealthzAndReadyzSurfaceTheOutage. Pre-fix /healthz carried no
// cluster-CA field at all and /readyz had no row, so a CP whose fleet had lost
// mTLS trust served an unqualified `status: ok`.
func TestChaos50_HealthzAndReadyzSurfaceTheOutage(t *testing.T) {
	expired := newClusterCAWithWindow(t, t.TempDir(),
		time.Now().Add(-400*24*time.Hour), time.Now().Add(-time.Hour))
	installClusterCA(t, expired)

	if got := computeHealth().ClusterCA; got != "expired" {
		t.Fatalf("/healthz cluster_ca = %q, want %q", got, "expired")
	}

	report, code := computeReadiness()
	row := report.Checks["cluster_ca"]
	if row == nil {
		t.Fatal("/readyz has no cluster_ca row for an expired cluster CA")
	}
	if row.Status != "fail" {
		t.Fatalf("cluster_ca row status = %q, want fail", row.Status)
	}
	// REPORT-ONLY: an expired cluster CA is fleet-wide by construction, so
	// gating would eject every node at once and take working proxy traffic with
	// it. The default verdict must be unchanged.
	if code != 200 {
		t.Fatalf("default readiness code = %d, want 200 — the row must not gate", code)
	}
	// …but strict mode must pick it up.
	if !strictVerdictFails(httptest.NewRequest("GET", "/readyz?strict=1", http.NoBody), report.Checks) {
		t.Fatal("strict verdict does not fail on a failing cluster_ca row")
	}

	// The detail is published on an UNAUTHENTICATED port, so it must be a fixed
	// string: no dates, no counts, no filesystem paths. Naming the posture
	// ("refused") is safe here precisely because this row fails CLOSED — the
	// CHAOS-28 hazard is publishing a fail-OPEN posture, which hands an observer
	// an exfiltration window.
	if strings.ContainsAny(row.Detail, "0123456789") {
		t.Fatalf("cluster_ca readiness detail carries a number (date/count): %q", row.Detail)
	}
	if strings.Contains(row.Detail, "/") {
		t.Fatalf("cluster_ca readiness detail carries a path: %q", row.Detail)
	}
}

// TestChaos50_HealthzReportsDisabledWithoutAClusterCA — a single-node appliance
// has no cluster CA, and must not carry a permanently-degraded field or row.
func TestChaos50_HealthzReportsDisabledWithoutAClusterCA(t *testing.T) {
	installClusterCA(t, &clusterCA{})

	if got := computeHealth().ClusterCA; got != "disabled" {
		t.Fatalf("/healthz cluster_ca = %q, want %q on a node with no cluster CA", got, "disabled")
	}
	report, code := computeReadiness()
	if _, ok := report.Checks["cluster_ca"]; ok {
		t.Fatal("/readyz carries a cluster_ca row on a node with no cluster CA")
	}
	if code != 200 {
		t.Fatalf("readiness code = %d, want 200", code)
	}
	for _, row := range buildOperatorContract().Checks {
		if row.Code == "cluster_ca" {
			t.Fatal("/api/diagnostics carries a cluster_ca row on a node with no cluster CA")
		}
	}
}

// TestChaos50_DiagnosticsRowFailsWithAnAction pins the operator-contract row:
// fail status, an impact statement, a remediation, and — because this is a
// viewer-role surface — no raw cause.
func TestChaos50_DiagnosticsRowFailsWithAnAction(t *testing.T) {
	expired := newClusterCAWithWindow(t, t.TempDir(),
		time.Now().Add(-400*24*time.Hour), time.Now().Add(-time.Hour))
	installClusterCA(t, expired)

	rows := checkClusterCA()
	if len(rows) != 1 {
		t.Fatalf("checkClusterCA returned %d rows, want 1", len(rows))
	}
	row := rows[0]
	if row.Status != diagFail {
		t.Fatalf("status = %q, want %q", row.Status, diagFail)
	}
	if !strings.Contains(row.Message, "REFUSED") {
		t.Fatalf("message does not state the impact: %q", row.Message)
	}
	if row.OperatorAction == "" {
		t.Fatal("no operator action for a blocking fault")
	}
	// Viewer-role guardrail: no absolute paths, no exact timestamps.
	if strings.Contains(row.Message, "/") || strings.Contains(row.Message, "T00:") {
		t.Fatalf("message leaks a path or timestamp to a viewer: %q", row.Message)
	}

	// Rotation-degraded (CA still usable) is its own failing DIAGNOSTICS row —
	// but deliberately NOT a readiness failure, because such a node still
	// enrolls, renews and syncs. Failing readiness would let /ready?strict=1
	// eject a fully working fleet a month before anything actually breaks.
	healthy := newClusterCAWithWindow(t, t.TempDir(),
		time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	installClusterCA(t, healthy)
	healthy.recordRotationFailure(errors.New("read-only file system"))
	rows = checkClusterCA()
	if len(rows) != 1 || rows[0].Status != diagFail {
		t.Fatalf("rotation-degraded row = %+v, want one fail row", rows)
	}
	if !strings.Contains(rows[0].Message, "auto-rotation is failing") {
		t.Fatalf("rotation-degraded message = %q", rows[0].Message)
	}
	if got := computeHealth().ClusterCA; got != "rotation_failing" {
		t.Fatalf("/healthz cluster_ca = %q, want %q", got, "rotation_failing")
	}
	report, code := computeReadiness()
	if row := report.Checks["cluster_ca"]; row == nil || row.Status != "ok" {
		t.Fatalf("readiness cluster_ca = %+v, want ok — a dated problem must not eject a working node", row)
	}
	if strictVerdictFails(httptest.NewRequest("GET", "/readyz?strict=1", http.NoBody), report.Checks) {
		t.Fatal("strict readiness ejects a node whose CA is still usable")
	}
	if code != 200 {
		t.Fatalf("readiness code = %d, want 200", code)
	}
}

// TestChaos50_DiagnosticsWarnsOnTheClampShoulder — clamping is the leading
// indicator: the CA is inside its final window and has not been replaced.
func TestChaos50_DiagnosticsWarnsOnTheClampShoulder(t *testing.T) {
	c := newClusterCAWithWindow(t, t.TempDir(),
		time.Now().Add(-100*24*time.Hour), time.Now().Add(10*24*time.Hour))
	installClusterCA(t, c)

	if rows := checkClusterCA(); len(rows) != 1 || rows[0].Status != diagOK {
		t.Fatalf("expected an ok row before any issuance, got %+v", rows)
	}
	if _, _, _, err := c.SignCSR(newTestCSR(t, "n"), "n"); err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	rows := checkClusterCA()
	if len(rows) != 1 || rows[0].Status != diagWarn {
		t.Fatalf("expected one warn row after a clamped issuance, got %+v", rows)
	}
	if rows[0].OperatorAction == "" {
		t.Fatal("clamp warning carries no operator action")
	}
}

// TestChaos50_MetricsExposeUsabilityAndExpiry. Pre-fix the only cluster-CA
// series counted rotation SUCCESSES, so a CP that had failed to rotate every day
// for a month read identically to one that had never needed to.
func TestChaos50_MetricsExposeUsabilityAndExpiry(t *testing.T) {
	expired := newClusterCAWithWindow(t, t.TempDir(),
		time.Now().Add(-400*24*time.Hour), time.Now().Add(-time.Hour))
	installClusterCA(t, expired)
	if _, _, _, err := expired.SignCSR(newTestCSR(t, "n"), "n"); err == nil {
		t.Fatal("expired CA signed")
	}
	expired.recordRotationFailure(errors.New("read-only file system"))

	var sb strings.Builder
	clusterCAWritePrometheus(&sb)
	out := sb.String()
	for _, want := range []string{
		"culvert_cluster_ca_usable 0",
		"culvert_cluster_ca_expires_in_seconds",
		"culvert_cluster_ca_sign_refused_total 1",
		"culvert_cluster_ca_rotation_failures_total 1",
		"culvert_cluster_ca_node_certs_clamped_total 0",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics missing %q:\n%s", want, out)
		}
	}
	// Label-free contract: no fingerprint, serial, subject, or node ID.
	if strings.Contains(out, "{") {
		t.Fatalf("cluster CA metrics carry labels: %s", out)
	}

	// With no CA loaded the expiry gauge must be OMITTED, not rendered 0 —
	// 0 reads as "expires now" and would page every non-cluster node.
	installClusterCA(t, &clusterCA{})
	sb.Reset()
	clusterCAWritePrometheus(&sb)
	if strings.Contains(sb.String(), "culvert_cluster_ca_expires_in_seconds") {
		t.Fatalf("expiry gauge rendered with no CA loaded:\n%s", sb.String())
	}
}

// TestChaos50_AdminAPISeparatesUsableFromInitialized pins the GET
// /api/cluster/ca contract the GUI banner reads.
func TestChaos50_AdminAPISeparatesUsableFromInitialized(t *testing.T) {
	expired := newClusterCAWithWindow(t, t.TempDir(),
		time.Now().Add(-400*24*time.Hour), time.Now().Add(-time.Hour))
	installClusterCA(t, expired)
	if _, _, _, err := expired.SignCSR(newTestCSR(t, "n"), "n"); err == nil {
		t.Fatal("expired CA signed")
	}

	info := expired.Info()
	if info["initialized"] != true {
		t.Fatal("initialized should stay true for an installed CA")
	}
	if info["usable"] != false {
		t.Fatalf("usable = %v, want false", info["usable"])
	}
	if s, _ := info["unusableReason"].(string); s == "" {
		t.Fatal("no unusableReason on the admin surface — the operator has nowhere to read the cause")
	}
	if got, _ := info["signRefused"].(int64); got != 1 {
		t.Fatalf("signRefused = %v, want 1", info["signRefused"])
	}
	if _, ok := info["expiresInDays"]; !ok {
		t.Fatal("expiresInDays absent")
	}
}

// ── 5. First-import nil dereference ─────────────────────────────────────────

// TestChaos50_FirstImportDoesNotPanic. Pre-fix ImportCA dereferenced
// ca.secondaryCert unconditionally, but the secondary is only set when a CA was
// ALREADY installed — so the first import on a node that never ran InitOrLoad
// panicked, AFTER swapping the new CA in. The panic left the CA installed with
// the TLS pool never rebuilt and no rotation tracking started: a partially
// applied trust change.
func TestChaos50_FirstImportDoesNotPanic(t *testing.T) {
	src := newClusterCAWithWindow(t, t.TempDir(),
		time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	keyDER, err := x509.MarshalECPrivateKey(src.key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	fresh := &clusterCA{dir: t.TempDir()} // never InitOrLoad'ed → cert == nil
	installClusterCA(t, fresh)

	rebuilt := false
	fresh.onRotate = func() { rebuilt = true }

	if err := fresh.ImportCA(src.certPEM, keyPEM); err != nil {
		t.Fatalf("first-ever ImportCA: %v", err)
	}
	if !fresh.Ready() {
		t.Fatal("CA not installed after import")
	}
	if !rebuilt {
		t.Fatal("onRotate never ran — the TLS pool was not rebuilt after a trust change")
	}
	if fresh.Usable() != nil {
		t.Fatalf("imported CA reported unusable: %v", fresh.Usable())
	}
}

// ── 6. The self-deadlock ────────────────────────────────────────────────────

// TestChaos50_ImportCADoesNotDeadlock is the gate for the most severe defect in
// this sweep, and it is written to fire ONLY under the production aliasing that
// every other test in the suite deliberately avoided.
//
// Pre-fix stack, captured against main:
//
//	panic: test timed out after 25s
//	goroutine 21 [sync.RWMutex.RLock]:
//	  sync.(*RWMutex).RLock(...)
//	  (*clusterCA).CACertFingerprint(0x69d1b99a480)
//	  (*clusterCA).ImportCA(0x69d1b99a480, …)
//
// Same object, holding Lock, taking RLock. The goroutine blocked forever WHILE
// HOLDING the write lock, so every enrollment, renewal, snapshot publication and
// TLS-pool rebuild queued behind it for the life of the process.
//
// globalClusterCA MUST be the receiver here: pointing it at a separate CA is
// exactly the workaround that hid this for as long as it existed.
func TestChaos50_ImportCADoesNotDeadlock(t *testing.T) {
	src := newClusterCAWithWindow(t, t.TempDir(),
		time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	keyDER, err := x509.MarshalECPrivateKey(src.key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	target := newClusterCAWithWindow(t, t.TempDir(),
		time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	installClusterCA(t, target)

	// Wire onRotate the way buildServerTLS does on a real CP with mTLS: the
	// callback reads the cluster CA back through the global, which is the OTHER
	// deadlock site inside the same function.
	target.onRotate = func() {
		if len(globalClusterCA.AllCACertsPEM()) == 0 {
			t.Error("onRotate saw an empty CA pool")
		}
	}

	done := make(chan error, 1)
	go func() { done <- globalClusterCA.ImportCA(src.certPEM, keyPEM) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ImportCA: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("DEADLOCK: ImportCA did not return — it is holding ca.mu across a call that reads the CA back")
	}

	// The side effects must all have run, not merely been skipped to dodge the
	// deadlock: the CA is swapped, the pool was rebuilt, the rotation counted.
	if globalClusterCA.CACertFingerprint() != src.CACertFingerprint() {
		t.Fatal("imported CA is not the active one")
	}
	if clusterCARotationDegraded() {
		t.Fatal("rotation reported degraded after a successful import")
	}
}

// TestChaos50_CleanupSecondaryDoesNotDeadlock covers the second, unattended site.
// The daily rotation loop reaches CleanupSecondary when a dual-CA overlap window
// closes, so pre-fix this wedged the shared rotation goroutine — taking the
// INSPECTION CA's rotation down with it — and left the cluster CA write lock held
// for the life of the process.
func TestChaos50_CleanupSecondaryDoesNotDeadlock(t *testing.T) {
	c := newClusterCAWithWindow(t, t.TempDir(),
		time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	installClusterCA(t, c)

	// An already-expired secondary, i.e. an overlap window that has closed.
	old := newClusterCAWithWindow(t, t.TempDir(),
		time.Now().Add(-400*24*time.Hour), time.Now().Add(-time.Hour))
	c.mu.Lock()
	c.secondaryCert = old.cert
	c.secondaryPEM = old.certPEM
	c.secondaryExp = old.cert.NotAfter
	c.onRotate = func() { _ = globalClusterCA.AllCACertsPEM() } // as buildServerTLS wires it
	c.mu.Unlock()

	done := make(chan struct{})
	go func() { globalClusterCA.CleanupSecondary(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("DEADLOCK: CleanupSecondary did not return — onRotate runs under ca.mu")
	}
	if c.SecondaryActive() {
		t.Fatal("expired secondary was not cleaned up")
	}
}

// ── 7. The cross-CA coupling ────────────────────────────────────────────────

// TestChaos50_ClusterRotationSurvivesInspectionCALoadFailure is the coupling
// gate. StartCAAutoRotation drives BOTH trust roots, and loadRootCA used to
// start it only when the INSPECTION CA was ready — so a corrupt bundle, a wrong
// CULVERT_CA_PASSPHRASE, or an unreadable -ca-path silently took the CLUSTER
// CA's entire lifecycle manager down with it. Two independent trust roots, one
// shared failure, and (because the cluster CA is a 10-year certificate) a
// consequence that surfaces years after the fault that caused it.
//
// The test drives the real startup loader with an inspection CA that cannot
// load, and asserts the cluster CA still rotates.
func TestChaos50_ClusterRotationSurvivesInspectionCALoadFailure(t *testing.T) {
	// A corrupt bundle file: LoadOrInitCA fails and certMgr stays not-ready.
	caPath := filepath.Join(t.TempDir(), "ca.bundle")
	if err := os.WriteFile(caPath, []byte("this is not a CA bundle"), 0o600); err != nil {
		t.Fatalf("write corrupt bundle: %v", err)
	}
	prevMgr := certMgr
	certMgr = ca.New()
	t.Cleanup(func() { certMgr = prevMgr })

	// loadRootCA is the REAL startup loader, so it writes process-global startup
	// state that outlives this test: sslInspectionLoadError (consulted by
	// computeHealth and appendCAReadinessCheck — an unrestored value makes every
	// later /healthz or /readyz assertion see ssl_inspection: load_failed), the
	// deferred-startup-alert queue, and caRuntime. Restore all three, following
	// the convention rootca_failure_visibility_test.go already establishes.
	// Without this the gate poisons unrelated tests under -shuffle/-count=2,
	// which is precisely the fence-pollution class installClusterCA guards against.
	prevLoadErr := sslInspectionLoadFailure()
	prevQueue, prevFlushed := startupAlertQueue, startupAlertFlushed
	prevRuntime := caRuntime
	t.Cleanup(func() {
		sslInspectionLoadError.Store(prevLoadErr)
		startupAlertMu.Lock()
		startupAlertQueue, startupAlertFlushed = prevQueue, prevFlushed
		startupAlertMu.Unlock()
		caRuntime = prevRuntime
	})

	// A cluster CA inside its rotation window (expires in 10 days).
	dir := t.TempDir()
	expiring := newClusterCAWithWindow(t, dir, time.Now().Add(-100*24*time.Hour), time.Now().Add(10*24*time.Hour))
	installClusterCA(t, expiring)
	before := expiring.CACertFingerprint()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	loadRootCA(rootCAStartupConfig{Path: caPath, Passphrase: "wrong-passphrase"}, ctx)

	if certMgr.Ready() {
		t.Skip("inspection CA loaded despite a corrupt bundle — the premise of this gate no longer holds")
	}

	// StartCAAutoRotation runs one round IMMEDIATELY (CHAOS-28), so the cluster
	// CA must rotate without waiting for the 24h ticker.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if globalClusterCA.CACertFingerprint() != before {
			return // rotated — the driver is not coupled to the inspection CA
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("DEFECT: cluster CA never rotated (fingerprint still %s…) — its rotation driver is "+
		"gated on the inspection CA being ready", before[:12])
}
