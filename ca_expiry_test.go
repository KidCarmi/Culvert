package main

// CHAOS-30 — Root CA expiry surveillance (main-side wiring).
//
// The engine-side gates live in internal/ca/ca_expiry_test.go. These pin the
// parts main owns: the latched escalation alert, the immediate first rotation
// round (the closed 24h blind spot), and the four surfaces an operator reads —
// /health, /ready, the operator contract, and /metrics.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
	"github.com/KidCarmi/Culvert/internal/ca"
)

// installTestCA points the process-wide certMgr at a Manager holding a CA with
// the given validity window, restoring the previous singleton afterwards.
// Passing a zero notAfter installs a Manager with no CA at all.
func installTestCA(t *testing.T, notBefore, notAfter time.Time) {
	t.Helper()
	old := certMgr
	t.Cleanup(func() { certMgr = old })

	cm := ca.New()
	certMgr = cm
	if notAfter.IsZero() {
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "CHAOS-30 Root"},
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
	cm.SetCAForTest(cert, key)
}

// captureCAExpiryAlerts routes deferred startup alerts into a capture and
// isolates the CHAOS-30 escalation latch (same seam as captureDPCertAlerts).
func captureCAExpiryAlerts(t *testing.T) *alertCapture {
	t.Helper()
	startupAlertMu.Lock()
	oldQueue, oldFlushed := startupAlertQueue, startupAlertFlushed
	startupAlertQueue, startupAlertFlushed = nil, true
	startupAlertMu.Unlock()
	oldFire := startupAlertFire
	captured := &alertCapture{}
	startupAlertFire = func(event string, p AlertPayload) {
		captured.mu.Lock()
		captured.alerts = append(captured.alerts, queuedStartupAlert{event, p})
		captured.mu.Unlock()
	}
	caExpiryAlert.mu.Lock()
	oldLevel := caExpiryAlert.level
	caExpiryAlert.level = 0
	caExpiryAlert.mu.Unlock()
	t.Cleanup(func() {
		startupAlertMu.Lock()
		startupAlertQueue, startupAlertFlushed = oldQueue, oldFlushed
		startupAlertMu.Unlock()
		startupAlertFire = oldFire
		caExpiryAlert.mu.Lock()
		caExpiryAlert.level = oldLevel
		caExpiryAlert.mu.Unlock()
	})
	return captured
}

func TestCAExpiryAlertLevel(t *testing.T) {
	for _, tc := range []struct {
		days int
		want int
	}{{365, 0}, {31, 0}, {30, 1}, {8, 1}, {7, 2}, {0, 2}, {-1, 3}, {-400, 3}} {
		if got := caExpiryAlertLevel(tc.days); got != tc.want {
			t.Errorf("caExpiryAlertLevel(%d) = %d, want %d", tc.days, got, tc.want)
		}
	}
}

// TestCheckCAExpiry_LatchesPerEscalation — one alert per escalation level, not
// one per 24h rotation tick, and a healthy CA re-arms the latch. Without the
// latch the daily ticker would deliver the same page every day for a month.
func TestCheckCAExpiry_LatchesPerEscalation(t *testing.T) {
	captured := captureCAExpiryAlerts(t)

	// Healthy CA: silent.
	installTestCA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	checkCAExpiry()
	checkCAExpiry()
	if got := captured.snapshot(); len(got) != 0 {
		t.Fatalf("healthy CA must not alert, got %d", len(got))
	}

	// Renewal window: one alert, then latched.
	installTestCA(t, time.Now().Add(-time.Hour), time.Now().Add(20*24*time.Hour))
	checkCAExpiry()
	checkCAExpiry()
	got := captured.snapshot()
	if len(got) != 1 {
		t.Fatalf("renewal window should alert exactly once, got %d", len(got))
	}
	if got[0].event != "cert_expiry" || got[0].payload.Host != "culvert-ca" || got[0].payload.Source != "ca" {
		t.Fatalf("unexpected alert: %+v", got[0])
	}

	// Final week: escalation fires again.
	installTestCA(t, time.Now().Add(-time.Hour), time.Now().Add(3*24*time.Hour))
	checkCAExpiry()
	if got := captured.snapshot(); len(got) != 2 {
		t.Fatalf("final-week escalation should alert, got %d total", len(got))
	}

	// Expired: escalates once more and says so explicitly.
	installTestCA(t, time.Now().Add(-400*24*time.Hour), time.Now().Add(-2*24*time.Hour))
	checkCAExpiry()
	checkCAExpiry()
	got = captured.snapshot()
	if len(got) != 3 {
		t.Fatalf("expired escalation should alert exactly once, got %d total", len(got))
	}
	if !strings.Contains(got[2].payload.Detail, "EXPIRED") {
		t.Fatalf("expired alert detail does not name the condition: %q", got[2].payload.Detail)
	}

	// Recovery (rotation succeeded): the latch clears, so the NEXT real
	// escalation is not swallowed.
	installTestCA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	checkCAExpiry()
	caExpiryAlert.mu.Lock()
	level := caExpiryAlert.level
	caExpiryAlert.mu.Unlock()
	if level != 0 {
		t.Fatalf("latch = %d after recovery, want 0", level)
	}
	installTestCA(t, time.Now().Add(-time.Hour), time.Now().Add(20*24*time.Hour))
	checkCAExpiry()
	if got := captured.snapshot(); len(got) != 4 {
		t.Fatalf("post-recovery escalation must alert again, got %d total", len(got))
	}
}

// TestCheckCAExpiry_NoCAIsSilent — a node with SSL inspection switched off has
// no CA and must never be told its CA is expiring.
func TestCheckCAExpiry_NoCAIsSilent(t *testing.T) {
	captured := captureCAExpiryAlerts(t)
	installTestCA(t, time.Time{}, time.Time{})
	checkCAExpiry()
	if got := captured.snapshot(); len(got) != 0 {
		t.Fatalf("a node with no CA must not alert, got %+v", got)
	}
}

// TestCAExpiryState_DistinguishesExpiredFromAbsent is the reason caExpiryState
// exists: caExpiryDaysRemaining folds both into -1, and they demand opposite
// operator responses ("inspection is off" vs "inspection is broken now").
func TestCAExpiryState_DistinguishesExpiredFromAbsent(t *testing.T) {
	installTestCA(t, time.Time{}, time.Time{})
	if _, ready := caExpiryState(); ready {
		t.Fatal("caExpiryState reports ready with no CA installed")
	}

	installTestCA(t, time.Now().Add(-400*24*time.Hour), time.Now().Add(-3*24*time.Hour))
	days, ready := caExpiryState()
	if !ready {
		t.Fatal("caExpiryState reports not-ready for an installed (expired) CA")
	}
	if days >= 0 {
		t.Fatalf("caExpiryState days = %d for an expired CA, want negative", days)
	}
}

// TestCARotationRound_RunsImmediately proves the 24h blind spot is closed: the
// first round happens at loop start, so a node that boots with an
// already-expiring CA rotates (and alerts) now rather than a day later.
func TestCARotationRound_RunsImmediately(t *testing.T) {
	captureCAExpiryAlerts(t)
	// Inside the 30-day rotation window: the round must rotate it away.
	installTestCA(t, time.Now().Add(-time.Hour), time.Now().Add(5*24*time.Hour))
	before := certMgr.CAExpiry()

	caRotationRound("", "")

	after := certMgr.CAExpiry()
	if !after.After(before) {
		t.Fatalf("caRotationRound did not rotate a CA inside the rotation window (expiry %s → %s)", before, after)
	}
	if !certMgr.SecondaryCAActive() {
		t.Fatal("dual-CA overlap not established by the immediate round")
	}
}

// TestCARotationRound_HealthyCAStaysSilent is the ordering contract: the round
// attempts rotation FIRST and evaluates expiry AFTER, so a CA inside the
// rotation window is fixed before it can page anyone. An alert from this path
// therefore means what an operator needs it to mean — rotation did not fix it.
func TestCARotationRound_HealthyCAStaysSilent(t *testing.T) {
	captured := captureCAExpiryAlerts(t)
	installTestCA(t, time.Now().Add(-time.Hour), time.Now().Add(5*24*time.Hour))

	caRotationRound("", "")

	if got := captured.snapshot(); len(got) != 0 {
		t.Fatalf("a CA that auto-rotation could fix must not alert, got %+v", got)
	}
}

// TestCheckCAExpiry_ExpiredDetailIsActionable — the alert has to say what the
// operator is looking at (signing refused, endpoint trust stores must be
// updated), not just that a date passed.
func TestCheckCAExpiry_ExpiredDetailIsActionable(t *testing.T) {
	captured := captureCAExpiryAlerts(t)
	installTestCA(t, time.Now().Add(-400*24*time.Hour), time.Now().Add(-2*24*time.Hour))
	checkCAExpiry()
	got := captured.snapshot()
	if len(got) != 1 {
		t.Fatalf("an expired CA must produce exactly one alert, got %d", len(got))
	}
	for _, want := range []string{"EXPIRED", "fail-closed", "trust store"} {
		if !strings.Contains(got[0].payload.Detail, want) {
			t.Errorf("alert detail missing %q: %s", want, got[0].payload.Detail)
		}
	}
}

// TestHealthAndReadiness_ReportExpiredCA — the two probe surfaces. Pre-fix both
// said the CA was fine: /health reported ssl_inspection "ready" and /ready's ca
// row said "ok", while every inspected handshake was failing.
func TestHealthAndReadiness_ReportExpiredCA(t *testing.T) {
	installTestCA(t, time.Now().Add(-400*24*time.Hour), time.Now().Add(-2*24*time.Hour))

	h := computeHealth()
	if !h.CAExpired {
		t.Error("/health ca_expired = false for an expired CA")
	}
	if h.SSLInspection != "expired" {
		t.Errorf("/health ssl_inspection = %q, want \"expired\"", h.SSLInspection)
	}

	rep, _ := computeReadiness()
	row := rep.Checks["ca"]
	if row == nil {
		t.Fatal("/ready has no ca row")
	}
	if row.Status != "fail" {
		t.Errorf("/ready ca row = %q, want \"fail\"", row.Status)
	}
	// The row is report-only: it must not flip the default verdict, or an
	// expired inspection CA would eject an otherwise-serving forward proxy
	// from every load balancer at once.
	if rep.Status != "ready" {
		t.Errorf("/ready verdict = %q — the ca row must stay report-only", rep.Status)
	}

	// Healthy CA: both surfaces stay clean.
	installTestCA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if h := computeHealth(); h.CAExpired || h.SSLInspection != "ready" {
		t.Errorf("healthy CA reported as expired=%v ssl_inspection=%q", h.CAExpired, h.SSLInspection)
	}
	rep2, _ := computeReadiness()
	if rep2.Checks["ca"].Status != "ok" {
		t.Errorf("healthy CA ca row = %q, want \"ok\"", rep2.Checks["ca"].Status)
	}
}

// TestCheckRootCA_ExpiryVerdicts — the operator contract row. It reported
// "root CA initialised" / diagOK for both an expiring and an expired CA.
func TestCheckRootCA_ExpiryVerdicts(t *testing.T) {
	installTestCA(t, time.Now().Add(-400*24*time.Hour), time.Now().Add(-2*24*time.Hour))
	if c := checkRootCA(); c.Status != diagFail {
		t.Errorf("expired CA verdict = %q, want %q (message %q)", c.Status, diagFail, c.Message)
	} else if c.OperatorAction == "" {
		t.Error("expired-CA row carries no operator action")
	}

	installTestCA(t, time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour))
	if c := checkRootCA(); c.Status != diagWarn {
		t.Errorf("expiring CA verdict = %q, want %q (message %q)", c.Status, diagWarn, c.Message)
	}

	installTestCA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if c := checkRootCA(); c.Status != diagOK {
		t.Errorf("healthy CA verdict = %q, want %q", c.Status, diagOK)
	}
}

// TestCAMetrics_ExpiryAndSignFailures — the Prometheus surface. The gauge is
// signed (negative once expired) and is OMITTED when no CA is loaded, so an
// absent series honestly means "SSL inspection is not configured".
func TestCAMetrics_ExpiryAndSignFailures(t *testing.T) {
	installTestCA(t, time.Now().Add(-400*24*time.Hour), time.Now().Add(-2*24*time.Hour))
	var b strings.Builder
	caWritePrometheus(&b)
	out := b.String()
	if !strings.Contains(out, "culvert_ca_sign_failures_total") {
		t.Error("culvert_ca_sign_failures_total missing from /metrics")
	}
	if !strings.Contains(out, "culvert_ca_expires_in_seconds -") {
		t.Errorf("culvert_ca_expires_in_seconds is not negative for an expired CA:\n%s", out)
	}

	// The counter moves when a sign is refused.
	if _, err := certMgr.GetCert(&tls.ClientHelloInfo{ServerName: "blocked.example.com"}); err == nil {
		t.Fatal("GetCert succeeded against an expired CA")
	}
	var b2 strings.Builder
	caWritePrometheus(&b2)
	if !strings.Contains(b2.String(), "culvert_ca_sign_failures_total 1") {
		t.Errorf("refused sign was not counted:\n%s", b2.String())
	}

	// No CA at all: the gauge is absent, the counter still present.
	installTestCA(t, time.Time{}, time.Time{})
	var b3 strings.Builder
	caWritePrometheus(&b3)
	if strings.Contains(b3.String(), "culvert_ca_expires_in_seconds") {
		t.Error("culvert_ca_expires_in_seconds emitted with no CA loaded")
	}
	if !strings.Contains(b3.String(), "culvert_ca_sign_failures_total") {
		t.Error("culvert_ca_sign_failures_total missing with no CA loaded")
	}
}

// TestMaybeFailOpenClient_ExpiredCADoesNotPoisonTheLearner — a wrongful-bypass
// guard found while wiring the fail-closed gate.
//
// When the Root CA is expired, signLeaf refuses, so the CLIENT-leg handshake
// fails for every host at once. Feeding those failures to the auto-exclusion
// learner would let one CA-lifecycle fault promote the entire fail-open traffic
// set into bypass — silently disabling DPI/CDR/file-blocking exactly when
// inspection is already broken. The guard is a state check rather than a string
// match, because ErrCAExpired's text ("Root CA certificate has expired") sits
// one word away from classifyClientInspectFailure's "certificate expired" token.
func TestMaybeFailOpenClient_ExpiredCADoesNotPoisonTheLearner(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	fo, scope := bindFailOpenProfile(t, "fo", "fail-open")
	id := ProxyIdentity{ClientIP: "203.0.113.11", Identity: "u1"}
	pinning := errors.New("remote error: tls: bad certificate")

	installTestCA(t, time.Now().Add(-400*24*time.Hour), time.Now().Add(-2*24*time.Hour))
	maybeFailOpenClient("victim.example", fo, id, pinning)
	if _, ok := autoExclude().Contains(scope, scopeGen(t, "fo"), "victim.example"); ok {
		t.Fatal("an expired Root CA must not feed the auto-exclusion learner — one CA fault would bypass the whole fail-open set")
	}

	// Control: with a healthy CA the same evidence still learns, so the guard
	// has not silently disabled the client leg.
	installTestCA(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	maybeFailOpenClient("victim.example", fo, id, pinning)
	if _, ok := autoExclude().Contains(scope, scopeGen(t, "fo"), "victim.example"); !ok {
		t.Fatal("healthy CA: a genuine client pinning rejection must still learn")
	}
}
