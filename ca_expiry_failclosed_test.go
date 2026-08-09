package main

// ca_expiry_failclosed_test.go — CHAOS-28 regression coverage.
//
// An expired inspection Root CA was the least visible failure in the appliance:
// the engine kept signing (x509.CreateCertificate never checks the parent's
// validity), every client rejected the resulting chain, and NOTHING inside
// Culvert moved — /healthz said `ssl_inspection: ready`, /readyz said `ca: ok`,
// no counter, no alert. These tests pin the fail-closed posture and the
// observability that replaced the silence.
//
// The most important assertion in this file is the negative one in
// TestHandleTunnel_ExpiredCAFailsClosedNotBypass: the fix must NOT be "bypass
// when the CA is unusable". That would trade an availability outage for a
// silent, fleet-wide security-control outage — every host uninspected at once,
// with DLP/AV/YARA/CDR/DPI all dark.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ca"
	"github.com/KidCarmi/Culvert/internal/decryptobs"
)

// installExpiredCA swaps in a process CA manager holding a Root CA that expired
// an hour ago, and isolates the usability health record for the test.
func installExpiredCA(t *testing.T) {
	t.Helper()
	installCAWithWindow(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
}

func installCAWithWindow(t *testing.T, notBefore, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "CHAOS-28 Test CA"},
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

	prev := certMgr
	cm := ca.New()
	cm.SetCAForTest(cert, key)
	certMgr = cm
	prevLoadErr := sslInspectionLoadFailure()
	sslInspectionLoadError.Store("")
	resetCAUsabilityHealthForTest()
	t.Cleanup(func() {
		certMgr = prev
		sslInspectionLoadError.Store(prevLoadErr)
		resetCAUsabilityHealthForTest()
	})
}

// muteCAAlerts replaces the alert seam so the assertion is synchronous and the
// process-global alerts sink is untouched (the -count/-shuffle determinism
// class the CI gate catches).
func muteCAAlerts(t *testing.T) *[]string {
	t.Helper()
	prev := fireCAUnusableAlert
	got := &[]string{}
	fireCAUnusableAlert = func(detail string) { *got = append(*got, detail) }
	t.Cleanup(func() { fireCAUnusableAlert = prev })
	return got
}

// TestHandleTunnel_ExpiredCAFailsClosedNotBypass is the security gate. An
// inspect-matched CONNECT hitting an expired CA must be REFUSED (502), and the
// session must be recorded as a decryption FAILURE — not as any flavour of
// bypass. Pre-fix this call proceeded into handleTunnelInspect and served a
// leaf chained to an expired issuer.
func TestHandleTunnel_ExpiredCAFailsClosedNotBypass(t *testing.T) {
	installExpiredCA(t)
	muteCAAlerts(t)

	const host = "chaos28-failclosed.example"
	dec := sslResolution{Action: SSLInspect, Source: decryptobs.DecisionPolicyInspect, ScopeID: "prof-ca"}
	match := &PolicyMatch{Rule: &PolicyRule{ID: "r-ca", Name: "inspect-all"}}
	id := ProxyIdentity{ClientIP: "198.51.100.77"}

	r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "http://"+host+":443", http.NoBody)
	r.Host = host + ":443"
	rr := httptest.NewRecorder()

	handleTunnel(rr, r, dec, match, id)

	if rr.Code != 502 {
		t.Fatalf("CONNECT with an expired Root CA returned %d, want 502 (fail closed)", rr.Code)
	}
	// The response body must not describe the appliance's certificate state to
	// an arbitrary client on the network.
	if b := rr.Body.String(); strings.Contains(strings.ToLower(b), "expired") || strings.Contains(b, "CHAOS-28 Test CA") {
		t.Fatalf("502 body leaks CA state to the client: %q", b)
	}

	e, ok := findDecFailEntry(t, host)
	if !ok || e.Dec == nil {
		t.Fatal("an unusable-CA block must write a DECRYPT_FAILED drill-down row")
	}
	if e.Dec.Outcome != "failed" {
		t.Fatalf("outcome = %q, want failed — a bypass outcome here would mean the fix "+
			"silently disabled inspection fleet-wide", e.Dec.Outcome)
	}
	if e.Dec.DecisionSource != "no_fail_open_502" {
		t.Fatalf("decision source = %q, want no_fail_open_502", e.Dec.DecisionSource)
	}
	if e.Dec.FailStage != "client_hello" || e.Dec.FailCategory != "certificate" {
		t.Fatalf("taxonomy = %q/%q, want client_hello/certificate", e.Dec.FailStage, e.Dec.FailCategory)
	}
	// The fault is appliance-wide, so it must never feed the per-host learner:
	// one expired CA would otherwise promote every host requested during the
	// outage into a permanent decryption exclusion.
	if e.Dec.CacheLearned || e.Dec.ExclReason != "" || e.Dec.ExclScope != "" {
		t.Fatalf("unusable-CA block fed the auto-exclusion learner: learned=%v reason=%q scope=%q",
			e.Dec.CacheLearned, e.Dec.ExclReason, e.Dec.ExclScope)
	}

	if snap := caUsabilityFailures(); snap.Blocks != 1 {
		t.Fatalf("blocked-CONNECT counter = %d, want 1", snap.Blocks)
	}
	if !caUsabilityDegraded() {
		t.Fatal("caUsabilityDegraded() = false after a blocked CONNECT")
	}
}

// TestHandleTunnel_ValidCAIsUnaffected is the negative control: the guard must
// be invisible on a healthy node. A valid CA still dispatches to the inspect
// path (which then fails on the unreachable origin, not on the CA), and no
// usability fault is recorded.
func TestHandleTunnel_ValidCAIsUnaffected(t *testing.T) {
	installCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	muteCAAlerts(t)

	// 203.0.113.0/24 is TEST-NET-3: routable-looking, never answers.
	const host = "203.0.113.9"
	dec := sslResolution{Action: SSLInspect, Source: decryptobs.DecisionPolicyInspect}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "http://"+host+":443", http.NoBody)
	r.Host = host + ":443"
	rr := httptest.NewRecorder()

	handleTunnel(rr, r, dec, nil, ProxyIdentity{ClientIP: "198.51.100.78"})

	if snap := caUsabilityFailures(); snap.Blocks != 0 || snap.Refusals != 0 {
		t.Fatalf("a valid CA recorded a usability fault: %+v", snap)
	}
	if caUsabilityDegraded() {
		t.Fatal("caUsabilityDegraded() = true with a valid CA")
	}
}

// TestHealthz_ExpiredCAIsNotReported_Ready pins the probe row that stayed green
// through the entire outage.
func TestHealthz_ExpiredCAIsNotReported_Ready(t *testing.T) {
	installExpiredCA(t)
	if got := computeHealth().SSLInspection; got != "expired" {
		t.Fatalf("/healthz ssl_inspection = %q, want %q", got, "expired")
	}

	installCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if got := computeHealth().SSLInspection; got != "ready" {
		t.Fatalf("/healthz ssl_inspection = %q for a valid CA, want %q", got, "ready")
	}
}

// TestReadyz_ExpiredCARowIsReportOnly pins both halves of the readiness
// contract: the row goes red, and it does NOT gate the default verdict (an
// expired CA is typically fleet-wide, so gating would eject every node at once
// and take working plain-HTTP/bypass traffic down with it). Strict mode opts in.
func TestReadyz_ExpiredCARowIsReportOnly(t *testing.T) {
	installExpiredCA(t)

	type readyResp struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	decode := func(rr *httptest.ResponseRecorder) readyResp {
		var r readyResp
		if err := json.NewDecoder(rr.Body).Decode(&r); err != nil {
			t.Fatalf("decode /readyz: %v", err)
		}
		return r
	}

	rr := httptest.NewRecorder()
	handleReady(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", http.NoBody))
	got := decode(rr)
	row, ok := got.Checks["ca"]
	if !ok {
		t.Fatal("ca row missing from /readyz with an expired CA")
	}
	if row.Status != "fail" {
		t.Fatalf("ca row = %q with an expired CA, want fail", row.Status)
	}
	// Unauthenticated surface: the detail must not disclose the exact expiry.
	if strings.Contains(row.Detail, "20") && strings.Contains(row.Detail, "T") {
		t.Fatalf("ca readiness detail leaks a timestamp to an unauthenticated probe: %q", row.Detail)
	}

	// Strict mode is the opt-in that DOES gate.
	rrStrict := httptest.NewRecorder()
	handleReady(rrStrict, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz?strict=1", http.NoBody))
	if rrStrict.Code != 503 {
		t.Fatalf("/readyz?strict=1 with an expired CA returned %d, want 503", rrStrict.Code)
	}
}

// TestCAUsabilityMetrics pins the scrape-time series. `culvert_ca_usable` is the
// one an operator alerts on for the cliff; `culvert_ca_expires_in_seconds` is
// the one that lets them avoid it entirely.
func TestCAUsabilityMetrics(t *testing.T) {
	installExpiredCA(t)
	muteCAAlerts(t)
	noteCAConnectBlocked("expired at 2026-01-01T00:00:00Z")

	var b strings.Builder
	caWritePrometheus(&b)
	out := b.String()

	for _, want := range []string{
		"culvert_ca_usable 0",
		"culvert_ca_inspect_blocked_total 1",
		"culvert_ca_sign_refused_total 0",
		"culvert_ca_rotation_persist_failures_total 0",
		"culvert_ca_expires_in_seconds ",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, out)
		}
	}
	// Negative seconds once expired — the series must not clamp at zero, or a
	// "how long has this been down" query is unanswerable.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "culvert_ca_expires_in_seconds ") &&
			!strings.Contains(line, "-") {
			t.Fatalf("expired CA reported a non-negative expiry: %q", line)
		}
	}

	// A CA-less node omits the expiry series entirely rather than reporting 0,
	// which would read as "expires now" and page on every such node.
	prev := certMgr
	certMgr = ca.New()
	t.Cleanup(func() { certMgr = prev })
	var b2 strings.Builder
	caWritePrometheus(&b2)
	if strings.Contains(b2.String(), "culvert_ca_expires_in_seconds") {
		t.Fatal("expiry series emitted with no CA loaded — 0 would read as 'expires now'")
	}
}

// TestCAUnusable_AlertAndLogAreRateLimited pins the flood control. An expired CA
// fails EVERY inspected connection, so an ungated producer would emit one
// webhook per CONNECT — overflowing the bounded alert queue and dropping the
// alerts that matter. The counter must still carry the full magnitude.
func TestCAUnusable_AlertAndLogAreRateLimited(t *testing.T) {
	installExpiredCA(t)
	alerts := muteCAAlerts(t)

	const n = 500
	for i := 0; i < n; i++ {
		noteCAConnectBlocked("expired at 2026-01-01T00:00:00Z")
	}

	if len(*alerts) != 1 {
		t.Fatalf("%d faults produced %d alerts, want 1 (rate-limited)", n, len(*alerts))
	}
	if snap := caUsabilityFailures(); snap.Blocks != n {
		t.Fatalf("blocked counter = %d, want %d — rate limiting must never lose magnitude", snap.Blocks, n)
	}
	if !strings.Contains((*alerts)[0], "SSL inspection is DOWN") {
		t.Fatalf("alert detail does not state the impact: %q", (*alerts)[0])
	}
}

// TestCAUsabilityDegraded_RecoveryNeedsEvidence pins "silence is not recovery":
// the degraded state clears only on an OBSERVED usable verification, never on
// elapsed time. A CA that is still expired but happens to receive no traffic
// must not look healthy.
func TestCAUsabilityDegraded_RecoveryNeedsEvidence(t *testing.T) {
	installExpiredCA(t)
	muteCAAlerts(t)

	noteCAConnectBlocked("expired")
	if !caUsabilityDegraded() {
		t.Fatal("degraded = false right after a fault")
	}

	// Time passing alone changes nothing.
	if !caUsabilityDegraded() {
		t.Fatal("degraded cleared without any successful verification")
	}

	// Rotate to a valid CA and let a caller observe it.
	installCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	noteCAConnectBlocked("expired") // seed a fault against the NEW manager
	if !caUsabilityDegraded() {
		t.Fatal("degraded = false after seeding a fault")
	}
	if !caInspectionUsable() {
		t.Fatal("caInspectionUsable() = false for a valid CA")
	}
	if caUsabilityDegraded() {
		t.Fatal("degraded stayed set after an observed usable verification")
	}
}

// TestCAUnusableOutcome_Projection pins the ADR-0011 mapping in isolation, so a
// future edit cannot quietly reclassify an appliance-wide fault as a bypass.
func TestCAUnusableOutcome_Projection(t *testing.T) {
	match := &PolicyMatch{Rule: &PolicyRule{ID: "r-x", Name: "inspect-x"}}
	dec := sslResolution{Action: SSLInspect, Source: decryptobs.DecisionPolicyInspect, ScopeID: "prof-x", Consulted: true}

	b := caUnusableOutcome("host.example", dec, match).toBlock(false)
	if b.Outcome != "failed" || b.DecisionSource != "no_fail_open_502" {
		t.Fatalf("outcome/source = %q/%q, want failed/no_fail_open_502", b.Outcome, b.DecisionSource)
	}
	if b.FailStage != "client_hello" || b.FailCategory != "certificate" {
		t.Fatalf("taxonomy = %q/%q, want client_hello/certificate", b.FailStage, b.FailCategory)
	}
	if b.ProfileID != "prof-x" || b.RuleID != "r-x" {
		t.Fatalf("scope/rule attribution lost: %+v", b)
	}
	if b.CacheLearned || b.ExclReason != "" || b.ExclScope != "" || b.Rescued {
		t.Fatalf("appliance-wide fault must not set learner/rescue fields: %+v", b)
	}
	if b.CertVerify != "not_checked" {
		t.Fatalf("cert-verify sentinel = %q, want not_checked (no origin handshake ran)", b.CertVerify)
	}
}

// TestCARotationPersistFailure_IsAlerted pins the CA-2 half: a rotation that
// could not be written is reported as a distinct, always-alerted fault rather
// than being folded into the "rotated successfully" message.
func TestCARotationPersistFailure_IsAlerted(t *testing.T) {
	installExpiredCA(t) // isolates the health record via resetCAUsabilityHealthForTest

	noteCARotationPersistFailure("atomic write ca.bundle: no space left on device")

	snap := caUsabilityFailures()
	if snap.PersistFailures != 1 {
		t.Fatalf("persist-failure counter = %d, want 1", snap.PersistFailures)
	}
	if !strings.Contains(snap.PersistErr, "no space left on device") {
		t.Fatalf("persist error detail lost: %q", snap.PersistErr)
	}
	// Persist failures must NOT be charged to the per-connection fault record —
	// they are a different incident with a different remediation.
	if snap.Blocks != 0 || snap.Refusals != 0 {
		t.Fatalf("persist failure polluted the connection-fault counters: %+v", snap)
	}
}

// TestOperatorContract_RootCARowReflectsUsability pins the /api/diagnostics row.
// "Initialised" is not "usable": the row reported diagOK through the entire
// outage, so the one surface explicitly built to tell an operator what is wrong
// told them nothing was.
func TestOperatorContract_RootCARowReflectsUsability(t *testing.T) {
	installExpiredCA(t)
	muteCAAlerts(t)

	row := checkRootCA()
	if row.Status != diagFail {
		t.Fatalf("root_ca status = %q with an expired CA, want %q", row.Status, diagFail)
	}
	if !strings.Contains(row.Message, "BLOCKED") {
		t.Fatalf("root_ca message does not state the impact: %q", row.Message)
	}
	if row.OperatorAction == "" {
		t.Fatal("root_ca row carries no operator action for a blocking fault")
	}
	// Viewer-role surface: no filesystem paths, no exact certificate timestamps.
	if strings.Contains(row.Message, "/") || strings.Contains(row.Message, "Z") {
		t.Fatalf("root_ca message leaks a path or timestamp to a viewer: %q", row.Message)
	}

	// A rotation that could not persist is a distinct, non-blocking warning.
	installCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if got := checkRootCA(); got.Status != diagOK {
		t.Fatalf("root_ca status = %q with a healthy CA, want %q", got.Status, diagOK)
	}
	noteCARotationPersistFailure("no space left on device")
	warn := checkRootCA()
	if warn.Status != diagWarn {
		t.Fatalf("root_ca status = %q after a persist failure, want %q", warn.Status, diagWarn)
	}
	if !strings.Contains(warn.Message, "lost on restart") {
		t.Fatalf("persist-failure row does not state the consequence: %q", warn.Message)
	}
}

// TestCARotationPersistWarning_ClearsOnEvidence pins the Codex review finding:
// the persistence warning must key on the CURRENT state, not the cumulative
// counter. An operator who restores the volume and force-rotates has fixed the
// problem; a row latched on the counter would keep telling them the active CA
// is memory-only until the process restarts — the opposite of the
// recovery-on-evidence rule the rest of this plane follows.
func TestCARotationPersistWarning_ClearsOnEvidence(t *testing.T) {
	installCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	noteCARotationPersistFailure("no space left on device")
	if !caRotationPersistDegraded() {
		t.Fatal("persist state not degraded right after a failed save")
	}
	if checkRootCA().Status != diagWarn {
		t.Fatal("root_ca row did not warn after a failed save")
	}

	// Elapsed time alone must not clear it.
	if !caRotationPersistDegraded() {
		t.Fatal("persist state cleared without an observed successful save")
	}

	// The operator fixes the volume and force-rotates: a successful save.
	noteCARotationPersisted()
	if caRotationPersistDegraded() {
		t.Fatal("persist state stayed degraded after an observed successful save")
	}
	if got := checkRootCA(); got.Status != diagOK {
		t.Fatalf("root_ca status = %q after a successful re-save, want %q — the warning latched", got.Status, diagOK)
	}

	snap := caUsabilityFailures()
	if snap.PersistDegraded {
		t.Fatal("snapshot still reports PersistDegraded after recovery")
	}
	// The cumulative counter must NOT go backwards: it feeds a Prometheus
	// counter, and the historical fact stays worth knowing.
	if snap.PersistFailures != 1 {
		t.Fatalf("cumulative persist-failure counter = %d after recovery, want 1 (counters never decrease)",
			snap.PersistFailures)
	}

	// A later failure re-arms the warning.
	noteCARotationPersistFailure("read-only file system")
	if !caRotationPersistDegraded() {
		t.Fatal("a new save failure did not re-arm the warning")
	}
}

// TestForceRotate_UnpersistedRotationDoesNotReportSuccess pins the manual half
// of CA-2. The force-rotate handler carried the same swallowed-save defect as
// auto-rotation: it logged the error, then answered 200 and bumped
// culvert_ca_rotations_total for a CA that lives only in RAM. The operator
// running this command is very often the one trying to RECOVER from an expiry
// outage, so a false success here costs them the whole incident.
func TestForceRotate_UnpersistedRotationDoesNotReportSuccess(t *testing.T) {
	installCAWithWindow(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	// A path whose parent is a regular file — every write fails ENOTDIR.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	prevPath, prevPass := caRuntime.path, caRuntime.passphrase
	caRuntime.path, caRuntime.passphrase = filepath.Join(blocker, "ca.bundle"), "pw"
	t.Cleanup(func() { caRuntime.path, caRuntime.passphrase = prevPath, prevPass })

	before := statCARotations.Load()
	if persistRotatedCA() {
		t.Fatal("persistRotatedCA reported success writing through a regular file")
	}
	if statCARotations.Load() != before {
		t.Fatal("an unpersisted rotation advanced culvert_ca_rotations_total")
	}
	if !caRotationPersistDegraded() {
		t.Fatal("a failed force-rotate save did not degrade the persistence state")
	}

	// A writable path recovers it.
	caRuntime.path = filepath.Join(t.TempDir(), "ca.bundle")
	if !persistRotatedCA() {
		t.Fatal("persistRotatedCA failed on a writable path")
	}
	if caRotationPersistDegraded() {
		t.Fatal("persistence state stayed degraded after a successful save")
	}

	// No bundle path configured: nothing is written, so there is no durability
	// claim to fail and neither observer should fire.
	resetCAUsabilityHealthForTest()
	caRuntime.path = ""
	if !persistRotatedCA() {
		t.Fatal("persistRotatedCA reported failure with no bundle path configured")
	}
	if caRotationPersistDegraded() {
		t.Fatal("no-bundle-path invented a degraded persistence state")
	}
}
