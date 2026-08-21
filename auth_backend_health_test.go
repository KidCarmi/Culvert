package main

// auth_backend_health_test.go — CHAOS-47 regression suite.
//
// The defect these pin is a RECOVERY failure, not a denial failure. Denying
// while the identity backend is down is correct and unchanged. What was wrong
// is that the denial was written into the auth cache, so it kept denying for
// the full cache TTL AFTER the backend recovered — a one-second directory blip
// bought minutes of lockout for every user who authenticated during it.
//
// So the assertions are deliberately shaped around the recovery edge:
//   - an unreachable backend leaves NO cache entry;
//   - the first attempt after the backend answers again succeeds, without
//     waiting out any TTL;
//   - an AUTHORITATIVE deny (the backend answered "no") is still cached, since
//     that cache is what protects the directory from credential-stuffing load.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── The gate ─────────────────────────────────────────────────────────────────

func TestAuthProbeGate_HealthyAlwaysAllows(t *testing.T) {
	var g authProbeGate
	for i := 0; i < 100; i++ {
		if !g.allow() {
			t.Fatalf("healthy gate denied probe %d", i)
		}
	}
	if g.gated() {
		t.Fatal("healthy gate reports itself gated")
	}
}

func TestAuthProbeGate_OneProbePerCooldown(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	g := authProbeGate{now: func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}}
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}

	g.recordUnavailable()
	if !g.gated() {
		t.Fatal("gate should be armed after an unreachable outcome")
	}
	// Inside the cooldown nobody probes — that is what stops a hard-down
	// backend from turning every request into a full dial timeout.
	for i := 0; i < 50; i++ {
		if g.allow() {
			t.Fatalf("gate allowed a probe inside the cooldown (attempt %d)", i)
		}
	}
	// After the cooldown exactly ONE caller gets through, and the gate re-arms
	// on grant rather than on the result, so a probe that never reports back
	// cannot leave the gate open.
	advance(authBackendProbeCooldown)
	if !g.allow() {
		t.Fatal("gate did not grant a probe after the cooldown elapsed")
	}
	if g.allow() {
		t.Fatal("gate granted a second concurrent probe — a recovering backend would be stampeded")
	}
}

func TestAuthProbeGate_ReachClearsImmediately(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := authProbeGate{now: func() time.Time { return now }}
	g.recordUnavailable()
	if g.allow() {
		t.Fatal("precondition: gate should be armed")
	}
	// One observed reach releases everyone at once — recovery is evidence-based
	// and shared, not per-credential.
	g.recordReachable()
	if g.gated() {
		t.Fatal("gate still armed after an observed reach")
	}
	for i := 0; i < 20; i++ {
		if !g.allow() {
			t.Fatalf("gate denied caller %d after recovery", i)
		}
	}
}

// ── The process-wide record ──────────────────────────────────────────────────

func TestAuthBackendHealth_RecordAndRecover(t *testing.T) {
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	if snap := authBackendHealthStatus(); snap.Degraded || snap.Unavailable != 0 {
		t.Fatalf("clean record should be healthy, got %+v", snap)
	}

	noteAuthBackendUnavailable("ldap", "dial: connection refused")
	snap := authBackendHealthStatus()
	if !snap.Degraded {
		t.Error("record should be degraded after an unreachable outcome")
	}
	if snap.Unavailable != 1 || snap.Backend != "ldap" {
		t.Errorf("unexpected record: %+v", snap)
	}

	noteAuthBackendGatedDenial()
	noteAuthBackendGatedDenial()
	if got := authBackendHealthStatus().GatedDenials; got != 2 {
		t.Errorf("gated denials = %d, want 2", got)
	}

	// Only an OBSERVED reach clears the gauge — elapsed time never does, for
	// the same reason it does not for durable writes (CHAOS-45): a backend
	// nobody happens to query looks identical to a healthy one under a timer.
	noteAuthBackendReachable("ldap")
	if authBackendHealthStatus().Degraded {
		t.Error("record still degraded after an observed reach")
	}
	// The counters are cumulative history and must survive recovery.
	if snap := authBackendHealthStatus(); snap.Unavailable != 1 || snap.GatedDenials != 2 {
		t.Errorf("counters reset by recovery: %+v", snap)
	}
}

// ── OIDC: the end-to-end recovery proof ──────────────────────────────────────

// oidcFlappingIDP serves an introspection endpoint whose health is switchable.
func oidcFlappingIDP(t *testing.T, healthy *atomic.Bool, calls *atomic.Int64) (*httptest.Server, *OIDCAuth) {
	t.Helper()
	allowLoopbackSSRF(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		if !healthy.Load() {
			// The realistic outage shape: the IdP is up enough to answer, but
			// its backing store is down. RFC 7662 reserves 200 for a verdict,
			// so a 503 is unambiguously "no verdict available".
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(introspectionResponse{Active: true, Sub: "alice"})
	}))
	a, err := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "client", ClientSecret: "secret"})
	if err != nil {
		t.Fatalf("NewOIDCAuth: %v", err)
	}
	return srv, a
}

func TestOIDC_IdPOutageIsNotCached_RecoversImmediately(t *testing.T) {
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	var healthy atomic.Bool
	var calls atomic.Int64
	srv, a := oidcFlappingIDP(t, &healthy, &calls)
	defer srv.Close()

	// Drive the gate's cooldown from the test clock so recovery is asserted
	// deterministically instead of by sleeping.
	now := time.Unix(1_700_000_000, 0)
	a.gate.now = func() time.Time { return now }

	// ── IdP down: the request must be denied ──────────────────────────────
	if _, ok := a.ResolveIdentity("alice", "good-token"); ok {
		t.Fatal("expected deny while the IdP is unreachable (fail closed)")
	}
	// ...but nothing about that denial may be remembered. This is the defect:
	// before the fix the negative sat in the cache for the full TTL.
	a.mu.Lock()
	cached := len(a.cache)
	a.mu.Unlock()
	if cached != 0 {
		t.Fatalf("IdP outage poisoned the auth cache with %d entr(ies) — a valid token stays denied for the whole TTL after recovery", cached)
	}
	if snap := authBackendHealthStatus(); snap.Unavailable == 0 || !snap.Degraded {
		t.Errorf("outage not visible to the operator: %+v", snap)
	}

	// ── Still down: further requests are gated, not re-introspected ───────
	callsAfterFirst := calls.Load()
	for i := 0; i < 25; i++ {
		if _, ok := a.ResolveIdentity("alice", "good-token"); ok {
			t.Fatal("expected deny while gated")
		}
	}
	if extra := calls.Load() - callsAfterFirst; extra != 0 {
		t.Errorf("gated requests still hit the IdP %d times — a hard-down IdP would be hammered at full request rate", extra)
	}
	if got := authBackendHealthStatus().GatedDenials; got != 25 {
		t.Errorf("gated denials = %d, want 25 (the outage blast radius must be measurable)", got)
	}

	// ── IdP recovers: the very next probe succeeds ────────────────────────
	// No TTL is waited out. The only delay is the gate cooldown, which is
	// seconds — the whole point of the fix.
	healthy.Store(true)
	now = now.Add(authBackendProbeCooldown)
	id, ok := a.ResolveIdentity("alice", "good-token")
	if !ok || id == nil || id.Sub != "alice" {
		t.Fatalf("auth did not recover on the first probe after the IdP came back: ok=%v id=%+v", ok, id)
	}
	if authBackendHealthStatus().Degraded {
		t.Error("gauge still degraded after a successful reach")
	}
}

func TestOIDC_AuthoritativeDenyIsStillCached(t *testing.T) {
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	// A reachable IdP answering "this token is inactive" is a verdict, not an
	// outage. That negative MUST stay cached — it is what keeps a
	// credential-stuffing flood off the IdP.
	allowLoopbackSSRF(t)
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(introspectionResponse{Active: false})
	}))
	defer srv.Close()
	a, err := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "client"})
	if err != nil {
		t.Fatalf("NewOIDCAuth: %v", err)
	}

	for i := 0; i < 5; i++ {
		if a.Verify("alice", "revoked-token") {
			t.Fatal("inactive token must be denied")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("introspection called %d times for a cached authoritative deny, want 1", got)
	}
	if snap := authBackendHealthStatus(); snap.Unavailable != 0 || snap.Degraded {
		t.Errorf("an authoritative deny must not be reported as an outage: %+v", snap)
	}
}

func TestOIDC_MalformedResponseIsTreatedAsUnavailable(t *testing.T) {
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	// HTTP 200 with a body that is not an introspection response means the
	// endpoint is not speaking RFC 7662 — a captive portal, a misrouted
	// ingress, a proxy error page. That is infrastructure, not a verdict.
	allowLoopbackSSRF(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>login here</html>"))
	}))
	defer srv.Close()
	a, err := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "client"})
	if err != nil {
		t.Fatalf("NewOIDCAuth: %v", err)
	}

	if a.Verify("alice", "some-token") {
		t.Fatal("malformed introspection response must fail closed")
	}
	a.mu.Lock()
	cached := len(a.cache)
	a.mu.Unlock()
	if cached != 0 {
		t.Errorf("malformed response cached %d entr(ies); it is an endpoint fault, not a token verdict", cached)
	}
	if authBackendHealthStatus().Unavailable == 0 {
		t.Error("malformed introspection response not recorded as backend-unavailable")
	}
}

func TestOIDC_UnreachableIdPFiresAlert(t *testing.T) {
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	// Capture through the package-level seam so the assertion is synchronous
	// and does not race the process-global alert sink.
	var mu sync.Mutex
	var fired []string
	orig := fireIdentityBackendUnreachableAlert
	fireIdentityBackendUnreachableAlert = func(backend, detail string) {
		mu.Lock()
		fired = append(fired, backend+": "+detail)
		mu.Unlock()
	}
	t.Cleanup(func() { fireIdentityBackendUnreachableAlert = orig })

	noteAuthBackendUnavailable("oidc", "introspection request: connection refused")

	mu.Lock()
	defer mu.Unlock()
	if len(fired) != 1 {
		t.Fatalf("want exactly one identity_backend_unreachable alert, got %d", len(fired))
	}
	// Rate limiting is what keeps a down IdP from emitting one alert per
	// request; the counter carries the magnitude.
	noteAuthBackendUnavailable("oidc", "introspection request: connection refused")
	if len(fired) != 1 {
		t.Errorf("alert not rate-limited: %d alerts for a continuing outage", len(fired))
	}
}

// ── LDAP ─────────────────────────────────────────────────────────────────────

func TestLDAP_UnreachableDirectoryIsNotCached(t *testing.T) {
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	// Port 1 on loopback refuses immediately: a directory that is down, which
	// is what a restart, a failover, or a firewall change looks like.
	a, err := NewLDAPAuth(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=com"})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}

	if a.Verify("alice", "correct-password") {
		t.Fatal("expected deny while the directory is unreachable (fail closed)")
	}
	a.mu.Lock()
	cached := len(a.cache)
	a.mu.Unlock()
	if cached != 0 {
		t.Fatalf("directory outage poisoned the auth cache with %d entr(ies) — the user stays locked out for the whole TTL after the directory returns", cached)
	}
	snap := authBackendHealthStatus()
	if snap.Unavailable == 0 || !snap.Degraded || snap.Backend != "ldap" {
		t.Errorf("directory outage not visible to the operator: %+v", snap)
	}

	// While gated, further attempts are denied without re-dialing, so a
	// hard-down directory costs one dial per cooldown instead of one per
	// request (each of which would otherwise pay the 10s dial timeout).
	if !a.gate.gated() {
		t.Fatal("gate not armed after an unreachable directory")
	}
	before := authBackendHealthStatus().Unavailable
	for i := 0; i < 10; i++ {
		_ = a.Verify("alice", "correct-password")
	}
	if got := authBackendHealthStatus().Unavailable; got != before {
		t.Errorf("gated attempts re-dialed the directory (%d new probes)", got-before)
	}
	if got := authBackendHealthStatus().GatedDenials; got != 10 {
		t.Errorf("gated denials = %d, want 10", got)
	}
}

func TestLDAP_EmptyPasswordNeverTouchesTheBackend(t *testing.T) {
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	a, err := NewLDAPAuth(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=com"})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}
	if a.Verify("alice", "") {
		t.Fatal("empty password must be denied")
	}
	// An empty password is rejected locally, so it must not be reported as an
	// outage — otherwise a scanner spraying blank passwords would light up the
	// operator's IdP-down alarm.
	if snap := authBackendHealthStatus(); snap.Unavailable != 0 || snap.GatedDenials != 0 {
		t.Errorf("empty-password rejection charged to backend health: %+v", snap)
	}
}

// ── Operator contract ────────────────────────────────────────────────────────

func TestDiagnostics_IdentityBackendRow(t *testing.T) {
	resetDiagVerdictGlobals(t) // isolates BOTH the storage and identity-backend globals

	contract := buildOperatorContract()
	row := findDiagnosticCheck(contract, "identity_backend")
	if row == nil {
		t.Fatal("identity_backend row missing from the operator contract")
	}
	if row.Status != diagOK {
		t.Errorf("clean record should be ok, got %q (%s)", row.Status, row.Message)
	}

	// An outage in progress must read as FAIL with an actionable message — the
	// whole point of the row is that an operator can tell a directory outage
	// apart from a brute-force spike.
	noteAuthBackendUnavailable("ldap", "dial: connection refused")
	row = findDiagnosticCheck(buildOperatorContract(), "identity_backend")
	if row == nil || row.Status != diagFail {
		t.Fatalf("in-progress outage should be fail, got %+v", row)
	}
	if row.OperatorAction == "" {
		t.Error("fail row has no operator action")
	}

	// Recovery is by EVIDENCE: an observed reach downgrades the row to warn
	// (the incident is history), never straight back to ok, so the window
	// stays visible for the rest of the process.
	noteAuthBackendReachable("ldap")
	row = findDiagnosticCheck(buildOperatorContract(), "identity_backend")
	if row == nil || row.Status != diagWarn {
		t.Fatalf("recovered outage should be warn, got %+v", row)
	}
}
