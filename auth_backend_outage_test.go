package main

// auth_backend_outage_test.go — CHAOS-16 / F-11: an auth-backend OUTAGE must
// not be recorded as a credential DECISION.
//
// Pre-fix behaviour these tests would have caught:
//   - LDAPAuth.verify returned bare false for a dial/STARTTLS/service-bind/
//     search failure, and Verify cached it for CacheTTL (5m default), so a
//     momentary directory blip denied valid logins for five minutes after the
//     directory came back
//   - OIDCAuth.introspect returned active=false for a transport error, a non-200
//     status and an unparseable body, cached for CacheTTL (2m default) — a 401
//     caused by OUR client credentials being wrong became a mass, cached
//     rejection of every user's token
//   - both logged the same words a wrong password produces, so an IdP outage was
//     indistinguishable from a brute-force spike on every operator surface
//
// The posture is unchanged and deliberately so: an unreachable backend still
// DENIES. What changes is that the denial expires with the outage instead of
// outliving it, and that the outage is now visible as an outage.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// withCleanAuthBackendHealth isolates the process-global reachability record.
//
// Same assertion convention as the storage-health suite: the record is
// process-global and a leaked goroutine from another test can in principle
// touch it, so tests assert on CONTENT and direction rather than on exact
// process-wide totals. Alert counts ARE exact because the alert seam is swapped
// for a test-local synchronous recorder.
func withCleanAuthBackendHealth(t *testing.T) {
	t.Helper()
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)
}

// captureAuthBackendAlerts swaps the alert seam for a SYNCHRONOUS recorder. The
// production seam fires `go fireAlert(...)`; letting that goroutine run in the
// test binary is the -count/-shuffle determinism class the CI gate catches.
func captureAuthBackendAlerts(t *testing.T) *[]string {
	t.Helper()
	var got []string
	prev := fireAuthBackendAlert
	fireAuthBackendAlert = func(detail string) { got = append(got, detail) }
	t.Cleanup(func() { fireAuthBackendAlert = prev })
	return &got
}

// deadLDAPURL returns an ldap:// URL for a port that is bound and then closed,
// so the dial is refused rather than hanging on a firewall-black-holed address.
func deadLDAPURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return "ldap://" + addr
}

// ldapEntry reads a cache entry under the lock.
func ldapEntry(a *LDAPAuth, key string) *ldapCacheEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.cache[key]
	if e == nil {
		return nil
	}
	cp := *e
	return &cp
}

// ── LDAP ──────────────────────────────────────────────────────────────────────

// TestLDAP_UnreachableDirectoryIsNotCachedAsACredentialDecision is the core
// regression. Before the fix the dial failure below was cached for a.ttl (5m
// here), so the user stayed locked out for five minutes after the directory
// recovered.
func TestLDAP_UnreachableDirectoryIsNotCachedAsACredentialDecision(t *testing.T) {
	withCleanAuthBackendHealth(t)
	captureAuthBackendAlerts(t)

	a, err := NewLDAPAuth(LDAPConfig{
		URL:      deadLDAPURL(t),
		BaseDN:   "dc=corp,dc=com",
		StartTLS: false,
		CacheTTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}

	if a.Verify("alice", "correct-horse") {
		t.Fatal("Verify() = true against an unreachable directory — the posture must stay fail-closed")
	}

	e := ldapEntry(a, cacheKey("alice", "correct-horse"))
	if e == nil {
		t.Fatal("no cache entry recorded")
	}
	if !e.indeterminate {
		t.Error("entry is not marked indeterminate — a dial failure was recorded as a credential decision")
	}
	if e.ok {
		t.Error("entry caches ok=true for an unreachable directory")
	}
	if remaining := time.Until(e.expiry); remaining > authIndeterminateTTL {
		t.Errorf("indeterminate entry lives %v, want at most %v — an outage must not outlive itself (pre-fix this was the full %v CacheTTL)",
			remaining, authIndeterminateTTL, a.ttl)
	}
}

// TestLDAP_OutageIsRecordedAsUnreachableNotAsAuthFailure pins the observability
// half: an operator must be able to tell "the directory rejected them" from
// "the directory is gone", which before the fix produced identical log lines
// and no metric at all.
func TestLDAP_OutageIsRecordedAsUnreachableNotAsAuthFailure(t *testing.T) {
	withCleanAuthBackendHealth(t)
	alerts := captureAuthBackendAlerts(t)

	a, err := NewLDAPAuth(LDAPConfig{URL: deadLDAPURL(t), BaseDN: "dc=corp,dc=com"})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}
	a.Verify("alice", "pw")

	var found *authBackendSnapshotEntry
	for _, e := range authBackendHealthSnapshot() {
		if e.Backend == "ldap" {
			cp := e
			found = &cp
		}
	}
	if found == nil {
		t.Fatal("no reachability record for the ldap backend")
	}
	if found.Unreachable < 1 {
		t.Errorf("unreachable count = %d, want at least 1", found.Unreachable)
	}
	if !found.Degraded {
		t.Error("backend not degraded immediately after a failure with no answer since")
	}
	if found.LastErr == "" {
		t.Error("no reason text recorded — the operator gets no cause")
	}
	if len(*alerts) != 1 {
		t.Fatalf("fired %d alerts, want exactly 1", len(*alerts))
	}
	if !strings.Contains((*alerts)[0], "ldap") {
		t.Errorf("alert %q does not name the backend", (*alerts)[0])
	}
}

// TestLDAP_CredentialRejectionClassification pins which LDAP result codes are
// treated as the directory ANSWERING (cacheable) versus failing. Getting this
// wrong in the permissive direction re-introduces the finding at the last step
// of the bind.
func TestLDAP_CredentialRejectionClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"invalid credentials", ldap.NewError(ldap.LDAPResultInvalidCredentials, fmt.Errorf("bad password")), true},
		{"inappropriate authentication", ldap.NewError(ldap.LDAPResultInappropriateAuthentication, fmt.Errorf("no")), true},
		{"network error", ldap.NewError(ldap.ErrorNetwork, fmt.Errorf("connection reset")), false},
		{"busy", ldap.NewError(ldap.LDAPResultBusy, fmt.Errorf("busy")), false},
		{"unavailable", ldap.NewError(ldap.LDAPResultUnavailable, fmt.Errorf("down")), false},
		{"unwilling to perform", ldap.NewError(ldap.LDAPResultUnwillingToPerform, fmt.Errorf("nope")), false},
		{"plain error", fmt.Errorf("i/o timeout"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLDAPCredentialRejection(tc.err); got != tc.want {
				t.Errorf("isLDAPCredentialRejection(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestLDAP_DecisionKeepsTheConfiguredTTL proves the fix did not throw away the
// bcrypt/directory-load protection the cache exists for.
func TestLDAP_DecisionKeepsTheConfiguredTTL(t *testing.T) {
	withCleanAuthBackendHealth(t)
	a, err := NewLDAPAuth(LDAPConfig{URL: "ldaps://dc.corp.com", BaseDN: "dc=corp,dc=com", CacheTTL: 30 * time.Minute})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}
	for _, outcome := range []authBackendOutcome{backendAllow, backendDeny} {
		k := fmt.Sprintf("k-%d", outcome)
		a.cacheSet(k, outcome)
		e := ldapEntry(a, k)
		if e == nil {
			t.Fatalf("outcome %d: no entry", outcome)
		}
		if e.indeterminate {
			t.Errorf("outcome %d marked indeterminate", outcome)
		}
		if remaining := time.Until(e.expiry); remaining < 25*time.Minute {
			t.Errorf("outcome %d lives %v, want ~the configured 30m TTL", outcome, remaining)
		}
		if e.ok != outcome.allowed() {
			t.Errorf("outcome %d cached ok=%v", outcome, e.ok)
		}
	}
}

// ── OIDC ──────────────────────────────────────────────────────────────────────

// flakyIDP serves 503 until healthy is set, then a valid active-token response.
func flakyIDP(t *testing.T, healthy *atomic.Bool) (*httptest.Server, *OIDCAuth) {
	t.Helper()
	allowLoopbackSSRF(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(introspectionResponse{Active: true, Sub: "alice"}) //nolint:errcheck // test response writer
	}))
	t.Cleanup(srv.Close)
	a, err := NewOIDCAuth(OIDCConfig{
		IntrospectionURL: srv.URL,
		ClientID:         "client",
		ClientSecret:     "secret",
		// Deliberately long: this is the value that used to pin an outage.
		CacheTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewOIDCAuth: %v", err)
	}
	return srv, a
}

func oidcEntry(a *OIDCAuth, key string) *oidcCacheEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.cache[key]
	if e == nil {
		return nil
	}
	cp := *e
	return &cp
}

// TestOIDC_IntrospectionOutageDoesNotOutliveItself is the end-to-end recovery
// proof. The IdP fails, recovers, and the SAME token is accepted once the short
// indeterminate window has elapsed.
//
// The window is elapsed by rewinding the cached entry's expiry by exactly
// authIndeterminateTTL rather than sleeping. That rewind is what makes the test
// discriminating: under the pre-fix code the entry carried the provider's
// CacheTTL (one hour here), so advancing five seconds would NOT have expired it
// and the recovered IdP would still have been denied.
func TestOIDC_IntrospectionOutageDoesNotOutliveItself(t *testing.T) {
	withCleanAuthBackendHealth(t)
	captureAuthBackendAlerts(t)

	var healthy atomic.Bool
	_, a := flakyIDP(t, &healthy)

	const token = "opaque-access-token"
	if _, ok := a.ResolveIdentity("alice", token); ok {
		t.Fatal("ResolveIdentity() = true while the IdP was returning 503 — the posture must stay fail-closed")
	}

	k := cacheKey("", token)
	e := oidcEntry(a, k)
	if e == nil {
		t.Fatal("no cache entry recorded")
	}
	if remaining := time.Until(e.expiry); remaining > authIndeterminateTTL {
		t.Fatalf("entry from a 503 lives %v, want at most %v (pre-fix: the full %v CacheTTL)",
			remaining, authIndeterminateTTL, a.ttl)
	}

	// The IdP comes back, and the indeterminate window elapses.
	healthy.Store(true)
	a.mu.Lock()
	a.cache[k].expiry = a.cache[k].expiry.Add(-authIndeterminateTTL - time.Second)
	a.mu.Unlock()

	id, ok := a.ResolveIdentity("alice", token)
	if !ok {
		t.Fatal("ResolveIdentity() = false after the IdP recovered — the outage outlived itself, which is the whole finding")
	}
	if id == nil || id.Sub != "alice" {
		t.Fatalf("identity = %+v, want sub=alice", id)
	}
	// The recovery answer clears the degraded state — by evidence, not by a timer.
	for _, be := range authBackendHealthSnapshot() {
		if be.Backend == "oidc" && be.Degraded {
			t.Error("oidc still degraded after an observed answer")
		}
	}
}

// TestOIDC_Non200IsNotACredentialDecision covers the misconfiguration case that
// is worse than an outage: a 401 means OUR client credentials are wrong, and
// before the fix that was cached as "every user's token is inactive".
func TestOIDC_Non200IsNotACredentialDecision(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusInternalServerError, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			withCleanAuthBackendHealth(t)
			captureAuthBackendAlerts(t)
			allowLoopbackSSRF(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer srv.Close()
			a, err := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "id", CacheTTL: time.Hour})
			if err != nil {
				t.Fatalf("NewOIDCAuth: %v", err)
			}
			if a.Verify("alice", "tok") {
				t.Fatal("Verify() = true on a non-200 introspection response")
			}
			e := oidcEntry(a, cacheKey("", "tok"))
			if e == nil {
				t.Fatal("no cache entry recorded")
			}
			if remaining := time.Until(e.expiry); remaining > authIndeterminateTTL {
				t.Errorf("HTTP %d cached for %v, want at most %v", status, remaining, authIndeterminateTTL)
			}
			degraded := false
			for _, be := range authBackendHealthSnapshot() {
				if be.Backend == "oidc" {
					degraded = be.Degraded
				}
			}
			if !degraded {
				t.Errorf("HTTP %d did not mark the oidc backend unreachable", status)
			}
		})
	}
}

// TestOIDC_ActiveFalseStaysAFullTTLDecision is the other half of the contract:
// the IdP ANSWERED, so the answer is cached exactly as before and the backend
// is not reported unreachable. A fix that made every negative uncacheable would
// turn each rejected token into an introspection round-trip per request.
func TestOIDC_ActiveFalseStaysAFullTTLDecision(t *testing.T) {
	withCleanAuthBackendHealth(t)
	captureAuthBackendAlerts(t)
	allowLoopbackSSRF(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(introspectionResponse{Active: false}) //nolint:errcheck // test response writer
	}))
	defer srv.Close()
	a, err := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "id", CacheTTL: time.Hour})
	if err != nil {
		t.Fatalf("NewOIDCAuth: %v", err)
	}
	if a.Verify("alice", "revoked") {
		t.Fatal("Verify() = true for an inactive token")
	}
	e := oidcEntry(a, cacheKey("", "revoked"))
	if e == nil {
		t.Fatal("no cache entry recorded")
	}
	if remaining := time.Until(e.expiry); remaining < 55*time.Minute {
		t.Errorf("active=false cached for %v, want ~the configured 1h TTL — a real decision must stay cacheable", remaining)
	}
	if len(authBackendHealthSnapshot()) != 0 {
		t.Error("an answered rejection was recorded as a backend outage")
	}
}

// ── Health record ─────────────────────────────────────────────────────────────

// TestAuthBackendAlert_RateGatedPerBackend pins both gate properties: a down
// backend cannot flood the bounded webhook queue, and a second broken backend
// cannot mute the page for the first (the shared-gate hazard CHAOS-45 hit).
func TestAuthBackendAlert_RateGatedPerBackend(t *testing.T) {
	withCleanAuthBackendHealth(t)
	alerts := captureAuthBackendAlerts(t)

	for i := 0; i < 25; i++ {
		noteAuthBackendUnreachable("ldap", "dial: connection refused")
	}
	if len(*alerts) != 1 {
		t.Fatalf("25 failures on one backend fired %d alerts, want exactly 1", len(*alerts))
	}
	// The counter is NEVER gated — magnitude must survive.
	for _, e := range authBackendHealthSnapshot() {
		if e.Backend == "ldap" && e.Unreachable != 25 {
			t.Errorf("ldap unreachable = %d, want 25 — the counter must not be rate-gated", e.Unreachable)
		}
	}

	// A different backend has its own gate and still pages.
	noteAuthBackendUnreachable("oidc", "introspection endpoint returned HTTP 503")
	if len(*alerts) != 2 {
		t.Fatalf("second backend fired %d total alerts, want 2 — gates must be per backend", len(*alerts))
	}

	// The gate re-arms, so a backend that stays down keeps paging.
	authBackends.mu.Lock()
	authBackends.backends["ldap"].alertAt = time.Now().Add(-2 * authBackendAlertInterval)
	authBackends.mu.Unlock()
	noteAuthBackendUnreachable("ldap", "dial: connection refused")
	if len(*alerts) != 3 {
		t.Fatalf("after the interval elapsed the gate fired %d total alerts, want 3 — a persistent outage must not go quiet", len(*alerts))
	}
}

// TestAuthBackendDegraded_SilenceIsNotRecovery is the CHAOS-45 lesson carried
// over: a directory that is still down looks exactly like a healthy one if
// nothing happens to ask it, so elapsed time must never clear the state.
func TestAuthBackendDegraded_SilenceIsNotRecovery(t *testing.T) {
	withCleanAuthBackendHealth(t)
	captureAuthBackendAlerts(t)

	noteAuthBackendUnreachable("ldap", "dial: connection refused")
	authBackends.mu.Lock()
	authBackends.backends["ldap"].last = time.Now().Add(-24 * time.Hour)
	authBackends.mu.Unlock()

	for _, e := range authBackendHealthSnapshot() {
		if e.Backend == "ldap" && !e.Degraded {
			t.Error("a 24h-old failure with no observed answer since reported as recovered — time is not evidence")
		}
	}

	noteAuthBackendAnswered("ldap")
	for _, e := range authBackendHealthSnapshot() {
		if e.Backend == "ldap" && e.Degraded {
			t.Error("still degraded after an OBSERVED answer")
		}
	}
}

// TestAuthBackendHealth_HealthyPathTakesNoLock pins the hot-path guard: until
// something has failed, recording an answer must not touch the map.
func TestAuthBackendHealth_HealthyPathTakesNoLock(t *testing.T) {
	withCleanAuthBackendHealth(t)
	noteAuthOutcome("ldap", backendAllow, "")
	noteAuthOutcome("oidc", backendDeny, "")
	if got := len(authBackendHealthSnapshot()); got != 0 {
		t.Errorf("snapshot has %d entries after answers only, want 0 — a backend that has never failed must be ABSENT, not reported healthy", got)
	}
}

// TestAuthBackendHealth_RecordIsBounded guards the map that feeds Prometheus
// labels against a future caller passing something dynamic.
func TestAuthBackendHealth_RecordIsBounded(t *testing.T) {
	withCleanAuthBackendHealth(t)
	captureAuthBackendAlerts(t)
	for i := 0; i < maxAuthBackendRecords*4; i++ {
		noteAuthBackendUnreachable(fmt.Sprintf("backend-%d", i), "boom")
	}
	if got := len(authBackendHealthSnapshot()); got > maxAuthBackendRecords {
		t.Errorf("record holds %d backends, want at most %d", got, maxAuthBackendRecords)
	}
}

// TestAuthBackendHealth_ReasonIsSanitized pins the CWE-117 barrier at the
// recording boundary, so every downstream sink (log, alert, diagnostics row) is
// fed clean text.
func TestAuthBackendHealth_ReasonIsSanitized(t *testing.T) {
	withCleanAuthBackendHealth(t)
	captureAuthBackendAlerts(t)
	noteAuthBackendUnreachable("ldap", "dial:\nFAKE LOG LINE\r injected")
	for _, e := range authBackendHealthSnapshot() {
		if e.Backend != "ldap" {
			continue
		}
		if strings.ContainsAny(e.LastErr, "\n\r") {
			t.Errorf("reason %q retains control characters", e.LastErr)
		}
	}
}

// TestAuthBackendReason_RedactsEndpointTopology pins the disclosure barrier.
// /api/diagnostics is a VIEWER-role surface, and the errors these reasons come
// from embed the configured IdP URL and the resolved internal address — so an
// unredacted reason would publish corporate topology to every read-only admin
// the first time the directory hiccupped. The failure CLASS must survive.
func TestAuthBackendReason_RedactsEndpointTopology(t *testing.T) {
	cases := []struct {
		name     string
		msg      string
		endpoint string
		leaks    []string
	}{
		{
			name:     "oidc url.Error with resolved address",
			msg:      `introspection request: Post "https://idp.corp.example/introspect": dial tcp 10.4.7.19:443: connect: connection refused`,
			endpoint: "https://idp.corp.example/introspect",
			leaks:    []string{"idp.corp.example", "10.4.7.19"},
		},
		{
			name:     "ldap dial error",
			msg:      `dial: LDAP Result Code 200 "Network Error": dial tcp 192.168.10.4:636: i/o timeout`,
			endpoint: "ldaps://dc.corp.example:636",
			leaks:    []string{"dc.corp.example", "192.168.10.4"},
		},
		{
			name:     "ipv6 peer",
			msg:      `dial: dial tcp [2001:db8::7]:636: connect: no route to host`,
			endpoint: "ldaps://dc.corp.example:636",
			leaks:    []string{"2001:db8::7"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactAuthReason(tc.msg, tc.endpoint)
			for _, leak := range tc.leaks {
				if strings.Contains(got, leak) {
					t.Errorf("redacted reason %q still leaks %q", got, leak)
				}
			}
			// The operator-actionable part must survive — a reason that says
			// nothing is as useless as no reason at all.
			if !strings.ContainsAny(got, "abcdefghijklmnopqrstuvwxyz") {
				t.Errorf("redaction emptied the reason: %q", got)
			}
		})
	}
	// The failure class specifically.
	if got := redactAuthReason(`introspection request: Post "https://idp.corp.example/x": dial tcp 10.0.0.1:443: connect: connection refused`, "https://idp.corp.example/x"); !strings.Contains(got, "connection refused") {
		t.Errorf("redaction dropped the failure class: %q", got)
	}
}

// ── Operator surfaces ─────────────────────────────────────────────────────────

func TestMetrics_AuthBackendSeries(t *testing.T) {
	withCleanAuthBackendHealth(t)
	captureAuthBackendAlerts(t)

	// Absent, not zero: a backend that has never failed must not appear at all.
	if body := renderMetrics(t); strings.Contains(body, "culvert_auth_backend_unreachable_total") {
		t.Fatal("auth-backend series present before any failure — a zero row would read as a probed 'healthy'")
	}

	noteAuthBackendUnreachable("ldap", "dial: connection refused")
	body := renderMetrics(t)
	if !strings.Contains(body, `culvert_auth_backend_unreachable_total{backend="ldap"} 1`) {
		t.Errorf("missing unreachable counter in:\n%s", body)
	}
	if !strings.Contains(body, `culvert_auth_backend_degraded{backend="ldap"} 1`) {
		t.Errorf("missing degraded gauge in:\n%s", body)
	}
	// HELP/TYPE must appear once per metric name, not once per backend row.
	if n := strings.Count(body, "# HELP culvert_auth_backend_unreachable_total"); n != 1 {
		t.Errorf("HELP for the unreachable counter appears %d times, want 1 (a repeat is a scrape parse error)", n)
	}

	noteAuthBackendAnswered("ldap")
	if body := renderMetrics(t); !strings.Contains(body, `culvert_auth_backend_degraded{backend="ldap"} 0`) {
		t.Errorf("degraded gauge did not clear after an observed answer:\n%s", body)
	}
}

func TestDiagnostics_AuthBackendRow(t *testing.T) {
	withCleanAuthBackendHealth(t)
	captureAuthBackendAlerts(t)

	if rows := authBackendDiagnostics(); len(rows) != 0 {
		t.Fatalf("got %d rows before any failure, want 0 — this signal is observed, never probed", len(rows))
	}

	noteAuthBackendUnreachable("ldap", "dial: connection refused")
	rows := authBackendDiagnostics()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].Code != "auth_backend_reachability" || rows[0].Status != diagFail {
		t.Errorf("row = %+v, want auth_backend_reachability/fail", rows[0])
	}
	if !strings.Contains(rows[0].Message, "ldap") {
		t.Errorf("row message %q does not name the backend", rows[0].Message)
	}
	if rows[0].OperatorAction == "" {
		t.Error("no operator action — the row tells nobody what to do")
	}

	noteAuthBackendAnswered("ldap")
	rows = authBackendDiagnostics()
	if len(rows) != 1 || rows[0].Status != diagWarn {
		t.Fatalf("after recovery got %+v, want a single warn row — a healed outage still denied requests during the window", rows)
	}
}
