package main

// auth_idp_outage_test.go — CHAOS-16 regression suite.
//
// The defect: the auth plane could not tell "the IdP said no" from "the IdP
// did not answer", so an infrastructure failure was written into the negative
// cache exactly like a wrong password and kept denying the user for the full
// TTL AFTER the IdP recovered. These tests pin the tri-state that fixes it,
// the post-dial LDAP deadline that was missing entirely, and the observability
// that makes an IdP outage distinguishable from a credential-stuffing spike.

import (
	"context"
	"errors"
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

// ── helpers ───────────────────────────────────────────────────────────────────

func withCleanIdPHealth(t *testing.T) {
	t.Helper()
	resetIdPHealthForTest()
	t.Cleanup(resetIdPHealthForTest)
}

// captureIdPAlerts replaces the alert seam with a synchronous collector, so
// assertions never race the process-global alerts sink (the -count/-shuffle
// determinism class).
func captureIdPAlerts(t *testing.T) *[]string {
	t.Helper()
	var got []string
	prev := fireIdPUnreachableAlert
	fireIdPUnreachableAlert = func(detail string) { got = append(got, detail) }
	t.Cleanup(func() { fireIdPUnreachableAlert = prev })
	return &got
}

func idpEntry(t *testing.T, backend string) idpHealthEntry {
	t.Helper()
	for _, e := range idpHealthSnapshot() {
		if e.Backend == backend {
			return e
		}
	}
	t.Fatalf("no IdP health entry recorded for backend %q", backend)
	return idpHealthEntry{}
}

// ── OIDC: the headline regression ─────────────────────────────────────────────

// TestOIDC_OutageIsNotCached_RecoveryIsImmediate is the core CHAOS-16 test.
//
// A token is introspected while the IdP is returning 503, then again the
// instant the IdP recovers — with NO wait and NO cache flush. Before the fix
// the 503 was cached as a token rejection and the second call returned false
// for the full 2-minute TTL: a momentary IdP fault became a multi-minute user
// outage that IdP recovery could not shorten.
func TestOIDC_OutageIsNotCached_RecoveryIsImmediate(t *testing.T) {
	withCleanIdPHealth(t)
	captureIdPAlerts(t)
	allowLoopbackSSRF(t)

	var down atomic.Bool
	down.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if down.Load() {
			http.Error(w, "backend unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"active":true,"sub":"alice","exp":%d}`, time.Now().Add(time.Hour).Unix())
	}))
	defer srv.Close()

	a, err := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "c", ClientSecret: "s"})
	if err != nil {
		t.Fatalf("NewOIDCAuth: %v", err)
	}

	// During the outage: denied (fail-closed posture is unchanged).
	if a.Verify("alice", "tok") {
		t.Fatal("expected deny while the introspection endpoint is down (fail closed)")
	}
	// ...and NOT remembered. This is the fix: an empty cache is precisely why
	// recovery needs no TTL to elapse.
	a.mu.Lock()
	cached := len(a.cache)
	a.mu.Unlock()
	if cached != 0 {
		t.Fatalf("IdP outage left %d cache entries — a transient fault is being remembered as a token rejection", cached)
	}

	// The IdP recovers. No sleep, no flush.
	down.Store(false)
	if !a.Verify("alice", "tok") {
		t.Fatal("token still denied after the IdP recovered — the outage was cached (CHAOS-16 regression)")
	}
}

// TestOIDC_InactiveTokenIsStillCached guards the other direction: the fix must
// not disable the cache. `active:false` is a real answer and must still absorb
// repeat lookups, or every rejected token becomes an IdP round-trip.
func TestOIDC_InactiveTokenIsStillCached(t *testing.T) {
	withCleanIdPHealth(t)
	allowLoopbackSSRF(t)

	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"active":false}`)
	}))
	defer srv.Close()

	a, err := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "c", ClientSecret: "s"})
	if err != nil {
		t.Fatalf("NewOIDCAuth: %v", err)
	}

	for i := 0; i < 5; i++ {
		if a.Verify("alice", "revoked") {
			t.Fatal("inactive token must be denied")
		}
	}
	if n := atomic.LoadInt64(&hits); n != 1 {
		t.Errorf("introspection called %d times for a definitively-inactive token, want 1 — the negative cache stopped working", n)
	}
	// A definitive answer must NOT look like an outage.
	if len(idpHealthSnapshot()) != 0 {
		t.Error("a definitive `active:false` answer was recorded as IdP unavailability — this would page on every revoked token")
	}
}

// TestOIDC_NonOKStatusIsUnavailableNotDenial covers the subtlety that makes
// this a security-relevant classification rather than a caching tweak. Under
// RFC 7662 the ONLY statement about the user's token is `active:false` in a
// 200. A 401 means OUR client credentials are wrong, a 429 that we are being
// throttled, a 5xx that the IdP is broken — caching any of them as a token
// rejection denies a legitimate user for reasons that have nothing to do with
// their token.
func TestOIDC_NonOKStatusIsUnavailableNotDenial(t *testing.T) {
	allowLoopbackSSRF(t)
	for _, status := range []int{http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			withCleanIdPHealth(t)
			captureIdPAlerts(t)

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer srv.Close()

			a, err := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "c", ClientSecret: "s"})
			if err != nil {
				t.Fatalf("NewOIDCAuth: %v", err)
			}
			if a.Verify("alice", "tok") {
				t.Fatal("expected fail-closed deny")
			}
			a.mu.Lock()
			cached := len(a.cache)
			a.mu.Unlock()
			if cached != 0 {
				t.Errorf("HTTP %d was cached as a token rejection", status)
			}
			if got := idpEntry(t, "oidc").Reason; got != fmt.Sprintf("http_%d", status) {
				t.Errorf("reason = %q, want http_%d", got, status)
			}
		})
	}
}

// TestOIDC_UnparseableBodyIsUnavailable — a 200 we cannot parse is not an
// answer either. A truncated body or an HTML error page from an intercepting
// middlebox lands here, and neither says anything about the token.
func TestOIDC_UnparseableBodyIsUnavailable(t *testing.T) {
	withCleanIdPHealth(t)
	captureIdPAlerts(t)
	allowLoopbackSSRF(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html>502 Bad Gateway</html>")
	}))
	defer srv.Close()

	a, err := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "c", ClientSecret: "s"})
	if err != nil {
		t.Fatalf("NewOIDCAuth: %v", err)
	}
	if a.Verify("alice", "tok") {
		t.Fatal("expected fail-closed deny")
	}
	a.mu.Lock()
	cached := len(a.cache)
	a.mu.Unlock()
	if cached != 0 {
		t.Error("an unparseable introspection reply was cached as a token rejection")
	}
	if got := idpEntry(t, "oidc").Reason; got != "parse_failed" {
		t.Errorf("reason = %q, want parse_failed", got)
	}
}

// TestOIDC_TransportFailureIsUnavailable — the endpoint is simply gone.
func TestOIDC_TransportFailureIsUnavailable(t *testing.T) {
	withCleanIdPHealth(t)
	captureIdPAlerts(t)
	allowLoopbackSSRF(t)

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening now

	a, err := NewOIDCAuth(OIDCConfig{IntrospectionURL: url, ClientID: "c", ClientSecret: "s"})
	if err != nil {
		t.Fatalf("NewOIDCAuth: %v", err)
	}
	if a.Verify("alice", "tok") {
		t.Fatal("expected fail-closed deny")
	}
	a.mu.Lock()
	cached := len(a.cache)
	a.mu.Unlock()
	if cached != 0 {
		t.Error("a dead introspection endpoint was cached as a token rejection")
	}
	if got := idpEntry(t, "oidc").Reason; got != "request_failed" {
		t.Errorf("reason = %q, want request_failed", got)
	}
}

// ── LDAP ──────────────────────────────────────────────────────────────────────

// TestLDAP_DialFailureIsNotCached — the directory is unreachable. Denied, but
// never remembered, so the first request after the directory returns is
// served normally.
func TestLDAP_DialFailureIsNotCached(t *testing.T) {
	withCleanIdPHealth(t)
	captureIdPAlerts(t)

	a, err := NewLDAPAuth(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=x,dc=com"})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}
	if a.Verify("alice", "secret") {
		t.Fatal("expected fail-closed deny when the directory is unreachable")
	}
	a.mu.Lock()
	cached := len(a.cache)
	a.mu.Unlock()
	if cached != 0 {
		t.Fatalf("unreachable directory left %d cache entries — the outage would keep denying this user for the full TTL after recovery", cached)
	}
	if got := idpEntry(t, "ldap").Reason; got != "dial_failed" {
		t.Errorf("reason = %q, want dial_failed", got)
	}
}

// TestLDAP_StalledDirectoryIsReleased proves the deadline that did not exist
// before this change. The dialer timeout bounds only the TCP connect; a
// directory that accepts the connection and then goes silent — an overloaded
// DC, a firewall state-table flush leaving a half-open connection, a middlebox
// black-holing the reply — used to block the bind FOREVER, pinning a proxy
// request goroutine and its client socket with no upper bound.
func TestLDAP_StalledDirectoryIsReleased(t *testing.T) {
	withCleanIdPHealth(t)
	captureIdPAlerts(t)

	// Shrink the production deadline; waiting out 10s per case would make the
	// suite unusable.
	prev := ldapOpTimeout
	ldapOpTimeout = 250 * time.Millisecond
	t.Cleanup(func() { ldapOpTimeout = prev })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept and stall: never write a single byte back.
	accepted := make(chan struct{}, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case accepted <- struct{}{}:
			default:
			}
			// Hold the connection open, silent, until the test tears down.
			t.Cleanup(func() { _ = c.Close() })
		}
	}()

	a, err := NewLDAPAuth(LDAPConfig{
		URL:    "ldap://" + ln.Addr().String(),
		BaseDN: "dc=x,dc=com",
		BindDN: "cn=svc,dc=x,dc=com",
		// A NON-EMPTY service password is load-bearing: go-ldap rejects a
		// simple bind that carries a DN with an empty password locally, before
		// touching the socket, so an empty one would return in ~1ms and the
		// test would pass without ever reaching the code path it exists to
		// cover.
		BindPassword: "svcpass",
	})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}
	start := time.Now()

	done := make(chan bool, 1)
	go func() { done <- a.Verify("alice", "secret") }()

	select {
	case ok := <-done:
		if ok {
			t.Fatal("a stalled directory must never authenticate")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Verify never returned against a stalled directory — the post-dial deadline is not armed, so a sick directory pins proxy goroutines without bound (CHAOS-16 regression)")
	}

	// The release must come from the DEADLINE, not from some faster local
	// rejection. Without this floor the test would still pass if go-ldap
	// short-circuited before touching the socket, which is exactly how an
	// earlier draft of it passed while covering nothing.
	if elapsed := time.Since(start); elapsed < ldapOpTimeout {
		t.Fatalf("Verify returned in %v, before the %v operation deadline — the stall was never exercised", elapsed, ldapOpTimeout)
	}

	select {
	case <-accepted:
	default:
		t.Fatal("test did not exercise the post-connect path — nothing connected")
	}

	// The stall is a transport failure, so it must not be cached either.
	a.mu.Lock()
	cached := len(a.cache)
	a.mu.Unlock()
	if cached != 0 {
		t.Errorf("a stalled directory left %d cache entries", cached)
	}
}

// TestLDAPErrorIsTransport_Classification pins the line between "the server
// answered" and "we never got an answer". Getting this wrong in the permissive
// direction (treating a rejection as an outage) would page the directory team
// every time an account is locked; getting it wrong in the strict direction
// (treating an outage as a rejection) is the original defect.
func TestLDAPErrorIsTransport_Classification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		// No answer.
		{"network error", ldap.NewError(ldap.ErrorNetwork, errors.New("connection reset")), true},
		{"unexpected response", ldap.NewError(ldap.ErrorUnexpectedResponse, errors.New("bad packet")), true},
		{"server down", ldap.NewError(ldap.LDAPResultServerDown, errors.New("down")), true},
		{"client timeout", ldap.NewError(ldap.LDAPResultTimeout, errors.New("timeout")), true},
		{"connect error", ldap.NewError(ldap.LDAPResultConnectError, errors.New("connect")), true},
		{"server busy", ldap.NewError(ldap.LDAPResultBusy, errors.New("busy")), true},
		{"server unavailable", ldap.NewError(ldap.LDAPResultUnavailable, errors.New("unavailable")), true},
		{"non-LDAP error", errors.New("something else entirely"), true},
		{"context deadline", context.DeadlineExceeded, true},

		// The server answered — these are everyday rejections from a HEALTHY
		// directory and must stay cacheable and must never page anyone.
		{"invalid credentials", ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("wrong password")), false},
		{"account disabled", ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New("account disabled")), false},
		{"inappropriate auth", ldap.NewError(ldap.LDAPResultInappropriateAuthentication, errors.New("no")), false},
		{"insufficient rights", ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied")), false},
		{"no such object", ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("missing")), false},

		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ldapErrorIsTransport(tc.err); got != tc.want {
				t.Errorf("ldapErrorIsTransport(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// ── health record ─────────────────────────────────────────────────────────────

// TestIdPHealth_CountedButAlertRateGated — a down IdP fails EVERY
// authenticating request. Un-gated, this producer would saturate the bounded
// webhook queue and evict every other alert, so the auth-plane fault would
// take the alerting channel down with it. The counter must stay un-gated so
// magnitude survives.
func TestIdPHealth_CountedButAlertRateGated(t *testing.T) {
	withCleanIdPHealth(t)
	alerts := captureIdPAlerts(t)

	const n = 25
	for i := 0; i < n; i++ {
		noteIdPUnavailable("ldap", "dial_failed")
	}
	if got := idpEntry(t, "ldap").Total; got != n {
		t.Errorf("counter = %d, want %d — magnitude must never be rate-gated", got, n)
	}
	if len(*alerts) != 1 {
		t.Errorf("fired %d alerts for %d failures, want 1 — the webhook queue is not protected", len(*alerts), n)
	}

	// The gate must RE-ARM: an IdP that stays down has to keep paging rather
	// than going quiet after one message.
	idpHealth.mu.Lock()
	idpHealth.backends["ldap"].alertAt = time.Now().Add(-2 * idpUnavailableAlertInterval)
	idpHealth.mu.Unlock()
	noteIdPUnavailable("ldap", "dial_failed")
	if len(*alerts) != 2 {
		t.Errorf("alert gate did not re-arm after the interval (%d alerts)", len(*alerts))
	}
}

// TestIdPHealth_GatesArePerBackend — an LDAP outage must not consume the alert
// budget for OIDC. Sharing one gate across backends would silence the page for
// a second, unrelated provider failing inside the same interval, which is the
// shared-gate mistake the durable-write work had to correct.
func TestIdPHealth_GatesArePerBackend(t *testing.T) {
	withCleanIdPHealth(t)
	alerts := captureIdPAlerts(t)

	noteIdPUnavailable("ldap", "dial_failed")
	noteIdPUnavailable("oidc", "http_503")

	if len(*alerts) != 2 {
		t.Fatalf("got %d alerts, want 2 — one backend's outage consumed another's alert gate", len(*alerts))
	}
	if !strings.Contains((*alerts)[0], "ldap") || !strings.Contains((*alerts)[1], "oidc") {
		t.Errorf("alerts do not name their backends: %q", *alerts)
	}
}

// TestIdPHealth_SilenceIsNotRecovery — an IdP that is still down looks exactly
// like a healthy one when nothing happens to authenticate. Degraded state must
// therefore never age out on a timer; only an observed definitive answer
// clears it. Same rule the durable-write record had to learn (CHAOS-45).
func TestIdPHealth_SilenceIsNotRecovery(t *testing.T) {
	withCleanIdPHealth(t)
	captureIdPAlerts(t)

	noteIdPUnavailable("ldap", "dial_failed")

	// Push the incident a day into the past. Nothing else happens.
	idpHealth.mu.Lock()
	idpHealth.backends["ldap"].last = time.Now().Add(-24 * time.Hour)
	idpHealth.mu.Unlock()

	if !idpEntry(t, "ldap").Degraded() {
		t.Error("backend reported recovered after 24h of silence — no answer was ever observed to justify it")
	}
	if len(idpDegradedBackends()) != 1 {
		t.Error("idpDegradedBackends() lost the still-degraded backend")
	}
}

// TestIdPHealth_AnyDefinitiveAnswerClearsDegraded — a REJECTION counts as
// recovery evidence, not just a success. Requiring a successful login would
// leave a perfectly healthy directory reported as down for as long as it
// happened to receive only bad passwords.
func TestIdPHealth_AnyDefinitiveAnswerClearsDegraded(t *testing.T) {
	withCleanIdPHealth(t)
	captureIdPAlerts(t)

	noteIdPUnavailable("ldap", "dial_failed")
	if !idpEntry(t, "ldap").Degraded() {
		t.Fatal("expected degraded after an unanswered attempt")
	}

	noteIdPAnswered("ldap") // e.g. a wrong password — still an answer
	if idpEntry(t, "ldap").Degraded() {
		t.Error("a definitive answer did not clear the degraded state")
	}
	// The historical count must survive: the incident happened.
	if got := idpEntry(t, "ldap").Total; got != 1 {
		t.Errorf("total = %d, want 1 — recovery must not erase the incident", got)
	}
}

// TestIdPHealth_ReasonVocabularyIsClosed is a disclosure guardrail.
// /api/diagnostics is a VIEWER-role surface, and LDAP/OIDC error text carries
// directory hostnames, bind DNs and introspection URLs. The reason recorded
// here must come from a fixed vocabulary, never from a raw error string — so
// no redaction pass is needed and no future consumer can reintroduce a leak by
// formatting the record somewhere new.
func TestIdPHealth_ReasonVocabularyIsClosed(t *testing.T) {
	allowLoopbackSSRF(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	allowed := map[string]bool{
		"dial_failed": true, "starttls_failed": true, "service_bind_failed": true,
		"search_failed": true, "bind_transport_failed": true,
		"request_build_failed": true, "request_failed": true, "parse_failed": true,
	}

	withCleanIdPHealth(t)
	captureIdPAlerts(t)

	// One failure from each provider, driven through the real code paths.
	a, err := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "c", ClientSecret: "s"})
	if err != nil {
		t.Fatalf("NewOIDCAuth: %v", err)
	}
	a.Verify("alice", "tok")

	l, err := NewLDAPAuth(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=x,dc=com"})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}
	l.Verify("alice", "secret")

	for _, e := range idpHealthSnapshot() {
		if !allowed[e.Reason] && !strings.HasPrefix(e.Reason, "http_") {
			t.Errorf("backend %q recorded reason %q, which is outside the fixed vocabulary — raw error text must never reach the record", e.Backend, e.Reason)
		}
		for _, leak := range []string{host, "127.0.0.1", "://", srv.URL} {
			if strings.Contains(e.Reason, leak) {
				t.Errorf("backend %q reason %q leaks %q to a viewer-role surface", e.Backend, e.Reason, leak)
			}
		}
	}

	// The rendered operator-contract row must be clean for the same reason.
	row := checkIdPReachability()
	for _, leak := range []string{host, "127.0.0.1", "://"} {
		if strings.Contains(row.Message, leak) {
			t.Errorf("idp_reachability message leaks %q: %s", leak, row.Message)
		}
	}
}

// ── operator surfaces ─────────────────────────────────────────────────────────

func TestCheckIdPReachability_Verdicts(t *testing.T) {
	t.Run("clean", func(t *testing.T) {
		withCleanIdPHealth(t)
		if got := checkIdPReachability().Status; got != diagOK {
			t.Errorf("status = %q, want ok on a node with no unanswered attempts", got)
		}
	})

	t.Run("degraded", func(t *testing.T) {
		withCleanIdPHealth(t)
		captureIdPAlerts(t)
		noteIdPUnavailable("ldap", "dial_failed")

		row := checkIdPReachability()
		if row.Status != diagFail {
			t.Errorf("status = %q, want fail while the provider is not answering", row.Status)
		}
		if !strings.Contains(row.Message, "ldap") || !strings.Contains(row.Message, "dial_failed") {
			t.Errorf("message does not name the backend and reason: %s", row.Message)
		}
		if row.OperatorAction == "" {
			t.Error("no operator action on a fail row")
		}
	})

	t.Run("healed", func(t *testing.T) {
		withCleanIdPHealth(t)
		captureIdPAlerts(t)
		noteIdPUnavailable("oidc", "http_503")
		noteIdPAnswered("oidc")

		row := checkIdPReachability()
		if row.Status != diagWarn {
			t.Errorf("status = %q, want warn once the provider answers again", row.Status)
		}
		if !strings.Contains(row.Message, "oidc") {
			t.Errorf("healed message does not name the backend: %s", row.Message)
		}
	})
}

func TestMetrics_IdPUnavailableSeries(t *testing.T) {
	withCleanIdPHealth(t)
	captureIdPAlerts(t)

	// A healthy fleet must carry NO series at all rather than a wall of
	// zeroes — and in particular no age gauge, whose 0 would read as "an IdP
	// just failed" on every node.
	if body := renderMetrics(t); strings.Contains(body, "culvert_idp_unavailable") {
		t.Error("IdP series exported with no unavailability ever recorded")
	}

	noteIdPUnavailable("ldap", "dial_failed")
	body := renderMetrics(t)
	for _, want := range []string{
		`culvert_idp_unavailable_total{backend="ldap"} 1`,
		`culvert_idp_unavailable{backend="ldap"} 1`,
		`culvert_idp_unavailable_last_age_seconds{backend="ldap"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}

	noteIdPAnswered("ldap")
	body = renderMetrics(t)
	if !strings.Contains(body, `culvert_idp_unavailable{backend="ldap"} 0`) {
		t.Error("gauge did not clear after a definitive answer was observed")
	}
	if !strings.Contains(body, `culvert_idp_unavailable_total{backend="ldap"} 1`) {
		t.Error("counter was reset by recovery — the incident must stay countable")
	}
}
