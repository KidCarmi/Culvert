package main

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
	"github.com/KidCarmi/Culvert/internal/decryptprofile"
)

// swapAutoExclude installs a fresh empty cache for a test and restores the prior
// singleton on cleanup. Mirrors swapDecProfileStore — MANDATORY for any test that
// calls Observe/recordAutoExclude or drives resolveSSLAction, so the global cache
// cannot leak state into later tests under -shuffle (the PR3d fence-pollution
// class of bug).
func swapAutoExclude(t *testing.T, cfg autoexclude.Config) {
	t.Helper()
	prev := autoExclude
	autoExclude = autoexclude.New(cfg)
	t.Cleanup(func() { autoExclude = prev })
}

// bindFailOpenProfile installs a decryption-profile store with a single named
// fail-open (or fail-close) profile and returns a rule match referencing it plus
// the profile's scope ID (the cache key).
func bindFailOpenProfile(t *testing.T, name, onInspectError string) (match *PolicyMatch, scopeID string) {
	t.Helper()
	if globalDecryptionProfiles.GetByName(name) == nil {
		if _, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: name, OnInspectError: onInspectError}); err != nil {
			t.Fatalf("seed profile: %v", err)
		}
	}
	p := globalDecryptionProfiles.GetByName(name)
	m := &PolicyMatch{
		Action:    ActionAllow,
		SSLAction: SSLInspect,
		Rule:      &PolicyRule{Name: "r-" + name, SSLAction: SSLInspect, DecryptionProfile: name},
	}
	return m, p.ID
}

func swapProfiles(t *testing.T) {
	t.Helper()
	prev := globalDecryptionProfiles
	globalDecryptionProfiles = decryptprofile.New()
	t.Cleanup(func() { globalDecryptionProfiles = prev })
}

// TestResolveSSLAction_EmptyCacheByteIdentical pins "byte-identical when unused":
// with an empty cache, an Inspect decision stays Inspect.
func TestResolveSSLAction_EmptyCacheByteIdentical(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{})
	swapProfiles(t)
	m := &PolicyMatch{Action: ActionAllow, SSLAction: SSLInspect, Rule: &PolicyRule{Name: "r", SSLAction: SSLInspect}}
	if a, _ := resolveSSLAction(m, "example.com", "1.2.3.4"); a != SSLInspect {
		t.Fatalf("empty cache changed the SSL action: got %q want Inspect", a)
	}
	fo, _ := bindFailOpenProfile(t, "fo", "fail-open")
	if a, _ := resolveSSLAction(fo, "example.com", "1.2.3.4"); a != SSLInspect {
		t.Fatalf("fail-open rule + empty cache should still Inspect: got %q", a)
	}
}

// TestResolveSSLAction_FailCloseNeverConsults pins the never-exclude control.
func TestResolveSSLAction_FailCloseNeverConsults(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	fo, foScope := bindFailOpenProfile(t, "fo", "fail-open")
	autoExclude.Observe(foScope, "fo", "locked.example", autoexclude.ReasonUnsupportedParams, "id:probe")
	if _, ok := autoExclude.Contains(foScope, "locked.example"); !ok {
		t.Fatal("precondition: host should be excluded under fo scope")
	}
	// fail-close profile → resolveFailOpen false → cache NOT consulted → Inspect.
	fc, _ := bindFailOpenProfile(t, "fc", "fail-close")
	if a, _ := resolveSSLAction(fc, "locked.example", "1.2.3.4"); a != SSLInspect {
		t.Fatalf("fail-close rule consulted the cache: got %q want Inspect", a)
	}
	// The fail-open rule for the SAME host DOES self-heal.
	if a, _ := resolveSSLAction(fo, "locked.example", "1.2.3.4"); a != SSLBypass {
		t.Fatalf("fail-open rule did not self-heal: got %q want Bypass", a)
	}
}

// TestResolveSSLAction_CrossScopeContamination pins B1: a host learned under one
// fail-open profile must NOT be bypassed for a different fail-open profile's rule
// targeting the same host.
func TestResolveSSLAction_CrossScopeContamination(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	foA, scopeA := bindFailOpenProfile(t, "profA", "fail-open")
	foB, _ := bindFailOpenProfile(t, "profB", "fail-open")
	autoExclude.Observe(scopeA, "profA", "shared.example", autoexclude.ReasonClientCertRequired, "id:u1")
	if a, _ := resolveSSLAction(foA, "shared.example", "1.2.3.4"); a != SSLBypass {
		t.Fatalf("profA (owner) should bypass: got %q", a)
	}
	if a, _ := resolveSSLAction(foB, "shared.example", "1.2.3.4"); a != SSLInspect {
		t.Fatalf("profB must NOT consume profA's exclusion (cross-scope leak): got %q", a)
	}
}

// TestClassifyOriginInspectFailure_TightenedTriggers pins B2/B3: only
// client-cert-required (learn+rescue) and locally-detected unsupported-params
// (learn, no rescue) are trusted; generic/origin-controlled/ambiguous failures
// and cert-verify errors never learn.
func TestClassifyOriginInspectFailure_TightenedTriggers(t *testing.T) {
	// Must NOT learn — cert-verify, generic origin alerts, transport failures.
	noLearn := []error{
		x509.UnknownAuthorityError{},
		x509.CertificateInvalidError{Reason: x509.IncompatibleUsage},
		x509.HostnameError{Host: "x"},
		errors.New("remote error: tls: handshake failure"),       // origin-controlled generic alert
		errors.New("remote error: tls: no application protocol"), // ambiguous ALPN alert
		errors.New("remote error: tls: internal error"),
		errors.New("remote error: tls: unrecognized name"),
		errors.New("EOF"),
		errors.New("read tcp 1.2.3.4:443: connection reset by peer"),
		errors.New("dial tcp: i/o timeout"),
		errors.New("tls: bad record MAC"),
		&wrapErr{errors.New("remote error: tls: handshake failure")}, // wrapped generic
		// Deliberately NOT learned (SWG N1/N2): host-independent local config error
		// and a Go server-side string that never fires on the origin (client) leg.
		errors.New("tls: no supported versions satisfy MinVersion and MaxVersion"),
		errors.New("tls: no cipher suite supported by both client and server"),
	}
	for _, e := range noLearn {
		if _, learn, rescue := classifyOriginInspectFailure(e); learn || rescue {
			t.Fatalf("must NOT learn/rescue %q (learn=%v rescue=%v)", e, learn, rescue)
		}
	}
	// client-cert-required → learn AND rescue.
	if r, learn, rescue := classifyOriginInspectFailure(errors.New("remote error: tls: certificate required")); !learn || !rescue || r != autoExReasonClientCert {
		t.Fatalf("certificate required = (%q,%v,%v), want (client_cert_required,true,true)", r, learn, rescue)
	}
	// Genuine per-origin version mismatch → learn, NO rescue. (Only this string;
	// the host-independent config error and the server-side cipher string are in
	// the noLearn set above per SWG N1/N2.)
	r, learn, rescue := classifyOriginInspectFailure(errors.New("tls: server selected unsupported protocol version 301"))
	if !learn || rescue || r != autoExReasonUnsupported {
		t.Fatalf("server-selected-version = (%q,%v,%v), want (unsupported_params,true,false)", r, learn, rescue)
	}
}

type wrapErr struct{ e error }

func (w *wrapErr) Error() string { return "wrapped: " + w.e.Error() }
func (w *wrapErr) Unwrap() error { return w.e }

// TestClassifyClientInspectFailure pins that only a specific client cert-alert is
// a pinning signal; generic failures are not.
func TestClassifyClientInspectFailure(t *testing.T) {
	if r, ok := classifyClientInspectFailure(errors.New("remote error: tls: bad certificate")); !ok || r != autoExReasonClientPinned {
		t.Fatalf("bad-certificate alert should be client_pinned, got (%q,%v)", r, ok)
	}
	for _, s := range []string{"read: connection reset by peer", "remote error: tls: access denied", "remote error: tls: handshake failure"} {
		if _, ok := classifyClientInspectFailure(errors.New(s)); ok {
			t.Fatalf("%q must not be a pinning signal", s)
		}
	}
}

// TestClientEvidence pins B4: authenticated identity preferred, IPv6 collapses to
// /64, IPv4 stays raw.
func TestClientEvidence(t *testing.T) {
	if got := clientEvidence("alice@corp", "9.9.9.9"); got != "id:alice@corp" {
		t.Fatalf("identity should win: %q", got)
	}
	if got := clientEvidence("", "203.0.113.5"); got != "ip:203.0.113.5" {
		t.Fatalf("IPv4 must be raw (no /24 collapse): %q", got)
	}
	a := clientEvidence("", "2001:db8:a:b::1")
	b := clientEvidence("", "2001:db8:a:b::99")
	if a != b {
		t.Fatalf("same IPv6 /64 must collapse: %q vs %q", a, b)
	}
	c := clientEvidence("", "2001:db8:a:c::1")
	if a == c {
		t.Fatalf("different IPv6 /64 must differ: %q vs %q", a, c)
	}
}

// TestMaybeFailOpenOrigin_RescueOnlyClientCert pins B3: only client-cert-required
// rescues the triggering session; unsupported-params learns but does not rescue.
func TestMaybeFailOpenOrigin_RescueOnlyClientCert(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	fo, _ := bindFailOpenProfile(t, "fo", "fail-open")
	id := ProxyIdentity{ClientIP: "1.2.3.4", Identity: "u1"}
	if !maybeFailOpenOrigin("cc.example", fo, id, errors.New("remote error: tls: certificate required")) {
		t.Fatal("client-cert-required must rescue the triggering session")
	}
	if maybeFailOpenOrigin("unsup.example", fo, id, errors.New("tls: server selected unsupported protocol version 301")) {
		t.Fatal("unsupported-params must NOT rescue the triggering session (learn-only)")
	}
	// ...but it DID learn (confirmN=1) — next session self-heals.
	_, scope := bindFailOpenProfile(t, "fo", "fail-open")
	if _, ok := autoExclude.Contains(scope, "unsup.example"); !ok {
		t.Fatal("unsupported-params should have entered the cache (learn-only)")
	}
	// A fail-close rule never learns/rescues.
	fc, _ := bindFailOpenProfile(t, "fc", "fail-close")
	if maybeFailOpenOrigin("x.example", fc, id, errors.New("remote error: tls: certificate required")) {
		t.Fatal("fail-close rule must never rescue")
	}
}

// TestRecordAutoExclude_PromotesAndAudits pins that a confirm-count promotion
// (distinct identities) emits a scoped audit event (content-asserted, not len).
func TestRecordAutoExclude_PromotesAndAudits(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 2})
	swapProfiles(t)
	fo, scope := bindFailOpenProfile(t, "fo", "fail-open")
	baseline := time.Now().UnixMilli()
	recordAutoExclude(fo, "learn-audit.example", autoExReasonUnsupported, ProxyIdentity{ClientIP: "198.51.100.7", Identity: "u1"})
	recordAutoExclude(fo, "learn-audit.example", autoExReasonUnsupported, ProxyIdentity{ClientIP: "198.51.100.8", Identity: "u2"})
	if _, ok := autoExclude.Contains(scope, "learn-audit.example"); !ok {
		t.Fatal("host not excluded after confirm-count reached")
	}
	found := false
	for _, e := range auditGet() {
		if e.TS >= baseline && e.Action == "decryption.autoexclude.learn" && strings.Contains(e.Object, "learn-audit.example") && strings.Contains(e.Detail, "scope=fo") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no scoped decryption.autoexclude.learn audit entry")
	}
}

// TestRecordAutoExcludeRescue_EmitsObservability pins F1: the confirm-count-exempt
// live rescue emits the full observability triple (metric counter + audit entry +
// alert) on the rescue ACT — not just a log line, and independent of any
// persistent-cache promotion. Asserts audit CONTENT (unique host discriminator +
// baseline TS), never len(auditGet()) (audit-ring-saturation pitfall).
func TestRecordAutoExcludeRescue_EmitsObservability(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 2})
	swapProfiles(t)
	fo, _ := bindFailOpenProfile(t, "fo", "fail-open")

	before := atomic.LoadInt64(&autoExcludeRescueCounter)
	baseline := time.Now().UnixMilli()
	id := ProxyIdentity{ClientIP: "198.51.100.42", Identity: "u1"}

	// A SINGLE rescue: no promotion happens (confirm-count is 2, one client), so
	// this is exactly the previously-invisible case.
	recordAutoExcludeRescue(fo, "rescue-obs.example", autoExReasonClientCert, id)

	if got := atomic.LoadInt64(&autoExcludeRescueCounter); got != before+1 {
		t.Fatalf("rescue counter = %d, want %d (metric did not increment)", got, before+1)
	}
	// The rescue must NOT have created a persistent exclusion (it is confirm-count-
	// exempt for the live session only; the cache still requires the confirm-count).
	_, scope := bindFailOpenProfile(t, "fo", "fail-open")
	if _, ok := autoExclude.Contains(scope, "rescue-obs.example"); ok {
		t.Fatal("live rescue must not itself promote a persistent exclusion")
	}
	found := false
	for _, e := range auditGet() {
		if e.TS >= baseline && e.Action == "decryption.autoexclude.rescue" &&
			strings.Contains(e.Object, "rescue-obs.example") && strings.Contains(e.Detail, "scope=fo") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no decryption.autoexclude.rescue audit entry with the expected scope/host content")
	}

	// The counter must surface on /metrics.
	rw := httptest.NewRecorder()
	handleMetrics(rw, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	if !strings.Contains(rw.Body.String(), "culvert_decrypt_autoexclude_rescue_total") {
		t.Fatal("/metrics missing culvert_decrypt_autoexclude_rescue_total")
	}
}

// TestApiDecryptionExclusions_ListEvictClear exercises the handler surface.
func TestApiDecryptionExclusions_ListEvictClear(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	_, scope := bindFailOpenProfile(t, "fo", "fail-open")
	autoExclude.Observe(scope, "fo", "a.example", autoexclude.ReasonUnsupportedParams, "id:u1")
	autoExclude.Observe(scope, "fo", "b.example", autoexclude.ReasonClientPinned, "id:u1")

	rw := httptest.NewRecorder()
	apiDecryptionExclusions(rw, roleReq(RoleViewer, http.MethodGet, "/api/decryption-exclusions", nil))
	if rw.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", rw.Code)
	}
	body := rw.Body.String()
	if !strings.Contains(body, "a.example") || !strings.Contains(body, "\"stats\"") || !strings.Contains(body, "scope_rule_counts") {
		t.Fatalf("GET body missing entries/stats/scope: %s", body)
	}

	rw = httptest.NewRecorder()
	apiDecryptionExclusions(rw, roleReq(RoleOperator, http.MethodDelete, "/api/decryption-exclusions?scope="+scope+"&host=a.example", nil))
	if rw.Code != http.StatusOK {
		t.Fatalf("DELETE one status = %d, want 200", rw.Code)
	}
	if _, ok := autoExclude.Contains(scope, "a.example"); ok {
		t.Fatal("evicted host still present")
	}

	rw = httptest.NewRecorder()
	apiDecryptionExclusions(rw, roleReq(RoleOperator, http.MethodDelete, "/api/decryption-exclusions", nil))
	if rw.Code != http.StatusOK || autoExclude.Len() != 0 {
		t.Fatalf("clear failed: status=%d len=%d", rw.Code, autoExclude.Len())
	}
}

// TestApiDecryptionExclusions_ViewerCannotDelete pins the per-method RBAC split.
func TestApiDecryptionExclusions_ViewerCannotDelete(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	_, scope := bindFailOpenProfile(t, "fo", "fail-open")
	autoExclude.Observe(scope, "fo", "a.example", autoexclude.ReasonUnsupportedParams, "id:u1")
	rw := httptest.NewRecorder()
	apiDecryptionExclusions(rw, roleReq(RoleViewer, http.MethodDelete, "/api/decryption-exclusions?scope="+scope+"&host=a.example", nil))
	if rw.Code == http.StatusOK {
		t.Fatal("viewer was allowed to DELETE (operator-only)")
	}
	if _, ok := autoExclude.Contains(scope, "a.example"); !ok {
		t.Fatal("viewer DELETE mutated the cache")
	}
}
