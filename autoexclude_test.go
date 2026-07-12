package main

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
	"github.com/KidCarmi/Culvert/internal/decryptprofile"
)

// swapAutoExclude installs a fresh empty cache for a test and restores the prior
// singleton on cleanup. Mirrors swapDecProfileStore — MANDATORY for any test that
// calls Observe/recordAutoExclude or drives resolveSSLAction, so the global cache
// cannot leak state into later tests under -shuffle (the PR3d fence-pollution
// class of bug). cfg lets a test tune the confirm-count etc.
func swapAutoExclude(t *testing.T, cfg autoexclude.Config) {
	t.Helper()
	prev := autoExclude
	autoExclude = autoexclude.New(cfg)
	t.Cleanup(func() { autoExclude = prev })
}

// bindFailOpenProfile installs a decryption-profile store with a single
// fail-open profile and a rule match that references it. Returns the match.
func bindFailOpenProfile(t *testing.T, onInspectError string) *PolicyMatch {
	t.Helper()
	prev := globalDecryptionProfiles
	globalDecryptionProfiles = decryptprofile.New()
	t.Cleanup(func() { globalDecryptionProfiles = prev })
	if _, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "fo", OnInspectError: onInspectError}); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	return &PolicyMatch{
		Action:    ActionAllow,
		SSLAction: SSLInspect,
		Rule:      &PolicyRule{Name: "r", SSLAction: SSLInspect, DecryptionProfile: "fo"},
	}
}

// TestResolveSSLAction_EmptyCacheByteIdentical pins the "byte-identical when
// unused" invariant: with an empty cache, an Inspect decision stays Inspect —
// the added fail-open block is dead. This is the regression that guards against
// the cache ever silently changing today's behavior for non-fail-open traffic.
func TestResolveSSLAction_EmptyCacheByteIdentical(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{})
	// No profile at all (fail-open not opted in) → cache never consulted.
	m := &PolicyMatch{Action: ActionAllow, SSLAction: SSLInspect, Rule: &PolicyRule{Name: "r", SSLAction: SSLInspect}}
	if a, _ := resolveSSLAction(m, "example.com", "1.2.3.4"); a != SSLInspect {
		t.Fatalf("empty cache changed the SSL action: got %q want Inspect", a)
	}
	// Even a fail-open rule, with an empty cache, stays Inspect (nothing learned).
	fo := bindFailOpenProfile(t, "fail-open")
	if a, _ := resolveSSLAction(fo, "example.com", "1.2.3.4"); a != SSLInspect {
		t.Fatalf("fail-open rule + empty cache should still Inspect: got %q", a)
	}
}

// TestResolveSSLAction_FailCloseNeverConsults pins the never-exclude control: a
// host that IS in the cache is still inspected when the matched rule is
// fail-close (the read is gated on fail-open). This is what makes critical hosts
// on fail-close rules un-poisonable.
func TestResolveSSLAction_FailCloseNeverConsults(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	autoExclude.Observe("locked.example", autoexclude.ReasonUnsupported, "9.9.9.9") // now excluded
	if _, ok := autoExclude.Contains("locked.example"); !ok {
		t.Fatal("precondition: host should be excluded")
	}
	// fail-close profile → resolveFailOpen false → cache NOT consulted → Inspect.
	fc := bindFailOpenProfile(t, "fail-close")
	if a, _ := resolveSSLAction(fc, "locked.example", "1.2.3.4"); a != SSLInspect {
		t.Fatalf("fail-close rule consulted the cache: got %q want Inspect", a)
	}
	// A fail-open rule for the SAME host DOES bypass (self-heal).
	fo := bindFailOpenProfile(t, "fail-open")
	if a, _ := resolveSSLAction(fo, "locked.example", "1.2.3.4"); a != SSLBypass {
		t.Fatalf("fail-open rule did not self-heal: got %q want Bypass", a)
	}
}

// TestClassifyOriginInspectFailure_NeverLearnsCertVerify pins the reframe: an
// untrusted/expired/mismatch origin cert is NOT learnable (it is a Block signal,
// and the poisoning vector), while unsupported/client-cert-required ARE.
func TestClassifyOriginInspectFailure_NeverLearnsCertVerify(t *testing.T) {
	certVerifyErrs := []error{
		x509.UnknownAuthorityError{},
		&x509.CertificateInvalidError{Reason: x509.Expired},
		x509.HostnameError{Host: "x"},
		errors.New("x509: certificate signed by unknown authority"),
		errors.New("tls: failed to verify certificate: x509: certificate has expired"),
	}
	for _, e := range certVerifyErrs {
		if _, learn := classifyOriginInspectFailure(e); learn {
			t.Fatalf("cert-verify error learned (poisoning vector): %v", e)
		}
	}
	learnable := map[error]AutoExcludeReason{
		errors.New("remote error: tls: certificate required"): autoExReasonClientCert,
		errors.New("tls: protocol version not supported"):     autoExReasonUnsupported,
		errors.New("remote error: tls: handshake failure"):    autoExReasonUnsupported,
		errors.New("tls: no cipher suite supported by both"):  autoExReasonUnsupported,
	}
	for e, want := range learnable {
		r, learn := classifyOriginInspectFailure(e)
		if !learn || r != want {
			t.Fatalf("classify %q = (%q,%v), want (%q,true)", e, r, learn, want)
		}
	}
	// EOF / unrecognized → do not learn (fail-closed default).
	if _, learn := classifyOriginInspectFailure(errors.New("EOF")); learn {
		t.Fatal("EOF must not be learnable")
	}
}

// TestClassifyClientInspectFailure pins that only a client cert-alert is a
// pinning signal; a plain EOF/RST is not.
func TestClassifyClientInspectFailure(t *testing.T) {
	if r, ok := classifyClientInspectFailure(errors.New("remote error: tls: bad certificate")); !ok || r != autoExReasonClientPinned {
		t.Fatalf("bad-certificate alert should be client_pinned, got (%q,%v)", r, ok)
	}
	if _, ok := classifyClientInspectFailure(errors.New("read: connection reset by peer")); ok {
		t.Fatal("a plain RST must not be a pinning signal")
	}
}

// TestRecordAutoExclude_PromotesAndAudits pins that a confirm-count promotion
// emits an audit event (content-asserted, NOT len-delta — the ring saturates
// under -shuffle). Uses a TEST-NET-2 actor IP as the unique discriminator.
func TestRecordAutoExclude_PromotesAndAudits(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 2})
	const host = "learn-audit.example"
	baseline := time.Now().UnixMilli()
	recordAutoExclude(host, autoExReasonUnsupported, "198.51.100.7") // 1st distinct IP → no promote
	recordAutoExclude(host, autoExReasonUnsupported, "198.51.100.8") // 2nd → promote
	if _, ok := autoExclude.Contains(host); !ok {
		t.Fatal("host not excluded after confirm-count reached")
	}
	found := false
	for _, e := range auditGet() {
		if e.TS >= baseline && e.Action == "decryption.autoexclude.learn" && e.Object == host && strings.Contains(e.Actor, "198.51.100.8") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no decryption.autoexclude.learn audit entry with the triggering client IP")
	}
}

// TestApiDecryptionExclusions_ListEvictClear exercises the handler surface:
// viewer GET lists entries + posture; operator DELETE evicts one and clears all,
// each auditing (so C2c does not flag audit_missing).
func TestApiDecryptionExclusions_ListEvictClear(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	autoExclude.Observe("a.example", autoexclude.ReasonUnsupported, "1.1.1.1")
	autoExclude.Observe("b.example", autoexclude.ReasonClientPinned, "1.1.1.1")

	// GET as viewer.
	rw := httptest.NewRecorder()
	apiDecryptionExclusions(rw, roleReq(RoleViewer, http.MethodGet, "/api/decryption-exclusions", nil))
	if rw.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", rw.Code)
	}
	body := rw.Body.String()
	if !strings.Contains(body, "a.example") || !strings.Contains(body, "\"stats\"") {
		t.Fatalf("GET body missing entries or stats: %s", body)
	}

	// DELETE one host as operator.
	rw = httptest.NewRecorder()
	apiDecryptionExclusions(rw, roleReq(RoleOperator, http.MethodDelete, "/api/decryption-exclusions?host=a.example", nil))
	if rw.Code != http.StatusOK {
		t.Fatalf("DELETE one status = %d, want 200", rw.Code)
	}
	if _, ok := autoExclude.Contains("a.example"); ok {
		t.Fatal("evicted host still present")
	}

	// DELETE all (clear) as operator.
	rw = httptest.NewRecorder()
	apiDecryptionExclusions(rw, roleReq(RoleOperator, http.MethodDelete, "/api/decryption-exclusions", nil))
	if rw.Code != http.StatusOK || autoExclude.Len() != 0 {
		t.Fatalf("clear failed: status=%d len=%d", rw.Code, autoExclude.Len())
	}
}

// TestApiDecryptionExclusions_ViewerCannotDelete pins the per-method RBAC split:
// a viewer is rejected on DELETE (operator-only) even though GET is viewer-ok.
func TestApiDecryptionExclusions_ViewerCannotDelete(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	autoExclude.Observe("a.example", autoexclude.ReasonUnsupported, "1.1.1.1")
	rw := httptest.NewRecorder()
	apiDecryptionExclusions(rw, roleReq(RoleViewer, http.MethodDelete, "/api/decryption-exclusions?host=a.example", nil))
	if rw.Code == http.StatusOK {
		t.Fatal("viewer was allowed to DELETE (operator-only)")
	}
	if _, ok := autoExclude.Contains("a.example"); !ok {
		t.Fatal("viewer DELETE mutated the cache")
	}
}
