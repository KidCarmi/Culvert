package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Audit-actor attribution on the HTTP Basic fallback.
//
// One admin action writes an actor to TWO surfaces: the audit ring (auditActor)
// and the config-version store (sessionAdmin). sessionAdmin learned to resolve
// the Basic-auth username the UI middleware authenticates into context; if
// auditActor did not, the same action would be attributed to two different
// identities — a bare IP in the audit trail beside a username in config
// history — which is exactly the correlation an incident review depends on.
//
// The authentication boundary is the load-bearing half: attribution comes from
// the context value uiAuthMiddleware sets AFTER cfg.VerifyUIUser succeeded,
// never from the request's own Authorization header, so an unauthenticated
// caller can never assert an actor.

const auditActorTestIP = "198.51.100.91" // TEST-NET-2 discriminator

func auditActorTestRequest(t *testing.T, path string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, nil)
	r.RemoteAddr = auditActorTestIP + ":4242"
	return r
}

// TestAuditActor_BasicAuthUsernameFromContext is the POSITIVE case: the
// authenticated Basic username reaches the audit actor, and the client IP is
// still kept for accountability.
func TestAuditActor_BasicAuthUsernameFromContext(t *testing.T) {
	r := auditActorTestRequest(t, "/api/policy")
	r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, "basic-admin"))

	if got, want := auditActor(r), "basic-admin@"+auditActorTestIP; got != want {
		t.Fatalf("auditActor = %q, want %q (an authenticated Basic actor must not audit as a bare IP)", got, want)
	}
}

// TestAuditActor_NoIdentityStaysBareIP is the NEGATIVE case: with no cookie and
// no authenticated username, the actor is the bare client IP — never a dangling
// "@" and never a fabricated name.
func TestAuditActor_NoIdentityStaysBareIP(t *testing.T) {
	if got := auditActor(auditActorTestRequest(t, "/api/policy")); got != auditActorTestIP {
		t.Fatalf("auditActor = %q, want the bare IP %q", got, auditActorTestIP)
	}
}

// TestAuditActor_EmptyContextUsernameIsNotAttributed is the BOUNDARY case: an
// empty username in context must be treated as no identity, not as an empty
// name producing a malformed "@IP" actor.
func TestAuditActor_EmptyContextUsernameIsNotAttributed(t *testing.T) {
	r := auditActorTestRequest(t, "/api/policy")
	r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, ""))

	if got := auditActor(r); got != auditActorTestIP {
		t.Fatalf("auditActor = %q, want the bare IP %q for an empty context username", got, auditActorTestIP)
	}
}

// TestAuditActor_WrongTypeContextValueIsIgnored is the MALFORMED case: a
// context value of an unexpected type must not panic and must not attribute.
func TestAuditActor_WrongTypeContextValueIsIgnored(t *testing.T) {
	r := auditActorTestRequest(t, "/api/policy")
	r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, 42))

	if got := auditActor(r); got != auditActorTestIP {
		t.Fatalf("auditActor = %q, want the bare IP %q for a non-string context value", got, auditActorTestIP)
	}
}

// TestAuditActor_SessionCookieWinsOverBasicUsername pins PRECEDENCE: when both
// identities are present the UI session cookie wins, exactly as in
// sessionAdmin. The Basic fallback must never override a real login.
func TestAuditActor_SessionCookieWinsOverBasicUsername(t *testing.T) {
	if !sessionSecretSet() {
		initSessionSecret()
	}
	r := auditActorTestRequest(t, "/api/policy")
	r.AddCookie(uiSessionCookieForTest(t, "cookie-admin"))
	r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, "basic-admin"))

	if got, want := auditActor(r), "cookie-admin@"+auditActorTestIP; got != want {
		t.Fatalf("auditActor = %q, want %q (the session cookie identity must win)", got, want)
	}
}

// TestAuditActor_ProxyUserCookieStillNeverAttributes is the REGRESSION guard
// for the original contract: the proxy-user cookie belongs to a different
// identity and must not attribute an admin action, and adding the Basic
// fallback must not have opened a path around that.
func TestAuditActor_ProxyUserCookieStillNeverAttributes(t *testing.T) {
	if !sessionSecretSet() {
		initSessionSecret()
	}
	r := auditActorTestRequest(t, "/api/policy")
	r.AddCookie(proxySessionCookieForTest(t, "browsing-user"))

	if got := auditActor(r); got != auditActorTestIP {
		t.Fatalf("auditActor = %q, want the bare IP %q (a proxy-user cookie must never attribute an admin action)", got, auditActorTestIP)
	}
}

// TestAuditActor_AgreesWithSessionAdmin is the PARITY proof that motivated the
// fix: for one request, the audit ring and the config-version store must name
// the same identity. A future change that teaches one surface an identity the
// other does not know fails here.
func TestAuditActor_AgreesWithSessionAdmin(t *testing.T) {
	if !sessionSecretSet() {
		initSessionSecret()
	}
	cases := []struct {
		name  string
		build func(t *testing.T) *http.Request
		want  string // the identity both surfaces must resolve ("" ⇒ no identity)
	}{
		{"basic_auth", func(t *testing.T) *http.Request {
			r := auditActorTestRequest(t, "/api/policy")
			return r.WithContext(context.WithValue(r.Context(), uiUserKey{}, "basic-admin"))
		}, "basic-admin"},
		{"ui_cookie", func(t *testing.T) *http.Request {
			r := auditActorTestRequest(t, "/api/policy")
			r.AddCookie(uiSessionCookieForTest(t, "cookie-admin"))
			return r
		}, "cookie-admin"},
		{"cookie_beats_basic", func(t *testing.T) *http.Request {
			r := auditActorTestRequest(t, "/api/policy")
			r.AddCookie(uiSessionCookieForTest(t, "cookie-admin"))
			return r.WithContext(context.WithValue(r.Context(), uiUserKey{}, "basic-admin"))
		}, "cookie-admin"},
		{"none", func(t *testing.T) *http.Request {
			return auditActorTestRequest(t, "/api/policy")
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.build(t)
			gotAudit := auditActor(r)
			gotVersion := sessionAdmin(r)
			wantAudit := auditActorTestIP
			wantVersion := "unknown"
			if tc.want != "" {
				wantAudit = tc.want + "@" + auditActorTestIP
				wantVersion = tc.want
			}
			if gotAudit != wantAudit || gotVersion != wantVersion {
				t.Fatalf("ATTRIBUTION DIVERGENCE: auditActor=%q (want %q), sessionAdmin=%q (want %q) — one admin action must name one identity on both surfaces",
					gotAudit, wantAudit, gotVersion, wantVersion)
			}
		})
	}
}

// TestAuditActor_UnverifiedBasicHeaderIsNeverAttributed is the AUTHENTICATION
// boundary: attribution reads the context value the middleware sets, never the
// request's own Authorization header. A caller that simply sends credentials
// must not be able to assert an actor into the audit trail.
func TestAuditActor_UnverifiedBasicHeaderIsNeverAttributed(t *testing.T) {
	raw := auditActorTestRequest(t, "/api/policy")
	raw.SetBasicAuth("attacker", "whatever")

	if got := auditActor(raw); got != auditActorTestIP {
		t.Fatalf("auditActor = %q, want the bare IP %q — an unverified Authorization header must never assert an actor", got, auditActorTestIP)
	}
	if got := sessionAdmin(raw); got != "unknown" {
		t.Fatalf("sessionAdmin = %q, want %q for an unverified Authorization header", got, "unknown")
	}
}

// TestAuditActor_BasicIdentityOriginatesOnlyFromVerifiedLogin is the STRUCTURAL
// half of the authentication boundary: the identity auditActor and sessionAdmin
// now trust is only as good as the single place that writes it. This pins that
// uiUserKey is written in exactly one non-test source location, in
// ui_middleware.go, inside the branch guarded by cfg.VerifyUIUser — so no future
// handler can inject an actor that was never authenticated.
func TestAuditActor_BasicIdentityOriginatesOnlyFromVerifiedLogin(t *testing.T) {
	sources, err := filepath.Glob(filepath.Join(pkgSourceDir(), "*.go"))
	if err != nil {
		t.Fatalf("glob sources: %v", err)
	}
	writers := map[string]int{}
	for _, f := range sources {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, rerr := os.ReadFile(f) // #nosec G304 -- test-local glob of this package's own sources
		if rerr != nil {
			t.Fatalf("read %s: %v", f, rerr)
		}
		// bytes.Count over the raw file, not strings.Count(string(raw), …): converting
		// every source file to a string allocates a copy per file (gocritic indexAlloc).
		if n := bytes.Count(raw, []byte("context.WithValue(ctx, uiUserKey{}")) +
			bytes.Count(raw, []byte("context.WithValue(r.Context(), uiUserKey{}")); n > 0 {
			writers[filepath.Base(f)] = n
		}
	}
	if len(writers) != 1 || writers["ui_middleware.go"] != 1 {
		t.Fatalf("uiUserKey must be written exactly once, in ui_middleware.go, got %v", writers)
	}
	mw, err := os.ReadFile(filepath.Join(pkgSourceDir(), "ui_middleware.go"))
	if err != nil {
		t.Fatalf("read ui_middleware.go: %v", err)
	}
	verifyAt := bytes.Index(mw, []byte("cfg.VerifyUIUser(user, pass)"))
	writeAt := bytes.Index(mw, []byte("uiUserKey{}"))
	if verifyAt < 0 || writeAt < 0 || writeAt < verifyAt {
		t.Fatalf("the uiUserKey write must follow cfg.VerifyUIUser (verify@%d, write@%d)", verifyAt, writeAt)
	}
}

// TestAuditEvent_BasicAuthActorReachesTheRing proves the identity survives the
// whole auditEvent path into the ring. It asserts on entry CONTENT (unique
// action + TEST-NET-2 actor + baseline TS), never on ring length, because the
// ring is bounded at maxAuditLogs and saturates under -count=2 -shuffle=on.
func TestAuditEvent_BasicAuthActorReachesTheRing(t *testing.T) {
	r := auditActorTestRequest(t, "/api/policy")
	r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, "ring-basic-admin"))

	baseline := time.Now().UnixMilli()
	auditEvent(r, "test.audit_actor_basic_auth", "obj", "detail")

	want := "ring-basic-admin@" + auditActorTestIP
	for _, e := range auditGet() {
		if e.TS >= baseline && e.Action == "test.audit_actor_basic_auth" && e.Actor == want {
			return
		}
	}
	t.Fatalf("no audit entry with actor %q for action %q after baseline", want, "test.audit_actor_basic_auth")
}

// TestAuditActor_ConcurrentIsRaceClean hammers auditActor across all identity
// shapes so the added context read is proven race-free under -race. Each
// goroutine builds its own request; the test asserts only completion.
func TestAuditActor_ConcurrentIsRaceClean(t *testing.T) {
	if !sessionSecretSet() {
		initSessionSecret()
	}
	cookie := uiSessionCookieForTest(t, "concurrent-admin")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/policy", nil)
				r.RemoteAddr = auditActorTestIP + ":4242"
				switch i % 3 {
				case 0:
					r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, "basic-admin"))
				case 1:
					r.AddCookie(cookie)
				}
				_ = auditActor(r)
			}
		}(i)
	}
	wg.Wait() // completes ⇒ no deadlock; -race ⇒ no data race
}
