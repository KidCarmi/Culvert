package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// d0Mutating is the set of HTTP methods securityMiddleware treats as
// state-changing for the purposes of CSRF, body-limit, and rate-limit
// enforcement. Mirrors the literal isMutating expression at
// ui_middleware.go:securityMiddleware.
var d0Mutating = []string{http.MethodPost, http.MethodPut, http.MethodDelete}

// d0NoopOK is a sentinel handler that records whether it was invoked and
// always returns 200. Used by the mutation tests to distinguish "middleware
// blocked the request" from "downstream handler ran and returned X".
type d0NoopOK struct{ called bool }

func (n *d0NoopOK) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	n.called = true
	w.WriteHeader(http.StatusOK)
}

// TestD0_CSRF_ForeignOriginMutating_Rejected pins the same-origin CSRF
// guard at securityMiddleware. For each mutating method, an Origin header
// pointing at a foreign host MUST cause a 403 before the handler runs.
func TestD0_CSRF_ForeignOriginMutating_Rejected(t *testing.T) {
	for _, m := range d0Mutating {
		t.Run(m, func(t *testing.T) {
			noop := &d0NoopOK{}
			handler := securityMiddleware(noop)

			req := httptest.NewRequest(m, "/api/policy", strings.NewReader(`{}`))
			req.Host = "ui.internal:9090"
			req.Header.Set("Origin", "https://evil.example.com")
			req.RemoteAddr = "198.51.100.30:0"

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("%s with foreign Origin: got %d, want 403", m, rec.Code)
			}
			if noop.called {
				t.Errorf("%s with foreign Origin: handler ran (CSRF guard bypassed)", m)
			}
		})
	}
}

// TestD0_CSRF_GETForeignOrigin_NotRejected confirms the CSRF guard
// applies ONLY to mutating methods. A GET with a foreign Origin must
// still reach the handler — this protects safe browser navigation and
// cross-origin tooling that respects same-origin policy at the response
// layer (Access-Control-Allow-Origin reflection).
func TestD0_CSRF_GETForeignOrigin_NotRejected(t *testing.T) {
	noop := &d0NoopOK{}
	handler := securityMiddleware(noop)

	req := httptest.NewRequest(http.MethodGet, "/api/policy", http.NoBody)
	req.Host = "ui.internal:9090"
	req.Header.Set("Origin", "https://evil.example.com")
	req.RemoteAddr = "198.51.100.31:0"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !noop.called {
		t.Errorf("GET with foreign Origin: handler did not run (CSRF guard now over-rejects safe methods)")
	}
	if rec.Code == http.StatusForbidden {
		t.Errorf("GET with foreign Origin: got 403, want non-403")
	}
}

// TestD0_CSRF_NoOriginMutating_NotRejected confirms the CSRF guard does
// NOT block mutating requests that omit the Origin header altogether
// (curl, CLI tooling, Basic-Auth API clients). Those callers cannot be
// browser-driven cross-site forgeries and must remain functional.
func TestD0_CSRF_NoOriginMutating_NotRejected(t *testing.T) {
	noop := &d0NoopOK{}
	handler := securityMiddleware(noop)

	req := httptest.NewRequest(http.MethodPost, "/api/policy", strings.NewReader(`{}`))
	req.Host = "ui.internal:9090"
	// no Origin header set
	req.RemoteAddr = "198.51.100.32:0"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !noop.called {
		t.Errorf("POST without Origin: handler did not run (CSRF guard now over-rejects API clients)")
	}
}

// TestD0_BodyLimit_MutatingCappedAt1MiB pins the 1 MiB body cap that
// securityMiddleware installs via http.MaxBytesReader on every mutating
// request. We send a 2 MiB body and confirm the downstream handler can
// read at most 1 MiB before MaxBytesReader returns an error.
//
// MaxBytesReader returns *http.MaxBytesError on overflow; the bytes
// actually delivered are bounded at the configured limit. Both checks
// must hold.
func TestD0_BodyLimit_MutatingCappedAt1MiB(t *testing.T) {
	const cap = 1 << 20 // matches ui_middleware.go
	const oversize = 2 << 20

	var (
		gotLen int
		gotErr error
	)
	handler := securityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		gotLen = len(b)
		gotErr = err
	}))

	body := strings.NewReader(strings.Repeat("x", oversize))
	req := httptest.NewRequest(http.MethodPost, "/api/policy", body)
	req.RemoteAddr = "198.51.100.33:0"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if gotLen > cap {
		t.Errorf("body read = %d bytes, want ≤ %d (MaxBytesReader cap broken)", gotLen, cap)
	}
	if gotErr == nil {
		t.Errorf("expected an error from io.ReadAll on a 2 MiB body, got nil (MaxBytesReader not wired)")
	}
}

// TestD0_RateLimit_MutatingTrips429 pins the per-IP rate limiter at
// securityMiddleware. We hammer mutating /api/* requests from a single,
// unique remote address and assert that 429 fires within
// apiRateBurst+slack iterations. Using a unique IP avoids leaking state
// into other suites.
func TestD0_RateLimit_MutatingTrips429(t *testing.T) {
	const slack = 5
	const remoteIP = "198.51.100.34:0"

	noop := &d0NoopOK{}
	handler := securityMiddleware(noop)

	var saw429 bool
	for i := 0; i < apiRateBurst+slack; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/policy", http.NoBody)
		req.RemoteAddr = remoteIP
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			saw429 = true
			break
		}
	}
	if !saw429 {
		t.Errorf("expected to trip 429 within %d POSTs from %s; rate limiter inactive", apiRateBurst+slack, remoteIP)
	}
}

// TestD0_RateLimit_NotAppliedToReads confirms the rate limiter is scoped
// to mutating methods. A burst of GETs from a single IP must NEVER
// produce a 429 — read-only dashboards would break otherwise.
func TestD0_RateLimit_NotAppliedToReads(t *testing.T) {
	const remoteIP = "198.51.100.35:0"

	noop := &d0NoopOK{}
	handler := securityMiddleware(noop)

	for i := 0; i < apiRateBurst*2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/policy", http.NoBody)
		req.RemoteAddr = remoteIP
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("GET #%d returned 429: rate limit now applies to reads (regression)", i+1)
		}
	}
}

// TestD0_Chain_HealthzReachable is the smallest possible end-to-end smoke
// of the full middleware chain composition. /healthz is public (non-/api/
// so uiAuthMiddleware passes it through), is GET so securityMiddleware's
// CSRF + body + rate-limit checks are no-ops, and is unrestricted by
// uiIPGuardMiddleware when no allowlist is set. Anything other than 200
// here means the chain wiring itself broke.
func TestD0_Chain_HealthzReachable(t *testing.T) {
	d0EnableLocalAuth(t)

	handler := d0WrappedHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	req.RemoteAddr = "198.51.100.36:0"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("/healthz through full chain: got %d, want 200 (body=%s)",
			rec.Code, rec.Body.String())
	}
}
