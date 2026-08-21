package main

// Ingress trust boundary for the internal X-User-Identity header (F1, security
// review docs/security-reviews/2026-08-13-x-user-identity-ingress-trust.md).
//
// The product invariant under test: NO client-controlled X-User-Identity value
// may influence policy evaluation, authorization semantics, or log attribution.
// The existing spoof test (TestAuthzMatrix_IdentityHeaderSpoofIgnored) covers
// the auth-required posture, where the request 407s before evaluation. These
// tests cover the identity-free postures — default-Exempt and no-backend inert
// — where the request DOES reach Stage-2 evaluation and, before the F1 fix,
// a client-supplied header value flowed into policyStore.Evaluate as the
// SourceIdentity input (proxy.go read the header back after conditionally
// stamping it, and nothing scrubbed it on ingress).
//
// Each e2e case asserts all three planes: proxy response, upstream reach, and
// request-log attribution.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// spoofedGet sends a GET through the proxy with a client-supplied
// X-User-Identity header and no credentials.
func spoofedGet(t *testing.T, proxyURL *url.URL, targetURL, spoof string) int {
	t.Helper()
	p := *proxyURL
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&p)},
		Timeout:   5 * time.Second,
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-User-Identity", spoof)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("spoofed GET: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// assertNoIdentityAttribution scans the request-log ring for entries about the
// given destination host and fails if any carries a non-empty identity: the
// only identity source on these test paths would be the spoofed header.
func assertNoIdentityAttribution(t *testing.T, destHost string) {
	t.Helper()
	entries := logGet()
	for i := range entries { // index-based: LogEntry is a large struct (rangeValCopy)
		if entries[i].Host == destHost && entries[i].Identity != "" {
			t.Errorf("log entry for %s attributed to identity %q — client-controlled header must never reach log attribution", destHost, entries[i].Identity)
		}
	}
}

// TestIdentityIngress_ExemptSpoofDenied: default-Exempt (open) posture with a
// SourceIdentity-scoped allow rule. The unauthenticated request reaches
// Stage-2 with an EMPTY identity; a spoofed X-User-Identity: alice must not
// satisfy the alice-scoped rule, so the default-deny applies (403), the
// upstream is never reached, and no log entry is attributed to "alice".
func TestIdentityIngress_ExemptSpoofDenied(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(), []PolicyRule{{
		Priority: 1, Name: "alice-allow", DestFQDN: "*", SourceIdentity: "alice", Action: ActionAllow,
	}})
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })

	got := spoofedGet(t, proxyURL, backend.URL+"/", "alice")
	if got != http.StatusForbidden {
		t.Errorf("exempt + spoofed X-User-Identity: status %d, want 403 — the spoofed header must not satisfy a SourceIdentity rule", got)
	}
	if cb.hitCount() != 0 {
		t.Errorf("spoofed-identity request reached upstream %d times, want 0", cb.hitCount())
	}
	if u, err := url.Parse(backend.URL); err == nil {
		assertNoIdentityAttribution(t, u.Host)
	}
}

// TestIdentityIngress_NoBackendSpoofDenied: the no-backend inert posture (no
// local user, no legacy provider, no enabled IdP, Default outcome). Stage-1 is
// skipped entirely, so the request reaches Stage-2 with an empty identity; a
// spoofed header must not satisfy the identity-scoped rule.
func TestIdentityIngress_NoBackendSpoofDenied(t *testing.T) {
	backend, cb := startCountingBackend(t)
	setupProxyTest(t) // fresh cfg: no local user, no provider; default deny

	origReg := idpRegistry
	idpRegistry = &IdPRegistry{}
	t.Cleanup(func() { idpRegistry = origReg })

	policyStore.Add(PolicyRule{
		Priority: 1, Name: "alice-allow", DestFQDN: "*", SourceIdentity: "alice", Action: ActionAllow,
	})

	srv := httptest.NewServer(http.HandlerFunc(handleRequest))
	t.Cleanup(srv.Close)
	proxyURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}

	got := spoofedGet(t, proxyURL, backend.URL+"/", "alice")
	if got != http.StatusForbidden {
		t.Errorf("no-backend + spoofed X-User-Identity: status %d, want 403 (default deny)", got)
	}
	if cb.hitCount() != 0 {
		t.Errorf("spoofed-identity request reached upstream %d times, want 0", cb.hitCount())
	}
	if u, err := url.Parse(backend.URL); err == nil {
		assertNoIdentityAttribution(t, u.Host)
	}
}

// TestIdentityIngress_AuthenticatedIdentityStillAttributed: regression guard
// for the fix itself — the server-stamped identity channel must keep working.
// An authenticated request in the right group is allowed and its log entry
// carries the REAL identity, proving the ingress scrub removed only the
// client-supplied value, not the internal stamping.
func TestIdentityIngress_AuthenticatedIdentityStillAttributed(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(), engRule())

	p := *proxyURL
	p.User = url.UserPassword("alice", "eng-token")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&p)}, Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, backend.URL+"/", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-User-Identity", "mallory") // spoof attempt alongside real creds
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("authenticated GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated request: status %d, want 200", resp.StatusCode)
	}
	if cb.hitCount() == 0 {
		t.Fatalf("authenticated request should reach upstream")
	}

	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	found := false
	for _, e := range logGet() {
		if e.Host != u.Host {
			continue
		}
		if e.Identity == "mallory" {
			t.Fatalf("log entry attributed to the SPOOFED identity %q", e.Identity)
		}
		if e.Identity == "alice" {
			found = true
		}
	}
	if !found {
		t.Errorf("no log entry attributed to the authenticated identity 'alice' — internal identity stamping must survive the ingress scrub")
	}
}

// TestIdentityIngress_LateTrailerCannotResurrectScrubbedKeys (Codex round 7):
// the early trailer deletion alone is defeated by net/http itself — for a
// chunked request with declared trailers, the server merges the RECEIVED
// trailer values back into r.Trailer when the body reaches EOF, AFTER
// scrubForwardedHeaders ran, and the forward paths (client.Do(r), r.Write)
// emit trailers from that same map. The scrub's body wrapper must re-delete
// the banned keys at EOF, so the map the outbound writer reads is clean.
func TestIdentityIngress_LateTrailerCannotResurrectScrubbedKeys(t *testing.T) {
	type result struct{ pre, post string }
	got := make(chan result, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scrubForwardedHeaders(r) // as every forward path does before sending upstream
		pre := r.Trailer.Get("X-User-Identity")
		// Reading the body to EOF is exactly what the upstream transport does
		// before writing the trailer section from r.Trailer.
		_, _ = io.Copy(io.Discard, r.Body)
		got <- result{pre: pre, post: r.Trailer.Get("X-User-Identity")}
	}))
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.ContentLength = -1 // chunked, so the trailer section exists
	req.Trailer = http.Header{}
	req.Trailer.Set("X-User-Identity", "mallory@evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	resp.Body.Close()

	r := <-got
	if r.pre != "" {
		t.Fatalf("early scrub failed outright: %q", r.pre)
	}
	if r.post != "" {
		t.Fatalf("late trailer resurrected the scrubbed identity key after body EOF: %q — the forwarded trailer map is poisoned", r.post)
	}
}

// TestIdentityIngress_TrailerScrubbed: scrubForwardedHeaders must strip the
// identity/topology keys from request TRAILERS too — Go forwards r.Trailer on
// r.Write, and the 2026-07-11 security review noted the scrub was Header-only.
func TestIdentityIngress_TrailerScrubbed(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Trailer = http.Header{
		"X-User-Identity": []string{"spoof@evil.example"},
		"X-Forwarded-For": []string{"10.0.0.1"},
		"X-Real-Ip":       []string{"10.0.0.2"},
	}
	scrubForwardedHeaders(req)
	for _, k := range []string{"X-User-Identity", "X-Forwarded-For", "X-Real-Ip"} {
		if got := req.Trailer.Get(k); got != "" {
			if strings.Contains(k, "Identity") {
				t.Errorf("trailer %s survived scrubForwardedHeaders: %q — identity claims must not ride through as trailers", k, got)
			} else {
				t.Errorf("trailer %s survived scrubForwardedHeaders: %q", k, got)
			}
		}
	}
}
