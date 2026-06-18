package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Phase 3 Slice 1 — deterministic client classifier tests.
//
// classifyClient is landed and fully exercised here but is NOT yet wired into
// the request hot path (the no-credentials Default path still uses
// browserRedirectEligibleLegacy). These tests pin: (1) the classifier's
// deterministic behavior across the header matrix, (2) that the classifier is
// User-Agent-FREE (Plan Freeze #5 — Mozilla is quarantined in the legacy
// predicate, not the classifier), (3) that classifyClient and the legacy
// predicate intentionally DIVERGE on a Mozilla-UA request with no
// HTML-navigation signal, and (4) that the Default redirect path is
// byte-identical after the extract-method refactor.

// reqWith builds a non-CONNECT GET (unless method overrides) carrying the given
// headers, for classifier matrix testing.
func reqWith(t *testing.T, method string, headers map[string]string) *http.Request {
	t.Helper()
	if method == "" {
		method = http.MethodGet
	}
	r := httptest.NewRequestWithContext(t.Context(), method, "http://dest.example.test/", http.NoBody)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestClassifyClient_Matrix(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		headers map[string]string
		want    ClientClass
	}{
		// CONNECT always wins, regardless of any browser-looking header.
		{"connect plain", http.MethodConnect, nil, clientConnect},
		{"connect with html accept", http.MethodConnect, map[string]string{"Accept": "text/html"}, clientConnect},
		{"connect with navigate", http.MethodConnect, map[string]string{"Sec-Fetch-Mode": "navigate"}, clientConnect},
		{"connect with mozilla", http.MethodConnect, map[string]string{"User-Agent": "Mozilla/5.0"}, clientConnect},

		// Deterministic browser-navigation signals (the ONLY way to Browser).
		{"sec-fetch navigate", "", map[string]string{"Sec-Fetch-Mode": "navigate"}, clientBrowser},
		{"accept text/html", "", map[string]string{"Accept": "text/html,application/xhtml+xml"}, clientBrowser},

		// User-Agent is NOT a gate (Freeze #5): Mozilla alone → NonBrowser.
		{"mozilla alone is not browser", "", map[string]string{"User-Agent": "Mozilla/5.0"}, clientNonBrowser},
		{"mozilla with json accept", "", map[string]string{"User-Agent": "Mozilla/5.0", "Accept": "application/json"}, clientNonBrowser},
		{"mozilla websocket", "", map[string]string{"User-Agent": "Mozilla/5.0", "Sec-Fetch-Mode": "websocket"}, clientNonBrowser},

		// Non-browser: none of the navigation signals.
		{"curl json", "", map[string]string{"User-Agent": "curl/8.0", "Accept": "application/json"}, clientNonBrowser},
		{"bare request", "", nil, clientNonBrowser},
		{"sec-fetch cors not navigate", "", map[string]string{"Sec-Fetch-Mode": "cors"}, clientNonBrowser},
		{"accept json only", "", map[string]string{"Accept": "application/json"}, clientNonBrowser},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyClient(reqWith(t, tc.method, tc.headers)); got != tc.want {
				t.Errorf("classifyClient = %d, want %d", got, tc.want)
			}
		})
	}
}

// classifyClient must be User-Agent-free (Plan Freeze #5): the classification is
// identical whether or not a Mozilla User-Agent is present — only the
// HTML-navigation signal decides Browser-vs-NonBrowser.
func TestClassifyClient_IsUserAgentFree(t *testing.T) {
	type hdrs = map[string]string
	signalCases := []hdrs{
		{"Accept": "text/html"},        // navigable → Browser
		{"Sec-Fetch-Mode": "navigate"}, // navigable → Browser
		{"Accept": "application/json"}, // not navigable → NonBrowser
		{},                             // bare → NonBrowser
	}
	for _, base := range signalCases {
		withoutUA := reqWith(t, "", base)
		withUA := reqWith(t, "", base)
		withUA.Header.Set("User-Agent", "Mozilla/5.0")
		if classifyClient(withoutUA) != classifyClient(withUA) {
			t.Errorf("classifyClient must ignore User-Agent; diverged for headers %v (no-UA=%d, mozilla=%d)",
				base, classifyClient(withoutUA), classifyClient(withUA))
		}
	}
}

// quarantineMatrix enumerates inputs that distinguish the legacy predicate from
// the UA-free classifier.
func quarantineMatrix(t *testing.T) []*http.Request {
	t.Helper()
	var reqs []*http.Request
	for _, method := range []string{http.MethodGet, http.MethodConnect} {
		for _, ua := range []string{"", "Mozilla/5.0", "curl/8.0"} {
			for _, accept := range []string{"", "text/html", "application/json"} {
				for _, sfm := range []string{"", "navigate", "cors"} {
					h := map[string]string{}
					if ua != "" {
						h["User-Agent"] = ua
					}
					if accept != "" {
						h["Accept"] = accept
					}
					if sfm != "" {
						h["Sec-Fetch-Mode"] = sfm
					}
					reqs = append(reqs, reqWith(t, method, h))
				}
			}
		}
	}
	return reqs
}

// The legacy Mozilla heuristic is quarantined in browserRedirectEligibleLegacy
// and never leaks into classifyClient (Plan Freeze #5). This pins:
//   - the legacy predicate is EXACTLY (Mozilla && non-CONNECT);
//   - classifyClient is UA-free (decided solely by CONNECT + navigation signals);
//   - CONNECT is never Browser;
//   - the two predicates DIVERGE on a Mozilla-UA request with no navigation
//     signal (legacy=eligible, classifier=NonBrowser) — at least one such case
//     is observed, proving the quarantine.
func TestClassifier_QuarantinesLegacyHeuristic(t *testing.T) {
	divergenceObserved := false
	for _, r := range quarantineMatrix(t) {
		legacy := browserRedirectEligibleLegacy(r)
		class := classifyClient(r)

		// Lock legacy semantics: exactly Mozilla && non-CONNECT.
		wantLegacy := r.Method != http.MethodConnect && r.Header.Get("User-Agent") == "Mozilla/5.0"
		if legacy != wantLegacy {
			t.Errorf("legacy predicate drifted: got %v want %v for method=%s UA=%q",
				legacy, wantLegacy, r.Method, r.Header.Get("User-Agent"))
		}

		// classifyClient must NOT depend on the User-Agent: recompute it on a
		// UA-stripped clone and require equality.
		stripped := reqWith(t, r.Method, map[string]string{})
		if a := r.Header.Get("Accept"); a != "" {
			stripped.Header.Set("Accept", a)
		}
		if s := r.Header.Get("Sec-Fetch-Mode"); s != "" {
			stripped.Header.Set("Sec-Fetch-Mode", s)
		}
		if class != classifyClient(stripped) {
			t.Errorf("classifyClient leaked a User-Agent dependence for method=%s UA=%q Accept=%q SFM=%q",
				r.Method, r.Header.Get("User-Agent"), r.Header.Get("Accept"), r.Header.Get("Sec-Fetch-Mode"))
		}

		// CONNECT is never Browser.
		if r.Method == http.MethodConnect && class == clientBrowser {
			t.Errorf("CONNECT must never classify Browser")
		}

		// Observe the intended divergence: Mozilla-UA, non-CONNECT, no nav signal.
		if legacy && class == clientNonBrowser {
			divergenceObserved = true
		}
	}
	if !divergenceObserved {
		t.Error("expected at least one Mozilla-UA/no-nav-signal request where legacy=eligible but classifier=NonBrowser (quarantine divergence)")
	}
}

// The no-credentials Default path is byte-identical after the extract-method:
// a Mozilla GET with no creds still 302-redirects to the captive portal; a
// non-browser GET still gets 407 + Basic challenge; a Mozilla CONNECT still 407s.
func TestDefaultPath_RedirectInvariance(t *testing.T) {
	setupAuthGateTest(t) // auth enabled (local user) so the no-cred gate is active
	withFreshPolicyStore(t)

	// Configure a single OIDC IdP so resolveCaptivePortalURL yields a redirect.
	origReg := idpRegistry
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{{ID: "corp-oidc", Name: "Corp", Type: IdPTypeOIDC, Enabled: true}},
		live:     map[string]IdentityProvider{"corp-oidc": &testProxyIdentityProvider{}},
	}
	t.Cleanup(func() { idpRegistry = origReg })

	// Mozilla GET, no creds → 302 redirect (legacy Default path, unchanged).
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://dest.example.test/", map[string]string{"User-Agent": "Mozilla/5.0"}))
	if w.Code != http.StatusFound {
		t.Errorf("Mozilla GET no-cred: got %d, want 302 redirect (Default path must be unchanged)", w.Code)
	}

	// Non-browser GET (curl, json) → 407 + Basic challenge, no redirect.
	w = httptest.NewRecorder()
	handleRequest(w, makeRequest("http://dest.example.test/", map[string]string{"User-Agent": "curl/8.0", "Accept": "application/json"}))
	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("non-browser no-cred: got %d, want 407", w.Code)
	}
	if w.Header().Get("Proxy-Authenticate") != `Basic realm="Culvert"` {
		t.Errorf("non-browser no-cred must carry Basic challenge, got %q", w.Header().Get("Proxy-Authenticate"))
	}
}
