package main

// FE-1B test matrix (directive §14/§15): flag gating, static route resolution,
// MIME/cache/method semantics, strict CSP, legacy isolation, failure
// semantics, and adversarial manifest validation. Serving tests run through
// the FULL production middleware chain (d0WrappedHandler) so header behavior
// is the real one.

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func fe1bReadyState(t *testing.T) *frontendV2State {
	t.Helper()
	dist, err := fs.Sub(frontendV2DistFS, "frontend/dist")
	if err != nil {
		t.Fatalf("sub: %v", err)
	}
	shell, assets, err := validateFrontendV2(dist)
	if err != nil {
		t.Fatalf("embedded dist must validate: %v", err)
	}
	return &frontendV2State{status: frontendV2Ready, shell: shell, assets: assets}
}

func fe1bServe(t *testing.T, st *frontendV2State, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	restore := swapFrontendV2ForTest(st)
	t.Cleanup(restore)
	h := d0WrappedHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, target, nil)
	h.ServeHTTP(rec, req)
	return rec
}

func fe1bJSAsset(t *testing.T, st *frontendV2State) string {
	t.Helper()
	for _, p := range frontendV2AssetInventory(st) {
		if strings.HasSuffix(p, ".js") {
			return "/" + p
		}
	}
	t.Fatal("no js asset in validated set")
	return ""
}

func fe1bCSSAsset(t *testing.T, st *frontendV2State) string {
	t.Helper()
	for _, p := range frontendV2AssetInventory(st) {
		if strings.HasSuffix(p, ".css") {
			return "/" + p
		}
	}
	t.Fatal("no css asset in validated set")
	return ""
}

// ── Flag gating ─────────────────────────────────────────────────────────────

func TestFE1B_FlagOff_AppUnavailable(t *testing.T) {
	off := &frontendV2State{status: frontendV2Disabled}
	for _, target := range []string{"/app", "/app/", "/app/deep/link", "/assets/index-abc12345.js"} {
		rec := fe1bServe(t, off, http.MethodGet, target)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: disabled must 404, got %d", target, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "<div id=\"root\">") {
			t.Errorf("%s: disabled leaked the SPA shell", target)
		}
	}
}

func TestFE1B_ReadFlagDefaultOff(t *testing.T) {
	for _, v := range []string{"", "0", "false", "off", "no", "garbage"} {
		if readFrontendV2Enabled(v) {
			t.Errorf("%q must not enable the experimental UI", v)
		}
	}
	for _, v := range []string{"1", "true", "yes", "on", " TRUE "} {
		if !readFrontendV2Enabled(v) {
			t.Errorf("%q must enable the experimental UI", v)
		}
	}
}

// ── Shell serving ───────────────────────────────────────────────────────────

func TestFE1B_ShellServedByteExact(t *testing.T) {
	st := fe1bReadyState(t)
	embedded, err := fs.ReadFile(frontendV2DistFS, "frontend/dist/index.html")
	if err != nil {
		t.Fatalf("read embed: %v", err)
	}
	for _, target := range []string{"/app", "/app/", "/app/policy/rules/42"} {
		rec := fe1bServe(t, st, http.MethodGet, target)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d", target, rec.Code)
		}
		// §12: the served body must equal the embedded bytes exactly — no
		// substitution, templating, nonce, or base injection.
		if rec.Body.String() != string(embedded) {
			t.Fatalf("%s: served shell differs from embedded index.html bytes", target)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Errorf("%s: Content-Type = %q", target, ct)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: Cache-Control = %q", target, cc)
		}
		if csp := rec.Header().Get("Content-Security-Policy"); csp != frontendV2CSP {
			t.Errorf("%s: CSP = %q, want strict FrontendV2 policy", target, csp)
		}
	}
}

func TestFE1B_HeadShell(t *testing.T) {
	st := fe1bReadyState(t)
	rec := fe1bServe(t, st, http.MethodHead, "/app/")
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD /app/: %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD /app/: body must be empty, got %d bytes", rec.Body.Len())
	}
	if cl := rec.Header().Get("Content-Length"); cl == "" || cl == "0" {
		t.Errorf("HEAD /app/: Content-Length = %q, want shell size", cl)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("HEAD /app/: Cache-Control = %q", cc)
	}
}

// ── Asset serving ───────────────────────────────────────────────────────────

func TestFE1B_AssetServing(t *testing.T) {
	st := fe1bReadyState(t)
	js := fe1bJSAsset(t, st)
	css := fe1bCSSAsset(t, st)

	rec := fe1bServe(t, st, http.MethodGet, js)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d", js, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Errorf("js Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("js Cache-Control = %q", cc)
	}
	if rec.Body.Len() == 0 {
		t.Error("js body empty")
	}

	rec = fe1bServe(t, st, http.MethodGet, css)
	if ct := rec.Header().Get("Content-Type"); ct != "text/css; charset=utf-8" {
		t.Errorf("css Content-Type = %q", ct)
	}

	rec = fe1bServe(t, st, http.MethodHead, js)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD %s: code=%d bodyLen=%d, want 200 with empty body", js, rec.Code, rec.Body.Len())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("HEAD js Cache-Control = %q", cc)
	}
}

func TestFE1B_AssetMissesNeverFallBackToShell(t *testing.T) {
	st := fe1bReadyState(t)
	for _, target := range []string{
		"/assets/nope-12345678.js",   // unknown asset
		"/assets/manifest.json",      // manifest is never in the asset set
		"/assets/index-abc123.map",   // sourcemap
		"/assets/notes-12345678.txt", // unsupported extension
		"/assets/",                   // directory listing
	} {
		rec := fe1bServe(t, st, http.MethodGet, target)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: want 404, got %d", target, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "<div id=\"root\">") {
			t.Errorf("%s: asset miss fell back to the shell", target)
		}
	}
}

func TestFE1B_ManifestAndTraversalUnreachable(t *testing.T) {
	st := fe1bReadyState(t)
	// /app/manifest.json is a deep link: it gets the shell, never the manifest.
	rec := fe1bServe(t, st, http.MethodGet, "/app/manifest.json")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<div id=\"root\">") {
		t.Fatalf("/app/manifest.json: want shell, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "\"isEntry\"") {
		t.Error("/app/manifest.json leaked manifest content")
	}
	// Traversal shapes: ServeMux canonicalizes dotted paths (301) — either a
	// redirect or a 404 is acceptable; a 200 with file bytes is not.
	for _, target := range []string{"/assets/../ca.bundle", "/assets/..%2fmain.go", "/assets/%2e%2e/secret"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		restore := swapFrontendV2ForTest(st)
		rec := httptest.NewRecorder()
		d0WrappedHandler(t).ServeHTTP(rec, req)
		restore()
		if rec.Code == http.StatusOK {
			t.Errorf("%s: traversal shape must not serve content (got 200)", target)
		}
	}
}

func TestFE1B_MutationsNeverReceiveShell(t *testing.T) {
	st := fe1bReadyState(t)
	js := fe1bJSAsset(t, st)
	cases := []struct{ method, target string }{
		{http.MethodPost, "/app/dashboard"},
		{http.MethodPut, "/app/"},
		{http.MethodDelete, "/app/foo"},
		{http.MethodPatch, "/app/settings"},
		{http.MethodPost, "/app"},
		{http.MethodPost, js},
		{http.MethodDelete, js},
	}
	for _, c := range cases {
		rec := fe1bServe(t, st, c.method, c.target)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s: want 404, got %d", c.method, c.target, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "<div id=\"root\">") {
			t.Errorf("%s %s: mutation received the SPA shell", c.method, c.target)
		}
	}
}

// ── Legacy isolation ────────────────────────────────────────────────────────

func TestFE1B_LegacySurfaceUnchanged(t *testing.T) {
	st := fe1bReadyState(t)
	// Legacy shell at / — nonce CSP, legacy markup, no strict-policy override.
	rec := fe1bServe(t, st, http.MethodGet, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "data-view=") {
		t.Error("GET /: legacy shell markup missing")
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "'nonce-") || !strings.Contains(csp, "style-src 'self' 'unsafe-inline'") {
		t.Errorf("GET /: legacy CSP changed: %q", csp)
	}
	if csp == frontendV2CSP {
		t.Error("GET /: legacy route received the FrontendV2 CSP")
	}
	// Legacy asset still served with its existing cache policy.
	rec = fe1bServe(t, st, http.MethodGet, "/chart.umd.js")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /chart.umd.js: %d", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=86400" {
		t.Errorf("legacy chart asset Cache-Control = %q", cc)
	}
	// API + auth + PAC + health surfaces unaffected.
	if rec = fe1bServe(t, st, http.MethodGet, "/api/setup/status"); rec.Code != http.StatusOK {
		t.Errorf("GET /api/setup/status: %d", rec.Code)
	}
	if rec = fe1bServe(t, st, http.MethodGet, "/api/auth/status"); rec.Code != http.StatusOK {
		t.Errorf("GET /api/auth/status: %d", rec.Code)
	}
	if rec = fe1bServe(t, st, http.MethodGet, "/proxy.pac"); rec.Code != http.StatusOK {
		t.Errorf("GET /proxy.pac: %d", rec.Code)
	}
	if rec = fe1bServe(t, st, http.MethodGet, "/healthz"); rec.Code == http.StatusNotFound {
		t.Errorf("GET /healthz: unexpectedly 404")
	}
}

// ── Failure semantics ───────────────────────────────────────────────────────

func TestFE1B_InvalidArtifactDegradesTo503(t *testing.T) {
	bad := &frontendV2State{status: frontendV2Invalid, reason: "manifest.json does not parse"}
	for _, target := range []string{"/app", "/app/", "/app/deep", "/assets/index-abc12345.js"} {
		rec := fe1bServe(t, bad, http.MethodGet, target)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: want 503, got %d", target, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Errorf("%s: Content-Type = %q", target, ct)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: Cache-Control = %q", target, cc)
		}
		body := rec.Body.String()
		if strings.Contains(body, "manifest") && strings.Contains(body, "parse") {
			t.Errorf("%s: 503 body leaked validation internals: %q", target, body)
		}
		if strings.Contains(body, "/home/") || strings.Contains(body, "frontend/dist") {
			t.Errorf("%s: 503 body leaked build paths", target)
		}
	}
	// The rest of the surface keeps serving — the data/admin plane is intact.
	if rec := fe1bServe(t, bad, http.MethodGet, "/"); rec.Code != http.StatusOK {
		t.Errorf("legacy / degraded alongside v2: %d", rec.Code)
	}
	if rec := fe1bServe(t, bad, http.MethodGet, "/api/setup/status"); rec.Code != http.StatusOK {
		t.Errorf("/api/setup/status degraded alongside v2: %d", rec.Code)
	}
}

func TestFE1B_ReadinessRow(t *testing.T) {
	cases := []struct {
		st         *frontendV2State
		wantRow    bool
		wantStatus string
	}{
		{&frontendV2State{status: frontendV2Disabled}, false, ""},
		{&frontendV2State{status: frontendV2Ready}, true, "ok"},
		{&frontendV2State{status: frontendV2Invalid, reason: "x"}, true, "fail"},
	}
	for _, c := range cases {
		restore := swapFrontendV2ForTest(c.st)
		checks := map[string]*readinessCheck{}
		appendFrontendV2ReadinessCheck(checks)
		restore()
		row, ok := checks["frontend_v2"]
		if ok != c.wantRow {
			t.Errorf("status %s: row present=%v want %v", c.st.status, ok, c.wantRow)
			continue
		}
		if ok && row.Status != c.wantStatus {
			t.Errorf("status %s: row status %q want %q", c.st.status, row.Status, c.wantStatus)
		}
		if ok && row.Status == "fail" && strings.Contains(row.Detail, "parse") {
			t.Errorf("readiness detail must be fixed, not the raw reason: %q", row.Detail)
		}
	}
}

// ── Resolution ──────────────────────────────────────────────────────────────

func TestFE1B_ResolveDisabledAndReady(t *testing.T) {
	if st := resolveFrontendV2(""); st.status != frontendV2Disabled {
		t.Errorf("empty env: status %s, want disabled", st.status)
	}
	st := resolveFrontendV2("1")
	if st.status != frontendV2Ready {
		t.Fatalf("enabled: status %s (%s), want ready — the committed dist must validate", st.status, st.reason)
	}
	if len(st.shell) == 0 || len(st.assets) == 0 {
		t.Error("ready state missing shell or assets")
	}
}

// ── Adversarial manifest validation (§15) ───────────────────────────────────

func fe1bFixture(mutate func(m map[string]*fstest.MapFile)) fs.FS {
	m := map[string]*fstest.MapFile{
		"index.html":              {Data: []byte("<!doctype html><div id=\"root\"></div>")},
		"manifest.json":           {Data: []byte(`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true}}`)},
		"assets/app-abc12345.js":  {Data: []byte("console.log(1)")},
		"assets/app-abc12345.css": {Data: []byte("body{}")},
	}
	if mutate != nil {
		mutate(m)
	}
	return fstest.MapFS(m)
}

func TestFE1B_ValidatorAdversarialFixtures(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(m map[string]*fstest.MapFile)
	}{
		{"invalid json", func(m map[string]*fstest.MapFile) {
			m["manifest.json"] = &fstest.MapFile{Data: []byte("{not json")}
		}},
		{"missing manifest", func(m map[string]*fstest.MapFile) { delete(m, "manifest.json") }},
		{"missing index", func(m map[string]*fstest.MapFile) { delete(m, "index.html") }},
		{"empty manifest", func(m map[string]*fstest.MapFile) {
			m["manifest.json"] = &fstest.MapFile{Data: []byte(`{}`)}
		}},
		{"no entry chunk", func(m map[string]*fstest.MapFile) {
			m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"]}}`)}
		}},
		{"entry without file", func(m map[string]*fstest.MapFile) {
			m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"index.html":{"isEntry":true}}`)}
		}},
		{"missing referenced file", func(m map[string]*fstest.MapFile) { delete(m, "assets/app-abc12345.js") }},
		{"traversal reference", func(m map[string]*fstest.MapFile) {
			m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/../secret.js","isEntry":true}}`)}
		}},
		{"absolute path reference", func(m map[string]*fstest.MapFile) {
			m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"index.html":{"file":"/etc/passwd","isEntry":true}}`)}
		}},
		{"external url reference", func(m map[string]*fstest.MapFile) {
			m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"index.html":{"file":"https://cdn.evil/app.js","isEntry":true}}`)}
		}},
		{"unsupported extension", func(m map[string]*fstest.MapFile) {
			m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/app-abc12345.wasm","isEntry":true}}`)}
			m["assets/app-abc12345.wasm"] = &fstest.MapFile{Data: []byte("x")}
		}},
		{"sourcemap referenced", func(m map[string]*fstest.MapFile) {
			m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.js.map"],"isEntry":true}}`)}
		}},
		{"sourcemap embedded", func(m map[string]*fstest.MapFile) {
			m["assets/app-abc12345.js.map"] = &fstest.MapFile{Data: []byte("{}")}
		}},
		{"unreferenced stray asset", func(m map[string]*fstest.MapFile) {
			m["assets/stray-def45678.js"] = &fstest.MapFile{Data: []byte("x")}
		}},
		{"stray root file", func(m map[string]*fstest.MapFile) {
			m["extra.txt"] = &fstest.MapFile{Data: []byte("x")}
		}},
		{"encoded reference", func(m map[string]*fstest.MapFile) {
			m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/%2e%2e/app.js","isEntry":true}}`)}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("validator panicked (must fail closed): %v", r)
				}
			}()
			_, _, err := validateFrontendV2(fe1bFixture(c.mutate))
			if err == nil {
				t.Fatal("malformed build validated — must fail closed")
			}
		})
	}
	// Control: the unmutated fixture validates.
	if _, _, err := validateFrontendV2(fe1bFixture(nil)); err != nil {
		t.Fatalf("control fixture must validate: %v", err)
	}
}

func TestFE1B_AmbiguousCaseCollision(t *testing.T) {
	m := fe1bFixture(func(m map[string]*fstest.MapFile) {
		m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"a":{"file":"assets/app-abc12345.js","isEntry":true},"b":{"file":"assets/APP-abc12345.js"}}`)}
		m["assets/APP-abc12345.js"] = &fstest.MapFile{Data: []byte("x")}
	})
	if _, _, err := validateFrontendV2(m); err == nil {
		t.Fatal("case-ambiguous assets must fail validation")
	}
}
