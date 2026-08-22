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
	"os"
	"path/filepath"
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

// fe1bShell builds a constrained Vite-style shell referencing the given
// script + stylesheets (the shape the shell↔manifest binding validates).
func fe1bShell(script string, css ...string) []byte {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head>")
	b.WriteString(`<script type="module" crossorigin src="` + script + `"></script>`)
	for _, c := range css {
		b.WriteString(`<link rel="stylesheet" crossorigin href="` + c + `">`)
	}
	b.WriteString(`</head><body><div id="root"></div></body></html>`)
	return []byte(b.String())
}

func fe1bFixture(mutate func(m map[string]*fstest.MapFile)) fs.FS {
	m := map[string]*fstest.MapFile{
		"index.html":              {Data: fe1bShell("/assets/app-abc12345.js", "/assets/app-abc12345.css")},
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
		m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true},"b":{"file":"assets/APP-abc12345.js"}}`)}
		m["assets/APP-abc12345.js"] = &fstest.MapFile{Data: []byte("x")}
	})
	_, _, err := validateFrontendV2(m)
	if err == nil || !strings.Contains(err.Error(), "case") {
		t.Fatalf("case-ambiguous assets must fail on the case dimension, got %v", err)
	}
}

// ── Import graph (validator hardening §1) ───────────────────────────────────

func TestFE1B_ImportGraph(t *testing.T) {
	// Shared chunk plumbing: entry + chunks a/b/c, all with hashed files.
	chunkFiles := func(m map[string]*fstest.MapFile) {
		for _, f := range []string{"assets/ck-a-abcd1234.js", "assets/ck-b-abcd1234.js", "assets/ck-c-abcd1234.js"} {
			m[f] = &fstest.MapFile{Data: []byte("x")}
		}
	}
	valid := []struct {
		name     string
		manifest string
	}{
		{"nested import chain", `{
			"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true,"imports":["_a"]},
			"_a":{"file":"assets/ck-a-abcd1234.js","imports":["_b"]},
			"_b":{"file":"assets/ck-b-abcd1234.js"},
			"_c":{"file":"assets/ck-c-abcd1234.js"}}`},
		{"shared imported chunk", `{
			"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true,"imports":["_a","_b"]},
			"_a":{"file":"assets/ck-a-abcd1234.js","imports":["_c"]},
			"_b":{"file":"assets/ck-b-abcd1234.js","imports":["_c"]},
			"_c":{"file":"assets/ck-c-abcd1234.js"}}`},
		{"cyclic hostile graph terminates", `{
			"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true,"dynamicImports":["_a"]},
			"_a":{"file":"assets/ck-a-abcd1234.js","isDynamicEntry":true,"imports":["_b"]},
			"_b":{"file":"assets/ck-b-abcd1234.js","imports":["_a","_b"]},
			"_c":{"file":"assets/ck-c-abcd1234.js"}}`},
	}
	for _, c := range valid {
		t.Run("valid/"+c.name, func(t *testing.T) {
			m := fe1bFixture(func(m map[string]*fstest.MapFile) {
				m["manifest.json"] = &fstest.MapFile{Data: []byte(c.manifest)}
				chunkFiles(m)
			})
			if _, _, err := validateFrontendV2(m); err != nil {
				t.Fatalf("valid graph rejected: %v", err)
			}
		})
	}
	invalid := []struct {
		name     string
		manifest string
		wantErr  string
	}{
		{"missing static import key", `{
			"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true,"imports":["_gone"]},
			"_c":{"file":"assets/ck-c-abcd1234.js"}}`, "imports missing key"},
		{"missing dynamicImport key", `{
			"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true,"dynamicImports":["_gone"]},
			"_c":{"file":"assets/ck-c-abcd1234.js"}}`, "imports missing key"},
		{"imported chunk missing its file", `{
			"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true,"imports":["_a"]},
			"_a":{"imports":[]}}`, "no file"},
		{"imported chunk references missing css", `{
			"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true,"imports":["_a"]},
			"_a":{"file":"assets/ck-a-abcd1234.js","css":["assets/gone-abcd1234.css"]}}`, "missing file"},
	}
	for _, c := range invalid {
		t.Run("invalid/"+c.name, func(t *testing.T) {
			m := fe1bFixture(func(m map[string]*fstest.MapFile) {
				m["manifest.json"] = &fstest.MapFile{Data: []byte(c.manifest)}
				chunkFiles(m)
			})
			_, _, err := validateFrontendV2(m)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("want error containing %q, got %v", c.wantErr, err)
			}
		})
	}
}

// ── Immutable-cache hashed-name contract (validator hardening §2) ───────────

func TestFE1B_HashedNameContract(t *testing.T) {
	rejected := []string{
		"assets/app.js",           // un-hashed JS
		"assets/foo.css",          // un-hashed CSS
		"assets/logo.png",         // un-hashed image
		"assets/font.woff2",       // un-hashed font
		"assets/app-abc.js",       // malformed too-short hash
		"assets/app-abc1234.webp", // 7-char hash still too short
	}
	for _, p := range rejected {
		if err := frontendV2ValidateAssetPath(p); err == nil || !strings.Contains(err.Error(), "content-hash") {
			t.Errorf("%s: want content-hash rejection, got %v", p, err)
		}
	}
	accepted := []string{
		"assets/app-abc12345.js",
		"assets/app--XtOykcB.css",
		"assets/logo-abcd1234.png",
		"assets/icon-abcd1234.svg",
		"assets/photo-abcd1234.webp",
		"assets/font-abcd1234.woff2",
	}
	for _, p := range accepted {
		if err := frontendV2ValidateAssetPath(p); err != nil {
			t.Errorf("%s: valid hashed asset rejected: %v", p, err)
		}
	}
	// End-to-end: a manifest-referenced un-hashed image fails validation.
	m := fe1bFixture(func(m map[string]*fstest.MapFile) {
		m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"assets":["assets/logo.png"],"isEntry":true}}`)}
		m["assets/logo.png"] = &fstest.MapFile{Data: []byte("x")}
	})
	if _, _, err := validateFrontendV2(m); err == nil || !strings.Contains(err.Error(), "content-hash") {
		t.Fatalf("un-hashed manifest asset must fail on the hash dimension, got %v", err)
	}
}

// TestFE1B_HashRuleMatchesBundleScan pins the Go runtime hash rule to the
// FE-1A JS bundle scan's pattern — the two representations must not drift.
func TestFE1B_HashRuleMatchesBundleScan(t *testing.T) {
	const shared = `-[A-Za-z0-9_-]{8,}`
	if got := frontendV2HashedName.String(); got != shared+"$" {
		t.Fatalf("Go hash rule %q no longer matches the shared pattern %q$", got, shared)
	}
	js, err := os.ReadFile(filepath.Join(pkgSourceDir(), "frontend", "scripts", "check-dist.mjs"))
	if err != nil {
		t.Fatalf("read check-dist.mjs: %v", err)
	}
	if !strings.Contains(string(js), shared) {
		t.Fatalf("frontend/scripts/check-dist.mjs no longer contains the shared hash pattern %q — update both sides of the lockstep contract", shared)
	}
}

// ── Shell ↔ manifest binding (validator hardening §3) ───────────────────────

func TestFE1B_ShellManifestBinding(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(m map[string]*fstest.MapFile)
		wantErr string
	}{
		{"A shell references missing JS", func(m map[string]*fstest.MapFile) {
			m["index.html"] = &fstest.MapFile{Data: fe1bShell("/assets/gone-abcd1234.js", "/assets/app-abc12345.css")}
		}, "does not reference the manifest entry JS"},
		{"B manifest points at A shell points at B", func(m map[string]*fstest.MapFile) {
			m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true},"_b":{"file":"assets/ck-b-abcd1234.js"}}`)}
			m["assets/ck-b-abcd1234.js"] = &fstest.MapFile{Data: []byte("x")}
			m["index.html"] = &fstest.MapFile{Data: fe1bShell("/assets/ck-b-abcd1234.js", "/assets/app-abc12345.css")}
		}, "does not reference the manifest entry JS"},
		{"C1 shell omits declared CSS", func(m map[string]*fstest.MapFile) {
			m["index.html"] = &fstest.MapFile{Data: fe1bShell("/assets/app-abc12345.js")}
		}, "stylesheet set differs"},
		{"C2 shell references wrong CSS", func(m map[string]*fstest.MapFile) {
			m["index.html"] = &fstest.MapFile{Data: fe1bShell("/assets/app-abc12345.js", "/assets/wrong-abcd1234.css")}
		}, "outside the manifest entry css"},
		{"D1 extra unmanifested script", func(m map[string]*fstest.MapFile) {
			shell := string(fe1bShell("/assets/app-abc12345.js", "/assets/app-abc12345.css"))
			shell = strings.Replace(shell, "</head>", `<script src="/assets/extra-abcd1234.js"></script></head>`, 1)
			m["index.html"] = &fstest.MapFile{Data: []byte(shell)}
		}, "want exactly the entry chunk"},
		{"D2 extra unmanifested stylesheet", func(m map[string]*fstest.MapFile) {
			shell := string(fe1bShell("/assets/app-abc12345.js", "/assets/app-abc12345.css"))
			shell = strings.Replace(shell, "</head>", `<link rel="stylesheet" href="/assets/extra-abcd1234.css"></head>`, 1)
			m["index.html"] = &fstest.MapFile{Data: []byte(shell)}
		}, "stylesheet set differs"},
		{"no authoritative index.html entry", func(m map[string]*fstest.MapFile) {
			m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"src/main.tsx":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true}}`)}
		}, `no "index.html" entry`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Anti-vacuity: the mutation must actually change the fixture.
			base, _ := fs.ReadFile(fe1bFixture(nil), "index.html")
			mutated := fe1bFixture(c.mutate)
			mIdx, _ := fs.ReadFile(mutated, "index.html")
			mMan, _ := fs.ReadFile(mutated, "manifest.json")
			bMan, _ := fs.ReadFile(fe1bFixture(nil), "manifest.json")
			if string(mIdx) == string(base) && string(mMan) == string(bMan) {
				t.Fatal("fixture mutation did not change shell or manifest")
			}
			_, _, err := validateFrontendV2(mutated)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("want error containing %q, got %v", c.wantErr, err)
			}
		})
	}
	// E: the control fixture and the REAL committed dist both validate.
	if _, _, err := validateFrontendV2(fe1bFixture(nil)); err != nil {
		t.Fatalf("control fixture must validate: %v", err)
	}
	dist, err := fs.Sub(frontendV2DistFS, "frontend/dist")
	if err != nil {
		t.Fatalf("sub: %v", err)
	}
	if _, _, err := validateFrontendV2(dist); err != nil {
		t.Fatalf("committed production dist must validate: %v", err)
	}
}

// ── Strict JSON handling (validator hardening §4) ───────────────────────────

func TestFE1B_DuplicateManifestKeysRejected(t *testing.T) {
	dupTop := fe1bFixture(func(m map[string]*fstest.MapFile) {
		m["manifest.json"] = &fstest.MapFile{Data: []byte(`{
			"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true},
			"index.html":{"file":"assets/other-abcd1234.js","isEntry":true}}`)}
	})
	if _, _, err := validateFrontendV2(dupTop); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate top-level manifest key must be rejected, got %v", err)
	}
	dupInner := fe1bFixture(func(m map[string]*fstest.MapFile) {
		m["manifest.json"] = &fstest.MapFile{Data: []byte(`{
			"index.html":{"file":"assets/app-abc12345.js","file":"assets/other-abcd1234.js","css":["assets/app-abc12345.css"],"isEntry":true}}`)}
	})
	if _, _, err := validateFrontendV2(dupInner); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate chunk-level key must be rejected, got %v", err)
	}
	if err := frontendV2RejectDuplicateJSONKeys([]byte(`{"a":{"x":1},"b":[{"x":1},{"x":2}],"c":"a"}`)); err != nil {
		t.Fatalf("distinct keys across sibling objects must pass: %v", err)
	}
}
