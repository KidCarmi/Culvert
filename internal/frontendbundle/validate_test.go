package frontendbundle

// FE-1B validator matrix (directive §15 and validator hardening §1-§4), moved
// from package main's ui_frontend_v2_test.go with the test names unchanged
// (ADR-0050). These drive Validate over in-memory trees; the tests that need
// the real embedded dist, the routes or the middleware chain stay in root.

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

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
			_, _, err := Validate(fe1bFixture(c.mutate))
			if err == nil {
				t.Fatal("malformed build validated — must fail closed")
			}
		})
	}
	// Control: the unmutated fixture validates.
	if _, _, err := Validate(fe1bFixture(nil)); err != nil {
		t.Fatalf("control fixture must validate: %v", err)
	}
}

func TestFE1B_AmbiguousCaseCollision(t *testing.T) {
	m := fe1bFixture(func(m map[string]*fstest.MapFile) {
		m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true},"b":{"file":"assets/APP-abc12345.js"}}`)}
		m["assets/APP-abc12345.js"] = &fstest.MapFile{Data: []byte("x")}
	})
	_, _, err := Validate(m)
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
			if _, _, err := Validate(m); err != nil {
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
			_, _, err := Validate(m)
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
		if err := validateAssetPath(p); err == nil || !strings.Contains(err.Error(), "content-hash") {
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
		if err := validateAssetPath(p); err != nil {
			t.Errorf("%s: valid hashed asset rejected: %v", p, err)
		}
	}
	// End-to-end: a manifest-referenced un-hashed image fails validation.
	m := fe1bFixture(func(m map[string]*fstest.MapFile) {
		m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"assets":["assets/logo.png"],"isEntry":true}}`)}
		m["assets/logo.png"] = &fstest.MapFile{Data: []byte("x")}
	})
	if _, _, err := Validate(m); err == nil || !strings.Contains(err.Error(), "content-hash") {
		t.Fatalf("un-hashed manifest asset must fail on the hash dimension, got %v", err)
	}
}

// TestFE1B_HashRuleMatchesBundleScan pins the Go runtime hash rule to the
// FE-1A JS bundle scan's pattern — the two representations must not drift.
func TestFE1B_HashRuleMatchesBundleScan(t *testing.T) {
	const shared = `-[A-Za-z0-9_-]{8,}`
	if got := hashedName.String(); got != shared+"$" {
		t.Fatalf("Go hash rule %q no longer matches the shared pattern %q$", got, shared)
	}
	// The test binary runs in this package's directory (internal/frontendbundle).
	js, err := os.ReadFile(filepath.Join("..", "..", "frontend", "scripts", "check-dist.mjs"))
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
			if bytes.Equal(mIdx, base) && bytes.Equal(mMan, bMan) {
				t.Fatal("fixture mutation did not change shell or manifest")
			}
			_, _, err := Validate(mutated)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("want error containing %q, got %v", c.wantErr, err)
			}
		})
	}
	// E: the control fixture validates. (The REAL committed dist is embedded
	// by package main, so that half of this assertion stays in the root test
	// of the same name.)
	if _, _, err := Validate(fe1bFixture(nil)); err != nil {
		t.Fatalf("control fixture must validate: %v", err)
	}
}

// ── Strict JSON handling (validator hardening §4) ───────────────────────────

func TestFE1B_DuplicateManifestKeysRejected(t *testing.T) {
	dupTop := fe1bFixture(func(m map[string]*fstest.MapFile) {
		m["manifest.json"] = &fstest.MapFile{Data: []byte(`{
			"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true},
			"index.html":{"file":"assets/other-abcd1234.js","isEntry":true}}`)}
	})
	if _, _, err := Validate(dupTop); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate top-level manifest key must be rejected, got %v", err)
	}
	dupInner := fe1bFixture(func(m map[string]*fstest.MapFile) {
		m["manifest.json"] = &fstest.MapFile{Data: []byte(`{
			"index.html":{"file":"assets/app-abc12345.js","file":"assets/other-abcd1234.js","css":["assets/app-abc12345.css"],"isEntry":true}}`)}
	})
	if _, _, err := Validate(dupInner); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate chunk-level key must be rejected, got %v", err)
	}
	if err := rejectDuplicateJSONKeys([]byte(`{"a":{"x":1},"b":[{"x":1},{"x":2}],"c":"a"}`)); err != nil {
		t.Fatalf("distinct keys across sibling objects must pass: %v", err)
	}
}
