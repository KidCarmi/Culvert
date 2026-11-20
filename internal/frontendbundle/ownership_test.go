package frontendbundle

import (
	"bytes"
	"io/fs"
	"reflect"
	"sync"
	"testing"
	"testing/fstest"
)

// oracleContentType is a frozen copy of package main's serving allowlist
// (frontendV2MIME in ui_frontend_v2.go at main 5333aab), from before it moved
// here as contentTypeFor (IM-017). With nosniff active the bytes of these
// values are load-bearing, so a later edit must be deliberate.
var oracleContentType = map[string]string{
	".js":    "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".webp":  "image/webp",
	".woff2": "font/woff2",
}

func TestContentTypeFor_MatchesRootAllowlist(t *testing.T) {
	for ext, want := range oracleContentType {
		got, ok := contentTypeFor(ext)
		if !ok || got != want {
			t.Errorf("contentTypeFor(%q) = (%q, %v), root allowlist had %q", ext, got, ok, want)
		}
	}
	for _, ext := range []string{"", ".map", ".html", ".json", ".wasm", ".JS", ".mjs", ".ico", "js", ".js "} {
		if got, ok := contentTypeFor(ext); ok || got != "" {
			t.Errorf("contentTypeFor(%q) = (%q, %v); the root allowlist had no such entry", ext, got, ok)
		}
	}
}

// Validate reports each admitted asset with its allowlisted content type and
// its size in the tree, and returns the shell bytes exactly.
func TestValidate_ReturnsShellBytesAndAssetMetadata(t *testing.T) {
	fixture := fe1bFixture(nil)
	wantShell, err := fs.ReadFile(fixture, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	shell, assets, err := Validate(fixture)
	if err != nil {
		t.Fatalf("control fixture must validate: %v", err)
	}
	if !bytes.Equal(shell, wantShell) {
		t.Fatal("returned shell differs from index.html; it must be byte-exact")
	}
	want := map[string]Asset{
		"assets/app-abc12345.js":  {ContentType: "text/javascript; charset=utf-8", Size: int64(len("console.log(1)"))},
		"assets/app-abc12345.css": {ContentType: "text/css; charset=utf-8", Size: int64(len("body{}"))},
	}
	if !reflect.DeepEqual(assets, want) {
		t.Fatalf("assets = %#v, want %#v", assets, want)
	}
}

// A rejected tree yields nothing to serve: no shell and no asset set.
func TestValidate_RejectionReturnsNothingToServe(t *testing.T) {
	shell, assets, err := Validate(fe1bFixture(func(m map[string]*fstest.MapFile) {
		m["assets/stray-def45678.js"] = &fstest.MapFile{Data: []byte("x")}
	}))
	if err == nil {
		t.Fatal("a tree with an unreferenced asset validated")
	}
	if shell != nil || assets != nil {
		t.Fatalf("rejected tree returned shell=%d bytes and %d assets, want neither", len(shell), len(assets))
	}
}

// Untrusted manifest strings quoted in an error are sanitized first, so the
// text cannot forge a log record (CWE-117) when the caller logs it.
func TestValidate_ErrorTextCarriesNoControlBytes(t *testing.T) {
	_, _, err := Validate(fe1bFixture(func(m map[string]*fstest.MapFile) {
		m["manifest.json"] = &fstest.MapFile{Data: []byte(
			`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true},` +
				`"evil\nCRITICAL: forged\r\u0000\u007f":{"imports":["x"]}}`)}
	}))
	if err == nil {
		t.Fatal("a manifest entry with no file validated")
	}
	for _, c := range []byte(err.Error()) {
		if c < 0x20 || c == 0x7F {
			t.Fatalf("error text carries control byte 0x%02x: %q", c, err.Error())
		}
	}
}

// The package keeps no state between calls: concurrent validations of
// different trees neither race (run under -race) nor see each other's result.
func TestValidate_ConcurrentCallsAreIndependent(t *testing.T) {
	good := fe1bFixture(nil)
	bad := fe1bFixture(func(m map[string]*fstest.MapFile) { delete(m, "manifest.json") })
	other := fe1bFixture(func(m map[string]*fstest.MapFile) {
		m["manifest.json"] = &fstest.MapFile{Data: []byte(`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"assets":["assets/logo-abcd1234.png"],"isEntry":true}}`)}
		m["assets/logo-abcd1234.png"] = &fstest.MapFile{Data: []byte("png")}
	})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			if _, assets, err := Validate(good); err != nil || len(assets) != 2 {
				t.Errorf("good tree: %d assets, err %v; want 2 and nil", len(assets), err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, assets, err := Validate(bad); err == nil || assets != nil {
				t.Errorf("bad tree: %d assets, err %v; want rejection", len(assets), err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, assets, err := Validate(other); err != nil || len(assets) != 3 {
				t.Errorf("other tree: %d assets, err %v; want 3 and nil", len(assets), err)
			}
		}()
	}
	wg.Wait()
}
