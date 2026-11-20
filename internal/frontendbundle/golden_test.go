package frontendbundle

// Differential oracle for the move out of package main (IM-017, ADR-0050).
//
// goldenMain holds the verdict the validator returned for each tree below when
// it was still validateFrontendV2 in ui_frontend_v2.go, captured by running
// this same corpus against unmodified main 5333aab. The error text reaches the
// server log and decides ready-versus-503, and the content types are served
// under nosniff, so the move must not change a byte of either.

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

// goldenCase is one tree and the exact verdict the validator gave for it on
// main before the move.
type goldenCase struct {
	name   string
	mutate func(m map[string]*fstest.MapFile)
}

func manifestOnly(js string) func(m map[string]*fstest.MapFile) {
	return func(m map[string]*fstest.MapFile) { m["manifest.json"] = &fstest.MapFile{Data: []byte(js)} }
}

func shellOnly(html string) func(m map[string]*fstest.MapFile) {
	return func(m map[string]*fstest.MapFile) { m["index.html"] = &fstest.MapFile{Data: []byte(html)} }
}

func addFile(name string, then func(m map[string]*fstest.MapFile)) func(m map[string]*fstest.MapFile) {
	return func(m map[string]*fstest.MapFile) {
		m[name] = &fstest.MapFile{Data: []byte("x")}
		if then != nil {
			then(m)
		}
	}
}

const goldenEntry = `"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true}`

func goldenCases() []goldenCase {
	return []goldenCase{
		{"control", nil},
		{"empty index", shellOnly("")},
		{"missing index", func(m map[string]*fstest.MapFile) { delete(m, "index.html") }},
		{"missing manifest", func(m map[string]*fstest.MapFile) { delete(m, "manifest.json") }},
		{"invalid json", manifestOnly("{not json")},
		{"manifest is array", manifestOnly(`[]`)},
		{"empty manifest", manifestOnly(`{}`)},
		{"null manifest", manifestOnly(`null`)},
		{"duplicate top-level key", manifestOnly(`{` + goldenEntry + `,` + goldenEntry + `}`)},
		{"duplicate nested key", manifestOnly(`{"index.html":{"file":"assets/app-abc12345.js","file":"assets/app-abc12345.js","isEntry":true}}`)},
		{"no entry chunk", manifestOnly(`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"]}}`)},
		{"entry without file", manifestOnly(`{"index.html":{"isEntry":true}}`)},
		{"entry key with control bytes", manifestOnly(`{` + goldenEntry + `,"a\nb\r\u0000\u007f\tc":{"imports":[]}}`)},
		{"empty path in css", manifestOnly(`{"index.html":{"file":"assets/app-abc12345.js","css":[""],"isEntry":true}}`)},
		{"absolute path", manifestOnly(`{"index.html":{"file":"/etc/passwd","isEntry":true}}`)},
		{"backslash path", manifestOnly(`{"index.html":{"file":"assets\\app-abc12345.js","isEntry":true}}`)},
		{"traversal", manifestOnly(`{"index.html":{"file":"assets/../secret-abc12345.js","isEntry":true}}`)},
		{"encoded", manifestOnly(`{"index.html":{"file":"assets/%2e%2e/app-abc12345.js","isEntry":true}}`)},
		{"scheme", manifestOnly(`{"index.html":{"file":"https://cdn.evil/app-abc12345.js","isEntry":true}}`)},
		{"double slash", manifestOnly(`{"index.html":{"file":"assets//app-abc12345.js","isEntry":true}}`)},
		{"non-canonical", manifestOnly(`{"index.html":{"file":"assets/./app-abc12345.js","isEntry":true}}`)},
		{"outside namespace", manifestOnly(`{"index.html":{"file":"static/app-abc12345.js","isEntry":true}}`)},
		{"sourcemap referenced", manifestOnly(`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.js.map"],"isEntry":true}}`)},
		{"unsupported extension", manifestOnly(`{"index.html":{"file":"assets/app-abc12345.wasm","isEntry":true}}`)},
		{"no extension", manifestOnly(`{"index.html":{"file":"assets/app-abc12345","isEntry":true}}`)},
		{"unhashed name", manifestOnly(`{"index.html":{"file":"assets/app.js","isEntry":true}}`)},
		{"short hash", manifestOnly(`{"index.html":{"file":"assets/app-abc1234.js","isEntry":true}}`)},
		{"disallowed character", manifestOnly(`{"index.html":{"file":"assets/app name-abc12345.js","isEntry":true}}`)},
		{"non-ascii character", manifestOnly(`{"index.html":{"file":"assets/äpp-abc12345.js","isEntry":true}}`)},
		{"control byte in path", manifestOnly(`{"index.html":{"file":"assets/a\nb-abc12345.js","isEntry":true}}`)},
		{"missing static import key", manifestOnly(`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true,"imports":["_g\none"]}}`)},
		{"missing dynamic import key", manifestOnly(`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true,"dynamicImports":["_gone"]}}`)},
		{"missing referenced file", func(m map[string]*fstest.MapFile) { delete(m, "assets/app-abc12345.css") }},
		{"unreferenced stray asset", addFile("assets/stray-def45678.js", nil)},
		{"stray root file", addFile("extra.txt", nil)},
		{"stray directory", addFile("vendor/lib-abc12345.js", nil)},
		{"nested assets directory", addFile("assets/sub/lib-abc12345.js", nil)},
		{"sourcemap embedded", addFile("assets/app-abc12345.js.map", nil)},
		{"unhashed embedded file", addFile("assets/logo.png", nil)},
		{"no assets at all", func(m map[string]*fstest.MapFile) {
			delete(m, "assets/app-abc12345.js")
			delete(m, "assets/app-abc12345.css")
		}},
		{"case collision", addFile("assets/APP-abc12345.js", manifestOnly(`{`+goldenEntry+`,"b":{"file":"assets/APP-abc12345.js"}}`))},
		{"no index.html entry", manifestOnly(`{"src/main.tsx":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"isEntry":true}}`)},
		{"index.html entry not isEntry", addFile("assets/ck-b-abcd1234.js", manifestOnly(`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"]},"b":{"file":"assets/ck-b-abcd1234.js","isEntry":true}}`))},
		{"entry file is css", manifestOnly(`{"index.html":{"file":"assets/app-abc12345.css","css":["assets/app-abc12345.css"],"assets":["assets/app-abc12345.js"],"isEntry":true}}`)},
		{"shell references other script", shellOnly(string(fe1bShell("/assets/gone-abcd1234.js", "/assets/app-abc12345.css")))},
		{"shell has two scripts", shellOnly(strings.Replace(string(fe1bShell("/assets/app-abc12345.js", "/assets/app-abc12345.css")), "</head>", `<script src="/assets/extra-abcd1234.js"></script></head>`, 1))},
		{"shell omits css", shellOnly(string(fe1bShell("/assets/app-abc12345.js")))},
		{"shell wrong css", shellOnly(string(fe1bShell("/assets/app-abc12345.js", "/assets/wrong-abcd1234.css")))},
		{"shell relative script", shellOnly(string(fe1bShell("assets/app-abc12345.js", "/assets/app-abc12345.css")))},
		{"shell preload not validated", shellOnly(strings.Replace(string(fe1bShell("/assets/app-abc12345.js", "/assets/app-abc12345.css")), "</head>", `<link rel="modulepreload" href="/assets/ghost-abcd1234.js"></head>`, 1))},
		{"shell preload validated", shellOnly(strings.Replace(string(fe1bShell("/assets/app-abc12345.js", "/assets/app-abc12345.css")), "</head>", `<link rel="modulepreload" crossorigin href="/assets/app-abc12345.js"></head>`, 1))},
		{"shell single-quoted script is invisible", shellOnly(`<!doctype html><script type="module" src='/assets/app-abc12345.js'></script><link rel="stylesheet" href="/assets/app-abc12345.css">`)},
		{"chunk with extra asset kinds", addFile("assets/logo-abcd1234.svg", addFile("assets/font-abcd1234.woff2", manifestOnly(`{"index.html":{"file":"assets/app-abc12345.js","css":["assets/app-abc12345.css"],"assets":["assets/logo-abcd1234.svg","assets/font-abcd1234.woff2"],"isEntry":true}}`)))},
	}
}

// goldenVerdict renders what the validator returned for one tree: the error
// text, or the shell length and the sorted asset set with its metadata.
func goldenVerdict(shell []byte, paths []string, meta func(p string) (string, int64), err error) string {
	if err != nil {
		return "ERR " + err.Error()
	}
	sort.Strings(paths)
	var b strings.Builder
	fmt.Fprintf(&b, "OK shell=%d", len(shell))
	for _, p := range paths {
		ct, size := meta(p)
		fmt.Fprintf(&b, " | %s [%s] %d", p, ct, size)
	}
	return b.String()
}

var goldenMain = map[string]string{
	"control":                                 "OK shell=215 | assets/app-abc12345.css [text/css; charset=utf-8] 6 | assets/app-abc12345.js [text/javascript; charset=utf-8] 14",
	"empty index":                             "ERR index.html missing or empty",
	"missing index":                           "ERR index.html missing or empty",
	"missing manifest":                        "ERR manifest.json missing",
	"invalid json":                            "ERR manifest.json does not parse",
	"manifest is array":                       "ERR manifest.json does not parse",
	"empty manifest":                          "ERR manifest.json has no entries",
	"null manifest":                           "ERR manifest.json has no entries",
	"duplicate top-level key":                 "ERR manifest.json has a duplicate object key",
	"duplicate nested key":                    "ERR manifest.json has a duplicate object key",
	"no entry chunk":                          "ERR manifest has no entry chunk",
	"entry without file":                      "ERR manifest entry \"index.html\" has no file",
	"entry key with control bytes":            "ERR manifest entry \"a_b____c\" has no file",
	"empty path in css":                       "ERR manifest entry \"index.html\": empty asset path",
	"absolute path":                           "ERR manifest entry \"index.html\": absolute or backslash asset path",
	"backslash path":                          "ERR manifest entry \"index.html\": absolute or backslash asset path",
	"traversal":                               "ERR manifest entry \"index.html\": traversal in asset path",
	"encoded":                                 "ERR manifest entry \"index.html\": encoded characters in asset path",
	"scheme":                                  "ERR manifest entry \"index.html\": scheme or origin in asset path",
	"double slash":                            "ERR manifest entry \"index.html\": scheme or origin in asset path",
	"non-canonical":                           "ERR manifest entry \"index.html\": non-canonical asset path",
	"outside namespace":                       "ERR manifest entry \"index.html\": asset outside assets/ namespace",
	"sourcemap referenced":                    "ERR manifest entry \"index.html\": sourcemap referenced",
	"unsupported extension":                   "ERR manifest entry \"index.html\": unsupported asset extension \".wasm\"",
	"no extension":                            "ERR manifest entry \"index.html\": unsupported asset extension \"\"",
	"unhashed name":                           "ERR manifest entry \"index.html\": asset \"assets/app.js\" lacks the content-hash suffix required for immutable caching",
	"short hash":                              "ERR manifest entry \"index.html\": asset \"assets/app-abc1234.js\" lacks the content-hash suffix required for immutable caching",
	"disallowed character":                    "ERR manifest entry \"index.html\": disallowed character in asset path",
	"non-ascii character":                     "ERR manifest entry \"index.html\": disallowed character in asset path",
	"control byte in path":                    "ERR manifest entry \"index.html\": disallowed character in asset path",
	"missing static import key":               "ERR manifest entry \"index.html\" imports missing key \"_g_one\"",
	"missing dynamic import key":              "ERR manifest entry \"index.html\" dynamically imports missing key \"_gone\"",
	"missing referenced file":                 "ERR manifest references missing file \"assets/app-abc12345.css\"",
	"unreferenced stray asset":                "ERR embedded asset \"assets/stray-def45678.js\" not referenced by manifest",
	"stray root file":                         "ERR embedded file \"extra.txt\": asset outside assets/ namespace",
	"stray directory":                         "ERR unexpected directory \"vendor\" in dist",
	"nested assets directory":                 "ERR unexpected directory \"assets/sub\" in dist",
	"sourcemap embedded":                      "ERR sourcemap \"assets/app-abc12345.js.map\" embedded",
	"unhashed embedded file":                  "ERR embedded file \"assets/logo.png\": asset \"assets/logo.png\" lacks the content-hash suffix required for immutable caching",
	"no assets at all":                        "ERR no assets in dist",
	"case collision":                          "ERR ambiguous assets differing only by case",
	"no index.html entry":                     "ERR manifest has no \"index.html\" entry",
	"index.html entry not isEntry":            "ERR manifest \"index.html\" entry is not isEntry",
	"entry file is css":                       "ERR manifest \"index.html\" entry file is not a JS chunk",
	"shell references other script":           "ERR shell does not reference the manifest entry JS",
	"shell has two scripts":                   "ERR shell references 2 scripts, want exactly the entry chunk",
	"shell omits css":                         "ERR shell stylesheet set differs from manifest entry css",
	"shell wrong css":                         "ERR shell references stylesheet outside the manifest entry css",
	"shell relative script":                   "ERR shell does not reference the manifest entry JS",
	"shell preload not validated":             "ERR shell modulepreload is not a validated /assets/ artifact",
	"shell preload validated":                 "OK shell=284 | assets/app-abc12345.css [text/css; charset=utf-8] 6 | assets/app-abc12345.js [text/javascript; charset=utf-8] 14",
	"shell single-quoted script is invisible": "ERR shell does not reference the manifest entry JS",
	"chunk with extra asset kinds":            "OK shell=215 | assets/app-abc12345.css [text/css; charset=utf-8] 6 | assets/app-abc12345.js [text/javascript; charset=utf-8] 14 | assets/font-abcd1234.woff2 [font/woff2] 1 | assets/logo-abcd1234.svg [image/svg+xml] 1",
}

func verdictFor(mutate func(m map[string]*fstest.MapFile)) string {
	shell, assets, err := Validate(fe1bFixture(mutate))
	paths := make([]string, 0, len(assets))
	for p := range assets {
		paths = append(paths, p)
	}
	return goldenVerdict(shell, paths, func(p string) (string, int64) { return assets[p].ContentType, assets[p].Size }, err)
}

func TestValidate_VerdictsMatchMainBeforeTheMove(t *testing.T) {
	cases := goldenCases()
	if len(cases) != len(goldenMain) {
		t.Fatalf("corpus has %d cases but %d recorded verdicts", len(cases), len(goldenMain))
	}
	accepted, rejected := 0, 0
	for _, c := range cases {
		want, ok := goldenMain[c.name]
		if !ok {
			t.Errorf("%s: no verdict recorded from main", c.name)
			continue
		}
		// Twice: a verdict must not depend on map iteration order.
		for run := 0; run < 2; run++ {
			if got := verdictFor(c.mutate); got != want {
				t.Errorf("%s: verdict changed\n got  %s\n main %s", c.name, got, want)
			}
		}
		if strings.HasPrefix(want, "OK ") {
			accepted++
		} else {
			rejected++
		}
	}
	// Anti-vacuity: the corpus must exercise both outcomes.
	if accepted < 3 || rejected < 40 {
		t.Fatalf("corpus covers %d accepted and %d rejected trees; too thin to pin the move", accepted, rejected)
	}
}

// Mutation control: the comparison must notice the two regressions a careless
// edit would make, a changed error string and a changed content type.
func TestValidate_GoldenComparisonDetectsDrift(t *testing.T) {
	if got := verdictFor(manifestOnly("{not json")); got == strings.Replace(goldenMain["invalid json"], "does not parse", "is invalid", 1) {
		t.Fatal("comparison cannot see a reworded error")
	}
	drifted := strings.Replace(goldenMain["control"], "text/javascript; charset=utf-8", "application/javascript", 1)
	if drifted == goldenMain["control"] || verdictFor(nil) == drifted {
		t.Fatal("comparison cannot see a changed content type")
	}
}
