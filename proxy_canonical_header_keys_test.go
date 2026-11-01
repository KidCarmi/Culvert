package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// ── The contract ────────────────────────────────────────────────────────────
//
// Every HTTP header key this tree hands to Header.Get/Set/Del/Add/Values must
// already be spelled in textproto canonical form (first byte and every byte
// after a '-' upper, the rest lower).
//
// WHY IT IS A GATE AND NOT A STYLE PREFERENCE. Those methods canonicalise the
// key they are given. An already-canonical spelling is scanned and returned
// verbatim; any other spelling takes the slow path that copies the key into a
// []byte, rewrites the casing and ALLOCATES. So a non-canonical constant buys
// nothing and costs an allocation plus a re-derivation on every call — on the
// request path, per request, forever. The two shapes are wire-identical
// (TestCanonicalHeaderKeys_WireIdentical below proves it), which is exactly why
// nothing ever failed and the cost went unnoticed: "X-Real-IP" sat behind a
// comment claiming the constants were canonical through several performance
// sweeps of this very file.
//
// For the keys ALSO used as direct map indices — r.Header[hdrForwardedFor] in
// scrubForwardedHeaders reads the slice without canonicalising — the rule is
// load-bearing for CORRECTNESS too: a non-canonical spelling there misses the
// header outright. That is the failure this gate is really here to prevent.

// headerShaped matches a string that could be an HTTP field name. Anything else
// (a URL query key, a form field, a map key) is not this gate's business.
var headerShaped = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(-[A-Za-z0-9]+)*$`)

// headerNamedDecl matches an identifier that declares a header NAME, so the
// gate can check constants as well as inline literals. hdrRealIP reached
// Header.Get through a constant, so a literal-only gate would have missed it.
var headerNamedDecl = regexp.MustCompile(`(?i)^(hdr|header)[A-Z0-9_]`)

// headerMethods are the net/http Header accessors that canonicalise their key.
var headerMethods = map[string]bool{"Get": true, "Set": true, "Del": true, "Add": true, "Values": true}

// repoGoFiles walks the module for production Go files. _test.go is excluded
// deliberately: a test may pass a deliberately non-canonical spelling as a
// negative control, which is the point of the control (see
// internal/mcpacceptance/scenarios.go, whose raw map fixture mirrors the
// spelling a real client sends and must keep doing so).
func repoGoFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	skip := map[string]bool{"vendor": true, "testdata": true, "node_modules": true, ".git": true}
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if skip[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(out) < 200 {
		t.Fatalf("walked only %d production .go files; the walk is broken, so a clean "+
			"run would be vacuous", len(out))
	}
	return out
}

// receiverMentionsHeader reports whether a call's receiver expression names a
// header map. It keeps the gate off same-named accessors on unrelated types —
// url.Values.Get("page") would otherwise be flagged, since "page" is not
// canonical. Narrowing by receiver rather than by key shape is what makes the
// gate precise enough to be absolute: no allowlist, no count.
func receiverMentionsHeader(sel *ast.SelectorExpr) bool {
	var sb strings.Builder
	var render func(ast.Expr)
	render = func(e ast.Expr) {
		switch v := e.(type) {
		case *ast.Ident:
			sb.WriteString(v.Name)
		case *ast.SelectorExpr:
			render(v.X)
			sb.WriteByte('.')
			sb.WriteString(v.Sel.Name)
		case *ast.CallExpr:
			render(v.Fun)
		case *ast.IndexExpr:
			render(v.X)
		case *ast.StarExpr:
			render(v.X)
		case *ast.ParenExpr:
			render(v.X)
		}
	}
	render(sel.X)
	r := sb.String()
	return strings.Contains(r, "Header") || strings.Contains(r, "Trailer")
}

func TestCanonicalHeaderKeys_Tree(t *testing.T) {
	fset := token.NewFileSet()
	type bad struct {
		pos, got, want, kind string
	}
	var found []bad

	for _, path := range repoGoFiles(t) {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			// (a) Inline literals handed to a Header accessor.
			case *ast.CallExpr:
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if !ok || !headerMethods[sel.Sel.Name] || len(node.Args) == 0 {
					return true
				}
				if !receiverMentionsHeader(sel) {
					return true
				}
				lit, ok := node.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil || !headerShaped.MatchString(s) {
					return true
				}
				if c := textproto.CanonicalMIMEHeaderKey(s); c != s {
					found = append(found, bad{fset.Position(lit.Pos()).String(), s, c, "literal"})
				}

			// (b) Declared header-name constants, which is how hdrRealIP
			// reached Header.Get without ever appearing as a literal there.
			case *ast.ValueSpec:
				for i, name := range node.Names {
					if !headerNamedDecl.MatchString(name.Name) || i >= len(node.Values) {
						continue
					}
					lit, ok := node.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					s, err := strconv.Unquote(lit.Value)
					if err != nil || !headerShaped.MatchString(s) {
						continue
					}
					if c := textproto.CanonicalMIMEHeaderKey(s); c != s {
						found = append(found, bad{fset.Position(lit.Pos()).String(), s, c, "const " + name.Name})
					}
				}
			}
			return true
		})
	}

	for _, b := range found {
		t.Errorf("%s: non-canonical header key %q (%s); use %q.\n"+
			"\tHeader.Get/Set/Del canonicalise the key, so %q allocates and re-derives on "+
			"every call while %q is returned verbatim. The two are wire-identical, so this "+
			"is pure cost — and for a key also used as a direct map index "+
			"(r.Header[...]) the non-canonical spelling misses the header entirely.",
			b.pos, b.got, b.kind, b.want, b.got, b.want)
	}
}

// TestCanonicalHeaderKeys_SelfCheck proves the gate can FAIL. A structural gate
// that silently stopped matching would be worse than no gate: it would read as
// a green guarantee of a property nothing was checking, which is precisely how
// "X-Real-IP" survived under a comment asserting canonicality.
func TestCanonicalHeaderKeys_SelfCheck(t *testing.T) {
	src := `package p
import "net/http"
const hdrThing = "X-Real-IP"
func f(r *http.Request) { _ = r.Header.Get("X-Bad-ID"); _ = r.Header.Get("Mcp-Session-Id") }
func g(v interface{ Get(string) string }) { _ = v.Get("page") }
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var hits []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || !headerMethods[sel.Sel.Name] || len(node.Args) == 0 || !receiverMentionsHeader(sel) {
				return true
			}
			if lit, ok := node.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				s, _ := strconv.Unquote(lit.Value)
				if headerShaped.MatchString(s) && textproto.CanonicalMIMEHeaderKey(s) != s {
					hits = append(hits, s)
				}
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				if !headerNamedDecl.MatchString(name.Name) || i >= len(node.Values) {
					continue
				}
				if lit, ok := node.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					s, _ := strconv.Unquote(lit.Value)
					if headerShaped.MatchString(s) && textproto.CanonicalMIMEHeaderKey(s) != s {
						hits = append(hits, s)
					}
				}
			}
		}
		return true
	})

	got := strings.Join(hits, ",")
	// "X-Real-IP" (const) and "X-Bad-ID" (literal) must be caught;
	// "Mcp-Session-Id" is canonical and must not be; "page" must not be, since
	// its receiver is not a header map — that negative is what keeps the
	// tree-wide gate free of an allowlist.
	if want := "X-Real-IP,X-Bad-ID"; got != want {
		t.Fatalf("self-check detected %q, want %q: the gate's matching has drifted, so "+
			"TestCanonicalHeaderKeys_Tree passing proves nothing", got, want)
	}
}

// TestCanonicalHeaderKeys_WireIdentical is the differential oracle behind the
// whole change: for every key canonicalised here, the old and new spellings
// address the SAME header, both when we read a received request and when we
// build an outbound one. This is what makes the optimisation provably
// behaviour-preserving rather than argued to be.
func TestCanonicalHeaderKeys_WireIdentical(t *testing.T) {
	pairs := []struct{ old, canonical string }{
		{"X-Real-IP", "X-Real-Ip"},
		{"MCP-Protocol-Version", "Mcp-Protocol-Version"},
		{"DPoP", "Dpop"},
		{"ETag", "Etag"},
		{"X-GitHub-Api-Version", "X-Github-Api-Version"},
		{"X-aws-ec2-metadata-token-ttl-seconds", "X-Aws-Ec2-Metadata-Token-Ttl-Seconds"},
	}
	for _, p := range pairs {
		if c := textproto.CanonicalMIMEHeaderKey(p.old); c != p.canonical {
			t.Fatalf("%q canonicalises to %q, not the %q this change substituted",
				p.old, c, p.canonical)
		}
		if c := textproto.CanonicalMIMEHeaderKey(p.canonical); c != p.canonical {
			t.Fatalf("substituted key %q is itself not canonical (-> %q)", p.canonical, c)
		}

		// Written under the OLD spelling, readable under the NEW one and vice
		// versa — Set canonicalises the stored key, so there was only ever one
		// map slot.
		for _, writeWith := range []string{p.old, p.canonical} {
			h := http.Header{}
			h.Set(writeWith, "v")
			if got := h.Get(p.old); got != "v" {
				t.Errorf("Set(%q) then Get(%q) = %q, want %q", writeWith, p.old, got, "v")
			}
			if got := h.Get(p.canonical); got != "v" {
				t.Errorf("Set(%q) then Get(%q) = %q, want %q", writeWith, p.canonical, got, "v")
			}
			// One slot, stored canonically: that is why the wire form is
			// unchanged, since Header.Write emits the map key.
			if _, ok := h[p.canonical]; !ok {
				t.Errorf("Set(%q) did not store under canonical key %q; map=%v",
					writeWith, p.canonical, h)
			}
			if len(h) != 1 {
				t.Errorf("Set(%q) produced %d map keys, want 1: %v", writeWith, len(h), h)
			}
		}

		// Del addresses the same slot under either spelling.
		for _, delWith := range []string{p.old, p.canonical} {
			h := http.Header{}
			h.Set(p.canonical, "v")
			h.Del(delWith)
			if got := h.Get(p.canonical); got != "" {
				t.Errorf("Del(%q) left %q = %q", delWith, p.canonical, got)
			}
		}
	}
}

// TestCanonicalHeaderKeys_ScrubStillScrubs pins the behaviour that the hot-path
// constant actually serves: the X-Real-IP scrub must keep removing a private
// hop and keep a public one, addressed through the canonicalised constant.
func TestCanonicalHeaderKeys_ScrubStillScrubs(t *testing.T) {
	cases := []struct {
		name, set, wantAfter string
	}{
		{"private is removed", "10.1.2.3", ""},
		{"loopback is removed", "127.0.0.1", ""},
		{"public survives", "203.0.113.9", "203.0.113.9"},
		{"unparseable is removed", "not-an-ip", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Written with the pre-change spelling on purpose: a real client
			// sends whatever casing it likes, and the scrub must still see it.
			for _, writeWith := range []string{"X-Real-IP", "X-Real-Ip", "x-real-ip"} {
				r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://t.example.com/", http.NoBody)
				if err != nil {
					t.Fatalf("new request: %v", err)
				}
				r.Header.Set(writeWith, tc.set)
				scrubForwardedHeaders(r)
				if got := r.Header.Get(hdrRealIP); got != tc.wantAfter {
					t.Errorf("set via %q: after scrub %s = %q, want %q",
						writeWith, hdrRealIP, got, tc.wantAfter)
				}
			}
		})
	}
}
