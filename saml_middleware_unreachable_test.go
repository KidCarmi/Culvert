package main

// saml_middleware_unreachable_test.go — structural wall over the vendored
// crewjam/saml samlsp package.
//
// Culvert runs its own SAML AuthnRequest-state + ACS flow (auth_saml.go,
// internal/authstate). samlsp.New is called ONLY to assemble a
// ServiceProvider. The samlsp.Middleware HTTP entry points (ServeHTTP,
// ServeACS, RequireAccount, HandleStartAuthFlow, ...) and its cookie session
// provider / request tracker carry CodeQL findings in
// third_party/crewjam-saml (open redirect via RelayState, cookies without a
// forced Secure flag) that are UNREACHABLE today precisely because nothing
// mounts or calls them. This wall keeps it that way: production code outside
// third_party/ may bind samlsp.New's result only to read .ServiceProvider,
// and may never name the middleware type or its session/tracker machinery.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const samlspImportPath = "github.com/crewjam/saml/samlsp"

// samlspForbiddenSymbols are package-level samlsp names production code must
// not reference: the middleware type (so it cannot be stored or mounted) and
// the cookie session/request-tracking machinery behind its ACS flow.
var samlspForbiddenSymbols = map[string]bool{
	"Middleware":                 true,
	"CookieSessionProvider":      true,
	"CookieRequestTracker":       true,
	"DefaultSessionProvider":     true,
	"DefaultRequestTracker":      true,
	"DefaultSessionCodec":        true,
	"DefaultTrackedRequestCodec": true,
}

type samlspScan struct {
	files      int // files importing samlsp
	bindings   int // samlsp.New results bound to a local
	spReads    int // allowed <binding>.ServiceProvider reads
	violations []string
}

func (s *samlspScan) violate(fset *token.FileSet, pos token.Pos, what string) {
	s.violations = append(s.violations, fset.Position(pos).String()+": "+what)
}

// samlspLocalName returns the name the file uses for samlsp, or "".
func samlspLocalName(f *ast.File) string {
	for _, imp := range f.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err != nil || p != samlspImportPath {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return "samlsp"
	}
	return ""
}

func isSamlspSel(n ast.Node, pkg, name string) bool {
	sel, ok := n.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg && (name == "" || sel.Sel.Name == name)
}

func scanSAMLSPFile(fset *token.FileSet, f *ast.File, s *samlspScan) {
	pkg := samlspLocalName(f)
	if pkg == "" {
		return
	}
	s.files++
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && isSamlspSel(sel, pkg, "") && samlspForbiddenSymbols[sel.Sel.Name] {
			s.violate(fset, sel.Pos(), "references samlsp."+sel.Sel.Name)
		}
		return true
	})
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
			scanSAMLSPFunc(fset, fn.Body, pkg, s)
		}
	}
}

// scanSAMLSPFunc requires every samlsp.New result to be bound to a local
// whose ONLY use is reading .ServiceProvider. Passing the middleware anywhere
// (mux.Handle, a struct field, a return), calling any of its methods, or
// touching its Session/RequestTracker/OnError fields is a violation.
func scanSAMLSPFunc(fset *token.FileSet, body *ast.BlockStmt, pkg string, s *samlspScan) {
	bound := map[string]bool{}
	defs := map[*ast.Ident]bool{}
	newCalls := map[*ast.CallExpr]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 || len(as.Lhs) == 0 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok || !isSamlspSel(call.Fun, pkg, "New") {
			return true
		}
		newCalls[call] = true
		if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
			bound[id.Name], defs[id] = true, true
			s.bindings++
		} else {
			s.violate(fset, as.Pos(), "samlsp.New result discarded or stored outside a local")
		}
		return true
	})
	allowed := map[*ast.Ident]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if isSamlspSel(x.Fun, pkg, "New") && !newCalls[x] {
				s.violate(fset, x.Pos(), "samlsp.New result used directly (not bound to a local)")
			}
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && bound[id.Name] && x.Sel.Name == "ServiceProvider" {
				allowed[id] = true
				s.spReads++
			}
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && bound[id.Name] && !defs[id] && !allowed[id] {
			s.violate(fset, id.Pos(), "samlsp middleware "+id.Name+" used beyond .ServiceProvider")
		}
		return true
	})
}

func scanSAMLSPSource(t *testing.T, name, src string) *samlspScan {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	s := &samlspScan{}
	scanSAMLSPFile(fset, f, s)
	return s
}

func TestSAMLSPMiddlewareIsNeverServed(t *testing.T) {
	skipDirs := map[string]bool{"third_party": true, ".git": true, "node_modules": true, "frontend": true, "testdata": true, "vendor": true}
	fset := token.NewFileSet()
	s := &samlspScan{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil || samlspLocalName(f) == "" {
			return nil //nolint:nilerr // unparsable files are the compiler's job
		}
		if f, perr = parser.ParseFile(fset, path, nil, 0); perr != nil {
			return perr
		}
		scanSAMLSPFile(fset, f, s)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range s.violations {
		t.Errorf("samlsp middleware reachable: %s", v)
	}
	// Not vacuous: the scan must actually see the one production use.
	if s.files == 0 || s.bindings == 0 || s.spReads == 0 {
		t.Fatalf("scan saw no samlsp use (files=%d bindings=%d serviceProvider reads=%d) — the wall would pass against anything", s.files, s.bindings, s.spReads)
	}
}

// The checker must REJECT each way the middleware could become reachable,
// and accept the shape auth_saml.go uses.
func TestSAMLSPMiddlewareWallRejectsReachableShapes(t *testing.T) {
	const head = "package p\nimport (\n\"net/http\"\n\"github.com/crewjam/saml/samlsp\"\n)\nvar _ http.Handler\n"
	allowed := head + `func ok(o samlsp.Options) { m, err := samlsp.New(o); _ = err; sp := &m.ServiceProvider; _ = sp; m.ServiceProvider.EntityID = "x" }`
	if s := scanSAMLSPSource(t, "ok.go", allowed); len(s.violations) != 0 || s.bindings != 1 || s.spReads != 2 {
		t.Fatalf("allowed shape rejected or miscounted: %+v", s)
	}
	for name, body := range map[string]string{
		"mounted":       `func f(o samlsp.Options, mux *http.ServeMux) { m, _ := samlsp.New(o); mux.Handle("/saml/", m) }`,
		"ServeACS":      `func f(o samlsp.Options, w http.ResponseWriter, r *http.Request) { m, _ := samlsp.New(o); m.ServeACS(w, r) }`,
		"RequireAcct":   `func f(o samlsp.Options, h http.Handler) http.Handler { m, _ := samlsp.New(o); return m.RequireAccount(h) }`,
		"StartFlow":     `func f(o samlsp.Options, w http.ResponseWriter, r *http.Request) { m, _ := samlsp.New(o); m.HandleStartAuthFlow(w, r) }`,
		"ServeHTTP":     `func f(o samlsp.Options, w http.ResponseWriter, r *http.Request) { m, _ := samlsp.New(o); m.ServeHTTP(w, r) }`,
		"session":       `func f(o samlsp.Options) { m, _ := samlsp.New(o); _ = m.Session }`,
		"direct":        `func f(o samlsp.Options, mux *http.ServeMux) { mux.Handle("/", must(samlsp.New(o))) }`,
		"field":         `type t struct{ m *samlsp.Middleware }`,
		"cookieSession": `var _ = samlsp.CookieSessionProvider{}`,
		"tracker":       `func f(o samlsp.Options) { _ = samlsp.DefaultRequestTracker(o, nil) }`,
	} {
		if s := scanSAMLSPSource(t, name+".go", head+body); len(s.violations) == 0 {
			t.Errorf("%s: reachable middleware shape not rejected", name)
		}
	}
	aliased := "package p\nimport sp \"github.com/crewjam/saml/samlsp\"\nfunc f(o sp.Options) { _ = sp.DefaultSessionProvider(o) }"
	if s := scanSAMLSPSource(t, "alias.go", aliased); len(s.violations) == 0 {
		t.Error("aliased samlsp import escaped the wall")
	}
}
