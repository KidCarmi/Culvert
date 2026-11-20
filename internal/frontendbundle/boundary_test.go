package frontendbundle

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// maxExported caps the package's exported surface (ADR-0050): Validate and the
// two types its signature and the manifest format need.
const maxExported = 3

// allowedInternal is the only module import the package may have: the leaf
// CWE-117 sanitizer. Anything else (the application, a store, the logger's
// owner) would make the validator depend on what it is meant to be judged
// independently of.
const allowedInternal = "github.com/KidCarmi/Culvert/internal/obs"

// Boundary (ADR-0050): no application imports, no logging, networking, process
// or shared-state imports, no init(), and no package-level variable other than
// a compiled regular expression (immutable and safe for concurrent use).
func boundaryViolations(name string, source []byte) (violations []string, exported int) {
	f, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return []string{err.Error()}, 0
	}
	violations = importViolations(f)
	for _, decl := range f.Decls {
		var v []string
		var n int
		switch d := decl.(type) {
		case *ast.FuncDecl:
			v, n = funcViolations(d)
		case *ast.GenDecl:
			v, n = genDeclViolations(d)
		}
		violations = append(violations, v...)
		exported += n
	}
	return violations, exported
}

func importViolations(f *ast.File) []string {
	var v []string
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if strings.HasPrefix(p, "github.com/KidCarmi/Culvert") && p != allowedInternal {
			v = append(v, "dependency: "+p)
		}
		switch {
		case p == "log", p == "os", p == "sync", p == "embed", p == "time":
			v = append(v, "logging, process, shared-state, embedding or clock import: "+p)
		case p == "net" || strings.HasPrefix(p, "net/"):
			v = append(v, "network import: "+p)
		}
	}
	return v
}

func funcViolations(d *ast.FuncDecl) (violations []string, exported int) {
	if d.Recv != nil {
		return nil, 0
	}
	if d.Name.Name == "init" {
		violations = append(violations, "implicit initialization")
	}
	if d.Name.IsExported() {
		exported = 1
	}
	return violations, exported
}

func genDeclViolations(d *ast.GenDecl) (violations []string, exported int) {
	for _, s := range d.Specs {
		switch s := s.(type) {
		case *ast.TypeSpec:
			if s.Name.IsExported() {
				exported++
			}
		case *ast.ValueSpec:
			for i, n := range s.Names {
				if n.IsExported() {
					exported++
				}
				if d.Tok == token.VAR && !isCompiledRegexp(s, i) {
					violations = append(violations, "package state: "+n.Name)
				}
			}
		}
	}
	return violations, exported
}

// isCompiledRegexp reports whether the i-th name of s is initialised directly
// by regexp.MustCompile.
func isCompiledRegexp(s *ast.ValueSpec, i int) bool {
	if i >= len(s.Values) {
		return false
	}
	call, ok := s.Values[i].(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "regexp" && sel.Sel.Name == "MustCompile"
}

func TestFrontendBundleBoundary_NoAppImportsOrSharedState(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked, exported := 0, 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		checked++
		got, n := boundaryViolations(e.Name(), src)
		exported += n
		if len(got) != 0 {
			t.Errorf("%s: %v", e.Name(), got)
		}
	}
	if checked < 5 {
		t.Fatalf("inspected %d production files, want doc.go, validate.go, shell.go, jsonkeys.go and assetpath.go", checked)
	}
	if exported != maxExported {
		t.Fatalf("exported surface is %d identifiers, want exactly %d (Validate, Asset, ManifestEntry)", exported, maxExported)
	}
}

func TestFrontendBundleBoundary_RejectsRegressions(t *testing.T) {
	for name, src := range map[string]string{
		"app import":        `package frontendbundle; import "github.com/KidCarmi/Culvert/internal/audit"`,
		"root import":       `package frontendbundle; import "github.com/KidCarmi/Culvert"`,
		"logging":           `package frontendbundle; import "log"`,
		"process I/O":       `package frontendbundle; import "os"`,
		"serving layer":     `package frontendbundle; import "net/http"`,
		"shared lock":       `package frontendbundle; import "sync"`,
		"embedded artifact": `package frontendbundle; import "embed"`,
		"mutable table":     `package frontendbundle; var mime = map[string]string{".js": "text/javascript"}`,
		"cached result":     "package frontendbundle; var last []byte",
		"lazy regexp":       `package frontendbundle; import "regexp"; var re *regexp.Regexp`,
		"init":              "package frontendbundle; func init() {}",
	} {
		t.Run(name, func(t *testing.T) {
			if got, _ := boundaryViolations("r.go", []byte(src)); len(got) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
	t.Run("compiled regexp is allowed", func(t *testing.T) {
		src := "package frontendbundle; import \"regexp\"; var re = regexp.MustCompile(`x`)"
		if got, _ := boundaryViolations("r.go", []byte(src)); len(got) != 0 {
			t.Fatalf("a directly compiled regexp was rejected: %v", got)
		}
	})
	t.Run("exported surface is counted", func(t *testing.T) {
		src := "package frontendbundle; func A(){}; type B struct{}; const C = 1; var D = 0; func (B) M(){}; func e(){}"
		if _, n := boundaryViolations("r.go", []byte(src)); n != 4 {
			t.Fatalf("counted %d exported names, want 4 (methods and unexported names excluded)", n)
		}
	})
}
