package livetier

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Boundary (ADR-0057): no Culvert import at all, no I/O, logging or network
// import, no init(), no package-level variable except an Err* sentinel built
// by errors.New, and at most maxExported exported package-level identifiers.
//
// The cap is 10, above the program's usual 8, and is stated rather than
// hidden: five of the names are one enumeration (State and its four values),
// two are the sentinel errors main already compared against, and three are
// the constructor surface (Tier, Options, New).
const maxExported = 10

func boundaryViolations(name string, source []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return []string{err.Error()}
	}
	var v []string
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if strings.HasPrefix(p, "github.com/KidCarmi/Culvert") {
			v = append(v, "dependency: "+p)
		}
		if p == "log" || p == "os" || p == "io" || p == "unsafe" || strings.HasPrefix(p, "net") || strings.HasPrefix(p, "log/") {
			v = append(v, "I/O, logging or network import: "+p)
		}
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "init" {
			v = append(v, "implicit initialization")
		}
		if g, ok := decl.(*ast.GenDecl); ok && g.Tok == token.VAR {
			for _, s := range g.Specs {
				v = append(v, packageStateViolations(s.(*ast.ValueSpec))...)
			}
		}
	}
	return v
}

// packageStateViolations admits exactly one shape of package variable:
// `ErrX = errors.New("literal")`.
func packageStateViolations(vs *ast.ValueSpec) []string {
	var v []string
	for i, n := range vs.Names {
		if strings.HasPrefix(n.Name, "Err") && i < len(vs.Values) && isErrorsNewLiteral(vs.Values[i]) {
			continue
		}
		v = append(v, "package state: "+n.Name)
	}
	return v
}

func isErrorsNewLiteral(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "New" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "errors" {
		return false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

func exportedTopLevel(source []byte) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", source, 0)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil && d.Name.IsExported() {
				names = append(names, d.Name.Name)
			}
		case *ast.GenDecl:
			names = append(names, exportedSpecNames(d.Specs)...)
		}
	}
	return names, nil
}

func exportedSpecNames(specs []ast.Spec) []string {
	var names []string
	for _, s := range specs {
		switch sp := s.(type) {
		case *ast.TypeSpec:
			if sp.Name.IsExported() {
				names = append(names, sp.Name.Name)
			}
		case *ast.ValueSpec:
			for _, n := range sp.Names {
				if n.IsExported() {
					names = append(names, n.Name)
				}
			}
		}
	}
	return names
}

func TestLiveTierBoundary_NoAppImportsOrSharedState(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	var exported []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		checked++
		if got := boundaryViolations(e.Name(), src); len(got) != 0 {
			t.Errorf("%s: %v", e.Name(), got)
		}
		names, err := exportedTopLevel(src)
		if err != nil {
			t.Fatal(err)
		}
		exported = append(exported, names...)
	}
	if checked < 2 {
		t.Fatalf("inspected %d production files, want doc.go and tier.go", checked)
	}
	if len(exported) > maxExported {
		t.Fatalf("exported surface grew to %d (>%d): %v", len(exported), maxExported, exported)
	}
}

func TestLiveTierBoundary_RejectsRegressions(t *testing.T) {
	for name, src := range map[string]string{
		"root import":       `package livetier; import "github.com/KidCarmi/Culvert"`,
		"sibling import":    `package livetier; import "github.com/KidCarmi/Culvert/internal/mcp/rollout"`,
		"network":           `package livetier; import "net/http"`,
		"logging":           `package livetier; import "log"`,
		"files":             `package livetier; import "os"`,
		"package tier":      "package livetier; var global = New(Options{})",
		"package flag":      "package livetier; var armed bool",
		"mutable Err value": "package livetier; var ErrCount int",
		"computed sentinel": `package livetier; import "fmt"; var ErrX = fmt.Errorf("x %d", 1)`,
		"init":              "package livetier; func init() {}",
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations("r.go", []byte(src))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
	if got := boundaryViolations("ok.go", []byte(`package livetier; import "errors"; var ErrX = errors.New("x")`)); len(got) != 0 {
		t.Fatalf("the one permitted package variable shape was rejected: %v", got)
	}
	names, err := exportedTopLevel([]byte("package livetier; type A int; type B int; const C, D = 1, 2; func E() {}; var F, G, H, I, J, K int"))
	if err != nil || len(names) != maxExported+1 {
		t.Fatalf("export counter missed a deliberate %d-name surface: %v %v", maxExported+1, names, err)
	}
}
