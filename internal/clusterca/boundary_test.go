package clusterca

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// maxExported caps the package's exported surface (ADR-0048): the predicate,
// the clamp, the classifier, its remediation, the renewal window and the three
// error sentinels.
const maxExported = 8

// Boundary (ADR-0048): no application imports, no I/O or logging, no init(),
// and no package-level variable other than an Err* sentinel built directly by
// errors.New. The CA instance and its lock live in package main.
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
		if strings.HasPrefix(p, "github.com/KidCarmi/Culvert") {
			v = append(v, "dependency: "+p)
		}
		if p == "log" || p == "os" || p == "net" || p == "sync" {
			v = append(v, "I/O, logging or shared-state import: "+p)
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
				if d.Tok == token.VAR && !isErrorSentinel(n.Name, s, i) {
					violations = append(violations, "package state: "+n.Name)
				}
			}
		}
	}
	return violations, exported
}

func isErrorSentinel(name string, s *ast.ValueSpec, i int) bool {
	if !strings.HasPrefix(name, "Err") || i >= len(s.Values) {
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
	return ok && pkg.Name == "errors" && sel.Sel.Name == "New"
}

func TestClusterCABoundary_NoAppImportsOrSharedState(t *testing.T) {
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
	if checked < 2 {
		t.Fatalf("inspected %d production files, want doc.go and validity.go", checked)
	}
	if exported > maxExported {
		t.Fatalf("exported surface is %d identifiers, cap %d", exported, maxExported)
	}
}

func TestClusterCABoundary_RejectsRegressions(t *testing.T) {
	for name, src := range map[string]string{
		"app import":         `package clusterca; import "github.com/KidCarmi/Culvert/internal/ca"`,
		"logging":            `package clusterca; import "log"`,
		"file I/O":           `package clusterca; import "os"`,
		"shared lock":        `package clusterca; import "sync"`,
		"package state":      "package clusterca; var current any",
		"mutable Err holder": "package clusterca; var ErrLast error",
		"Err from non-New":   `package clusterca; import "fmt"; var ErrX = fmt.Errorf("x")`,
		"init":               "package clusterca; func init() {}",
	} {
		t.Run(name, func(t *testing.T) {
			if got, _ := boundaryViolations("r.go", []byte(src)); len(got) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
	t.Run("exported surface", func(t *testing.T) {
		src := "package clusterca; func A(){}; func B(){}; func C(){}; func D(){}; func E(){}; func F(){}; func G(){}; func H(){}; func I(){}"
		if _, n := boundaryViolations("r.go", []byte(src)); n <= maxExported {
			t.Fatalf("counted %d exported names, want > %d", n, maxExported)
		}
	})
}
