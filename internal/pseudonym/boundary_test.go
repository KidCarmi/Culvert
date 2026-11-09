package pseudonym

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Boundary (ADR-0044): no application/root imports, no package-level mutable
// state, no init(). Key state lives on the Pseudonymizer instance.
func boundaryViolations(name string, source []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return []string{err.Error()}
	}
	var v []string
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if strings.HasPrefix(p, "github.com/KidCarmi/Culvert") && p != "github.com/KidCarmi/Culvert/internal/hostutil" {
			v = append(v, "dependency: "+p)
		}
		if p == "log" || p == "fmt" || p == "os" || strings.HasPrefix(p, "net") {
			v = append(v, "I/O or logging import: "+p)
		}
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "init" {
			v = append(v, "implicit initialization")
		}
		if g, ok := decl.(*ast.GenDecl); ok && g.Tok == token.VAR {
			for _, s := range g.Specs {
				for _, n := range s.(*ast.ValueSpec).Names {
					v = append(v, "package state: "+n.Name)
				}
			}
		}
	}
	return v
}

func TestPseudonymBoundary_NoAppImportsOrSharedState(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
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
	}
	if checked < 2 {
		t.Fatalf("inspected %d production files, want doc.go and pseudonym.go", checked)
	}
}

func TestPseudonymBoundary_RejectsRegressions(t *testing.T) {
	for name, src := range map[string]string{
		"root import":   `package pseudonym; import "github.com/KidCarmi/Culvert/internal/obs"`,
		"logging":       `package pseudonym; import "log"`,
		"package state": "package pseudonym; var key []byte",
		"init":          "package pseudonym; func init() {}",
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations("r.go", []byte(src))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
}
