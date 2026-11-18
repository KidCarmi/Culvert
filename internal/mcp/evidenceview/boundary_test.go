package evidenceview

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Boundary (ADR-0046): the only Culvert import is internal/mcp/rollout (the
// evidence owner); no I/O or logging imports, no package-level mutable state,
// no init(), and at most 8 exported package-level identifiers.
func boundaryViolations(name string, source []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return []string{err.Error()}
	}
	var v []string
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if strings.HasPrefix(p, "github.com/KidCarmi/Culvert") && p != "github.com/KidCarmi/Culvert/internal/mcp/rollout" {
			v = append(v, "dependency: "+p)
		}
		if p == "log" || p == "fmt" || p == "os" || strings.HasPrefix(p, "net") || strings.HasPrefix(p, "sync") {
			v = append(v, "I/O, logging or shared-state import: "+p)
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

func TestEvidenceViewBoundary_NoAppImportsOrSharedState(t *testing.T) {
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
		t.Fatalf("inspected %d production files, want doc.go and evidenceview.go", checked)
	}
	if len(exported) > 8 {
		t.Fatalf("exported surface grew to %d (>8): %v", len(exported), exported)
	}
}

func TestEvidenceViewBoundary_RejectsRegressions(t *testing.T) {
	for name, src := range map[string]string{
		"root import":    `package evidenceview; import "github.com/KidCarmi/Culvert/internal/obs"`,
		"sibling import": `package evidenceview; import "github.com/KidCarmi/Culvert/internal/mcp/execution"`,
		"logging":        `package evidenceview; import "log"`,
		"shared state":   `package evidenceview; import "sync"`,
		"package state":  "package evidenceview; var categories = []string{\"x\"}",
		"init":           "package evidenceview; func init() {}",
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations("r.go", []byte(src))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
	names, err := exportedTopLevel([]byte("package evidenceview; type A int; type B int; const C, D = 1, 2; func E() {}; var F, G, H, I int"))
	if err != nil || len(names) != 9 {
		t.Fatalf("export counter missed a deliberate 9-name surface: %v %v", names, err)
	}
}
