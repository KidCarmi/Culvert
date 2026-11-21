package keyedmutex

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Boundary (ADR-0054): the lock is a leaf. Its only import is "sync"; it has
// no package-level variable, no init func and no package-level function that
// could hand out a shared instance other than the constructor. Changing one of
// these requires revisiting the ADR.
func boundaryViolations(name string, source []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return []string{err.Error()}
	}
	var v []string
	for _, imp := range f.Imports {
		if p := strings.Trim(imp.Path.Value, `"`); p != "sync" {
			v = append(v, "dependency: "+p)
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

func TestKeyedMutexBoundary_NoAppImportsOrSharedState(t *testing.T) {
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
		t.Fatalf("inspected %d production files, want doc.go and keyedmutex.go", checked)
	}
	if len(exported) != 2 {
		t.Fatalf("exported surface is %d names, want Mutex and New: %v", len(exported), exported)
	}
}

func TestKeyedMutexBoundary_RejectsRegressions(t *testing.T) {
	for name, src := range map[string]string{
		"root import":        `package keyedmutex; import "github.com/KidCarmi/Culvert"`,
		"sibling import":     `package keyedmutex; import "github.com/KidCarmi/Culvert/internal/obs"`,
		"logging":            `package keyedmutex; import "log"`,
		"clock":              `package keyedmutex; import "time"`,
		"atomics":            `package keyedmutex; import "sync/atomic"`,
		"context":            `package keyedmutex; import "context"`,
		"shared instance":    "package keyedmutex; var Default = New()",
		"package state":      "package keyedmutex; var held = map[string]int{}",
		"implicit lifecycle": "package keyedmutex; func init() {}",
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations("r.go", []byte(src))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
	if got := boundaryViolations("ok.go", []byte(`package keyedmutex; import "sync"; type T struct{ mu sync.Mutex }`)); len(got) != 0 {
		t.Fatalf("the allowed import was rejected: %v", got)
	}
	names, err := exportedTopLevel([]byte("package keyedmutex; type A int; const B, C = 1, 2; func D() {}; var E int; func (A) M() {}"))
	if err != nil || len(names) != 5 {
		t.Fatalf("export counter missed a deliberate 5-name surface: %v %v", names, err)
	}
}
