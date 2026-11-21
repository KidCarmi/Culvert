package hostpin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Boundary (ADR-0052): the only Culvert import is internal/hostutil (the
// canonicalization the comparison is defined over), the only network import is
// the address-parsing package "net" (never net/http or a dialer's packages), no
// I/O, logging, clock, context or shared-state imports, no package-level
// variable, no init(), and at most 8 exported package-level identifiers.
var allowedImports = map[string]bool{
	"github.com/KidCarmi/Culvert/internal/hostutil": true,
}

// forbiddenImports are the standard-library packages that would give the
// predicate I/O, a logger, a clock, cancellation or shared state.
var forbiddenImports = map[string]bool{
	"log": true, "os": true, "io": true, "sync": true, "sync/atomic": true,
	"unsafe": true, "time": true, "context": true, "bufio": true,
}

func boundaryViolations(name string, source []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return []string{err.Error()}
	}
	var v []string
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if strings.HasPrefix(p, "github.com/KidCarmi/Culvert") && !allowedImports[p] {
			v = append(v, "dependency: "+p)
		}
		if forbiddenImports[p] || strings.HasPrefix(p, "net/") || strings.HasPrefix(p, "log/") {
			v = append(v, "I/O, logging, clock or shared-state import: "+p)
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

func TestHostPinBoundary_NoAppImportsOrSharedState(t *testing.T) {
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
		t.Fatalf("inspected %d production files, want doc.go and pin.go", checked)
	}
	if len(exported) > 8 {
		t.Fatalf("exported surface grew to %d (>8): %v", len(exported), exported)
	}
}

func TestHostPinBoundary_RejectsRegressions(t *testing.T) {
	for name, src := range map[string]string{
		"root import":    `package hostpin; import "github.com/KidCarmi/Culvert"`,
		"sibling import": `package hostpin; import "github.com/KidCarmi/Culvert/internal/urlcat"`,
		"http":           `package hostpin; import "net/http"`,
		"logging":        `package hostpin; import "log"`,
		"shared state":   `package hostpin; import "sync"`,
		"counter":        `package hostpin; import "sync/atomic"`,
		"clock":          `package hostpin; import "time"`,
		"package state":  "package hostpin; var refused int64",
		"init":           "package hostpin; func init() {}",
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations("r.go", []byte(src))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
	// Control: the imports the package really has are accepted.
	const accepted = `package hostpin; import ("net"; "strings"; "golang.org/x/net/http/httpguts"; "github.com/KidCarmi/Culvert/internal/hostutil")`
	if got := boundaryViolations("ok.go", []byte(accepted)); len(got) != 0 {
		t.Fatalf("boundary rejected the package's own imports: %v", got)
	}
	names, err := exportedTopLevel([]byte("package hostpin; type A int; type B int; const C, D = 1, 2; func E() {}; var F, G, H, I int"))
	if err != nil || len(names) != 9 {
		t.Fatalf("export counter missed a deliberate 9-name surface: %v %v", names, err)
	}
}
