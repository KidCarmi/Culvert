package authposture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Boundary (ADR-0063): the ratchet is a leaf owned by the authentication
// domain. It imports only the standard library packages below — no root
// package, no sibling internal package (the durable writer is injected), no
// logger, no network — and has no package-level variable and no init, so no
// shared instance can exist outside the one its owner constructs. Changing one
// of these requires revisiting the ADR.
var allowedImports = map[string]bool{
	"bytes": true, "encoding/json": true, "errors": true, "fmt": true, "io": true,
	"io/fs": true, "os": true, "sync": true, "sync/atomic": true, "time": true,
}

func boundaryViolations(name string, source []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return []string{err.Error()}
	}
	var v []string
	for _, imp := range f.Imports {
		if p := strings.Trim(imp.Path.Value, `"`); !allowedImports[p] {
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
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if _, ok := n.(*ast.GoStmt); ok {
					v = append(v, "goroutine in "+fn.Name.Name)
				}
				return true
			})
		}
	}
	return v
}

func TestAuthPostureBoundary_LeafWithNoSharedState(t *testing.T) {
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
		t.Fatalf("inspected %d production files, want doc.go and ratchet.go", checked)
	}
}

// Negative controls: the checker must reject each regression it exists for.
func TestAuthPostureBoundary_RejectsRegressions(t *testing.T) {
	for name, src := range map[string]string{
		"root import":     `package authposture; import "github.com/KidCarmi/Culvert"`,
		"sibling import":  `package authposture; import "github.com/KidCarmi/Culvert/internal/fileutil"`,
		"logging":         `package authposture; import "log"`,
		"network":         `package authposture; import "net/http"`,
		"shared instance": "package authposture; var Default Ratchet",
		"implicit init":   "package authposture; func init() {}",
		"background loop": "package authposture; func poll() { go func() {}() }",
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations("r.go", []byte(src))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
	if got := boundaryViolations("ok.go", []byte(`package authposture; import ("os"; "sync/atomic"); type T struct{ b atomic.Bool }; func f() { _ = os.ReadFile }`)); len(got) != 0 {
		t.Fatalf("allowed imports were rejected: %v", got)
	}
}
