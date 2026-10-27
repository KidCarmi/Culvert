package identcache

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// These restrictions are specific to this engine, not a proposed architecture
// framework. Changing one requires revisiting ADR-0041.
//
// The engine is a stdlib leaf: package main supplies the cap and the eviction
// sink through Options, so an application import, a package-level variable (the
// process-wide eviction total used to be one, in package main) or an init func
// would each reintroduce state that independent caches, and tests, share.
func boundaryViolations(name string, source []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return []string{err.Error()}
	}
	var violations []string
	allowed := map[string]bool{"sync": true, "time": true}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if !allowed[path] {
			violations = append(violations, "dependency: "+path)
		}
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "init" {
			violations = append(violations, "implicit initialization")
		}
		g, ok := decl.(*ast.GenDecl)
		if !ok || g.Tok != token.VAR {
			continue
		}
		for _, spec := range g.Specs {
			for _, n := range spec.(*ast.ValueSpec).Names {
				violations = append(violations, "package state: "+n.Name)
			}
		}
	}
	return violations
}

func TestIdentcacheBoundary_NoApplicationDependenciesOrSharedState(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		source, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		checked++
		if got := boundaryViolations(entry.Name(), source); len(got) != 0 {
			t.Errorf("%s: %v", entry.Name(), got)
		}
	}
	if checked < 2 {
		t.Fatalf("inspected %d production files, want at least doc.go and identcache.go", checked)
	}
}

func TestIdentcacheBoundary_RejectsRegressions(t *testing.T) {
	for name, source := range map[string]string{
		"process-wide eviction total": `package identcache; import "sync/atomic"; var evictionsTotal atomic.Uint64`,
		"package singleton":           "package identcache; var shared = New[int](Options{MaxEntries: 1})",
		"shared cap":                  "package identcache; var maxEntries = 5000",
		"application logging":         `package identcache; import "github.com/KidCarmi/Culvert/internal/obs"`,
		"persistence":                 `package identcache; import "os"`,
		"implicit lifecycle":          "package identcache; func init() {}",
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations("regression.go", []byte(source))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
}
