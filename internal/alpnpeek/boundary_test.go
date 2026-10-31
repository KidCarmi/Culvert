package alpnpeek

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// These restrictions are specific to this parser, not a proposed architecture
// framework. Changing one requires revisiting ADR-0042.
//
// The parser is an import-free leaf: package main owns the buffered reader and
// the fail-closed "http/1.1" fallback, so any import, package-level variable or
// init func here would add I/O, logging or shared state to code that parses
// attacker-influenced bytes.
func boundaryViolations(name string, source []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return []string{err.Error()}
	}
	var violations []string
	for _, imp := range f.Imports {
		violations = append(violations, "dependency: "+imp.Path.Value)
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

func TestAlpnpeekBoundary_NoDependenciesOrSharedState(t *testing.T) {
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
		t.Fatalf("inspected %d production files, want at least doc.go and alpn.go", checked)
	}
}

func TestAlpnpeekBoundary_RejectsRegressions(t *testing.T) {
	for name, source := range map[string]string{
		"logging":            `package alpnpeek; import "log"`,
		"application import": `package alpnpeek; import "github.com/KidCarmi/Culvert/internal/obs"`,
		"package state":      "package alpnpeek; var seen = map[string]int{}",
		"implicit lifecycle": "package alpnpeek; func init() {}",
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations("regression.go", []byte(source))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
}
