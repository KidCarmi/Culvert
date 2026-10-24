package hashcache

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// packageLevelVars returns "file:line name" for every package-level var
// declared in src.
func packageLevelVars(t *testing.T, fset *token.FileSet, name string, src any) []string {
	t.Helper()
	f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	var out []string
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			for _, id := range spec.(*ast.ValueSpec).Names {
				out = append(out, fset.Position(id.Pos()).String()+" "+id.Name)
			}
		}
	}
	return out
}

// TestBenchFiles_NoPackageLevelVars walls the benchmark harness against
// cross-benchmark shared state. A package-level fixture (an earlier memoized
// key table kept ~80 MB alive for the rest of `-bench .`) skews GC pacing for
// every later benchmark, including the pointer-versus-value layout A/B
// (Codex, PR #1604). Constants are fine; vars, including sync.Once, sync.Map
// and caches, are not. Each benchmark builds its own state and lets it die
// when it returns.
func TestBenchFiles_NoPackageLevelVars(t *testing.T) {
	// Not vacuous: the checker must flag a var when one is present.
	fset := token.NewFileSet()
	if got := packageLevelVars(t, fset, "synthetic_test.go", "package x\nvar cache = map[string][]string{}\nconst ok = 1\n"); len(got) != 1 {
		t.Fatalf("wall checker is vacuous: flagged %v for a file with exactly one package-level var", got)
	}

	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	sawBench := false
	for _, name := range files {
		if strings.HasSuffix(name, "_bench_test.go") {
			sawBench = true
		}
		// src nil: the parser reads the file itself (a Glob result in this
		// package's own directory).
		for _, v := range packageLevelVars(t, fset, name, nil) {
			t.Errorf("package-level var in a test file: %s — benchmarks must not share fixture state across runs; build it inside the benchmark", v)
		}
	}
	if !sawBench {
		t.Fatal("no *_bench_test.go file found; the wall is checking nothing")
	}
}
