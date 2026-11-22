package writerlock

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Boundary (ADR-0060): the lock is a leaf over the filesystem. It imports
// errors, os, path/filepath and golang.org/x/sys/unix and nothing else: no
// application or sibling package, no logger, no clock, no environment-policy
// helper. It has no package-level variable and no init func, and it does not
// read the environment (the override is main's decision). Changing one of
// these requires revisiting the ADR.
var allowedImports = map[string]bool{
	"errors":                true,
	"os":                    true,
	"path/filepath":         true,
	"golang.org/x/sys/unix": true,
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
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok && x.Name == "os" {
			switch sel.Sel.Name {
			case "Getenv", "LookupEnv", "Environ", "Exit", "Remove", "RemoveAll", "Rename":
				v = append(v, "os."+sel.Sel.Name)
			}
		}
		return true
	})
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

func TestWriterLockBoundary_NoAppImportsOrSharedState(t *testing.T) {
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
	if checked != 4 {
		t.Fatalf("inspected %d production files, want doc.go, lock.go and the two flock files", checked)
	}
	if len(exported) != 8 {
		t.Fatalf("exported surface is %d names, want FileName, Verdict, Acquired, Held, Undetermined, Lock, Attempt, Take: %v", len(exported), exported)
	}
}

func TestWriterLockBoundary_RejectsRegressions(t *testing.T) {
	for name, src := range map[string]string{
		"root import":        `package writerlock; import "github.com/KidCarmi/Culvert"`,
		"sibling import":     `package writerlock; import "github.com/KidCarmi/Culvert/internal/storeguard"`,
		"logging":            `package writerlock; import "log"`,
		"clock":              `package writerlock; import "time"`,
		"sync":               `package writerlock; import "sync"`,
		"atomics":            `package writerlock; import "sync/atomic"`,
		"retained handle":    `package writerlock; import "os"; var held *os.File`,
		"shared instance":    "package writerlock; var Default = Take(\"/data\")",
		"implicit lifecycle": "package writerlock; func init() {}",
		"override in engine": `package writerlock; import "os"; func allow() bool { return os.Getenv("CULVERT_ALLOW_MULTIPLE_WRITERS") == "1" }`,
		"exits the process":  `package writerlock; import "os"; func refuse() { os.Exit(1) }`,
		"removes the file":   `package writerlock; import "os"; func clean(p string) { _ = os.Remove(p) }`,
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations("r.go", []byte(src))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
	ok := `package writerlock; import ("errors"; "os"; "path/filepath"; "golang.org/x/sys/unix"); func f() error { _, _ = os.OpenFile(filepath.Join("a", "b"), unix.O_RDWR, 0o600); return errors.New("x") }`
	if got := boundaryViolations("ok.go", []byte(ok)); len(got) != 0 {
		t.Fatalf("the allowed imports were rejected: %v", got)
	}
	names, err := exportedTopLevel([]byte("package writerlock; type A int; const B, C = 1, 2; func D() {}; var E int; func (A) M() {}"))
	if err != nil || len(names) != 5 {
		t.Fatalf("export counter missed a deliberate 5-name surface: %v %v", names, err)
	}
}
