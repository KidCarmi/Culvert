package qualarchive

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

const culvertModule = "github.com/KidCarmi/Culvert"

// allowedCulvertImports is the whole Culvert dependency set (ADR-0056): the
// durable-write primitive and the leaf event model.
var allowedCulvertImports = map[string]bool{
	culvertModule + "/internal/fileutil":         true,
	culvertModule + "/internal/mcp/events/model": true,
}

// boundaryViolations reports what one production source file does that the
// boundary forbids: a Culvert import outside the allowed set (so no root
// package, no events manager or spool, no runtime), a logging, formatting or
// network import, a package-level variable, an init func, or a goroutine.
func boundaryViolations(name string, source []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return []string{err.Error()}
	}
	var v []string
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if strings.HasPrefix(p, culvertModule) && !allowedCulvertImports[p] {
			v = append(v, "dependency: "+p)
		}
		if p == "log" || p == "log/slog" || p == "fmt" || p == "sync/atomic" || strings.HasPrefix(p, "net") {
			v = append(v, "logging, formatting, network or lock-free-state import: "+p)
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
		if _, ok := n.(*ast.GoStmt); ok {
			v = append(v, "starts a goroutine")
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

func TestQualArchiveBoundary_NoAppImportsOrSharedState(t *testing.T) {
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
		t.Fatalf("inspected %d production files, want doc.go and archive.go", checked)
	}
	want := "CursorStore Exporter NewCursorStore NewExporter PartitionName Stats"
	sortStrings(exported)
	if got := strings.Join(exported, " "); got != want {
		t.Fatalf("exported surface = %q, want %q (ADR-0056)", got, want)
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func TestQualArchiveBoundary_RejectsRegressions(t *testing.T) {
	for name, src := range map[string]string{
		"root import":      `package qualarchive; import "github.com/KidCarmi/Culvert"`,
		"observability":    `package qualarchive; import "github.com/KidCarmi/Culvert/internal/obs"`,
		"events manager":   `package qualarchive; import "github.com/KidCarmi/Culvert/internal/mcp/events"`,
		"spool":            `package qualarchive; import "github.com/KidCarmi/Culvert/internal/mcp/events/spool"`,
		"export pump":      `package qualarchive; import "github.com/KidCarmi/Culvert/internal/mcp/events/export"`,
		"runtime":          `package qualarchive; import "github.com/KidCarmi/Culvert/internal/mcp/runtime"`,
		"logging":          `package qualarchive; import "log"`,
		"structured log":   `package qualarchive; import "log/slog"`,
		"formatted output": `package qualarchive; import "fmt"`,
		"network":          `package qualarchive; import "net/http"`,
		"atomics":          `package qualarchive; import "sync/atomic"`,
		"package state":    "package qualarchive; var last *Exporter",
		"init":             "package qualarchive; func init() {}",
		"goroutine":        "package qualarchive; func f() { go f() }",
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations("r.go", []byte(src))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
	// The allowed set is accepted, so the checker is not rejecting everything.
	ok := `package qualarchive; import ("os"; "sync"; "time"; "github.com/KidCarmi/Culvert/internal/fileutil"); const c = 1`
	if got := boundaryViolations("ok.go", []byte(ok)); len(got) != 0 {
		t.Fatalf("boundary rejected an allowed file: %v", got)
	}
	names, err := exportedTopLevel([]byte("package qualarchive; type A int; const B, C = 1, 2; func D() {}; func e() {}; var F int"))
	if err != nil || len(names) != 5 {
		t.Fatalf("export counter miscounted a deliberate 5-name surface: %v %v", names, err)
	}
}
