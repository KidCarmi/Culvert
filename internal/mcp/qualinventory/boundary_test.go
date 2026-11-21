package qualinventory

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

const culvertModule = "github.com/KidCarmi/Culvert"

// allowedCulvertImports is the whole Culvert dependency set (ADR-0055): the
// two engines a seed writes through, their limits and the capability enum.
var allowedCulvertImports = map[string]bool{
	culvertModule + "/internal/mcp/catalog":  true,
	culvertModule + "/internal/mcp/limits":   true,
	culvertModule + "/internal/mcp/protocol": true,
	culvertModule + "/internal/mcp/registry": true,
}

// boundaryViolations reports what one production source file does that the
// boundary forbids: a Culvert import outside the allowed set (so no root
// package, no execution/rollout/tooltrust authority), logging, networking,
// clocks or shared-state imports, a package-level variable, an init func, or
// any mention of the peer-observed ingest entrypoint.
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
		if p == "log" || p == "fmt" || p == "time" || p == "context" || strings.HasPrefix(p, "net") || strings.HasPrefix(p, "sync") {
			v = append(v, "logging, network, clock or shared-state import: "+p)
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
		if id, ok := n.(*ast.Ident); ok && id.Name == "IngestObserved" {
			v = append(v, "names the peer-observed ingest entrypoint")
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

func TestQualInventoryBoundary_NoAppImportsOrSharedState(t *testing.T) {
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
		t.Fatalf("inspected %d production files, want doc.go and inventory.go", checked)
	}
	want := "Decode Doc MaxFileBytes ReadFile Seed ServerEntry ToolEntry"
	sortStrings(exported)
	if got := strings.Join(exported, " "); got != want {
		t.Fatalf("exported surface = %q, want %q (ADR-0055)", got, want)
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func TestQualInventoryBoundary_RejectsRegressions(t *testing.T) {
	for name, src := range map[string]string{
		"root import":      `package qualinventory; import "github.com/KidCarmi/Culvert"`,
		"observability":    `package qualinventory; import "github.com/KidCarmi/Culvert/internal/obs"`,
		"execution":        `package qualinventory; import "github.com/KidCarmi/Culvert/internal/mcp/execution"`,
		"tool trust":       `package qualinventory; import "github.com/KidCarmi/Culvert/internal/mcp/tooltrust"`,
		"rollout":          `package qualinventory; import "github.com/KidCarmi/Culvert/internal/mcp/rollout"`,
		"logging":          `package qualinventory; import "log"`,
		"formatted output": `package qualinventory; import "fmt"`,
		"network":          `package qualinventory; import "net/http"`,
		"clock":            `package qualinventory; import "time"`,
		"shared state":     `package qualinventory; import "sync"`,
		"atomics":          `package qualinventory; import "sync/atomic"`,
		"package state":    "package qualinventory; var last *Doc",
		"init":             "package qualinventory; func init() {}",
		"observed ingest":  "package qualinventory; func f(c interface{ IngestObserved() }) { c.IngestObserved() }",
		"observed value":   "package qualinventory; func f(c interface{ IngestObserved() }) func() { return c.IngestObserved }",
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations("r.go", []byte(src))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
	// The allowed set is accepted, so the checker is not rejecting everything.
	ok := `package qualinventory; import ("os"; "encoding/json"; "github.com/KidCarmi/Culvert/internal/mcp/catalog"); const c = 1`
	if got := boundaryViolations("ok.go", []byte(ok)); len(got) != 0 {
		t.Fatalf("boundary rejected an allowed file: %v", got)
	}
	names, err := exportedTopLevel([]byte("package qualinventory; type A int; const B, C = 1, 2; func D() {}; func e() {}; var F int"))
	if err != nil || len(names) != 5 {
		t.Fatalf("export counter miscounted a deliberate 5-name surface: %v %v", names, err)
	}
}
