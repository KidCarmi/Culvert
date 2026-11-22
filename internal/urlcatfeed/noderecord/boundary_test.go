package noderecord

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Boundary (ADR-0053, ADR-0059): the only Culvert import is the feed protocol whose
// canonical encoder the records bind; no I/O, logging or shared-state import,
// no package-level variable, no init(), and at most 8 exported package-level
// identifiers.
var allowedImports = map[string]bool{
	"github.com/KidCarmi/Culvert/internal/urlcatfeed": true,
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
		if p == "log" || p == "os" || p == "io" || p == "sync" || p == "time" || p == "unsafe" ||
			strings.HasPrefix(p, "net") || strings.HasPrefix(p, "log/") || strings.HasPrefix(p, "sync/") ||
			strings.HasPrefix(p, "path") {
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

func TestNodeRecordBoundary_NoAppImportsOrSharedState(t *testing.T) {
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
	if checked < 3 {
		t.Fatalf("inspected %d production files, want decode.go, doc.go and record.go", checked)
	}
	if len(exported) != 6 {
		t.Fatalf("exported surface is %d names, want Canonical, Checksum, Decode, Envelope, Seal, ValidChecksum: %v", len(exported), exported)
	}
}

func TestNodeRecordBoundary_RejectsRegressions(t *testing.T) {
	for name, src := range map[string]string{
		"root import":    `package noderecord; import "github.com/KidCarmi/Culvert"`,
		"sibling import": `package noderecord; import "github.com/KidCarmi/Culvert/internal/fileutil"`,
		"filesystem":     `package noderecord; import "os"`,
		"paths":          `package noderecord; import "path/filepath"`,
		"network":        `package noderecord; import "net/http"`,
		"logging":        `package noderecord; import "log"`,
		"clock":          `package noderecord; import "time"`,
		"shared state":   `package noderecord; import "sync"`,
		"atomics":        `package noderecord; import "sync/atomic"`,
		"package state":  `package noderecord; import "hash/crc32"; var table = crc32.MakeTable(crc32.Castagnoli)`,
		"init":           "package noderecord; func init() {}",
		// The tempting ones for a decoder: package-level sentinels (each record
		// kind's owner supplies its own) and a reader-based API.
		"shared sentinel": `package noderecord; import "errors"; var ErrEmpty = errors.New("empty")`,
		"reader":          `package noderecord; import "io"; func DecodeFrom(io.Reader) {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations("r.go", []byte(src))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
	// The protocol import the package is allowed is not flagged.
	if got := boundaryViolations("ok.go", []byte(`package noderecord; import "github.com/KidCarmi/Culvert/internal/urlcatfeed"`)); len(got) != 0 {
		t.Fatalf("the allowed protocol import was rejected: %v", got)
	}
	names, err := exportedTopLevel([]byte("package noderecord; type A int; const B, C = 1, 2; func D() {}; var E int"))
	if err != nil || len(names) != 5 {
		t.Fatalf("export counter missed a deliberate 5-name surface: %v %v", names, err)
	}
}
