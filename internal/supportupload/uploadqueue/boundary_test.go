package uploadqueue

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Boundary (ADR-0062): the queue is an engine over files in a directory its
// owner names. It imports the standard library and its parent package (for
// Receipt and GatewayError) and nothing else: no application package, no
// logger, no durable-write helper, no id rule, no network. Its only
// package-level variables are error values. It has no init, starts no
// goroutine, reads no environment and reads the clock nowhere (every time is
// an argument). Changing one of these requires revisiting the ADR.
var allowedImports = map[string]bool{
	"context":       true,
	"encoding/json": true,
	"errors":        true,
	"os":            true,
	"path/filepath": true,
	"sort":          true,
	"strings":       true,
	"sync":          true,
	"time":          true,
	"github.com/KidCarmi/Culvert/internal/supportupload": true,
}

// isErrorValue reports whether a var spec is `name = errors.New("...")`.
func isErrorValue(vs *ast.ValueSpec) bool {
	if len(vs.Names) != 1 || len(vs.Values) != 1 || vs.Names[0].IsExported() {
		return false
	}
	call, ok := vs.Values[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "New" {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == "errors"
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
				vs := s.(*ast.ValueSpec)
				if isErrorValue(vs) {
					continue
				}
				for _, n := range vs.Names {
					v = append(v, "package state: "+n.Name)
				}
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.GoStmt:
			v = append(v, "starts a goroutine")
		case *ast.SelectorExpr:
			if pkg, ok := x.X.(*ast.Ident); ok && refusedSelector(pkg.Name, x.Sel.Name) {
				v = append(v, pkg.Name+"."+x.Sel.Name)
			}
		}
		return true
	})
	return v
}

// refusedCalls are the standard-library names the engine must not use. Time
// is always an argument. Writes and directory creation go through Options, so
// they reach the owner's durable-write chokepoint; os.Remove of one pruned
// entry and the two reads are the engine's.
var refusedCalls = map[string]map[string]bool{
	"time": {"Now": true, "Since": true, "Sleep": true, "After": true, "NewTimer": true, "NewTicker": true},
	"os": {
		"Getenv": true, "LookupEnv": true, "Environ": true, "Exit": true, "WriteFile": true, "Rename": true,
		"Create": true, "OpenFile": true, "MkdirAll": true, "Mkdir": true, "RemoveAll": true,
	},
}

// refusedSelector reports whether pkg.name is outside the boundary. From the
// parent package only the two types the queue records and classifies are used.
func refusedSelector(pkg, name string) bool {
	if pkg == "supportupload" {
		return name != "Receipt" && name != "GatewayError"
	}
	return refusedCalls[pkg][name]
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

func TestUploadQueueBoundary_NoAppImportsOrSharedState(t *testing.T) {
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
	if checked != 2 {
		t.Fatalf("inspected %d production files, want doc.go and queue.go", checked)
	}
	// Ten names: five are the values of one persisted vocabulary (ADR-0062
	// records why that is over the program's eight).
	if len(exported) != 10 {
		t.Fatalf("exported surface is %d names, want Queue, New, Options, Entry, State and its five values: %v", len(exported), exported)
	}
}

func TestUploadQueueBoundary_RejectsRegressions(t *testing.T) {
	for name, src := range map[string]string{
		"root import":             `package uploadqueue; import "github.com/KidCarmi/Culvert"`,
		"sibling import":          `package uploadqueue; import "github.com/KidCarmi/Culvert/internal/fileutil"`,
		"support import":          `package uploadqueue; import "github.com/KidCarmi/Culvert/internal/support"`,
		"logging":                 `package uploadqueue; import "log"`,
		"network":                 `package uploadqueue; import "net/http"`,
		"own id rule":             `package uploadqueue; import "regexp"`,
		"atomics":                 `package uploadqueue; import "sync/atomic"`,
		"shared instance":         `package uploadqueue; var Default = New(Options{})`,
		"shared lock":             `package uploadqueue; import "sync"; var mu sync.Mutex`,
		"mutable bound":           `package uploadqueue; var maxPending = 256`,
		"exported error value":    `package uploadqueue; import "errors"; var ErrFull = errors.New("full")`,
		"implicit lifecycle":      `package uploadqueue; func init() {}`,
		"background loop":         `package uploadqueue; func (q *Queue) run() { go func() {}() }`,
		"reads the clock":         `package uploadqueue; import "time"; func now() time.Time { return time.Now() }`,
		"sleeps":                  `package uploadqueue; import "time"; func wait() { time.Sleep(time.Second) }`,
		"reads the environment":   `package uploadqueue; import "os"; func dir() string { return os.Getenv("CULVERT_DATA_DIR") }`,
		"writes past the option":  `package uploadqueue; import "os"; func save(p string, b []byte) error { return os.WriteFile(p, b, 0o600) }`,
		"renames past the option": `package uploadqueue; import "os"; func save(a, b string) error { return os.Rename(a, b) }`,
		"mkdir past the option":   `package uploadqueue; import "os"; func mk(d string) error { return os.MkdirAll(d, 0o700) }`,
		"removes a tree":          `package uploadqueue; import "os"; func wipe(d string) error { return os.RemoveAll(d) }`,
		"builds the client":       `package uploadqueue; import "github.com/KidCarmi/Culvert/internal/supportupload"; func c() { _, _ = supportupload.NewClient(supportupload.Config{}) }`,
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations("r.go", []byte(src))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
	ok := `package uploadqueue
import ("errors"; "os"; "time"; "github.com/KidCarmi/Culvert/internal/supportupload")
var errX = errors.New("x")
func f(p string, now time.Time) (*supportupload.Receipt, error) {
	_, _ = os.ReadFile(p); _, _ = os.ReadDir(p); _ = os.Remove(p)
	var ge *supportupload.GatewayError
	_ = errors.As(errX, &ge)
	_ = now.Add(time.Second).Unix()
	return nil, errX
}`
	if got := boundaryViolations("ok.go", []byte(ok)); len(got) != 0 {
		t.Fatalf("the allowed shape was rejected: %v", got)
	}
	names, err := exportedTopLevel([]byte("package uploadqueue; type A int; const B, C = 1, 2; func D() {}; var E int; func (A) M() {}"))
	if err != nil || len(names) != 5 {
		t.Fatalf("export counter missed a deliberate 5-name surface: %v %v", names, err)
	}
}
