package listenretry

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Boundary (ADR-0064): no Culvert import at all; the only import is "time",
// and from it only the Duration type. The package may not read a clock, sleep
// or build a timer, so it cannot become the supervisor. No package-level
// variable, no init(), no function-typed field or parameter through which a
// caller could hand it a clock or a logger, and at most 8 exported
// package-level identifiers.
//
// The package has no constructor: a Ladder or a Clamp is a value of two
// durations. "Independently constructible instances cannot leak state into one
// another" is enforced by there being no package variable and no pointer
// receiver, and run by TestIndependentValues_ConcurrentCallersAgree.

// allowedImports is the whole import list the package may have.
var allowedImports = map[string]bool{"time": true}

// allowedTimeNames are the only names the package may take from "time".
var allowedTimeNames = map[string]bool{"Duration": true}

func boundaryViolations(name string, source []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return []string{err.Error()}
	}
	v, timeName := importViolations(f)
	for _, decl := range f.Decls {
		v = append(v, declViolations(decl)...)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		v = append(v, nodeViolations(n, timeName)...)
		return true
	})
	return v
}

// importViolations reports every import outside allowedImports and returns the
// name under which "time" is visible in the file ("" when it is not imported).
func importViolations(f *ast.File) (v []string, timeName string) {
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if !allowedImports[p] {
			v = append(v, "import: "+p)
			continue
		}
		timeName = "time"
		if imp.Name != nil {
			// A renamed or dot import would let a clock call pass the
			// selector check under another name.
			v = append(v, "renamed import of "+p+": "+imp.Name.Name)
			timeName = imp.Name.Name
		}
	}
	return v, timeName
}

// declViolations reports init(), a pointer receiver and a package variable.
func declViolations(decl ast.Decl) []string {
	var v []string
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Recv == nil && d.Name.Name == "init" {
			v = append(v, "implicit initialization")
		}
		if d.Recv != nil && len(d.Recv.List) == 1 {
			if _, ptr := d.Recv.List[0].Type.(*ast.StarExpr); ptr {
				v = append(v, "pointer receiver (a value that can be mutated through a call): "+d.Name.Name)
			}
		}
	case *ast.GenDecl:
		if d.Tok != token.VAR {
			break
		}
		for _, s := range d.Specs {
			for _, n := range s.(*ast.ValueSpec).Names {
				v = append(v, "package state: "+n.Name)
			}
		}
	}
	return v
}

// nodeViolations reports, for one syntax node: a name taken from "time" other
// than Duration, a function-typed field, parameter or result (a capability a
// caller could inject, such as a clock), a goroutine and a channel.
func nodeViolations(n ast.Node, timeName string) []string {
	var v []string
	switch x := n.(type) {
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		if ok && timeName != "" && id.Name == timeName && id.Obj == nil && !allowedTimeNames[x.Sel.Name] {
			v = append(v, "clock, timer or sleep: time."+x.Sel.Name)
		}
	case *ast.FuncType:
		// A declaration's own signature is a FuncType too; only a parameter
		// or result that is ITSELF of function type is reported.
		if hasFuncTypedField(x.Params) || hasFuncTypedField(x.Results) {
			v = append(v, "function-typed parameter or result")
		}
	case *ast.StructType:
		if hasFuncTypedField(x.Fields) {
			v = append(v, "function-typed field")
		}
	case *ast.GoStmt:
		v = append(v, "goroutine")
	case *ast.ChanType:
		v = append(v, "channel")
	}
	return v
}

func hasFuncTypedField(list *ast.FieldList) bool {
	if list == nil {
		return false
	}
	for _, field := range list.List {
		if _, isFunc := field.Type.(*ast.FuncType); isFunc {
			return true
		}
	}
	return false
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

func TestListenRetryBoundary_NoAppImportsClockOrSharedState(t *testing.T) {
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
		t.Fatalf("inspected %d production files, want doc.go and sleep.go", checked)
	}
	if len(exported) > 8 {
		t.Fatalf("exported surface grew to %d (>8): %v", len(exported), exported)
	}
	if len(exported) == 0 {
		t.Fatal("found no exported name: the export counter is not reading the package")
	}
}

func TestListenRetryBoundary_RejectsRegressions(t *testing.T) {
	for name, src := range map[string]string{
		"root import":       `package listenretry; import "github.com/KidCarmi/Culvert"`,
		"sibling import":    `package listenretry; import "github.com/KidCarmi/Culvert/internal/listenfault"`,
		"logging":           `package listenretry; import "log"`,
		"shared state":      `package listenretry; import "sync"`,
		"counter":           `package listenretry; import "sync/atomic"`,
		"cancellation":      `package listenretry; import "context"`,
		"randomness":        `package listenretry; import "math/rand/v2"`,
		"network":           `package listenretry; import "net"`,
		"files":             `package listenretry; import "os"`,
		"clock":             `package listenretry; import "time"; func f() time.Duration { return time.Since(time.Now()) }`,
		"sleep":             `package listenretry; import "time"; func f(d time.Duration) { time.Sleep(d) }`,
		"timer":             `package listenretry; import "time"; func f(d time.Duration) { <-time.After(d) }`,
		"timer type":        `package listenretry; import "time"; type w struct{ t *time.Timer }`,
		"renamed time":      `package listenretry; import t "time"; func f(d t.Duration) { t.Sleep(d) }`,
		"dot time":          `package listenretry; import . "time"; func f(d Duration) { Sleep(d) }`,
		"package state":     `package listenretry; import "time"; var lastWait time.Duration`,
		"init":              "package listenretry; func init() {}",
		"pointer receiver":  `package listenretry; import "time"; type L struct{ c time.Duration }; func (l *L) Next() { l.c *= 2 }`,
		"injected clock":    `package listenretry; import "time"; type L struct{ now func() time.Duration }`,
		"injected callback": `package listenretry; import "time"; func f(sleep func(time.Duration)) {}`,
		"goroutine":         "package listenretry; func f() { go f() }",
		"channel":           "package listenretry; func f(stop chan struct{}) {}",
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations("r.go", []byte(src))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
	// Controls: the shapes the package really has are accepted.
	for name, src := range map[string]string{
		"own shape": `package listenretry; import "time"
			type Ladder struct{ Initial, Ceiling time.Duration }
			func (l Ladder) Next(cur time.Duration) time.Duration { cur *= 2; return cur }`,
		"no import": "package listenretry",
	} {
		if got := boundaryViolations("ok.go", []byte(src)); len(got) != 0 {
			t.Fatalf("%s: boundary rejected the package's own shape: %v", name, got)
		}
	}
	names, err := exportedTopLevel([]byte("package listenretry; type A int; type B int; const C, D = 1, 2; func E() {}; var F, G, H, I int"))
	if err != nil || len(names) != 9 {
		t.Fatalf("export counter missed a deliberate 9-name surface: %v %v", names, err)
	}
}
