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
// or build a timer, so it cannot become the supervisor.
//
// The rules are written as what the package MAY contain, so that a capability
// cannot arrive in a form the list did not think of:
//
//   - a named type must be a struct, and every field of it a time.Duration
//     (no function, interface, pointer, map, slice or channel field through
//     which a clock, a logger or shared state could be handed in);
//   - no function type anywhere except a declaration's own signature (no
//     function-typed parameter or result, no named function type, no function
//     literal), and no interface type;
//   - no pointer, so no pointer receiver and no state reached through one;
//   - no package-level variable, no init(), no goroutine, no channel, and no
//     call of the print or println builtins;
//   - at most 8 exported package-level identifiers.
//
// The package has no constructor: a Ladder or a Clamp is a value of two
// durations. "Independently constructible instances cannot leak state into one
// another" follows from the rules above, and
// TestIndependentValues_ConcurrentCallersAgree runs it.

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
	// A declaration's own signature is a function type; every other function
	// type in the file is a capability.
	signatures := map[*ast.FuncType]bool{}
	for _, decl := range f.Decls {
		v = append(v, declViolations(decl)...)
		if fn, ok := decl.(*ast.FuncDecl); ok {
			signatures[fn.Type] = true
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		v = append(v, nodeViolations(n, timeName, signatures)...)
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

// declViolations reports init() and a package variable.
func declViolations(decl ast.Decl) []string {
	var v []string
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Recv == nil && d.Name.Name == "init" {
			v = append(v, "implicit initialization")
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

// nodeViolations reports what one syntax node breaks of the rules in the
// comment at the top of this file.
func nodeViolations(n ast.Node, timeName string, signatures map[*ast.FuncType]bool) []string {
	switch x := n.(type) {
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		if ok && timeName != "" && id.Name == timeName && id.Obj == nil && !allowedTimeNames[x.Sel.Name] {
			return []string{"clock, timer or sleep: time." + x.Sel.Name}
		}
	case *ast.TypeSpec:
		return typeSpecViolations(x, timeName)
	case *ast.FuncType:
		if !signatures[x] {
			return []string{"function type outside a declaration's signature"}
		}
	case *ast.InterfaceType:
		return []string{"interface type"}
	case *ast.StarExpr:
		// A pointer type or a dereference. Multiplication is a binary
		// expression or an assignment and is not this node.
		return []string{"pointer"}
	case *ast.GoStmt:
		return []string{"goroutine"}
	case *ast.ChanType:
		return []string{"channel"}
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok && (id.Name == "print" || id.Name == "println") {
			return []string{"output through builtin " + id.Name}
		}
	}
	return nil
}

// typeSpecViolations requires a named type to be a struct whose every field is
// a time.Duration.
func typeSpecViolations(spec *ast.TypeSpec, timeName string) []string {
	st, ok := spec.Type.(*ast.StructType)
	if !ok {
		return []string{"named type that is not a struct: " + spec.Name.Name}
	}
	var v []string
	for _, field := range st.Fields.List {
		if !isTimeDuration(field.Type, timeName) {
			v = append(v, "field that is not a time.Duration in "+spec.Name.Name)
		}
	}
	return v
}

func isTimeDuration(expr ast.Expr, timeName string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || timeName == "" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == timeName && sel.Sel.Name == "Duration"
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
	// Each control names the violation it must be refused FOR, so a control
	// cannot pass by tripping a different rule.
	for name, tc := range map[string]struct{ src, want string }{
		"root import":         {`package listenretry; import "github.com/KidCarmi/Culvert"`, "import: github.com/KidCarmi/Culvert"},
		"sibling import":      {`package listenretry; import "github.com/KidCarmi/Culvert/internal/listenfault"`, "import: github.com/KidCarmi/Culvert/internal/listenfault"},
		"logging":             {`package listenretry; import "log"`, "import: log"},
		"shared state":        {`package listenretry; import "sync"`, "import: sync"},
		"counter":             {`package listenretry; import "sync/atomic"`, "import: sync/atomic"},
		"cancellation":        {`package listenretry; import "context"`, "import: context"},
		"randomness":          {`package listenretry; import "math/rand/v2"`, "import: math/rand/v2"},
		"network":             {`package listenretry; import "net"`, "import: net"},
		"files":               {`package listenretry; import "os"`, "import: os"},
		"clock":               {`package listenretry; import "time"; func f() time.Duration { return time.Since(time.Now()) }`, "time.Now"},
		"sleep":               {`package listenretry; import "time"; func f(d time.Duration) { time.Sleep(d) }`, "time.Sleep"},
		"timer":               {`package listenretry; import "time"; func f(d time.Duration) { <-time.After(d) }`, "time.After"},
		"timer type":          {`package listenretry; import "time"; func f(t time.Timer) {}`, "time.Timer"},
		"renamed time":        {`package listenretry; import t "time"; func f(d t.Duration) { t.Sleep(d) }`, "renamed import of time: t"},
		"dot time":            {`package listenretry; import . "time"; func f(d Duration) { Sleep(d) }`, "renamed import of time: ."},
		"package state":       {`package listenretry; import "time"; var lastWait time.Duration`, "package state: lastWait"},
		"init":                {"package listenretry; func init() {}", "implicit initialization"},
		"pointer receiver":    {`package listenretry; import "time"; type L struct{ c time.Duration }; func (l *L) Next() { l.c *= 2 }`, "pointer"},
		"pointer field":       {`package listenretry; type L struct{ n *int64 }`, "pointer"},
		"map field":           {`package listenretry; type L struct{ seen map[int64]bool }`, "field that is not a time.Duration in L"},
		"plain integer field": {`package listenretry; type L struct{ n int64 }`, "field that is not a time.Duration in L"},
		"injected clock":      {`package listenretry; import "time"; type L struct{ now func() time.Duration }`, "function type outside a declaration's signature"},
		"named clock type":    {`package listenretry; import "time"; type Clock func() time.Duration`, "named type that is not a struct: Clock"},
		"clock interface":     {`package listenretry; type L struct{ c interface{ Now() int64 } }`, "interface type"},
		"named interface":     {`package listenretry; type Clock interface{ Now() int64 }`, "named type that is not a struct: Clock"},
		"injected callback":   {`package listenretry; import "time"; func f(sleep func(time.Duration)) {}`, "function type outside a declaration's signature"},
		"callback slice":      {`package listenretry; func f(hooks []func()) {}`, "function type outside a declaration's signature"},
		"variadic callbacks":  {`package listenretry; func f(hooks ...func()) {}`, "function type outside a declaration's signature"},
		"function literal":    {`package listenretry; func f() { g := func() {}; g() }`, "function type outside a declaration's signature"},
		"goroutine":           {"package listenretry; func f() { go f() }", "goroutine"},
		"channel":             {"package listenretry; func f(stop chan struct{}) {}", "channel"},
		"builtin output":      {`package listenretry; func f() { println("retry") }`, "output through builtin println"},
	} {
		t.Run(name, func(t *testing.T) {
			got := boundaryViolations("r.go", []byte(tc.src))
			for _, violation := range got {
				if strings.Contains(violation, tc.want) {
					return
				}
			}
			t.Fatalf("boundary did not refuse it for %q; violations: %v", tc.want, got)
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
