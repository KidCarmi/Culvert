package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestWall_RosterFactsStayInTheirRenderers pins Codex P2 4327431906 on PR
// #1601 by TYPE, not by name or call: rosterDurabilityFacts carries
// admin-only roster state, and the earlier walls (operator_contract_wall_test)
// follow calls and names, so a helper that RECEIVED a facts value — as a
// parameter, through an `any`, or as a local copy — and rendered a field of
// it escaped them. This wall type-checks the package's production files with
// go/types (standard library; imports are stubbed, which leaves every local
// type intact) and fails on any use of a facts value outside the classified
// renderers:
//
//   - a parameter, result or receiver of a facts type;
//   - a variable of a facts type;
//   - a field read of a facts value;
//   - a facts value passed as an argument, converted, assigned, returned or
//     stored anywhere (an `any` parameter and fmt.Sprint(facts) included).
//
// The only use allowed outside them is calling one of the type's own methods
// on a facts value (readRosterDurabilityFacts().adminRow()). The allowed
// functions are the type's methods, its one producer, and the one builder.
//
// The alternative, making the facts unforgeable behind an internal owner
// package, would move the renderers and every message, the contract row type
// and the redaction constant out of package main for a type whose whole
// surface is these few functions; checking the type here is the smaller
// change and the compiler-grade evidence (go/types resolves every
// expression's type, so renaming or aliasing does not evade it).

const rosterFactsTypeName = "rosterDurabilityFacts"

// rosterFactsAllowed are the functions outside the type's own methods that may
// hold a facts value: its producer and the contract builder that reads it once.
var rosterFactsAllowed = map[string]bool{"readRosterDurabilityFacts": true, "buildOperatorContract": true}

// stubImporter gives every import an empty, complete package: go/types then
// reports (and the wall ignores) unresolved imported names, while every type
// declared in this package is still resolved exactly.
type stubImporter struct{}

func (stubImporter) Import(path string) (*types.Package, error) {
	name := path[strings.LastIndex(path, "/")+1:]
	if i := strings.IndexAny(name, ".-"); i >= 0 {
		name = name[:i]
	}
	pkg := types.NewPackage(path, name)
	pkg.MarkComplete()
	return pkg, nil
}

// rosterFactsWallPackage type-checks the root package's production files
// (extra adds or overrides files, for negative controls).
func rosterFactsWallPackage(t *testing.T, extra map[string]string) (*token.FileSet, []*ast.File, *types.Info, *types.Named) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(pkgSourceDir(), "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	seen := map[string]bool{}
	parse := func(name string, src any) {
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	for _, p := range paths {
		name := filepath.Base(p)
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		seen[name] = true
		if src, ok := extra[name]; ok {
			parse(name, src)
			continue
		}
		parse(p, nil)
	}
	for name, src := range extra {
		if !seen[name] {
			parse(name, src)
		}
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	conf := types.Config{Importer: stubImporter{}, Error: func(error) {}, FakeImportC: true}
	pkg, _ := conf.Check("github.com/KidCarmi/Culvert", fset, files, info) // errors: stubbed imports
	obj, ok := pkg.Scope().Lookup(rosterFactsTypeName).(*types.TypeName)
	if !ok {
		t.Fatalf("type %s not found: renamed without updating the wall", rosterFactsTypeName)
	}
	named, ok := obj.Type().(*types.Named)
	if !ok {
		t.Fatalf("%s is not a named type", rosterFactsTypeName)
	}
	return fset, files, info, named
}

// holdsFacts reports whether t is, or is built from (pointer, slice, array,
// map, channel, struct field, function signature), the facts type.
func holdsFacts(t types.Type, facts *types.Named, depth int) bool {
	if t == nil || depth > 8 {
		return false
	}
	if types.Identical(t, facts) {
		return true
	}
	switch x := t.(type) {
	case *types.Pointer:
		return holdsFacts(x.Elem(), facts, depth+1)
	case *types.Slice:
		return holdsFacts(x.Elem(), facts, depth+1)
	case *types.Array:
		return holdsFacts(x.Elem(), facts, depth+1)
	case *types.Map:
		return holdsFacts(x.Key(), facts, depth+1) || holdsFacts(x.Elem(), facts, depth+1)
	case *types.Chan:
		return holdsFacts(x.Elem(), facts, depth+1)
	case *types.Struct:
		for i := 0; i < x.NumFields(); i++ {
			if holdsFacts(x.Field(i).Type(), facts, depth+1) {
				return true
			}
		}
	case *types.Signature:
		return holdsFacts(x.Params(), facts, depth+1) || holdsFacts(x.Results(), facts, depth+1)
	case *types.Tuple:
		for i := 0; i < x.Len(); i++ {
			if holdsFacts(x.At(i).Type(), facts, depth+1) {
				return true
			}
		}
	}
	return false
}

func isSignature(t types.Type) bool {
	_, ok := t.Underlying().(*types.Signature)
	return ok
}

// factsReceiverSelectors maps every expression that is the receiver of a
// method-value call on the facts type to true.
func factsReceiverSelectors(files []*ast.File, info *types.Info, facts *types.Named) map[ast.Expr]bool {
	out := map[ast.Expr]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fun := call.Fun
			for {
				if p, ok := fun.(*ast.ParenExpr); ok {
					fun = p.X
					continue
				}
				break
			}
			sel, ok := fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if s := info.Selections[sel]; s != nil && s.Kind() == types.MethodVal && holdsFacts(s.Recv(), facts, 0) {
				out[sel.X] = true
			}
			return true
		})
	}
	return out
}

// rosterFactsOwner names the function a node belongs to, and whether it may
// hold facts.
func rosterFactsOwner(fd *ast.FuncDecl, info *types.Info, facts *types.Named) (name string, allowed bool) {
	name = fd.Name.Name
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		if tv, ok := info.Types[fd.Recv.List[0].Type]; ok && holdsFacts(tv.Type, facts, 0) {
			return rosterFactsTypeName + "." + name, true
		}
		return "(method) " + name, false
	}
	return name, rosterFactsAllowed[name]
}

// rosterFactsScan accumulates the wall's findings over the package.
type rosterFactsScan struct {
	fset        *token.FileSet
	info        *types.Info
	facts       *types.Named
	receivers   map[ast.Expr]bool
	violations  []string
	allowedUses int
}

func (sc *rosterFactsScan) add(owner string, n ast.Node, what string) {
	p := sc.fset.Position(n.Pos())
	sc.violations = append(sc.violations, fmt.Sprintf("%s:%d:%d: %s %s", filepath.Base(p.Filename), p.Line,
		p.Column, owner, what))
}

// definesFactsVar reports whether id declares a variable holding facts.
func (sc *rosterFactsScan) definesFactsVar(id *ast.Ident) bool {
	obj := sc.info.Defs[id]
	if obj == nil {
		return false
	}
	_, isVar := obj.(*types.Var)
	return isVar && holdsFacts(obj.Type(), sc.facts, 0)
}

// finding is what node n does with a facts value, or "".
func (sc *rosterFactsScan) finding(n ast.Node) string {
	switch x := n.(type) {
	case *ast.Ident:
		if sc.definesFactsVar(x) {
			return "declares " + x.Name + " holding " + rosterFactsTypeName
		}
	case *ast.SelectorExpr:
		if s := sc.info.Selections[x]; s != nil && s.Kind() == types.FieldVal && holdsFacts(s.Recv(), sc.facts, 0) {
			return "reads field " + x.Sel.Name + " of " + rosterFactsTypeName
		}
	}
	return ""
}

// valueFinding reports a facts value used other than as the receiver of one
// of its own methods. A function value (the producer named in a call) is not
// a facts value; what calling it returns is checked as one.
func (sc *rosterFactsScan) valueFinding(n ast.Node) string {
	e, ok := n.(ast.Expr)
	if !ok || sc.receivers[e] {
		return ""
	}
	tv, ok := sc.info.Types[e]
	if !ok || !tv.IsValue() || isSignature(tv.Type) || !holdsFacts(tv.Type, sc.facts, 0) {
		return ""
	}
	return "uses a " + rosterFactsTypeName + " value other than to call its methods"
}

// scanPackageDecl flags a facts-typed package-level variable.
func (sc *rosterFactsScan) scanPackageDecl(decl ast.Decl) {
	ast.Inspect(decl, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && sc.definesFactsVar(id) {
			sc.add("package scope", id, "declares "+id.Name+" holding "+rosterFactsTypeName)
		}
		return true
	})
}

// scanFunc flags every use of a facts value in fd unless fd may hold one.
func (sc *rosterFactsScan) scanFunc(fd *ast.FuncDecl) {
	owner, allowed := rosterFactsOwner(fd, sc.info, sc.facts)
	note := func(n ast.Node, what string) {
		if what == "" {
			return
		}
		if allowed {
			sc.allowedUses++
			return
		}
		sc.add(owner, n, what)
	}
	if obj := sc.info.Defs[fd.Name]; obj != nil && holdsFacts(obj.Type(), sc.facts, 0) {
		note(fd.Name, "has a parameter or result holding "+rosterFactsTypeName)
	}
	if fd.Body == nil {
		return
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		note(n, sc.finding(n))
		note(n, sc.valueFinding(n))
		return true
	})
}

// rosterFactsViolations reports every use of a facts value outside the
// allowed functions, and how many uses the allowed functions make.
func rosterFactsViolations(fset *token.FileSet, files []*ast.File, info *types.Info, facts *types.Named) (violations []string, allowedUses int) {
	sc := &rosterFactsScan{fset: fset, info: info, facts: facts, receivers: factsReceiverSelectors(files, info, facts)}
	for _, f := range files {
		for _, decl := range f.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok {
				sc.scanFunc(fd)
			} else {
				sc.scanPackageDecl(decl)
			}
		}
	}
	sort.Strings(sc.violations)
	return sc.violations, sc.allowedUses
}

func TestWall_RosterFactsStayInTheirRenderers(t *testing.T) {
	fset, files, info, facts := rosterFactsWallPackage(t, nil)
	violations, allowedUses := rosterFactsViolations(fset, files, info, facts)
	for _, v := range violations {
		t.Error(v)
	}
	// Not vacuous: the renderers and the producer do use facts values, so
	// the type resolution and the scan really see them.
	if allowedUses == 0 {
		t.Fatal("no use of a facts value found anywhere: the scan is resolving nothing")
	}

	// Negative controls: each fixture must fail the wall.
	const hdr = "package main\n\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n\n"
	for name, tc := range map[string]struct{ src, want string }{
		"a helper taking the facts, called from a reachable function": {
			src: hdr + "func fixtureFactsHelper(f rosterDurabilityFacts) string { return fmt.Sprint(f.refused) }\n\n" +
				"func fixtureFactsCaller() string { return fixtureFactsHelper(readRosterDurabilityFacts()) }\n",
			want: "fixtureFactsHelper has a parameter or result holding",
		},
		"the helper's field read": {
			src:  hdr + "func fixtureFactsHelper(f rosterDurabilityFacts) string { return fmt.Sprint(f.refused) }\n",
			want: "fixtureFactsHelper reads field refused",
		},
		"passing the facts as an argument": {
			src: hdr + "func fixtureFactsHelper(f rosterDurabilityFacts) string { return fmt.Sprint(f.refused) }\n\n" +
				"func fixtureFactsCaller() string { return fixtureFactsHelper(readRosterDurabilityFacts()) }\n",
			want: "fixtureFactsCaller uses a rosterDurabilityFacts value",
		},
		"a helper taking any that receives the facts": {
			src: hdr + "func fixtureAnyHelper(v any) string { return fmt.Sprint(v) }\n\n" +
				"func fixtureAnyCaller() string { return fixtureAnyHelper(readRosterDurabilityFacts()) }\n",
			want: "fixtureAnyCaller uses a rosterDurabilityFacts value",
		},
		"fmt.Sprint of the facts": {
			src:  hdr + "func fixtureSprint() string { return fmt.Sprint(readRosterDurabilityFacts()) }\n",
			want: "fixtureSprint uses a rosterDurabilityFacts value",
		},
		"a local copy outside the renderers": {
			src:  hdr + "func fixtureCopy() int64 {\n\tfacts := readRosterDurabilityFacts()\n\tg := facts\n\treturn g.degraded\n}\n",
			want: "fixtureCopy reads field degraded",
		},
		"a facts-typed global": {
			src:  hdr + "var fixtureLeaked []rosterDurabilityFacts\n",
			want: "package scope declares fixtureLeaked",
		},
		"a variable holding the producer": {
			src:  hdr + "func fixtureProducerVar() { get := readRosterDurabilityFacts\n\t_ = get\n}\n",
			want: "fixtureProducerVar declares get holding",
		},
		"a facts pointer in a closure": {
			src: hdr + "func fixtureClosure() func() int64 {\n\tf := readRosterDurabilityFacts()\n" +
				"\treturn func() int64 { p := &f; return p.refused }\n}\n",
			want: "fixtureClosure reads field refused",
		},
	} {
		fset, files, info, facts := rosterFactsWallPackage(t, map[string]string{"zz_fixture_facts.go": tc.src})
		v, _ := rosterFactsViolations(fset, files, info, facts)
		found := false
		for _, s := range v {
			if strings.Contains(s, tc.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: passed the wall; want a violation containing %q, got %q", name, tc.want, v)
		}
	}

	// Precision control: calling the facts' own methods outside the
	// renderers is what checkAdminRosterDurability-style callers do, and it
	// is allowed.
	ok := hdr + "func fixtureMethodCall() OperatorContractCheck { return readRosterDurabilityFacts().adminRow() }\n"
	fset, files, info, facts = rosterFactsWallPackage(t, map[string]string{"zz_fixture_facts.go": ok})
	if v, _ := rosterFactsViolations(fset, files, info, facts); len(v) != 0 {
		t.Errorf("calling a facts method outside the renderers was flagged: %q", v)
	}
	if _, err := os.Stat(filepath.Join(pkgSourceDir(), "zz_fixture_facts.go")); err == nil {
		t.Fatal("a fixture file exists on disk; the controls must be in memory only")
	}
}
