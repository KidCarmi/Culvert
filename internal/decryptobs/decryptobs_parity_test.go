package decryptobs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"
)

// AST reverse-parity — the real exhaustiveness guard (PR #758 red-team, drift-guard).
//
// pinEnum (decryptobs_test.go) pins each All<Type> slice against a hardcoded literal,
// but that is a forward check: it cannot detect a const that was DECLARED yet never
// added to its All<Type> slice (an orphan const whose Valid() would silently be false),
// nor a whole new enum type that ships with no pin at all. Those are exactly the human
// steps the "adding a value is a deliberate, tested change" claim relies on.
//
// This test closes both by parsing the package source (like the uiRoutes C1 source
// scan): it asserts, per enum type, that the set of declared consts EQUALS the set of
// members in its All<Type> slice, and that every All<Type> slice is exercised by a
// pinEnum call. A new const not registered in All<Type>, or a new enum type with no
// pin, fails here.

// enumSet is an All<Type> slice discovered in source: its element (enum) type and the
// set of const identifiers it lists.
type enumSet struct {
	elemType string
	members  map[string]bool
}

func mustParse(t *testing.T, name string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return f
}

// collectConsts maps each enum type name → set of declared const identifiers of that
// type. Every decryptobs const carries its explicit enum type, so vs.Type names it.
func collectConsts(f *ast.File) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, s := range gd.Specs {
			vs := s.(*ast.ValueSpec)
			typeIdent, ok := vs.Type.(*ast.Ident)
			if !ok {
				continue
			}
			if out[typeIdent.Name] == nil {
				out[typeIdent.Name] = map[string]bool{}
			}
			for _, n := range vs.Names {
				out[typeIdent.Name][n.Name] = true
			}
		}
	}
	return out
}

// allSliceMembers extracts the const identifiers listed in a `[]EnumType{...}` literal;
// ok is false when the value is not such a literal.
func allSliceMembers(t *testing.T, varName string, val ast.Expr) (enumSet, bool) {
	cl, ok := val.(*ast.CompositeLit)
	if !ok {
		return enumSet{}, false
	}
	at, ok := cl.Type.(*ast.ArrayType)
	if !ok {
		return enumSet{}, false
	}
	elem, ok := at.Elt.(*ast.Ident)
	if !ok {
		return enumSet{}, false
	}
	members := map[string]bool{}
	for _, e := range cl.Elts {
		id, ok := e.(*ast.Ident)
		if !ok {
			t.Errorf("var %s: element %T is not a bare const identifier", varName, e)
			continue
		}
		members[id.Name] = true
	}
	return enumSet{elemType: elem.Name, members: members}, true
}

// collectAllVars maps each All<Type> var name → its enumSet.
func collectAllVars(t *testing.T, f *ast.File) map[string]enumSet {
	out := map[string]enumSet{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, s := range gd.Specs {
			vs := s.(*ast.ValueSpec)
			if len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			if set, ok := allSliceMembers(t, vs.Names[0].Name, vs.Values[0]); ok {
				out[vs.Names[0].Name] = set
			}
		}
	}
	return out
}

// collectPinned returns the set of All<Type> var names passed as the 3rd argument to a
// pinEnum(t, name, <ALLVAR>, ...) call.
func collectPinned(f *ast.File) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := ce.Fun.(*ast.Ident); !ok || id.Name != "pinEnum" {
			return true
		}
		if len(ce.Args) >= 3 {
			if arg, ok := ce.Args[2].(*ast.Ident); ok {
				out[arg.Name] = true
			}
		}
		return true
	})
	return out
}

// TestParity_DeclaredConstsEqualAllSlice pins that, for every enum type, the set of
// consts DECLARED in source exactly equals the set listed in its All<Type> slice. This
// is the guard pinEnum cannot provide: an orphan const (declared, never added to All)
// makes the two sets diverge and fails here.
func TestParity_DeclaredConstsEqualAllSlice(t *testing.T) {
	src := mustParse(t, "decryptobs.go")
	constsByType := collectConsts(src)
	allVars := collectAllVars(t, src)

	allByType := map[string]string{} // elemType → varName
	for varName, v := range allVars {
		if prev, dup := allByType[v.elemType]; dup {
			t.Errorf("enum type %s has two All-slices (%s and %s)", v.elemType, prev, varName)
		}
		allByType[v.elemType] = varName
	}

	for typeName, consts := range constsByType {
		varName, ok := allByType[typeName]
		if !ok {
			t.Errorf("enum type %s declares consts but has no All%s slice — every enum type needs a closed set", typeName, typeName)
			continue
		}
		assertSameSet(t, typeName, varName, consts, allVars[varName].members)
	}

	for varName, v := range allVars {
		if _, ok := constsByType[v.elemType]; !ok {
			t.Errorf("%s is an All-slice for type %s, which declares no consts", varName, v.elemType)
		}
	}
}

// assertSameSet fails for any const declared-but-missing-from-All, or listed-in-All-but-not-declared.
func assertSameSet(t *testing.T, typeName, varName string, consts, all map[string]bool) {
	t.Helper()
	for c := range consts {
		if !all[c] {
			t.Errorf("const %s (type %s) is declared but MISSING from %s — an orphan const whose Valid() is silently false", c, typeName, varName)
		}
	}
	for c := range all {
		if !consts[c] {
			t.Errorf("%s lists %s, which is not a declared const of type %s", varName, c, typeName)
		}
	}
}

// TestParity_EveryAllSliceIsPinned pins that every All<Type> slice is exercised by a
// pinEnum(...) call — so a future 8th enum type cannot ship with zero exhaustiveness
// coverage (PR #758 red-team, test-adequacy gap).
func TestParity_EveryAllSliceIsPinned(t *testing.T) {
	allVars := collectAllVars(t, mustParse(t, "decryptobs.go"))
	pinned := collectPinned(mustParse(t, "decryptobs_test.go"))

	var unpinned []string
	for varName := range allVars {
		if !pinned[varName] {
			unpinned = append(unpinned, varName)
		}
	}
	sort.Strings(unpinned)
	for _, v := range unpinned {
		t.Errorf("%s has no pinEnum(...) call — every enum's closed set must be pinned", v)
	}
	for varName := range pinned {
		if _, ok := allVars[varName]; !ok {
			t.Errorf("pinEnum called with %s, which is not an All<Type> slice in decryptobs.go", varName)
		}
	}
}
