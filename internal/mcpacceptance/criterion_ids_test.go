package mcpacceptance

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The criterion-id wall.
//
// A run's verdict is computed by matching emitted criterion IDs against the
// canonical set in expectedRequiredIDs. An emitted ID that is in NO set is an
// orphan: it is reported to the operator, but the canonical criterion it was meant
// to be goes MISSING instead. The artifact then says "two criteria did not run"
// where the truth was "this control failed, and here is why" — a real difference to
// whoever is deciding whether the deployment is sound.
//
// That is not hypothetical: the mTLS fixture-failure path recorded "tls.mtls",
// which matches neither tls.mtls_accept nor tls.mtls_reject.
//
// Every ID the harness can emit must therefore be either canonically required or
// explicitly declared here as conditional/advisory, with a reason. Adding a
// criterion is fine; adding one nobody classified is not.

// nonRequiredCriterionIDs are the IDs deliberately outside expectedRequiredIDs.
// Each needs a reason, because "not required" is the claim that lets a failure
// through.
var nonRequiredCriterionIDs = map[string]string{
	"evidence.denial_aggregated": "advisory by design: aggregation timing is not a control, " +
		"and the underlying denial is already gated by tenant.no_leak.",
	"artifact.version": "conditional: emitted ONLY when the binary under test is not the " +
		"expected version. It carries Required:true so it gates when present, but it " +
		"must not be in the required set — a matching build correctly never emits it.",
}

// criterionIDShape matches a criterion id: a lowercase group, a dot, a lowercase
// name. It is what lets the scanner read table-driven emission without hand-listing
// every table type.
var criterionIDShape = regexp.MustCompile(`^[a-z][a-z0-9]*\.[a-z0-9_]+$`)

// emittedCriterionIDs collects the criterion IDs the production harness can emit.
//
// Three shapes, because the harness legitimately uses all three and the wall must
// read the code as written rather than dictate one style:
//
//   - the first argument of a runCriterion call;
//   - the ID field of a CriterionResult literal;
//   - the first element of a composite-literal row INSIDE a function that also
//     emits criteria, which is how the table-driven scenarios (oauth, tenant,
//     protocol) name theirs.
//
// The third is scoped twice — to emitting functions, and by criterionIDShape —
// because plenty of unrelated tables elsewhere have a dotted lowercase first column
// (spec.go alone has telemetry.node_id, supervision.admin_user). Scoping by
// enclosing function is what distinguishes "this string names a criterion" from
// "this string is shaped like one". Missing this shape entirely was a real blind
// spot: mutation testing showed an orphan id substituted inside such a table left
// TestCriterionIDs_NoOrphans passing.
func emittedCriterionIDs(t *testing.T) map[string]token.Position {
	t.Helper()
	out := map[string]token.Position{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, filepath.Clean(name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		scanned++
		collectDirectIDs(fset, f, out)
		collectTableIDs(fset, f, out)
	}
	if scanned == 0 || len(out) < 20 {
		t.Fatalf("scanned %d files and found %d criterion ids; the wall is not reading the harness", scanned, len(out))
	}
	return out
}

// stringLit returns the value of a string literal expression.
func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(bl.Value)
	return v, err == nil
}

// collectDirectIDs records shapes (1) and (2): the first argument of a
// runCriterion call, and the ID field of a CriterionResult literal. Both name a
// criterion unambiguously, so they are read anywhere in the file.
func collectDirectIDs(fset *token.FileSet, f *ast.File, out map[string]token.Position) {
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			sel, ok := v.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "runCriterion" || len(v.Args) == 0 {
				return true
			}
			if id, ok := stringLit(v.Args[0]); ok {
				out[id] = fset.Position(v.Args[0].Pos())
			}
		case *ast.CompositeLit:
			ident, ok := v.Type.(*ast.Ident)
			if !ok || ident.Name != "CriterionResult" {
				return true
			}
			recordIDField(fset, v, out)
		}
		return true
	})
}

// recordIDField records the ID field of one CriterionResult literal.
func recordIDField(fset *token.FileSet, lit *ast.CompositeLit, out map[string]token.Position) {
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		k, ok := kv.Key.(*ast.Ident)
		if !ok || k.Name != "ID" {
			continue
		}
		if id, ok := stringLit(kv.Value); ok {
			out[id] = fset.Position(kv.Value.Pos())
		}
	}
}

// collectTableIDs records shape (3): the first element of a composite-literal row,
// read ONLY inside a function that itself emits criteria.
//
// Scoping per FuncDecl (rather than a running flag over the whole file) is what
// keeps the scope real: a flag set on entering the first emitting function and
// never cleared makes every later table in the file look emitted.
func collectTableIDs(fset *token.FileSet, f *ast.File, out map[string]token.Position) {
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !functionEmitsCriteria(fn) {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			recordTableRows(fset, cl, out)
			return true
		})
	}
}

// recordTableRows records the first element of each row of one table literal, when
// it is shaped like a criterion id.
func recordTableRows(fset *token.FileSet, table *ast.CompositeLit, out map[string]token.Position) {
	for _, el := range table.Elts {
		row, ok := el.(*ast.CompositeLit)
		if !ok || len(row.Elts) == 0 {
			continue
		}
		if id, ok := stringLit(row.Elts[0]); ok && criterionIDShape.MatchString(id) {
			out[id] = fset.Position(row.Elts[0].Pos())
		}
	}
}

// functionEmitsCriteria reports whether fn calls runCriterion or record, i.e.
// whether a table inside it plausibly names criteria.
func functionEmitsCriteria(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if sel.Sel.Name == "runCriterion" || sel.Sel.Name == "record" {
				found = true
			}
		}
		return true
	})
	return found
}

// TestCriterionIDs_NoOrphans pins that every emitted id is classified.
func TestCriterionIDs_NoOrphans(t *testing.T) {
	canonical := map[string]bool{}
	for _, id := range expectedRequiredIDs(true) {
		canonical[id] = true
	}
	for id, pos := range emittedCriterionIDs(t) {
		if canonical[id] {
			continue
		}
		if _, declared := nonRequiredCriterionIDs[id]; declared {
			continue
		}
		t.Errorf("%s: criterion id %q is emitted but is neither in expectedRequiredIDs nor "+
			"declared in nonRequiredCriterionIDs.\nAn unclassified id is an orphan: it is "+
			"reported on its own while the canonical criterion it stands for is counted as "+
			"MISSING, so the artifact describes the wrong failure.", pos, id)
	}
}

// TestCriterionIDs_DeclaredNonRequiredAreNotAlsoCanonical keeps the two lists
// disjoint, so an id cannot be simultaneously required and excused.
func TestCriterionIDs_DeclaredNonRequiredAreNotAlsoCanonical(t *testing.T) {
	canonical := map[string]bool{}
	for _, id := range expectedRequiredIDs(true) {
		canonical[id] = true
	}
	for id := range nonRequiredCriterionIDs {
		if canonical[id] {
			t.Errorf("criterion id %q is both canonically required and declared non-required", id)
		}
	}
}

// TestCriterionIDs_MTLSFixtureFailureReportsBothCanonicalCriteria pins the specific
// regression: when the mTLS fixture cannot start, the artifact must fail the two
// real criteria rather than invent a third id and leave them missing.
func TestCriterionIDs_MTLSFixtureFailureReportsBothCanonicalCriteria(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	h := &Harness{now: func() time.Time { return base }, start: base, summary: &Summary{}}
	h.failTLSCriteria("aux_start", "boom")
	got := map[string]Status{}
	for _, c := range h.summary.Criteria {
		if !c.Required {
			t.Errorf("criterion %q recorded as non-required on the fixture-failure path", c.ID)
		}
		got[c.ID] = c.Status
	}
	for _, want := range []string{"tls.mtls_accept", "tls.mtls_reject"} {
		if got[want] != StatusFail {
			t.Errorf("mTLS fixture failure did not fail %q (got %q); the operator would see it as MISSING", want, got[want])
		}
	}
	if _, orphan := got["tls.mtls"]; orphan {
		t.Error(`the orphan id "tls.mtls" is still emitted`)
	}
}

// TestCriterionIDs_EveryRequiredCriterionIsEmitted closes the wall's own blind
// spot, and is the stronger of the two directions.
//
// TestCriterionIDs_NoOrphans checks emitted ⊆ classified. That says nothing about
// a required criterion NOTHING emits, and it is silently weakened by any refactor
// that moves an id out of the shapes the scanner reads — a loop over an anonymous
// struct, a map, a helper table. Mutation testing caught exactly that: replacing a
// canonical id with an orphan inside such a literal left NoOrphans passing.
//
// Requiring classified ⊆ emitted makes both failures loud: a required criterion
// with no emitter, and an id refactored out of the scanner's view.
func TestCriterionIDs_EveryRequiredCriterionIsEmitted(t *testing.T) {
	emitted := emittedCriterionIDs(t)
	for _, id := range expectedRequiredIDs(true) {
		if _, ok := emitted[id]; !ok {
			t.Errorf("required criterion %q is emitted by no harness code the wall can see.\n"+
				"Either nothing runs it — in which case every run fails it as MISSING — or it was "+
				"refactored into a literal shape emittedCriterionIDs does not read, which blinds "+
				"TestCriterionIDs_NoOrphans. Emit it as a runCriterion call or a CriterionResult literal.", id)
		}
	}
}
