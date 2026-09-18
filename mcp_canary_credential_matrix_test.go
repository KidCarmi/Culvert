package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
)

// ---------------------------------------------------------------------------
// BLOCKER #9 §11/§12 — the matrix INDEX and the structural wall.
//
// The index exists because a coverage claim written in prose drifts silently: a case can be
// renamed, merged into another test, or deleted, and the ledger still says twelve. Here the
// twelve required cases name the gate that establishes each, and the gate must exist.
// ---------------------------------------------------------------------------

// credentialMatrix is the §11 required matrix. Each row names the case and the test function
// that establishes it. Every negative row also names the positive control that stops it being
// satisfiable by a resolver that simply refuses everything.
var credentialMatrix = []struct {
	num     int
	case_   string
	gate    string
	control string // the positive control for a negative row; empty when the row IS a control
}{
	{1, "canonical exact ALLOW, no credential anywhere -> valid",
		"TestCredFreeE2E_CanonicalPathIsCredentialFree", ""},
	{2, "policy obligation CredentialProfile set -> invalid",
		"TestCredFreeE2E_PolicyObligationCredentialIsRefused", "TestCredFreeE2E_CanonicalPathIsCredentialFree"},
	{3, "registry/server credential profile set -> invalid",
		"TestCredFreeE2E_ServerCredentialProfileIsRefused", "TestCredFreeE2E_CanonicalPathIsCredentialFree"},
	{4, "reviewed target implies a credential requirement -> invalid",
		"TestCredFreeE2E_ServerCredentialProfileIsRefused", "TestCredFreeE2E_CanonicalPathIsCredentialFree"},
	{5, "policy none + server requires -> invalid",
		"TestCredFreeE2E_PolicyNoneServerRequiresIsNotReady", "TestCredFreeE2E_CanonicalPathIsCredentialFree"},
	{6, "server none + policy requires -> invalid",
		"TestCredFreeE2E_PolicyRequiresServerAnonymousIsNotReady", "TestCredFreeE2E_CanonicalPathIsCredentialFree"},
	{7, "valid path reaches the execution boundary with the broker untouched",
		"TestCredZeroUse_CanonicalPathNeverTouchesTheCredentialMachinery", ""},
	{8, "valid path sends no Authorization header",
		"TestCredZeroUse_CanonicalPathNeverTouchesTheCredentialMachinery", ""},
	{9, "credential-required forced execution -> fail closed, upstream 0",
		"TestCredZeroUse_CredentialRequiredWithNoBrokerFailsClosed", "TestCredZeroUse_CanonicalPathNeverTouchesTheCredentialMachinery"},
	{10, "no-credential -> credential-required drift after activation -> old binding refuses",
		"TestCredDrift_CredentialChangeBreaksTheReviewedBinding", "TestCredFreeE2E_CanonicalPathIsCredentialFree"},
	{11, "restart preserves the credential-free reviewed state",
		"TestCredFreeE2E_RestartPreservesTheCredentialFreeReviewedState", ""},
	{12, "auxiliary lifecycle/discovery traffic carries no Authorization",
		"TestCredZeroUse_AuxiliaryTrafficCarriesNoAuthorization", ""},
}

// TestCredMatrix_EveryRequiredCaseHasALivingGate asserts each row's gate (and each negative row's
// positive control) exists as a test function in this package. A renamed or deleted gate fails
// here instead of quietly shrinking the matrix.
func TestCredMatrix_EveryRequiredCaseHasALivingGate(t *testing.T) {
	funcs := rootTestFuncNames(t)
	if len(credentialMatrix) != 12 {
		t.Fatalf("the §11 matrix requires 12 cases, the index carries %d", len(credentialMatrix))
	}
	seen := map[int]bool{}
	for _, row := range credentialMatrix {
		if seen[row.num] {
			t.Errorf("duplicate case number %d", row.num)
		}
		seen[row.num] = true
		if !funcs[row.gate] {
			t.Errorf("case %d (%s): gate %s does not exist", row.num, row.case_, row.gate)
		}
		if row.control != "" && !funcs[row.control] {
			t.Errorf("case %d (%s): positive control %s does not exist — the negative would be "+
				"satisfiable by a resolver that refuses everything", row.num, row.case_, row.control)
		}
	}
	for i := 1; i <= 12; i++ {
		if !seen[i] {
			t.Errorf("case %d is missing from the index", i)
		}
	}
}

// rootTestFuncNames returns every Test* function declared in this package's test files.
func rootTestFuncNames(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	// Anchored to the package source dir, never the CWD: a concurrent os.Chdir would
	// otherwise make this enumerate the wrong directory and silently find no gates at all —
	// the failure mode TestTestFileReadsAreCWDIndependent exists to prevent, and which would
	// turn this wall into one that passes by seeing nothing.
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.AllErrors)
		if err != nil {
			continue // a file that does not parse cannot be hiding a gate we rely on
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
				out[fn.Name.Name] = true
			}
		}
	}
	return out
}

// ── §12 — the structural wall ────────────────────────────────────────────────

// TestCredWall_ReadinessConsumesTheResolvedFactNotALiteral is the §12 wall, and it targets the
// cheapest way to defeat every behavioural gate at once: wiring the readiness input to a constant.
//
// `FirstCanaryCredentialFree: true` in productionCanaryActivationInputs would satisfy every
// negative gate that does not route through the production probe, because those gates call the
// resolver directly. The wall requires the production input to be fed from the resolved facts
// value — the same one ExactPolicyPermit is fed from — so a literal fails the build.
//
// It is deliberately NOT a grep for `CredentialProfile == ""`: that spelling is not what makes
// the property hold, and pinning it would forbid a correct refactor while permitting this one.
func TestCredWall_ReadinessConsumesTheResolvedFactNotALiteral(t *testing.T) {
	fn := parseRootFunc(t, "mcp_canary_preflight.go", "productionCanaryActivationInputs")
	var found bool
	ast.Inspect(fn, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "FirstCanaryCredentialFree" {
			return true
		}
		found = true
		sel, ok := kv.Value.(*ast.SelectorExpr)
		if !ok {
			t.Errorf("SECURITY: FirstCanaryCredentialFree is wired to %T, not to the resolved "+
				"facts. A constant here satisfies every behavioural gate at once.", kv.Value)
			return false
		}
		x, _ := sel.X.(*ast.Ident)
		if x == nil || x.Name != "exact" || sel.Sel.Name != "CredentialFree" {
			t.Errorf("SECURITY: FirstCanaryCredentialFree must come from the resolved facts "+
				"(exact.CredentialFree), got %v.%s", sel.X, sel.Sel.Name)
		}
		return false
	})
	if !found {
		t.Fatal("productionCanaryActivationInputs no longer wires FirstCanaryCredentialFree — the " +
			"readiness row is fed by nothing and defaults false, which is fail-closed but means " +
			"no Canary can ever be prepared. Re-wire it or remove the row deliberately.")
	}
}

// TestCredWall_EveryActivationInputFieldIsWired is the companion non-vacuity check: the wall
// above pins ONE field, so it would keep passing if the field were dropped from the struct. This
// asserts every bool on canaryActivationInputs is both produced by the production resolver and
// consumed into canary.Facts, so a row cannot be added and left dangling.
func TestCredWall_EveryActivationInputFieldIsWired(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "mcp_canary_preflight.go"))
	if err != nil {
		t.Fatalf("read preflight: %v", err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "mcp_canary_preflight.go", src, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse preflight: %v", err)
	}
	var fields []string
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "canaryActivationInputs" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, fld := range st.Fields.List {
			id, isIdent := fld.Type.(*ast.Ident)
			if !isIdent || id.Name != "bool" {
				continue
			}
			for _, nm := range fld.Names {
				fields = append(fields, nm.Name)
			}
		}
		return false
	})
	if len(fields) == 0 {
		t.Fatal("no bool fields found on canaryActivationInputs — this wall is checking nothing")
	}
	body := string(src)
	for _, name := range fields {
		// Produced by the production resolver AND consumed into the Facts table.
		if !strings.Contains(body, name+": ") && !strings.Contains(body, name+":") {
			t.Errorf("canaryActivationInputs.%s is never produced", name)
		}
		if !strings.Contains(body, "in."+name) {
			t.Errorf("SECURITY: canaryActivationInputs.%s is never consumed into canary.Facts — "+
				"the readiness row it feeds silently defaults false and the input is dead", name)
		}
	}
}

// parseRootFunc returns a named top-level func from a root-package file.
func parseRootFunc(t *testing.T, file, name string) *ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(pkgSourceDir(), file), nil, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("%s not found in %s — this wall is checking nothing", name, file)
	return nil
}

// TestCredWall_EngineErrorIsNotACredentialFreeAnswer pins the fail-closed direction at the
// resolver: the credential input's Resolved flag must be derived from the engine's error, never
// asserted true unconditionally.
//
// WHY THIS IS A WALL AND NOT A BEHAVIOURAL GATE. An engine error is not reachable through the
// production resolver today — mcpruntime.ExactPermitTuple validates the tuple and returns
// built=false on anything malformed, so buildExactPermitInput returns `unavailable` before
// Evaluate is ever called. The guard is therefore defense-in-depth against a future change to the
// tuple builder or the engine's contract, and a behavioural test would have to fabricate a state
// the production path cannot produce.
//
// WHY IT MATTERS ANYWAY. On an engine-error path `dec` is the zero Decision, so the POLICY
// credential statement reads "" — and against an empty inventory the verdict would be CredFreeOK:
// "provably credential-free" for a tuple whose policy verdict could not be computed at all. The
// tempting defence is that the permit row refuses the same tuple (PermitEvaluationFailed) so the
// node cannot be Ready regardless. That is true today and is exactly the wrong shape of argument:
// it makes THIS row's soundness depend on ANOTHER row staying required. The pure verdict's own
// half — that an unresolved capture reads as unavailable rather than credential-free — is pinned
// by TestCredFree_UnresolvedIsUnavailableNotCredentialFree.
func TestCredWall_EngineErrorIsNotACredentialFreeAnswer(t *testing.T) {
	fn := parseRootFunc(t, "mcp_canary_policy_permit.go", "buildExactPermitInput")
	var found bool
	ast.Inspect(fn, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "CredentialFreeInput" {
			return true
		}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "Resolved" {
				continue
			}
			// EXACTLY TWO spellings are admissible, and both are fail-closed:
			//   Resolved: false      — the explicit unavailable value the early returns use
			//   Resolved: err == nil — the established case, gated on the engine succeeding
			// Anything else (notably a bare `true`) lets an engine error be reported as
			// credential-free on the strength of a zero Decision.
			if id, isIdent := kv.Value.(*ast.Ident); isIdent && id.Name == "false" {
				continue // the fail-closed literal; admissible, and not a condition to check
			}
			found = true
			bin, ok := kv.Value.(*ast.BinaryExpr)
			if !ok {
				t.Errorf("SECURITY: CredentialFreeInput.Resolved is set to %T rather than derived "+
					"from the engine error. An engine error would then report the tuple as "+
					"credential-free on the strength of a zero Decision.", kv.Value)
				continue
			}
			x, _ := bin.X.(*ast.Ident)
			y, _ := bin.Y.(*ast.Ident)
			if x == nil || x.Name != "err" || bin.Op != token.EQL || y == nil || y.Name != "nil" {
				t.Errorf("SECURITY: CredentialFreeInput.Resolved must be `err == nil`, got a " +
					"different condition — an engine error must read as NOT ESTABLISHED")
			}
		}
		return true
	})
	if !found {
		t.Fatal("buildExactPermitInput no longer builds a CredentialFreeInput whose Resolved is a " +
			"CONDITION — only fail-closed `false` literals remain, so either the resolver stopped " +
			"establishing the fact at all or this wall is checking nothing")
	}
}

// TestCredWall_MatrixDocActivationRowsMatchTheTable is the ROOT-CAUSE gate for a defect this
// document has now produced three times: prose that names readiness rows by NUMBER, and a table
// whose numbers shift when a row is inserted.
//
// Its own §"Node vs activation readiness" paragraph carries the history — "CANARY-READINESS-MATRIX.md
// drifted to an undercount by exactly this route and stayed wrong across two reviews" — and this PR
// produced it again: inserting the credential-free row as 21 pushed budget from 23 to 24 and the
// rollback rows from 21/22 to 22/23, leaving EIGHT stale references behind. Codex caught one of
// them. A reviewer catching one instance of a systematic drift is not a fix.
//
// So the numbers are no longer trusted to prose review. This derives the activation set from the
// EXPORTED evaluator behaviour (a fact is activation-level exactly when Evaluate reports its reason
// and EvaluateNode does not), maps it through the document's own table, and requires the paragraph's
// row list to name precisely those rows.
//
// It deliberately does NOT restate the expected numbers: a test that hard-coded "3, 4, 4a, …" would
// need editing by the same hand that edits the paragraph, and would drift with it.
func TestCredWall_MatrixDocActivationRowsMatchTheTable(t *testing.T) {
	activationReasons := derivedActivationReasons(t)
	if len(activationReasons) == 0 {
		t.Fatal("derived no activation reasons — this wall is checking nothing")
	}

	doc, err := os.ReadFile(filepath.Join(pkgSourceDir(), "docs", "design", "mcp", "CANARY-READINESS-MATRIX.md"))
	if err != nil {
		t.Fatalf("read matrix doc: %v", err)
	}
	rowReason := matrixTableRows(t, string(doc))
	listed := matrixProseActivationRows(t, string(doc))

	got := map[string]bool{}
	for _, row := range listed {
		reason, ok := rowReason[row]
		if !ok {
			t.Errorf("the activation paragraph names row %q, which the table does not define", row)
			continue
		}
		got[reason] = true
	}
	for reason := range activationReasons {
		if !got[reason] {
			t.Errorf("readiness reason %q is ACTIVATION-level but the matrix doc's activation "+
				"paragraph does not list its row — an operator reading the paragraph would "+
				"misclassify it as node-level", reason)
		}
	}
	for reason := range got {
		if !activationReasons[reason] {
			t.Errorf("the matrix doc's activation paragraph lists the row for %q, which is "+
				"NODE-level — the row numbers have drifted from the table", reason)
		}
	}
}

// derivedActivationReasons returns the reasons Evaluate reports but EvaluateNode does not, which is
// the definition of an activation-level row. It is derived by flipping one prerequisite at a time
// from the all-true baseline, so a row added to readinessChecks is picked up with no edit here.
func derivedActivationReasons(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	base := credAllTrueFacts()
	v := reflect.ValueOf(&base).Elem()
	ty := v.Type()
	for i := range ty.NumField() {
		if v.Field(i).Kind() != reflect.Bool || ty.Field(i).Name == "CapabilityGateway" {
			continue // CapabilityGateway is the short-circuit, not a prerequisite row
		}
		f := credAllTrueFacts()
		reflect.ValueOf(&f).Elem().Field(i).SetBool(false)
		full := canary.Evaluate(f)
		if len(full.Unmet) != 1 {
			t.Fatalf("flipping %s must yield exactly one unmet reason, got %v",
				ty.Field(i).Name, full.Unmet)
		}
		reason := string(full.Unmet[0])
		nodeSees := false
		for _, r := range canary.EvaluateNode(f).Unmet {
			if string(r) == reason {
				nodeSees = true
			}
		}
		if !nodeSees {
			out[reason] = true
		}
	}
	return out
}

// matrixTableRows parses the readiness table into row-label -> reason-code. The table's rows look
// like `| 21 | Title | ` + "`reason_code`" + ` | … |`, and row labels are not all numeric ("4a").
func matrixTableRows(t *testing.T, doc string) map[string]string {
	t.Helper()
	out := map[string]string{}
	row := regexp.MustCompile(`^\|\s*(\d+[a-z]?)\s*\|[^|]*\|\s*` + "`" + `([a-z0-9_]+)` + "`" + `\s*\|`)
	for _, line := range strings.Split(doc, "\n") {
		if m := row.FindStringSubmatch(line); m != nil {
			out[m[1]] = m[2]
		}
	}
	if len(out) < 10 {
		t.Fatalf("parsed only %d table rows — the table format changed and this wall is checking "+
			"nothing", len(out))
	}
	return out
}

// matrixProseActivationRows extracts the row labels the "Node vs activation readiness" paragraph
// declares activation-level.
func matrixProseActivationRows(t *testing.T, doc string) []string {
	t.Helper()
	const anchor = "**Node vs activation readiness (two evaluators).** Rows "
	i := strings.Index(doc, anchor)
	if i < 0 {
		t.Fatal("the activation paragraph's anchor text changed — this wall is checking nothing")
	}
	rest := doc[i+len(anchor):]
	end := strings.Index(rest, "(")
	if end < 0 {
		t.Fatal("could not find the end of the activation row list")
	}
	var out []string
	for _, tok := range strings.Split(rest[:end], ",") {
		if tok = strings.TrimSpace(strings.ReplaceAll(tok, "\n", " ")); tok != "" {
			out = append(out, tok)
		}
	}
	if len(out) == 0 {
		t.Fatal("the activation paragraph lists no rows — this wall is checking nothing")
	}
	return out
}
