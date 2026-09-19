package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
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

// TestCredWall_NodeStatusSurfaceCannotReportActivationReasons pins the OBSERVABILITY BOUNDARY
// that §25d's residual paragraph depends on, and it exists because that paragraph originally
// got it WRONG (Codex P2, round 2).
//
// The claim made was: after a mid-window policy edit "the readiness row then reports the node
// un-ready on the next read". The evidence behind it,
// TestCredDrift_ReadinessIsReEvaluatedNotFrozen, proves something NARROWER — that the credential
// FACT is re-observed from authoritative state rather than frozen into the reviewed snapshot.
// It says nothing about WHICH READ SURFACE exposes it, and the operator-facing one does not:
// mcpCanaryStatus (GET /api/mcp/rollout, the "canary" sub-view) reports evaluateCanaryNodeReadiness
// -> canary.EvaluateNode -> evaluate(f, nodeOnly=true), whose loop SKIPS every factActivation row.
// FirstCanaryCredentialFree is a factActivation row, so `credential_path_required` can never
// appear in that surface's `unmet`. The only non-test caller of the full canary.Evaluate is the
// activation preflight, reached from the rollout commit gate and the startup restore reconcile.
//
// This is the same defect shape as campaign M17: a gate proves one proposition and the prose
// claims a stronger one built on it. The rule to carry forward is that an observability claim
// names the SURFACE, and the surface is checked — so the boundary is asserted here rather than
// described.
//
// Both directions are asserted on purpose. Checking only "no activation reason appears in
// unmet" is VACUOUS under the very mutation that would break the boundary: if EvaluateNode
// stopped excluding activation rows, derivedActivationReasons — which derives the set from
// exported behaviour, by construction — would return EMPTY and the containment check would
// pass over nothing. So the derived set must be non-empty AND must contain this PR's own row.
func TestCredWall_NodeStatusSurfaceCannotReportActivationReasons(t *testing.T) {
	activation := derivedActivationReasons(t)
	if len(activation) == 0 {
		t.Fatal("derived activation set is EMPTY: canary.EvaluateNode no longer excludes " +
			"activation facts, so the node status surface now reports them. The observability " +
			"boundary §25d relies on has moved and that paragraph must be re-derived.")
	}
	if !activation[string(canary.ReasonCredentialPathRequired)] {
		t.Fatalf("%q must be an ACTIVATION-level reason (Evaluate reports it, EvaluateNode does "+
			"not); derived activation set: %v", canary.ReasonCredentialPathRequired, activation)
	}

	status := mcpCanaryStatus()
	unmet, ok := status["unmet"].([]string)
	if !ok {
		t.Fatalf("status surface has no []string unmet field, got %T", status["unmet"])
	}
	// Positive control: the surface must actually be reporting state. A surface that returned
	// nothing would satisfy the containment check below while telling an operator nothing.
	if len(unmet) == 0 {
		t.Fatal("control: the node status surface reported NO unmet prerequisites. On a build " +
			"where no Canary is armed it must report the unmet NODE prerequisites, else this " +
			"gate passes by seeing nothing.")
	}
	for _, r := range unmet {
		if activation[r] {
			t.Fatalf("the node status surface reported ACTIVATION-level reason %q in unmet. "+
				"That contradicts EvaluateNode's contract; if this is now intended, §25d's "+
				"residual paragraph must be updated — it states the opposite.", r)
		}
	}

	// The vocabulary IS advertised on the same surface, which is why the distinction matters:
	// an operator sees credential_path_required listed as a prerequisite and could reasonably
	// infer the surface would report it as unmet when it fails. It will not.
	all, ok := status["all_prerequisites"].([]string)
	if !ok {
		t.Fatalf("status surface has no []string all_prerequisites field, got %T", status["all_prerequisites"])
	}
	found := false
	for _, r := range all {
		if r == string(canary.ReasonCredentialPathRequired) {
			found = true
		}
	}
	if !found {
		t.Fatalf("%q must appear in the advertised prerequisite vocabulary", canary.ReasonCredentialPathRequired)
	}
}

// ---------------------------------------------------------------------------
// THE NODE-READINESS PROMISE WALL (campaign M20), rebuilt after Codex round 4.
//
// Round 3 found the claim "must be able to make a node un-ready" standing on eight surfaces,
// every one of them about a factActivation row that EvaluateNode excludes. The first wall shipped
// for that finding had TWO defects a fourth review round caught, and both are the same shape as
// the defect they were meant to close — claiming more than the evidence supports:
//
//  1. It parsed ONLY internal/mcp/canary/readiness.go, while the ledger claimed M20 closed the
//     class across all six surfaces. Reintroducing the promise in the matrix, the operator ledger
//     or any of the three test files left the gate green.
//  2. Its "control" never applied the matcher and never read a node-level doc — it only compared
//     two derived classifications. Worse, the doc it CITED as the legitimate node-level case
//     ("a rehearsed-mechanics node is still not ready") did not match the matcher at all, so the
//     control exercised nothing. A control that cannot fail is decoration.
//
// Both are fixed here. The matcher now recognises the node-level phrasing too, so the real
// RollbackCoordinatorRehearsed doc genuinely exercises it; the scan covers every surface the claim
// names; and permission to say it is an explicit, reasoned ALLOWLIST rather than a silent gap.
// ---------------------------------------------------------------------------

// nodeReadyPromise matches a claim about what a NODE's readiness verdict does, in EITHER
// polarity. That is the whole point, and the reason this pattern has now been widened twice.
//
// "X makes the node un-ready" and "X stops a node reporting Ready" are the SAME PROPOSITION.
// Round 3 swept the tree for the claim and fixed eight sites — all of them phrased negatively,
// because that is the phrasing it searched for. Four more sites stated it positively and survived
// untouched, including the doc comment on ReasonExactPolicyNotExecutable itself, which is the
// reason string for an ACTIVATION-level fact. Codex round 5 found one of them.
//
// So the lesson round 3 recorded — search for the CLAIM, not the words — was applied to the words
// of one polarity. A matcher for a proposition has to admit that the proposition has a negation.
//
// The positive branch anchors on the VERB (report / reach), not on "node ... Ready" adjacency,
// so a true statement ABOUT node readiness ("the verdict is Ready — node readiness AND the
// activation-level facts") is not swept up. Legitimate node-level claims that DO match are
// permitted by name in nodeReadyMentionAllowed, never by loosening this pattern: a blanket phrase
// ban is the failure mode the control below exists to prevent.
var nodeReadyPromise = regexp.MustCompile(
	`(?i)(` +
		// negative polarity: "the node is still not ready", "an un-ready node"
		`node\s+(is\s+)?(still\s+)?(un-?ready|not\s+ready)|un-?ready\s+node` +
		`|` +
		// positive polarity: "stops a node reporting Ready", "a node can no longer report
		// Ready", "the node must NOT be able to report Ready"
		`node\b[^.]{0,60}?\b(report|reports|reporting|reach|reaches|reaching)\b[^.]{0,40}?\bready\b` +
		`)`)

// nodeReadyMentionAllowed is the EXPLICIT allowlist of places that may speak of node readiness.
// Every entry needs a reason, so permitting a new one is a deliberate act rather than a hole. The
// wall fails on any occurrence not listed here, and TestCredWall_AllowlistIsNotStale fails if a
// listed entry stops matching — an allowlist that matches nothing silently permits everything.
var nodeReadyMentionAllowed = []struct {
	file   string
	needle string
	why    string
}{
	{"internal/mcp/canary/readiness.go", "rehearsed-mechanics node is still not ready",
		"RollbackCoordinatorRehearsed is NODE-level; the claim is true of it."},
	{"docs/operator/mcp-first-controlled-canary-review.md", "reports the node un-ready on the next read",
		"§25d quotes the round-2 false claim in order to refute it. The needle now covers the CLAIM, not the refutation beside it — under span matching a needle that quotes only \"That was FALSE\" permits nothing."},
	{"docs/operator/mcp-first-controlled-canary-review.md", "prerequisite genuinely does make the node un-ready",
		"§25d explains why the wall must NOT be a blanket phrase ban."},
	// Surfaced when the scan was inverted from a six-file list to a whole-tree walk.
	{"mcp_shadow_activation_test.go", "shadow deps ARMED but the node NOT ready",
		"Genuinely node-level: the deps it names (telemetry/policy/inventory/listener) are factNode rows, so the node IS un-ready."},

	// ── GENUINE node-level claims living inside Go string literals ──────────────
	//
	// Added when the quotation rule was REMOVED (Codex round 6). While it stood, every Go string
	// literal was treated as a citation, so these three were skipped without anyone deciding they
	// should be — and so would any FALSE claim written into an error message or test failure
	// string. Each is now permitted by name, with the reason it is true.
	// ── The two CORRECTIVE sentences ───────────────────────────────────────────
	//
	// Added when nodeReadyIndependence was deleted (Codex round 7). A syntactic rule that tried to
	// recognise the corrective form was bypassed twice by negating it, so these are named like
	// every other permitted claim instead of being detected.
	{"internal/mcp/canary/readiness.go", "EvaluateNode skips it and node status can still report Ready",
		"The corrective sentence itself: it states that EvaluateNode skips this factActivation row, which is true."},
	{"mcp_canary_credential_free_test.go", "EvaluateNode skips it and node status can still report Ready",
		"Same corrective sentence, explaining why this test calls canary.Evaluate rather than EvaluateNode."},

	{"mcp_live_tier.go", "mcp live tier: node not ready to arm",
		"True and node-level: live-tier arming is gated on NODE readiness, so this error names the node's own state."},
	{"mcp_canary_matrix_mutation_test.go", "make the full preflight ready while the node is not ready",
		"True in this direction: an un-ready NODE makes the FULL preflight un-ready. It is the converse — an activation fact making the NODE un-ready — that is false."},
	{"mcp_live_tier_test.go", "a composed-but-unready node must name a downstream unmet prerequisite",
		"Node-level by construction: the live tier's own composed-vs-armed lifecycle, not an activation fact."},

	// ── §25d QUOTING the false claims it documents ──────────────────────────────
	//
	// Also added when the quotation rule was removed. A ledger that records five rounds of this
	// defect has to restate the wording; no syntactic rule could separate citing a claim from
	// asserting one (an assertion with a scare-quoted predicate defeated the attempt), so each
	// quotation is named here. Quoting a false claim in a security ledger is a deliberate act and
	// is now recorded as one.
	{"docs/operator/mcp-first-controlled-canary-review.md", "(\"a rehearsed-mechanics node is still not ready\")",
		"§25d quotes the allowlisted readiness.go wording to explain why the matcher had to be widened to see it."},
	{"docs/operator/mcp-first-controlled-canary-review.md", "\"makes a node un-ready\" — because that is what it searched for",
		"§25d quotes the NEGATIVE polarity to explain why the round-3 sweep found only that half."},
	{"docs/operator/mcp-first-controlled-canary-review.md", "*\"this row only stops a node reporting Ready\"*",
		"§25d quotes the POSITIVE polarity — the wording that survived round 3 — in order to refute it."},
	{"docs/operator/mcp-first-controlled-canary-review.md", "node from STILL REPORTING Ready\"* matched both the promise pattern",
		"§25d quotes the negated form Codex round 6 found the `still` exemption swallowing, in order to record it."},
	// --- Codex round 17: claims that a PER-LINE scan could not see ---------------------------
	// Every entry below names a mention that was invisible while the scan read one line at a
	// time, because the sentence carrying it is WRAPPED. None of them is the forbidden claim;
	// each is a legitimate statement that now has to be permitted explicitly, which is the
	// allowlist working as designed rather than a new exemption.
	{"docs/operator/mcp-first-controlled-canary-review.md", "node-level surface that included them would report every node permanently not-ready",
		"§25d explains why EvaluateNode excludes activation facts at all: a node surface that included them would report every node permanently un-ready. A statement about the NODE surface's design, not an activation fact promising node readiness."},
	{"docs/operator/mcp-first-controlled-canary-review.md", "*\"must be able to make a node un-ready\"*",
		"§25d QUOTES the round-2 phrasing in order to explain why the round-3 sweep, which searched for words rather than for the claim, did not match it."},
	{"docs/operator/mcp-first-controlled-canary-review.md", "\"EvaluateNode skips it and node status can still report Ready\" is the one sentence that makes an activation fact's scope unambiguous",
		"§25d quotes the CORRECTING sentence while explaining why the widened matcher flags it; the quoted text asserts the node surface is UNAFFECTED."},
	{"docs/operator/mcp-first-controlled-canary-review.md", "*\"It is FALSE THAT node status can still report Ready\u2026\"*",
		"§25d quotes the NEGATED form that bypassed the deleted exemption, as the evidence for deleting it."},
	{"mcp_canary_catalog_usable_test.go", "so a node could report Ready:true for an experiment in which every single request dies at that override",
		"Describes the DEFECT this test pins — a node reporting Ready for an experiment whose every request dies at the policy hard-override. A statement of the gap being closed, not a promise."},
	{"mcp_canary_matrix_mutation_test.go", "what the live node actually reports, and that no path makes it Ready",
		"Asserts that NO path makes the node Ready — the opposite of a promise, and the posture these composition-layer tests exist to pin."},
	{"mcp_shadow_usable_tool_test.go", "if the node status folded the usable-tool check in it would always report node-not-ready",
		"Genuinely node-level: it explains why the scope-dependent usable-tool check is excluded from the node-readiness dry-run — folding it in would report every node not-ready."},
}

// nodeReadyScanExcluded names the files the scan deliberately does NOT read, with a reason each.
//
// This is an EXCLUSION list, not an inclusion list, and the inversion is the round-5 fix. The wall
// used to name the six surfaces it scanned. Round 4 had already caught it naming one while its
// record claimed six; round 5's own sweep then found a SEVENTH — mcp_canary_policy_permit.go, root
// production source — carrying the identical claim, because a hand-maintained list of places to
// look rots exactly the way the claim it hunts does.
//
// Scanning everything and naming the exceptions cannot drift that way: a new file is covered the
// moment it exists, and every gap is written down here.
var nodeReadyScanExcluded = []struct {
	file string
	why  string
}{
	{"mcp_canary_credential_matrix_test.go",
		"defines nodeReadyPromise and the allowlist needles, so a self-scan reports its own machinery forever."},
}

// claimPassage is ONE PARAGRAPH of a scanned file with its wrapped lines JOINED, plus the mapping
// back to source line numbers so a failure still names the line it was found on.
//
// Codex round 17: the claim scan matched LINE BY LINE, and both Go comments and Markdown wrap. A
// forbidden claim split over two lines -- "stops a node reporting" / "Ready on the next read" --
// matched neither line, so the whole-tree wall stayed green while the exact claim it exists to
// forbid was present in the tree. That is round 16's finding one layer up: the round collector was
// taught that a line wrap is not a boundary, and this scanner, which reads the same wrapped files,
// was not. The rule is now stated ONCE and applied in both places: a line wrap is not a boundary,
// a BLANK LINE is.
//
// Joining can only make the matcher see MORE text, so it can only ever turn a silent pass into a
// visible failure -- the safe direction. Paragraphs are NOT joined to each other, so the scan
// cannot manufacture a claim by stitching two unrelated statements together.
type claimPassage struct {
	text     string
	segStart []int // byte offset in text where each contributing source line begins
	segLine  []int // 1-based source line number of that contribution
}

// lineAt maps a byte offset in the joined text back to the source line it came from.
func (p claimPassage) lineAt(off int) int {
	line := 0
	for i, s := range p.segStart {
		if s > off {
			break
		}
		line = p.segLine[i]
	}
	return line
}

// claimPassages splits a file into paragraphs and joins each paragraph's wrapped lines with a
// single space, dropping each line's indentation and any leading `//` so an allowlist needle can
// be written as prose and stays valid however the line happens to be re-wrapped.
func claimPassages(data string) []claimPassage {
	var out []claimPassage
	var b strings.Builder
	var segStart, segLine []int
	flush := func() {
		if b.Len() > 0 {
			out = append(out, claimPassage{text: b.String(), segStart: segStart, segLine: segLine})
		}
		b.Reset()
		segStart, segLine = nil, nil
	}
	for i, raw := range strings.Split(data, "\n") {
		body := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "//"))
		if body == "" {
			flush() // a blank line -- or a bare `//` -- ends the paragraph
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		segStart = append(segStart, b.Len())
		segLine = append(segLine, i+1)
		b.WriteString(body)
	}
	flush()
	return out
}

// claimUnit is one maximal DOT-FREE run of a joined paragraph, with its offset inside that
// paragraph so a failure can still be reported against the source line it started on.
type claimUnit struct {
	text string
	base int
}

// units splits a joined paragraph at sentence terminators, which is exactly the matcher's OWN
// horizon: every branch of nodeReadyPromise is bounded by `[^.]`, so a match can never span a
// `.` and splitting there loses no possible match.
//
// That property is what makes the unit a sentence rather than the whole paragraph. Scanning
// whole paragraphs was tried first and is WRONG for a reason worth recording: the regex is
// leftmost-first, so an earlier unrelated "node" in the same paragraph starts the match and
// widens its span past the allowlist needle that quotes the claim -- the permission then fails
// to cover the very text it was written for, and the wall reports live, reasoned entries as
// unreachable. A sentence keeps every match span as narrow as a single line used to make it,
// which is what the span-based allowlist depends on, while still spanning a line WRAP.
func (p claimPassage) units() []claimUnit {
	var out []claimUnit
	base := 0
	for _, seg := range strings.Split(p.text, ".") {
		if strings.TrimSpace(seg) != "" {
			out = append(out, claimUnit{text: seg, base: base})
		}
		base += len(seg) + 1
	}
	return out
}

// allowlistCoversEveryClaim reports whether EVERY claim the matcher finds on this line sits inside
// text an allowlist entry quotes, and returns the entries that covered one.
//
// A needle used to permit the WHOLE LINE it appeared on. Codex round 7: appending
// "but this activation row stops a node reporting Ready" after an allowlisted phrase stayed green,
// because the substring was still present and marked the line allowed. A permission to quote one
// historical claim had silently become a permission to assert a new one beside it, and the
// reachability check could not see it — reachability proves an entry is USED, never that it is
// NARROW.
//
// Matching by SPAN makes an entry permit exactly the claim it quotes. A second claim elsewhere on
// the line produces a match outside every needle occurrence and is flagged. That is structural: it
// no longer depends on an author choosing a tight needle.
func allowlistCoversEveryClaim(rel, line string) (allowed bool, hits []string) {
	var spans [][2]int
	for _, a := range nodeReadyMentionAllowed {
		if a.file != rel || a.needle == "" {
			continue
		}
		for idx := 0; idx <= len(line)-len(a.needle); {
			at := strings.Index(line[idx:], a.needle)
			if at < 0 {
				break
			}
			lo := idx + at
			spans = append(spans, [2]int{lo, lo + len(a.needle)})
			hits = append(hits, a.file+"|"+a.needle)
			idx = lo + 1
		}
	}
	for _, m := range nodeReadyPromise.FindAllStringIndex(line, -1) {
		covered := false
		for _, sp := range spans {
			if m[0] >= sp[0] && m[1] <= sp[1] {
				covered = true
				break
			}
		}
		if !covered {
			return false, nil
		}
	}
	return true, hits
}

// needleCoversAClaim is the reachability half: does this needle actually cover a claim on the line?
func needleCoversAClaim(line, needle string) bool {
	if needle == "" {
		return false
	}
	ms := nodeReadyPromise.FindAllStringIndex(line, -1)
	for idx := 0; idx <= len(line)-len(needle); {
		at := strings.Index(line[idx:], needle)
		if at < 0 {
			return false
		}
		lo, hi := idx+at, idx+at+len(needle)
		for _, m := range ms {
			if m[0] >= lo && m[1] <= hi {
				return true
			}
		}
		idx = lo + 1
	}
	return false
}

// nodeReadyScanExcludedDirs names the directories the walk does not descend into, with a reason
// each — the same discipline as the per-file exclusions, applied to the axis that was silently
// exempt.
//
// The first inverted scan skipped frontend, dist and testdata as well, and recorded none of them.
// The ledger then claimed every Go and Markdown file was covered automatically, which was false
// for those subtrees, and no staleness check could see the gap: Codex round 6 found it. frontend
// and dist are now SCANNED (they hold no Go and almost no Markdown, so the cost is nil and the
// claim becomes true); testdata is scanned too, since a fixture asserting a false claim is exactly
// the kind of thing that later gets copied into real source.
//
// What is left is the two directories where a match could not mean anything: version-control
// internals and vendored dependencies nobody here writes.
var nodeReadyScanExcludedDirs = []struct {
	dir string
	why string
}{
	{".git", "version-control internals: object storage, not authored source."},
	{"node_modules", "vendored third-party JavaScript; nothing here authors it, and a match would name someone else's prose."},
}

// TestCredWall_LedgerStatesTheRealScanCount pins the ledger's file count to the walker's.
//
// §25d states a number. Codex round 7 found it wrong by one: the text said 2,555 SCANNED while the
// walk returns one fewer, because it removes the wall's own file. That is the coverage overclaim
// this section exists to record, committed in the sentence recording its fix.
//
// The number was also MEASURED wrong, and the way is worth keeping. The count was taken by adding
// a temporary probe test to the tree — which the walk then counted. The observer was in the
// sample. So the ledger no longer carries a number a human transcribes; this test reads it back
// out of the document and compares it to what the walker actually returns.
func TestCredWall_LedgerStatesTheRealScanCount(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(pkgSourceDir(), "docs", "operator", "mcp-first-controlled-canary-review.md")) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	m := regexp.MustCompile(`SCANNED \(([0-9,]+) files\)`).FindStringSubmatch(string(data))
	if m == nil {
		t.Fatal("§25d no longer states a scanned-file count in the form \"SCANNED (N files)\", so " +
			"this gate cannot compare it to the walker. Restore the claim or delete this test.")
	}
	stated, err := strconv.Atoi(strings.ReplaceAll(m[1], ",", ""))
	if err != nil {
		t.Fatalf("unparsable count %q: %v", m[1], err)
	}
	if got := len(nodeReadyScanFiles(t)); stated != got {
		t.Errorf("§25d claims %d files are scanned; the walker returns %d. A coverage claim that "+
			"overstates the walk by even one file is the defect this section records.", stated, got)
	}
}

// TestCredWall_LedgerRoundCountMatchesItsOwnEnumeration pins the review-round total against the
// STRUCTURED enumeration in §25d, not against a numeral scraped from its prose.
//
// The first version took the largest `round N` token anywhere in the section. Codex round 9: that
// does not establish what the gate claims. A ninth entry headed differently would not move it, and
// a deleted entry would not shrink it while an incidental earlier mention kept it green — so the
// gate measured "the biggest number written down" and the record said "the rounds enumerated".
// That is this section's own defect class, inside the gate added one round earlier to close it.
//
// Both sides now derive from the same list: `- **Round N** — ...` entries, which must be contiguous
// from 1 (a gap means an entry was dropped) and must number exactly what the summary claims.
func TestCredWall_LedgerRoundCountMatchesItsOwnEnumeration(t *testing.T) {
	doc := ledgerSection(t)

	m := regexp.MustCompile(`\*\*(\d+) rounds, one defect shape\.\*\*`).FindStringSubmatch(doc)
	if m == nil {
		t.Fatal("§25d no longer states a round total in the form \"**N rounds, one defect shape.**\"")
	}
	stated, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("unparsable round total %q: %v", m[1], err)
	}

	var seen []int
	for _, r := range regexp.MustCompile(`(?m)^- \*\*Round (\d+)\*\*`).FindAllStringSubmatch(doc, -1) {
		n, e := strconv.Atoi(r[1])
		if e != nil {
			t.Fatalf("unparsable round entry %q", r[1])
		}
		seen = append(seen, n)
	}
	if len(seen) == 0 {
		t.Fatal("§25d enumerates no rounds in the structured `- **Round N**` form, so the total " +
			"is checked against nothing. Restore the enumeration or delete this gate.")
	}
	for i, n := range seen {
		if n != i+1 {
			t.Errorf("the round enumeration is not contiguous from 1: entry %d is Round %d. A gap "+
				"means an entry was dropped and the total would still look right.", i+1, n)
		}
	}
	if stated != len(seen) {
		t.Errorf("§25d claims %d review rounds; it enumerates %d. The summary and its own list "+
			"must derive from the same thing.", stated, len(seen))
	}

	// Codex round 11: the two checks above tie the TOTAL to the ENUMERATION, and both were
	// self-consistent while the section's PROSE discussed a round the list did not contain —
	// §25d described Codex round 10 in detail with the list stopping at 9 and the total reading
	// "9 rounds", and this gate stayed green throughout. That is round 9's finding one level out:
	// the gate checked the two things it derived from each other and never asked whether they
	// covered what the section actually talks about.
	//
	// So every round §25d NAMES must also be enumerated. A round worth a paragraph is a round
	// worth an audit-trail entry, and if a mention is not about this section's own review history
	// it should not be phrased as "round N" here.
	enumerated := make(map[int]bool, len(seen))
	for _, n := range seen {
		enumerated[n] = true
	}
	var unlisted []int
	for _, n := range roundsNamedIn(doc) {
		if !enumerated[n] {
			unlisted = append(unlisted, n)
		}
	}
	if len(unlisted) > 0 {
		t.Errorf("§25d discusses round(s) %v that its structured enumeration does not contain. "+
			"The total and the list agree with each other and both understate the section: add a "+
			"`- **Round N** — ...` entry for each, or stop calling it a round here.", unlisted)
	}
}

// TestCredWall_LedgerStatesTheCampaignSize ties §25d's mutation count to the script.
//
// Codex round 9 again: a second paragraph carried its own account of the campaign's growth and
// stopped at M21 while the script reached M28, so the section gave two incompatible histories of
// one thing. The size is stated once now, and derived.
func TestCredWall_LedgerStatesTheCampaignSize(t *testing.T) {
	doc := ledgerSection(t)
	m := regexp.MustCompile(`mutations\.sh` + "`" + ` — (\d+) mutations`).FindStringSubmatch(doc)
	if m == nil {
		t.Fatal("§25d no longer states the campaign size beside the script name")
	}
	stated, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("unparsable campaign size %q: %v", m[1], err)
	}
	script, err := os.ReadFile(filepath.Join(pkgSourceDir(), "scripts", "mcp-first-canary-no-credential-mutations.sh")) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read campaign script: %v", err)
	}
	actual := len(regexp.MustCompile(`(?m)^run_mutation `).FindAllString(string(script), -1))
	if actual == 0 {
		t.Fatal("found no run_mutation invocations, so this gate compares against nothing")
	}
	if stated != actual {
		t.Errorf("§25d claims %d mutations; the script runs %d", stated, actual)
	}
}

// roundsNamedIn returns every round number a passage NAMES, in each of the forms §25d actually
// uses.
//
// Codex round 12: the first version matched only `round N`, so the PLURAL form was invisible --
// and not "only the first number" as one might assume, but NOTHING, because `round\s+` cannot
// match the `s` in `rounds`. §25d already contained one (`rounds 7 and 8`), so the gate's claim
// that every named round is enumerated was false for the most natural phrasing, and it was green
// on that text by luck: 7 and 8 happen to be enumerated. A range is expanded rather than read as
// two isolated endpoints, because `rounds 11-13` names 12 as much as it names 11 (`to` counts as
// a range token for the same reason).
//
// Codex round 13: the comma-list arm accepted only ONE separator token between numbers, so an
// Oxford comma -- `rounds 7, 8, and 98` -- stopped the list at the serial comma and returned just
// 7 and 8. Both are enumerated, so the gate stayed green while 98 went unseen. The separator is
// now a sequence, which is what `, and` actually is.
//
// Codex round 16: a hard line wrap is not a sentence boundary. `\n` was in the stop class, so
// `rounds 7 and\n98` -- ordinary wrapped Markdown, which is how this very section is written --
// truncated at the wrap and returned only 7, leaving round 98 unenumerated and the gate green.
// The stop is now a PARAGRAPH break (a blank line), not any newline. That change can only WIDEN
// each window, so the collected set is a superset of what it was: the gate can get stricter, it
// cannot go blind. Over-collection would show up as a false failure, and does not -- the live
// §25d still yields exactly the enumerated set (see below).
var (
	// NO CONNECTOR VOCABULARY -- see roundsNamedIn for why there is none.
	roundToken  = regexp.MustCompile(`(?i)\brounds?\b`)
	roundStop   = regexp.MustCompile(`[.;:!?]|\n[ \t]*\n`)
	roundNumber = regexp.MustCompile(`\b\d{1,2}\b`)
	roundRange  = regexp.MustCompile(`\b(\d{1,2})\s*(?:[\x{2013}\x{2014}-]|\bto\b|\bthrough\b)\s*(\d{1,2})\b`)
)

// roundsNamedIn returns every round number a passage NAMES.
//
// It has NO CONNECTOR VOCABULARY, and that is the design. Rounds 12, 13, 14 and 15 were the same
// finding with a different word in it -- the plural `and`, the Oxford comma, a serial `or`, then
// multi-word forms like `as well as` and `followed by`. Each fix that learned one more separator
// left the next one silently truncating the list, and round 14's "refuse what you cannot read"
// only moved the problem: a refusal matching ONE short token is evaded by TWO words. A vocabulary
// cannot be completed, so there is none.
//
// Instead: every one- or two-digit number in the same SENTENCE as a `round`/`rounds` token is a
// named round, whatever joins it to the previous one. Numbers are bounded to two digits because
// round numbers here are small -- which is what keeps ordinary prose like "round 9 in 2026" out
// of it. Ranges are still expanded, because `rounds 11-13` names 12.
//
// Codex round 17: there used to be a 60-BYTE cutoff on top of the sentence bound, and it silently
// truncated an ordinary long list -- `rounds 7 and 8, followed after the baseline and campaign
// instrumentation were repaired by 97` returned 7 and 8 and never reached 97. An arbitrary byte
// count is not a property of the language, so it could only ever be a guess about how far a
// sentence runs; the sentence and paragraph terminators already say exactly that. Removing it
// only WIDENS each window, so the collected set is a superset and the gate can get stricter but
// not blind. Measured against the live §25d before and after: the same set, [1..N].
//
// The cost of having no cutoff is stated rather than hidden: an unrelated one- or two-digit
// number in the SAME SENTENCE as a round token is now read as a round, so the ledger must not
// write "in round 9 we ran 36 mutations" with no sentence break. That direction is a visible
// false FAILURE an author fixes by rewording; the direction it replaces was a silent false PASS.
//
// The window stops at a sentence terminator or a BLANK LINE. A single newline is a line wrap in
// this document, not a boundary, and treating it as one made the scan blind to any list that
// happened to wrap (round 16).
//
// Verified against the live §25d: this collects EXACTLY the enumerated set, so it is neither
// under-reading the section nor manufacturing rounds out of neighbouring numbers.
func roundsNamedIn(doc string) []int {
	seen := map[int]bool{}
	for _, loc := range roundToken.FindAllStringIndex(doc, -1) {
		w := doc[loc[1]:]
		if stop := roundStop.FindStringIndex(w); stop != nil {
			w = w[:stop[0]]
		}
		for _, r := range roundRange.FindAllStringSubmatch(w, -1) {
			lo, loErr := strconv.Atoi(r[1])
			hi, hiErr := strconv.Atoi(r[2])
			if loErr != nil || hiErr != nil || lo > hi || hi-lo > 50 {
				continue // the endpoints are still picked up by the scan below
			}
			for n := lo; n <= hi; n++ {
				seen[n] = true
			}
		}
		for _, d := range roundNumber.FindAllString(w, -1) {
			if n, err := strconv.Atoi(d); err == nil {
				seen[n] = true
			}
		}
	}
	out := make([]int, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// ledgerSection returns §25d alone. The document records Codex rounds from OTHER sections' reviews
// (31, 33 and others from earlier work), so every derivation here must be scoped or it reads them.
func ledgerSection(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(pkgSourceDir(), "docs", "operator", "mcp-first-controlled-canary-review.md")) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	doc := string(data)
	start := strings.Index(doc, "## \u00a725d ")
	if start < 0 {
		t.Fatal("cannot locate the \u00a725d heading")
	}
	end := strings.Index(doc[start:], "\n## \u00a726 ")
	if end < 0 {
		t.Fatal("cannot locate the end of \u00a725d")
	}
	return doc[start : start+end]
}

// TestCredWall_LedgerCountsItsOwnQuotationPermissions pins the other number §25d states.
//
// Codex round 7 again: the narrative said three ledger quotations were allowlisted when four had
// been added, so the audit trail understated the permissions introduced. Counting entries by file
// is exact, so the document no longer has to be right by hand.
func TestCredWall_LedgerCountsItsOwnQuotationPermissions(t *testing.T) {
	ledger := filepath.Join("docs", "operator", "mcp-first-controlled-canary-review.md")
	actual := 0
	for _, a := range nodeReadyMentionAllowed {
		if a.file == ledger {
			actual++
		}
	}
	data, err := os.ReadFile(filepath.Join(pkgSourceDir(), ledger)) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	m := regexp.MustCompile(`(\d+) allowlist entries name ledger lines`).FindStringSubmatch(string(data))
	if m == nil {
		t.Fatal("§25d no longer states how many allowlist entries name its own lines. That count " +
			"is the audit trail for the permissions introduced when the quotation rule was removed.")
	}
	stated, _ := strconv.Atoi(m[1])
	if stated != actual {
		t.Errorf("§25d claims %d allowlist entries name ledger lines; there are %d", stated, actual)
	}
}

// nodeReadyScanFiles returns every Go and Markdown file in the repository except the exclusions.
//
// .sh is deliberately out of scope: the mutation campaigns REINTRODUCE the claim as their payload,
// so a campaign script contains it by construction and scanning one would flag the tests that
// prove the wall works.
func nodeReadyScanFiles(t *testing.T) []string {
	t.Helper()
	excluded := map[string]bool{}
	for _, e := range nodeReadyScanExcluded {
		excluded[e.file] = true
	}
	root := pkgSourceDir()
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			for _, d := range nodeReadyScanExcludedDirs {
				if info.Name() == d.dir {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if ext := filepath.Ext(path); ext != ".go" && ext != ".md" {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil || excluded[rel] {
			return nil //nolint:nilerr // a path we cannot relativise is not a surface we can name
		}
		out = append(out, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree for node-readiness claims: %v", err)
	}
	if len(out) < 100 {
		t.Fatalf("the walk found only %d files, which is not this repository — a scan that reads "+
			"almost nothing passes by seeing nothing", len(out))
	}
	return out
}

// activationFactFieldNames returns the canary.Facts FIELD names that are ACTIVATION-level,
// derived from exported evaluator behaviour exactly as derivedActivationReasons derives the
// reasons: flip one fact false, and the field is activation-level when Evaluate reports its
// reason and EvaluateNode does not. Nothing is hard-coded, so a new row is classified the moment
// it is declared.
func activationFactFieldNames(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	base := credAllTrueFacts()
	ty := reflect.ValueOf(&base).Elem().Type()
	for i := range ty.NumField() {
		name := ty.Field(i).Name
		if ty.Field(i).Type.Kind() != reflect.Bool || name == "CapabilityGateway" {
			continue
		}
		f := credAllTrueFacts()
		reflect.ValueOf(&f).Elem().Field(i).SetBool(false)
		full := canary.Evaluate(f)
		if len(full.Unmet) != 1 {
			t.Fatalf("flipping %s must yield exactly one unmet reason, got %v", name, full.Unmet)
		}
		nodeSees := false
		for _, r := range canary.EvaluateNode(f).Unmet {
			if r == full.Unmet[0] {
				nodeSees = true
			}
		}
		if !nodeSees {
			out[name] = true
		}
	}
	return out
}

// factsFieldDocs AST-reads the doc comment of every canary.Facts field from the real source.
func factsFieldDocs(t *testing.T) map[string]string {
	t.Helper()
	src := filepath.Join(pkgSourceDir(), "internal", "mcp", "canary", "readiness.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, src, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}
	docs := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Facts" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, fld := range st.Fields.List {
			if fld.Doc == nil || len(fld.Names) == 0 {
				continue
			}
			docs[fld.Names[0].Name] = fld.Doc.Text()
		}
		return false
	})
	return docs
}

// TestCredWall_NoActivationFactPromisesNodeReadiness is the PRECISE half: an ACTIVATION-level
// canary.Facts field may not document itself as able to make the node un-ready, because
// EvaluateNode excludes every activation row and `node_ready` is a literal field on that surface.
func TestCredWall_NoActivationFactPromisesNodeReadiness(t *testing.T) {
	activation := activationFactFieldNames(t)
	if len(activation) == 0 {
		t.Fatal("derived activation set is EMPTY: EvaluateNode no longer excludes activation facts, " +
			"so this gate would inspect nothing. Re-derive the boundary before trusting it.")
	}
	docs := factsFieldDocs(t)
	if len(docs) == 0 {
		t.Fatal("read NO Facts field docs — the struct moved or lost its comments, so this gate is " +
			"passing by seeing nothing.")
	}

	checked := 0
	for name, doc := range docs {
		if !activation[name] {
			continue // node-level fields may legitimately speak of node readiness
		}
		checked++
		if nodeReadyPromise.MatchString(doc) {
			t.Errorf("canary.Facts.%s is an ACTIVATION-level fact, but its doc promises NODE "+
				"readiness. EvaluateNode excludes every activation row, so no status read can "+
				"report it. Say it refuses the next FULL ACTIVATION PREFLIGHT instead.", name)
		}
	}
	if checked == 0 {
		t.Fatal("inspected NO documented ACTIVATION fields — this gate is passing by seeing nothing.")
	}
}

// TestCredWall_EveryClaimedSurfaceIsScanned answers Codex round 4's first finding: M20's ledger
// entry claims the class is closed across six surfaces, so the wall must READ six surfaces. A gate
// that inspects one file while its record claims six is the same overclaim the class is made of.
func TestCredWall_EveryClaimedSurfaceIsScanned(t *testing.T) {
	activation := activationFactFieldNames(t)
	docs := factsFieldDocs(t)

	// Build the set of node-level Facts docs, which are allowed to make the claim.
	nodeLevelDoc := map[string]bool{}
	for name, doc := range docs {
		if !activation[name] {
			nodeLevelDoc[doc] = true
		}
	}

	allowHits := map[string]int{}
	scanned := 0
	for _, rel := range nodeReadyScanFiles(t) {
		path := filepath.Join(pkgSourceDir(), rel)
		data, err := os.ReadFile(path) //nolint:gosec // fixed in-repo path list, not caller input
		if err != nil {
			t.Fatalf("the wall claims to scan %s but cannot read it: %v", rel, err)
		}
		scanned++
		for _, psg := range claimPassages(string(data)) {
			for _, u := range psg.units() {
				loc := nodeReadyPromise.FindStringIndex(u.text)
				if loc == nil {
					continue
				}
				allowed, hits := allowlistCoversEveryClaim(rel, u.text)
				for _, h := range hits {
					allowHits[h]++
				}
				if !allowed {
					t.Errorf("%s:%d claims something makes the NODE un-ready, and is not on the "+
						"reasoned allowlist:\n    %s\nIf this is an ACTIVATION fact, say it refuses "+
						"the next FULL ACTIVATION PREFLIGHT. If it is genuinely node-level, add an "+
						"allowlist entry saying why.", rel, psg.lineAt(u.base+loc[0]),
						strings.TrimSpace(u.text))
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no files at all")
	}
	if len(allowHits) == 0 {
		t.Fatal("the scan matched NOTHING anywhere, allowlisted or not. Either the matcher broke " +
			"or every mention vanished; both mean this wall is now passing by seeing nothing.")
	}
}

// needlePresent reports whether an allowlist needle appears in the file AS THE SCAN READS IT —
// that is, in the wrap-joined paragraph text rather than in any one raw line.
func needlePresent(data, needle string) bool {
	if needle == "" {
		return false
	}
	for _, psg := range claimPassages(data) {
		if strings.Contains(psg.text, needle) {
			return true
		}
	}
	return false
}

// allowlistEntryReached reports whether the scan actually REACHES a line carrying this needle —
// that is, a line the wall would flag were the entry not there.
//
// It is a named function rather than a loop inside the test so that a control can drive it in both
// directions. Campaign M25 survived its first run precisely because it could not: with every entry
// currently reachable, weakening the check to mere presence changed no verdict, so the mutation
// passed and the gate proved nothing about the property it advertises. A check whose claim only
// holds when the tree happens to violate it is not a check.
func allowlistEntryReached(data, needle string) bool {
	for _, psg := range claimPassages(data) {
		for _, u := range psg.units() {
			if !nodeReadyPromise.MatchString(u.text) {
				continue
			}
			if needleCoversAClaim(u.text, needle) {
				return true
			}
		}
	}
	return false
}

// TestCredWall_AllowlistIsNotStale keeps the allowlist honest: an entry that no longer matches any
// line silently widens the wall's permission, which is how an allowlist rots into a hole.
func TestCredWall_AllowlistIsNotStale(t *testing.T) {
	for _, a := range nodeReadyMentionAllowed {
		data, err := os.ReadFile(filepath.Join(pkgSourceDir(), a.file)) //nolint:gosec // fixed in-repo path
		if err != nil {
			t.Fatalf("allowlist names unreadable file %s: %v", a.file, err)
		}
		// The presence check reads the SAME joined view the scan does. Reading raw bytes here
		// was wrong for the reason Codex round 17 found in the scan itself: both Go comments
		// and Markdown wrap, so a needle quoting a claim that spans a line break appears in no
		// single line of the file and a literal containment check calls the live entry stale.
		if !needlePresent(string(data), a.needle) {
			t.Errorf("allowlist entry {%s, %q} matches nothing any more (%s). Remove it rather "+
				"than leaving a standing permission nobody uses.", a.file, a.needle, a.why)
			continue
		}
		// Present in the file is not the same as REACHED by the scan. An entry whose lines are
		// already exempted earlier — or whose needle covers no claim — is a
		// permission nothing exercises, and the containment check above cannot see that. Added
		// after the quotation rule made one entry unreachable the moment it was written.
		if !allowlistEntryReached(string(data), a.needle) {
			t.Errorf("allowlist entry {%s, %q} is never REACHED by the scan (%s): every line it "+
				"names is already exempted by an earlier rule. Delete it — an unreachable "+
				"permission is the thing this test exists to catch.", a.file, a.needle, a.why)
		}
	}
}

// TestCredWall_NodeLevelFactsMayStillSpeakOfNodeReadiness is the REAL control, rebuilt after Codex
// round 4 found the first one vacuous: it compared two derived classifications, never applied the
// matcher, and cited a doc whose wording the matcher did not even recognise.
//
// It now drives the matcher against the ACTUAL RollbackCoordinatorRehearsed doc and asserts BOTH
// halves of the discrimination: the matcher DOES fire on that legitimate node-level wording, and
// the wall nonetheless permits it because the field is node-level. Together those rule out the
// cheapest wrong fix — turning the wall into an indiscriminate phrase ban, which would be a
// spell-checker rather than a wall.
func TestCredWall_NodeLevelFactsMayStillSpeakOfNodeReadiness(t *testing.T) {
	activation := activationFactFieldNames(t)
	docs := factsFieldDocs(t)

	const nodeField = "RollbackCoordinatorRehearsed"
	if activation[nodeField] {
		t.Fatalf("premise moved: %s is no longer NODE-level, so it can no longer serve as the "+
			"control for the activation-only ban.", nodeField)
	}
	doc, ok := docs[nodeField]
	if !ok {
		t.Fatalf("premise moved: %s has no doc comment, so this control exercises nothing.", nodeField)
	}

	// Half one: the matcher must actually FIRE on this legitimate wording. Without this the
	// control is decoration — the exact defect round 4 found, where the cited doc said "node is
	// still not ready" and the matcher only knew "node un-ready".
	if !nodeReadyPromise.MatchString(doc) {
		t.Fatalf("control is VACUOUS: the matcher does not recognise %s's node-readiness wording, "+
			"so it never exercises the discrimination this test claims to prove.\ndoc: %s",
			nodeField, strings.TrimSpace(doc))
	}

	// Half two: and the wall must permit it anyway, because the field is node-level.
	if activation[nodeField] {
		t.Fatal("unreachable given the premise check above")
	}

	// And the activation side must still be banned, or the discrimination is one-sided.
	if !activation["FirstCanaryCredentialFree"] {
		t.Fatal("premise moved: FirstCanaryCredentialFree must be ACTIVATION-level; if it is not, " +
			"the ban applies to nothing this PR added.")
	}
}

// TestCredWall_NoSyntacticExemptionForCorrectiveWording pins the REMOVAL of nodeReadyIndependence,
// and the reason it was removed rather than tightened again.
//
// The exemption let an author write the one sentence that states an activation fact's scope. A
// reviewer defeated it twice, in consecutive rounds:
//
//	round 6: "...PREVENTS the node from STILL REPORTING Ready"      (any "still <verb> ready")
//	round 7: "It is FALSE THAT node status can still report Ready"  (the anchored subject)
//
// The second matters more, because the fix for the first was justified in this file as
// "self-limiting — a sentence containing this phrase asserts the node surface is UNAFFECTED".
// That is false: any assertion can be negated, and a pattern that recognises a phrase cannot see
// the operator in front of it. Two tightenings produced two bypasses, which is the signature of a
// losing game rather than a nearly-correct rule.
//
// So there is no syntactic exemption. The two real corrective sentences are named in
// nodeReadyMentionAllowed like every other permitted claim — the conclusion round 6 reached for the
// quotation rule, now applied consistently rather than one mechanism at a time.
func TestCredWall_NoSyntacticExemptionForCorrectiveWording(t *testing.T) {
	for _, line := range []string{
		"It is false that node status can still report Ready after this activation fact fails.",
		"This activation prerequisite prevents the node from still reporting Ready for an unsafe experiment",
		"It is not true that node status can still report Ready here.",
	} {
		if !nodeReadyPromise.MatchString(line) {
			t.Errorf("the matcher does not see the claim: %q", line)
			continue
		}
		allowed, _ := allowlistCoversEveryClaim("docs/operator/mcp-first-controlled-canary-review.md", line)
		if allowed {
			t.Errorf("a NEGATED corrective sentence is permitted, so the forbidden claim can be "+
				"written by negating the exemption's own wording: %q", line)
		}
	}
}

// TestCredWall_AnAllowlistEntryPermitsOnlyWhatItQuotes is the control for span matching.
//
// Codex round 7: a needle used to permit the WHOLE LINE it appeared on, so appending a fresh claim
// after an allowlisted phrase stayed green. A permission to quote one historical claim had become a
// permission to assert a new one beside it, and the reachability check could not see it —
// reachability proves an entry is USED, never that it is NARROW.
func TestCredWall_AnAllowlistEntryPermitsOnlyWhatItQuotes(t *testing.T) {
	const ledger = "docs/operator/mcp-first-controlled-canary-review.md"

	// The REAL allowlisted line, verbatim. An invented one is how this control went vacuous once
	// already: it was written around the needle "**That was FALSE**", that needle was later
	// repointed at the claim it was supposed to quote, and the sample line then contained no claim
	// and no needle at all — so "permitted" was true because there was nothing to permit, and the
	// mutation could not change the verdict. Campaign M23 SURVIVED and exposed it.
	quotedOnly := `readiness row then reports the node un-ready on the next read". **That was FALSE**, and the way it`

	// Non-vacuity, asserted rather than assumed: the sample must carry a claim AND be covered by a
	// real allowlist entry, or everything below is trivially true.
	if got := len(nodeReadyPromise.FindAllStringIndex(quotedOnly, -1)); got != 1 {
		t.Fatalf("the sample line must carry exactly one claim for this control to mean anything, "+
			"it carries %d — the ledger wording drifted away from the allowlist needle", got)
	}
	ok, hits := allowlistCoversEveryClaim(ledger, quotedOnly)
	if !ok || len(hits) == 0 {
		t.Fatalf("premise broken: the allowlisted quotation alone is not permitted by a real entry "+
			"(ok=%v hits=%d), so this control cannot say anything about breadth", ok, len(hits))
	}

	appended := quotedOnly + ` but this activation row stops a node reporting Ready`
	if got := len(nodeReadyPromise.FindAllStringIndex(appended, -1)); got != 2 {
		t.Fatalf("the appended line must carry two claims, it carries %d", got)
	}
	if ok, _ := allowlistCoversEveryClaim(ledger, appended); ok {
		t.Errorf("an allowlist entry permits a SECOND claim appended to its line, so the entry is a "+
			"whole-line permission rather than a quotation: %q", appended)
	}
}

// TestCredWall_AQuotedClaimIsStillAClaim pins the REMOVAL of the quotation rule.
//
// A previous version stripped every quoted span from a line before testing it, on the reasoning
// that §25d must be able to QUOTE the false claims it documents. Codex round 6 showed the rule was
// unsound in two ways, the second worse than the first:
//
//   - An ordinary scare-quoted assertion — This activation fact "stops a node reporting Ready". —
//     has its subject outside the quotes and its predicate inside, so stripping left nothing to
//     match and the wall permitted the claim.
//   - In Go source, "quoted span" means STRING LITERAL. The rule was exempting the contents of
//     every error message, log line and test-failure string in the repository. Three real lines
//     were being skipped for exactly that reason, none of them citations.
//
// A general syntactic rule could not separate citing a claim from asserting one, so there is no
// general rule any more: the ledger's quotations are named individually in nodeReadyMentionAllowed
// with a reason each, and the reachability check keeps them honest. Quoting a false claim in a
// security ledger is a deliberate act, and it is now recorded as one.
func TestCredWall_AQuotedClaimIsStillAClaim(t *testing.T) {
	for _, line := range []string{
		`This activation fact "stops a node reporting Ready".`,
		`errLiveTierNotReady = errors.New("this row makes the node un-ready")`,
		`t.Fatalf("this activation row makes a node un-ready")`,
	} {
		if !nodeReadyPromise.MatchString(line) {
			t.Errorf("the matcher does not see the claim at all: %q", line)
			continue
		}
		if ok, _ := allowlistCoversEveryClaim("internal/mcp/canary/readiness.go", line); ok {
			t.Errorf("a quoted ASSERTION is permitted, so a claim written inside a string literal "+
				"or scare quotes is invisible to the wall: %q", line)
		}
	}
}

// TestCredWall_ReachabilityCheckCanActuallyFail is the control for allowlistEntryReached.
//
// It exists because campaign M25 SURVIVED its first run. That mutation weakens
// TestCredWall_AllowlistIsNotStale from "the scan REACHES this entry" back to "the needle appears
// somewhere in the file" — and with every entry currently reachable, the weakened form reaches the
// same verdict on every one of them. The gate passed with the defect reintroduced, so it was
// establishing nothing about reachability; it was riding on the tree being clean.
//
// A control fixes that by making the predicate answer a question whose answer is known and NOT
// dependent on the current state of the allowlist: a needle that sits only on lines the scan never
// flags is unreachable, and a needle on a genuinely flagged line is reachable. Now the campaign has
// something to break.
func TestCredWall_ReachabilityCheckCanActuallyFail(t *testing.T) {
	read := func(rel string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(pkgSourceDir(), rel)) //nolint:gosec // fixed in-repo path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(data)
	}

	// UNREACHABLE: present in the file, but only on lines that carry no claim at all, so the scan
	// never gets as far as consulting the allowlist for them.
	readiness := read(filepath.Join("internal", "mcp", "canary", "readiness.go"))
	const neverFlagged = "package canary"
	if !strings.Contains(readiness, neverFlagged) {
		t.Fatalf("premise broken: %q is no longer in readiness.go, so this control tests nothing", neverFlagged)
	}
	if allowlistEntryReached(readiness, neverFlagged) {
		t.Errorf("allowlistEntryReached says a needle on a line the scan never flags is REACHED. "+
			"The check cannot distinguish a live permission from a dead one, which is the whole "+
			"property TestCredWall_AllowlistIsNotStale claims to enforce (needle %q)", neverFlagged)
	}

	// REACHABLE: the real node-level claim the allowlist exists for.
	const liveClaim = "rehearsed-mechanics node is still not ready"
	if !allowlistEntryReached(readiness, liveClaim) {
		t.Errorf("allowlistEntryReached says the genuine node-level claim is NOT reached, so every "+
			"real entry would be reported dead and the wall would demand their deletion (needle %q)",
			liveClaim)
	}
}

// TestCredWall_ClaimScanSeesWrappedClaims is the direct control for Codex round 17's second
// finding, and it carries its own proof of non-vacuity.
//
// The scan used to read one line at a time. Both Go comments and Markdown wrap, so a claim split
// over a line break matched NEITHER line and the whole-tree wall stayed green with the forbidden
// claim present. Each case below therefore asserts BOTH halves: the joined view sees the claim,
// and a per-line view does NOT -- so if the join were ever removed these cases fail instead of
// quietly proving nothing. The last case is the opposite guarantee: paragraphs are not stitched
// together, so the scan cannot manufacture a claim out of two unrelated statements.
func TestCredWall_ClaimScanSeesWrappedClaims(t *testing.T) {
	seenPerLine := func(doc string) bool {
		for _, line := range strings.Split(doc, "\n") {
			if nodeReadyPromise.MatchString(line) {
				return true
			}
		}
		return false
	}
	seenJoined := func(doc string) bool {
		for _, psg := range claimPassages(doc) {
			for _, u := range psg.units() {
				if nodeReadyPromise.MatchString(u.text) {
					return true
				}
			}
		}
		return false
	}

	for _, tc := range []struct {
		name        string
		doc         string
		wantJoined  bool
		wantPerLine bool // what the OLD scan saw -- false is the defect this closes
	}{
		{
			name:        "go comment wrapped mid-claim",
			doc:         "// this activation row stops a node reporting\n// Ready on the next status read\n",
			wantJoined:  true,
			wantPerLine: false,
		},
		{
			name:        "markdown wrapped mid-claim",
			doc:         "The row stops a node from reporting\nReady on the next read.\n",
			wantJoined:  true,
			wantPerLine: false,
		},
		{
			name:        "unwrapped claim, unchanged",
			doc:         "// this row stops a node reporting Ready on the next read\n",
			wantJoined:  true,
			wantPerLine: true,
		},
		{
			name:        "two paragraphs are never stitched",
			doc:         "a sentence ending in the word node\n\nreport Ready is a separate paragraph\n",
			wantJoined:  false,
			wantPerLine: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := seenJoined(tc.doc); got != tc.wantJoined {
				t.Errorf("joined scan saw claim = %v, want %v, in:\n%s", got, tc.wantJoined, tc.doc)
			}
			if got := seenPerLine(tc.doc); got != tc.wantPerLine {
				t.Errorf("per-line scan saw claim = %v, want %v — this case no longer proves "+
					"what it claims to prove, in:\n%s", got, tc.wantPerLine, tc.doc)
			}
		})
	}
}

// TestCredWall_ClaimUnitsDoNotWidenAMatchPastItsSentence pins WHY the scan unit is a sentence and
// not a whole paragraph.
//
// Joining whole paragraphs was tried first and is wrong: nodeReadyPromise is leftmost-first, so an
// earlier unrelated `node` in the same paragraph starts the match and widens its span past the
// allowlist needle that quotes the claim. The permission then covers nothing, and the wall reports
// live, reasoned entries as unreachable — a gate failing on correct text, which is how a wall gets
// switched off. Every branch of the matcher is bounded by `[^.]`, so splitting at a sentence
// terminator cannot lose a match; it can only keep the span narrow.
func TestCredWall_ClaimUnitsDoNotWidenAMatchPastItsSentence(t *testing.T) {
	doc := "// An unrelated mention of a node here. The row stops a node reporting\n// Ready.\n"
	psgs := claimPassages(doc)
	if len(psgs) != 1 {
		t.Fatalf("expected one paragraph, got %d", len(psgs))
	}
	var spans []string
	for _, u := range psgs[0].units() {
		if loc := nodeReadyPromise.FindStringIndex(u.text); loc != nil {
			spans = append(spans, u.text[loc[0]:loc[1]])
		}
	}
	if len(spans) != 1 {
		t.Fatalf("expected exactly one match, got %d: %q", len(spans), spans)
	}
	if strings.Contains(spans[0], "unrelated") {
		t.Fatalf("the match span reached back into the previous sentence: %q\nA paragraph-wide "+
			"unit does this, and it is what breaks span-based allowlisting.", spans[0])
	}
}

// TestCredWall_RoundNamesAreParsedInEveryFormTheLedgerUses pins roundsNamedIn directly.
//
// The gate above consumes it, but a gate that is green proves only that the rounds it FOUND are
// enumerated — it cannot distinguish "found them all" from "found none". That is exactly how the
// plural blind spot survived: §25d has said `rounds 7 and 8` throughout, the extractor saw
// nothing there, and the gate passed. Codex round 12.
func TestCredWall_RoundNamesAreParsedInEveryFormTheLedgerUses(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want []int
	}{
		{"singular", "which Codex round 10 found", []int{10}},
		{"plural and", "learned the hard way in rounds 7 and 8, state each fact once", []int{7, 8}},
		{"plural comma", "rounds 7, 8 and 9 each found one", []int{7, 8, 9}},
		{"en dash range", "rounds 11–13 covered the apparatus", []int{11, 12, 13}},
		{"hyphen range", "rounds 4-6 were about scope", []int{4, 5, 6}},
		{"oxford comma", "rounds 7, 8, and 98 each found one", []int{7, 8, 98}},
		{"serial or", "rounds 7, 8, or 98 each found one", []int{7, 8, 98}},
		{"as well as", "rounds 7 as well as 98 found it", []int{7, 98}},
		{"followed by", "rounds 7 followed by 98 found it", []int{7, 98}},
		{"alongside", "rounds 7 alongside 98 found it", []int{7, 98}},
		{"slash", "rounds 7/98 found it", []int{7, 98}},
		{"plain or", "rounds 7 or 98 found it", []int{7, 98}},
		{"ampersand", "rounds 7 & 98 found it", []int{7, 98}},
		{"through range", "rounds 5 through 7 were about scope", []int{5, 6, 7}},
		{"comma list no and", "rounds 7, 8, 98 each found one", []int{7, 8, 98}},
		{"to range", "rounds 5 to 7 were about scope", []int{5, 6, 7}},
		{"several phrases", "round 2 and later round 9", []int{2, 9}},
		{"no rounds named", "the gates get stronger every round; nothing numbered follows", nil},
		{"not a round", "roundabout 7 and background 9", nil},
		{"wrapped and", "rounds 7 and\n98 found it", []int{7, 98}},
		{"wrapped comma list", "rounds 7,\n8, 98 found it", []int{7, 8, 98}},
		{"wrapped list item", "- rounds 7 and\n  98 were merged\n", []int{7, 98}},
		{"paragraph break stops the scan", "rounds 7\n\n98 mutations ran", []int{7}},
		{"sentence end stops the scan", "round 7. 98 mutations ran", []int{7}},
		{"long list past byte 60", "rounds 7 and 8, followed after the baseline and campaign instrumentation were repaired by 97", []int{7, 8, 97}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := roundsNamedIn(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("roundsNamedIn(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("roundsNamedIn(%q) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}
