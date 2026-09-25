package main

// ── Phase C1.6: delegated-handler MinRole parity (ENFORCING) ──────────────
//
// WHY THIS FILE EXISTS
//
// C1.5 (ui_routes_meta_audit_test.go) cross-checks uiRoutes metadata against
// what each handler does, but it is DELIBERATELY conservative: its own header
// records that it "does NOT trace control flow into helper functions,
// closures, or dynamically-dispatched methods. Such cases surface as
// 'unknown'", and unknowns are reported via t.Logf WITHOUT failing the run.
//
// At the time this gate was written that blind spot covered 60 route/method
// pairs, and 22 of them were PRIVILEGED (operator or admin) — among them
// POST /api/cluster/tokens, POST /api/releases/dispatch, POST
// /api/pac/profiles/, POST+DELETE /api/mcp/canary/shadow-exit-review and
// POST/PUT/DELETE /api/policy. Every one of those is a thin dispatcher whose
// per-method branch delegates to a helper (apiPolicyCreate, apiClusterTokenCreate,
// …) that does call requireRole. So the invariant HELD — but nothing enforced
// it: a future delegate that simply forgot its requireRole would leave C2
// metadata as the ONLY gate, which directly contradicts the two standing
// Admin-UI invariants in CLAUDE.md:
//
//	#6 "Do not remove handler-level requireRole. C2 is an additional gate,
//	    not a replacement. Defense-in-depth is the contract."
//	#2 "Metadata must never be more permissive than handler behavior."
//
// C4 (ui_metadata_divergence_test.go) observes that divergence only at
// RUNTIME, only once a request actually exercises the path, and it never
// blocks. So for a delegated privileged route the defense-in-depth contract
// had no build-time enforcement at all.
//
// WHAT THIS GATE ADDS
//
// One resolution step C1.5 declines to take: when a method's branch contains
// no direct requireRole, follow calls to package-level functions with the
// handler signature (w http.ResponseWriter, r *http.Request) and inherit the
// roles they enforce. Recursion is depth-bounded and cycle-guarded.
//
// The resulting rule is ENFORCING, not informational:
//
//   - A resolved role weaker than the declared MinRole FAILS (metadata more
//     permissive than the handler — invariant #2).
//   - A privileged route (operator/admin) whose role cannot be resolved at
//     all FAILS (invariant #6: a privileged handler must carry its own check).
//   - A VIEWER-floor route with no resolvable check is permitted ONLY when its
//     uiRoutes entry carries an explicit Note documenting the deviation. Those
//     routes are genuinely gated by uiAuthMiddleware + C2 and viewer is the
//     lowest authenticated role, so there is no escalation — but the deviation
//     must be DECLARED, so adding one is a visible decision rather than an
//     omission.
//
// KNOWN BOUNDARY (deliberate, and pinned rather than hidden)
//
// Method attribution is exact only for the `switch r.Method { case … }` shape.
// For any other handler the WHOLE body governs every declared method, so a
// handler that branched on the method some other way and guarded only one
// branch would resolve as guarded for all of them — a false PASS. That fold is
// sound today because exactly one multi-method route lacks a method switch
// (PUT/DELETE/POST /api/upstream/entries/, whose apiUpstreamEntryRouter takes a
// single requireRole(RoleAdmin) BEFORE it branches, so the fold is correct),
// and TestC16_WholeBodyFoldInventory fails the build if a second one appears.
// The gate therefore errs toward not failing, never toward inventing a pass it
// has not audited.
//
// This file is _test.go only: zero production behavior change.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// c16MaxDelegationDepth bounds how far a dispatcher chain is followed.
// Two hops covers every shape in the tree today (route handler → method
// dispatcher → per-method helper) and keeps the walk cheap and obviously
// terminating; the cycle guard below is the real safety net.
const c16MaxDelegationDepth = 4

// c16Func is one top-level function declaration indexed by name, together
// with whether it has the admin-API handler signature.
type c16Func struct {
	decl      *ast.FuncDecl
	isHandler bool // func(w http.ResponseWriter, r *http.Request)
	file      string
}

var (
	c16Once  sync.Once
	c16Funcs map[string]*c16Func
	c16Err   error
)

// c16Index parses every non-test .go file in the package source directory
// and indexes top-level (non-method) function declarations by name.
func c16Index(t *testing.T) map[string]*c16Func {
	t.Helper()
	c16Once.Do(func() { c16Funcs, c16Err = doC16Index() })
	if c16Err != nil {
		t.Fatalf("c16Index: %v", c16Err)
	}
	return c16Funcs
}

func doC16Index() (map[string]*c16Func, error) {
	fset := token.NewFileSet()
	out := make(map[string]*c16Func, 512)
	// Absolute package source dir — NOT CWD — so a concurrent test's os.Chdir
	// cannot make this scan enumerate a different directory (same CWD-race
	// reasoning as C1.5's doScanHandlers).
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, fmt.Errorf("parse %s: %w", name, perr)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			out[fn.Name.Name] = &c16Func{decl: fn, isHandler: c16HasHandlerSig(fn), file: name}
		}
	}
	return out, nil
}

// c16HasHandlerSig reports whether fn's parameter list is
// (http.ResponseWriter, *http.Request) — the admin-API handler shape. Only
// functions with this signature are followed as delegates, so the walk can
// never wander into unrelated helpers.
func c16HasHandlerSig(fn *ast.FuncDecl) bool {
	if fn.Type == nil || fn.Type.Params == nil || len(fn.Type.Params.List) != 2 {
		return false
	}
	return c16TypeString(fn.Type.Params.List[0].Type) == "http.ResponseWriter" &&
		c16TypeString(fn.Type.Params.List[1].Type) == "*http.Request"
}

func c16TypeString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			return id.Name + "." + x.Sel.Name
		}
	case *ast.StarExpr:
		return "*" + c16TypeString(x.X)
	case *ast.Ident:
		return x.Name
	}
	return ""
}

// c16MethodBranch returns the statements that govern `method` inside fn.
//
// Shape 1 — `switch r.Method { case http.MethodPost: ... }`: the governing
// statements are everything BEFORE the switch (preamble guards such as a
// shared requireRole) plus the matching case body. A switch with no matching
// case but a default returns preamble + default.
//
// Shape 2 — anything else (single-method handler, if-guard, MethodAny): the
// whole body governs.
//
// Returning the preamble as well is what keeps the gate from producing false
// FAILURES on handlers that gate once up front and then switch.
func c16MethodBranch(fn *ast.FuncDecl, method string) []ast.Stmt {
	if method == MethodAny {
		return fn.Body.List
	}
	for i, st := range fn.Body.List {
		sw, ok := st.(*ast.SwitchStmt)
		if !ok || !c16IsMethodSwitch(sw) {
			continue
		}
		preamble := fn.Body.List[:i]
		var deflt []ast.Stmt
		for _, cs := range sw.Body.List {
			cc, ok := cs.(*ast.CaseClause)
			if !ok {
				continue
			}
			if len(cc.List) == 0 { // default:
				deflt = cc.Body
				continue
			}
			for _, expr := range cc.List {
				if c16HTTPMethodLiteral(expr) == method {
					return append(append([]ast.Stmt{}, preamble...), cc.Body...)
				}
			}
		}
		if deflt != nil {
			return append(append([]ast.Stmt{}, preamble...), deflt...)
		}
		// Method not handled by this switch — the preamble is all that runs.
		return preamble
	}
	return fn.Body.List
}

// c16IsMethodSwitch reports whether sw switches on r.Method.
func c16IsMethodSwitch(sw *ast.SwitchStmt) bool {
	sel, ok := sw.Tag.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Method" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "r"
}

// c16HTTPMethodLiteral maps an `http.MethodPost` selector to "POST".
func c16HTTPMethodLiteral(e ast.Expr) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "http" || !strings.HasPrefix(sel.Sel.Name, "Method") {
		return ""
	}
	return strings.ToUpper(strings.TrimPrefix(sel.Sel.Name, "Method"))
}

// c16Resolution is the outcome of resolving one route/method.
type c16Resolution struct {
	role      UIRole   // weakest role enforced on this path ("" ⇔ unresolved)
	resolved  bool     // a requireRole call was reached
	viaDirect bool     // found without following any delegate
	chain     []string // delegate chain followed, for diagnostics
	rejects   bool     // the handler does not serve this method (no switch case; guard-free default)
}

// c16Resolve walks the statements governing one route/method and returns the
// WEAKEST role enforced on that path, following delegate handlers when the
// branch itself carries no requireRole.
//
// Weakest-wins is the security-correct fold: if any reachable path through
// the branch enforces only viewer, an attacker holding viewer can take it, so
// the branch's effective floor is viewer regardless of what a sibling call
// demands.
func c16Resolve(idx map[string]*c16Func, name, method string, depth int, seen map[string]bool) c16Resolution {
	if depth > c16MaxDelegationDepth || seen[name] {
		return c16Resolution{}
	}
	seen[name] = true
	fn := idx[name]
	if fn == nil || fn.decl.Body == nil {
		return c16Resolution{}
	}

	bc := c16BranchCalls(idx, fn, method)
	if len(bc.delegates) == 0 {
		if len(bc.direct) > 0 {
			return c16Resolution{role: c16Weakest(bc.direct), resolved: true, viaDirect: true}
		}
		return c16Resolution{rejects: c16MethodUnserved(fn.decl, method)}
	}

	// The branch delegates. A direct check in the same branch governs a
	// delegated path only when it DOMINATES it (an unconditional top-level
	// guard ahead of the first delegate call); any other direct check is just
	// one more path, folded weakest-wins with the delegates. Once delegated,
	// the delegate owns its own method dispatch, so it is resolved for the
	// SAME method.
	paths := append([]UIRole{}, bc.pathDirect...)
	unguarded := false
	var chain []string
	for _, d := range bc.delegates {
		sub := c16Resolve(idx, d, method, depth+1, seen)
		if sub.rejects {
			// The delegate does not serve this method at all (its method
			// switch answers it only through a guard-free default) — that
			// path grants nothing, so it is neither a floor nor unguarded.
			continue
		}
		if !sub.resolved {
			unguarded = true
			continue
		}
		if len(paths) == 0 || rolePriorityOf(sub.role) < rolePriorityOf(c16Weakest(paths)) {
			chain = append([]string{d}, sub.chain...)
		}
		paths = append(paths, sub.role)
	}

	var pathFloor UIRole
	if !unguarded && len(paths) > 0 {
		pathFloor = c16Weakest(paths)
	}
	if len(bc.dominating) > 0 {
		role := c16Weakest(bc.dominating)
		if pathFloor != "" && rolePriorityOf(pathFloor) > rolePriorityOf(role) {
			role = pathFloor
		} else {
			chain = nil
		}
		return c16Resolution{role: role, resolved: true, chain: chain}
	}
	if pathFloor == "" {
		// Some delegated path reaches no requireRole and no direct check
		// dominates it: conservatively unresolved, never a guessed pass.
		return c16Resolution{}
	}
	return c16Resolution{role: pathFloor, resolved: true, chain: chain}
}

// c16MethodUnserved reports whether fn dispatches on r.Method and has NO case
// for method, so the method reaches only a default arm that itself calls no
// handler and no requireRole (the method-not-allowed shape).
func c16MethodUnserved(fn *ast.FuncDecl, method string) bool {
	if method == MethodAny {
		return false
	}
	for _, st := range fn.Body.List {
		sw, ok := st.(*ast.SwitchStmt)
		if !ok || !c16IsMethodSwitch(sw) {
			continue
		}
		for _, cs := range sw.Body.List {
			cc, ok := cs.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, expr := range cc.List {
				if c16HTTPMethodLiteral(expr) == method {
					return false
				}
			}
		}
		return true
	}
	return false
}

// c16Calls is what one method branch of a handler calls.
type c16Calls struct {
	direct     []UIRole // every requireRole in the branch
	dominating []UIRole // requireRole guards that run unconditionally before any delegate call
	pathDirect []UIRole // requireRole calls that do NOT dominate the delegates
	delegates  []string
}

// c16IsDominatingGuard reports whether a top-level branch statement is an
// UNCONDITIONAL requireRole guard — `if !requireRole(...) { ... }`, a bare
// call, or an assignment from one — and returns its role. A guard behind a
// compound condition is conditional, and so is not dominating.
func c16IsDominatingGuard(st ast.Stmt) UIRole {
	var e ast.Expr
	switch s := st.(type) {
	case *ast.IfStmt:
		if s.Init != nil {
			return ""
		}
		e = s.Cond
		// The LEFTMOST operand of a && / || chain is always evaluated, so
		// `if !requireRole(...) || !other(w) { return }` is still an
		// unconditional guard.
		for {
			b, ok := e.(*ast.BinaryExpr)
			if !ok || (b.Op != token.LOR && b.Op != token.LAND) {
				break
			}
			e = b.X
		}
		if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.NOT {
			e = u.X
		}
	case *ast.ExprStmt:
		e = s.X
	case *ast.AssignStmt:
		if len(s.Rhs) != 1 {
			return ""
		}
		e = s.Rhs[0]
	default:
		return ""
	}
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return ""
	}
	if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "requireRole" {
		return extractRequireRoleArg(call)
	}
	return ""
}

// c16BranchCalls collects the requireRole roles and the delegate handler
// calls found in the statements governing one method of fn, classifying each
// requireRole as dominating (an unconditional top-level guard ahead of the
// first statement that calls a delegate) or not.
func c16BranchCalls(idx map[string]*c16Func, fn *c16Func, method string) c16Calls {
	var out c16Calls
	seenDelegate := false
	for _, st := range c16MethodBranch(fn.decl, method) {
		var stDirect []UIRole
		var stDelegates []string
		ast.Inspect(st, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			switch {
			case id.Name == "requireRole":
				if role := extractRequireRoleArg(call); role != "" {
					stDirect = append(stDirect, role)
				}
			case idx[id.Name] != nil && idx[id.Name].isHandler && len(call.Args) == 2:
				stDelegates = append(stDelegates, id.Name)
			}
			return true
		})
		out.direct = append(out.direct, stDirect...)
		if guard := c16IsDominatingGuard(st); guard != "" && !seenDelegate && len(stDelegates) == 0 {
			out.dominating = append(out.dominating, guard)
		} else {
			out.pathDirect = append(out.pathDirect, stDirect...)
		}
		out.delegates = append(out.delegates, stDelegates...)
		if len(stDelegates) > 0 {
			seenDelegate = true
		}
	}
	return out
}

// c16Weakest returns the least-privileged role in a non-empty list.
func c16Weakest(roles []UIRole) UIRole {
	weakest := roles[0]
	for _, r := range roles[1:] {
		if rolePriorityOf(r) < rolePriorityOf(weakest) {
			weakest = r
		}
	}
	return weakest
}

// TestC16_DelegatedHandlersEnforceDeclaredRole is the enforcing half of the
// C1.5 contract: every non-public route/method must be resolvable to a
// handler-level requireRole at least as strict as its declared MinRole, or
// carry an explicit Note declaring the viewer-floor deviation.
func TestC16_DelegatedHandlersEnforceDeclaredRole(t *testing.T) {
	idx := c16Index(t)

	var (
		weaker      []string
		unprotected []string
		undeclared  []string
		checked     int
	)

	for _, rt := range uiRoutes {
		if rt.Public {
			continue
		}
		for _, m := range rt.Methods {
			if m.MinRole == RolePublic || m.MinRole == "" {
				continue
			}
			checked++
			res := c16Resolve(idx, rt.Handler, m.Method, 0, map[string]bool{})
			where := fmt.Sprintf("%s %s → %s", m.Method, rt.Path, rt.Handler)
			if len(res.chain) > 0 {
				where += " (via " + strings.Join(res.chain, " → ") + ")"
			}

			switch {
			case res.resolved && rolePriorityOf(res.role) < rolePriorityOf(m.MinRole):
				weaker = append(weaker, fmt.Sprintf(
					"  %s: metadata MinRole=%s but handler enforces only %s — metadata is MORE PERMISSIVE than the handler (CLAUDE.md Admin-UI invariant #2)",
					where, m.MinRole, res.role))

			case !res.resolved && rolePriorityOf(m.MinRole) > rolePriorityOf(RoleViewer):
				unprotected = append(unprotected, fmt.Sprintf(
					"  %s: metadata MinRole=%s but NO handler-level requireRole is reachable on this branch — C2 metadata would be the only gate (CLAUDE.md Admin-UI invariant #6)",
					where, m.MinRole))

			case !res.resolved && strings.TrimSpace(m.Note) == "":
				undeclared = append(undeclared, fmt.Sprintf(
					"  %s: metadata MinRole=%s with no reachable requireRole and no Note declaring the deviation",
					where, m.MinRole))
			}
		}
	}

	// Not-vacuous guard: a selector typo that matched nothing would make every
	// assertion above pass forever. The route table is large and stable; this
	// floor simply proves the walk ran.
	if checked < 100 {
		t.Fatalf("C1.6 resolver examined only %d route/methods — the scan is not seeing uiRoutes (selector drift?)", checked)
	}

	if len(weaker) > 0 {
		t.Errorf("C1.6: %d route/method(s) where metadata is more permissive than the handler:\n%s",
			len(weaker), sortedJoin(weaker))
	}
	if len(unprotected) > 0 {
		t.Errorf("C1.6: %d PRIVILEGED route/method(s) with no reachable handler-level requireRole:\n%s\n"+
			"Add requireRole(w, r, Role…) to the handler (or its per-method delegate). C2 metadata is an additional gate, never a replacement.",
			len(unprotected), sortedJoin(unprotected))
	}
	if len(undeclared) > 0 {
		t.Errorf("C1.6: %d viewer-floor route/method(s) rely solely on uiAuthMiddleware + C2 without declaring it:\n%s\n"+
			"Either add a handler-level requireRole(w, r, RoleViewer), or add a Note to the uiRoutes entry recording the deviation deliberately.",
			len(undeclared), sortedJoin(undeclared))
	}
}

// ── CONTROLS ──────────────────────────────────────────────────────────────
//
// The cheapest way for TestC16_DelegatedHandlersEnforceDeclaredRole to pass is
// for the resolver to stop resolving anything: every route would land in the
// "unresolved" buckets, and the viewer/Note carve-out would swallow them. The
// three controls below pin that (a) delegation following actually works, (b)
// attribution is PER METHOD rather than a whole-body fold, and (c) the gate
// genuinely FIRES on a weakened delegate.

// TestC16_ResolverFollowsDelegation pins that the resolver reaches a role that
// exists ONLY behind a delegate. apiPolicy is a pure `switch r.Method`
// dispatcher whose POST branch calls apiPolicyCreate; only apiPolicyCreate
// calls requireRole(RoleOperator).
func TestC16_ResolverFollowsDelegation(t *testing.T) {
	idx := c16Index(t)

	res := c16Resolve(idx, "apiPolicy", "POST", 0, map[string]bool{})
	if !res.resolved {
		t.Fatal("resolver failed to follow apiPolicy POST → apiPolicyCreate; delegation following is broken and the gate proves nothing")
	}
	if res.viaDirect {
		t.Fatal("apiPolicy POST resolved without following a delegate — the fixture no longer exercises delegation; pick another dispatcher")
	}
	if res.role != RoleOperator {
		t.Fatalf("apiPolicy POST resolved to %q, want %q", res.role, RoleOperator)
	}
}

// TestC16_ResolutionIsPerMethod pins that two branches of ONE dispatcher
// resolve independently. apiMCPToolApprovals delegates GET to a viewer-gated
// lister and POST to an operator-gated creator, so a whole-body fold would
// report viewer for both and silently accept an operator route guarded only by
// a viewer check.
func TestC16_ResolutionIsPerMethod(t *testing.T) {
	idx := c16Index(t)

	get := c16Resolve(idx, "apiMCPToolApprovals", "GET", 0, map[string]bool{})
	post := c16Resolve(idx, "apiMCPToolApprovals", "POST", 0, map[string]bool{})
	if !get.resolved || !post.resolved {
		t.Fatalf("apiMCPToolApprovals did not resolve both branches (GET resolved=%v, POST resolved=%v)", get.resolved, post.resolved)
	}
	if get.role != RoleViewer {
		t.Errorf("apiMCPToolApprovals GET resolved to %q, want %q", get.role, RoleViewer)
	}
	if post.role != RoleOperator {
		t.Errorf("apiMCPToolApprovals POST resolved to %q, want %q", post.role, RoleOperator)
	}
	if get.role == post.role {
		t.Fatal("both branches resolved to the same role — per-method attribution is not actually distinguishing them")
	}
}

// TestC16_GateFiresOnAWeakenedDelegate is the DEFECT PROOF. It builds a
// synthetic dispatcher — one whose POST branch delegates to a helper that
// checks only viewer — and runs the REAL resolver over it, asserting the gate's
// own comparison rejects it against an admin floor. Without this, a resolver
// that silently returned "" for everything would keep the main gate green.
func TestC16_GateFiresOnAWeakenedDelegate(t *testing.T) {
	const src = `package main

import "net/http"

func fixtureDispatcher(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		fixtureRead(w, r)
	case http.MethodPost:
		fixtureWrite(w, r)
	}
}

func fixtureRead(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
}

// fixtureWrite is the DEFECT: a mutating delegate that forgot to raise its
// floor above viewer.
func fixtureWrite(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
}

func fixtureUnguarded(w http.ResponseWriter, r *http.Request) {
	_ = r
	_ = w
}

func fixtureUnguardedDispatcher(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodDelete:
		fixtureUnguarded(w, r)
	}
}
`
	idx := c16ParseFixture(t, src)

	// (a) A weakened delegate must resolve to the WEAK role, so the gate's
	//     "metadata more permissive than handler" comparison trips.
	got := c16Resolve(idx, "fixtureDispatcher", "POST", 0, map[string]bool{})
	if !got.resolved {
		t.Fatal("resolver did not follow fixtureDispatcher POST → fixtureWrite")
	}
	if got.role != RoleViewer {
		t.Fatalf("fixtureDispatcher POST resolved to %q, want %q", got.role, RoleViewer)
	}
	if rolePriorityOf(got.role) >= rolePriorityOf(RoleAdmin) {
		t.Fatal("the gate would NOT flag a viewer-only delegate on an admin route — the comparison is inert")
	}

	// (b) A delegate with no check at all must stay UNRESOLVED, which is what
	//     routes the privileged case into the hard-failure bucket.
	if un := c16Resolve(idx, "fixtureUnguardedDispatcher", "DELETE", 0, map[string]bool{}); un.resolved {
		t.Fatalf("an unguarded delegate resolved to %q; privileged routes would never reach the failure bucket", un.role)
	}

	// (c) A method the switch does not handle must not inherit another
	//     branch's role.
	if x := c16Resolve(idx, "fixtureDispatcher", "DELETE", 0, map[string]bool{}); x.resolved {
		t.Fatalf("unhandled method DELETE inherited role %q from a sibling branch", x.role)
	}
}

// c16ParseFixture parses an in-test source string into the same index shape
// the production scan produces, so the controls exercise the REAL resolver.
func c16ParseFixture(t *testing.T, src string) map[string]*c16Func {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	out := map[string]*c16Func{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil {
			continue
		}
		out[fn.Name.Name] = &c16Func{decl: fn, isHandler: c16HasHandlerSig(fn), file: "fixture.go"}
	}
	return out
}

// c16FoldExemptRoutes is the audited inventory of multi-method routes whose
// handler does NOT use a `switch r.Method`, so C1.6 folds the whole body when
// resolving each method (see KNOWN BOUNDARY above). Each entry records WHY the
// fold is sound for that handler. A new entry must not be added without
// confirming the same property by hand.
var c16FoldExemptRoutes = map[string]string{
	"/api/upstream/entries/": "apiUpstreamEntryRouter takes one requireRole(RoleAdmin) BEFORE branching, so every method it serves is covered by that single guard",
}

// TestC16_WholeBodyFoldInventory keeps C1.6's one soft spot from widening
// silently. A multi-method handler without a `switch r.Method` is resolved by
// folding its whole body, which is only sound when its role guard runs before
// the method branch. That property cannot be read off the AST cheaply, so it is
// audited by hand and pinned here: a NEW such route fails the build until
// somebody confirms the guard really covers every method it declares.
func TestC16_WholeBodyFoldInventory(t *testing.T) {
	idx := c16Index(t)

	var found []string
	for _, rt := range uiRoutes {
		if rt.Public || len(rt.Methods) < 2 {
			continue
		}
		fn := idx[rt.Handler]
		if fn == nil || fn.decl.Body == nil {
			continue
		}
		hasSwitch := false
		for _, st := range fn.decl.Body.List {
			if sw, ok := st.(*ast.SwitchStmt); ok && c16IsMethodSwitch(sw) {
				hasSwitch = true
				break
			}
		}
		if !hasSwitch {
			found = append(found, rt.Path)
		}
	}

	for _, p := range found {
		if _, ok := c16FoldExemptRoutes[p]; !ok {
			t.Errorf("C1.6: %s declares multiple methods but its handler has no `switch r.Method`, so C1.6 folds the whole body when resolving each method.\n"+
				"Confirm by hand that its role guard runs BEFORE any method branching (so every declared method is covered), then add it to c16FoldExemptRoutes with that reason — or give the handler a `switch r.Method` so attribution becomes exact.", p)
		}
	}

	// Reverse parity: a stale exemption is a claim nobody is checking any more.
	inFound := map[string]bool{}
	for _, p := range found {
		inFound[p] = true
	}
	for p := range c16FoldExemptRoutes {
		if !inFound[p] {
			t.Errorf("C1.6: %s is listed in c16FoldExemptRoutes but no longer needs the exemption (its handler now switches on r.Method, or it is no longer a multi-method route) — remove the entry", p)
		}
	}
}

// TestC16_MixedDirectAndDelegatedBranchIsPathAware pins that a direct
// requireRole in a branch does NOT automatically govern the delegates the same
// branch calls. A CONDITIONAL direct check beside a viewer-only or unguarded
// delegate must resolve to the delegate's weak floor (or stay unresolved); an
// UNCONDITIONAL guard ahead of the delegate call still governs it.
func TestC16_MixedDirectAndDelegatedBranchIsPathAware(t *testing.T) {
	const src = `package main

import "net/http"

func fixtureMixedWeak(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if r.URL.Query().Get("x") == "1" {
			if !requireRole(w, r, RoleAdmin) {
				return
			}
			return
		}
		fixtureViewerOnly(w, r)
	}
}

func fixtureMixedUnguarded(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if r.URL.Query().Get("x") == "1" {
			if !requireRole(w, r, RoleAdmin) {
				return
			}
			return
		}
		fixtureNoCheck(w, r)
	}
}

func fixtureMixedDominated(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		fixtureNoCheck(w, r)
	}
}

func fixtureViewerOnly(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
}

func fixtureNoCheck(w http.ResponseWriter, r *http.Request) {
	_ = r
	_ = w
}
`
	idx := c16ParseFixture(t, src)

	weak := c16Resolve(idx, "fixtureMixedWeak", "POST", 0, map[string]bool{})
	if !weak.resolved || weak.role != RoleViewer {
		t.Fatalf("conditional admin check + viewer-only delegate resolved to (%v, %q), want (true, %q) — the direct check hid the weak delegated path",
			weak.resolved, weak.role, RoleViewer)
	}
	if un := c16Resolve(idx, "fixtureMixedUnguarded", "POST", 0, map[string]bool{}); un.resolved {
		t.Fatalf("conditional admin check + unguarded delegate resolved to %q; it must stay unresolved so a privileged route fails", un.role)
	}
	dom := c16Resolve(idx, "fixtureMixedDominated", "POST", 0, map[string]bool{})
	if !dom.resolved || dom.role != RoleAdmin {
		t.Fatalf("an unconditional admin guard ahead of the delegate resolved to (%v, %q), want (true, %q)", dom.resolved, dom.role, RoleAdmin)
	}
}
