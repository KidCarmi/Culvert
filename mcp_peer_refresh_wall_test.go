package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The provenance walls (blocker 11, §11).
//
// Provenance is only as trustworthy as the set of callers that can create it. The catalog makes
// it structurally impossible for a record to CLAIM peer evidence it does not carry, but nothing
// in the type system stops a future caller from handing IngestObserved a fabricated observation,
// or from reaching Discover down some path that never dialed anybody. These walls pin the caller
// sets instead.
//
// Every wall here is ANTI-VACUOUS BY CONSTRUCTION: each one requires its legitimate caller to be
// FOUND, and fails if the scan matches nothing. A scan that matches zero callers proves nothing
// at all — it is the exact shape of a gate that has quietly stopped reading the tree it claims to
// check — so "no matches" is a failure, never a pass.

// callSite is one production call of interest: the function that encloses it and where it is.
type callSite struct {
	File string
	Func string
	Line int
}

func (c callSite) String() string { return c.File + ":" + c.Func }

// findCallsites returns every production REFERENCE to a method named sel, with the enclosing
// function — not merely every call of it.
//
// The distinction is the whole gate (Codex round 8, P1 — verified as a real bypass before it was
// agreed with). A method VALUE is not a call: in
//
//	mint := cat.IngestObserved
//	mint(reg, in, obs)
//
// the selector is not the Fun of a CallExpr and the call is through a plain identifier, so a
// scan anchored on call position sees NEITHER statement while the legitimate direct call from
// Discovery.Discover keeps the expected-caller set satisfied. That path can supply current pin
// data, peer-shaped bytes and a timestamp without dialing anything — minting a fresh
// PeerObserved record with the wall green.
//
// Matching the SELECTOR wherever it appears closes the class rather than that one shape: a
// caller cannot use a method without naming it, so every call, method value, and any future
// syntactic form that reaches it must pass through this scan. It is deliberately BROADER than
// calls — a bare mention with no invocation is reported too, and that is the safe direction:
// naming the observed-ingest capability at all is what has to be justified.
//
// It does NOT reach reflection (reflect.Value.MethodByName and friends), which resolves the
// method from a string at runtime with no selector in the source. That is recorded as a limit,
// not papered over; nothing in this tree does it, and a gate that cannot see a construct should
// say so rather than imply coverage it does not have.
func findCallsites(t *testing.T, sel string) []callSite {
	t.Helper()
	var sites []callSite
	for _, path := range productionGoFiles(t) {
		src, err := os.ReadFile(path) //nolint:gosec // repo-local walk, not caller input
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		found, perr := referencesInSource(filepath.ToSlash(path), string(src), sel)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		sites = append(sites, found...)
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].String() < sites[j].String() })
	return sites
}

// referencesInSource is the per-file half of findCallsites, split out so the predicate can be
// driven against synthetic sources.
//
// A wall that can only be run over the real tree can only be shown to PASS, never shown to catch
// anything — the failure mode every gate in this PR has had at least once. With this seam a
// control can hand it the exact shapes it must reject, including ones no file in the tree has.
func referencesInSource(rel, src, sel string) ([]callSite, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, 0)
	if err != nil {
		return nil, err
	}
	var sites []callSite
	// Attribute each reference to the declaration it is INSIDE, by walking the declarations
	// themselves — never by carrying a running "last function seen" across the file.
	//
	// Codex round 9, P1, verified before it was agreed with: the running-variable form never reset
	// after leaving a FuncDecl, so a package-level alias declared after the allowed function
	//
	//	func (d *Discovery) Discover() { … }
	//	var mint = (*catalog.Catalog).IngestObserved
	//
	// was attributed to Discovery.Discover — the exact key on the reasoned list — and any other
	// function could then call mint(…) producing no selector at all. Measured: the alias reported
	// as "internal/mcp/execution/discovery.go:Discovery.Discover", so the wall stayed green.
	//
	// A package-scope reference is attributed to a sentinel that is deliberately impossible to put
	// on the reasoned list, so it is always reported. That is not a gap in the model: an alias to
	// the observed-ingest capability held in package scope is reachable from every function in the
	// package at once, which is precisely the thing a per-caller wall cannot certify.
	outer := fileOuterNames(file)
	for _, decl := range file.Decls {
		sc := &refScope{fset: fset, rel: rel, sel: sel, outer: outer, local: declLocalNames(decl)}
		collectSelectorRefs(sc, decl, declEnclosingName(decl), false, &sites)
	}
	return sites, nil
}

// declEnclosingName names the declaration a reference sits in, for the reasoned-caller list.
func declEnclosingName(decl ast.Decl) string {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok {
		return packageScopeCaller
	}
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		return recvTypeName(fn.Recv) + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// collectSelectorRefs appends every reference to sel under n, attributed to enclosing — or to the
// parameterised-closure sentinel once the walk is inside a function literal that takes parameters.
//
// It carries its own scope stack because ast.Inspect has none: the walk must know whether the node
// it is looking at is reachable with caller-supplied data, and that is a property of the ancestors,
// not of the node.
func collectSelectorRefs(sc *refScope, n ast.Node, enclosing string, inParamClosure bool, sites *[]callSite) {
	if n == nil {
		return
	}
	if lit, ok := n.(*ast.FuncLit); ok {
		if lit.Type.Params != nil && len(lit.Type.Params.List) > 0 {
			inParamClosure = true
		}
		for _, st := range lit.Body.List {
			collectSelectorRefs(sc, st, enclosing, inParamClosure, sites)
		}
		return
	}
	if call, ok := n.(*ast.CallExpr); ok {
		if ref, isSel := call.Fun.(*ast.SelectorExpr); isSel && ref.Sel.Name == sc.sel {
			*sites = append(*sites, sc.site(ref, enclosing, inParamClosure, call.Args))
			for _, a := range call.Args {
				collectSelectorRefs(sc, a, enclosing, inParamClosure, sites)
			}
			return
		}
	}
	if ref, ok := n.(*ast.SelectorExpr); ok && ref.Sel.Name == sc.sel {
		*sites = append(*sites, sc.site(ref, enclosing, inParamClosure, nil))
	}
	ast.Inspect(n, func(c ast.Node) bool {
		if c == n {
			return true
		}
		collectSelectorRefs(sc, c, enclosing, inParamClosure, sites)
		return false
	})
}

// refScope carries what attribution needs beyond the node itself: the names that are local to the
// declaration being walked, and the names the file legitimately reaches outside it (imports and
// builtins).
type refScope struct {
	fset  *token.FileSet
	rel   string
	sel   string
	outer map[string]bool
	local map[string]bool
}

// site attributes one reference, downgrading it to a sentinel when the reference is reachable with
// data the enclosing declaration does not control.
func (sc *refScope) site(ref *ast.SelectorExpr, enclosing string, inParamClosure bool, args []ast.Expr) callSite {
	who := enclosing
	switch {
	case inParamClosure:
		who = parameterisedClosureCaller
	case sc.argsEscapeDecl(args):
		who = callerMutableInputCaller
	}
	return callSite{File: sc.rel, Func: who, Line: sc.fset.Position(ref.Sel.Pos()).Line}
}

// argsEscapeDecl reports whether any value reaching the call comes from outside the declaration.
//
// Codex round 12, P1, verified before it was agreed with. Round 11 refused a PARAMETERISED closure
// because its caller chooses the inputs — and that was necessary, not sufficient. A ZERO-argument
// closure reads whatever it captures, so if it captures a package-level variable, a later holder
// sets that variable and then invokes it. Same outcome, no parameters:
//
//	var fabricatedRaw []byte
//	escaped = func() { d.Catalog.IngestObserved(d.Registry, DiscoveryInput{Raw: fabricatedRaw}, …) }
//
// Measured: still attributed to Discovery.Discover.
//
// So the rule stops asking about the closure and asks about the DATA. Every root identifier in the
// call's arguments must be something the declaration controls — its receiver, a parameter, a named
// result, or a local it declared — or a name the file legitimately reaches that is not a mutable
// value: an imported package qualifier or a builtin. A package-level variable is none of those.
//
// Production satisfies it: the arguments are d (receiver) plus rec, resp and observedAt, all
// locals assigned from the authenticated dial, under catalog.* type qualifiers.
func (sc *refScope) argsEscapeDecl(args []ast.Expr) bool {
	escapes := false
	for _, a := range args {
		walkValueRoots(a, func(id *ast.Ident) {
			if id.Name == "_" || sc.local[id.Name] || sc.outer[id.Name] {
				return
			}
			escapes = true
		})
	}
	return escapes
}

// walkValueRoots calls fn for every identifier that names a VALUE reaching e.
//
// The two skips are what make it mean that. A selector's right-hand side is a FIELD name, not a
// value in scope (rec.ID names a field of rec, and only rec can be a package variable), so the
// walk descends the chain to its leftmost identifier and stops. A composite-literal key is a field
// name for the same reason, so only its value is walked. Without both, production is rejected:
// every field name in DiscoveryInput{ServerID: rec.ID, …} reads as an unresolvable root, which is
// how the first version of this rule failed — the wall refused the real tree, which is exactly the
// direction a gate must not err in silently.
func walkValueRoots(e ast.Node, fn func(*ast.Ident)) {
	switch v := e.(type) {
	case nil:
		return
	case *ast.Ident:
		fn(v)
		return
	case *ast.SelectorExpr:
		walkValueRoots(v.X, fn)
		return
	case *ast.KeyValueExpr:
		walkValueRoots(v.Value, fn)
		return
	}
	ast.Inspect(e, func(c ast.Node) bool {
		if c == e || c == nil {
			return c == e
		}
		walkValueRoots(c, fn)
		return false
	})
}

// fileOuterNames collects the names a file may legitimately reach outside a declaration WITHOUT
// them being mutable values: imported package qualifiers and Go's builtins. Everything else at
// package scope is a var, func or const that other code can change or shadow.
func fileOuterNames(f *ast.File) map[string]bool {
	out := map[string]bool{}
	for _, name := range []string{
		"append", "cap", "clear", "close", "complex", "copy", "delete", "imag", "len", "make",
		"max", "min", "new", "panic", "print", "println", "real", "recover",
		"bool", "byte", "complex64", "complex128", "error", "float32", "float64", "int", "int8",
		"int16", "int32", "int64", "rune", "string", "uint", "uint8", "uint16", "uint32",
		"uint64", "uintptr", "any", "true", "false", "iota", "nil",
	} {
		out[name] = true
	}
	for _, imp := range f.Imports {
		if imp.Name != nil {
			out[imp.Name.Name] = true
			continue
		}
		path := strings.Trim(imp.Path.Value, `"`)
		if i := strings.LastIndex(path, "/"); i >= 0 {
			path = path[i+1:]
		}
		out[path] = true
	}
	return out
}

// declLocalNames collects every name a declaration controls: its receiver, parameters, named
// results, and anything it declares in its body — including inside nested closures, since a
// closure's own locals are equally beyond a later caller's reach.
func declLocalNames(decl ast.Decl) map[string]bool {
	out := map[string]bool{}
	fn, ok := decl.(*ast.FuncDecl)
	if !ok {
		return out
	}
	addFieldNames(out, fn.Recv)
	if fn.Type != nil {
		addFieldNames(out, fn.Type.Params)
		addFieldNames(out, fn.Type.Results)
	}
	if fn.Body == nil {
		return out
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			if v.Tok == token.DEFINE {
				addIdentNames(out, v.Lhs)
			}
		case *ast.ValueSpec:
			for _, id := range v.Names {
				out[id.Name] = true
			}
		case *ast.RangeStmt:
			addIdentNames(out, []ast.Expr{v.Key, v.Value})
		case *ast.FuncLit:
			if v.Type != nil {
				addFieldNames(out, v.Type.Params)
				addFieldNames(out, v.Type.Results)
			}
		}
		return true
	})
	return out
}

func addFieldNames(out map[string]bool, fl *ast.FieldList) {
	if fl == nil {
		return
	}
	for _, f := range fl.List {
		for _, id := range f.Names {
			out[id.Name] = true
		}
	}
}

func addIdentNames(out map[string]bool, exprs []ast.Expr) {
	for _, e := range exprs {
		if id, ok := e.(*ast.Ident); ok {
			out[id.Name] = true
		}
	}
}

// callerMutableInputCaller names a reference whose arguments reach outside the declaration for a
// mutable value — a package-level variable a later holder can set before invoking an escaped
// closure. It cannot be spelled on a reasoned-caller list.
const callerMutableInputCaller = "<caller-mutable input>"

// packageScopeCaller names a reference that is not inside any function declaration. It contains
// characters no Go identifier can, so it can never be spelled on a reasoned-caller list.
const packageScopeCaller = "<package scope>"

// parameterisedClosureCaller names a reference inside a function literal that TAKES PARAMETERS.
//
// Codex round 11, P1, verified before it was agreed with. A closure is not a scope boundary the
// way a declaration is: it can be stored, registered or handed to an injected dependency, and a
// reference inside one was attributed to the FuncDecl containing it — the allowed caller. A later
// holder could then invoke it with FABRICATED discovery bytes and a current timestamp, minting a
// fresh PeerObserved record while producing no selector of its own.
//
// What makes that dangerous is not the escape, it is WHERE THE DATA COMES FROM. Production's
// closure takes NO parameters:
//
//	ingest := func() error { … d.Catalog.IngestObserved(d.Registry, DiscoveryInput{Raw: resp.Result}, …) }
//
// Everything it feeds the catalog is CAPTURED from the authenticated dial — the verified pin, the
// response bytes, and an observedAt stamped before the request went out. It is deliberately handed
// to d.IngestGuard so the publish serialises with in-flight approvals, so it DOES escape; and that
// is safe, because a holder can only re-run it. Replaying it re-ingests the same authenticated
// bytes with the same (by then older) timestamp, which the freshness bound then refuses — the
// failure is closed.
//
// A closure that takes its inputs as PARAMETERS is the opposite: the caller chooses them. That is
// the whole finding, and it is the line this sentinel draws. The rule states the property directly
// rather than inferring it from where the closure ends up, which is the round-10 lesson applied to
// a capability instead of a value: a reference reachable with caller-supplied data is not bounded
// by the function it is written in, whatever that function is called.
const parameterisedClosureCaller = "<parameterised closure>"

// assertExactCallers is the shared wall body. want is the exact set of "file:Func" sites allowed
// to make this call in production.
func assertExactCallers(t *testing.T, sel string, want map[string]string) {
	t.Helper()
	sites := findCallsites(t, sel)
	if len(sites) == 0 {
		t.Fatalf("no production call to %s was found anywhere. Either the production path was "+
			"deleted or this scan has stopped matching it; both mean this wall now proves "+
			"nothing. A scan matching zero callers is not proof.", sel)
	}
	seen := map[string]bool{}
	for _, s := range sites {
		key := s.String()
		reason, allowed := want[key]
		if !allowed {
			t.Errorf("%s:%d references %s, and that caller is not on the reasoned list.\n"+
				"Peer provenance is only as trustworthy as the set of callers that can create "+
				"it. If this is a legitimate production path, add it here WITH the argument for "+
				"why its evidence is real.", s.File, s.Line, sel)
			continue
		}
		_ = reason
		seen[key] = true
	}
	for key := range want {
		if !seen[key] {
			t.Errorf("the wall expects %s to reference %s, and it does not. If the production path "+
				"moved, move this entry with it; if it was removed, blocker 11's evidence path "+
				"is gone and this gate must fail rather than be relaxed.", key, sel)
		}
	}
}

// TestPeerWall_ObservedIngestHasExactlyOneProducer pins WHO may mint peer evidence.
//
// catalog.IngestObserved is the only way a PeerObservation is ever attached to a record, so the
// set of its production callers IS the set of things the rest of the system trusts to have
// actually dialed a peer. Discovery.Discover earns it by doing exactly that; anything else
// appearing here would be asserting evidence rather than gathering it.
func TestPeerWall_ObservedIngestHasExactlyOneProducer(t *testing.T) {
	assertExactCallers(t, "IngestObserved", map[string]string{
		"internal/mcp/execution/discovery.go:Discovery.Discover": "" +
			"Discover has already resolved the server from the authoritative registry, refused a " +
			"server with no pinned identity, and completed a call over the authenticated " +
			"transport — so the identity it stamps was VERIFIED on the wire, not copied from " +
			"config or read out of the peer's payload.",
	})
}

// TestPeerWall_DiscoverHasExactlyOneProductionCaller is the §7 anti-vacuity gate, and it is the
// one that fails on the defect this whole change exists to close: before it, Discover had NO
// non-test caller, so the catalog could only ever hold what the operator declared.
//
// It therefore fails in BOTH directions — an unreasoned new caller, and the legitimate one
// disappearing. The second is the important one: if the governed refresh path is deleted or
// renamed, peer-observed freshness becomes unreachable in production while every other gate here
// would still pass, because each of them only ever says what must NOT happen.
func TestPeerWall_DiscoverHasExactlyOneProductionCaller(t *testing.T) {
	assertExactCallers(t, "Discover", map[string]string{
		"mcp_peer_refresh.go:mcpRefreshPeerObservation": "" +
			"The governed operator refresh (§7). It takes a ServerID and nothing else, resolves " +
			"endpoint and pin from the authoritative registry, holds no activation or rollout " +
			"lock across the dial, and confers no execution authority.",
	})
}

// TestPeerWall_SeedReachesOnlyTheSeededEntrypoint is the other half: the operator provisioning
// path must never touch the observed entrypoint.
//
// seedTools synthesizes a tools/list from operator JSON, which is deliberately shaped exactly
// like a real one. That shape is why the entrypoints exist — the bytes cannot tell you where
// they came from — and why this wall checks the CALL rather than inspecting the data.
func TestPeerWall_SeedReachesOnlyTheSeededEntrypoint(t *testing.T) {
	assertExactCallers(t, "Ingest", map[string]string{
		"mcp_inventory.go:seedTools": "" +
			"Operator-declared provisioning. It has dialed nobody, so it must produce records " +
			"with no observation — which is exactly what the seeded entrypoint does.",
	})

	// And the converse, stated explicitly rather than left to be inferred from the map above:
	// nothing in the inventory/provisioning file may reach the observed entrypoint.
	for _, s := range findCallsites(t, "IngestObserved") {
		if strings.HasPrefix(s.File, "mcp_inventory.go") {
			t.Errorf("%s:%d — the operator provisioning path must never mint peer evidence.", s.File, s.Line)
		}
	}
}

// TestPeerWall_RefreshIsIndependentOfActivation pins §3 structurally: a refresh is an
// observation, and observation is not authority.
//
// The check is by IDENTIFIER REACH rather than by behaviour, because the behavioural version can
// only ever test the paths someone thought to drive. If the refresh engine cannot even NAME the
// arming, activation, rollout, approval, promotion or budget machinery, it cannot invoke it by
// any interleaving — including ones no test enumerates.
func TestPeerWall_RefreshIsIndependentOfActivation(t *testing.T) {
	path := filepath.Join(pkgSourceDir(), "mcp_peer_refresh.go")
	src, err := os.ReadFile(path) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	fset := token.NewFileSet()
	file, perr := parser.ParseFile(fset, path, src, 0)
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	// Identifiers that would mean the refresh had reached into execution authority.
	forbidden := map[string]string{
		"armLiveTier":              "arming the live tier",
		"beginCanaryActivation":    "beginning a Canary generation",
		"reserveCanaryExecution":   "reserving Canary budget",
		"markGatewayExecDepsReady": "marking execution dependencies ready",
		"ApproveLive":              "issuing a live approval",
		"Promote":                  "promoting a tool",
		"Demote":                   "demoting a tool",
	}
	checked := 0
	ast.Inspect(file, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		checked++
		if what, bad := forbidden[id.Name]; bad {
			t.Errorf("mcp_peer_refresh.go names %q (%s). A refresh supplies TRUTH about what the "+
				"peer advertises and must confer no authority; an operator has to be able to "+
				"observe a peer while the node is Observe, Shadow or composed-but-unarmed.",
				id.Name, what)
		}
		return true
	})
	if checked == 0 {
		t.Fatal("inspected no identifiers — this wall is passing by seeing nothing")
	}
}

// TestPeerWall_NoNetworkCallUnderAnActivationLock pins §4 structurally.
//
// The dial must not happen inside an activation, rollout or durable-state critical section: a
// hung peer would otherwise stall an in-flight approval or a rollout transition for the whole
// upstream budget. The single-flight registration is taken and released BEFORE the dial, and the
// only lock the response meets is the ingest guard's, which serializes the catalog publish after
// the bytes have already arrived.
//
// The wall is a reach check for the same reason as the one above: mcp_peer_refresh.go must not be
// able to name the locks at all, so no ordering of its statements can put one around the network.
func TestPeerWall_NoNetworkCallUnderAnActivationLock(t *testing.T) {
	path := filepath.Join(pkgSourceDir(), "mcp_peer_refresh.go")
	src, err := os.ReadFile(path) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	text := string(src)
	for _, lock := range []string{"durableMu", "cr.mu", "deriveMu", "globalMCPRollout", "globalMCPLive"} {
		if strings.Contains(text, lock) {
			t.Errorf("mcp_peer_refresh.go names %q. No network I/O may happen under an "+
				"activation, rollout or durable-state lock; a hung peer would hold it for the "+
				"whole upstream budget.", lock)
		}
	}
	// Anti-vacuity: the file must actually contain the dial this wall is about, or it is
	// asserting the absence of locks around nothing.
	if !strings.Contains(text, "d.Discover(") {
		t.Fatal("mcp_peer_refresh.go no longer performs the discovery dial — this wall now " +
			"guards nothing. Move it with the code or delete it.")
	}
}

// TestPeerWall_ReferenceScanIsNotVacuous is the CONTROL for the provenance walls above.
//
// Those walls can only ever report that the tree contains no unreasoned caller. That is exactly
// what a scan matching nothing also reports, so on its own it is not evidence — and this is not
// hypothetical: the version that anchored on call position missed a method VALUE, and a
// production function minting a PeerObserved record through one passed the wall untouched
// (Codex round 8, P1; measured against the real tree before the fix).
//
// Each shape below must be FOUND, including the four that are not calls at all — a method value
// is how the capability escapes without ever appearing in call position, and reporting a bare
// reference is deliberate: naming the observed-ingest capability is itself what has to be
// justified, and the reasoned list is where that justification lives.
//
// The last case is the acceptance half. A scan that flagged every selector would satisfy every
// "is found" assertion above while making the reasoned list meaningless, so it must stay keyed on
// the exact name and leave an unrelated one alone.
func TestPeerWall_ReferenceScanIsNotVacuous(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"direct call", `package p
func f(c C) { c.IngestObserved(nil, nil, nil) }`},
		{"method value, then called through it", `package p
func f(c C) {
	mint := c.IngestObserved
	mint(nil, nil, nil)
}`},
		{"method value passed as an argument", `package p
func f(c C) { register(c.IngestObserved) }`},
		{"method value stored on a struct field", `package p
func f(c C) { h := holder{fn: c.IngestObserved}; _ = h }`},
		{"method value returned", `package p
func f(c C) func() { return func() { c.IngestObserved(nil, nil, nil) } }`},
		// Codex round 12, P1. A ZERO-argument closure, so round 11's rule does not fire — but it
		// reads PACKAGE-LEVEL variables a later holder sets before invoking it. Same outcome, no
		// parameters. This is the case that moved the rule from the closure to the DATA.
		{"zero-arg closure reading mutable package variables", `package p

var fabricatedRaw []byte
var fabricatedAt int64
var escaped func()

func (d *Discovery) Discover() {
	escaped = func() {
		d.Catalog.IngestObserved(d.Registry, DiscoveryInput{Raw: fabricatedRaw}, PeerObservation{At: fabricatedAt})
	}
}

func evil() { fabricatedRaw = []byte("{}"); fabricatedAt = 99; escaped() }`},
		// Codex round 11, P1. The capability is captured in a PARAMETERISED closure that is then
		// registered, so a later holder supplies the discovery bytes. Attribution used to name the
		// FuncDecl containing the closure — the allowed caller.
		{"capability escapes in a parameterised closure", `package p

var registry []func(interface{}, interface{}, interface{})

func (d *Discovery) Discover() {
	mint := func(reg, in, obs interface{}) {
		d.Catalog.IngestObserved(reg, in, obs)
	}
	registry = append(registry, mint)
}

func evil() { registry[0](nil, nil, nil) }`},
		// Codex round 9, P1. The alias sits in PACKAGE scope, after the allowed function, and the
		// running-variable form attributed it to that function.
		{"package-scope alias after the allowed function", `package p
func (d *Discovery) Discover() {}

var mint = (*catalog.Catalog).IngestObserved

func evil() { mint(nil, nil, nil) }`},
	} {
		got, err := referencesInSource("synth.go", c.src, "IngestObserved")
		if err != nil {
			t.Fatalf("%s: parse: %v", c.name, err)
		}
		if len(got) == 0 {
			t.Errorf("the provenance scan must find %q; it found nothing. A shape it cannot see "+
				"is a shape that can mint peer evidence with this wall green.", c.name)
			continue
		}
		// FINDING IT IS NOT ENOUGH — it must be attributed to the right caller. A reference
		// misattributed to a function that IS on the reasoned list is reported and then waved
		// through, which is indistinguishable from not finding it at all.
		for _, site := range got {
			if site.Func == "Discover" || site.Func == "Discovery.Discover" {
				if c.name != "direct call" {
					t.Errorf("%q was attributed to %q — the allowed caller — so the wall would "+
						"accept it. Attribution must follow the declaration the reference is "+
						"inside.", c.name, site.Func)
				}
			}
		}
	}
	// And it must NOT fire on an unrelated name, or every file in the tree would be a hit and the
	// reasoned list would be meaningless.
	quiet := `package p
func f(c C) { c.Ingest(nil, nil) }`
	if got, err := referencesInSource("synth.go", quiet, "IngestObserved"); err != nil {
		t.Fatalf("parse: %v", err)
	} else if len(got) != 0 {
		t.Errorf("the scan matched %d unrelated selector(s); it must key on the exact name", len(got))
	}
}
