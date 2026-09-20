package main

// mcp_canary_physical_effect_test.go — composition-layer gates for the First
// Controlled Canary physical-effect contract (review blockers #6/#8).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// TestCanaryPath_ProductionUpstreamClientIsRetryFree is the blocker-#6 closure gate
// at the composition layer. Transport SUPPORT for retry-freedom is not enough: the
// client the live tier actually uses must be constructed retry-free, or one
// accepted reservation can still cause several physical tool invocations.
func TestCanaryPath_ProductionUpstreamClientIsRetryFree(t *testing.T) {
	lim, err := upstreamclient.RetryFreeLimits(upstreamclient.LimitConfig{})
	if err != nil {
		t.Fatalf("RetryFreeLimits: %v", err)
	}
	if !lim.RetriesDisabled() {
		t.Fatal("the First-Canary limits must disable transport retries")
	}
	if got := lim.MaxReadRetries(); got != 0 {
		t.Fatalf("retry-free limits must carry a zero retry budget, got %d", got)
	}
	// The production client must construct successfully from exactly these limits —
	// a construction failure here would silently push the live tier back onto the
	// defaults.
	if _, err := newProductionUpstreamClient(); err != nil {
		t.Fatalf("production upstream client must construct: %v", err)
	}
}

// TestNonCanaryBehaviorUnchanged is the CONTROL for blocker #6: making the Canary
// path retry-free must not remove retries from anything else. If this ever fails,
// the change stopped being scoped to the Canary.
func TestNonCanaryBehaviorUnchanged(t *testing.T) {
	def := upstreamclient.DefaultLimits()
	if def.RetriesDisabled() {
		t.Fatal("default limits must still retry — non-Canary behavior is unchanged")
	}
	if def.MaxReadRetries() == 0 {
		t.Fatal("default limits must still carry a non-zero retry budget")
	}
}

// TestCanaryGate_MintsReservationIdentity pins that a granted admission names both
// the slot that paid for the effect and the activation generation it belongs to.
// Without them a physical effect cannot be attributed to an authorized reservation,
// and an orphan from a superseded generation cannot be recognized after a restart.
func TestCanaryGate_MintsReservationIdentity(t *testing.T) {
	seen := make(map[string]struct{}, 256)
	for i := 0; i < 256; i++ {
		id, err := newCanaryReservationID()
		if err != nil {
			t.Fatalf("newCanaryReservationID: %v", err)
		}
		if len(id) != 4+2*canaryReservationIDBytes {
			t.Fatalf("unbounded reservation id: %q", id)
		}
		if id[:4] != "rsv_" {
			t.Fatalf("reservation id must be self-describing, got %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("reservation id collision at %d: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}

// ── the production constructor must BE the shape, not merely resemble one ───────────────────

// TestCanaryPath_ProductionUpstreamClientIsBuiltFromRetryFreeLimits closes a vacuity in the gate
// above, found while verifying blocker #11's runtime invariant.
//
// THE GAP. TestCanaryPath_ProductionUpstreamClientIsRetryFree asserts two things: that
// RetryFreeLimits returns retry-free limits, and that newProductionUpstreamClient constructs
// without error. Neither reaches the property its own doc comment names — that the client the
// live tier actually uses is built retry-free. Swapping RetryFreeLimits for NewLimits inside
// newProductionUpstreamClient reintroduces transport retries AND redirects, and that gate still
// passes; so does every other test in the canary and peer-freshness families (measured). The E2E
// proofs cannot catch it either, because realUpstreamFor rebuilds the shape locally with its own
// RetryFreeLimits call — they prove properties of a REPLICA of the production client, not of the
// production constructor.
//
// WHY IT IS LOAD-BEARING, AND FOR TWO BLOCKERS. Blocker #6 is "one accepted reservation, at most
// one physical invocation" — retries and redirects each defeat it, and upstreamclient's own
// limits.go records that a redirect is "a retry by another name" (a 307/308 replays the POST body
// carrying the SAME AttemptID, so no witness could tell the two invocations apart). Blocker #11's
// runtime half then RESTS on that: the claim that nothing unbounded sits between the last
// peer-freshness re-ask and the first request byte holds because there is exactly ONE physical
// send. PreSend is re-asked per leg and the TLS dialer site reaches every leg — but a redirect to
// the SAME approved host can reuse a pooled connection, so it would not re-enter the dialer, and
// the peer chooses when its 3xx arrives. With redirects forced off that is unreachable.
//
// IT FOLLOWS THE VALUE, NOT THE NAMES, AND THE FIRST VERSION DID NOT. That version required the
// body to mention RetryFreeLimits and to mention no other limits constructor. It killed the
// obvious mutation and was still bypassable: keep the RetryFreeLimits call, then assign over its
// result from a local helper the deny-set cannot name (measured — the bypass PASSED). A deny-list
// of spellings can always be evaded by a new spelling, which is the same defect class this gate
// exists to close, one level up. So the check now starts at the Limits field of the
// upstreamclient.Config literal the constructor actually returns, takes the identifier bound
// there, and requires that identifier to be bound EXACTLY ONCE in the function, by a call to
// RetryFreeLimits on the upstreamclient package — resolved through the file's own import alias,
// so renaming the import cannot silently retire the gate either.
//
// WHY STRUCTURAL: production code cannot be driven against the controlled peer
// (DefaultGatewayPolicy refuses loopback, which is why the E2E relaxes exactly that knob), so
// behaviour cannot reach this constructor. The chain, each link gated somewhere: this wall pins
// that the constructor's limits come from RetryFreeLimits; RetryFreeLimits FORCES MaxRedirects=0
// and RetryDisabled (the gate above, and internal/mcp/upstreamclient/limits.go); and the client
// honours both (internal/mcp/upstreamclient/retryfree_test.go and the HTTPS E2E).
func TestCanaryPath_ProductionUpstreamClientIsBuiltFromRetryFreeLimits(t *testing.T) {
	const path = "mcp_live_production_deps.go"
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if why := retryFreeLimitsViolation(string(src)); why != "" {
		t.Fatalf("newProductionUpstreamClient must take the limits it passes to upstreamclient.Config "+
			"from upstreamclient.RetryFreeLimits, and must not rebind them: %s.\n\nA client built from "+
			"any other limits carries transport retries AND redirects, so one accepted reservation can "+
			"cause several physical tool invocations (blocker #6) and a peer-chosen 3xx can put a second "+
			"send after the last peer-freshness re-ask on a pooled connection (blocker #11).", why)
	}
}

// TestCanaryPath_RetryFreeWallIsNotVacuous is the CONTROL for the wall above.
//
// A selector that matched nothing would pass forever, which is the failure mode the wall exists to
// remove. Each case below is a way the constructor could stop being retry-free; every one must be
// REJECTED. The last two are not hypothetical — they are the bypasses that defeated the first
// version of this wall, kept here so the weaker predicate cannot come back.
func TestCanaryPath_RetryFreeWallIsNotVacuous(t *testing.T) {
	for _, bad := range []struct{ name, body string }{
		{"NewLimits instead", `lim, _ := upstreamclient.NewLimits(upstreamclient.LimitConfig{})
	return upstreamclient.New(upstreamclient.Config{Limits: lim}, limits.DefaultGateway())`},
		{"DefaultLimits instead", `lim := upstreamclient.DefaultLimits()
	return upstreamclient.New(upstreamclient.Config{Limits: lim}, limits.DefaultGateway())`},
		{"retry-free called, result overwritten", `lim, _ := upstreamclient.RetryFreeLimits(upstreamclient.LimitConfig{})
	lim = upstreamclient.DefaultLimits()
	return upstreamclient.New(upstreamclient.Config{Limits: lim}, limits.DefaultGateway())`},
		{"retry-free called, result replaced via an indirection", `lim, _ := upstreamclient.RetryFreeLimits(upstreamclient.LimitConfig{})
	lim = tunedUpstreamLimits()
	return upstreamclient.New(upstreamclient.Config{Limits: lim}, limits.DefaultGateway())`},
		{"retry-free called but a different value is passed", `lim, _ := upstreamclient.RetryFreeLimits(upstreamclient.LimitConfig{})
	_ = lim
	other := tunedUpstreamLimits()
	return upstreamclient.New(upstreamclient.Config{Limits: other}, limits.DefaultGateway())`},
		{"limits inlined from a helper", `return upstreamclient.New(upstreamclient.Config{Limits: tunedUpstreamLimits()}, limits.DefaultGateway())`},
		// The two below were found by probing this predicate, not by review. Both PASSED the
		// version that took the first Config literal and counted only Ident assignments.
		{"a decoy Config literal captures the check", `lim, _ := upstreamclient.RetryFreeLimits(upstreamclient.LimitConfig{})
	_ = upstreamclient.Config{Limits: lim}
	return upstreamclient.New(upstreamclient.Config{Limits: tunedUpstreamLimits()}, limits.DefaultGateway())`},
		{"value replaced through a pointer alias", `lim, _ := upstreamclient.RetryFreeLimits(upstreamclient.LimitConfig{})
	p := &lim
	*p = tunedUpstreamLimits()
	return upstreamclient.New(upstreamclient.Config{Limits: lim}, limits.DefaultGateway())`},
		{"Config assembled across statements", `lim, _ := upstreamclient.RetryFreeLimits(upstreamclient.LimitConfig{})
	_ = lim
	cfg := upstreamclient.Config{}
	cfg.Limits = tunedUpstreamLimits()
	return upstreamclient.New(cfg, limits.DefaultGateway())`},
		{"limits carried on a struct field", `lim, _ := upstreamclient.RetryFreeLimits(upstreamclient.LimitConfig{})
	_ = lim
	h := holder{lim: tunedUpstreamLimits()}
	return upstreamclient.New(upstreamclient.Config{Limits: h.lim}, limits.DefaultGateway())`},
	} {
		if why := retryFreeLimitsViolation(synthProductionDeps(bad.body)); why == "" {
			t.Fatalf("the retry-free wall must reject %q; it accepted it", bad.name)
		}
	}
	// It must ACCEPT the real shape, and the aliased-import form, or it is unfalsifiable the other
	// way: a wall nothing can satisfy gets deleted by the next person who touches the file.
	good := `lim, lerr := upstreamclient.RetryFreeLimits(upstreamclient.LimitConfig{})
	if lerr != nil {
		return nil, lerr
	}
	return upstreamclient.New(upstreamclient.Config{Limits: lim}, limits.DefaultGateway())`
	if why := retryFreeLimitsViolation(synthProductionDeps(good)); why != "" {
		t.Fatalf("the retry-free wall must accept the production form, rejected: %s", why)
	}
	aliased := strings.ReplaceAll(good, "upstreamclient.", "uc.")
	src := strings.Replace(synthProductionDeps(aliased),
		`"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"`,
		`uc "github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"`, 1)
	if why := retryFreeLimitsViolation(src); why != "" {
		t.Fatalf("the retry-free wall must follow the file's import alias, rejected: %s", why)
	}
}

// synthProductionDeps wraps a function body in a minimal file shaped like the real one, so the
// control exercises the SAME predicate the gate runs rather than a paraphrase of it.
func synthProductionDeps(body string) string {
	return "package main\n\nimport (\n\t\"github.com/KidCarmi/Culvert/internal/mcp/limits\"\n" +
		"\t\"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient\"\n)\n\n" +
		"func newProductionUpstreamClient() (*upstreamclient.Client, error) {\n\t" + body + "\n}\n"
}

const (
	upstreamClientPkgPath = "github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
	retryFreeLimitsFunc   = "RetryFreeLimits"
)

// retryFreeLimitsViolation returns "" when newProductionUpstreamClient in src passes
// upstreamclient.Config a Limits value that is bound exactly once, by a call to
// upstreamclient.RetryFreeLimits. Otherwise it returns the reason it is not sound.
//
// It works backwards from the VALUE that is actually used, which is what makes it robust against a
// bypass that merely adds a new name: whatever the body mentions, the Limits field must still
// resolve to the retry-free binding.
func retryFreeLimitsViolation(src string) string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "src.go", src, 0)
	if err != nil {
		return "source does not parse: " + err.Error()
	}
	pkg := upstreamClientAlias(f)
	if pkg == "" {
		return "the file does not import " + upstreamClientPkgPath
	}
	fn := findFunc(f, "newProductionUpstreamClient")
	if fn == nil {
		return "newProductionUpstreamClient not found — if it was renamed or moved, point this wall " +
			"at its new home rather than deleting it: it is the only gate connecting the live tier's " +
			"client to the retry-free (and therefore redirect-free) shape"
	}
	limitsExpr, why := newCallLimitsExpr(fn, pkg)
	if why != "" {
		return why
	}
	ident, ok := limitsExpr.(*ast.Ident)
	if !ok {
		return "the Limits field is not a plain identifier, so its binding cannot be followed; pass a " +
			"variable bound from " + retryFreeLimitsFunc
	}
	bindings := bindingsOf(fn, ident.Name)
	if len(bindings) == 0 {
		return "the Limits identifier " + ident.Name + " is never bound in this function"
	}
	if len(bindings) > 1 {
		return "the Limits identifier " + ident.Name + " is bound more than once, so the retry-free " +
			"binding can be overwritten before it is used"
	}
	if !isCallTo(bindings[0], pkg, retryFreeLimitsFunc) {
		return "the Limits identifier " + ident.Name + " is not bound by " + pkg + "." + retryFreeLimitsFunc
	}
	if addressIsTaken(fn, ident.Name) {
		return "the address of the Limits identifier " + ident.Name + " is taken, so its value can be " +
			"replaced through an alias without rebinding it"
	}
	return ""
}

// upstreamClientAlias reports the name upstreamclient is imported under in f, honouring an alias.
func upstreamClientAlias(f *ast.File) string {
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != upstreamClientPkgPath {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return "upstreamclient"
	}
	return ""
}

func findFunc(f *ast.File, name string) *ast.FuncDecl {
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name && fn.Body != nil {
			return fn
		}
	}
	return nil
}

// newCallLimitsExpr returns the expression assigned to the Limits field of the <pkg>.Config
// literal that is actually passed to <pkg>.New — NOT merely the first Config literal in the
// function.
//
// Taking the first literal was a bypass, found by probing this predicate rather than by review: a
// decoy `_ = upstreamclient.Config{Limits: lim}` earlier in the body satisfied the check while the
// literal actually handed to New carried weak limits. The rule this enforces is the same one that
// motivated the whole gate — follow the value that is USED.
func newCallLimitsExpr(fn *ast.FuncDecl, pkg string) (ast.Expr, string) {
	var calls []*ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isCallExprTo(call, pkg, "New") {
			calls = append(calls, call)
		}
		return true
	})
	if len(calls) == 0 {
		return nil, "no call to " + pkg + ".New was found"
	}
	if len(calls) > 1 {
		return nil, "more than one call to " + pkg + ".New; which one builds the live client is ambiguous"
	}
	if len(calls[0].Args) == 0 {
		return nil, pkg + ".New is called with no arguments"
	}
	lit, ok := calls[0].Args[0].(*ast.CompositeLit)
	if !ok {
		return nil, "the Config passed to " + pkg + ".New is not a literal, so the Limits it carries " +
			"cannot be followed; build it inline at the call"
	}
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Config" {
		return nil, "the first argument to " + pkg + ".New is not a " + pkg + ".Config literal"
	}
	if x, ok := sel.X.(*ast.Ident); !ok || x.Name != pkg {
		return nil, "the Config literal is not " + pkg + ".Config"
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Limits" {
			return kv.Value, ""
		}
	}
	return nil, "the Config passed to " + pkg + ".New sets no Limits field"
}

// addressIsTaken reports whether &name appears anywhere in fn.
//
// Once a variable's address escapes, its value can be replaced through the alias (`*p = weak()`)
// by a statement this analysis does not see as a rebinding — measured as a real bypass. Rather
// than chase aliases, the gate refuses: an address-taken limits variable is not followable, and
// fail-closed is the right direction for a wall.
func addressIsTaken(fn *ast.FuncDecl, name string) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		u, ok := n.(*ast.UnaryExpr)
		if !ok || u.Op != token.AND {
			return true
		}
		if id, ok := u.X.(*ast.Ident); ok && id.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}

// bindingsOf returns every right-hand side that binds name in fn (:= and = alike), so a rebinding
// after the retry-free call is visible rather than hidden behind the first one.
func bindingsOf(fn *ast.FuncDecl, name string) []ast.Expr {
	var out []ast.Expr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name != name {
				continue
			}
			// A multi-value call (lim, err := f()) binds every LHS from the one RHS call.
			if len(as.Rhs) == 1 {
				out = append(out, as.Rhs[0])
			} else if i < len(as.Rhs) {
				out = append(out, as.Rhs[i])
			}
		}
		return true
	})
	return out
}

func isCallTo(e ast.Expr, pkg, fn string) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	return isCallExprTo(call, pkg, fn)
}

func isCallExprTo(call *ast.CallExpr, pkg, fn string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != fn {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == pkg
}
