package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/admission"
)

// ── SEC-ADMISSION-OWNER-1 ───────────────────────────────────────────────────
//
// ADR-0038 moved the distributed admission state (remote counts, the receipt
// stamp, the cluster-enable flag, the stale-episode record) from process
// globals onto each RateLimiter, and ADR-0039 moved the engine into
// internal/admission. Both are faithful: the enforcement algorithm, the
// CHAOS-61 freshness arithmetic and every call site are unchanged, and no
// mutable engine internal is exported.
//
// Instance ownership does, however, create a failure mode the global shape
// could not have: the limiter the REQUEST PATH enforces with and the limiter
// the GOSSIP LOOP feeds are now two separate objects that must be the same
// object. Nothing structural held them together. ADR-0038 anticipated it in
// prose ("No optional dependency with global fallback", "Production composes
// one gossip loop per application limiter") and the production wiring is
// correct today — DataPlaneClient.Run passes rl, the same handle proxy.go and
// socks5.go consult — but no gate pinned it, and the existing wiring test
// drives rateLimitGossipLoop directly with its own limiter, so it would stay
// green if Run started feeding a different one.
//
// A split owner is a SILENT security regression, which is what earns it a
// wall rather than a comment. Measured on the real engine: the enforcing
// limiter's ClusterEnabled() is false, so AllowAuto dispatches to local-only
// Allow and a client may consume the full limit on EVERY node instead of once
// across the fleet — the exact degradation CHAOS-61 exists to surface. And
// CHAOS-61 cannot surface it, correctly so: an un-armed node is deliberately
// never "stale" (there is no enforcement for an expired broadcast to degrade),
// metrics are gated on Armed, so the remote_stale gauge, the broadcast age,
// the episode counter and the log line are ALL absent rather than alarming.
// Fleet-wide rate limiting silently becomes per-node with no operator signal.
//
// Both gates assert the MECHANISM and carry their own CONTROLS — the same
// predicate run against the broken shapes it exists to reject, so a selector
// that matches nothing cannot pass forever (the sanitizeLog scan-count and
// CHAOS-70 rate-gate precedent). Deterministic on any hardware, at any load,
// with or without -race.

// findMethodDecl returns the method named name on receiver type recv.
func findMethodDecl(file *ast.File, recv, name string) *ast.FuncDecl {
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		t := fn.Recv.List[0].Type
		if star, ok := t.(*ast.StarExpr); ok {
			t = star.X
		}
		if id, ok := t.(*ast.Ident); ok && id.Name == recv {
			return fn
		}
	}
	return nil
}

// gossipLoopLimiterArgs reports, for every rateLimitGossipLoop call inside fn,
// the identifier passed as its limiter argument. A non-identifier (a fresh
// constructor call, a field, an index) is reported as "<not an identifier>" —
// the shape cannot be proven to name the application's enforcing owner.
func gossipLoopLimiterArgs(fn *ast.FuncDecl) []string {
	var out []string
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "rateLimitGossipLoop" {
			return true
		}
		switch {
		case len(call.Args) < 3:
			out = append(out, "<too few arguments>")
		default:
			if id, ok := call.Args[2].(*ast.Ident); ok {
				out = append(out, id.Name)
			} else {
				out = append(out, "<not an identifier>")
			}
		}
		return true
	})
	return out
}

// The gossip loop must be handed the application composition handle the
// request path enforces with. Any other expression means the node can apply
// broadcasts to a limiter nobody consults.
func TestAdmissionOwner_Wall_GossipLoopIsFedTheEnforcingLimiter(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "controlplane_client.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse controlplane_client.go: %v", err)
	}
	run := findMethodDecl(file, "DataPlaneClient", "Run")
	if run == nil {
		t.Fatal("DataPlaneClient.Run not found; this gate's selector has gone stale")
	}
	args := gossipLoopLimiterArgs(run)
	if len(args) != 1 || args[0] != "rl" {
		t.Errorf("DataPlaneClient.Run must start the gossip loop on the application limiter rl, got %v: "+
			"a limiter the request path does not consult applies broadcasts nobody enforces, and because "+
			"the enforcing limiter is then never armed, CHAOS-61 reports it as healthy — fleet-wide rate "+
			"limiting silently degrades to per-node with no metric, episode or alert (SEC-ADMISSION-OWNER-1)", args)
	}

	// CONTROLS: the shapes this gate exists to reject must be rejected.
	for name, src := range map[string]string{
		"fresh limiter": `package main
func (c *DataPlaneClient) Run(ctx context.Context, pollInterval time.Duration) {
	go c.rateLimitGossipLoop(ctx, 5*time.Second, newRateLimiter())
}`,
		"other owner": `package main
func (c *DataPlaneClient) Run(ctx context.Context, pollInterval time.Duration) {
	go c.rateLimitGossipLoop(ctx, 5*time.Second, other)
}`,
		"client field": `package main
func (c *DataPlaneClient) Run(ctx context.Context, pollInterval time.Duration) {
	go c.rateLimitGossipLoop(ctx, 5*time.Second, c.limiter)
}`,
	} {
		cfset := token.NewFileSet()
		cfile, err := parser.ParseFile(cfset, "control.go", src, 0)
		if err != nil {
			t.Fatalf("parse %s control: %v", name, err)
		}
		crun := findMethodDecl(cfile, "DataPlaneClient", "Run")
		if crun == nil {
			t.Fatalf("%s control did not parse into DataPlaneClient.Run", name)
		}
		if got := gossipLoopLimiterArgs(crun); len(got) == 1 && got[0] == "rl" {
			t.Errorf("the %s control was ACCEPTED (%v); this gate is matching nothing and proves nothing", name, got)
		}
	}
}

// rlAdmissionEntryPoints reports every rl.Allow* method called in src.
func rlAdmissionEntryPoints(t *testing.T, filename, src string) []string {
	t.Helper()
	fset := token.NewFileSet()
	var mode parser.Mode
	var file *ast.File
	var err error
	if src == "" {
		file, err = parser.ParseFile(fset, filename, nil, mode)
	} else {
		file, err = parser.ParseFile(fset, filename, src, mode)
	}
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !strings.HasPrefix(sel.Sel.Name, "Allow") {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "rl" {
			out = append(out, sel.Sel.Name)
		}
		return true
	})
	return out
}

// Every protocol's front door must consult the CLUSTER-AWARE entry point.
// AllowAuto is the only one that reaches a remote count; rl.Allow is
// local-only and rl.AllowClusterAware bypasses the enable check, so either
// substitution silently drops this node out of fleet-wide limiting while
// local limiting — and therefore every behavioural rate-limit test — keeps
// passing.
func TestAdmissionOwner_Wall_RequestPathUsesClusterAwareEntryPoint(t *testing.T) {
	for _, file := range []string{"proxy.go", "socks5.go"} {
		calls := rlAdmissionEntryPoints(t, file, "")
		if len(calls) == 0 {
			t.Errorf("%s makes no rl.Allow* call; the front-door rate-limit gate has gone missing "+
				"or this gate's selector is stale", file)
			continue
		}
		for _, c := range calls {
			if c != "AllowAuto" {
				t.Errorf("%s admits traffic through rl.%s; the request path must use AllowAuto so a "+
					"node in a cluster consults remote counts (SEC-ADMISSION-OWNER-1)", file, c)
			}
		}
	}

	// CONTROLS: the local-only and enable-bypassing shapes must be rejected.
	for name, src := range map[string]string{
		"local only":    "package main\nfunc h(ip string) { if !rl.Allow(ip) { return } }",
		"enable bypass": "package main\nfunc h(ip string) { if !rl.AllowClusterAware(ip) { return } }",
	} {
		calls := rlAdmissionEntryPoints(t, "control.go", src)
		if len(calls) != 1 {
			t.Fatalf("%s control did not parse into one rl.Allow* call: %v", name, calls)
		}
		if calls[0] == "AllowAuto" {
			t.Errorf("the %s control was ACCEPTED; this gate is matching nothing", name)
		}
	}
}

// The behavioural half: WHY the wall above exists. A split owner is admitted
// traffic plus a clean bill of health on every operator surface at once.
//
// This pins a DOCUMENTED RESIDUAL, not a defect: the invisibility is a
// consequence of CHAOS-61's deliberate "an un-armed node is never stale" rule,
// which is correct — the alternative pins every standalone node at "degraded".
// The structural wall above, not detection, is the control. If a future change
// ever makes a split owner observable (an armed-but-unfed assertion at
// composition time, say), THIS assertion is the one to invert — deliberately,
// not by accident.
func TestAdmissionOwner_SplitOwnerDegradesSilently(t *testing.T) {
	const ip = "203.0.113.9"
	enforcing := newRateLimiter() // what proxy.go/socks5.go would consult
	gossip := withClusterRateLimiter(t, 10, time.Minute)
	enforcing.Configure(10, time.Minute)
	useProductionRateLimiter(t, enforcing)

	// The whole fleet has already spent this client's budget elsewhere.
	gossip.ApplyRemoteCounts(map[string]int{ip: 10})
	for i := 0; i < 9; i++ {
		if !enforcing.Allow(ip) {
			t.Fatalf("priming local count stopped early at %d", i)
		}
	}

	if !enforcing.AllowAuto(ip) {
		t.Fatal("control: a split owner must still admit locally — if this denies, the limiters are " +
			"sharing state and this test no longer reproduces the condition it documents")
	}
	st := enforcing.ClusterFreshness()
	if st.Armed || st.Stale || st.Applied || st.Episodes != 0 {
		t.Errorf("enforcing limiter reported armed=%v stale=%v applied=%v episodes=%d; "+
			"a split owner is expected to look entirely healthy", st.Armed, st.Stale, st.Applied, st.Episodes)
	}
	if obs := enforcing.ObserveClusterFreshness(); obs.Transition != admission.FreshnessUnchanged {
		t.Errorf("gossip observation reported transition %v on an un-armed owner", obs.Transition)
	}
	if body := renderMetrics(t); strings.Contains(body, "culvert_cluster_ratelimit_remote_stale") {
		t.Errorf("a split owner now emits a cluster rate-limit series — the residual this test "+
			"documents has changed; invert this assertion deliberately: %s", extractClusterRLMetrics(body))
	}
}
