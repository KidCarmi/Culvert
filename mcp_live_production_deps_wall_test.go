package main

// The MCP live-tier PRODUCTION-DEPENDENCY anti-synthetic wall (§20).
//
// The execution-posture wall (mcp_execution_posture_test.go) pins that only the two composition
// files may import internal/mcp/execution and assign Deps.Executor. THIS wall adds the
// complementary anti-synthetic guarantees for the production dependency graph: a synthetic
// collaborator (a recording upstream, an in-memory KEK, an in-memory credential provider) can
// never become the reason a PRODUCTION node believes it is safe to execute.
//
// Three structural facts, all AST-based (a string search would match comments and the very test
// files that legitimately use the synthetic doubles):
//
//   1. composeGatewayLiveTierInto — the ONE Deps.Executor-assigning seam — has exactly ONE
//      production CALL site, in mcp_live_production_deps.go (composeProductionGatewayLiveTier).
//      No other production file may call it, so there is no second production path that could
//      hand it synthetic collaborators.
//   2. composeProductionGatewayLiveTier — the ONE production entrypoint — has exactly ONE
//      production CALL site, in mcp_observe_startup.go (the disabled-by-default opt-in). So the
//      real dependency graph is composed from exactly one place, under the one env gate.
//   3. The test-only synthetic KEK/provider constructors (secret.MemoryProvider,
//      provider.NewInMemory) are referenced by NO production file. A production KEK is always a
//      real secret.FileProvider; a production credential provider is never installed (the honest
//      pre-Canary gap), and neither test double can leak into a shipped build.
//
// Whoever loosens any of these must edit THIS wall, and that edit is what a reviewer sees.

import (
	"go/ast"
	"path/filepath"
	"strings"
	"testing"
)

// productionCallSites returns the set of production files that CALL the named function (by
// simple name), each mapped to the number of call sites in that file. Definitions (func decls)
// are not calls and never appear.
func productionCallSites(t *testing.T, fnName string) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, pf := range productionAST(t) {
		base := filepath.Base(pf.path)
		ast.Inspect(pf.file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && callName(call) == fnName {
				out[base]++
			}
			return true
		})
	}
	return out
}

// TestLiveProdWall_ComposeSeamHasSingleProductionCaller pins fact (1): the Deps.Executor-
// assigning seam is CALLED from exactly one production file.
func TestLiveProdWall_ComposeSeamHasSingleProductionCaller(t *testing.T) {
	const seam = "composeGatewayLiveTierInto"
	const allowed = "mcp_live_production_deps.go"
	sites := productionCallSites(t, seam)
	for file, n := range sites {
		if file != allowed {
			t.Errorf("%s() is called from %s (%d site(s)); the ONLY permitted production caller is %s — a second caller could hand the seam synthetic collaborators (§20)", seam, file, n, allowed)
		}
	}
	if sites[allowed] != 1 {
		t.Errorf("expected exactly ONE call to %s() in %s, found %d; the single-caller wall must stay exact", seam, allowed, sites[allowed])
	}
}

// TestLiveProdWall_EntrypointHasSingleProductionCaller pins fact (2): the production entrypoint
// is CALLED from exactly one production file (the disabled-by-default observe-runtime opt-in).
func TestLiveProdWall_EntrypointHasSingleProductionCaller(t *testing.T) {
	const entry = "composeProductionGatewayLiveTier"
	const allowed = "mcp_observe_startup.go"
	sites := productionCallSites(t, entry)
	for file, n := range sites {
		if file != allowed {
			t.Errorf("%s() is called from %s (%d site(s)); the ONLY permitted production caller is %s (the CULVERT_MCP_LIVE_DEPS opt-in) — §20", entry, file, n, allowed)
		}
	}
	if sites[allowed] != 1 {
		t.Errorf("expected exactly ONE call to %s() in %s, found %d", entry, allowed, sites[allowed])
	}
}

// TestLiveProdWall_NoSyntheticKEKOrProviderInProduction pins fact (3): the test-only synthetic
// KEK/provider constructors are referenced by NO production file. A production build can only
// ever construct a real secret.FileProvider and never an in-memory KEK or an in-memory
// credential provider.
func TestLiveProdWall_NoSyntheticKEKOrProviderInProduction(t *testing.T) {
	// Simple identifier names of the test-only synthetic constructors. Matching the Sel name of a
	// SelectorExpr (secret.MemoryProvider → "MemoryProvider", provider.NewInMemory → "NewInMemory")
	// or a bare Ident catches both qualified and dot-imported references.
	forbidden := map[string]bool{
		"MemoryProvider": true, // secret.MemoryProvider — in-memory KEK (test/dormant only)
		"NewInMemory":    true, // provider.NewInMemory — in-memory credential provider (test only)
	}
	for _, pf := range productionAST(t) {
		// Scope to the root package-main composition layer: internal/* packages legitimately
		// DEFINE these test-support constructors (their own package_test suites and the dormant
		// broker use them). The wall's concern is that the shipped WIRING never names them.
		if strings.Contains(pf.path, "/") {
			continue
		}
		base := filepath.Base(pf.path)
		ast.Inspect(pf.file, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.SelectorExpr:
				if forbidden[e.Sel.Name] {
					t.Errorf("production file %s references the test-only synthetic constructor %q; a synthetic KEK/provider must never enter a shipped build (§20)", base, e.Sel.Name)
				}
			case *ast.Ident:
				if forbidden[e.Name] {
					t.Errorf("production file %s references the test-only synthetic constructor %q; a synthetic KEK/provider must never enter a shipped build (§20)", base, e.Name)
				}
			}
			return true
		})
	}
}
