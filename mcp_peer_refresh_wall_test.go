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

// findCallsites returns every production call to a method named sel, with the enclosing function.
func findCallsites(t *testing.T, sel string) []callSite {
	t.Helper()
	var sites []callSite
	for _, path := range productionGoFiles(t) {
		src, err := os.ReadFile(path) //nolint:gosec // repo-local walk, not caller input
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, src, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		rel := filepath.ToSlash(path)
		// Track the enclosing function as we walk, so a hit can name it.
		var enclosing string
		ast.Inspect(file, func(n ast.Node) bool {
			switch fn := n.(type) {
			case *ast.FuncDecl:
				enclosing = fn.Name.Name
				if fn.Recv != nil && len(fn.Recv.List) > 0 {
					enclosing = recvTypeName(fn.Recv) + "." + fn.Name.Name
				}
			case *ast.CallExpr:
				if s, ok := fn.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == sel {
					sites = append(sites, callSite{File: rel, Func: enclosing, Line: fset.Position(s.Sel.Pos()).Line})
				}
			}
			return true
		})
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].String() < sites[j].String() })
	return sites
}

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
			t.Errorf("%s:%d calls %s, and that caller is not on the reasoned list.\n"+
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
			t.Errorf("the wall expects %s to call %s, and it does not. If the production path "+
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
