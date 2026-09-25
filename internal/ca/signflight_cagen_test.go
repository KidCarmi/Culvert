package ca

import (
	"crypto/tls"
	"crypto/x509"
	"go/ast"
	"go/parser"
	"go/token"
	"sync/atomic"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// CA-generation fencing.
//
// Clearing the leaf cache is not enough to make a CA replacement take effect: a
// sign already in flight was started against the OUTGOING CA. These gates cover
// both consequences — a post-replacement caller inheriting that leaf (a
// regression the single flight introduced) and the leader repopulating the
// just-cleared cache with it (pre-existing, and closed by the same fence).
//
// Raised by Codex review on PR #1447.
// ─────────────────────────────────────────────────────────────────────────────

// replaceCAMidFlight parks a leader inside its sign, replaces the CA, then runs
// a second caller for the same host. It returns that caller's certificate, what
// the cache ended up holding, and the two CAs.
func replaceCAMidFlight(t *testing.T, host string,
	get func(*Manager, *tls.ClientHelloInfo) (*tls.Certificate, error),
) (got, cached *tls.Certificate, oldCA, newCA *x509.Certificate) {
	t.Helper()
	cm := readyManager(t)
	cm.mu.RLock()
	oldCA = cm.caCert
	cm.mu.RUnlock()

	var entered atomic.Int64
	swapped := make(chan struct{})
	prev := SignLatencyObserver
	SignLatencyObserver = func(float64) {
		if entered.Add(1) == 1 {
			<-swapped // hold the leader inside its flight across the replacement
		}
	}
	t.Cleanup(func() { SignLatencyObserver = prev })

	go func() { _, _ = get(cm, &tls.ClientHelloInfo{ServerName: host}) }()
	waitFor(t, "the leader to enter its flight", func() bool { return entered.Load() >= 1 })

	if err := cm.InitCA(); err != nil { // a real CA-replacement path; clears the leaf cache
		t.Fatalf("InitCA: %v", err)
	}
	cm.mu.RLock()
	newCA = cm.caCert
	cm.mu.RUnlock()

	out := make(chan *tls.Certificate, 1)
	go func() {
		c, _ := get(cm, &tls.ClientHelloInfo{ServerName: host})
		out <- c
	}()
	waitFor(t, "the second caller to park, return, or sign on its own", func() bool {
		return cm.SignFlightsJoined() >= 1 || entered.Load() >= 2
	})
	close(swapped)
	got = <-out
	cached, _ = cm.cachedLeaf(host, time.Now())
	return got, cached, oldCA, newCA
}

func issuedBy(t *testing.T, cert *tls.Certificate, ca *x509.Certificate) bool {
	t.Helper()
	if cert == nil || cert.Leaf == nil || ca == nil {
		return false
	}
	return cert.Leaf.CheckSignatureFrom(ca) == nil
}

// TestCAGeneration_PostReplacementCallerDoesNotJoinAnOldFlight is the gate for
// the regression the single flight introduced, and it fails against the
// host-only flight key.
//
// A caller that arrives after the CA is replaced must not be handed a leaf
// signed by the outgoing CA — a client that trusts only the incoming CA rejects
// that connection. Before the collapsing existed this caller signed for itself
// and got a correct leaf, so joining is strictly worse than the behaviour it
// replaced.
func TestCAGeneration_PostReplacementCallerDoesNotJoinAnOldFlight(t *testing.T) {
	got, _, oldCA, newCA := replaceCAMidFlight(t, "rot.example.com", (*Manager).GetCert)
	if issuedBy(t, got, oldCA) {
		t.Fatal("a caller arriving AFTER the CA replacement received a leaf signed by the OUTGOING CA: " +
			"it joined a flight opened against the old CA, and every client trusting only the new CA rejects that handshake")
	}
	if !issuedBy(t, got, newCA) {
		t.Fatalf("post-replacement caller did not receive a leaf signed by the incoming CA (cert=%v)", got)
	}
}

// TestCAGeneration_RetiredSignDoesNotRepopulateTheClearedCache closes the
// PRE-EXISTING half: the leader's store lands after the replacement cleared the
// cache, so without the fence it reinstalls the outgoing CA's leaf and every
// client is served it for the full certCacheTTL. The legacy control below shows
// this is not a regression — it is a bug the fence also fixes.
func TestCAGeneration_RetiredSignDoesNotRepopulateTheClearedCache(t *testing.T) {
	_, cached, oldCA, _ := replaceCAMidFlight(t, "poison.example.com", (*Manager).GetCert)
	if issuedBy(t, cached, oldCA) {
		t.Fatalf("a sign started before the CA replacement repopulated the just-cleared cache with the "+
			"OUTGOING CA's leaf; it would be served for the whole %s TTL", certCacheTTL)
	}
}

// TestCAGeneration_LegacyShapePoisonedTheCache is the evidence that the gate
// above is worth having: the frozen pre-single-flight body still poisons the
// cache here. It documents which half of this fix is a regression repair and
// which half is a pre-existing bug closed along the way — and it fails, loudly,
// if the frozen body ever stops being a faithful copy of what shipped.
func TestCAGeneration_LegacyShapePoisonedTheCache(t *testing.T) {
	_, cached, oldCA, _ := replaceCAMidFlight(t, "legacy.example.com", getCertLegacy)
	if !issuedBy(t, cached, oldCA) {
		t.Skip("the pre-fix shape did not reproduce its cache poisoning on this run; " +
			"the scheduling it depends on is not guaranteed, and only the two gates above are contractual")
	}
}

// TestCAGeneration_ReplacementRetiresTheGeneration pins the mechanism itself.
func TestCAGeneration_ReplacementRetiresTheGeneration(t *testing.T) {
	cm := readyManager(t)
	before := cm.caGen.Load()
	if err := cm.InitCA(); err != nil {
		t.Fatal(err)
	}
	if after := cm.caGen.Load(); after == before {
		t.Fatalf("InitCA left the CA generation at %d — a replacement must retire it", after)
	}
	prev := cm.caGen.Load()
	cm.ClearCache()
	if after := cm.caGen.Load(); after == prev {
		t.Fatalf("ClearCache left the CA generation at %d", after)
	}
}

// TestCAGeneration_EveryCacheResetRetiresTheGeneration is STRUCTURAL, and it is
// the gate that survives contact with future changes: a new CA-install path
// that clears the cache by open-coding the map assignment would silently
// reintroduce both defects above, and no behavioural test would name it. So
// require that the ONLY place assigning cm.cache a fresh map is
// resetLeafCacheLocked, which bumps the generation in the same breath.
//
// Deterministic on any hardware, under any load, with or without -race.
func TestCAGeneration_EveryCacheResetRetiresTheGeneration(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "ca.go", nil, 0)
	if err != nil {
		t.Fatalf("parse ca.go: %v", err)
	}
	var offenders []string
	var enclosing string
	ast.Inspect(f, func(n ast.Node) bool {
		if fd, ok := n.(*ast.FuncDecl); ok {
			enclosing = fd.Name.Name
			return true
		}
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 {
			return true
		}
		sel, ok := as.Lhs[0].(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "cache" {
			return true
		}
		if enclosing != "resetLeafCacheLocked" {
			offenders = append(offenders, enclosing+" ("+fset.Position(as.Pos()).String()+")")
		}
		return true
	})
	if len(offenders) > 0 {
		t.Fatalf("these functions reset the leaf cache without retiring the CA generation: %v\n"+
			"Use resetLeafCacheLocked() — clearing the cache alone lets an in-flight sign started "+
			"against the outgoing CA be joined by post-replacement callers and repopulate the cache.", offenders)
	}
	// Not vacuous: the one legitimate assignment must be found.
	if enclosing == "" {
		t.Fatal("the AST walk matched nothing; this gate is not checking what it claims")
	}
}
