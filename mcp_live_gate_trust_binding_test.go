package main

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
)

// Codex round-4 P1 fixes: the runtime live-trust revalidation must bind to the DECISION's fingerprint
// (not merely the current one) and reject a server that is no longer usable at the boundary.

// P1a: mcpLiveTrustRevalidate binds trust to the decision fingerprint. A valid live approval for the
// CURRENT fingerprint must NOT authorize a request that was decided under a DIFFERENT fingerprint
// (the F1→F2→F1 catalog-flap class), and an empty decision fingerprint fails closed.
func TestLiveTrustRevalidate_BindsToDecisionFingerprint(t *testing.T) {
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	clk, fn := liveFakeClock()
	composeToolTrust(t, fn)
	_ = clk
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
	now := mcpToolTrust.now()

	// Baseline: the decision fingerprint equals the current target ⇒ a valid approval revalidates OK.
	if ok, _ := mcpLiveTrustRevalidate(ttTenant, sid, tool, fpHex, now); !ok {
		t.Fatal("a valid live approval bound to the current fingerprint must revalidate OK")
	}
	// P1a: a decision fingerprint that does NOT match the current target is denied, even though a
	// valid approval exists for the current fingerprint (an F2 approval cannot authorize an F1 request).
	otherFP := "deadbeefdeadbeef" + fpHex[16:]
	if otherFP == fpHex {
		otherFP = "0123456789abcdef" + fpHex[16:]
	}
	if ok, _ := mcpLiveTrustRevalidate(ttTenant, sid, tool, otherFP, now); ok {
		t.Fatal("P1a: a decision fingerprint that does not match the current target must be denied")
	}
	// An empty decision fingerprint fails closed.
	if ok, _ := mcpLiveTrustRevalidate(ttTenant, sid, tool, "", now); ok {
		t.Fatal("an empty decision fingerprint must be denied")
	}
}

// P1b: a server that is no longer usable at the boundary (disabled / lost identity verification after
// the decision snapshot) is denied, even though a valid live approval for the tool still exists.
func TestLiveTrustRevalidate_RejectsUnusableServer(t *testing.T) {
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	clk, fn := liveFakeClock()
	composeToolTrust(t, fn)
	_ = clk
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
	now := mcpToolTrust.now()
	if ok, _ := mcpLiveTrustRevalidate(ttTenant, sid, tool, fpHex, now); !ok {
		t.Fatal("precondition: the valid approval must revalidate OK before the server is disabled")
	}

	// Re-publish the SAME tool under a DISABLED server (the approval is unchanged). The boundary must
	// now fail closed because the server is no longer usable.
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"` + sid + `","endpoint":"e","pinned_identity":"id","enabled":false,
	   "tools":[{"name":"` + tool + `","input_schema":{"type":"object"}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode disabled inventory: %v", err)
	}
	reg2, cat2, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed disabled inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg2, cat2)

	if ok, _ := mcpLiveTrustRevalidate(ttTenant, sid, tool, fpHex, now); ok {
		t.Fatal("P1b: a request against a server that is no longer usable must be denied at the boundary")
	}
}
