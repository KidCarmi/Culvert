package runtime

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// Eligibility is a SEPARATE axis from the fingerprint.
//
// catalog.DisableServer copies each record and changes ONLY Eligibility (to
// ServerDisabled) and Revision -- the fingerprint is deliberately preserved,
// because the tool's shape did not change, its server's identity did. A
// fingerprint-only drift check therefore reports "still current" for a tool the
// catalog has just marked unusable, and the guarded executor would call it under
// a decision made while it was still eligible. Disabling a server is the operator
// action that means "stop calling this", so it is exactly the transition that must
// not be missable.
func TestDrift_DisabledServerIsDriftEvenThoughTheFingerprintIsUnchanged(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, NewBoundedSink(8))
	before := ingestTool(t, deps.Registry, deps.Catalog, testServerID, "x", `{"type":"object"}`)

	ex := &hookCapturingExec{}
	deps.Executor = ex
	deps.Policy = fakePolicy{gw: gwPolicySnap(t,
		`{"id":"ALLOW_ALL","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE",`+
			`"remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`)}

	// Disable the server from INSIDE Execute: strictly after the runtime's entry
	// check has passed, in the window only the last-moment hook can see.
	ex.driftInside = func() {
		if _, err := deps.Catalog.DisableServer(registry.ServerID(testServerID)); err != nil {
			t.Errorf("DisableServer: %v", err)
		}
	}

	p := newGatewayPipeline(t, deps)
	tok, sid := driveToDecisionPoint(t, p, k)
	p.Process(context.Background(), withSession(gwRequest(tok, toolsCallBody(2)), sid), fixedClock())

	if ex.reached != 1 {
		t.Fatalf("executor reached %d times, want 1", ex.reached)
	}
	if !ex.beforeDrift {
		t.Fatal("the hook reported drift before anything changed")
	}
	// The fingerprint is the control: it must be UNCHANGED, or this test would be
	// passing for the fingerprint reason and proving nothing about eligibility.
	rec, ok := deps.Catalog.Current().Get(catalog.ToolKey{
		Server: registry.ServerID(testServerID), Name: "x",
	})
	if !ok {
		t.Fatal("tool vanished from the catalog; that is a different transition")
	}
	sum := rec.Fingerprint.Sum()
	if got := hex.EncodeToString(sum[:]); got != before {
		t.Fatalf("fingerprint changed (%s -> %s): DisableServer no longer preserves it, "+
			"so this test no longer exercises the eligibility axis", before, got)
	}
	if ex.afterDrift {
		t.Fatal("a tool whose server was DISABLED mid-execution still reported as " +
			"current: the drift check compares only the fingerprint, which DisableServer " +
			"preserves, so the guarded executor would call a server the catalog has " +
			"just marked unusable")
	}
}

// The stalled-body deadline must be COUNTED, not just answered with a 503.
// checkBudget and acquireSlot both increment timeouts when the budget elapses;
// leaving this path out understates the overload condition the deadline exists to
// expose -- and it is the one an operator would alert on during a slow-upload
// flood.
func TestDrift_StalledBodyDeadlineIncrementsTheTimeoutCounter(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, NewBoundedSink(8)))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := gwRequest(gwToken(k), nil)
	req.Body = nil
	req.BodyReader = &erroringReader{}

	before := p.ctr.timeouts.Load()
	_, reason, ok := p.readBody(ctx, req)
	if ok || reason != mcperr.ReasonRequestDeadlineExceeded {
		t.Fatalf("readBody = (%v, %v), want a deadline refusal", ok, reason)
	}
	// readBody itself must not count -- the caller owns the counter, exactly once.
	if got := p.ctr.timeouts.Load() - before; got != 0 {
		t.Fatalf("readBody incremented timeouts by %d; the reject branch owns that "+
			"increment and counting in both places double-counts every stalled body", got)
	}
}
