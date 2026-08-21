package main

// mcp_distribution_reject_reason_test.go — SEC-MCP-1: the DP's pre-check
// rejections must reach the Control Plane with a TRUTHFUL, alertable reason
// code.
//
// The acknowledgement's RejectReason is the CP's only signal about why a node
// nacked a signed envelope. It is derived via mcperr.ReasonOf(cause), which
// walks the error chain for an *mcperr.Error and otherwise returns ReasonNone.
// A cause built with a bare errors.New therefore renders EVERY pre-check
// rejection as the same unclassified code — including the capability-mismatch
// rejection, which is the exact shape of a capability-confusion attempt against
// the Gateway/Management isolation boundary and the one a fleet operator most
// needs to be able to alert on.
//
// These gates pin the classification, not the message text.

import (
	"errors"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// The two pre-check causes must each carry a distinct, non-empty reason.
func TestSecMCP_PreCheckCausesCarryDistinctReasons(t *testing.T) {
	capMismatch := mcperr.ReasonOf(errRolloutCapabilityMismatch)
	execDeps := mcperr.ReasonOf(errShadowExecDepsNotConfigured)

	if capMismatch == mcperr.ReasonNone {
		t.Fatal("the capability-mismatch rejection carries no mcperr.Reason — the CP " +
			"receives an unclassified nack for a capability-confusion attempt")
	}
	if execDeps == mcperr.ReasonNone {
		t.Fatal("the execution-dependency rejection carries no mcperr.Reason")
	}
	if capMismatch == execDeps {
		t.Fatalf("both pre-check rejections resolve to %q — the CP cannot tell a "+
			"capability-confusion attempt from an ordinary fail-closed precondition",
			capMismatch.Code())
	}
	if capMismatch != mcperr.ReasonSnapshotCapabilityMismatch {
		t.Fatalf("capability mismatch = %q, want snapshot_capability_mismatch", capMismatch.Code())
	}
}

// Identity must survive the reason change: the durable-transition tests and the
// coordinator both compare these sentinels directly.
func TestSecMCP_PreCheckCausesRemainComparableSentinels(t *testing.T) {
	err := error(errShadowExecDepsNotConfigured)
	if err != errShadowExecDepsNotConfigured || !errors.Is(err, errShadowExecDepsNotConfigured) {
		t.Fatal("errShadowExecDepsNotConfigured lost sentinel identity")
	}
	if errors.Is(errRolloutCapabilityMismatch, errShadowExecDepsNotConfigured) {
		t.Fatal("the two pre-check sentinels must not compare equal")
	}
}

// The Applier must propagate the cause's reason into the acknowledgement it
// hands back for a coordinator-driven rejection — the wire-level half of the
// contract above.
func TestSecMCP_RejectAckPropagatesCauseReason(t *testing.T) {
	s, _ := mcpProdSetup(t)
	a := globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway)
	env := mcpSignedGWEnv(t, s, 2, mcpObserveRollout(rollout.CapabilityGateway))

	ack := a.RejectAck(env, errRolloutCapabilityMismatch)
	if ack == nil {
		t.Fatal("RejectAck returned no acknowledgement")
	}
	if ack.State != cpdp.AckRejected {
		t.Fatalf("ack state = %v, want rejected", ack.State)
	}
	if ack.RejectReason != mcperr.ReasonSnapshotCapabilityMismatch.Code() {
		t.Fatalf("ack reject reason = %q, want %q — the CP cannot alert on a "+
			"capability-confusion nack it cannot classify",
			ack.RejectReason, mcperr.ReasonSnapshotCapabilityMismatch.Code())
	}
	// A rejection must never stage state.
	if a.Active() != nil {
		t.Fatal("RejectAck activated a snapshot")
	}
}
