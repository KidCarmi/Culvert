package tooltrust

import (
	"testing"
	"time"
)

// PURPOSE-PROJECTION SEPARATION (the live-execution firewall, at the STORE boundary).
//
// The store exposes TWO active-grant projections and they feed two structurally different
// authorities:
//
//	ActiveApprovals      → the coordinator's catalog.Usable PROMOTION (Shadow usability).
//	ActiveLiveApprovals  → the Canary activation preflight and the live SIDE-EFFECT gate.
//
// They are separated ONLY by the purpose predicate inside activeAsOf / activeLiveAsOf. Since
// Purpose.Issuable() was widened to admit live_execution, an ACTIVE live_execution record now
// exists at rest, so a relaxation of activeAsOf to "StatusActive && !expired" — which reads
// perfectly plausible and is what the predicate looked like before the purposes diverged —
// would silently make a live grant materialize catalog.Usable: a tool trusted ONLY for a real,
// four-eyes, ≤24h side effect would additionally become usable for Shadow evaluation, with no
// shadow review and no shadow approval. The mirror direction is worse: a shadow_evaluation
// approval (single-actor, no mandatory expiry, no TTL ceiling) leaking into
// ActiveLiveApprovals would put a grant that never passed live governance in front of the
// side-effect gate's approval scan.
//
// The Purpose predicates themselves are pinned by TestPurpose_ShadowAndLiveIssuable and the
// coordinator-level catalog effect by TestLiveTrust_ApproveDoesNotPromoteUsable; neither
// exercises the two Store projections, so an edit to either filter passes the package today.
// This is that wall: both directions, on genuinely ACTIVE grants.
func TestActiveApprovalProjections_PurposeSeparation(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	s := newTestStore(t, clk)

	// An ACTIVE shadow_evaluation grant.
	shIn := goodRequest()
	shReq, err := s.CreateRequest(shIn)
	if err != nil {
		t.Fatalf("create shadow request: %v", err)
	}
	if _, err := s.Approve(shReq.ApprovalID, "approver@corp", matchingTarget(shIn)); err != nil {
		t.Fatalf("approve shadow: %v", err)
	}

	// An ACTIVE live_execution grant on a DIFFERENT tool (four-eyes, in-ceiling expiry).
	lvIn := liveRequest(clk)
	lvIn.ToolName = "write_file"
	lvReq, err := s.CreateRequest(lvIn)
	if err != nil {
		t.Fatalf("create live request: %v", err)
	}
	if _, err := s.Approve(lvReq.ApprovalID, "approver@corp", matchingTarget(lvIn)); err != nil {
		t.Fatalf("approve live: %v", err)
	}

	// ActiveApprovals is the SHADOW projection (catalog.Usable promotion). It must contain the
	// shadow grant and NEVER the live one.
	shadowProjection := s.ActiveApprovals(clk.now())
	if len(shadowProjection) != 1 {
		t.Fatalf("ActiveApprovals must project exactly the one active shadow grant, got %d", len(shadowProjection))
	}
	if got := shadowProjection[0]; got.ApprovalID != shReq.ApprovalID || got.Purpose != PurposeShadowEvaluation {
		t.Fatalf("SECURITY: ActiveApprovals (the catalog.Usable promotion source) projected %s/%v; a live_execution grant must never materialize Shadow usability",
			got.ApprovalID, got.Purpose)
	}

	// ActiveLiveApprovals is the LIVE projection (Canary preflight + side-effect gate). It must
	// contain the live grant and NEVER the shadow one.
	liveProjection := s.ActiveLiveApprovals(clk.now())
	if len(liveProjection) != 1 {
		t.Fatalf("ActiveLiveApprovals must project exactly the one active live grant, got %d", len(liveProjection))
	}
	if got := liveProjection[0]; got.ApprovalID != lvReq.ApprovalID || got.Purpose != PurposeLiveExecution {
		t.Fatalf("SECURITY: ActiveLiveApprovals (the live side-effect authority) projected %s/%v; a shadow_evaluation grant must never authorize a real side effect",
			got.ApprovalID, got.Purpose)
	}
}

// A REVOKED live grant must leave the live projection immediately — the revoke path is the
// operator's only instant withdrawal of side-effect authority, and it is the projection filter
// (StatusActive), not the consumer, that enforces it here.
func TestActiveLiveApprovals_RevokedGrantLeavesProjection(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	s := newTestStore(t, clk)

	in := liveRequest(clk)
	req, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("create live request: %v", err)
	}
	if _, err := s.Approve(req.ApprovalID, "approver@corp", matchingTarget(in)); err != nil {
		t.Fatalf("approve live: %v", err)
	}
	if len(s.ActiveLiveApprovals(clk.now())) != 1 {
		t.Fatal("precondition: the approved live grant must be in the live projection")
	}

	if _, err := s.Revoke(req.ApprovalID, "oncall@corp", in.Tenant, "incident"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got := s.ActiveLiveApprovals(clk.now()); len(got) != 0 {
		t.Fatalf("SECURITY: a revoked live_execution grant must leave the live projection immediately, got %d", len(got))
	}
}

// An EXPIRED live grant must leave the live projection at and after its deadline, without any
// status write — expiry is evaluated against the caller's clock, so a node that never ran a
// prune still refuses. Pinned at the projection because that is the boundary the Canary
// preflight and the side-effect gate read.
func TestActiveLiveApprovals_ExpiredGrantLeavesProjection(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	s := newTestStore(t, clk)

	in := liveRequest(clk) // expiry = now + 1h
	req, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("create live request: %v", err)
	}
	if _, err := s.Approve(req.ApprovalID, "approver@corp", matchingTarget(in)); err != nil {
		t.Fatalf("approve live: %v", err)
	}

	justBefore := in.ExpiresAt.Add(-time.Nanosecond)
	if got := s.ActiveLiveApprovals(justBefore); len(got) != 1 {
		t.Fatalf("a live grant must still project one nanosecond before its expiry, got %d", len(got))
	}
	// AT the deadline the grant is already gone (the predicate is now.Before(expiry)).
	if got := s.ActiveLiveApprovals(*in.ExpiresAt); len(got) != 0 {
		t.Fatalf("SECURITY: a live_execution grant must stop projecting AT its expiry instant, got %d", len(got))
	}
	if got := s.ActiveLiveApprovals(in.ExpiresAt.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("SECURITY: an expired live_execution grant must never project, got %d", len(got))
	}
}
