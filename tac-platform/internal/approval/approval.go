// Package approval mints and verifies plan-bound human approvals.
package approval

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/kidcarmi/tac-platform/internal/audit"
	"github.com/kidcarmi/tac-platform/internal/domain"
)

// Build creates an approval bound to the exact plan signature and signed by the
// approver's identity (domain=approval). Rejects an author-approver (R7-F3 / four-eyes).
func Build(op domain.Operation, p domain.Plan, approver string, s *audit.Signer, now time.Time) (domain.Approval, error) {
	if approver == op.InitiatingActor {
		return domain.Approval{}, domain.Err(domain.CodeApprovalInvalid, "approver is the plan author (four-eyes)")
	}
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	aid := "APPROVAL-" + hex.EncodeToString(buf)
	payload := audit.Canon(map[string]any{
		"op_id": op.ID, "plan_id": p.PlanID, "plan_signature": p.Signature,
		"decision": "APPROVED", "approver": approver,
	})
	return domain.Approval{
		ApprovalID: aid, Scope: op.Scope, OpID: op.ID, PlanID: p.PlanID,
		BoundPlanSignature: p.Signature, Approver: approver, ApproverIsAuthor: false,
		ApproverSignature: s.Sign(domain.SigApproval, payload), Decision: "APPROVED",
		SingleUseConsumed: false, CreatedAt: now.UTC(), ExpiresAt: p.ExpiresAt,
	}, nil
}

// Verify checks an approval against the operation's CURRENT plan at execute time.
// Rejects: plan mismatch, changed signature (stale/changed plan/commit/digest),
// expiry, already-consumed, author-approver, and forged approver signature.
func Verify(op domain.Operation, currentPlan domain.Plan, a domain.Approval, s *audit.Signer, now time.Time) error {
	if a.OpID != op.ID {
		return domain.Err(domain.CodeApprovalInvalid, "approval/op mismatch")
	}
	if a.PlanID != currentPlan.PlanID {
		return domain.ErrD(domain.CodeApprovalInvalid, "approval/plan mismatch", "current plan changed since approval")
	}
	if a.BoundPlanSignature != currentPlan.Signature {
		return domain.ErrD(domain.CodeApprovalInvalid, "plan signature changed", "commit/digest/config changed after approval")
	}
	if a.ApproverIsAuthor || a.Approver == op.InitiatingActor {
		return domain.Err(domain.CodeApprovalInvalid, "approver is the plan author")
	}
	if a.SingleUseConsumed {
		return domain.Err(domain.CodeApprovalInvalid, "approval already consumed (single-use)")
	}
	if now.After(a.ExpiresAt) {
		return domain.Err(domain.CodeApprovalInvalid, "approval expired")
	}
	payload := audit.Canon(map[string]any{
		"op_id": op.ID, "plan_id": a.PlanID, "plan_signature": a.BoundPlanSignature,
		"decision": "APPROVED", "approver": a.Approver,
	})
	if !s.Verify(domain.SigApproval, payload, a.ApproverSignature) {
		return domain.Err(domain.CodeApprovalInvalid, "approver signature invalid")
	}
	return nil
}
