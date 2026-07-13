package approval

import (
	"testing"
	"time"

	"github.com/kidcarmi/tac-platform/internal/audit"
	"github.com/kidcarmi/tac-platform/internal/domain"
)

func fixture(now time.Time) (domain.Operation, domain.Plan) {
	op := domain.Operation{ID: "OP-1", InitiatingActor: "human:alice",
		Scope: domain.Scope{TenantID: "t1"}}
	p := domain.Plan{PlanID: "PLAN-abc", OpID: "OP-1", Signature: "sig-A", ExpiresAt: now.Add(time.Minute)}
	return op, p
}

func TestApproval_AuthorRejected(t *testing.T) {
	now := time.Now()
	op, p := fixture(now)
	if _, err := Build(op, p, "human:alice", audit.DefaultTestSigner(), now); err == nil {
		t.Fatal("author must not be able to approve")
	}
}

func TestApproval_HappyVerify(t *testing.T) {
	now := time.Now()
	op, p := fixture(now)
	a, err := Build(op, p, "human:bob", audit.DefaultTestSigner(), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(op, p, a, audit.DefaultTestSigner(), now); err != nil {
		t.Fatalf("valid approval rejected: %v", err)
	}
}

func TestApproval_Expiry(t *testing.T) {
	now := time.Now()
	op, p := fixture(now)
	a, _ := Build(op, p, "human:bob", audit.DefaultTestSigner(), now)
	if err := Verify(op, p, a, audit.DefaultTestSigner(), now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired approval must be rejected")
	}
}

func TestApproval_ChangedPlanInvalidates(t *testing.T) {
	now := time.Now()
	op, p := fixture(now)
	a, _ := Build(op, p, "human:bob", audit.DefaultTestSigner(), now)
	// plan regenerated: different id AND signature (changed commit/digest)
	p2 := domain.Plan{PlanID: "PLAN-xyz", OpID: "OP-1", Signature: "sig-B", ExpiresAt: now.Add(time.Minute)}
	if err := Verify(op, p2, a, audit.DefaultTestSigner(), now); err == nil {
		t.Fatal("approval bound to old plan must not apply to new plan")
	}
}

func TestApproval_ChangedSignatureInvalidates(t *testing.T) {
	now := time.Now()
	op, p := fixture(now)
	a, _ := Build(op, p, "human:bob", audit.DefaultTestSigner(), now)
	// same plan id, but signature changed (e.g. digest changed) -> stale
	p.Signature = "sig-CHANGED"
	if err := Verify(op, p, a, audit.DefaultTestSigner(), now); err == nil {
		t.Fatal("changed plan signature must invalidate approval")
	}
}

func TestApproval_ForgedApproverSignatureRejected(t *testing.T) {
	now := time.Now()
	op, p := fixture(now)
	a, _ := Build(op, p, "human:bob", audit.DefaultTestSigner(), now)
	a.ApproverSignature = "deadbeef"
	if err := Verify(op, p, a, audit.DefaultTestSigner(), now); err == nil {
		t.Fatal("forged approver signature must be rejected")
	}
}
