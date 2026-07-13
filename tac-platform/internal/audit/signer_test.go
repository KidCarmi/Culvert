package audit

import (
	"testing"

	"github.com/kidcarmi/tac-platform/internal/domain"
)

// R7-F1: a signature minted in one domain must be INVALID in every other domain.
func TestSigner_DomainSeparation(t *testing.T) {
	s := DefaultTestSigner()
	payload := []byte("the-thing-being-signed")
	planSig := s.Sign(domain.SigPlan, payload)
	apprSig := s.Sign(domain.SigApproval, payload)
	auditSig := s.Sign(domain.SigAudit, payload)

	if planSig == apprSig || planSig == auditSig || apprSig == auditSig {
		t.Fatal("signatures across domains must differ")
	}
	// each verifies in its own domain
	if !s.Verify(domain.SigPlan, payload, planSig) || !s.Verify(domain.SigApproval, payload, apprSig) || !s.Verify(domain.SigAudit, payload, auditSig) {
		t.Fatal("same-domain verify must succeed")
	}
	// cross-domain verify must fail
	if s.Verify(domain.SigApproval, payload, planSig) {
		t.Fatal("plan sig must NOT verify as approval")
	}
	if s.Verify(domain.SigAudit, payload, planSig) {
		t.Fatal("plan sig must NOT verify as audit")
	}
	if s.Verify(domain.SigPlan, payload, auditSig) {
		t.Fatal("audit sig must NOT verify as plan")
	}
}

func TestSigner_SharedKeyPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("shared keys must panic (structural separation)")
		}
	}()
	NewSigner([]byte("same"), []byte("same"), []byte("audit"), "a", "b", "c")
}
