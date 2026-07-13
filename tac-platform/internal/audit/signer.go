// Package audit provides purpose-separated signing and canonicalization.
// R7-F1: plan, approval, and audit signatures use DISTINCT keys, so a signature
// minted in one domain is invalid in every other domain. HMAC-SHA256 keys are a
// stand-in for distinct KMS/Ed25519 signing identities; the boundary is the point.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/kidcarmi/tac-platform/internal/domain"
)

// Signer holds one key per signing domain. In production these are distinct
// KMS/Ed25519 key handles; here they are distinct HMAC keys.
type Signer struct {
	keys   map[domain.SigDomain][]byte
	keyIDs map[domain.SigDomain]string
}

// NewSigner builds a signer from three distinct keys. Panics if any key is shared
// (the separation is a structural invariant, not a runtime hope).
func NewSigner(planKey, approvalKey, auditKey []byte, planID, approvalID, auditID string) *Signer {
	if hex.EncodeToString(planKey) == hex.EncodeToString(approvalKey) ||
		hex.EncodeToString(planKey) == hex.EncodeToString(auditKey) ||
		hex.EncodeToString(approvalKey) == hex.EncodeToString(auditKey) {
		panic("audit: signing keys must be distinct per domain")
	}
	return &Signer{
		keys:   map[domain.SigDomain][]byte{domain.SigPlan: planKey, domain.SigApproval: approvalKey, domain.SigAudit: auditKey},
		keyIDs: map[domain.SigDomain]string{domain.SigPlan: planID, domain.SigApproval: approvalID, domain.SigAudit: auditID},
	}
}

// DefaultTestSigner returns deterministic distinct keys for local/dev/test use.
func DefaultTestSigner() *Signer {
	return NewSigner([]byte("k-plan-standin"), []byte("k-approval-standin"), []byte("k-audit-standin"),
		"plan-signer-v1", "approval-signer-v1", "audit-writer-v1")
}

func (s *Signer) Sign(d domain.SigDomain, payload []byte) string {
	m := hmac.New(sha256.New, s.keys[d])
	m.Write(payload)
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Signer) Verify(d domain.SigDomain, payload []byte, sig string) bool {
	want := s.Sign(d, payload)
	return hmac.Equal([]byte(want), []byte(sig))
}

func (s *Signer) KeyID(d domain.SigDomain) string { return s.keyIDs[d] }

// Canon deterministically serializes v (sorted keys) for hashing/signing.
func Canon(v any) []byte {
	b, _ := json.Marshal(v) // encoding/json sorts map keys; structs use field order
	return b
}

func Sha256Hex(b ...[]byte) string {
	h := sha256.New()
	for _, x := range b {
		h.Write(x)
	}
	return hex.EncodeToString(h.Sum(nil))
}
