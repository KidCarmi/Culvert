package canary

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

// TestIsReadFirstOperation_OnlyReadAndDiscovery pins the request-time read-first gate (§5,
// Codex P1-A): ONLY OpRead and OpDiscovery qualify. Critically, OpControl must NOT — the
// scope-level RiskClass axis folds OpControl into RiskRead (mapRisk), so this finer predicate
// is the ONLY place a control-plane operation is excluded from a read-first Canary.
func TestIsReadFirstOperation_OnlyReadAndDiscovery(t *testing.T) {
	readFirst := []policy.OperationClass{policy.OpRead, policy.OpDiscovery}
	for _, c := range readFirst {
		if !IsReadFirstOperation(c) {
			t.Errorf("OperationClass %v must be read-first", c)
		}
	}
	notReadFirst := []policy.OperationClass{policy.OpUnset, policy.OpWrite, policy.OpDestructive, policy.OpControl}
	for _, c := range notReadFirst {
		if IsReadFirstOperation(c) {
			t.Errorf("SECURITY: OperationClass %v must NOT be read-first (a read-first Canary must never execute it)", c)
		}
	}
}

// TestIsReadFirstOperation_ControlIsExcluded is the explicit control-plane regression (Codex
// P1-A): a control operation is not a read, even though rollout.RiskClass cannot express that.
func TestIsReadFirstOperation_ControlIsExcluded(t *testing.T) {
	if IsReadFirstOperation(policy.OpControl) {
		t.Fatal("SECURITY: OpControl must be rejected by the request-time read-first gate; the RiskClass axis alone cannot exclude it")
	}
}
