package rollout

import (
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// lastReason is the highest mcperr.Reason this build knows about. It MUST be the
// final appended reason; the parity loop scans [0, lastReason]. When a new reason
// is appended to mcperr, extend this and classify it in hardfail.go.
const lastReason = mcperr.ReasonUpstreamDiscoveryFailed

// TestHardFailureClassificationComplete is the anti-drift wall: every mapped
// mcperr.Reason MUST have an explicit classification (a hard class OR an explicit
// non-hard entry), and the two tables MUST be disjoint. A newly introduced
// security reason that is left unclassified fails this test.
func TestHardFailureClassificationComplete(t *testing.T) {
	for r := mcperr.Reason(0); r <= lastReason; r++ {
		// Only reasons that are actually mapped (have a stable code) are in scope;
		// an unmapped iota gap would report code "unknown(n)".
		if strings.HasPrefix(r.Code(), "unknown(") {
			continue
		}
		_, inHard := hardClass[r]
		_, inNot := explicitlyNotHard[r]
		if inHard && inNot {
			t.Fatalf("reason %d (%q) is in BOTH hardClass and explicitlyNotHard", r, r.Code())
		}
		if !inHard && !inNot {
			t.Fatalf("reason %d (%q) is UNCLASSIFIED — add it to hardClass or explicitlyNotHard in hardfail.go", r, r.Code())
		}
		if !classified(r) {
			t.Fatalf("classified(%q) = false", r.Code())
		}
	}
}

// TestHardFailureCoreClasses proves the seven mandated security classes each map
// at least one representative reason and always block.
func TestHardFailureCoreClasses(t *testing.T) {
	reps := map[HardClass]mcperr.Reason{
		HardAuthIdentity:       mcperr.ReasonTokenExpired,
		HardServerTrust:        mcperr.ReasonUnregisteredServer,
		HardCredentialSafety:   mcperr.ReasonCredentialScopeMismatch,
		HardAvailabilityBounds: mcperr.ReasonResourceLimit,
		HardDestinationSafety:  mcperr.ReasonSSRFBlocked,
		HardToolTrust:          mcperr.ReasonUnknownTool,
		HardManagementSafety:   mcperr.ReasonManagementToolUnauthorized,
		HardInspectionPrivacy:  mcperr.ReasonSecretDetected,
	}
	for want, r := range reps {
		if got := Classify(r); got != want {
			t.Fatalf("Classify(%q) = %v, want %v", r.Code(), got, want)
		}
		if !IsHardFailure(r) {
			t.Fatalf("IsHardFailure(%q) = false, want true", r.Code())
		}
	}
}

// TestNonHardNeverBlocks proves an ordinary/informational reason is not a hard
// failure (so a rollout mode may apply its own semantics to it).
func TestNonHardNeverBlocks(t *testing.T) {
	for _, r := range []mcperr.Reason{mcperr.ReasonObserveOnly, mcperr.ReasonRolloutOutOfScope, mcperr.ReasonNone} {
		if IsHardFailure(r) {
			t.Fatalf("IsHardFailure(%q) = true, want false", r.Code())
		}
		if Classify(r) != HardNone {
			t.Fatalf("Classify(%q) != HardNone", r.Code())
		}
	}
}
