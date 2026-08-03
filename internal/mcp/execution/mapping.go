package execution

import (
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// mapAction maps a PR-6 policy action to the rollout-local action kind. It
// preserves the allow-class distinction exactly (the rollout resolver relies on
// it). This mapping lives here (not in the rollout leaf) so rollout never imports
// the policy engine.
func mapAction(a policy.Action) rollout.ActionKind {
	switch a {
	case policy.ActionAllow, policy.ActionMonitor:
		return rollout.ActionKindAllow
	case policy.ActionRequireConfirmation:
		return rollout.ActionKindConfirm
	case policy.ActionRequireApproval:
		return rollout.ActionKindApproval
	case policy.ActionAllowOnce:
		return rollout.ActionKindAllowOnce
	case policy.ActionAllowForSession:
		return rollout.ActionKindAllowSession
	case policy.ActionAllowWithRedaction:
		return rollout.ActionKindRedaction
	default:
		// DENY, QUARANTINE, and any invalid action are block-class.
		return rollout.ActionKindDenied
	}
}
