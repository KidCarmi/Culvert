package pac

import "testing"

// TestEvaluatePublish_DormantEnableRequiresDirectConfirm is the regression guard
// for the security fix that closed the DIRECT typed-confirmation laundering path.
//
// A DIRECT profile that is DISABLED serves nothing (servePACProfileFile 404s a
// disabled profile). Enabling it (disabled → enabled) makes its DIRECT full
// security-path bypass reachable to clients for the FIRST time, so the publish
// MUST demand the typed DIRECT confirmation — regardless of the fact that the
// prior (disabled) revision "already had" the same DIRECT rule.
//
// The dormant-active normalization used to live only in the CRUD guard
// (pacGuardDirectCRUD), so the same operation was gated via PUT but launderable
// through the publish/rollback lifecycle, which calls EvaluatePublish directly.
// The fix moved the normalization into EvaluatePublish so every call site agrees.
func TestEvaluatePublish_DormantEnableRequiresDirectConfirm(t *testing.T) {
	pools := pubPools()

	// A DIRECT-capable profile: availability mode appends DIRECT to the chain.
	directProfile := func(enabled bool) Profile {
		p := pubProfile(ModeAvailability)
		p.Enabled = enabled
		return p
	}

	// Baseline: the active revision is DISABLED (dormant) but carries DIRECT.
	active := directProfile(false)
	// Draft flips it enabled with the identical DIRECT capability.
	draft := directProfile(true)

	chk := EvaluatePublish(draft, pools, active, true)
	if !chk.RequiresConfirmation {
		t.Fatalf("enabling a dormant DIRECT profile must require typed confirmation; got OK=%v issues=%+v newDirect=%v",
			chk.OK, chk.Issues, chk.NewDirectPaths)
	}
	if len(chk.NewDirectPaths) == 0 {
		t.Fatal("confirmation must enumerate the newly-reachable DIRECT path(s)")
	}
}

// TestEvaluatePublish_EnabledToEnabledNoChurn proves the fix does not add
// friction where none is due: re-publishing an ALREADY-ENABLED DIRECT profile
// with the same DIRECT footprint must NOT re-trigger the confirmation (the
// DIRECT path was already reachable, so nothing new is exposed).
func TestEvaluatePublish_EnabledToEnabledNoChurn(t *testing.T) {
	pools := pubPools()
	active := pubProfile(ModeAvailability) // enabled true by default
	draft := pubProfile(ModeAvailability)
	draft.Description = "cosmetic edit"

	chk := EvaluatePublish(draft, pools, active, true)
	if chk.RequiresConfirmation {
		t.Fatalf("re-publishing an already-enabled DIRECT profile must not re-demand confirmation; newDirect=%v",
			chk.NewDirectPaths)
	}
	if !chk.OK {
		t.Fatalf("cosmetic edit of a valid enabled profile should publish cleanly: %+v", chk.Issues)
	}
}
