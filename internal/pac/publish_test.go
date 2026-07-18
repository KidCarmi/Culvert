package pac

import "testing"

func pubProfile(mode string) Profile {
	return Profile{ID: "hq", Name: "HQ", Enabled: true, PoolID: "main",
		PrivateNetworks: PrivateProxy, AvailabilityMode: mode}
}

func pubPools() map[string]Pool {
	return map[string]Pool{"main": {ID: "main", Endpoints: []PoolEndpoint{{Host: "p.example", Port: 8080}}}}
}

// ─── Lifecycle: publish, immutability, rollback ───────────────────────────────

func TestLifecycle_PublishAndRollback(t *testing.T) {
	lc := &ProfileLifecycle{ProfileID: "hq"}
	pools := pubPools()

	// First publish (revision 1).
	v1 := pubProfile(ModeBalanced)
	chk := EvaluatePublish(v1, pools, Profile{}, false)
	if !chk.OK && !chk.RequiresConfirmation {
		t.Fatalf("first publish should be publishable: %+v", chk.Issues)
	}
	n1 := lc.Publish(v1, chk.Digest, "admin", "initial", "2026-01-01T00:00:00Z")
	if n1 != 1 || lc.ActiveN != 1 {
		t.Fatalf("first revision must be 1, got %d (active %d)", n1, lc.ActiveN)
	}

	// Second publish (revision 2).
	v2 := pubProfile(ModeBalanced)
	v2.Description = "v2"
	chk = EvaluatePublish(v2, pools, v1, true)
	n2 := lc.Publish(v2, chk.Digest, "admin", "tweak", "2026-01-02T00:00:00Z")
	if n2 != 2 || lc.ActiveN != 2 {
		t.Fatalf("second revision must be 2, got %d", n2)
	}

	// Immutability: revision 1's stored spec is untouched by later edits.
	r1, ok := lc.revisionByN(1)
	if !ok || r1.Spec.Description != "" {
		t.Errorf("revision 1 must be immutable, got desc %q", r1.Spec.Description)
	}
	if prev, ok := lc.PreviousRevision(); !ok || prev.N != 1 {
		t.Errorf("previous revision of active(2) must be 1, got %+v", prev)
	}

	// Rollback to revision 1: creates revision 3 (monotonic, history intact).
	n3, ok := lc.Rollback(1, "admin", "2026-01-03T00:00:00Z")
	if !ok || n3 != 3 || lc.ActiveN != 3 {
		t.Fatalf("rollback must mint revision 3, got %d (ok=%v)", n3, ok)
	}
	if len(lc.Revisions) != 3 {
		t.Errorf("rollback must preserve history (3 revisions), got %d", len(lc.Revisions))
	}
	r3, _ := lc.revisionByN(3)
	if r3.Spec.Description != "" { // rollback restored v1's content
		t.Errorf("rollback should restore revision 1 content, got desc %q", r3.Spec.Description)
	}
	if r3.Digest != r1.Digest {
		t.Errorf("rollback must restore the exact prior artifact digest: %q vs %q", r3.Digest, r1.Digest)
	}

	// Rollback to a nonexistent revision fails.
	if _, ok := lc.Rollback(99, "admin", "2026-01-04T00:00:00Z"); ok {
		t.Error("rollback to unknown revision must fail")
	}
}

// ─── Publish guardrails ───────────────────────────────────────────────────────

func TestEvaluatePublish_Guardrails(t *testing.T) {
	pools := pubPools()

	// Missing pool → no valid proxy route.
	bad := pubProfile(ModeBalanced)
	bad.PoolID = "gone"
	chk := EvaluatePublish(bad, pools, Profile{}, false)
	if chk.OK || !hasIssue(chk.Issues, GuardMissingPool) && !hasIssue(chk.Issues, IssueUnknownPool) {
		t.Errorf("missing pool must block publish: %+v", chk.Issues)
	}

	// Validation failure (bad rule) blocks.
	badRule := pubProfile(ModeBalanced)
	badRule.Rules = []Rule{{Kind: "regex", Pattern: ".*", Action: ActionDirect}}
	chk = EvaluatePublish(badRule, pools, Profile{}, false)
	if chk.OK {
		t.Error("invalid rule must block publish")
	}

	// Valid secure profile publishes without confirmation.
	sec := pubProfile(ModeSecure)
	chk = EvaluatePublish(sec, pools, Profile{}, false)
	if !chk.OK {
		t.Errorf("valid secure profile should publish cleanly: %+v", chk.Issues)
	}
}

func TestEvaluatePublish_NewDirectRequiresConfirmation(t *testing.T) {
	pools := pubPools()
	active := pubProfile(ModeBalanced) // no DIRECT
	// Candidate adds a DIRECT rule → new DIRECT path → confirmation required.
	cand := pubProfile(ModeBalanced)
	cand.Rules = []Rule{{Kind: RuleKindDomain, Pattern: "x.example", Action: ActionDirect}}
	chk := EvaluatePublish(cand, pools, active, true)
	if chk.OK {
		t.Error("a new DIRECT path must NOT be OK without confirmation")
	}
	if !chk.RequiresConfirmation || len(chk.NewDirectPaths) == 0 {
		t.Errorf("new DIRECT path must require typed confirmation: %+v", chk)
	}

	// Switching to availability mode is also a new DIRECT path.
	cand2 := pubProfile(ModeAvailability)
	chk = EvaluatePublish(cand2, pools, active, true)
	if !chk.RequiresConfirmation {
		t.Error("availability mode over a non-availability active must require confirmation")
	}
}

func TestEvaluatePublish_SecureModeCannotProduceDirect(t *testing.T) {
	pools := pubPools()
	// A secure profile that (via a replayed spec) carries a DIRECT rule: the
	// compiler neutralizes it, so EvaluatePublish must NOT see DIRECT and the
	// guard must pass (the compile-time enforcement is what protects us). But
	// a secure profile with privateNetworks=direct is rejected by validation.
	p := pubProfile(ModeSecure)
	p.PrivateNetworks = PrivateDirect
	chk := EvaluatePublish(p, pools, Profile{}, false)
	if chk.OK {
		t.Error("secure + privateNetworks=direct must be rejected by validation")
	}
}

func TestLifecycle_TouchDraftDirty(t *testing.T) {
	lc := &ProfileLifecycle{ProfileID: "hq"}
	v1 := pubProfile(ModeBalanced)
	lc.Publish(v1, "digest1", "admin", "init", "2026-01-01T00:00:00Z")
	// Draft equal to active → not dirty.
	lc.TouchDraft(v1)
	if lc.DraftDirty {
		t.Error("unchanged draft must not be dirty")
	}
	// Edited draft → dirty.
	edited := v1
	edited.Description = "changed"
	lc.TouchDraft(edited)
	if !lc.DraftDirty {
		t.Error("edited draft must be dirty")
	}
}

func hasIssue(issues []ValidationIssue, code string) bool {
	for i := range issues {
		if issues[i].Code == code {
			return true
		}
	}
	return false
}
