//go:build lifecycle_conformance

package lifecyclemodel

// Record holds the fields the real journal record would hold at a state
// (journal_phases.go foldIdentifiers), in model symbols.
type Record struct {
	Phase     string `json:"phase"`
	PriorRef  bool   `json:"prior_ref"`
	PriorID   string `json:"prior_id"`
	TargetRef bool   `json:"target_ref"`
	TargetID  string `json:"target_id"`
}

// RecordForState returns the journal record the model expects at s.
func RecordForState(s State) Record {
	seen := stagesSeen[s.JR]
	r := Record{Phase: s.JR, PriorRef: seen >= 1 && s.Prior == priorValid, TargetRef: seen >= 2, TargetID: s.TID}
	if seen >= 1 && s.Prior != priorDown {
		r.PriorID = imgP
	}
	return r
}

// ReconcileInputs is the reconcile decision's input in model symbols: image ids and
// digests are "P", "T", "X" or empty.
type ReconcileInputs struct {
	Kind           string
	Mode           string
	Phase          string
	Attempts       int
	MaxAttempts    int
	RefValid       bool
	RunningID      string
	TargetID       string
	PriorID        string
	RunningDigests []string
	TargetDigests  []string
	PriorDigests   []string
	TagDigests     []string
}

// ReconcileInputsForState is how a startup caller would populate the reconcile inputs
// from the record plus Docker truth. ASSUMPTION: no such caller exists on main
// (contract AGT-900); this mapping is the model's.
func ReconcileInputsForState(s State) ReconcileInputs {
	r := RecordForState(s)
	in := ReconcileInputs{Kind: "upgrades.apply", Phase: s.JR, MaxAttempts: 3,
		RefValid: r.PriorRef || r.TargetRef, TargetID: r.TargetID, PriorID: r.PriorID,
		TagDigests: []string{s.Tag}}
	if s.Running != imgNone {
		in.RunningID = s.Running
		if s.Running != imgP || s.Prior == priorValid {
			in.RunningDigests = []string{s.Running}
		}
	}
	if r.TargetRef {
		in.TargetDigests = []string{imgT}
	}
	if r.PriorRef {
		in.PriorDigests = []string{imgP}
	}
	return in
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func sameImage(a, b string, da, db []string) bool {
	return (a != "" && a == b) || intersects(da, db)
}

func isSafePhase(p string) bool {
	return p == "admitted" || p == "captured" || p == "resolved" || p == "pulled"
}

// ReconcileSpec is the reference decision table, transcribed from
// roadmap/RISK-022-PR-E design section 0 (v2). It returns (action, reason).
func ReconcileSpec(i ReconcileInputs) (action, reason string) {
	if i.Kind == "rollbacks.create" && i.Mode == "data" {
		return "data_manual", "data_window_manual"
	}
	if !i.RefValid {
		return "loud_stop", "invalid_record_ref"
	}
	if i.MaxAttempts > 0 && i.Attempts >= i.MaxAttempts {
		return "loud_stop", "reconcile_exhausted"
	}
	return reconcileImages(i)
}

func reconcileImages(i ReconcileInputs) (action, reason string) {
	liveT := sameImage(i.RunningID, i.TargetID, i.RunningDigests, i.TargetDigests)
	liveP := sameImage(i.RunningID, i.PriorID, i.RunningDigests, i.PriorDigests)
	pEqT := sameImage(i.PriorID, i.TargetID, i.PriorDigests, i.TargetDigests)
	switch {
	case liveT && pEqT:
		return "verify_adopt_else_rollback", "live_target_prior_equals_target"
	case liveT:
		return "verify_adopt_else_rollback", "live_target"
	case intersects(i.TagDigests, i.TargetDigests):
		return "reup", "tag_advanced_container_stale"
	case liveP:
		return "noop", "already_on_prior"
	case isSafePhase(i.Phase):
		return "noop", "safe_boundary_confirmed"
	case i.PriorID != "" || len(i.PriorDigests) > 0:
		return "rollback_to_prior", "indeterminate_restore_prior"
	}
	return "loud_stop", "no_recovery_target"
}
