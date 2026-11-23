package server

import (
	"strings"
	"testing"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// Symbolic image ids for the V2 tests: P (prior), T (target), X (neither).
const imgOther = "9999999999999999999999999999999999999999999999999999999999999999"

var (
	idP = "sha256:" + imgPrior
	idT = "sha256:" + imgTarget
	idX = "sha256:" + imgOther
)

// v2Base is an upgrades.apply record at `restarted` whose refs validated, with
// the prior image running under the tag and both images local.
func v2Base() reconcileInputsV2 {
	return reconcileInputsV2{
		Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarted,
		RefValid: true, TargetRefPresent: true, PriorRefPresent: true,
		TargetDigest: manTarget, PriorImageID: idP, MaxAttempts: 2,
		DockerReadable: true, RunningImageID: idP, ContainerRunning: true,
		TagImageID: idP, TargetLocalID: idT, PriorLocalID: idP,
	}
}

// TestReconcileDecisionV2_FailureMatrix pins one verdict per row of the AGT-900
// failure matrix (A1..X5; X6, a corrupt record, never reaches the decision:
// startup refuses to serve). The row names are the proposal's.
func TestReconcileDecisionV2_FailureMatrix(t *testing.T) {
	type row struct {
		name   string
		mod    func(*reconcileInputsV2)
		action reconcileActionV2
		reason string
	}
	ph := func(p journal.Phase) func(*reconcileInputsV2) {
		return func(in *reconcileInputsV2) { in.Phase = p }
	}
	all := func(fs ...func(*reconcileInputsV2)) func(*reconcileInputsV2) {
		return func(in *reconcileInputsV2) {
			for _, f := range fs {
				f(in)
			}
		}
	}
	runTag := func(run, tag string) func(*reconcileInputsV2) {
		return func(in *reconcileInputsV2) { in.RunningImageID, in.TagImageID = run, tag }
	}
	noRefs := func(in *reconcileInputsV2) {
		in.RefValid, in.TargetRefPresent, in.PriorRefPresent, in.TargetLocalID, in.PriorLocalID = false, false, false, "", ""
	}
	verified := func(in *reconcileInputsV2) {
		in.Phase, in.TargetImageID, in.RunningDigests = journal.PhaseVerified, idT, []string{repo + "@sha256:" + manTarget}
		in.RunningImageID, in.TagImageID, in.Probe = idT, idT, probeReady
	}
	armed := func(in *reconcileInputsV2) { in.RollbackArmed = true }
	probe := func(p probeState) func(*reconcileInputsV2) {
		return func(in *reconcileInputsV2) { in.Probe = p }
	}
	standalone := func(in *reconcileInputsV2) {
		in.Kind, in.Mode, in.Phase = ops.KindRollbackCreate, "image", journal.PhaseAdmitted
		in.PriorRefPresent, in.PriorImageID, in.PriorLocalID = false, "", ""
	}
	rows := []row{
		{"A1 admitted, no refs, tag==run", all(ph(journal.PhaseAdmitted), noRefs, func(in *reconcileInputsV2) { in.PriorImageID = "" }), actV2Noop, "safe_boundary_unchanged"},
		{"A1 admitted, stack down", all(ph(journal.PhaseAdmitted), noRefs, runTag("", idP)), actV2RecoveryRequired, "stack_down_unverifiable"},
		{"A2 captured P/P", all(ph(journal.PhaseCaptured), func(in *reconcileInputsV2) { in.TargetRefPresent, in.TargetLocalID = false, "" }), actV2Noop, "safe_boundary_unchanged"},
		{"A3 pulled P/P", ph(journal.PhasePulled), actV2Noop, "safe_boundary_unchanged"},
		{"A3 pulled, tag on target (elided fsync)", all(ph(journal.PhasePulled), runTag(idP, idT)), actV2RecoveryRequired, "journal_contradicts_docker"},
		{"A4 restarting before tag P/P", ph(journal.PhaseRestarting), actV2Noop, "already_on_prior"},
		{"A4 restarting, stack was down", all(ph(journal.PhaseRestarting), runTag("", idP), func(in *reconcileInputsV2) { in.PriorImageID = "" }), actV2RecoveryRequired, "stack_down"},
		{"A5 restarting P/T", all(ph(journal.PhaseRestarting), runTag(idP, idT)), actV2Realign, "tag_ahead_container_on_prior"},
		{"A5 restarting P/T, prior has no registry ref", all(ph(journal.PhaseRestarting), runTag(idP, idT), func(in *reconcileInputsV2) { in.PriorRefPresent = false }), actV2RecoveryRequired, "prior_not_restorable"},
		{"A6 restarting after up T/T", all(ph(journal.PhaseRestarting), runTag(idT, idT)), actV2RecoveryRequired, "target_live_ungated"},
		{"A7 restarted T/T TID=T", all(runTag(idT, idT), func(in *reconcileInputsV2) { in.TargetImageID = idT }), actV2RecoveryRequired, "target_live_ungated"},
		{"A8 restarted ok_stale P/T TID=P", all(runTag(idP, idT), func(in *reconcileInputsV2) { in.TargetImageID = idP }), actV2Realign, "tag_ahead_container_on_prior"},
		{"A9 restarted, prior down, none/T", all(runTag("", idT), func(in *reconcileInputsV2) { in.PriorImageID, in.PriorRefPresent, in.PriorLocalID = "", false, "" }), actV2RecoveryRequired, "stack_down"},
		{"A10 verified T/T, ready", verified, actV2Adopt, "verified_target_live"},
		{"A10 verified T/T, not ready", all(verified, func(in *reconcileInputsV2) { in.Probe = probeNotReady }), actV2RecoveryRequired, "verified_target_not_ready"},
		{"A10 verified T/T, probe not run", all(verified, func(in *reconcileInputsV2) { in.Probe = probeNotRun }), actV2RecoveryRequired, "readiness_not_probed"},
		{"A10 verified T/T, TID=P (ambiguous)", all(verified, func(in *reconcileInputsV2) { in.TargetImageID = idP }), actV2RecoveryRequired, "verified_target_id_mismatch"},
		{"A10 verified T/T, digest not listed", all(verified, func(in *reconcileInputsV2) { in.RunningDigests = nil }), actV2RecoveryRequired, "target_digest_unverified"},
		{"A11 terminal success not retired (= A10)", verified, actV2Adopt, "verified_target_live"},
		{"A11 terminal, rollback ok, P/P, ready", all(ph(journal.PhaseRestarted), armed, probe(probeReady)), actV2Noop, "armed_rollback_prior_ready"},
		{"A11 terminal, tag left ahead P/T", runTag(idP, idT), actV2Realign, "tag_ahead_container_on_prior"},
		{"R1 rb_pull T/T not armed", runTag(idT, idT), actV2RecoveryRequired, "target_live_ungated"},
		{"R1 rb_pull T/T armed (Decision 1: finish)", all(runTag(idT, idT), armed), actV2RetagFinishRollback, "rollback_armed_tag_not_moved"},
		{"R1 rb P/T armed", all(runTag(idP, idT), armed), actV2Realign, "tag_ahead_container_on_prior"},
		{"R1 rb P/P, ready", all(armed, probe(probeReady)), actV2Noop, "armed_rollback_prior_ready"},
		{"R2 rb_restart after tag T/P armed", all(runTag(idT, idP), armed), actV2FinishRollback, "rollback_interrupted"},
		{"R2 T/P without marker (older agent or operator)", runTag(idT, idP), actV2RecoveryRequired, "tag_on_prior_rollback_unproven"},
		{"R2 T/P armed, prior not local", all(runTag(idT, idP), armed, func(in *reconcileInputsV2) { in.PriorLocalID = "" }), actV2RecoveryRequired, "prior_not_restorable"},
		{"R3 rb_health P/P, not ready", all(armed, probe(probeNotReady)), actV2RecoveryRequired, "armed_rollback_prior_not_ready"},
		{"R3 rb_health P/P, probe not run", armed, actV2RecoveryRequired, "readiness_not_probed"},
		{"R3 rb_verify T/P (ok_stale) armed", all(runTag(idT, idP), armed), actV2FinishRollback, "rollback_interrupted"},
		// Owner Decision 1 (2026-11-23): finish an already-armed rollback whose
		// tag never moved back ("T/T armed", real-Docker e2e finding 2), and
		// every refusal around it.
		{"F1 T/T armed at restarted: retag+up+gate+verify", all(runTag(idT, idT), armed), actV2RetagFinishRollback, "rollback_armed_tag_not_moved"},
		{"F1 T/T armed at restarting (forward up failed after recreate)", all(ph(journal.PhaseRestarting), runTag(idT, idT), armed), actV2RetagFinishRollback, "rollback_armed_tag_not_moved"},
		{"F1 T/T armed, the probe plays no part", all(runTag(idT, idT), armed, probe(probeNotReady)), actV2RetagFinishRollback, "rollback_armed_tag_not_moved"},
		{"F2 T/T armed, prior not local", all(runTag(idT, idT), armed, func(in *reconcileInputsV2) { in.PriorLocalID = "" }), actV2RecoveryRequired, "prior_not_restorable"},
		{"F2 T/T armed, PriorRef resolves to another id", all(runTag(idT, idT), armed, func(in *reconcileInputsV2) { in.PriorLocalID = idX }), actV2RecoveryRequired, "prior_not_restorable"},
		{"F2 T/T armed, record has no PriorRef", all(runTag(idT, idT), armed, func(in *reconcileInputsV2) { in.PriorRefPresent, in.PriorLocalID = false, "" }), actV2RecoveryRequired, "prior_not_restorable"},
		{"F2 T/T armed, record has no prior image id", all(runTag(idT, idT), armed, func(in *reconcileInputsV2) { in.PriorImageID = "" }), actV2RecoveryRequired, "prior_not_restorable"},
		{"F3 T/T unarmed (older agent, or arm write failed)", all(runTag(idT, idT), ph(journal.PhaseRestarting)), actV2RecoveryRequired, "target_live_ungated"},
		{"F4 T/T armed, refs failed validation", all(runTag(idT, idT), armed, func(in *reconcileInputsV2) { in.RefValid = false }), actV2RecoveryRequired, "invalid_record_ref"},
		{"F5 T/T armed, attempts exhausted", all(runTag(idT, idT), armed, func(in *reconcileInputsV2) { in.Attempts = 2 }), actV2RecoveryRequired, "reconcile_exhausted"},
		{"F6 T/T armed at verified (contradiction)", all(verified, armed), actV2RecoveryRequired, "rollback_armed_at_verified"},
		{"F6 T/P armed at verified (contradiction)", all(verified, armed, runTag(idT, idP)), actV2RecoveryRequired, "rollback_armed_at_verified"},
		{"F7 T/T armed, container stopped", all(runTag(idT, idT), armed, func(in *reconcileInputsV2) { in.ContainerRunning = false }), actV2RecoveryRequired, "container_not_running"},
		{"F8 T/T armed, target not local", all(runTag(idT, idT), armed, func(in *reconcileInputsV2) { in.TargetLocalID = "" }), actV2RecoveryRequired, "target_not_identifiable"},
		{"F8 T/T armed, target resolves to the prior", all(runTag(idT, idT), armed, func(in *reconcileInputsV2) { in.TargetLocalID = idP }), actV2RecoveryRequired, "target_equals_prior_ambiguous"},
		{"F9 X/T armed (operator started something else)", all(runTag(idX, idT), armed), actV2RecoveryRequired, "docker_state_unrecognised"},
		{"F9 T/X armed (operator moved the tag)", all(runTag(idT, idX), armed), actV2RecoveryRequired, "docker_state_unrecognised"},
		{"F10 T/T armed, Docker unreadable", all(runTag(idT, idT), armed, func(in *reconcileInputsV2) { in.DockerReadable = false }), actV2Defer, "docker_unavailable"},
		{"F11 standalone rollback T/T armed is never finished", all(standalone, runTag(idT, idT), armed), actV2RecoveryRequired, "rollback_target_partially_applied"},
		{"S1 standalone rollback, tag never moved", standalone, actV2Noop, "rollback_never_moved_tag"},
		{"S2 standalone rollback, tag on target", all(standalone, runTag(idP, idT)), actV2RecoveryRequired, "rollback_target_partially_applied"},
		{"S3 standalone rollback, target live", all(standalone, runTag(idT, idT)), actV2RecoveryRequired, "rollback_target_partially_applied"},
		{"D1 data rollback", func(in *reconcileInputsV2) { in.Kind, in.Mode = ops.KindRollbackCreate, "data" }, actV2RecoveryRequired, "data_window_manual"},
		{"X1 docker unreadable", all(runTag(idP, idT), func(in *reconcileInputsV2) { in.DockerReadable = false }), actV2Defer, "docker_unavailable"},
		{"X2 running another image", runTag(idX, idT), actV2RecoveryRequired, "docker_state_unrecognised"},
		{"X3 tag on another image", runTag(idP, idX), actV2RecoveryRequired, "docker_state_unrecognised"},
		{"X4 attempts exhausted", all(runTag(idP, idT), func(in *reconcileInputsV2) { in.Attempts = 2 }), actV2RecoveryRequired, "reconcile_exhausted"},
		{"X5 container not running", func(in *reconcileInputsV2) { in.ContainerRunning = false }, actV2RecoveryRequired, "container_not_running"},
		{"danger phase, invalid ref", func(in *reconcileInputsV2) { in.RefValid = false }, actV2RecoveryRequired, "invalid_record_ref"},
	}
	for _, r := range rows {
		in := v2Base()
		r.mod(&in)
		v := reconcileDecisionV2(in)
		if v.Action != r.action || v.Reason != r.reason {
			t.Errorf("%s: got %s/%s, want %s/%s", r.name, v.Action, v.Reason, r.action, r.reason)
		}
		if viol := v2PropertyViolations(&in, v, reconcileDecisionV2); viol != "" {
			t.Errorf("%s: %s", r.name, viol)
		}
	}
}

// ───────────────────────── exhaustive bounded space

type v2Domains struct {
	kindMode    [][2]string
	phase       []journal.Phase
	attempts    [][2]int
	bools       []bool
	tid, pid    []string
	run, tag    []string
	targetLocal []string
	priorLocal  []string
	digests     [][]string
	probe       []probeState
}

func newV2Domains() v2Domains {
	return v2Domains{
		kindMode: [][2]string{{ops.KindUpgradeApply, ""}, {ops.KindRollbackCreate, "image"}, {ops.KindRollbackCreate, "data"}, {ops.KindUpgradeApply, "data"}},
		phase: []journal.Phase{journal.PhaseAdmitted, journal.PhaseCaptured, journal.PhaseResolved, journal.PhasePulled,
			journal.PhaseRestarting, journal.PhaseRestarted, journal.PhaseVerified},
		attempts:    [][2]int{{0, 2}, {2, 2}},
		bools:       []bool{false, true},
		tid:         []string{"", idP, idT},
		pid:         []string{"", idP, idT},
		run:         []string{"", idP, idT, idX},
		tag:         []string{"", idP, idT, idX},
		targetLocal: []string{"", idT, idP},
		priorLocal:  []string{"", idP, idX},
		digests:     [][]string{nil, {repo + "@sha256:" + manTarget}, {repo + "@sha256:" + manPrior}},
		probe:       []probeState{probeNotRun, probeReady, probeNotReady},
	}
}

// v2Axis is one enumerated input dimension: n values, applied by set.
type v2Axis struct {
	n   int
	set func(in *reconcileInputsV2, i int)
}

// v2Docker is one combination of the Docker facts.
type v2Docker struct {
	readable, running bool
	run, tag, tl, pl  string
	digests           []string
}

// dockerCombos lists the Docker fact combinations. An unreadable Docker is a
// single combination: no other Docker fact is then known. full=false gives the
// reduced set used for data/unknown records, which are decided before any
// Docker fact is read (it keeps the space affordable under -race).
func (d *v2Domains) dockerCombos(full bool) []v2Docker {
	out := []v2Docker{{}}
	tags, tls, pls, dgs := d.tag, d.targetLocal, d.priorLocal, d.digests
	if !full {
		tags, tls, pls, dgs = d.tag[1:2], d.targetLocal[1:2], d.priorLocal[1:2], d.digests[:1]
	}
	for _, run := range d.run {
		for _, running := range d.bools {
			if run == "" && !running {
				continue
			}
			for _, tag := range tags {
				for _, tl := range tls {
					for _, pl := range pls {
						for _, dg := range dgs {
							out = append(out, v2Docker{true, running, run, tag, tl, pl, dg})
						}
					}
				}
			}
		}
	}
	return out
}

// recordAxes are the journal-record dimensions (and the probe) of the space.
func (d *v2Domains) recordAxes() []v2Axis {
	b := func(set func(in *reconcileInputsV2, v bool)) v2Axis {
		return v2Axis{2, func(in *reconcileInputsV2, i int) { set(in, d.bools[i]) }}
	}
	return []v2Axis{
		{len(d.phase), func(in *reconcileInputsV2, i int) { in.Phase = d.phase[i] }},
		{len(d.attempts), func(in *reconcileInputsV2, i int) { in.Attempts, in.MaxAttempts = d.attempts[i][0], d.attempts[i][1] }},
		b(func(in *reconcileInputsV2, v bool) { in.RefValid = v }),
		b(func(in *reconcileInputsV2, v bool) { in.TargetRefPresent = v }),
		b(func(in *reconcileInputsV2, v bool) { in.PriorRefPresent = v }),
		b(func(in *reconcileInputsV2, v bool) { in.RollbackArmed = v }),
		{len(d.tid), func(in *reconcileInputsV2, i int) { in.TargetImageID = d.tid[i] }},
		{len(d.pid), func(in *reconcileInputsV2, i int) { in.PriorImageID = d.pid[i] }},
		{len(d.probe), func(in *reconcileInputsV2, i int) { in.Probe = d.probe[i] }},
	}
}

// forEachV2Input enumerates the bounded V2 input space: the record axes of the
// existing reconcile table (kind/mode, phase, attempts, ref validity, journal
// ids) extended with the new axes (RollbackArmed, Docker readability, container
// state, the pinned tag's id, the local ids of both refs, the probe), in
// odometer order. fn returns false to stop early; the count is returned.
func forEachV2Input(fn func(*reconcileInputsV2) bool) int {
	d := newV2Domains()
	full, reduced := d.dockerCombos(true), d.dockerCombos(false)
	n := 0
	for _, km := range d.kindMode {
		in := reconcileInputsV2{Kind: km[0], Mode: km[1], TargetDigest: manTarget}
		dockers := reduced
		if (km[0] == ops.KindUpgradeApply && km[1] == "") || (km[0] == ops.KindRollbackCreate && km[1] == "image") {
			dockers = full
		}
		axes := append(d.recordAxes(), v2Axis{len(dockers), func(in *reconcileInputsV2, i int) {
			dk := &dockers[i]
			in.DockerReadable, in.ContainerRunning, in.RunningImageID = dk.readable, dk.running, dk.run
			in.TagImageID, in.TargetLocalID, in.PriorLocalID, in.RunningDigests = dk.tag, dk.tl, dk.pl, dk.digests
		}})
		idx := make([]int, len(axes))
		for {
			for a := range axes {
				axes[a].set(&in, idx[a])
			}
			n++
			if !fn(&in) {
				return n
			}
			a := len(idx) - 1
			for ; a >= 0; a-- {
				idx[a]++
				if idx[a] < axes[a].n {
					break
				}
				idx[a] = 0
			}
			if a < 0 {
				break
			}
		}
	}
	return n
}

// flipV2Prefixes returns in with every `sha256:` id prefix removed and the
// digests given as bare `sha256:<hex>` instead of repo references.
func flipV2Prefixes(in reconcileInputsV2) reconcileInputsV2 {
	in.RunningImageID, in.TagImageID = normID(in.RunningImageID), normID(in.TagImageID)
	in.TargetLocalID, in.PriorLocalID = normID(in.TargetLocalID), normID(in.PriorLocalID)
	in.TargetImageID, in.PriorImageID = normID(in.TargetImageID), normID(in.PriorImageID)
	in.TargetDigest = "sha256:" + normID(in.TargetDigest)
	if len(in.RunningDigests) > 0 {
		out := make([]string, len(in.RunningDigests))
		for i, r := range in.RunningDigests {
			out[i] = "sha256:" + r[strings.LastIndexByte(r, ':')+1:]
		}
		in.RunningDigests = out
	}
	return in
}

// v2PropertyViolations checks the V2 properties for one input and verdict and
// returns the first violation, or "". decide is the function under test (the
// real one, or a mutant for the negative controls).
//
//nolint:gocognit,cyclop // one flat list of independent properties reads best
func v2PropertyViolations(in *reconcileInputsV2, v reconcileVerdictV2, decide func(reconcileInputsV2) reconcileVerdictV2) string {
	ids := v2ids{run: normID(in.RunningImageID), tag: normID(in.TagImageID), prior: normID(in.PriorImageID),
		priorLocal: normID(in.PriorLocalID), tid: normID(in.TargetImageID), target: normID(in.TargetLocalID)}
	data := in.Kind == ops.KindRollbackCreate && in.Mode == "data"
	imageKind := (in.Kind == ops.KindUpgradeApply && in.Mode == "") || (in.Kind == ops.KindRollbackCreate && in.Mode == "image")
	exhausted := in.MaxAttempts > 0 && in.Attempts >= in.MaxAttempts
	mut := v.Action.mutatesDocker()
	switch {
	case v.Action.String() == "unknown":
		return "RV0 verdict outside the closed action set"
	case data && v.Action != actV2RecoveryRequired:
		return "RV1 a data rollback must only be reported"
	case imageKind && !in.DockerReadable && v.Action != actV2Defer:
		return "RV2 Docker unreadable must defer"
	case v.Action == actV2Defer && in.DockerReadable:
		return "RV3 defer only when Docker is unreadable"
	case (exhausted || !in.DockerReadable) && (mut || v.Action == actV2Adopt):
		return "RV4 no action when exhausted or Docker unreadable"
	}
	if v.Action == actV2Adopt {
		switch {
		case in.Kind != ops.KindUpgradeApply || in.Mode != "":
			return "RV5 adopt only an upgrade"
		case in.Phase != journal.PhaseVerified:
			return "RV5 adopt only at phase verified"
		case !in.RefValid || !in.TargetRefPresent || ids.target == "":
			return "RV5 adopt only a validated, locally identified target"
		case ids.run != ids.target || ids.tag != ids.target || !in.ContainerRunning:
			return "RV5 adopt only with container and tag on the target"
		case in.RollbackArmed:
			return "RV5 never adopt the target of an armed rollback"
		case in.Probe != probeReady:
			return "RV5 adopt only on a fresh ReadyOK"
		case ids.tid != ids.target:
			return "RV6 an ambiguous journal target id must never adopt"
		case !digestListed(in.RunningDigests, in.TargetDigest):
			return "RV5 adopt only when the running image carries the target digest"
		}
	}
	if mut {
		switch {
		case !imageKind || in.Kind != ops.KindUpgradeApply || safeBoundary(in.Phase):
			return "RV7 only an upgrade in the danger window is acted on"
		case !in.RefValid || !in.PriorRefPresent || ids.prior == "" || ids.priorLocal != ids.prior:
			return "RV7 act only with a validated PriorRef that resolves locally to the recorded prior"
		case !in.ContainerRunning:
			return "RV7 act only on a running container"
		}
	}
	switch v.Action {
	case actV2Realign:
		if ids.run != ids.prior || ids.tag != ids.target || ids.target == "" {
			return "RV8 realign only retags while the container provably runs the prior image"
		}
	case actV2FinishRollback:
		if ids.tag != ids.prior || !in.RollbackArmed || ids.run != ids.target || ids.target == "" {
			return "RV9 `up` only with the tag already on the prior image, after an armed rollback"
		}
		if in.Phase == journal.PhaseVerified {
			return "RV9 an armed marker at phase verified contradicts the journal: never finished"
		}
	case actV2RetagFinishRollback:
		if !in.RollbackArmed || in.Phase == journal.PhaseVerified {
			return "RV12 a T/T finish only after an armed rollback the journal does not contradict"
		}
		if ids.target == "" || ids.target == ids.prior || ids.run != ids.target || ids.tag != ids.target {
			return "RV12 a T/T finish only with container and tag provably on the distinct target"
		}
	case actV2Noop:
		if ids.run == "" || ids.tag != ids.run {
			return "RV10 noop only when tag and container agree"
		}
		if ids.target != "" && ids.target != ids.prior && (ids.run == ids.target || ids.tag == ids.target) && in.RefValid && in.TargetRefPresent {
			return "RV10 never noop with the target live or under the tag"
		}
	}
	if viol := v2ArmedOnPriorViolation(in, v, ids); viol != "" {
		return viol
	}
	if viol := v2PlanViolations(in, v, decide, reconcilePlan); viol != "" {
		return viol
	}
	if w := decide(flipV2Prefixes(*in)); w != v {
		return "RV11 verdict must not depend on id/digest notation"
	}
	return ""
}

// v2ArmedOnPriorViolation: RV16. An armed record found with container and tag
// on the prior image had a rollback `up` whose gate is not durable; it is
// retired (noop) only on a fresh ReadyOK.
func v2ArmedOnPriorViolation(in *reconcileInputsV2, v reconcileVerdictV2, ids v2ids) string {
	upgradeDanger := in.Kind == ops.KindUpgradeApply && in.Mode == "" && !safeBoundary(in.Phase)
	if v.Action == actV2Noop && upgradeDanger && in.RollbackArmed && in.Probe != probeReady {
		return "RV16 an armed rollback found on the prior image is retired only on a fresh ReadyOK"
	}
	if v.Action == actV2Noop && upgradeDanger && in.RollbackArmed && (ids.run != ids.prior || ids.tag != ids.prior) {
		return "RV16 an armed record is retired only with container and tag on the recorded prior"
	}
	return ""
}

// v2PlanViolations checks the steps an acting verdict executes (RV13-RV15) by
// applying them symbolically to the Docker facts the verdict was decided on:
// `docker tag <PriorRef>` makes the tag resolve to PriorRef's local id, and
// `compose up` makes the container run what the tag resolves to.
//
//   - RV13 structure: every mutating step carries a recheck verdict that
//     itself changes Docker; the first recheck is the verdict being executed;
//     every `up` is immediately followed by the gate, and the gate follows
//     nothing else; a plan has at most one `up` and at most one tag.
//   - RV14 an `up` is only ever issued when its recheck decides
//     finish_rollback and the tag is on the validated prior image id (the tag
//     resolves to the record's prior id and so does the validated PriorRef).
//   - RV15 closure: on the decided-on facts, each recheck is passed by the
//     state this plan's own earlier steps leave (a plan never relies on a
//     change it does not make), and the plan ends with container and tag on
//     the prior image, the state verifiedOnPrior then requires. A T/T-armed
//     finish tags exactly once, to PriorRef, before its `up`.
func v2PlanViolations(in *reconcileInputsV2, v reconcileVerdictV2, decide func(reconcileInputsV2) reconcileVerdictV2,
	plan func(reconcileVerdictV2) []reconcileStep) string {
	steps := plan(v)
	if (len(steps) > 0) != v.Action.mutatesDocker() {
		return "RV13 exactly the verdicts that change Docker have steps"
	}
	if viol := v2PlanShape(steps, v); viol != "" {
		return viol
	}
	cur := *in
	prior := normID(in.PriorImageID)
	for _, st := range steps {
		if st.op.mutates() && decide(cur) != st.expect {
			return "RV15 a recheck is not passed by the state the plan's own steps leave"
		}
		switch st.op {
		case stepTagPrior:
			cur.TagImageID = cur.PriorLocalID
		case stepUp:
			if st.expect != verdictFinishRollback || prior == "" || normID(cur.TagImageID) != prior || normID(cur.PriorLocalID) != prior {
				return "RV14 an `up` only with the tag on the validated prior image id"
			}
			cur.RunningImageID, cur.ContainerRunning = cur.TagImageID, true
		}
	}
	if len(steps) > 0 && (prior == "" || normID(cur.RunningImageID) != prior || normID(cur.TagImageID) != prior) {
		return "RV15 an acting plan must leave container and tag on the prior image"
	}
	if v.Action == actV2RetagFinishRollback && (len(steps) == 0 || steps[0].op != stepTagPrior) {
		return "RV15 a T/T-armed finish retags to PriorRef before anything else"
	}
	return ""
}

// v2PlanShape is the structural half of RV13.
func v2PlanShape(steps []reconcileStep, v reconcileVerdictV2) string {
	ups, tags := 0, 0
	for i, st := range steps {
		switch st.op {
		case stepTagPrior:
			tags++
		case stepUp:
			ups++
			if i+1 >= len(steps) || steps[i+1].op != stepGate {
				return "RV13 every `up` is immediately followed by a fresh gate"
			}
		case stepGate:
			if i == 0 || steps[i-1].op != stepUp {
				return "RV13 a gate only right after an `up`"
			}
		default:
			return "RV13 a step outside the closed set"
		}
		if st.op.mutates() && !st.expect.Action.mutatesDocker() {
			return "RV13 every mutation is guarded by a recheck of an acting verdict"
		}
	}
	if ups > 1 || tags > 1 {
		return "RV13 a plan restarts at most once and tags at most once"
	}
	if len(steps) > 0 && steps[0].expect != v {
		return "RV13 the first recheck is the verdict being executed"
	}
	return ""
}

// v2ProbeViolation: the caller probes exactly when the probe can change the
// verdict, and the probe can change it only towards adopt or the retirement of
// an armed rollback found on the prior image: never towards a Docker change.
func v2ProbeViolation(in *reconcileInputsV2) string {
	c := *in
	c.Probe = probeNotRun
	without := reconcileDecisionV2(c)
	c.Probe = probeReady
	ready := reconcileDecisionV2(c)
	if reconcileNeedsProbe(*in) != (ready != without) {
		return "reconcileNeedsProbe inconsistent"
	}
	if ready != without {
		ok := ready.Action == actV2Adopt || ready == (reconcileVerdictV2{actV2Noop, "armed_rollback_prior_ready"})
		if !ok || without.Action != actV2RecoveryRequired {
			return "the probe changed a verdict other than adopt / armed-on-prior retirement"
		}
	}
	for _, p := range []probeState{probeNotRun, probeReady, probeNotReady} {
		c.Probe = p
		if v := reconcileDecisionV2(c); v.Action.mutatesDocker() != without.Action.mutatesDocker() || (v.Action.mutatesDocker() && v != without) {
			return "the probe changed whether or how Docker is changed"
		}
	}
	return ""
}

// TestReconcileDecisionV2_ExhaustiveProperties evaluates V2 on every input of
// the bounded space, checks every property, and requires every reason to be
// produced (no vacuous branch).
func TestReconcileDecisionV2_ExhaustiveProperties(t *testing.T) {
	seen := map[string]int{}
	fails := 0
	total := forEachV2Input(func(in *reconcileInputsV2) bool {
		v := reconcileDecisionV2(*in)
		seen[v.Action.String()+"/"+v.Reason]++
		if viol := v2PropertyViolations(in, v, reconcileDecisionV2); viol != "" {
			if fails < 10 {
				t.Errorf("PROPERTY %s\n input=%+v verdict=%s/%s", viol, *in, v.Action, v.Reason)
			}
			fails++
		}
		if viol := v2ProbeViolation(in); viol != "" {
			t.Errorf("%s for %+v", viol, *in)
			return false
		}
		return true
	})
	if total < 5_000_000 {
		t.Fatalf("input space unexpectedly small: %d", total)
	}
	wantVerdicts := []string{
		"noop/safe_boundary_unchanged", "noop/already_on_prior", "noop/rollback_never_moved_tag",
		"noop/armed_rollback_prior_ready",
		"realign/tag_ahead_container_on_prior", "finish_rollback/rollback_interrupted", "adopt/verified_target_live",
		"finish_rollback_retag/rollback_armed_tag_not_moved",
		"recovery_required/rollback_armed_at_verified", "recovery_required/armed_rollback_prior_not_ready",
		"defer/docker_unavailable",
		"recovery_required/data_window_manual", "recovery_required/unknown_kind_or_mode",
		"recovery_required/reconcile_exhausted", "recovery_required/container_not_running",
		"recovery_required/journal_contradicts_docker", "recovery_required/stack_down_unverifiable",
		"recovery_required/tag_differs_from_running", "recovery_required/running_not_prior",
		"recovery_required/invalid_record_ref", "recovery_required/stack_down",
		"recovery_required/target_not_identifiable", "recovery_required/target_equals_prior_ambiguous",
		"recovery_required/prior_not_restorable",
		"recovery_required/target_live_ungated", "recovery_required/verified_target_id_mismatch",
		"recovery_required/target_digest_unverified", "recovery_required/verified_target_not_ready",
		"recovery_required/readiness_not_probed", "recovery_required/tag_on_prior_rollback_unproven",
		"recovery_required/docker_state_unrecognised", "recovery_required/rollback_target_partially_applied",
	}
	for _, w := range wantVerdicts {
		if seen[w] == 0 {
			t.Errorf("VACUOUS: verdict %q never produced", w)
		}
	}
	if len(seen) != len(wantVerdicts) {
		t.Errorf("verdicts produced %d, listed %d: %v", len(seen), len(wantVerdicts), seen)
	}
	t.Logf("%d inputs, %d property violations, verdicts=%v", total, fails, seen)
}

// TestReconcileDecisionV2_NegativeControls: each mutant reintroduces one unsafe
// verdict the owner decision forbids; the property check must catch every one
// somewhere in the bounded space (otherwise the properties are not strong
// enough to protect the decision).
func TestReconcileDecisionV2_NegativeControls(t *testing.T) {
	live := func(in reconcileInputsV2) bool {
		ids := idsOf(&in)
		return in.Kind == ops.KindUpgradeApply && in.DockerReadable && ids.target != "" && ids.run == ids.target && ids.tag == ids.target
	}
	mutants := map[string]func(reconcileInputsV2) reconcileVerdictV2{
		"adopt at phase restarted": func(in reconcileInputsV2) reconcileVerdictV2 {
			if in.Phase == journal.PhaseRestarted && live(in) {
				return reconcileVerdictV2{actV2Adopt, "verified_target_live"}
			}
			return reconcileDecisionV2(in)
		},
		"adopt without a ready probe": func(in reconcileInputsV2) reconcileVerdictV2 {
			if in.Phase == journal.PhaseVerified && live(in) && !in.RollbackArmed {
				return reconcileVerdictV2{actV2Adopt, "verified_target_live"}
			}
			return reconcileDecisionV2(in)
		},
		"adopt an armed rollback's target": func(in reconcileInputsV2) reconcileVerdictV2 {
			c := in
			c.RollbackArmed = false
			if v := reconcileDecisionV2(c); v.Action == actV2Adopt {
				return v
			}
			return reconcileDecisionV2(in)
		},
		"realign with an unverified prior": func(in reconcileInputsV2) reconcileVerdictV2 {
			c := in
			c.PriorLocalID = c.PriorImageID
			if v := reconcileDecisionV2(c); v.Action == actV2Realign {
				return v
			}
			return reconcileDecisionV2(in)
		},
		"reup: finish a rollback with the tag on the target": func(in reconcileInputsV2) reconcileVerdictV2 {
			if v := reconcileDecisionV2(in); v.Reason == "target_live_ungated" {
				return reconcileVerdictV2{actV2FinishRollback, "rollback_interrupted"}
			}
			return reconcileDecisionV2(in)
		},
		"act while Docker is unreadable": func(in reconcileInputsV2) reconcileVerdictV2 {
			if !in.DockerReadable && in.Kind == ops.KindUpgradeApply {
				return reconcileVerdictV2{actV2Noop, "safe_boundary_unchanged"}
			}
			return reconcileDecisionV2(in)
		},
		"trust TargetImageID before verified": func(in reconcileInputsV2) reconcileVerdictV2 {
			if in.Phase == journal.PhaseRestarted && normID(in.TargetImageID) == normID(in.TargetLocalID) && in.Probe == probeReady && live(in) {
				return reconcileVerdictV2{actV2Adopt, "verified_target_live"}
			}
			return reconcileDecisionV2(in)
		},
	}
	for k, m := range v2ArmedFinishMutants() {
		mutants[k] = m
	}
	for name, m := range mutants {
		caught := ""
		forEachV2Input(func(in *reconcileInputsV2) bool {
			caught = v2PropertyViolations(in, m(*in), m)
			return caught == ""
		})
		if caught == "" {
			t.Errorf("mutant %q survived the property check", name)
		} else {
			t.Logf("mutant %q killed: %s", name, caught)
		}
	}
}

// v2Promote returns a mutant that answers the verdict of the input as changed
// by mod whenever take accepts that verdict, and the real verdict otherwise.
func v2Promote(mod func(*reconcileInputsV2), take func(reconcileVerdictV2) bool) func(reconcileInputsV2) reconcileVerdictV2 {
	return func(in reconcileInputsV2) reconcileVerdictV2 {
		c := in
		mod(&c)
		if v := reconcileDecisionV2(c); take(v) {
			return v
		}
		return reconcileDecisionV2(in)
	}
}

// v2ArmedFinishMutants are the decision mutants of owner Decision 1 (finish an
// already-armed rollback): each one finishes, or retires, on evidence the
// decision must refuse.
func v2ArmedFinishMutants() map[string]func(reconcileInputsV2) reconcileVerdictV2 {
	retag := func(v reconcileVerdictV2) bool { return v.Action == actV2RetagFinishRollback }
	return map[string]func(reconcileInputsV2) reconcileVerdictV2{
		"finish T/T when unarmed": v2Promote(func(c *reconcileInputsV2) { c.RollbackArmed = true }, retag),
		"finish T/T at phase verified": v2Promote(func(c *reconcileInputsV2) {
			if c.Phase == journal.PhaseVerified {
				c.Phase = journal.PhaseRestarted
			}
		}, retag),
		"finish T/T with an unverified prior image":              v2Promote(func(c *reconcileInputsV2) { c.PriorLocalID = c.PriorImageID }, retag),
		"finish T/T from a record whose refs failed validation":  v2Promote(func(c *reconcileInputsV2) { c.RefValid = true }, retag),
		"finish T/T past the attempt cap":                        v2Promote(func(c *reconcileInputsV2) { c.Attempts = 0 }, retag),
		"finish an armed rollback with the tag on another image": v2Promote(func(c *reconcileInputsV2) { c.TagImageID = c.TargetLocalID }, retag),
		"retire an armed rollback on the prior without a ready probe": v2Promote(func(c *reconcileInputsV2) { c.Probe = probeReady },
			func(v reconcileVerdictV2) bool { return v.Reason == "armed_rollback_prior_ready" }),
	}
}

// TestReconcilePlan_NegativeControls: each mutant plan reintroduces one unsafe
// step order the owner decision forbids for an acting verdict; the plan
// properties (RV13-RV15) must catch every one somewhere in the bounded space.
func TestReconcilePlan_NegativeControls(t *testing.T) {
	retag := reconcileVerdictV2{actV2RetagFinishRollback, "rollback_armed_tag_not_moved"}
	mutants := map[string]func(reconcileVerdictV2) []reconcileStep{
		"T/T finish without the fresh gate": func(v reconcileVerdictV2) []reconcileStep {
			if v == retag {
				return []reconcileStep{{stepTagPrior, v}, {stepUp, verdictFinishRollback}}
			}
			return reconcilePlan(v)
		},
		"T/T finish: `up` before the retag": func(v reconcileVerdictV2) []reconcileStep {
			if v == retag {
				return []reconcileStep{{stepUp, v}, {op: stepGate}, {stepTagPrior, v}}
			}
			return reconcilePlan(v)
		},
		"T/T finish: `up` without the retag": func(v reconcileVerdictV2) []reconcileStep {
			if v == retag {
				return []reconcileStep{{stepUp, verdictFinishRollback}, {op: stepGate}}
			}
			return reconcilePlan(v)
		},
		"T/T finish: pre-up recheck expects the stale T/T verdict": func(v reconcileVerdictV2) []reconcileStep {
			if v == retag {
				return []reconcileStep{{stepTagPrior, v}, {stepUp, v}, {op: stepGate}}
			}
			return reconcilePlan(v)
		},
		"T/P finish: a second `up` after the gate": func(v reconcileVerdictV2) []reconcileStep {
			if v == verdictFinishRollback {
				return []reconcileStep{{stepUp, v}, {op: stepGate}, {stepUp, v}, {op: stepGate}}
			}
			return reconcilePlan(v)
		},
		"realign restarts": func(v reconcileVerdictV2) []reconcileStep {
			if v.Action == actV2Realign {
				return []reconcileStep{{stepTagPrior, v}, {stepUp, v}, {op: stepGate}}
			}
			return reconcilePlan(v)
		},
		"T/T finish stops after the retag": func(v reconcileVerdictV2) []reconcileStep {
			if v == retag {
				return []reconcileStep{{stepTagPrior, v}}
			}
			return reconcilePlan(v)
		},
	}
	for name, m := range mutants {
		caught := ""
		forEachV2Input(func(in *reconcileInputsV2) bool {
			caught = v2PlanViolations(in, reconcileDecisionV2(*in), reconcileDecisionV2, m)
			return caught == ""
		})
		if caught == "" {
			t.Errorf("mutant plan %q survived the plan properties", name)
		} else {
			t.Logf("mutant plan %q killed: %s", name, caught)
		}
	}
}
