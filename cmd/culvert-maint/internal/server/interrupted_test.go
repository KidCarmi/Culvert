package server

// interrupted_test.go — the report built from a journal record: what it
// classifies, and what it refuses to repeat from an unauthenticated file.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

const (
	idOld = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	idNew = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func fullRec(phase journal.Phase) *journal.Record {
	return &journal.Record{
		OpID: testOpULID, Kind: ops.KindUpgradeApply, Phase: phase, Actor: "uid=0,user=cp",
		TargetRef: repo + "@sha256:" + digNew, TargetDigest: digNew,
		PriorRef: repo + "@sha256:" + digOld, PriorDigest: digOld,
		TargetImageID: idNew, PriorImageID: idOld,
		StartedAt: time.Unix(1700000000, 0).UTC(), UpdatedAt: time.Unix(1700000060, 0).UTC(),
	}
}

func TestDescribeInterrupted_DockerStateByKindAndPhase(t *testing.T) {
	tests := []struct {
		kind, mode string
		phase      journal.Phase
		want       string
	}{
		{ops.KindUpgradeApply, "", journal.PhaseAdmitted, DockerStateUnchanged},
		{ops.KindUpgradeApply, "", journal.PhaseCaptured, DockerStateUnchanged},
		{ops.KindUpgradeApply, "", journal.PhaseResolved, DockerStateUnchanged},
		{ops.KindUpgradeApply, "", journal.PhasePulled, DockerStateUnchanged},
		{ops.KindUpgradeApply, "", journal.PhaseRestarting, DockerStateIndeterminate},
		{ops.KindUpgradeApply, "", journal.PhaseRestarted, DockerStateIndeterminate},
		{ops.KindUpgradeApply, "", journal.PhaseVerified, DockerStateIndeterminate},
		// An image rollback is not phase-instrumented: "admitted" says nothing
		// about whether its tag move ran.
		{ops.KindRollbackCreate, "image", journal.PhaseAdmitted, DockerStateIndeterminate},
		{ops.KindRollbackCreate, "data", journal.PhaseAdmitted, DockerStateDataIndeterminate},
		// A kind this build does not journal is never called safe.
		{"something.else", "", journal.PhaseAdmitted, DockerStateIndeterminate},
	}
	for _, tc := range tests {
		rec := fullRec(tc.phase)
		rec.Kind, rec.Mode = tc.kind, tc.mode
		got := DescribeInterrupted(rec, repo)
		if got.DockerState != tc.want {
			t.Errorf("%s/%s at %s: docker_state = %q, want %q", tc.kind, tc.mode, tc.phase, got.DockerState, tc.want)
		}
		if got.DockerReconciled {
			t.Errorf("%s at %s: docker_reconciled must be false", tc.kind, tc.phase)
		}
		if got.OperatorAction == "" {
			t.Errorf("%s at %s: no operator_action", tc.kind, tc.phase)
		}
	}
}

func TestDescribeInterrupted_ValidRefsAreReported(t *testing.T) {
	got := DescribeInterrupted(fullRec(journal.PhaseRestarting), repo)
	if !got.RefsValid || got.TargetRef != repo+"@sha256:"+digNew || got.PriorRef != repo+"@sha256:"+digOld {
		t.Errorf("valid refs not reported: %+v", got)
	}
	if got.TargetImageID != idNew || got.PriorImageID != idOld {
		t.Errorf("image ids not reported: %+v", got)
	}
	if !strings.Contains(got.OperatorAction, "image_ref=prior_ref") {
		t.Errorf("operator_action must name the rollback: %q", got.OperatorAction)
	}
}

// TestDescribeInterrupted_UntrustedContentIsNotRepeated: every free string in a
// record is file content. None of it may reach the report unvalidated.
func TestDescribeInterrupted_UntrustedContentIsNotRepeated(t *testing.T) {
	const marker = "EVIL-MARKER"
	rec := fullRec(journal.PhaseRestarting)
	rec.Kind = "upgrades.apply<script>" + marker
	rec.Mode = marker
	rec.Actor = "uid=0\n" + marker + "\x1b[31m<b>"
	rec.PriorRef = "evil.example/" + marker + "@sha256:" + digOld
	rec.TargetImageID = "sha256:" + marker
	rec.PriorImageID = marker

	got := DescribeInterrupted(rec, repo)
	if got.RefsValid || got.TargetRef != "" || got.PriorRef != "" || got.TargetImageID != "" || got.PriorImageID != "" {
		t.Errorf("a record that fails the ref gate must carry no refs or ids: %+v", got)
	}
	if got.Kind != "unknown" || got.Mode != "unknown" {
		t.Errorf("kind/mode outside the closed sets must read unknown, got %q/%q", got.Kind, got.Mode)
	}
	if strings.ContainsAny(got.Actor, "\n\x1b<>") {
		t.Errorf("actor kept control or markup characters: %q", got.Actor)
	}
	// The actor is filtered to a safe alphabet, not dropped, so the marker's
	// letters survive there; nowhere else.
	got.Actor = ""
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), marker) || strings.Contains(string(raw), "evil.example") {
		t.Errorf("report repeats unvalidated record content: %s", raw)
	}
	audit, err := json.Marshal(got.AuditParams())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(audit), marker) {
		t.Errorf("audit params repeat unvalidated record content: %s", audit)
	}
}

func TestDescribeInterrupted_NoRefsYet(t *testing.T) {
	rec := &journal.Record{OpID: testOpULID, Kind: ops.KindUpgradeApply, Phase: journal.PhaseAdmitted}
	got := DescribeInterrupted(rec, repo)
	if got.RefsValid || !strings.Contains(got.RefsNote, "had not recorded") {
		t.Errorf("an admitted record has no refs to validate: valid=%v note=%q", got.RefsValid, got.RefsNote)
	}
}

func TestDescribeInterrupted_ResultMapIsJSONShaped(t *testing.T) {
	d := DescribeInterrupted(fullRec(journal.PhaseRestarted), repo)
	m := d.ResultMap()
	inner, ok := m["interrupted"].(map[string]interface{})
	if !ok {
		t.Fatalf("result = %#v", m)
	}
	if inner["journal_phase"] != "restarted" || inner["docker_reconciled"] != false || inner["docker_state"] != DockerStateIndeterminate {
		t.Errorf("result.interrupted = %#v", inner)
	}
}

func TestClassifyRunning(t *testing.T) {
	rd := func(d string) []string { return []string{repo + "@sha256:" + d} }
	rec := fullRec(journal.PhaseRestarting)
	tests := []struct {
		name     string
		captured bool
		id       string
		digests  []string
		want     string
	}{
		{"no capture", false, "", nil, RunningIsUnknown},
		{"target by id", true, idNew, nil, RunningIsTarget},
		{"prior by id", true, idOld, nil, RunningIsPrior},
		{"target by digest only", true, "sha256:" + strings.Repeat("9", 64), rd(digNew), RunningIsTarget},
		{"prior by digest only", true, "sha256:" + strings.Repeat("9", 64), rd(digOld), RunningIsPrior},
		{"neither", true, "sha256:" + strings.Repeat("9", 64), rd(strings.Repeat("8", 64)), RunningIsOther},
	}
	for _, tc := range tests {
		if got := ClassifyRunning(rec, repo, tc.captured, tc.id, tc.digests); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}

	// A record that fails the ref gate is never compared.
	bad := fullRec(journal.PhaseRestarting)
	bad.PriorRef = "evil.example/x@sha256:" + digOld
	if got := ClassifyRunning(bad, repo, true, idOld, nil); got != RunningIsUnknown {
		t.Errorf("invalid record: %q, want unknown", got)
	}
}

// TestClassifyRunning_ConflictingTargetIDIsAmbiguous: the record's target image
// id is captured right after `compose up`, before the image is verified. If
// the container was not recreated it is the PREVIOUS image's id, and the
// record then names one id as both target and prior while its digests differ.
// The report must say so rather than call the previous image the target.
func TestClassifyRunning_ConflictingTargetIDIsAmbiguous(t *testing.T) {
	rec := fullRec(journal.PhaseRestarted)
	rec.TargetImageID = idOld // unverified capture returned the image still running
	if got := ClassifyRunning(rec, repo, true, idOld, []string{repo + "@sha256:" + digOld}); got != RunningIsAmbiguous {
		t.Errorf("running the previous image under a record whose target id equals its prior id: %q, want %q", got, RunningIsAmbiguous)
	}
}

func TestOperatorAction_DependsOnRunningImage(t *testing.T) {
	d := DescribeInterrupted(fullRec(journal.PhaseRestarting), repo)
	d.SetRunningImage(RunningIsTarget)
	if !strings.Contains(d.OperatorAction, "already-current") {
		t.Errorf("with the target running, the action must not offer a re-apply as a health gate: %q", d.OperatorAction)
	}
	d.SetRunningImage(RunningIsPrior)
	if !strings.Contains(d.OperatorAction, "submit the upgrade again") {
		t.Errorf("with the previous image running, a re-apply is a valid answer: %q", d.OperatorAction)
	}
}
