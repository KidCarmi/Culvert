package server

import (
	"log"
	"regexp"
	"strings"
	"time"

	"culvert-maint/internal/journal"
)

// Gate checkpoints (ADR-0062 slice 3b; journal/checkpoint.go). Record-and-
// report only: no decision reads them yet (slice 7 will).

// writeCheckpoint read-modify-writes the record of opID with mutate. No
// journal, no op id, or no record for it: nothing is written and the result is
// nil, because there is then nothing a later start could resume. mutate
// returning false skips the write.
func (s *Server) writeCheckpoint(opID string, mutate func(*journal.Record) bool) error {
	if s.opts.Journal == nil || opID == "" {
		return nil
	}
	rec, found, err := s.opts.Journal.Read(opID)
	if err != nil {
		return err
	}
	if !found || !mutate(rec) {
		return nil
	}
	return s.opts.Journal.Write(*rec)
}

// beginTargetGate records, FAIL-CLOSED, that the upgrade is about to gate the
// target it just started. The caller treats an error as a failed gate, so the
// inline rollback runs: refusing can only lead to the conservative branch.
// image_id is the target's id as the restart captured and digest-verified it
// (empty when it could not be: nothing to resume on, by design).
func (s *Server) beginTargetGate(acc *upgradeApplyAccumulator) error {
	now := time.Now().UTC()
	return s.writeCheckpoint(acc.opID, func(rec *journal.Record) bool {
		rec.BeginCheckpoint(journal.StepGateTarget, acc.runningAfterID, now)
		return true
	})
}

// beginPriorGateBestEffort records that the inline rollback is about to gate
// the prior image. BEST-EFFORT: fail-closed would refuse the rollback's own
// gate on a full disk and leave a target that failed its gate serving.
func (s *Server) beginPriorGateBestEffort(acc *upgradeApplyAccumulator) {
	now := time.Now().UTC()
	if err := s.writeCheckpoint(acc.opID, func(rec *journal.Record) bool {
		rec.BeginCheckpoint(journal.StepGatePrior, acc.priorImageID, now)
		return true
	}); err != nil {
		log.Printf("culvert-maint: WARN: op %s: could not record the rollback gate as begun (gating anyway): %v", acc.opID, err)
	}
}

// endGateBestEffort records the result of the open run of step. Never
// blocking: a `failed` result is attempted before the rollback moves anything,
// but blocking on it would keep a target that failed its gate serving; a lost
// `passed` only withholds a resumption that is not needed.
func (s *Server) endGateBestEffort(opID, step, result string) {
	now := time.Now().UTC()
	if err := s.writeCheckpoint(opID, func(rec *journal.Record) bool {
		return rec.EndCheckpoint(step, result, now)
	}); err != nil {
		log.Printf("culvert-maint: WARN: op %s: could not record %s result %q: %v", opID, step, result, err)
	}
}

// GateCheckpointReport is the operator-facing view of a record's checkpoint.
// Every field is checked before it is reported: the record is content from a
// file, and a value this build does not recognise is reported as such, never
// echoed.
type GateCheckpointReport struct {
	Step     string     `json:"step"`
	ImageID  string     `json:"image_id,omitempty"`
	Attempts int        `json:"attempts"`
	BeganAt  time.Time  `json:"began_at"`
	Result   string     `json:"result,omitempty"`
	EndedAt  *time.Time `json:"ended_at,omitempty"`
}

// checkpointUnrecognised replaces a step or result this build does not know.
const checkpointUnrecognised = "unrecognised"

// checkpointFailedDetailRE is the shape of every failure detail this build
// writes.
var checkpointFailedDetailRE = regexp.MustCompile(`^[a-z][a-z_]{0,31}$`)

func reportGateCheckpoint(c *journal.Checkpoint) *GateCheckpointReport {
	if c == nil {
		return nil
	}
	out := &GateCheckpointReport{
		Step: checkpointUnrecognised, ImageID: reportImageID(c.ImageID),
		BeganAt: c.IntentAt, EndedAt: c.ResultAt,
	}
	if c.Step == journal.StepGateTarget || c.Step == journal.StepGatePrior {
		out.Step = c.Step
	}
	if c.Attempts > 0 {
		out.Attempts = c.Attempts
	}
	switch detail, failed := strings.CutPrefix(c.Result, journal.CheckpointFailedPrefix); {
	case c.Result == "" || c.Result == journal.CheckpointPassed:
		out.Result = c.Result
	case failed && checkpointFailedDetailRE.MatchString(detail):
		out.Result = c.Result
	default:
		out.Result = checkpointUnrecognised
	}
	return out
}

// gateFailed is the checkpoint result for a gate that failed for detail.
func gateFailed(detail string) string { return journal.CheckpointFailedPrefix + detail }
