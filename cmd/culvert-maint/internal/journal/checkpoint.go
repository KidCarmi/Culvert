package journal

import "time"

// Checkpoint is a gate checkpoint (ADR-0062 slice 3b).
//
// It records, in the operation's own record, that a health gate was
// begun, on which image, how often, and how it ended. It is the evidence a
// later start needs to tell "the agent died while gating the target it had
// just started" from "the gate ran and failed" (slice 7 resumes the first and
// never the second). Nothing decides on it yet: it is record-and-report until
// slice 7 brings the only consumer together with the rules that constrain it.
//
// Which write may refuse what is decided per write (ADR-0062 slice 3, rule 1's
// test: can refusing lead anywhere but the conservative branch?):
//   - the gate:target intent is FAIL-CLOSED: a write that fails is a failed
//     gate, so the inline rollback runs (failure_reason checkpoint_unwritable);
//   - the gate:prior intent is best-effort: refusing would strand the inline
//     rollback's own gate on a full disk;
//   - a `failed` result is attempted before the rollback moves anything and
//     never blocks it; `passed` is best-effort (PhaseVerified records it too).
//
// The record holds one checkpoint, the most recent gate's: gate:prior replaces
// gate:target, which is itself the proof that the target's gate had ended.
type Checkpoint struct {
	Step     string    `json:"step"`      // StepGateTarget | StepGatePrior
	IntentAt time.Time `json:"intent_at"` // when the gate was begun; diagnostics only
	// Attempts counts the gate runs begun for Step, written ahead of each and
	// only ever raised (like ReconcileAttempts). The original gate is 1.
	Attempts int `json:"attempts"`
	// Epoch is the record's InterruptedSeen at IntentAt. A start that counted
	// the record since makes the checkpoint history, not an interruption to
	// resume (the rule command intents carry, intent.go).
	Epoch int `json:"epoch"`
	// Result is "" while the gate runs, then "passed" or "failed:<detail>".
	Result   string     `json:"result,omitempty"`
	ResultAt *time.Time `json:"result_at,omitempty"`
	// ImageID is the immutable image config digest the gate is gating, as the
	// agent captured and digest-verified it; empty when it could not be.
	ImageID string `json:"image_id,omitempty"`
}

// Checkpoint steps.
const (
	StepGateTarget = "gate:target" // the upgrade's gate of the target it just started
	StepGatePrior  = "gate:prior"  // the inline rollback's gate of the prior image
)

// Checkpoint results.
const (
	CheckpointPassed = "passed"
	// CheckpointFailedPrefix starts every failed result: "failed:<detail>".
	CheckpointFailedPrefix = "failed:"
)

// BeginCheckpoint sets rec's checkpoint to a new run of step on imageID at now.
// Attempts continues the count when the record's checkpoint is already step,
// and starts at 1 otherwise.
func (r *Record) BeginCheckpoint(step, imageID string, now time.Time) {
	attempts := 1
	if r.Checkpoint != nil && r.Checkpoint.Step == step && r.Checkpoint.Attempts > 0 {
		attempts = r.Checkpoint.Attempts + 1
	}
	r.Checkpoint = &Checkpoint{
		Step: step, IntentAt: now, Attempts: attempts,
		Epoch: r.InterruptedSeen, ImageID: imageID,
	}
}

// EndCheckpoint records result on rec's checkpoint when it is still the open
// run of step. It reports whether it changed anything: a checkpoint of another
// step, or one that already has a result, is left alone.
func (r *Record) EndCheckpoint(step, result string, now time.Time) bool {
	c := r.Checkpoint
	if c == nil || c.Step != step || c.Result != "" {
		return false
	}
	at := now
	c.Result, c.ResultAt = result, &at
	return true
}
