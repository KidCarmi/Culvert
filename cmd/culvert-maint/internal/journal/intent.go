package journal

import "time"

// Command attribution (ADR-0062, slice 3).
//
// "Did the agent die inside this operation's own docker command?" is a fact
// about one operation, so it lives in that operation's record:
//
//   - Intent is written BEFORE a command that can stop a container (`compose
//     up`, `compose down`) and removed when the command RETURNS to a live
//     process, whether it succeeded or failed. An Intent on disk with no
//     process behind the record therefore means the process died in the
//     command. The write is best effort: without it the command still runs
//     (an inline rollback must not be stopped by a full disk), and an agent
//     that dies in it leaves nothing to attribute, which is the safe side.
//   - Every agent start, in every mode, takes what it finds (SeenByStartup):
//     an open Intent becomes Cut, stamped with that start's ordinal
//     (InterruptedSeen), in the same best-effort write that counts the start.
//     Nothing about this depends on Docker being readable, on the reconcile
//     mode, or on a clock.
//   - CutByThisStart is true only while the record's start ordinal is still
//     the one that took the Intent. The next start advances the ordinal, and
//     the same Cut says nothing any more: whatever happened to the stack in
//     between (an operator stopping it, for one) is not the command's doing.
//
// Three independent reviews of an earlier design (#2093, parked) each found a
// wrong recovery when this fact was inferred from a global marker instead:
// the marker outlived a start that only reported; another record claimed it;
// a command that merely FAILED left it usable; and an age bound made the
// "seen" stamp conditional on the wall clock. There is no marker, no owner
// check across records, no lock and no time comparison here.
//
// An OPEN Intent is schema 2: an agent that predates the field would drop it
// on rewrite, and with it the difference between "died in the command" and
// "never ran it". The record is written behind the downgrade fence (schema.go)
// for exactly as long as the Intent is open. A Cut needs no fence: its only
// reader is the start that made it, and an older agent that drops it, or
// carries it, still advances the start ordinal, so it is stale either way.

// CommandIntent is a docker command of this operation that has been begun
// and has not returned.
type CommandIntent struct {
	Command string    `json:"command"` // MutationComposeUp | MutationComposeDown
	Began   time.Time `json:"began"`   // diagnostics only; nothing decides on it
}

// CommandCut is an Intent an agent start found with no process behind it.
type CommandCut struct {
	Command string    `json:"command"`
	Began   time.Time `json:"began"` // diagnostics only
	// Seen is InterruptedSeen of the start that took the Intent, or 0 when
	// that start could not be told apart from a later one (the counter was
	// at its cap). 0 never matches.
	Seen int `json:"seen"`
}

// BeginCommand records that command is about to be run for this operation.
// The caller writes the record before running it.
func (r *Record) BeginCommand(command string, now time.Time) {
	r.Intent = &CommandIntent{Command: command, Began: now}
	r.settleSchema()
}

// neededSchema is the lowest schema this record can be written at: the one
// place that decides it. A field that an older agent must not drop or misread
// adds its condition here.
func (r *Record) neededSchema() int {
	if r.Intent != nil {
		return SchemaFenced
	}
	return 1
}

// settleSchema sets Schema to what the record needs now. A record from a
// newer agent is left alone (this build does not write it anyway).
func (r *Record) settleSchema() {
	if r.FromNewerAgent() {
		return
	}
	if n := r.neededSchema(); n > 1 {
		r.Schema = n
	} else {
		r.Schema = 0 // absent on disk: schema 1, as every earlier agent wrote it
	}
}

// EndCommand records that the command returned. It reports whether the record
// changed (an Intent was open).
func (r *Record) EndCommand() bool {
	if r.Intent == nil {
		return false
	}
	r.Intent = nil
	r.settleSchema()
	return true
}

// SeenByStartup is the per-record bookkeeping of an agent start that found
// the record with no process behind it: the first-seen time, the start
// ordinal (capped at maxSeen), and the consumption of an open Intent. The
// caller writes the record afterwards. When an Intent was open that write is
// not optional: a start that cannot record that it looked must not serve
// (main.go reportInterrupted), or the next start would take the same Intent
// for new.
func (r *Record) SeenByStartup(now time.Time, maxSeen int) {
	if r.InterruptedAt == nil {
		r.InterruptedAt = &now
	}
	advanced := r.InterruptedSeen < maxSeen
	if advanced {
		r.InterruptedSeen++
	}
	switch {
	case r.Intent != nil:
		cut := &CommandCut{Command: r.Intent.Command, Began: r.Intent.Began}
		if advanced {
			cut.Seen = r.InterruptedSeen
		}
		r.Cut, r.Intent = cut, nil
		r.settleSchema()
	case r.Cut != nil && !advanced:
		// The ordinal no longer tells this start from the one that took the
		// Intent: the Cut must stop matching.
		r.Cut.Seen = 0
	}
}

// CutByThisStart reports whether the agent start that last counted this
// record (and no earlier one) found the process dead inside command.
func (r *Record) CutByThisStart(command string) bool {
	return r.Cut != nil && r.Cut.Command == command && r.Cut.Seen > 0 && r.Cut.Seen == r.InterruptedSeen
}
