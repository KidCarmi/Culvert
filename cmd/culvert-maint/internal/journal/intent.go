package journal

import "time"

// Command attribution (ADR-0062, slice 3).
//
// "Did the agent process die inside this operation's own docker command?" is
// a fact about one operation and one process death. It is kept in three
// places, each for one job:
//
//   - On disk, in the operation's record: Intent, written before a command
//     that can stop a container (`compose up`, `compose down`) and removed
//     when the command RETURNS to a live process, however it returns
//     (Journal.BeginCommand / EndCommand). An Intent found by a start with no
//     process behind the record means the process died in the command.
//   - In the starting process's memory: TakeIntent removes the Intent from the
//     record, and only after that removal is durable may the caller remember
//     "this process found the agent dead inside <command> of <op>". A start
//     that cannot write the removal must not serve (main.go initJournal):
//     otherwise it would report, and the next start would find the same
//     Intent and take it for new.
//   - Nowhere after that. The next process starts with an empty memory and a
//     record without an Intent. There is no ordinal to compare, no clock, no
//     marker, no lock and no check across records: evidence that is gone
//     cannot be read again.
//
// Epoch guards the one way an Intent can outlive a start: an agent build that
// does not know the field but carries unknown keys through its rewrites (main
// between ADR-0062 slice 2 and this file). Such an agent counts its start in
// InterruptedSeen like every other; an Intent whose Epoch is not the record's
// current InterruptedSeen has therefore been looked at, and is taken without
// being attributed. An agent older than slice 2 drops the key on rewrite,
// which is the safe side. So an Intent needs no schema bump and no downgrade
// fence.
//
// Why this shape: three independent reviews of a marker-based design (#2093,
// parked) and one of the first version of this file each reproduced a wrong
// "died in the command": a marker that outlived a start; another record
// claiming it; a command that merely failed; a stamp that depended on the wall
// clock; an Intent carried across a downgrade; one failed write leaving a
// stale Intent, or leaving a consumed one looking current.

// CommandIntent is a docker command of this operation that has been begun
// and has not returned.
type CommandIntent struct {
	Command string    `json:"command"` // MutationComposeUp | MutationComposeDown
	Began   time.Time `json:"began"`   // diagnostics only; nothing decides on it
	// Epoch is the record's InterruptedSeen when the command was begun.
	Epoch int `json:"epoch"`
}

// CommandCut is what a start leaves in place of an Intent it took. It is for
// the person reading the file: nothing decides on it.
type CommandCut struct {
	Command string    `json:"command"`
	Began   time.Time `json:"began"`
	// Attributed: the start that took the Intent was the first to see it.
	Attributed bool `json:"attributed"`
}

// TakeIntent removes an open Intent from the record, as an agent start does
// before it counts itself in InterruptedSeen. had: there was one. attributed:
// no agent start had counted the record since the command was begun, so the
// process that began it died in it. The caller writes the record and may act
// on attributed only once that write has succeeded.
func (r *Record) TakeIntent() (command string, attributed, had bool) {
	if r.Intent == nil {
		return "", false, false
	}
	in := r.Intent
	attributed = in.Epoch == r.InterruptedSeen && in.Epoch >= 0 &&
		(in.Command == MutationComposeUp || in.Command == MutationComposeDown)
	r.Cut = &CommandCut{Command: in.Command, Began: in.Began, Attributed: attributed}
	r.Intent = nil
	return in.Command, attributed, true
}

// BeginCommand writes into the record of opID that command is about to be
// run. No record for opID: nothing is written and nothing will be attributed
// (found=false). The command is "in flight" for this Journal from the moment
// this is called until EndCommand, whether or not the write succeeded.
func (j *Journal) BeginCommand(opID, command string, now time.Time) (found bool, err error) {
	if opID == "" {
		return false, nil
	}
	j.setInFlight(opID, true)
	rec, found, err := j.Read(opID)
	if err != nil || !found {
		return found, err
	}
	rec.Intent = &CommandIntent{Command: command, Began: now, Epoch: rec.InterruptedSeen}
	return true, j.Write(*rec)
}

// EndCommand records that the command of opID returned. From here on every
// Write of that record by this process drops an Intent, so one failed write
// here does not leave "in flight" on disk past the record's next update.
func (j *Journal) EndCommand(opID string) error {
	if opID == "" {
		return nil
	}
	j.setInFlight(opID, false)
	rec, found, err := j.Read(opID)
	if err != nil {
		return err
	}
	if !found || rec.Intent == nil {
		return nil
	}
	return j.Write(*rec) // Write drops the Intent: the command is not in flight
}

func (j *Journal) setInFlight(opID string, on bool) {
	j.flightMu.Lock()
	defer j.flightMu.Unlock()
	if on {
		if j.inFlight == nil {
			j.inFlight = map[string]struct{}{}
		}
		j.inFlight[opID] = struct{}{}
		return
	}
	delete(j.inFlight, opID)
}

func (j *Journal) commandInFlight(opID string) bool {
	j.flightMu.Lock()
	defer j.flightMu.Unlock()
	_, ok := j.inFlight[opID]
	return ok
}
