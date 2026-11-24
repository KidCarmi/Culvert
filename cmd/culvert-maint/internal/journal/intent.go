package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

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
// Two guards cover the one way an Intent can outlive a start: an OLDER agent
// build started on this state directory. Such a build does not take the
// Intent; one from between ADR-0062 slice 2 and this file even carries the key
// it does not know through its rewrites.
//
//   - Epoch: an older build counts its start in InterruptedSeen. An Intent
//     whose Epoch is not the record's current InterruptedSeen has therefore
//     been looked at, and is taken without being attributed.
//   - The intent fence: an older build counts best-effort. If that one write
//     fails it still serves and reports, and the Epoch would not show it. So
//     for as long as any record holds an open Intent, the journal also holds a
//     second-generation fence file, on which every build before this file
//     refuses to serve (schema.go describes the first generation, which
//     builds since slice 2 skip by name; they do not skip this one). No fence,
//     no Intent: if the fence cannot be written the Intent is not written
//     either, and nothing will be attributed.
//
// The Intent does not raise the record's schema.
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
	if ferr := j.ensureIntentFence(); ferr != nil {
		return true, ferr // no fence, no intent
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
		j.releaseIntentFenceIfUnused()
		return nil
	}
	// Write drops the Intent (the command is not in flight) and then the fence.
	return j.Write(*rec)
}

// intentFenceOpID names the second-generation fence: a valid ULID (timestamp
// 0) no operation can have, and not the name builds since ADR-0062 slice 2
// skip. Any build before this file reads it as a record, finds a phase it does
// not know, and refuses to serve.
const intentFenceOpID = "00000000000000000000000001"

func (j *Journal) intentFencePath() string { return filepath.Join(j.dir, intentFenceOpID+fileExt) }

// IntentFenceActive reports whether the intent fence is present.
func (j *Journal) IntentFenceActive() (bool, error) {
	_, err := os.Stat(j.intentFencePath())
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("journal: stat intent fence: %w", err)
	}
}

func (j *Journal) ensureIntentFence() error {
	if on, err := j.IntentFenceActive(); err != nil || on {
		return err
	}
	now := time.Now().UTC()
	data, err := json.MarshalIndent(fenceRecord{
		OpID: intentFenceOpID, Kind: "journal.intent_fence", Phase: PhaseSchemaFence, Schema: SchemaFenced,
		Reason: "an operation in this directory is, or was when the agent died, inside a docker compose command; " +
			"only a maintenance agent that takes command intents may start here (ADR-0062 slice 3). Start the newer agent once; it removes this file",
		StartedAt: now, UpdatedAt: now,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("journal: marshal intent fence: %w", err)
	}
	return writeIntentFence(j.intentFencePath(), data, fenceMode)
}

// writeIntentFence is atomicWrite; a test replaces it to fail the fence write
// alone.
var writeIntentFence = atomicWrite

// ReleaseIntentFence removes the intent fence if no record holds an open
// Intent any more. An agent start calls it after it has taken every intent.
func (j *Journal) ReleaseIntentFence() { j.releaseIntentFenceIfUnused() }

// releaseIntentFenceIfUnused: best effort. A journal that cannot be listed
// keeps the fence (what is left cannot be judged), and so does a failed
// removal: either only keeps older agents out a little longer.
func (j *Journal) releaseIntentFenceIfUnused() {
	if on, err := j.IntentFenceActive(); err != nil || !on {
		return
	}
	recs, err := j.List()
	if err != nil {
		return
	}
	for i := range recs {
		if recs[i].Intent != nil {
			return
		}
	}
	if os.Remove(j.intentFencePath()) == nil {
		_ = fsyncDir(j.dir)
	}
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
