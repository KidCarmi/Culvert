// Runtime recovery attempt counter (ADR-0062 slice 6, PR 3).
//
// <state_dir>/health/recover_attempts.json counts the runtime recoveries begun
// per (source, image): the source is the op that put the image there (the
// install installed.json names, or a kept upgrade record of this agent). It is
// written ahead of each recovery's journal record, so a recovery that fails or
// dies still counts: the cap outlives the record, which a successful recovery
// retires. A later install of the same image is another source and starts at
// zero.
//
// The file keeps a count for EVERY source that can still authorize a recovery,
// not only the last one used: two sources can authorize opposite directions
// (installed.json: B replaced A; a kept record: A replaced B), and a single
// slot would forget one count each time the other is used, so the two
// recoveries could alternate forever (Codex review on #2140). Only an entry
// whose source can no longer authorize anything is dropped, and a file that
// would exceed MaxRecoverEntries is refused, never trimmed.
package runtimehealth

import (
	"errors"
	"fmt"
	"strings"
)

const (
	recoverAttemptsName = "recover_attempts.json"
	// MaxRecoverAttempts is how many runtime recoveries may be begun for one
	// (source, image).
	MaxRecoverAttempts = 2
	// MaxRecoverEntries bounds the file. Sources in force are installed.json
	// and the kept records, so this is never reached in practice; reaching it
	// refuses the recovery.
	MaxRecoverEntries = 32
)

// ErrRecoverEntriesFull is returned when recording one more source would exceed the bound.
var ErrRecoverEntriesFull = errors.New("runtimehealth: recover attempts would exceed the entry bound")

// RecoverAttempt is the count for one (source, image).
type RecoverAttempt struct {
	SourceOpID string `json:"source_op_id"`
	ImageID    string `json:"image_id"`
	Begun      int    `json:"begun"`
}

// RecoverAttempts is the durable count of runtime recoveries begun.
type RecoverAttempts struct {
	Schema  int              `json:"schema"`
	Entries []RecoverAttempt `json:"entries"`
}

// For returns the count for (sourceOpID, imageID); a nil receiver counts zero.
func (a *RecoverAttempts) For(sourceOpID, imageID string) int {
	if a == nil {
		return 0
	}
	for _, e := range a.Entries {
		if e.SourceOpID == sourceOpID && e.ImageID == imageID {
			return e.Begun
		}
	}
	return 0
}

// Counted returns the counter with (sourceOpID, imageID) set to begun. It
// keeps every other entry whose source inForce still reports as able to
// authorize a recovery, and refuses, rather than drops one, when the result
// would exceed MaxRecoverEntries. A nil receiver starts empty.
func (a *RecoverAttempts) Counted(sourceOpID, imageID string, begun int, inForce func(sourceOpID string) bool) (RecoverAttempts, error) {
	out := RecoverAttempts{Entries: []RecoverAttempt{{SourceOpID: sourceOpID, ImageID: imageID, Begun: begun}}}
	if a != nil {
		for _, e := range a.Entries {
			if (e.SourceOpID == sourceOpID && e.ImageID == imageID) || !inForce(e.SourceOpID) {
				continue
			}
			out.Entries = append(out.Entries, e)
		}
	}
	if len(out.Entries) > MaxRecoverEntries {
		return RecoverAttempts{}, ErrRecoverEntriesFull
	}
	return out, nil
}

// WriteRecoverAttempts replaces recover_attempts.json.
func (s *Store) WriteRecoverAttempts(a RecoverAttempts) error {
	a.Schema = SchemaVersion
	if err := validRecoverAttempts(&a); err != nil {
		return err
	}
	return s.write(recoverAttemptsName, a)
}

// ReadRecoverAttempts returns the counter, or nil when there is none. A file
// that cannot be read or trusted is an error: the caller must not take it for
// zero.
func (s *Store) ReadRecoverAttempts() (*RecoverAttempts, error) {
	var a RecoverAttempts
	ok, err := s.read(recoverAttemptsName, &a)
	if err != nil || !ok {
		return nil, err
	}
	if a.Schema != SchemaVersion {
		return nil, fmt.Errorf("runtimehealth: %s has schema %d, this agent reads %d", recoverAttemptsName, a.Schema, SchemaVersion)
	}
	if err := validRecoverAttempts(&a); err != nil {
		return nil, err
	}
	return &a, nil
}

func validRecoverAttempts(a *RecoverAttempts) error {
	if len(a.Entries) == 0 || len(a.Entries) > MaxRecoverEntries {
		return fmt.Errorf("runtimehealth: recover attempts hold %d entries", len(a.Entries))
	}
	seen := map[string]bool{}
	for i := range a.Entries {
		e := &a.Entries[i]
		switch {
		case e.SourceOpID == "" || len(e.SourceOpID) > 64 || strings.ContainsAny(e.SourceOpID, "/\\\n\r\t "):
			return fmt.Errorf("runtimehealth: recover attempts source_op_id %q is malformed", e.SourceOpID)
		case !imageIDRE.MatchString(e.ImageID):
			return fmt.Errorf("runtimehealth: recover attempts image_id %q is malformed", e.ImageID)
		case e.Begun < 1 || e.Begun > MaxRecoverAttempts:
			return fmt.Errorf("runtimehealth: recover attempts begun %d is outside 1..%d", e.Begun, MaxRecoverAttempts)
		}
		key := e.SourceOpID + "/" + e.ImageID
		if seen[key] {
			return errors.New("runtimehealth: recover attempts repeat an entry")
		}
		seen[key] = true
	}
	return nil
}
