// Runtime recovery attempt counter (ADR-0062 slice 6, PR 3).
//
// <state_dir>/health/recover_attempts.json counts the runtime recoveries begun
// for one installed image. It is written ahead of each recovery's journal
// record, so a recovery that fails or dies still counts: the cap outlives the
// record, which a successful recovery retires. The key is the source (the op
// that installed the image) and the image, so a later install of the same image
// starts again from zero.
package runtimehealth

import (
	"fmt"
	"strings"
)

const (
	recoverAttemptsName = "recover_attempts.json"
	// MaxRecoverAttempts is how many runtime recoveries may be begun for one
	// installed image.
	MaxRecoverAttempts = 2
)

// RecoverAttempts is the durable count of runtime recoveries begun for one
// installed image.
type RecoverAttempts struct {
	Schema     int    `json:"schema"`
	SourceOpID string `json:"source_op_id"`
	ImageID    string `json:"image_id"`
	Begun      int    `json:"begun"`
}

// For returns the count for (sourceOpID, imageID): the stored one when it is
// for them, zero otherwise. A nil receiver counts zero.
func (a *RecoverAttempts) For(sourceOpID, imageID string) int {
	if a == nil || a.SourceOpID != sourceOpID || a.ImageID != imageID {
		return 0
	}
	return a.Begun
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
	switch {
	case a.SourceOpID == "" || len(a.SourceOpID) > 64 || strings.ContainsAny(a.SourceOpID, "/\\\n\r\t "):
		return fmt.Errorf("runtimehealth: recover attempts source_op_id %q is malformed", a.SourceOpID)
	case !imageIDRE.MatchString(a.ImageID):
		return fmt.Errorf("runtimehealth: recover attempts image_id %q is malformed", a.ImageID)
	case a.Begun < 1 || a.Begun > MaxRecoverAttempts:
		return fmt.Errorf("runtimehealth: recover attempts begun %d is outside 1..%d", a.Begun, MaxRecoverAttempts)
	}
	return nil
}
