package policylearn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// SchemaVersion is the session-store document schema. Bump on any incompatible
// shape change; a store carrying a HIGHER version puts the engine into the
// read-only fail-closed posture (ErrStoreReadOnly) so a downgraded binary can
// never clobber newer state.
const SchemaVersion = 1

// persistEnvelope is the on-disk document. Strict-decoded: unknown fields or
// trailing data are corruption (quarantine), not tolerated drift — schema
// evolution goes through SchemaVersion, matching the catoverride precedent.
type persistEnvelope struct {
	SchemaVersion int        `json:"schema_version"`
	Sessions      []*Session `json:"sessions"`
}

// load reads the store fail-closed:
//   - missing file / empty path ⇒ fresh empty store (writable);
//   - parse/validation failure ⇒ injected quarantine seam, then fresh empty
//     store (writable — the quarantine renamed the bad file away, or, with no
//     seam wired, the next save overwrites it);
//   - schema NEWER than this binary ⇒ file left untouched, engine READ-ONLY;
//   - any other I/O error ⇒ returned (constructor fails; caller decides).
func (e *Engine) load() error {
	if e.cfg.StorePath == "" {
		return nil
	}
	raw, err := os.ReadFile(e.cfg.StorePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	env, perr := decodeEnvelope(raw)
	if perr != nil {
		if errors.Is(perr, errSchemaTooNew) {
			e.readOnly = true
			return nil
		}
		if e.cfg.Quarantine != nil {
			e.cfg.Quarantine(e.cfg.StorePath, perr)
		}
		return nil
	}
	e.sessions = env.Sessions
	// Restart recovery: an active session survives a restart but records the
	// gap (never silent — ADR-0025 §8), then the ordinary lazy-expiry rule
	// applies (an overdue session completes deterministically).
	now := e.cfg.Now()
	for _, s := range e.sessions {
		if s.State == StateLearning {
			s.Gaps = append(s.Gaps, Gap{At: rfc3339(now), Reason: "process_restart"})
			e.dirty = true
		}
	}
	e.maybeExpireLocked(now) // constructor-time: no concurrent access yet
	e.pruneLocked()
	if e.dirty {
		return e.saveLocked()
	}
	return nil
}

var errSchemaTooNew = errors.New("schema newer than binary")

func decodeEnvelope(raw []byte) (*persistEnvelope, error) {
	// Peek the schema version LENIENTLY first: a newer-schema document may
	// legitimately carry fields this binary's strict decoder rejects, and it
	// must be classified as "newer" (read-only), not "corrupt" (quarantine).
	var peek struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &peek); err == nil && peek.SchemaVersion > SchemaVersion {
		return nil, errSchemaTooNew
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var env persistEnvelope
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("decode session store: %w", err)
	}
	// Trailing-data check (strict, catoverride precedent).
	if dec.More() {
		return nil, errors.New("decode session store: trailing data")
	}
	if env.SchemaVersion != SchemaVersion {
		if env.SchemaVersion > SchemaVersion {
			return nil, errSchemaTooNew
		}
		return nil, fmt.Errorf("decode session store: unsupported schema_version %d", env.SchemaVersion)
	}
	for _, s := range env.Sessions {
		if s == nil || s.ID == "" || s.State == "" {
			return nil, errors.New("decode session store: malformed session record")
		}
		switch s.State {
		case StateLearning, StateCompleted, StateCancelled:
		default:
			return nil, fmt.Errorf("decode session store: unknown session state %q", s.State)
		}
	}
	return &env, nil
}

// saveLocked persists the store via AtomicWrite (0600). Memory-only and
// read-only engines are no-ops (the read-only file must never be touched).
// Callers hold e.mu.
func (e *Engine) saveLocked() error {
	if e.cfg.StorePath == "" || e.readOnly {
		e.dirty = false
		return nil
	}
	env := persistEnvelope{SchemaVersion: SchemaVersion, Sessions: e.sessions}
	raw, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("policylearn: marshal session store: %w", err)
	}
	if err := fileutil.AtomicWrite(e.cfg.StorePath, raw, 0o600); err != nil {
		return fmt.Errorf("policylearn: persist session store: %w", err)
	}
	e.dirty = false
	return nil
}

// Stats is the M1 posture snapshot (bounded scalars only).
type Stats struct {
	Sessions      int
	Active        bool
	ReadOnly      bool
	MaxRetained   int
	MaxDuration   time.Duration
	SchemaVersion int
}

// Snapshot returns the engine posture.
func (e *Engine) Snapshot() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.maybeExpireLocked(e.cfg.Now())
	return Stats{
		Sessions:      len(e.sessions),
		Active:        e.activeLocked() != nil,
		ReadOnly:      e.readOnly,
		MaxRetained:   e.cfg.MaxRetainedSessions,
		MaxDuration:   e.cfg.MaxSessionDuration,
		SchemaVersion: SchemaVersion,
	}
}
