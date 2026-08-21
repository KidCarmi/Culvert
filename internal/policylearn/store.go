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

// SchemaVersion is the session-store document schema. Bump on any shape
// change that an OLDER binary's strict decoder would reject (added fields
// count — DisallowUnknownFields makes them corruption to an old reader); a
// store carrying a HIGHER version puts the engine into the read-only
// fail-closed posture (ErrStoreReadOnly) so a downgraded binary can never
// clobber newer state. Version history: 1 = M1 sessions; 2 = M3 aggregation
// (subject_key_id / category_churn / transport / agg / baseline
// category_epoch); 3 = M4 recommendations (top-level recommendations array +
// baseline guardrails_hash); 4 = M4.1 recommendation-policy identity
// (policy / policy_hash embedded per recommendation); 5 = M5A baseline
// policy_content_hash (canonical access-policy content identity); 6 = M5B
// decision lifecycle (accepting/accepted/rejected states + target_rule_id /
// accepted_* / rejected_* / reject_reason); 7 = M5B.1 group-truncation loss
// accounting (transport groups_truncated). Older documents load cleanly on a
// newer binary (pure field additions, all omitempty); saves always write the
// current version.
const SchemaVersion = 7

// minReadableSchemaVersion: every version in [min, current] loads.
const minReadableSchemaVersion = 1

// persistEnvelope is the on-disk document. Strict-decoded: unknown fields or
// trailing data are corruption (quarantine), not tolerated drift — schema
// evolution goes through SchemaVersion, matching the catoverride precedent.
type persistEnvelope struct {
	SchemaVersion   int               `json:"schema_version"`
	Sessions        []*Session        `json:"sessions"`
	Recommendations []*Recommendation `json:"recommendations,omitempty"` // M4 (schema v3)
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
	e.recs = env.Recommendations
	if pruned := pruneRecommendations(e.recs); len(pruned) != len(e.recs) {
		e.recs = pruned
		e.dirty = true
	}
	// Restart recovery: an active session survives a restart but records the
	// gap (never silent — ADR-0025 §8), then the ordinary lazy-expiry rule
	// applies (an overdue session completes deterministically). Observations
	// drained after this point attribute to the recovered session; the
	// transport baseline re-pins at zero (fresh process counters), which the
	// recorded restart gap makes honest.
	now := e.cfg.Now()
	for _, s := range e.sessions {
		if s.State != StateLearning {
			continue
		}
		e.recoverLearningSession(s, now)
	}
	e.maybeExpireLocked(now) // constructor-time: no concurrent access yet
	e.pruneLocked()
	if e.dirty {
		return e.saveLocked()
	}
	return nil
}

// recoverLearningSession resumes one active session at load: restart-gap
// record, subject-key continuity, and window re-arm. Constructor-time only.
func (e *Engine) recoverLearningSession(s *Session, now time.Time) {
	s.Gaps = append(s.Gaps, Gap{At: rfc3339(now), Reason: "process_restart"})
	// A legacy active session with NO key pin (pre-pseudonym schema, or a
	// stripped store) must not stay unpinned (Codex fix): unpinned, a
	// later key loss would merge disjoint token populations without ever
	// setting SubjectKeyChanged — double-counting subjects, the one
	// inflationary direction evidence must never err in — and the blank
	// ID is skipped by StaleReasons, so the failure would never surface.
	// Pin the CURRENT key so continuity is verifiable from here on; if
	// the session somehow already carries subject evidence (tokens
	// minted under an unknowable key), record the discontinuity first.
	if s.SubjectKeyID == "" {
		if s.Agg != nil && s.Agg.SubjectBudgetUsed > 0 {
			s.Gaps = append(s.Gaps, Gap{At: rfc3339(now), Reason: "subject_key_changed"})
			s.Agg.SubjectKeyChanged = true
		}
		s.SubjectKeyID = e.subjKey.keyID
	}
	// M3: subject-key continuity is part of distinct-subject identity.
	// A different key after restart (deleted/rotated) makes pre/post
	// token populations DISJOINT — record it, never merge silently.
	if s.SubjectKeyID != e.subjKey.keyID {
		s.Gaps = append(s.Gaps, Gap{At: rfc3339(now), Reason: "subject_key_changed"})
		if s.Agg == nil {
			s.Agg = newAggregate()
		}
		s.Agg.SubjectKeyChanged = true
		s.SubjectKeyID = e.subjKey.keyID // re-pin so the flag fires once per change
	}
	e.aggSession = s
	e.aggGen = e.windowGen.Add(1) // resumed window: post-restart events attribute here
	e.dirty = true
}

var errSchemaTooNew = errors.New("schema newer than binary")

func decodeEnvelope(raw []byte) (*persistEnvelope, error) { //nolint:cyclop // one explicit branch per schema version in the v1..v7 migration ladder
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
	if env.SchemaVersion > SchemaVersion {
		return nil, errSchemaTooNew
	}
	if env.SchemaVersion < minReadableSchemaVersion {
		return nil, fmt.Errorf("decode session store: unsupported schema_version %d", env.SchemaVersion)
	}
	learning := 0
	for _, s := range env.Sessions {
		if s == nil || s.ID == "" || s.State == "" {
			return nil, errors.New("decode session store: malformed session record")
		}
		switch s.State {
		case StateLearning:
			learning++
		case StateCompleted, StateCancelled:
		default:
			return nil, fmt.Errorf("decode session store: unknown session state %q", s.State)
		}
	}
	// One-active is a load-bearing invariant, so enforce it at decode (Codex
	// fix): with two Learning records, load would aggregate into the LAST one
	// while activeLocked and every session API select the FIRST — observations
	// silently attributed to a session other than the one displayed/completed,
	// and completing the first would strand the other as Learning with the
	// aggregation target cleared. A store that violates it is corrupt and goes
	// to the quarantine path, never partially honored.
	if learning > 1 {
		return nil, fmt.Errorf("decode session store: %d learning sessions (one-active invariant)", learning)
	}
	for _, r := range env.Recommendations {
		if r == nil || r.ID == "" || r.SessionID == "" {
			return nil, errors.New("decode session store: malformed recommendation record")
		}
		switch r.State {
		case RecStateGenerated, RecStateSuperseded, RecStateRejected:
		case RecStateAccepting, RecStateAccepted:
			// The cross-store linkage is load-bearing for these states: an
			// intent or acceptance without its target identity cannot be
			// reconciled and must be treated as corruption, not tolerated.
			if r.TargetRuleID == "" {
				return nil, fmt.Errorf("decode session store: %s recommendation without target_rule_id", r.State)
			}
		default:
			return nil, fmt.Errorf("decode session store: unknown recommendation state %q", r.State)
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
	env := persistEnvelope{SchemaVersion: SchemaVersion, Sessions: e.sessions, Recommendations: e.recs}
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
	Sessions        int
	Recommendations int
	Active          bool
	ReadOnly        bool
	MaxRetained     int
	MaxDuration     time.Duration
	SchemaVersion   int
}

// Snapshot returns the engine posture.
func (e *Engine) Snapshot() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.maybeExpireLocked(e.cfg.Now())
	return Stats{
		Sessions:        len(e.sessions),
		Recommendations: len(e.recs),
		Active:          e.activeLocked() != nil,
		ReadOnly:        e.readOnly,
		MaxRetained:     e.cfg.MaxRetainedSessions,
		MaxDuration:     e.cfg.MaxSessionDuration,
		SchemaVersion:   SchemaVersion,
	}
}
