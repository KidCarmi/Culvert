package authposture

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// FormatVersion is the only marker version this build reads or writes. A
// marker with any other version is corrupt, and so treated as established.
const FormatVersion = 1

// maxByLen bounds the "by" description kept in the marker and the status.
const maxByLen = 200

// Record is the marker file's content.
//
// An established record carries Since (RFC 3339, UTC) and By (what established
// it). A fresh record carries EvaluatedAt: the moment a node whose marker was
// missing was evaluated and found no evidence that proxy authentication had
// ever been established.
type Record struct {
	Version     int    `json:"version"`
	Established bool   `json:"established"`
	Since       string `json:"since,omitempty"`
	By          string `json:"by,omitempty"`
	EvaluatedAt string `json:"evaluated_at,omitempty"`
}

// Problem names why an established status is not backed by a readable,
// durable marker. The empty Problem means none.
type Problem string

const (
	// ProblemCorrupt means the marker exists but is not a valid record.
	ProblemCorrupt Problem = "corrupt"
	// ProblemUnreadable means the marker exists (or cannot be shown not to) but
	// could not be read.
	ProblemUnreadable Problem = "unreadable"
	// ProblemNotDurable means established in memory by EstablishFailClosed, but the
	// marker could not be written.
	ProblemNotDurable Problem = "not_durable"
)

// Status is a point-in-time copy of the ratchet's state.
type Status struct {
	Established bool
	Since       string // RFC 3339; empty when unknown (corrupt/unreadable marker)
	By          string // what established it; empty when unknown
	Problem     Problem
	Detail      string // the read/parse/write error behind Problem, for the owner's log
}

// Outcome is what Open found.
type Outcome int

const (
	// OutcomeMissing means no marker file. Not established; a migration is pending.
	OutcomeMissing Outcome = iota
	// OutcomeFresh means a valid fresh record. Not established; no migration.
	OutcomeFresh
	// OutcomeEstablished means a valid established record.
	OutcomeEstablished
	// OutcomeCorrupt means present but invalid. Treated as established.
	OutcomeCorrupt
	// OutcomeUnreadable means it could not be read. Treated as established.
	OutcomeUnreadable
)

// WriteFunc durably replaces the file at path with data. In production it is
// the repository's atomic write helper (temp file, fsync, rename, directory
// fsync), so a crash never leaves a torn marker.
type WriteFunc func(path string, data []byte, perm fs.FileMode) error

// ReadFunc reads the whole file at path. Nil means os.ReadFile.
type ReadFunc func(path string) ([]byte, error)

// Ratchet is the monotonic "proxy authentication established" flag and its
// marker file. The zero value is usable: in memory only and not established.
type Ratchet struct {
	established atomic.Bool
	// unsynced is set while the in-memory flag is raised but the marker on
	// disk does not say so (EstablishFailClosed after a failed write), so the
	// next Establish retries the write instead of taking the fast path.
	unsynced atomic.Bool
	status   atomic.Pointer[Status]

	mu               sync.Mutex // serializes Open and every write
	path             string     // "" = in memory only
	write            WriteFunc
	read             ReadFunc
	migrationPending bool
}

// Established reports whether proxy authentication is required even with no
// usable provider. Lock-free and allocation-free: an atomic load.
func (r *Ratchet) Established() bool { return r.established.Load() }

// Status returns a copy of the current state.
func (r *Ratchet) Status() Status {
	if s := r.status.Load(); s != nil {
		return *s
	}
	return Status{Established: r.established.Load()}
}

// MigrationPending reports whether Open found no marker and no later Establish
// or RecordFresh has settled the posture yet.
func (r *Ratchet) MigrationPending() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.migrationPending && !r.established.Load()
}

// Open names the marker file, the writer that persists it and (optionally) the
// reader, and loads the marker. It never lowers a flag already raised: a
// ratchet established in memory stays established whatever the file says.
//
// The error is non-nil only for OutcomeCorrupt and OutcomeUnreadable and
// carries the cause; the ratchet is then established (fail closed).
func (r *Ratchet) Open(path string, write WriteFunc, read ReadFunc) (Outcome, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.path, r.write, r.read = path, write, read
	if read == nil {
		read = os.ReadFile
	}
	data, err := read(path)
	if errors.Is(err, fs.ErrNotExist) {
		r.migrationPending = true
		return OutcomeMissing, nil
	}
	if err != nil {
		r.raiseLocked(Status{Established: true, Problem: ProblemUnreadable, Detail: err.Error()}, false)
		return OutcomeUnreadable, fmt.Errorf("authposture: read marker: %w", err)
	}
	rec, err := Decode(data)
	if err != nil {
		r.raiseLocked(Status{Established: true, Problem: ProblemCorrupt, Detail: err.Error()}, false)
		return OutcomeCorrupt, err
	}
	if rec.Established {
		r.raiseLocked(Status{Established: true, Since: rec.Since, By: rec.By}, false)
		return OutcomeEstablished, nil
	}
	return OutcomeFresh, nil
}

// Establish records that proxy authentication is established, WRITE-AHEAD: the
// marker is written first and the in-memory flag is raised only once the write
// succeeded. On a write error nothing changes and the error is returned, so
// the caller can refuse the activation it was about to report. changed is true
// only for the call that raised the flag (or completed a pending write).
func (r *Ratchet) Establish(by string, now time.Time) (changed bool, err error) {
	return r.establish(by, now, false)
}

// EstablishFailClosed is Establish for an activation that cannot be refused:
// the flag is raised even when the marker cannot be written, the status then
// reports ProblemNotDurable, and the write error is still returned for the
// caller to log. A later Establish retries the write.
func (r *Ratchet) EstablishFailClosed(by string, now time.Time) (changed bool, err error) {
	return r.establish(by, now, true)
}

func (r *Ratchet) establish(by string, now time.Time, failClosed bool) (bool, error) {
	if r.established.Load() && !r.unsynced.Load() {
		return false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	wasEstablished := r.established.Load()
	if wasEstablished && !r.unsynced.Load() {
		return false, nil
	}
	st := Status{Established: true, Since: now.UTC().Format(time.RFC3339), By: boundBy(by)}
	if wasEstablished {
		// Retrying the write of a flag already raised: keep its origin.
		if prev := r.status.Load(); prev != nil && prev.Since != "" {
			st.Since, st.By = prev.Since, prev.By
		}
	}
	if err := r.persistLocked(Record{Version: FormatVersion, Established: true, Since: st.Since, By: st.By}); err != nil {
		if !failClosed || wasEstablished {
			return false, err
		}
		st.Problem, st.Detail = ProblemNotDurable, err.Error()
		r.raiseLocked(st, true)
		return true, err
	}
	r.raiseLocked(st, false)
	return true, nil
}

// RecordFresh settles a pending migration that found no evidence: it writes a
// fresh record so later starts do not re-run the migration. A no-op unless
// Open found the marker missing and nothing has established it since. On a
// write error the migration stays pending (the next start evaluates again).
func (r *Ratchet) RecordFresh(now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.migrationPending || r.established.Load() {
		return nil
	}
	if err := r.persistLocked(Record{Version: FormatVersion, EvaluatedAt: now.UTC().Format(time.RFC3339)}); err != nil {
		return err
	}
	r.migrationPending = false
	return nil
}

// persistLocked writes rec to the marker. In memory only (no path) it is a
// no-op. Called with r.mu held.
func (r *Ratchet) persistLocked(rec Record) error {
	if r.path == "" {
		return nil
	}
	if r.write == nil {
		return errors.New("authposture: no marker writer configured")
	}
	data, err := Encode(rec)
	if err != nil {
		return err
	}
	if err := r.write(r.path, data, 0o600); err != nil {
		return fmt.Errorf("authposture: write marker: %w", err)
	}
	return nil
}

// raiseLocked publishes st and raises the flag: the status first, so a reader
// that observes the flag also observes why. Never lowers. Called with r.mu held.
func (r *Ratchet) raiseLocked(st Status, unsynced bool) {
	r.status.Store(&st)
	r.unsynced.Store(unsynced)
	r.established.Store(true)
	r.migrationPending = false
}

// Encode renders a record as the marker file content.
func Encode(rec Record) ([]byte, error) {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("authposture: encode marker: %w", err)
	}
	return append(data, '\n'), nil
}

// Decode parses and validates marker content strictly. Any error means the
// marker is corrupt, which its readers treat as established.
func Decode(data []byte) (Record, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rec Record
	if err := dec.Decode(&rec); err != nil {
		return Record{}, fmt.Errorf("authposture: corrupt marker: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Record{}, errors.New("authposture: corrupt marker: trailing data")
	}
	if rec.Version != FormatVersion {
		return Record{}, fmt.Errorf("authposture: corrupt marker: unsupported version %d", rec.Version)
	}
	if rec.Established {
		if !validTimestamp(rec.Since) || rec.By == "" {
			return Record{}, errors.New("authposture: corrupt marker: established without since/by")
		}
		return rec, nil
	}
	if !validTimestamp(rec.EvaluatedAt) || rec.Since != "" || rec.By != "" {
		return Record{}, errors.New("authposture: corrupt marker: invalid fresh record")
	}
	return rec, nil
}

// MergeForRestore is the monotonic marker merge of a backup restore. current is
// the marker on the node being restored and incoming the one in the archive;
// each is nil when absent. A side that establishes, or is corrupt (and so
// treated as established), wins, the current node first; keep is false when
// neither does, in which case the restore must leave NO marker, so the next
// start re-derives the posture from the restored data. A fresh record is
// never carried over. A restore can therefore set the posture but never clear
// it.
func MergeForRestore(current, incoming []byte) (out []byte, keep bool) {
	if current != nil && establishes(current) {
		return current, true
	}
	if incoming != nil && establishes(incoming) {
		return incoming, true
	}
	return nil, false
}

func establishes(data []byte) bool {
	rec, err := Decode(data)
	return err != nil || rec.Established
}

func validTimestamp(s string) bool {
	_, err := time.Parse(time.RFC3339, s)
	return s != "" && err == nil
}

func boundBy(by string) string {
	if by == "" {
		by = "unspecified"
	}
	if len(by) > maxByLen {
		by = by[:maxByLen]
	}
	return by
}
