// Package idem is the durable half of the operation idempotency cache.
//
// ops.Manager keeps (actor, kind, idempotency_key) → op_id in process memory,
// which a restart empties: a retry of a request that had already completed was
// admitted as new work and executed again. This package records, on disk, that
// a keyed request was admitted and how it ended, so a restarted agent can
// answer the retry from the record.
//
// What it guarantees, and what it does not:
//
//   - Admit is WRITE-AHEAD and FAIL-CLOSED. The record is on disk (fsync of the
//     file and of the directory) before Admit returns, and the caller runs
//     nothing until then. If it cannot be written the keyed request is refused.
//   - Complete records the terminal outcome when the op finishes. It is
//     best-effort: if it fails, or the agent dies before it, the record still
//     says "admitted".
//   - A record that says "admitted" when a NEW process opens the store belongs
//     to an op nobody is running. It is reported as interrupted with an unknown
//     outcome. It is never reported as succeeded and never run again under the
//     same key.
//
// This is NOT exactly-once execution. The side effects of an op and the write
// of its outcome are not atomic: an agent that dies after the last side effect
// and before Complete leaves an op that may have fully succeeded recorded as
// "unknown". The store only ensures the answer to a same-key retry is the
// recorded one, or "unknown", and not a second execution.
//
// On-disk discipline mirrors internal/journal: one JSON file per record under
// <state_dir>/idempotency/, written through a temp file with fsync(file) →
// rename → fsync(dir). The file name is the SHA-256 of the scope, so no
// caller-supplied text reaches a path. Records hold the same sanitised params
// the audit log already holds — a passphrase is only ever a `passphrase_ref`,
// never its value — plus a SHA-256 fingerprint of (kind, params) that decides
// whether a retry is the same request.
//
// The maint binary is its own Go module and cannot import the root
// internal/fileutil; like internal/journal this package owns a stdlib-only
// atomic writer.
package idem

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Record states. StateAdmitted is the only non-terminal one; the terminal
// values are the ops.State strings, kept as plain strings so this package does
// not depend on internal/ops.
const (
	StateAdmitted  = "admitted"
	StateSucceeded = "succeeded"
	StateFailed    = "failed"
	StateCancelled = "cancelled"
)

// ReasonInterrupted is the failure_reason of a record whose op was admitted by
// a process that is gone. It equals ops.ReasonAgentRestartInterrupted, so a
// keyed retry and the journal's startup projection name the same thing.
const ReasonInterrupted = "agent_restart_interrupted"

// Bounds. All are hard limits; none is configurable.
const (
	// DefaultTTL is how long a record answers for its key, measured from
	// admission (the same origin the in-memory cache uses).
	DefaultTTL = 24 * time.Hour
	// DefaultMaxRecords caps the number of files in the store. At the cap the
	// oldest TERMINAL records are evicted first; a record of a running op is
	// never evicted.
	DefaultMaxRecords = 1024
	// MaxRecordBytes bounds one record on disk. A record that would exceed it
	// is reduced (stage output, then result, then progress, then params) and
	// flagged Truncated; it is never a reason to fail the write.
	MaxRecordBytes = 64 * 1024
	// maxStageOutput is what a stage's output is cut to in the first reduction.
	maxStageOutput = 512
)

const (
	dirName     = "idempotency"
	dirMode     = 0o750
	fileMode    = 0o640
	fileExt     = ".json"
	corruptExt  = ".corrupt"
	tmpPattern  = ".idem-*.tmp"
	schemaV1    = 1
	hashHexLen  = sha256.Size * 2
	outcomeKey  = "outcome"
	outcomeUnk  = "unknown"
	interruptAt = "interrupted_detected_at"
)

// Errors a caller distinguishes.
var (
	// ErrUnavailable: the store could not be opened or written. A keyed
	// admission must be refused; nothing was recorded and nothing may run.
	ErrUnavailable = errors.New("idem: store unavailable")
	// ErrCorruptRecord: a record exists for this exact scope but cannot be
	// read. Whether that request ran is unknown, so it must not be re-admitted
	// under the same key.
	ErrCorruptRecord = errors.New("idem: record unreadable")
	// ErrFull: the store is at its cap and every record belongs to a running
	// op, so nothing can be evicted.
	ErrFull = errors.New("idem: store full")
)

// Stage is one progress entry of a finished op (the ops.Stage JSON shape).
type Stage struct {
	Name    string    `json:"stage"`
	State   string    `json:"state"`
	Started time.Time `json:"started_at,omitempty"`
	Ended   time.Time `json:"ended_at,omitempty"`
	Output  string    `json:"output,omitempty"`
}

// Record is one durable idempotency record. Plain data, no secrets.
type Record struct {
	Version        int    `json:"v"`
	Actor          string `json:"actor"`
	Kind           string `json:"kind"`
	IdempotencyKey string `json:"idempotency_key"`
	// Fingerprint is the hex SHA-256 of the canonical JSON of (kind, params).
	Fingerprint string `json:"fingerprint"`
	OpID        string `json:"op_id"`
	State       string `json:"state"`

	AdmittedAt time.Time  `json:"admitted_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`

	FailureReason string                 `json:"failure_reason,omitempty"`
	Params        map[string]interface{} `json:"params,omitempty"`
	Progress      []Stage                `json:"progress,omitempty"`
	Result        map[string]interface{} `json:"result,omitempty"`

	// Interrupted is set when a starting agent found the record still
	// "admitted": the op has no recorded outcome and no process behind it.
	Interrupted bool `json:"interrupted,omitempty"`
	// Truncated is set when the record was reduced to fit MaxRecordBytes.
	Truncated bool `json:"truncated,omitempty"`
}

// Terminal reports whether the record carries a final answer.
func (r *Record) Terminal() bool { return r.State != StateAdmitted }

// Fingerprint returns the hex SHA-256 of the canonical JSON of (kind, params).
// encoding/json writes map keys in sorted order at every depth, so two params
// maps with the same content fingerprint the same regardless of build order.
// params must already be sanitised: the fingerprint is stored and compared, and
// it must never be a function of a secret.
func Fingerprint(kind string, params map[string]interface{}) (string, error) {
	raw, err := json.Marshal(struct {
		Kind   string                 `json:"kind"`
		Params map[string]interface{} `json:"params"`
	}{Kind: kind, Params: params})
	if err != nil {
		return "", fmt.Errorf("idem: fingerprint: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// scopeHash names the record of (actor, kind, key). The fields are length-
// prefixed so no choice of values can make two scopes collide.
func scopeHash(actor, kind, key string) string {
	h := sha256.New()
	for _, s := range []string{actor, kind, key} {
		_, _ = fmt.Fprintf(h, "%d:", len(s))
		_, _ = io.WriteString(h, s)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// meta is the in-memory index entry of one file.
type meta struct {
	opID     string
	terminal bool
	corrupt  bool
	admitted time.Time // TTL origin; file mtime for a corrupt record
	finished time.Time // eviction order; zero while running
}

// Options configures Open. Zero values select the defaults.
type Options struct {
	TTL        time.Duration
	MaxRecords int
	Now        func() time.Time
	// Logf receives one line per noteworthy event. It is never given record
	// content, a key, or params — only file names, counts and error text.
	Logf func(format string, args ...interface{})
}

// Store is the durable record set. Goroutine-safe.
type Store struct {
	mu      sync.Mutex
	dir     string
	ttl     time.Duration
	max     int
	now     func() time.Time
	logf    func(format string, args ...interface{})
	index   map[string]meta   // scope hash → entry
	byOp    map[string]string // op_id → scope hash
	openErr error             // non-nil: the store never opened
	// interruptedAtOpen counts the records Open found without an outcome.
	interruptedAtOpen int
}

func (o *Options) fill() {
	if o.TTL <= 0 {
		o.TTL = DefaultTTL
	}
	if o.MaxRecords <= 0 {
		o.MaxRecords = DefaultMaxRecords
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.Logf == nil {
		o.Logf = func(string, ...interface{}) {}
	}
}

// Unavailable returns a store that refuses every keyed admission with
// ErrUnavailable. The agent installs it when Open fails, so a broken state
// directory degrades to "keyed requests refused, un-keyed requests served"
// and never to "keyed requests silently re-executed".
func Unavailable(cause error) *Store {
	if cause == nil {
		cause = errors.New("not opened")
	}
	return &Store{openErr: fmt.Errorf("%w: %v", ErrUnavailable, cause), logf: func(string, ...interface{}) {}}
}

// Open loads <stateDir>/idempotency/ and returns the store.
//
// It also does the only startup work the store has: every record still
// "admitted" was left by a process that is gone, so it is turned into an
// interrupted record (failed, agent_restart_interrupted, result.outcome
// "unknown"). That is decided in memory first and then persisted best-effort,
// so a read-only state directory cannot turn an interrupted op back into an
// admissible one. Open runs no command and consults nothing but its directory.
//
// An unreadable directory is an error (the caller installs Unavailable). An
// unreadable single record is not: it is renamed to <scope>.corrupt, its
// contents are not logged, and its scope keeps refusing with ErrCorruptRecord
// until the TTL passes.
func Open(stateDir string, opt Options) (*Store, error) {
	opt.fill()
	dir := filepath.Join(stateDir, dirName)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("%w: mkdir: %v", ErrUnavailable, err)
	}
	if err := fsyncDir(filepath.Dir(dir)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	s := &Store{
		dir: dir, ttl: opt.TTL, max: opt.MaxRecords, now: opt.Now, logf: opt.Logf,
		index: map[string]meta{}, byOp: map[string]string{},
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: readdir: %v", ErrUnavailable, err)
	}
	for _, e := range entries {
		s.loadEntry(e)
	}
	s.sweepLocked()
	if s.interruptedAtOpen > 0 {
		s.logf("idem: %d keyed operation(s) were admitted by a prior agent process and have no recorded outcome; "+
			"a retry with the same idempotency_key reports failed(%s), outcome unknown, and does not run them again",
			s.interruptedAtOpen, ReasonInterrupted)
	}
	return s, nil
}

// InterruptedAtOpen returns how many records Open found without an outcome.
func (s *Store) InterruptedAtOpen() int { return s.interruptedAtOpen }

// loadEntry indexes one directory entry at Open.
func (s *Store) loadEntry(e fs.DirEntry) {
	name := e.Name()
	switch {
	case e.IsDir():
		return
	case strings.HasPrefix(name, ".idem-") && strings.HasSuffix(name, ".tmp"):
		// A temp file of a write the previous process never renamed.
		_ = os.Remove(filepath.Join(s.dir, name))
	case strings.HasSuffix(name, corruptExt):
		if hash := strings.TrimSuffix(name, corruptExt); validHash(hash) {
			s.index[hash] = meta{corrupt: true, terminal: true, admitted: s.mtime(name), finished: s.mtime(name)}
		}
	case strings.HasSuffix(name, fileExt):
		if hash := strings.TrimSuffix(name, fileExt); validHash(hash) {
			s.loadRecord(hash)
		}
	}
}

// loadRecord reads one record at Open, quarantining it if unreadable and
// marking it interrupted if it never reached a terminal state.
func (s *Store) loadRecord(hash string) {
	rec, err := s.readLocked(hash)
	if err != nil {
		s.quarantineLocked(hash, err)
		return
	}
	if !rec.Terminal() {
		MarkInterrupted(rec, s.now())
		if werr := s.writeLocked(hash, rec); werr != nil {
			// Not persisted; the next start decides the same thing again.
			s.logf("idem: could not persist the interruption of op %s: %v", rec.OpID, werr)
		}
		s.interruptedAtOpen++
	}
	// rec is terminal here either way, so the index holds the verdict even
	// when the interruption could not be written back.
	s.putIndexLocked(hash, rec)
}

// MarkInterrupted turns an admitted record into the honest terminal answer for
// an op that has no process behind it and no recorded outcome.
func MarkInterrupted(rec *Record, now time.Time) {
	rec.State = StateFailed
	rec.FailureReason = ReasonInterrupted
	rec.Interrupted = true
	rec.FinishedAt = &now
	rec.Result = map[string]interface{}{
		outcomeKey:  outcomeUnk,
		interruptAt: now.Format(time.RFC3339),
		"detail": "the agent stopped after admitting this operation and before recording its outcome; " +
			"it may have run partly, fully or not at all. It was not run again. " +
			"Verify the state, then submit a new idempotency_key to proceed.",
	}
}

func validHash(h string) bool {
	if len(h) != hashHexLen {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil && strings.ToLower(h) == h
}

func (s *Store) mtime(name string) time.Time {
	fi, err := os.Stat(filepath.Join(s.dir, name))
	if err != nil {
		return s.now()
	}
	return fi.ModTime().UTC()
}

func (s *Store) putIndexLocked(hash string, rec *Record) {
	if old, ok := s.index[hash]; ok && old.opID != "" && old.opID != rec.OpID {
		delete(s.byOp, old.opID)
	}
	m := meta{opID: rec.OpID, terminal: rec.Terminal(), admitted: rec.AdmittedAt}
	if rec.FinishedAt != nil {
		m.finished = *rec.FinishedAt
	}
	s.index[hash] = m
	s.byOp[rec.OpID] = hash
}

func (s *Store) dropIndexLocked(hash string) {
	if m, ok := s.index[hash]; ok && m.opID != "" && s.byOp[m.opID] == hash {
		delete(s.byOp, m.opID)
	}
	delete(s.index, hash)
}

// quarantineLocked sets an unreadable record aside. Only the file name and the
// error class are logged, never the bytes.
func (s *Store) quarantineLocked(hash string, cause error) {
	from := filepath.Join(s.dir, hash+fileExt)
	when := s.mtime(hash + fileExt)
	if err := os.Rename(from, filepath.Join(s.dir, hash+corruptExt)); err != nil {
		s.logf("idem: unreadable record %s could not be set aside (%v); its key stays refused", hash+fileExt, err)
	} else {
		_ = fsyncDir(s.dir)
		s.logf("idem: unreadable record set aside as %s (%v); its key is refused until the retention window passes",
			hash+corruptExt, errClass(cause))
	}
	s.dropIndexLocked(hash)
	s.index[hash] = meta{corrupt: true, terminal: true, admitted: when, finished: when}
}

// errClass reduces a read error to text that cannot carry record content.
func errClass(err error) string {
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	switch {
	case errors.As(err, &se), errors.As(err, &te):
		return "invalid JSON"
	case errors.Is(err, errTooLarge):
		return "exceeds size bound"
	case errors.Is(err, errScopeMismatch):
		return "scope does not match file name"
	case errors.Is(err, errBadRecord):
		return "invalid record"
	default:
		return "read error"
	}
}

var (
	errTooLarge      = errors.New("record too large")
	errScopeMismatch = errors.New("scope mismatch")
	errBadRecord     = errors.New("invalid record")
)

// readLocked reads and validates the record file of hash. The read is bounded:
// a file larger than MaxRecordBytes was not written by this package.
func (s *Store) readLocked(hash string) (*Record, error) {
	f, err := os.Open(filepath.Join(s.dir, hash+fileExt)) // #nosec G304 -- hash is validated hex under the store dir
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, MaxRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxRecordBytes {
		return nil, errTooLarge
	}
	var rec Record
	if uerr := json.Unmarshal(data, &rec); uerr != nil {
		return nil, uerr
	}
	if scopeHash(rec.Actor, rec.Kind, rec.IdempotencyKey) != hash {
		return nil, errScopeMismatch
	}
	if !validRecord(&rec) {
		return nil, errBadRecord
	}
	return &rec, nil
}

func validRecord(rec *Record) bool {
	switch rec.State {
	case StateAdmitted, StateSucceeded, StateFailed, StateCancelled:
	default:
		return false
	}
	return rec.Version == schemaV1 && rec.OpID != "" && rec.IdempotencyKey != "" &&
		len(rec.Fingerprint) == hashHexLen && !rec.AdmittedAt.IsZero()
}

// writeLocked persists rec under hash, reduced to MaxRecordBytes if needed.
func (s *Store) writeLocked(hash string, rec *Record) error {
	data, err := encodeBounded(rec)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.dir, hash+fileExt), data, fileMode)
}

// encodeBounded marshals rec, shedding the largest optional content first until
// it fits. Scope, fingerprint, op_id, state and reason are never shed, so a
// reduced record still dedupes and still names its outcome.
func encodeBounded(rec *Record) ([]byte, error) {
	reduce := []func(){
		func() {},
		func() {
			for i := range rec.Progress {
				if len(rec.Progress[i].Output) > maxStageOutput {
					rec.Progress[i].Output = rec.Progress[i].Output[:maxStageOutput] + "…[truncated]"
				}
			}
		},
		func() {
			rec.Result = map[string]interface{}{"result_omitted": true, "detail": "result exceeded the idempotency record size bound"}
		},
		func() { rec.Progress = nil },
		func() { rec.Params = nil },
	}
	for i, step := range reduce {
		step()
		if i > 0 {
			rec.Truncated = true
		}
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, fmt.Errorf("idem: marshal: %w", err)
		}
		if len(data) <= MaxRecordBytes {
			return data, nil
		}
	}
	return nil, fmt.Errorf("idem: record of op %s cannot be reduced below %d bytes", rec.OpID, MaxRecordBytes)
}

// Lookup returns the live record of (actor, kind, key), or found=false. A
// record past its TTL is not found. ErrCorruptRecord means a record for this
// exact scope exists but is unreadable; ErrUnavailable that the store is.
func (s *Store) Lookup(actor, kind, key string) (rec *Record, found bool, err error) {
	if s.openErr != nil {
		return nil, false, s.openErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := scopeHash(actor, kind, key)
	m, ok := s.index[hash]
	if !ok || s.expired(m) {
		return nil, false, nil
	}
	if m.corrupt {
		return nil, true, ErrCorruptRecord
	}
	rec, rerr := s.readLocked(hash)
	if rerr != nil {
		s.quarantineLocked(hash, rerr)
		return nil, true, ErrCorruptRecord
	}
	if m.terminal && !rec.Terminal() {
		// Open decided "interrupted" but could not persist it.
		MarkInterrupted(rec, m.finishedOr(s.now()))
	}
	return rec, true, nil
}

func (m meta) finishedOr(t time.Time) time.Time {
	if m.finished.IsZero() {
		return t
	}
	return m.finished
}

// Has reports whether Lookup would find something (a record or a refusal) for
// the scope, without reading the file.
func (s *Store) Has(actor, kind, key string) bool {
	if s.openErr != nil {
		return true // a keyed admission will be refused, not admitted
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.index[scopeHash(actor, kind, key)]
	return ok && !s.expired(m)
}

// ByOpID returns the record of opID, if the store holds one within its TTL.
func (s *Store) ByOpID(opID string) (*Record, bool) {
	if s.openErr != nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, ok := s.byOp[opID]
	if !ok {
		return nil, false
	}
	m := s.index[hash]
	if s.expired(m) || m.corrupt {
		return nil, false
	}
	rec, err := s.readLocked(hash)
	if err != nil {
		s.quarantineLocked(hash, err)
		return nil, false
	}
	if m.terminal && !rec.Terminal() {
		MarkInterrupted(rec, m.finishedOr(s.now()))
	}
	return rec, true
}

func (s *Store) expired(m meta) bool {
	return !m.admitted.After(s.now().Add(-s.ttl))
}

// Admit durably records that rec's op is about to run. It returns only after
// the record and its directory entry are fsynced; on any error nothing may run.
// rec.State is forced to StateAdmitted. Admit replaces an expired record of the
// same scope; the caller has already established (via Lookup) that no live one
// exists.
func (s *Store) Admit(rec Record) error {
	if s.openErr != nil {
		return s.openErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	hash := scopeHash(rec.Actor, rec.Kind, rec.IdempotencyKey)
	if _, replacing := s.index[hash]; !replacing && len(s.index) >= s.max {
		if !s.evictOneLocked() {
			return fmt.Errorf("%w: %d records, none terminal", ErrFull, len(s.index))
		}
	}
	rec.Version = schemaV1
	rec.State = StateAdmitted
	rec.FinishedAt = nil
	if !validRecord(&rec) {
		return fmt.Errorf("%w: incomplete record", ErrUnavailable)
	}
	if err := s.writeLocked(hash, &rec); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	// A quarantined predecessor of this scope has expired (Lookup said so).
	_ = os.Remove(filepath.Join(s.dir, hash+corruptExt))
	s.putIndexLocked(hash, &rec)
	return nil
}

// Complete records the terminal outcome of the op admitted for rec's scope. It
// is a no-op when the scope's record now belongs to a different op (the first
// op's record expired and the key was admitted again). The caller treats an
// error as "outcome not recorded": the record stays admitted, and a restart
// reports the op as interrupted.
func (s *Store) Complete(rec Record) error {
	if s.openErr != nil {
		return s.openErr
	}
	if rec.State == StateAdmitted || rec.FinishedAt == nil {
		return errors.New("idem: Complete needs a terminal state and finished_at")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := scopeHash(rec.Actor, rec.Kind, rec.IdempotencyKey)
	m, ok := s.index[hash]
	if !ok || m.opID != rec.OpID {
		return nil
	}
	rec.Version = schemaV1
	if err := s.writeLocked(hash, &rec); err != nil {
		s.logf("idem: outcome of op %s (%s) could not be recorded: %v; after a restart it is reported as outcome unknown",
			rec.OpID, rec.State, err)
		return fmt.Errorf("idem: record outcome of op %s: %w", rec.OpID, err)
	}
	s.putIndexLocked(hash, &rec)
	return nil
}

// Len returns the number of records held, quarantined ones included.
func (s *Store) Len() int {
	if s.openErr != nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.index)
}

// Dir returns the store directory (tests and diagnostics).
func (s *Store) Dir() string { return s.dir }

// sweepLocked removes every TERMINAL record past its TTL. A record of a
// running op is left alone whatever its age: its op will still call Complete.
func (s *Store) sweepLocked() {
	removed := false
	for hash, m := range s.index {
		if m.terminal && s.expired(m) {
			s.removeLocked(hash)
			removed = true
		}
	}
	if removed {
		_ = fsyncDir(s.dir)
	}
}

func (s *Store) removeLocked(hash string) {
	_ = os.Remove(filepath.Join(s.dir, hash+fileExt))
	_ = os.Remove(filepath.Join(s.dir, hash+corruptExt))
	s.dropIndexLocked(hash)
}

// evictOneLocked removes the oldest-finished terminal record to make room.
// Evicting a record inside its TTL means a retry of that key is admitted as new
// work; the cap is the bound on storage and this is its documented cost.
func (s *Store) evictOneLocked() bool {
	hashes := make([]string, 0, len(s.index))
	for hash, m := range s.index {
		if m.terminal {
			hashes = append(hashes, hash)
		}
	}
	if len(hashes) == 0 {
		return false
	}
	sort.Slice(hashes, func(i, j int) bool {
		a, b := s.index[hashes[i]], s.index[hashes[j]]
		if !a.finished.Equal(b.finished) {
			return a.finished.Before(b.finished)
		}
		return hashes[i] < hashes[j]
	})
	s.removeLocked(hashes[0])
	_ = fsyncDir(s.dir)
	return true
}

// atomicWrite writes data to path via a temp file in the same directory:
// chmod → fsync(file) → rename → fsync(dir). Same sequence as internal/journal.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, tmpPattern)
	if err != nil {
		return fmt.Errorf("idem: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("idem: write temp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("idem: chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("idem: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("idem: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("idem: rename: %w", err)
	}
	return fsyncDir(dir)
}

// fsyncDir fsyncs a directory so a create/rename/unlink within it is durable.
func fsyncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- agent-owned state directory
	if err != nil {
		return fmt.Errorf("idem: open dir for fsync: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("idem: fsync dir: %w", err)
	}
	return nil
}
