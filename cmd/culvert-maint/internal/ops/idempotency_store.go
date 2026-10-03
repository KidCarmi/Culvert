// Persisted idempotency index (on-prem readiness, deliverable D).
//
// The in-memory idempotency cache (Manager.idempCache) is lost on every agent
// restart, so a Control Plane retrying POST /v1/upgrades/apply with the SAME
// idempotency_key after a crash was admitted as a SECOND destructive op. This
// file persists the (actor|kind|key → op_id + terminal outcome) index for the
// JOURNALED kinds only (upgrades.apply, rollbacks.create — the ones whose
// duplicate is a second stack mutation) to <state_dir>/idempotency.json, so the
// retry dedupes to the prior op's outcome instead.
//
// Properties:
//   - Atomic write (temp + rename + fsync) on every change; best-effort — a
//     persist failure never blocks admission (it is counted, see
//     IdempPersistErrors), because refusing to run an op over a bookkeeping
//     write would convert an availability nicety into an outage.
//   - Bounded: at most maxPersistedIdemp entries (oldest evicted) and the same
//     24h TTL as the in-memory cache; entries past the TTL are dropped on load.
//   - On load, each live entry is re-inserted into the in-memory cache AND its
//     op is re-materialized in the active map with the stored terminal outcome,
//     so BeginIdempotent's existing dedupe path answers 200 deduped with the
//     prior op's state/result. An entry whose op never reached terminal (crash
//     mid-flight) materializes as failed(agent_restart_interrupted) — the agent
//     never guesses success.
package ops

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// maxPersistedIdemp bounds the on-disk index; oldest entries are evicted first.
const maxPersistedIdemp = 256

// IdempRecord is one persisted idempotency entry. Params carry the sanitized
// admission params (never a secret — handlers strip those before admission).
type IdempRecord struct {
	Actor          string                 `json:"actor"`
	Kind           string                 `json:"kind"`
	IdempotencyKey string                 `json:"idempotency_key"`
	OpID           string                 `json:"op_id"`
	CreatedAt      time.Time              `json:"created_at"`
	State          State                  `json:"state"` // terminal state, or "" while in flight
	FailureReason  string                 `json:"failure_reason,omitempty"`
	FinishedAt     *time.Time             `json:"finished_at,omitempty"`
	Params         map[string]interface{} `json:"params,omitempty"`
	Result         map[string]interface{} `json:"result,omitempty"`
}

type idempFile struct {
	Version int           `json:"version"`
	Entries []IdempRecord `json:"entries"`
}

// EnableIdempotencyPersistence turns on persistence to path for journaled
// kinds. Call once at startup, BEFORE LoadIdempotencyIndex.
func (m *Manager) EnableIdempotencyPersistence(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idempPath = path
	if m.persisted == nil {
		m.persisted = map[string]*IdempRecord{}
	}
}

// IdempPersistErrors reports how many persist attempts failed (best-effort
// bookkeeping; surfaced for tests and diagnostics).
func (m *Manager) IdempPersistErrors() int64 { return m.idempPersistErrs.Load() }

// LoadIdempotencyIndex reads the persisted index, drops entries older than the
// cache TTL, and re-materializes the rest into the in-memory cache + active map
// (skipping any op_id already present, e.g. one MarkAllInterrupted registered).
// A missing file is not an error; a corrupt file is returned as an error and the
// index starts empty (the caller logs; admission continues). Returns the number
// of entries re-materialized.
func (m *Manager) LoadIdempotencyIndex() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idempPath == "" {
		return 0, nil
	}
	data, err := os.ReadFile(m.idempPath) // #nosec G304 -- agent-owned state path from config
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("idempotency index: read: %w", err)
	}
	var f idempFile
	if uerr := json.Unmarshal(data, &f); uerr != nil {
		return 0, fmt.Errorf("idempotency index: corrupt (%v) — starting empty", uerr)
	}
	cutoff := m.now().Add(-m.idempCacheTTL)
	n := 0
	for i := range f.Entries {
		e := f.Entries[i]
		if e.OpID == "" || e.IdempotencyKey == "" || e.CreatedAt.Before(cutoff) || !IsJournaled(e.Kind) {
			continue
		}
		rec := e
		m.persisted[idempCacheKey(e.Actor, e.Kind, e.IdempotencyKey)] = &rec
		m.idempCache[idempCacheKey(e.Actor, e.Kind, e.IdempotencyKey)] = idempEntry{OpID: e.OpID, When: e.CreatedAt}
		if _, exists := m.active[e.OpID]; !exists {
			m.active[e.OpID] = materializeIdempOp(&rec, m.now())
		}
		n++
	}
	return n, nil
}

// materializeIdempOp rebuilds a terminal Op from a persisted entry. An entry
// that never recorded a terminal state is materialized as interrupted — the
// crash happened mid-flight and the agent never guesses success.
func materializeIdempOp(e *IdempRecord, now time.Time) *Op {
	op := &Op{
		ID:             e.OpID,
		Kind:           e.Kind,
		Actor:          e.Actor,
		IdempotencyKey: e.IdempotencyKey,
		Started:        e.CreatedAt,
		Params:         e.Params,
		Result:         e.Result,
		Progress:       []Stage{},
	}
	if e.State.IsTerminal() {
		op.State = e.State
		op.FailureReason = e.FailureReason
		fin := now
		if e.FinishedAt != nil {
			fin = *e.FinishedAt
		}
		op.Finished = &fin
		return op
	}
	op.State = StateFailed
	op.FailureReason = string(ReasonAgentRestartInterrupted)
	fin := now
	op.Finished = &fin
	return op
}

// recordIdempAdmissionLocked persists a fresh admission. Caller holds m.mu.
func (m *Manager) recordIdempAdmissionLocked(op *Op) {
	if m.idempPath == "" || op.IdempotencyKey == "" || !IsJournaled(op.Kind) {
		return
	}
	m.persisted[idempCacheKey(op.Actor, op.Kind, op.IdempotencyKey)] = &IdempRecord{
		Actor: op.Actor, Kind: op.Kind, IdempotencyKey: op.IdempotencyKey, OpID: op.ID,
		CreatedAt: op.Started, Params: op.Params,
	}
	m.persistIdempLocked()
}

// recordIdempTerminalLocked updates the persisted entry (if any) with the
// op's terminal outcome. Caller holds m.mu.
func (m *Manager) recordIdempTerminalLocked(op *Op) {
	if m.idempPath == "" || op.IdempotencyKey == "" {
		return
	}
	rec, ok := m.persisted[idempCacheKey(op.Actor, op.Kind, op.IdempotencyKey)]
	if !ok || rec.OpID != op.ID {
		return
	}
	rec.State = op.State
	rec.FailureReason = op.FailureReason
	rec.FinishedAt = op.Finished
	rec.Result = op.Result
	m.persistIdempLocked()
}

// persistIdempLocked writes the bounded, TTL-pruned index atomically.
// Best-effort: failures are counted, never returned. Caller holds m.mu.
func (m *Manager) persistIdempLocked() {
	cutoff := m.now().Add(-m.idempCacheTTL)
	entries := make([]IdempRecord, 0, len(m.persisted))
	for k, r := range m.persisted {
		if r.CreatedAt.Before(cutoff) {
			delete(m.persisted, k)
			continue
		}
		entries = append(entries, *r)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].CreatedAt.After(entries[j].CreatedAt) })
	if len(entries) > maxPersistedIdemp {
		for i := maxPersistedIdemp; i < len(entries); i++ {
			delete(m.persisted, idempCacheKey(entries[i].Actor, entries[i].Kind, entries[i].IdempotencyKey))
		}
		entries = entries[:maxPersistedIdemp]
	}
	data, err := json.MarshalIndent(idempFile{Version: 1, Entries: entries}, "", "  ")
	if err != nil {
		m.idempPersistErrs.Add(1)
		return
	}
	if err := atomicWriteFile(m.idempPath, data); err != nil {
		m.idempPersistErrs.Add(1)
	}
}

// atomicWriteFile writes data via temp + fsync + rename + parent fsync.
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".idemp-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	d, err := os.Open(dir) // #nosec G304 -- agent-owned state dir
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
