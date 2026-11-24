package ops

import (
	"errors"
	"fmt"

	"culvert-maint/internal/idem"
)

// Durable idempotency (internal/idem).
//
// The in-memory idempCache answers a same-key retry while the process lives.
// With a store installed the Manager also:
//
//   - writes the admission record BEFORE it admits a keyed op (write-ahead,
//     fail-closed: no record, no op);
//   - writes the terminal outcome when the op finishes (Finish);
//   - answers a same-key retry, and GET /v1/operations/{id}, from the record
//     when the op is no longer in memory — which is every keyed op after a
//     restart. Answering takes neither the maintenance lock nor an execution
//     slot and runs nothing.
//
// A record with no outcome after a restart is an interrupted op: it is answered
// as failed(agent_restart_interrupted) with result.outcome "unknown" and is not
// run again under that key. For a journaled kind the journal's own projection
// (MarkAllInterrupted) is already in the active map under the same op_id and is
// what the retry returns.
//
// This is not exactly-once execution; see the internal/idem package comment
// for the failure boundaries.

// IdempotencyMismatch is returned by BeginIdempotent when the idempotency key
// was first used, by the same actor for the same kind, with a different
// payload. Nothing is admitted and nothing runs.
type IdempotencyMismatch struct {
	// OpID is the operation the key belongs to.
	OpID string
	Kind string
}

func (e *IdempotencyMismatch) Error() string {
	return fmt.Sprintf("ops: idempotency_key was already used for %s operation %s with a different payload", e.Kind, e.OpID)
}

// IdempotencyUnavailable is returned by BeginIdempotent when a keyed request
// cannot be admitted safely: the durable store cannot be read or written
// (Unreadable=false), or the record of this exact key exists but cannot be read
// (Unreadable=true), so whether the request already ran is unknown. Un-keyed
// requests are not affected.
type IdempotencyUnavailable struct {
	Unreadable bool
	Err        error
}

func (e *IdempotencyUnavailable) Error() string {
	if e.Unreadable {
		return "ops: the idempotency record of this key is unreadable; its outcome is unknown"
	}
	return fmt.Sprintf("ops: idempotency store unavailable: %v", e.Err)
}

func (e *IdempotencyUnavailable) Unwrap() error { return e.Err }

// SetIdempotencyStore installs the durable store. Call it once, at wiring time,
// before the Manager admits anything. The store should share the Manager's TTL
// and clock so both halves expire a key at the same moment.
func (m *Manager) SetIdempotencyStore(s *idem.Store) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idem = s
}

// priorForKeyLocked resolves a keyed submission against what is already known
// for (actor, kind, key): first the in-memory cache, then the durable store.
// It returns the op to answer with, or an error that refuses the submission.
// (nil, nil) means the key is free and the caller admits new work. It never
// consults the maintenance lock. Caller holds m.mu.
func (m *Manager) priorForKeyLocked(kind, actor, key, fingerprint string) (*Op, error) {
	cacheKey := idempCacheKey(actor, kind, key)
	if entry, ok := m.idempCache[cacheKey]; ok {
		if existing, alive := m.active[entry.OpID]; alive {
			if entry.Fingerprint != fingerprint {
				return nil, &IdempotencyMismatch{OpID: existing.ID, Kind: kind}
			}
			return m.cloneLocked(existing), nil
		}
		// Cache references a dropped op; clear it and let the durable record,
		// if any, answer.
		delete(m.idempCache, cacheKey)
	}
	if m.idem == nil {
		return nil, nil
	}
	rec, found, err := m.idem.Lookup(actor, kind, key)
	if err != nil {
		return nil, &IdempotencyUnavailable{Unreadable: errors.Is(err, idem.ErrCorruptRecord), Err: err}
	}
	if !found {
		return nil, nil
	}
	if rec.Fingerprint != fingerprint {
		return nil, &IdempotencyMismatch{OpID: rec.OpID, Kind: kind}
	}
	return m.opFromRecordLocked(rec), nil
}

// opFromRecordLocked projects a durable record as an op. An op of the same id
// still in the active map wins: that is the journal's interrupted projection
// (MarkAllInterrupted), which knows more than the record does. A record with
// no outcome and no op behind it is reported as interrupted, never as running.
// Caller holds m.mu.
func (m *Manager) opFromRecordLocked(rec *idem.Record) *Op {
	if existing, ok := m.active[rec.OpID]; ok {
		return m.cloneLocked(existing)
	}
	if !rec.Terminal() {
		idem.MarkInterrupted(rec, m.now())
	}
	op := &Op{
		ID:             rec.OpID,
		Kind:           rec.Kind,
		State:          State(rec.State),
		Actor:          rec.Actor,
		IdempotencyKey: rec.IdempotencyKey,
		Started:        rec.AdmittedAt,
		Finished:       rec.FinishedAt,
		FailureReason:  rec.FailureReason,
		Params:         rec.Params,
		Progress:       make([]Stage, 0, len(rec.Progress)),
		Result:         rec.Result,
		fingerprint:    rec.Fingerprint,
	}
	if IsStateChanging(rec.Kind) {
		op.LockHeldBy = rec.OpID // as the in-memory record of a finished op reads
	}
	for _, st := range rec.Progress {
		op.Progress = append(op.Progress, Stage{
			Name: st.Name, State: State(st.State), Started: st.Started, Ended: st.Ended, Output: st.Output,
		})
	}
	return op
}

// recordOf builds the durable record of a keyed op from its in-memory state.
func recordOf(op *Op) idem.Record {
	rec := idem.Record{
		Actor:          op.Actor,
		Kind:           op.Kind,
		IdempotencyKey: op.IdempotencyKey,
		Fingerprint:    op.fingerprint,
		OpID:           op.ID,
		State:          idem.StateAdmitted,
		AdmittedAt:     op.Started,
		Params:         op.Params,
	}
	if !op.State.IsTerminal() {
		return rec
	}
	rec.State = string(op.State)
	rec.FinishedAt = op.Finished
	rec.FailureReason = op.FailureReason
	rec.Result = op.Result
	rec.Progress = make([]idem.Stage, 0, len(op.Progress))
	for _, st := range op.Progress {
		rec.Progress = append(rec.Progress, idem.Stage{
			Name: st.Name, State: string(st.State), Started: st.Started, Ended: st.Ended, Output: st.Output,
		})
	}
	return rec
}

// admitDurableLocked writes the write-ahead admission record of a keyed op. A
// no-op for an un-keyed op or a Manager without a store. Caller holds m.mu;
// the fsync happens under it on purpose, so "record durable" and "op admitted"
// cannot be observed out of order.
func (m *Manager) admitDurableLocked(op *Op) error {
	if op.IdempotencyKey == "" || m.idem == nil {
		return nil
	}
	if err := m.idem.Admit(recordOf(op)); err != nil {
		return &IdempotencyUnavailable{Err: err}
	}
	return nil
}

// recordOutcomeLocked writes the terminal outcome of a keyed op. Best-effort:
// the store logs a failure, and the record then still says "admitted", which a
// restart reports as outcome unknown — never as succeeded. Caller holds m.mu.
func (m *Manager) recordOutcomeLocked(op *Op) {
	if op.IdempotencyKey == "" || m.idem == nil || op.fingerprint == "" {
		return
	}
	_ = m.idem.Complete(recordOf(op)) //nolint:errcheck // logged by the store; see above
}

// GetRecorded is Get that also answers for an op known only to the durable
// idempotency store: a keyed op admitted by an earlier agent process, or one
// already reaped from memory. Returns nil if neither knows the id. Un-keyed
// ops are not recorded durably and are not found after a restart.
func (m *Manager) GetRecorded(opID string) *Op {
	m.mu.Lock()
	defer m.mu.Unlock()
	if op, ok := m.active[opID]; ok {
		return m.cloneLocked(op)
	}
	if m.idem == nil {
		return nil
	}
	rec, ok := m.idem.ByOpID(opID)
	if !ok {
		return nil
	}
	return m.opFromRecordLocked(rec)
}
