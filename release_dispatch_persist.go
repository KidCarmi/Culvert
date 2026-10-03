package main

// release_dispatch_persist.go — durable dispatch state + resume after a
// control-plane restart (appliance readiness, lifecycle item E).
//
// A release dispatch is the ONE operation whose watcher is killed by its own
// success: the maintenance agent recreates the proxy container, and the proxy
// IS the control plane running the dispatch goroutine and holding the
// in-memory dispatchStore. Before this file the op_id survived only inside a
// free-text audit line, GET /api/releases/dispatch/status answered
// {"phase":"none"} after the restart, the GUI's Resume button never appeared,
// and the only recovery was a hand-built resume_context POST within the
// agent's 1h terminal-op retention. release_dispatch_exec.go documented the
// gap ("recovery goes through Resume()") without anything ever calling it.
//
// Two mechanics close it, both deliberately non-mutating:
//
//  1. The per-agent dispatch record is persisted to
//     <dataDir>/release_dispatch_state.json on every store update (atomic
//     write; a persist failure is logged once and never fails the dispatch).
//  2. At startup, every record still in phase "dispatched" with an op_id and
//     a verify target is RESUMED: the executor's Resume re-polls the agent's
//     existing op and verifies the running digest. Resume never calls Apply,
//     so a restart can never start a second upgrade; the worst case is the
//     existing FAILED_NEEDS_ATTN classification when the agent no longer
//     remembers the op.

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	releaseDispatchStateFile    = "release_dispatch_state.json"
	releaseDispatchStateVersion = 1
	// dispatchResumeActor is the audit actor for a startup-driven resume: no
	// admin asked for it, the process did.
	dispatchResumeActor = "system:startup"
)

type dispatchStateFile struct {
	Version int                        `json:"version"`
	Records map[string]*dispatchRecord `json:"records"`
}

// newPersistentDispatchStore returns a store that mirrors every update to
// path. An existing file is loaded; a malformed one is moved aside (never
// trusted, never silently overwritten) and the store starts empty.
func newPersistentDispatchStore(path string) *dispatchStore {
	st := newDispatchStore()
	st.path = path
	body, err := os.ReadFile(path) // #nosec G304 -- operator-controlled data dir
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return st // absent ⇒ fresh (the common case before the first dispatch)
		}
		// Present but unreadable (permissions, I/O error during a restart):
		// starting empty would silently abandon the in-flight dispatch this
		// file exists to resume, and the next persist would OVERWRITE the
		// unread records with an empty store. Start empty, say so, and refuse
		// to write over the file until a restart reads it (Codex P2, PR #1528).
		st.loadErr = err
		logger.Printf("release dispatch state: %s exists but could not be read (%v); interrupted dispatches will NOT be resumed and the file is left untouched until the next restart reads it", sanitizeLog(path), err)
		return st
	}
	var f dispatchStateFile
	if jerr := json.Unmarshal(body, &f); jerr != nil || f.Version != releaseDispatchStateVersion {
		aside := path + ".corrupt." + time.Now().UTC().Format("20060102T150405Z")
		_ = os.Rename(path, aside)
		logger.Printf("release dispatch state: %s unreadable (%v); moved aside to %s and starting empty",
			sanitizeLog(path), jerr, sanitizeLog(aside))
		return st
	}
	for agent, rec := range f.Records {
		if rec == nil || rec.Agent == "" || rec.DispatchID == "" {
			continue
		}
		st.byAgent[agent] = rec
	}
	return st
}

// persistLocked writes the whole (bounded, per-agent) record set. Called with
// st.mu held. Best-effort: the in-memory record is already updated, and a
// dispatch must not fail because its bookkeeping could not be written — but
// the failure is logged once per store so a read-only volume is visible.
func (st *dispatchStore) persistLocked() {
	if st.path == "" {
		return
	}
	if st.loadErr != nil {
		st.persistErrOnce.Do(func() {
			logger.Printf("release dispatch state: not persisting to %s — the file could not be read at startup (%v) and writing would discard the records it holds", sanitizeLog(st.path), st.loadErr)
		})
		return
	}
	f := dispatchStateFile{Version: releaseDispatchStateVersion, Records: st.byAgent}
	body, err := json.MarshalIndent(f, "", "  ")
	if err == nil {
		err = atomicWriteFile(st.path, body, 0o600)
	}
	if err != nil {
		st.persistErrOnce.Do(func() {
			logger.Printf("release dispatch state: persist to %s failed (%v); dispatch bookkeeping will not survive a restart", sanitizeLog(st.path), err)
		})
	}
}

// interruptedDispatches returns the records whose watch was cut short by a
// control-plane restart: still "dispatched" and carrying what Resume needs.
func (st *dispatchStore) interruptedDispatches() []dispatchRecord {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []dispatchRecord
	for _, rec := range st.byAgent {
		if rec.Phase == phaseDispatched && rec.ResumeContext.OpID != "" && rec.ResumeContext.TargetPinnedRef != "" {
			out = append(out, *rec)
		}
	}
	return out
}

// resumeInterruptedDispatches re-attaches to every dispatch the previous
// process did not see to a terminal state. It is called once at startup after
// the manager is published, runs each resume on its own goroutine (the agent
// watch can take minutes), and returns the number it started.
//
// The resume is op_id-driven and never applies; see DispatchExecutor.Resume.
// An agent that answers 404 for the op (restarted, or past its 1h retention)
// yields FAILED_NEEDS_ATTN with the detail naming the cause, which is the
// honest answer: the operator checks GET /api/releases/current and the agent
// audit log rather than being shown "no dispatch recorded".
func (rm *releaseManager) resumeInterruptedDispatches() int {
	if rm == nil || rm.svc == nil || rm.store == nil {
		return 0
	}
	recs := rm.store.interruptedDispatches()
	var wg sync.WaitGroup
	for i := range recs {
		rec := recs[i]
		ep, ok := rm.resolve(rec.Agent)
		if !ok {
			rm.store.markTerminal(rec.Agent, rec.DispatchID, &DispatchReport{
				Outcome: OutcomePlan, OpID: rec.OpID, ReleaseID: rec.ReleaseID,
				Terminal: TerminalFailedNeedsAttn, Detail: "resume_skipped: agent " + rec.Agent + " is not configured in this process",
			})
			continue
		}
		logger.Printf("release dispatch: %s (op %s, release %s) was in flight when the control plane restarted; resuming the watch (no re-apply)",
			sanitizeLog(rec.DispatchID), sanitizeLog(rec.OpID), sanitizeLog(rec.ReleaseID))
		wg.Add(1)
		go func() {
			defer wg.Done()
			rep, err := rm.svc.Resume(context.Background(), dispatchResumeActor, ep, rec.ResumeContext)
			if errors.Is(err, errDispatchInFlight) {
				return // another resume for this agent already owns the slot
			}
			rm.store.markTerminal(rec.Agent, rec.DispatchID, rep)
		}()
	}
	if rm.resumeWait != nil {
		rm.resumeWait(&wg)
	}
	return len(recs)
}

// releaseDispatchStatePath is the durable dispatch bookkeeping file under the
// persisted-state root.
func releaseDispatchStatePath() string {
	return filepath.Join(dataDir, releaseDispatchStateFile)
}
