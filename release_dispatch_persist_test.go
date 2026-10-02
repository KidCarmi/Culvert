package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ─── durable dispatch state + resume after a control-plane restart ──────────

func TestDispatchStore_PersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), releaseDispatchStateFile)
	st := newPersistentDispatchStore(path)
	rc := DispatchResumeContext{AgentID: "local", OpID: "op-9", ReleaseID: "rel_a", VersionID: "1.10.0",
		TargetPinnedRef: dispatchRepo + "@" + digA, ImageRef: dispatchRepo + "@" + digA, IdempotencyKey: "rel-rel_a-K"}
	st.markDispatched("local", "01HDISPATCH000000000000001", rc)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state file must be written on update: %v", err)
	}
	st2 := newPersistentDispatchStore(path)
	rec, ok := st2.get("local")
	if !ok || rec.Phase != phaseDispatched || rec.OpID != "op-9" || rec.ResumeContext.TargetPinnedRef != rc.TargetPinnedRef {
		t.Fatalf("reloaded record = %+v ok=%v", rec, ok)
	}
	got := st2.interruptedDispatches()
	if len(got) != 1 || got[0].DispatchID != "01HDISPATCH000000000000001" {
		t.Fatalf("interrupted = %+v", got)
	}
	// A terminal record is not interrupted and survives the round trip too.
	st2.markTerminal("local", "01HDISPATCH000000000000001", &DispatchReport{Outcome: OutcomePlan, OpID: "op-9", Terminal: TerminalSucceeded, Verified: true})
	st3 := newPersistentDispatchStore(path)
	if rec, _ := st3.get("local"); rec.Phase != phaseTerminal || rec.Terminal != TerminalSucceeded || !rec.Verified {
		t.Fatalf("terminal record lost in round trip: %+v", rec)
	}
	if n := len(st3.interruptedDispatches()); n != 0 {
		t.Fatalf("terminal record must not be resumed, got %d", n)
	}
}

func TestDispatchStore_MalformedStateIsMovedAsideNotTrusted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, releaseDispatchStateFile)
	if err := os.WriteFile(path, []byte("{\"version\":1,\"records\":"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := newPersistentDispatchStore(path)
	if _, ok := st.get("local"); ok {
		t.Fatal("malformed state must not yield records")
	}
	entries, _ := os.ReadDir(dir)
	aside := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), releaseDispatchStateFile+".corrupt.") {
			aside++
		}
	}
	if aside != 1 {
		t.Fatalf("malformed file must be moved aside exactly once, found %d", aside)
	}
	// The store keeps working on the same path afterwards.
	st.markDispatched("local", "01HDISPATCH000000000000002", DispatchResumeContext{OpID: "op-1", TargetPinnedRef: "x@sha256:" + strings.Repeat("a", 64)})
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state must be re-created after a move-aside: %v", err)
	}
}

// After the proxy container is replaced by its own upgrade, the new process
// must re-attach to the in-flight dispatch, verify by digest, and leave a
// terminal record the GUI can show — without ever calling Apply again.
func TestReleaseManager_ResumesInterruptedDispatchAtStartup(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent := &fakeAgent{waitState: agentStateSucceeded, runningSeq: [][]string{{dispatchRepo + "@" + digA}}}
	rm, au, _ := newReleaseFixture(t, cat, map[string]*fakeAgent{"local": agent})

	path := filepath.Join(t.TempDir(), releaseDispatchStateFile)
	prev := newPersistentDispatchStore(path)
	rc := DispatchResumeContext{AgentID: "local", OpID: "op-77", ReleaseID: "rel_a", VersionID: "1.10.0",
		TargetPinnedRef: dispatchRepo + "@" + digA, ImageRef: dispatchRepo + "@" + digA}
	prev.markDispatched("local", "01HDISPATCH000000000000003", rc)

	// "Restart": a fresh manager over the same file.
	rm.store = newPersistentDispatchStore(path)
	rm.resumeWait = func(wg *sync.WaitGroup) { wg.Wait() }
	if n := rm.resumeInterruptedDispatches(); n != 1 {
		t.Fatalf("resumed %d, want 1", n)
	}
	rec, ok := rm.store.get("local")
	if !ok || rec.Phase != phaseTerminal || rec.Terminal != TerminalSucceeded || !rec.Verified || rec.OpID != "op-77" {
		t.Fatalf("record after resume = %+v ok=%v", rec, ok)
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("resume must never re-apply; saw %d apply request(s)", len(agent.applyReqs))
	}
	if agent.waitCalls.Load() != 1 {
		t.Fatalf("resume must re-poll the existing op exactly once, got %d", agent.waitCalls.Load())
	}
	// The outcome is audited under the startup actor.
	au.mu.Lock()
	found := false
	for _, e := range au.entries {
		if e.Actor == dispatchResumeActor {
			found = true
		}
	}
	au.mu.Unlock()
	if !found {
		t.Fatalf("resume outcome must be audited as %s", dispatchResumeActor)
	}
	// Idempotent: nothing left to resume, and the terminal record survives on disk.
	if n := rm.resumeInterruptedDispatches(); n != 0 {
		t.Fatalf("second startup must find nothing to resume, got %d", n)
	}
	if rec, _ := newPersistentDispatchStore(path).get("local"); rec.Terminal != TerminalSucceeded {
		t.Fatalf("terminal record not persisted: %+v", rec)
	}
}

// An agent that no longer knows the op (restarted, or past its retention)
// yields the honest needs-attention classification rather than "no dispatch".
func TestReleaseManager_ResumeUnknownOpIsNeedsAttention(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent := &fakeAgent{waitErr: &agentHTTPError{Status: 404, Method: "GET", Path: "/v1/operations/op-gone"}, runningSeq: [][]string{{dispatchRepo + "@" + digB}}}
	rm, _, _ := newReleaseFixture(t, cat, map[string]*fakeAgent{"local": agent})
	path := filepath.Join(t.TempDir(), releaseDispatchStateFile)
	prev := newPersistentDispatchStore(path)
	prev.markDispatched("local", "01HDISPATCH000000000000004", DispatchResumeContext{AgentID: "local", OpID: "op-gone", ReleaseID: "rel_a", TargetPinnedRef: dispatchRepo + "@" + digA})
	rm.store = newPersistentDispatchStore(path)
	rm.resumeWait = func(wg *sync.WaitGroup) { wg.Wait() }
	rm.resumeInterruptedDispatches()
	rec, _ := rm.store.get("local")
	if rec.Phase != phaseTerminal || rec.Terminal != TerminalFailedNeedsAttn || rec.OpID != "op-gone" {
		t.Fatalf("record = %+v; want terminal failed_needs_attn keeping the op_id (the GUI's Resume handle)", rec)
	}
}
