package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// A state file that EXISTS but cannot be read is not an absent one: the
// store must say so and must never write over it (Codex P2, PR #1528 — the
// first shape treated every ReadFile error as "fresh", so a transient EACCES
// during a control-plane restart silently abandoned the in-flight dispatch
// and the next persist overwrote the records with an empty store).
func TestDispatchStore_UnreadableStateIsSurfacedNotOverwritten(t *testing.T) {
	// Root-proof half: a path that exists but is a DIRECTORY reads as EISDIR,
	// which is not fs.ErrNotExist, on every uid.
	asDir := filepath.Join(t.TempDir(), releaseDispatchStateFile)
	if err := os.Mkdir(asDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if st := newPersistentDispatchStore(asDir); st.loadErr == nil {
		t.Fatal("an existing-but-unreadable state path must be recorded, not read as absent")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 file; the overwrite half needs the permission fault")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, releaseDispatchStateFile)
	seed := newPersistentDispatchStore(path)
	seed.markDispatched("local", "01HDISPATCH000000000000007", DispatchResumeContext{OpID: "op-7", TargetPinnedRef: "x@sha256:" + strings.Repeat("a", 64)})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	st := newPersistentDispatchStore(path)
	if st.loadErr == nil {
		t.Fatal("an unreadable state file must be recorded, not read as absent")
	}
	if _, ok := st.get("local"); ok {
		t.Fatal("nothing can be loaded from an unreadable file")
	}
	// A write while degraded must leave the unread records intact.
	st.markDispatched("local", "01HDISPATCH000000000000008", DispatchResumeContext{OpID: "op-8", TargetPinnedRef: "x@sha256:" + strings.Repeat("b", 64)})
	_ = os.Chmod(path, 0o600)
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("a persist while the file was unreadable overwrote the records it could not read")
	}
	// CONTROL: an ABSENT file is still the ordinary fresh store.
	fresh := newPersistentDispatchStore(filepath.Join(dir, "absent.json"))
	if fresh.loadErr != nil {
		t.Fatalf("absent must stay fresh, got %v", fresh.loadErr)
	}
}

// An accepted dispatch whose record cannot reach disk is still a 202 — the
// agent has started the op and it cannot be taken back — but the response must
// not imply the durable-record contract was met: a restarted control plane
// would have nothing to resume (Codex P2). CONTROL: a writable path is durable.
func TestReleaseAPI_DispatchReportsAnUntrackedOp(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    func(t *testing.T) string
		durable bool
	}{
		{"writable", func(t *testing.T) string { return filepath.Join(t.TempDir(), "release_dispatch_state.json") }, true},
		{"unwritable", func(t *testing.T) string {
			blocker := filepath.Join(t.TempDir(), "not-a-dir")
			if err := os.WriteFile(blocker, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(blocker, "release_dispatch_state.json")
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cat := mustLoad(t, validSource())
			rm, _, _ := newReleaseFixture(t, cat, map[string]*fakeAgent{"A": {runningSeq: freshDispatchSeq(), applyOpID: "op", waitState: agentStateSucceeded}})
			rm.store.path = tc.path(t)
			rec := httptest.NewRecorder()
			apiReleaseDispatch(rec, releaseReq(http.MethodPost, "/api/releases/dispatch",
				dispatchRequest{ReleaseID: "rel_a", Agent: "A"}, RoleAdmin))
			if rec.Code != http.StatusAccepted {
				t.Fatalf("dispatch = %d; want 202 (the op was accepted)", rec.Code)
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["durable"] != tc.durable {
				t.Fatalf("durable = %v; want %v (%s)", body["durable"], tc.durable, rec.Body.String())
			}
			w, hasWarning := body["warning"].(string)
			if tc.durable == hasWarning {
				t.Fatalf("warning present=%v for durable=%v: %q", hasWarning, tc.durable, w)
			}
			if !tc.durable && !strings.Contains(w, "dispatch_record_not_persisted") {
				t.Fatalf("warning does not name the condition: %q", w)
			}
			waitTerminal(t, rm, "A")
		})
	}
}
