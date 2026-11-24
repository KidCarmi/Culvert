package server

// idempotency_durable_test.go — the durable idempotency contract at the HTTP
// surface (ops/idempotency.go, internal/idem).
//
// A "restart" here is a second rig over the state directory the first one
// used: a new ops.Manager (empty memory) and a freshly opened idem.Store, as
// main() builds them. The runner is the capturing fake, so "ran nothing" is
// asserted on the commands the second agent executed, not inferred from the
// response.

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"culvert-maint/internal/auth"
	"culvert-maint/internal/idem"
	"culvert-maint/internal/ops"
)

// startDurableRig starts one agent "process" on stateDir.
func startDurableRig(t *testing.T, stateDir, sockName string) *d16bTestRig {
	t.Helper()
	mgr := ops.NewManager(nil)
	store, err := idem.Open(stateDir, idem.Options{Logf: t.Logf})
	if err != nil {
		t.Fatalf("idem.Open: %v", err)
	}
	mgr.SetIdempotencyStore(store)
	return startD16bRigIn(t, stateDir, sockName, mgr)
}

func decodeMap(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return m
}

func str(m map[string]interface{}, k string) string {
	s, _ := m[k].(string) //nolint:errcheck // absent → ""
	return s
}

// holdLock starts an un-keyed state-changing op on rig and parks it mid-stage,
// so the maintenance lock is held until the returned release is called.
func holdLock(t *testing.T, rig *d16bTestRig) (holderID string, release func()) {
	t.Helper()
	gate := make(chan struct{})
	rig.execGate.Store(&gate)
	status, body := rig.post(t, "/v1/backups", map[string]interface{}{"filename": "holder.tar.gz"})
	if status != http.StatusAccepted {
		t.Fatalf("holder: %d %s", status, body)
	}
	holderID = str(decodeMap(t, body), "op_id")
	waitForCommands(t, rig, 1)
	var once bool
	return holderID, func() {
		if once {
			return
		}
		once = true
		close(gate)
		rig.waitForOpFinished(t, holderID)
	}
}

func waitForCommands(t *testing.T, rig *d16bTestRig, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(rig.captured.snapshot()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("runner executed %d command(s), want at least %d", len(rig.captured.snapshot()), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestDurableIdempotency_CompletedResultReplayedAfterRestart: for backup.create
// and restore.commit, a keyed request that finished is answered after a restart
// with the same op_id and the same record, runs no command, and is not blocked
// by another state-changing op holding the maintenance lock.
func TestDurableIdempotency_CompletedResultReplayedAfterRestart(t *testing.T) {
	cases := []struct {
		name, path string
		body       map[string]interface{}
	}{
		{"backup.create", "/v1/backups", map[string]interface{}{"filename": "nightly.tar.gz", "idempotency_key": "key-1"}},
		{"restore.commit", "/v1/restores/commit", map[string]interface{}{"path": "/backup/x.enc", "mode": "full", "idempotency_key": "key-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { assertCompletedReplay(t, tc.path, tc.body) })
	}
}

// assertCompletedReplay runs reqBody to completion on one agent, restarts, and
// replays it while another op holds the maintenance lock.
func assertCompletedReplay(t *testing.T, path string, reqBody map[string]interface{}) {
	t.Helper()
	dir := t.TempDir()
	first := startDurableRig(t, dir, "a.sock")
	status, body := first.post(t, path, reqBody)
	if status != http.StatusAccepted {
		t.Fatalf("first submission: %d %s", status, body)
	}
	opID := str(decodeMap(t, body), "op_id")
	before := first.waitForOpFinished(t, opID)
	if str(before, "state") != "succeeded" {
		t.Fatalf("first run did not succeed: %v", before)
	}
	ranBefore := len(first.captured.snapshot())
	if ranBefore == 0 {
		t.Fatal("the first run executed nothing; the test would prove nothing")
	}
	first.stop()

	second := startDurableRig(t, dir, "b.sock") // restart
	defer second.stop()
	holderID, release := holdLock(t, second)
	defer release()

	status, body = second.post(t, path, reqBody)
	if status != http.StatusOK {
		t.Fatalf("replay: got %d want 200 (not 202 new work, not 409 lock conflict); body=%s", status, body)
	}
	ack := decodeMap(t, body)
	if str(ack, "op_id") != opID || ack["deduped"] != true || str(ack, "state") != "succeeded" {
		t.Fatalf("replay ack: %s (want op_id=%s deduped succeeded)", body, opID)
	}
	if _, has := ack["failure_reason"]; has {
		t.Errorf("a succeeded replay carries failure_reason: %s", body)
	}

	status, body = second.get(t, "/v1/operations/"+opID)
	if status != http.StatusOK {
		t.Fatalf("GET after restart: %d %s", status, body)
	}
	after := decodeMap(t, body)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("operation record changed across the restart:\nbefore: %v\nafter:  %v", before, after)
	}

	// Only the lock holder's single command ran in the second agent.
	if cmds := second.captured.snapshot(); len(cmds) != 1 {
		t.Fatalf("replay executed commands: %d ran, want 1 (the holder's): %+v", len(cmds), cmds)
	}
	// And the holder still holds the lock.
	status, body = second.post(t, "/v1/backups", map[string]interface{}{"filename": "other.tar.gz"})
	if status != http.StatusConflict || str(decodeMap(t, body)["holder_op"].(map[string]interface{}), "op_id") != holderID { //nolint:errcheck // a wrong shape fails the assertion
		t.Fatalf("lock holder changed: %d %s", status, body)
	}
}

// TestDurableIdempotency_DifferentPayloadRefused: the same key with another
// payload is 422 idempotency_key_reused naming the original op — while that op
// is still running (in memory) and after a restart (from the record). Nothing
// runs either time.
func TestDurableIdempotency_DifferentPayloadRefused(t *testing.T) {
	dir := t.TempDir()
	first := startDurableRig(t, dir, "a.sock")
	gate := make(chan struct{})
	first.execGate.Store(&gate)
	status, body := first.post(t, "/v1/backups", map[string]interface{}{"filename": "a.tar.gz", "idempotency_key": "k"})
	if status != http.StatusAccepted {
		t.Fatalf("first: %d %s", status, body)
	}
	opID := str(decodeMap(t, body), "op_id")
	waitForCommands(t, first, 1)

	assertRefused := func(rig *d16bTestRig, when string, ranWant int) {
		t.Helper()
		st, b := rig.post(t, "/v1/backups", map[string]interface{}{"filename": "DIFFERENT.tar.gz", "idempotency_key": "k"})
		if st != http.StatusUnprocessableEntity {
			t.Fatalf("%s: got %d want 422; body=%s", when, st, b)
		}
		m := decodeMap(t, b)
		if str(m, "error") != "idempotency_key_reused" || str(m, "op_id") != opID || str(m, "kind") != ops.KindBackupCreate {
			t.Fatalf("%s: body %s", when, b)
		}
		if n := len(rig.captured.snapshot()); n != ranWant {
			t.Fatalf("%s: runner ran %d command(s), want %d", when, n, ranWant)
		}
	}
	assertRefused(first, "while the first op is running", 1)

	close(gate)
	first.waitForOpFinished(t, opID)
	first.stop()

	second := startDurableRig(t, dir, "b.sock")
	defer second.stop()
	assertRefused(second, "after a restart", 0)

	// The original payload is still answered with the original op.
	status, body = second.post(t, "/v1/backups", map[string]interface{}{"filename": "a.tar.gz", "idempotency_key": "k"})
	if status != http.StatusOK || str(decodeMap(t, body), "op_id") != opID {
		t.Fatalf("original payload: %d %s", status, body)
	}
}

// TestDurableIdempotency_InterruptedIsUnknownAndNotRerun: a keyed op that was
// mid-stage when its agent stopped. The next agent answers the same key with
// the ORIGINAL op_id, failed(agent_restart_interrupted), outcome unknown, and
// runs nothing. A new key runs.
func TestDurableIdempotency_InterruptedIsUnknownAndNotRerun(t *testing.T) {
	dir := t.TempDir()
	req := map[string]interface{}{"path": "/backup/x.enc", "mode": "full", "idempotency_key": "restore-1"}

	crashed := startDurableRig(t, dir, "a.sock")
	gate := make(chan struct{})
	crashed.execGate.Store(&gate)
	// The first agent is never stopped cleanly while the test asserts: its op
	// stays parked in its first command, as a killed agent's would.
	var opID string
	t.Cleanup(func() {
		close(gate)
		if opID != "" {
			crashed.waitForOpFinished(t, opID) // let it finish writing before TempDir is removed
		}
		crashed.stop()
	})
	status, body := crashed.post(t, "/v1/restores/commit", req)
	if status != http.StatusAccepted {
		t.Fatalf("first: %d %s", status, body)
	}
	opID = str(decodeMap(t, body), "op_id")
	waitForCommands(t, crashed, 1) // compose down is "running"

	next := startDurableRig(t, dir, "b.sock")
	defer next.stop()

	status, body = next.post(t, "/v1/restores/commit", req)
	if status != http.StatusOK {
		t.Fatalf("same-key retry: got %d want 200; body=%s", status, body)
	}
	ack := decodeMap(t, body)
	if str(ack, "op_id") != opID || ack["deduped"] != true || str(ack, "state") != "failed" {
		t.Fatalf("retry ack: %s", body)
	}
	if str(ack, "failure_reason") != string(ops.ReasonAgentRestartInterrupted) || str(ack, "outcome") != "unknown" {
		t.Fatalf("retry ack does not say interrupted/unknown: %s", body)
	}

	status, body = next.get(t, "/v1/operations/"+opID)
	if status != http.StatusOK {
		t.Fatalf("GET: %d %s", status, body)
	}
	op := decodeMap(t, body)
	result, _ := op["result"].(map[string]interface{}) //nolint:errcheck // asserted below
	if str(op, "state") != "failed" || str(op, "failure_reason") != "agent_restart_interrupted" || str(result, "outcome") != "unknown" {
		t.Fatalf("operation record: %s", body)
	}
	if str(op, "state") == "succeeded" {
		t.Fatal("an interrupted op was reported succeeded")
	}
	if n := len(next.captured.snapshot()); n != 0 {
		t.Fatalf("the interrupted restore was run again: %d command(s): %+v", n, next.captured.snapshot())
	}

	// Deliberate re-run under a new key.
	fresh := map[string]interface{}{"path": "/backup/x.enc", "mode": "full", "idempotency_key": "restore-2"}
	status, body = next.post(t, "/v1/restores/commit", fresh)
	if status != http.StatusAccepted {
		t.Fatalf("new key: %d %s", status, body)
	}
	freshID := str(decodeMap(t, body), "op_id")
	if freshID == opID {
		t.Fatal("new key returned the interrupted op")
	}
	next.waitForOpFinished(t, freshID)
	if len(next.captured.snapshot()) == 0 {
		t.Fatal("the new-key request did not run")
	}
}

// TestDurableIdempotency_UnkeyedUnaffected: without a key every submission is
// new work before and after a restart, and an un-keyed op is not recorded.
func TestDurableIdempotency_UnkeyedUnaffected(t *testing.T) {
	dir := t.TempDir()
	req := map[string]interface{}{"filename": "a.tar.gz"}
	first := startDurableRig(t, dir, "a.sock")
	status, body := first.post(t, "/v1/backups", req)
	if status != http.StatusAccepted {
		t.Fatalf("first: %d %s", status, body)
	}
	opID := str(decodeMap(t, body), "op_id")
	first.waitForOpFinished(t, opID)
	first.stop()

	if entries, err := os.ReadDir(filepath.Join(dir, "idempotency")); err != nil || len(entries) != 0 {
		t.Fatalf("an un-keyed op left a durable record: %v (err=%v)", entries, err)
	}

	second := startDurableRig(t, dir, "b.sock")
	defer second.stop()
	status, body = second.post(t, "/v1/backups", req)
	if status != http.StatusAccepted || decodeMap(t, body)["deduped"] != false {
		t.Fatalf("un-keyed after restart: %d %s", status, body)
	}
	newID := str(decodeMap(t, body), "op_id")
	if newID == opID {
		t.Fatal("un-keyed submission returned the earlier op")
	}
	second.waitForOpFinished(t, newID)
	if len(second.captured.snapshot()) != 1 {
		t.Fatalf("un-keyed submission did not run exactly once: %d", len(second.captured.snapshot()))
	}
	// Documented limit: an un-keyed op is memory-only, so it is unknown here.
	if status, _ = second.get(t, "/v1/operations/"+opID); status != http.StatusNotFound {
		t.Errorf("un-keyed op from before the restart: got %d want 404", status)
	}
}

// TestDurableIdempotency_DifferentKindIsIndependent: the key is scoped per
// kind, as the in-memory cache always was. The same key under another kind is
// a separate request and is admitted.
func TestDurableIdempotency_DifferentKindIsIndependent(t *testing.T) {
	dir := t.TempDir()
	first := startDurableRig(t, dir, "a.sock")
	status, body := first.post(t, "/v1/restores/dryrun", map[string]interface{}{"path": "/backup/x.enc", "mode": "full", "idempotency_key": "k"})
	if status != http.StatusAccepted {
		t.Fatalf("dryrun: %d %s", status, body)
	}
	dryID := str(decodeMap(t, body), "op_id")
	first.waitForOpFinished(t, dryID)
	first.stop()

	second := startDurableRig(t, dir, "b.sock")
	defer second.stop()
	status, body = second.post(t, "/v1/restores/commit", map[string]interface{}{"path": "/backup/x.enc", "mode": "full", "idempotency_key": "k"})
	if status != http.StatusAccepted {
		t.Fatalf("commit under the dry-run's key: got %d want 202; body=%s", status, body)
	}
	commitID := str(decodeMap(t, body), "op_id")
	if commitID == dryID {
		t.Fatal("restore.commit was deduped onto the restore.dryrun op")
	}
	second.waitForOpFinished(t, commitID)
	// The dry-run's own key still replays the dry-run.
	status, body = second.post(t, "/v1/restores/dryrun", map[string]interface{}{"path": "/backup/x.enc", "mode": "full", "idempotency_key": "k"})
	if status != http.StatusOK || str(decodeMap(t, body), "op_id") != dryID {
		t.Fatalf("dryrun replay: %d %s", status, body)
	}
}

// TestDurableIdempotency_DifferentActorIsIndependent: a record another peer
// left under the same kind and key does not answer for this peer.
func TestDurableIdempotency_DifferentActorIsIndependent(t *testing.T) {
	dir := t.TempDir()
	const otherActor = "uid=4242,user=someone-else"
	params := map[string]interface{}{"filename": "a.tar.gz", "encrypt": false, "passphrase_ref": ""}
	fp, err := idem.Fingerprint(ops.KindBackupCreate, params)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := idem.Open(dir, idem.Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rec := idem.Record{
		Actor: otherActor, Kind: ops.KindBackupCreate, IdempotencyKey: "shared-key", Fingerprint: fp,
		OpID: ops.NewID(), AdmittedAt: now, Params: params,
	}
	if err := seed.Admit(rec); err != nil {
		t.Fatal(err)
	}
	rec.State, rec.FinishedAt = idem.StateSucceeded, &now
	if err := seed.Complete(rec); err != nil {
		t.Fatal(err)
	}

	rig := startDurableRig(t, dir, "a.sock")
	defer rig.stop()
	self := auth.PeerInfo{UID: uint32(os.Geteuid())}.String() //nolint:gosec // a uid fits
	if self == otherActor || strconv.Itoa(os.Geteuid()) == "4242" {
		t.Skip("test peer collides with the seeded actor")
	}
	status, body := rig.post(t, "/v1/backups", map[string]interface{}{"filename": "a.tar.gz", "idempotency_key": "shared-key"})
	if status != http.StatusAccepted {
		t.Fatalf("got %d want 202 (another actor's record must not answer); body=%s", status, body)
	}
	ack := decodeMap(t, body)
	if str(ack, "op_id") == rec.OpID || ack["deduped"] != false {
		t.Fatalf("this peer was answered with another actor's op: %s", body)
	}
	rig.waitForOpFinished(t, str(ack, "op_id"))
	// The other actor's op is still readable by id (GET is not actor-scoped,
	// as before), and unchanged.
	if status, _ = rig.get(t, "/v1/operations/"+rec.OpID); status != http.StatusOK {
		t.Errorf("GET of the seeded op: %d", status)
	}
}

// TestDurableIdempotency_StoreUnavailable: keyed requests are refused with 503
// and run nothing; un-keyed requests are served.
func TestDurableIdempotency_StoreUnavailable(t *testing.T) {
	mgr := ops.NewManager(nil)
	mgr.SetIdempotencyStore(idem.Unavailable(errors.New("state_dir unreadable")))
	rig := startD16bRigIn(t, t.TempDir(), "a.sock", mgr)
	defer rig.stop()

	status, body := rig.post(t, "/v1/backups", map[string]interface{}{"filename": "a.tar.gz", "idempotency_key": "k"})
	if status != http.StatusServiceUnavailable || str(decodeMap(t, body), "error") != "idempotency_store_unavailable" {
		t.Fatalf("keyed: %d %s", status, body)
	}
	if _, has := decodeMap(t, body)["op_id"]; has {
		t.Errorf("a refused admission reports an op_id: %s", body)
	}
	if n := len(rig.captured.snapshot()); n != 0 {
		t.Fatalf("a refused keyed request ran %d command(s)", n)
	}
	status, body = rig.post(t, "/v1/backups", map[string]interface{}{"filename": "a.tar.gz"})
	if status != http.StatusAccepted {
		t.Fatalf("un-keyed: %d %s", status, body)
	}
	rig.waitForOpFinished(t, str(decodeMap(t, body), "op_id"))
}

// TestDurableIdempotency_UnreadableRecordRefusesItsKey: 409
// idempotency_record_unreadable, outcome unknown, nothing run.
func TestDurableIdempotency_UnreadableRecordRefusesItsKey(t *testing.T) {
	dir := t.TempDir()
	first := startDurableRig(t, dir, "a.sock")
	req := map[string]interface{}{"filename": "a.tar.gz", "idempotency_key": "k"}
	status, body := first.post(t, "/v1/backups", req)
	if status != http.StatusAccepted {
		t.Fatalf("first: %d %s", status, body)
	}
	first.waitForOpFinished(t, str(decodeMap(t, body), "op_id"))
	first.stop()

	entries, err := os.ReadDir(filepath.Join(dir, "idempotency"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "idempotency", entries[0].Name()), []byte("{torn"), 0o600); err != nil {
		t.Fatal(err)
	}

	second := startDurableRig(t, dir, "b.sock")
	defer second.stop()
	status, body = second.post(t, "/v1/backups", req)
	m := decodeMap(t, body)
	if status != http.StatusConflict || str(m, "error") != "idempotency_record_unreadable" || str(m, "outcome") != "unknown" {
		t.Fatalf("got %d %s", status, body)
	}
	if n := len(second.captured.snapshot()); n != 0 {
		t.Fatalf("the request behind an unreadable record ran again: %d command(s)", n)
	}
	// Another key is served.
	status, body = second.post(t, "/v1/backups", map[string]interface{}{"filename": "a.tar.gz", "idempotency_key": "k2"})
	if status != http.StatusAccepted {
		t.Fatalf("other key: %d %s", status, body)
	}
	second.waitForOpFinished(t, str(decodeMap(t, body), "op_id"))
}

// TestDurableIdempotency_ReplayNeedsNoReadOnlySlot: with every read-only
// execution slot taken, a recorded read-only result is still served (200, not
// 429) and its stages are never built.
func TestDurableIdempotency_ReplayNeedsNoReadOnlySlot(t *testing.T) {
	srv := newAdmissionTestServer(t, 1)
	peer := auth.PeerInfo{UID: 1000, Username: "test-cp"}
	dir := srv.opts.StateDir
	attach := func() {
		mgr := ops.NewManager(nil)
		store, err := idem.Open(dir, idem.Options{Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		mgr.SetIdempotencyStore(store)
		srv.opts.Ops = mgr
	}
	attach()
	op, deduped, herr := srv.startAsyncOp(nil, peer, ops.KindBackupList, "list-1", nil, quickStages)
	if herr != nil || deduped {
		t.Fatalf("first: deduped=%v err=%+v", deduped, herr)
	}
	srv.opWG.Wait()

	attach() // restart: new manager, reopened store
	release := make(chan struct{})
	if _, _, e := srv.startAsyncOp(nil, peer, ops.KindBackupList, "", nil, blockingStages(release)); e != nil {
		t.Fatalf("saturating op: %+v", e)
	}
	defer func() { close(release); srv.opWG.Wait() }()

	// Control: the slot really is exhausted for new work.
	if _, _, e := srv.startAsyncOp(nil, peer, ops.KindBackupList, "list-2", nil, quickStages); e == nil || e.Status != http.StatusTooManyRequests {
		t.Fatalf("control: new read-only work at capacity must be 429, got %+v", e)
	}
	got, deduped, herr := srv.startAsyncOp(nil, peer, ops.KindBackupList, "list-1", nil, func() ([]ops.FlowStage, *opError) {
		t.Error("stages were built for a replay")
		return nil, nil
	})
	if herr != nil {
		t.Fatalf("replay at capacity: %+v", herr)
	}
	if !deduped || got.ID != op.ID || got.State != ops.StateSucceeded {
		t.Fatalf("replay: deduped=%v op=%+v", deduped, got)
	}
}
