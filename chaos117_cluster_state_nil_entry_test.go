package main

// chaos117_cluster_state_nil_entry_test.go — CHAOS-117.
//
// A persisted cluster.json whose node or token MAP contains a JSON `null`
// VALUE used to be a crash loop:
//
//	{"nodes":{"dp-1":null}}
//
// is valid JSON, so CHAOS-07's quarantine — which fires on a PARSE failure —
// never saw it; ClusterStore.Load normalised nil MAPS but not nil map VALUES,
// published the state, and every consumer that dereferences an *EnrolledNode /
// *EnrollToken out of those maps then nil-dereferenced. The worst consumer is
// StartHeartbeatMonitor's DETACHED 30 s ticker, started on control-plane
// activation: Go terminates the process on an unrecovered panic in any
// goroutine, the poison is on disk, so the gateway died 30 s after every
// restart — and ImportFullState had the same one-level-too-shallow defence and
// PERSISTED what it imported, so an HA leader propagated it fleet-wide.
//
// These tests pin all three halves of the fix:
//  1. normalisation at BOTH ingestion boundaries, dropping the unusable
//     records while keeping every healthy one and the whole revoked-cert list;
//  2. per-ITERATION panic containment on the heartbeat ticker, WITH deferred
//     release of cs.mu — a contained panic that leaked the lock would turn a
//     loud crash into a permanent silent stall, which is strictly worse;
//  3. operator visibility: counter, log, diagnostics row, one alert.

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── 1. the defect: a null record must not reach a consumer ──────────────────

// TestCHAOS117_NullNodeRecordIsDroppedNotPublished is the direct regression.
// Pre-fix, Load accepted the document and checkHeartbeats panicked at
// enrollment.go:676 (checkNodeLiveness dereferencing node.Status).
func TestCHAOS117_NullNodeRecordIsDroppedNotPublished(t *testing.T) {
	isolateStateCorruption(t)
	_ = captureStartupAlerts(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	// One healthy node, one null node, one revoked cert: the healthy state
	// must survive the repair, because the alternative fix — quarantining the
	// whole file — would discard it.
	doc := `{
	  "nodes": {
	    "dp-healthy": {"node_id":"dp-healthy","status":"connected","cert_serial":"AA"},
	    "dp-null": null
	  },
	  "tokens": {},
	  "revoked": [{"node_id":"dp-gone","cert_serial":"BB","reason":"stolen"}]
	}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	cs := &ClusterStore{}
	if err := cs.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// No consumer may observe the null record.
	if _, ok := cs.GetNode("dp-null"); ok {
		t.Error("the null node record is still in the published map — every consumer that dereferences it nil-panics")
	}
	if _, ok := cs.GetNode("dp-healthy"); !ok {
		t.Error("the HEALTHY node was lost: repairing one bad record must not discard good roster state")
	}
	// The security-relevant half must be intact: a dropped revocation means a
	// revoked DP certificate validates again (the CHAOS-07 lesson).
	cs.mu.RLock()
	revoked := len(cs.st.Revoked)
	cs.mu.RUnlock()
	if revoked != 1 {
		t.Errorf("revoked-cert list has %d entries, want 1 — a repair must never drop revocation evidence", revoked)
	}

	// The two consumers that killed the process / the admin plane pre-fix.
	cs.checkHeartbeats()
	if got := cs.ListNodes(); len(got) != 1 {
		t.Errorf("ListNodes returned %d nodes, want 1", len(got))
	}
	if total, connected := cs.NodeCounts(); total != 1 || connected != 1 {
		t.Errorf("NodeCounts = (%d, %d), want (1, 1)", total, connected)
	}
}

// TestCHAOS117_NullTokenRecordIsDroppedNotPublished covers the second map.
// Pre-fix this panicked in tokenExpired (enrollment.go:706) via
// gcExpiredTokens, on the same detached ticker.
func TestCHAOS117_NullTokenRecordIsDroppedNotPublished(t *testing.T) {
	isolateStateCorruption(t)
	_ = captureStartupAlerts(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	doc := `{"nodes":{},"tokens":{"` + strings.Repeat("a", 64) + `":null}}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	cs := &ClusterStore{}
	if err := cs.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cs.ListTokens(); len(got) != 0 {
		t.Errorf("ListTokens returned %d tokens, want 0 — a null token record was published", len(got))
	}
	cs.checkHeartbeats() // gcExpiredTokens ran over the token map
}

// TestCHAOS117_NullTokenHashNeverReachesTheLog pins the CL-9 secret-handling
// contract on the new diagnostic: a token map key is the SHA-256 hash of a
// live enrollment token, so the repair reports a COUNT. Node IDs are
// operator-facing and ARE named; hashes are not.
func TestCHAOS117_NullTokenHashNeverReachesTheLog(t *testing.T) {
	hash := strings.Repeat("d", 64)
	var st ClusterState
	if err := json.Unmarshal([]byte(`{"tokens":{"`+hash+`":null}}`), &st); err != nil {
		t.Fatal(err)
	}
	repair := normalizeClusterState(&st)
	if repair.NilTokens != 1 {
		t.Fatalf("NilTokens = %d, want 1", repair.NilTokens)
	}
	for _, id := range repair.NilNodes {
		if id == hash {
			t.Fatal("a token hash leaked into the node-ID list that the log line prints")
		}
	}
}

// TestCHAOS117_ReplicatedNullRecordIsNotAdoptedOrPersisted is the propagation
// leg. Pre-fix a standby adopted the leader's null record AND wrote it to its
// own cluster.json, so one damaged document became a fleet-wide crash loop
// that outlived the leader that produced it.
func TestCHAOS117_ReplicatedNullRecordIsNotAdoptedOrPersisted(t *testing.T) {
	isolateStateCorruption(t)
	_ = captureStartupAlerts(t)
	resetReplicatedNilEntryAlertOnce(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	cs := &ClusterStore{path: path}

	bundle := json.RawMessage(`{"nodes":{"dp-good":{"node_id":"dp-good","status":"connected"},"dp-null":null}}`)
	if err := cs.ImportFullState(bundle); err != nil {
		t.Fatalf("ImportFullState: %v", err)
	}
	if _, ok := cs.GetNode("dp-null"); ok {
		t.Error("the standby adopted a null record from the leader")
	}
	if _, ok := cs.GetNode("dp-good"); !ok {
		t.Error("the standby dropped a HEALTHY replicated node")
	}

	// The poison must not be on this node's disk: that is what made it
	// survive restarts and turned a leader fault into a local crash loop.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted state: %v", err)
	}
	var persisted ClusterState
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("persisted state does not parse: %v", err)
	}
	for id, node := range persisted.Nodes {
		if node == nil {
			t.Errorf("persisted cluster.json still carries a null record for %q — the next boot reloads the crash loop", id)
		}
	}

	// And the imported state is usable on the paths that panicked pre-fix.
	cs.checkHeartbeats()
	if total, _ := cs.NodeCounts(); total != 1 {
		t.Errorf("NodeCounts total = %d, want 1", total)
	}
}

// ── 2. containment: the ticker, and the lock it holds ───────────────────────

// TestCHAOS117_HeartbeatRoundPanicDoesNotWedgeTheStore is the 8.2a pairing
// gate. Adding a panic guard WITHOUT converting checkHeartbeats' trailing
// cs.mu.Unlock() to a defer would contain the panic into a PERMANENTLY held
// ClusterStore lock: every enrollment, heartbeat and admin cluster read blocks
// forever — no crash, no restart, no alert. This test fails by TIMING OUT in
// that world, which is the correct report for a silent stall.
func TestCHAOS117_HeartbeatRoundPanicDoesNotWedgeTheStore(t *testing.T) {
	cs := &ClusterStore{st: ClusterState{
		Nodes:  map[string]*EnrolledNode{},
		Tokens: map[string]*EnrollToken{},
	}}

	// Force a panic inside the round while cs.mu is held, the same way the
	// defect did: a nil record reached past normalisation (here injected
	// directly, since normalisation now prevents it arriving by parse).
	cs.mu.Lock()
	cs.st.Nodes["poison"] = nil
	cs.mu.Unlock()

	if panicked := runGuarded(crashComponentClusterHeartbeat, cs.checkHeartbeats); !panicked {
		t.Fatal("the round did not panic — this test no longer exercises containment; re-derive the poison")
	}

	// The lock must be free. A direct Lock() would hang the test binary with
	// no diagnosis, so probe it with a deadline and report the stall.
	done := make(chan struct{})
	go func() {
		cs.mu.Lock()
		defer cs.mu.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("cs.mu is still held after a contained panic: the guard converted a crash into a permanent silent stall of enrollment, heartbeats and every admin cluster read")
	}

	// And the store is still usable, not just unlocked.
	cs.RegisterNode(&EnrolledNode{NodeID: "dp-after", Status: "connected"})
	if _, ok := cs.GetNode("dp-after"); !ok {
		t.Error("the ClusterStore is unlocked but no longer accepts enrollments after a contained panic")
	}
}

// TestCHAOS117_HeartbeatMonitorSurvivesAPanickingRound pins that containment
// is per-ITERATION: the monitor must keep evaluating node liveness after a
// bad round. A goroutine-level recover would make the loop RETURN, so node
// liveness would silently never be evaluated again with the process up and
// every dashboard green — the inversion internal/obs/guard.go warns about.
func TestCHAOS117_HeartbeatMonitorSurvivesAPanickingRound(t *testing.T) {
	body := funcSource(t, "enrollment.go", "StartHeartbeatMonitor")
	if strings.Contains(body, "defer func()") || strings.Contains(body, "recover()") {
		t.Error("StartHeartbeatMonitor recovers at the GOROUTINE level: the loop would exit on the first panic and node liveness would never be evaluated again")
	}
	if !strings.Contains(body, "runGuarded(crashComponentClusterHeartbeat") {
		t.Fatal("the heartbeat round is not guarded: an unrecovered panic in this detached goroutine terminates the gateway")
	}

	// Behavioural half: two rounds, the first poisoned, and the second must
	// still run and still mark a stale node disconnected.
	cs := &ClusterStore{st: ClusterState{
		Nodes:  map[string]*EnrolledNode{"poison": nil},
		Tokens: map[string]*EnrollToken{},
	}}
	if panicked := runGuarded(crashComponentClusterHeartbeat, cs.checkHeartbeats); !panicked {
		t.Fatal("round 1 did not panic; re-derive the poison")
	}
	cs.mu.Lock()
	delete(cs.st.Nodes, "poison")
	cs.st.Nodes["dp-stale"] = &EnrolledNode{
		NodeID:   "dp-stale",
		Status:   "connected",
		LastSeen: time.Now().Add(-10 * heartbeatTimeout),
	}
	cs.mu.Unlock()
	if panicked := runGuarded(crashComponentClusterHeartbeat, cs.checkHeartbeats); panicked {
		t.Fatal("round 2 panicked")
	}
	n, ok := cs.GetNode("dp-stale")
	if !ok {
		t.Fatal("dp-stale vanished")
	}
	if n.Status != "disconnected" {
		t.Errorf("after a contained panic the monitor stopped doing its job: dp-stale status = %q, want %q", n.Status, "disconnected")
	}
}

// TestCHAOS117_ClusterStoreLockReleasesAreDeferred is the source-level half of
// 8.2a, stated as a rule rather than a single case: a lock taken in a function
// that now runs under a panic guard must be released by defer. A trailing
// Unlock is correct only while a panic is fatal.
func TestCHAOS117_ClusterStoreLockReleasesAreDeferred(t *testing.T) {
	for _, fn := range []string{"checkHeartbeats", "ImportFullState"} {
		body := funcSource(t, "enrollment.go", fn)
		if !strings.Contains(body, "defer cs.mu.Unlock()") {
			t.Errorf("%s does not defer its Unlock: a contained panic would leave the ClusterStore locked forever, which is a silent stall rather than a crash", fn)
		}
		for _, line := range strings.Split(body, "\n") {
			if strings.TrimSpace(line) == "cs.mu.Unlock()" {
				t.Errorf("%s still has a bare trailing cs.mu.Unlock(): %q", fn, strings.TrimSpace(line))
			}
		}
	}
}

// ── 3. the invariant, enforced at every ingestion boundary ──────────────────

// TestCHAOS117_EveryIngestionBoundaryNormalises is the anti-regression gate
// for the CLASS, not the instance. This nil-value class survived two prior
// fixes of the nil-MAP class precisely because each boundary hand-rolled its
// own normalisation and the second was never updated. Any future decoder of a
// ClusterState must route through the one helper.
func TestCHAOS117_EveryIngestionBoundaryNormalises(t *testing.T) {
	// Anchored to pkgSourceDir(), not the CWD: a concurrent os.Chdir in
	// another test would otherwise flake this (static_read_wall_test.go).
	path := filepath.Join(pkgSourceDir(), "enrollment.go")
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse enrollment.go: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)

	var offenders []string
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		body := src[fset.Position(fn.Body.Lbrace).Offset:fset.Position(fn.Body.Rbrace).Offset]
		// A function that decodes JSON into a ClusterState is an ingestion
		// boundary; normalizeClusterState itself is the normaliser.
		if fn.Name.Name == "normalizeClusterState" {
			continue
		}
		if !strings.Contains(body, "var st ClusterState") && !strings.Contains(body, "st ClusterState") {
			continue
		}
		if !strings.Contains(body, "json.Unmarshal") {
			continue
		}
		if !strings.Contains(body, "normalizeClusterState(") {
			offenders = append(offenders, fn.Name.Name)
		}
	}
	if len(offenders) > 0 {
		t.Errorf("these functions decode a ClusterState without normalising it: %v — a nil map VALUE from any of them nil-panics the detached heartbeat ticker, which is process-fatal and persists across restarts",
			offenders)
	}
}

// ── 4. operator visibility ──────────────────────────────────────────────────

// TestCHAOS117_DroppedRecordsAreVisibleToAnOperator pins the whole reporting
// path. Silently dropping an enrolled node is itself an operational surprise:
// the node's next heartbeat is refused and nothing says why.
func TestCHAOS117_DroppedRecordsAreVisibleToAnOperator(t *testing.T) {
	isolateStateCorruption(t)
	captured := captureStartupAlerts(t)

	before := statClusterStateNilEntriesDropped.Load()

	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	doc := `{"nodes":{"dp-a":null,"dp-b":null},"tokens":{}}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cs := &ClusterStore{}
	if err := cs.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Counter.
	if got := statClusterStateNilEntriesDropped.Load() - before; got != 2 {
		t.Errorf("culvert_cluster_state_nil_entries_dropped_total rose by %d, want 2", got)
	}

	// The file must NOT have been quarantined: it parsed, and the records it
	// still holds are in effect. Moving it aside would discard good state.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the state file was moved or removed: %v — a parseable file with one bad record must stay where it is", err)
	}
	if q := quarantinedFiles(t, path); len(q) != 0 {
		t.Errorf("the state file was quarantined (%v); CHAOS-07 quarantine is for a file that cannot be PARSED", q)
	}

	// Authenticated diagnostics row, viewer-safe (no path).
	rows := checkStateFileIntegrity()
	var row *OperatorContractCheck
	for i := range rows {
		if rows[i].Code == "state_file_cluster" {
			row = &rows[i]
		}
	}
	if row == nil {
		t.Fatalf("no state_file_cluster diagnostics row: an operator has no way to learn that nodes vanished from the roster (rows: %+v)", rows)
	}
	if row.Status != diagWarn {
		t.Errorf("row status = %q, want %q", row.Status, diagWarn)
	}
	if !strings.Contains(row.Message, "2") {
		t.Errorf("row does not report how many records were dropped: %q", row.Message)
	}
	if strings.Contains(row.Message, dir) || strings.Contains(row.OperatorAction, dir) ||
		strings.Contains(row.Message, "cluster.json") {
		t.Errorf("the viewer-role diagnostics row leaked a filesystem path: %q / %q", row.Message, row.OperatorAction)
	}

	// The /ready probe must be UNCHANGED: this degradation is survivable
	// (re-enrol), and holding a fleet out of service for it is worse.
	if got := stateCorruptionSnapshot(); len(got) != 0 {
		t.Errorf("the dropped-record repair gated /ready (%v); only an unparseable file does that", got)
	}

	// Exactly one alert, carrying the fact.
	flushStartupAlerts()
	if len(*captured) != 1 {
		t.Fatalf("flush delivered %d alerts, want 1", len(*captured))
	}
	if a := (*captured)[0]; a.event != "state_file_corrupt" || a.payload.Source != "storage" {
		t.Fatalf("unexpected alert %q source %q", a.event, a.payload.Source)
	}
}

// TestCHAOS117_DroppedRecordRowNeverMasksAWorseOne: the dropped-record record
// is the LEAST severe of this plane. A quarantine failure recorded for the
// same kind this boot names a file still in the save path's line of fire and a
// different, more urgent operator action; it must survive.
func TestCHAOS117_DroppedRecordRowNeverMasksAWorseOne(t *testing.T) {
	isolateStateCorruption(t)
	_ = captureStartupAlerts(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	if err := os.WriteFile(path, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	quarantineCorruptStateFile("cluster", path, errUnparseableForTest)
	noteStateFileEntriesDropped("cluster", path, 3)

	rec := stateCorruptionRecordsSnapshot()["cluster"]
	if rec.DroppedEntries != 0 {
		t.Errorf("the dropped-record note overwrote the quarantine record: %+v", rec)
	}
	if rec.ParseErr == "" {
		t.Errorf("the quarantine record's cause was lost: %+v", rec)
	}
}

// TestCHAOS117_NoDroppedRecordsIsSilent: a healthy load must contribute
// nothing — no counter movement, no row, no alert. An always-on row is an
// alert nobody reads.
func TestCHAOS117_NoDroppedRecordsIsSilent(t *testing.T) {
	isolateStateCorruption(t)
	captured := captureStartupAlerts(t)
	before := statClusterStateNilEntriesDropped.Load()

	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	if err := os.WriteFile(path, []byte(`{"nodes":{"dp-a":{"node_id":"dp-a"}},"tokens":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cs := &ClusterStore{}
	if err := cs.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := statClusterStateNilEntriesDropped.Load(); got != before {
		t.Errorf("counter moved on a healthy load: %d → %d", before, got)
	}
	if rows := checkStateFileIntegrity(); len(rows) != 0 {
		t.Errorf("a healthy load produced diagnostics rows: %+v", rows)
	}
	flushStartupAlerts()
	if len(*captured) != 0 {
		t.Errorf("a healthy load fired %d alerts, want 0", len(*captured))
	}
}

// TestCHAOS117_ReplicatedRepairAlertsAtMostOncePerProcess: a standby resyncs
// on a timer, so a persistently damaged leader would page on every round. The
// counter and the log line carry every occurrence; the alert carries the fact.
func TestCHAOS117_ReplicatedRepairAlertsAtMostOncePerProcess(t *testing.T) {
	isolateStateCorruption(t)
	captured := captureStartupAlerts(t)
	resetReplicatedNilEntryAlertOnce(t)

	dir := t.TempDir()
	cs := &ClusterStore{path: filepath.Join(dir, "cluster.json")}
	bundle := json.RawMessage(`{"nodes":{"dp-null":null}}`)
	for i := 0; i < 5; i++ {
		if err := cs.ImportFullState(bundle); err != nil {
			t.Fatalf("resync %d: %v", i, err)
		}
	}
	flushStartupAlerts()
	if len(*captured) != 1 {
		t.Errorf("5 resync rounds fired %d alerts, want 1 — a damaged leader must not page per round", len(*captured))
	}
	if got := statClusterStateNilEntriesDropped.Load(); got < 5 {
		t.Errorf("the counter does not record every occurrence (%d after 5 rounds)", got)
	}
}

// resetReplicatedNilEntryAlertOnce isolates the process-global once latch so
// these tests do not depend on execution order (-shuffle=on).
func resetReplicatedNilEntryAlertOnce(t *testing.T) {
	t.Helper()
	replicatedNilEntryAlertOnce = sync.Once{}
	t.Cleanup(func() { replicatedNilEntryAlertOnce = sync.Once{} })
}

// errUnparseableForTest stands in for a real json parse error in the
// severity-ordering test above.
var errUnparseableForTest = &json.SyntaxError{}
