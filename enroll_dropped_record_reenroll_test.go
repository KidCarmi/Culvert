package main

// CHAOS-117 follow-up — re-enrollment over a DROPPED node record.
//
// CHAOS-117 stopped a null node record from crash-looping the control plane by
// DROPPING it. That trade has a second half the normalisation comment first
// called a pure "availability cost": the dropped record was the only thing on
// the CP that named the node's certificate serial, and admitEnrollment's
// duplicate-identity denial keys on the record EXISTING
// (`GetNode(...)` → ok), so after a drop:
//
//   - the same node ID is re-enrollable on a fresh token with NO prior record,
//   - the predecessor's serial can never be added to the CRL (it is gone), so
//     the legitimate holder's certificate stays valid until it expires,
//   - and none of that was audited, alerted or logged — the identity swap was
//     indistinguishable from a first enrollment.
//
// The admit DECISION is correct and deliberately unchanged here: an
// admin-issued single-use token is still required, and a token holder can
// already enroll a new node. What was missing is the evidence trail for the
// replacement, which is what these tests pin.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// loadStateWithNullNode installs a fresh enroll fixture whose cluster.json
// carries a null record for nodeID, i.e. the post-CHAOS-117 state: the record
// is dropped, the CP is up, and the serial is unrecoverable.
func loadStateWithNullNode(t *testing.T, nodeID string) {
	t.Helper()
	swapEnrollFixture(t)
	path := filepath.Join(t.TempDir(), "cluster.json")
	if err := os.WriteFile(path, []byte(`{"nodes":{"`+nodeID+`":null}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := globalClusterStore.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := globalClusterStore.GetNode(nodeID); ok {
		t.Fatalf("precondition: %q must have been dropped, not published", nodeID)
	}
	if !globalClusterStore.NodeRecordWasDropped(nodeID) {
		t.Fatalf("precondition: the drop of %q must be remembered", nodeID)
	}
}

func auditHasDroppedReenroll(t *testing.T, since int64, nodeID string) (AuditEntry, bool) {
	t.Helper()
	entries := auditGet()
	for i := range entries { // by index: AuditEntry is large enough that a copy per iteration trips gocritic
		if e := &entries[i]; e.TS >= since && e.Action == "cluster.node.reenroll-dropped" && e.Object == nodeID {
			return *e, true
		}
	}
	return AuditEntry{}, false
}

// ── 1. the replacement is audited, alerted and logged ───────────────────────

func TestEnroll_DroppedRecordReenrollmentIsAuditedAndAlerted(t *testing.T) {
	loadStateWithNullNode(t, "dp-dropped")
	alerts := enrollAlertCapture(t)

	token, err := globalClusterStore.GenerateToken("", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	baseline := time.Now().UnixMilli()
	srv := &controlPlaneServer{}
	resp, err := srv.Enroll(context.Background(), enrollRequestJSON(t, token, "dp-dropped"))
	if err != nil {
		t.Fatalf("enrollment with a valid token must still succeed (the decision is unchanged): %v", err)
	}
	var er EnrollResponse
	if err := json.Unmarshal(resp, &er); err != nil || er.CertPEM == "" {
		t.Fatalf("enrollment response missing cert: err=%v resp=%s", err, resp)
	}

	entry, ok := auditHasDroppedReenroll(t, baseline, "dp-dropped")
	if !ok {
		t.Fatal("no cluster.node.reenroll-dropped audit entry — an identity replacement " +
			"over a dropped record is indistinguishable from a first enrollment")
	}
	// The entry must say the predecessor could NOT be revoked; that is the
	// part an operator cannot infer and cannot fix after the fact.
	if !strings.Contains(entry.Detail, "CRL") {
		t.Errorf("audit detail must state that the predecessor serial could not reach the CRL, got %q", entry.Detail)
	}

	if len(*alerts) != 1 || (*alerts)[0].Event != "cluster_node_reenrolled" ||
		(*alerts)[0].Host != "dp-dropped" || (*alerts)[0].Source != "cluster" {
		t.Fatalf("want one cluster_node_reenrolled alert for dp-dropped, got %+v", *alerts)
	}
}

// ── 2. negative control: an ordinary first enrollment is not flagged ──────────

func TestEnroll_FirstEnrollmentIsNotFlaggedAsDroppedReenrollment(t *testing.T) {
	swapEnrollFixture(t)
	alerts := enrollAlertCapture(t)

	token, err := globalClusterStore.GenerateToken("", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	baseline := time.Now().UnixMilli()
	srv := &controlPlaneServer{}
	if _, err := srv.Enroll(context.Background(), enrollRequestJSON(t, token, "dp-brand-new")); err != nil {
		t.Fatalf("first enrollment must succeed: %v", err)
	}

	if _, ok := auditHasDroppedReenroll(t, baseline, "dp-brand-new"); ok {
		t.Error("a node ID that was never dropped must not be audited as a replacement " +
			"(false positives would make the real signal unreadable)")
	}
	if len(*alerts) != 0 {
		t.Errorf("a first enrollment must raise no re-enrollment alert, got %+v", *alerts)
	}
}

// ── 3. the evidence cannot be driven without a valid token ──────────────────

// An audit entry and an alert are an operator-visible signal, so an
// unauthenticated prober must not be able to emit either by guessing the node
// ID of a dropped record. The recording sits AFTER ValidateAndConsumeToken for
// exactly this reason.
func TestEnroll_DroppedRecordEvidenceRequiresAValidToken(t *testing.T) {
	loadStateWithNullNode(t, "dp-dropped")
	alerts := enrollAlertCapture(t)

	baseline := time.Now().UnixMilli()
	srv := &controlPlaneServer{}
	if _, err := srv.Enroll(context.Background(), enrollRequestJSON(t, "not-a-real-token", "dp-dropped")); err == nil {
		t.Fatal("enrollment with an invalid token must be denied")
	}

	if _, ok := auditHasDroppedReenroll(t, baseline, "dp-dropped"); ok {
		t.Error("a rejected enrollment must not write the replacement audit entry — " +
			"an unauthenticated prober could otherwise forge the signal at will")
	}
	if len(*alerts) != 0 {
		t.Errorf("a rejected enrollment must raise no alert, got %+v", *alerts)
	}
	if _, ok := globalClusterStore.GetNode("dp-dropped"); ok {
		t.Error("a rejected enrollment must not register the node")
	}
}

// ── 3b. ... nor by an enrollment that fails after the token is spent ─────────

// A valid token reaches past admission, but the request can still fail at CSR
// validation, before anything is signed or registered. The audit entry and the
// alert say an identity replacement COMPLETED, so a failed enrollment must not
// emit either (Codex review on PR #1879).
func TestEnroll_DroppedRecordEvidenceRequiresASuccessfulEnrollment(t *testing.T) {
	loadStateWithNullNode(t, "dp-dropped")
	alerts := enrollAlertCapture(t)

	token, err := globalClusterStore.GenerateToken("", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	raw, err := json.Marshal(EnrollRequest{Token: token, NodeID: "dp-dropped", CSR: "not a PEM"})
	if err != nil {
		t.Fatal(err)
	}

	baseline := time.Now().UnixMilli()
	srv := &controlPlaneServer{}
	if _, err := srv.Enroll(context.Background(), raw); err == nil {
		t.Fatal("enrollment with a malformed CSR must be refused")
	}

	if _, ok := auditHasDroppedReenroll(t, baseline, "dp-dropped"); ok {
		t.Error("a failed enrollment must not write the replacement audit entry")
	}
	if len(*alerts) != 0 {
		t.Errorf("a failed enrollment must raise no alert, got %+v", *alerts)
	}
	if _, ok := globalClusterStore.GetNode("dp-dropped"); ok {
		t.Error("a failed enrollment must not register the node")
	}
}

// ── 4. both ingestion boundaries record, and only what they dropped ─────────

func TestClusterStore_DroppedNodeIDsRecordedAtBothIngestionBoundaries(t *testing.T) {
	isolateStateCorruption(t)
	_ = captureStartupAlerts(t)
	resetReplicatedNilEntryAlertOnce(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	doc := `{"nodes":{"dp-load-null":null,"dp-load-ok":{"node_id":"dp-load-ok","status":"connected"}}}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	cs := &ClusterStore{}
	if err := cs.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cs.NodeRecordWasDropped("dp-load-null") {
		t.Error("Load must remember the node it dropped")
	}
	if cs.NodeRecordWasDropped("dp-load-ok") {
		t.Error("a healthy node must NOT be recorded as dropped")
	}
	if cs.NodeRecordWasDropped("dp-never-heard-of") {
		t.Error("an unknown node ID must not report as dropped")
	}

	// The replication boundary records too, and the Load entry survives it:
	// the serial lost on either path never becomes revocable again.
	bundle := json.RawMessage(`{"nodes":{"dp-import-null":null,"dp-load-ok":{"node_id":"dp-load-ok","status":"connected"}}}`)
	if err := cs.ImportFullState(bundle); err != nil {
		t.Fatalf("ImportFullState: %v", err)
	}
	if !cs.NodeRecordWasDropped("dp-import-null") {
		t.Error("ImportFullState must remember the node it dropped")
	}
	if !cs.NodeRecordWasDropped("dp-load-null") {
		t.Error("a later import must not forget an earlier drop — the lost serial stays lost")
	}
}

// ── 5. concurrency: the reader races the ingestion boundary ─────────────────

// admitEnrollment calls NodeRecordWasDropped on the gRPC path while an HA
// resync can be importing state, so the read takes cs.mu and must not race the
// write. Run under -race.
func TestClusterStore_DroppedNodeIDsConcurrentReadAndImport(t *testing.T) {
	isolateStateCorruption(t)
	_ = captureStartupAlerts(t)
	resetReplicatedNilEntryAlertOnce(t)

	cs := &ClusterStore{path: filepath.Join(t.TempDir(), "cluster.json")}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = cs.ImportFullState(json.RawMessage(`{"nodes":{"dp-null":null}}`))
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = cs.NodeRecordWasDropped("dp-null")
			}
		}()
	}
	wg.Wait()
	if !cs.NodeRecordWasDropped("dp-null") {
		t.Error("the drop must be recorded after the concurrent rounds")
	}
}
