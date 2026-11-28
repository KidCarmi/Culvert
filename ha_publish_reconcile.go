package main

// ha_publish_reconcile.go — ADR-0064 part D: automatic reconciliation of a
// publication hold with the PREVIOUS LEADER's state.
//
// A hold means a data plane runs configuration the promoted node never
// replicated. The node that committed it is the previous leader. Two halves:
//
//  1. PRESERVE BEFORE OVERWRITE (the demoted side). A leader that becomes a
//     standby is about to replace its state with the new leader's bundle. Before
//     it enters standby it writes its committed snapshot — version, term, epoch
//     — to ha_preserved_snapshot.json, atomically. A resync never deletes it.
//
//  2. FETCH AND ADOPT (the promoted side). While held, the new leader fetches
//     that file over the cluster channel (HAPeerSnapshot: HA-token
//     authenticated like HASync, answered only by a Control Plane, never by a
//     data plane) and adopts it only when ALL of these hold:
//       - its version covers every version reported inside a gap;
//       - this node committed no configuration of its own since the promotion
//         (its distributed content is still what the promotion published);
//       - its term is below ours and, with a fencing lease, its epoch too;
//       - it passes the same validation as every other snapshot door
//         (applyConfigSnapshot → validateConfigSnapshot, the ruleset gate).
//     Adoption applies it through applyConfigSnapshot, publishes it as a NEW
//     version above every reported and every known version, releases the hold
//     and writes a cluster.ha-auto-reconcile audit entry with the diff.
//
// Anything else — own writes since the promotion, peer unreachable or an older
// build, snapshot invalid or too old, lineage mismatch — keeps the hold, with
// the reason on the status, for the operator's release.
//
// Idempotent: the gate file records phase "reconciling" before anything is
// applied. A crash at any point leaves a held gate; the next attempt (after a
// restart too) fetches the same snapshot, applies the same content and
// publishes it, so every path converges on the same configuration. A data
// plane's reported version is only ever EVIDENCE; nothing is adopted from one.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const haPreservedSnapshotFile = "ha_preserved_snapshot.json"

// haReconcileInterval is the retry cadence of the automatic reconciliation.
const haReconcileInterval = 15 * time.Second

var methodHAPeerSnapshot = fmt.Sprintf("/%s/HAPeerSnapshot", configServiceName)

// haPreservedSnapshot is what a demoted leader keeps of its own leadership.
type haPreservedSnapshot struct {
	Version  int64          `json:"version"`
	Term     uint64         `json:"term"`
	Epoch    int64          `json:"epoch,omitempty"`
	SavedAt  string         `json:"saved_at"`
	Reason   string         `json:"reason"`
	Snapshot ConfigSnapshot `json:"snapshot"`
}

func haPreservedSnapshotPath() string {
	return filepath.Join(filepath.Dir(haConfigPath()), haPreservedSnapshotFile)
}

// preserveLedSnapshot durably records this node's committed snapshot as the
// last act of its leadership. Called before the node enters standby after a
// demotion (self-fence, a foreign lease holder, a restart that finds the peer
// leading). A node that has published nothing has nothing to preserve.
func (h *HAState) preserveLedSnapshot(reason string) {
	if h != haTopologySource() {
		return
	}
	if ok, _ := globalConfigStore.ServableConfig(); !ok {
		return
	}
	snap := globalConfigStore.Get()
	h.mu.RLock()
	term := h.term
	h.mu.RUnlock()
	rec := haPreservedSnapshot{
		Version: snap.Version, Term: term, Epoch: snap.Epoch,
		SavedAt: time.Now().UTC().Format(time.RFC3339), Reason: reason, Snapshot: snap,
	}
	data, err := json.Marshal(rec)
	if err == nil {
		err = atomicWriteFile(haPreservedSnapshotPath(), data, 0o600)
	}
	if err != nil {
		logger.Printf("HA: PRESERVING this node's committed configuration (v%d) before it re-enters standby FAILED: %v — "+
			"if the new leader lacks it, it cannot be adopted automatically", snap.Version, err)
		return
	}
	logger.Printf("HA: preserved this node's committed configuration v%d (term %d) before re-entering standby (%s)",
		snap.Version, term, sanitizeLog(reason))
}

func loadPreservedSnapshot() (*haPreservedSnapshot, error) {
	data, err := os.ReadFile(haPreservedSnapshotPath())
	if err != nil {
		return nil, err
	}
	var rec haPreservedSnapshot
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("preserved snapshot unreadable: %w", err)
	}
	return &rec, nil
}

// HAPeerSnapshot serves this node's preserved snapshot to the leader that
// replaced it. Authenticated by the HA token, exactly like HASync; answered by
// any Control Plane that holds one (it is not leader-gated: the node that
// answers is, by construction, no longer the leader).
func (s *controlPlaneServer) HAPeerSnapshot(_ context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	if !globalHA.VerifyToken(req.Token) {
		return nil, status.Errorf(codes.PermissionDenied, "invalid HA token")
	}
	rec, err := loadPreservedSnapshot()
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "no preserved snapshot on this node")
	}
	return json.Marshal(rec)
}

// haFetchPeerSnapshot fetches the previous leader's preserved snapshot. Test
// seam; production dials the peer's cluster address with this node's cluster
// credentials.
var haFetchPeerSnapshot = func(ctx context.Context) (*haPreservedSnapshot, error) {
	h := haTopologySource()
	h.mu.RLock()
	token, rc := h.token, h.resync
	addrs := []string{h.standbyAddr, h.peerAddr}
	h.mu.RUnlock()
	var lastErr error = fmt.Errorf("no previous-leader address is known")
	for _, addr := range addrs {
		if addr == "" {
			continue
		}
		rec, err := fetchPeerSnapshotFrom(ctx, addr, token, rc)
		if err == nil {
			return rec, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func fetchPeerSnapshotFrom(ctx context.Context, addr, token string, rc haResyncContext) (*haPreservedSnapshot, error) {
	client, err := NewDataPlaneClient("ha-reconcile", addr, rc.certFile, rc.keyFile, rc.caFile)
	if err != nil {
		return nil, fmt.Errorf("dial previous leader: %w", err)
	}
	defer func() {
		client.mu.Lock()
		if client.conn != nil {
			_ = client.conn.Close()
		}
		client.mu.Unlock()
	}()
	req, _ := json.Marshal(map[string]string{"token": token})
	raw, err := client.call(ctx, methodHAPeerSnapshot, json.RawMessage(req))
	if err != nil {
		return nil, fmt.Errorf("fetch preserved snapshot: %w", err)
	}
	var rec haPreservedSnapshot
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("decode preserved snapshot: %w", err)
	}
	return &rec, nil
}

// contentFingerprint identifies a snapshot's distributed CONTENT, ignoring the
// fields a leadership change or a re-commit alone moves. It works on the
// encoded form so it never writes a snapshot field.
func contentFingerprint(snap ConfigSnapshot) string {
	b, err := json.Marshal(snap)
	if err != nil {
		return ""
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return ""
	}
	for _, k := range []string{"version", "epoch", "cp_addresses", "ca_fingerprint", "updated_at"} {
		delete(fields, k)
	}
	canon, err := json.Marshal(fields) // map keys are emitted sorted
	if err != nil {
		return ""
	}
	return sha256Hex(canon)
}

// reconcileRefusal explains why a fetched snapshot is not adopted ("" = adopt).
func reconcileRefusal(st *publishGateState, rec *haPreservedSnapshot, ourTerm uint64, ourEpoch int64, currentFP string) string {
	maxK := int64(0)
	for i := range st.Evidence {
		if st.Evidence[i].Version > maxK {
			maxK = st.Evidence[i].Version
		}
	}
	switch {
	case publishGateConflict(st.Evidence) != "":
		return "the fleet reports conflicting generations: " + publishGateConflict(st.Evidence)
	case rec.Version < maxK:
		return fmt.Sprintf("the previous leader's preserved configuration (v%d) is older than a version a data plane reports (v%d)", rec.Version, maxK)
	case rec.Term >= ourTerm:
		return fmt.Sprintf("lineage: the preserved configuration is from term %d, not below this leader's term %d", rec.Term, ourTerm)
	case ourEpoch != 0 && (rec.Epoch <= 0 || rec.Epoch >= ourEpoch):
		return fmt.Sprintf("lineage: the preserved configuration carries fencing epoch %d, not below this leader's epoch %d", rec.Epoch, ourEpoch)
	case !(st.Phase == "reconciling" && st.AdoptingVersion == rec.Version) && currentFP != st.ContentFP:
		// Not checked when resuming an interrupted adoption of this very
		// snapshot: the committed content may already be the adopted one, and
		// nothing else can have changed it — operator mutations are refused for
		// the whole of a hold.
		return "this leader has committed configuration of its own since the promotion: both sides hold changes the other lacks"
	}
	return ""
}

// reconcilePublishHoldOnce makes one reconciliation attempt. It reports
// whether the hold was released.
func reconcilePublishHoldOnce(ctx context.Context) bool {
	st := publishGateSnapshot()
	if !st.Armed || !st.Held || !publishGateApplies() || !haLeadershipHeld() {
		return false
	}
	rec, err := haFetchPeerSnapshot(ctx)
	if err != nil {
		notePublishReconcile("the previous leader's configuration could not be fetched: " + err.Error())
		return false
	}
	hs := globalHA.Status()
	if why := reconcileRefusal(&st, rec, hs.Term, globalHA.CurrentEpoch(), contentFingerprint(globalConfigStore.Get())); why != "" {
		notePublishReconcile(why)
		return false
	}
	return adoptPreservedSnapshot(st, rec)
}

// adoptPreservedSnapshot applies, publishes and releases. Each step is safe to
// repeat; the journal phase makes a crash resume here.
func adoptPreservedSnapshot(before publishGateState, rec *haPreservedSnapshot) bool {
	setPublishGatePhase("reconciling", rec.Version)
	snap := rec.Snapshot
	if err := applyConfigSnapshot(snap); err != nil {
		notePublishReconcile("the previous leader's configuration was refused by validation: " + err.Error())
		return false
	}
	maxV := rec.Version
	for i := range before.Evidence {
		if before.Evidence[i].Version > maxV {
			maxV = before.Evidence[i].Version
		}
	}
	globalConfigStore.raiseVersionAtLeast(maxV) // CLU-002: strictly above every reported and known version
	if err := publishCurrentConfigSnapshot(); err != nil {
		notePublishReconcile("publishing the adopted configuration failed: " + err.Error())
		return false
	}
	published := globalConfigStore.Version()

	publishGate.mu.Lock()
	g := &publishGate.st
	g.Watermark, g.FirstOwn, g.Gaps = maxV, published, nil
	g.Held, g.HoldReason, g.HeldSince, g.Phase, g.ReconcileNote = false, "", "", "", ""
	g.AdoptingVersion = 0
	g.Evidence = nil
	g.Reconciled = rec.Version
	g.ContentFP = contentFingerprint(globalConfigStore.Get())
	publishGate.alerted = false
	savePublishGateLocked()
	publishGate.mu.Unlock()

	diff, _ := json.Marshal(before.Evidence)
	logger.Printf("HA: publication hold RECONCILED automatically — adopted the previous leader's configuration v%d (term %d) "+
		"and published it as v%d; the hold is released", rec.Version, rec.Term, published)
	auditSystem("cluster.ha-auto-reconcile", "self", fmt.Sprintf(
		"ha_auto_reconcile: adopted the previous leader's preserved configuration v%d (term %d, epoch %d) and published it as v%d; "+
			"nodes that were ahead: %s", rec.Version, rec.Term, rec.Epoch, published, auditCutString(string(diff), 1500)))
	return true
}

// setPublishGatePhase journals an adoption before anything is applied.
func setPublishGatePhase(phase string, adopting int64) {
	publishGate.mu.Lock()
	loadPublishGateLocked()
	if publishGate.st.Phase != phase || publishGate.st.AdoptingVersion != adopting {
		publishGate.st.Phase, publishGate.st.AdoptingVersion = phase, adopting
		savePublishGateLocked()
	}
	publishGate.mu.Unlock()
}

// notePublishReconcile records why the last attempt did not reconcile (status).
func notePublishReconcile(why string) {
	publishGate.mu.Lock()
	loadPublishGateLocked()
	if publishGate.st.ReconcileNote != why {
		publishGate.st.ReconcileNote = why
		savePublishGateLocked()
		logger.Printf("HA: publication hold not reconciled automatically: %q", sanitizeLog(why))
	}
	publishGate.mu.Unlock()
}

// publishReconcileRunning is the single-flight latch of the retry loop.
var publishReconcileRunning atomic.Bool

// publishReconcileSpawn starts the retry loop. Test seam.
var publishReconcileSpawn = func(loop func()) { go loop() }

// ensurePublishReconcileLoop starts the retry loop for a held gate, once.
func ensurePublishReconcileLoop() {
	if !publishReconcileRunning.CompareAndSwap(false, true) {
		return
	}
	publishReconcileSpawn(func() {
		defer publishReconcileRunning.Store(false)
		runGuarded("ha-publish-reconcile", publishReconcileLoop)
	})
}

func publishReconcileLoop() {
	for publishHoldInForce() && publishGateApplies() {
		ctx, cancel := context.WithTimeout(context.Background(), scaledConfigDeadline(dpLastFullSnapshotBytes.Load()))
		done := reconcilePublishHoldOnce(ctx)
		cancel()
		if done || !globalHA.sleepUnlessShutdown(haReconcileInterval) {
			return
		}
	}
}
