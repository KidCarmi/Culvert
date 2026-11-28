package main

// ha_publish_gate_test.go — ADR-0064 part D: a promoted control plane never
// hands a data plane older content at a higher version, a healthy failover is
// never held, and a hold is visible, persistent and releasable.
//
// The failover is the real one (guardedTick → promote); what a data plane
// receives is read through the real GetConfig / GetConfigDelta handlers.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/KidCarmi/Culvert/internal/halease"
)

const gateWatermark = 4242 // the Version of eligBundle: what the standby replicated

// promotedPair is a standby that replicated v4242 from its leader, lost it,
// and promoted through the real loop. Its activation seeds the version counter
// from the wall clock exactly as activateControlPlane does.
func promotedPair(t *testing.T) *eligPair {
	t.Helper()
	p := newEligPair(t)
	resetPublishGateForTest()
	t.Cleanup(resetPublishGateForTest)
	prevReach := haPreviousLeaderReachable
	haPreviousLeaderReachable = func() bool { return false }
	t.Cleanup(func() { haPreviousLeaderReachable = prevReach })

	floor := filepath.Join(t.TempDir(), cpConfigVersionFile)
	p.h.mu.Lock()
	p.h.pc.onPromote = func() error {
		p.promotes.Add(1)
		globalConfigStore.armVersionPersistence(floor)
		return publishCurrentConfigSnapshot()
	}
	p.h.mu.Unlock()

	p.leader.serve(p.good)
	p.s.guardedSyncOnce()
	if !p.outage(haStandbyMaxFail) || !p.h.IsLeader() {
		t.Fatal("setup: the synced standby must promote")
	}
	st := publishGateSnapshot()
	if !st.Armed || st.Watermark != gateWatermark || st.FirstOwn <= gateWatermark+1 {
		t.Fatalf("setup: gate must be armed with W=%d and a first own version far above it; got %+v", gateWatermark, st)
	}
	return p
}

// dpGetConfig is a data plane holding version k polling GetConfig.
func dpGetConfig(t *testing.T, k int64) (unchanged bool, snap ConfigSnapshot, err error) {
	t.Helper()
	conn := startBufconnCP(t)(t, clusterClientCallOptions()...)
	req, _ := json.Marshal(getConfigRequest{KnownVersion: k})
	var raw json.RawMessage
	if ierr := conn.Invoke(context.Background(), methodGetConfig, json.RawMessage(req), &raw); ierr != nil {
		return false, snap, ierr
	}
	var probe configUnchangedReply
	if json.Unmarshal(raw, &probe) == nil && probe.ConfigUnchanged {
		if probe.Version != k {
			t.Fatalf("unchanged reply must echo the caller's version %d, got %d", k, probe.Version)
		}
		return true, snap, nil
	}
	if uerr := json.Unmarshal(raw, &snap); uerr != nil {
		t.Fatalf("decode snapshot: %v", uerr)
	}
	return false, snap, nil
}

func dpGetConfigDelta(t *testing.T, k int64) getConfigDeltaReply {
	t.Helper()
	conn := startBufconnCP(t)(t, clusterClientCallOptions()...)
	req, _ := json.Marshal(getConfigDeltaRequest{KnownVersion: k})
	var raw json.RawMessage
	if err := conn.Invoke(context.Background(), methodGetConfigDelta, json.RawMessage(req), &raw); err != nil {
		t.Fatalf("GetConfigDelta: %v", err)
	}
	var reply getConfigDeltaReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		t.Fatalf("decode delta reply: %v", err)
	}
	return reply
}

// The main availability guarantee: a healthy failover is not held and needs
// no operator. Every data plane at or below the watermark is served at once.
func TestPublishGate_ConsistentFailoverProceedsWithoutHold(t *testing.T) {
	promotedPair(t)
	for _, k := range []int64{gateWatermark, gateWatermark - 200, 1} {
		unchanged, snap, err := dpGetConfig(t, k)
		if err != nil || unchanged {
			t.Fatalf("k=%d: a data plane at or below the watermark must be served the promoted configuration (unchanged=%v err=%v)", k, unchanged, err)
		}
		if snap.Version <= gateWatermark || !snapHasLeaderConfig(snap) {
			t.Fatalf("k=%d: served v%d rules=[%s]", k, snap.Version, ruleNamesOf(snap.PolicyRules))
		}
	}
	if ok, why := haPublishAuthorized(); !ok {
		t.Fatalf("a consistent failover must be publish-authorized without an operator; held: %s", why)
	}
	if st := publishGateSnapshot(); st.Held || len(st.Evidence) != 0 {
		t.Fatalf("unexpected hold: %+v", st)
	}
	if w := haGateRequest(http.MethodPost, "/api/policy"); w.Code != http.StatusTeapot {
		t.Errorf("configuration changes must be accepted after a consistent failover; got %d", w.Code)
	}
	// An old data plane that sends no version is served as before.
	if unchanged, _, err := dpGetConfig(t, 0); err != nil || unchanged {
		t.Errorf("a data plane that states no version must be served when nothing is held (unchanged=%v err=%v)", unchanged, err)
	}
}

// The promoted node is BEHIND by 3 versions: a data plane had applied v4245.
func TestPublishGate_AheadDataPlaneIsNeverRolledBack(t *testing.T) {
	promotedPair(t)
	const ahead = gateWatermark + 3

	unchanged, snap, err := dpGetConfig(t, ahead)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if !unchanged {
		t.Fatalf("ROLLBACK: a data plane at v%d was handed v%d (rules=[%s]) — older content, replicated only "+
			"through v%d, at a higher version", ahead, snap.Version, ruleNamesOf(snap.PolicyRules), gateWatermark)
	}
	if reply := dpGetConfigDelta(t, ahead); reply.Mode != "unchanged" || reply.TargetVersion != ahead {
		t.Fatalf("delta path must also keep the node on its state; got mode=%q target=%d", reply.Mode, reply.TargetVersion)
	}

	// HOLD: publishing authorization is withdrawn, leadership is not.
	if ok, why := haPublishAuthorized(); ok || !strings.Contains(why, "roll them back") {
		t.Fatalf("want a hold with a reason; ok=%v why=%q", ok, why)
	}
	if !haLeadershipHeld() {
		t.Error("a publication hold must not take leadership away (two separate concepts)")
	}
	if w := haGateRequest(http.MethodPost, "/api/policy"); w.Code != http.StatusServiceUnavailable {
		t.Errorf("configuration changes must be refused during a hold; got %d", w.Code)
	}
	// Never freeze a data plane that is consistent with this node.
	if unchanged, snap, err := dpGetConfig(t, gateWatermark); err != nil || unchanged || !snapHasLeaderConfig(snap) {
		t.Errorf("a consistent data plane must keep being served during a hold (unchanged=%v err=%v)", unchanged, err)
	}
	// Unknown state during a hold: keep last-good.
	if _, _, err := dpGetConfig(t, 0); status.Code(err) != codes.Unavailable {
		t.Errorf("a data plane that states no version must get Unavailable during a hold; got %v", err)
	}

	// The actionable diff.
	gate, _ := haStatusJSON(t)["publish_gate"].(map[string]any)
	nodes, _ := gate["ahead_nodes"].([]any)
	if gate["held"] != true || len(nodes) != 1 || gate["action"] == nil {
		t.Fatalf("status must carry the diff and the action; got %v", gate)
	}
	if n, _ := nodes[0].(map[string]any); int64(n["version"].(float64)) != ahead {
		t.Errorf("diff must name the reported version; got %v", nodes[0])
	}
	if st := haStatusJSON(t); st["publish_authorized"] != false || st["leadership_held"] != true {
		t.Errorf("status flags: %v / %v", st["publish_authorized"], st["leadership_held"])
	}
}

// Evidence from the heartbeat (the authenticated per-node report), a version
// above everything this node issued (a stale leader's separate lineage), and
// two fingerprints for one version (no single state can explain both).
func TestPublishGate_ConflictingFleetGenerations(t *testing.T) {
	promotedPair(t)
	cur := globalConfigStore.Version()
	if v := publishGateDecide("dp-own", "heartbeat", cur, 0, "fp-own"); v != gateServe {
		t.Fatalf("a node on this node's own version must be consistent; got %v", v)
	}
	if v := publishGateDecide("dp-a", "heartbeat", gateWatermark+2, 0, "fp-1"); v != gateKeepCurrent {
		t.Fatalf("heartbeat evidence of an unreplicated version must hold; got %v", v)
	}
	publishGateDecide("dp-b", "heartbeat", gateWatermark+2, 0, "fp-2")
	publishGateDecide("dp-c", "heartbeat", cur+500, 7, "")
	st := publishGateSnapshot()
	if !st.Held || len(st.Evidence) != 3 {
		t.Fatalf("want a hold with three nodes; got %+v", st)
	}
	if c := publishGateConflict(st.Evidence); !strings.Contains(c, "two different blocklist fingerprints") {
		t.Errorf("conflict not reported: %q", c)
	}
	// Idempotent: the same reports again change nothing.
	publishGateDecide("dp-a", "heartbeat", gateWatermark+2, 0, "fp-1")
	if again := publishGateSnapshot(); len(again.Evidence) != 3 || again.HeldSince != st.HeldSince {
		t.Errorf("a repeated report must not grow or restart the hold: %+v", again)
	}
}

// The hold and its bounds survive a restart of the promoted node.
func TestPublishGate_HoldSurvivesRestart(t *testing.T) {
	promotedPair(t)
	if unchanged, _, _ := dpGetConfig(t, gateWatermark+1); !unchanged {
		t.Fatal("setup: ahead data plane must be kept")
	}
	before := publishGateSnapshot()

	// The restart: process memory is gone, the gate file is not.
	publishGate.mu.Lock()
	publishGate.st, publishGate.loadedFrom, publishGate.alerted = publishGateState{}, "", false
	publishGate.mu.Unlock()

	after := publishGateSnapshot()
	if !after.Held || after.Watermark != before.Watermark || after.FirstOwn != before.FirstOwn || len(after.Evidence) != 1 {
		t.Fatalf("gate after restart = %+v, want the hold and bounds of %+v", after, before)
	}
	if unchanged, _, _ := dpGetConfig(t, gateWatermark+1); !unchanged {
		t.Fatal("after a restart the ahead data plane was rolled back")
	}
}

func postPublishRelease(t *testing.T, body string) (code int, resp map[string]any) {
	t.Helper()
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	w := httptest.NewRecorder()
	apiClusterHAPublishRelease(w, httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/cluster/ha/publish-release", strings.NewReader(body)))
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

// Operator release: the exception path. Refused while reconciliation is still
// possible unless forced; shows the diff; audited; idempotent; afterwards the
// node that was ahead is served — above its own version, so it applies.
func TestPublishGate_OperatorRelease(t *testing.T) {
	promotedPair(t)
	const ahead = gateWatermark + 3
	dpGetConfig(t, ahead)
	// A second node, on a version ABOVE everything this node has issued (a
	// separate lineage): the release must publish above it too.
	far := globalConfigStore.Version() + 500
	if unchanged, _, _ := dpGetConfig(t, far); !unchanged {
		t.Fatal("setup: a node above the current version must be kept")
	}

	haPreviousLeaderReachable = func() bool { return true }
	if code, resp := postPublishRelease(t, `{}`); code != http.StatusConflict || resp["code"] != "ha_reconciliation_possible" {
		t.Fatalf("release must be refused while the previous leader is reachable; got %d %v", code, resp)
	}
	if st := publishGateSnapshot(); !st.Held {
		t.Fatal("a refused release changed the gate")
	}

	code, resp := postPublishRelease(t, `{"force":true}`)
	if code != http.StatusOK || resp["released"] != true {
		t.Fatalf("forced release = %d %v", code, resp)
	}
	if nodes, _ := resp["rolled_back_nodes"].([]any); len(nodes) != 1 { // both reports come from the same peer address
		t.Errorf("the response must show the diff; got %v", resp["rolled_back_nodes"])
	}
	entry := findAuditEntry(t, "cluster.ha-publish-release", "self")
	if !strings.Contains(entry.Detail, "force=true") || !strings.Contains(entry.Detail, `"version":`) {
		t.Errorf("audit detail must record the force flag and the diff; got %q", entry.Detail)
	}
	if ok, _ := haPublishAuthorized(); !ok {
		t.Fatal("publishing must be authorized after the release")
	}
	unchanged, snap, err := dpGetConfig(t, ahead)
	if err != nil || unchanged || snap.Version <= ahead {
		t.Fatalf("after the release the node must be served ABOVE its version (unchanged=%v v%d err=%v)", unchanged, snap.Version, err)
	}
	published := globalConfigStore.Version()
	// The node that was ahead holds DIFFERENT content at its version: it must
	// be resynced in full, never offered a delta built from this node's content.
	for _, k := range []int64{ahead, far} {
		if reply := dpGetConfigDelta(t, k); reply.Mode == "delta" {
			t.Fatalf("the released node at v%d was offered a delta: it would be applied onto content this node never had", k)
		}
	}
	if published <= far {
		t.Fatalf("published v%d is not above the highest reported version v%d", published, far)
	}

	// Idempotent.
	if code, resp := postPublishRelease(t, `{"force":true}`); code != http.StatusOK || resp["released"] != false {
		t.Fatalf("second release = %d %v, want released=false", code, resp)
	}
	if globalConfigStore.Version() != published {
		t.Error("an idempotent release must not publish again")
	}
}

// A second failover during a hold: the standby replicated the held leader, and
// must start from its gate — or it would serve the ahead nodes the moment it leads.
func TestPublishGate_HoldAndGapsAreInheritedAcrossASecondFailover(t *testing.T) {
	promotedPair(t)
	dpGetConfig(t, gateWatermark+3) // hold
	bundleGate := publishGateForBundle()
	if bundleGate == nil || !bundleGate.Held {
		t.Fatal("the HA bundle must carry the held gate (HASync stays served during a hold)")
	}
	firstGap := bundleGate.Gaps[0]

	// The standby of that leader: it stored the bundle's gate, then promotes.
	resetPublishGateForTest()
	setInheritedPublishGate(bundleGate)
	cur := globalConfigStore.Version()
	armPublishGate(cur, cur+1000, 99, 0)

	st := publishGateSnapshot()
	if !st.Held || len(st.Evidence) != 1 || len(st.Gaps) != 2 || st.Gaps[0] != firstGap {
		t.Fatalf("the second leader must inherit the hold, the evidence and the first gap; got %+v", st)
	}
	if v := publishGateDecide("dp-late", "heartbeat", gateWatermark+1, 0, ""); v != gateKeepCurrent {
		t.Errorf("a straggler inside the FIRST failover's gap must still be kept; got %v", v)
	}
}

// A control plane that was never promoted has no gate: behaviour is unchanged.
func TestPublishGate_NotArmedWithoutAPromotion(t *testing.T) {
	isolateEligGlobals(t)
	resetPublishGateForTest()
	t.Cleanup(resetPublishGateForTest)
	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: []string{"plain.example"}}); err != nil {
		t.Fatal(err)
	}
	if v := publishGateDecide("dp", "heartbeat", 999999999999, 0, ""); v != gateServe {
		t.Fatalf("an unarmed gate must not classify anything; got %v", v)
	}
	if ok, _ := haPublishAuthorized(); !ok {
		t.Fatal("an unarmed gate authorizes publishing")
	}
}

// Leadership lost: the bounds described a leadership that is over.
func TestPublishGate_DemotionDisarms(t *testing.T) {
	p := promotedPair(t)
	dpGetConfig(t, gateWatermark+3)
	p.h.StartAsStandby(resyncCtx(t), "new-leader.example:50051", eligSharedSecret, ":50051", "", "", "", true, func() error { return nil })
	if st := publishGateSnapshot(); st.Armed || st.Held {
		t.Fatalf("a standby must hold no publication gate; got %+v", st)
	}
}

// Lease mode: a promotion that fails (the lease is held elsewhere, or expires
// mid-way) arms nothing — the gate follows leadership, it never precedes it.
func TestPublishGate_FailedLeasePromotionArmsNothing(t *testing.T) {
	isolateEligGlobals(t)
	resetPublishGateForTest()
	t.Cleanup(resetPublishGateForTest)
	restore := swapGlobalHA(t)
	f := halease.NewFake(time.Minute)
	if granted, _, _ := f.Acquire(context.Background(), "cp-other"); !granted {
		t.Fatal("seed acquire")
	}
	globalHA = leaseStandby(f, "cp-me")
	t.Cleanup(func() { globalHA.Stop(); restore() })
	if err := globalHA.PromoteManually(); err == nil {
		t.Fatal("promotion must fail while another node holds the lease")
	}
	if st := publishGateSnapshot(); st.Armed {
		t.Fatalf("a failed promotion armed the gate: %+v", st)
	}
}

// Stale-leader fencing (lease mode): a leader whose resume the lease DENIED and
// that has no standby to join keeps the leader role read-only (ADR-0005 S2).
// The lease is the authority, so that node distributes nothing: data planes
// and a standby get CULVERT_PUBLISH_NOT_AUTHORIZED and keep what they have.
func TestStaleLeader_DeniedLeaseResumeDistributesNothing(t *testing.T) {
	isolateEligGlobals(t)
	resetPublishGateForTest()
	t.Cleanup(resetPublishGateForTest)
	restore := swapGlobalHA(t)
	t.Cleanup(func() { globalHA.Stop(); restore() })
	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: []string{"stale-leader.example"}}); err != nil {
		t.Fatal(err)
	}

	f := halease.NewFake(time.Minute)
	if granted, _, _ := f.Acquire(context.Background(), "cp-new-leader"); !granted {
		t.Fatal("seed acquire: another node holds the lease")
	}
	globalHA.SetLeaseProvider(f, "cp-stale")
	globalHA.SetResyncMaterial(resyncCtx(t), ":50051", "", "", "")
	globalHA.ResumeAsLeader(&haConfig{Enabled: true, Token: eligSharedSecret, PeerAddr: "peer:50051", Role: "leader", Term: 9})
	if !globalHA.IsLeader() || globalHA.WriteAllowed() {
		t.Fatalf("setup: want the read-only leader stance (leader=%v write=%v)", globalHA.IsLeader(), globalHA.WriteAllowed())
	}

	if haLeadershipHeld() {
		t.Error("a leader without the lease does not hold leadership")
	}
	if ok, why := haPublishAuthorized(); ok || !strings.Contains(why, "without the fencing lease") {
		t.Errorf("publishing must not be authorized; ok=%v why=%q", ok, why)
	}
	for _, k := range []int64{0, 1, globalConfigStore.Version()} {
		_, snap, err := dpGetConfig(t, k)
		if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), cpPublishRefusedMarker) {
			t.Fatalf("k=%d: a stale leader served configuration (v%d, blocked=%v, err=%v)", k, snap.Version, snap.BlockedHosts, err)
		}
	}
	conn := startBufconnCP(t)(t, clusterClientCallOptions()...)
	var raw json.RawMessage
	dreq, _ := json.Marshal(getConfigDeltaRequest{KnownVersion: 1})
	if err := conn.Invoke(context.Background(), methodGetConfigDelta, json.RawMessage(dreq), &raw); !strings.Contains(status.Convert(err).Message(), cpPublishRefusedMarker) {
		t.Errorf("GetConfigDelta from a stale leader: %v", err)
	}
	hreq, _ := json.Marshal(map[string]any{"token": eligSharedSecret, "role": "standby"})
	if err := conn.Invoke(context.Background(), methodHASync, json.RawMessage(hreq), &raw); !strings.Contains(status.Convert(err).Message(), cpPublishRefusedMarker) {
		t.Errorf("HASync from a stale leader: %v", err)
	}
	// A standby counts that refusal as a live leader holding, not as an outage.
	if got := haLeaderAnswerOf(status.Error(codes.Unavailable, cpPublishRefusedMarker+": x")); got != haAnsweredHolding {
		t.Errorf("standby classification = %v, want holding", got)
	}

	// Control: once the node holds the lease it distributes again.
	f.ExpireForTest()
	if !globalHA.acquireLeaseForLeadership("test") {
		t.Fatal("control: acquire after expiry")
	}
	epoch, err := globalHA.commitGrant("test")
	if err == nil {
		globalHA.mu.Lock()
		var page *haDeferredPage
		page, err = globalHA.exposeGrantLocked("test", epoch)
		globalHA.mu.Unlock()
		page.dispatch()
	}
	if err != nil {
		t.Fatalf("control: install grant: %v", err)
	}
	if _, snap, gerr := dpGetConfig(t, 0); gerr != nil || len(snap.BlockedHosts) != 1 {
		t.Fatalf("control: a fenced leader must serve (err=%v)", gerr)
	}
}

// The promotion exception to "publishing needs leadership" cannot be held open
// and cannot be borrowed by a stale leader.
func TestPromotionCommitting_IsBoundedToPromoteAndClosedToAStaleLeader(t *testing.T) {
	isolateEligGlobals(t)
	restore := swapGlobalHA(t)
	t.Cleanup(func() { globalHA.Stop(); restore() })
	if n := haPromotionsInFlight.Load(); n != 0 {
		t.Fatalf("precondition: %d promotion(s) in flight", n)
	}

	// A promotion whose activation fails, and one whose activation PANICS,
	// both leave the counter at zero (the decrement is deferred in promote()).
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	var sawInFlight bool
	for _, onPromote := range []func() error{
		func() error { sawInFlight = haPromotionCommitting(); return errors.New("listener: address in use") },
		func() error { panic("activation blew up") },
	} {
		h := newEligStandby(&atomic.Int32{})
		h.mu.Lock()
		h.pc.onPromote = onPromote
		h.mu.Unlock()
		globalHA = h
		if err := h.PromoteManually(); err == nil {
			t.Fatal("setup: the promotion must fail")
		}
		if n := haPromotionsInFlight.Load(); n != 0 {
			t.Fatalf("a failed promotion left %d promotion(s) in flight: the exception is held open", n)
		}
	}
	if !sawInFlight {
		t.Fatal("control: inside promote() the exception must be visible to the activation publish")
	}

	// A stale leader: role leader, lease held by another node. It is not a
	// standby, so promote() is never entered on it (PromoteManually refuses the
	// role before the counter moves), and its publish is refused.
	f := halease.NewFake(time.Minute)
	if granted, _, _ := f.Acquire(context.Background(), "cp-new-leader"); !granted {
		t.Fatal("seed acquire")
	}
	stale := &HAState{}
	stale.SetLeaseProvider(f, "cp-stale")
	stale.ResumeAsLeader(&haConfig{Enabled: true, Token: eligSharedSecret, PeerAddr: "peer:50051", Role: "leader", Term: 9})
	globalHA = stale
	if !stale.IsLeader() || stale.WriteAllowed() {
		t.Fatalf("setup: want the read-only leader stance (leader=%v write=%v)", stale.IsLeader(), stale.WriteAllowed())
	}
	if err := stale.PromoteManually(); err == nil {
		t.Fatal("a node that already holds the leader role must not enter promote()")
	}
	if haPromotionCommitting() {
		t.Fatal("a refused promotion of a stale leader opened the publish exception")
	}
	before := globalConfigStore.Version()
	if err := publishCurrentConfigSnapshot(); !errors.Is(err, errPublishWithoutLeadership) || globalConfigStore.Version() != before {
		t.Fatalf("a stale leader published (err=%v, v%d → v%d)", err, before, globalConfigStore.Version())
	}
}
