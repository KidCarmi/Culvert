package main

// ha_failover_sync_eligibility_test.go — automatic failover never promotes a
// standby that has not applied the leader's configuration, in LEGACY mode as
// in lease mode.
//
// The defect these tests pin: the legacy (no fencing lease) auto-failover path
// promoted on three failed sync rounds with no synchronization check at all. A
// standby that had never completed a sync — or whose only attempts were refused
// (POL-005) — became leader holding empty configuration and published it to
// every data plane as authoritative: no policy rules, an empty blocklist. The
// lease path already refused that (ADR-0005 Finding 8).
//
// Everything here drives the REAL path: standbyLoopState.guardedTick →
// syncFromLeader → applyHABundle → onMaxFail → promote. The only seam is the
// leader's wire (DataPlaneClient.callForTest), and "what a data plane receives"
// is read through the real GetConfig handler over bufconn. The tests reference
// no symbol the fix introduced, so reverting the production change makes them
// FAIL rather than fail to compile (the negative control).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/KidCarmi/Culvert/internal/blocklist"
	"github.com/KidCarmi/Culvert/internal/halease"
)

const (
	eligLeaderRule   = "ha-elig-leader-block-rule"
	eligLeaderHost   = "leader-blocked.ha-elig.example"
	eligLeaderAddr   = "dead-leader.ha-elig.example:50051"
	eligSharedSecret = "ha-elig-token" // #nosec G101 -- synthetic test fixture; never leaves this test
)

// eligLeader is the leader as the standby sees it over the wire.
type eligLeader struct {
	mu    sync.Mutex
	reply []byte // nil ⇒ unreachable
	calls int
}

func (l *eligLeader) call(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if method != methodHASync {
		return nil, fmt.Errorf("unexpected RPC %q", method)
	}
	if l.reply == nil {
		return nil, status.Error(codes.Unavailable, "connection refused")
	}
	return l.reply, nil
}

func (l *eligLeader) down() { l.serve(nil) }

func (l *eligLeader) serve(b []byte) {
	l.mu.Lock()
	l.reply = b
	l.mu.Unlock()
}

// eligPair is a legacy-mode HA standby (auto-failover ON, no fencing lease)
// wired to a scripted leader.
type eligPair struct {
	h        *HAState
	s        *standbyLoopState
	leader   *eligLeader
	promotes *atomic.Int32
	good     []byte // a bundle that applies: the leader's rule + blocked host
	refused  []byte // a bundle POL-005 refuses whole
}

// isolateEligGlobals gives the test its own copy of every global the HA sync,
// the promotion publish and the GetConfig handler touch, and restores each one.
func isolateEligGlobals(t *testing.T) {
	t.Helper()
	tempHADir(t)
	resetPublishGateForTest() // a promotion arms the publication gate (ADR-0064)
	t.Cleanup(resetPublishGateForTest)
	bindFreshAdmissionOwners(t) // the snapshot apply mutates ipf/rl in place (RISK-030)
	snapshotPolicyStoreForTest(t)
	policyStore.ReplaceAll(nil)
	resetReplicatedLeaderVersion(t)

	origAction := defaultPolicyAction()
	origBL, origCluster, origConfig := bl, globalClusterStore, globalConfigStore
	origEpoch := dpLastSeenEpoch.Load()
	bl = blocklist.New()
	globalClusterStore = newTestClusterStore(t)
	globalConfigStore = &ConfigStore{}
	dpLastSeenEpoch.Store(0) // legacy (epoch 0) bundles need an unseeded ratchet
	gcMarshalCache.reset()
	gcDeltaRemainderCache.reset()
	t.Cleanup(func() {
		bl, globalClusterStore, globalConfigStore = origBL, origCluster, origConfig
		dpLastSeenEpoch.Store(origEpoch)
		setDefaultPolicyAction(origAction)
		gcMarshalCache.reset()
		gcDeltaRemainderCache.reset()
	})
}

// newEligPair builds the standby exactly as StartAsStandby leaves it, minus the
// ticker goroutine (the test drives the rounds itself). onPromote performs the
// Control Plane activation's first publish — the real publishCurrentConfigSnapshot
// — so a promoted node serves what a real one would.
func newEligPair(t *testing.T) *eligPair {
	t.Helper()
	isolateEligGlobals(t)
	restoreHA := swapGlobalHA(t)

	p := &eligPair{leader: &eligLeader{}, promotes: &atomic.Int32{}}
	p.h = newEligStandby(p.promotes)
	globalHA = p.h
	t.Cleanup(func() {
		globalHA.Stop()
		restoreHA()
	})

	p.s = newEligLoop(p.h, p.leader)
	p.good = eligBundle(t, []PolicyRule{{Priority: 1, Name: eligLeaderRule, DestFQDN: "blocked.ha-elig.example", Action: ActionBlockPage}})
	p.refused = eligBundle(t, []PolicyRule{subjectMatchRule("ha-elig-unenforceable")})
	return p
}

func newEligStandby(promotes *atomic.Int32) *HAState {
	h := &HAState{}
	h.mu.Lock()
	h.role = "standby"
	h.token = eligSharedSecret
	h.autoFailover = true // legacy, opted in to automatic failover
	h.peerAddr = eligLeaderAddr
	h.since = time.Now()
	h.pc = promoteContext{set: true, onPromote: func() error {
		promotes.Add(1)
		return publishCurrentConfigSnapshot()
	}}
	h.mu.Unlock()
	return h
}

func newEligLoop(h *HAState, leader *eligLeader) *standbyLoopState {
	return &standbyLoopState{
		h: h, ctx: context.Background(), leaderAddr: eligLeaderAddr, token: eligSharedSecret,
		client: &DataPlaneClient{callForTest: leader.call},
	}
}

// eligBundle is the leader's HASync reply: this process's current config (so
// applying it is an identity on everything else) plus the leader's rules and
// one blocked host.
func eligBundle(t *testing.T, rules []PolicyRule) []byte {
	t.Helper()
	state, err := newTestClusterStore(t).ExportState()
	if err != nil {
		t.Fatalf("export cluster state: %v", err)
	}
	snap := CurrentConfigSnapshot()
	snap.IdPProfiles = nil
	snap.PolicyRules = rules
	snap.BlockedHosts = []string{eligLeaderHost}
	raw, err := json.Marshal(HAStateBundle{ClusterState: state, Config: snap, Version: 4242, LeaderTerm: 7})
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return raw
}

// outage runs n leader-unreachable rounds and reports whether any of them told
// the loop to exit (the node promoted).
func (p *eligPair) outage(n int) (exited bool) {
	p.leader.down()
	for i := 0; i < n; i++ {
		if p.s.guardedTick() {
			return true
		}
	}
	return false
}

// dataPlaneGetConfig is a data plane polling this node: the real GetConfig
// handler, HA serving gate included, over bufconn.
func dataPlaneGetConfig(t *testing.T) (ConfigSnapshot, error) {
	t.Helper()
	conn := startBufconnCP(t)(t, clusterClientCallOptions()...)
	var raw json.RawMessage
	if err := conn.Invoke(context.Background(), methodGetConfig, json.RawMessage(`{}`), &raw); err != nil {
		return ConfigSnapshot{}, err
	}
	var snap ConfigSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("decode GetConfig reply: %v", err)
	}
	return snap, nil
}

func snapHasLeaderConfig(snap ConfigSnapshot) bool {
	return strings.Contains(ruleNamesOf(snap.PolicyRules), eligLeaderRule) &&
		strings.Contains(strings.Join(snap.BlockedHosts, ","), eligLeaderHost)
}

// haStatusJSON is the operator's view: GET /api/cluster/ha.
func haStatusJSON(t *testing.T) map[string]any {
	t.Helper()
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleViewer)
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/cluster/ha", http.NoBody)
	w := httptest.NewRecorder()
	apiClusterHA(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/cluster/ha = %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

// assertStaysUnpromotedStandby is the post-condition of a refused automatic
// failover: still a standby, nothing activated, and a polling data plane is
// REFUSED (so it keeps its last applied config) rather than handed this node's
// unsynchronized state.
func (p *eligPair) assertStaysUnpromotedStandby(t *testing.T) {
	t.Helper()
	if p.h.IsLeader() || p.promotes.Load() != 0 {
		snap, err := dataPlaneGetConfig(t)
		t.Fatalf("an unsynchronized standby AUTO-PROMOTED (leader=%v, activations=%d). A polling data plane now "+
			"receives as authoritative config: err=%v version=%d policy_rules=[%s] blocked_hosts=%v — the "+
			"leader's rule %q and blocked host %q are gone",
			p.h.IsLeader(), p.promotes.Load(), err, snap.Version, ruleNamesOf(snap.PolicyRules), snap.BlockedHosts,
			eligLeaderRule, eligLeaderHost)
	}
	if _, err := dataPlaneGetConfig(t); status.Code(err) != codes.Unavailable {
		t.Fatalf("a standby must refuse GetConfig with Unavailable so data planes keep their last config; got %v", err)
	}
	st := haStatusJSON(t)
	if st["role"] != "standby" {
		t.Fatalf("role = %v, want standby", st["role"])
	}
	if blocked, _ := st["auto_promote_blocked"].(string); blocked == "" {
		t.Errorf("the refusal must be visible on the HA status surface (auto_promote_blocked); got %v", st)
	}
	if !p.s.manualWarned {
		t.Error("the refusal must page once (ha_manual_failover_required latch)")
	}
}

// A standby that never completed a sync reaches the failure threshold.
func TestLegacyAutoFailover_NeverSyncedStandbyIsNotPromoted(t *testing.T) {
	p := newEligPair(t)
	p.leader.down()
	p.s.guardedSyncOnce() // the immediate try at loop start

	if p.outage(haStandbyMaxFail + 3) {
		t.Error("the standby loop exited: replication and leader monitoring would stop")
	}
	p.assertStaysUnpromotedStandby(t)
	if got, _ := haStatusJSON(t)["sync_fail_count"].(float64); int(got) < haStandbyMaxFail {
		t.Errorf("sync_fail_count = %v, want >= %d (the outage must stay visible)", got, haStandbyMaxFail)
	}
	if p.leader.calls < haStandbyMaxFail+3 {
		t.Errorf("standby stopped retrying the sync after the refusal (calls=%d)", p.leader.calls)
	}
}

// The only bundle the leader ever sent was refused whole (POL-005), then the
// leader died. The standby applied nothing, so it is exactly as unsynchronized
// as one that never reached the leader.
func TestLegacyAutoFailover_RefusedOnlySyncIsNotPromoted(t *testing.T) {
	p := newEligPair(t)
	p.leader.serve(p.refused)
	p.s.guardedSyncOnce()
	if got := ruleNamesOf(policyStore.List()); got != "" {
		t.Fatalf("a POL-005-refused bundle installed rules: [%s]", got)
	}
	if last, _ := haStatusJSON(t)["last_sync_ok"].(string); last != "" {
		t.Fatalf("a refused bundle was recorded as a successful sync (last_sync_ok=%q)", last)
	}

	if p.outage(haStandbyMaxFail + 2) {
		t.Error("the standby loop exited")
	}
	p.assertStaysUnpromotedStandby(t)
}

// A leader that is ALIVE but whose bundle this standby keeps refusing must not
// be replaced by a standby that has never applied anything. (Since the
// refused-round fix the rounds do not even reach the threshold; the node is
// ineligible either way.)
func TestLegacyAutoFailover_RepeatedRefusalsNeverPromote(t *testing.T) {
	p := newEligPair(t)
	p.leader.serve(p.refused)
	p.s.guardedSyncOnce()
	for i := 0; i < haStandbyMaxFail+2; i++ {
		if p.s.guardedTick() {
			t.Fatalf("round %d: loop exited", i)
		}
	}
	if p.h.IsLeader() || p.promotes.Load() != 0 {
		t.Fatalf("a never-synced standby promoted against a live leader (leader=%v activations=%d)", p.h.IsLeader(), p.promotes.Load())
	}
	st := haStatusJSON(t)
	if blocked, _ := st["auto_promote_blocked"].(string); st["role"] != "standby" || blocked == "" {
		t.Fatalf("want a standby reporting auto_promote_blocked; got %v", st)
	}
}

// No availability regression for a healthy pair: synced, then the leader dies
// → the standby still takes over on the third failed round, and serves the
// LEADER's configuration.
func TestLegacyAutoFailover_SyncedStandbyStillPromotes(t *testing.T) {
	p := newEligPair(t)
	p.leader.serve(p.good)
	p.s.guardedSyncOnce()
	if got := ruleNamesOf(policyStore.List()); got != eligLeaderRule {
		t.Fatalf("leader bundle not applied: rules=[%s]", got)
	}
	if blocked, _ := haStatusJSON(t)["auto_promote_blocked"].(string); blocked != "" {
		t.Fatalf("a freshly synced standby reports auto_promote_blocked=%q", blocked)
	}

	p.leader.down()
	for i := 1; i < haStandbyMaxFail; i++ {
		if p.s.guardedTick() {
			t.Fatalf("promoted after %d failed round(s); threshold is %d", i, haStandbyMaxFail)
		}
	}
	if !p.s.guardedTick() {
		t.Fatal("a synced standby must still auto-promote when the leader dies (availability regression)")
	}
	if !p.h.IsLeader() || p.promotes.Load() != 1 {
		t.Fatalf("leader=%v activations=%d, want leader with exactly one activation", p.h.IsLeader(), p.promotes.Load())
	}
	snap, err := dataPlaneGetConfig(t)
	if err != nil {
		t.Fatalf("promoted leader refused GetConfig: %v", err)
	}
	if !snapHasLeaderConfig(snap) {
		t.Fatalf("promoted standby serves rules=[%s] blocked=%v, want the leader's %q + %q",
			ruleNamesOf(snap.PolicyRules), snap.BlockedHosts, eligLeaderRule, eligLeaderHost)
	}
}

// A sync that succeeded longer ago than the lease path's freshness window is
// stale for the legacy path too (one shared bound, not a second threshold).
func TestLegacyAutoFailover_StaleSyncIsNotPromoted(t *testing.T) {
	p := newEligPair(t)
	p.leader.serve(p.good)
	p.s.guardedSyncOnce()
	p.h.mu.Lock()
	p.h.lastSyncOK = time.Now().Add(-haPromoteFreshnessWindow - time.Minute)
	p.h.mu.Unlock()

	if p.outage(haStandbyMaxFail + 1) {
		t.Error("the standby loop exited")
	}
	p.assertStaysUnpromotedStandby(t)
}

// Leader flapping: a refusal is not a latch, and a recovered leader resets the
// streak. Never-synced + outage → refused; leader returns and syncs → eligible;
// short blips never reach the threshold; a real outage then promotes ONCE.
func TestLegacyAutoFailover_LeaderFlapping(t *testing.T) {
	p := newEligPair(t)
	p.leader.down()
	p.s.guardedSyncOnce()
	if p.outage(haStandbyMaxFail + 1) {
		t.Fatal("never-synced standby promoted during the first outage")
	}
	p.assertStaysUnpromotedStandby(t)

	// The leader comes back: the standby finally syncs.
	p.leader.serve(p.good)
	if p.s.guardedTick() {
		t.Fatal("a successful sync round must not exit the loop")
	}
	st := haStatusJSON(t)
	if blocked, _ := st["auto_promote_blocked"].(string); blocked != "" {
		t.Fatalf("after a successful sync the standby still reports auto_promote_blocked=%q", blocked)
	}
	if n, _ := st["sync_fail_count"].(float64); n != 0 {
		t.Fatalf("sync_fail_count = %v after recovery, want 0", n)
	}
	if p.s.manualWarned {
		t.Fatal("recovery must re-arm the page-once latch")
	}

	// Blips shorter than the threshold, each followed by a recovery.
	for i := 0; i < 3; i++ {
		if p.outage(haStandbyMaxFail - 1) {
			t.Fatalf("blip %d: promoted below the failure threshold", i)
		}
		p.leader.serve(p.good)
		if p.s.guardedTick() || p.h.IsLeader() {
			t.Fatalf("blip %d: promoted on recovery", i)
		}
	}

	// A real outage.
	if !p.outage(haStandbyMaxFail) {
		t.Fatal("a synced standby must promote on a real outage after earlier flaps")
	}
	if p.promotes.Load() != 1 {
		t.Fatalf("activations = %d, want exactly 1", p.promotes.Load())
	}
}

// Where "has synced" lives, and what a standby restart does to it.
//
// The evidence is HAState.lastSyncOK — process memory. ha_config.json, the only
// HA file a standby persists, records role/peer/token/preference and NOTHING
// about synchronization. So a restarted standby starts ineligible; if the
// leader dies before the first post-restart sync it does not auto-promote (the
// lease path has always behaved this way). It is not a dead end: one successful
// sync restores eligibility, and manual promotion is never refused.
func TestLegacyAutoFailover_StandbyRestart(t *testing.T) {
	p := newEligPair(t)
	p.leader.serve(p.good)
	p.s.guardedSyncOnce()
	if err := saveHAConfig(&haConfig{Enabled: true, Token: eligSharedSecret, PeerAddr: eligLeaderAddr, Role: "standby", AutoFailover: true}); err != nil {
		t.Fatalf("persist standby config: %v", err)
	}

	// What survives the restart: the persisted HA intent, with no sync record.
	raw, err := os.ReadFile(haConfigPath())
	if err != nil {
		t.Fatalf("read %s: %v", haConfigFile, err)
	}
	var persisted map[string]any
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("decode %s: %v", haConfigFile, err)
	}
	for k := range persisted {
		if strings.Contains(strings.ToLower(k), "sync") {
			t.Fatalf("%s now persists %q: sync evidence became durable — revisit the restart behaviour this test pins", haConfigFile, k)
		}
	}
	cfg, loadErr := loadHAConfig()
	if got := haRestartAction(cfg, loadErr); got != "standby" {
		t.Fatalf("restart action = %q, want standby", got)
	}

	// The restart: a new process, i.e. a new HAState, against the same disk.
	p.h.Stop()
	p.promotes.Store(0)
	p.h = newEligStandby(p.promotes)
	globalHA = p.h
	p.s = newEligLoop(p.h, p.leader)

	// Leader dies before the first post-restart sync.
	p.leader.down()
	p.s.guardedSyncOnce()
	if p.outage(haStandbyMaxFail + 1) {
		t.Fatal("restarted standby promoted before any post-restart sync")
	}
	p.assertStaysUnpromotedStandby(t)

	// Not permanent: the leader returns, one sync restores eligibility…
	p.leader.serve(p.good)
	if p.s.guardedTick() {
		t.Fatal("recovery round exited the loop")
	}
	// …and the next real outage fails over automatically.
	if !p.outage(haStandbyMaxFail) {
		t.Fatal("a restarted standby that re-synced must auto-promote on the next outage")
	}
}

// The restarted standby whose leader never returns is recoverable by hand.
func TestLegacyAutoFailover_RestartedStandbyManualPromotionStillWorks(t *testing.T) {
	p := newEligPair(t)
	p.leader.down()
	p.s.guardedSyncOnce()
	if p.outage(haStandbyMaxFail + 1) {
		t.Fatal("never-synced standby promoted automatically")
	}
	if err := p.h.PromoteManually(); err != nil {
		t.Fatalf("manual promotion is the break-glass and must not be refused on sync grounds: %v", err)
	}
	if !p.h.IsLeader() {
		t.Fatal("manual promotion did not make the node leader")
	}
}

// Concurrent promotion attempts on an INELIGIBLE standby: no interleaving of
// the automatic path promotes it.
func TestLegacyAutoFailover_ConcurrentAutoAttemptsOnUnsyncedStandby(t *testing.T) {
	p := newEligPair(t)
	const n = 16
	var wg sync.WaitGroup
	var exits atomic.Int32
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := newEligLoop(p.h, p.leader) // each caller its own loop state, one shared HAState
			<-start
			if s.onMaxFail() {
				exits.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if exits.Load() != 0 || p.h.IsLeader() || p.promotes.Load() != 0 {
		t.Fatalf("unsynced standby promoted under concurrency: exits=%d leader=%v activations=%d",
			exits.Load(), p.h.IsLeader(), p.promotes.Load())
	}
}

// Concurrent promotion attempts on an ELIGIBLE standby — the automatic path
// racing itself and a manual promotion: exactly one activation.
func TestLegacyAutoFailover_ConcurrentAutoAndManualPromoteOnce(t *testing.T) {
	p := newEligPair(t)
	p.leader.serve(p.good)
	p.s.guardedSyncOnce()
	p.leader.down()

	const n = 12
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := newEligLoop(p.h, p.leader)
			<-start
			if i%4 == 0 {
				_ = p.h.PromoteManually() // loses the race with "role is leader": fine
				return
			}
			s.onMaxFail()
		}(i)
	}
	close(start)
	wg.Wait()
	if !p.h.IsLeader() {
		t.Fatal("no attempt promoted an eligible standby")
	}
	if got := p.promotes.Load(); got != 1 {
		t.Fatalf("Control Plane activated %d times, want exactly 1", got)
	}
}

// The guarantee is equivalent across the two automatic paths BY CONSTRUCTION:
// for every sync state, a lease-mode standby (lease free, so only eligibility
// decides) and a legacy standby reach the same verdict.
func TestAutoFailover_SyncEligibilityParityAcrossLeaseAndLegacy(t *testing.T) {
	cases := []struct {
		name        string
		age         time.Duration // 0 ⇒ never synced
		wantPromote bool
	}{
		{"never synced", 0, false},
		{"synced just now", time.Millisecond, true},
		{"synced inside the freshness window", haPromoteFreshnessWindow - time.Minute, true},
		{"synced just past the freshness window", haPromoteFreshnessWindow + time.Minute, false},
		{"synced long ago", 24 * time.Hour, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tempHADir(t)
			setSync := func(h *HAState) {
				if c.age == 0 {
					return
				}
				h.mu.Lock()
				h.lastSyncOK = time.Now().Add(-c.age)
				h.mu.Unlock()
			}

			lease := leaseStandby(halease.NewFake(time.Minute), "cp-standby")
			setSync(lease)
			t.Cleanup(lease.Stop)
			gotLease := (&standbyLoopState{h: lease, leaderAddr: eligLeaderAddr}).onMaxFail()

			legacy := &HAState{}
			legacy.mu.Lock()
			legacy.role = "standby"
			legacy.autoFailover = true
			legacy.pc = promoteContext{set: true, onPromote: func() error { return nil }}
			legacy.mu.Unlock()
			setSync(legacy)
			t.Cleanup(legacy.Stop)
			gotLegacy := (&standbyLoopState{h: legacy, leaderAddr: eligLeaderAddr}).onMaxFail()

			if gotLease != c.wantPromote || gotLegacy != c.wantPromote {
				t.Fatalf("promote: lease=%v legacy=%v, want both %v", gotLease, gotLegacy, c.wantPromote)
			}
		})
	}
}

// ── Manual promotion: never refused, but never silent ───────────────────────

func postHAPromote(t *testing.T) (code int, resp map[string]any) {
	t.Helper()
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/cluster/ha/promote", http.NoBody)
	w := httptest.NewRecorder()
	apiClusterHAPromote(w, req)
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

// promoteAuditDetail finds this test's cluster.ha-promote entry by its unique
// term (the audit ring is bounded and shared — never assert on its length).
func promoteAuditDetail(t *testing.T, term uint64) string {
	t.Helper()
	want := fmt.Sprintf("(term=%d)", term)
	entries := auditGet()
	for i := range entries {
		if entries[i].Action == "cluster.ha-promote" && strings.Contains(entries[i].Detail, want) {
			return entries[i].Detail
		}
	}
	t.Fatalf("no cluster.ha-promote audit entry carrying %s", want)
	return ""
}

// uniqueTerm gives each run its own leadership term so its audit entry is
// identifiable in the shared ring (also under -count>1).
func uniqueTerm(h *HAState) uint64 {
	term := uint64(time.Now().UnixNano())
	h.mu.Lock()
	h.term = term
	h.mu.Unlock()
	return term + 1 // legacy promote() increments
}

func TestManualPromotion_UnsyncedStandbyPromotesWithExplicitWarning(t *testing.T) {
	p := newEligPair(t)
	p.leader.down()
	p.s.guardedSyncOnce()
	wantTerm := uniqueTerm(p.h)

	code, resp := postHAPromote(t)
	if code != http.StatusOK || resp["role"] != "leader" {
		t.Fatalf("manual promotion of an unsynced standby must still succeed (operator recovery); got %d %v", code, resp)
	}
	warning, _ := resp["warning"].(string)
	if !strings.Contains(warning, "never completed a state sync") {
		t.Errorf("the response must state the standby never synced; warning=%q", warning)
	}
	if detail := promoteAuditDetail(t, wantTerm); !strings.Contains(detail, "never completed a state sync") {
		t.Errorf("the audit entry must record the override; detail=%q", detail)
	}
}

func TestManualPromotion_StaleStandbyWarningNamesTheLastSync(t *testing.T) {
	p := newEligPair(t)
	last := time.Now().Add(-3 * haPromoteFreshnessWindow)
	p.h.mu.Lock()
	p.h.lastSyncOK = last
	p.h.mu.Unlock()
	wantTerm := uniqueTerm(p.h)

	code, resp := postHAPromote(t)
	if code != http.StatusOK {
		t.Fatalf("manual promotion of a stale standby must succeed; got %d %v", code, resp)
	}
	stamp := last.UTC().Format(time.RFC3339)
	if warning, _ := resp["warning"].(string); !strings.Contains(warning, stamp) {
		t.Errorf("warning must name the last successful sync %s; got %q", stamp, warning)
	}
	if detail := promoteAuditDetail(t, wantTerm); !strings.Contains(detail, stamp) {
		t.Errorf("audit detail must name the last successful sync %s; got %q", stamp, detail)
	}
}

func TestManualPromotion_SyncedStandbyCarriesNoWarning(t *testing.T) {
	p := newEligPair(t)
	p.leader.serve(p.good)
	p.s.guardedSyncOnce()
	wantTerm := uniqueTerm(p.h)

	code, resp := postHAPromote(t)
	if code != http.StatusOK {
		t.Fatalf("promote = %d %v", code, resp)
	}
	if w, present := resp["warning"]; present {
		t.Errorf("a synchronized standby's promotion must carry no warning; got %v", w)
	}
	if detail := promoteAuditDetail(t, wantTerm); strings.Contains(detail, "WARNING") {
		t.Errorf("unexpected warning in the audit detail: %q", detail)
	}
}

// The refusal is logged on the same line the lease path uses, and the alert
// path's leader address is sanitised (CWE-117).
func TestLegacyAutoFailover_RefusalIsLoggedSanitised(t *testing.T) {
	sink := captureLoggerForTest(t) // before the fixture: its cleanup must run last
	p := newEligPair(t)
	p.s.leaderAddr = "evil-leader\nHA: now serving as leader (forged)"
	p.leader.down()
	p.s.guardedSyncOnce()
	if p.outage(haStandbyMaxFail) {
		t.Fatal("unsynced standby promoted")
	}
	out := sink.String()
	if !strings.Contains(out, "HA: auto-promotion refused — no successful state sync yet") {
		t.Errorf("missing the refusal log line; got:\n%s", out)
	}
	if !strings.Contains(out, "automatic failover was REFUSED") {
		t.Errorf("missing the operator-facing refusal line; got:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "HA: now serving as leader (forged)") {
			t.Fatalf("leader address reached the log unsanitised (forged line):\n%s", out)
		}
	}
	if errors.Is(context.Cause(p.s.ctx), context.Canceled) {
		t.Fatal("loop context cancelled")
	}
}
