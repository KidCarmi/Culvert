package main

// ha_legacy_authority_test.go — ADR-0064 part C: a restarting LEGACY leader
// resumes only on evidence of exclusive authority; otherwise it fails closed
// for leadership-dependent operations and keeps independent services.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/KidCarmi/Culvert/internal/halease"
)

const (
	revalToken   = "ha-reval-token" // #nosec G101 -- synthetic test fixture
	revalStandby = "cp-standby.reval.example:50051"
)

// revalFixture is a node whose ha_config.json says it LEADS term 5 with a
// standby that has synced from it, about to run its boot resume.
type revalFixture struct {
	probes    atomic.Int32
	peerTerm  uint64 // what the peer answers the probe with
	peerLeads bool   // whether the peer answers as leader at all
}

func newRevalFixture(t *testing.T, standbyAddr string) *revalFixture {
	t.Helper()
	tempHADir(t)
	restore := swapGlobalHA(t)
	resetLegacyAuthorityEvidence()
	f := &revalFixture{}
	prevProbe, prevSpawn := haProbePeerLeader, haIntentRetrySpawn
	haProbePeerLeader = func(*haConfig) (uint64, bool) {
		f.probes.Add(1)
		return f.peerTerm, f.peerLeads
	}
	haIntentRetrySpawn = func(func()) {} // the test drives the retries
	t.Cleanup(func() {
		globalHA.Stop()
		haProbePeerLeader, haIntentRetrySpawn = prevProbe, prevSpawn
		resetLegacyAuthorityEvidence()
		restore()
	})
	globalHA.SetResyncMaterial(resyncCtx(t), ":50051", "", "", "")
	if err := saveHAConfig(&haConfig{
		Enabled: true, Token: revalToken, PeerAddr: "cp-leader.reval.example:50051", Role: "leader",
		AutoFailover: true, Term: 5, StandbyAddr: standbyAddr,
	}); err != nil {
		t.Fatalf("persist leader config: %v", err)
	}
	return f
}

// standbyPoll sends an HASync through the REAL gated handler, as the peer.
func standbyPoll(t *testing.T, body map[string]any) (json.RawMessage, error) {
	t.Helper()
	req, _ := json.Marshal(body)
	h := gatedUnary("HASync", (&controlPlaneServer{}).HASync)
	out, err := h(nil, context.Background(), func(v any) error {
		*(v.(*json.RawMessage)) = req
		return nil
	}, nil)
	if err != nil {
		return nil, err
	}
	return out.(json.RawMessage), nil
}

func haGateRequest(method, path string) *httptest.ResponseRecorder {
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	w := httptest.NewRecorder()
	haWriteGateMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot) // reached the handler
	})).ServeHTTP(w, httptest.NewRequestWithContext(ctx, method, path, http.NoBody))
	return w
}

// assertRevalidating is the fail-closed state: not leader for anything that
// depends on leadership, independent services untouched, condition visible.
func assertRevalidating(t *testing.T) {
	t.Helper()
	if globalHA.IsLeader() || globalHA.Status().Role != "" {
		t.Fatalf("the node took an HA role without evidence of exclusive authority: %+v", globalHA.Status())
	}
	if ok, _ := haServingAllowed(); ok {
		t.Error("leader-gated RPCs must be refused while revalidating")
	}
	if ok, _ := haIssuanceAllowed(); ok {
		t.Error("CA issuance must be refused while revalidating")
	}
	if haLeadershipHeld() {
		t.Error("haLeadershipHeld must be false while revalidating")
	}
	if w := haGateRequest(http.MethodPost, "/api/policy"); w.Code != http.StatusServiceUnavailable ||
		!strings.Contains(w.Body.String(), "ha_write_hold") {
		t.Errorf("a distributed-configuration mutation must be refused with 503 ha_write_hold; got %d %s", w.Code, w.Body.String())
	}
	// Independent services: reads, and the recovery action, are not refused.
	if w := haGateRequest(http.MethodGet, "/api/policy"); w.Code != http.StatusTeapot {
		t.Errorf("a read must reach its handler while revalidating; got %d", w.Code)
	}
	if w := haGateRequest(http.MethodPost, "/api/cluster/ha/promote"); w.Code != http.StatusTeapot {
		t.Errorf("the promote endpoint (the recovery action) must stay reachable; got %d", w.Code)
	}
	rec := httptest.NewRecorder()
	apiHealthz(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", http.NoBody))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/healthz = %d, want 503 so a load balancer does not route data planes here", rec.Code)
	}
	st := haStatusJSON(t)
	if st["authority"] != "revalidating" || st["authority_action"] == nil || st["leadership_held"] != false {
		t.Errorf("the condition and its recovery action must be on the HA status; got %v", st)
	}
}

// Evidence 1: no standby ever synced from this node — nothing else can lead.
func TestLegacyRestart_NoStandbyEverSyncedResumesAtOnce(t *testing.T) {
	f := newRevalFixture(t, "")
	if !resumeLeadershipAttempt() || !globalHA.IsLeader() {
		t.Fatal("a leader with no standby on record must resume without waiting")
	}
	if f.probes.Load() != 0 {
		t.Error("no peer exists to probe")
	}
}

// No evidence: the standby neither polls nor answers. Unreachable proves
// nothing (a healthy standby has no listener; so does a partitioned promoted one).
func TestLegacyRestart_SilentPeerFailsClosed(t *testing.T) {
	newRevalFixture(t, revalStandby)
	for i := 0; i < 3; i++ { // every retry: still no evidence, still gated
		if resumeLeadershipAttempt() {
			t.Fatalf("attempt %d decided the intent with no evidence", i)
		}
		assertRevalidating(t)
	}
}

// Evidence 2: the standby polls. The poll establishes authority AND is answered.
func TestLegacyRestart_StandbyPollEstablishesAuthorityAndIsAnswered(t *testing.T) {
	newRevalFixture(t, revalStandby)
	origStore := globalConfigStore
	t.Cleanup(func() { globalConfigStore = origStore; gcMarshalCache.reset(); gcDeltaRemainderCache.reset() })
	globalConfigStore = &ConfigStore{}
	gcMarshalCache.reset()
	gcDeltaRemainderCache.reset()
	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: []string{"reval.example"}}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if resumeLeadershipAttempt() {
		t.Fatal("precondition: no evidence yet")
	}
	assertRevalidating(t)

	// Not evidence: a wrong token; another restarting leader's probe; a
	// standby of a LATER term than ours.
	for name, body := range map[string]map[string]any{
		"wrong token":             {"token": "nope", "role": "standby", "term": 5},
		"another leader's probe":  {"token": revalToken, "role": haRoleRevalidating, "term": 5},
		"standby of a later term": {"token": revalToken, "role": "standby", "term": 9},
	} {
		if _, err := standbyPoll(t, body); status.Code(err) != codes.Unavailable {
			t.Fatalf("%s: want the poll refused (Unavailable), got %v", name, err)
		}
		if globalHA.IsLeader() {
			t.Fatalf("%s established leadership", name)
		}
	}

	raw, err := standbyPoll(t, map[string]any{"token": revalToken, "role": "standby", "term": 5, "standby_addr": revalStandby})
	if err != nil {
		t.Fatalf("the standby's own poll must be ANSWERED (a refusal would count toward its failover): %v", err)
	}
	var bundle HAStateBundle
	if json.Unmarshal(raw, &bundle) != nil || bundle.LeaderTerm != 5 {
		t.Fatalf("want a bundle from the leader of term 5; got term %d", bundle.LeaderTerm)
	}
	if !globalHA.IsLeader() || globalHA.legacyRevalidationPending() {
		t.Fatal("the standby's poll must establish leadership automatically, with no operator act")
	}
	if st := haStatusJSON(t); st["authority"] != nil || st["leadership_held"] != true {
		t.Errorf("status must clear once authority is established; got %v", st)
	}
	if w := haGateRequest(http.MethodPost, "/api/policy"); w.Code != http.StatusTeapot {
		t.Errorf("mutations must be accepted again; got %d", w.Code)
	}
}

// An older standby build sends no role: only a standby calls HASync, so it counts.
func TestLegacyRestart_OldStandbyPollWithoutRoleCounts(t *testing.T) {
	newRevalFixture(t, revalStandby)
	resumeLeadershipAttempt()
	_, _ = standbyPoll(t, map[string]any{"token": revalToken, "standby_addr": revalStandby})
	if !globalHA.IsLeader() {
		t.Fatal("a poll from a standby build that sends no role must establish authority")
	}
}

// Evidence 3: the peer promoted while this node was down. Join it, automatically,
// idempotently — never two leaders.
func TestLegacyRestart_PeerLeadsLaterTermJoinsAsStandby(t *testing.T) {
	f := newRevalFixture(t, revalStandby)
	f.peerLeads, f.peerTerm = true, 6
	if !resumeLeadershipAttempt() {
		t.Fatal("joining the peer decides the intent")
	}
	st := globalHA.Status()
	if st.Role != "standby" || st.PeerAddr != revalStandby {
		t.Fatalf("want a standby of the promoted peer; got role=%q peer=%q", st.Role, st.PeerAddr)
	}
	cfg, err := loadHAConfig()
	if err != nil || cfg.Role != "standby" {
		t.Fatalf("the standby role must be persisted (a second restart must not resume as leader); got %+v err=%v", cfg, err)
	}
	if _, gated := globalHA.intentGate(); gated {
		t.Error("the gate must clear once the node holds the standby role")
	}
	// Idempotent: another attempt changes nothing.
	if !resumeLeadershipAttempt() || globalHA.Status().Role != "standby" {
		t.Fatal("a repeated attempt must leave the node a standby")
	}
}

// The peer serves as leader at a term NOT above ours: two leaders, neither
// provably later. No automatic winner.
func TestLegacyRestart_PeerLeadsSameTermFailsClosed(t *testing.T) {
	f := newRevalFixture(t, revalStandby)
	f.peerLeads, f.peerTerm = true, 5
	if resumeLeadershipAttempt() {
		t.Fatal("must not decide")
	}
	assertRevalidating(t)
	if r, _ := globalHA.intentGate(); !strings.Contains(r, "two leaders") {
		t.Errorf("the reason must name the conflict; got %q", r)
	}
}

// Break-glass: the standby is gone for good; the operator asserts leadership.
func TestLegacyRestart_OperatorAssertsLeadership(t *testing.T) {
	newRevalFixture(t, revalStandby)
	resumeLeadershipAttempt()
	assertRevalidating(t)
	code, resp := postHAPromote(t)
	if code != http.StatusOK || resp["role"] != "leader" || !globalHA.IsLeader() {
		t.Fatalf("an operator must be able to assert leadership; got %d %v", code, resp)
	}
	if w, _ := resp["warning"].(string); !strings.Contains(w, "two leaders") {
		t.Errorf("the response must state the risk; got %q", w)
	}
	if d := promoteAuditDetail(t, 5); !strings.Contains(d, "operator asserted leadership") {
		t.Errorf("audit detail = %q", d)
	}
}

// Lease mode: the lease is the authority; this path never probes or waits.
func TestLegacyRestart_LeaseModeIsNotSubjectToIt(t *testing.T) {
	f := newRevalFixture(t, revalStandby)
	if v := legacyRestartAuthority(&haConfig{StandbyAddr: revalStandby, Term: 5}); v != legacyUndecided {
		t.Fatalf("control: legacy mode with a silent peer must be undecided, got %v", v)
	}
	n := f.probes.Load()
	globalHA.SetLeaseProvider(halease.NewFake(time.Minute), "cp-me")
	if v := legacyRestartAuthority(&haConfig{StandbyAddr: revalStandby, Term: 5}); v != legacyProceed {
		t.Fatalf("lease mode must proceed to the lease-gated resume, got %v", v)
	}
	if f.probes.Load() != n {
		t.Error("lease mode must not probe the peer")
	}
}

// A leader whose listener is up before the node is ready refuses with the
// agreed "starting" status. For a legacy standby that is an ANSWERED round: a
// restarting leader must never trigger its live standby's promotion.
func TestLegacyStandby_StartingLeaderIsAnAnsweredRound(t *testing.T) {
	p := newEligPair(t)
	p.leader.serve(p.good)
	p.s.guardedSyncOnce() // synced: eligible to promote on a real outage
	p.s.client = &DataPlaneClient{callForTest: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		return nil, status.Error(codes.Unavailable, "HASync refused: "+haNodeStartingMarker+": stores are loading")
	}}
	for i := 0; i < haStandbyMaxFail*3; i++ {
		if p.s.guardedTick() || p.h.IsLeader() {
			t.Fatalf("round %d: the standby promoted while its leader was merely starting", i)
		}
	}
	if got := p.h.Status().SyncFailCount; got != 0 {
		t.Errorf("sync_fail_count = %d, want 0: a starting leader answered", got)
	}
	// Control: an ordinary Unavailable is still an unreachable round.
	p.s.client = &DataPlaneClient{callForTest: p.leader.call}
	if !p.outage(haStandbyMaxFail) {
		t.Fatal("control: a leader that does not answer must still be replaced")
	}
}
