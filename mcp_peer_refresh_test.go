package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// Governed peer-refresh behaviour (blocker 11, §7). The structural caller walls live in
// mcp_peer_refresh_wall_test.go; these drive the path.

// refreshPeer is a scriptable upstream for the refresh seam. It records what it was asked and can
// block, so the single-flight rule can be driven deterministically rather than by timing.
type refreshPeer struct {
	mu      sync.Mutex
	calls   int
	methods []string
	result  string
	err     error
	gate    chan struct{} // when non-nil, Call blocks until it is closed
}

func (p *refreshPeer) Call(_ context.Context, _ upstreamclient.Target, method string, _ json.RawMessage, _ upstreamclient.CallOptions) (*upstreamclient.Response, error) {
	p.mu.Lock()
	p.calls++
	p.methods = append(p.methods, method)
	gate, err, res := p.gate, p.err, p.result
	p.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if err != nil {
		return nil, err
	}
	if res == "" {
		res = `{"tools":[]}`
	}
	return &upstreamclient.Response{ID: jsonrpc.ID{Kind: jsonrpc.IDString, Str: "d"}, Result: json.RawMessage(res), RawBytes: []byte(res)}, nil
}

func (p *refreshPeer) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// useRefreshPeer installs a scripted upstream for the duration of one test.
func useRefreshPeer(t *testing.T, p *refreshPeer) {
	t.Helper()
	prev := mcpPeerRefreshUpstream
	mcpPeerRefreshUpstream = func() (execution.UpstreamCaller, error) { return p, nil }
	t.Cleanup(func() { mcpPeerRefreshUpstream = prev })
}

// refreshInventory publishes a one-server, one-tool inventory whose tool metadata is `schema`,
// and returns the live stores. The server carries a pinned identity, because a server without one
// cannot be observed at all.
func refreshInventory(t *testing.T, schema string) (*registry.Registry, *catalog.Catalog) {
	t.Helper()
	restoreMCPInventory(t)
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"controlled","endpoint":"e","pinned_identity":"id","enabled":true,
	   "tools":[{"name":"t","input_schema":` + schema + `}]}
	]}`))
	if err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)
	return reg, cat
}

func refreshRecord(t *testing.T, cat *catalog.Catalog) catalog.ToolRecord {
	t.Helper()
	rec, ok := cat.Current().Get(catalog.ToolKey{Server: "controlled", Name: "t"})
	if !ok {
		t.Fatal("expected the controlled tool to be present")
	}
	return rec
}

// TestPeerRefresh_TurnsASeededRecordIntoAnObservedOne is the positive control for this whole
// file. Every negative below could be satisfied by a refresh that never succeeds at all, which
// would leave blocker 11 permanently unclosable — strictly worse than the defect.
func TestPeerRefresh_TurnsASeededRecordIntoAnObservedOne(t *testing.T) {
	_, cat := refreshInventory(t, `{"type":"object"}`)
	if got := refreshRecord(t, cat).Provenance(); got != catalog.OperatorSeeded {
		t.Fatalf("premise: provisioning must land a SEEDED record, got %v", got)
	}
	peer := &refreshPeer{result: `{"tools":[{"name":"t","inputSchema":{"type":"object"}}]}`}
	useRefreshPeer(t, peer)

	out, reason, err := mcpRefreshPeerObservation(context.Background(), "controlled")
	if reason != "" || err != nil {
		t.Fatalf("refresh must succeed, got reason=%q err=%v", reason, err)
	}
	if peer.callCount() != 1 {
		t.Fatalf("exactly one upstream call, got %d", peer.callCount())
	}
	if got := peer.methods[0]; got != "tools/list" {
		t.Fatalf("a refresh observes via tools/list, got %q", got)
	}
	rec := refreshRecord(t, cat)
	if rec.Provenance() != catalog.PeerObserved {
		t.Fatalf("after an authenticated refresh the record must be PeerObserved, got %v", rec.Provenance())
	}
	if rec.Observed.Identity != registry.Identity("id") {
		t.Fatalf("the observation must carry the VERIFIED pin, got %q", rec.Observed.Identity)
	}
	if out.Observations != 1 || out.Revision == 0 {
		t.Fatalf("bounded outcome must report the observation count and revision, got %+v", out)
	}
}

// TestPeerRefresh_TakesOnlyAServerID pins §1 at the engine boundary: the ONLY caller-supplied
// value is the server id. Everything else is resolved from authoritative state, so there is no
// input an operator could use to make the catalog assert something the peer did not say.
//
// It is checked by SIGNATURE rather than by trying values, because the point is that no such
// field exists to try.
func TestPeerRefresh_TakesOnlyAServerID(t *testing.T) {
	// A compile-time assertion: the engine's shape is (ctx, serverID) and nothing more. If a
	// future change adds an endpoint, identity, fingerprint or timestamp parameter, this stops
	// building — which is the point.
	var f func(context.Context, string) (mcpPeerRefreshOutcome, string, error) = mcpRefreshPeerObservation
	_ = f
	if _, reason, _ := mcpRefreshPeerObservation(context.Background(), ""); reason != mcpPeerRefreshReasonNoServerID {
		t.Fatalf("an empty server id must be refused, got %q", reason)
	}
}

// TestPeerRefresh_FailedDiscoveryChangesNothing is §9, and it is four separate claims because
// three of them are ways an implementation could be "helpful" and wrong.
func TestPeerRefresh_FailedDiscoveryChangesNothing(t *testing.T) {
	_, cat := refreshInventory(t, `{"type":"object"}`)
	// Establish a real observation first, so the failure has something it could damage.
	good := &refreshPeer{result: `{"tools":[{"name":"t","inputSchema":{"type":"object"}}]}`}
	useRefreshPeer(t, good)
	if _, reason, err := mcpRefreshPeerObservation(context.Background(), "controlled"); reason != "" || err != nil {
		t.Fatalf("premise: the first observation must land, got %q %v", reason, err)
	}
	before := refreshRecord(t, cat)
	if before.Provenance() != catalog.PeerObserved {
		t.Fatal("premise: the record must be observed before the failure")
	}
	revBefore := cat.Current().Revision()

	// Now the peer stops answering.
	bad := &refreshPeer{err: mcperr.New(mcperr.ReasonUpstreamTimeout, "test", "unreachable")}
	useRefreshPeer(t, bad)
	_, reason, err := mcpRefreshPeerObservation(context.Background(), "controlled")
	if reason != mcpPeerRefreshReasonFailed {
		t.Fatalf("a failed discovery must report the bounded failure reason, got %q", reason)
	}
	if err == nil {
		t.Fatal("a failed discovery must return the underlying error to the caller for logging")
	}

	after := refreshRecord(t, cat)
	if !after.Observed.At.Equal(before.Observed.At) {
		t.Fatalf("a failed discovery must NOT advance freshness: %v -> %v", before.Observed.At, after.Observed.At)
	}
	if after.Provenance() != catalog.PeerObserved {
		t.Fatal("a failed discovery must NOT erase the last good observation — the peer being " +
			"unreachable is not evidence about what it advertises, in either direction")
	}
	if !after.Fingerprint.Equal(before.Fingerprint) {
		t.Fatal("a failed discovery must not fabricate a fingerprint")
	}
	if cat.Current().Revision() != revBefore {
		t.Fatal("a failed discovery must publish no new catalog snapshot")
	}
}

// TestPeerRefresh_SingleFlightPerServer is §8: a second concurrent refresh for the SAME server is
// refused deterministically rather than becoming a second dial. The first call is held open on a
// gate so the overlap is exact, not a timing hope.
func TestPeerRefresh_SingleFlightPerServer(t *testing.T) {
	refreshInventory(t, `{"type":"object"}`)
	gate := make(chan struct{})
	peer := &refreshPeer{result: `{"tools":[{"name":"t","inputSchema":{"type":"object"}}]}`, gate: gate}
	useRefreshPeer(t, peer)

	entered := make(chan struct{})
	done := make(chan string, 1)
	go func() {
		close(entered)
		_, reason, _ := mcpRefreshPeerObservation(context.Background(), "controlled")
		done <- reason
	}()
	<-entered
	// Wait until the first refresh is provably inside the dial.
	deadline := time.After(5 * time.Second)
	for peer.callCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("the first refresh never reached the upstream call")
		default:
		}
	}

	_, reason, _ := mcpRefreshPeerObservation(context.Background(), "controlled")
	if reason != mcpPeerRefreshReasonInProgress {
		t.Fatalf("a concurrent refresh of the same server must be refused, got %q", reason)
	}
	if got := peer.callCount(); got != 1 {
		t.Fatalf("the refused refresh must NOT have dialed: %d calls", got)
	}

	close(gate)
	if r := <-done; r != "" {
		t.Fatalf("the first refresh should have succeeded, got %q", r)
	}

	// And the lock is released: a later refresh works.
	if _, r, _ := mcpRefreshPeerObservation(context.Background(), "controlled"); r != "" {
		t.Fatalf("after the in-flight refresh completed, a new one must be allowed, got %q", r)
	}
}

// TestPeerRefresh_RefusesWhenInventoryIsNotConfigured pins the fail-closed default: with no
// inventory there is no authoritative endpoint or pin to resolve, so there is nothing to observe
// and nothing is dialed.
func TestPeerRefresh_RefusesWhenInventoryIsNotConfigured(t *testing.T) {
	restoreMCPInventory(t)
	publishMCPInventory(mcpInvNotConfigured, "", nil, nil)
	peer := &refreshPeer{}
	useRefreshPeer(t, peer)
	_, reason, _ := mcpRefreshPeerObservation(context.Background(), "controlled")
	if reason != mcpPeerRefreshReasonNotConfigured {
		t.Fatalf("expected %q, got %q", mcpPeerRefreshReasonNotConfigured, reason)
	}
	if peer.callCount() != 0 {
		t.Fatal("nothing may be dialed when there is no authoritative inventory")
	}
}

// TestPeerRefresh_UnregisteredServerIsNeverDialed pins §1's "exact server only": a server id that
// is not in the authoritative registry produces no outbound call at all. Without this the
// endpoint would effectively be caller-influenced — the thing §1 forbids.
func TestPeerRefresh_UnregisteredServerIsNeverDialed(t *testing.T) {
	refreshInventory(t, `{"type":"object"}`)
	peer := &refreshPeer{}
	useRefreshPeer(t, peer)
	_, reason, _ := mcpRefreshPeerObservation(context.Background(), "not-a-server")
	if reason != mcpPeerRefreshReasonUnregistered {
		t.Fatalf("expected %q, got %q", mcpPeerRefreshReasonUnregistered, reason)
	}
	if peer.callCount() != 0 {
		t.Fatal("an unregistered server must never be dialed")
	}
}

// TestPeerRefresh_PeerDriftIsIngestedAndQuarantined is §10's second half. A refresh that finds a
// CHANGED peer records the change and lets the ordinary drift machinery run; it does not approve,
// promote or otherwise bless what it found.
func TestPeerRefresh_PeerDriftIsIngestedAndQuarantined(t *testing.T) {
	_, cat := refreshInventory(t, `{"type":"object"}`)
	seeded := refreshRecord(t, cat)

	// The peer now advertises a DIFFERENT schema than the operator declared.
	peer := &refreshPeer{result: `{"tools":[{"name":"t","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}}]}`}
	useRefreshPeer(t, peer)
	if _, reason, err := mcpRefreshPeerObservation(context.Background(), "controlled"); reason != "" || err != nil {
		t.Fatalf("refresh must succeed, got %q %v", reason, err)
	}

	got := refreshRecord(t, cat)
	if got.Fingerprint.Equal(seeded.Fingerprint) {
		t.Fatal("the peer advertised a different tool; the catalog must have moved off the seeded fingerprint")
	}
	if got.Provenance() != catalog.PeerObserved {
		t.Fatalf("the new record must be peer-observed, got %v", got.Provenance())
	}
	if got.Eligibility == catalog.Usable {
		t.Fatal("a refresh must never produce Usable — observation is not approval. The changed " +
			"tool has to go back through the ordinary trust path.")
	}
}

// TestPeerRefresh_RepeatObservationRefreshesWithoutChangingTheFingerprint is §10's first half,
// driven through the production engine rather than the catalog API: an unchanged peer yields a
// NEW observation timestamp and the same fingerprint.
func TestPeerRefresh_RepeatObservationRefreshesWithoutChangingTheFingerprint(t *testing.T) {
	_, cat := refreshInventory(t, `{"type":"object"}`)
	peer := &refreshPeer{result: `{"tools":[{"name":"t","inputSchema":{"type":"object"}}]}`}
	useRefreshPeer(t, peer)

	if _, r, _ := mcpRefreshPeerObservation(context.Background(), "controlled"); r != "" {
		t.Fatalf("first refresh: %q", r)
	}
	first := refreshRecord(t, cat)
	// The engine stamps from the wall clock, so give it a measurable gap rather than asserting
	// on sub-nanosecond ordering.
	time.Sleep(2 * time.Millisecond)
	if _, r, _ := mcpRefreshPeerObservation(context.Background(), "controlled"); r != "" {
		t.Fatalf("second refresh: %q", r)
	}
	second := refreshRecord(t, cat)

	if !second.Fingerprint.Equal(first.Fingerprint) {
		t.Fatal("an unchanged peer must not move the fingerprint")
	}
	if !second.Observed.At.After(first.Observed.At) {
		t.Fatalf("re-observing an unchanged peer must advance the observation: %v -> %v",
			first.Observed.At, second.Observed.At)
	}
}

// TestPeerRefresh_UpstreamConstructionFailureIsBounded pins that a transport that cannot even be
// built is reported as a bounded reason rather than surfacing an arbitrary error to the operator
// surface or the audit record.
func TestPeerRefresh_UpstreamConstructionFailureIsBounded(t *testing.T) {
	refreshInventory(t, `{"type":"object"}`)
	prev := mcpPeerRefreshUpstream
	mcpPeerRefreshUpstream = func() (execution.UpstreamCaller, error) {
		return nil, errors.New("tls material unavailable: /very/specific/path")
	}
	t.Cleanup(func() { mcpPeerRefreshUpstream = prev })

	_, reason, err := mcpRefreshPeerObservation(context.Background(), "controlled")
	if reason != mcpPeerRefreshReasonTransport {
		t.Fatalf("expected %q, got %q", mcpPeerRefreshReasonTransport, reason)
	}
	if err == nil {
		t.Fatal("the cause must still reach the caller for logging, even though the reason is bounded")
	}
}
