package main

// session_revocation_cp_merge_bound_test.go — the per-node bound on what a
// peer's SyncRevocations push may write into the CONTROL PLANE'S OWN
// revocation list.
//
// THE DEFECT. CHAOS-68 gave the CP handler a second consumer of a Data Plane's
// pushed entries: `mergeAndPersistRevocations` writes them into the CP's own
// `sessionRevoked`, which is what `Decode` enforces for the admin UI and what
// `SaveRevocations` persists. `globalRevAggregator.Update` already bounded the
// same slice at `maxRevocationsPerNode` for the FAN-OUT slot and dropped the
// overflow with a counter — but it did not return the bounded set, and the new
// consumer was handed the raw `req.Entries`. So the cap governed what the CP
// broadcast and not what it enforced and persisted.
//
// The CP accepts `maxClusterInboundMsgSize` (16 MiB) on this RPC and a minimal
// entry marshals to 33 bytes, so ONE request from one enrolled node carries
// ~490k entries against a GLOBAL `MaxRevocationEntries` of 65536. Past that
// cap `admitUntrustedLocked` refuses every further untrusted entry with
// `RevokeCapacity` — so a genuine logout performed on another Data Plane is no
// longer honoured on the Control Plane. That is the exact fail-OPEN direction
// CHAOS-68 exists to close, reached from inside the fleet.
//
// The fix is structural, not a second cap: `Update` returns the set it
// retained and the handler merges THAT, so one bound governs both consumers
// and a future consumer inherits it.

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// cpMergeBoundSetup isolates every process-global this path writes: the
// revocation list, the aggregator, the refusal/drop counters and the health
// record. clusterInsecure stands in for mTLS so verifyNode admits the claimed
// node id without an enrollment fixture; the AUTHENTICATION ordering itself is
// asserted separately by TestCPMergeBound_UnverifiedNodeMergesNothing.
func cpMergeBoundSetup(t *testing.T) {
	t.Helper()
	withChaos68Revocations(t)
	withChaos68Aggregator(t)
	prev := clusterInsecure
	clusterInsecure = true
	t.Cleanup(func() { clusterInsecure = prev })
}

// cpMergeBoundPush drives the REAL handler, so the bound is measured where
// production applies it rather than on a helper.
func cpMergeBoundPush(t *testing.T, s *controlPlaneServer, nodeID string, entries []RevocationEntry) {
	t.Helper()
	body, err := json.Marshal(revocationSyncRequest{NodeID: nodeID, Entries: entries})
	if err != nil {
		t.Fatalf("marshal push: %v", err)
	}
	if _, err := s.SyncRevocations(context.Background(), body); err != nil {
		t.Fatalf("SyncRevocations(%s): %v", nodeID, err)
	}
}

func cpMergeBoundEntries(prefix string, n int, expiry int64) []RevocationEntry {
	out := make([]RevocationEntry, n)
	for i := range out {
		out[i] = RevocationEntry{Token: fmt.Sprintf("%s-%07d", prefix, i), Expiry: expiry}
	}
	return out
}

// THE REGRESSION GATE. One node's oversized push must not put more than the
// per-node cap into the CP's own list. Fails on the pre-fix handler, which
// merged all 2x entries.
func TestCPMergeBound_OnePeerPushCannotExceedThePerNodeCap(t *testing.T) {
	cpMergeBoundSetup(t)
	exp := time.Now().Add(time.Hour).Unix()
	s := &controlPlaneServer{}

	cpMergeBoundPush(t, s, "dp-greedy", cpMergeBoundEntries("greedy", maxRevocationsPerNode*2, exp))

	if got := sessionRevoked.Count(); got > maxRevocationsPerNode {
		t.Fatalf("the CP's own revocation list holds %d entries from one peer; the per-node cap is %d", got, maxRevocationsPerNode)
	}
	// The overflow is accounted for, not silently absent: a dropped revocation
	// means cluster-wide revocation is incomplete and must be visible.
	if clusterRevocationDrops.Load() == 0 {
		t.Error("the refused overflow was not counted in clusterRevocationDrops")
	}
	// CONTROL: the bound is the per-node cap, not zero — the push still landed.
	if got := sessionRevoked.Count(); got != maxRevocationsPerNode {
		t.Errorf("merged %d entries; want exactly the cap %d", got, maxRevocationsPerNode)
	}
}

// THE SECURITY PROPERTY the cap protects, stated as the fail-open it prevents.
//
// Pre-fix, one node could fill the GLOBAL MaxRevocationEntries in a single
// request, after which `admitUntrustedLocked` refused every later untrusted
// entry with RevokeCapacity — so an HONEST node's logout stopped being
// honoured on the Control Plane.
func TestCPMergeBound_AGreedyPeerCannotLockOutAnHonestNodesRevocation(t *testing.T) {
	cpMergeBoundSetup(t)
	exp := time.Now().Add(time.Hour).Unix()
	s := &controlPlaneServer{}

	// A single push that, unbounded, would saturate the global cap outright.
	cpMergeBoundPush(t, s, "dp-greedy",
		cpMergeBoundEntries("flood", session.MaxRevocationEntries+1024, exp))

	// Now an honest Data Plane reports a real logout.
	const honest = "honest-logout-token"
	cpMergeBoundPush(t, s, "dp-honest", []RevocationEntry{{Token: honest, Expiry: exp}})

	if !sessionRevoked.IsRevoked(honest) {
		t.Fatal("FAIL-OPEN: a genuine logout from another node is not honoured on the Control Plane " +
			"because one peer's push had filled the global revocation cap")
	}
	if got := session.Refused(session.RevokeCapacity); got != 0 {
		t.Errorf("capacity refusals = %d; the per-node cap should have kept the global cap far away", got)
	}
}

// POSITIVE CONTROL. An ordinary under-cap push must merge in FULL and be
// enforced — the bound must not cost a legitimate peer anything.
func TestCPMergeBound_OrdinaryPushIsMergedInFullAndEnforced(t *testing.T) {
	cpMergeBoundSetup(t)
	exp := time.Now().Add(time.Hour).Unix()
	s := &controlPlaneServer{}

	entries := cpMergeBoundEntries("ordinary", 64, exp)
	cpMergeBoundPush(t, s, "dp-1", entries)

	if got := sessionRevoked.Count(); got != len(entries) {
		t.Fatalf("merged %d of %d ordinary entries", got, len(entries))
	}
	for i := range entries {
		if !sessionRevoked.IsRevoked(entries[i].Token) {
			t.Fatalf("entry %q was merged but is not enforced", entries[i].Token)
		}
	}
	if clusterRevocationDrops.Load() != 0 {
		t.Error("an under-cap push dropped entries")
	}
}

// BOUNDARY. Exactly the cap merges with nothing dropped; one more drops
// exactly one. Pins the comparison as >= rather than >.
func TestCPMergeBound_Boundary(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	for _, tc := range []struct {
		name        string
		n           int
		wantMerged  int
		wantDropped int64
	}{
		{"exactly the cap", maxRevocationsPerNode, maxRevocationsPerNode, 0},
		{"one past the cap", maxRevocationsPerNode + 1, maxRevocationsPerNode, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cpMergeBoundSetup(t)
			s := &controlPlaneServer{}
			cpMergeBoundPush(t, s, "dp-edge", cpMergeBoundEntries("edge", tc.n, exp))
			if got := sessionRevoked.Count(); got != tc.wantMerged {
				t.Errorf("merged %d entries; want %d", got, tc.wantMerged)
			}
			if got := clusterRevocationDrops.Load(); got != tc.wantDropped {
				t.Errorf("dropped %d entries; want %d", got, tc.wantDropped)
			}
		})
	}
}

// MALFORMED / OVERSIZE INPUT. The field-length bounds Update applies must also
// govern what reaches the CP's own list, for BOTH free-form wire fields — a
// bound on the token is no bound if the sibling User field is unbounded.
func TestCPMergeBound_OversizeFieldsNeverReachTheControlPlaneList(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	long := make([]byte, session.MaxRevocationTokenLen+1)
	for i := range long {
		long[i] = 'x'
	}
	for _, tc := range []struct {
		name  string
		entry RevocationEntry
	}{
		{"oversize token", RevocationEntry{Token: string(long), Expiry: exp}},
		{"oversize user", RevocationEntry{Token: "user:" + string(long), User: string(long), Expiry: exp}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cpMergeBoundSetup(t)
			s := &controlPlaneServer{}
			cpMergeBoundPush(t, s, "dp-malformed", []RevocationEntry{tc.entry})
			if got := sessionRevoked.Count(); got != 0 {
				t.Errorf("an oversize entry reached the CP's token list (%d entries)", got)
			}
			if got := sessionRevoked.UserCount(); got != 0 {
				t.Errorf("an oversize entry reached the CP's user list (%d entries)", got)
			}
			if clusterRevocationDrops.Load() == 0 {
				t.Error("the oversize refusal was not counted")
			}
		})
	}
}

// ACCOUNT-ENTRY PARITY. CHAOS-68 put USER revocations on the same wire. The
// per-node cap must govern them too, or the token half is bounded while its
// twin is not — the shape this repo keeps recording.
func TestCPMergeBound_AccountEntriesAreBoundedToo(t *testing.T) {
	cpMergeBoundSetup(t)
	exp := time.Now().Add(time.Hour).Unix()
	s := &controlPlaneServer{}

	entries := make([]RevocationEntry, maxRevocationsPerNode*2)
	for i := range entries {
		user := fmt.Sprintf("acct-%07d", i)
		entries[i] = RevocationEntry{Token: "user:" + user, User: user, Expiry: exp}
	}
	cpMergeBoundPush(t, s, "dp-accounts", entries)

	if got := sessionRevoked.UserCount(); got > maxRevocationsPerNode {
		t.Fatalf("the CP holds %d account revocations from one peer; the per-node cap is %d", got, maxRevocationsPerNode)
	}
}

// CONCURRENCY. Several nodes push at once (the production cadence is every 3 s
// per node). Each node is bounded independently, the handler is race-free
// under -race, and the shared list stays coherent.
func TestCPMergeBound_ConcurrentPeerPushesStayBounded(t *testing.T) {
	cpMergeBoundSetup(t)
	exp := time.Now().Add(time.Hour).Unix()
	s := &controlPlaneServer{}

	const nodes = 8
	var wg sync.WaitGroup
	for n := range nodes {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			node := fmt.Sprintf("dp-%d", n)
			body, err := json.Marshal(revocationSyncRequest{
				NodeID:  node,
				Entries: cpMergeBoundEntries(node, 512, exp),
			})
			if err != nil {
				t.Errorf("marshal %s: %v", node, err)
				return
			}
			if _, err := s.SyncRevocations(context.Background(), body); err != nil {
				t.Errorf("SyncRevocations(%s): %v", node, err)
			}
		}(n)
	}
	wg.Wait()

	// Every node was under the cap, so nothing may have been dropped and every
	// node's entries must be present: the bound is PER NODE, not a shared pool.
	if got := clusterRevocationDrops.Load(); got != 0 {
		t.Errorf("concurrent under-cap pushes dropped %d entries", got)
	}
	if got := sessionRevoked.Count(); got != nodes*512 {
		t.Errorf("the CP holds %d entries; want %d from %d nodes", got, nodes*512, nodes)
	}
}

// AUTHENTICATION ORDERING. The bound is a second line, never the first one:
// an unverified caller must be refused before anything is merged at all.
func TestCPMergeBound_UnverifiedNodeMergesNothing(t *testing.T) {
	withChaos68Revocations(t)
	withChaos68Aggregator(t)
	prev := clusterInsecure
	clusterInsecure = false // mTLS required; the test context carries no peer cert
	t.Cleanup(func() { clusterInsecure = prev })

	s := &controlPlaneServer{}
	body, err := json.Marshal(revocationSyncRequest{
		NodeID:  "dp-unverified",
		Entries: []RevocationEntry{{Token: "unverified", Expiry: time.Now().Add(time.Hour).Unix()}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := s.SyncRevocations(context.Background(), body); err == nil {
		t.Fatal("an unauthenticated SyncRevocations was accepted")
	}
	if got := sessionRevoked.Count(); got != 0 {
		t.Fatalf("an unauthenticated push merged %d entries", got)
	}
}
