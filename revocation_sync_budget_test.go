package main

// revocation_sync_budget_test.go — AU-50 (Codex P1, PR #1437) and AU-71.
//
// AU-50: a Data Plane's SyncRevocations REQUEST rides the 16 MiB inbound
// bound, and it carried the node's whole live list — including every fleet
// entry it had merged — so past 16 MiB every sync failed ResourceExhausted
// and the node could neither publish nor learn a revocation. AU-71: the CP's
// reply had the same shape against the 128 MiB frame.
//
// The gates below prove the three properties the fix claims, through the REAL
// gRPC limits where it matters:
//
//  1. a list whose encoding exceeds 16 MiB still syncs, and every request is
//     inside the cap (the negative control proves the fixture really exceeds
//     it: the pre-fix full-list request is refused by gRPC);
//  2. this node's OWN logouts ride the very first tick;
//  3. nothing is lost: every live entry reaches the CP over later ticks, and
//     the local list never shrinks — a planner that silently dropped its tail
//     (a fixed prefix, AU-40's HA trim shape) fails the coverage gate, which
//     TestAU50_ControlFixedPrefixStarvesTheTail demonstrates.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// au50Learned builds n learned (gossip) entries whose tokens are tokLen bytes.
// Labels are built from parameters, not literals, to keep gosec's G101
// heuristic off fixture strings.
func au50Learned(prefix string, n, tokLen int, expiry int64) []RevocationEntry {
	out := make([]RevocationEntry, n)
	for i := range out {
		label := fmt.Sprintf("%s-%06d-", prefix, i)
		out[i] = RevocationEntry{Token: label + strings.Repeat("x", max(0, tokLen-len(label))), Expiry: expiry}
	}
	return out
}

func au50Tokens(es []RevocationEntry) map[string]struct{} {
	m := make(map[string]struct{}, len(es))
	for i := range es {
		m[es[i].Token] = struct{}{}
	}
	return m
}

func au50DecodeRequest(t *testing.T, b []byte) revocationSyncRequest {
	t.Helper()
	var req revocationSyncRequest
	if err := json.Unmarshal(b, &req); err != nil {
		t.Fatalf("the budgeted request is not the wire shape the CP decodes: %v", err)
	}
	return req
}

// DEFECT (AU-50), end to end through the production gRPC limits.
func TestAU50_RevocationListOverTheRequestCapStillSyncs(t *testing.T) {
	withChaos68Revocations(t)
	withChaos68Aggregator(t)
	prevInsecure := clusterInsecure
	clusterInsecure = true // bufconn carries no TLS peer; verifyNode's dev-mode opt-in
	t.Cleanup(func() { clusterInsecure = prevInsecure })

	// This node's own logouts: genuine cookies, MAC-verified.
	const localN = 200
	localKeys := make(map[string]struct{}, localN)
	for i := range localN {
		value, key := logoutTestSession(t, fmt.Sprintf("au50-local-%d", i))
		if changed, reason := sessionRevoked.RevokeVerified(value); !changed {
			t.Fatalf("precondition: RevokeVerified refused a genuine cookie (%s)", reason)
		}
		localKeys[key] = struct{}{}
	}
	// The fleet's entries this node learned from earlier replies: ~17.6 MiB.
	learned := au50Learned("au50-fleet", 2200, 8000, time.Now().Add(2*time.Hour).Unix())
	if n := sessionRevoked.MergeRevocations(learned); n != len(learned) {
		t.Fatalf("precondition: merged %d of %d learned entries", n, len(learned))
	}
	all := au50Tokens(sessionRevoked.ExportRevocations())
	before := len(all)

	dial := startBufconnCP(t)
	conn := dial(t, clusterClientCallOptions()...)

	// NEGATIVE CONTROL: the pre-fix request — the whole list — is refused by
	// gRPC itself. Without this the gate could pass on a fixture that never
	// exceeded the cap.
	full, err := json.Marshal(revocationSyncRequest{NodeID: "au50-dp", Entries: sessionRevoked.ExportRevocations()})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(full) <= maxClusterInboundMsgSize {
		t.Fatalf("fixture is %d bytes, not over the %d byte cap — the gate proves nothing", len(full), maxClusterInboundMsgSize)
	}
	var discard json.RawMessage
	if err := conn.Invoke(context.Background(), methodSyncRevocations, json.RawMessage(full), &discard); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("control: the full-list request returned %v, want ResourceExhausted (the defect this gate exists for)", err)
	}

	reached := map[string]struct{}{}
	var firstTick map[string]struct{}
	var callErr error
	c := &DataPlaneClient{nodeID: "au50-dp"}
	c.callForTest = func(ctx context.Context, method string, req json.RawMessage) (json.RawMessage, error) {
		if len(req) > maxRevocationSyncRequestBytes {
			t.Errorf("request is %d bytes, over the %d byte budget", len(req), maxRevocationSyncRequestBytes)
		}
		var resp json.RawMessage
		if err := conn.Invoke(ctx, method, req, &resp); err != nil {
			callErr = err
			return nil, err
		}
		sent := au50Tokens(au50DecodeRequest(t, req).Entries)
		if firstTick == nil {
			firstTick = sent
		}
		for tok := range sent {
			reached[tok] = struct{}{}
		}
		return resp, nil
	}

	const maxTicks = 6 // ~17.7 MiB of backlog through a >=7.5 MiB window: 3 ticks
	ticks := 0
	for ticks < maxTicks && len(reached) < len(all) {
		c.syncRevocationsOnce(context.Background())
		if callErr != nil {
			t.Fatalf("tick %d: SyncRevocations failed through the real frame: %v", ticks+1, callErr)
		}
		ticks++
	}

	for key := range localKeys {
		if _, ok := firstTick[key]; !ok {
			t.Fatalf("a local logout was not in the FIRST request; this node's own revocations must go first")
		}
	}
	missing := 0
	for tok := range all {
		if _, ok := reached[tok]; !ok {
			missing++
		}
	}
	if missing > 0 {
		t.Fatalf("%d of %d entries never reached the CP in %d ticks — deferred must mean sent later, not dropped", missing, len(all), ticks)
	}
	if ticks < 2 {
		t.Fatalf("everything went in %d tick(s); the budget never engaged", ticks)
	}
	if got := len(sessionRevoked.ExportRevocations()); got != before {
		t.Fatalf("the local list went from %d to %d entries; budgeting must never remove a revocation", before, got)
	}
	if revocationSyncRequestDeferred.Load() == 0 {
		t.Error("deferral was not counted on culvert_cluster_revocation_sync_deferred_total{leg=\"request\"}")
	}
}

// The planner's own contract at a small budget: local first, every tick inside
// the budget, full coverage, including when the LOCAL class alone overflows.
func TestAU50_PlannerSendsLocalFirstAndRotatesEveryEntry(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	for _, tc := range []struct {
		name           string
		localN, otherN int
	}{
		{"local fits the prefix", 5, 120},
		{"local alone overflows the budget", 120, 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local := au50Learned("loc", tc.localN, 40, exp)
			for i := range local {
				local[i].Expiry -= int64(i) // distinct ages, newest first
			}
			other := au50Learned("oth", tc.otherN, 40, exp+10)
			acct := "au50-acct"
			other = append(other, RevocationEntry{Token: fmt.Sprintf("user:%s", acct), User: acct, Expiry: exp})
			reached := au50RunPlanner(t, local, other, 1500)
			for _, e := range append(append([]RevocationEntry{}, local...), other...) {
				if _, ok := reached[e.Token]; !ok {
					t.Fatalf("entry %q was never sent; the rotation starved it", e.Token)
				}
			}
		})
	}
}

// au50RunPlanner drives buildRevocationSyncRequest tick by tick until every
// entry has been sent (or 50 ticks pass), checking the per-tick invariants,
// and returns the tokens that were sent.
func au50RunPlanner(t *testing.T, local, other []RevocationEntry, budget int) map[string]struct{} {
	t.Helper()
	total := len(local) + len(other)
	var cur revSyncCursor
	reached := map[string]struct{}{}
	for tick := 0; tick < 50 && len(reached) < total; tick++ {
		b, deferred, err := buildRevocationSyncRequest("n1", local, other, budget, &cur)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > budget {
			t.Fatalf("tick %d: %d bytes over the %d budget", tick, len(b), budget)
		}
		req := au50DecodeRequest(t, b)
		if deferred != total-len(req.Entries) {
			t.Fatalf("tick %d: deferred=%d does not account for the %d entries left out", tick, deferred, total-len(req.Entries))
		}
		if tick == 0 && req.Entries[0].Token != local[0].Token {
			t.Fatalf("first entry of the first tick is %q, want this node's newest logout %q", req.Entries[0].Token, local[0].Token)
		}
		for _, e := range req.Entries {
			reached[e.Token] = struct{}{}
		}
	}
	return reached
}

// NEGATIVE CONTROL: why the planner rotates rather than trimming. The HA
// bundle's fixed priority prefix, applied to the same backlog tick after tick,
// carries the same entries every time and never the tail — which on the
// request leg would be a local revocation the fleet never hears about.
func TestAU50_ControlFixedPrefixStarvesTheTail(t *testing.T) {
	entries := au50Learned("tail", 100, 40, time.Now().Add(time.Hour).Unix())
	reached := map[string]struct{}{}
	for range 50 {
		kept, _ := fitRevocationsToBudget(entries, 1500)
		for _, e := range kept {
			reached[e.Token] = struct{}{}
		}
	}
	if len(reached) == len(entries) {
		t.Fatal("a fixed prefix covered the whole backlog; this control no longer demonstrates why rotation is needed")
	}
}

// CONTROL: a list that fits is sent byte-identically to the pre-fix request,
// with nothing deferred and no cursor retained — the common case is unchanged
// on the wire and pays one marshal.
func TestAU50_ControlFittingListIsSentWholeAndUnchanged(t *testing.T) {
	local := au50Learned("fit-l", 3, 30, 2_000_000_000)
	other := au50Learned("fit-o", 3, 30, 2_000_000_000)
	cur := revSyncCursor{set: true, last: revSyncKey{token: "stale"}}
	b, deferred, err := buildRevocationSyncRequest("n1", local, other, maxRevocationSyncRequestBytes, &cur)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(struct {
		NodeID  string            `json:"node_id"`
		Entries []RevocationEntry `json:"entries"`
	}{"n1", append(append([]RevocationEntry{}, local...), other...)})
	if !bytes.Equal(b, want) {
		t.Fatalf("a fitting request changed on the wire:\n got %s\nwant %s", b, want)
	}
	if deferred != 0 || cur.set {
		t.Fatalf("deferred=%d cursor=%+v, want 0 and cleared", deferred, cur)
	}
}

// DEFECT (AU-71): the CP's reply is budgeted against the DP's receive frame,
// rotated per requesting node, and covers the fleet over ticks.
func TestAU71_ReplyOverBudgetRotatesPerNode(t *testing.T) {
	withChaos68Revocations(t)
	withChaos68Aggregator(t)
	prevInsecure, prevBudget := clusterInsecure, revocationSyncResponseBudget
	clusterInsecure = true
	revocationSyncResponseBudget = 4096
	t.Cleanup(func() { clusterInsecure, revocationSyncResponseBudget = prevInsecure, prevBudget })

	learned := au50Learned("au71-cp", 300, 60, time.Now().Add(time.Hour).Unix())
	if n := sessionRevoked.MergeRevocations(learned); n != len(learned) {
		t.Fatalf("precondition: merged %d of %d", n, len(learned))
	}
	s := &controlPlaneServer{}
	reqBody, _ := json.Marshal(revocationSyncRequest{NodeID: "au71-dp", Entries: []RevocationEntry{}})
	reached := map[string]struct{}{}
	for tick := 0; tick < 40 && len(reached) < len(learned); tick++ {
		raw, err := s.SyncRevocations(context.Background(), reqBody)
		if err != nil {
			t.Fatalf("tick %d: %v", tick, err)
		}
		if len(raw) > revocationSyncResponseBudget {
			t.Fatalf("tick %d: reply is %d bytes, over the %d budget", tick, len(raw), revocationSyncResponseBudget)
		}
		var resp struct {
			Entries []RevocationEntry `json:"entries"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatalf("tick %d: reply is not the wire shape the DP decodes: %v", tick, err)
		}
		for _, e := range resp.Entries {
			reached[e.Token] = struct{}{}
		}
	}
	if len(reached) != len(learned) {
		t.Fatalf("the requester learned %d of %d entries; deferred reply entries must arrive on later ticks", len(reached), len(learned))
	}
	if revocationSyncResponseDeferred.Load() == 0 {
		t.Error("reply deferral was not counted")
	}
	if got := len(sessionRevoked.ExportRevocations()); got != len(learned) {
		t.Fatalf("the CP's list went from %d to %d entries", len(learned), got)
	}

	// CONTROL: once the reply fits, the node's cursor is released, so the map
	// holds an entry only while a reply is actually over budget.
	revocationSyncResponseBudget = maxRevocationSyncResponseBytes
	if _, err := s.SyncRevocations(context.Background(), reqBody); err != nil {
		t.Fatal(err)
	}
	globalRevAggregator.mu.Lock()
	_, held := globalRevAggregator.respCursor["au71-dp"]
	globalRevAggregator.mu.Unlock()
	if held {
		t.Error("a fitting reply left the node's rotation cursor behind")
	}
}
