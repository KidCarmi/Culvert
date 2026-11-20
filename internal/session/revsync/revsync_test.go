package revsync

// AU-50 (Codex P1, PR #1437) and AU-71: the planner's own contract. The gates
// that need the application — the real gRPC frame limits, the session store,
// the Control Plane aggregator — stay in package main
// (revocation_sync_budget_test.go). The two TestAU50_* tests below moved here
// from that file with their names and assertions unchanged (IM-015).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// requestBudgetBytes is the production DP→CP request budget (package main's
// maxRevocationSyncRequestBytes: the 16 MiB inbound bound less the 1 MiB frame
// reserve). Only its being far larger than the fixture matters here.
const requestBudgetBytes = 15 << 20

// au50Learned builds n learned (gossip) entries whose tokens are tokLen bytes.
// Labels are built from parameters, not literals, to keep gosec's G101
// heuristic off fixture strings.
func au50Learned(prefix string, n, tokLen int, expiry int64) []session.RevocationEntry {
	out := make([]session.RevocationEntry, n)
	for i := range out {
		label := fmt.Sprintf("%s-%06d-", prefix, i)
		out[i] = session.RevocationEntry{Token: label + strings.Repeat("x", max(0, tokLen-len(label))), Expiry: expiry}
	}
	return out
}

// accountEntry builds an account revocation. The token is built from the
// parameter, not a literal, for the same G101 reason as au50Learned.
func accountEntry(acct string, expiry int64) session.RevocationEntry {
	return session.RevocationEntry{Token: fmt.Sprintf("user:%s", acct), User: acct, Expiry: expiry}
}

func au50DecodeRequest(t *testing.T, b []byte) Request {
	t.Helper()
	var req Request
	if err := json.Unmarshal(b, &req); err != nil {
		t.Fatalf("the budgeted request is not the wire shape the CP decodes: %v", err)
	}
	return req
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
			other = append(other, session.RevocationEntry{Token: fmt.Sprintf("user:%s", acct), User: acct, Expiry: exp})
			reached := au50RunPlanner(t, local, other, 1500)
			for _, e := range append(append([]session.RevocationEntry{}, local...), other...) {
				if _, ok := reached[e.Token]; !ok {
					t.Fatalf("entry %q was never sent; the rotation starved it", e.Token)
				}
			}
		})
	}
}

// au50RunPlanner drives BuildRequest tick by tick until every entry has been
// sent (or 50 ticks pass), checking the per-tick invariants, and returns the
// tokens that were sent.
func au50RunPlanner(t *testing.T, local, other []session.RevocationEntry, budget int) map[string]struct{} {
	t.Helper()
	total := len(local) + len(other)
	var cur Cursor
	reached := map[string]struct{}{}
	for tick := 0; tick < 50 && len(reached) < total; tick++ {
		b, deferred, err := BuildRequest("n1", local, other, budget, &cur)
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

// CONTROL: a list that fits is sent byte-identically to the pre-fix request,
// with nothing deferred and no cursor retained — the common case is unchanged
// on the wire and pays one marshal.
func TestAU50_ControlFittingListIsSentWholeAndUnchanged(t *testing.T) {
	local := au50Learned("fit-l", 3, 30, 2_000_000_000)
	other := au50Learned("fit-o", 3, 30, 2_000_000_000)
	cur := Cursor{set: true, last: key{token: "stale"}}
	b, deferred, err := BuildRequest("n1", local, other, requestBudgetBytes, &cur)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(struct {
		NodeID  string                    `json:"node_id"`
		Entries []session.RevocationEntry `json:"entries"`
	}{"n1", append(append([]session.RevocationEntry{}, local...), other...)})
	if !bytes.Equal(b, want) {
		t.Fatalf("a fitting request changed on the wire:\n got %s\nwant %s", b, want)
	}
	if deferred != 0 || cur.set {
		t.Fatalf("deferred=%d cursor=%+v, want 0 and cleared", deferred, cur)
	}
}

// goldenFixture is the deterministic backlog the two golden digests were
// captured over.
func goldenFixture() (local, other []session.RevocationEntry) {
	build := func(prefix string, n, tokLen int, expiry int64) []session.RevocationEntry {
		out := au50Learned(prefix, n, tokLen, expiry)
		for i := range out {
			out[i].Expiry -= int64(i % 7)
		}
		return out
	}
	local = build("loc", 40, 40, 2_000_000_000)
	other = build("oth", 90, 48, 2_000_000_100)
	other = append(other, accountEntry("golden-acct", 2_000_000_050))
	return local, other
}

// goldenDigest hashes twelve consecutive over-budget ticks: the tick number,
// the deferred count and the exact message bytes.
func goldenDigest(t *testing.T, build func(cur *Cursor) ([]byte, int, error)) string {
	t.Helper()
	h := sha256.New()
	var cur Cursor
	for tick := range 12 {
		b, deferred, err := build(&cur)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(h, "%d:%d:%s\n", tick, deferred, b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// The move changed no byte on either leg. The two digests were captured from
// package main's planner at main 530445b, BEFORE the move, over the same
// fixture, budgets and tick count; they cover the priority order, the comma
// accounting, the envelope and the rotation's resume point across wraps.
func TestIM015_WireBytesMatchThePreMovePlanner(t *testing.T) {
	local, other := goldenFixture()
	all := append(append([]session.RevocationEntry{}, local...), other...)

	const wantRequest = "6b76c680450fd8c73f4d1b3bdac1fc5de56ae8af36f2dbce7e58cb59246d933a"
	if got := goldenDigest(t, func(cur *Cursor) ([]byte, int, error) {
		return BuildRequest("golden-node", local, other, 1800, cur)
	}); got != wantRequest {
		t.Errorf("request leg digest = %s, want %s", got, wantRequest)
	}

	const wantResponse = "a2ca5bbeb4c9fd1dea43bab5671d4bfb92f853fbed0cbd302e2e4e971db8e75e"
	if got := goldenDigest(t, func(cur *Cursor) ([]byte, int, error) {
		return BuildResponse(all, 1700, cur)
	}); got != wantResponse {
		t.Errorf("reply leg digest = %s, want %s", got, wantResponse)
	}

	// NEGATIVE CONTROL: the digest is sensitive to the order. Swapping which
	// half is "local" changes the request leg's priority prefix.
	if got := goldenDigest(t, func(cur *Cursor) ([]byte, int, error) {
		return BuildRequest("golden-node", other, local, 1800, cur)
	}); got == wantRequest {
		t.Error("the golden digest did not notice a different priority order")
	}
}

// The reply leg: account revocations ride the priority prefix ahead of every
// token, and every entry arrives within the rotation.
func TestAU71_ReplyPutsAccountRevocationsFirstAndRotates(t *testing.T) {
	entries := au50Learned("tok", 150, 40, 2_000_000_500) // later expiry than the account entry
	entries = append(entries, accountEntry("late-acct", 2_000_000_000))
	var cur Cursor
	reached := map[string]struct{}{}
	const budget = 1500
	for tick := 0; tick < 50 && len(reached) < len(entries); tick++ {
		b, deferred, err := BuildResponse(entries, budget, &cur)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > budget {
			t.Fatalf("tick %d: %d bytes over the %d budget", tick, len(b), budget)
		}
		var resp struct {
			Entries []session.RevocationEntry `json:"entries"`
		}
		if err := json.Unmarshal(b, &resp); err != nil {
			t.Fatalf("tick %d: reply is not the wire shape the DP decodes: %v", tick, err)
		}
		if deferred != len(entries)-len(resp.Entries) {
			t.Fatalf("tick %d: deferred=%d, sent %d of %d", tick, deferred, len(resp.Entries), len(entries))
		}
		if resp.Entries[0].User != "late-acct" {
			t.Fatalf("tick %d: first reply entry is %q, want the account revocation on every tick", tick, resp.Entries[0].Token)
		}
		if !cur.Active() {
			t.Fatalf("tick %d: an over-budget reply left no active cursor", tick)
		}
		for _, e := range resp.Entries {
			reached[e.Token] = struct{}{}
		}
	}
	if len(reached) != len(entries) {
		t.Fatalf("the requester learned %d of %d entries", len(reached), len(entries))
	}
}

// Two cursors are two rotations: advancing one peer's window must not move
// another's, and the package keeps nothing between calls but the Cursor.
func TestCursorsAreIndependent(t *testing.T) {
	entries := au50Learned("ind", 120, 40, 2_000_000_000)
	var a, b Cursor
	first, _, err := BuildResponse(entries, 1500, &a)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 { // advance a only
		if _, _, err := BuildResponse(entries, 1500, &a); err != nil {
			t.Fatal(err)
		}
	}
	got, _, err := BuildResponse(entries, 1500, &b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, got) {
		t.Fatal("a fresh cursor did not start where the first one started; state leaked between cursors")
	}
	if a == b {
		t.Fatal("the advanced cursor equals the fresh one's; the rotation did not move")
	}
	if (Cursor{}).Active() {
		t.Fatal("the zero Cursor reports an active rotation")
	}
}

// An entry larger than the whole window can never ride. It must not jam the
// rotation for the entries behind it, and it must stay counted as deferred.
func TestOversizeEntryDoesNotJamTheRotation(t *testing.T) {
	entries := au50Learned("ok", 60, 40, 2_000_000_000)
	huge := session.RevocationEntry{Token: "huge-" + strings.Repeat("y", 4000), Expiry: 2_000_000_000}
	entries = append(entries, huge)
	var cur Cursor
	reached := map[string]struct{}{}
	const budget = 1500
	for tick := 0; tick < 50 && len(reached) < len(entries)-1; tick++ {
		b, deferred, err := BuildResponse(entries, budget, &cur)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > budget {
			t.Fatalf("tick %d: %d bytes over the %d budget", tick, len(b), budget)
		}
		if deferred < 1 {
			t.Fatalf("tick %d: deferred=%d, but the oversize entry cannot have been sent", tick, deferred)
		}
		var resp struct {
			Entries []session.RevocationEntry `json:"entries"`
		}
		if err := json.Unmarshal(b, &resp); err != nil {
			t.Fatal(err)
		}
		for _, e := range resp.Entries {
			reached[e.Token] = struct{}{}
		}
	}
	if _, sent := reached[huge.Token]; sent {
		t.Fatal("an entry larger than the budget was sent")
	}
	if len(reached) != len(entries)-1 {
		t.Fatalf("%d of %d sendable entries went out; the oversize entry jammed the rotation", len(reached), len(entries)-1)
	}
}
