package main

// cluster_promote_addresslist_chaos_test.go — CHAOS-91 (found beside the CHAOS-71 address-republish rider): the CP address
// list a promoted leader publishes, and what a data plane does with a shrinking
// one.
//
// Both came out of the Codex review of PR #1618, and both are consequences of
// CHAOS-71 promote-deadlock rider having made HA promotion complete at all: the ordering below was
// always wrong, but before the deadlock was fixed the promotion path never
// reached the publish.
//
//   rider    — buildCPAddressList composes the list from the HA peer address and
//         clusterRole.grpcAddr, and grpcAddr is assigned only AFTER the
//         listener is up. The first snapshot therefore names the PEER — for a
//         promoting standby, the leader that just died — and not the node
//         taking over.
//   CHAOS-91 — updateDPAddresses REPLACED c.addrs without re-resolving activeIdx,
//         which indexes it. A shrinking list left the index past the end, and
//         reconnectActive (the certificate-renewal redial) indexes it directly.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// dpAddrState snapshots the client's address list and active index UNDER its
// mutex. The fields are written by updateDPAddresses while holding c.mu, and a
// background loop left over from an earlier test in this binary could still
// reach updateDPAddresses through the activeDPClient global, so an
// unsynchronised read here would be a real -race finding rather than a
// theoretical one.
func dpAddrState(c *DataPlaneClient) (addrs []string, activeIdx int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.addrs...), c.activeIdx
}

// TestChaos91_ShrinkingAddressListDoesNotStrandTheIndex is the regression test
// for the panic. The pre-fix sequence — two configured CPs, one failover, then a
// one-element list from a promoting leader — left activeIdx=1 against a
// one-element slice, and the next redial died with "index out of range [1] with
// length 1" on an unattended cert-renewal path.
func TestChaos91_ShrinkingAddressListDoesNotStrandTheIndex(t *testing.T) {
	c := &DataPlaneClient{
		nodeID:    "dp-chaos91",
		addrs:     []string{"cp1:50051", "cp2:50051"},
		activeIdx: 1, // where one failover leaves it
	}
	prev := activeDPClient.Load()
	activeDPClient.Store(c)
	t.Cleanup(func() { activeDPClient.Store(prev) })

	// The authoritative list shrinks and drops the address in use.
	updateDPAddresses([]string{"cp1:50051"})

	addrs, idx := dpAddrState(c)
	if idx < 0 || idx >= len(addrs) {
		t.Fatalf("activeIdx=%d is out of range for %d address(es) — reconnectActive indexes this directly and will panic on the cert-renewal redial", idx, len(addrs))
	}

	// The real crash site. connect() will fail to dial, which is fine and
	// expected; what must not happen is a panic before it gets there.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("reconnectActive panicked after the address list shrank: %v", r)
		}
	}()
	_ = c.reconnectActive()
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

// TestChaos91_ActiveAddressIsTrackedByValueNotIndex pins the stronger property
// the fix provides. Clamping the index into range would also stop the panic,
// but it would silently re-point activeIdx at a DIFFERENT control plane than
// the one c.conn actually holds — so the invariant "activeIdx names the address
// this client is connected to" has to survive a reorder, not just a shrink.
func TestChaos91_ActiveAddressIsTrackedByValueNotIndex(t *testing.T) {
	c := &DataPlaneClient{
		nodeID:    "dp-chaos91",
		addrs:     []string{"cp1:50051", "cp2:50051"},
		activeIdx: 1, // connected to cp2
	}
	prev := activeDPClient.Load()
	activeDPClient.Store(c)
	t.Cleanup(func() { activeDPClient.Store(prev) })

	// Same members, different order — exactly what a promotion produces when
	// the new leader's own address is appended after the peer's.
	updateDPAddresses([]string{"cp2:50051", "cp1:50051"})

	addrs, idx := dpAddrState(c)
	if got := addrs[idx]; got != "cp2:50051" {
		t.Errorf("activeIdx now names %q, want the address the connection actually holds (%q) — a reorder silently re-pointed the client at a different CP", got, "cp2:50051")
	}
}

// TestChaos91_DroppedActiveAddressFallsBackToAListedOne covers the honest case:
// when the CP says the address in use is no longer a member, the client must
// land on a listed address rather than keep an index it cannot justify.
func TestChaos91_DroppedActiveAddressFallsBackToAListedOne(t *testing.T) {
	c := &DataPlaneClient{
		nodeID:    "dp-chaos91",
		addrs:     []string{"cp1:50051", "cp2:50051"},
		activeIdx: 1,
	}
	prev := activeDPClient.Load()
	activeDPClient.Store(c)
	t.Cleanup(func() { activeDPClient.Store(prev) })

	updateDPAddresses([]string{"cp3:50051", "cp4:50051"})

	addrs, idx := dpAddrState(c)
	if idx != 0 {
		t.Errorf("activeIdx=%d after the active address was dropped, want 0", idx)
	}
	if got := addrs[idx]; got != "cp3:50051" {
		t.Errorf("activeIdx names %q, want the first listed member %q", got, "cp3:50051")
	}
}

// TestChaos91_DroppedActiveAddressRedialsRatherThanOnlyReindexing is the
// CodeRabbit finding from the review of PR #1618, and it is the part that
// actually matters. Re-pointing activeIdx is cosmetic on its own: `call`
// invokes over c.conn, not over c.addrs[c.activeIdx], and nothing else redials
// when the list changes (reconnectActive runs only for a certificate renewal;
// failover only off a failure streak).
//
// So a de-listed CP that is still RESPONSIVE — the ordinary shape right after
// an HA promotion, where the old leader is up but no longer authoritative —
// would keep answering this node's polls. Every poll would SUCCEED, resetBackoff
// would clear the streak, the failover gate would never be reached, and the data
// plane would apply a demoted CP's configuration indefinitely. With the fencing
// lease unset the snapshot carries epoch 0, so the DP-side ratchet does not
// reject it either.
func TestChaos91_DroppedActiveAddressRedialsRatherThanOnlyReindexing(t *testing.T) {
	c := &DataPlaneClient{
		nodeID:    "dp-chaos91",
		addrs:     []string{"cp1:50051", "cp2:50051"},
		activeIdx: 1, // connected to cp2
	}
	// A real (lazy) connection, so the redial has something to replace and the
	// nil-conn guard does not short-circuit the branch under test.
	if err := c.connect("cp2:50051"); err != nil {
		t.Fatalf("seed connect: %v", err)
	}
	before := c.conn
	t.Cleanup(func() {
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
	prev := activeDPClient.Load()
	activeDPClient.Store(c)
	t.Cleanup(func() { activeDPClient.Store(prev) })

	// The authoritative list drops cp2 entirely.
	updateDPAddresses([]string{"cp3:50051", "cp4:50051"})

	c.mu.Lock()
	after, idx, addrs := c.conn, c.activeIdx, append([]string(nil), c.addrs...)
	c.mu.Unlock()

	if after == before {
		t.Error("the connection still points at the de-listed CP — a responsive but demoted control plane would keep serving this node config forever, because every poll succeeds and the failover gate is never reached")
	}
	if idx != 0 || addrs[idx] != "cp3:50051" {
		t.Errorf("activeIdx=%d names %q, want index 0 naming %q", idx, addrs[idx], "cp3:50051")
	}
}

// TestChaos91_FailedRedialIsRetriedNotDropped: a redial that fails keeps the old
// list and connection, and the new list must then be RETRIED, not dropped.
// fetchAndApply persists the snapshot and advances lastVersion either way, so an
// unchanged CP never re-sends the list (Codex P2 on #1618) — without the pending
// retry the DP stays pinned to a de-listed CP until the next config version.
func TestChaos91_FailedRedialIsRetriedNotDropped(t *testing.T) {
	c := &DataPlaneClient{
		nodeID:    "dp-chaos91",
		addrs:     []string{"cp1:50051", "cp2:50051"},
		activeIdx: 1,
	}
	if err := c.connect("cp2:50051"); err != nil {
		t.Fatalf("seed connect: %v", err)
	}
	t.Cleanup(func() {
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
	prev := activeDPClient.Load()
	activeDPClient.Store(c)
	t.Cleanup(func() { activeDPClient.Store(prev) })

	// Make the redial fail: the client TLS material cannot be loaded (the shape
	// of a certificate renewal caught between writing the cert and the key).
	missing := t.TempDir() + "/missing"
	c.mu.Lock()
	c.certFile, c.keyFile = missing+".crt", missing+".key"
	c.mu.Unlock()

	updateDPAddresses([]string{"cp3:50051", "cp4:50051"})
	c.mu.Lock()
	addrs, pending := append([]string(nil), c.addrs...), append([]string(nil), c.pendingAddrs...)
	c.mu.Unlock()
	if !slicesEqual(addrs, []string{"cp1:50051", "cp2:50051"}) {
		t.Fatalf("a failed redial adopted the new list %v; it must keep the reachable one", addrs)
	}
	if !slicesEqual(pending, []string{"cp3:50051", "cp4:50051"}) {
		t.Fatalf("pending = %v: the list whose redial failed was dropped instead of retained for retry", pending)
	}

	// The dial works again; the retry the next poll runs adopts the list.
	c.mu.Lock()
	c.certFile, c.keyFile = "", ""
	c.mu.Unlock()
	c.retryPendingAddresses()
	c.mu.Lock()
	addrs, pending = append([]string(nil), c.addrs...), c.pendingAddrs
	c.mu.Unlock()
	if !slicesEqual(addrs, []string{"cp3:50051", "cp4:50051"}) || pending != nil {
		t.Fatalf("after a working retry: addrs=%v pending=%v, want the new list and nothing pending", addrs, pending)
	}
}

// TestChaos91_PendingAddressesRetryOnTheDeltaFastPath: the retry must run on a
// cycle the delta fast path handles. A CP that supports GetConfigDelta answers
// "unchanged" on every steady-state poll and fetchAndApply returns before the
// full poll, so a retry placed inside pollConfig never ran (Codex P2 on #1618).
func TestChaos91_PendingAddressesRetryOnTheDeltaFastPath(t *testing.T) {
	// fetchAndApply reaches the snapshot apply path, which mutates the admission
	// owners in place (RISK-030).
	bindFreshAdmissionOwners(t)
	c := &DataPlaneClient{
		nodeID:       "dp-chaos91",
		addrs:        []string{"cp1:50051", "cp2:50051"},
		activeIdx:    1,
		pendingAddrs: []string{"cp3:50051", "cp4:50051"},
	}
	if err := c.connect("cp2:50051"); err != nil {
		t.Fatalf("seed connect: %v", err)
	}
	t.Cleanup(func() {
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
	c.lastVersion.Store(7)
	var fullPolls int
	c.callForTest = func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
		if method == methodGetConfigDelta {
			return json.RawMessage(`{"mode":"unchanged"}`), nil
		}
		fullPolls++
		return nil, fmt.Errorf("unexpected full poll %s", method)
	}

	c.fetchAndApply(t.Context())

	c.mu.Lock()
	addrs, pending := append([]string(nil), c.addrs...), c.pendingAddrs
	c.mu.Unlock()
	if fullPolls != 0 {
		t.Fatalf("precondition: the delta fast path must have handled the cycle, got %d full polls", fullPolls)
	}
	if !slicesEqual(addrs, []string{"cp3:50051", "cp4:50051"}) || pending != nil {
		t.Fatalf("a cycle handled by the delta fast path left addrs=%v pending=%v; the deferred list "+
			"must be retried on every cycle", addrs, pending)
	}
}

// TestChaos91_RetainedActiveAddressKeepsItsConnection is the negative control
// for the redial: when the active address is STILL a member, the connection must
// be left alone. Redialling unconditionally would throw away a working link on
// every unrelated list change — a reorder, or a peer being added.
func TestChaos91_RetainedActiveAddressKeepsItsConnection(t *testing.T) {
	c := &DataPlaneClient{
		nodeID:    "dp-chaos91",
		addrs:     []string{"cp1:50051", "cp2:50051"},
		activeIdx: 1,
	}
	if err := c.connect("cp2:50051"); err != nil {
		t.Fatalf("seed connect: %v", err)
	}
	before := c.conn
	t.Cleanup(func() {
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
	prev := activeDPClient.Load()
	activeDPClient.Store(c)
	t.Cleanup(func() { activeDPClient.Store(prev) })

	// cp2 is still listed, just reordered, and a third CP joins.
	updateDPAddresses([]string{"cp2:50051", "cp1:50051", "cp5:50051"})

	c.mu.Lock()
	after, idx, addrs := c.conn, c.activeIdx, append([]string(nil), c.addrs...)
	c.mu.Unlock()

	if after != before {
		t.Error("the connection was redialled although the active address is still a member — an unrelated list change must not drop a working CP link")
	}
	if addrs[idx] != "cp2:50051" {
		t.Errorf("activeIdx names %q, want the address the connection holds (%q)", addrs[idx], "cp2:50051")
	}
}

// TestChaos91_EmptyListIsIgnored pins the existing guard that an empty
// CPAddresses (every non-HA snapshot carries one) must not wipe a DP's
// configured addresses.
func TestChaos91_EmptyListIsIgnored(t *testing.T) {
	c := &DataPlaneClient{
		nodeID:    "dp-chaos91",
		addrs:     []string{"cp1:50051", "cp2:50051"},
		activeIdx: 1,
	}
	prev := activeDPClient.Load()
	activeDPClient.Store(c)
	t.Cleanup(func() { activeDPClient.Store(prev) })

	updateDPAddresses(nil)

	addrs, idx := dpAddrState(c)
	if len(addrs) != 2 || idx != 1 {
		t.Errorf("an empty list changed the client state: addrs=%v activeIdx=%d", addrs, idx)
	}
}

// The 72b regression (the promoting leader's republished list names itself)
// is pinned on main by TestChaos71_CPAddrRepublish_PromotingLeaderPublishesAListNamingItself
// in cluster_promote_deadlock_chaos_test.go, ported from this PR.

// TestChaos91_AddressListLogIsInjectionSafe is the CWE-117 gate on the line
// updateDPAddresses writes. The address list arrives verbatim in the Control
// Plane's config snapshot, so it is peer-supplied: a newline in an address
// would otherwise forge whole log lines in the process log an operator reads
// after a failover. The pre-fix line logged both lists with a bare %v.
//
// CodeQL flagged the sibling line in enableControlPlane for exactly this during
// review of PR #1618, which is what prompted auditing this one.
func TestChaos91_AddressListLogIsInjectionSafe(t *testing.T) {
	const forged = "10.0.0.9:50051\nFORGED ControlPlane: enabled via GUI (gRPC evil:1)"

	c := &DataPlaneClient{
		nodeID:    "dp-chaos91",
		addrs:     []string{"cp1:50051"},
		activeIdx: 0,
	}
	prev := activeDPClient.Load()
	activeDPClient.Store(c)
	t.Cleanup(func() { activeDPClient.Store(prev) })

	sink := captureLoggerForTest(t)
	updateDPAddresses([]string{forged})

	got := sink.String()
	if got == "" {
		t.Fatal("updateDPAddresses logged nothing, so this gate asserts nothing")
	}
	if strings.Contains(got, "\nFORGED") {
		t.Errorf("a newline in a peer-supplied CP address reached the process log unescaped, forging a line:\n%s", got)
	}
	// The address must still be identifiable — sanitizing is not redacting.
	if !strings.Contains(got, "10.0.0.9:50051") {
		t.Errorf("the sanitized line no longer names the address, so the log is useless for diagnosing a failover:\n%s", got)
	}
}
