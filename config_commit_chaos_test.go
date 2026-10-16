package main

// config_commit_chaos_test.go — CHAOS-71: ONE commit path for every config
// publish (Codex P1 4296091768 + P2 4296091783 on #1556). The address-only
// publish used to be a second commit path that skipped invariants the full
// path kept; both now go through commitPublish, and this file pins the
// invariants against BOTH paths.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// cpCommitFixture is a bare, published store with a controllable snapshot
// size and a fixed fence epoch.
func cpCommitFixture(t *testing.T, epoch *int64) *ConfigStore {
	t.Helper()
	prevEpoch := publishFenceEpoch
	publishFenceEpoch = func() int64 { return *epoch }
	t.Cleanup(func() { publishFenceEpoch = prevEpoch })
	prevBudget := snapshotWireBudget
	t.Cleanup(func() { snapshotWireBudget = prevBudget })

	s := &ConfigStore{}
	if err := s.Update(cpCommitSnapshot(50)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return s
}

func cpCommitSnapshot(hosts int) ConfigSnapshot {
	snap := ConfigSnapshot{BlockedHosts: make([]string, hosts)}
	for i := range snap.BlockedHosts {
		snap.BlockedHosts[i] = fmt.Sprintf("blocked-%04d.example", i)
	}
	return snap
}

// cpRejectFull latches a FULL-publish rejection (an over-budget snapshot).
func cpRejectFull(t *testing.T, s *ConfigStore) string {
	t.Helper()
	snapshotWireBudget = 2048
	err := s.Update(cpCommitSnapshot(2000))
	snapshotWireBudget = maxSnapshotWireBytes
	if err == nil {
		t.Fatal("precondition: the over-budget full publish was accepted")
	}
	msg, _ := s.LastPublishError()
	if msg == "" {
		t.Fatal("precondition: no full-publish rejection latched")
	}
	return msg
}

// cpRejectAddresses latches an ADDRESS-publish rejection.
func cpRejectAddresses(t *testing.T, s *ConfigStore) {
	t.Helper()
	long := make([]string, 400)
	for i := range long {
		long[i] = fmt.Sprintf("cp-%03d.a-rather-long-control-plane-hostname.example.internal:50051", i)
	}
	snapshotWireBudget = 8192
	_, err := s.UpdateCPAddressesFrom(func() []string { return long })
	snapshotWireBudget = maxSnapshotWireBytes
	if err == nil {
		t.Fatal("precondition: the over-budget address publish was accepted")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.addrPublishErr == "" {
		t.Fatal("precondition: no address-publish rejection latched")
	}
}

// TestChaos71_EveryCommitPathKeepsTheCommitInvariants runs the SAME invariant
// table against both publish paths: the commit carries the current fence
// epoch, the version strictly increases, sizes are recorded for exactly what
// was committed, and the OTHER kind's rejection latch survives.
func TestChaos71_EveryCommitPathKeepsTheCommitInvariants(t *testing.T) {
	paths := []struct {
		name        string
		kind        publishKind
		commit      func(s *ConfigStore, n int) error
		wantedHosts func(n int) int
	}{
		{"full_update", publishFull, func(s *ConfigStore, n int) error { return s.Update(cpCommitSnapshot(n)) },
			func(n int) int { return n }},
		{"address_publish", publishAddresses, func(s *ConfigStore, n int) error {
			_, err := s.UpdateCPAddressesFrom(func() []string { return []string{fmt.Sprintf("10.0.0.%d:50051", n)} })
			return err
		}, func(int) int { return 50 }}, // address-only: the committed policy is unchanged
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			epoch := int64(7)
			s := cpCommitFixture(t, &epoch)
			cpRejectFull(t, s) // latch BOTH kinds: a commit clears only its own
			cpRejectAddresses(t, s)
			other := publishAddresses
			if p.kind == publishAddresses {
				other = publishFull
			}
			for round, n := range []int{51, 52} {
				epoch = int64(7 + round*2) // a new grant between commits
				before := s.Get().Version
				if err := p.commit(s, n); err != nil {
					t.Fatalf("round %d: commit: %v", round, err)
				}
				cpAssertCommitInvariants(t, s, round, epoch, before, p.wantedHosts(n))
				if cpLatch(s, other) == "" {
					t.Errorf("round %d: a %s commit cleared the OTHER publish kind's rejection latch", round, p.name)
				}
				if own := cpLatch(s, p.kind); own != "" {
					t.Errorf("round %d: a successful %s left its own rejection latched: %q", round, p.name, own)
				}
			}
		})
	}
}

// cpAssertCommitInvariants checks one commit: current fence epoch, strictly
// increasing version, sizes recorded for exactly what was committed.
func cpAssertCommitInvariants(t *testing.T, s *ConfigStore, round int, epoch, before int64, wantHosts int) {
	t.Helper()
	got := s.Get()
	if got.Epoch != epoch {
		t.Errorf("round %d: committed epoch %d, want the current fence epoch %d", round, got.Epoch, epoch)
	}
	if got.Version <= before {
		t.Errorf("round %d: version %d did not increase past %d", round, got.Version, before)
	}
	sizes, _ := lastPublishedSnapshotSizes.Load().(publishedSnapshotSizes)
	if len(got.BlockedHosts) != wantHosts || sizes.Aggregate != wantHosts {
		t.Errorf("round %d: committed %d hosts, recorded aggregate %d, want %d", round, len(got.BlockedHosts), sizes.Aggregate, wantHosts)
	}
}

// cpLatch reads one kind's rejection latch.
func cpLatch(s *ConfigStore, kind publishKind) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if kind == publishFull {
		return s.lastPublishErr
	}
	return s.addrPublishErr
}

// TestChaos71_FullRejectionStaysVisibleAcrossAnAddressCommit is the operator
// view of the P2: after a rejected full publish, an HA topology change that
// commits a new address list must not clear the fleet-freeze banner
// (/api/stats and diagnose read LastPublishError).
func TestChaos71_FullRejectionStaysVisibleAcrossAnAddressCommit(t *testing.T) {
	epoch := int64(0)
	s := cpCommitFixture(t, &epoch)
	msg := cpRejectFull(t, s)
	if _, err := s.UpdateCPAddressesFrom(func() []string { return []string{"10.0.0.9:50051"} }); err != nil {
		t.Fatalf("address publish: %v", err)
	}
	if got, _ := s.LastPublishError(); got != msg {
		t.Errorf("after an address-only commit LastPublishError = %q, want the full rejection %q — the fleet is still on stale policy", got, msg)
	}
	if err := s.Update(cpCommitSnapshot(10)); err != nil {
		t.Fatalf("full publish: %v", err)
	}
	if got, _ := s.LastPublishError(); got != "" {
		t.Errorf("a successful full publish left LastPublishError = %q", got)
	}
}

// TestChaos71_EnableAsLeaderPublishesTheNewFenceEpoch is the P1 end to end: a
// published, owned Control Plane enables HA under a real (fake-backend) lease.
// The topology writer's address publish must carry the epoch EnableAsLeader
// just acquired, so a DP that learned it on heartbeat accepts the snapshot.
// An unchanged list with a changed epoch (a fresh grant) is restamped too.
func TestChaos71_EnableAsLeaderPublishesTheNewFenceEpoch(t *testing.T) {
	h := cpAddrTopologyFixture(t)
	h.SetLeaseProvider(halease.NewFake(time.Minute), "cp-a")
	cpAddrActiveCP(t, "10.0.0.2:50051")
	if got := globalConfigStore.Get().Epoch; got != 0 {
		t.Fatalf("precondition: epoch before HA = %d", got)
	}

	if _, err := h.EnableAsLeader("10.0.0.9:50051", false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	fence := h.CurrentEpoch()
	if fence <= 0 {
		t.Fatalf("precondition: no fence epoch after enable (%d)", fence)
	}
	got := globalConfigStore.Get()
	if got.Epoch != fence {
		t.Fatalf("the address publish carried epoch %d, want the fence epoch %d — a DP that saw %d on heartbeat rejects it", got.Epoch, fence, fence)
	}
	// The DP side, for real: the ratchet learned the epoch from a heartbeat.
	t.Cleanup(resetDPLastSeenEpochForTest())
	if !dpObserveEpoch("heartbeat", fence) || !dpObserveEpoch("config snapshot", got.Epoch) {
		t.Fatalf("a DP that saw epoch %d on heartbeat rejected the snapshot stamped %d", fence, got.Epoch)
	}

	// Same list, new grant: restamped, not "up to date".
	h.mu.Lock()
	h.setLeaseEpochLocked(fence + 3)
	h.mu.Unlock()
	if err := globalConfigStore.reconcileCPAddressesFrom("test", buildCPAddressList); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if e := globalConfigStore.Get().Epoch; e != fence+3 {
		t.Errorf("an unchanged list under a new grant kept epoch %d, want %d", e, fence+3)
	}
}

// TestChaos71_FenceEpochMirrorFollowsTheLease: the lock-free mirror a publish
// stamps from equals CurrentEpoch across provider install, acquire and
// self-fence.
func TestChaos71_FenceEpochMirrorFollowsTheLease(t *testing.T) {
	tempHADir(t)
	h := &HAState{}
	t.Cleanup(h.Stop)
	check := func(step string) {
		t.Helper()
		if got, want := h.PublishedFenceEpoch(), h.CurrentEpoch(); got != want {
			t.Errorf("%s: mirror %d != CurrentEpoch %d", step, got, want)
		}
	}
	check("legacy")
	h.SetLeaseProvider(halease.NewFake(time.Minute), "cp-a")
	check("provider installed")
	if _, err := h.EnableAsLeader("10.0.0.9:50051", false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if h.PublishedFenceEpoch() <= 0 {
		t.Fatal("no mirrored epoch after acquire")
	}
	check("acquired")
	h.selfFence("test")
	check("self-fenced")
	h.SetLeaseProvider(nil, "")
	check("provider removed")
}

// TestChaos71_Wall_OnlyCommitPublishCommits: commitLocked has ONE caller, so
// no publish path can skip the epoch stamp, the validation, the size record or
// the keyed latch. And the fence mirror has one writer, so it cannot drift
// from CurrentEpoch.
func TestChaos71_Wall_OnlyCommitPublishCommits(t *testing.T) {
	callers, writes := cpScanCommitAndFenceWrites(t)
	if len(callers) != 1 || callers["commitPublish"] == 0 {
		t.Errorf("commitLocked callers = %v, want only commitPublish", callers)
	}
	allowed := map[string]map[string]bool{
		"fenceEpoch": {"syncFenceEpochLocked": true},
		"leaseEpoch": {"setLeaseEpochLocked": true},
		"lease":      {"SetLeaseProvider": true},
	}
	for field, owners := range writes {
		for owner := range owners {
			if !allowed[field][owner] {
				t.Errorf("%s writes %s directly — go through %v so the fence mirror stays in step", owner, field, allowed[field])
			}
		}
	}
	for field := range allowed {
		if len(writes[field]) == 0 {
			t.Errorf("the wall found no write of %s — its selector has gone stale", field)
		}
	}
}

// cpScanCommitAndFenceWrites walks every production file: who calls
// commitLocked, and who writes fenceEpoch / leaseEpoch / lease.
func cpScanCommitAndFenceWrites(t *testing.T) (callers map[string]int, writes map[string]map[string]int) {
	t.Helper()
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	callers, writes = map[string]int{}, map[string]map[string]int{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range f.Decls {
			owner := cpTopLevelName(decl)
			ast.Inspect(decl, func(n ast.Node) bool {
				cpNoteCommitOrFenceWrite(n, owner, callers, writes)
				return true
			})
		}
	}
	return callers, writes
}

func cpNoteCommitOrFenceWrite(n ast.Node, owner string, callers map[string]int, writes map[string]map[string]int) {
	switch x := n.(type) {
	case *ast.CallExpr:
		sel, ok := x.Fun.(*ast.SelectorExpr)
		if !ok {
			return
		}
		if sel.Sel.Name == "commitLocked" {
			callers[owner]++
		}
		if inner, ok := sel.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "Store" && inner.Sel.Name == "fenceEpoch" {
			cpCount(writes, "fenceEpoch", owner)
		}
	case *ast.AssignStmt:
		for _, lhs := range x.Lhs {
			if sel, ok := lhs.(*ast.SelectorExpr); ok && (sel.Sel.Name == "leaseEpoch" || sel.Sel.Name == "lease") {
				cpCount(writes, sel.Sel.Name, owner)
			}
		}
	}
}

func cpCount(m map[string]map[string]int, field, owner string) {
	if m[field] == nil {
		m[field] = map[string]int{}
	}
	m[field][owner]++
}
