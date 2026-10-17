package main

// config_commit_chaos_test.go — CHAOS-71: ONE commit path for every config
// publish (Codex P1 4296091768 + P2 4296091783 on #1556). The address-only
// publish used to be a second commit path that skipped invariants the full
// path kept; both now go through commitPublish, and this file pins the
// invariants against BOTH paths.

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

// cpRejectAddresses latches an ADDRESS-publish rejection through the owned
// publish path (the only writer of the address latch). The store is marked as
// already retrying, so no background retry loop is spawned.
func cpRejectAddresses(t *testing.T, s *ConfigStore) {
	t.Helper()
	long := make([]string, 400)
	for i := range long {
		long[i] = fmt.Sprintf("cp-%03d.a-rather-long-control-plane-hostname.example.internal:50051", i)
	}
	s.addrPubMu.Lock()
	s.addrPub.retrying = true
	s.addrPubMu.Unlock()
	snapshotWireBudget = 8192
	_, err := s.publishOwnedCPAddresses("test", func() []string { return long })
	snapshotWireBudget = maxSnapshotWireBytes
	if err == nil {
		t.Fatal("precondition: the over-budget address publish was accepted")
	}
	if cpLatch(s, publishAddresses) == "" {
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
			_, err := s.publishOwnedCPAddresses("test", func() []string { return []string{fmt.Sprintf("10.0.0.%d:50051", n)} })
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

// cpLatch reads one kind's rejection latch: the full kind's is store state,
// the address kind's is part of the generation-guarded publish record.
func cpLatch(s *ConfigStore, kind publishKind) string {
	if kind == publishFull {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.lastPublishErr
	}
	return s.cpAddrPublishSnapshot().rejectErr
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

// cpCommitPath is one publish path under test, with the seam that opens its
// validation→commit window and a competing commit of the OTHER kind.
type cpCommitPath struct {
	name    string
	commit  func(s *ConfigStore, n int) error
	window  *func()
	compete func(t *testing.T, s *ConfigStore)
}

func cpCommitPaths() []cpCommitPath {
	return []cpCommitPath{
		{"full_update", func(s *ConfigStore, n int) error { return s.Update(cpCommitSnapshot(n)) },
			&configPublishBeforeCommit, func(t *testing.T, s *ConfigStore) {
				if _, err := s.UpdateCPAddressesFrom(func() []string { return []string{"10.9.9.9:50051"} }); err != nil {
					t.Fatalf("competitor: %v", err)
				}
			}},
		{"address_publish", func(s *ConfigStore, n int) error {
			_, err := s.UpdateCPAddressesFrom(func() []string { return []string{fmt.Sprintf("10.0.0.%d:50051", n)} })
			return err
		}, &cpAddrMergeBeforeCommit, func(t *testing.T, s *ConfigStore) {
			if err := s.Update(cpCommitSnapshot(77)); err != nil {
				t.Fatalf("competitor: %v", err)
			}
		}},
	}
}

// TestChaos71_EveryCommitIsBasedOnTheVersionItValidated — Codex P1s 4296608932
// and 4296608940, against BOTH paths:
//   - a commit that lands between an attempt's validation and its commit makes
//     the attempt REBUILD and revalidate (it commits onto the competitor, not
//     over it);
//   - the committed version is never lower than any version served or seeded
//     (a replicated snapshot seeded above the counter included).
func TestChaos71_EveryCommitIsBasedOnTheVersionItValidated(t *testing.T) {
	for _, p := range cpCommitPaths() {
		t.Run(p.name+"/rebuilds_onto_a_competing_commit", func(t *testing.T) {
			epoch := int64(0)
			s := cpCommitFixture(t, &epoch)
			calls, competitorVersion := 0, int64(0)
			prev := *p.window
			*p.window = func() {
				calls++
				if calls == 1 {
					p.compete(t, s)
					competitorVersion = s.Get().Version
				}
			}
			t.Cleanup(func() { *p.window = prev })

			if err := p.commit(s, 60); err != nil {
				t.Fatalf("commit: %v", err)
			}
			if calls != 2 {
				t.Errorf("the attempt validated %d time(s), want 2 — a commit between validation and commit must force a rebuild", calls)
			}
			if got := s.Get().Version; got != competitorVersion+1 {
				t.Errorf("committed v%d, want v%d (directly onto the competitor's commit)", got, competitorVersion+1)
			}
			if p.name == "address_publish" && len(s.Get().BlockedHosts) != 77 {
				t.Errorf("the address publish was merged onto a stale base (%d hosts, competitor committed 77)", len(s.Get().BlockedHosts))
			}
		})
		t.Run(p.name+"/never_below_a_seeded_version", func(t *testing.T) {
			epoch := int64(0)
			s := cpCommitFixture(t, &epoch)
			seeded := s.Get()
			seeded.Version = s.Version() + 100
			s.seedReplicatedSnapshot(seeded)
			if got := s.Version(); got != seeded.Version {
				t.Errorf("after the seed the store reports v%d, want the seeded v%d — DPs at it would read \"unchanged\"", got, seeded.Version)
			}
			if err := p.commit(s, 61); err != nil {
				t.Fatalf("commit: %v", err)
			}
			if got := s.Get().Version; got <= seeded.Version || s.Version() != got {
				t.Errorf("committed v%d (store v%d) after a seed at v%d — must be strictly above it", got, s.Version(), seeded.Version)
			}
		})
	}
}

// TestChaos71_FullPublishCannotOverwriteAPromotionRestamp — Codex P1
// 4296608932, deterministically: a full publish validated at epoch 0 loses the
// window to a promotion that restamps the committed list at epoch E. It must
// rebuild and commit at E, so a DP that learned E on heartbeat accepts it.
func TestChaos71_FullPublishCannotOverwriteAPromotionRestamp(t *testing.T) {
	epoch := int64(0)
	s := cpCommitFixture(t, &epoch)
	const promoted = int64(41)
	calls := 0
	prev := configPublishBeforeCommit
	configPublishBeforeCommit = func() {
		calls++
		if calls == 1 { // the promotion lands inside the full publish's window
			epoch = promoted
			if _, err := s.UpdateCPAddressesFrom(func() []string { return s.Get().CPAddresses }); err != nil {
				t.Fatalf("restamp: %v", err)
			}
			if got := s.Get().Epoch; got != promoted {
				t.Fatalf("precondition: the promotion restamp committed epoch %d", got)
			}
		}
	}
	t.Cleanup(func() { configPublishBeforeCommit = prev })

	if err := s.Update(cpCommitSnapshot(70)); err != nil {
		t.Fatalf("full publish: %v", err)
	}
	got := s.Get()
	if got.Epoch != promoted || len(got.BlockedHosts) != 70 {
		t.Fatalf("committed epoch %d with %d hosts, want epoch %d with the full publish's 70", got.Epoch, len(got.BlockedHosts), promoted)
	}
	t.Cleanup(resetDPLastSeenEpochForTest())
	if !dpObserveEpoch("heartbeat", promoted) || !dpObserveEpoch("config snapshot", got.Epoch) {
		t.Fatal("a DP that saw the promotion's epoch on heartbeat rejected the full publish")
	}
}

// TestChaos71_ConcurrentPublishesAndRestampsEndOnTheCurrentEpoch is the -race
// version: full publishes race epoch changes and their restamps. Whatever the
// interleaving, the final commit carries the final epoch and versions only
// ever rise.
func TestChaos71_ConcurrentPublishesAndRestampsEndOnTheCurrentEpoch(t *testing.T) {
	var epoch atomic.Int64
	prevEpoch := publishFenceEpoch
	publishFenceEpoch = epoch.Load
	t.Cleanup(func() { publishFenceEpoch = prevEpoch })
	s := &ConfigStore{}
	if err := s.Update(cpCommitSnapshot(5)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var wg sync.WaitGroup
	var lastSeen atomic.Int64
	observe := func() {
		v := s.Version()
		for {
			prev := lastSeen.Load()
			if v <= prev || lastSeen.CompareAndSwap(prev, v) {
				return
			}
		}
	}
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				_ = s.Update(cpCommitSnapshot(10 + w))
				observe()
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := int64(1); e <= 25; e++ {
			epoch.Store(e)
			_, _ = s.UpdateCPAddressesFrom(func() []string { return s.Get().CPAddresses })
			observe()
		}
	}()
	wg.Wait()
	// One last restamp settles a final epoch change that raced a publish.
	_, _ = s.UpdateCPAddressesFrom(func() []string { return s.Get().CPAddresses })
	if got, want := s.Get().Epoch, epoch.Load(); got != want {
		t.Errorf("final committed epoch %d, want the current fence epoch %d", got, want)
	}
	if v := s.Version(); v < lastSeen.Load() {
		t.Errorf("version went backwards: final v%d below an observed v%d", v, lastSeen.Load())
	}
}

// TestChaos71_ResyncThenRepromoteNeverRewindsTheVersion — Codex P1 4296608940
// end to end. A long-lived leader's counter is at v100; it self-fences,
// resyncs as a standby and seeds the new leader's snapshot at v200; then it is
// promoted again (the no-op onPromote: armVersionPersistence does not re-run).
// The re-promotion republish must commit above v200, never v101.
func TestChaos71_ResyncThenRepromoteNeverRewindsTheVersion(t *testing.T) {
	const (
		myAddr    = "10.0.0.2:50051"
		peer      = "10.0.0.9:50051"
		newLeader = "10.0.0.7:50051"
	)
	h := cpAddrTopologyFixture(t)
	cpAddrActiveCP(t, myAddr)
	if _, err := h.EnableAsLeader(peer, false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	s := globalConfigStore
	s.mu.Lock()
	s.version, s.snap.Version = 100, 100 // a long-lived leader's counter
	s.mu.Unlock()

	h.selfFence("test: lease lost")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.StartAsStandby(ctx, newLeader, "tok", myAddr, "", "", "", false, func() error { return nil })

	leaderSnap := cpCommitSnapshot(90)
	leaderSnap.Version = 200
	leaderSnap.CPAddresses = []string{"new-leader-view.example:50051"}
	s.seedReplicatedSnapshot(leaderSnap) // what applyHABundle installs on resync
	if got := s.Version(); got < 200 {
		t.Fatalf("after the resync seed the store serves v%d — DPs at v200 would read \"unchanged\"", got)
	}

	if err := h.PromoteManually(); err != nil {
		t.Fatalf("re-promote: %v", err)
	}
	got := s.Get()
	if got.Version <= 200 || s.Version() != got.Version {
		t.Fatalf("re-promotion committed v%d (store v%d) — must be above the seeded v200", got.Version, s.Version())
	}
	if !slicesEqual(got.CPAddresses, buildCPAddressList()) {
		t.Errorf("re-promotion list %v != derived %v", got.CPAddresses, buildCPAddressList())
	}
}

// TestChaos71_CommitCarriesTheEpochCurrentAtCommit: a new grant that lands
// inside the validation→commit window with NO competing commit still makes
// the attempt restamp — the epoch is the one current at commit, not at plan.
func TestChaos71_CommitCarriesTheEpochCurrentAtCommit(t *testing.T) {
	for _, p := range cpCommitPaths() {
		t.Run(p.name, func(t *testing.T) {
			epoch := int64(3)
			s := cpCommitFixture(t, &epoch)
			calls := 0
			prev := *p.window
			*p.window = func() {
				calls++
				if calls == 1 {
					epoch = 9 // a grant, and nothing else, inside the window
				}
			}
			t.Cleanup(func() { *p.window = prev })
			if err := p.commit(s, 62); err != nil {
				t.Fatalf("commit: %v", err)
			}
			if got := s.Get().Epoch; got != 9 {
				t.Errorf("committed epoch %d, want 9 — the epoch current at commit", got)
			}
		})
	}
}

// TestChaos71_AddressPublishRebuildsOntoASeedBelowTheCounter: a replicated
// snapshot seeded inside the window at a version BELOW this store's counter
// changes the committed content without moving the counter. The base check
// covers the whole committed state, so the address publish rebuilds onto the
// seeded snapshot instead of merging onto the content it replaced.
func TestChaos71_AddressPublishRebuildsOntoASeedBelowTheCounter(t *testing.T) {
	epoch := int64(0)
	s := cpCommitFixture(t, &epoch)
	s.mu.Lock()
	s.version = 500 // this store's own counter is ahead of the leader's
	s.mu.Unlock()
	calls := 0
	prev := cpAddrMergeBeforeCommit
	cpAddrMergeBeforeCommit = func() {
		calls++
		if calls == 1 {
			seeded := cpCommitSnapshot(33)
			seeded.Version = 200
			s.seedReplicatedSnapshot(seeded)
		}
	}
	t.Cleanup(func() { cpAddrMergeBeforeCommit = prev })

	if _, err := s.UpdateCPAddressesFrom(func() []string { return []string{"10.0.0.4:50051"} }); err != nil {
		t.Fatalf("address publish: %v", err)
	}
	got := s.Get()
	if calls != 2 || len(got.BlockedHosts) != 33 {
		t.Errorf("validated %d time(s), committed %d hosts — want a rebuild onto the seeded 33-host snapshot", calls, len(got.BlockedHosts))
	}
	if got.Version <= 500 {
		t.Errorf("committed v%d, want above the counter's v500", got.Version)
	}
}

// TestChaos71_ReleaseCPAddressSourceClearsOwnershipState: releasing ownership
// (a refused synchronous activation) takes the pending-republish state and the
// address rejection latch with it, so nothing reports a Control Plane list.
func TestChaos71_ReleaseCPAddressSourceClearsOwnershipState(t *testing.T) {
	_ = cpIsolateActivation(t)
	s := globalConfigStore
	s.setCPAddressSource(buildCPAddressList)
	if err := s.Update(ConfigSnapshot{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_ = s.noteCPAddrPublish("test", errors.New("injected address rejection"), s.cpAddrPublishGen())
	if row := checkCPAddressList(); row.Status != diagFail {
		t.Fatalf("precondition: row %+v", row)
	}

	s.releaseCPAddressSource()
	if st := s.cpAddrPublishSnapshot(); st.pending {
		t.Errorf("pending state survived the release: %+v", st)
	}
	if got := cpLatch(s, publishAddresses); got != "" {
		t.Errorf("address rejection latch survived the release: %q", got)
	}
	if row := checkCPAddressList(); row.Status != diagOK || !strings.Contains(row.Message, "Not an active Control Plane") {
		t.Errorf("cp_address_list after release = %+v", row)
	}
}

// TestChaos71_StaleRetrySuccessDoesNotClearANewerFailure — Codex P1
// 4297020949, the exact interleaving: the retry loop publishes topology A;
// before it records that success, an HA transition to topology B fails its
// own publish and latches. A's success must NOT clear B's pending state — the
// loop goes round again from the live source and publishes B.
func TestChaos71_StaleRetrySuccessDoesNotClearANewerFailure(t *testing.T) {
	_ = cpIsolateActivation(t)
	s := globalConfigStore
	topoA := []string{"10.0.0.9:50051", "10.0.0.2:50051"}
	topoB := []string{"10.0.0.7:50051", "10.0.0.2:50051"}
	var mu sync.Mutex
	live := topoA
	s.setCPAddressSource(func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), live...) })
	if err := s.Update(ConfigSnapshot{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// An earlier failure left the list pending (the loop now owns it).
	s.mu.Lock()
	s.snap.CPAddresses = nil
	s.mu.Unlock()
	_ = s.noteCPAddrPublish("ha_enable", errors.New("injected: rejected at commit"), s.cpAddrPublishGen())

	hookCalls := 0
	prevHook := cpAddrMergeBeforeCommit
	cpAddrMergeBeforeCommit = func() {
		hookCalls++
		if hookCalls == 1 { // A is validated and about to commit; B's publish fails NOW
			mu.Lock()
			live = topoB
			mu.Unlock()
			_ = s.noteCPAddrPublish(haTransitionPromote, errors.New("injected: B rejected at commit"), s.cpAddrPublishGen())
		}
	}
	t.Cleanup(func() { cpAddrMergeBeforeCommit = prevHook })
	rounds := 0
	prevSleep := cpAddrRetrySleep
	cpAddrRetrySleep = func(context.Context, time.Duration) bool { rounds++; return rounds <= 5 }
	t.Cleanup(func() { cpAddrRetrySleep = prevSleep })

	s.retryCPAddrPublish(context.Background())

	if st := s.cpAddrPublishSnapshot(); st.pending {
		t.Fatalf("the loop ended with the publish still pending: %+v", st)
	}
	if got := s.Get().CPAddresses; !slicesEqual(got, topoB) {
		t.Fatalf("committed %v, want topology B %v — A's stale success cleared B's failure and nothing retried B", got, topoB)
	}
	if rounds < 2 {
		t.Errorf("the loop ran %d round(s), want a second round for B", rounds)
	}
}

// TestChaos71_DeltaRingAppliesDeltasInCommitOrder is Codex P2 4302641878 on
// #1556: a full publish commits vN and then spends O(N) computing its delta
// outside the lock; meanwhile an address-only publish commits vN+1 and
// finishes first. The ring must still end contiguous at Version() — the late
// vN delta must not clear vN+1 — so a DP at vN-1 is served a delta to vN+1
// instead of a full snapshot.
func TestChaos71_DeltaRingAppliesDeltasInCommitOrder(t *testing.T) {
	ip := "203.0.113.71"
	clearUnenrolledPull(ip)
	t.Cleanup(func() { clearUnenrolledPull(ip) })
	svc := setupDeltaStore(t, cpCommitSnapshot(50).BlockedHosts, cpCommitSnapshot(60).BlockedHosts)
	s := globalConfigStore
	base := s.Version() // vN-1
	slow := base + 1    // vN: the full publish whose delta is slow

	entered, release := make(chan struct{}), make(chan struct{})
	prev := afterCommitBeforeDelta
	afterCommitBeforeDelta = func(target int64) {
		if target == slow {
			close(entered)
			<-release
		}
	}
	t.Cleanup(func() { afterCommitBeforeDelta = prev })

	done := make(chan error, 1)
	go func() { done <- s.Update(cpCommitSnapshot(80)) }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("the full publish never reached its delta computation")
	}
	// vN+1 commits and finishes its afterCommit while vN's delta is pending.
	if changed, err := s.UpdateCPAddressesFrom(func() []string { return []string{"10.0.0.7:50051"} }); err != nil || !changed {
		close(release)
		t.Fatalf("address publish: changed=%v err=%v", changed, err)
	}
	if _, _, _, newest := s.deltaRing.stats(); newest != base {
		t.Errorf("ring head = v%d while v%d is still computing, want v%d: a delta was applied out of commit order", newest, slow, base)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("full publish: %v", err)
	}

	cur := s.Version()
	if cur != slow+1 {
		t.Fatalf("Version() = %d, want %d", cur, slow+1)
	}
	if _, _, _, newest := s.deltaRing.stats(); newest != cur {
		t.Fatalf("ring head = v%d, want Version() v%d: the late delta left the ring behind", newest, cur)
	}
	chain, latest, ok := s.deltaRing.chain(base)
	if !ok || latest != cur || len(chain) != 2 {
		t.Fatalf("chain(v%d) = %d deltas, latest v%d, ok=%v; want 2 deltas to v%d", base, len(chain), latest, ok, cur)
	}
	for i := range chain {
		if want := base + int64(i); chain[i].Base != want || chain[i].Version != want+1 {
			t.Errorf("chain[%d] = v%d→v%d, want v%d→v%d", i, chain[i].Base, chain[i].Version, want, want+1)
		}
	}
	if len(chain[0].Added) != 20 || len(chain[1].Added)+len(chain[1].Removed) != 0 {
		t.Errorf("deltas: vN added %d, vN+1 changed %d; want 20 and 0", len(chain[0].Added), len(chain[1].Added)+len(chain[1].Removed))
	}
	if reply := callDelta(t, svc, deltaCtx(ip), base); reply.Mode != "delta" || reply.TargetVersion != cur || len(reply.Deltas) != 2 {
		t.Errorf("GetConfigDelta(v%d) = mode %q to v%d with %d deltas, want delta to v%d with 2", base, reply.Mode, reply.TargetVersion, len(reply.Deltas), cur)
	}
}

// TestChaos71_DeltaSlotCompletesWhenItsComputationPanics pins the hand-off's
// liveness: a commit whose delta computation panics still completes its slot
// (as a resync marker), so every later commit's delta is not stalled behind
// it forever.
func TestChaos71_DeltaSlotCompletesWhenItsComputationPanics(t *testing.T) {
	setupDeltaStore(t, cpCommitSnapshot(5).BlockedHosts)
	s := globalConfigStore
	boom := s.Version() + 1
	prev := afterCommitBeforeDelta
	afterCommitBeforeDelta = func(target int64) {
		if target == boom {
			panic("delta computation failed")
		}
	}
	t.Cleanup(func() { afterCommitBeforeDelta = prev })
	func() {
		defer func() { _ = recover() }()
		_ = s.Update(cpCommitSnapshot(6))
	}()
	if err := s.Update(cpCommitSnapshot(7)); err != nil {
		t.Fatalf("publish after the panic: %v", err)
	}
	if _, _, _, newest := s.deltaRing.stats(); newest != s.Version() {
		t.Fatalf("ring head = v%d, want v%d: a panicked commit's slot stalled the hand-off", newest, s.Version())
	}
	if _, _, ok := s.deltaRing.chain(boom - 1); ok {
		t.Error("a DP before the panicked commit was offered a delta across it, want a resync")
	}
	if _, latest, ok := s.deltaRing.chain(boom); !ok || latest != s.Version() {
		t.Errorf("chain(v%d) ok=%v latest=v%d, want a delta to v%d", boom, ok, latest, s.Version())
	}
}
