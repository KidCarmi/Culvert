package main

// cp_addr_alert_latch_chaos_test.go — CHAOS-71: one config_snapshot_rejected
// page per address-publish rejection episode (Codex P2 4298687158 on #1556).

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

// cpRejectedPages counts config_snapshot_rejected pages.
func cpRejectedPages(t *testing.T) func() int {
	t.Helper()
	cpStartupAlertsLoaded(t, true) // steady state: the webhooks are loaded
	var mu sync.Mutex
	n := 0
	prev := fireAlert
	fireAlert = func(event string, _ AlertPayload) {
		if event == "config_snapshot_rejected" {
			mu.Lock()
			n++
			mu.Unlock()
		}
	}
	t.Cleanup(func() { fireAlert = prev })
	return func() int { mu.Lock(); defer mu.Unlock(); return n }
}

// cpOversizedListStore is a published, owned store whose budget admits the
// committed snapshot but not long.
func cpOversizedListStore(t *testing.T, long []string) *ConfigStore {
	t.Helper()
	s := &ConfigStore{}
	if err := s.Update(cpCommitSnapshot(50)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	snap := s.Get()
	snap.CPAddresses = long
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	prev := snapshotWireBudget
	snapshotWireBudget = len(b) - 1
	t.Cleanup(func() { snapshotWireBudget = prev })
	return s
}

func cpLongList(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s-%02d.a-rather-long-control-plane-hostname.example.internal:50051", prefix, i)
	}
	return out
}

// TestChaos71_AddressRejectionPagesOncePerEpisode: N rejected retries of a
// persistently oversized owned republish page exactly ONCE (every attempt is
// still counted); a successful publish ends the episode and the next failure
// pages exactly once more; replacing ownership opens a new episode too.
func TestChaos71_AddressRejectionPagesOncePerEpisode(t *testing.T) {
	pages := cpRejectedPages(t)
	long := cpLongList("cp", 40)
	s := cpOversizedListStore(t, long)
	src := func() []string { return long }
	s.setCPAddressSource(src)
	// The test drives the retry loop itself: mark the store as already
	// retrying so no failure spawns a background loop, and the sleep seam is
	// only ever called from this goroutine.
	ownTheLoop := func() {
		s.addrPubMu.Lock()
		s.addrPub.retrying = true
		s.addrPubMu.Unlock()
	}
	ownTheLoop()
	rounds, limit := 0, 0
	prevSleep := cpAddrRetrySleep
	cpAddrRetrySleep = func(context.Context, time.Duration) bool { rounds++; return rounds <= limit }
	t.Cleanup(func() { cpAddrRetrySleep = prevSleep })
	runRetries := func(n int) {
		rounds, limit = 0, n
		s.retryCPAddrPublish(context.Background())
		ownTheLoop()
	}

	// The first rejection pages — the fail-closed visibility stays.
	if err := s.reconcileCPAddressesFrom("ha_enable", src); err == nil {
		t.Fatal("precondition: the oversized republish was accepted")
	}
	if got := pages(); got != 1 {
		t.Fatalf("the first rejection paged %d time(s), want 1", got)
	}

	const retries = 6
	runRetries(retries)
	if got := pages(); got != 1 {
		t.Errorf("%d rejected retries paged %d time(s) in total, want 1 — a persistent rejection would page every 30 s forever", retries, got)
	}
	if st := s.cpAddrPublishSnapshot(); !st.pending || st.attempts != retries+1 {
		t.Errorf("pending state = %+v, want pending with every attempt counted (%d)", st, retries+1)
	}

	// The supervisor's activation re-runs the same address publish on every
	// rebind: latched by the same episode.
	for i := 0; i < 3; i++ {
		_, _ = s.UpdateCPAddressesFrom(src)
	}
	if got := pages(); got != 1 {
		t.Errorf("repeated activation publishes paged again (%d pages)", got)
	}

	// Success ends the episode.
	snapshotWireBudget = maxSnapshotWireBytes
	runRetries(3)
	if st := s.cpAddrPublishSnapshot(); st.pending {
		t.Fatalf("the retry did not clear the pending state after the budget was restored: %+v", st)
	}

	// A new failure pages exactly once more.
	longer := cpLongList("cp-b", 60)
	b, _ := json.Marshal(func() ConfigSnapshot { x := s.Get(); x.CPAddresses = longer; return x }())
	snapshotWireBudget = len(b) - 1
	_ = s.reconcileCPAddressesFrom("ha_standby_entry", func() []string { return longer })
	_ = s.reconcileCPAddressesFrom("config_publish", func() []string { return longer })
	if got := pages(); got != 2 {
		t.Errorf("a new episode after a success paged %d time(s) in total, want 2", got)
	}

	// A NEW owner superseding the old one (no release in between) starts a
	// new episode: its first rejection pages.
	s.setCPAddressSource(func() []string { return longer })
	_ = s.reconcileCPAddressesFrom("ha_enable", func() []string { return longer })
	if got := pages(); got != 3 {
		t.Errorf("the first rejection under a superseding owner paged %d time(s) in total, want 3", got)
	}

	// Releasing and re-taking ownership likewise.
	s.releaseCPAddressSource()
	ownTheLoop()
	s.setCPAddressSource(func() []string { return longer })
	_ = s.reconcileCPAddressesFrom("ha_enable", func() []string { return longer })
	if got := pages(); got != 4 {
		t.Errorf("the first rejection after an ownership change paged %d time(s) in total, want 4", got)
	}
}

// TestChaos71_FullPublishRejectionsStillPageEach: the latch is the ADDRESS
// kind's. A full publish is an operator action, never retried in a loop, and
// each rejected one still pages (dedupe aside).
func TestChaos71_FullPublishRejectionsStillPageEach(t *testing.T) {
	pages := cpRejectedPages(t)
	s := &ConfigStore{}
	if err := s.Update(cpCommitSnapshot(10)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	prev := snapshotWireBudget
	snapshotWireBudget = 2048
	t.Cleanup(func() { snapshotWireBudget = prev })
	_ = s.Update(cpCommitSnapshot(2000))
	_ = s.Update(cpCommitSnapshot(2001))
	if got := pages(); got != 2 {
		t.Errorf("two rejected full publishes paged %d time(s), want 2", got)
	}
}

// cpStartupAlertsLoaded sets whether the startup alert flush has happened (the
// webhooks are loaded) for the test's duration, with an empty queue. The test
// binary otherwise inherits whatever an earlier test left.
func cpStartupAlertsLoaded(t *testing.T, loaded bool) {
	t.Helper()
	startupAlertMu.Lock()
	prevQueue, prevFlushed := startupAlertQueue, startupAlertFlushed
	startupAlertQueue, startupAlertFlushed = nil, loaded
	startupAlertMu.Unlock()
	t.Cleanup(func() {
		startupAlertMu.Lock()
		startupAlertQueue, startupAlertFlushed = prevQueue, prevFlushed
		startupAlertMu.Unlock()
	})
}

// cpBootPages captures config_snapshot_rejected on BOTH delivery paths: direct
// fires (fireAlert, which before the startup flush would reach an empty webhook
// list — lost) and deliveries made by the startup flush (startupAlertFire).
// The startup queue starts unflushed and empty, as at boot.
func cpBootPages(t *testing.T) (direct, flushed func() int) {
	t.Helper()
	cpStartupAlertsLoaded(t, false)
	var mu sync.Mutex
	nDirect, nFlushed := 0, 0
	prevFire := fireAlert
	fireAlert = func(event string, _ AlertPayload) {
		if event == "config_snapshot_rejected" {
			mu.Lock()
			nDirect++
			mu.Unlock()
		}
	}
	prevStartup := startupAlertFire
	startupAlertFire = func(event string, _ AlertPayload) {
		if event == "config_snapshot_rejected" {
			mu.Lock()
			nFlushed++
			mu.Unlock()
		}
	}
	t.Cleanup(func() { fireAlert, startupAlertFire = prevFire, prevStartup })
	return func() int { mu.Lock(); defer mu.Unlock(); return nDirect },
		func() int { mu.Lock(); defer mu.Unlock(); return nFlushed }
}

// cpOwnedRejectingStore is an owned store whose address publish is rejected,
// with the retry loop driven by the test (no background loop is spawned).
func cpOwnedRejectingStore(t *testing.T) (s *ConfigStore, src func() []string, runRetries func(int)) {
	t.Helper()
	long := cpLongList("boot", 40)
	s = cpOversizedListStore(t, long)
	src = func() []string { return long }
	s.setCPAddressSource(src)
	own := func() {
		s.addrPubMu.Lock()
		s.addrPub.retrying = true
		s.addrPubMu.Unlock()
	}
	own()
	rounds, limit := 0, 0
	prev := cpAddrRetrySleep
	cpAddrRetrySleep = func(context.Context, time.Duration) bool { rounds++; return rounds <= limit }
	t.Cleanup(func() { cpAddrRetrySleep = prev })
	return s, src, func(n int) {
		rounds, limit = 0, n
		s.retryCPAddrPublish(context.Background())
		own()
	}
}

// TestChaos71_BootAddressRejectionIsPagedOnceAfterTheWebhooksLoad — Codex P2
// 4299279051. A persisted leader's address rejection lands in initCluster,
// before initPersistentAdminState loads the webhooks. It must not be fired
// into the empty store (and then latched silent): it queues, and the startup
// flush delivers it exactly ONCE. Retries in the same episode, before or after
// the flush, stay silent.
func TestChaos71_BootAddressRejectionIsPagedOnceAfterTheWebhooksLoad(t *testing.T) {
	direct, flushed := cpBootPages(t)
	s, src, runRetries := cpOwnedRejectingStore(t)

	if err := s.reconcileCPAddressesFrom(haTransitionResume, src); err == nil {
		t.Fatal("precondition: the boot republish was accepted")
	}
	runRetries(4) // the retry loop keeps failing before the webhooks load
	if d := direct(); d != 0 {
		t.Fatalf("%d page(s) fired before the webhooks loaded — lost to an empty webhook list while the latch silences every retry", d)
	}

	flushStartupAlerts() // initPersistentAdminState: the webhooks are loaded
	if f := flushed(); f != 1 {
		t.Fatalf("the startup flush delivered %d config_snapshot_rejected page(s), want exactly 1", f)
	}
	runRetries(4)
	_, _ = s.UpdateCPAddressesFrom(src) // an activation retry, same episode
	if d, f := direct(), flushed(); d != 0 || f != 1 {
		t.Errorf("retries in the same episode paged again after the flush (direct=%d flushed=%d)", d, f)
	}
}

// TestChaos71_BootAddressRejectionResolvedBeforeTheFlushIsDropped is the
// control in the other direction: an episode that ended before the webhooks
// loaded (the list published) is not paged late. And after the flush, a new
// episode's first rejection pages at once — nothing is held back.
func TestChaos71_BootAddressRejectionResolvedBeforeTheFlushIsDropped(t *testing.T) {
	direct, flushed := cpBootPages(t)
	s, src, runRetries := cpOwnedRejectingStore(t)

	_ = s.reconcileCPAddressesFrom(haTransitionResume, src)
	snapshotWireBudget = maxSnapshotWireBytes
	runRetries(2) // the list publishes: the episode ends before the flush
	if st := s.cpAddrPublishSnapshot(); st.pending {
		t.Fatalf("precondition: still pending %+v", st)
	}
	flushStartupAlerts()
	if f := flushed(); f != 0 {
		t.Errorf("a rejection whose episode ended before the webhooks loaded was paged late (%d)", f)
	}

	longer := cpLongList("boot-b", 60)
	b, _ := json.Marshal(func() ConfigSnapshot { x := s.Get(); x.CPAddresses = longer; return x }())
	snapshotWireBudget = len(b) - 1
	_ = s.reconcileCPAddressesFrom(haTransitionEnable, func() []string { return longer })
	if d := direct(); d != 1 {
		t.Errorf("a new episode's first rejection after the flush paged %d time(s), want 1", d)
	}
}
