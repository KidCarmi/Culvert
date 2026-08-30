package main

// CHAOS-57 — gates for the threat-feed freshness plane.
//
// The defect these pin is a MONITORING defect, so the gates are mostly about
// what the surfaces say rather than what the proxy does. The one that matters
// most is TestChaos57_StaleFeedIsDistinguishableFromAHealthyOne: pre-fix a
// feed frozen a month ago and a feed synced a minute ago published the SAME
// /metrics output, because carryForward keeps culvert_threat_feed_entries
// steady through an outage. Everything else here exists to stop that fix from
// regressing into noise (alerting on every evaluation) or into silence
// (alerting on a node that has no threat feed at all).

import (
	"strings"
	"testing"
	"time"
)

// captureThreatFeedAlerts swaps the emission seam for a recorder and restores
// it, resetting the latches on both sides of the test so ordering under
// -shuffle cannot leak state between cases.
func captureThreatFeedAlerts(t *testing.T) *[]AlertPayload {
	t.Helper()
	resetThreatFeedAlertsForTest()
	var got []AlertPayload
	prev := threatFeedAlertFire
	threatFeedAlertFire = func(_ string, p AlertPayload) { got = append(got, p) }
	t.Cleanup(func() {
		threatFeedAlertFire = prev
		resetThreatFeedAlertsForTest()
	})
	return &got
}

func threatFeedEventNames(ps []AlertPayload) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Event)
	}
	return out
}

// running builds a snapshot for a feed that is enabled and holding entries.
func running(lastSuccess time.Time, fails int) threatFeedSnapshot {
	return threatFeedSnapshot{
		Enabled:      true,
		Entries:      200_000,
		LastAttempt:  lastSuccess,
		LastSuccess:  lastSuccess,
		LastRefresh:  lastSuccess,
		SyncInterval: 6 * time.Hour,

		ConsecutiveFailures: fails,
	}
}

// ── The core defect: a frozen feed must be distinguishable ───────────────────

// TestChaos57_StaleFeedIsDistinguishableFromAHealthyOne is the DEFECT gate.
// Two feeds — one refreshed a minute ago, one frozen for a month — must not
// produce the same scrape. Pre-fix they did: the only threat-feed series were
// blocked_total, entries and allowlist_masked_total, and carryForward holds
// `entries` steady through an arbitrarily long outage.
func TestChaos57_StaleFeedIsDistinguishableFromAHealthyOne(t *testing.T) {
	now := time.Now()
	var fresh, frozen strings.Builder
	writeThreatFeedMetricsAt(&fresh, running(now.Add(-time.Minute), 0), now)
	writeThreatFeedMetricsAt(&frozen, running(now.Add(-30*24*time.Hour), 12), now)

	if fresh.String() == frozen.String() {
		t.Fatal("a month-stale feed scrapes identically to a fresh one — the fault is invisible to Prometheus")
	}
	if !strings.Contains(frozen.String(), "culvert_threat_feed_stale 1") {
		t.Fatalf("stale feed must publish culvert_threat_feed_stale 1, got:\n%s", frozen.String())
	}
	if !strings.Contains(fresh.String(), "culvert_threat_feed_stale 0") {
		t.Fatalf("fresh feed must publish culvert_threat_feed_stale 0, got:\n%s", fresh.String())
	}
}

// TestChaos57_MetricsAbsentWhenFeedNotRunning is the CONTROL for the gauge.
// The documented paging rule is `culvert_threat_feed_stale == 1`; a node that
// never had a threat feed must publish no series at all rather than a 0 that
// an operator has to learn to distinguish from a healthy 0 (the CHAOS-54
// rule, applied to this plane).
func TestChaos57_MetricsAbsentWhenFeedNotRunning(t *testing.T) {
	var b strings.Builder
	writeThreatFeedMetricsAt(&b, threatFeedSnapshot{Enabled: false}, time.Now())
	if b.Len() != 0 {
		t.Fatalf("a node with no threat feed must publish no threat-feed freshness series, got:\n%s", b.String())
	}
}

// ── Status derivation ────────────────────────────────────────────────────────

func TestChaos57_StaleThresholdTracksTheConfiguredInterval(t *testing.T) {
	// A daily-syncing deployment must not be called stale at 24h — that is
	// one window, not four.
	if got := threatFeedStaleAfter(24 * time.Hour); got != 96*time.Hour {
		t.Fatalf("staleAfter(24h) = %s, want 96h (four windows)", got)
	}
	// A fast-syncing deployment must not page on twenty minutes of a public
	// feed being slow: the floor holds.
	if got := threatFeedStaleAfter(5 * time.Minute); got != threatFeedStaleFloor {
		t.Fatalf("staleAfter(5m) = %s, want the %s floor", got, threatFeedStaleFloor)
	}
}

// TestChaos57_NeverSyncedIsNotStale pins the distinction. Staleness is not
// computable from a zero timestamp, and an appliance two minutes into its
// first boot on a slow link has simply not finished — reporting it as
// "serving month-old intelligence" would be false.
func TestChaos57_NeverSyncedIsNotStale(t *testing.T) {
	s := threatFeedSnapshot{Enabled: true, SyncInterval: 6 * time.Hour}
	st := evaluateThreatFeedStatus(s, time.Now())
	if !st.NeverSynced {
		t.Fatal("a feed with a zero LastSuccess must report NeverSynced")
	}
	if st.Stale {
		t.Fatal("never-synced must not be reported as stale — the age is unknown, not infinite")
	}
}

// TestChaos57_ClockRollbackDoesNotInvertTheVerdict: NTP correcting a skewed
// appliance backwards puts LastSuccess in the future. The honest reading is
// "no usable age", not "fresh for the size of the jump" and not a negative
// staleness gauge.
func TestChaos57_ClockRollbackDoesNotInvertTheVerdict(t *testing.T) {
	now := time.Now()
	st := evaluateThreatFeedStatus(running(now.Add(2*time.Hour), 0), now)
	if st.Age < 0 {
		t.Fatalf("Age = %s, must never be negative", st.Age)
	}
	if st.Stale {
		t.Fatal("a future LastSuccess must not be reported as stale")
	}

	var b strings.Builder
	writeThreatFeedMetricsAt(&b, running(now.Add(2*time.Hour), 0), now)
	if strings.Contains(b.String(), "culvert_threat_feed_staleness_seconds -") {
		t.Fatalf("staleness gauge went negative under clock rollback:\n%s", b.String())
	}
}

// ── Alert latching ───────────────────────────────────────────────────────────

// TestChaos57_StaleAlertFiresOncePerCrossing is the noise CONTROL. The alert
// store's dedup window is 30s and the evaluation runs on every sync round, so
// without the latch a stale feed would re-page every window for as long as it
// stayed stale — which is how an operator learns to mute the channel.
func TestChaos57_StaleAlertFiresOncePerCrossing(t *testing.T) {
	got := captureThreatFeedAlerts(t)
	now := time.Now()
	stale := running(now.Add(-30*24*time.Hour), 0)

	for i := 0; i < 5; i++ {
		evaluateThreatFeedAlertsAt(stale, now)
	}
	if n := len(*got); n != 1 {
		t.Fatalf("stale alert fired %d times across 5 evaluations, want 1 (%v)", n, threatFeedEventNames(*got))
	}
	if (*got)[0].Event != "threat_feed_stale" {
		t.Fatalf("event = %q, want threat_feed_stale", (*got)[0].Event)
	}
}

// TestChaos57_RecoveryFiresAndRearms pins that the latch clears on OBSERVED
// evidence — a sync that actually landed — so a feed that goes stale twice
// pages twice, and that the recovery itself is reported.
func TestChaos57_RecoveryFiresAndRearms(t *testing.T) {
	got := captureThreatFeedAlerts(t)
	now := time.Now()

	evaluateThreatFeedAlertsAt(running(now.Add(-30*24*time.Hour), 0), now) // stale
	evaluateThreatFeedAlertsAt(running(now.Add(-time.Minute), 0), now)     // recovered
	evaluateThreatFeedAlertsAt(running(now.Add(-30*24*time.Hour), 0), now) // stale again

	want := []string{"threat_feed_stale", "threat_feed_recovered", "threat_feed_stale"}
	if names := threatFeedEventNames(*got); strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", names, want)
	}
}

// TestChaos57_SyncFailingFiresAtTheThreshold pins that a single blip stays
// silent and the third consecutive empty round pages — the release-catalog and
// SaaS-feed convention, so an operator learns one number for all three planes.
func TestChaos57_SyncFailingFiresAtTheThreshold(t *testing.T) {
	got := captureThreatFeedAlerts(t)
	now := time.Now()
	fresh := now.Add(-time.Minute)

	evaluateThreatFeedAlertsAt(running(fresh, 1), now)
	evaluateThreatFeedAlertsAt(running(fresh, 2), now)
	if len(*got) != 0 {
		t.Fatalf("alerts fired below the threshold: %v", threatFeedEventNames(*got))
	}
	evaluateThreatFeedAlertsAt(running(fresh, threatFeedFailingThreshold), now)
	if names := threatFeedEventNames(*got); len(names) != 1 || names[0] != "threat_feed_sync_failing" {
		t.Fatalf("events = %v, want [threat_feed_sync_failing]", names)
	}
}

// TestChaos57_NoAlertsWhenFeedNotRunning is the other side of the CHAOS-54
// rule: an appliance with no threat feed configured must never be paged about
// one. Its snapshot is all zeroes, which naively reads as "never synced,
// infinitely stale".
func TestChaos57_NoAlertsWhenFeedNotRunning(t *testing.T) {
	got := captureThreatFeedAlerts(t)
	evaluateThreatFeedAlertsAt(threatFeedSnapshot{Enabled: false}, time.Now())
	if len(*got) != 0 {
		t.Fatalf("a node with no threat feed was alerted about it: %v", threatFeedEventNames(*got))
	}
}

// ── Diagnostics row ──────────────────────────────────────────────────────────

// TestChaos57_ContractRowNeverFailsAServingNode pins the severity policy from
// the file header: a degraded feed is a warn, never a fail. The node is still
// enforcing policy and still blocking every entry it holds; a fail row would
// report a working gateway as broken, and on a surface operators wire to
// automation that has consequences.
func TestChaos57_ContractRowSeverityPolicy(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		snap threatFeedSnapshot
		want string
	}{
		{"not running", threatFeedSnapshot{Enabled: false}, diagOK},
		{"healthy", running(now.Add(-time.Minute), 0), diagOK},
		{"never synced", threatFeedSnapshot{Enabled: true, SyncInterval: 6 * time.Hour}, diagWarn},
		{"stale", running(now.Add(-30*24*time.Hour), 0), diagWarn},
		{"failing", running(now.Add(-time.Minute), 5), diagWarn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := threatFeedContractRow(evaluateThreatFeedStatus(tc.snap, now))
			if got.Status != tc.want {
				t.Fatalf("status = %q, want %q (message: %s)", got.Status, tc.want, got.Message)
			}
			if got.Code != "threat_feed" {
				t.Fatalf("code = %q, want threat_feed", got.Code)
			}
			if got.Status != diagOK && got.OperatorAction == "" {
				t.Fatal("a degraded row must carry an OperatorAction — a warning with no next step is noise")
			}
		})
	}
}

// TestChaos57_ContractRowIsRegistered pins the wiring. A health plane that is
// never called is the failure mode this whole file exists to prevent, one
// level up.
func TestChaos57_ContractRowIsRegistered(t *testing.T) {
	found := false
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "threat_feed" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("threat_feed row missing from the operator contract — the freshness plane is unreachable")
	}
}

// ── Codex review follow-ups (PR #1264) ───────────────────────────────────────

// TestChaos57_SyncOkIsFalseUntilARoundHasSucceeded is the DEFECT gate for the
// false healthy signal. On an enabled feed that has never synced, LastErr
// starts empty, so keying sync_ok on it alone published `sync_ok 1` beside a
// zero last-refresh timestamp and a diagnostics row reading "never synced" —
// visible on every boot, and permanent if the first fetch died before
// recording an error. An unknown state must never render as the healthy value.
func TestChaos57_SyncOkIsFalseUntilARoundHasSucceeded(t *testing.T) {
	var b strings.Builder
	writeThreatFeedMetricsAt(&b, threatFeedSnapshot{
		Enabled: true, SyncInterval: 6 * time.Hour, // never synced: LastErr == "", LastSuccess zero
	}, time.Now())

	if !strings.Contains(b.String(), "culvert_threat_feed_sync_ok 0") {
		t.Fatalf("a feed that has never synced must publish sync_ok 0, got:\n%s", b.String())
	}
}

// TestChaos57_SyncOkTrueOnlyAfterACleanRound is its CONTROL: the fix must not
// pin sync_ok to 0 forever.
func TestChaos57_SyncOkTrueOnlyAfterACleanRound(t *testing.T) {
	var b strings.Builder
	writeThreatFeedMetricsAt(&b, running(time.Now().Add(-time.Minute), 0), time.Now())
	if !strings.Contains(b.String(), "culvert_threat_feed_sync_ok 1") {
		t.Fatalf("a feed that just synced cleanly must publish sync_ok 1, got:\n%s", b.String())
	}
}

// TestChaos57_PartialRefreshIsNotStale is the root-side half of the engine gate
// with the same name. A feed whose surviving source refreshes on every window
// must not be reported stale — nor paged about — just because the other source
// is permanently 403ing and lastSuccess therefore never advances.
func TestChaos57_PartialRefreshIsNotStale(t *testing.T) {
	got := captureThreatFeedAlerts(t)
	now := time.Now()
	partial := threatFeedSnapshot{
		Enabled: true, Entries: 200_000,
		LastAttempt:  now.Add(-time.Minute),
		LastRefresh:  now.Add(-time.Minute), // surviving source refreshed just now
		LastSuccess:  time.Time{},           // never a fully-clean round
		LastErr:      "OpenPhish: HTTP 403",
		SyncInterval: 6 * time.Hour,
	}

	st := evaluateThreatFeedStatus(partial, now)
	if st.Stale {
		t.Fatal("a feed refreshed a minute ago by its surviving source must not be stale")
	}
	if st.NeverSynced {
		t.Fatal("a feed holding freshly-refreshed entries must not report NeverSynced")
	}
	evaluateThreatFeedAlertsAt(partial, now)
	if len(*got) != 0 {
		t.Fatalf("a partially-refreshing feed was alerted on: %v", threatFeedEventNames(*got))
	}
	// But the operator must still be able to SEE that one source is failing.
	var b strings.Builder
	writeThreatFeedMetricsAt(&b, partial, now)
	if !strings.Contains(b.String(), "culvert_threat_feed_sync_ok 0") {
		t.Fatalf("a feed with a permanently failing source must publish sync_ok 0, got:\n%s", b.String())
	}
}
