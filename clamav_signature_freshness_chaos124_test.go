package main

// clamav_signature_freshness_chaos124_test.go — CHAOS-124's gates.
//
// Four groups:
//  1. the SHAPE the pre-round surfaces could not see: a daemon that is
//     reachable, answering and scanning while its definitions are months old;
//  2. the two UNMEASURABLE shapes (no readable build date, a future-dated
//     database) and the rule that neither may be reported as fresh and neither
//     may page;
//  3. the ALERT discipline (fire once per episode, cleared only on an observed
//     newer database, never by elapsed time, and never by a daemon that simply
//     stopped answering);
//  4. the CONTAINMENT rules that make an observability plane safe — no series
//     at all on a node with no local ClamAV, no engine/version label on the
//     scrape endpoint, and no dial from a scrape.

import (
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/clamav"
)

// clamavSigTestClock installs a fixed clock and registers restoration. Global
// state, so every test that drives this plane registers cleanup per the
// repository's convention.
func clamavSigTestClock(t *testing.T, now time.Time) {
	t.Helper()
	resetClamAVSigHealthForTest()
	t.Cleanup(resetClamAVSigHealthForTest)
	clamavSigNow = func() time.Time { return now }
}

// versionWithDate builds a VERSION reply in clamd's own format.
func versionWithDate(dbTime time.Time) clamav.Version {
	return clamav.Version{
		Engine:    "ClamAV 1.4.1",
		DBVersion: "27456",
		DBDate:    dbTime.Format("Mon Jan 02 15:04:05 2006"),
		Raw:       "ClamAV 1.4.1/27456/" + dbTime.Format("Mon Jan 02 15:04:05 2006"),
	}
}

// captureSigAlerts redirects the alert seam and returns the collected details.
// The stand-in reports DISPATCHED, which is the subscribed posture: the
// once-per-episode latch is consumed only by a delivered alert
// (SEC-CLAMSIG-STALE-LATCH-1), so a stand-in that reported false would leave
// every episode open and make the fire-once gates below vacuous.
func captureSigAlerts(t *testing.T) *[]string {
	t.Helper()
	var fired []string
	prev := fireClamAVSignatureStaleAlert
	fireClamAVSignatureStaleAlert = func(detail string) bool {
		fired = append(fired, detail)
		return true
	}
	t.Cleanup(func() { fireClamAVSignatureStaleAlert = prev })
	return &fired
}

// captureUndeliveredSigAlerts is captureSigAlerts for the UNSUBSCRIBED
// posture: the sink is reached but dispatches nothing, exactly as the real
// HasSubscriber-gated sink does with no webhook configured (and as it does at
// boot, before the webhook store has loaded).
func captureUndeliveredSigAlerts(t *testing.T) *int {
	t.Helper()
	attempts := 0
	prev := fireClamAVSignatureStaleAlert
	fireClamAVSignatureStaleAlert = func(string) bool {
		attempts++
		return false
	}
	t.Cleanup(func() { fireClamAVSignatureStaleAlert = prev })
	return &attempts
}

// ── 1. the shape nothing could see ───────────────────────────────────────────

// TestStaleSignaturesAreObservable is the round's headline. A daemon whose
// definitions are 30 days old is reachable, answers VERSION, and scans — so
// ClamAVStatus is "connected", the clamav readiness row passes, the
// clamav_scan diagnostics row is silent and scan_clam_error never fires.
// Before this round nothing anywhere said the database had stopped moving.
func TestStaleSignaturesAreObservable(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	clamavSigTestClock(t, now)

	noteClamAVSignatureObservation(versionWithDate(now.Add(-30*24*time.Hour)), true)

	snap := clamavSigState()
	if !snap.Armed {
		t.Fatal("plane reports absent after an observation landed")
	}
	if !snap.AgeKnown {
		t.Fatal("age unknown for a reply carrying a parseable build date")
	}
	if !snap.Stale {
		t.Fatalf("a 30-day-old signature database is not reported stale (age %s, threshold %s)", snap.Age, clamavSigStaleAfter)
	}
	if got := snap.Age; got != 30*24*time.Hour {
		t.Fatalf("age = %s, want 720h", got)
	}

	var sb strings.Builder
	clamavSigWritePrometheus(&sb)
	out := sb.String()
	for _, want := range []string{
		"culvert_clamav_signature_stale 1",
		"culvert_clamav_signature_age_seconds 2592000",
		"culvert_clamav_signature_age_unknown 0",
		"culvert_clamav_signature_future_dated 0",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics missing %q — an operator on Prometheus/Alertmanager still cannot see AV currency.\n%s", want, out)
		}
	}
}

// TestFreshSignaturesAreQuiet is the negative control: the healthy case must
// produce no stale gauge, no row and no alert. A plane that reports every node
// is worse than none.
func TestFreshSignaturesAreQuiet(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	clamavSigTestClock(t, now)
	fired := captureSigAlerts(t)

	noteClamAVSignatureObservation(versionWithDate(now.Add(-3*time.Hour)), true)

	snap := clamavSigState()
	if snap.Stale || snap.Unknown || snap.FutureDated {
		t.Fatalf("a 3-hour-old database is not healthy: %+v", snap)
	}
	if len(*fired) != 0 {
		t.Fatalf("a fresh database paged: %q", *fired)
	}
	var sb strings.Builder
	clamavSigWritePrometheus(&sb)
	if !strings.Contains(sb.String(), "culvert_clamav_signature_stale 0") {
		t.Fatalf("stale gauge not 0 for a fresh database:\n%s", sb.String())
	}
}

// TestStalenessThresholdBoundary pins the 48-hour bound on both sides, so a
// later change to clamavSigStaleAfter has to be deliberate.
func TestStalenessThresholdBoundary(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		age       time.Duration
		wantStale bool
	}{
		{"one minute inside", clamavSigStaleAfter - time.Minute, false},
		{"exactly at the threshold", clamavSigStaleAfter, false},
		{"one minute past", clamavSigStaleAfter + time.Minute, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clamavSigTestClock(t, now)
			noteClamAVSignatureObservation(versionWithDate(now.Add(-tc.age)), true)
			if got := clamavSigState().Stale; got != tc.wantStale {
				t.Fatalf("age %s: stale = %v, want %v", tc.age, got, tc.wantStale)
			}
		})
	}
}

// ── 2. the unmeasurable shapes ───────────────────────────────────────────────

// TestUnreadableBuildDateIsUnknownNotFresh is the fail-safe rule of the whole
// plane. A daemon that answers VERSION with no parseable build date must be
// reported as UNKNOWN. Reporting it as fresh (age 0, stale 0 and nothing else)
// would be a silent failure of exactly the kind this round exists to remove:
// the operator would have a green signature gauge and no way to learn that it
// means nothing.
func TestUnreadableBuildDateIsUnknownNotFresh(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	clamavSigTestClock(t, now)
	fired := captureSigAlerts(t)

	noteClamAVSignatureObservation(clamav.Version{
		Engine: "ClamAV 0.103.8",
		Raw:    "ClamAV 0.103.8",
	}, true)

	snap := clamavSigState()
	if !snap.Armed {
		t.Fatal("plane reports absent after a VERSION reply landed")
	}
	if snap.AgeKnown {
		t.Fatal("age reported as KNOWN for a reply with no build date")
	}
	if !snap.Unknown {
		t.Fatal("a reply with no readable build date is not reported as unknown — it reads as a fresh database")
	}
	if snap.Stale {
		t.Fatal("an unmeasurable date was reported stale; it is an inability to measure, not evidence of staleness")
	}

	// It must be VISIBLE as its own gauge, and it must not page.
	var sb strings.Builder
	clamavSigWritePrometheus(&sb)
	if !strings.Contains(sb.String(), "culvert_clamav_signature_age_unknown 1") {
		t.Fatalf("no _age_unknown gauge for an unmeasurable date:\n%s", sb.String())
	}
	if len(*fired) != 0 {
		t.Fatalf("an unmeasurable date paged: %q — paging on an inability to measure would page on every daemon build this parse does not understand", *fired)
	}
}

// TestFutureDatedBuildDateIsFlaggedNotFresh covers clock skew between this
// node and whatever host reported the database. A negative age would compare
// below every threshold and pass the staleness check silently for as long as
// the skew lasted, so it is clamped to zero AND flagged.
func TestFutureDatedBuildDateIsFlaggedNotFresh(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	clamavSigTestClock(t, now)
	fired := captureSigAlerts(t)

	noteClamAVSignatureObservation(versionWithDate(now.Add(36*time.Hour)), true)

	snap := clamavSigState()
	if !snap.FutureDated {
		t.Fatal("a build date ahead of this node's clock is not flagged — the skew presents as a perfectly current database")
	}
	if snap.Age < 0 {
		t.Fatalf("age is negative (%s): it would compare below every threshold", snap.Age)
	}
	if snap.Age != 0 {
		t.Fatalf("age = %s, want 0 (clamped)", snap.Age)
	}
	if snap.Stale {
		t.Fatal("a future-dated database was reported stale")
	}
	var sb strings.Builder
	clamavSigWritePrometheus(&sb)
	if !strings.Contains(sb.String(), "culvert_clamav_signature_future_dated 1") {
		t.Fatalf("no _future_dated gauge:\n%s", sb.String())
	}
	if len(*fired) != 0 {
		t.Fatalf("clock skew paged: %q", *fired)
	}
}

// ── 3. alert discipline ──────────────────────────────────────────────────────

// TestStaleAlertFiresOncePerEpisode: the watcher polls every five minutes. An
// alert per poll would be 288 pages a day for one unchanged fault.
func TestStaleAlertFiresOncePerEpisode(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	clamavSigTestClock(t, now)
	fired := captureSigAlerts(t)

	stale := versionWithDate(now.Add(-10 * 24 * time.Hour))
	for range 12 {
		noteClamAVSignatureObservation(stale, true)
	}

	if len(*fired) != 1 {
		t.Fatalf("stale alert fired %d times across 12 polls, want 1: %q", len(*fired), *fired)
	}
	if d := (*fired)[0]; !strings.Contains(d, "10d") {
		t.Fatalf("alert Detail %q does not carry the age an operator needs", d)
	}
}

// TestStaleAlertClearedOnlyByObservedNewerDatabase. Elapsed time must not
// clear the episode, and neither must a daemon that stopped answering: both
// look identical to a healthy node from the outside, which is the mistake
// ca_health.go and storage_health.go call out by name.
func TestStaleAlertClearedOnlyByObservedNewerDatabase(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	clamavSigTestClock(t, now)
	fired := captureSigAlerts(t)

	noteClamAVSignatureObservation(versionWithDate(now.Add(-10*24*time.Hour)), true)
	if len(*fired) != 1 {
		t.Fatalf("onset did not fire: %q", *fired)
	}

	// A daemon that stops answering: ok=false. This must neither clear the
	// episode nor re-fire, and must leave the last observation in place.
	for range 5 {
		noteClamAVSignatureObservation(clamav.Version{}, false)
	}
	if len(*fired) != 1 {
		t.Fatalf("an unreachable daemon changed the alert state: %q — the unreachable fault already has its own row and alert", *fired)
	}
	if snap := clamavSigState(); !snap.Stale {
		t.Fatalf("a failed observation discarded the last known state: %+v", snap)
	}

	// Time passing is not evidence either: advance a week with no observation.
	clamavSigNow = func() time.Time { return now.Add(7 * 24 * time.Hour) }
	if snap := clamavSigState(); !snap.Stale {
		t.Fatal("staleness cleared itself as time passed")
	}

	// Only an OBSERVED newer database ends it...
	clamavSigNow = func() time.Time { return now }
	noteClamAVSignatureObservation(versionWithDate(now.Add(-1*time.Hour)), true)
	if snap := clamavSigState(); snap.Stale {
		t.Fatalf("a fresh observation did not clear staleness: %+v", snap)
	}

	// ...and the episode must be re-armed, so the NEXT outage pages again
	// rather than being suppressed by a latch nobody cleared.
	noteClamAVSignatureObservation(versionWithDate(now.Add(-20*24*time.Hour)), true)
	if len(*fired) != 2 {
		t.Fatalf("a second episode did not page (fired %d): %q", len(*fired), *fired)
	}
}

// TestUnknownDateDoesNotClearAnEpisode. A daemon that went stale and then
// started replying without a build date — an engine downgrade, a database
// unload, a different service answering the port — must not have its episode
// cleared by a reply that carries no evidence of anything.
func TestUnknownDateDoesNotClearAnEpisode(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	clamavSigTestClock(t, now)
	fired := captureSigAlerts(t)

	noteClamAVSignatureObservation(versionWithDate(now.Add(-10*24*time.Hour)), true)
	noteClamAVSignatureObservation(clamav.Version{Engine: "ClamAV 0.103.8", Raw: "ClamAV 0.103.8"}, true)

	// Back to a stale-but-readable database: the episode was never cleared, so
	// this must NOT be a second page.
	noteClamAVSignatureObservation(versionWithDate(now.Add(-11*24*time.Hour)), true)
	if len(*fired) != 1 {
		t.Fatalf("an unreadable reply cleared the episode and the same fault paged again (fired %d): %q", len(*fired), *fired)
	}
}

// TestFutureDatedReadingDoesNotClearAnEpisode. A stale node whose ClamAV host
// clock then jumps forward reports a future-dated build date, whose age is
// CLAMPED to zero. Without an explicit exclusion that clamp reads as a current
// database: the episode clears, a recovery is logged, and the stale database is
// still exactly as stale. Skew is an inability to measure, not evidence of
// freshness.
func TestFutureDatedReadingDoesNotClearAnEpisode(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	clamavSigTestClock(t, now)
	fired := captureSigAlerts(t)

	noteClamAVSignatureObservation(versionWithDate(now.Add(-10*24*time.Hour)), true)
	if len(*fired) != 1 {
		t.Fatalf("onset did not fire: %q", *fired)
	}

	// The ClamAV host's clock jumps a day ahead.
	noteClamAVSignatureObservation(versionWithDate(now.Add(24*time.Hour)), true)
	if snap := clamavSigState(); !snap.FutureDated {
		t.Fatalf("skew not flagged: %+v", snap)
	}

	// Clocks agree again and the database is still ten days old: this must NOT
	// be a second page, because the first episode was never legitimately
	// cleared.
	noteClamAVSignatureObservation(versionWithDate(now.Add(-10*24*time.Hour)), true)
	if len(*fired) != 1 {
		t.Fatalf("a future-dated reading cleared the episode and the same unresolved fault paged again (fired %d): %q", len(*fired), *fired)
	}
}

// TestStaleEpisodeSurvivesAnUndeliveredPage is SEC-CLAMSIG-STALE-LATCH-1's
// gate. The default posture is NO webhook configured, and this plane's latch
// clears only on an OBSERVED newer database — never on elapsed time. So if the
// latch were consumed by an alert that reached nobody, the operator who
// subscribes afterwards would never be paged for as long as freshclam stayed
// broken, which is precisely the condition the alert exists to report.
func TestStaleEpisodeSurvivesAnUndeliveredPage(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	clamavSigTestClock(t, now)

	stale := versionWithDate(now.Add(-10 * 24 * time.Hour))

	// Polls while nothing subscribes: the sink is reached every time and
	// dispatches nothing, so no episode may be consumed.
	attempts := captureUndeliveredSigAlerts(t)
	for range 3 {
		noteClamAVSignatureObservation(stale, true)
	}
	if *attempts != 3 {
		t.Fatalf("sink reached %d times across 3 unsubscribed polls, want 3: a consumed latch stopped re-attempting", *attempts)
	}

	// The operator now adds the webhook. The next poll must page.
	fired := captureSigAlerts(t)
	noteClamAVSignatureObservation(stale, true)
	if len(*fired) != 1 {
		t.Fatalf("after subscribing, the still-stale database paged %d times, want 1: the episode was burned on an undelivered alert", len(*fired))
	}
	if d := (*fired)[0]; !strings.Contains(d, "10d") {
		t.Fatalf("alert Detail %q does not carry the age an operator needs", d)
	}

	// And it is still once per episode from there.
	noteClamAVSignatureObservation(stale, true)
	if len(*fired) != 1 {
		t.Fatalf("delivered alert did not consume the episode (fired %d): %q", len(*fired), *fired)
	}
}

// TestStaleAlertAtBootPagesOnceTheWebhookStoreHasLoaded pins the ORDERING that
// made the latch-before-dispatch bug certain rather than merely likely.
// startScanSignatureWatch's immediate poll runs from initBackgroundServices,
// before initPersistentAdminState loads the webhook store, so the first
// observation of a node that booted with stale definitions always sees an
// empty subscription index — even when the webhook is configured on disk.
// Delivery at the next poll is what makes the page survive that.
func TestStaleAlertAtBootPagesOnceTheWebhookStoreHasLoaded(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	clamavSigTestClock(t, now)

	stale := versionWithDate(now.Add(-45 * 24 * time.Hour))

	// The watcher's immediate poll, before the webhook store exists.
	bootAttempts := captureUndeliveredSigAlerts(t)
	noteClamAVSignatureObservation(stale, true)
	if *bootAttempts != 1 {
		t.Fatalf("boot poll reached the sink %d times, want 1", *bootAttempts)
	}
	if snap := clamavSigState(); !snap.Stale {
		t.Fatalf("boot observation did not record staleness: %+v", snap)
	}

	// loadPersistentAdminState has now run and the subscription is live.
	fired := captureSigAlerts(t)
	noteClamAVSignatureObservation(stale, true)
	if len(*fired) != 1 {
		t.Fatalf("a node that booted with 45-day-old definitions paged %d times after the webhook store loaded, want 1", len(*fired))
	}
}

// ── 4. containment ───────────────────────────────────────────────────────────

// TestNoSeriesBeforeAnyObservation: a node with no local ClamAV must export
// NOTHING from this family. A row of zeros would be read by an alert rule as a
// signature database built at the Unix epoch — which is the CHAOS-54 rule, and
// is why the whole family is gated on Armed.
func TestNoSeriesBeforeAnyObservation(t *testing.T) {
	clamavSigTestClock(t, time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC))

	var sb strings.Builder
	clamavSigWritePrometheus(&sb)
	if out := sb.String(); out != "" {
		t.Fatalf("exported series with no observation — a node without ClamAV would publish a 1970 signature date:\n%s", out)
	}
	if snap := clamavSigState(); snap.Armed {
		t.Fatal("plane reports armed before any observation")
	}
}

// TestNoEngineOrVersionOnTheScrapeEndpoint. The engine string and database
// counter are on the role-gated /api/security-scan/status. As metric labels
// they would churn cardinality on every definition update — several times a
// day on a HEALTHY node, so the cost would land entirely on operators who have
// nothing wrong.
func TestNoEngineOrVersionOnTheScrapeEndpoint(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	clamavSigTestClock(t, now)

	noteClamAVSignatureObservation(versionWithDate(now.Add(-10*24*time.Hour)), true)

	var sb strings.Builder
	clamavSigWritePrometheus(&sb)
	out := sb.String()
	for _, banned := range []string{"ClamAV 1.4.1", "27456", "engine=", "db_version=", "{"} {
		if strings.Contains(out, banned) {
			t.Fatalf("scrape output carries %q — this family is deliberately unlabelled:\n%s", banned, out)
		}
	}
}

// TestObservationAgeDistinguishesFrozenReadings. A daemon that stopped
// answering freezes the age series: the database looks exactly as old as it
// was at the last reading, forever. _observation_age_seconds is the series
// that says so, and without it a stale row cannot be told from a fresh reading
// of an old database.
func TestObservationAgeDistinguishesFrozenReadings(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	clamavSigTestClock(t, now)

	noteClamAVSignatureObservation(versionWithDate(now.Add(-time.Hour)), true)

	var sb strings.Builder
	clamavSigWritePrometheus(&sb)
	if !strings.Contains(sb.String(), "culvert_clamav_signature_observation_age_seconds 0") {
		t.Fatalf("fresh observation not reported as age 0:\n%s", sb.String())
	}

	// Six hours with no further observation: the DATABASE age is frozen at one
	// hour, and the OBSERVATION age must show the six.
	clamavSigNow = func() time.Time { return now.Add(6 * time.Hour) }
	snap := clamavSigState()
	if snap.ObservationAge != 6*time.Hour {
		t.Fatalf("observation age = %s, want 6h", snap.ObservationAge)
	}
	if snap.Age != 7*time.Hour {
		t.Fatalf("database age = %s, want 7h (the reading is 6h old and the database was 1h old then)", snap.Age)
	}
}

// The diagnostics rows are tested per shape, through clamavSignatureRows,
// which takes a snapshot and reads no globals.
//
// The operator action is the whole value of these rows. Culvert does not update
// definitions, so "restart the proxy" is the operator's wrong instinct and every
// row has to spend its words saying where the updater actually lives. The rows
// are viewer-readable, so none may carry the daemon's address.

func TestStaleRowNamesFreshclamAndTheConsequence(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	rows := clamavSignatureRows(clamavSigSnapshot{
		Armed: true, AgeKnown: true, Stale: true,
		Age:    30 * 24 * time.Hour,
		DBTime: now.Add(-30 * 24 * time.Hour),
	})
	if len(rows) != 1 {
		t.Fatalf("stale produced %d rows, want 1", len(rows))
	}
	if rows[0].Code != clamAVSignaturesCode || rows[0].Status != diagWarn {
		t.Fatalf("unexpected code/status: %+v", rows[0])
	}
	if !strings.Contains(rows[0].OperatorAction, "freshclam") {
		t.Fatalf("stale row does not name freshclam, so it does not say who updates definitions: %q", rows[0].OperatorAction)
	}
	// The consequence, not just the fact: a stale AV database silently reports
	// infected downloads as clean, and the row has to say so or an operator
	// will triage it as cosmetic.
	if !strings.Contains(rows[0].Message, "clean") {
		t.Fatalf("stale row does not state the consequence: %q", rows[0].Message)
	}
	if !strings.Contains(rows[0].Message, "30d") {
		t.Fatalf("stale row does not carry the age: %q", rows[0].Message)
	}
}

// TestStaleRowDisclosesAFrozenReading: when the daemon has also stopped
// answering, the age in the row is a snapshot from the last reading. The row
// has to say so, or an operator reads a precise-looking age that is not current.
func TestStaleRowDisclosesAFrozenReading(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	rows := clamavSignatureRows(clamavSigSnapshot{
		Armed: true, AgeKnown: true, Stale: true,
		Age:            30 * 24 * time.Hour,
		DBTime:         now.Add(-30 * 24 * time.Hour),
		ObservationAge: 10 * 24 * time.Hour,
	})
	if len(rows) != 1 || !strings.Contains(rows[0].Message, "has not answered since") {
		t.Fatalf("a reading frozen by an unreachable daemon is not disclosed: %+v", rows)
	}
}

func TestUnknownDateGetsItsOwnRow(t *testing.T) {
	rows := clamavSignatureRows(clamavSigSnapshot{Armed: true, Unknown: true})
	if len(rows) != 1 {
		t.Fatalf("unknown produced %d rows, want 1", len(rows))
	}
	if !strings.Contains(rows[0].Message, "cannot be checked") {
		t.Fatalf("unknown row does not say the check is not running: %q", rows[0].Message)
	}
}

func TestFutureDatedGetsItsOwnRow(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	rows := clamavSignatureRows(clamavSigSnapshot{
		Armed: true, AgeKnown: true, FutureDated: true,
		DBTime: now.Add(36 * time.Hour),
	})
	if len(rows) != 1 {
		t.Fatalf("future-dated produced %d rows, want 1", len(rows))
	}
	if !strings.Contains(rows[0].OperatorAction, "NTP") {
		t.Fatalf("future-dated row does not point at clock sync: %q", rows[0].OperatorAction)
	}
}

// TestHealthyAndUnarmedProduceNoRow is the negative control for the report: a
// plane that files a row on every node is one an operator learns to skip.
func TestHealthyAndUnarmedProduceNoRow(t *testing.T) {
	if rows := clamavSignatureRows(clamavSigSnapshot{Armed: true, AgeKnown: true, Age: time.Hour}); len(rows) != 0 {
		t.Fatalf("a fresh database produced a row: %+v", rows)
	}
	if rows := clamavSignatureRows(clamavSigSnapshot{}); len(rows) != 0 {
		t.Fatalf("an unarmed plane produced a row: %+v", rows)
	}
}

// TestNoRowCarriesTheDaemonAddress: these rows are readable by the viewer
// role, which is why the unreachable-ClamAV row (diagnostics_clamav_scan.go)
// keeps the probe error on the role-gated status endpoint. Same rule here.
func TestNoRowCarriesTheDaemonAddress(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	for _, snap := range []clamavSigSnapshot{
		{Armed: true, AgeKnown: true, Stale: true, Age: 30 * 24 * time.Hour, DBTime: now},
		{Armed: true, Unknown: true},
		{Armed: true, AgeKnown: true, FutureDated: true, DBTime: now},
	} {
		for _, r := range clamavSignatureRows(snap) {
			for _, banned := range []string{"3310", "tcp://", "127.0.0.1"} {
				if strings.Contains(r.Message+r.OperatorAction, banned) {
					t.Fatalf("viewer-readable row leaks %q: %+v", banned, r)
				}
			}
		}
	}
}

// SEC-CLAMSIG-RECOVERY-LINE-1. The end of a stale-definitions episode must be
// recorded on a node with NO webhook configured — the default posture.
//
// The sibling of SEC-TFEED-RECOVERY-LINE-1: `alerted` is set only by a
// DISPATCHED page, so with nothing subscribed it stays false for the whole
// episode, and gating the "current again" line on it meant the node that pages
// nobody also records nothing when the definitions start moving again — while
// still logging every staleness line in between. `sawStale` answers "was this
// episode observed stale?" separately from "was anyone paged?".
func TestRecoveryIsLoggedWithNoSubscriber(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	clamavSigTestClock(t, now)
	attempts := captureUndeliveredSigAlerts(t)

	noteClamAVSignatureObservation(versionWithDate(now.Add(-30*24*time.Hour)), true)
	if !clamavSigState().Stale {
		t.Fatal("a 30-day-old database is not reported stale; the fixture never reached the episode")
	}
	if *attempts != 1 {
		t.Fatalf("sink reached %d times, want 1", *attempts)
	}

	out := captureLogger(t, func() {
		noteClamAVSignatureObservation(versionWithDate(now.Add(-time.Hour)), true)
	})
	if !strings.Contains(out, "current again") {
		t.Fatalf("no recovery line logged when the episode ended with no subscriber; the end of a stale-definitions episode went unrecorded.\ngot: %q", out)
	}
}

// The control: a database that was never stale logs no recovery line.
func TestRecoveryIsSilentWhenNeverStale(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	clamavSigTestClock(t, now)
	captureUndeliveredSigAlerts(t)

	noteClamAVSignatureObservation(versionWithDate(now.Add(-2*time.Hour)), true)
	out := captureLogger(t, func() {
		noteClamAVSignatureObservation(versionWithDate(now.Add(-time.Hour)), true)
	})
	if strings.Contains(out, "current again") {
		t.Fatalf("a recovery line was logged for an episode that was never stale: %q", out)
	}
}
