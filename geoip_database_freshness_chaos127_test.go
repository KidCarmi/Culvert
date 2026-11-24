package main

// geoip_database_freshness_chaos127_test.go — CHAOS-127's gates for the GeoIP
// country-database freshness plane.
//
// Five groups:
//  1. the SHAPE the pre-round surfaces could not see: a database that is
//     loaded, serving and answering every liveness probe while its country
//     data is years old;
//  2. the two UNMEASURABLE shapes (no readable build epoch, a future-dated
//     build) and the rule that neither may be reported as fresh;
//  3. the PENDING-RESTART row — the finding's second half, where the operator
//     has already replaced the file and the process is still serving the old
//     one — including every inconclusive shape it must stay silent on;
//  4. the CONTAINMENT rules that make an observability plane safe: no series
//     at all on a node with no database, and no file I/O from a scrape;
//  5. the DIVERGENCE oracle that holds this plane's threshold to the browser
//     judgement it was lifted from.

import (
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// geoipDBTestSeams installs a fixed clock and a stubbed owner package, and
// registers restoration of every global it moves. These are package-level
// seams, so every test that drives this plane restores them per the
// repository's global-test-cleanup convention.
func geoipDBTestSeams(t *testing.T, now time.Time) {
	t.Helper()
	prevNow, prevBuild, prevFile, prevPath := geoipDBNow, geoipDBBuildTimeFn, geoipDBFileBuildTimeFn, geoipDBPathFn
	t.Cleanup(func() {
		geoipDBNow, geoipDBBuildTimeFn, geoipDBFileBuildTimeFn, geoipDBPathFn = prevNow, prevBuild, prevFile, prevPath
	})
	geoipDBNow = func() time.Time { return now }
	// Default posture: nothing loaded, no path, and a file seam that FAILS the
	// test if it is reached. Each case opts in to what it needs.
	geoipDBBuildTimeFn = func() (time.Time, bool) { return time.Time{}, false }
	geoipDBPathFn = func() string { return "" }
	geoipDBFileBuildTimeFn = func(string) (time.Time, error) {
		t.Errorf("geoipDBFileBuildTimeFn called by a case that did not install it")
		return time.Time{}, errors.New("unexpected")
	}
}

// loadedAt installs a loaded database with the given build timestamp.
func loadedAt(built time.Time) {
	geoipDBBuildTimeFn = func() (time.Time, bool) { return built, true }
}

// scrapeGeoIPDB renders just this plane's slice of /metrics.
func scrapeGeoIPDB() string {
	var b strings.Builder
	geoipDBWritePrometheus(&b)
	return b.String()
}

// seriesValue extracts a single-sample gauge's value from a scrape body. It
// matches the SAMPLE line only (anchored, and not the "# HELP"/"# TYPE"
// lines), so a name that also appears inside another series' help text cannot
// satisfy it.
func seriesValue(t *testing.T, body, name string) (int64, bool) {
	t.Helper()
	for _, ln := range strings.Split(body, "\n") {
		if !strings.HasPrefix(ln, name+" ") {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(ln, name+" ")), 10, 64)
		if err != nil {
			t.Fatalf("series %s has unparseable value in %q: %v", name, ln, err)
		}
		return v, true
	}
	return 0, false
}

func mustSeries(t *testing.T, body, name string) int64 {
	t.Helper()
	v, ok := seriesValue(t, body, name)
	if !ok {
		t.Fatalf("series %s absent from scrape:\n%s", name, body)
	}
	return v
}

func rowByCode(rows []OperatorContractCheck, code string) (OperatorContractCheck, bool) {
	for _, r := range rows {
		if r.Code == code {
			return r, true
		}
	}
	return OperatorContractCheck{}, false
}

// ── 1. The shape nothing could see ──────────────────────────────────────────

// TestCHAOS127StaleLoadedDatabaseIsVisible is the round's defining property.
// At the claim revision this exact state — a 1096-day-old database, loaded and
// serving — produced zero lines on /metrics about the database, `geoip: ok`
// from readiness, and no diagnostics row.
func TestCHAOS127StaleLoadedDatabaseIsVisible(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	geoipDBTestSeams(t, now)
	built := now.AddDate(-3, 0, 0)
	loadedAt(built)

	body := scrapeGeoIPDB()
	if got := mustSeries(t, body, "culvert_geoip_database_loaded"); got != 1 {
		t.Errorf("culvert_geoip_database_loaded = %d, want 1", got)
	}
	if got := mustSeries(t, body, "culvert_geoip_database_stale"); got != 1 {
		t.Errorf("culvert_geoip_database_stale = %d, want 1 — the staleness judgement is back in the browser", got)
	}
	if got := mustSeries(t, body, "culvert_geoip_database_age_unknown"); got != 0 {
		t.Errorf("culvert_geoip_database_age_unknown = %d, want 0: this age IS measurable", got)
	}
	wantAge := int64(now.Sub(built).Seconds())
	if got := mustSeries(t, body, "culvert_geoip_database_age_seconds"); got != wantAge {
		t.Errorf("culvert_geoip_database_age_seconds = %d, want %d", got, wantAge)
	}
	if got := mustSeries(t, body, "culvert_geoip_database_build_timestamp_seconds"); got != built.Unix() {
		t.Errorf("culvert_geoip_database_build_timestamp_seconds = %d, want %d", got, built.Unix())
	}

	row, ok := rowByCode(checkGeoDatabaseAge(), "geoip_database_age")
	if !ok {
		t.Fatal("no geoip_database_age diagnostics row for a 3-year-old loaded database")
	}
	if row.Status != diagWarn {
		t.Errorf("row status = %q, want %q", row.Status, diagWarn)
	}
	// The row must carry the consequence, not just the number: the whole
	// point is that destCountry rules are enforcing against stale data.
	if !strings.Contains(row.Message, "1096 days ago") {
		t.Errorf("row message does not carry the measured age: %q", row.Message)
	}
	if !strings.Contains(strings.ToLower(row.Message), "destination-country") {
		t.Errorf("row message does not name the control that degrades: %q", row.Message)
	}
	// The remedy is a restart, and saying "update the file" without that is
	// exactly the advice the GUI already gave that could not take effect.
	//
	// The row CODE geoip_database_pending_restart is referenced in this
	// action's text and itself contains the substring "restart", so a naive
	// Contains check passes even when every word of advice is gone. Mutation
	// M14 proved that: dropping "and RESTART the proxy — a loaded database is
	// never re-read" was caught by NOTHING. Strip the identifier first, then
	// assert on what is left, which is prose addressed to a human.
	advice := strings.ReplaceAll(row.OperatorAction, "geoip_database_pending_restart", "")
	if !strings.Contains(strings.ToUpper(advice), "RESTART") {
		t.Errorf("row action omits the restart requirement (ignoring the referenced row code): %q", row.OperatorAction)
	}
	if !strings.Contains(strings.ToLower(advice), "never re-read") {
		t.Errorf("row action does not say WHY a restart is needed, which is the whole second half of this finding: %q", row.OperatorAction)
	}
}

// TestCHAOS127FreshDatabaseIsQuiet pins the other side: a current database
// exports the family with stale=0 and produces no row. A plane that warns on a
// healthy node is a plane an operator mutes.
func TestCHAOS127FreshDatabaseIsQuiet(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	geoipDBTestSeams(t, now)
	loadedAt(now.AddDate(0, 0, -3))

	body := scrapeGeoIPDB()
	if got := mustSeries(t, body, "culvert_geoip_database_stale"); got != 0 {
		t.Errorf("culvert_geoip_database_stale = %d on a 3-day-old database, want 0", got)
	}
	if rows := checkGeoDatabaseAge(); len(rows) != 0 {
		t.Errorf("a 3-day-old database produced %d diagnostics row(s): %+v", len(rows), rows)
	}
}

// TestCHAOS127StalenessBoundary pins the threshold exactly. An off-by-one here
// is the difference between a fleet that pages a day early and one that never
// does, and the constant is shared with the GUI.
func TestCHAOS127StalenessBoundary(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		age       time.Duration
		wantStale int64
	}{
		{"one second inside the threshold", geoipDBStaleAfter - time.Second, 0},
		{"exactly at the threshold", geoipDBStaleAfter, 0},
		{"one second past the threshold", geoipDBStaleAfter + time.Second, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			geoipDBTestSeams(t, now)
			loadedAt(now.Add(-tc.age))
			if got := mustSeries(t, scrapeGeoIPDB(), "culvert_geoip_database_stale"); got != tc.wantStale {
				t.Errorf("stale = %d at age %s, want %d", got, tc.age, tc.wantStale)
			}
		})
	}
}

// ── 2. The two unmeasurable shapes ──────────────────────────────────────────

// TestCHAOS127UnmeasurableIsNeverReportedFresh is the fail-safe rule. A
// database with no readable build epoch, and one dated in the future, both
// have no age — and the one thing neither may do is read as fresh, because a
// corrupt or hand-edited metadata block would then silence this plane forever.
func TestCHAOS127UnmeasurableIsNeverReportedFresh(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name      string
		built     time.Time
		wantInMsg string
	}{
		// time.Unix(0,0) is what readerBuildTime returns for a .mmdb whose
		// metadata carried no build_epoch. As an "age" it would be ~56 years,
		// the most alarming number the plane can print, and one the product
		// cannot stand behind.
		{"absent build epoch", time.Unix(0, 0).UTC(), "no readable"},
		{"zero time", time.Time{}, "no readable"},
		{"dated in the future", now.AddDate(0, 1, 0), "in the future"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			geoipDBTestSeams(t, now)
			loadedAt(tc.built)

			body := scrapeGeoIPDB()
			if got := mustSeries(t, body, "culvert_geoip_database_age_unknown"); got != 1 {
				t.Errorf("age_unknown = %d, want 1", got)
			}
			if got := mustSeries(t, body, "culvert_geoip_database_stale"); got != 0 {
				t.Errorf("stale = %d, want 0: unmeasurable is not stale, it is its own shape", got)
			}
			if got := mustSeries(t, body, "culvert_geoip_database_age_seconds"); got != 0 {
				t.Errorf("age_seconds = %d, want 0 for an unmeasurable age", got)
			}
			// loaded stays 1: there IS a database, it is just not datable.
			if got := mustSeries(t, body, "culvert_geoip_database_loaded"); got != 1 {
				t.Errorf("loaded = %d, want 1", got)
			}

			row, ok := rowByCode(checkGeoDatabaseAge(), "geoip_database_age")
			if !ok {
				t.Fatal("an unmeasurable database produced no diagnostics row — it must be a visible gap, not a silent pass")
			}
			if row.Status != diagWarn {
				t.Errorf("row status = %q, want %q", row.Status, diagWarn)
			}
			if !strings.Contains(row.Message, tc.wantInMsg) {
				t.Errorf("row message %q does not distinguish this shape (want %q)", row.Message, tc.wantInMsg)
			}
		})
	}
}

// TestCHAOS127FutureBuildTimestampNeverRendersNegative pins the scrape
// surface's rendering for the pre-epoch case. A negative Unix time passed
// through would be read by every dashboard as a date in 1969 rather than as
// "absent".
func TestCHAOS127FutureBuildTimestampNeverRendersNegative(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	geoipDBTestSeams(t, now)
	loadedAt(time.Unix(-5000, 0).UTC())

	if got := mustSeries(t, scrapeGeoIPDB(), "culvert_geoip_database_build_timestamp_seconds"); got != 0 {
		t.Errorf("build_timestamp_seconds = %d for a pre-epoch build, want 0", got)
	}
}

// TestCHAOS127SmallClockSkewIsNotUnmeasurable pins the tolerance. A node a
// couple of minutes behind real time must not report every database as
// future-dated and so disable its own staleness check.
func TestCHAOS127SmallClockSkewIsNotUnmeasurable(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	geoipDBTestSeams(t, now)
	loadedAt(now.Add(2 * time.Minute)) // inside geoipDBFutureSkew

	body := scrapeGeoIPDB()
	if got := mustSeries(t, body, "culvert_geoip_database_age_unknown"); got != 0 {
		t.Errorf("age_unknown = %d for %s of clock skew, want 0", got, 2*time.Minute)
	}
	if got := mustSeries(t, body, "culvert_geoip_database_age_seconds"); got != 0 {
		t.Errorf("age_seconds = %d, want 0 (floored, not negative)", got)
	}
	if got := mustSeries(t, body, "culvert_geoip_database_stale"); got != 0 {
		t.Errorf("stale = %d, want 0", got)
	}
}

// ── 3. The pending-restart row ──────────────────────────────────────────────

// TestCHAOS127PendingRestartIsReported is the finding's second half. At the
// claim revision, writing a current .mmdb to the configured path produced NO
// observable change anywhere: ArmDeferredLoad returned false because a reader
// was already installed, TryDeferredLoad loaded nothing, and the reported
// build date did not move.
func TestCHAOS127PendingRestartIsReported(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	geoipDBTestSeams(t, now)
	servingBuild := now.AddDate(-3, 0, 0)
	loadedAt(servingBuild)
	geoipDBPathFn = func() string { return "/var/lib/culvert/GeoLite2-Country.mmdb" }
	geoipDBFileBuildTimeFn = func(string) (time.Time, error) { return now.AddDate(0, 0, -2), nil }

	rows := checkGeoDatabaseAge()
	row, ok := rowByCode(rows, "geoip_database_pending_restart")
	if !ok {
		t.Fatalf("no geoip_database_pending_restart row when the file on disk is newer: %+v", rows)
	}
	if row.Status != diagWarn {
		t.Errorf("row status = %q, want %q", row.Status, diagWarn)
	}
	if !strings.Contains(strings.ToUpper(row.OperatorAction), "RESTART") {
		t.Errorf("row action does not name the remedy: %q", row.OperatorAction)
	}
	// It must NOT tell them to download again — they already did the download.
	if strings.Contains(strings.ToLower(row.OperatorAction), "download a current") {
		t.Errorf("pending-restart action repeats the download step: %q", row.OperatorAction)
	}
	// The stale row is still correct and must still be present: the node IS
	// serving stale data until it restarts. The two rows are complementary.
	if _, ok := rowByCode(rows, "geoip_database_age"); !ok {
		t.Error("the stale row vanished once a newer file appeared on disk — the node is still SERVING the old one")
	}
}

// TestCHAOS127PendingRestartStaysSilentWhenInconclusive pins every shape that
// must NOT produce the row. Reporting an unopenable file, or an equal build,
// as a pending restart would send an operator to restart a fleet for nothing —
// and an unreadable path is already geoip_database_for_rules' and
// /api/geoip lastError's business.
func TestCHAOS127PendingRestartStaysSilentWhenInconclusive(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	serving := now.AddDate(0, 0, -200)

	for _, tc := range []struct {
		name string
		path string
		file func(string) (time.Time, error)
	}{
		{"no path configured", "", nil},
		{"file unreadable", "/nope.mmdb", func(string) (time.Time, error) { return time.Time{}, errors.New("open: no such file") }},
		{"file build epoch absent", "/db.mmdb", func(string) (time.Time, error) { return time.Unix(0, 0).UTC(), nil }},
		{"file build epoch zero time", "/db.mmdb", func(string) (time.Time, error) { return time.Time{}, nil }},
		{"same build as the loaded reader", "/db.mmdb", func(string) (time.Time, error) { return serving, nil }},
		{"older build than the loaded reader", "/db.mmdb", func(string) (time.Time, error) { return serving.AddDate(0, 0, -30), nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			geoipDBTestSeams(t, now)
			loadedAt(serving)
			geoipDBPathFn = func() string { return tc.path }
			if tc.file != nil {
				geoipDBFileBuildTimeFn = tc.file
			}
			if row, ok := rowByCode(checkGeoDatabaseAge(), "geoip_database_pending_restart"); ok {
				t.Errorf("pending-restart row fired on an inconclusive shape: %+v", row)
			}
		})
	}
}

// TestCHAOS127PendingRestartNeedsALoadedDatabase pins that the row never
// speaks on a node with nothing loaded. That state belongs entirely to
// geoip_database_for_rules, and a second voice saying "restart to pick up the
// newer file" would be wrong: there is no older one being served.
func TestCHAOS127PendingRestartNeedsALoadedDatabase(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	geoipDBTestSeams(t, now)
	geoipDBPathFn = func() string { return "/db.mmdb" }
	// The file seam stays the one that fails the test if reached: with nothing
	// loaded there is nothing to compare against, so the file must not be
	// opened at all.
	if rows := checkGeoDatabaseAge(); len(rows) != 0 {
		t.Errorf("rows produced with no database loaded: %+v", rows)
	}
}

// ── 4. Containment ──────────────────────────────────────────────────────────

// TestCHAOS127NoSeriesWithoutADatabase is the containment rule. GeoIP is
// optional and off by default, so most nodes must publish nothing at all
// rather than a zero: a fleet-wide `culvert_geoip_database_age_seconds > X`
// alert must not be silently satisfied by every node that has no database to
// be current about.
func TestCHAOS127NoSeriesWithoutADatabase(t *testing.T) {
	geoipDBTestSeams(t, time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC))

	if body := scrapeGeoIPDB(); body != "" {
		t.Errorf("a node with no GeoIP database emitted series:\n%s", body)
	}
	if rows := checkGeoDatabaseAge(); len(rows) != 0 {
		t.Errorf("a node with no GeoIP database produced diagnostics rows: %+v", rows)
	}
}

// TestCHAOS127ScrapeDoesNoFileIO pins the posture every freshness plane in
// this tree shares. /metrics is commonly unauthenticated when metricsToken is
// unset; a scrape that opened and mmapped a ~9 MB database would let any
// scraper drive file I/O at this process once per scrape.
//
// The seam installed by geoipDBTestSeams fails the test if it is reached, so
// this case asserts by construction across every scrape shape.
func TestCHAOS127ScrapeDoesNoFileIO(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	for _, built := range []time.Time{
		now.AddDate(-3, 0, 0), // stale
		now.AddDate(0, 0, -1), // fresh
		time.Unix(0, 0).UTC(), // unmeasurable
		now.AddDate(0, 1, 0),  // future-dated
	} {
		geoipDBTestSeams(t, now)
		geoipDBPathFn = func() string { return "/db.mmdb" }
		loadedAt(built)
		_ = scrapeGeoIPDB()
	}
}

// TestCHAOS127ScrapeCarriesNoPathOrFilename pins that the scrape surface
// leaks nothing about the deployment's filesystem layout. /metrics is the one
// surface here that may be unauthenticated.
func TestCHAOS127ScrapeCarriesNoPathOrFilename(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	geoipDBTestSeams(t, now)
	loadedAt(now.AddDate(-3, 0, 0))
	geoipDBPathFn = func() string { return "/srv/secret-tenant-42/GeoLite2-Country.mmdb" }

	body := scrapeGeoIPDB()
	// The generic word ".mmdb" appears in a HELP string, which is a static
	// documentation phrase and not deployment data. What must never appear is
	// the CONFIGURED path or any segment of it.
	for _, leak := range []string{"/srv/secret-tenant-42/GeoLite2-Country.mmdb", "secret-tenant-42", "/srv/"} {
		if strings.Contains(body, leak) {
			t.Errorf("scrape body leaks %q:\n%s", leak, body)
		}
	}
}

// ── 5. The divergence oracle ────────────────────────────────────────────────

// TestCHAOS127GUIThresholdMatchesBackend holds this plane's threshold to the
// browser judgement it was lifted from.
//
// The whole finding is that the only staleness judgement in the product lived
// in static/index.html. Moving it into the process without binding the two
// together would leave the exact failure the round exists to end, one layer
// further in: an operator reading "stale" from Prometheus and "fine" from the
// GUI, or the reverse, with no way to tell which is right.
//
// A comment would not have caught it. This reads the JavaScript.
func TestCHAOS127GUIThresholdMatchesBackend(t *testing.T) {
	const panel = "static/index.html"
	src, err := os.ReadFile(panel)
	if err != nil {
		t.Fatalf("read %s: %v", panel, err)
	}
	// Matches `const stale = g.dbAgeDays > 90;` tolerantly of spacing and of
	// the variable name, but NOT of the comparison itself.
	re := regexp.MustCompile(`dbAgeDays\s*>\s*(\d+)`)
	m := re.FindAllSubmatch(src, -1)
	if len(m) == 0 {
		t.Fatalf("no `dbAgeDays > N` staleness comparison found in %s. If the GUI now reads the verdict from the API instead of deriving it, delete this gate and say so in the review — do not weaken it.", panel)
	}
	if len(m) > 1 {
		t.Fatalf("%s carries %d `dbAgeDays > N` comparisons; the GUI must judge staleness in exactly one place", panel, len(m))
	}
	guiDays, err := strconv.Atoi(string(m[0][1]))
	if err != nil {
		t.Fatalf("parse GUI threshold %q: %v", m[0][1], err)
	}
	if guiDays != geoipDBStaleAfterDays {
		t.Errorf("GUI judges a GeoIP database stale at %d days, this process at %d. They must agree: an operator reads both. Change both, or make the GUI read the verdict from the API.",
			guiDays, geoipDBStaleAfterDays)
	}
}
