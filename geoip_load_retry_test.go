package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/geoip"
	"github.com/KidCarmi/Culvert/internal/geoip/geoiptest"
)

// isolateGeoIPLoadRetry gives the test a clean GeoIP engine (no database, no
// recorded error, nothing armed) and restores that state afterwards, so the
// rest of the suite keeps running with GeoIP disabled. It returns a database
// path that does not exist yet.
func isolateGeoIPLoadRetry(t *testing.T) string {
	t.Helper()
	ensureGeoIPTestLogger(t)
	geoip.ResetForTest()
	t.Cleanup(geoip.ResetForTest)
	return filepath.Join(t.TempDir(), "GeoLite2-Country.mmdb")
}

func writeGeoIPTestDB(t *testing.T, path string) {
	t.Helper()
	if err := geoiptest.WriteCountryDB(path, "IL", "Israel", time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatalf("write test database: %v", err)
	}
}

func countryRuleDiag(t *testing.T) []OperatorContractCheck {
	t.Helper()
	return checkGeoDatabaseForRules([]PolicyRule{{Name: "block-il", DestCountry: []string{"IL"}}})
}

// The operator-visible reproduction, through the real boot path: startup could
// not open the configured database, so a destination-country rule does not
// match. The operator puts the file in place and the rule matches with no
// restart. The diagnostics row clears only once the database is actually
// loaded, and the automatic load is attributed to system.
func TestGeoIPLoadRetry_CompletesAStartupFailureWithoutRestart(t *testing.T) {
	path := isolateGeoIPLoadRetry(t)
	rule := &PolicyRule{DestCountry: []string{"IL"}}

	loadGeoIP(geoIPStartupConfig{DBPath: path})
	if geoip.Enabled() {
		t.Fatal("precondition: the startup load must fail")
	}
	if got := geoip.DeferredLoadPending(); got != path {
		t.Fatalf("the failed startup load armed %q, want %q", got, path)
	}
	geo.LookupFull(geoiptest.MatchedIP) // what the off-path warmer would do
	if matchDest(rule, geoiptest.MatchedIP) {
		t.Fatal("precondition: a country rule must not match without a database")
	}
	if rows := countryRuleDiag(t); len(rows) != 1 || rows[0].Status != diagWarn {
		t.Fatalf("diagnostics before the load = %+v, want one warning", rows)
	}

	var attempts atomic.Int32
	delay := func(int) time.Duration {
		// The first attempt meets the missing file; the operator's fix lands
		// before the second.
		if attempts.Add(1) == 2 {
			writeGeoIPTestDB(t, path)
		}
		return 0
	}
	done := make(chan struct{})
	go func() { runGeoIPLoadRetry(context.Background(), delay); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the retry loop did not finish after the database became readable")
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2 (one failure, one success)", got)
	}
	if !geoip.Enabled() {
		t.Fatal("GeoIP is still disabled after the database became readable")
	}
	if _, _, ok := geoip.LoadError(); ok {
		t.Fatal("the load error is still on record after a successful load")
	}
	if rows := countryRuleDiag(t); rows != nil {
		t.Fatalf("diagnostics after the load = %+v, want no row", rows)
	}

	// The business outcome: the country resolves and the rule now matches.
	if code, name := geo.LookupFull(geoiptest.MatchedIP); code != "IL" || name != "Israel" {
		t.Fatalf("geo.LookupFull = (%q, %q), want (IL, Israel)", code, name)
	}
	if !matchDest(rule, geoiptest.MatchedIP) {
		t.Fatal("the country rule does not match after the database loaded")
	}
	// An address the database has no data for still does not match.
	geo.LookupFull(geoiptest.UnmatchedIP)
	if matchDest(rule, geoiptest.UnmatchedIP) {
		t.Fatal("the country rule matched an address with no country data")
	}

	e, ok := findAuditByActionObject(t, "geoip.database.auto_load", path)
	if !ok {
		t.Fatal("no system audit entry for the automatic load")
	}
	if e.Actor != "system" {
		t.Fatalf("automatic load attributed to %q, want system", e.Actor)
	}
}

// Unchanged success path: a startup load that succeeds arms nothing, and the
// loop returns at once without waiting.
func TestGeoIPLoadRetry_SuccessfulStartupArmsNothing(t *testing.T) {
	path := isolateGeoIPLoadRetry(t)
	writeGeoIPTestDB(t, path)
	loadGeoIP(geoIPStartupConfig{DBPath: path})
	if !geoip.Enabled() {
		t.Fatal("precondition: the startup load must succeed")
	}
	if p := geoip.DeferredLoadPending(); p != "" {
		t.Fatalf("a successful startup armed a deferred load (%q)", p)
	}
	called := false
	runGeoIPLoadRetry(context.Background(), func(int) time.Duration { called = true; return 0 })
	if called {
		t.Fatal("the loop waited although no deferred load is armed")
	}
	if _, ok := findAuditByActionObject(t, "geoip.database.auto_load", path); ok {
		t.Fatal("a startup load was audited as an automatic load")
	}
}

// Restraint: no database configured means GeoIP stays an explicit "disabled",
// nothing armed, no loop wait.
func TestGeoIPLoadRetry_IdleWhenNotConfigured(t *testing.T) {
	_ = isolateGeoIPLoadRetry(t)
	loadGeoIP(geoIPStartupConfig{})
	called := false
	runGeoIPLoadRetry(context.Background(), func(int) time.Duration { called = true; return 0 })
	if called {
		t.Fatal("the loop waited although no database is configured")
	}
	if geoip.Enabled() || geoip.DeferredLoadPending() != "" {
		t.Fatal("an unconfigured database must stay disabled with nothing armed")
	}
}

// Restraint: a file that is present but not a valid database never enables
// GeoIP. The loop keeps the intent armed and keeps the error on record.
func TestGeoIPLoadRetry_InvalidFileNeverEnables(t *testing.T) {
	path := isolateGeoIPLoadRetry(t)
	if err := os.WriteFile(path, []byte("not a MaxMind database"), 0o600); err != nil {
		t.Fatal(err)
	}
	loadGeoIP(geoIPStartupConfig{DBPath: path})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	done := make(chan struct{})
	go func() {
		runGeoIPLoadRetry(ctx, func(int) time.Duration {
			if attempts.Add(1) == 4 {
				cancel() // three failed attempts are enough
				return time.Hour
			}
			return 0
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the retry loop did not stop")
	}
	if geoip.Enabled() {
		t.Fatal("an invalid file enabled GeoIP")
	}
	if geoip.DeferredLoadPending() != path {
		t.Fatal("a failing path must stay armed")
	}
	if _, _, ok := geoip.LoadError(); !ok {
		t.Fatal("the failure must stay on record for /api/geoip")
	}
	if _, ok := findAuditByActionObject(t, "geoip.database.auto_load", path); ok {
		t.Fatal("a failed load was audited as a success")
	}
}

// Shutdown: a cancelled lifecycle ends the loop while it waits, and nothing is
// loaded afterwards even if the file becomes readable.
func TestGeoIPLoadRetry_StopsOnCancelAndLoadsNothing(t *testing.T) {
	path := isolateGeoIPLoadRetry(t)
	armGeoIPDeferredLoad(path)
	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		runGeoIPLoadRetry(ctx, func(int) time.Duration {
			waiting <- struct{}{}
			return time.Hour
		})
		close(done)
	}()
	<-waiting
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the retry loop ignored cancellation")
	}
	writeGeoIPTestDB(t, path)
	if !attemptGeoIPLoadRetry(ctx, 1) {
		t.Fatal("an attempt on a cancelled lifecycle must end the loop")
	}
	if geoip.Enabled() {
		t.Fatal("a database was loaded after the lifecycle was cancelled")
	}
}

// The GEO-1 boundary, through the loop: when a database is already loaded the
// retry never replaces it, even though its armed path now holds a valid file.
func TestGeoIPLoadRetry_NeverReplacesALoadedDatabase(t *testing.T) {
	armed := isolateGeoIPLoadRetry(t)
	live := filepath.Join(t.TempDir(), "live.mmdb")
	if err := geoiptest.WriteCountryDB(live, "FR", "France", time.Unix(1_600_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	armGeoIPDeferredLoad(armed)
	if err := geoip.InitGeoDB(live); err != nil {
		t.Fatal(err)
	}
	writeGeoIPTestDB(t, armed) // carries IL

	done := make(chan struct{})
	go func() {
		runGeoIPLoadRetry(context.Background(), func(int) time.Duration { return 0 })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the retry loop kept running although a database is loaded")
	}
	if code, _ := geo.LookupFull(geoiptest.MatchedIP); code != "FR" {
		t.Fatalf("the loaded database was replaced: lookup = %q, want FR", code)
	}
	if _, ok := findAuditByActionObject(t, "geoip.database.auto_load", armed); ok {
		t.Fatal("a refused load was audited as a success")
	}
}

// The diagnostics remedy for a failed load no longer tells the operator that a
// restart is needed once the file is fixed. With no database configured at
// all, a restart is still the remedy, because the path is startup-only.
func TestCheckGeoDatabaseForRules_FailedLoadActionNoLongerRequiresRestartForAFixedFile(t *testing.T) {
	path := isolateGeoIPLoadRetry(t)

	rows := countryRuleDiag(t)
	if len(rows) != 1 || !strings.Contains(rows[0].OperatorAction, "and restart") {
		t.Fatalf("unconfigured database: want the configure-and-restart action, got %+v", rows)
	}

	loadGeoIP(geoIPStartupConfig{DBPath: path})
	rows = countryRuleDiag(t)
	if len(rows) != 1 || rows[0].Status != diagWarn {
		t.Fatalf("failed load: want one warning, got %+v", rows)
	}
	action := rows[0].OperatorAction
	if !strings.Contains(action, "retries that path automatically") || !strings.Contains(action, "without a restart") {
		t.Fatalf("failed-load action does not describe the automatic retry: %q", action)
	}
	if strings.Contains(action, "then restart") {
		t.Fatalf("failed-load action still requires a restart: %q", action)
	}
}
