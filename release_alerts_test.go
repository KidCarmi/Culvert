package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// M1-3 (design §3 Slice C) — RT-H2 §10 enforcement: every alert fires ONCE per
// threshold crossing, never per evaluation. These tests are the recorded
// enforcement mechanism for that row; weakening the latch fails them.

// alertRecorder swaps the releaseAlertFire seam for a synchronous capture.
func alertRecorder(t *testing.T) *[]AlertPayload {
	t.Helper()
	var got []AlertPayload
	orig := releaseAlertFire
	releaseAlertFire = func(event string, p AlertPayload) {
		p.Event = event
		got = append(got, p)
	}
	t.Cleanup(func() { releaseAlertFire = orig })
	return &got
}

func eventNames(ps []AlertPayload) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Event)
	}
	return out
}

// RT-H2 (stale): two evaluations inside the stale window emit exactly ONE
// release_catalog_stale; crossing back to fresh re-arms the latch, and
// crossing forth again fires exactly once more.
func TestStaleAlert_OncePerCrossing(t *testing.T) {
	rm := &releaseManager{catalogOrigin: "catalog.example.com"}
	now := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	stale := now.Add(10 * 24 * time.Hour)  // 10d left — inside the 30d threshold
	fresh := now.Add(200 * 24 * time.Hour) // far outside

	// First stale evaluation fires; the second (same window) is silent.
	ev1 := rm.evalStale(stale, now)
	if len(ev1) != 1 || ev1[0].Event != "release_catalog_stale" {
		t.Fatalf("first stale evaluation must fire exactly once; got %v", eventNames(ev1))
	}
	if ev2 := rm.evalStale(stale, now); len(ev2) != 0 {
		t.Fatalf("second stale evaluation inside the window must be latched-silent; got %v", eventNames(ev2))
	}
	// Even 6h later (a loop tick), still latched.
	if ev := rm.evalStale(stale, now.Add(6*time.Hour)); len(ev) != 0 {
		t.Fatalf("subsequent tick inside the window must stay silent; got %v", eventNames(ev))
	}

	// Crossing back (fresh catalog installed) re-arms silently…
	if ev := rm.evalStale(fresh, now); len(ev) != 0 {
		t.Fatalf("fresh evaluation must not fire; got %v", eventNames(ev))
	}
	// …and the next crossing fires exactly once again.
	if ev := rm.evalStale(stale, now); len(ev) != 1 || ev[0].Event != "release_catalog_stale" {
		t.Fatalf("re-crossing must fire exactly once; got %v", eventNames(ev))
	}

	// Already-expired counts as stale (negative remaining) and reports it.
	rm2 := &releaseManager{}
	ev := rm2.evalStale(now.Add(-24*time.Hour), now)
	if len(ev) != 1 || !strings.Contains(ev[0].Detail, "-1.0 days") {
		t.Fatalf("expired catalog must fire with negative remaining; got %+v", ev)
	}
}

// RT-H2 (refresh failing / recovered): the failing alert fires on the ≥N
// transition only; recovered fires on the FIRST success after a fired failing
// alert; a sub-threshold blip (fail, fail, success) stays completely silent.
// Driven through the REAL recordRefreshOutcome fold, so the latch, the shared
// status, and the counters are exercised together.
func TestRefreshFailingAlert_TransitionsOnly(t *testing.T) {
	got := alertRecorder(t)
	rm := &releaseManager{catalogOrigin: "catalog.example.com"}
	fail := errors.New("origin unreachable")

	// Failures 1 and 2: below threshold — silent.
	rm.recordRefreshOutcome("loop", fail)
	rm.recordRefreshOutcome("loop", fail)
	if len(*got) != 0 {
		t.Fatalf("sub-threshold failures must be silent; got %v", eventNames(*got))
	}
	// Failure 3 crosses the threshold: exactly one failing alert.
	rm.recordRefreshOutcome("loop", fail)
	if names := eventNames(*got); len(names) != 1 || names[0] != "release_catalog_refresh_failing" {
		t.Fatalf("threshold crossing must fire exactly one failing alert; got %v", names)
	}
	// Failures 4 and 5: latched — still exactly one.
	rm.recordRefreshOutcome("loop", fail)
	rm.recordRefreshOutcome("manual", fail)
	if len(*got) != 1 {
		t.Fatalf("post-crossing failures must stay latched-silent; got %v", eventNames(*got))
	}
	// First success: exactly one recovered; the latch re-arms.
	rm.recordRefreshOutcome("loop", nil)
	if names := eventNames(*got); len(names) != 2 || names[1] != "release_catalog_recovered" {
		t.Fatalf("first success after failing must fire exactly one recovered; got %v", names)
	}
	// Second success: silent.
	rm.recordRefreshOutcome("loop", nil)
	if len(*got) != 2 {
		t.Fatalf("further successes must be silent; got %v", eventNames(*got))
	}

	// Re-crossing after recovery fires the failing alert again (once).
	for i := 0; i < releaseRefreshFailingThreshold; i++ {
		rm.recordRefreshOutcome("loop", fail)
	}
	if names := eventNames(*got); len(names) != 3 || names[2] != "release_catalog_refresh_failing" {
		t.Fatalf("re-crossing after recovery must fire failing exactly once more; got %v", names)
	}

	// Sub-threshold blip on a fresh manager: fail, fail, success ⇒ NO alerts
	// (recovered pairs with a fired failing alert, never with a blip). Installs
	// its own recorder, so this stays the LAST block — the rm recorder above is
	// superseded from here on.
	rm2 := &releaseManager{}
	got2 := alertRecorder(t)
	rm2.recordRefreshOutcome("loop", fail)
	rm2.recordRefreshOutcome("loop", fail)
	rm2.recordRefreshOutcome("loop", nil)
	if len(*got2) != 0 {
		t.Fatalf("sub-threshold blip must fire nothing; got %v", eventNames(*got2))
	}
}

// The refresh_total counters advance with outcomes, and the expiry gauge is
// emitted only while a catalog with an expiry is actually installed.
func TestReleaseCatalogMetrics(t *testing.T) {
	got := alertRecorder(t) // swallow transition alerts; not under test here
	_ = got
	rm := &releaseManager{}
	s0 := atomic.LoadInt64(&statReleaseRefreshSuccess)
	f0 := atomic.LoadInt64(&statReleaseRefreshFailure)
	rm.recordRefreshOutcome("loop", nil)
	rm.recordRefreshOutcome("loop", errors.New("x"))
	rm.recordRefreshOutcome("manual", nil)
	if s := atomic.LoadInt64(&statReleaseRefreshSuccess) - s0; s != 2 {
		t.Fatalf("success counter advanced by %d; want 2", s)
	}
	if f := atomic.LoadInt64(&statReleaseRefreshFailure) - f0; f != 1 {
		t.Fatalf("failure counter advanced by %d; want 1", f)
	}

	// No manager published ⇒ counters only, no gauge (absent series beats a
	// fake zero, which Prometheus would read as "expired").
	setReleaseManager(nil)
	t.Cleanup(func() { setReleaseManager(nil) })
	var buf strings.Builder
	releaseCatalogWritePrometheus(&buf)
	out := buf.String()
	if !strings.Contains(out, `culvert_release_catalog_refresh_total{result="success"}`) ||
		!strings.Contains(out, `culvert_release_catalog_refresh_total{result="failure"}`) {
		t.Fatalf("refresh_total series missing:\n%s", out)
	}
	if strings.Contains(out, "culvert_release_catalog_expires_in_seconds") {
		t.Fatalf("expiry gauge must be omitted with no catalog:\n%s", out)
	}
}

// MED-2 (impl review): the stale evaluation WIRING is enforced, not just the
// latch — deleting the startup eval call in loadReleaseManagement fails this
// test (a catalog installed already inside the 30d window must alert at boot,
// not one refresh interval later).
func TestStaleAlert_FiresAtStartupWiring(t *testing.T) {
	t.Cleanup(func() { setReleaseManager(nil) })
	got := alertRecorder(t)
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Valid (loads through the enforce freshness gate) but inside the stale
	// window: expires 10 days from now.
	exp := time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	writeSignedCatalogDir(t, dir, priv, freshValidSource(exp, 3))

	setReleaseManager(nil)
	loadReleaseManagement(releaseStartupConfig{
		proxyRepo:  defaultReleaseProxyRepo,
		catalogDir: dir,
		statePath:  dir + "/state.json",
		verifyMode: VerifyEnforce,
		trustKeys:  []TrustKey{{KeyID: holderTestKeyID, Alg: catalogSigAlg, PublicKey: pub}},
	})
	if currentReleaseManager() == nil {
		t.Fatal("manager not published")
	}
	names := eventNames(*got)
	stale := 0
	for _, n := range names {
		if n == "release_catalog_stale" {
			stale++
		}
	}
	if stale != 1 {
		t.Fatalf("startup wiring must evaluate freshness exactly once; got %v", names)
	}
}

// MED-2 (impl review): runRefresh must run a freshness evaluation on EVERY
// outcome (incl. success/304 no-ops) — deleting the evaluateCatalogFreshness
// call in runRefresh fails this test. Uses the observability accessor directly
// (the same seam production wires to holder.PublishedRaw).
func TestStaleAlert_EvaluatedOnRunRefresh(t *testing.T) {
	got := alertRecorder(t)
	staleCat := &Catalog{expiresAt: time.Now().Add(5 * 24 * time.Hour)}
	rm := &releaseManager{
		refresh:        func(context.Context) error { return nil },
		observeCatalog: func() *Catalog { return staleCat },
	}
	if err := rm.runRefresh(context.Background(), "loop"); err != nil {
		t.Fatal(err)
	}
	if names := eventNames(*got); len(names) != 1 || names[0] != "release_catalog_stale" {
		t.Fatalf("runRefresh must evaluate freshness (one stale alert); got %v", names)
	}
	// Second tick inside the window: latched-silent (RT-H2 through the real path).
	if err := rm.runRefresh(context.Background(), "loop"); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 {
		t.Fatalf("second tick must stay latched-silent; got %v", eventNames(*got))
	}
}

// MED-1 (impl review): booting AFTER the catalog lapsed — the enforce-mode
// Reload refuses the expired dir, the holder stays empty, and the ONLY signal
// for the terminal case the 180-day watchdog exists for is the boot-after-lapse
// stale alert fired by the wiring.
func TestStaleAlert_BootAfterLapse(t *testing.T) {
	t.Cleanup(func() { setReleaseManager(nil) })
	got := alertRecorder(t)
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Signed but already expired ⇒ enforce Reload refuses it at load.
	writeSignedCatalogDir(t, dir, priv, freshValidSource("2020-01-01T00:00:00Z", 3))

	setReleaseManager(nil)
	loadReleaseManagement(releaseStartupConfig{
		proxyRepo:  defaultReleaseProxyRepo,
		catalogDir: dir,
		statePath:  dir + "/state.json",
		verifyMode: VerifyEnforce,
		trustKeys:  []TrustKey{{KeyID: holderTestKeyID, Alg: catalogSigAlg, PublicKey: pub}},
	})
	rm := currentReleaseManager()
	if rm == nil {
		t.Fatal("manager must still publish (expired catalog is the no-catalog state, not fatal)")
	}
	names := eventNames(*got)
	if len(names) != 1 || names[0] != "release_catalog_stale" || !strings.Contains((*got)[0].Detail, "EXPIRED") {
		t.Fatalf("boot-after-lapse must fire exactly one expired stale alert; got %+v", *got)
	}
}

// MED-1 (impl review): a RUNTIME lapse — the catalog was fresh at load and
// expires while running. GetCatalog hides it from serving, but detection must
// keep seeing it: the API reports the expired reason + negative expires_in_days,
// the gauge exports a negative value, and the watchdog still evaluates.
func TestReleaseExpiry_RuntimeLapseStaysObservable(t *testing.T) {
	t.Cleanup(func() { setReleaseManager(nil) })
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Expired 36h ago in REAL time; the holder's freshness clock is faked to
	// load-time (10d before expiry) so the catalog loads, then advanced to real
	// now so GetCatalog hides it — exactly the runtime-lapse sequence.
	exp := time.Now().Add(-36 * time.Hour)
	writeSignedCatalogDir(t, dir, priv, freshValidSource(exp.UTC().Format(time.RFC3339), 3))
	var clock atomic.Int64
	clock.Store(exp.Add(-10 * 24 * time.Hour).UnixNano())
	trust, err := NewTrustStore([]TrustKey{{KeyID: holderTestKeyID, Alg: catalogSigAlg, PublicKey: pub}}, VerifyEnforce)
	if err != nil {
		t.Fatal(err)
	}
	holder := NewCatalogHolder(dir, trust,
		WithFreshnessEnforcement(func() time.Time { return time.Unix(0, clock.Load()) }, catalogClockSkew, dir+"/state.json"))
	if err := holder.Reload(); err != nil {
		t.Fatalf("catalog must load while fresh: %v", err)
	}
	clock.Store(time.Now().UnixNano()) // the lapse

	svc, err := NewDispatchService(holder, DispatchConfig{ProxyRepo: defaultReleaseProxyRepo})
	if err != nil {
		t.Fatal(err)
	}
	rm := newReleaseManager(svc, func(string) (AgentEndpoint, bool) { return AgentEndpoint{}, false })
	rm.observeCatalog = holder.PublishedRaw
	setReleaseManager(rm)

	// API: hidden from serving, but the WHY is surfaced.
	rec := httptest.NewRecorder()
	apiReleases(rec, releaseReq(http.MethodGet, "/api/releases", nil, RoleViewer))
	body := decodeBody(t, rec)
	if body["available"] != false || body["reason"] != "installed catalog expired" {
		t.Fatalf("runtime lapse must surface the expired reason: %v", body)
	}
	if days, ok := body["expires_in_days"].(float64); !ok || days != -2 {
		// 36h past expiry, floor ⇒ -2 (LOW-1: truncation would say -1).
		t.Fatalf("expires_in_days = %v; want -2 (floor semantics)", body["expires_in_days"])
	}
	// Gauge: still exported, negative.
	var buf strings.Builder
	releaseCatalogWritePrometheus(&buf)
	if !strings.Contains(buf.String(), "culvert_release_catalog_expires_in_seconds -") {
		t.Fatalf("expired catalog must export a NEGATIVE gauge, not vanish:\n%s", buf.String())
	}
	// Watchdog: still evaluates (fires once — expired counts as stale).
	got := alertRecorder(t)
	rm.evaluateCatalogFreshness()
	if names := eventNames(*got); len(names) != 1 || names[0] != "release_catalog_stale" {
		t.Fatalf("runtime-lapsed catalog must still trip the watchdog; got %v", names)
	}
}

// GUI-parity field + scrape-time gauge with a REAL installed catalog: load a
// signed catalog through the production wiring, then check /api/releases
// reports expires_in_days and the gauge appears.
func TestReleaseExpirySurfaces(t *testing.T) {
	t.Cleanup(func() { setReleaseManager(nil) })
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	writeSignedCatalogDir(t, dir, priv, freshValidSource("2099-01-01T00:00:00Z", 3))

	setReleaseManager(nil)
	loadReleaseManagement(releaseStartupConfig{
		proxyRepo:  defaultReleaseProxyRepo,
		catalogDir: dir,
		statePath:  dir + "/state.json",
		verifyMode: VerifyEnforce,
		trustKeys:  []TrustKey{{KeyID: holderTestKeyID, Alg: catalogSigAlg, PublicKey: pub}},
	})
	rm := currentReleaseManager()
	if rm == nil {
		t.Fatal("manager not published")
	}

	rec := httptest.NewRecorder()
	apiReleases(rec, releaseReq(http.MethodGet, "/api/releases", nil, RoleViewer))
	body := decodeBody(t, rec)
	days, ok := body["expires_in_days"].(float64)
	if !ok || days < 300 {
		t.Fatalf("expires_in_days missing or wrong: %v (body %v)", body["expires_in_days"], body)
	}

	var buf strings.Builder
	releaseCatalogWritePrometheus(&buf)
	if !strings.Contains(buf.String(), "culvert_release_catalog_expires_in_seconds") {
		t.Fatalf("expiry gauge missing with an installed catalog:\n%s", buf.String())
	}
}
