package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// readyBody renders the proxy's /ready shape with the given row statuses.
func readyBody(rows map[string]string) string {
	var b strings.Builder
	b.WriteString(`{"status":"ready","checks":{`)
	first := true
	for k, v := range rows {
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.WriteString(`"` + k + `":{"status":"` + v + `"}`)
	}
	b.WriteString(`}}`)
	return b.String()
}

func fastProbe(t *testing.T, srvURL string) Probe {
	t.Helper()
	return Probe{
		BaseURL: mustParseURL(t, srvURL), HealthPath: "/health", ReadyPath: "/ready",
		Budget: 2 * time.Second, PollInterval: 20 * time.Millisecond, RequestTimeout: time.Second,
	}
}

// `ready_path = "/ready?strict=1"` must reach the proxy as path /ready with
// the query intact; assigning it to URL.Path escaped the "?" (owner review).
func TestJoinURL_KeepsTheReadyPathQuery(t *testing.T) {
	base := mustParseURL(t, "http://127.0.0.1:8080/ignored?x=1#f")
	got := joinURL(base, "/ready?strict=1")
	if got != "http://127.0.0.1:8080/ready?strict=1" {
		t.Fatalf("joinURL = %q", got)
	}
	if got := joinURL(base, "/health"); got != "http://127.0.0.1:8080/health" {
		t.Fatalf("joinURL without a query = %q (base query/fragment must not leak)", got)
	}
	var seen atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/ready") {
			seen.Store(r.URL.Path + "|" + r.URL.RawQuery)
		}
	}))
	defer srv.Close()
	p := fastProbe(t, srv.URL)
	p.ReadyPath = "/ready?strict=1"
	if _, err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if v, _ := seen.Load().(string); v != "/ready|strict=1" {
		t.Fatalf("server saw %q, want path /ready with query strict=1", v)
	}
}

func TestBaseline_RecordsOnlyPreservedRowsThatAreOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // a 503 body still carries the rows
		_, _ = w.Write([]byte(readyBody(map[string]string{
			"setup_complete": "ok", "ca": "fail", "policy_posture": "ok", "clamav": "ok", "session_secret": "ok",
		})))
	}))
	defer srv.Close()
	snap, detail := fastProbe(t, srv.URL).Baseline(context.Background())
	if snap == nil || strings.Join(snap.Preserved, ",") != "setup_complete,session_secret,policy_posture" {
		t.Fatalf("baseline = %+v (%s); want only preserved rows that are ok, never external rows like clamav", snap, detail)
	}
	if snap.Ready || strings.Join(snap.OK, ",") != "clamav,policy_posture,session_secret,setup_complete" || !strings.Contains(detail, "failing=[ca]") {
		t.Fatalf("snapshot = %+v (%s)", snap, detail)
	}
}

func TestBaseline_StackDownRequiresNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	u := srv.URL
	srv.Close()
	snap, detail := fastProbe(t, u).Baseline(context.Background())
	if snap != nil || !strings.Contains(detail, "no readiness rows") {
		t.Fatalf("a stack that does not answer must yield an empty baseline: %v %q", snap, detail)
	}
}

// The defect: a 2xx /ready used to be enough, so an upgrade that came up
// with the admin unclaimed or enforcement gone passed the gate.
func TestRun_RegressedPreservedRowFailsTheGate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(readyBody(map[string]string{"setup_complete": "fail", "policy_posture": "ok"})))
	}))
	defer srv.Close()
	p := fastProbe(t, srv.URL)
	p.Preserve = []string{"setup_complete", "policy_posture", "ca"}
	res, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Failed() || !strings.Contains(res.ReadyDetail, "preserved_check_regressed: ca,setup_complete") {
		t.Fatalf("a regressed (or missing) preserved row must fail the gate: %+v", res)
	}
}

// Rows can lag the listener; the gate keeps polling inside its budget.
func TestRun_WaitsForPreservedRowsWithinBudget(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		st := "fail"
		if n.Add(1) > 3 {
			st = "ok"
		}
		_, _ = w.Write([]byte(readyBody(map[string]string{"policy_loaded": st})))
	}))
	defer srv.Close()
	p := fastProbe(t, srv.URL)
	p.Preserve = []string{"policy_loaded"}
	res, err := p.Run(context.Background())
	if err != nil || res.Failed() || len(res.Regressed) != 0 {
		t.Fatalf("preserved row recovered within budget must pass: %+v %v", res, err)
	}
}

// CONTROLS: no baseline keeps the historical 2xx-only contract (a plain
// "ok" body included), and report-only records without gating.
func TestRun_EmptyPreserveIsTheHistoricalContract(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	res, err := fastProbe(t, srv.URL).Run(context.Background())
	if err != nil || res.Failed() {
		t.Fatalf("empty Preserve must gate on 2xx alone: %+v %v", res, err)
	}
}

func TestRun_ReportOnlyRecordsWithoutGating(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(readyBody(map[string]string{"ca": "fail"})))
	}))
	defer srv.Close()
	p := fastProbe(t, srv.URL)
	p.Preserve, p.PreserveReportOnly = []string{"ca"}, true
	res, err := p.Run(context.Background())
	if err != nil || res.Failed() || strings.Join(res.Regressed, ",") != "ca" {
		t.Fatalf("report-only must pass and record the regression: %+v %v", res, err)
	}
}

// A gating row that was already failing before the restart (a ClamAV
// sidecar that was down) answers 503 after it too; that is not something
// the upgrade broke, so it must not fail the gate and roll back.
func TestRun_ToleratesA503ThatPredatesTheRestart(t *testing.T) {
	body := readyBody(map[string]string{"clamav": "fail", "setup_complete": "ok", "policy_posture": "fail"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	p := fastProbe(t, srv.URL)
	// A NEW row (policy_posture, absent before) may fail: it did not break.
	p.Preserve, p.Before = []string{"setup_complete"}, &Snapshot{Ready: false, OK: []string{"setup_complete"}}
	if res, err := p.Run(context.Background()); err != nil || res.Failed() || !strings.Contains(res.ReadyDetail, "tolerated: failing [clamav,policy_posture]") {
		t.Fatalf("a 503 that predates the restart must be tolerated: %+v %v", res, err)
	}
	// The defect direction: a row that WAS ok and now fails is never tolerated.
	p.Before = &Snapshot{Ready: false, OK: []string{"setup_complete", "session_secret"}}
	body = readyBody(map[string]string{"clamav": "fail", "session_secret": "fail", "setup_complete": "ok"})
	if res, _ := p.Run(context.Background()); !res.Failed() {
		t.Fatalf("a row that was ok and now fails must fail the gate: %+v", res)
	}
	// /ready was 2xx before ⇒ it must be 2xx after, whatever the rows say.
	p.Before = &Snapshot{Ready: true, OK: []string{"setup_complete"}}
	body = readyBody(map[string]string{"clamav": "fail", "setup_complete": "ok"})
	if res, _ := p.Run(context.Background()); !res.Failed() {
		t.Fatalf("a /ready that was 2xx before must be 2xx after: %+v", res)
	}
	// CONTROL: without a baseline a 503 fails exactly as before.
	p.Before = nil
	if res, _ := p.Run(context.Background()); !res.Failed() {
		t.Fatalf("no baseline ⇒ non-2xx must fail: %+v", res)
	}
}

// A rollback may target an older release that predates rows the newer one
// added: with MissingIsUnknown an ABSENT row does not count as broken, an
// explicit failure still does.
func TestRun_RollbackTreatsAbsentRowsAsUnknown(t *testing.T) {
	body := readyBody(map[string]string{"clamav": "fail", "session_secret": "ok"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	p := fastProbe(t, srv.URL)
	p.Before = &Snapshot{Ready: false, OK: []string{"session_secret", "setup_complete", "policy_posture"}}
	if res, _ := p.Run(context.Background()); !res.Failed() {
		t.Fatalf("an upgrade must treat a vanished row as broken: %+v", res)
	}
	p.MissingIsUnknown = true
	if res, err := p.Run(context.Background()); err != nil || res.Failed() {
		t.Fatalf("a rollback to a release without those rows must be tolerated: %+v %v", res, err)
	}
	body = readyBody(map[string]string{"clamav": "fail", "session_secret": "fail"})
	if res, _ := p.Run(context.Background()); !res.Failed() {
		t.Fatalf("an explicit failure must still fail a rollback: %+v", res)
	}
}
