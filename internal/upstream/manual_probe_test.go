package upstream

// manual_probe_test.go — the manual-probe gate (2F-D, R24): single-flight,
// one accepted run per window, reset by Configure/Restore, count-only
// summary, periodic runs never gated. Injected clock, no sleeps.

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestManualProbeGate_SingleFlightAndWindow(t *testing.T) {
	p := &Pool{}
	t0 := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	ok, code, _ := p.BeginManualProbe(t0)
	if !ok || code != "" {
		t.Fatalf("first run must be admitted: %v %q", ok, code)
	}
	if ok, code, _ := p.BeginManualProbe(t0.Add(time.Second)); ok || code != ManualProbeInFlight {
		t.Fatalf("a run in flight must refuse with %s, got %v %q", ManualProbeInFlight, ok, code)
	}
	p.EndManualProbe()
	if ok, code, retry := p.BeginManualProbe(t0.Add(3 * time.Second)); ok || code != ManualProbeRateLimited || retry != 7*time.Second {
		t.Fatalf("inside the window: want %s retry 7s, got %v %q %v", ManualProbeRateLimited, ok, code, retry)
	}
	if ok, _, _ := p.BeginManualProbe(t0.Add(ManualProbeWindow)); !ok {
		t.Fatal("at the window boundary the next run is admitted")
	}
	p.EndManualProbe()
	// Configure resets the gate (test isolation, config reload).
	if err := p.Configure(nil, 5, time.Minute); err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := p.BeginManualProbe(t0.Add(ManualProbeWindow + time.Second)); !ok {
		t.Fatal("Configure must reset the gate")
	}
	p.EndManualProbe()
}

func TestHealthCheck_SummaryCountsAndPeriodicUngated(t *testing.T) {
	p := &Pool{}
	if err := p.Configure(nil, 5, time.Minute); err != nil {
		t.Fatal(err)
	}
	doc := Document{Schema: DocumentSchema, Revision: 1, Entries: []ManagedEntry{
		{ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scheme: "http", Host: "a.test", Port: 3128, Revision: 1, Source: SourceManaged},
		{ID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", Scheme: "http", Host: "b.test", Port: 3128, Revision: 1, Source: SourceManaged, RequiresReplacement: true},
	}}
	if err := p.SetDocument(doc); err != nil {
		t.Fatal(err)
	}
	prev := ProbeTransport
	t.Cleanup(func() { ProbeTransport = prev })
	ProbeTransport = func(*url.URL) http.RoundTripper {
		return rtFunc(func(r *http.Request) (*http.Response, error) { return okResp(r, 407), nil })
	}
	// A run in flight never blocks the periodic loop.
	if ok, _, _ := p.BeginManualProbe(time.Now()); !ok {
		t.Fatal("admit")
	}
	sum := p.HealthCheck(ProbePeriodic)
	p.EndManualProbe()
	if sum.Probed != 1 || sum.Unhealthy != 1 || sum.Healthy != 0 || sum.Skipped != 1 {
		t.Fatalf("summary: %+v", sum)
	}
	for _, st := range p.List() {
		if st.ID == "01ARZ3NDEKTSV4RRFFQ69G5FAW" && st.CredentialState != CredentialRequiresReplacement {
			t.Fatalf("requiresReplacement must be derived: %+v", st)
		}
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func okResp(r *http.Request, code int) *http.Response {
	return &http.Response{StatusCode: code, Status: http.StatusText(code), Body: http.NoBody, Header: http.Header{}, Request: r}
}
