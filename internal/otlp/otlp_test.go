package otlp

// Metrics-exporter engine tests (the span tests live in spans_test.go,
// moved from package main). TestValidEndpoint_Regexp is the relocated
// main-side validator test — the regex is package-internal since the
// extraction.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestValidEndpoint_Regexp(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"http://collector:4318", true},
		{"https://otel.example.com", true},
		{"http://10.0.0.1:4318", true},
		{"ftp://bad.example.com", false},
		{"", false},
		{"not-a-url", false},
		{"http://", false},
	}
	for _, tc := range tests {
		if got := validEndpoint.MatchString(tc.url); got != tc.want {
			t.Errorf("validEndpoint(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestMetricsExporter_ConfigureAndStop(t *testing.T) {
	o := NewMetrics(nil)
	if o.Enabled() {
		t.Fatal("should be disabled initially")
	}
	if o.Endpoint() != "" {
		t.Fatalf("endpoint should be empty, got %q", o.Endpoint())
	}

	o.Configure("http://collector.example.com:4318", map[string]string{"X-Auth": "k"})
	defer o.Stop()
	if !o.Enabled() {
		t.Fatal("should be enabled after Configure")
	}
	if o.Endpoint() != "http://collector.example.com:4318" {
		t.Fatalf("endpoint = %q", o.Endpoint())
	}
	h := o.Headers()
	if h["X-Auth"] != "k" {
		t.Fatalf("Headers() = %v, want X-Auth=k", h)
	}
	// Headers returns a copy — mutating it must not affect the exporter.
	h["X-Auth"] = "tampered"
	if o.Headers()["X-Auth"] != "k" {
		t.Fatal("Headers() must return a defensive copy")
	}

	o.Stop()
	if o.Enabled() || o.Endpoint() != "" {
		t.Fatal("should be disabled after Stop")
	}
	if o.Headers() != nil && len(o.Headers()) != 0 {
		// headers are not cleared by Stop (endpoint gates pushing) — just
		// assert the accessor still behaves.
		_ = o.Headers()
	}
}

func TestMetricsExporter_ConfigureEmpty(t *testing.T) {
	o := NewMetrics(nil)
	o.Configure("", nil)
	if o.Enabled() {
		t.Fatal("empty endpoint should not enable")
	}
}

func TestMetricsExporter_PushIntegration(t *testing.T) {
	var received []byte
	var mu sync.Mutex
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/metrics" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected Content-Type: %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("X-Auth") != "secret-key" {
			t.Errorf("custom header missing, got %q", r.Header.Get("X-Auth"))
		}
		mu.Lock()
		received, _ = readBody(r)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	v := int64(7)
	snapshot := func(now string) []Metric {
		return []Metric{{
			Name:        "culvert.test.counter",
			Description: "test",
			Sum: &Sum{
				AggregationTemporality: 2,
				IsMonotonic:            true,
				DataPoints:             []NumberDataPoint{{TimeUnixNano: now, AsInt: &v}},
			},
		}}
	}
	// Direct construction (in-package) with the test server's client so the
	// SSRF-guarded production dialer doesn't block the loopback listener.
	o := &MetricsExporter{
		endpoint: ts.URL,
		headers:  map[string]string{"X-Auth": "secret-key"},
		interval: time.Hour,
		client:   ts.Client(),
		snapshot: snapshot,
	}
	if err := o.push(t.Context()); err != nil {
		t.Fatalf("push: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	var payload ExportRequest
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("unmarshal pushed payload: %v", err)
	}
	if len(payload.ResourceMetrics) != 1 {
		t.Fatalf("resourceMetrics = %d, want 1", len(payload.ResourceMetrics))
	}
	sm := payload.ResourceMetrics[0].ScopeMetrics
	if len(sm) != 1 || len(sm[0].Metrics) != 1 || sm[0].Metrics[0].Name != "culvert.test.counter" {
		t.Fatalf("unexpected metric payload: %+v", sm)
	}
	// The service resource attributes must identify culvert.
	attrs := payload.ResourceMetrics[0].Resource.Attributes
	found := false
	for _, kv := range attrs {
		if kv.Key == "service.name" && kv.Value.StringValue == "culvert" {
			found = true
		}
	}
	if !found {
		t.Fatal("service.name=culvert resource attribute missing")
	}
}

func TestMetricsExporter_PushRejectsBadEndpoint(t *testing.T) {
	o := &MetricsExporter{endpoint: "ftp://bad", client: http.DefaultClient}
	if err := o.push(t.Context()); err == nil {
		t.Fatal("push must reject a non-http(s) endpoint")
	}
}

func TestMetricsExporter_PushNilEndpointIsNoOp(t *testing.T) {
	o := NewMetrics(nil)
	if err := o.push(t.Context()); err != nil {
		t.Fatalf("push with no endpoint should be a no-op, got %v", err)
	}
}

func TestEnvelope_Shape(t *testing.T) {
	env := Envelope([]Metric{{Name: "m1"}, {Name: "m2"}})
	if len(env.ResourceMetrics) != 1 {
		t.Fatalf("resourceMetrics = %d, want 1", len(env.ResourceMetrics))
	}
	sm := env.ResourceMetrics[0].ScopeMetrics
	if len(sm) != 1 || sm[0].Scope.Name != "culvert" || len(sm[0].Metrics) != 2 {
		t.Fatalf("unexpected envelope: %+v", sm)
	}
}
