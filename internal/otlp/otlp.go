// Package otlp exports metrics and request spans to any OpenTelemetry
// Collector via the OTLP/HTTP JSON protocol (POST /v1/metrics, /v1/traces).
// No SDK dependency — plain net/http and encoding/json keep the binary
// self-contained. Extracted from package main's otlp.go / otlp_traces.go
// per a recorded ADR-0002-style design (post-program extraction).
//
// The package owns the transport (push loops, SSRF-guarded client, endpoint
// validation) and the OTLP JSON schema. What each METRIC contains is the
// caller's business: package main wires a snapshot func into NewMetrics
// that reads its stat singletons and returns []Metric — the engine never
// imports main's state.
package otlp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/obs"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// validEndpoint matches http:// or https:// followed by at least one host
// character. Regexp.MatchString is a CodeQL-recognised SSRF sanitiser,
// breaking the taint chain on the endpoint URL (go/request-forgery).
var validEndpoint = regexp.MustCompile(`^https?://[^/]`)

// SnapshotFunc returns the current metric set, stamped with the given
// UnixNano timestamp string. package main's implementation reads the
// culvert_* stat singletons.
type SnapshotFunc func(nowUnixNano string) []Metric

// MetricsExporter pushes metrics to an OTLP/HTTP endpoint.
type MetricsExporter struct {
	mu       sync.RWMutex
	endpoint string            // e.g. "http://otel-collector:4318"
	headers  map[string]string // custom headers (auth, etc.)
	interval time.Duration
	client   *http.Client
	cancel   context.CancelFunc
	snapshot SnapshotFunc
}

// NewMetrics builds a metrics exporter over the given snapshot source
// (nil = export an empty metric set; useful for tests).
func NewMetrics(snapshot SnapshotFunc) *MetricsExporter {
	return &MetricsExporter{
		interval: 15 * time.Second,
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{DialContext: ssrf.SafeDialContext},
		},
		snapshot: snapshot,
	}
}

// Configure sets the OTLP endpoint and starts the push loop.
func (o *MetricsExporter) Configure(endpoint string, headers map[string]string) {
	o.mu.Lock()
	// Stop existing loop if reconfiguring.
	if o.cancel != nil {
		o.cancel()
	}
	o.endpoint = strings.TrimRight(endpoint, "/")
	o.headers = headers
	o.mu.Unlock()

	if endpoint == "" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	o.mu.Lock()
	o.cancel = cancel
	o.mu.Unlock()
	go o.pushLoop(ctx)
	obs.Printf("OTLP: exporting metrics to %s every %s", obs.Sanitize(endpoint), o.interval)
}

// Stop halts the push loop.
func (o *MetricsExporter) Stop() {
	o.mu.Lock()
	if o.cancel != nil {
		o.cancel()
		o.cancel = nil
	}
	o.endpoint = ""
	o.mu.Unlock()
}

// Enabled returns whether OTLP export is active.
func (o *MetricsExporter) Enabled() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.endpoint != ""
}

// Endpoint returns the current endpoint URL.
func (o *MetricsExporter) Endpoint() string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.endpoint
}

// Headers returns a copy of the configured custom headers (nil when none).
func (o *MetricsExporter) Headers() map[string]string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if len(o.headers) == 0 {
		return nil
	}
	cp := make(map[string]string, len(o.headers))
	for k, v := range o.headers {
		cp[k] = v
	}
	return cp
}

func (o *MetricsExporter) pushLoop(ctx context.Context) {
	ticker := time.NewTicker(o.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := o.push(ctx); err != nil {
				obs.Printf("OTLP push error: %s", obs.Sanitize(err.Error()))
			}
		}
	}
}

func (o *MetricsExporter) push(ctx context.Context) error {
	o.mu.RLock()
	endpoint := o.endpoint
	headers := o.headers
	o.mu.RUnlock()

	if endpoint == "" {
		return nil
	}

	// Regexp barrier: CodeQL recognises Regexp.MatchString as an SSRF
	// sanitiser, breaking the taint chain on endpoint (go/request-forgery).
	if !validEndpoint.MatchString(endpoint) {
		return fmt.Errorf("invalid OTLP endpoint URL: %q", endpoint)
	}
	metricsURL := strings.TrimRight(endpoint, "/") + "/v1/metrics"

	now := fmt.Sprintf("%d", time.Now().UnixNano())
	var metrics []Metric
	if o.snapshot != nil {
		metrics = o.snapshot(now)
	}
	body, err := json.Marshal(Envelope(metrics))
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		metricsURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("OTLP collector returned %d", resp.StatusCode)
	}
	return nil
}

// ─── OTLP JSON payload schema ────────────────────────────────────────────────
// Follows the OTLP/HTTP JSON schema:
// https://opentelemetry.io/docs/specs/otlp/#otlphttp
// Exported so package main's snapshot func can construct []Metric.

// ExportRequest is the top-level /v1/metrics payload.
type ExportRequest struct {
	ResourceMetrics []ResourceMetrics `json:"resourceMetrics"`
}

// ResourceMetrics groups metrics under one resource.
type ResourceMetrics struct {
	Resource     Resource      `json:"resource"`
	ScopeMetrics []ScopeMetric `json:"scopeMetrics"`
}

// Resource carries the resource-identifying attributes.
type Resource struct {
	Attributes []KeyValue `json:"attributes"`
}

// ScopeMetric groups metrics under one instrumentation scope.
type ScopeMetric struct {
	Scope   Scope    `json:"scope"`
	Metrics []Metric `json:"metrics"`
}

// Scope identifies the instrumentation scope.
type Scope struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Metric is one named metric with exactly one of Sum/Gauge/Histogram set.
type Metric struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Unit        string `json:"unit,omitempty"`
	Sum         *Sum   `json:"sum,omitempty"`
	Gauge       *Gauge `json:"gauge,omitempty"`
	Histogram   *Hist  `json:"histogram,omitempty"`
}

// Sum is a monotonic or non-monotonic cumulative counter.
type Sum struct {
	DataPoints             []NumberDataPoint `json:"dataPoints"`
	AggregationTemporality int               `json:"aggregationTemporality"` // 2 = cumulative
	IsMonotonic            bool              `json:"isMonotonic"`
}

// Gauge is a point-in-time value.
type Gauge struct {
	DataPoints []NumberDataPoint `json:"dataPoints"`
}

// Hist is a cumulative histogram.
type Hist struct {
	DataPoints             []HistDataPoint `json:"dataPoints"`
	AggregationTemporality int             `json:"aggregationTemporality"`
}

// NumberDataPoint is one numeric sample.
type NumberDataPoint struct {
	Attributes   []KeyValue `json:"attributes,omitempty"`
	TimeUnixNano string     `json:"timeUnixNano"`
	AsInt        *int64     `json:"asInt,omitempty"`
	AsDouble     *float64   `json:"asDouble,omitempty"`
}

// HistDataPoint is one histogram sample.
type HistDataPoint struct {
	TimeUnixNano   string    `json:"timeUnixNano"`
	Count          int64     `json:"count,string"`
	Sum            float64   `json:"sum"`
	BucketCounts   []string  `json:"bucketCounts"`
	ExplicitBounds []float64 `json:"explicitBounds"`
}

// KeyValue is one attribute.
type KeyValue struct {
	Key   string   `json:"key"`
	Value AnyValue `json:"value"`
}

// AnyValue is an attribute value (string-only — all Culvert attributes are
// strings).
type AnyValue struct {
	StringValue string `json:"stringValue,omitempty"`
}

// culvertResource is the shared service-identifying attribute set.
func culvertResource() Resource {
	return Resource{
		Attributes: []KeyValue{
			{Key: "service.name", Value: AnyValue{StringValue: "culvert"}},
			{Key: "service.version", Value: AnyValue{StringValue: "1.0.0"}},
		},
	}
}

// Envelope wraps a metric set in the standard Culvert resource/scope
// envelope. Exported so main's payload tests can assert the full shape.
func Envelope(metrics []Metric) ExportRequest {
	return ExportRequest{
		ResourceMetrics: []ResourceMetrics{{
			Resource: culvertResource(),
			ScopeMetrics: []ScopeMetric{{
				Scope:   Scope{Name: "culvert", Version: "1.0.0"},
				Metrics: metrics,
			}},
		}},
	}
}
