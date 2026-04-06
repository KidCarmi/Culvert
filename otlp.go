package main

// ─── OpenTelemetry OTLP/HTTP metrics export ──────────────────────────────────
//
// Exports Culvert metrics to any OpenTelemetry Collector via the OTLP/HTTP
// JSON protocol (POST /v1/metrics). No SDK dependency — uses plain net/http
// and encoding/json, keeping the binary self-contained.
//
// Configuration:
//   -otlp-endpoint http://otel-collector:4318    (OTLP/HTTP receiver)
//   config.yaml:  otlp_endpoint: "http://otel-collector:4318"
//
// The exporter pushes a snapshot of all culvert_* metrics every push interval
// (default 15s). Headers can be set for authentication (e.g. API keys).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// OTLPExporter pushes metrics to an OTLP/HTTP endpoint.
type OTLPExporter struct {
	mu       sync.RWMutex
	endpoint string            // e.g. "http://otel-collector:4318"
	headers  map[string]string // custom headers (auth, etc.)
	interval time.Duration
	client   *http.Client
	cancel   context.CancelFunc
}

var globalOTLP = &OTLPExporter{
	interval: 15 * time.Second,
	client:   &http.Client{Timeout: 10 * time.Second},
}

// Configure sets the OTLP endpoint and starts the push loop.
func (o *OTLPExporter) Configure(endpoint string, headers map[string]string) {
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
	logger.Printf("OTLP     → exporting metrics to %s every %s", sanitizeLog(endpoint), o.interval)
}

// Stop halts the push loop.
func (o *OTLPExporter) Stop() {
	o.mu.Lock()
	if o.cancel != nil {
		o.cancel()
		o.cancel = nil
	}
	o.endpoint = ""
	o.mu.Unlock()
}

// Enabled returns whether OTLP export is active.
func (o *OTLPExporter) Enabled() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.endpoint != ""
}

// Endpoint returns the current endpoint URL.
func (o *OTLPExporter) Endpoint() string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.endpoint
}

func (o *OTLPExporter) pushLoop(ctx context.Context) {
	ticker := time.NewTicker(o.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := o.push(ctx); err != nil {
				logger.Printf("OTLP push error: %v", err)
			}
		}
	}
}

func (o *OTLPExporter) push(ctx context.Context) error {
	o.mu.RLock()
	endpoint := o.endpoint
	headers := o.headers
	o.mu.RUnlock()

	if endpoint == "" {
		return nil
	}

	// Inline SSRF guard: validate scheme + reject private hosts (CodeQL CWE-918).
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid OTLP endpoint scheme: %q", endpoint)
	}
	if err := isPrivateHost(u.Hostname()); err != nil {
		return fmt.Errorf("OTLP endpoint resolves to private network: %w", err)
	}

	payload := o.buildPayload()
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint+"/v1/metrics", bytes.NewReader(body))
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

// ─── OTLP JSON payload construction ─────────────────────────────────────────
// Follows the OTLP/HTTP JSON schema:
// https://opentelemetry.io/docs/specs/otlp/#otlphttp

type otlpExportRequest struct {
	ResourceMetrics []otlpResourceMetrics `json:"resourceMetrics"`
}

type otlpResourceMetrics struct {
	Resource     otlpResource      `json:"resource"`
	ScopeMetrics []otlpScopeMetric `json:"scopeMetrics"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpScopeMetric struct {
	Scope   otlpScope    `json:"scope"`
	Metrics []otlpMetric `json:"metrics"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type otlpMetric struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Unit        string     `json:"unit,omitempty"`
	Sum         *otlpSum   `json:"sum,omitempty"`
	Gauge       *otlpGauge `json:"gauge,omitempty"`
	Histogram   *otlpHist  `json:"histogram,omitempty"`
}

type otlpSum struct {
	DataPoints             []otlpNumberDataPoint `json:"dataPoints"`
	AggregationTemporality int                   `json:"aggregationTemporality"` // 2 = cumulative
	IsMonotonic            bool                  `json:"isMonotonic"`
}

type otlpGauge struct {
	DataPoints []otlpNumberDataPoint `json:"dataPoints"`
}

type otlpHist struct {
	DataPoints             []otlpHistDataPoint `json:"dataPoints"`
	AggregationTemporality int                 `json:"aggregationTemporality"`
}

type otlpNumberDataPoint struct {
	Attributes   []otlpKeyValue `json:"attributes,omitempty"`
	TimeUnixNano string         `json:"timeUnixNano"`
	AsInt        *int64         `json:"asInt,omitempty"`
	AsDouble     *float64       `json:"asDouble,omitempty"`
}

type otlpHistDataPoint struct {
	TimeUnixNano   string    `json:"timeUnixNano"`
	Count          int64     `json:"count,string"`
	Sum            float64   `json:"sum"`
	BucketCounts   []string  `json:"bucketCounts"`
	ExplicitBounds []float64 `json:"explicitBounds"`
}

type otlpKeyValue struct {
	Key   string        `json:"key"`
	Value otlpAnyValue  `json:"value"`
}

type otlpAnyValue struct {
	StringValue string `json:"stringValue,omitempty"`
}

func otlpCounterMetrics(now string) []otlpMetric {
	counters := []struct {
		name string
		desc string
		val  int64
	}{
		{"culvert.requests.total", "Total proxy requests", atomic.LoadInt64(&statTotal)},
		{"culvert.requests.blocked", "Total blocked requests", atomic.LoadInt64(&statBlocked)},
		{"culvert.requests.auth_fail", "Total auth failures", atomic.LoadInt64(&statAuthFail)},
		{"culvert.requests.file_blocked", "File extension blocks", atomic.LoadInt64(&statFileBlocked)},
		{"culvert.requests.dpi_blocked", "DPI content blocks", atomic.LoadInt64(&statDPIBlocked)},
		{"culvert.requests.clamav_blocked", "ClamAV blocks", atomic.LoadInt64(&statClamBlocked)},
		{"culvert.requests.yara_blocked", "YARA blocks", atomic.LoadInt64(&statYARABlocked)},
		{"culvert.requests.threat_feed_blocked", "Threat feed blocks", atomic.LoadInt64(&statThreatFeedBlocked)},
		{"culvert.bytes.sent", "Bytes sent upstream", atomic.LoadInt64(&statBytesSent)},
		{"culvert.bytes.recv", "Bytes received", atomic.LoadInt64(&statBytesRecv)},
	}
	metrics := make([]otlpMetric, 0, len(counters))
	for _, c := range counters {
		v := c.val
		metrics = append(metrics, otlpMetric{
			Name:        c.name,
			Description: c.desc,
			Sum: &otlpSum{
				AggregationTemporality: 2, // cumulative
				IsMonotonic:            true,
				DataPoints: []otlpNumberDataPoint{{
					TimeUnixNano: now,
					AsInt:        &v,
				}},
			},
		})
	}
	return metrics
}

func otlpGaugeMetrics(now string) []otlpMetric {
	uptimeSec := time.Since(startTime).Seconds()
	feedEntries, _, _ := globalThreatFeed.Stats()
	_, _, cacheSize := globalSecScanner.cache.Stats()
	gauges := []struct {
		name string
		desc string
		val  float64
	}{
		{"culvert.uptime", "Proxy uptime in seconds", uptimeSec},
		{"culvert.blocklist.size", "Blocked domains count", float64(bl.Count())},
		{"culvert.rate_limit.rpm", "Configured rate limit RPM", float64(rl.Limit())},
		{"culvert.threat_feed.entries", "Threat feed entries", float64(feedEntries)},
		{"culvert.scan_cache.size", "Scan cache entries", float64(cacheSize)},
	}
	metrics := make([]otlpMetric, 0, len(gauges))
	for _, g := range gauges {
		v := g.val
		metrics = append(metrics, otlpMetric{
			Name:        g.name,
			Description: g.desc,
			Unit:        "1",
			Gauge: &otlpGauge{
				DataPoints: []otlpNumberDataPoint{{
					TimeUnixNano: now,
					AsDouble:     &v,
				}},
			},
		})
	}
	return metrics
}

func otlpHistogramMetric(now string) otlpMetric {
	bucketCounts := make([]string, len(latencyHist.buckets)+1)
	for i := range latencyHist.counts {
		bucketCounts[i] = fmt.Sprintf("%d", atomic.LoadInt64(&latencyHist.counts[i]))
	}
	histSum := math.Float64frombits(uint64(atomic.LoadInt64(&latencyHist.sumBits))) // #nosec G115
	return otlpMetric{
		Name:        "culvert.request.duration",
		Description: "Request latency",
		Unit:        "s",
		Histogram: &otlpHist{
			AggregationTemporality: 2,
			DataPoints: []otlpHistDataPoint{{
				TimeUnixNano:   now,
				Count:          atomic.LoadInt64(&latencyHist.total),
				Sum:            histSum,
				BucketCounts:   bucketCounts,
				ExplicitBounds: latencyHist.buckets,
			}},
		},
	}
}

func otlpRuleMetrics(now string) []otlpMetric {
	ruleMet.mu.RLock()
	defer ruleMet.mu.RUnlock()
	metrics := make([]otlpMetric, 0, len(ruleMet.order))
	for _, name := range ruleMet.order {
		ctr := ruleMet.hits[name]
		v := atomic.LoadInt64(ctr)
		metrics = append(metrics, otlpMetric{
			Name:        "culvert.policy.rule_hits",
			Description: "Per-rule hit count",
			Sum: &otlpSum{
				AggregationTemporality: 2,
				IsMonotonic:            true,
				DataPoints: []otlpNumberDataPoint{{
					TimeUnixNano: now,
					AsInt:        &v,
					Attributes: []otlpKeyValue{{
						Key:   "rule",
						Value: otlpAnyValue{StringValue: name},
					}},
				}},
			},
		})
	}
	return metrics
}

func (o *OTLPExporter) buildPayload() otlpExportRequest {
	now := fmt.Sprintf("%d", time.Now().UnixNano())

	metrics := otlpCounterMetrics(now)
	metrics = append(metrics, otlpGaugeMetrics(now)...)
	metrics = append(metrics, otlpHistogramMetric(now))
	metrics = append(metrics, otlpRuleMetrics(now)...)

	return otlpExportRequest{
		ResourceMetrics: []otlpResourceMetrics{{
			Resource: otlpResource{
				Attributes: []otlpKeyValue{
					{Key: "service.name", Value: otlpAnyValue{StringValue: "culvert"}},
					{Key: "service.version", Value: otlpAnyValue{StringValue: "1.0.0"}},
				},
			},
			ScopeMetrics: []otlpScopeMetric{{
				Scope:   otlpScope{Name: "culvert", Version: "1.0.0"},
				Metrics: metrics,
			}},
		}},
	}
}
