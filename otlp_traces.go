package main

// ─── OpenTelemetry OTLP/HTTP trace (span) export ───────────────────────────
//
// Exports request-level spans to any OpenTelemetry Collector via OTLP/HTTP
// JSON (POST /v1/traces). Mirrors the metrics exporter in otlp.go: no SDK
// dependency, background push loop, fire-and-forget semantics.
//
// Spans are collected into a bounded ring buffer during request handling
// (one mutex-guarded append per request ≈ nanoseconds). A background
// goroutine batch-flushes them to the collector every push interval.
// The buffer cap (spanBufferCap) prevents OOM when the collector is down.
//
// Configuration: shares the same -otlp-endpoint as the metrics exporter.
// When the endpoint is set, both metrics and traces push to it.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// spanBufferCap is the maximum number of spans held in memory before the
// oldest are silently dropped. 4096 spans × ~512 bytes ≈ 2 MB peak.
const spanBufferCap = 4096

// SpanRecord holds the data collected per proxied request. Allocated on the
// stack in handleRequest and copied into the ring buffer — no heap escape
// for the common no-OTLP case because RecordSpan checks Enabled() first.
type SpanRecord struct {
	TraceID   string // 32 hex chars from Traceparent
	SpanID    string // 16 hex chars from Traceparent
	Name      string // "proxy_request"
	Method    string // GET, CONNECT, etc.
	Host      string // target host
	Status    string // OK, BLOCKED, FILE_BLOCKED, etc.
	Rule      string // matched policy rule name (may be empty)
	ClientIP  string // net.SplitHostPort(r.RemoteAddr)
	SSLAction string // "inspect", "bypass", or ""
	StartNano int64  // time.Now().UnixNano() at request start
	EndNano   int64  // time.Now().UnixNano() at request end
}

// OTLPSpanExporter collects spans and pushes them to an OTLP/HTTP endpoint.
type OTLPSpanExporter struct {
	mu       sync.Mutex
	active   atomic.Bool // lock-free fast path for Enabled()
	endpoint string
	headers  map[string]string
	interval time.Duration
	client   *http.Client
	cancel   context.CancelFunc

	// Ring buffer: spans are appended at buf[head % cap]; when full the
	// oldest span is overwritten silently.
	buf   []SpanRecord
	head  int
	count int
}

var globalOTLPTraces = &OTLPSpanExporter{
	interval: 15 * time.Second,
	client: &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     90 * time.Second,
			DialContext:         ssrfSafeDialContext,
		},
	},
	buf: make([]SpanRecord, spanBufferCap),
}

// Configure sets the OTLP endpoint and starts the push loop.
func (e *OTLPSpanExporter) Configure(endpoint string, headers map[string]string) {
	e.mu.Lock()
	if e.cancel != nil {
		e.cancel()
	}
	e.endpoint = strings.TrimRight(endpoint, "/")
	e.headers = headers
	e.active.Store(endpoint != "")
	e.mu.Unlock()

	if endpoint == "" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.cancel = cancel
	e.mu.Unlock()
	go e.pushLoop(ctx)
	logger.Printf("OTLP: exporting traces to %s every %s", sanitizeLog(endpoint), e.interval)
}

// Stop halts the push loop and clears the endpoint.
func (e *OTLPSpanExporter) Stop() {
	e.mu.Lock()
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	e.endpoint = ""
	e.active.Store(false)
	e.mu.Unlock()
}

// Enabled returns whether trace export is active (lock-free fast path).
func (e *OTLPSpanExporter) Enabled() bool {
	return e.active.Load()
}

// RecordSpan appends a span to the ring buffer. Lock-free fast path: callers
// should check Enabled() first to avoid constructing the SpanRecord at all
// when tracing is off.
func (e *OTLPSpanExporter) RecordSpan(s SpanRecord) {
	e.mu.Lock()
	e.buf[e.head%spanBufferCap] = s
	e.head++
	if e.count < spanBufferCap {
		e.count++
	}
	e.mu.Unlock()
}

// drain returns all buffered spans and resets the buffer.
func (e *OTLPSpanExporter) drain() []SpanRecord {
	e.mu.Lock()
	if e.count == 0 {
		e.mu.Unlock()
		return nil
	}
	out := make([]SpanRecord, e.count)
	// Read oldest-first from the ring buffer.
	start := e.head - e.count
	for i := 0; i < e.count; i++ {
		out[i] = e.buf[(start+i)%spanBufferCap]
	}
	e.count = 0
	e.head = 0
	e.mu.Unlock()
	return out
}

func (e *OTLPSpanExporter) pushLoop(ctx context.Context) {
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Final flush on shutdown.
			e.push(context.Background()) //nolint:errcheck
			return
		case <-ticker.C:
			if err := e.push(ctx); err != nil {
				logger.Printf("OTLP traces push error: %s", sanitizeLog(err.Error()))
			}
		}
	}
}

func (e *OTLPSpanExporter) push(ctx context.Context) error {
	spans := e.drain()
	if len(spans) == 0 {
		return nil
	}

	e.mu.Lock()
	endpoint := e.endpoint
	headers := e.headers
	e.mu.Unlock()

	if endpoint == "" {
		return nil
	}

	if !validOTLPEndpoint.MatchString(endpoint) {
		return fmt.Errorf("invalid OTLP endpoint URL: %q", endpoint)
	}
	tracesURL := strings.TrimRight(endpoint, "/") + "/v1/traces"

	payload := buildTracePayload(spans)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		tracesURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("OTLP collector returned %d", resp.StatusCode)
	}
	return nil
}

// ─── OTLP trace JSON payload ───────────────────────────────────────────────
// Follows the OTLP/HTTP JSON schema:
// https://opentelemetry.io/docs/specs/otlp/#otlphttp-request

type otlpTraceExportRequest struct {
	ResourceSpans []otlpResourceSpan `json:"resourceSpans"`
}

type otlpResourceSpan struct {
	Resource   otlpResource    `json:"resource"`
	ScopeSpans []otlpScopeSpan `json:"scopeSpans"`
}

type otlpScopeSpan struct {
	Scope otlpScope  `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type otlpSpan struct {
	TraceID           string         `json:"traceId"`
	SpanID            string         `json:"spanId"`
	Name              string         `json:"name"`
	Kind              int            `json:"kind"` // 2 = SPAN_KIND_SERVER
	StartTimeUnixNano string         `json:"startTimeUnixNano"`
	EndTimeUnixNano   string         `json:"endTimeUnixNano"`
	Attributes        []otlpKeyValue `json:"attributes,omitempty"`
	Status            otlpSpanStatus `json:"status"`
}

type otlpSpanStatus struct {
	Code    int    `json:"code"` // 0=unset, 1=ok, 2=error
	Message string `json:"message,omitempty"`
}

// parseTraceparent extracts the trace-id and span-id from a W3C Traceparent
// header value: "00-{traceID}-{spanID}-{flags}"
func parseTraceparent(tp string) (traceID, spanID string) {
	parts := strings.Split(tp, "-")
	if len(parts) >= 3 {
		traceID = parts[1]
		spanID = parts[2]
	}
	return
}

func spanStatusCode(status string) int {
	switch status {
	case "OK", "POLICY_ALLOW":
		return 1 // STATUS_CODE_OK
	default:
		return 2 // STATUS_CODE_ERROR
	}
}

func buildTracePayload(spans []SpanRecord) otlpTraceExportRequest {
	otlpSpans := make([]otlpSpan, 0, len(spans))
	for i := range spans {
		s := &spans[i]
		attrs := []otlpKeyValue{
			{Key: "http.method", Value: otlpAnyValue{StringValue: s.Method}},
			{Key: "http.host", Value: otlpAnyValue{StringValue: s.Host}},
			{Key: "culvert.status", Value: otlpAnyValue{StringValue: s.Status}},
			{Key: "net.peer.ip", Value: otlpAnyValue{StringValue: s.ClientIP}},
		}
		if s.Rule != "" {
			attrs = append(attrs, otlpKeyValue{
				Key: "culvert.rule", Value: otlpAnyValue{StringValue: s.Rule},
			})
		}
		if s.SSLAction != "" {
			attrs = append(attrs, otlpKeyValue{
				Key: "culvert.ssl_action", Value: otlpAnyValue{StringValue: s.SSLAction},
			})
		}
		otlpSpans = append(otlpSpans, otlpSpan{
			TraceID:           s.TraceID,
			SpanID:            s.SpanID,
			Name:              s.Name,
			Kind:              2, // SPAN_KIND_SERVER
			StartTimeUnixNano: fmt.Sprintf("%d", s.StartNano),
			EndTimeUnixNano:   fmt.Sprintf("%d", s.EndNano),
			Attributes:        attrs,
			Status:            otlpSpanStatus{Code: spanStatusCode(s.Status)},
		})
	}

	return otlpTraceExportRequest{
		ResourceSpans: []otlpResourceSpan{{
			Resource: otlpResource{
				Attributes: []otlpKeyValue{
					{Key: "service.name", Value: otlpAnyValue{StringValue: "culvert"}},
					{Key: "service.version", Value: otlpAnyValue{StringValue: "1.0.0"}},
				},
			},
			ScopeSpans: []otlpScopeSpan{{
				Scope: otlpScope{Name: "culvert.proxy", Version: "1.0.0"},
				Spans: otlpSpans,
			}},
		}},
	}
}
