package otlp

// OTLP/HTTP trace (span) export (POST /v1/traces). Mirrors the metrics
// exporter: no SDK dependency, background push loop, fire-and-forget.
//
// Spans are collected into a bounded ring buffer during request handling
// (one mutex-guarded append per request ≈ nanoseconds). A background
// goroutine batch-flushes them to the collector every push interval.
// The buffer cap (spanBufferCap) prevents OOM when the collector is down.

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

	"github.com/KidCarmi/Culvert/internal/obs"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// spanBufferCap is the maximum number of spans held in memory before the
// oldest are silently dropped. 4096 spans × ~512 bytes ≈ 2 MB peak.
const spanBufferCap = 4096

// SpanRecord holds the data collected per proxied request. Allocated on the
// stack in handleRequest and copied into the ring buffer — no heap escape
// for the common no-OTLP case because RecordSpan callers check Enabled()
// first.
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

// SpanExporter collects spans and pushes them to an OTLP/HTTP endpoint.
type SpanExporter struct {
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

// NewSpans builds a span exporter.
func NewSpans() *SpanExporter {
	return &SpanExporter{
		interval: 15 * time.Second,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     90 * time.Second,
				DialContext:         ssrf.SafeDialContext,
			},
		},
		buf: make([]SpanRecord, spanBufferCap),
	}
}

// Configure sets the OTLP endpoint and starts the push loop.
func (e *SpanExporter) Configure(endpoint string, headers map[string]string) {
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
	obs.Printf("OTLP: exporting traces to %s every %s", obs.Sanitize(endpoint), e.interval)
}

// Stop halts the push loop and clears the endpoint.
func (e *SpanExporter) Stop() {
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
func (e *SpanExporter) Enabled() bool {
	return e.active.Load()
}

// RecordSpan appends a span to the ring buffer. Callers should check
// Enabled() first to avoid constructing the SpanRecord at all when tracing
// is off.
func (e *SpanExporter) RecordSpan(s SpanRecord) {
	e.mu.Lock()
	e.buf[e.head%spanBufferCap] = s
	e.head++
	if e.count < spanBufferCap {
		e.count++
	}
	e.mu.Unlock()
}

// drain returns all buffered spans and resets the buffer.
func (e *SpanExporter) drain() []SpanRecord {
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

func (e *SpanExporter) pushLoop(ctx context.Context) {
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Final flush on shutdown.
			e.push(context.Background()) //nolint:errcheck // best-effort final flush
			return
		case <-ticker.C:
			if err := e.push(ctx); err != nil {
				obs.Printf("OTLP traces push error: %s", obs.Sanitize(err.Error()))
			}
		}
	}
}

func (e *SpanExporter) push(ctx context.Context) error {
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

	if !validEndpoint.MatchString(endpoint) {
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

type traceExportRequest struct {
	ResourceSpans []resourceSpan `json:"resourceSpans"`
}

type resourceSpan struct {
	Resource   Resource    `json:"resource"`
	ScopeSpans []scopeSpan `json:"scopeSpans"`
}

type scopeSpan struct {
	Scope Scope  `json:"scope"`
	Spans []span `json:"spans"`
}

type span struct {
	TraceID           string     `json:"traceId"`
	SpanID            string     `json:"spanId"`
	Name              string     `json:"name"`
	Kind              int        `json:"kind"` // 2 = SPAN_KIND_SERVER
	StartTimeUnixNano string     `json:"startTimeUnixNano"`
	EndTimeUnixNano   string     `json:"endTimeUnixNano"`
	Attributes        []KeyValue `json:"attributes,omitempty"`
	Status            spanStatus `json:"status"`
}

type spanStatus struct {
	Code    int    `json:"code"` // 0=unset, 1=ok, 2=error
	Message string `json:"message,omitempty"`
}

// ParseTraceparent extracts the trace-id and span-id from a W3C Traceparent
// header value: "00-{traceID}-{spanID}-{flags}"
func ParseTraceparent(tp string) (traceID, spanID string) {
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

func buildTracePayload(spans []SpanRecord) traceExportRequest {
	otlpSpans := make([]span, 0, len(spans))
	for i := range spans {
		s := &spans[i]
		attrs := []KeyValue{
			{Key: "http.method", Value: AnyValue{StringValue: s.Method}},
			{Key: "http.host", Value: AnyValue{StringValue: s.Host}},
			{Key: "culvert.status", Value: AnyValue{StringValue: s.Status}},
			{Key: "net.peer.ip", Value: AnyValue{StringValue: s.ClientIP}},
		}
		if s.Rule != "" {
			attrs = append(attrs, KeyValue{
				Key: "culvert.rule", Value: AnyValue{StringValue: s.Rule},
			})
		}
		if s.SSLAction != "" {
			attrs = append(attrs, KeyValue{
				Key: "culvert.ssl_action", Value: AnyValue{StringValue: s.SSLAction},
			})
		}
		otlpSpans = append(otlpSpans, span{
			TraceID:           s.TraceID,
			SpanID:            s.SpanID,
			Name:              s.Name,
			Kind:              2, // SPAN_KIND_SERVER
			StartTimeUnixNano: fmt.Sprintf("%d", s.StartNano),
			EndTimeUnixNano:   fmt.Sprintf("%d", s.EndNano),
			Attributes:        attrs,
			Status:            spanStatus{Code: spanStatusCode(s.Status)},
		})
	}

	return traceExportRequest{
		ResourceSpans: []resourceSpan{{
			Resource: culvertResource(),
			ScopeSpans: []scopeSpan{{
				Scope: Scope{Name: "culvert.proxy", Version: "1.0.0"},
				Spans: otlpSpans,
			}},
		}},
	}
}
