package otlp

// OTLP/HTTP trace (span) export (POST /v1/traces). Mirrors the metrics
// exporter: no SDK dependency, background push loop, fire-and-forget.
//
// Spans are collected into a bounded ring buffer during request handling
// (one mutex-guarded append per request ≈ nanoseconds). A background
// goroutine batch-flushes them to the collector every push interval.
// The buffer cap (spanBufferCap) prevents OOM when the collector is down.
//
// CHAOS-126 — a span is a ONE-SHOT record. The metrics exporter beside this
// one pushes a cumulative snapshot, so a failed push costs resolution and
// the next tick re-derives everything; nothing re-derives a span. push()
// therefore does not destroy a batch the collector declined: an undelivered
// batch goes back to the FRONT of the ring (requeue), which is what makes
// the cap above a real bound and droppedSpans a real count during an outage
// rather than the 0 it used to read while every span was being lost.

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
// oldest are dropped (counted in droppedSpans — never silently).
// 4096 spans × ~512 bytes ≈ 2 MB peak.
const spanBufferCap = 4096

// spanFinalFlushTimeout bounds the flush the push loop makes when its
// context is cancelled (a reconfigure or a disable) and the flush the
// shutdown sequence asks for. The client's own 10 s timeout is the wrong
// bound for either: a reconfigure must not block on a dead collector, and a
// shutdown flush runs inside the flush reserve every durable closer shares.
const spanFinalFlushTimeout = 5 * time.Second

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
	// oldest span is overwritten (counted — see droppedSpans).
	buf   []SpanRecord
	head  int
	count int

	// pushSlot serializes push(): one in-flight batch at a time, acquired
	// ctx-aware so a caller with a deadline (the shutdown flush) cannot be
	// pinned behind a slow one. Two concurrent pushers each hold a drained
	// batch, and requeue puts whichever finishes LAST at the front of the
	// ring — so a newer batch finishing after an older one INVERTED the
	// oldest-first order the ring documents, and at the cap that made
	// overflow evict the NEWEST spans instead of the oldest (reproduced:
	// [100 101 0 1 2] for a ring that should read [0 1 2 100 101]). The
	// shutdown flush created that second pusher by design, since it runs
	// while the ticker loop is still live. Lazily built so a zero-value
	// exporter (the in-package test fixtures) still works.
	pushSlot chan struct{}

	// Push-health diagnostics (read-only; never gates or alters push
	// behavior) — see MetricsExporter's identical fields for rationale.
	pushFailures  atomic.Int64
	lastErr       atomic.Value // string
	lastErrAt     atomic.Int64 // UnixNano; 0 = never
	lastSuccessAt atomic.Int64 // UnixNano; 0 = never
	// droppedSpans counts spans THAT WERE NEVER DELIVERED, whatever ended
	// them: a ring-buffer overwrite, a batch the collector rejected outright
	// (a 4xx that re-posting cannot change), and the buffer a disable or an
	// endpoint change throws away. It used to count overwrites alone — a
	// state the running push loop could not reach, because the loop emptied
	// the ring on every tick whether or not the collector took it, so the
	// counter read 0 through a total outage (CHAOS-126).
	droppedSpans atomic.Int64
}

// Health returns the current push-loop diagnostic snapshot, including spans
// that were never delivered (DroppedSpans — see the field's comment for
// what ends a span's life).
func (e *SpanExporter) Health() PushHealth {
	h := PushHealth{
		FailureCount: e.pushFailures.Load(),
		DroppedSpans: e.droppedSpans.Load(),
	}
	if v, _ := e.lastErr.Load().(string); v != "" {
		h.LastError = v
	}
	if t := e.lastErrAt.Load(); t != 0 {
		h.LastErrorAt = time.Unix(0, t).UTC().Format(time.RFC3339)
	}
	if t := e.lastSuccessAt.Load(); t != 0 {
		h.LastSuccessAt = time.Unix(0, t).UTC().Format(time.RFC3339)
	}
	return h
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
		buf:      make([]SpanRecord, spanBufferCap),
		pushSlot: make(chan struct{}, 1),
	}
}

// pushGate returns the one-slot push semaphore, building it on first use so a
// zero-value SpanExporter behaves like a constructed one.
func (e *SpanExporter) pushGate() chan struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pushSlot == nil {
		e.pushSlot = make(chan struct{}, 1)
	}
	return e.pushSlot
}

// Configure sets the OTLP endpoint and starts the push loop.
func (e *SpanExporter) Configure(endpoint string, headers map[string]string) {
	// CHAOS-126: normalise FIRST, then derive both the active flag and the
	// start decision from the normalised value. Deriving them from the raw
	// argument let Configure("/") store an empty endpoint while reporting
	// Enabled() == true and starting a loop that could never post.
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")

	e.mu.Lock()
	if e.cancel != nil {
		e.cancel()
	}
	// CHAOS-126: spans buffered for the PREVIOUS collector are not shipped
	// to a different one. A SpanRecord carries the client IP, the target
	// host and the enforcement decision; an operator who repoints the
	// gateway did not choose that destination for the window already
	// collected. Dropped here explicitly and counted, where the cancelled
	// loop's "final flush" used to deliver them to the new endpoint.
	dropped := 0
	if e.endpoint != "" && e.endpoint != endpoint {
		dropped = e.discardBufferedLocked()
	}
	e.endpoint = endpoint
	e.headers = headers
	e.active.Store(endpoint != "")
	e.mu.Unlock()

	if dropped > 0 {
		obs.Printf("OTLP traces: dropped %d buffered span(s) on an endpoint change", dropped)
	}
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
	// CHAOS-126: disabling trace export ends the buffered spans' chance of
	// delivery, so they are dropped HERE — explicitly and counted. The
	// cancelled loop's "final flush" cannot do it: Stop clears the endpoint
	// first, so that flush used to drain the ring and only then discover it
	// had nowhere to post it, losing the batch with droppedSpans still 0.
	dropped := e.discardBufferedLocked()
	e.mu.Unlock()
	if dropped > 0 {
		obs.Printf("OTLP traces: dropped %d buffered span(s) on disable", dropped)
	}
}

// Flush makes ONE bounded delivery attempt for everything buffered right now.
// The shutdown sequence calls it (main_shutdown.go,
// shutdownOrderOTLPTracesFlush) because nothing else can: no caller cancels
// the push loop at process exit, so the loop's own ctx.Done() flush — the one
// its comment called "Final flush on shutdown" — has never run on a shutdown
// in this binary's life (CHAOS-126). A no-op when export is disabled.
func (e *SpanExporter) Flush(ctx context.Context) error {
	return e.push(ctx)
}

// FlushFinal is Flush for a process that is going away: one bounded attempt,
// and then whatever is still held is ENDED — counted, and logged WITH ITS
// SIZE, because that log line is the only form in which the number survives
// the exit. Retention is the right answer for a failure with a next interval
// ahead of it and the wrong answer here: a retained batch would die in RAM
// having moved no counter and named no quantity, which is the silent loss
// this round exists to remove, merely relocated to the last second of the
// process's life.
func (e *SpanExporter) FlushFinal(ctx context.Context) error {
	err := e.push(ctx)
	e.mu.Lock()
	n := e.discardBufferedLocked()
	e.mu.Unlock()
	if n > 0 {
		obs.Printf("OTLP traces: %d span(s) could not be delivered before shutdown", n)
	}
	return err
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
	} else {
		e.droppedSpans.Add(1)
	}
	e.mu.Unlock()
}

// drain returns all buffered spans and resets the buffer. The caller OWNS
// the returned batch: it must either deliver it or hand it back through
// requeue/discard, because nothing else holds a reference to it any more
// (CHAOS-126).
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

// requeue returns an undelivered batch to the FRONT of the ring buffer,
// ahead of spans recorded while the push was in flight, and counts whatever
// no longer fits as dropped.
//
// This is RETENTION, not a retry ladder: the next tick makes one attempt
// with whatever the buffer then holds, so a collector that stays down costs
// a bounded 4096 spans of memory, one request per interval, and a counted
// overflow — the behaviour spanBufferCap and droppedSpans were documented to
// have.
//
// `postedTo` is the endpoint the batch was ACTUALLY posted to, and a batch is
// only ever retained for that same destination. Testing the CURRENT endpoint
// instead was a privacy defect with a demonstrated reproduction: Configure
// discards what is in the RING, but a batch already drained by an in-flight
// push is invisible to it, so a repoint mid-push put collector A's spans —
// client IPs, target hosts, enforcement decisions — in the queue for
// collector B and delivered them on the next tick, with droppedSpans still 0.
// A batch whose destination is gone (Stop) or has changed has nothing left to
// be retained FOR, so it is counted and said out loud.
func (e *SpanExporter) requeue(batch []SpanRecord, postedTo string) {
	if len(batch) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.endpoint != postedTo {
		e.droppedSpans.Add(int64(len(batch)))
		reason := "export was disabled while the push was in flight"
		if e.endpoint != "" {
			reason = "the endpoint changed while the push was in flight; a batch is never delivered to a destination it was not collected for"
		}
		obs.Printf("OTLP traces: discarded %d span(s) — %s", len(batch), reason)
		return
	}
	// One transient slice of at most 2×spanBufferCap records (≈1.3 MB),
	// allocated at most once per push interval on the failure path only.
	// Rotating in place would avoid it and would be considerably harder to
	// read for a buffer this size; the memory bound that matters is the
	// RESIDENT one below, which is still exactly spanBufferCap.
	merged := make([]SpanRecord, 0, len(batch)+e.count)
	merged = append(merged, batch...)
	start := e.head - e.count
	for i := 0; i < e.count; i++ {
		merged = append(merged, e.buf[(start+i)%spanBufferCap])
	}
	// Ring semantics are unchanged: on overflow the OLDEST lose.
	if over := len(merged) - spanBufferCap; over > 0 {
		e.droppedSpans.Add(int64(over))
		merged = merged[over:]
	}
	copy(e.buf, merged)
	e.head = len(merged)
	e.count = len(merged)
}

// discard counts a batch that will never be delivered and says why. Every
// span that leaves this exporter without reaching a collector passes through
// here or through requeue's overflow arm, so droppedSpans can be read as
// total undelivered (CHAOS-126).
func (e *SpanExporter) discard(spans []SpanRecord, reason string) {
	if len(spans) == 0 {
		return
	}
	e.droppedSpans.Add(int64(len(spans)))
	obs.Printf("OTLP traces: discarded %d span(s) — %s", len(spans), reason)
}

// discardBufferedLocked empties the ring, counting what it throws away, and
// returns that count. Caller holds e.mu.
func (e *SpanExporter) discardBufferedLocked() int {
	n := e.count
	if n == 0 {
		return 0
	}
	e.droppedSpans.Add(int64(n))
	e.count = 0
	e.head = 0
	return n
}

// retryableCollectorStatus reports whether a status code describes a
// condition that can change on its own — the collector is overloaded,
// restarting or behind a proxy that is. Any OTHER 4xx is the collector
// rejecting THIS batch (its shape, its size, its credentials, its path), and
// re-posting the identical bytes every interval cannot change that answer,
// so such a batch is discarded and counted rather than retained at the
// expense of spans that could still be delivered.
func retryableCollectorStatus(code int) bool {
	return code >= 500 ||
		code == http.StatusRequestTimeout ||
		code == http.StatusTooManyRequests
}

func (e *SpanExporter) pushLoop(ctx context.Context) {
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// CHAOS-126: this is the flush on RECONFIGURE or DISABLE, and
			// it is NOT a shutdown flush — nothing cancels this loop at
			// process exit, which is why the shutdown sequence calls
			// Flush() directly. Bounded, so a repoint onto a blackholed
			// collector cannot keep a dead loop alive for the client's full
			// 10 s timeout. After Stop() it is a no-op by design: Stop has
			// already counted and released the buffer.
			flushCtx, cancel := context.WithTimeout(context.Background(), spanFinalFlushTimeout)
			if err := e.push(flushCtx); err != nil {
				obs.Printf("OTLP traces final flush error: %s", obs.Sanitize(err.Error()))
			}
			cancel()
			return
		case <-ticker.C:
			if err := e.push(ctx); err != nil {
				obs.Printf("OTLP traces push error: %s", obs.Sanitize(err.Error()))
			}
		}
	}
}

func (e *SpanExporter) push(ctx context.Context) error {
	// One in-flight batch at a time (see pushSlot). Waiting is bounded by
	// the caller's own context, so the shutdown flush spends its budget and
	// not the client timeout of a tick that beat it to the slot.
	gate := e.pushGate()
	select {
	case gate <- struct{}{}:
		defer func() { <-gate }()
	case <-ctx.Done():
		// Not a delivery failure, so it does not move the push-health
		// counters: nothing was sent and nothing was taken from the ring.
		return fmt.Errorf("push gate: %w", ctx.Err())
	}

	e.mu.Lock()
	endpoint := e.endpoint
	headers := e.headers
	e.mu.Unlock()

	// CHAOS-126: the endpoint is read BEFORE the drain. Draining first meant
	// a disabled exporter destroyed its buffer and only then discovered it
	// had nowhere to send it — the exact path Stop() took the loop down.
	if endpoint == "" {
		return nil
	}
	// Regexp barrier: CodeQL recognises Regexp.MatchString as an SSRF
	// sanitiser, breaking the taint chain on endpoint (go/request-forgery).
	//
	// CHAOS-126: no drain on this arm either. An unpostable endpoint is a
	// configuration fault, not a delivery attempt; the ring holds (and
	// counts its own overflow) until a reconfigure makes delivery possible.
	if !validEndpoint.MatchString(endpoint) {
		err := fmt.Errorf("invalid OTLP endpoint URL: %q", endpoint)
		e.recordPushFailure(err)
		return err
	}

	spans := e.drain()
	if len(spans) == 0 {
		return nil
	}
	if err := e.deliver(ctx, endpoint, headers, spans); err != nil {
		e.recordPushFailure(err)
		return err
	}
	e.lastSuccessAt.Store(time.Now().UnixNano())
	return nil
}

// recordPushFailure stamps the diagnostic trio an operator reads. Split out
// of push's deferred closure so the "nothing was buffered" and "export is
// off" arms cannot stamp a SUCCESS for a push that never happened.
func (e *SpanExporter) recordPushFailure(err error) {
	e.pushFailures.Add(1)
	e.lastErr.Store(err.Error())
	e.lastErrAt.Store(time.Now().UnixNano())
}

// deliver POSTs one batch and decides what becomes of it when the POST does
// not succeed. CHAOS-126: the batch is RETAINED whenever the collector did
// not take it for a reason that can change (a transport error, a 408, a 429,
// any 5xx) and DISCARDED-AND-COUNTED when the collector rejected the batch
// itself or the payload could not be built. It is never simply dropped.
func (e *SpanExporter) deliver(ctx context.Context, endpoint string, headers map[string]string, spans []SpanRecord) error {
	tracesURL := strings.TrimRight(endpoint, "/") + "/v1/traces"

	body, err := json.Marshal(buildTracePayload(spans))
	if err != nil {
		e.discard(spans, "payload could not be marshalled")
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		tracesURL, bytes.NewReader(body))
	if err != nil {
		// Not retained: validEndpoint is a regexp barrier, not a parser, so
		// an endpoint can pass it and still be unusable here (a control byte
		// in the host, say). That verdict is identical every interval, so a
		// retained batch would pin the ring against spans that could still
		// go and attribute the loss to overflow instead of to the
		// configuration that caused it.
		e.discard(spans, "the endpoint cannot be used to build a request")
		return fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		e.requeue(spans, endpoint)
		return fmt.Errorf("post: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		if retryableCollectorStatus(resp.StatusCode) {
			e.requeue(spans, endpoint)
		} else {
			e.discard(spans, fmt.Sprintf("collector rejected the batch with status %d", resp.StatusCode))
		}
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
