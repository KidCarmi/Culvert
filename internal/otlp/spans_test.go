package otlp

// Engine tests, moved in-package from package main's otlp_traces_test.go
// with the extraction.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// ── parseTraceparent ────────────────────────────────────────────────────────

func TestParseTraceparent(t *testing.T) {
	traceID, spanID := ParseTraceparent("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	if traceID != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("traceID = %q, want 0af7651916cd43dd8448eb211c80319c", traceID)
	}
	if spanID != "b7ad6b7169203331" {
		t.Errorf("spanID = %q, want b7ad6b7169203331", spanID)
	}
}

func TestParseTraceparent_Empty(t *testing.T) {
	traceID, spanID := ParseTraceparent("")
	if traceID != "" || spanID != "" {
		t.Errorf("expected empty for empty input, got %q / %q", traceID, spanID)
	}
}

func TestParseTraceparent_Short(t *testing.T) {
	// "00-abc" has only 2 parts → both empty (need at least 3 for trace+span).
	traceID, spanID := ParseTraceparent("00-abc")
	if traceID != "" || spanID != "" {
		t.Errorf("expected empty for short input, got %q / %q", traceID, spanID)
	}
}

// ── spanStatusCode ──────────────────────────────────────────────────────────

func TestSpanStatusCode(t *testing.T) {
	if spanStatusCode("OK") != 1 {
		t.Error("OK should be status code 1")
	}
	if spanStatusCode("POLICY_ALLOW") != 1 {
		t.Error("POLICY_ALLOW should be status code 1")
	}
	if spanStatusCode("BLOCKED") != 2 {
		t.Error("BLOCKED should be status code 2")
	}
	if spanStatusCode("FILE_BLOCKED") != 2 {
		t.Error("FILE_BLOCKED should be status code 2")
	}
}

// ── Ring buffer: RecordSpan + drain ─────────────────────────────────────────

func TestSpanExporter_RecordAndDrain(t *testing.T) {
	e := &SpanExporter{buf: make([]SpanRecord, spanBufferCap)}

	for i := 0; i < 10; i++ {
		e.RecordSpan(SpanRecord{
			TraceID:   "aaaa",
			SpanID:    "bbbb",
			Name:      "test",
			Host:      "example.com",
			StartNano: int64(i),
		})
	}
	spans := e.drain()
	if len(spans) != 10 {
		t.Fatalf("expected 10 spans, got %d", len(spans))
	}
	// Oldest first.
	if spans[0].StartNano != 0 {
		t.Errorf("first span StartNano = %d, want 0", spans[0].StartNano)
	}
	if spans[9].StartNano != 9 {
		t.Errorf("last span StartNano = %d, want 9", spans[9].StartNano)
	}
	// Drain again should be empty.
	if d := e.drain(); len(d) != 0 {
		t.Errorf("second drain should be empty, got %d", len(d))
	}
}

func TestSpanExporter_RingBufferOverflow(t *testing.T) {
	e := &SpanExporter{buf: make([]SpanRecord, spanBufferCap)}

	// Write more than cap to trigger ring-buffer wrap.
	total := spanBufferCap + 500
	for i := 0; i < total; i++ {
		e.RecordSpan(SpanRecord{StartNano: int64(i)})
	}
	spans := e.drain()
	if len(spans) != spanBufferCap {
		t.Fatalf("expected %d spans (cap), got %d", spanBufferCap, len(spans))
	}
	// Oldest surviving span should be total - cap.
	if spans[0].StartNano != int64(total-spanBufferCap) {
		t.Errorf("oldest span StartNano = %d, want %d", spans[0].StartNano, total-spanBufferCap)
	}
	// Newest should be total - 1.
	if spans[len(spans)-1].StartNano != int64(total-1) {
		t.Errorf("newest span StartNano = %d, want %d", spans[len(spans)-1].StartNano, total-1)
	}
}

func TestSpanExporter_ConcurrentRecordDrain(t *testing.T) {
	e := &SpanExporter{buf: make([]SpanRecord, spanBufferCap)}

	var wg sync.WaitGroup
	// Concurrent writers.
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				e.RecordSpan(SpanRecord{Host: "test.com"})
			}
		}()
	}
	// Concurrent drainer.
	wg.Add(1)
	total := 0
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			total += len(e.drain())
			time.Sleep(time.Millisecond)
		}
	}()
	wg.Wait()
	total += len(e.drain()) // pick up any remaining
	// 8 * 500 = 4000 total written; some may have been dropped if buffer
	// overflowed, but total drained should be <= 4000.
	if total > 4000 {
		t.Errorf("drained %d spans, but only 4000 were written", total)
	}
}

// ── OTLP JSON schema validation ─────────────────────────────────────────────

// testSpanPayload is a helper that builds, marshals, and round-trips a
// single-span payload, returning the parsed span map. Keeps sub-tests short.
func testSpanPayload(t *testing.T) map[string]any {
	t.Helper()
	spans := []SpanRecord{{
		TraceID: "0af7651916cd43dd8448eb211c80319c", SpanID: "b7ad6b7169203331",
		Name: "proxy_request", Method: "CONNECT", Host: "github.com",
		Status: "OK", Rule: "allow-github", ClientIP: "10.0.0.1", SSLAction: "inspect",
		StartNano: 1700000000000000000, EndNano: 1700000000050000000,
	}}
	payload := buildTracePayload(spans)
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rs := m["resourceSpans"].([]any)
	rsMap := rs[0].(map[string]any)
	ss := rsMap["scopeSpans"].([]any)
	ssMap := ss[0].(map[string]any)
	spansArr := ssMap["spans"].([]any)
	if len(spansArr) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spansArr))
	}
	return spansArr[0].(map[string]any)
}

func TestBuildTracePayload_SpanFields(t *testing.T) {
	span := testSpanPayload(t)
	if span["traceId"] != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("traceId = %v", span["traceId"])
	}
	if span["spanId"] != "b7ad6b7169203331" {
		t.Errorf("spanId = %v", span["spanId"])
	}
	if span["name"] != "proxy_request" {
		t.Errorf("name = %v", span["name"])
	}
}

func TestBuildTracePayload_KindAndStatus(t *testing.T) {
	span := testSpanPayload(t)
	if kind, ok := span["kind"].(float64); !ok || kind != 2 {
		t.Errorf("kind = %v, want 2 (SERVER)", span["kind"])
	}
	st := span["status"].(map[string]any)
	if code, ok := st["code"].(float64); !ok || code != 1 {
		t.Errorf("status.code = %v, want 1 (OK)", st["code"])
	}
}

func TestBuildTracePayload_IDLengths(t *testing.T) {
	span := testSpanPayload(t)
	tid := span["traceId"].(string)
	sid := span["spanId"].(string)
	if len(tid) != 32 {
		t.Errorf("traceId length = %d, want 32", len(tid))
	}
	if len(sid) != 16 {
		t.Errorf("spanId length = %d, want 16", len(sid))
	}
}

func TestBuildTracePayload_ServiceName(t *testing.T) {
	spans := []SpanRecord{{TraceID: "a", SpanID: "b", Name: "test"}}
	payload := buildTracePayload(spans)
	b, _ := json.Marshal(payload)
	var m map[string]any
	json.Unmarshal(b, &m) //nolint:errcheck
	rs := m["resourceSpans"].([]any)
	rsMap := rs[0].(map[string]any)
	res := rsMap["resource"].(map[string]any)
	attrs := res["attributes"].([]any)
	found := false
	for _, a := range attrs {
		attr := a.(map[string]any)
		if attr["key"] == "service.name" {
			val := attr["value"].(map[string]any)
			if val["stringValue"] == "culvert" {
				found = true
			}
		}
	}
	if !found {
		t.Error("missing service.name=culvert in resource attributes")
	}
}

func TestBuildTracePayload_EmptySpans(t *testing.T) {
	payload := buildTracePayload(nil)
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Should still be valid JSON with zero spans in the array.
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

// ── Push integration: verify the exporter POSTs valid JSON to /v1/traces ────

func TestSpanExporter_PushIntegration(t *testing.T) {
	var received []byte
	var mu sync.Mutex
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/traces" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected Content-Type: %s", r.Header.Get("Content-Type"))
		}
		mu.Lock()
		received, _ = readBody(r)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	e := &SpanExporter{
		endpoint: ts.URL,
		interval: 100 * time.Millisecond,
		client:   ts.Client(),
		buf:      make([]SpanRecord, spanBufferCap),
	}

	e.RecordSpan(SpanRecord{
		TraceID:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
		SpanID:    "bbbbbbbbbbbbbb01",
		Name:      "proxy_request",
		Method:    "GET",
		Host:      "example.com",
		Status:    "OK",
		StartNano: time.Now().UnixNano(),
		EndNano:   time.Now().UnixNano(),
	})

	if err := e.push(t.Context()); err != nil {
		t.Fatalf("push: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("server received no data")
	}
	// Verify it's valid OTLP JSON.
	var payload traceExportRequest
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("unmarshal received payload: %v", err)
	}
	if len(payload.ResourceSpans) != 1 {
		t.Fatalf("expected 1 resourceSpans, got %d", len(payload.ResourceSpans))
	}
	ss := payload.ResourceSpans[0].ScopeSpans
	if len(ss) != 1 || len(ss[0].Spans) != 1 {
		t.Fatalf("expected 1 span in scopeSpans, got %v", ss)
	}
	if ss[0].Spans[0].TraceID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1" {
		t.Errorf("traceId mismatch: %s", ss[0].Spans[0].TraceID)
	}
}

// readBody is a small helper to read the request body for the push test.
func readBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	var buf [64 * 1024]byte
	n := 0
	for {
		nn, err := r.Body.Read(buf[n:])
		n += nn
		if err != nil {
			break
		}
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
}
