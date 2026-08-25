package fileblock

import (
	"mime"
	"runtime"
	"sync"
	"testing"
)

// Benchmarks for the per-transaction file-block gate. The *Legacy* variants
// freeze the pre-fix shapes in-tree so the before/after comparison stays
// reproducible on whatever hardware CI happens to run — quote the RATIO, not
// the constants.

var benchSink string

func benchFB() *FileBlocker {
	fb := NewBlocker()
	for _, e := range DefaultBlockedExts {
		fb.Add(e)
	}
	return fb
}

// ── Content-Type: the parse this change stopped paying ───────────────────────

func BenchmarkCheckContentType_Common(b *testing.B) {
	fb := benchFB()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = fb.CheckContentType("text/html; charset=utf-8")
	}
}

func BenchmarkCheckContentType_CommonLegacy(b *testing.B) {
	fb := benchFB()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = checkContentTypeLegacy(fb, "text/html; charset=utf-8")
	}
}

// BenchmarkCheckContentType_Dangerous is the arm that still parses — the ten
// MIME types the pre-filter cannot decide on its own. It must not have got
// meaningfully slower.
func BenchmarkCheckContentType_Dangerous(b *testing.B) {
	fb := benchFB()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = fb.CheckContentType("application/x-msdownload; charset=utf-8")
	}
}

func BenchmarkCheckContentType_DangerousLegacy(b *testing.B) {
	fb := benchFB()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = checkContentTypeLegacy(fb, "application/x-msdownload; charset=utf-8")
	}
}

// ── CheckPath: the lock this change stopped taking ───────────────────────────

func BenchmarkCheckPath(b *testing.B) {
	fb := benchFB()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = fb.CheckPath("/static/app.js")
	}
}

func BenchmarkCheckPathLegacy(b *testing.B) {
	fb := benchFB()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = checkPathLegacy(fb, "/static/app.js")
	}
}

func BenchmarkCheckPathParallel(b *testing.B) {
	fb := benchFB()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			benchSink = fb.CheckPath("/static/app.js")
		}
	})
}

func BenchmarkCheckPathParallelLegacy(b *testing.B) {
	fb := benchFB()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			benchSink = checkPathLegacy(fb, "/static/app.js")
		}
	})
}

// BenchmarkInspectedTransaction is the realistic unit: what ONE SSL-inspected
// request/response pair pays this store — CheckPath on the inner request, then
// CheckContentDisposition and CheckContentType on the response.
func BenchmarkInspectedTransaction(b *testing.B) {
	fb := benchFB()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			benchSink = fb.CheckPath("/static/app.js")
			benchSink = fb.CheckContentDisposition("")
			benchSink = fb.CheckContentType("text/html; charset=utf-8")
		}
	})
}

func BenchmarkInspectedTransactionLegacy(b *testing.B) {
	fb := benchFB()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			benchSink = checkPathLegacy(fb, "/static/app.js")
			benchSink = fb.CheckContentDisposition("")
			benchSink = checkContentTypeLegacy(fb, "text/html; charset=utf-8")
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Regression gates.
// ─────────────────────────────────────────────────────────────────────────────

// TestBenchGate_CheckContentTypeAllocsFree pins the allocation contract for the
// shape ~all traffic carries. mime.ParseMediaType allocates its parameter map
// unconditionally, so any reintroduction of an unconditional parse fails here
// deterministically — no timing, no hardware assumptions, valid under -race.
func TestBenchGate_CheckContentTypeAllocsFree(t *testing.T) {
	fb := benchFB()
	for _, ct := range []string{
		"text/html; charset=utf-8",
		"application/json",
		"image/png",
		"text/plain;charset=UTF-8",
		"",
	} {
		got := testing.AllocsPerRun(200, func() { benchSink = fb.CheckContentType(ct) })
		if got != 0 {
			t.Errorf("CheckContentType(%q): %.0f allocs/op, want 0", ct, got)
		}
	}
	// Control: the pre-fix body DOES allocate on the same input, so a passing
	// gate above cannot mean the benchmark simply stopped doing the work.
	if got := testing.AllocsPerRun(200, func() {
		benchSink = checkContentTypeLegacy(fb, "text/html; charset=utf-8")
	}); got == 0 {
		t.Error("control: pre-fix body reported 0 allocs/op — the oracle is not exercising mime.ParseMediaType")
	}
}

// TestBenchGate_CheckPathAllocsFree pins the request-side probe at zero.
func TestBenchGate_CheckPathAllocsFree(t *testing.T) {
	fb := benchFB()
	for _, p := range []string{"/static/app.js", "/download/setup.exe", "/no-extension", ""} {
		if got := testing.AllocsPerRun(200, func() { benchSink = fb.CheckPath(p) }); got != 0 {
			t.Errorf("CheckPath(%q): %.0f allocs/op, want 0", p, got)
		}
	}
}

// TestBenchGate_ChecksTakeNoStoreLock is STRUCTURAL, not timing-based: it holds
// the store's write lock and requires every per-transaction check to answer
// anyway. A collapse back to mu.RLock deadlocks the probe and fails
// deterministically on any hardware, under any load, with or without -race —
// the scaling-ratio form was rejected for the reason the sibling gates in
// internal/connlimit and security.go record: a gate that can flake gets muted.
func TestBenchGate_ChecksTakeNoStoreLock(t *testing.T) {
	fb := benchFB()

	fb.mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = fb.CheckPath("/download/setup.exe")
		_ = fb.CheckExt(".exe")
		_ = fb.CheckContentType("application/x-msdownload")
		_ = fb.CheckContentDisposition(`attachment; filename="setup.exe"`)
	}()

	// Wait bounded — a lock-free reader finishes in nanoseconds; a locked one
	// never finishes while the write lock is held.
	timeout := make(chan struct{})
	var once sync.Once
	go func() {
		for i := 0; i < 1_000_000; i++ {
			select {
			case <-done:
				return
			default:
				runtime.Gosched()
			}
		}
		once.Do(func() { close(timeout) })
	}()

	select {
	case <-done:
	case <-timeout:
		fb.mu.Unlock()
		t.Fatal("per-transaction checks did not complete while the store write lock was held — a read path took the lock")
	}
	fb.mu.Unlock()
}

// TestBenchGate_DangerousMIMEStillParses is the control for the pre-filter: the
// ten dangerous media types must still reach mime.ParseMediaType, otherwise the
// "malformed parameters do not block" contract is being decided by the cheap
// split instead of the stdlib.
func TestBenchGate_DangerousMIMEStillParses(t *testing.T) {
	fb := benchFB()
	const malformed = "application/x-msdownload; bogus"
	if _, _, err := mime.ParseMediaType(malformed); err == nil {
		t.Skip("stdlib no longer rejects this parameter shape; contract needs re-derivation")
	}
	if got := fb.CheckContentType(malformed); got != "" {
		t.Fatalf("CheckContentType(%q) = %q, want \"\" (malformed parameters must not block)", malformed, got)
	}
	if got := fb.CheckContentType("application/x-msdownload"); got != ".exe" {
		t.Fatalf("CheckContentType of a well-formed dangerous type = %q, want %q", got, ".exe")
	}
}
