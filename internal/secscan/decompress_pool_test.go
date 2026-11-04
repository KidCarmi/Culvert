package secscan

// decompress_pool_test.go — the correctness contracts for the pooled scan-path
// decompressors (secscan.go). These run in the NORMAL suite, which is where
// they belong: the allocation saving is gated separately under the `benchgate`
// tag, but a pooled decoder that leaks state between responses or pins the
// buffer it just expanded is a CORRECTNESS and MEMORY defect, and neither
// depends on hardware.
//
// The oracle for "unchanged behaviour" is the frozen pre-change arm in
// decompress_pool_bench_test.go, not a hand-written expectation.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"testing"

	"github.com/andybalholm/brotli"
)

func benchBrotliPayload(tb testing.TB, n int) []byte {
	tb.Helper()
	var buf bytes.Buffer
	bw := brotli.NewWriter(&buf)
	if _, err := bw.Write(benchMarkupBody(n)); err != nil {
		tb.Fatalf("brotli write: %v", err)
	}
	if err := bw.Close(); err != nil {
		tb.Fatalf("brotli close: %v", err)
	}
	return buf.Bytes()
}

// gzipWithHeader produces a gzip stream carrying an origin-supplied member
// name. The name is what release() has to clear: gzip.Reader.Header holds it
// as a string read out of the stream, so a pooled reader that kept it would
// retain origin-chosen bytes across responses.
func gzipWithHeader(tb testing.TB, body []byte, name, comment string) []byte {
	tb.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Name = name
	zw.Comment = comment
	if _, err := zw.Write(body); err != nil {
		tb.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		tb.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// decompressShapes are the stream shapes the two arms have to agree on. Each
// entry names the branch it exercises, so a future failure says which contract
// moved rather than only that something did.
type decompressShape struct {
	name string
	gzip func(tb testing.TB) []byte // nil when the shape is deflate-only
	defl func(tb testing.TB) []byte
}

func decompressShapes() []decompressShape {
	return []decompressShape{
		{
			name: "small-markup",
			gzip: func(tb testing.TB) []byte { return benchGzipPayload(tb, 512) },
			defl: func(tb testing.TB) []byte { return benchDeflatePayload(tb, 512) },
		},
		{
			name: "window-spanning", // larger than flate's 32 KiB history window
			gzip: func(tb testing.TB) []byte { return benchGzipPayload(tb, 96<<10) },
			defl: func(tb testing.TB) []byte { return benchDeflatePayload(tb, 96<<10) },
		},
		{
			name: "empty-body", // decodes to zero bytes — the "scan original" branch
			gzip: func(tb testing.TB) []byte { return gzipWithHeader(tb, nil, "", "") },
			defl: func(tb testing.TB) []byte { return benchDeflatePayload(tb, 0) },
		},
		{
			name: "origin-supplied-header",
			gzip: func(tb testing.TB) []byte {
				return gzipWithHeader(tb, benchMarkupBody(4<<10), "payload.bin", "origin comment")
			},
			defl: func(tb testing.TB) []byte { return benchDeflatePayload(tb, 4<<10) },
		},
		{
			name: "truncated", // mid-stream EOF: the readErr fallback
			gzip: func(tb testing.TB) []byte {
				full := benchGzipPayload(tb, 32<<10)
				return full[:len(full)/2]
			},
			defl: func(tb testing.TB) []byte {
				full := benchDeflatePayload(tb, 32<<10)
				return full[:len(full)/2]
			},
		},
		{
			name: "not-compressed-at-all", // malformed header / corrupt stream
			gzip: func(testing.TB) []byte { return []byte("this is not gzip at all") },
			defl: func(testing.TB) []byte { return []byte("this is not deflate at all") },
		},
	}
}

// TestExpandPooled_MatchesLegacy is the differential oracle. Each shape is run
// REPEATEDLY through the pooled arm before being compared, because a single
// call cannot distinguish a correctly reset decoder from a freshly allocated
// one — reuse is the only state a stale-state bug lives in. The shapes are also
// interleaved, so a reader that carried a window, a Huffman table or a header
// field over from the previous stream would decode the next one differently
// from the frozen arm.
func TestExpandPooled_MatchesLegacy(t *testing.T) {
	shapes := decompressShapes()
	for round := 0; round < 4; round++ {
		for _, sh := range shapes {
			gz := sh.gzip(t)
			wantOut, wantBomb := legacyExpandGzipForScan(gz, "gzip")
			gotOut, gotBomb := expandGzipForScan(gz, "gzip")
			if gotBomb != wantBomb || !bytes.Equal(gotOut, wantOut) {
				t.Errorf("round %d gzip shape %q: pooled arm returned (%d bytes, bomb=%v), "+
					"frozen pre-pool arm returned (%d bytes, bomb=%v) — the pooled decoder "+
					"is not equivalent to a fresh one",
					round, sh.name, len(gotOut), gotBomb, len(wantOut), wantBomb)
			}

			df := sh.defl(t)
			wantOut, wantBomb = legacyExpandDeflateForScan(df, "deflate")
			gotOut, gotBomb = expandDeflateForScan(df, "deflate")
			if gotBomb != wantBomb || !bytes.Equal(gotOut, wantOut) {
				t.Errorf("round %d deflate shape %q: pooled arm returned (%d bytes, bomb=%v), "+
					"frozen pre-pool arm returned (%d bytes, bomb=%v)",
					round, sh.name, len(gotOut), gotBomb, len(wantOut), wantBomb)
			}
		}
	}
}

// TestExpandPooled_MatchesLegacyUnderConcurrency runs the same differential
// with every goroutine drawing from the shared pool, which is how the scan path
// uses it: one expansion per response, on the request goroutine. A reader
// handed to two responses at once, or returned to the pool while still in use,
// shows up here (and under -race) rather than in production.
func TestExpandPooled_MatchesLegacyUnderConcurrency(t *testing.T) {
	gz := benchGzipPayload(t, 48<<10)
	df := benchDeflatePayload(t, 48<<10)
	wantGzip, _ := legacyExpandGzipForScan(gz, "gzip")
	wantDeflate, _ := legacyExpandDeflateForScan(df, "deflate")

	const workers, rounds = 8, 25
	errs := make(chan string, workers*rounds*2)
	done := make(chan struct{})
	for w := 0; w < workers; w++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := 0; i < rounds; i++ {
				if out, bomb := expandGzipForScan(gz, "gzip"); bomb || !bytes.Equal(out, wantGzip) {
					errs <- "concurrent gzip expansion diverged from the single-threaded result"
				}
				if out, bomb := expandDeflateForScan(df, "deflate"); bomb || !bytes.Equal(out, wantDeflate) {
					errs <- "concurrent deflate expansion diverged from the single-threaded result"
				}
			}
		}()
	}
	for w := 0; w < workers; w++ {
		<-done
	}
	close(errs)
	for msg := range errs {
		t.Error(msg)
		break
	}
}

// TestExpandPooled_ReleaseDropsTheScanBuffer is the retention contract, and the
// reason the source reader is a field rather than an argument. A pooled decoder
// outlives the response, so anything it still points at stays resident in a
// pool slot until its next use — up to the whole scan window (5 MiB by
// default), and worst on the refusal path where that reference would be the
// last thing holding a buffer just declared hostile. The reader is inspected
// after release(); nothing else runs in this test, so the pool cannot have
// handed it on.
func TestExpandPooled_ReleaseDropsTheScanBuffer(t *testing.T) {
	data := gzipWithHeader(t, benchMarkupBody(8<<10), "origin-chosen-name.bin", "origin comment")

	g := new(gzipScanReader)
	g.src.Reset(data)
	if err := g.z.Reset(&g.src); err != nil {
		t.Fatalf("gzip reset on a well-formed stream: %v", err)
	}
	if _, _, bomb := expandForScan(&g.z, data, "gzip"); bomb {
		t.Fatal("well-formed markup was refused as a decompression bomb")
	}
	if g.src.Size() == 0 {
		t.Fatal("precondition: the reader is not holding the scan buffer before release")
	}
	g.release()

	if n := g.src.Size(); n != 0 {
		t.Errorf("after release the pooled gzip reader still points at %d bytes of scan "+
			"buffer; want 0 — a pooled decoder retains it until its next use", n)
	}
	if g.z.Name != "" || g.z.Comment != "" {
		t.Errorf("after release the pooled gzip reader still holds origin-supplied header "+
			"fields (name=%q comment=%q); want both cleared", g.z.Name, g.z.Comment)
	}

	f := new(flateScanReader)
	f.r = flate.NewReader(&f.src)
	f.src.Reset(benchDeflatePayload(t, 8<<10))
	if err := f.r.(flate.Resetter).Reset(&f.src, nil); err != nil {
		t.Fatalf("flate reset: %v", err)
	}
	if _, _, bomb := expandForScan(f.r, data, "deflate"); bomb {
		t.Fatal("well-formed deflate stream was refused as a decompression bomb")
	}
	f.release()
	if n := f.src.Size(); n != 0 {
		t.Errorf("after release the pooled deflate reader still points at %d bytes of scan "+
			"buffer; want 0", n)
	}
}

// TestExpandPooled_StillRefusesABomb is the CONTROL. Every saving above is
// available most cheaply from an arm that stops expanding, which would switch
// off the CHAOS-106 fail-closed bound while the admin plane still reported it
// as on. A bomb must still be refused through the pooled arm, and the refusal
// must still return nil rather than a prefix an attacker chose.
func TestExpandPooled_StillRefusesABomb(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	// 8 MiB of zeros compresses at roughly 1000:1, far past the 64x allowance
	// and past the 1 MiB small-response floor.
	if _, err := zw.Write(make([]byte, 8<<20)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	bomb := buf.Bytes()

	out, isBomb := expandGzipForScan(bomb, "gzip")
	if !isBomb {
		t.Fatalf("a %d-byte gzip stream expanding to 8 MiB was not refused; the "+
			"CHAOS-106 ratio allowance is not being applied on the pooled arm", len(bomb))
	}
	if out != nil {
		t.Errorf("refused expansion returned %d bytes; want nil so no caller can scan "+
			"an attacker-chosen prefix", len(out))
	}

	// And the pooled reader is reusable afterwards: the refusal path returns it
	// without having consumed the stream to EOF, which is the asymmetry a bomb
	// deliberately creates.
	good := benchGzipPayload(t, 4<<10)
	want, _ := legacyExpandGzipForScan(good, "gzip")
	got, gotBomb := expandGzipForScan(good, "gzip")
	if gotBomb || !bytes.Equal(got, want) {
		t.Error("the response after a refused bomb decoded differently from a fresh " +
			"reader — the refusal path returns a reader to the pool mid-stream")
	}
}

// TestDecompressForScan_ArmsAreReachable pins the dispatch itself: the switch
// was flattened into per-encoding arms, so each label must still reach the arm
// that handles it. A mis-wired label would fall through to "scan raw bytes",
// which is silent — the scanners would simply see compressed bytes again, the
// exact signature gap the 1.1 fix closed.
func TestDecompressForScan_ArmsAreReachable(t *testing.T) {
	body := benchMarkupBody(4 << 10)
	for _, tc := range []struct {
		ce   string
		data []byte
	}{
		{"gzip", benchGzipPayload(t, 4<<10)},
		{"x-gzip", benchGzipPayload(t, 4<<10)},
		{"GZIP", benchGzipPayload(t, 4<<10)}, // case folded by the caller
		{"deflate", benchDeflatePayload(t, 4<<10)},
		{"br", benchBrotliPayload(t, 4<<10)},
	} {
		out, bomb := DecompressForScan(tc.data, tc.ce)
		if bomb {
			t.Errorf("Content-Encoding %q: well-formed body refused as a bomb", tc.ce)
			continue
		}
		if !bytes.Equal(out, body) {
			t.Errorf("Content-Encoding %q: expanded %d bytes, want the %d-byte original — "+
				"the arm for this encoding is not being reached", tc.ce, len(out), len(body))
		}
	}
}
