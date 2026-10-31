package secscan

// CHAOS-106 — the scan-path expansion bound.
//
// Before this round the only bound on a scan-path expansion was the flat
// MaxDecompressBytes (64 MiB), unrelated to the scan window the operator
// configures or to the bytes the origin actually transferred. Measured on the
// pre-fix tree: 160 KiB of gzip bought a 64 MiB expansion (408:1), and
// io.ReadAll's doubling growth — which cannot see the LimitReader's ceiling —
// pushed the peak to ~1.8x the bytes actually held (3.64 GiB peak for 2.0 GiB
// live across 32 concurrent expansions, i.e. one inspected H2 connection at
// h2MaxConcurrentStreams, from 5 MiB of wire traffic).
//
// These gates pin the three halves of the fix: the bound is proportional to
// what was transferred, a disproportionate expansion is REFUSED rather than
// truncated-and-forwarded, and the expansion never allocates past its own
// ceiling. The negative controls matter at least as much: every legitimate
// compression ratio, every pre-existing fallback and the pre-existing
// MaxDecompressBytes truncation must all behave exactly as they did.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// gzipOf returns a gzip stream of n bytes produced by fill.
func gzipOf(t *testing.T, n int, fill func(i int) byte) []byte {
	t.Helper()
	raw := make([]byte, n)
	for i := range raw {
		raw[i] = fill(i)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// zeros is the classic decompression-bomb payload: gzip reaches ~1030:1 on it.
func zeros(int) byte { return 0 }

// ─── The bound itself ────────────────────────────────────────────────────────

func TestCHAOS106_ExpandBound_ProportionalWithAFloorAndACeiling(t *testing.T) {
	tests := []struct {
		name       string
		compressed int
		wantLimit  int64
		wantRatio  bool
	}{
		// Small responses get the flat floor: a few hundred bytes of framing
		// legitimately expand far past the ratio, so the ratio alone would
		// refuse honest traffic.
		{"empty", 0, decompressFloorBytes, true},
		{"tiny", 512, decompressFloorBytes, true},
		{"at the floor crossover", decompressFloorBytes / decompressRatioLimit, decompressFloorBytes, true},
		// Past the crossover the bound tracks what was transferred.
		{"proportional", 64 << 10, 64 << 10 * decompressRatioLimit, true},
		// Once the allowance reaches the flat ceiling, the ceiling binds and
		// the refusal is NOT armed — that content transferred its bytes
		// honestly, and its prefix keeps being scanned exactly as before.
		{"ceiling binds", MaxDecompressBytes / decompressRatioLimit, MaxDecompressBytes, false},
		{"well past the ceiling", 8 << 20, MaxDecompressBytes, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			limit, ratioBound := expandBound(tc.compressed)
			if limit != tc.wantLimit || ratioBound != tc.wantRatio {
				t.Errorf("expandBound(%d) = (%d, %v), want (%d, %v)",
					tc.compressed, limit, ratioBound, tc.wantLimit, tc.wantRatio)
			}
			if limit > MaxDecompressBytes {
				t.Errorf("expandBound(%d) returned %d, past the flat ceiling %d",
					tc.compressed, limit, int64(MaxDecompressBytes))
			}
		})
	}
}

// ─── The reproduction ────────────────────────────────────────────────────────

// This is the pre-fix amplification, reproduced and then refused. On the
// pre-fix tree the same input returned 64 MiB of expansion and no refusal.
func TestCHAOS106_DisproportionateExpansionIsRefused(t *testing.T) {
	// 20 MiB of zeros compresses to ~20 KiB, i.e. ~1000:1 — past the ratio
	// allowance (64x) and past the floor, so this is the bomb shape and not
	// the small-response shape.
	bomb := gzipOf(t, 20<<20, zeros)
	if len(bomb) <= decompressFloorBytes/decompressRatioLimit {
		t.Fatalf("fixture too small (%d bytes) — the floor, not the ratio, would decide", len(bomb))
	}
	allowance, ratioBound := expandBound(len(bomb))
	if !ratioBound {
		t.Fatalf("fixture too large (%d bytes) — the flat ceiling, not the ratio, would decide", len(bomb))
	}

	before := DecompressBombs()
	out, refused := DecompressForScan(bomb, "gzip")

	if !refused {
		t.Fatalf("a %d:1 expansion of %d wire bytes was admitted — pre-CHAOS-106 this allocated %d bytes",
			(20<<20)/len(bomb), len(bomb), MaxDecompressBytes)
	}
	if out != nil {
		t.Errorf("a refused expansion must hand back no bytes, got %d", len(out))
	}
	if got := DecompressBombs() - before; got != 1 {
		t.Errorf("DecompressBombs delta = %d, want exactly 1 per refused response", got)
	}
	// The ceiling is what the refusal cost this process, and it is now a
	// function of what the origin sent rather than a flat 64 MiB.
	if allowance >= MaxDecompressBytes {
		t.Errorf("allowance %d did not improve on the flat ceiling %d", allowance, int64(MaxDecompressBytes))
	}
}

// The refusal must reach the counter snapshot package main exports, not only
// the package-local atomic: a refusal nobody can see is a silent failure.
func TestCHAOS106_RefusalReachesTheCounterSnapshot(t *testing.T) {
	bomb := gzipOf(t, 20<<20, zeros)
	before := Counters().DecompressBombs
	if _, refused := DecompressForScan(bomb, "gzip"); !refused {
		t.Fatal("fixture was not refused")
	}
	if got := Counters().DecompressBombs - before; got != 1 {
		t.Errorf("Counters().DecompressBombs delta = %d, want 1", got)
	}
}

// ─── Negative controls: nothing legitimate may be refused ────────────────────

func TestCHAOS106_LegitimateCompressionRatiosAreAdmittedWhole(t *testing.T) {
	// Real web content: 3-10:1 for HTML/JS/CSS, 10-20:1 for JSON, up to ~50:1
	// for highly repetitive XML or log text. Every one of these must come back
	// byte-identical, because this bound must not be a detection change.
	//
	// The fixtures are deliberately NOT synthetic periodic patterns. A
	// repeating alphabet gzips at ~400:1, which says nothing about real
	// traffic and everything about DEFLATE's window; building the controls
	// that way would have "proved" the bound safe while hiding whether it
	// refuses honest content. Each fixture below carries varying bytes, and
	// the test asserts the ratio it actually achieved is inside the range it
	// claims to represent — a control that drifts out of that range is a
	// broken control, not a passing one.
	tests := []struct {
		name               string
		build              func() []byte
		minRatio, maxRatio float64
	}{
		{
			name: "incompressible",
			build: func() []byte {
				raw := make([]byte, 4<<20)
				fillPseudoRandom(raw, 1)
				return raw
			},
			minRatio: 0.9, maxRatio: 1.2,
		},
		{
			name: "html shaped",
			build: func() []byte {
				var b bytes.Buffer
				rng := newByteStream(2, 1<<16)
				words := strings.Fields("the quick brown fox jumps over a lazy dog while several " +
					"other animals watch from behind the fence and consider whether " +
					"this sentence contains enough entropy to resemble ordinary prose")
				for b.Len() < 4<<20 {
					fmt.Fprintf(&b, "<p id=%q data-row=\"%d\">", words[rng.below(len(words))], rng.below(1<<20))
					for i := 0; i < 12; i++ {
						b.WriteString(words[rng.below(len(words))])
						b.WriteByte(' ')
					}
					b.WriteString("</p>\n")
				}
				return b.Bytes()
			},
			minRatio: 2, maxRatio: 12,
		},
		{
			name: "repetitive json",
			build: func() []byte {
				var b bytes.Buffer
				rng := newByteStream(3, 1<<16)
				b.WriteString("[")
				for b.Len() < 4<<20 {
					fmt.Fprintf(&b, `{"id":%d,"ts":%d,"level":"info","msg":"request completed"},`,
						rng.below(1<<30), 1760000000+rng.below(1<<22))
				}
				b.WriteString("]")
				return b.Bytes()
			},
			minRatio: 4, maxRatio: 40,
		},
		{
			name:  "small and highly repetitive",
			build: func() []byte { return make([]byte, 2<<10) },
			// 2 KiB of zeros is ~1000:1, i.e. bomb-shaped by ratio alone. It is
			// admitted only because of the floor, which is exactly what the
			// floor is for — this is the control that pins it.
			minRatio: 50, maxRatio: 100000,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.build()
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			if _, err := zw.Write(raw); err != nil {
				t.Fatal(err)
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			ratio := float64(len(raw)) / float64(buf.Len())
			if ratio < tc.minRatio || ratio > tc.maxRatio {
				t.Fatalf("fixture compressed at %.1f:1, outside the %.1f-%.1f:1 range it claims to represent — the control proves nothing",
					ratio, tc.minRatio, tc.maxRatio)
			}
			out, refused := DecompressForScan(buf.Bytes(), "gzip")
			if refused {
				t.Fatalf("a %.1f:1 expansion was refused — legitimate content must never hit the bound", ratio)
			}
			if !bytes.Equal(out, raw) {
				t.Errorf("expansion at %.1f:1 was not byte-identical: got %d bytes, want %d", ratio, len(out), len(raw))
			}
		})
	}
}

// Every pre-existing fallback keeps its exact posture: these are NOT refusals,
// and the caller must still receive the original bytes to scan.
func TestCHAOS106_PreExistingFallbacksAreUnchanged(t *testing.T) {
	raw := []byte("this is not compressed at all")
	tests := []struct{ name, ce string }{
		{"identity", "identity"},
		{"absent", ""},
		{"unknown encoding", "exotic-v9"},
		{"malformed gzip", "gzip"},
		{"malformed deflate", "deflate"},
		{"malformed zstd", "zstd"},
		{"malformed brotli", "br"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, refused := DecompressForScan(raw, tc.ce)
			if refused {
				t.Fatalf("%s must fall back, not refuse — refusing here would block traffic on a header typo", tc.ce)
			}
			if !bytes.Equal(out, raw) {
				t.Errorf("fallback must hand back the original bytes, got %q", out)
			}
		})
	}
}

// The flat MaxDecompressBytes ceiling keeps its pre-CHAOS-106 behavior:
// truncate the prefix and scan it, never refuse. A response large enough for
// the allowance to reach the ceiling has transferred its bytes honestly, so
// refusing it would be a traffic change this round did not decide to make.
func TestCHAOS106_FlatCeilingStillTruncatesAndIsNeverRefused(t *testing.T) {
	// Compressed size past MaxDecompressBytes/ratio (1 MiB), so expandBound
	// returns the flat ceiling with the refusal disarmed. 1 MiB of
	// incompressible bytes followed by a long run of zeros gives a stream
	// whose expansion runs well past 64 MiB.
	raw := make([]byte, 2<<20)
	fillPseudoRandom(raw, 4)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(make([]byte, 80<<20)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ratioBound := expandBound(buf.Len()); ratioBound {
		t.Fatalf("fixture compressed to %d bytes — the ratio, not the ceiling, would decide", buf.Len())
	}

	out, refused := DecompressForScan(buf.Bytes(), "gzip")
	if refused {
		t.Fatal("hitting the flat ceiling must truncate and scan, not refuse")
	}
	if int64(len(out)) != int64(MaxDecompressBytes) {
		t.Errorf("truncated expansion = %d bytes, want exactly the ceiling %d", len(out), int64(MaxDecompressBytes))
	}
}

// The flat ceiling must not read past itself. Before CHAOS-106 the expansion
// was io.ReadAll(io.LimitReader(r, MaxDecompressBytes)), which never asked the
// decompressor for a byte beyond the ceiling, so a stream that yields exactly
// the ceiling and is corrupt only AFTER it returned the decoded prefix. A
// one-byte probe past the ceiling reaches that corruption, and the expansion
// falls back to the compressed bytes — the archive/DPI/YARA stages lose
// visibility of a response that sits inside the default scan window. The
// probe is only meaningful for the ratio ceiling, which refuses; the flat
// ceiling truncates and must keep its capped read.
func TestCHAOS106_FlatCeilingDoesNotProbePastItself(t *testing.T) {
	// 2 MiB of incompressible bytes keeps the compressed size past 1 MiB, so
	// expandBound returns the flat ceiling; zeros pad the expansion to
	// EXACTLY MaxDecompressBytes.
	raw := make([]byte, 2<<20)
	fillPseudoRandom(raw, 7)
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(make([]byte, MaxDecompressBytes-len(raw))); err != nil {
		t.Fatal(err)
	}
	// Sync flush: every decoded byte is emitted and the stream is byte-aligned
	// but not final, so whatever follows is read as the next block header.
	if err := fw.Flush(); err != nil {
		t.Fatal(err)
	}
	// 0x07 = BFINAL 1, BTYPE 11 (reserved): a corrupt block header.
	buf.WriteByte(0x07)
	if _, ratioBound := expandBound(buf.Len()); ratioBound {
		t.Fatalf("fixture compressed to %d bytes — the ratio, not the ceiling, would decide", buf.Len())
	}

	out, refused := DecompressForScan(buf.Bytes(), "deflate")
	if refused {
		t.Fatal("an expansion at the flat ceiling must never be refused")
	}
	if int64(len(out)) != int64(MaxDecompressBytes) {
		t.Fatalf("expansion = %d bytes, want the %d-byte decoded prefix (got %d compressed bytes back means the read went past the ceiling into the corrupt block)",
			len(out), int64(MaxDecompressBytes), buf.Len())
	}
	if !bytes.Equal(out[:len(raw)], raw) {
		t.Error("decoded prefix does not match the fixture")
	}
}

// Negative control for the test above: the ratio ceiling still probes one byte
// past itself, so an expansion of exactly the allowance is admitted while one
// byte more is refused — the probe is what distinguishes the two.
func TestCHAOS106_RatioCeilingStillProbesPastItself(t *testing.T) {
	const compressed = 64 << 10
	limit, ratioBound := expandBound(compressed)
	if !ratioBound {
		t.Fatalf("expandBound(%d) is not ratio-bound", compressed)
	}
	data := make([]byte, compressed)

	exact, readErr, bomb := expandForScan(bytes.NewReader(make([]byte, limit)), data, "gzip")
	if bomb || readErr != nil || int64(len(exact)) != limit {
		t.Errorf("exactly the allowance: len=%d err=%v bomb=%v, want len=%d admitted", len(exact), readErr, bomb, limit)
	}

	before := DecompressBombs()
	over, _, bomb := expandForScan(bytes.NewReader(make([]byte, limit+1)), data, "gzip")
	if !bomb || over != nil {
		t.Errorf("one byte past the allowance: bomb=%v out=%d bytes, want refused with nil out", bomb, len(over))
	}
	if DecompressBombs()-before != 1 {
		t.Error("the refusal was not counted")
	}
}

// ─── The allocation half ─────────────────────────────────────────────────────

// readCapped must never allocate past the ceiling it was given. This is the
// differential oracle for the measured ~1.8x peak: io.ReadAll cannot see the
// LimitReader's ceiling, so it keeps doubling THROUGH it and ends up holding a
// buffer larger than the limit plus the array it just outgrew.
func TestCHAOS106_ReadCappedNeverAllocatesPastItsCeiling(t *testing.T) {
	// Deliberately NOT a power of two. io.ReadAll's growth happens to land
	// exactly on a power-of-two ceiling, so a 1 MiB limit makes the comparison
	// below pass for the wrong reason; a real expansion ceiling is
	// ratio x transferred-bytes and lands anywhere.
	const limit = (1 << 20) + 12345
	src := bytes.Repeat([]byte("z"), 4*limit)

	got, err := readCapped(bytes.NewReader(src), limit)
	if err != nil {
		t.Fatalf("readCapped: %v", err)
	}
	if len(got) != limit {
		t.Fatalf("readCapped read %d bytes, want %d", len(got), limit)
	}
	if cap(got) > limit {
		t.Errorf("readCapped allocated cap %d past its %d ceiling", cap(got), limit)
	}

	// The behavior being replaced, measured on the same input: io.ReadAll
	// cannot see the LimitReader's ceiling, so it grows THROUGH it.
	loose, err := io.ReadAll(io.LimitReader(bytes.NewReader(src), limit))
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	t.Logf("ceiling %d: readCapped cap=%d (%.3fx), io.ReadAll cap=%d (%.3fx)",
		limit, cap(got), float64(cap(got))/limit, cap(loose), float64(cap(loose))/limit)
	if cap(loose) <= cap(got) {
		t.Errorf("io.ReadAll cap %d did not exceed readCapped's %d — the overshoot this gate documents is gone, so the clamp may no longer be doing anything",
			cap(loose), cap(got))
	}
}

// A reader that makes no progress must not spin forever: io.Reader discourages
// (0, nil) but does not forbid it, and this loop is on the response path.
func TestCHAOS106_ReadCappedBoundsANoProgressReader(t *testing.T) {
	done := make(chan error, 1)
	go func() { _, err := readCapped(noProgressReader{}, 1<<20); done <- err }()
	select {
	case err := <-done:
		if err != io.ErrNoProgress {
			t.Errorf("readCapped on a no-progress reader: err = %v, want io.ErrNoProgress", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("readCapped did not bound a no-progress reader")
	}
}

type noProgressReader struct{}

func (noProgressReader) Read([]byte) (int, error) { return 0, nil }

// ─── The rate gate ───────────────────────────────────────────────────────────

// The refusal line is rate-limited because an attacker sets its rate: this
// fires once per refused RESPONSE, and internal/logsink blocks its producer on
// a full queue, so an ungated line adds latency to every proxied response
// exactly while the node is under attack (the CHAOS-54 shape).
//
// It must have its OWN gate. A gate shared with the ClamAV-error or
// late-discard lines lets whichever condition fires first suppress the other
// for a whole window, and the three point at different operator actions —
// storage_health.go's rule, applied in yara.go for the same reason.
func TestCHAOS106_RefusalLineHasItsOwnRateGate(t *testing.T) {
	lastDecompressBombLog.Store(0)
	lastClamErrorLog.Store(0)

	if !degradedLogAllowed(&lastDecompressBombLog) {
		t.Fatal("the first refusal line must always be emitted")
	}
	if degradedLogAllowed(&lastDecompressBombLog) {
		t.Error("a second refusal line inside the window must be suppressed")
	}
	// The neighbouring condition is unaffected: its slot was never claimed.
	if !degradedLogAllowed(&lastClamErrorLog) {
		t.Error("the refusal gate swallowed the ClamAV-error line — the two must not share a gate")
	}
}

// The refusal counter must stay exact even while the log line is suppressed:
// the magnitude belongs to the counter, the cause to the rate-limited line.
func TestCHAOS106_CounterStaysExactWhileTheLineIsSuppressed(t *testing.T) {
	bomb := gzipOf(t, 20<<20, zeros)
	// Claim the log slot so every refusal below is suppressed.
	lastDecompressBombLog.Store(time.Now().UnixNano())

	before := DecompressBombs()
	const refusals = 5
	for i := 0; i < refusals; i++ {
		if _, refused := DecompressForScan(bomb, "gzip"); !refused {
			t.Fatal("fixture was not refused")
		}
	}
	if got := DecompressBombs() - before; got != refusals {
		t.Errorf("DecompressBombs delta = %d, want %d — the counter must not be rate-limited with the line", got, refusals)
	}
}

// ─── Fixture randomness ──────────────────────────────────────────────────────
//
// A local xorshift64* rather than math/rand: these fixtures need REPRODUCIBLE
// bytes (a control that asserts the ratio it achieved cannot drift run to
// run), and gosec's G404 correctly objects to math/rand wherever it appears —
// so using it here would cost four suppressions to say "this is a test
// fixture, not a key".
//
// Everything the fixtures draw is read as BYTES rather than as a converted
// word, so there is no narrowing conversion for gosec's G115 to object to
// either.

// fillPseudoRandom writes incompressible-looking bytes into b.
func fillPseudoRandom(b []byte, seed uint64) {
	state := seed*2685821657736338717 + 1
	for i := range b {
		state ^= state >> 12
		state ^= state << 25
		state ^= state >> 27
		b[i] = byte((state * 2685821657736338717) & 0xff)
	}
}

// byteStream hands out the bytes fillPseudoRandom produced, cycling when
// exhausted. Deterministic, and every draw is byte-wide by construction.
type byteStream struct {
	b []byte
	i int
}

func newByteStream(seed uint64, n int) *byteStream {
	b := make([]byte, n)
	fillPseudoRandom(b, seed)
	return &byteStream{b: b}
}

// nextByte returns the next byte of the stream.
func (s *byteStream) nextByte() int {
	v := s.b[s.i%len(s.b)]
	s.i++
	return int(v)
}

// below returns a value in [0, n) for a small n, built from two bytes so the
// fixtures' identifiers vary over a wide enough range to look like real data.
func (s *byteStream) below(n int) int {
	if n <= 0 {
		return 0
	}
	return (s.nextByte()<<8 | s.nextByte()) % n
}
