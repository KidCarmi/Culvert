package secscan

// CHAOS-106 follow-up — the operator-tunable expansion ratio.
//
// The 64:1 bound stays the fail-closed DEFAULT; an administrator may move it
// inside [MinDecompressRatioLimit, MaxDecompressRatioLimit] so legitimate,
// highly repetitive downloads (CSV/log exports compressing past 64:1) are not
// refused. These gates pin: the default when nothing is set, the range (an
// out-of-range value is refused and the current bound kept), the runtime effect
// on a real ~100:1 stream in both directions, and that the hot-path read is
// race-free against a concurrent change.

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"testing"
)

// fillNoise fills dst with incompressible, deterministic bytes (SHA-256 in
// counter mode), so a fixture's compression ratio is reproducible.
func fillNoise(dst []byte, seed uint64) {
	var ctr [16]byte
	binary.BigEndian.PutUint64(ctr[:8], seed)
	for off, n := 0, uint64(0); off < len(dst); n++ {
		binary.BigEndian.PutUint64(ctr[8:], n)
		sum := sha256.Sum256(ctr[:])
		off += copy(dst[off:], sum[:])
	}
}

// withRatio installs ratio for one test and restores the prior bound.
func withRatio(t *testing.T, ratio int64) {
	t.Helper()
	prev := decompressRatioOverride.Load()
	if err := SetDecompressRatioLimit(ratio); err != nil {
		t.Fatalf("SetDecompressRatioLimit(%d): %v", ratio, err)
	}
	t.Cleanup(func() { decompressRatioOverride.Store(prev) })
}

// restoreRatio restores the bound a test may change.
func restoreRatio(t *testing.T) {
	t.Helper()
	prev := decompressRatioOverride.Load()
	t.Cleanup(func() { decompressRatioOverride.Store(prev) })
}

// ratio100Fixture returns a gzip stream that expands at roughly 90-100:1:
// 1 KiB of incompressible bytes followed by 99 KiB of zeros, repeated to
// 8 MiB. The incompressible run dominates the compressed size, so the ratio is
// set by the mix rather than by gzip's ~1030:1 on zeros. It is the shape of a
// legitimately repetitive export, between the 64 default and 128.
func ratio100Fixture(t *testing.T) (wire []byte, expanded int) {
	t.Helper()
	const (
		chunk  = 100 << 10
		noise  = 1 << 10
		chunks = 80
	)
	raw := make([]byte, chunk*chunks)
	for c := 0; c < chunks; c++ {
		fillNoise(raw[c*chunk:c*chunk+noise], uint64(c))
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	ratio := len(raw) / buf.Len()
	// The fixture is only meaningful strictly between the default and 128,
	// and past the small-response floor so the ratio (not the floor) decides.
	if ratio <= DefaultDecompressRatioLimit || ratio >= 128 {
		t.Fatalf("fixture ratio %d:1, want strictly between %d and 128", ratio, DefaultDecompressRatioLimit)
	}
	if int64(buf.Len())*DefaultDecompressRatioLimit <= DecompressFloorBytes {
		t.Fatalf("fixture compressed to %d bytes — the 1 MiB floor would decide, not the ratio", buf.Len())
	}
	return buf.Bytes(), len(raw)
}

func TestDecompressRatioLimit_DefaultsTo64WhenUnset(t *testing.T) {
	restoreRatio(t)
	decompressRatioOverride.Store(0) // the zero value: nothing ever set

	if got := DecompressRatioLimit(); got != 64 {
		t.Fatalf("DecompressRatioLimit() = %d with no override, want 64", got)
	}
	if DefaultDecompressRatioLimit != 64 {
		t.Fatalf("DefaultDecompressRatioLimit = %d — the shipped default must stay 64", DefaultDecompressRatioLimit)
	}
	// The bound the hot path computes follows the default too.
	limit, ratioBound := expandBound(64 << 10)
	if !ratioBound || limit != (64<<10)*64 {
		t.Fatalf("expandBound(64 KiB) = (%d, %v), want (%d, true)", limit, ratioBound, (64<<10)*64)
	}
}

func TestSetDecompressRatioLimit_RejectsOutOfRangeAndKeepsTheBound(t *testing.T) {
	withRatio(t, 100)
	for _, bad := range []int64{0, -1, MinDecompressRatioLimit - 1, MaxDecompressRatioLimit + 1, 1024, 1 << 40} {
		if err := SetDecompressRatioLimit(bad); err == nil {
			t.Errorf("SetDecompressRatioLimit(%d) accepted an out-of-range ratio", bad)
		}
		if got := DecompressRatioLimit(); got != 100 {
			t.Fatalf("after refused %d the ratio is %d, want the previous 100 kept", bad, got)
		}
	}
	for _, ok := range []int64{MinDecompressRatioLimit, MaxDecompressRatioLimit} {
		if err := SetDecompressRatioLimit(ok); err != nil {
			t.Errorf("SetDecompressRatioLimit(%d) refused an in-range boundary: %v", ok, err)
		}
		if got := DecompressRatioLimit(); got != ok {
			t.Errorf("ratio = %d after setting %d", got, ok)
		}
	}
}

// The range must stay below every bomb ratio CHAOS-106 measured (408:1 for the
// fixture, ~1030:1 for zeros), or the setting could switch the bound off.
func TestDecompressRatioLimit_MaximumStillRefusesTheMeasuredBomb(t *testing.T) {
	if MaxDecompressRatioLimit >= 408 {
		t.Fatalf("MaxDecompressRatioLimit = %d, at or above the measured 408:1 bomb", MaxDecompressRatioLimit)
	}
	withRatio(t, MaxDecompressRatioLimit)
	bomb := gzipOf(t, 20<<20, zeros) // ~1030:1
	if out, refused := DecompressForScan(bomb, "gzip"); !refused || out != nil {
		t.Fatalf("at the maximum ratio a zeros bomb was admitted (refused=%v, %d bytes)", refused, len(out))
	}
}

// Setting the default clears the override: a node reset to 64 is the same
// state as one that was never touched.
func TestSetDecompressRatioLimit_DefaultClearsTheOverride(t *testing.T) {
	withRatio(t, 200)
	if err := SetDecompressRatioLimit(DefaultDecompressRatioLimit); err != nil {
		t.Fatal(err)
	}
	if v := decompressRatioOverride.Load(); v != 0 {
		t.Fatalf("override = %d after setting the default, want 0 (unset)", v)
	}
	if got := DecompressRatioLimit(); got != DefaultDecompressRatioLimit {
		t.Fatalf("ratio = %d, want the default", got)
	}
}

// The runtime effect, both directions, on the same bytes: refused at the
// default, admitted (fully expanded) at 128.
func TestDecompressForScan_RatioSettingChangesTheVerdict(t *testing.T) {
	wire, expanded := ratio100Fixture(t)

	restoreRatio(t)
	decompressRatioOverride.Store(0)
	before := DecompressBombs()
	if out, refused := DecompressForScan(wire, "gzip"); !refused || out != nil {
		t.Fatalf("at the default 64:1 a ~100:1 stream was admitted (refused=%v, %d bytes)", refused, len(out))
	}
	if DecompressBombs()-before != 1 {
		t.Errorf("refusal at the default was not counted")
	}

	withRatio(t, 128)
	out, refused := DecompressForScan(wire, "gzip")
	if refused {
		t.Fatal("at 128:1 a ~100:1 stream was refused — the setting had no runtime effect")
	}
	if len(out) != expanded {
		t.Fatalf("admitted expansion is %d bytes, want the full %d (not a truncated prefix)", len(out), expanded)
	}
}

// Lowering the ratio tightens the bound on content the default admits.
func TestDecompressForScan_LoweredRatioRefusesWhatTheDefaultAdmits(t *testing.T) {
	// ~40:1: 1 KiB noise + 39 KiB zeros, 64 chunks = 2.5 MiB.
	raw := make([]byte, 40<<10*64)
	for c := 0; c < 64; c++ {
		fillNoise(raw[c*(40<<10):c*(40<<10)+1<<10], uint64(1000+c))
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	if r := len(raw) / buf.Len(); r <= MinDecompressRatioLimit || r >= DefaultDecompressRatioLimit {
		t.Fatalf("fixture ratio %d:1, want strictly between %d and %d", r, MinDecompressRatioLimit, DefaultDecompressRatioLimit)
	}

	restoreRatio(t)
	decompressRatioOverride.Store(0)
	if _, refused := DecompressForScan(buf.Bytes(), "gzip"); refused {
		t.Fatal("negative control: the default refused a ~40:1 stream")
	}
	withRatio(t, MinDecompressRatioLimit)
	if _, refused := DecompressForScan(buf.Bytes(), "gzip"); !refused {
		t.Fatal("at 16:1 a ~40:1 stream was admitted — lowering the ratio had no effect")
	}
}

// The ratio is read on every response; a concurrent change must be race-free
// (run under -race) and every expansion must decide against SOME valid bound.
func TestDecompressRatioLimit_ConcurrentChangeIsRaceFree(t *testing.T) {
	restoreRatio(t)
	wire, _ := ratio100Fixture(t)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		vals := []int64{DefaultDecompressRatioLimit, 128, MinDecompressRatioLimit, MaxDecompressRatioLimit}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = SetDecompressRatioLimit(vals[i%len(vals)])
		}
	}()
	for i := 0; i < 8; i++ {
		_, _ = DecompressForScan(wire, "gzip")
		if r := DecompressRatioLimit(); r < MinDecompressRatioLimit || r > MaxDecompressRatioLimit {
			t.Errorf("observed out-of-range ratio %d", r)
		}
	}
	close(stop)
	wg.Wait()
}
