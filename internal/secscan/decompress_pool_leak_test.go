package secscan

// decompress_pool_leak_test.go — the negative control the pooled scan-path
// decompressors need and decompress_pool_test.go does not have.
//
// A pooled gzip/flate decoder keeps a 32 KiB history window between responses.
// decompress_pool_test.go proves the pooled arm decodes the same bytes as a
// fresh one and that release() drops the COMPRESSED buffer; neither question is
// the one that would make pooling a disclosure bug on a security gateway.
// That question is whether a hostile stream can read the PREVIOUS response's
// plaintext out of the retained window — on an SWG, response bodies belonging
// to different users of the same appliance share these pool slots.
//
// The protection is in compress/flate (a back-reference past histSize() is
// CorruptInputError, and histSize() counts only what THIS stream wrote), not in
// anything this repository owns, so it is pinned here rather than reasoned
// about: a toolchain or vendoring change that relaxed it would otherwise be
// silent.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"runtime"
	"strings"
	"testing"
)

const leakCanary = "CULVERT-POOL-CANARY-7f3a9b2e-DO-NOT-LEAK"

// leakWindow is compress/flate's history window (its unexported
// maxMatchOffset): the most a back-reference can reach, and the size of the
// buffer a pooled decoder keeps between streams.
const leakWindow = 32 << 10

// leakSecret is the "previous response": exactly one flate window of
// canary-bearing rows. Exactly one window is deliberate — after the decoder
// has emitted it, its ring buffer holds the secret byte-for-byte at the same
// offsets a preset dictionary would occupy, so a decoder that failed to bound
// history to the current stream would resolve the attack's back-references to
// the secret EXACTLY rather than to shifted garbage. The row counter keeps the
// rows distinct so the attack's references have to reach a specific offset in
// the window rather than the nearest copy of a repeating period.
func leakSecret() []byte {
	var b bytes.Buffer
	for i := 0; b.Len() < leakWindow; i++ {
		fmt.Fprintf(&b, "%s-row-%05d-padding-", leakCanary, i)
	}
	return b.Bytes()[:leakWindow]
}

// leakAttack returns a hostile plaintext and its raw deflate encoding against
// the secret as a preset dictionary. The plaintext is copied OUT OF the secret,
// so the encoder expresses it as back-references reaching before the start of
// the stream, into the dictionary — the stream's only way to produce those
// bytes is to read them from history it did not write. Before returning, it
// proves that dependence rather than assuming it: the stream decodes to the
// plaintext WITH the dictionary, is rejected by a fresh decoder WITHOUT it,
// and does not carry the canary as literal bytes (the scan path's
// corrupt-stream fallback returns the compressed bytes, so a literal canary
// would trip the disclosure assertion even when the decoder is correct).
func leakAttack(t *testing.T, secret []byte) (plain, raw []byte) {
	t.Helper()
	plain = append([]byte(nil), secret[8<<10:12<<10]...)
	raw = leakFlateDict(t, secret, plain)

	if bytes.Contains(raw, []byte(leakCanary)) {
		t.Fatalf("attack stream carries the canary as literals; it must reach it only through the dictionary")
	}
	if len(raw) >= len(plain)/8 {
		t.Fatalf("attack stream is %d bytes for %d plaintext bytes; expected back-references into the dictionary, not literals", len(raw), len(plain))
	}
	withDict, err := io.ReadAll(flate.NewReaderDict(bytes.NewReader(raw), secret))
	if err != nil || !bytes.Equal(withDict, plain) {
		t.Fatalf("attack stream does not decode to its plaintext with the dictionary (err=%v len=%d)", err, len(withDict))
	}
	fresh, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err == nil {
		t.Fatalf("control: a fresh dictionary-free flate decoder accepted the attack stream (%d bytes); it does not exercise the history bound", len(fresh))
	}
	if bytes.Contains(fresh, []byte(leakCanary)) {
		t.Fatalf("control: a fresh dictionary-free flate decoder emitted the canary before failing")
	}
	return plain, raw
}

func leakGzip(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func leakFlate(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// leakFlateDict builds a raw deflate stream whose back-references reach BEFORE
// the start of the stream, into a preset dictionary the decoder was never
// given. HTTP `Content-Encoding: deflate` has no dictionary negotiation, so
// such a body is purely hostile: its only possible source of those bytes is
// whatever happens to be sitting in the decompressor's 32 KiB history window —
// which, with a pooled decoder, is the PREVIOUS response's plaintext.
func leakFlateDict(t *testing.T, dict, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriterDict(&buf, flate.BestCompression, dict)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// leakGzipWrapRaw wraps an arbitrary raw deflate payload in a gzip envelope,
// with a trailer computed over `claimed` so the envelope is well-formed.
func leakGzipWrapRaw(raw, claimed []byte) []byte {
	out := []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255}
	out = append(out, raw...)
	var tail [8]byte
	binary.LittleEndian.PutUint32(tail[0:4], crc32.ChecksumIEEE(claimed))
	//nolint:gosec // G115: the gzip ISIZE field is the length mod 2^32 by RFC 1952; this helper's payload is a few KiB
	binary.LittleEndian.PutUint32(tail[4:8], uint32(len(claimed)))
	return append(out, tail[:]...)
}

// leakGzipNamed emits a gzip stream carrying an origin-supplied FNAME field.
// gzip's readHeader reads that NUL-terminated string into Reader.Header.Name
// with no length bound of its own, so it is an origin-chosen allocation that a
// POOLED reader could pin in a pool slot for the process lifetime.
func leakGzipNamed(t *testing.T, name string, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Name = name
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestExpandPooled_CannotLeakAPriorResponse is the negative control the
// pooling change needs and does not have: a pooled decompressor retains a
// 32 KiB history window across responses, and a hostile stream that
// back-references past its own start would read a PREVIOUS response's
// plaintext out of it.
//
// The attack stream is built so that it CAN only succeed by reading stale
// history (leakAttack proves a fresh decoder rejects it), and each attack is
// served immediately after the SAME encoding's pooled decoder expanded the
// secret — gzip and deflate are separate pools, so priming one and attacking
// the other would test nothing. The production guarantee pinned here is the
// one compress/flate gives a reset decoder: the back-references fail with
// CorruptInputError, DecompressForScan takes its corrupt-stream fallback and
// returns the compressed bytes unchanged, and the secret never appears.
func TestExpandPooled_CannotLeakAPriorResponse(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))

	secret := leakSecret()
	attackPlain, attackRaw := leakAttack(t, secret)

	gzAttack := leakGzipWrapRaw(attackRaw, attackPlain)
	if fresh, err := gzip.NewReader(bytes.NewReader(gzAttack)); err == nil {
		if out, err := io.ReadAll(fresh); err == nil {
			t.Fatalf("control: a fresh gzip reader accepted the attack stream (%d bytes); it does not exercise the history bound", len(out))
		}
	}

	arms := []struct {
		name   string
		ce     string
		prime  []byte
		attack []byte
	}{
		{"deflate", "deflate", leakFlate(t, secret), attackRaw},
		{"gzip", "gzip", leakGzip(t, secret), gzAttack},
	}

	// Run each arm on ONE goroutine at GOMAXPROCS=1 so the attack is normally
	// served by the very pooled object that just expanded the secret. Under
	// -race sync.Pool drops a random share of Puts, so the rounds are repeated
	// rather than relying on any single one reusing the object.
	for _, arm := range arms {
		for i := 0; i < 200; i++ {
			if out, bomb := DecompressForScan(arm.prime, arm.ce); bomb || !bytes.Equal(out, secret) {
				t.Fatalf("%s round %d: priming expansion did not decode the secret (bomb=%v len=%d)", arm.name, i, bomb, len(out))
			}
			out, bomb := DecompressForScan(arm.attack, arm.ce)
			if bomb {
				t.Fatalf("%s round %d: attack stream refused as a bomb, unexpected", arm.name, i)
			}
			if bytes.Contains(out, []byte(leakCanary)) {
				t.Fatalf("%s round %d: LEAK — the pooled decoder resolved the attack against the previous response's history and returned its plaintext (%d bytes)", arm.name, i, len(out))
			}
			if !bytes.Equal(out, arm.attack) {
				t.Fatalf("%s round %d: attack stream was not rejected: got %d bytes, want the corrupt-stream fallback (the %d compressed bytes)", arm.name, i, len(out), len(arm.attack))
			}
		}
	}
}

// TestExpandPooled_ReleaseDropsOriginHeaderState checks the other half of the
// retention question: a pooled gzip reader must not keep the origin-chosen
// FNAME/FCOMMENT strings, or the source reference, of the response it just
// expanded. The bytes at stake are small — compress/gzip caps a header string
// at 512 — but "the pooled reader holds nothing of the last response" is the
// property the pool's safety argument rests on, so it is pinned rather than
// reasoned about.
func TestExpandPooled_ReleaseDropsOriginHeaderState(t *testing.T) {
	// compress/gzip bounds a header string at its 512-byte scratch buffer
	// (readString returns ErrHeader past it), so 400 is the largest
	// origin-chosen FNAME that actually reaches Header.Name.
	name := strings.Repeat("A", 400)
	body := []byte(strings.Repeat("hello world ", 64))

	if out, bomb := DecompressForScan(leakGzipNamed(t, name, body), "gzip"); bomb || !bytes.Equal(out, body) {
		t.Fatalf("named-gzip expansion failed (bomb=%v len=%d)", bomb, len(out))
	}

	// Drain the pool and assert no slot still holds the header strings.
	var held []*gzipScanReader
	for i := 0; i < 64; i++ {
		g := gzipScanReaderPool.Get().(*gzipScanReader)
		if g.z.Name != "" || g.z.Comment != "" || g.z.Extra != nil {
			t.Fatalf("pooled gzip reader retains origin header state: name=%d comment=%d extra=%d",
				len(g.z.Name), len(g.z.Comment), len(g.z.Extra))
		}
		if g.src.Len() != 0 {
			t.Fatalf("pooled gzip reader retains %d source bytes", g.src.Len())
		}
		held = append(held, g)
	}
	for _, g := range held {
		gzipScanReaderPool.Put(g)
	}
}
