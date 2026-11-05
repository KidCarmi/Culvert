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
	"hash/crc32"
	"runtime"
	"strings"
	"testing"
)

const leakCanary = "CULVERT-POOL-CANARY-7f3a9b2e-DO-NOT-LEAK"

func leakSecret() []byte {
	var b bytes.Buffer
	for b.Len() < 20<<10 {
		b.WriteString(leakCanary)
		b.WriteString("-padding-padding-padding-")
	}
	return b.Bytes()
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
	//nolint:gosec // G115: the gzip ISIZE field is the length mod 2^32 by RFC 1952; this helper's payload is a few dozen bytes
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
// plaintext out of it. Every expansion below must either error or decode only
// its own bytes; none may contain the prior response's canary.
func TestExpandPooled_CannotLeakAPriorResponse(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))

	secret := leakSecret()
	hostilePlain := []byte(strings.Repeat("x", 64))

	// Interleave repeatedly on ONE goroutine at GOMAXPROCS=1 so the hostile
	// stream is served by the same pooled object that just expanded the secret.
	for i := 0; i < 200; i++ {
		if out, bomb := DecompressForScan(leakGzip(t, secret), "gzip"); bomb || !bytes.Contains(out, []byte(leakCanary)) {
			t.Fatalf("round %d: priming gzip expansion did not happen (bomb=%v len=%d)", i, bomb, len(out))
		}
		hostile := leakFlateDict(t, secret, hostilePlain)
		out, bomb := DecompressForScan(hostile, "deflate")
		if bomb {
			t.Fatalf("round %d: hostile deflate refused as a bomb, unexpected", i)
		}
		if bytes.Contains(out, []byte(leakCanary)) {
			t.Fatalf("round %d: LEAK — deflate arm returned a prior response's plaintext (%d bytes)", i, len(out))
		}

		if out, bomb := DecompressForScan(leakFlate(t, secret), "deflate"); bomb || !bytes.Contains(out, []byte(leakCanary)) {
			t.Fatalf("round %d: priming deflate expansion did not happen (bomb=%v len=%d)", i, bomb, len(out))
		}
		gzHostile := leakGzipWrapRaw(leakFlateDict(t, secret, hostilePlain), hostilePlain)
		out, bomb = DecompressForScan(gzHostile, "gzip")
		if bomb {
			t.Fatalf("round %d: hostile gzip refused as a bomb, unexpected", i)
		}
		if bytes.Contains(out, []byte(leakCanary)) {
			t.Fatalf("round %d: LEAK — gzip arm returned a prior response's plaintext (%d bytes)", i, len(out))
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
