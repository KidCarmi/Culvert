package backupcrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

const streamTestPass = "correct horse battery staple"

func sealStream(t *testing.T, pt []byte, pass string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewStreamWriter(&buf, pass)
	if err != nil {
		t.Fatal(err)
	}
	// Uneven write sizes so chunk boundaries never align with writes.
	for off := 0; off < len(pt); {
		n := min(7919, len(pt)-off)
		if _, err := w.Write(pt[off : off+n]); err != nil {
			t.Fatal(err)
		}
		off += n
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func openStream(blob []byte, pass string) ([]byte, error) {
	r, err := NewStreamReader(bytes.NewReader(blob), pass)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// Every length class around the chunk boundary, including the empty stream and
// exact multiples (which end with an EMPTY final chunk).
func TestStream_RoundTripAtEveryBoundary(t *testing.T) {
	for _, n := range []int{0, 1, StreamChunkSize - 1, StreamChunkSize, StreamChunkSize + 1, 2 * StreamChunkSize, 3*StreamChunkSize + 17} {
		pt := randBytes(t, n)
		blob := sealStream(t, pt, streamTestPass)
		if !IsEncryptedStream(blob) || IsEncryptedBlob(blob) {
			t.Fatalf("n=%d: magic sniffing wrong", n)
		}
		got, err := openStream(blob, streamTestPass)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("n=%d: round trip err=%v equal=%v", n, err, bytes.Equal(got, pt))
		}
		chunks := n/StreamChunkSize + 1
		if want := StreamHdrLen + n + chunks*encTagLen; len(blob) != want {
			t.Fatalf("n=%d: blob %d bytes, want %d (%d chunks)", n, len(blob), want, chunks)
		}
	}
}

func TestStream_WrongPassphraseIsOpaque(t *testing.T) {
	blob := sealStream(t, randBytes(t, 3*StreamChunkSize), streamTestPass)
	if _, err := openStream(blob, "wrong"); !errors.Is(err, ErrDecryptOpaque) {
		t.Fatalf("wrong passphrase: %v", err)
	}
}

// Cutting the stream at ANY chunk boundary must fail: no chunk is flagged last.
func TestStream_TruncationAtEveryBoundaryFails(t *testing.T) {
	pt := randBytes(t, 3*StreamChunkSize+100)
	blob := sealStream(t, pt, streamTestPass)
	full := StreamChunkSize + encTagLen
	for k := 1; k <= 3; k++ {
		cut := blob[:StreamHdrLen+k*full]
		got, err := openStream(cut, streamTestPass)
		if !errors.Is(err, ErrStreamTruncated) {
			t.Fatalf("cut after %d full chunks: err=%v (got %d bytes)", k, err, len(got))
		}
		if len(got) > k*StreamChunkSize {
			t.Fatalf("cut after %d chunks returned %d bytes", k, len(got))
		}
	}
	// Header only, or a header plus a few bytes: nothing authenticated, so the
	// error must not claim the passphrase was right.
	for _, cut := range []int{StreamHdrLen, StreamHdrLen + 5} {
		if _, err := openStream(blob[:cut], streamTestPass); !errors.Is(err, ErrDecryptOpaque) {
			t.Fatalf("cut at %d: %v, want opaque", cut, err)
		}
	}
	// Mid-chunk cut: the partial chunk cannot authenticate as the last one.
	if _, err := openStream(blob[:len(blob)-5], streamTestPass); err == nil {
		t.Fatal("mid-chunk truncation accepted")
	}
}

func TestStream_ChunkTamperingFails(t *testing.T) {
	pt := randBytes(t, 3*StreamChunkSize+100)
	blob := sealStream(t, pt, streamTestPass)
	full := StreamChunkSize + encTagLen
	chunk := func(b []byte, i int) []byte { return b[StreamHdrLen+i*full : StreamHdrLen+(i+1)*full] }
	cases := map[string][]byte{}
	// Swap chunks 0 and 1.
	sw := append([]byte(nil), blob...)
	copy(chunk(sw, 0), chunk(blob, 1))
	copy(chunk(sw, 1), chunk(blob, 0))
	cases["reordered"] = sw
	// Drop chunk 1.
	cases["dropped"] = append(append([]byte(nil), blob[:StreamHdrLen+full]...), blob[StreamHdrLen+2*full:]...)
	// Flip one ciphertext bit in chunk 2.
	fl := append([]byte(nil), blob...)
	chunk(fl, 2)[100] ^= 1
	cases["bitflip"] = fl
	// Trailing garbage after the final chunk.
	cases["trailing"] = append(append([]byte(nil), blob...), 0xAA, 0xBB)
	for name, b := range cases {
		if _, err := openStream(b, streamTestPass); !errors.Is(err, ErrDecryptOpaque) {
			t.Errorf("%s: err=%v, want opaque", name, err)
		}
	}
}

func TestStream_HeaderTamperingFails(t *testing.T) {
	blob := sealStream(t, randBytes(t, 1000), streamTestPass)
	// A changed salt or nonce prefix changes the key/nonce and the AAD.
	for _, off := range []int{14, 31, 37} {
		b := append([]byte(nil), blob...)
		b[off] ^= 1
		if _, err := openStream(b, streamTestPass); !errors.Is(err, ErrDecryptOpaque) {
			t.Errorf("header byte %d flipped: %v", off, err)
		}
	}
	// KDF downgrade below the floor is refused before any key derivation.
	b := append([]byte(nil), blob...)
	binary.BigEndian.PutUint32(b[10:14], 1000)
	if _, err := openStream(b, streamTestPass); err == nil || errors.Is(err, ErrDecryptOpaque) {
		t.Errorf("KDF downgrade: %v", err)
	}
	// An iteration count above the ceiling is refused before the KDF runs.
	b = append([]byte(nil), blob...)
	binary.BigEndian.PutUint32(b[10:14], 0xFFFFFFFF)
	if _, err := openStream(b, streamTestPass); err == nil || errors.Is(err, ErrDecryptOpaque) {
		t.Errorf("iteration ceiling: %v", err)
	}
	// An iteration count ABOVE the floor but not the one sealed: AAD mismatch.
	b = append([]byte(nil), blob...)
	binary.BigEndian.PutUint32(b[10:14], encMinIters)
	if _, err := openStream(b, streamTestPass); !errors.Is(err, ErrDecryptOpaque) {
		t.Errorf("iteration change: %v", err)
	}
	// A blob envelope is not a stream.
	if _, err := NewStreamReader(bytes.NewReader([]byte(Magic+"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")), streamTestPass); err == nil {
		t.Error("blob magic accepted as a stream")
	}
}

// No plaintext leaves the reader before its chunk authenticated: a stream
// whose SECOND chunk is corrupt yields at most the first chunk, then fails.
func TestStream_NoUnauthenticatedPlaintext(t *testing.T) {
	pt := randBytes(t, 2*StreamChunkSize+10)
	blob := sealStream(t, pt, streamTestPass)
	blob[StreamHdrLen+StreamChunkSize+encTagLen+3] ^= 1
	r, err := NewStreamReader(bytes.NewReader(blob), streamTestPass)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if !errors.Is(err, ErrDecryptOpaque) {
		t.Fatalf("err=%v", err)
	}
	if !bytes.Equal(got, pt[:len(got)]) || len(got) > StreamChunkSize {
		t.Fatalf("released %d bytes past the authenticated prefix", len(got))
	}
}

func TestStream_WriteAfterCloseRefused(t *testing.T) {
	w, err := NewStreamWriter(io.Discard, streamTestPass)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("write after close accepted")
	}
}
