package backupcrypt

// Streaming envelope ("CVRTST01") for archives too large to hold in memory —
// the request-history export, which can run to gigabytes. Same KDF and cipher
// as the D1.4 blob envelope, but the plaintext is sealed in fixed-size chunks
// (the STREAM construction):
//
//	offset  size  field          notes
//	------  ----  -------------  ---------------------------------
//	  0       8   magic          "CVRTST01" (ASCII)
//	  8       1   version        0x01
//	  9       1   kdf_id         0x01 = PBKDF2-SHA256
//	 10       4   kdf_iters      uint32 BE; 600000 for v1
//	 14      16   salt           random
//	 30       1   cipher_id      0x01 = AES-256-GCM
//	 31       7   nonce_prefix   random
//	 38       4   chunk_size     uint32 BE; plaintext bytes per full chunk
//	 42      ..   chunks         AES-GCM(chunk_i), each with a 16-byte tag
//
// Chunk i is sealed with nonce = nonce_prefix || uint32 BE(i) || last, where
// last is 0x01 for the final chunk and 0x00 otherwise, and the header as AAD.
// Every chunk but the last carries exactly chunk_size plaintext bytes; the
// last carries fewer (an empty final chunk is written when the plaintext is a
// multiple of chunk_size). So a reader detects, with authentication rather
// than by convention: a reordered or dropped chunk (counter), a stream cut at
// a chunk boundary (no chunk flagged last), trailing data after the last
// chunk, and any header change including a KDF downgrade (AAD).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// StreamMagic is the 8-byte ASCII magic of the streaming envelope.
	StreamMagic = "CVRTST01"
	// StreamHdrLen is the fixed serialized streaming header length.
	StreamHdrLen = 8 + 1 + 1 + 4 + 16 + 1 + 7 + 4 // = 42
	// StreamChunkSize is the plaintext size of every full chunk.
	StreamChunkSize = 64 << 10

	streamNoncePrefixLen = 7
	streamMaxChunkSize   = 1 << 20 // refuse a header that would make the reader allocate more
	// streamMaxIters refuses a header that would make the reader spin in the
	// KDF (a crafted 0xFFFFFFFF is ~4e9 PBKDF2 rounds before any check fails).
	streamMaxIters = 10 * KDFIters
)

// ErrStreamTruncated reports a stream that ended before its final chunk. It is
// returned only after at least one chunk authenticated (so the passphrase was
// right and the archive is incomplete); a stream with no authenticated chunk
// at all is ErrDecryptOpaque, since it proves nothing about the passphrase.
var ErrStreamTruncated = errors.New("encrypted stream truncated (no final chunk)")

// IsEncryptedStream reports whether prefix begins with the streaming magic.
func IsEncryptedStream(prefix []byte) bool {
	return len(prefix) >= MagicLen && string(prefix[:MagicLen]) == StreamMagic
}

type streamCipher struct {
	gcm    cipher.AEAD
	hdr    []byte
	prefix []byte
	ctr    uint32
}

func (c *streamCipher) nonce(last bool) ([]byte, error) {
	if c.ctr == ^uint32(0) {
		return nil, errors.New("encrypted stream: chunk counter exhausted")
	}
	n := make([]byte, 0, encNonceLen)
	n = append(n, c.prefix...)
	n = binary.BigEndian.AppendUint32(n, c.ctr)
	if last {
		return append(n, 1), nil
	}
	return append(n, 0), nil
}

func newStreamCipher(passphrase string, hdr []byte) (*streamCipher, error) {
	iters := int(binary.BigEndian.Uint32(hdr[10:14]))
	key := pbkdf2.Key([]byte(passphrase), hdr[14:14+encSaltLen], iters, 32, sha256.New)
	defer ZeroBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &streamCipher{gcm: gcm, hdr: hdr, prefix: hdr[31 : 31+streamNoncePrefixLen]}, nil
}

// StreamWriter seals everything written to it; Close writes the final chunk
// and MUST be called (an unclosed stream is, by design, unreadable).
type StreamWriter struct {
	w      io.Writer
	c      *streamCipher
	buf    []byte
	closed bool
}

// NewStreamWriter writes the header to w and returns a writer that seals the
// plaintext under passphrase.
func NewStreamWriter(w io.Writer, passphrase string) (*StreamWriter, error) {
	hdr := make([]byte, 0, StreamHdrLen)
	hdr = append(hdr, StreamMagic...)
	hdr = append(hdr, encVersion, encKDFPBKDF2)
	hdr = binary.BigEndian.AppendUint32(hdr, KDFIters)
	salt := make([]byte, encSaltLen+streamNoncePrefixLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("stream encrypt: random: %w", err)
	}
	hdr = append(hdr, salt[:encSaltLen]...)
	hdr = append(hdr, encCipherAESGCM)
	hdr = append(hdr, salt[encSaltLen:]...)
	hdr = binary.BigEndian.AppendUint32(hdr, StreamChunkSize)
	c, err := newStreamCipher(passphrase, hdr)
	if err != nil {
		return nil, fmt.Errorf("stream encrypt: cipher init: %w", err)
	}
	if _, err := w.Write(hdr); err != nil {
		return nil, err
	}
	return &StreamWriter{w: w, c: c, buf: make([]byte, 0, StreamChunkSize)}, nil
}

func (s *StreamWriter) seal(last bool) error {
	n, err := s.c.nonce(last)
	if err != nil {
		return err
	}
	out := s.c.gcm.Seal(nil, n, s.buf, s.c.hdr)
	s.c.ctr++
	s.buf = s.buf[:0]
	_, err = s.w.Write(out)
	return err
}

// Write buffers p and emits every chunk that fills. A full chunk is sealed as
// NON-final only once more plaintext follows it, so Close can always end the
// stream with a short (possibly empty) final chunk.
func (s *StreamWriter) Write(p []byte) (int, error) {
	if s.closed {
		return 0, errors.New("stream encrypt: write after close")
	}
	written := 0
	for len(p) > 0 {
		if len(s.buf) == StreamChunkSize {
			if err := s.seal(false); err != nil {
				return written, err
			}
		}
		n := copy(s.buf[len(s.buf):StreamChunkSize], p)
		s.buf = s.buf[:len(s.buf)+n]
		p = p[n:]
		written += n
	}
	return written, nil
}

// Close seals the remaining plaintext as the final chunk. When the buffer is
// exactly full it is first sealed as a non-final chunk, then an empty final
// chunk follows — the reader relies on the last chunk being short.
func (s *StreamWriter) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if len(s.buf) == StreamChunkSize {
		if err := s.seal(false); err != nil {
			return err
		}
	}
	return s.seal(true)
}

// StreamReader authenticates and decrypts a stream chunk by chunk. A read
// returns ErrDecryptOpaque on any authentication failure (wrong passphrase or
// tampering) and ErrStreamTruncated when the stream ends without its final
// chunk; no plaintext is ever returned from a chunk that did not authenticate.
type StreamReader struct {
	r    io.Reader
	c    *streamCipher
	ct   []byte // one full ciphertext chunk + 1 lookahead byte
	have int    // lookahead bytes carried into ct[0:have]
	out  []byte // authenticated plaintext not yet returned
	done bool
	err  error
}

// NewStreamReader reads and validates the header (non-opaque errors: they
// cannot leak passphrase information) and returns the decrypting reader.
func NewStreamReader(r io.Reader, passphrase string) (*StreamReader, error) {
	hdr := make([]byte, StreamHdrLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("stream decrypt: header: %w", err)
	}
	if string(hdr[:MagicLen]) != StreamMagic {
		return nil, errors.New("stream decrypt: bad magic (not a Culvert encrypted stream)")
	}
	if hdr[8] != encVersion || hdr[9] != encKDFPBKDF2 || hdr[30] != encCipherAESGCM {
		return nil, fmt.Errorf("stream decrypt: unsupported version/kdf/cipher %d/%d/%d", hdr[8], hdr[9], hdr[30])
	}
	if iters := binary.BigEndian.Uint32(hdr[10:14]); iters < encMinIters || iters > streamMaxIters {
		return nil, fmt.Errorf("stream decrypt: KDF iterations %d outside %d..%d", iters, encMinIters, streamMaxIters)
	}
	size := binary.BigEndian.Uint32(hdr[38:42])
	if size == 0 || size > streamMaxChunkSize {
		return nil, fmt.Errorf("stream decrypt: chunk size %d out of range", size)
	}
	c, err := newStreamCipher(passphrase, hdr)
	if err != nil {
		return nil, ErrDecryptOpaque
	}
	return &StreamReader{r: r, c: c, ct: make([]byte, int(size)+encTagLen+1)}, nil
}

func (s *StreamReader) open(ct []byte, last bool) error {
	n, err := s.c.nonce(last)
	if err != nil {
		return err
	}
	pt, err := s.c.gcm.Open(nil, n, ct, s.c.hdr)
	if err != nil {
		return ErrDecryptOpaque
	}
	s.c.ctr++
	s.out = pt
	return nil
}

// next authenticates the next chunk into s.out. It reads one byte past a full
// chunk: when that byte exists the chunk is non-final; when the stream ends
// first, what was read is the final (short) chunk.
func (s *StreamReader) next() error {
	full := len(s.ct) - 1
	n, err := io.ReadFull(s.r, s.ct[s.have:])
	total := s.have + n
	if err == nil {
		if err := s.open(s.ct[:full], false); err != nil {
			return err
		}
		s.ct[0], s.have = s.ct[full], 1
		return nil
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return err
	}
	s.done = true
	if total == full {
		// A full-size chunk is never final: authenticate it as non-final,
		// then the missing final chunk is a truncation.
		if err := s.open(s.ct[:full], false); err != nil {
			return err
		}
		s.out = nil
		return ErrStreamTruncated
	}
	if total < encTagLen {
		if s.c.ctr == 0 {
			return ErrDecryptOpaque
		}
		return ErrStreamTruncated
	}
	return s.open(s.ct[:total], true)
}

// Read returns authenticated plaintext. io.EOF is returned only after the
// final chunk authenticated.
func (s *StreamReader) Read(p []byte) (int, error) {
	for len(s.out) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		if s.done {
			return 0, io.EOF
		}
		if err := s.next(); err != nil {
			s.err = err
			return 0, err
		}
	}
	n := copy(p, s.out)
	s.out = s.out[n:]
	return n, nil
}
