package pseudonym

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

const (
	// Sentinel is the fail-closed value: key missing, never plaintext.
	Sentinel = "redacted"
	// Prefix is the keyed-HMAC destination token prefix.
	Prefix = "h_"
	// KeyLen is the required HMAC key length in bytes.
	KeyLen = 32

	// hexLen is how many hex characters of the MAC the token keeps. Load-bearing:
	// it fixes the token's shape and collision domain.
	hexLen = 12
	// hexDigits matches encoding/hex (lowercase); uppercase would silently break
	// correlation against already-written records.
	hexDigits = "0123456789abcdef"
	// hasherScratchCap bounds the scratch buffer a pooled hasher may retain.
	hasherScratchCap = 512
)

// keyState bundles the active key with a monotonic generation so one atomic load
// yields a consistent (key, gen, id) triple. id is the NON-SECRET durable
// pseudonym-generation identifier minted with each key (never derived from it);
// gen is a process-local pool-invalidation counter. They are deliberately separate.
type keyState struct {
	key []byte
	gen uint64
	id  string
}

// hasher is a pooled, key-bound HMAC. gen binds it to the key generation it was
// built for; a hasher whose gen differs from the loaded state is rebuilt. buf and
// sum are per-hasher scratch that remove the per-call allocations.
type hasher struct {
	gen uint64
	mac hash.Hash
	buf []byte
	sum [sha256.Size]byte
}

// Pseudonymizer is an instance-owned keyed pseudonymizer. The zero value is not
// usable; construct with New. Safe for concurrent use.
type Pseudonymizer struct {
	state atomic.Pointer[keyState]
	gen   atomic.Uint64
	pool  sync.Pool
}

// New returns a Pseudonymizer with no key installed (fail-closed).
func New() *Pseudonymizer {
	p := &Pseudonymizer{}
	p.pool.New = func() any { return new(hasher) }
	return p
}

// Set publishes the key (copying the input) with a freshly minted id. An empty
// key clears it, so Pseudonymize fails closed.
func (p *Pseudonymizer) Set(k []byte) {
	if len(k) == 0 {
		p.SetPair(nil, "")
		return
	}
	p.SetPair(k, p.mintID())
}

// SetPair publishes a (key, id) pair with one pointer store, so a reader can
// never pair a new key with an old id. An empty key clears the state and burns
// a generation so pooled hashers for the old key are stale.
func (p *Pseudonymizer) SetPair(k []byte, id string) {
	if len(k) == 0 {
		p.gen.Add(1)
		p.state.Store(nil)
		return
	}
	c := make([]byte, len(k))
	copy(c, k)
	p.state.Store(&keyState{key: c, gen: p.gen.Add(1), id: id})
}

// KeyID returns the non-secret generation id ("" when no key is installed).
func (p *Pseudonymizer) KeyID() string {
	if s := p.state.Load(); s != nil {
		return s.id
	}
	return ""
}

// Key returns the active key (nil if unset). Callers must treat it as read-only.
func (p *Pseudonymizer) Key() []byte {
	if s := p.state.Load(); s != nil {
		return s.key
	}
	return nil
}

// Rotate publishes a FRESH key unconditionally; correlation with pre-rotation
// records is intentionally broken.
func (p *Pseudonymizer) Rotate() error {
	k := make([]byte, KeyLen)
	if _, err := rand.Read(k); err != nil {
		return err
	}
	p.Set(k)
	return nil
}

// Ensure publishes a fresh key iff no full-length key exists.
func (p *Pseudonymizer) Ensure() error {
	if len(p.Key()) == KeyLen {
		return nil
	}
	k := make([]byte, KeyLen)
	if _, err := rand.Read(k); err != nil {
		return err
	}
	p.Set(k)
	return nil
}

// MintPair mints a fresh (key, id) pair WITHOUT publishing it, for persist-before-apply
// callers that publish via SetPair only after their write lands.
func (p *Pseudonymizer) MintPair() (key []byte, id string, err error) {
	k := make([]byte, KeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, "", err
	}
	return k, p.mintID(), nil
}

// MintID mints a generation id ALONE, for the caller that needs an id without a
// key — the legacy-upgrade path in package main, where a persisted key carries
// no persisted id and must be given one without disturbing the key.
//
// It exists because expressing that through MintPair is wrong in two ways.
// MintPair reads a 32-byte KEY the caller then discards, which spends entropy on
// nothing; and its signature forces an id-only caller to carry an error it
// cannot act on, which the only such caller in the tree answered by dropping it
// and returning MintPair's zero id. The EMPTY id is not a degraded id: it is the
// exact value KeyID reports for "no key is installed", so publishing it beside a
// VALID key would make an active node read as keyless on the admin API and give
// a client resolving an unknown-outcome rotation nothing to compare. On the
// pinned toolchain that leg is unreachable (see mintID), so nothing regressed —
// but a signature whose only correct use depends on a stdlib branch that cannot
// fire is the wrong shape for the contract, and this is the right one.
func (p *Pseudonymizer) MintID() string { return p.mintID() }

// mintID mints a random 16-hex id independent of any key material.
//
// The counter fallback is kept and is DEAD CODE on the pinned toolchain, which
// is worth saying rather than leaving as an implied guarantee: as of Go 1.24
// crypto/rand.Read "never returns an error" — it crashes the program
// irrecoverably through crypto/rand.fatal instead (go.dev/issue/66821). Neither
// this branch nor the error returns on Rotate, Ensure and MintPair can
// therefore be reached. That posture is the right one for a gateway — a node
// with no entropy must not keep deriving tokens — and the branch costs nothing,
// so it stays as the behaviour for a future source that does report failure.
// What must not happen is a caller reasoning that "the fallback protects me" or
// that "the error tells me": on this toolchain neither fires.
func (p *Pseudonymizer) mintID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "gen-" + strconv.FormatUint(p.gen.Add(1), 10)
	}
	return hex.EncodeToString(b[:])
}

// Pseudonymize returns the keyed token for a host (port/case/trailing dot
// normalized away), or Sentinel when no key is installed. Empty input stays
// empty. It never returns the plaintext.
func (p *Pseudonymizer) Pseudonymize(host string) string {
	if host == "" {
		return host
	}
	state := p.state.Load()
	if state == nil || len(state.key) == 0 {
		return Sentinel // fail-closed: never plaintext
	}
	norm := hostutil.NormalizeHost(hostutil.StripHostPort(host))

	ph, _ := p.pool.Get().(*hasher)
	if ph == nil {
		ph = new(hasher) // unreachable (pool New is typed); never nil-deref the hot path
	}
	if ph.mac == nil || ph.gen != state.gen {
		ph.mac = hmac.New(sha256.New, state.key)
		ph.gen = state.gen
	} else {
		ph.mac.Reset()
	}
	ph.buf = append(ph.buf[:0], norm...)
	ph.mac.Write(ph.buf)
	token := encode(ph.mac.Sum(ph.sum[:0]))
	if cap(ph.buf) > hasherScratchCap {
		ph.buf = nil
	}
	p.pool.Put(ph)
	return token
}

// encode renders Prefix plus the first hexLen hex characters of mac.
func encode(mac []byte) string {
	var out [len(Prefix) + hexLen]byte
	copy(out[:], Prefix)
	for i := 0; i < hexLen/2; i++ {
		out[len(Prefix)+i*2] = hexDigits[mac[i]>>4]
		out[len(Prefix)+i*2+1] = hexDigits[mac[i]&0x0f]
	}
	return string(out[:])
}

// hostByteClass reports whether b can be part of a hostname label.
func hostByteClass(b byte) bool {
	return b == '-' || b == '.' ||
		(b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// asciiLower lowercases A-Z only and returns a string of exactly len(s) bytes,
// so an index into the result is an index into s.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for k := i; k < len(b); k++ {
				if b[k] >= 'A' && b[k] <= 'Z' {
					b[k] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// ReplaceHostFold replaces every WHOLE-hostname (case-insensitive) occurrence of
// host in s with tok. "Whole" = not flanked by another host-label byte, so
// "ex.com" does not match inside "complex.com". The unmatched remainder keeps
// its original casing.
func ReplaceHostFold(s, host, tok string) string {
	if host == "" {
		return s
	}
	// Fold ASCII only. strings.ToLower is not length-preserving (U+023A is 2
	// bytes, its lowercase 3; an invalid UTF-8 byte becomes 3-byte U+FFFD), and
	// the match index found in the folded copy is used to slice s: any byte
	// that grows before the host shifts every later offset, which left the host
	// in plaintext or indexed past the end. Hosts on the wire are ASCII
	// (IDNA/punycode), so byte-wise ASCII folding loses no match that matters.
	ls, lh := asciiLower(s), asciiLower(host)
	var b strings.Builder
	last := 0
	for {
		rel := strings.Index(ls[last:], lh)
		if rel < 0 {
			break
		}
		i := last + rel
		end := i + len(host)
		beforeOK := i == 0 || !hostByteClass(s[i-1])
		afterOK := end == len(s) || !hostByteClass(s[end])
		if beforeOK && afterOK {
			b.WriteString(s[last:i])
			b.WriteString(tok)
			last = end
		} else {
			b.WriteString(s[last : i+1]) // not a whole-host match — advance one byte
			last = i + 1
		}
	}
	b.WriteString(s[last:])
	return b.String()
}
