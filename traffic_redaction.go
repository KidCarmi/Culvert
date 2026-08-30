package main

// traffic_redaction.go — PR3 Option B: the destination-privacy posture. When the
// redaction posture (decRedactHosts) is ON, the destination is pseudonymized with a
// KEYED HMAC-SHA256 → "h_"+12hex, applied at the SINGLE persistLogEntry chokepoint so
// EVERY sink (in-memory feed, JSONL, queryable history store, syslog/SIEM, drill-down)
// AND the nested dec.host/dec.sni carry the identical token and NO plaintext
// destination.
//
// This SUPERSEDES the B0 metadata-only interim (PR #868): the posture is now
// traffic-wide, and the retired unsalted 48-bit hash (decryption_observability.go's
// old redactHost) is replaced by a keyed HMAC — not dictionary-recoverable, yet stable
// so a SOC still correlates on the token. The key is NODE-LOCAL (fleet-wide correlation
// via a CP→DP key sync is the deferred B3 follow-up, roadmap/PR3-...md): a stable
// per-node pseudonym.
//
// FAIL-CLOSED (the load-bearing safety property): posture ON but key unavailable ⇒ the
// destination is dropped to a constant sentinel, NEVER plaintext — so enabling the
// posture can never silently leak a destination on a node missing the key.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

const (
	redactedSentinel = "redacted" // fail-closed value: posture on, key missing
	pseudonymPrefix  = "h_"       // keyed-HMAC destination token prefix (shared with dec.*)
	trafficKeyLen    = 32
)

// trafficKeyState bundles the active key with a monotonic generation. The generation
// is what lets a POOLED HMAC (see pseudonymHasher) prove it was built for the key that
// is still current: a hasher carries the generation it was keyed with, and any hasher
// whose generation differs from the loaded state is discarded rather than reused. One
// atomic load yields key and generation together, so a rotation racing a redaction can
// never pair a new generation with an old key.
type trafficKeyState struct {
	key []byte
	gen uint64
	// id is the NON-SECRET pseudonym-generation identifier (2E-B §B): a random
	// 16-hex string minted WITH each key (never derived from it), persisted in
	// admin_settings.json beside the key, and exposed on the admin API as
	// key_id. It is what makes rotation exactly-once observable: a rotation
	// mints a new id, the id survives restart, and a client resolving an
	// unknown-outcome rotation compares ids instead of blindly retrying.
	// Unlike gen (process-local pool-invalidation counter), id is durable
	// identity; the two are deliberately separate.
	id string
}

// trafficPseudonymKey holds the node-local 32-byte HMAC key. atomic.Pointer so the
// per-record redaction reads it lock-free; published once at settings load and on the
// first enable. The pointee is never mutated after publish (a new state is stored).
var trafficPseudonymKey atomic.Pointer[trafficKeyState]

// trafficKeyGen issues the generation stamped onto each published key. It only ever
// increases, including across clear/re-publish, so a hasher pooled before a rotation
// can never be mistaken for one keyed after it.
var trafficKeyGen atomic.Uint64

// setTrafficPseudonymKey publishes the key (copying the input so the caller's slice is
// not aliased). An empty key clears it (⇒ fail-closed while the posture is on).
func setTrafficPseudonymKey(k []byte) {
	setTrafficPseudonymKeyPair(k, mintTrafficKeyID())
}

// setTrafficPseudonymKeyPair publishes a (key, key-id) pair atomically — one
// pointer store, so a reader can never pair a new key with an old id. The
// settings LOAD path uses this to restore the PERSISTED id (restart must not
// change the observable pseudonym generation); every other install mints a
// fresh id via setTrafficPseudonymKey.
func setTrafficPseudonymKeyPair(k []byte, id string) {
	if len(k) == 0 {
		trafficKeyGen.Add(1) // burn a generation so pooled hashers for the old key are stale
		trafficPseudonymKey.Store(nil)
		return
	}
	c := make([]byte, len(k))
	copy(c, k)
	trafficPseudonymKey.Store(&trafficKeyState{key: c, gen: trafficKeyGen.Add(1), id: id})
}

// getTrafficPseudonymKeyID returns the non-secret pseudonym-generation id
// ("" when no key is installed).
func getTrafficPseudonymKeyID() string {
	if s := trafficPseudonymKey.Load(); s != nil {
		return s.id
	}
	return ""
}

// mintTrafficKeyID mints a random 16-hex generation id, independent of any key
// material (deliberately NOT a key fingerprint — nothing derivable ever leaves
// the node). Falls back to a monotonic counter-based id if the entropy source
// fails, so a key install never silently loses its observable generation.
func mintTrafficKeyID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "gen-" + strconv.FormatUint(trafficKeyGen.Add(1), 10)
	}
	return hex.EncodeToString(b[:])
}

// getTrafficPseudonymKey returns the active key (nil if unset). Callers must treat the
// returned slice as read-only.
func getTrafficPseudonymKey() []byte {
	if s := trafficPseudonymKey.Load(); s != nil {
		return s.key
	}
	return nil
}

// rotateTrafficPseudonymKey publishes a FRESH 32-byte key unconditionally (unlike
// ensure, which no-ops when a key exists). Rotation changes all future tokens, so
// correlation with pre-rotation records is intentionally and irrecoverably broken —
// the caller surfaces that (audit + operator warning).
func rotateTrafficPseudonymKey() error {
	k := make([]byte, trafficKeyLen)
	if _, err := rand.Read(k); err != nil {
		return err
	}
	setTrafficPseudonymKey(k)
	return nil
}

// mintTrafficPseudonymKeyPair mints a fresh (key, generation-id) pair WITHOUT
// publishing it — the persist-before-apply redaction PUT builds its durable
// target from this and publishes only after the write lands (2E-B §B/§C).
func mintTrafficPseudonymKeyPair() ([]byte, string, error) {
	k := make([]byte, trafficKeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, "", err
	}
	return k, mintTrafficKeyID(), nil
}

// ensureTrafficPseudonymKey publishes a fresh 32-byte key iff none exists. Called on the
// enable path BEFORE persisting, so key generation and admin_settings durability are one
// transaction (the caller persists via SaveAdminSettings).
func ensureTrafficPseudonymKey() error {
	if len(getTrafficPseudonymKey()) == trafficKeyLen {
		return nil
	}
	k := make([]byte, trafficKeyLen)
	if _, err := rand.Read(k); err != nil {
		return err
	}
	setTrafficPseudonymKey(k)
	return nil
}

// pseudonymHexLen is how many hex characters of the MAC the token keeps — i.e. its
// first pseudonymHexLen/2 bytes. Load-bearing: it fixes the token's shape and its
// collision domain, and is the sole reason the whole 32-byte digest is not emitted.
const pseudonymHexLen = 12

// pseudonymHexDigits is the lowercase alphabet encodePseudonym emits, matching what
// encoding/hex produces (the token format is a persisted, correlatable identifier —
// uppercase would silently break correlation against already-written records).
const pseudonymHexDigits = "0123456789abcdef"

// pseudonymHasher is a pooled, key-bound HMAC. Constructing an HMAC is the dominant
// cost of pseudonymizeHost — hmac.New re-derives the ipad/opad key schedule (two SHA-256
// block compressions) and allocates two hash states on EVERY call — while the actual
// message is one short hostname. Reusing the hasher amortizes that schedule away:
// hash.Hash.Reset on a marshalable inner hash restores the precomputed ipad state
// instead of recomputing it.
//
// gen binds the hasher to the key generation it was constructed with, so a rotation
// invalidates pooled hashers rather than silently producing tokens under a superseded
// key. buf and sum are per-hasher scratch, which is what removes the remaining
// per-call allocations (the []byte(host) conversion and the digest destination).
type pseudonymHasher struct {
	gen uint64
	mac hash.Hash
	buf []byte
	sum [sha256.Size]byte
}

// pseudonymHasherScratchCap bounds the scratch buffer a pooled hasher may retain.
// The normalized input is a hostname (≤255 bytes in practice) but is not length-
// validated here, so a single outsized input must not pin an outsized buffer in the
// pool for the process lifetime.
const pseudonymHasherScratchCap = 512

var pseudonymHasherPool = sync.Pool{New: func() any { return new(pseudonymHasher) }}

// pseudonymizeHost returns the keyed-HMAC token for a host (host-only normalized so the
// port/case/trailing-dot cannot vary the token), or the fail-closed sentinel when the
// key is missing. Callers gate on the posture being ON, so this never returns the
// plaintext. An empty input stays empty (nothing to redact).
//
// The token is byte-identical to the previous hmac.New-per-call form; only the cost of
// producing it changed (pinned by TestTrafficRedaction_TokenMatchesReferenceHMAC).
func pseudonymizeHost(host string) string {
	if host == "" {
		return host
	}
	state := trafficPseudonymKey.Load()
	if state == nil || len(state.key) == 0 {
		return redactedSentinel // fail-closed: never plaintext
	}
	norm := hostutil.NormalizeHost(hostutil.StripHostPort(host))

	ph, _ := pseudonymHasherPool.Get().(*pseudonymHasher)
	if ph == nil {
		ph = new(pseudonymHasher) // unreachable (the pool's New is typed); never nil-deref the hot path
	}
	if ph.mac == nil || ph.gen != state.gen {
		// First use, or the key rotated under us: build a hasher for the CURRENT key.
		ph.mac = hmac.New(sha256.New, state.key)
		ph.gen = state.gen
	} else {
		ph.mac.Reset()
	}
	ph.buf = append(ph.buf[:0], norm...)
	ph.mac.Write(ph.buf)
	token := encodePseudonym(ph.mac.Sum(ph.sum[:0]))
	if cap(ph.buf) > pseudonymHasherScratchCap {
		ph.buf = nil
	}
	pseudonymHasherPool.Put(ph)
	return token
}

// encodePseudonym renders the token prefix plus the first pseudonymHexLen hex
// characters of mac. Equivalent to pseudonymPrefix+hex.EncodeToString(mac)[:12], but
// without hex-encoding all 32 digest bytes just to discard 26 of them.
func encodePseudonym(mac []byte) string {
	var out [len(pseudonymPrefix) + pseudonymHexLen]byte
	copy(out[:], pseudonymPrefix)
	for i := 0; i < pseudonymHexLen/2; i++ {
		out[len(pseudonymPrefix)+i*2] = pseudonymHexDigits[mac[i]>>4]
		out[len(pseudonymPrefix)+i*2+1] = pseudonymHexDigits[mac[i]&0x0f]
	}
	return string(out[:])
}

// redactDestinationHost pseudonymizes a top-level host iff the posture is on; otherwise
// returns it unchanged (byte-identical to today when off).
func redactDestinationHost(host string) string {
	if !decRedactHosts() {
		return host
	}
	return pseudonymizeHost(host)
}

// redactDestinationURI pseudonymizes the destination in a request URI when the posture
// is on, guaranteeing the plaintext host cannot survive anywhere in the result — the
// authority AND any copy echoed in the path (the URI-can't-leak-host invariant).
// plainHost is the known destination host from the same record; tokenHost is its
// precomputed token (avoids re-HMACing on the per-record path). The scrub is
// case-INSENSITIVE (so an upper/mixed-case copy cannot slip through) and
// boundary-aware (so "ex.com" is not rewritten inside "complex.com" and a prefix of a
// longer host is not partially mangled). When plainHost is empty (rare — the caller
// almost always knows the host) it falls back to the parsed authority, or the
// fail-closed sentinel if the URI cannot be parsed. Off ⇒ byte-identical.
//
// Known limitation: an IPv6-literal destination echoed in the path in a DIFFERENTLY
// bracketed form than the authority (e.g. bracketed authority, bare copy in the path)
// may survive the residual scrub. Extremely contrived (the client would echo its own
// destination) and the authority itself is always tokenized; documented, not fixed.
func redactDestinationURI(uri, plainHost, tokenHost string) string {
	if !decRedactHosts() || uri == "" {
		return uri
	}
	if plainHost == "" {
		if u, err := url.Parse(uri); err == nil && u.Hostname() != "" {
			return replaceHostFold(uri, u.Hostname(), pseudonymizeHost(u.Hostname()))
		}
		return redactedSentinel // unparseable + unknown host ⇒ never risk a leak
	}
	// tokenHost is pseudonymizeHost(plainHost); recompute defensively if the caller
	// passed the plaintext (posture-off callers never reach here).
	if tokenHost == "" || tokenHost == plainHost {
		tokenHost = pseudonymizeHost(plainHost)
	}
	// Scrub the host in BOTH the exact logged form (which may carry a :port) and the
	// port-stripped/normalized form. pseudonymizeHost normalizes away the port, so the
	// token stands for the PORTLESS host — meaning a non-default-port record
	// (host="patient.example.com:8443") whose path echoes the bare "patient.example.com"
	// would otherwise leave that echo in plaintext. Scrub the with-port form first (it is
	// longer, so the "host:port" authority is replaced whole), then the portless form to
	// catch any bare-host copy in the path.
	out := replaceHostFold(uri, plainHost, tokenHost)
	if portless := hostutil.StripHostPort(plainHost); portless != "" && portless != plainHost {
		out = replaceHostFold(out, portless, tokenHost)
	}
	return out
}

// hostByteClass reports whether b can be part of a hostname label — used to detect
// host boundaries so a whole-host match isn't found inside a larger token.
func hostByteClass(b byte) bool {
	return b == '-' || b == '.' ||
		(b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// replaceHostFold replaces every WHOLE-hostname (case-insensitive) occurrence of host
// in s with tok. "Whole" = not flanked by another host-label byte on either side, so
// "ex.com" does not match inside "complex.com" and "example.com" is not matched inside
// "example.com.evil". Preserves the original casing of the non-matched remainder.
func replaceHostFold(s, host, tok string) string {
	if host == "" {
		return s
	}
	ls, lh := strings.ToLower(s), strings.ToLower(host)
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
