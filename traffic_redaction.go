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
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

const (
	redactedSentinel = "redacted" // fail-closed value: posture on, key missing
	pseudonymPrefix  = "h_"       // keyed-HMAC destination token prefix (shared with dec.*)
	trafficKeyLen    = 32
)

// trafficPseudonymKey holds the node-local 32-byte HMAC key. atomic.Pointer so the
// per-record redaction reads it lock-free; published once at settings load and on the
// first enable. The pointee is never mutated after publish (a new slice is stored).
var trafficPseudonymKey atomic.Pointer[[]byte]

// setTrafficPseudonymKey publishes the key (copying the input so the caller's slice is
// not aliased). An empty key clears it (⇒ fail-closed while the posture is on).
func setTrafficPseudonymKey(k []byte) {
	if len(k) == 0 {
		trafficPseudonymKey.Store(nil)
		return
	}
	c := make([]byte, len(k))
	copy(c, k)
	trafficPseudonymKey.Store(&c)
}

// getTrafficPseudonymKey returns the active key (nil if unset). Callers must treat the
// returned slice as read-only.
func getTrafficPseudonymKey() []byte {
	if p := trafficPseudonymKey.Load(); p != nil {
		return *p
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

// pseudonymizeHost returns the keyed-HMAC token for a host (host-only normalized so the
// port/case/trailing-dot cannot vary the token), or the fail-closed sentinel when the
// key is missing. Callers gate on the posture being ON, so this never returns the
// plaintext. An empty input stays empty (nothing to redact).
func pseudonymizeHost(host string) string {
	if host == "" {
		return host
	}
	key := getTrafficPseudonymKey()
	if len(key) == 0 {
		return redactedSentinel // fail-closed: never plaintext
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte(hostutil.NormalizeHost(hostutil.StripHostPort(host))))
	return pseudonymPrefix + hex.EncodeToString(h.Sum(nil))[:12]
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
	return replaceHostFold(uri, plainHost, tokenHost)
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
