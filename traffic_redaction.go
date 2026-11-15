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
	"net/url"

	"github.com/KidCarmi/Culvert/internal/hostutil"
	"github.com/KidCarmi/Culvert/internal/pseudonym"
)

// The keyed-HMAC engine, key state and token derivation live in internal/pseudonym
// (ADR-0044). This file keeps the posture gate (decRedactHosts) and the URI policy
// that decides WHEN and WHERE a token is applied, plus thin wrappers so existing
// call sites and tests keep their names.

const (
	redactedSentinel = pseudonym.Sentinel // fail-closed value: posture on, key missing
	trafficKeyLen    = pseudonym.KeyLen
)

// trafficPseudonymizer is the application's node-local pseudonymizer instance,
// owned by main. Published once at settings load and on the first enable.
var trafficPseudonymizer = pseudonym.New()

// setTrafficPseudonymKey publishes the key (an empty key clears it ⇒ fail-closed
// while the posture is on).
func setTrafficPseudonymKey(k []byte) { trafficPseudonymizer.Set(k) }

// setTrafficPseudonymKeyPair publishes a (key, key-id) pair atomically. The settings
// LOAD path uses this to restore the PERSISTED id.
func setTrafficPseudonymKeyPair(k []byte, id string) { trafficPseudonymizer.SetPair(k, id) }

// getTrafficPseudonymKeyID returns the non-secret pseudonym-generation id.
func getTrafficPseudonymKeyID() string { return trafficPseudonymizer.KeyID() }

// mintTrafficKeyID mints a random generation id independent of key material.
//
// It routes through MintID, not MintPair: MintPair also reads a 32-byte KEY that
// this caller discards, and its error leg returns an EMPTY id — which
// getTrafficPseudonymKeyID and the admin redaction surface cannot tell apart
// from "no key is installed". The only caller is applyAdminTrafficPseudonym's
// legacy-upgrade leg (a persisted key with no persisted id), where publishing an
// empty id beside a VALID key is exactly the state the 2E-B generation identity
// exists to rule out.
//
// No observable behaviour changed by this: crypto/rand.Read cannot return an
// error on the pinned toolchain (it crashes the process instead —
// go.dev/issue/66821), so MintPair's zero-id leg was unreachable too. The point
// is the shape of the contract, not a live bug: an id-only caller should not be
// one stdlib change away from publishing the keyless sentinel, and should not
// spend a key to get an id.
func mintTrafficKeyID() string { return trafficPseudonymizer.MintID() }

// getTrafficPseudonymKey returns the active key (nil if unset); read-only.
func getTrafficPseudonymKey() []byte { return trafficPseudonymizer.Key() }

// rotateTrafficPseudonymKey publishes a FRESH key unconditionally; the caller
// surfaces that correlation with pre-rotation records is broken (audit + warning).
func rotateTrafficPseudonymKey() error { return trafficPseudonymizer.Rotate() }

// mintTrafficPseudonymKeyPair mints a (key, id) pair WITHOUT publishing it — the
// persist-before-apply redaction PUT publishes only after the write lands.
func mintTrafficPseudonymKeyPair() (key []byte, keyID string, err error) {
	return trafficPseudonymizer.MintPair()
}

// ensureTrafficPseudonymKey publishes a fresh key iff none exists, BEFORE
// persisting, so key generation and admin_settings durability are one transaction.
func ensureTrafficPseudonymKey() error { return trafficPseudonymizer.Ensure() }

// pseudonymizeHost returns the keyed token for a host, or the fail-closed sentinel
// when the key is missing. Callers gate on the posture being ON.
func pseudonymizeHost(host string) string { return trafficPseudonymizer.Pseudonymize(host) }

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
			return pseudonym.ReplaceHostFold(uri, u.Hostname(), pseudonymizeHost(u.Hostname()))
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
	out := pseudonym.ReplaceHostFold(uri, plainHost, tokenHost)
	if portless := hostutil.StripHostPort(plainHost); portless != "" && portless != plainHost {
		out = pseudonym.ReplaceHostFold(out, portless, tokenHost)
	}
	return out
}
