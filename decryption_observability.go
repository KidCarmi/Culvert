package main

// decryption_observability.go — ADR-0011 Phase 1: the canonical DecryptionOutcome value
// and its projection onto the shared log Entry's nested "dec" block.
//
// This is the "assembled once, projected onto each surface" model: a DecryptionOutcome is
// built from values already computed on the decision path (the resolveSSLAction decision,
// the matched rule, the resolved decryption profile, the completed handshake, the
// autoexclude classifier reason) and then flattened via toBlock() into the wire type on
// logstore.Entry. Nothing populates it yet — the record-wiring at the tunnel-close /
// decision points is the next ADR-0011 slice, so the feature is still dark and the wire
// stays byte-identical (Entry.Dec == nil).

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"strings"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
	"github.com/KidCarmi/Culvert/internal/decryptobs"
	"github.com/KidCarmi/Culvert/internal/logstore"
)

// decBlockSchemaVersion is the independent schema version of the "dec" block (distinct
// from Entry.SchemaVersion, which versions the auth_* block). Bump only on a breaking
// change to the dec field set.
const decBlockSchemaVersion = 1

// DecryptionOutcome is the single canonical decryption-decision value for a session,
// carrying the TYPED (validated) enum vocabulary from internal/decryptobs. It is
// projected onto the wire via toBlock(); it never serializes directly, so the typed
// fields cannot leak an unbounded value onto a record.
type DecryptionOutcome struct {
	Outcome        decryptobs.Outcome
	DecisionSource decryptobs.DecisionSource

	RuleID      string
	RuleName    string
	ProfileID   string
	ProfileName string

	Host string // raw host; redacted via redactDecField at projection time
	SNI  string // raw SNI; redacted likewise

	TLSVersion   decryptobs.TLSVersion
	Cipher       string
	ALPN         decryptobs.ALPN
	CertVerify   decryptobs.CertVerify
	FailStage    decryptobs.FailStage
	FailCategory decryptobs.FailCategory

	// ExclReason reuses the engine's bounded reason enum. The empty value is the explicit
	// "no exclusion" member (ADR-0011 red-team: autoexclude.Reason PLUS an empty sentinel).
	ExclReason autoexclude.Reason
	ExclScope  string

	CacheConsulted bool
	CacheHit       bool
	CacheLearned   bool
	Rescued        bool

	ScopeRuleCount  int
	NodeID          string
	CertFingerprint string // bounded SPKI/cert SHA-256 hash (already hashed by the caller; never a raw subject)
}

// decEnum is any bounded decryptobs enum: it can validate its own membership and
// render its wire form. Used by decEnumOr to keep only-bounded values on a record.
type decEnum interface {
	Valid() bool
	String() string
}

// decEnumOr returns v.String() when v is a valid member, else the fallback's string.
// This is the ADR-0011 bounded-SIEM guard at the projection boundary (PR #786 Codex
// review): a zero-value or cast enum — e.g. a FailStage left at "" instead of "none" by
// a caller that only sets fields on failure — would otherwise reach the record verbatim
// and break dashboards/filters that expect a closed vocabulary. Coercing to the type's
// sentinel keeps the wire vocabulary closed even if a future caller under-populates the
// struct. (Outcome/failure/cert/tls fields all have a natural sentinel; ALPN's is the
// valid empty member.)
func decEnumOr(v, fallback decEnum) string {
	if v.Valid() {
		return v.String()
	}
	return fallback.String()
}

// toBlock projects the typed outcome into the plain-scalar wire block. Every enum passes
// through decEnumOr so only BOUNDED values ever reach a record (an unset/invalid enum
// coerces to its sentinel, never "" or a cast token); host/SNI pass through redactHost
// when redaction is enabled. A block produced here is always fully populated, so explicit
// false/none/0 fields are meaningful (never "path forgot to set it").
//
// DecisionSource has no neutral member (a block is only built on a real decision, so the
// wiring always sets it); an invalid one coerces to non_tls_fallback — the most
// conservative "not a real decrypt decision" source — so the field stays in-vocabulary
// rather than emitting "".
func (o DecryptionOutcome) toBlock(redact bool) *logstore.DecryptionBlock {
	return &logstore.DecryptionBlock{
		SchemaVersion:   decBlockSchemaVersion,
		Outcome:         decEnumOr(o.Outcome, decryptobs.OutcomeNotDecrypted),
		DecisionSource:  decEnumOr(o.DecisionSource, decryptobs.DecisionNonTLSFallback),
		RuleID:          o.RuleID,
		RuleName:        o.RuleName,
		ProfileID:       o.ProfileID,
		ProfileName:     o.ProfileName,
		Host:            redactHost(o.Host, redact),
		SNI:             redactHost(o.SNI, redact),
		TLSVersion:      decEnumOr(o.TLSVersion, decryptobs.TLSVersionUnknown),
		Cipher:          o.Cipher,
		ALPN:            decEnumOr(o.ALPN, decryptobs.ALPNNone),
		CertVerify:      decEnumOr(o.CertVerify, decryptobs.CertVerifyNotChecked),
		FailStage:       decEnumOr(o.FailStage, decryptobs.FailStageNone),
		FailCategory:    decEnumOr(o.FailCategory, decryptobs.FailCategoryNone),
		ExclReason:      decExclReason(o.ExclReason),
		ExclScope:       o.ExclScope,
		CacheConsulted:  o.CacheConsulted,
		CacheHit:        o.CacheHit,
		CacheLearned:    o.CacheLearned,
		Rescued:         o.Rescued,
		ScopeRuleCount:  o.ScopeRuleCount,
		NodeID:          o.NodeID,
		CertFingerprint: o.CertFingerprint,
	}
}

// inspectedOutcome builds the ADR-0011 DecryptionOutcome for a session that was
// successfully MITM-decrypted and is being inspected. It is built ONCE per tunnel, after
// BOTH handshakes complete, from the ORIGIN (upstream) TLS parameters — the real
// encrypted session Culvert broke into — and reused for every inner-request log entry
// (opt-in via the rule's LogFullURI, so most inspected sessions build it but never emit
// it). The TLS/cipher/ALPN come from the completed upstream ConnectionState; CertVerify
// reflects whether upstream verification was skipped for the matched rule (dec.SkipVerify);
// CacheConsulted/ProfileID carry the fail-open scope read (hit-or-miss) from resolveSSLDecision.
// FailStage/FailCategory stay `none` — a decrypted, inspected session has no failure.
func inspectedOutcome(dec sslResolution, hostOnly string, upstreamCS tls.ConnectionState, match *PolicyMatch) *DecryptionOutcome {
	// CertVerify must reflect the EFFECTIVE upstream verification the origin leg actually
	// performed — resolveInspectSkipVerify, the same resolver upstreamInspectTLSConfigForMatch
	// feeds. A decryption profile's CertVerification ("skip"/"strict"/"permissive") overrides
	// the rule's inline dec.SkipVerify, so deriving from dec.SkipVerify alone would record the
	// opposite of what happened (Codex #801). resolveInspectSkipVerify is deterministic in
	// match, so this reproduces the handshake's effective skip without a second config build.
	certVerify := decryptobs.CertVerifyVerified
	if resolveInspectSkipVerify(match, dec.SkipVerify) {
		certVerify = decryptobs.CertVerifySkipped
	}
	o := &DecryptionOutcome{
		Outcome:        decryptobs.OutcomeInspected,
		DecisionSource: dec.Source, // policy_inspect on the inspect dispatch path
		Host:           hostOnly,
		TLSVersion:     tlsVersionEnum(upstreamCS.Version),
		Cipher:         tls.CipherSuiteName(upstreamCS.CipherSuite),
		ALPN:           alpnEnum(upstreamCS.NegotiatedProtocol),
		CertVerify:     certVerify,
		FailStage:      decryptobs.FailStageNone,
		FailCategory:   decryptobs.FailCategoryNone,
		ProfileID:      dec.ScopeID,
		CacheConsulted: dec.Consulted,
	}
	if match != nil && match.Rule != nil {
		o.RuleID = match.Rule.ID
		o.RuleName = match.Rule.Name
	}
	return o
}

// originInspectFailureOutcome builds the ADR-0011 DecryptionOutcome for an UPSTREAM
// (origin-leg) inspect-handshake FAILURE — the session was attempted and could not be
// decrypted, so it 502s. The bounded (FailStage, FailCategory, DecisionSource) come from
// classifyOriginFailure; the raw error string is NEVER stored (only the categorical
// result). TLS fields stay at sentinels (no negotiated session). Used for the failure
// taxonomy metric; the per-session record projection is a later slice.
func originInspectFailureOutcome(err error, hostOnly string, dec sslResolution, match *PolicyMatch) *DecryptionOutcome {
	stage, category, source := classifyOriginFailure(err)
	certVerify := decryptobs.CertVerifyNotChecked
	if category == decryptobs.FailCategoryCertificate {
		certVerify = decryptobs.CertVerifyUnknown // coarse; the fine cert sub-status is a record-projection follow-up
	}
	o := &DecryptionOutcome{
		Outcome:        decryptobs.OutcomeFailed,
		DecisionSource: source,
		Host:           hostOnly,
		CertVerify:     certVerify,
		FailStage:      stage,
		FailCategory:   category,
		ProfileID:      dec.ScopeID,
		CacheConsulted: dec.Consulted,
	}
	if match != nil && match.Rule != nil {
		o.RuleID = match.Rule.ID
		o.RuleName = match.Rule.Name
	}
	return o
}

// clientInspectFailureOutcome builds the ADR-0011 DecryptionOutcome for a CLIENT-leg
// (forged-leaf) inspect-handshake FAILURE — the client rejected our leaf (pinning) or its
// hello was incompatible. Same sentinel/redaction posture as the origin builder.
func clientInspectFailureOutcome(err error, hostOnly string, dec sslResolution, match *PolicyMatch) *DecryptionOutcome {
	stage, category := classifyClientFailure(err)
	o := &DecryptionOutcome{
		Outcome: decryptobs.OutcomeFailed,
		// A client-leg (forged-leaf) failure always blocks the current session (502); there
		// is no cert-verify-block source on this leg.
		DecisionSource: decryptobs.DecisionNoFailOpen502,
		Host:           hostOnly,
		CertVerify:     decryptobs.CertVerifyNotChecked,
		FailStage:      stage,
		FailCategory:   category,
		ProfileID:      dec.ScopeID,
		CacheConsulted: dec.Consulted,
	}
	if match != nil && match.Rule != nil {
		o.RuleID = match.Rule.ID
		o.RuleName = match.Rule.Name
	}
	return o
}

// classifyOriginFailure maps an upstream (origin-leg) inspect-handshake error to the
// bounded ADR-0011 (FailStage, FailCategory, DecisionSource). It reuses isOriginCertVerifyErr
// for the certificate class (a Block decision) and matches the same narrow, deliberate TLS
// error strings as the autoexclude classifier — but here EVERY failure gets a category, so
// unknown errors fail SAFE to (upstream_handshake, other, no_fail_open_502): an
// unrecognised error is never mislabelled as a specific class. The raw string never leaves
// this function.
func classifyOriginFailure(err error) (decryptobs.FailStage, decryptobs.FailCategory, decryptobs.DecisionSource) {
	if err == nil {
		return decryptobs.FailStageUpstreamHandshake, decryptobs.FailCategoryOther, decryptobs.DecisionNoFailOpen502
	}
	if isOriginCertVerifyErr(err) {
		// A verified-and-rejected origin cert is a Block decision, not a fail-open 502.
		return decryptobs.FailStageCertVerify, decryptobs.FailCategoryCertificate, decryptobs.DecisionCertVerifyBlock
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "certificate required"):
		return decryptobs.FailStageUpstreamHandshake, decryptobs.FailCategoryClientCertRequired, decryptobs.DecisionNoFailOpen502
	case containsAny(msg, "server selected unsupported protocol version", "no supported versions satisfy", "protocol version not supported"):
		return decryptobs.FailStageUpstreamHandshake, decryptobs.FailCategoryVersion, decryptobs.DecisionNoFailOpen502
	case strings.Contains(msg, "no cipher suite supported"):
		return decryptobs.FailStageUpstreamHandshake, decryptobs.FailCategoryCipher, decryptobs.DecisionNoFailOpen502
	case containsAny(msg, "i/o timeout", "deadline exceeded", "timed out"):
		return decryptobs.FailStageUpstreamHandshake, decryptobs.FailCategoryTimeout, decryptobs.DecisionNoFailOpen502
	case containsAny(msg, "handshake failure", "no application protocol", "unexpected message", "protocol version"):
		return decryptobs.FailStageUpstreamHandshake, decryptobs.FailCategoryProtocol, decryptobs.DecisionNoFailOpen502
	}
	return decryptobs.FailStageUpstreamHandshake, decryptobs.FailCategoryOther, decryptobs.DecisionNoFailOpen502
}

// classifyClientFailure maps a client-leg (forged-leaf) handshake error to the bounded
// ADR-0011 (FailStage, FailCategory). It reuses classifyClientInspectFailure for the
// pinning class, then mirrors the origin classifier's protocol/version/timeout buckets so
// a known client-leg failure is not lost to `other`: the native-ALPN path can force an
// h2-only client onto http/1.1 against an h1-only origin, whose handshake then fails with
// `no application protocol` / `requested unsupported application protocols` — a genuine
// PROTOCOL failure, not other (Codex #812). Anything unrecognised still fails safe to
// (client_hello, other). The DecisionSource is always no_fail_open_502 on this leg, so the
// builder sets it directly.
func classifyClientFailure(err error) (decryptobs.FailStage, decryptobs.FailCategory) {
	if err == nil {
		return decryptobs.FailStageClientHello, decryptobs.FailCategoryOther
	}
	if _, pinned := classifyClientInspectFailure(err); pinned {
		return decryptobs.FailStageClientLeafReject, decryptobs.FailCategoryClientPinned
	}
	msg := strings.ToLower(err.Error())
	switch {
	case containsAny(msg, "i/o timeout", "deadline exceeded", "timed out"):
		return decryptobs.FailStageClientHello, decryptobs.FailCategoryTimeout
	case containsAny(msg, "no supported versions satisfy", "protocol version not supported"):
		return decryptobs.FailStageClientHello, decryptobs.FailCategoryVersion
	case containsAny(msg, "no application protocol", "unsupported application protocol",
		"requested unsupported application protocols", "handshake failure", "unexpected message"):
		return decryptobs.FailStageClientHello, decryptobs.FailCategoryProtocol
	}
	return decryptobs.FailStageClientHello, decryptobs.FailCategoryOther
}

// nonTLSFallbackOutcome builds the ADR-0011 DecryptionOutcome for a CONNECT that reached
// the inspect path but whose CLIENT sent a non-TLS protocol (SSH/RDP/raw), so Culvert
// could not MITM and fell back to a raw byte relay. The session was NOT decrypted; the
// source is non_tls_fallback and the TLS/cert/fail fields stay at their sentinels (no
// client handshake happened) — the honest "we did not inspect this" value, matching the
// bypass path's sentinel philosophy.
func nonTLSFallbackOutcome(hostOnly string) *DecryptionOutcome {
	return &DecryptionOutcome{
		Outcome:        decryptobs.OutcomeNotDecrypted,
		DecisionSource: decryptobs.DecisionNonTLSFallback,
		Host:           hostOnly,
		FailStage:      decryptobs.FailStageNone,
		FailCategory:   decryptobs.FailCategoryNone,
	}
}

// tlsVersionEnum maps a crypto/tls version constant to the bounded ADR-0011 TLSVersion
// enum. Anything outside the two versions Culvert inspects (incl. 0 = no handshake) is
// `unknown` — the enum is bounded on purpose (§2.2), so a legacy/unexpected version never
// widens the recorded vocabulary.
func tlsVersionEnum(v uint16) decryptobs.TLSVersion {
	switch v {
	case tls.VersionTLS12:
		return decryptobs.TLSVersion12
	case tls.VersionTLS13:
		return decryptobs.TLSVersion13
	}
	return decryptobs.TLSVersionUnknown
}

// alpnEnum maps a negotiated ALPN protocol string to the bounded ADR-0011 ALPN enum.
// The empty string is the valid "no ALPN negotiated" member; any unrecognised protocol
// also coerces to the empty member so the recorded vocabulary stays closed.
func alpnEnum(proto string) decryptobs.ALPN {
	switch proto {
	case "h2":
		return decryptobs.ALPNH2
	case "http/1.1":
		return decryptobs.ALPNHTTP11
	}
	return decryptobs.ALPNNone
}

// decExclReason bounds the exclusion reason: autoexclude.Reason has no Valid method, so
// membership is checked against the engine's canonical set. The empty value is the valid
// "no exclusion" member (kept as ""); any other non-member coerces to "" as well, so a
// cast/garbage reason never reaches the record.
func decExclReason(r autoexclude.Reason) string {
	if r == "" {
		return "" // explicit "no exclusion"
	}
	for _, ok := range autoexclude.AllReasons() {
		if r == ok {
			return string(r)
		}
	}
	return "" // non-member ⇒ treat as no exclusion rather than emit an unbounded token
}

// redactHost applies the ADR-0011 §4 host/SNI privacy posture. When redaction is OFF it
// returns the value unchanged. When ON it redacts by HASHING to a fixed-length token
// (12 hex chars of a SHA-256), NOT by omission — so the field stays present and joinable
// across records for the same host while the plaintext host is never recorded (PR #758
// red-team: host is redacted by a present sentinel, not an absent field). An empty input
// stays empty (nothing to redact).
func redactHost(v string, redact bool) string {
	if !redact || v == "" {
		return v
	}
	sum := sha256.Sum256([]byte(v))
	return "h_" + hex.EncodeToString(sum[:])[:12]
}
