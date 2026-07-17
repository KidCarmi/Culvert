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
	"encoding/hex"

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
