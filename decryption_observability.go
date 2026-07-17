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

// toBlock projects the typed outcome into the plain-scalar wire block. Enum fields go
// through String() so only bounded values ever reach a record; host/SNI pass through
// redactHost when redaction is enabled. A block produced here is always fully populated,
// so explicit false/none/0 fields are meaningful (never "path forgot to set it").
func (o DecryptionOutcome) toBlock(redact bool) *logstore.DecryptionBlock {
	return &logstore.DecryptionBlock{
		SchemaVersion:   decBlockSchemaVersion,
		Outcome:         o.Outcome.String(),
		DecisionSource:  o.DecisionSource.String(),
		RuleID:          o.RuleID,
		RuleName:        o.RuleName,
		ProfileID:       o.ProfileID,
		ProfileName:     o.ProfileName,
		Host:            redactHost(o.Host, redact),
		SNI:             redactHost(o.SNI, redact),
		TLSVersion:      o.TLSVersion.String(),
		Cipher:          o.Cipher,
		ALPN:            o.ALPN.String(),
		CertVerify:      o.CertVerify.String(),
		FailStage:       o.FailStage.String(),
		FailCategory:    o.FailCategory.String(),
		ExclReason:      string(o.ExclReason),
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
