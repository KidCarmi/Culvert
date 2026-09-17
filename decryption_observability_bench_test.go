package main

// Per-session cost of the ADR-0011 decryption-outcome projection (Performance
// Guardian).
//
// toBlock and recordDecryptSession run once per CONNECT tunnel close —
// recordDecryptSession UNCONDITIONALLY (recordTunnelCloseGatedDec counts a
// session even for a quiet rule), toBlock for every logged close and again per
// inner request on an inspected session that opts into LogFullURI. For an
// enterprise gateway, where effectively all traffic is HTTPS, that is the
// tunnel hot path.
//
// Both reach the same helper, decEnumOr. It used to take two INTERFACE
// parameters; every decryptobs enum is a named string type, so each call boxed
// both arguments and a non-empty string box is a heap allocation. See the
// contract comment above decEnumOr in decryption_observability.go.
//
// EVERYTHING HERE MEASURES THE PRODUCTION FUNCTIONS. The one exception is
// decEnumOrLegacy and legacyOutcomeToBlock, which deliberately freeze the
// PRE-CHANGE interface shape so the before/after comparison stays reproducible
// in-tree on any runner — the convention
// BenchmarkHTTPForward_LegacyClientPerRequest and
// BenchmarkPolicyDecisionLine_Legacy already follow. They are the baseline,
// never the thing under test.
//
//	go test -run '^$' -bench 'BenchmarkDecryptionProjection' -benchmem -count=6 .

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/decryptobs"
	"github.com/KidCarmi/Culvert/internal/logstore"
)

// decEnumOrLegacy is the verbatim pre-change body: two interface parameters.
// It is the allocation baseline, and the oracle the differential test compares
// the production generic against.
func decEnumOrLegacy(v, fallback decEnum) string {
	if v.Valid() {
		return v.String()
	}
	return fallback.String()
}

// legacyOutcomeToBlock reproduces toBlock's pre-change projection verbatim,
// routing every enum through decEnumOrLegacy. Field-for-field identical to the
// production toBlock so the only difference measured is the boxing.
func legacyOutcomeToBlock(o DecryptionOutcome, redact bool) *logstore.DecryptionBlock {
	return &logstore.DecryptionBlock{
		SchemaVersion:   decBlockSchemaVersion,
		Outcome:         decEnumOrLegacy(o.Outcome, decryptobs.OutcomeNotDecrypted),
		DecisionSource:  decEnumOrLegacy(o.DecisionSource, decryptobs.DecisionNonTLSFallback),
		RuleID:          o.RuleID,
		RuleName:        o.RuleName,
		ProfileID:       o.ProfileID,
		ProfileName:     o.ProfileName,
		Host:            redactHost(o.Host, redact),
		SNI:             redactHost(o.SNI, redact),
		TLSVersion:      decEnumOrLegacy(o.TLSVersion, decryptobs.TLSVersionUnknown),
		Cipher:          o.Cipher,
		ALPN:            decEnumOrLegacy(o.ALPN, decryptobs.ALPNNone),
		CertVerify:      decEnumOrLegacy(o.CertVerify, decryptobs.CertVerifyNotChecked),
		FailStage:       decEnumOrLegacy(o.FailStage, decryptobs.FailStageNone),
		FailCategory:    decEnumOrLegacy(o.FailCategory, decryptobs.FailCategoryNone),
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

// decBenchInspected is the fixture inspectedOutcome produces: all seven bounded
// enums populated. This is the WORST case and the one an SSL-inspecting gateway
// pays on every tunnel.
//
// Held in a package-level var, not built from constants at the call site: Go
// boxes a constant into an interface at compile time into read-only data, so a
// constant fixture would understate the legacy shape and make the fix look
// smaller than it is (the trap plArgs documents for the policy decision line).
var decBenchInspected = DecryptionOutcome{
	Outcome:        decryptobs.OutcomeInspected,
	DecisionSource: decryptobs.DecisionPolicyInspect,
	Host:           "files.example.com",
	TLSVersion:     decryptobs.TLSVersion13,
	Cipher:         "TLS_AES_128_GCM_SHA256",
	ALPN:           decryptobs.ALPNHTTP11,
	CertVerify:     decryptobs.CertVerifyVerified,
	FailStage:      decryptobs.FailStageNone,
	FailCategory:   decryptobs.FailCategoryNone,
	RuleID:         "01J0000000000000000000000",
	RuleName:       "corp-saas-inspect",
}

// decBenchBypassed is the fixture bypassOutcome produces: only Outcome and
// DecisionSource carry a value, the rest coerce to their sentinels. This is the
// common case on a mixed-policy gateway, and the shape whose zero-value fields
// made the waste easy to miss — an empty string boxes for free.
var decBenchBypassed = DecryptionOutcome{
	Outcome:        decryptobs.OutcomeBypassManual,
	DecisionSource: decryptobs.DecisionManualSSLBypass,
	Host:           "updates.example.com",
}

func BenchmarkDecryptionProjection_ToBlockLegacy_Inspected(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		decSink = legacyOutcomeToBlock(decBenchInspected, false)
	}
}

func BenchmarkDecryptionProjection_ToBlock_Inspected(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		decSink = decBenchInspected.toBlock(false)
	}
}

func BenchmarkDecryptionProjection_ToBlockLegacy_Bypassed(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		decSink = legacyOutcomeToBlock(decBenchBypassed, false)
	}
}

func BenchmarkDecryptionProjection_ToBlock_Bypassed(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		decSink = decBenchBypassed.toBlock(false)
	}
}

// BenchmarkDecryptionProjection_SessionMetric measures the other per-session
// consumer: three decEnumOr calls feeding the coverage counter. It runs on EVERY
// tunnel close, including quiet-rule closes that write no feed entry at all.
func BenchmarkDecryptionProjection_SessionMetricLegacy(b *testing.B) {
	o := decBenchInspected
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		strSinks[0] = decEnumOrLegacy(o.Outcome, decryptobs.OutcomeNotDecrypted)
		strSinks[1] = decEnumOrLegacy(o.DecisionSource, decryptobs.DecisionNonTLSFallback)
		strSinks[2] = decEnumOrLegacy(o.TLSVersion, decryptobs.TLSVersionUnknown)
	}
}

func BenchmarkDecryptionProjection_SessionMetric(b *testing.B) {
	o := decBenchInspected
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		strSinks[0] = decEnumOr(o.Outcome, decryptobs.OutcomeNotDecrypted)
		strSinks[1] = decEnumOr(o.DecisionSource, decryptobs.DecisionNonTLSFallback)
		strSinks[2] = decEnumOr(o.TLSVersion, decryptobs.TLSVersionUnknown)
	}
}

// Parallel arms: a gateway terminates tunnels on every core at once, and an
// allocation-heavy projection costs more than its own ns there (allocator and GC
// pressure are shared). Each worker writes its OWN sink — a single shared package
// sink would false-share one cache line per iteration and become the thing being
// measured (the trap internal/blocklist's hot-read benchmark documents).
func BenchmarkDecryptionProjection_ToBlockLegacyParallel(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(p *testing.PB) {
		var local *logstore.DecryptionBlock
		for p.Next() {
			local = legacyOutcomeToBlock(decBenchInspected, false)
		}
		_ = local
	})
}

func BenchmarkDecryptionProjection_ToBlockParallel(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(p *testing.PB) {
		var local *logstore.DecryptionBlock
		for p.Next() {
			local = decBenchInspected.toBlock(false)
		}
		_ = local
	})
}

// Benchmark sinks. strSinks is an ARRAY with one slot per call, not a single
// string, and that is load-bearing rather than a lint workaround: the metric
// arms make THREE decEnumOr calls because recordDecryptSession makes three, and
// writing all three into one variable makes the first two assignments
// ineffectual — a dead store the compiler is free to eliminate along with the
// call that produced it, which would silently reduce the benchmark to measuring
// ONE call in both arms and understate the very cost being compared. Distinct
// package-level slots keep every result live. (Caught by golangci-lint's
// ineffassign on PR #1416.)
var (
	decSink  *logstore.DecryptionBlock
	strSinks [3]string
)
