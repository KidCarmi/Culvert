// Package decryptobs is the bounded-enum vocabulary for Culvert's decryption-
// observability model (ADR-0011). It holds ONLY closed, categorical value types — the
// canonical DecryptionOutcome record, its projections (request/tunnel record, metrics,
// API, GUI), and its SIEM export all draw their categorical fields from here, so every
// surface speaks one vocabulary and no categorical field can drift between them.
//
// The package adds NO behavior and is unused at runtime until a later ADR-0011 slice
// wires the record onto the shared log Entry. Every type is a string enum with an
// explicit All<Type> set, a String, and a Valid method; decryptobs_test.go pins each
// set exhaustively so adding a value is a deliberate, tested change — the same
// drift-guard discipline as autoexclude.allReasons and uiRoutes.
//
// The values are the ADR-0011 §2.2 taxonomy. FailCategory deliberately mirrors the
// PAN-OS Decryption "Error-Index" classes so operators migrating from PAN-OS recognise
// it. These are RECORD/label vocabularies only — raw Go error strings never appear here
// (that stays out of the record and out of metrics per the CWE-117 posture).
package decryptobs

// Outcome is what happened to a session's decryption decision (ADR-0011 §2.2, 6 values).
type Outcome string

const (
	// OutcomeInspected — the session was MITM-decrypted and inspected.
	OutcomeInspected Outcome = "inspected"
	// OutcomeBypassManual — a decryption-profile / SSL-bypass rule chose not to inspect.
	OutcomeBypassManual Outcome = "bypass_manual"
	// OutcomeBypassLearned — the adaptive auto-exclusion cache bypassed this session.
	OutcomeBypassLearned Outcome = "bypass_learned"
	// OutcomeRescued — a live-rescue re-dialled the session in bypass after an inspect failure.
	OutcomeRescued Outcome = "rescued"
	// OutcomeFailed — decryption was attempted and failed (see FailStage/FailCategory).
	OutcomeFailed Outcome = "failed"
	// OutcomeNotDecrypted — no decryption decision applied (plain-HTTP / non-TLS / no decision).
	OutcomeNotDecrypted Outcome = "not_decrypted"
)

// AllOutcomes is the closed set of Outcome values, in canonical order.
//
// READ-ONLY: exported so callers can range it (e.g. to pre-register bounded metric
// labels). Do NOT mutate or reassign it — Valid() does NOT consult it (Valid is a
// compile-time switch, immune to slice mutation), and decryptobs_parity_test.go pins
// this slice against the declared consts, but a mutation would still corrupt any
// consumer that ranges it. Treat every All<Type> var as an immutable literal.
var AllOutcomes = []Outcome{
	OutcomeInspected, OutcomeBypassManual, OutcomeBypassLearned,
	OutcomeRescued, OutcomeFailed, OutcomeNotDecrypted,
}

func (o Outcome) String() string { return string(o) }

// Valid reports whether o is a member of the closed set. It is a compile-time switch
// over the constants, NOT a scan of AllOutcomes — so membership cannot be changed at
// runtime by mutating or reassigning the exported slice (defence-in-depth for the
// bounded-label contract; PR #758 review).
func (o Outcome) Valid() bool {
	switch o {
	case OutcomeInspected, OutcomeBypassManual, OutcomeBypassLearned,
		OutcomeRescued, OutcomeFailed, OutcomeNotDecrypted:
		return true
	}
	return false
}

// DecisionSource is which part of the pipeline made the decryption decision
// (ADR-0011 §2.2, 7 values).
type DecisionSource string

const (
	// DecisionPolicyInspect — a policy rule / decryption profile selected inspection.
	DecisionPolicyInspect DecisionSource = "policy_inspect"
	// DecisionManualSSLBypass — an explicit SSL-bypass match.
	// #nosec G101 -- categorical enum value, not a credential ("ssl_bypass" contains "pass", which trips gosec's hardcoded-credential pattern)
	DecisionManualSSLBypass DecisionSource = "manual_ssl_bypass"
	// DecisionAutoexcludeCache — a learned exclusion in the fail-open cache bypassed it.
	DecisionAutoexcludeCache DecisionSource = "autoexclude_cache"
	// DecisionAutoexcludeRescue — a live-rescue on the inspect-failure path.
	DecisionAutoexcludeRescue DecisionSource = "autoexclude_rescue"
	// DecisionNoFailOpen502 — inspect failed under a fail-CLOSE rule; the session was blocked (502).
	DecisionNoFailOpen502 DecisionSource = "no_fail_open_502"
	// DecisionCertVerifyBlock — the origin certificate failed verification and was blocked.
	DecisionCertVerifyBlock DecisionSource = "cert_verify_block"
	// DecisionNonTLSFallback — the CONNECT target was not TLS; the non-TLS relay fallback ran.
	DecisionNonTLSFallback DecisionSource = "non_tls_fallback"
	// DecisionInspectUnavailable — a rule selected inspection but the MITM CA was not
	// ready (no root CA / passphrase), so handleTunnel silently degraded to bypass
	// (proxy_tunnel.go). A distinct source so this MISCONFIGURATION is visible on the
	// coverage view rather than hiding inside manual bypass (PR #758 red-team, model gap).
	DecisionInspectUnavailable DecisionSource = "inspect_unavailable"
)

// AllDecisionSources is the closed set of DecisionSource values, in canonical order.
// READ-ONLY — see the AllOutcomes note.
var AllDecisionSources = []DecisionSource{
	DecisionPolicyInspect, DecisionManualSSLBypass, DecisionAutoexcludeCache,
	DecisionAutoexcludeRescue, DecisionNoFailOpen502, DecisionCertVerifyBlock,
	DecisionNonTLSFallback, DecisionInspectUnavailable,
}

func (d DecisionSource) String() string { return string(d) }

// Valid reports whether d is a member of the closed set (compile-time switch — see Outcome.Valid).
func (d DecisionSource) Valid() bool {
	switch d {
	case DecisionPolicyInspect, DecisionManualSSLBypass, DecisionAutoexcludeCache,
		DecisionAutoexcludeRescue, DecisionNoFailOpen502, DecisionCertVerifyBlock,
		DecisionNonTLSFallback, DecisionInspectUnavailable:
		return true
	}
	return false
}

// FailStage is where in the connection lifecycle a failure occurred (ADR-0011 §2.2,
// 7 values). `none` = no failure (a successful/decisioned session).
type FailStage string

const (
	// FailStageNone — no failure on this session.
	FailStageNone FailStage = "none"
	// FailStageTCPConnect — the upstream TCP dial failed.
	FailStageTCPConnect FailStage = "tcp_connect"
	// FailStageClientHello — the client-side TLS hello / handshake failed.
	FailStageClientHello FailStage = "client_hello"
	// FailStageUpstreamHandshake — the origin TLS handshake failed.
	FailStageUpstreamHandshake FailStage = "upstream_handshake"
	// FailStageCertVerify — origin certificate verification failed.
	FailStageCertVerify FailStage = "cert_verify"
	// FailStageClientLeafReject — the client rejected our forged leaf (pinning).
	FailStageClientLeafReject FailStage = "client_leaf_reject"
	// FailStageRelay — an error during the byte relay after a successful setup.
	FailStageRelay FailStage = "relay"
)

// AllFailStages is the closed set of FailStage values, in canonical order.
var AllFailStages = []FailStage{
	FailStageNone, FailStageTCPConnect, FailStageClientHello,
	FailStageUpstreamHandshake, FailStageCertVerify, FailStageClientLeafReject,
	FailStageRelay,
}

func (f FailStage) String() string { return string(f) }

// Valid reports whether f is a member of the closed set (compile-time switch — see Outcome.Valid).
func (f FailStage) Valid() bool {
	switch f {
	case FailStageNone, FailStageTCPConnect, FailStageClientHello,
		FailStageUpstreamHandshake, FailStageCertVerify, FailStageClientLeafReject,
		FailStageRelay:
		return true
	}
	return false
}

// FailCategory is the normalized failure class (ADR-0011 §2.2, 10 values). It mirrors
// the PAN-OS Decryption Error-Index classes. `none` = no failure.
type FailCategory string

const (
	// FailCategoryNone — no failure on this session.
	FailCategoryNone FailCategory = "none"
	// FailCategoryCertificate — origin certificate untrusted/expired/mismatched.
	FailCategoryCertificate FailCategory = "certificate"
	// FailCategoryProtocol — a protocol-level handshake failure.
	FailCategoryProtocol FailCategory = "protocol"
	// FailCategoryVersion — no overlapping TLS version.
	FailCategoryVersion FailCategory = "version"
	// FailCategoryCipher — no overlapping cipher suite.
	FailCategoryCipher FailCategory = "cipher"
	// FailCategoryClientCertRequired — the origin demanded a client certificate.
	FailCategoryClientCertRequired FailCategory = "client_cert_required"
	// FailCategoryClientPinned — the client pinned and rejected our forged leaf.
	FailCategoryClientPinned FailCategory = "client_pinned"
	// FailCategoryResource — a local resource limit (fd/memory) aborted the session.
	FailCategoryResource FailCategory = "resource"
	// FailCategoryTimeout — a handshake/idle timeout.
	FailCategoryTimeout FailCategory = "timeout"
	// FailCategoryOther — a classified-but-uncategorised failure.
	FailCategoryOther FailCategory = "other"
)

// AllFailCategories is the closed set of FailCategory values, in canonical order.
var AllFailCategories = []FailCategory{
	FailCategoryNone, FailCategoryCertificate, FailCategoryProtocol,
	FailCategoryVersion, FailCategoryCipher, FailCategoryClientCertRequired,
	FailCategoryClientPinned, FailCategoryResource, FailCategoryTimeout,
	FailCategoryOther,
}

func (f FailCategory) String() string { return string(f) }

// Valid reports whether f is a member of the closed set (compile-time switch — see Outcome.Valid).
func (f FailCategory) Valid() bool {
	switch f {
	case FailCategoryNone, FailCategoryCertificate, FailCategoryProtocol,
		FailCategoryVersion, FailCategoryCipher, FailCategoryClientCertRequired,
		FailCategoryClientPinned, FailCategoryResource, FailCategoryTimeout,
		FailCategoryOther:
		return true
	}
	return false
}

// CertVerify is the origin-certificate verification status (ADR-0011 §2.2, 7 values).
// It is the *status* enum — raw cert subject/issuer strings are never stored here.
type CertVerify string

const (
	// CertVerifyNotChecked — verification did not run (e.g. no decryption on this session).
	CertVerifyNotChecked CertVerify = "not_checked"
	// CertVerifyVerified — the origin certificate verified against the trust store.
	CertVerifyVerified CertVerify = "verified"
	// CertVerifySkipped — verification was deliberately skipped (bypass path).
	CertVerifySkipped CertVerify = "skipped"
	// CertVerifyUntrustedIssuer — the chain did not build to a trusted root.
	CertVerifyUntrustedIssuer CertVerify = "untrusted_issuer"
	// CertVerifyExpired — the certificate was expired / not yet valid.
	CertVerifyExpired CertVerify = "expired"
	// CertVerifyHostnameMismatch — the certificate did not match the host.
	CertVerifyHostnameMismatch CertVerify = "hostname_mismatch"
	// CertVerifyUnknown — a verification failure that did not classify further.
	CertVerifyUnknown CertVerify = "unknown"
)

// AllCertVerify is the closed set of CertVerify values, in canonical order.
var AllCertVerify = []CertVerify{
	CertVerifyNotChecked, CertVerifyVerified, CertVerifySkipped,
	CertVerifyUntrustedIssuer, CertVerifyExpired, CertVerifyHostnameMismatch,
	CertVerifyUnknown,
}

func (c CertVerify) String() string { return string(c) }

// Valid reports whether c is a member of the closed set (compile-time switch — see Outcome.Valid).
func (c CertVerify) Valid() bool {
	switch c {
	case CertVerifyNotChecked, CertVerifyVerified, CertVerifySkipped,
		CertVerifyUntrustedIssuer, CertVerifyExpired, CertVerifyHostnameMismatch,
		CertVerifyUnknown:
		return true
	}
	return false
}

// TLSVersion is the negotiated TLS version, bounded to the versions Culvert inspects
// plus `unknown` (ADR-0011 §2.2, 3 values).
type TLSVersion string

const (
	// TLSVersion12 — TLS 1.2.
	TLSVersion12 TLSVersion = "1.2"
	// TLSVersion13 — TLS 1.3.
	TLSVersion13 TLSVersion = "1.3"
	// TLSVersionUnknown — no handshake completed / version not observed.
	TLSVersionUnknown TLSVersion = "unknown"
)

// AllTLSVersions is the closed set of TLSVersion values, in canonical order.
var AllTLSVersions = []TLSVersion{TLSVersion12, TLSVersion13, TLSVersionUnknown}

func (v TLSVersion) String() string { return string(v) }

// Valid reports whether v is a member of the closed set (compile-time switch — see Outcome.Valid).
func (v TLSVersion) Valid() bool {
	switch v {
	case TLSVersion12, TLSVersion13, TLSVersionUnknown:
		return true
	}
	return false
}

// ALPN is the negotiated application protocol, bounded to the two Culvert relays plus
// the empty value (ADR-0011 §2.2). The empty string is a VALID member — it means "no
// ALPN negotiated" and, per the §2.1 shape, serializes explicitly when the block is present.
type ALPN string

const (
	// ALPNNone — no ALPN negotiated (empty; a valid member, not "unset").
	ALPNNone ALPN = ""
	// ALPNH2 — HTTP/2.
	ALPNH2 ALPN = "h2"
	// ALPNHTTP11 — HTTP/1.1.
	ALPNHTTP11 ALPN = "http/1.1"
)

// AllALPN is the closed set of ALPN values, in canonical order (the empty member first).
var AllALPN = []ALPN{ALPNNone, ALPNH2, ALPNHTTP11}

func (a ALPN) String() string { return string(a) }

// Valid reports whether a is a member of the closed set, INCLUDING the empty member
// (compile-time switch — see Outcome.Valid).
func (a ALPN) Valid() bool {
	switch a {
	case ALPNNone, ALPNH2, ALPNHTTP11:
		return true
	}
	return false
}
