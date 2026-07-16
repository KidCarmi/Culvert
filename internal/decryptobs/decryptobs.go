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
var AllOutcomes = []Outcome{
	OutcomeInspected, OutcomeBypassManual, OutcomeBypassLearned,
	OutcomeRescued, OutcomeFailed, OutcomeNotDecrypted,
}

func (o Outcome) String() string { return string(o) }

// Valid reports whether o is a member of the closed set.
func (o Outcome) Valid() bool { return validMember(o, AllOutcomes) }

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
)

// AllDecisionSources is the closed set of DecisionSource values, in canonical order.
var AllDecisionSources = []DecisionSource{
	DecisionPolicyInspect, DecisionManualSSLBypass, DecisionAutoexcludeCache,
	DecisionAutoexcludeRescue, DecisionNoFailOpen502, DecisionCertVerifyBlock,
	DecisionNonTLSFallback,
}

func (d DecisionSource) String() string { return string(d) }

// Valid reports whether d is a member of the closed set.
func (d DecisionSource) Valid() bool { return validMember(d, AllDecisionSources) }

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

// Valid reports whether f is a member of the closed set.
func (f FailStage) Valid() bool { return validMember(f, AllFailStages) }

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

// Valid reports whether f is a member of the closed set.
func (f FailCategory) Valid() bool { return validMember(f, AllFailCategories) }

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

// Valid reports whether c is a member of the closed set.
func (c CertVerify) Valid() bool { return validMember(c, AllCertVerify) }

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

// Valid reports whether v is a member of the closed set.
func (v TLSVersion) Valid() bool { return validMember(v, AllTLSVersions) }

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

// Valid reports whether a is a member of the closed set (including the empty member).
func (a ALPN) Valid() bool { return validMember(a, AllALPN) }

// validMember reports whether v appears in set. Generic over the string-enum types so
// each Valid method is a one-liner; the closed sets are tiny (≤10), so linear scan is
// the right choice (no map allocation, no init ordering concern).
func validMember[T ~string](v T, set []T) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
