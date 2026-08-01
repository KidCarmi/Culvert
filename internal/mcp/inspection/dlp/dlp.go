// Package dlp is the PR-7 deterministic, bounded DLP classifier (MCP-INSP-003)
// and best-effort prompt-injection labeler (MCP-INSP-007). It scans an
// already-decoded canonical value (tool-call arguments or a future upstream
// output), classifying secret / PII / financial / injection shapes and producing
// SANITIZED findings — a stable classification, severity, bounded path, detector
// id, count and a safe evidence hash. A finding NEVER retains the raw matched
// secret, and the original secret never appears in any error, finding,
// observation or log.
//
// Secret detection reuses the existing bounded deterministic scrubber
// (internal/redaction) as the credential-shape backstop — there is no second,
// divergent secret scrubber. PII detection is a small, explicit, deterministic V1
// corpus of precise detectors (each with documented false-positive/false-negative
// limits) — NOT a broad entropy or dictionary heuristic that would destroy normal
// MCP data. Injection labeling is best-effort deterministic pattern labeling: it
// never claims complete prevention, never copies raw output text into metadata,
// and performs only bounded work (no unbounded base64/compressed decoding).
package dlp

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Classification is the CLOSED V1 data-classification enum. The zero value fails
// closed (treated as an unknown/oversized classification).
type Classification uint8

const (
	// ClassUnset — zero value; never a real finding class.
	ClassUnset Classification = iota
	// ClassCredentialSecret — a provider credential/API secret shape.
	ClassCredentialSecret
	// ClassPrivateKey — private-key material (PEM/OpenSSH/PGP).
	ClassPrivateKey
	// ClassBearerToken — bearer/JWT token material.
	ClassBearerToken
	// ClassPasswordOrAPIKey — a password or api-key assignment / basic-auth URL.
	ClassPasswordOrAPIKey
	// ClassPII — personally identifiable information (email, phone, national id).
	ClassPII
	// ClassFinancial — a financial identifier (payment card number).
	ClassFinancial
	// ClassSourceCodeSecret — a secret embedded in a source-code-shaped assignment.
	ClassSourceCodeSecret
	// ClassInternalOnly — internal-only data marker (reserved; conservative).
	ClassInternalOnly
	// ClassPossibleInjection — output content that appears to instruct the agent.
	ClassPossibleInjection
	// ClassOversizedUnknown — an oversized/over-count leaf that failed closed.
	ClassOversizedUnknown
)

// String returns the stable classification label.
func (c Classification) String() string {
	switch c {
	case ClassCredentialSecret:
		return "credential_secret"
	case ClassPrivateKey:
		return "private_key"
	case ClassBearerToken:
		return "bearer_token"
	case ClassPasswordOrAPIKey:
		return "password_or_api_key"
	case ClassPII:
		return "pii"
	case ClassFinancial:
		return "financial_identifier"
	case ClassSourceCodeSecret:
		return "source_code_secret"
	case ClassInternalOnly:
		return "internal_only"
	case ClassPossibleInjection:
		return "possible_prompt_injection"
	case ClassOversizedUnknown:
		return "oversized_or_unknown"
	default:
		return "unset"
	}
}

// IsSecret reports whether the classification is a secret/credential family
// (drives the SecretFound signal fed to policy).
func (c Classification) IsSecret() bool {
	switch c {
	case ClassCredentialSecret, ClassPrivateKey, ClassBearerToken,
		ClassPasswordOrAPIKey, ClassSourceCodeSecret:
		return true
	default:
		return false
	}
}

// Severity is the ordered confidence/impact of a finding.
type Severity uint8

const (
	// SevUnset — zero value.
	SevUnset Severity = iota
	// SevInfo — informational.
	SevInfo
	// SevLow — low confidence/impact (labeled, rarely blocked).
	SevLow
	// SevMedium — medium.
	SevMedium
	// SevHigh — high confidence/impact.
	SevHigh
	// SevCritical — critical (secret/private key).
	SevCritical
)

// String returns the severity label.
func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "info"
	case SevLow:
		return "low"
	case SevMedium:
		return "medium"
	case SevHigh:
		return "high"
	case SevCritical:
		return "critical"
	default:
		return "unset"
	}
}

// Finding is an immutable, sanitized DLP/injection finding. It carries ONLY safe
// metadata: never the matched secret value, never the raw text.
type Finding struct {
	Class      Classification
	Severity   Severity
	Path       string // bounded JSON-pointer-like location
	DetectorID string // stable detector id (e.g. "secret.jwt", "pii.us_ssn")
	Count      int    // occurrences at this path for this detector
	Evidence   string // safe, non-reversible evidence hash (hex); no secret content
}

// Report is the bounded result of a scan. It is safe to embed in an observation.
type Report struct {
	Findings  []Finding
	Truncated bool // a finding/scan bound was hit; treat as fail-conservative
	secret    bool
	inject    bool
}

// SecretFound reports whether any secret-family classification was found.
func (r *Report) SecretFound() bool { return r != nil && r.secret }

// InjectionSuspected reports whether any injection label was produced.
func (r *Report) InjectionSuspected() bool { return r != nil && r.inject }

// MaxSeverity returns the highest finding severity (SevUnset if none).
func (r *Report) MaxSeverity() Severity {
	max := SevUnset
	if r == nil {
		return max
	}
	for i := range r.Findings {
		if r.Findings[i].Severity > max {
			max = r.Findings[i].Severity
		}
	}
	return max
}

// Classes returns the sorted, unique set of finding classifications.
func (r *Report) Classes() []Classification {
	if r == nil {
		return nil
	}
	seen := map[Classification]struct{}{}
	var out []Classification
	for i := range r.Findings {
		c := r.Findings[i].Class
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Mode selects which detector families run in a scan.
type Mode struct {
	Secrets   bool // secret/credential shapes (request + output)
	PII       bool // PII/financial corpus
	Injection bool // best-effort prompt-injection labeling (output-oriented)
}

// RequestMode is the default detector set for tool-call ARGUMENTS: secrets + PII,
// no injection (arguments are client-authored, not agent-facing output).
func RequestMode() Mode { return Mode{Secrets: true, PII: true} }

// ResponseMode is the default detector set for a future upstream OUTPUT: every
// family, including injection labeling.
func ResponseMode() Mode { return Mode{Secrets: true, PII: true, Injection: true} }

// scanState carries the bounded budgets for one scan.
type scanState struct {
	lim       limits.InspectionLimits
	mode      Mode
	strings   int
	scanBytes int
	ops       int
	rep       Report
}

func dlpLimit(detail string) error {
	return mcperr.New(mcperr.ReasonInspectionLimitExceeded, "dlp.scan", detail)
}

// Scan walks value and classifies secret/PII/injection shapes under the injected
// limits. It is deterministic and bounded; a bound overflow returns a typed error
// (ReasonInspectionLimitExceeded) OR marks the Report Truncated and fails
// conservative, never silently under-reporting on a high-risk value. A nil value
// yields an empty report.
func Scan(value *canonical.Node, mode Mode, lim limits.InspectionLimits) (*Report, error) {
	st := &scanState{lim: lim, mode: mode}
	if value == nil {
		return &st.rep, nil
	}
	if err := st.walk(value, ""); err != nil {
		return nil, err
	}
	return &st.rep, nil
}

// ScanText labels a single already-bounded text (a display/output field) for
// prompt injection only. It is the bounded entry point the response inspector
// uses per text field.
func ScanText(text, path string, lim limits.InspectionLimits) (*Report, error) {
	st := &scanState{lim: lim, mode: Mode{Injection: true}}
	if err := st.scanString(text, path); err != nil {
		return nil, err
	}
	return &st.rep, nil
}

func (st *scanState) walk(n *canonical.Node, path string) error {
	st.ops++
	if st.ops > st.lim.MaxValidationOps() {
		st.rep.Truncated = true
		return dlpLimit("scan operations")
	}
	switch n.Kind {
	case canonical.KindObject:
		for i, k := range n.Keys {
			// Object KEYS are scanned for secrets too (a secret can hide in a key).
			if st.mode.Secrets {
				if err := st.scanSecretString(k, join(path, k)); err != nil {
					return err
				}
			}
			if err := st.walk(n.Vals[i], join(path, k)); err != nil {
				return err
			}
		}
	case canonical.KindArray:
		for i, e := range n.Arr {
			if err := st.walk(e, joinIdx(path, i)); err != nil {
				return err
			}
		}
	case canonical.KindString:
		return st.scanString(n.Str, path)
	}
	return nil
}

// scanString applies the enabled detectors to one string leaf under the
// per-string and total scan budgets.
func (st *scanState) scanString(s, path string) error {
	st.strings++
	if st.strings > st.lim.MaxStringsScanned() {
		st.rep.Truncated = true
		return dlpLimit("strings scanned")
	}
	if len(s) > st.lim.MaxBytesPerString() {
		// Whole-leaf fail-closed: an over-cap leaf is a conservative oversized finding.
		st.add(Finding{Class: ClassOversizedUnknown, Severity: SevMedium, Path: path,
			DetectorID: "dlp.oversized_leaf", Count: 1})
		return nil
	}
	st.scanBytes += len(s)
	if st.scanBytes > st.lim.MaxTotalScanBytes() {
		st.rep.Truncated = true
		return dlpLimit("total scan bytes")
	}
	if st.mode.Secrets {
		if err := st.scanSecretString(s, path); err != nil {
			return err
		}
	}
	if st.mode.PII {
		if err := st.scanPII(s, path); err != nil {
			return err
		}
	}
	if st.mode.Injection {
		if err := st.scanInjection(s, path); err != nil {
			return err
		}
	}
	return nil
}

// add appends a finding under the finding cap, failing conservative on overflow.
func (st *scanState) add(f Finding) {
	if len(st.rep.Findings) >= st.lim.MaxFindings() {
		st.rep.Truncated = true
		return
	}
	f.Evidence = evidenceHash(f.DetectorID, f.Path, f.Count)
	st.rep.Findings = append(st.rep.Findings, f)
	if f.Class.IsSecret() {
		st.secretSeen()
	}
	if f.Class == ClassPossibleInjection {
		st.rep.inject = true
	}
}

func (st *scanState) secretSeen() { st.rep.secret = true }

// evidenceHash produces a safe, non-reversible evidence hash from ONLY safe
// metadata (detector id, bounded path, count). It never hashes the matched
// secret, so it can appear in observations, logs and golden files without leaking.
func evidenceHash(detectorID, path string, count int) string {
	h := sha256.Sum256([]byte(detectorID + "|" + path + "|" + strconv.Itoa(count)))
	return hex.EncodeToString(h[:8])
}

// --- bounded JSON-pointer-like path helpers (local; no cross-package dep) ---

func join(path, key string) string {
	if len(key) > 64 {
		key = key[:64]
	}
	key = strings.ReplaceAll(key, "~", "~0")
	key = strings.ReplaceAll(key, "/", "~1")
	return path + "/" + key
}

func joinIdx(path string, i int) string {
	return path + "/" + strconv.Itoa(i)
}
