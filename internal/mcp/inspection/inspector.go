package inspection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/destination"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/dlp"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/schema"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// ToolRef is the exact resolved catalog tool identity the request inspector
// cross-checks against the request. It carries one-way hashes only.
type ToolRef struct {
	Name               string
	ServerID           string
	FingerprintHex     string
	InputSchemaHash    [32]byte
	HasInputSchemaHash bool
	CatalogRevision    uint64
}

// RequestInput is the exact, already-validated request the inspector consumes. It
// operates on the SINGLE canonical representation (Args is the one strict decode
// of params.arguments); there is no second semantic parse.
type RequestInput struct {
	Tool            ToolRef
	RequestedName   string           // params.name (must equal Tool.Name)
	RequestedServer string           // resolved server id (must equal Tool.ServerID)
	InputSchema     *canonical.Node  // catalog input schema (nil ⇒ none)
	Compiled        *schema.Compiled // optional pre-compiled schema (cache)
	Args            *canonical.Node  // canonical tools/call arguments (nil ⇒ none)
	ExplicitDests   []string         // modeled destination strings from the operation registry
}

// InspectRequest runs the ordered request-inspection pipeline for a Gateway
// tools/call and returns a sanitized Result. Order: identity/schema-hash
// consistency → semantic schema validation → DLP secret/PII classification +
// disposition → destination extraction/canonicalization/(optional resolve+pin) →
// summary. A hard security failure sets HardFail + HardReason; the runtime blocks
// on it regardless of the PR-6 policy action. It performs NO upstream execution
// and NO credential work.
func InspectRequest(ctx context.Context, p Profile, in RequestInput, now time.Time) Result {
	res := Result{Summary: baseSummary(p)}
	// 1. identity consistency — no name-only lookup, no record swap.
	if in.RequestedName != "" && in.RequestedName != in.Tool.Name {
		return hardFail(res, mcperr.ReasonSchemaInvalid)
	}
	if in.RequestedServer != "" && in.RequestedServer != in.Tool.ServerID {
		return hardFail(res, mcperr.ReasonSchemaInvalid)
	}
	if in.InputSchema != nil && in.Tool.HasInputSchemaHash {
		if canonical.HashNode(in.InputSchema) != in.Tool.InputSchemaHash {
			return hardFail(res, mcperr.ReasonSchemaInvalid)
		}
	}
	// 2. semantic schema validation.
	st, hardReason := compileAndValidate(p, in)
	res.Summary.SchemaStatus = st
	if st != schema.StatusValid {
		return hardFail(res, hardReason)
	}
	// 3. DLP secret/PII classification + disposition.
	rep, err := dlp.Scan(in.Args, dlp.RequestMode(), p.lim)
	if err != nil {
		return hardFail(res, mcperr.ReasonInspectionLimitExceeded)
	}
	// A truncated scan (a bound was hit — findings/strings/bytes) is a fail-closed
	// signal: dropped findings could have hidden a blocking secret behind a flood of
	// label-only findings, so a high-risk operation must not proceed on partial DLP.
	if rep.Truncated {
		return hardFail(res, mcperr.ReasonInspectionLimitExceeded)
	}
	res.Findings = append(res.Findings, rep.Findings...)
	applyDLPToSummary(&res.Summary, rep)
	worst, blocked, reason := p.evaluateDispositions(rep)
	res.Summary.Disposition = worst
	if blocked {
		return hardFail(res, reason)
	}
	// 4. destination extraction + SSRF classification (+ optional pinned resolution).
	if hf, dreason := p.inspectDestinations(ctx, in, now, &res); hf {
		return hardFail(res, dreason)
	}
	return res
}

func baseSummary(p Profile) Summary {
	return Summary{
		Revision:             p.revision,
		DLPAvailable:         true,
		RedactionAvailable:   true,
		DestInspectAvailable: true,
		SecretScanAvailable:  true,
		DestInspected:        true,
		DestClass:            destination.ClassUnknown,
		RedirectStatus:       RedirectNone,
	}
}

func hardFail(res Result, reason mcperr.Reason) Result {
	res.HardFail = true
	res.HardReason = reason
	res.Summary.Disposition = DispBlock
	return res
}

func compileAndValidate(p Profile, in RequestInput) (schema.Status, mcperr.Reason) {
	compiled := in.Compiled
	if compiled == nil {
		c, err := schema.Compile(in.InputSchema, p.lim)
		if err != nil {
			return compileStatus(err), mcperr.ReasonOf(err)
		}
		compiled = c
	}
	r := compiled.Validate(in.Args)
	if r.Valid() {
		return schema.StatusValid, mcperr.ReasonNone
	}
	return r.Status, schemaStatusReason(r.Status)
}

func compileStatus(err error) schema.Status {
	switch mcperr.ReasonOf(err) {
	case mcperr.ReasonSchemaUnsupported:
		return schema.StatusUnsupported
	case mcperr.ReasonSchemaLimitExceeded:
		return schema.StatusLimitExceeded
	default:
		return schema.StatusInvalid
	}
}

func schemaStatusReason(st schema.Status) mcperr.Reason {
	switch st {
	case schema.StatusUnsupported:
		return mcperr.ReasonSchemaUnsupported
	case schema.StatusLimitExceeded:
		return mcperr.ReasonSchemaLimitExceeded
	default:
		return mcperr.ReasonSchemaInvalid
	}
}

// evaluateDispositions computes the worst disposition across all findings and
// whether any finding is a hard block (with the block reason). Redact/label/pass do
// not block here (redaction runs on the ALLOW_WITH_REDACTION obligation); injection
// is labeled unless the profile opts into a severity-based hard block.
func (p Profile) evaluateDispositions(rep *dlp.Report) (Disposition, bool, mcperr.Reason) {
	worst := DispPass
	blocked := false
	reason := mcperr.ReasonNone
	for i := range rep.Findings {
		d, blocks, blockReason := p.findingDisposition(&rep.Findings[i])
		if blocks && !blocked {
			blocked, reason = true, blockReason
		}
		worst = worse(worst, d)
	}
	return worst, blocked, reason
}

// findingDisposition maps one finding to its disposition and, when it hard-blocks,
// the block reason. Injection is labeled unless the profile opts into a
// severity-based hard block; every other class uses the profile disposition.
func (p Profile) findingDisposition(f *dlp.Finding) (Disposition, bool, mcperr.Reason) {
	if f.Class == dlp.ClassPossibleInjection {
		if p.injectionBlockSeverity != dlp.SevUnset && f.Severity >= p.injectionBlockSeverity {
			return DispBlock, true, mcperr.ReasonInjectionSuspected
		}
		return DispLabel, false, mcperr.ReasonNone
	}
	d := p.disposition(f.Class)
	if d.Blocks() {
		return d, true, blockReasonForClass(f.Class)
	}
	return d, false, mcperr.ReasonNone
}

func blockReasonForClass(c dlp.Classification) mcperr.Reason {
	switch {
	case c.IsSecret():
		return mcperr.ReasonSecretDetected
	case c == dlp.ClassPII || c == dlp.ClassFinancial:
		return mcperr.ReasonPIIDetected
	case c == dlp.ClassOversizedUnknown:
		return mcperr.ReasonInspectionLimitExceeded
	default:
		return mcperr.ReasonSecretDetected
	}
}

// applyDLPToSummary folds scan facts into the summary.
func applyDLPToSummary(s *Summary, rep *dlp.Report) {
	s.SecretFound = rep.SecretFound()
	s.InjectionSuspected = rep.InjectionSuspected()
	s.MaxSeverity = rep.MaxSeverity()
	s.Classes = rep.Classes()
	for _, c := range s.Classes {
		if c == dlp.ClassPII || c == dlp.ClassFinancial {
			s.PIIFound = true
		}
	}
}

// inspectDestinations extracts, canonicalizes and (optionally) resolves+pins every
// destination candidate. A modeled destination that is malformed/blocked/private/
// SSRF-blocked is a HARD failure; an unmodeled (heuristic) candidate is a
// conservative finding but a private/metadata IP literal is always a hard block.
func (p Profile) inspectDestinations(ctx context.Context, in RequestInput, now time.Time, res *Result) (bool, mcperr.Reason) {
	cands, err := p.extraction.Extract(in.Args, p.lim)
	if err != nil {
		return true, mcperr.ReasonInspectionLimitExceeded
	}
	for _, d := range in.ExplicitDests {
		cands = append(cands, destination.Candidate{Path: "/_explicit", RawURL: d, Modeled: true})
	}
	worst := destination.ClassUnknown
	for _, cand := range cands {
		hf, reason, class := p.inspectOneDestination(ctx, cand, now, res)
		if hf {
			return true, reason
		}
		worst = worseClass(worst, class)
		if !cand.Modeled {
			res.Findings = append(res.Findings, dlp.Finding{
				Class: dlp.ClassInternalOnly, Severity: dlp.SevLow, Path: cand.Path,
				DetectorID: "destination.unmodeled", Count: 1,
				Evidence: shortHash("destination.unmodeled|" + cand.Path),
			})
		}
	}
	if len(cands) > 0 {
		res.Summary.DestClass = worst
	}
	return false, mcperr.ReasonNone
}

// inspectOneDestination canonicalizes one candidate and, when a resolver is
// present, resolves + pins it. Returns (hardFail, reason, class).
func (p Profile) inspectOneDestination(ctx context.Context, cand destination.Candidate, now time.Time, res *Result) (bool, mcperr.Reason, destination.Class) {
	c, class, err := destination.Canonicalize(cand.RawURL, p.destPolicy, p.lim)
	if err != nil {
		if cand.Modeled {
			return true, mcperr.ReasonOf(err), destination.ClassMalformed
		}
		return false, mcperr.ReasonNone, destination.ClassMalformed // unmodeled: conservative finding, not a block
	}
	// An IP-literal private/metadata/loopback destination is ALWAYS a hard block,
	// modeled or not (SSRF).
	if c.IsIP && !class.Permitted() {
		return true, mcperr.ReasonSSRFBlocked, class
	}
	if p.resolver != nil {
		pin, st, rerr := destination.Resolve(ctx, c, p.destPolicy, p.resolver, p.lim, now, p.pinTTL)
		if rerr != nil {
			if cand.Modeled {
				return true, mcperr.ReasonOf(rerr), st.Class
			}
			return false, mcperr.ReasonNone, st.Class
		}
		res.Pins = append(res.Pins, pinEvidence(pin, st.Class))
		res.Summary.Pinned = true
		res.Summary.PinnedHash = res.Pins[len(res.Pins)-1].Hash
		return false, mcperr.ReasonNone, st.Class
	}
	return false, mcperr.ReasonNone, class
}

func pinEvidence(pin destination.PinnedDestination, class destination.Class) PinnedEvidence {
	origin := pin.Scheme + "://" + pin.Host + ":" + pin.Port
	// deterministic hash over origin + sorted addr strings + revision
	addrs := make([]string, 0, len(pin.AllowedIPs))
	for _, a := range pin.AllowedIPs {
		addrs = append(addrs, a.String())
	}
	sort.Strings(addrs)
	h := sha256.New()
	h.Write([]byte(origin))
	for _, a := range addrs {
		h.Write([]byte{0})
		h.Write([]byte(a))
	}
	sum := h.Sum(nil)
	return PinnedEvidence{
		Origin: origin, AddrCount: len(pin.AllowedIPs), ResolverRevision: pin.ResolverRevision,
		Hash: hex.EncodeToString(sum[:8]), Class: class,
	}
}

func worseClass(a, b destination.Class) destination.Class {
	// Any non-public class is "worse" than public/unknown for the summary fact.
	rank := func(c destination.Class) int {
		switch c {
		case destination.ClassPublic:
			return 1
		case destination.ClassUnknown:
			return 0
		default:
			return 2
		}
	}
	if rank(a) >= rank(b) {
		return a
	}
	return b
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}
