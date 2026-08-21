package inspection

import (
	"context"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/dlp"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/schema"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// ResponseInput is a future upstream response to inspect. PR-7 has NO live
// upstream — Body is supplied only by fixtures/explicit callers through this seam.
type ResponseInput struct {
	Tool         ToolRef
	OutputSchema *canonical.Node // registered output schema (nil ⇒ none)
	Body         []byte          // raw response body
}

// InspectResponse is the bounded output-inspection seam (MCP-INSP-002). It is a
// PURE function over an explicit body — it NEVER contacts an upstream and NEVER
// fabricates an "accepted" response. A caller cannot obtain a passing result
// without size validation, JSON validation, output-schema validation (when
// registered), full-content DLP inspection, and injection labeling.
//
// Truncation contract: a structured output over the security byte limit is
// BLOCKED (never blindly truncated); invalid JSON where JSON is required is
// BLOCKED; a schema-invalid output is BLOCKED. Only bounded textual/display
// fields may be truncated, and only under an explicit profile flag — and DLP +
// security inspection always run on the FULL admitted content BEFORE any allowed
// display truncation (see TruncateText).
func InspectResponse(ctx context.Context, p Profile, in ResponseInput, now time.Time) Result {
	res := Result{Summary: baseSummary(p)}
	res.Summary.DestInspected = false // response inspection does not extract request destinations
	// 1. size bound — structured over-limit output blocks (no blind truncation).
	if len(in.Body) > p.lim.MaxOutputBytes() {
		return hardFail(res, mcperr.ReasonOutputTooLarge)
	}
	// 2. JSON validity (JSON is required for a structured tool result).
	node, err := canonical.Decode(in.Body, outputBounds(p.lim))
	if err != nil {
		return hardFail(res, mcperr.ReasonOutputSchemaInvalid)
	}
	// 3. registered output-schema validation.
	if in.OutputSchema != nil {
		compiled, cerr := schema.Compile(in.OutputSchema, p.lim)
		if cerr != nil {
			res.Summary.OutputSchemaStatus = compileStatus(cerr)
			return hardFail(res, mcperr.ReasonOutputSchemaInvalid)
		}
		r := compiled.Validate(node)
		res.Summary.OutputSchemaStatus = r.Status
		if !r.Valid() {
			return hardFail(res, mcperr.ReasonOutputSchemaInvalid)
		}
	}
	// 4. FULL-content DLP + injection inspection (before any display truncation).
	rep, serr := dlp.Scan(node, dlp.ResponseMode(), p.lim)
	if serr != nil {
		return hardFail(res, mcperr.ReasonInspectionLimitExceeded)
	}
	if rep.Truncated {
		// Partial DLP on a high-risk output fails closed (a dropped finding could
		// have hidden a blocking secret behind a flood of label-only findings).
		return hardFail(res, mcperr.ReasonInspectionLimitExceeded)
	}
	res.Findings = append(res.Findings, rep.Findings...)
	applyDLPToSummary(&res.Summary, rep)
	worst, blocked, reason := p.evaluateDispositions(rep)
	res.Summary.Disposition = worst
	if blocked {
		return hardFail(res, reason)
	}
	return res
}

// TruncationEvidence is the safe attestation of an allowed display truncation.
type TruncationEvidence struct {
	OriginalSize    int
	ResultingSize   int
	Truncated       bool
	TransformedHash string
}

// TruncateText applies the ONLY permitted truncation: a bounded textual/display
// field, under the profile's explicit AllowTextTruncation flag, capped at
// MaxTruncatedTextBytes. It returns the (possibly) truncated text plus evidence
// (original size, resulting size, marker, transformed hash). It is a caller
// convenience for a future display path; security inspection must already have run
// on the FULL content. When the profile forbids truncation the text is returned
// unchanged with Truncated=false.
func (p Profile) TruncateText(s string) (result string, evidence TruncationEvidence) {
	ev := TruncationEvidence{OriginalSize: len(s), ResultingSize: len(s)}
	if !p.allowTextTruncation || len(s) <= p.lim.MaxTruncatedTextBytes() {
		ev.TransformedHash = shortHash(s)
		return s, ev
	}
	out := s[:p.lim.MaxTruncatedTextBytes()] + "…[truncated]"
	ev.Truncated = true
	ev.ResultingSize = len(out)
	ev.TransformedHash = shortHash(out)
	return out, ev
}

func outputBounds(lim interface {
	MaxOutputBytes() int
	MaxBytesPerString() int
}) canonical.Bounds {
	return canonical.Bounds{
		MaxBytes:         lim.MaxOutputBytes(),
		MaxDepth:         64,
		MaxObjectMembers: 1 << 16,
		MaxArrayElements: 1 << 16,
		MaxStringBytes:   lim.MaxBytesPerString(),
	}
}
