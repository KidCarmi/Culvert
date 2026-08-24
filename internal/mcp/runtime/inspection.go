package runtime

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/destination"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/schema"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// inspectionErrorCode is the stable JSON-RPC error code for a PR-7 hard inspection
// failure (distinct from the policy and observe-only codes).
const inspectionErrorCode = -32060

// InspectionProvider supplies the capability-local, immutable inspection profile to
// a listener. It is READ-ONLY from the listener's perspective; the listener never
// mutates it. A false ok means no inspection is configured for that capability —
// the runtime then keeps the pre-inspection decision path.
type InspectionProvider interface {
	InspectionProfile(capNS protocol.Capability) (inspection.Profile, bool)
}

// inspectionRun carries the result of running request inspection plus the material
// a later redaction obligation needs (the profile, the decoded args, the compiled
// schema). It is request-local.
type inspectionRun struct {
	ran      bool
	profile  inspection.Profile
	args     *canonical.Node
	compiled *schema.Compiled
	result   inspection.Result
}

// runInspection runs PR-7 semantic inspection for a Gateway tools/call BEFORE
// policy evaluation. It resolves the exact catalog record (never a name-only
// lookup — the record's input-schema hash is cross-checked inside InspectRequest),
// performs the SINGLE strict decode of the arguments, and returns the sanitized
// result. It performs NO upstream/credential work and (in the decision-only default
// with no resolver) NO DNS. Returns ran=false for any non-inspected path
// (nil provider, non-Gateway, non-tools/call), leaving the old path byte-identical.
func (p *pipeline) runInspection(ctx context.Context, req Request, msg jsonrpc.Message, now time.Time) inspectionRun {
	if p.inspection == nil || p.capability != protocol.Gateway || msg.Method != "tools/call" {
		return inspectionRun{}
	}
	prof, ok := p.inspection.InspectionProfile(p.capability)
	if !ok {
		return inspectionRun{}
	}
	name := toolNameFromParams(msg.Params)
	tool := inspection.ToolRef{Name: name, ServerID: req.ServerID}
	var inputSchema *canonical.Node
	if p.deps.Catalog != nil && name != "" {
		if rec, ok := p.deps.Catalog.Current().Get(catalog.ToolKey{Server: registry.ServerID(req.ServerID), Name: name}); ok {
			sum := rec.Fingerprint.Sum()
			tool.FingerprintHex = hex.EncodeToString(sum[:])
			tool.InputSchemaHash = rec.Fingerprint.InputSchemaHash
			tool.HasInputSchemaHash = true
			tool.CatalogRevision = rec.Revision
			inputSchema = rec.InputSchema
		}
	}
	args, derr := prof.DecodeArgs(argumentsRaw(msg.Params))
	run := inspectionRun{ran: true, profile: prof}
	if derr != nil {
		// A malformed/over-bound arguments value is a hard semantic failure.
		run.result = inspection.Result{HardFail: true, HardReason: mcperr.ReasonSchemaInvalid}
		run.result.Summary.Revision = prof.Revision()
		return run
	}
	run.args = args
	if inputSchema != nil {
		run.compiled, _ = prof.CompileSchema(inputSchema)
	}
	in := inspection.RequestInput{
		Tool: tool, RequestedName: name, RequestedServer: req.ServerID,
		InputSchema: inputSchema, Compiled: run.compiled, Args: args,
	}
	run.result = inspection.InspectRequest(ctx, prof, in, now)
	return run
}

// applyInspectionToInput folds the sanitized inspection summary into the decision
// tuple BEFORE policy evaluation. It sets only safe typed facts; the evaluator
// remains I/O-free.
func applyInspectionToInput(in *policy.DecisionInput, s inspection.Summary) {
	in.Inspection = policy.Inspection{
		DLPAvailable:         s.DLPAvailable,
		RedactionAvailable:   s.RedactionAvailable,
		DestInspectAvailable: s.DestInspectAvailable,
		SecretScanAvailable:  s.SecretScanAvailable,
		SecretFound:          s.SecretFound,
		PIIFound:             s.PIIFound,
		InjectionSuspected:   s.InjectionSuspected,
		SchemaInvalid:        s.SchemaStatus != schema.StatusValid,
	}
	if s.DestInspected {
		in.Destination.Class = mapDestClass(s.DestClass)
	}
}

// mapDestClass maps a destination inspection class to the policy destination fact.
func mapDestClass(c destination.Class) policy.Destination {
	switch c {
	case destination.ClassPublic:
		return policy.DestinationArbitrary
	case destination.ClassPrivate, destination.ClassLinkLocal, destination.ClassMetadata,
		destination.ClassLoopback, destination.ClassReserved, destination.ClassMulticast:
		return policy.DestinationInternal
	default:
		return policy.DestinationUnknown
	}
}

// recordInspection stamps the sanitized inspection facts onto the observe record.
func recordInspection(rb *recBuilder, s inspection.Summary) {
	rb.rec.InspectionRevision = s.Revision
	rb.rec.InspectionSchema = s.SchemaStatus.String()
	rb.rec.InspectionDestClass = s.DestClass.String()
	rb.rec.InspectionDisp = s.Disposition.String()
	rb.rec.SecretFound = s.SecretFound
	rb.rec.PIIFound = s.PIIFound
	rb.rec.InjectionSuspected = s.InjectionSuspected
}

// satisfyRedaction resolves and applies an ALLOW_WITH_REDACTION obligation. It
// returns true only when a re-validated transform with a transformed hash was
// produced; otherwise it fails closed (the caller blocks). It NEVER publishes a
// partial transform and NEVER fabricates execution.
func (p *pipeline) satisfyRedaction(rb *recBuilder, run inspectionRun, d policy.Decision) bool {
	if !run.ran || d.Obligations.Redaction == nil || d.Obligations.Redaction.ProfileRef == "" {
		return false // ALLOW_WITH_REDACTION with no usable obligation ⇒ fail closed
	}
	_, ev, err := inspection.ApplyRedaction(run.profile, d.Obligations.Redaction.ProfileRef, 0, run.args, run.compiled)
	if err != nil || ev.TransformedHash == "" {
		return false
	}
	rb.rec.RedactionApplied = true
	rb.rec.RedactionProfile = ev.ProfileRef
	rb.rec.TransformedHash = ev.TransformedHash
	return true
}

// argumentsRaw extracts the raw "arguments" object bytes from a tools/call params
// object without a second semantic parse (json.RawMessage view only).
func argumentsRaw(params json.RawMessage) []byte {
	if len(params) == 0 {
		return nil
	}
	var b struct {
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &b); err != nil {
		return nil
	}
	return b.Arguments
}
