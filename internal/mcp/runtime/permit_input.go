package runtime

import (
	"encoding/hex"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// EXACT FIRST-CANARY DECISION TUPLE (blocker #14).
//
// The Canary activation preflight must know what the exact First-Canary request RESOLVES to.
// It has no request: it runs before any traffic, from a signed scope and the authoritative
// inventory. So it has to CONSTRUCT the tuple — and a constructed tuple is only evidence about
// real traffic if it is built the same way the real request path builds one.
//
// That is why the projections live here and not in the root package. `buildPolicyInput`/
// `attachGatewayRefs` and `ExactPermitTuple` call the SAME GatewayServerRef / GatewayToolRef, so
// the Server and Tool halves of the two tuples are identical BY CONSTRUCTION rather than by two
// implementations agreeing. A second projection in the composition layer is exactly the
// divergence that makes a preflight verdict meaningless: the preflight would be certifying a
// tuple the runtime never produces.
//
// The remaining fields split cleanly:
//
//   - the activation BINDS capability, principal tenant/subject, the operation, and (through
//     the two projections) every server and tool field. Those are the fields canary's
//     PermitBoundFields lists, and the permit verdict refuses unless the decision was decided
//     entirely by them.
//   - everything else — groups, assurance, issuer, agent, client, session, inspection, resource,
//     destination metadata, credential metadata — is REQUEST-VARIABLE. This builder leaves each
//     at the zero value ON PURPOSE. It is not pretending the real request will carry zeros; it
//     is refusing to invent a value, and the permit's invariance check is what makes that safe:
//     a rule that consults any of them is reported as a non-invariant verdict rather than
//     certified against a guess.
//
// Nothing here evaluates. It builds a tuple; the caller hands it to the real shared engine.

// GatewayServerRef projects one registry record onto the decision tuple's Server. It is the
// SINGLE projection: the live request path and the Canary permit both call it, so a server's
// owner / enabled / verification can never be read one way for traffic and another for the
// activation gate.
func GatewayServerRef(rec registry.ServerRecord) *policy.Server {
	return &policy.Server{
		ServerID:     string(rec.ID),
		Owner:        string(rec.OwnerScope),
		Enabled:      rec.Enabled,
		Verification: policyVerification(rec.Verification),
	}
}

// GatewayToolRef projects one catalog record onto the decision tuple's Tool, for the tool named
// on the given server. It is the SINGLE projection, shared with the live request path.
//
// It populates exactly the fields the request path populates — name, server, fingerprint hash,
// disposition, drift, destination — and deliberately leaves RiskSignals, CredentialPower,
// Reversibility, InputSchemaHash, OutputSchemaHash and DescriptionHash at their zero values,
// because the request path leaves them there too. A rule keyed on one of those is matching a
// value no real request ever carries; the permit's bound-field set excludes them for that
// reason, so such a rule yields a non-invariant verdict instead of a certified permit.
func GatewayToolRef(serverID, name string, rec catalog.ToolRecord) *policy.Tool {
	sum := rec.Fingerprint.Sum()
	tl := &policy.Tool{Name: name, ServerID: serverID}
	tl.FingerprintHash = hex.EncodeToString(sum[:])
	tl.Disposition, tl.Drift = policyDisposition(rec.Eligibility)
	tl.Destination = policyDestination(rec.Fingerprint.Destination)
	return tl
}

// ExactPermitTupleInput carries everything the activation authoritatively knows about the one
// exact First-Canary request. Every field is resolved by the caller from authoritative node
// state — the signed scope, one coherent registry+catalog capture, the live policy snapshot and
// the four-eyes reviewed operation class — and never from a request.
type ExactPermitTupleInput struct {
	// PolicyRevision/CatalogRevision/RegistryRevision stamp the tuple. The engine REJECTS a zero
	// policy or catalog revision as structurally invalid, so a caller that could not read them
	// fails closed rather than evaluating an under-specified tuple.
	PolicyRevision   uint64
	CatalogRevision  uint64
	RegistryRevision uint64
	// EvalTime is the explicit evaluation instant; the engine never reads a clock.
	EvalTime time.Time
	// Tenant/SubjectID are the exact scope's one tenant and one principal.
	Tenant    string
	SubjectID string
	// ServerRec/ToolRec are the authoritative records for the exact target, taken from ONE
	// coherent capture by the caller.
	ServerRec registry.ServerRecord
	ToolRec   catalog.ToolRecord
	ToolName  string
	// ReviewedReadFirst is the four-eyes reviewed read-only determination for this exact
	// target, taken against the CANDIDATE reviewed record the activation is about to bind.
	// It is the SAME seam shape the live request path uses, and the class is written by the
	// SAME single site (classifyReadFirstToolCall) — so the preflight cannot classify anything
	// the runtime would not, and there is no second classification authority.
	//
	// A nil predicate never promotes, leaving the conservative OpWrite default, which the permit
	// then refuses as not read-first. That is the fail-closed direction.
	ReviewedReadFirst ReviewedReadFirstFn
}

// ExactPermitTuple builds the exact First-Canary decision tuple, or (zero, false) when the
// activation does not know enough to construct one. It performs NO I/O and reads no live state.
//
// It fails closed on every missing input rather than substituting a default, because every
// default here would be a value the permit then certifies: a zero revision, an empty tenant or
// principal, an unnamed tool, or an unset operation class each mean the activation cannot say
// what the request IS, and a permit for a request nobody can describe is worthless.
func ExactPermitTuple(in ExactPermitTupleInput) (policy.DecisionInput, bool) {
	if in.PolicyRevision == 0 || in.CatalogRevision == 0 || in.EvalTime.IsZero() {
		return policy.DecisionInput{}, false
	}
	if in.Tenant == "" || in.SubjectID == "" || in.ToolName == "" {
		return policy.DecisionInput{}, false
	}
	capNS := policyCapability(protocol.Gateway)
	// The operation is built and classified by EXACTLY the two sites the request path uses:
	// policyOperation sets the conservative OpWrite default, and classifyReadFirstToolCall is
	// THE one place that may promote it to OpRead, from a four-eyes reviewed record. This
	// function writes no class of its own — see the wall in canary_read_first_class_test.go.
	op := policyOperation(protocol.Gateway, "tools/call", string(in.ServerRec.ID))
	op.Operand = in.ToolName
	classifyReadFirstToolCall(&op, protocol.Gateway, in.ReviewedReadFirst, string(in.ServerRec.ID), in.ToolName)
	return policy.DecisionInput{
		Capability:       capNS,
		PolicyRevision:   in.PolicyRevision,
		CatalogRevision:  in.CatalogRevision,
		RegistryRevision: in.RegistryRevision,
		EvalTime:         in.EvalTime,
		Principal: policy.Principal{
			// SubjectWorkload is the FIRST CANARY's synthetic principal kind, and it is bound
			// rather than guessed: `principal.kind` is NOT in the permit's bound-field set, so a
			// rule that reads it makes the verdict non-invariant and the permit false. The value
			// here therefore cannot smuggle an authorization — it only has to be a structurally
			// valid kind so the tuple passes validation and reaches the rule loop.
			Kind:      policy.SubjectWorkload,
			SubjectID: in.SubjectID,
			Tenant:    in.Tenant,
		},
		// The client's capability must equal the input capability or the tuple is structurally
		// invalid; its tenant is left EMPTY, which Validate explicitly permits, so no client
		// identity is invented. Every client.* field is unbound, so a rule reading one yields a
		// non-invariant verdict.
		Client:    policy.Client{Capability: capNS},
		Server:    GatewayServerRef(in.ServerRec),
		Tool:      GatewayToolRef(string(in.ServerRec.ID), in.ToolName, in.ToolRec),
		Operation: op,
	}, true
}

// EvaluateExactPermitTuple evaluates one exact First-Canary tuple against one policy snapshot
// and returns the engine's Decision and ExplainTrace verbatim.
//
// It exists so the Canary activation preflight cannot construct an evaluator of its own. The
// engine and its Limits are built HERE, by the same newPolicyEngine the live pipeline uses, so
// "the preflight asks the same question the runtime will" is true by construction rather than by
// two call sites agreeing on policy.DefaultLimits(). A preflight that quietly evaluated under
// different limits could certify a permit the runtime would refuse — limits bound trace entries,
// set sizes and string lengths, all of which can change which rule matches.
//
// It performs no I/O and holds no state; policy.Engine is pure.
func EvaluateExactPermitTuple(snap *policy.Snapshot, in policy.DecisionInput) (policy.Decision, policy.ExplainTrace, error) {
	return newPolicyEngine().Evaluate(snap, &in)
}
