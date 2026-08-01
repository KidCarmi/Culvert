package policy

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// DecisionInput is the immutable, typed decision tuple the evaluator consumes. It
// is a self-contained value: every fact the pure evaluator needs is present here,
// so evaluation performs no I/O and never reads a live registry/catalog/clock. It
// carries NO raw request body and NO raw bearer token BY CONSTRUCTION — only safe
// opaque ids, one-way fingerprints, bounded enums and the explicit evaluation
// time. The caller (the runtime) translates PR-2/PR-3 objects into this tuple.
type DecisionInput struct {
	// Capability + revision context (stamped onto every decision).
	Capability       Capability
	PolicyRevision   uint64
	CatalogRevision  uint64
	RegistryRevision uint64
	RuntimeRevision  uint64
	// EvalTime is the EXPLICIT evaluation timestamp. The evaluator never calls
	// time.Now(); all time-window matching is against this value.
	EvalTime time.Time

	Principal   Principal
	Agent       *Agent // optional
	Client      Client
	Server      *Server // Gateway only
	Tool        *Tool   // Gateway tool operations
	Operation   Operation
	Resource    *Resource // optional
	Destination DestinationMeta
	Credential  *CredentialMeta // optional; policy-selected profile metadata only
	Session     Session
	Inspection  Inspection // PR-7 placeholders (absence flags)
}

// Principal is the authenticated subject (from PR-3 identity.ResolvedContext).
type Principal struct {
	Kind      SubjectKind
	SubjectID string // stable subject id or safe fingerprint (opaque; never a token)
	Tenant    string
	Groups    []string
	Assurance Assurance
	Issuer    string
}

// Agent is an optional agent principal acting on behalf of the subject.
type Agent struct {
	AgentID string
	Owner   string // owner reference (PR-3 proves it is the subject)
	Version string
	Managed ManagedState
	Trust   TrustClass
}

// Client is the OAuth client / application principal.
type Client struct {
	ClientID   string
	AppID      string
	Tenant     string
	Trust      TrustClass
	Capability Capability // MUST equal the input capability
}

// Server is a registered Gateway server (from PR-2 registry).
type Server struct {
	ServerID     string
	Owner        string
	Environment  string
	Enabled      bool
	Verification ServerVerification
}

// Tool is the resolved Gateway tool (from PR-2 catalog). All potentially sensitive
// content is a one-way hash; risk signals are bounded enum-like labels.
type Tool struct {
	Name             string
	ServerID         string // MUST equal Server.ServerID
	FingerprintHash  string // hex of the catalog composite fingerprint (required)
	Disposition      Disposition
	Drift            DriftClass
	Destination      Destination // observed breadth
	CredentialPower  CredentialPower
	Reversibility    Reversibility
	InputSchemaHash  string
	OutputSchemaHash string
	DescriptionHash  string
	RiskSignals      []string // bounded, opaque labels
}

// Operation is the method / operation-class / namespace / operand identity.
type Operation struct {
	Method        string // admitted protocol method (never a rejected method)
	Class         OperationClass
	Namespace     OperationNamespace
	Operand       string // normalized operand identity
	DecisionPoint string // exact decision point from the operation registry
}

// Resource is an optional protected-resource reference with bounded scope attrs.
type Resource struct {
	Type   string
	ID     string
	Tenant string
	Attrs  map[string]string // bounded scope attributes (e.g. repository, branch)
}

// DestinationMeta is PRE-RESOLVED destination metadata only — no DNS/network
// resolution happens during evaluation.
type DestinationMeta struct {
	Class           Destination
	Environment     string
	ApprovedBreadth Destination
}

// CredentialMeta is the policy-selected credential profile metadata. It carries NO
// secret and NO client token — only an opaque profile reference, the profile power
// ceiling and a credential-kind label.
type CredentialMeta struct {
	ProfileRef   string
	PowerCeiling CredentialPower
	Kind         string
}

// Session is the session/context fingerprint plus prior-decision metadata supplied
// ONLY when the caller explicitly has it.
type Session struct {
	Fingerprint       string
	Assurance         Assurance
	PriorConfirmation bool
	PriorApproval     bool
	PriorGrant        bool
}

// Inspection carries the PR-7 inspection placeholders. In PR-6 the *Available flags
// are all false, so a rule requiring inspection evidence never silently passes.
type Inspection struct {
	DLPAvailable         bool
	RedactionAvailable   bool
	DestInspectAvailable bool
	SecretScanAvailable  bool
	SecretFound          bool // meaningful only when SecretScanAvailable
}

func inputErr(detail string) error {
	return mcperr.New(mcperr.ReasonPolicyInputInvalid, "policy.input", detail)
}

// Validate checks the decision tuple for structural validity and fails CLOSED. A
// structurally invalid tuple is distinct from a valid tuple that no rule matched:
// this returns a typed *mcperr error (mapped to MCP.SYSTEM.INVALID_INPUT), never a
// misleading no-match default deny. It reads only the input (no I/O).
func (in DecisionInput) Validate(lim Limits) error {
	if !in.Capability.Valid() {
		return inputErr("missing or invalid capability")
	}
	if in.PolicyRevision == 0 || in.CatalogRevision == 0 {
		return inputErr("missing policy/catalog revision")
	}
	if in.EvalTime.IsZero() {
		return inputErr("missing explicit evaluation time")
	}
	if err := in.validatePrincipal(lim); err != nil {
		return err
	}
	if in.Client.Capability != in.Capability {
		return inputErr("client capability does not match the input capability")
	}
	if in.Client.Tenant != "" && in.Client.Tenant != in.Principal.Tenant {
		return inputErr("client tenant conflicts with the principal tenant")
	}
	if err := in.validateOperation(); err != nil {
		return err
	}
	if err := in.validateCapabilityRefs(lim); err != nil {
		return err
	}
	return in.validateResource(lim)
}

func (in DecisionInput) validatePrincipal(lim Limits) error {
	switch in.Principal.Kind {
	case SubjectHuman, SubjectWorkload:
	default:
		return inputErr("missing or invalid subject kind")
	}
	if in.Principal.SubjectID == "" {
		return inputErr("missing subject id")
	}
	if in.Principal.Tenant == "" {
		return inputErr("missing tenant")
	}
	if in.Principal.Assurance > AssuranceHigh {
		return inputErr("impossible assurance level")
	}
	if len(in.Principal.Groups) > lim.MaxGroupsScopes() {
		return inputErr("too many principal groups")
	}
	return nil
}

func (in DecisionInput) validateOperation() error {
	if in.Operation.Method == "" {
		return inputErr("missing operation method")
	}
	if !in.Operation.Class.Valid() {
		return inputErr("missing or invalid operation class")
	}
	switch in.Operation.Namespace {
	case NamespaceGatewayTool:
		if in.Capability != CapGateway {
			return inputErr("gateway-tool namespace on a non-Gateway capability")
		}
	case NamespaceManagementOperation:
		if in.Capability != CapManagement {
			return inputErr("management-operation namespace on a non-Management capability")
		}
	default:
		return inputErr("missing or invalid operation namespace")
	}
	return nil
}

// validateCapabilityRefs enforces the Gateway/Management server-tool split.
func (in DecisionInput) validateCapabilityRefs(lim Limits) error {
	if in.Capability == CapManagement {
		if in.Server != nil || in.Tool != nil {
			return inputErr("Management input carries Gateway server/tool authority")
		}
		return nil
	}
	// Gateway.
	if in.Server == nil || in.Server.ServerID == "" {
		return inputErr("Gateway input requires a server")
	}
	if in.Server.Verification == ServerVerifyUnset {
		return inputErr("Gateway server verification state is unset")
	}
	// A tool operation (not pure discovery) requires a bound, fingerprinted tool.
	if in.Operation.Class == OpDiscovery && in.Tool == nil {
		return nil // tools/list-style discovery may carry no specific tool
	}
	if in.Tool == nil {
		return inputErr("Gateway tool operation requires a resolved tool")
	}
	if in.Tool.Name == "" {
		return inputErr("Gateway tool requires a name")
	}
	if in.Tool.ServerID != in.Server.ServerID {
		return inputErr("tool is not bound to the selected server")
	}
	if in.Tool.Disposition == DispUnset || in.Tool.Drift == DriftUnset {
		return inputErr("Gateway tool requires a catalog disposition and drift class")
	}
	// An UNKNOWN tool (absent from the catalog) legitimately has no fingerprint — it
	// is a valid decision tuple defined by its unknown-ness, and the engine's hard
	// override quarantines it. A KNOWN tool must always carry its catalog fingerprint.
	if in.Tool.Drift != DriftUnknownTool && in.Tool.FingerprintHash == "" {
		return inputErr("missing fingerprint for a Gateway tool")
	}
	if len(in.Tool.RiskSignals) > lim.MaxSetValues() {
		return inputErr("too many tool risk signals")
	}
	return nil
}

func (in DecisionInput) validateResource(lim Limits) error {
	if in.Resource == nil {
		return nil
	}
	if in.Resource.Type == "" || in.Resource.ID == "" {
		return inputErr("ambiguous resource identity (type and id are required)")
	}
	if len(in.Resource.Attrs) > lim.MaxResourceAttrs() {
		return inputErr("too many resource attributes")
	}
	return nil
}
