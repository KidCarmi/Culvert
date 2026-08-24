package main

// QUAL-4 — node-local Gateway "Observe" policy composition. This file compiles a
// static, node-local policy SOURCE document ONCE at startup through the EXISTING
// policy compiler + limits and publishes it as the node-local ACTIVE Observe
// evaluation snapshot into the SAME capability-local policy.Store the read-only MCP
// Policy Admin API and the simulator read — so there is exactly ONE compiled
// snapshot (single source of truth: runtime evaluator, /api/mcp/policy active read,
// simulator Compare baseline, and decision-evidence snapshot hash all agree).
//
// It composes ONLY the policy provider (runtime Deps.Policy). It wires NO executor,
// upstream client, credential broker, or Inspection provider — so a decision-point
// method is EVALUATED against the snapshot and its true result recorded, but the
// effective runtime stays Observe-only: an evaluated ALLOW never executes
// (execution_state=not_implemented) and no credential/upstream/side-effect runs. The
// evaluated policy action is NOT execution authorization.
//
// Isolation + fail-closed by construction:
//   - the Gateway snapshot can never satisfy the Management capability (the provider
//     returns nil for Management, and the Management store is never published to);
//   - a Management-capability policy source is rejected (only "gateway" is composable);
//   - loading is atomic: read (bounded, traversal-safe) → compile (existing compiler,
//     full validation) → verify capability → publish into the store. Any error leaves
//     NO partially active snapshot and fails activation closed (nothing binds);
//   - absent ⇒ QUAL-3 behavior preserved (Deps.Policy nil, decision telemetry stays
//     pending-policy). This node-local qualification snapshot is NEVER labeled
//     published / approved / fleet-effective / distributed / Production policy, and it
//     never bypasses or weakens the existing four-eyes publication workflow.

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// maxPolicyFileBytes bounds the policy source document read from disk BEFORE
// compilation (a fail-closed memory-DoS guard on hostile operator input). It matches
// the policy compiler's own snapshot-bytes ceiling; the compiler enforces the exact
// configured limit during Compile.
const maxPolicyFileBytes = 8 << 20 // 8 MiB

// ── state / holder ────────────────────────────────────────────────────────────

// mcpPolicyState classifies the node-local policy-composition outcome for the
// truthful, read-only admin/health surface. It distinguishes a genuinely
// un-composed policy from a failed load, so an invalid policy is never rendered as
// an empty healthy one.
type mcpPolicyState string

const (
	// mcpPolNotConfigured — the listener is disabled, or enabled with no
	// qualification_policy_file (QUAL-3 posture): no snapshot composed, decision
	// telemetry stays pending-policy.
	mcpPolNotConfigured mcpPolicyState = "not_configured"
	// mcpPolLoaded — a present, valid policy source compiled + published as the
	// node-local active Observe evaluation snapshot.
	mcpPolLoaded mcpPolicyState = "loaded"
	// mcpPolInvalid — a present policy source failed to read/compile/publish; the
	// listener did not bind (fail closed). No snapshot is active; state is NOT loaded.
	mcpPolInvalid mcpPolicyState = "invalid"
)

// mcpPolicyHolder owns the two capability-local policy stores and the safe,
// secret-free metadata surfaced to the admin/health API. The SAME store pointers are
// read by the runtime PolicyProvider AND by the read-only Policy Admin API
// (getMCPAdmin), so the runtime evaluator and the admin/simulator views can never
// diverge. The Gateway store is published to when a snapshot loads; the Management
// store is NEVER published to (capability isolation). The store pointers are stable
// for the life of the holder — the admin adapter reads them live, so publishing a
// snapshot is immediately visible to a singleton that captured this holder earlier.
type mcpPolicyHolder struct {
	mu     sync.RWMutex
	state  mcpPolicyState
	reason string // bounded, secret-free classification when state == invalid
	gw     *policy.Store
	mgt    *policy.Store

	// Safe metadata cached at publish (all bounded, secret-free — never the raw
	// policy source, a rule body, a file path, or a tenant).
	revision      uint64
	hash          string
	ruleCount     int
	defaultAction string
}

// mcpPolicy is the process-wide node-local policy holder. Its store pointers are
// created once and never replaced, so getMCPAdmin (which captures this holder) always
// observes the snapshot the startup path publishes.
var mcpPolicy = newMCPPolicyHolder()

// newMCPPolicyHolder builds a holder with fresh, empty capability-local stores. The
// stores exist from process start (stable pointers) so getMCPAdmin and the runtime
// share the identical instances; they hold no snapshot until a valid policy loads.
func newMCPPolicyHolder() *mcpPolicyHolder {
	return &mcpPolicyHolder{
		state: mcpPolNotConfigured,
		gw:    policy.NewStore(policy.CapGateway),
		mgt:   policy.NewStore(policy.CapManagement),
	}
}

// compose compiles the startup policy source (if any) for the resolved config and
// returns the compiled snapshot, the runtime PolicyProvider (bound to THIS holder's
// Gateway store), the node-local state, a bounded reason, and an error. It does NOT
// publish — publication is the caller's atomic, post-validation step (publish) — so a
// later activation failure leaves no active snapshot. Contracts:
//
//   - listener disabled OR no policy file ⇒ (nil, nil, not_configured, "", nil):
//     QUAL-3 behavior — Deps.Policy stays nil so the decision-point path is
//     observe-only and decision telemetry stays pending-policy;
//   - present + valid ⇒ (snapshot, provider, loaded, "", nil);
//   - present + invalid ⇒ (nil, nil, invalid, reason, err): fail activation closed.
//
// It reads the file (bounded, traversal-safe) and compiles through the EXISTING
// policy compiler + DefaultLimits (identical hashing/validation the simulator + admin
// use), then verifies the snapshot is Gateway.
func (h *mcpPolicyHolder) compose(sc mcpObserveStartupConfig) (*policy.Snapshot, mcpruntime.PolicyProvider, mcpPolicyState, string, error) {
	if !sc.Enabled || sc.QualificationPolicyFile == "" {
		return nil, nil, mcpPolNotConfigured, "", nil
	}
	raw, reason, err := readPolicyFile(sc.QualificationPolicyFile)
	if err != nil {
		return nil, nil, mcpPolInvalid, reason, err
	}
	// EXACT existing compiler + limits — same bytes ⇒ same canonical hash the
	// simulator + publication workflow compute (no runtime/UI drift).
	snap, err := policy.Compile(raw, policy.CreatedMeta{}, policy.DefaultLimits())
	if err != nil {
		return nil, nil, mcpPolInvalid, "qualification_policy_uncompilable", errPolicy("policy source failed to compile")
	}
	if snap.Capability() != policy.CapGateway {
		// Only a Gateway policy is composable here; a Management (or unset) capability
		// fails closed so the Management surface can never be armed from this path.
		return nil, nil, mcpPolInvalid, "qualification_policy_wrong_capability", errPolicy("policy capability must be gateway")
	}
	return snap, gatewayPolicyProvider{h: h}, mcpPolLoaded, "", nil
}

// publish records the node-local policy outcome. A loaded state publishes the
// compiled snapshot into the Gateway store and caches its safe metadata; every other
// state records the bounded reason and leaves the stores untouched (an invalid or
// absent policy never installs a partial snapshot). A store-publish failure is folded
// to invalid (fail closed).
func (h *mcpPolicyHolder) publish(state mcpPolicyState, reason string, snap *policy.Snapshot) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state = state
	h.reason = reason
	h.revision, h.hash, h.ruleCount, h.defaultAction = 0, "", 0, ""
	if state != mcpPolLoaded || snap == nil {
		return nil
	}
	// Publish into the Gateway store (base = current revision; a fresh store is 0).
	// The store enforces capability match + monotonic revision; a failure here is a
	// fail-closed activation error (no partial snapshot).
	if err := h.gw.Publish(h.gw.CurrentRevision(), snap); err != nil {
		h.state, h.reason = mcpPolInvalid, "qualification_policy_publish_failed"
		return errPolicy("policy snapshot could not be published")
	}
	h.revision = uint64(snap.Revision())
	h.hash = snap.Hash()
	h.ruleCount = snap.RuleCount()
	h.defaultAction = snap.DefaultAction().String()
	return nil
}

// storeFor returns the capability-local store for the Policy Admin API, read LIVE from
// the holder so a snapshot published after getMCPAdmin captured the holder is still
// visible. The runtime PolicyProvider reads the SAME Gateway store.
func (h *mcpPolicyHolder) storeFor(capability string) (*policy.Store, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	switch capability {
	case "gateway":
		return h.gw, true
	case "management":
		return h.mgt, true
	default:
		return nil, false
	}
}

// stores returns the adminapi.PolicyStores adapter over this holder.
func (h *mcpPolicyHolder) stores() *mcpPolicyStores { return &mcpPolicyStores{h: h} }

// invalidateForStartupFailure clears a published snapshot when the listener fails to
// construct or start AFTER the loader published the policy, so a fail-closed startup
// never advertises an active policy for a listener that is not running. It sets the
// state to invalid AND replaces the Gateway store with an empty one, so BOTH the
// holder-status surface (/api/mcp/overview) and the store-backed read (/api/mcp/policy)
// report no active snapshot. A not-loaded holder is left untouched. Safe: the listener
// never bound, so no hot path reads the store; the admin adapter reads h.gw live.
func (h *mcpPolicyHolder) invalidateForStartupFailure() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.state != mcpPolLoaded {
		return
	}
	h.state, h.reason = mcpPolInvalid, "runtime_start_failed"
	h.revision, h.hash, h.ruleCount, h.defaultAction = 0, "", 0, ""
	h.gw = policy.NewStore(policy.CapGateway) // clears store.Current() for apiMCPPolicy
}

// invalidateMCPPolicyOnStartupFailure clears the process-wide node-local policy when
// the listener fails to construct/start after the loader published it.
func invalidateMCPPolicyOnStartupFailure() { mcpPolicy.invalidateForStartupFailure() }

// resetForTest re-initializes the holder's stores + metadata IN PLACE (TEST-ONLY),
// without replacing the holder pointer, so a test starts from an empty active
// snapshot while a singleton that captured this holder (getMCPAdmin, which reads the
// stores LIVE) stays consistent. Production composes exactly once at startup and never
// calls this.
func (h *mcpPolicyHolder) resetForTest() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state, h.reason = mcpPolNotConfigured, ""
	h.revision, h.hash, h.ruleCount, h.defaultAction = 0, "", 0, ""
	h.gw = policy.NewStore(policy.CapGateway)
	h.mgt = policy.NewStore(policy.CapManagement)
}

// composed reports whether a valid node-local policy snapshot is active.
func (h *mcpPolicyHolder) composed() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.state == mcpPolLoaded
}

// status builds the safe policy status from the holder. A failed load is reported as
// invalid with a bounded reason — never as an empty healthy policy.
func (h *mcpPolicyHolder) status() PolicyStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	st := PolicyStatus{
		State:              string(h.state),
		Reason:             h.reason,
		EnforcementEnabled: false,
		ExecutionEnabled:   false,
		FleetDistributed:   false,
	}
	if h.state == mcpPolLoaded {
		st.Source = "qualification_startup"
		st.Capability = protocol.Gateway.String()
		st.Revision = h.revision
		st.Hash = h.hash
		st.RuleCount = h.ruleCount
		st.DefaultAction = h.defaultAction
		st.EvaluationEnabled = true
	}
	return st
}

// ── package wrappers over the process-wide holder ────────────────────────────

// composeGatewayPolicy compiles the startup policy source against the process-wide
// holder (production entry). See (*mcpPolicyHolder).compose.
func composeGatewayPolicy(sc mcpObserveStartupConfig) (*policy.Snapshot, mcpruntime.PolicyProvider, mcpPolicyState, string, error) {
	return mcpPolicy.compose(sc)
}

// publishMCPPolicy records the node-local policy outcome on the process-wide holder.
func publishMCPPolicy(state mcpPolicyState, reason string, snap *policy.Snapshot) error {
	return mcpPolicy.publish(state, reason, snap)
}

// mcpPolicyComposed reports whether a valid node-local snapshot is active (process-
// wide). The telemetry health surface uses it to flip decision telemetry to ready.
func mcpPolicyComposed() bool { return mcpPolicy.composed() }

// mcpPolicyStatus builds the safe policy status from the process-wide holder.
func mcpPolicyStatus() PolicyStatus { return mcpPolicy.status() }

// ── runtime provider ────────────────────────────────────────────────────────────

// gatewayPolicyProvider is the runtime PolicyProvider (runtime Deps.Policy). It
// returns the Gateway store's current snapshot for the Gateway capability and NIL for
// Management — a Gateway qualification snapshot can never be consulted as a Management
// policy. A nil snapshot for Gateway (should never happen once composed) fails the
// runtime closed (SNAPSHOT_UNAVAILABLE), never permissive.
// It holds the HOLDER, not a captured *policy.Store. The holder documents its
// store pointers as stable, but invalidateForStartupFailure and resetForTest both
// REPLACE h.gw — so a captured pointer would keep serving the old store's snapshot
// to the runtime evaluator while the admin surface (which reads the holder live)
// reported no active policy. Nothing reaches that divergence today, because the
// only replacement path runs when the listener never started; reading the holder
// live makes the documented single-source-of-truth invariant true by construction
// rather than by that coincidence.
type gatewayPolicyProvider struct{ h *mcpPolicyHolder }

// PolicySnapshot satisfies mcpruntime.PolicyProvider.
func (p gatewayPolicyProvider) PolicySnapshot(capNS protocol.Capability) *policy.Snapshot {
	if capNS != protocol.Gateway || p.h == nil {
		return nil // Management (and any non-Gateway) is never served a Gateway snapshot
	}
	gw, ok := p.h.storeFor("gateway")
	if !ok || gw == nil {
		return nil
	}
	return gw.Current()
}

// ── loader helpers ───────────────────────────────────────────────────────────

// readPolicyFile reads the operator-supplied policy source path after rejecting a
// directory-traversal path and bounding the size BEFORE the full read (LimitReader
// one byte past the cap so an over-cap file is detected). It returns a bounded reason
// classification on failure and never echoes the path or contents.
func readPolicyFile(path string) ([]byte, string, error) {
	cleaned := filepath.Clean(path)
	if hasDotDotSegment(cleaned) {
		return nil, "qualification_policy_traversal", errPolicy("path traversal not allowed")
	}
	f, err := os.Open(cleaned) // #nosec G304 -- admin-provided startup path, ".." rejected above
	if err != nil {
		return nil, "qualification_policy_unreadable", errPolicy("policy file is not readable")
	}
	defer f.Close() //nolint:errcheck // read-only handle
	raw, err := io.ReadAll(io.LimitReader(f, maxPolicyFileBytes+1))
	if err != nil {
		return nil, "qualification_policy_unreadable", errPolicy("policy file is not readable")
	}
	if len(raw) > maxPolicyFileBytes {
		return nil, "qualification_policy_oversize", errPolicy("policy file exceeds byte bound")
	}
	if len(raw) == 0 {
		return nil, "qualification_policy_empty", errPolicy("policy file is empty")
	}
	return raw, "", nil
}

// errPolicy builds a bounded, secret-free policy composition error. The message is a
// fixed phrase (never a path, rule body, or policy content); the health surface
// further reduces failures to a stable classification code.
func errPolicy(msg string) error { return errors.New("mcp qualification policy: " + msg) }

// ensure the provider satisfies the runtime seam at compile time.
var _ mcpruntime.PolicyProvider = gatewayPolicyProvider{}

// ── safe admin/health surface ────────────────────────────────────────────────

// PolicyStatus is the safe, read-only policy readiness surfaced on the admin
// overview. It distinguishes not_configured / loaded / invalid and reports the
// node-local active snapshot's bounded metadata (revision, canonical hash, rule
// count, default action) plus the truthful posture flags. It NEVER exposes the raw
// policy source, a rule body, the file path, a tenant, or an unbounded compiler
// error, and it NEVER labels the snapshot published / fleet-effective / Production —
// this is a LOCAL Observe evaluation snapshot that is EVALUATED for evidence only.
type PolicyStatus struct {
	State  string `json:"state"` // not_configured | loaded | invalid
	Reason string `json:"reason,omitempty"`
	// Source classifies where the active snapshot came from. "qualification_startup"
	// is the node-local startup source — deliberately NOT "published"/"fleet".
	Source        string `json:"source,omitempty"`
	Capability    string `json:"capability,omitempty"`
	Revision      uint64 `json:"revision,omitempty"`
	Hash          string `json:"hash,omitempty"`
	RuleCount     int    `json:"rule_count,omitempty"`
	DefaultAction string `json:"default_action,omitempty"`
	// EvaluationEnabled is true only when a valid snapshot is composed: decision-point
	// methods are evaluated against it and their true results recorded.
	EvaluationEnabled bool `json:"evaluation_enabled"`
	// EnforcementEnabled is always false: this is Observe (evaluate + record), never
	// enforcement rollout. ExecutionEnabled is always false: no executor is composed,
	// so an evaluated ALLOW never executes. FleetDistributed is always false: the
	// snapshot is node-local, never CP→DP distributed.
	EnforcementEnabled bool `json:"enforcement_enabled"`
	ExecutionEnabled   bool `json:"execution_enabled"`
	FleetDistributed   bool `json:"fleet_distributed"`
}

// decisionTelemetryLabel reports the truthful decision-telemetry readiness for the
// process-wide holder. See decisionTelemetryLabelFor.
func decisionTelemetryLabel(telemetryReady bool) string {
	return decisionTelemetryLabelFor(mcpPolicyComposed(), telemetryReady)
}

// decisionTelemetryLabelFor is the pure readiness classifier. It is "ready" ONLY when
// a node-local policy snapshot is composed AND the durable telemetry plane is active
// (so an evaluated decision is actually committed); "pending_telemetry" when a policy
// is composed but telemetry is not (decisions evaluated but not durably recorded); and
// "pending_policy" otherwise (the QUAL-3 default — no policy, so only the denial lane
// commits). It never reports ready without a real snapshot.
func decisionTelemetryLabelFor(policyComposed, telemetryReady bool) string {
	switch {
	case policyComposed && telemetryReady:
		return "ready"
	case policyComposed:
		return "pending_telemetry"
	default:
		return "pending_policy"
	}
}
