package main

// MCP live-tier PRODUCTION DEPENDENCY composition (§3 entrypoint, §5–§16 real deps,
// atomicity, fail-closed, never-arm).
//
// This is the ONE production caller of composeGatewayLiveTierInto: the real dependency
// graph the live executor needs — a bounded upstreamclient.Client (destination resolver +
// SSRF policy + system-root trust), a materialize-capable broker.Broker (KEK secret
// provider + profile store + shared registry/catalog), the durable events manager, and a
// Gateway response-inspection profile — is constructed HERE from production authorities and
// handed to composeGatewayLiveTierInto, which performs the single Deps.Executor assignment.
//
// It deliberately does NOT import internal/mcp/execution and does NOT assign Deps.Executor:
// the execution-posture wall pins mcp_live_startup.go + mcp_shadow_startup.go as the only
// two importers/assigners, and this builder stays outside that wall by delegating the
// executor construction + assignment to composeGatewayLiveTierInto. A synthetic collaborator
// therefore has no shorter path to Deps.Executor than a production one — both go through the
// same seam (§20 anti-synthetic-fallback: there is no production code path that installs a
// test double).
//
// COMPOSED != ARMED (§16). This builder composes the guarded executor and STOPS.
// composeGatewayLiveTierInto records the tier COMPOSED and leaves the armed bit false, so
// modeExecReady refuses every Canary/Production transition. Arming is a separate,
// node-readiness-gated act (mcp_live_arming.go); a restart re-runs composition but NEVER
// re-arms (§17) — the armed bit is not persisted and no startup path calls the arming hook.
//
// ATOMICITY (§14/§15). Every collaborator is constructed into LOCAL variables and validated
// BEFORE composeGatewayLiveTierInto is called even once. Any failure returns early with a
// bounded reason and Deps.Executor is never touched — there is no half-composed live tier,
// and a composition failure can never arm (nothing was published).
//
// FAIL-CLOSED (§5–§12). A missing/unreadable KEK, a nil events manager, or an upstream
// construction error each aborts composition and records the machine-readable per-dependency
// reason. There is NO insecure fallback: no ephemeral KEK, no permissive resolver, no
// InsecureSkipVerify, no synthetic dependency. The credential broker is composed with its
// real KEK and profile store but ZERO providers registered — the honest state of the
// remaining pre-Canary gap (no production credential Provider adapter exists yet), so any
// tool that requires a materialized credential fails closed at the broker while a
// no-credential / read-first tool can execute once the node is explicitly armed.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/broker"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/destination"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
	"github.com/KidCarmi/Culvert/internal/secret"
)

// Per-dependency readiness reason tokens (§13). Bounded, machine-readable, stable strings —
// never a raw error, path, or secret. Consumed by the operator health surface (§22) and the
// Canary readiness rows (§18). A reason ending in a non-"ready" token is a fail-closed state.
const (
	// Top-level composition outcomes.
	liveDepsReasonNotRequested  = "not_requested"         // CULVERT_MCP_LIVE_DEPS unset/false
	liveDepsReasonConfigInvalid = "config_invalid"        // enabled but partial (no KEK)
	liveDepsReasonEventsAbsent  = "durable_events_absent" // telemetry not composed
	liveDepsReasonComposed      = "composed"              // full graph composed (NOT armed)

	// Per-dependency tokens.
	liveDepKEKReady             = "kek_ready"
	liveDepKEKUnavailable       = "kek_unavailable"
	liveDepProfileStoreReady    = "profile_store_ready"
	liveDepBrokerNoProvider     = "broker_composed_no_provider" // honest pre-Canary gap
	liveDepResolverReady        = "resolver_ready"
	liveDepDestPolicyGateway    = "gateway_policy_https_no_private"
	liveDepTrustSystemRoots     = "system_roots"
	liveDepUpstreamReady        = "upstream_ready"
	liveDepUpstreamFailed       = "upstream_construct_failed"
	liveDepEventsReady          = "events_ready"
	liveDepResponseProfileReady = "response_profile_ready"
	liveDepPending              = "pending"
)

// mcpLiveProdDeps is the per-dependency machine-readable readiness snapshot (§13). Every
// field is a bounded token from the constants above; there are no free-form strings, paths,
// or secrets. A field left at liveDepPending means composition aborted before reaching it.
type mcpLiveProdDeps struct {
	KEK             string `json:"kek"`
	ProfileStore    string `json:"credential_profiles"`
	Broker          string `json:"credential_broker"`
	Resolver        string `json:"destination_resolver"`
	DestinationPol  string `json:"destination_policy"`
	TrustRoots      string `json:"trust_roots"`
	Upstream        string `json:"upstream_client"`
	Events          string `json:"durable_events"`
	ResponseProfile string `json:"response_inspection"`
}

// mcpLiveProdStatus is the observable composition state (§13/§22). It never carries a live
// secret — the KEK is present only as a readiness token, never as key material.
type mcpLiveProdStatus struct {
	Requested bool            `json:"requested"`
	Composed  bool            `json:"composed"`
	Reason    string          `json:"reason"`
	Deps      mcpLiveProdDeps `json:"dependencies"`
}

// mcpLiveProdHolder is the process-global, race-safe holder of the production live-deps
// composition status. Distinct from the lifecycle holder (mcpLiveTierFor): this records
// WHY the production dependency graph is or is not composed, for the health/readiness
// surfaces; the lifecycle holder records the absent→composed→armed→quiescing state machine.
type mcpLiveProdHolder struct {
	mu     sync.RWMutex
	status mcpLiveProdStatus
}

var globalMCPLiveProd = &mcpLiveProdHolder{
	status: mcpLiveProdStatus{Reason: liveDepsReasonNotRequested, Deps: pendingLiveProdDeps()},
}

// pendingLiveProdDeps returns a deps snapshot with every field at liveDepPending — the
// pre-composition baseline.
func pendingLiveProdDeps() mcpLiveProdDeps {
	return mcpLiveProdDeps{
		KEK:             liveDepPending,
		ProfileStore:    liveDepPending,
		Broker:          liveDepPending,
		Resolver:        liveDepPending,
		DestinationPol:  liveDepPending,
		TrustRoots:      liveDepPending,
		Upstream:        liveDepPending,
		Events:          liveDepPending,
		ResponseProfile: liveDepPending,
	}
}

func (h *mcpLiveProdHolder) set(s mcpLiveProdStatus) {
	h.mu.Lock()
	h.status = s
	h.mu.Unlock()
}

// snapshot returns a copy of the current status (safe to hand to a JSON/health surface).
func (h *mcpLiveProdHolder) snapshot() mcpLiveProdStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.status
}

// invalidateForStartupFailure resets the production live-deps status to a bounded
// "runtime_start_failed" (not composed, all deps pending) when the runtime listener fails to
// start AFTER a successful composition. It acts ONLY on a currently-composed status, so a node
// that never composed the live tier is a no-op — the operator surface stops reporting
// events_ready / a composed executor for a listener that never started and whose event manager
// was closed.
func (h *mcpLiveProdHolder) invalidateForStartupFailure() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.status.Composed {
		return
	}
	h.status = mcpLiveProdStatus{Requested: true, Reason: "runtime_start_failed", Deps: pendingLiveProdDeps()}
}

// invalidateMCPLiveOnStartupFailure clears the live-tier holders this package publishes during
// composition (the lifecycle object + the production-deps status) after the runtime listener
// failed to start. Both are guarded to act only when the live tier was actually composed, so a
// stock node is a no-op. Called from invalidateMCPActivationOnStartupFailure alongside the
// policy/inventory/telemetry invalidation, so a startup failure leaves NO stale "composed"
// signal on any surface and an in-process retry starts clean.
func invalidateMCPLiveOnStartupFailure() {
	globalMCPLiveProd.invalidateForStartupFailure()
	mcpLiveTierFor(rollout.CapabilityGateway).resetForStartupFailure()
}

// mcpLiveProdStatusView returns the current production live-deps status as a viewer-safe,
// bounded map for the read-only tier/health surface (§22). Every value is a machine-readable
// token or a bool — never a path, error, or secret. The KEK appears ONLY as a readiness
// token (kek_ready / kek_unavailable / pending), never as key material or a file path.
func mcpLiveProdStatusView() map[string]any {
	s := globalMCPLiveProd.snapshot()
	return map[string]any{
		"requested": s.Requested,
		"composed":  s.Composed,
		"reason":    s.Reason,
		"dependencies": map[string]any{
			"kek":                  s.Deps.KEK,
			"credential_profiles":  s.Deps.ProfileStore,
			"credential_broker":    s.Deps.Broker,
			"destination_resolver": s.Deps.Resolver,
			"destination_policy":   s.Deps.DestinationPol,
			"trust_roots":          s.Deps.TrustRoots,
			"upstream_client":      s.Deps.Upstream,
			"durable_events":       s.Deps.Events,
			"response_inspection":  s.Deps.ResponseProfile,
		},
	}
}

// prodDestinationResolver adapts a bounded net.Resolver to destination.Resolver. It returns
// addresses only (LookupNetIP, never a CNAME chain) and honors the caller's context
// deadline. It performs NO private-address filtering itself: the SSRF rejection is owned by
// destination.Resolve + DefaultGatewayPolicy, which fail the WHOLE answer closed if ANY
// returned address is private/forbidden (mixed public/private is single-private poison). The
// adapter is deliberately thin so it cannot silently widen that guard.
type prodDestinationResolver struct {
	r *net.Resolver
}

// errLiveDepsKEKSymlink is the fail-closed reason for a KEK path whose final component is a
// symlink (§21). Key-free — it names the constraint, never the path.
var errLiveDepsKEKSymlink = errors.New("mcp live deps: credential KEK path final component is a symlink")

// kekPathNotSymlink rejects a KEK path whose final component is a symlink. A non-existent
// path is accepted (the provider generates a fresh 0600 file there). Any other lstat error
// (e.g. a permission error on the parent) is returned so composition fails closed rather than
// proceeding on an unverifiable path.
func kekPathNotSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return errLiveDepsKEKSymlink
	}
	return nil
}

func (p prodDestinationResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	// "ip" ⇒ both A and AAAA; addresses only. The caller bounds this with a context deadline
	// and the destination inspector caps the answer count (MaxDNSAddresses).
	return p.r.LookupNetIP(ctx, "ip", host)
}

// acquireProductionKEK validates the KEK path and opens the file-based KEK provider fail-closed.
// It rejects a path whose final component is a SYMLINK — a symlinked key file could redirect the
// 0600 write/read to an attacker-controlled target that secret.load's permission check would not
// see through (defense-in-depth; a parent-directory symlink race is the recorded residual, out of
// scope for a config-time lstat). secret.ValidateProvider then generates-or-loads the 0600 key
// once and REJECTS a world/group-readable or wrong-size file. There is NO plaintext or ephemeral
// fallback (§5).
func acquireProductionKEK(path string) (*secret.Provider, error) {
	if err := kekPathNotSymlink(path); err != nil {
		return nil, err
	}
	kek := secret.FileProvider(path)
	if err := secret.ValidateProvider(kek); err != nil {
		return nil, err
	}
	return kek, nil
}

// newProductionUpstreamClient builds the hardened upstream MCP client. NOT a generic
// http.Client: upstreamclient bounds per-server pools, admits only the V1 upstream method set,
// pins the resolved destination (no connect-time re-resolution), enforces the narrow Gateway
// destination policy (DefaultGatewayPolicy: https only, no private, no cross-origin redirect,
// no scheme downgrade), and NEVER uses InsecureSkipVerify for the unpinned branch.
//
// TRUST MODEL + the recorded connectivity gap (Codex PR #1291). RootCAs nil ⇒ the SYSTEM root
// pool is the CA pool for a server WITHOUT a pinned identity; Identity nil ⇒ the default
// spkiVerifier compares the leaf's base64 SHA-256 SPKI against the registry's PinnedIdentity
// when one is present. In the current inventory contract EVERY registered server MUST carry a
// nonempty PinnedIdentity (mcp_inventory.go), so in practice the client always takes the
// pinned branch and the system-roots-only path is not reached for a real server — the
// per-server SPKI pin is the trust anchor, not a public chain. Two documented formats are
// therefore NOT yet consumable by this client and are part of the remaining pre-Canary
// connectivity work, NOT a defect here (the tier never arms/executes in this build, and the
// qualification endpoint is a never-dialed reference today):
//   - the documented endpoint scheme `mcp+https://` (DefaultGatewayPolicy admits only literal
//     `https`, so destination.Canonicalize rejects it — an unsupported scheme fails closed, it
//     never downgrades or dials insecurely); and
//   - a SPIFFE-format PinnedIdentity (the default spkiVerifier reads it as an SPKI digest, so it
//     would fail closed rather than trust the wrong leaf).
//
// Supporting either — endpoint-scheme translation at the execution boundary and an
// identity-type-aware verifier — is tracked with the credential-Provider adapter and
// SPKI/SPIFFE pin-provisioning as the pre-Canary connectivity blockers (see the report). The
// fail-closed direction is preserved throughout: an unsupported scheme or a mismatched identity
// means NO connection, never an unauthenticated one.
func newProductionUpstreamClient() (*upstreamclient.Client, error) {
	resolver := prodDestinationResolver{r: &net.Resolver{}}
	return upstreamclient.New(upstreamclient.Config{
		Limits:           upstreamclient.DefaultLimits(),
		Resolver:         resolver,
		Policy:           destination.DefaultGatewayPolicy(),
		InspectionLimits: limits.DefaultGatewayInspection(),
		Identity:         nil, // ⇒ default SPKI verifier (pins the registry PinnedIdentity when present)
		RootCAs:          nil, // ⇒ system roots for the unpinned branch
		Clock:            nil, // ⇒ time.Now
	}, limits.DefaultGateway())
}

// composeProductionGatewayLiveTier is THE single production composition entrypoint (§3). It
// resolves the opt-in, validates it, constructs the real dependency graph from production
// authorities, and — only if every collaborator is valid — delegates to
// composeGatewayLiveTierInto for the single Deps.Executor assignment. It NEVER arms.
//
// Parameters carry the shared, already-composed authorities from the observe-runtime
// assembly so the live tier observes the IDENTICAL registry/catalog/events the rest of the
// Gateway does:
//   - cfg: the Gateway runtime config being assembled (Deps.Executor assigned by the seam).
//   - lp:  the resolved+cleaned live-deps config (opt-in + KEK path).
//   - reg/cat: the shared read-only inventory backing the broker.
//   - evMgr: the durable events manager (tel.Manager()); REQUIRED — nil fails closed.
//
// The collaborators are constructed with a nil clock (⇒ time.Now); a production node has no
// clock to inject and the tests that need determinism inject it into their own events manager.
//
// It records the machine-readable status on globalMCPLiveProd on every path (composed or
// fail-closed) so the operator health surface and the Canary readiness rows can read WHY.
func composeProductionGatewayLiveTier(cfg *mcpruntime.Config, lp mcpLiveProductionConfig, reg *registry.Registry, cat *catalog.Catalog, evMgr *events.Manager) {
	// Not requested: record and compose nothing (byte-identical to a build without the flag).
	if !lp.Requested {
		globalMCPLiveProd.set(mcpLiveProdStatus{Requested: false, Reason: liveDepsReasonNotRequested, Deps: pendingLiveProdDeps()})
		return
	}
	// Partial config fails closed (enabled but no KEK). No collaborator is constructed.
	if err := validateMCPLiveProductionConfig(lp); err != nil {
		globalMCPLiveProd.set(mcpLiveProdStatus{Requested: true, Reason: liveDepsReasonConfigInvalid, Deps: pendingLiveProdDeps()})
		logger.Printf("MCP gateway live production deps not composed: config invalid (fail-closed): %v", sanitizeLog(err.Error()))
		return
	}

	deps := pendingLiveProdDeps()

	// (1) Durable events are REQUIRED before any live tier (evidence-before-side-effect). A
	// live tier that cannot record what it executed is refused. This is checked FIRST because
	// it needs no construction and its absence means telemetry is not composed on this node.
	if evMgr == nil {
		deps.Events = liveDepsReasonEventsAbsent
		globalMCPLiveProd.set(mcpLiveProdStatus{Requested: true, Reason: liveDepsReasonEventsAbsent, Deps: deps})
		logger.Printf("MCP gateway live production deps not composed: durable telemetry (events) not configured; the live tier requires it (fail-closed)")
		return
	}
	deps.Events = liveDepEventsReady

	// (2) Production credential KEK (§5/§21). acquireProductionKEK rejects a symlinked path then
	// opens the file-based KEK fail-closed (no plaintext/ephemeral fallback; world/group-readable
	// or wrong-size rejected by secret.load).
	kek, err := acquireProductionKEK(lp.KEKFile)
	if err != nil {
		deps.KEK = liveDepKEKUnavailable
		globalMCPLiveProd.set(mcpLiveProdStatus{Requested: true, Reason: liveDepKEKUnavailable, Deps: deps})
		logger.Printf("MCP gateway live production deps not composed: credential KEK unavailable (fail-closed): %v", sanitizeLog(err.Error()))
		return
	}
	deps.KEK = liveDepKEKReady

	// (3) Credential profile store + materialize-capable broker (§6/§8). The broker is
	// constructed with its real KEK, a real profile store, and the SHARED registry/catalog —
	// but ZERO providers registered. That is the truthful pre-Canary posture: no production
	// credential Provider adapter exists yet, so any tool needing a materialized credential
	// fails closed at the broker (a no-op provider is NEVER installed as a stand-in). A
	// no-credential / read-first tool executes without ever reaching a provider.
	profiles := profile.NewStore(limits.DefaultCredential())
	deps.ProfileStore = liveDepProfileStoreReady
	brk := broker.New(broker.Deps{
		Profiles: profiles,
		Registry: reg,
		Catalog:  cat,
		KEK:      kek,
		Clock:    nil, // ⇒ time.Now
	}, limits.DefaultCredential())
	deps.Broker = liveDepBrokerNoProvider

	// (4) Hardened upstream client (§7). Constructed by newProductionUpstreamClient (see its
	// doc for the trust model and the recorded connectivity gap).
	deps.DestinationPol = liveDepDestPolicyGateway
	deps.TrustRoots = liveDepTrustSystemRoots
	deps.Resolver = liveDepResolverReady
	upstream, err := newProductionUpstreamClient()
	if err != nil {
		deps.Upstream = liveDepUpstreamFailed
		globalMCPLiveProd.set(mcpLiveProdStatus{Requested: true, Reason: liveDepUpstreamFailed, Deps: deps})
		logger.Printf("MCP gateway live production deps not composed: upstream client construction failed (fail-closed): %v", sanitizeLog(err.Error()))
		return
	}
	deps.Upstream = liveDepUpstreamReady

	// (5) Response DLP/inspection profile (§12). The live executor inspects every upstream
	// response BEFORE egress; the profile MUST be a Gateway profile with a positive output
	// bound (composeGatewayLiveTierInto re-checks this fail-closed).
	responseProfile := inspection.DefaultGatewayProfile(1)
	deps.ResponseProfile = liveDepResponseProfileReady

	// ATOMIC PUBLISH (§14). Every collaborator above is valid; NOW delegate the single
	// Deps.Executor assignment to the composition seam. LiveGate is left nil so the real
	// production side-effect gate is composed (a production build can never inject a test
	// gate). On the seam's own fail-closed path (which re-validates the response profile and
	// constructs the executor) Deps.Executor stays untouched and we record the seam reason.
	if err := composeGatewayLiveTierInto(cfg, liveTierComposition{
		Upstream:        upstream,
		Broker:          brk,
		Events:          evMgr,
		ResponseProfile: responseProfile,
		Clock:           nil, // ⇒ time.Now
		// LiveGate: nil — production real gate.
	}); err != nil {
		globalMCPLiveProd.set(mcpLiveProdStatus{Requested: true, Reason: mcpLiveTierFor(rollout.CapabilityGateway).Reason(), Deps: deps})
		logger.Printf("MCP gateway live production deps not composed: executor composition failed (fail-closed): %v", sanitizeLog(err.Error()))
		return
	}

	globalMCPLiveProd.set(mcpLiveProdStatus{Requested: true, Composed: true, Reason: liveDepsReasonComposed, Deps: deps})
	logger.Printf("MCP gateway LIVE production dependency graph composed (real upstream + credential broker + durable events + response DLP present; NOT armed). Arming is a separate, node-readiness-gated act.")
}
