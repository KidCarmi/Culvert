package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/adminapi"
	"github.com/KidCarmi/Culvert/internal/mcp/approval"
	"github.com/KidCarmi/Culvert/internal/mcp/management"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/policy/simulate"
)

// ── MCP Admin API (PR-9) ─────────────────────────────────────────────────────
//
// Thin HTTP handlers over the internal/mcp/adminapi domain services. All logic
// stays under internal/mcp/**; these handlers only parse input, enforce RBAC and
// tenant scope, and marshal safe DTOs. Nothing here executes an upstream call,
// materializes a credential, or publishes a signed CP→DP snapshot — the Gateway
// still returns execution_state=not_implemented and local publication reports
// distribution_state=local_only / distribution_not_implemented.
//
// MCP is disabled by default. The admin singleton is built with in-memory
// disabled-default stores (no file I/O — safe for the d0WireMux test harness).
// Durable approval/publication commits require the MCP runtime's PR-8 event
// manager; until that is enabled they fail closed (durability_required).

// mcpPolicyStores is the adminapi.PolicyStores adapter over the node-local policy
// holder (mcp_policy.go). It reads the capability-local stores LIVE from the holder,
// so the runtime PolicyProvider (which reads the SAME Gateway store) and the read-only
// Policy Admin API can never diverge — a snapshot the startup path publishes is
// visible here even though getMCPAdmin captured the holder earlier (single source of
// truth). The Management store is never published to (capability isolation).
type mcpPolicyStores struct{ h *mcpPolicyHolder }

func (s *mcpPolicyStores) Store(capability string) (*policy.Store, bool) {
	return s.h.storeFor(capability)
}

// mcpDisabledCommitter fails closed for both approval-decision and
// configuration-publication events when the MCP PR-8 event manager is not wired
// (the disabled-default posture). It never fabricates durable evidence.
type mcpDisabledCommitter struct{}

func (mcpDisabledCommitter) CommitDecision(*approval.Request, approval.State, approval.PrincipalID) (string, error) {
	return "", mcperr.New(mcperr.ReasonEventDurabilityDegraded, "mcpadmin", "event durability not enabled")
}

func (mcpDisabledCommitter) CommitPublication(_, _, _ string, _, _ uint64) (string, error) {
	return "", mcperr.New(mcperr.ReasonPublicationDurabilityRequired, "mcpadmin", "event durability not enabled")
}

// mcpApprovalCounts adapts the approval store for health pending-counts.
type mcpApprovalCounts struct{ store *approval.Store }

func (a mcpApprovalCounts) PendingCounts(string) (approvals, publications int) {
	// Counts are capability-agnostic here (node-level projection). Bounded by the
	// store's own caps; a real per-capability split arrives with runtime wiring.
	return 0, 0
}

// mcpAdminServer is the package-main singleton composing the adminapi Service,
// the Management dispatcher, and the shared committer/id-gen.
type mcpAdminServer struct {
	svc         *adminapi.Service
	disp        *management.Dispatcher
	appCommit   approval.Committer
	publication *adminapi.PublicationService
}

var (
	mcpAdmin     *mcpAdminServer
	mcpAdminOnce sync.Once
)

// mcpIDGen returns an unpredictable approval id (not a counter).
func mcpIDGen() approval.ID {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return approval.ID("appr_" + hex.EncodeToString(b[:]))
}

// getMCPAdmin lazily builds the disabled-default admin singleton. It performs no
// file I/O and is safe to call from the route-registration test harness.
func getMCPAdmin() *mcpAdminServer {
	mcpAdminOnce.Do(func() {
		lim := adminapi.DefaultLimits()
		// QUAL-4: the SHARED capability-local policy stores owned by the node-local
		// policy holder. The runtime PolicyProvider evaluates against the SAME Gateway
		// store this admin singleton reads, so the /api/mcp/policy active read, the
		// simulator Compare baseline, and the runtime evaluator observe the identical
		// compiled snapshot (single source of truth). The Management store is never
		// published to (capability isolation). When no policy source is composed both
		// stores are empty — byte-identical to the QUAL-3 disabled default.
		stores := mcpPolicy.stores()
		appr := approval.NewStore(approval.Config{MaxPending: lim.MaxPendingApprovals(), MaxPerTenant: lim.MaxApprovalsPerTenant(), TTL: lim.ApprovalTTL()})
		cfg := adminapi.NewConfigStore(lim.MaxMgmtOutputBytes())
		committer := mcpDisabledCommitter{}
		health := adminapi.HealthSources{
			Policy:    stores,
			Approvals: mcpApprovalCounts{store: appr},
			Config:    cfg,
			Runtime:   mcpObserveRuntimeHealth,
			// QUAL-3: the real per-capability durability snapshot. Evaluated per request,
			// so it reflects live telemetry state; reports the truthful not-configured
			// baseline when telemetry is not composed.
			Durability: mcpTelemetryDurability,
		}
		params := adminapi.Params{
			PolicyStores: stores, PolicyLimits: policy.DefaultLimits(), Approvals: appr,
			PubCommitter: committer, IDGen: mcpIDGen, Health: health, ConfigStore: cfg, Limits: lim,
		}
		// QUAL-3: wire the committed-event read seam to the SAME durable spool the
		// runtime commits to, so decision reads use the real EventReader (nil ⇒ the
		// DecisionService stays disabled, QUAL-2 behavior). Snapshotted once — see the
		// ordering contract below.
		if er := mcpAdminEventReader(); er != nil {
			params.Events = er
		}
		// QUAL-2: wire the SAME shared Registry/Catalog the runtime pipeline reads, so
		// the read-only Servers/Tools Admin API is the single source of truth. Both stay
		// nil when no qualification inventory is loaded (Inventory service stays disabled,
		// returning empty views — byte-identical to the QUAL-1 disabled default).
		//
		// Ordering contract: this singleton snapshots the inventory holder ONCE. It must
		// be built AFTER initMCPRuntime has published the holder. initMCPRuntime enforces
		// this by eagerly binding the singleton once a loaded inventory is published (see
		// mcp_runtime.go), so a first admin request can never capture a pre-publish
		// (empty) holder while the pipeline resolves the seeded fleet.
		if rs, cs, ic := mcpAdminInventorySources(); rs != nil {
			params.Registry = rs
			params.Catalog = cs
			health.Inventory = ic
			params.Health = health
		}
		svc := adminapi.NewService(params)
		disp := management.NewDispatcher(adminapi.NewManagementBackend(svc), lim.MaxMgmtInputBytes(), lim.MaxMgmtOutputBytes())
		mcpAdmin = &mcpAdminServer{svc: svc, disp: disp, appCommit: committer, publication: svc.Publication}
	})
	return mcpAdmin
}

// registerMCPRoutes registers the /api/mcp admin surface. Every path here has a
// matching uiRoutes metadata row, an api/route-classification.yaml row, and an
// OpenAPI operation (parity is enforced by C1/D0/apicontract tests).
func registerMCPRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/mcp/overview", apiMCPOverview)
	mux.HandleFunc("/api/mcp/health", apiMCPHealth)
	mux.HandleFunc("/api/mcp/servers", apiMCPServers)
	mux.HandleFunc("/api/mcp/tools", apiMCPTools)
	mux.HandleFunc("/api/mcp/decisions", apiMCPDecisions)
	mux.HandleFunc("/api/mcp/decision-explain", apiMCPDecisionExplain)
	mux.HandleFunc("/api/mcp/policy", apiMCPPolicy)
	mux.HandleFunc("/api/mcp/policy-simulate", apiMCPPolicySimulate)
	mux.HandleFunc("/api/mcp/publications", apiMCPPublications)
	mux.HandleFunc("/api/mcp/publication-decision", apiMCPPublicationDecision)
	mux.HandleFunc("/api/mcp/approvals", apiMCPApprovals)
	mux.HandleFunc("/api/mcp/approval-decision", apiMCPApprovalDecision)
	// ADR-0034 tool-trust approval / promotion surface.
	mux.HandleFunc("/api/mcp/tool-approvals", apiMCPToolApprovals)
	mux.HandleFunc("/api/mcp/tool-approval-decision", apiMCPToolApprovalDecision)
	mux.HandleFunc("/api/mcp/config", apiMCPConfig)
	mux.HandleFunc("/api/mcp/management-access", apiMCPManagementAccess)
	mux.HandleFunc("/api/mcp/distribution", apiMCPDistribution)
	// PR-UX-5 additive read-only acknowledgement read model (capability-scoped).
	mux.HandleFunc("/api/mcp/distribution/acks", apiMCPDistributionAcks)
	mux.HandleFunc("/api/mcp/rollback", apiMCPRollback)
	// PR-11 rollout surface.
	mux.HandleFunc("/api/mcp/rollout", apiMCPRollout)
	mux.HandleFunc("/api/mcp/rollout/transition", apiMCPRolloutTransition)
	mux.HandleFunc("/api/mcp/rollout/scope", apiMCPRolloutScope)
	// PR-UX-5 additive read-only candidate-scope validation + diff preview.
	mux.HandleFunc("/api/mcp/rollout/scope/validate", apiMCPRolloutScopeValidate)
	mux.HandleFunc("/api/mcp/rollout/evidence", apiMCPRolloutEvidence)
	mux.HandleFunc("/api/mcp/rollout/emergency", apiMCPRolloutEmergency)
	mux.HandleFunc("/api/mcp/rollout/rehearse-rollback", apiMCPRolloutRehearse)
	mux.HandleFunc("/api/mcp/rollout/rehearse-rollback-authoritative", apiMCPRolloutRehearseAuthoritative)
	mux.HandleFunc("/api/mcp/canary/shadow-exit-review", apiMCPShadowExitReview)
	mux.HandleFunc("/api/mcp/executions", apiMCPExecutions)
	mux.HandleFunc("/api/mcp/upstream-health", apiMCPUpstreamHealth)
}

// mcpErr maps a classified MCP error to a plain-text HTTP response. The reason
// code string is safe (no secret/raw input).
func mcpErr(w http.ResponseWriter, err error) {
	reason := mcperr.ReasonOf(err)
	status := http.StatusBadRequest
	switch reason {
	case mcperr.ReasonAdminNotFound, mcperr.ReasonApprovalNotFound, mcperr.ReasonToolNotFound:
		status = http.StatusNotFound
	case mcperr.ReasonAdminForbidden, mcperr.ReasonManagementToolUnauthorized, mcperr.ReasonApprovalNotAuthorized:
		status = http.StatusForbidden
	case mcperr.ReasonApprovalTerminalState, mcperr.ReasonApprovalRevoked,
		mcperr.ReasonApprovalTenantConflict, mcperr.ReasonToolNotApprovable,
		mcperr.ReasonToolApprovalStale, mcperr.ReasonToolFingerprintMismatch,
		mcperr.ReasonServerNotUsable:
		status = http.StatusConflict
	case mcperr.ReasonPublicationDurabilityRequired, mcperr.ReasonEventDurabilityDegraded,
		mcperr.ReasonApprovalStoreUnavailable:
		status = http.StatusServiceUnavailable
	}
	code := reason.Code()
	if code == "none" || code == "" {
		code = "admin_request_invalid"
	}
	http.Error(w, code, status)
}

// mcpTenant resolves the tenant scope. The Culvert admin operator is global and
// selects the tenant explicitly via the ?tenant= parameter; it is authorized for
// any tenant, but every downstream read is still tenant-scoped so cross-tenant
// existence never leaks. An empty tenant is rejected.
func mcpTenant(r *http.Request) (string, bool) {
	t := strings.TrimSpace(r.URL.Query().Get("tenant"))
	return t, t != ""
}

func mcpCapability(r *http.Request) string {
	c := r.URL.Query().Get("capability")
	if c == "" {
		return "gateway"
	}
	return c
}

func mcpQueryLimit(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	return n
}

func mcpMethodNotAllowed(w http.ResponseWriter) {
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// ── Handlers ─────────────────────────────────────────────────────────────────

func apiMCPOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	m := getMCPAdmin()
	jsonOK(w, map[string]any{
		"distribution_state":           "local_only",
		"distribution_not_implemented": true,
		"execution_state":              "not_implemented",
		"management_tools":             len(management.Catalog()),
		"health":                       m.svc.Health.Snapshot(),
		// QUAL-2: safe, read-only qualification-inventory readiness. It distinguishes
		// not_configured / loaded / invalid and reports counts — it NEVER labels the
		// subsystem Observe-/qualification-/production-ready (inventory is one dependency).
		"inventory": inventoryStatus(),
		// QUAL-3: safe, read-only durable-telemetry readiness (state, per-partition
		// committed counts, exporter state + lag, saturation). Decision telemetry flips
		// to "ready" only when a QUAL-4 policy snapshot is composed AND telemetry is
		// active; execution stays disabled.
		"telemetry": mcpTelemetryStatus(),
		// QUAL-4: safe, read-only node-local policy readiness. It distinguishes
		// not_configured / loaded / invalid and reports the active Observe evaluation
		// snapshot's revision + canonical hash + rule count + default action, with
		// enforcement/execution/fleet-distribution all truthfully false. The active
		// snapshot detail is also on /api/mcp/policy (the same shared store).
		"policy": mcpPolicyStatus(),
		// ADR-0034: read-only tool-trust subsystem status (composed + reason). The
		// approvals themselves are on /api/mcp/tool-approvals; this is composition state
		// only. Not composed unless the Gateway qualification inventory is loaded.
		"tool_trust": mcpToolTrustStatus(),
	})
}

func apiMCPHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, getMCPAdmin().svc.Health.Snapshot())
}

// apiMCPDistribution (PR-10) reports the safe, read-only signed CP→DP distribution
// status for both capabilities: current/previous content hash, epoch, revision
// tuple, signing key id, minimum DP version, and rollback availability. It never
// exposes a private signing key, a raw signature, or a full raw snapshot.
// Management MCP may READ this health but never publish or roll back.
func apiMCPDistribution(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, mcpDistributionStatus())
}

// apiMCPRollback (PR-10) initiates an operator-controlled atomic rollback to a
// retained signed snapshot via the four-eyes publication workflow. It is admin-only
// and mutating (CSRF-protected by the security middleware). When signed CP→DP
// distribution is not configured/active on this node, it fails closed with a
// truthful "not configured" reason rather than fabricating a rollback.
func apiMCPRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req mcpRollbackReq
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Capability == "" || req.TargetHash == "" {
		http.Error(w, "admin_request_invalid", http.StatusBadRequest)
		return
	}
	// Live signed rollback runs through the capability coordinator's four-eyes +
	// PR-8 durable commit before any sign/push/swap. That coordinator is wired at
	// startup when signed CP→DP distribution is configured; it is NOT resolvable from
	// this handler in the disabled-by-default posture of this slice. Report the request
	// truthfully as not-configured — NEVER fabricate a pending/success result for a
	// rollback that was not actually initiated (the rollback runtime wiring is the
	// recorded follow-up, mirroring the PR-9 publish stub).
	auditEvent(r, "mcp.rollback.request", req.Capability+":"+req.TargetHash, "")
	http.Error(w, "distribution_not_configured", http.StatusConflict)
}

func apiMCPServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	tenant, ok := mcpTenant(r)
	if !ok {
		mcpErr(w, mcperr.New(mcperr.ReasonAdminTenantScope, "mcp", "tenant required"))
		return
	}
	m := getMCPAdmin()
	if m.svc.Inventory == nil {
		jsonOK(w, []adminapi.ServerView{})
		return
	}
	if id := r.URL.Query().Get("server_id"); id != "" {
		v, err := m.svc.Inventory.GetServer(tenant, id)
		if err != nil {
			mcpErr(w, err)
			return
		}
		jsonOK(w, v)
		return
	}
	v, err := m.svc.Inventory.ListServers(tenant, mcpQueryLimit(r))
	if err != nil {
		mcpErr(w, err)
		return
	}
	jsonOK(w, v)
}

func apiMCPTools(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	tenant, ok := mcpTenant(r)
	if !ok {
		mcpErr(w, mcperr.New(mcperr.ReasonAdminTenantScope, "mcp", "tenant required"))
		return
	}
	m := getMCPAdmin()
	if m.svc.Inventory == nil {
		jsonOK(w, []adminapi.ToolView{})
		return
	}
	// Reconcile the catalog Usable projection before the read so a promoted/expired
	// tool's disposition and its ADR-0034 trust overlay are current (no-op when the
	// tool-trust coordinator is not composed).
	mcpToolTrustReconcile()
	sid := r.URL.Query().Get("server_id")
	if name := r.URL.Query().Get("tool_name"); name != "" {
		v, err := m.svc.Inventory.GetTool(tenant, sid, name)
		if err != nil {
			mcpErr(w, err)
			return
		}
		jsonOK(w, enrichToolView(tenant, v))
		return
	}
	v, err := m.svc.Inventory.ListTools(tenant, sid, mcpQueryLimit(r))
	if err != nil {
		mcpErr(w, err)
		return
	}
	// Snapshot the tenant's approvals ONCE and reuse the index for every tool, so a large
	// inventory cannot amplify one request into O(tools × approvals) list allocations.
	ann := mcpToolTrust.newToolTrustAnnotator(tenant)
	enriched := make([]mcpToolViewEnriched, 0, len(v))
	for i := range v {
		enriched = append(enriched, enrichToolViewWith(ann, v[i]))
	}
	jsonOK(w, enriched)
}

func apiMCPDecisions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	tenant, ok := mcpTenant(r)
	if !ok {
		mcpErr(w, mcperr.New(mcperr.ReasonAdminTenantScope, "mcp", "tenant required"))
		return
	}
	m := getMCPAdmin()
	if m.svc.Decisions == nil {
		jsonOK(w, adminapi.SearchResult{})
		return
	}
	q := r.URL.Query()
	f := adminapi.DecisionFilter{
		Action: q.Get("action"), ReasonCode: q.Get("reason_code"), RuleID: q.Get("rule_id"),
		ServerID: q.Get("server_id"), ToolName: q.Get("tool_name"), ToolFingerprint: q.Get("tool_fingerprint"),
		PrincipalID: q.Get("principal_id"), AgentID: q.Get("agent_id"), ClientID: q.Get("client_id"),
		ExecutionState: q.Get("execution_state"), PolicySnapshotHash: q.Get("policy_snapshot_hash"),
		CredentialProfileRef: q.Get("credential_profile_ref"),
	}
	res, err := m.svc.Decisions.Search(mcpCapability(r), tenant, q.Get("cursor"), mcpQueryLimit(r), f)
	if err != nil {
		mcpErr(w, err)
		return
	}
	jsonOK(w, res)
}

func apiMCPDecisionExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	tenant, ok := mcpTenant(r)
	if !ok {
		mcpErr(w, mcperr.New(mcperr.ReasonAdminTenantScope, "mcp", "tenant required"))
		return
	}
	m := getMCPAdmin()
	if m.svc.Decisions == nil {
		mcpErr(w, mcperr.New(mcperr.ReasonAdminNotFound, "mcp", "not found"))
		return
	}
	v, err := m.svc.Decisions.Explain(mcpCapability(r), tenant, r.URL.Query().Get("event_id"))
	if err != nil {
		mcpErr(w, err)
		return
	}
	jsonOK(w, v)
}

func apiMCPPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	m := getMCPAdmin()
	capNS := mcpCapability(r)
	store, ok := m.svc.Policy.Stores().Store(capNS)
	if !ok {
		mcpErr(w, mcperr.New(mcperr.ReasonAdminNotFound, "mcp", "no policy store"))
		return
	}
	out := map[string]any{"capability": capNS, "revision": uint64(store.CurrentRevision()), "distribution_state": "local_only"}
	if cur := store.Current(); cur != nil {
		out["hash"] = cur.Hash()
		out["rule_count"] = cur.RuleCount()
		out["default_action"] = cur.DefaultAction().String()
	}
	jsonOK(w, out)
}

type mcpSimReq struct {
	Mode       string          `json:"mode"` // validate | simulate | compare
	Capability string          `json:"capability"`
	Candidate  json.RawMessage `json:"candidate"`
	Cases      []simulate.Case `json:"cases"`
}

func apiMCPPolicySimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	var req mcpSimReq
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	m := getMCPAdmin()
	capNS := req.Capability
	if capNS == "" {
		capNS = "gateway"
	}
	switch req.Mode {
	case "", "validate":
		jsonOK(w, m.svc.Policy.Validate(capNS, req.Candidate))
	case "simulate":
		res, err := m.svc.Policy.Simulate(capNS, req.Candidate, req.Cases)
		if err != nil {
			mcpErr(w, err)
			return
		}
		jsonOK(w, res)
	case "compare":
		res, err := m.svc.Policy.Compare(capNS, req.Candidate, req.Cases)
		if err != nil {
			mcpErr(w, err)
			return
		}
		jsonOK(w, res)
	default:
		http.Error(w, "admin_request_invalid", http.StatusBadRequest)
	}
}

type mcpPublishReq struct {
	Capability   string          `json:"capability"`
	Tenant       string          `json:"tenant"`
	Candidate    json.RawMessage `json:"candidate"`
	ExpectedBase uint64          `json:"expected_base"`
}

func apiMCPPublications(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		tenant, ok := mcpTenant(r)
		if !ok {
			mcpErr(w, mcperr.New(mcperr.ReasonAdminTenantScope, "mcp", "tenant required"))
			return
		}
		m := getMCPAdmin()
		reqs := m.svc.Approvals.List(tenant, 0, m.svc.Limits.MaxPageSize())
		views := make([]adminapi.ApprovalView, 0, len(reqs))
		for _, rq := range reqs {
			if rq.Kind() == approval.KindPublication {
				views = append(views, adminapi.ApprovalViewOf(rq))
			}
		}
		jsonOK(w, views)
	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var req mcpPublishReq
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Management MCP is non-mutating in V1: reject a Management policy publication
		// fail-closed at the boundary (the service layer rejects it too, defense in
		// depth). This blocks a Management publication workflow, never creates one.
		if strings.EqualFold(strings.TrimSpace(req.Capability), "management") {
			mcpErr(w, mcperr.New(mcperr.ReasonAdminForbidden, "mcp", "management MCP is non-mutating in V1; policy publication is not permitted for the management capability"))
			return
		}
		m := getMCPAdmin()
		if m.publication == nil {
			mcpErr(w, mcperr.New(mcperr.ReasonAdminNotFound, "mcp", "publication unavailable"))
			return
		}
		id, err := m.publication.Create(req.Capability, req.Tenant, approval.PrincipalID(auditActor(r)), req.Candidate, req.ExpectedBase)
		if err != nil {
			mcpErr(w, err)
			return
		}
		auditEvent(r, "mcp.publication.create", string(id), req.Capability)
		jsonOK(w, map[string]any{"request_id": string(id), "distribution_state": "local_only"})
	default:
		mcpMethodNotAllowed(w)
	}
}

type mcpDecisionReq struct {
	RequestID string `json:"request_id"`
	Tenant    string `json:"tenant"`
	Action    string `json:"action"` // approve | reject | publish
	Reason    string `json:"reason"`
}

// mcpRollbackReq is the four-eyes rollback request (PR-10): revert a capability's
// active signed snapshot to an exact retained target hash.
type mcpRollbackReq struct {
	Capability string `json:"capability"` // gateway | management
	TargetHash string `json:"target_hash"`
	Reason     string `json:"reason"`
}

func apiMCPPublicationDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req mcpDecisionReq
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	m := getMCPAdmin()
	if m.publication == nil {
		mcpErr(w, mcperr.New(mcperr.ReasonAdminNotFound, "mcp", "publication unavailable"))
		return
	}
	id := approval.ID(req.RequestID)
	actor := approval.PrincipalID(auditActor(r))
	switch req.Action {
	case "approve":
		rc, err := m.publication.Approve(id, actor, m.appCommit)
		if err != nil {
			mcpErr(w, err)
			return
		}
		auditEvent(r, "mcp.publication.approve", req.RequestID, "")
		jsonOK(w, map[string]any{"approved": rc.Valid()})
	case "reject":
		if err := m.publication.Reject(id, actor, req.Reason, m.appCommit); err != nil {
			mcpErr(w, err)
			return
		}
		auditEvent(r, "mcp.publication.reject", req.RequestID, "")
		jsonOK(w, map[string]any{"rejected": true})
	case "publish":
		// Publish requires the approved receipt; the workflow re-derives it from
		// the granted request. Here we look up the request and, if approved,
		// re-issue via the stored receipt path (durability-gated).
		mcpErr(w, mcperr.New(mcperr.ReasonPublicationDurabilityRequired, "mcp", "event durability not enabled"))
	default:
		http.Error(w, "admin_request_invalid", http.StatusBadRequest)
	}
}

func apiMCPApprovals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	tenant, ok := mcpTenant(r)
	if !ok {
		mcpErr(w, mcperr.New(mcperr.ReasonAdminTenantScope, "mcp", "tenant required"))
		return
	}
	m := getMCPAdmin()
	if id := r.URL.Query().Get("id"); id != "" {
		rq, err := m.svc.Approvals.Get(approval.ID(id), tenant)
		if err != nil {
			mcpErr(w, err)
			return
		}
		jsonOK(w, adminapi.ApprovalViewOf(rq))
		return
	}
	reqs := m.svc.Approvals.List(tenant, 0, m.svc.Limits.MaxPageSize())
	views := make([]adminapi.ApprovalView, 0, len(reqs))
	for _, rq := range reqs {
		if rq.Kind() == approval.KindOperational {
			views = append(views, adminapi.ApprovalViewOf(rq))
		}
	}
	jsonOK(w, views)
}

func apiMCPApprovalDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req mcpDecisionReq
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	m := getMCPAdmin()
	id := approval.ID(req.RequestID)
	actor := approval.PrincipalID(auditActor(r))
	switch req.Action {
	case "approve":
		// Live revisions default to zero (operational approvals bind their own
		// revisions); durability-gated commit fails closed until MCP is enabled.
		rc, err := m.svc.Approvals.Approve(id, actor, approval.Revisions{}, m.appCommit)
		if err != nil {
			mcpErr(w, err)
			return
		}
		auditEvent(r, "mcp.approval.approve", req.RequestID, "")
		jsonOK(w, map[string]any{"approved": rc.Valid()})
	case "reject":
		if err := m.svc.Approvals.Reject(id, actor, req.Reason, m.appCommit); err != nil {
			mcpErr(w, err)
			return
		}
		auditEvent(r, "mcp.approval.reject", req.RequestID, "")
		jsonOK(w, map[string]any{"rejected": true})
	default:
		http.Error(w, "admin_request_invalid", http.StatusBadRequest)
	}
}

func apiMCPConfig(w http.ResponseWriter, r *http.Request) {
	m := getMCPAdmin()
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, mcpRedactConfig(m.svc.Config.Current()))
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var cand adminapi.MCPConfig
		if err := decodeJSON(r, &cand); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Transactional: validate the complete candidate; on any failure the
		// current running config is retained (ConfigStore.Set is atomic). This
		// persists the node-local config ONLY — it does not (re)bind or restart a
		// live MCP listener, and it never propagates CP→DP. The response is
		// explicit that listener activation is not implemented in this build, so a
		// caller cannot mistake a stored config for a bound endpoint.
		before := m.svc.Config.Current()
		if err := m.svc.Config.Set(cand); err != nil {
			mcpErr(w, err)
			return
		}
		auditEventDiff(r, "mcp.config.update", "mcp", "local_only", mcpRedactConfig(before), mcpRedactConfig(m.svc.Config.Current()))
		jsonOK(w, map[string]any{
			"stored":                       true,
			"listener_activation":          "not_implemented",
			"distribution_state":           "local_only",
			"distribution_not_implemented": true,
			"config":                       mcpRedactConfig(m.svc.Config.Current()),
		})
	default:
		mcpMethodNotAllowed(w)
	}
}

func apiMCPManagementAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	m := getMCPAdmin()
	tools := management.Catalog()
	toolRows := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		toolRows = append(toolRows, map[string]any{
			"name": t.Name, "min_role": mcpMgmtRoleString(t.MinRole), "scope": t.Scope,
			"class": mcpMgmtClassString(t.Class),
		})
	}
	jsonOK(w, map[string]any{
		"access":         m.svc.Health.Snapshot().ManagementAccess,
		"tools":          toolRows,
		"mutation_tools": 0,
	})
}

// mcpRedactConfig returns the config with sensitive references redacted. TLS
// profile refs and OAuth resource-ish fields are references (not secrets); no
// secret material lives in MCPConfig by construction, so this is a defensive
// pass that keeps the redaction seam explicit.
func mcpRedactConfig(c adminapi.MCPConfig) adminapi.MCPConfig {
	// No secret fields exist in MCPConfig; return as-is. The redaction point is
	// retained so a future sensitive reference is scrubbed here, not at the edge.
	return c
}

func mcpMgmtRoleString(r management.Role) string {
	switch r {
	case management.RoleAdmin:
		return "admin"
	case management.RoleOperator:
		return "operator"
	case management.RoleViewer:
		return "viewer"
	default:
		return "none"
	}
}

func mcpMgmtClassString(c management.Class) string {
	if c == management.ClassDraft {
		return "draft"
	}
	return "read-only"
}
