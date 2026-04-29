package main

import (
	"net/http"
	"sort"
	"time"
)

// ── Phase C3 — Control-plane governance surface (READ-ONLY) ────────────────
//
// C3 exposes the current state of the admin-UI governance machinery
// (route inventory, C2 enforcement mode, C2/C2c counters, derived
// health) as a single JSON document so operators can see what the
// control plane is doing without changing any of its behaviour.
//
// SCOPE (intentional):
//   - One read-only endpoint, admin-only.
//   - Aggregates ONLY runtime state (uiRoutes counts, c2Mode(),
//     c2CounterSnapshot()). No AST re-execution, no parity re-check at
//     request time — the C1/C1.5 layers stay CI-only and are reported
//     here as test-layer descriptors with runtime=false.
//   - No mutation surface. The CULVERT_C2_ENFORCE kill switch remains
//     read-once at startup as documented in ui_metadata_enforcement.go.
//   - No Prometheus exposure (deferred). The same counters remain
//     available via c2CounterSnapshot for tests and future metrics work.
//
// The handler is fully side-effect-free: it does not touch disk, the
// network, or any mutable global. Two reads of the C2 counter snapshot
// across calls are not guaranteed to match (other requests may bump
// counters in parallel) but the handler never moves them itself.
//
// Defense-in-depth (per the C2 invariants in CLAUDE.md):
//   - The route is gated by C2 metadata (MinRole=admin, GET-only).
//   - The handler ALSO calls requireRole(w, r, RoleAdmin) directly.
//   - The handler enforces a method gate (GET-only → 405) before the
//     RBAC check, so non-GET requests fail fast with a clear status.

// governanceSchemaVersion is the contract version for the JSON document
// returned by /api/governance/control-plane. Increment on any breaking
// change to field names, semantics, or structure.
const governanceSchemaVersion = 1

// governanceSnapshot is the top-level JSON document returned by the
// endpoint. Field order matches the design doc; JSON tag names are the
// stable contract.
type governanceSnapshot struct {
	SchemaVersion int                     `json:"schema_version"`
	GeneratedAt   string                  `json:"generated_at"`
	Routes        governanceRoutesSummary `json:"routes"`
	C2            governanceC2State       `json:"c2"`
	Counters      governanceCounters      `json:"counters"`
	Health        governanceHealth        `json:"governance_health"`
	TestLayers    []governanceTestLayer   `json:"test_layers"`
}

// governanceRoutesSummary aggregates uiRoutes into operator-facing
// totals. All fields are derived from a single pass over uiRoutes —
// no I/O, no locking.
type governanceRoutesSummary struct {
	Total           int                          `json:"total"`             // == len(uiRoutes)
	Public          int                          `json:"public"`            // entries with Public=true
	Protected       int                          `json:"protected"`         // == Total - Public
	MethodAnyRoutes int                          `json:"method_any_routes"` // routes whose Methods contains MethodAny
	MethodEntries   int                          `json:"method_entries"`    // sum of len(r.Methods)
	ByMinRole       map[string]governanceRoleAgg `json:"by_min_role"`       // per-role method-entry counts
	Totals          governanceMethodTotals       `json:"totals"`            // method-entry totals
	ByDomain        []governanceDomainSummary    `json:"by_domain"`         // alphabetised per-domain breakdown
}

// governanceRoleAgg counts method entries (NOT routes) for a given
// MinRole. Mutating and AuditExpected are sub-counts among those
// method entries.
type governanceRoleAgg struct {
	Methods       int `json:"methods"`
	Mutating      int `json:"mutating"`
	AuditExpected int `json:"audit_expected"`
}

// governanceMethodTotals reports totals across ALL method entries,
// regardless of MinRole. Useful as a cross-check for the by_min_role
// breakdown (sum of Mutating across roles == Totals.Mutating).
type governanceMethodTotals struct {
	Mutating      int `json:"mutating"`
	AuditExpected int `json:"audit_expected"`
	MethodAny     int `json:"method_any"`
}

// governanceDomainSummary is one row in the per-domain breakdown.
// Routes is the count of uiRoutes entries whose Domain equals this
// label; Methods is the total method-entry count under that domain.
type governanceDomainSummary struct {
	Domain  string `json:"domain"`
	Routes  int    `json:"routes"`
	Methods int    `json:"methods"`
}

// governanceC2State captures the runtime C2 enforcement state. It is
// honest about read-once-at-startup semantics: the kill switch cannot
// be toggled at runtime, so KillSwitchActive reflects the env var as
// parsed at process start.
type governanceC2State struct {
	Mode              string `json:"mode"`                 // c2Mode() — "enforce" or "shadow"
	DefaultMode       string `json:"default_mode"`         // documented fail-closed default
	KillSwitchEnv     string `json:"kill_switch_env"`      // env var name
	KillSwitchActive  bool   `json:"kill_switch_active"`   // true iff env forced "shadow"
	ReadOnceAtStartup bool   `json:"read_once_at_startup"` // documents non-runtime mutability
}

// governanceCounters is a verbatim copy of c2CounterSnapshot in JSON-
// friendly form. Keeping the field set identical means the SPA can
// render the same five tiles operators already see in the C2 logs.
type governanceCounters struct {
	WouldDeny     int64 `json:"would_deny"`
	EnforceDenied int64 `json:"enforce_denied"`
	MissingMeta   int64 `json:"missing_meta"`
	NoPolicy      int64 `json:"no_policy"`
	AuditMissing  int64 `json:"audit_missing"`
}

// governanceHealth is a tri-axis derivation over the counter snapshot
// and the active C2 mode. None of the axis fields require I/O.
//
// Derivation rules (kept in code so they are testable, not in YAML):
//   - metadata_parity:    "ok" iff missing_meta == 0 && no_policy == 0
//   - audit_completion:   "ok" iff audit_missing == 0
//   - enforce_consistency:"ok" iff (mode=="enforce") OR enforce_denied == 0
//   - status:             "drift"  if metadata_parity != "ok" OR enforce_consistency != "ok"
//     "warn"   else if audit_completion != "ok"
//     "healthy" otherwise
type governanceHealth struct {
	Status             string                  `json:"status"`
	MetadataParity     string                  `json:"metadata_parity"`
	AuditCompletion    string                  `json:"audit_completion"`
	EnforceConsistency string                  `json:"enforce_consistency"`
	Issues             []governanceHealthIssue `json:"issues"`
}

// governanceHealthIssue is one actionable finding. Hint is plain
// English so the SPA can render it inline without consulting a table.
type governanceHealthIssue struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`        // "warn" | "drift"
	Count    int64  `json:"count,omitempty"` // omitted when not applicable
	Hint     string `json:"hint"`
}

// governanceTestLayer documents a parity layer for the operator's
// benefit. Runtime=true means the layer evaluates each request;
// runtime=false means the layer runs in CI only (the handler does NOT
// re-execute it on demand — see scope notes at the top of this file).
type governanceTestLayer struct {
	ID      string `json:"id"`
	Purpose string `json:"purpose"`
	Runtime bool   `json:"runtime"`
	Mode    string `json:"mode,omitempty"`
}

// healthOK / healthWarn / healthDrift are the canonical status values
// for governanceHealth axes. Kept as constants so tests can compare
// against the same strings the handler emits.
const (
	healthOK    = "ok"
	healthWarn  = "warn"
	healthDrift = "drift"

	statusHealthy = "healthy"
	statusWarn    = "warn"
	statusDrift   = "drift"
)

// buildGovernanceSnapshot aggregates the current runtime state into a
// governanceSnapshot. Pure function over (uiRoutes, c2Mode(),
// c2CounterSnapshot(), CULVERT_C2_ENFORCE env var) — the test suite
// uses it directly to avoid a full HTTP round-trip.
func buildGovernanceSnapshot() governanceSnapshot {
	counters := governanceCounters(c2CounterSnapshot())
	mode := c2Mode()
	return governanceSnapshot{
		SchemaVersion: governanceSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Routes:        summariseRoutes(uiRoutes),
		C2: governanceC2State{
			Mode:              mode,
			DefaultMode:       c2ModeEnforce,
			KillSwitchEnv:     c2EnforceEnvVar,
			KillSwitchActive:  mode == c2ModeShadow,
			ReadOnceAtStartup: true,
		},
		Counters:   counters,
		Health:     deriveGovernanceHealth(counters, mode),
		TestLayers: governanceTestLayerCatalog(mode),
	}
}

// summariseRoutes walks the metadata table once and produces every
// derived count the JSON document needs. The single-pass design keeps
// the handler O(N) over the route table on each call — N is currently
// 132, so this is cheap.
func summariseRoutes(routes []uiRouteMetadata) governanceRoutesSummary {
	roleAgg := map[string]governanceRoleAgg{
		string(RoleAdmin):    {},
		string(RoleOperator): {},
		string(RoleViewer):   {},
		string(RolePublic):   {},
	}
	domainAgg := map[string]*governanceDomainSummary{}
	var (
		public          int
		methodAnyRoutes int
		methodEntries   int
		mutTotal        int
		auditTotal      int
		methodAnyTotal  int
	)

	for i := range routes {
		r := routes[i]
		if r.Public {
			public++
		}
		hasAny := false
		for _, m := range r.Methods {
			methodEntries++
			if m.Method == MethodAny {
				hasAny = true
				methodAnyTotal++
			}
			if m.Mutating {
				mutTotal++
			}
			if m.AuditExpected {
				auditTotal++
			}
			key := string(m.MinRole)
			agg := roleAgg[key]
			agg.Methods++
			if m.Mutating {
				agg.Mutating++
			}
			if m.AuditExpected {
				agg.AuditExpected++
			}
			roleAgg[key] = agg
		}
		if hasAny {
			methodAnyRoutes++
		}

		d, ok := domainAgg[r.Domain]
		if !ok {
			d = &governanceDomainSummary{Domain: r.Domain}
			domainAgg[r.Domain] = d
		}
		d.Routes++
		d.Methods += len(r.Methods)
	}

	domains := make([]governanceDomainSummary, 0, len(domainAgg))
	for _, d := range domainAgg {
		domains = append(domains, *d)
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i].Domain < domains[j].Domain })

	return governanceRoutesSummary{
		Total:           len(routes),
		Public:          public,
		Protected:       len(routes) - public,
		MethodAnyRoutes: methodAnyRoutes,
		MethodEntries:   methodEntries,
		ByMinRole:       roleAgg,
		Totals: governanceMethodTotals{
			Mutating:      mutTotal,
			AuditExpected: auditTotal,
			MethodAny:     methodAnyTotal,
		},
		ByDomain: domains,
	}
}

// deriveGovernanceHealth applies the documented rules over the counter
// snapshot and the active C2 mode. Returns a fully-populated health
// struct; Issues is nil-safe (encoded as []) when everything is OK.
//
// Severity policy (C3.1):
//
//   - missing_meta > 0  → metadata_parity = drift, status = drift.
//     This counter only increments when a path the mux dispatches
//     resolves to NO uiRoutes entry. Under C1's reverse-parity test
//     this is impossible at runtime, so a non-zero value indicates
//     genuine governance/config drift and warrants investigation.
//   - no_policy > 0     → metadata_parity = warn,  status ≥ warn.
//     This counter increments when a request reaches a route that
//     IS in metadata but whose HTTP method has no policy and no
//     MethodAny fallback. It can be triggered by genuine drift
//     (we forgot to declare a method) OR by client-side noise (a
//     scanner / typo'd curl / bot probing PATCH against a GET-only
//     route). Demoting to warn keeps the indicator from flipping
//     the global status to drift on benign client traffic.
//   - audit_missing > 0 → audit_completion = warn, status ≥ warn.
//   - enforce_denied > 0 in shadow mode → enforce_consistency =
//     drift, status = drift (the kill-switch contract is read-once;
//     a non-zero counter in shadow is a real anomaly).
func deriveGovernanceHealth(c governanceCounters, mode string) governanceHealth {
	h := governanceHealth{
		MetadataParity:     healthOK,
		AuditCompletion:    healthOK,
		EnforceConsistency: healthOK,
		Issues:             []governanceHealthIssue{},
	}

	if c.MissingMeta > 0 {
		h.MetadataParity = healthDrift
		h.Issues = append(h.Issues, governanceHealthIssue{
			Code:     "missing_metadata_nonzero",
			Severity: healthDrift,
			Count:    c.MissingMeta,
			Hint:     "One or more requests resolved to no uiRoutes entry. Grep logs for 'C2: no metadata' and reconcile the helper registration with the metadata table.",
		})
	}
	if c.NoPolicy > 0 {
		// no_policy can be triggered by client-side noise — a scanner,
		// a typo'd curl, or any client sending a method the route does
		// not accept (e.g. PATCH against a GET-only route). When the
		// metadata IS in drift it will also fire, so the counter is
		// still worth surfacing — just at warn severity, not drift.
		// Only escalate metadata_parity to warn if missing_meta has not
		// already pushed it to drift (drift > warn).
		if h.MetadataParity == healthOK {
			h.MetadataParity = healthWarn
		}
		h.Issues = append(h.Issues, governanceHealthIssue{
			Code:     "no_method_policy_nonzero",
			Severity: healthWarn,
			Count:    c.NoPolicy,
			Hint:     "One or more requests hit a route whose method has no exact policy and no MethodAny fallback. This can also be triggered by a client sending a method the route does not accept (e.g. PATCH against a GET-only route). Grep logs for 'C2: no method policy' to identify whether the cause is genuine metadata drift (add the missing per-method entry) or client-side noise (no action needed).",
		})
	}
	if c.AuditMissing > 0 {
		h.AuditCompletion = healthWarn
		h.Issues = append(h.Issues, governanceHealthIssue{
			Code:     "audit_missing_nonzero",
			Severity: healthWarn,
			Count:    c.AuditMissing,
			Hint:     "Successful requests on AuditExpected=true routes did not emit audit events. Grep logs for 'C2: audit missing' and confirm the handler calls auditEvent / auditEventDiff on the success path.",
		})
	}
	// EnforceConsistency: in shadow mode the EnforceDenied counter must
	// stay at zero (the middleware only increments it inside the
	// enforce branch). Anything non-zero in shadow indicates either a
	// bug in the middleware or a process-lifetime mode flip the kill-
	// switch contract is supposed to forbid. Either way, surface it.
	if mode == c2ModeShadow && c.EnforceDenied > 0 {
		h.EnforceConsistency = healthDrift
		h.Issues = append(h.Issues, governanceHealthIssue{
			Code:     "enforce_denied_in_shadow",
			Severity: healthDrift,
			Count:    c.EnforceDenied,
			Hint:     "C2 mode is shadow but the enforce-denied counter is non-zero. The kill switch is read once at startup; investigate whether the process started in enforce and was reconfigured, or whether the counter was bumped by an unintended path.",
		})
	}

	// Status precedence: drift > warn > healthy.
	// drift fires only on genuine governance/config anomalies
	// (missing_meta or enforce_denied-in-shadow); warn is the
	// catch-all for noisy-but-actionable signals (no_policy,
	// audit_missing).
	switch {
	case c.MissingMeta > 0 || (mode == c2ModeShadow && c.EnforceDenied > 0):
		h.Status = statusDrift
	case c.NoPolicy > 0 || c.AuditMissing > 0:
		h.Status = statusWarn
	default:
		h.Status = statusHealthy
	}
	return h
}

// governanceTestLayerCatalog returns the static description of the
// parity-test pyramid that protects the admin UI. The handler does NOT
// re-execute D0/C1/C1.5 at runtime; those are CI-only and reported
// here with Runtime=false. C2 and C2c run inline on every request and
// are reported with Runtime=true.
func governanceTestLayerCatalog(mode string) []governanceTestLayer {
	return []governanceTestLayer{
		{ID: "D0", Purpose: "route/auth/security baseline invariants", Runtime: false},
		{ID: "C1", Purpose: "forward/reverse route↔metadata parity", Runtime: false},
		{ID: "C1.5", Purpose: "AST parity between metadata and handler", Runtime: false},
		{ID: "C2", Purpose: "metadata enforcement middleware", Runtime: true, Mode: mode},
		{ID: "C2c", Purpose: "audit-completion observability", Runtime: true},
	}
}

// apiGovernanceControlPlane serves the read-only governance snapshot.
// Auth: admin role. Method: GET only.
//
// Defense-in-depth: requireRole(RoleAdmin) is intentional even though
// C2 metadata enforces the same MinRole — per the CLAUDE.md control-
// plane invariants, the handler-level check is the real backstop and
// MUST remain.
func apiGovernanceControlPlane(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	jsonOK(w, buildGovernanceSnapshot())
}

// registerGovernanceRoutes wires the C3 governance surface. One
// admin-only GET endpoint, no mutations. The kill switch for C2 stays
// env-only and is intentionally NOT exposed as an API surface here.
func registerGovernanceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/governance/control-plane", apiGovernanceControlPlane) // GET — admin
}
