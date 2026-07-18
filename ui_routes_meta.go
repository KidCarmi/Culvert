package main

// ── Phase C1 + C1.5: Route Metadata Table (SHADOW / REPORT-ONLY) ──────────
//
// uiRoutes is the canonical, alphabetised metadata for every admin-UI
// route. It supersedes the hand-maintained d0KnownRoutes mirror as the
// authoritative inventory source for D0 regression tests.
//
// PHASE C1 SHADOW MODE — every field below is documentation only:
//   • Methods entries (MinRole, Mutating, AuditExpected, Method) are
//     declarations of intent. Nothing in the request lifecycle reads
//     these fields. uiAuthMiddleware still uses its hand-coded
//     allowlist; per-handler requireRole calls still gate RBAC; the
//     securityMiddleware CSRF/body/rate-limit checks still derive
//     "mutating" from r.Method directly.
//   • The metadata exists so tests can verify intent matches the
//     registered mux, and so Phase C2 can switch enforcement on without
//     introducing the table at the same time.
//
// PHASE C1.5 EVOLUTION — schema is now method-aware. Each route carries
// a Methods slice so handlers with split per-method behaviour
// (typically GET=Viewer, POST/PUT/DELETE=Operator-or-Admin) can be
// expressed precisely. The C1.5 AST scanner cross-checks every
// per-method entry against the handler's actual requireRole and
// auditEvent calls.
//
// PHASE C2 (NOT YET): the metadata becomes authoritative. Middleware
// will look up Methods[r.Method].MinRole / Mutating from this table
// instead of duplicating the logic at each call site.

// RolePublic is a sentinel UIRole used in metadata to mark a route as
// intentionally exposed without authentication. It is NOT enrolled in
// rolePriority, so HasRole(RolePublic, anyRealRole) is false for every
// real role — the value is documentation, not an enforcement primitive.
const RolePublic UIRole = "public"

// MethodAny ("*") is the wildcard method in metadata. Used for routes
// whose handler applies behaviour uniformly across all methods, OR
// whose method dispatch is internal/dynamic (apiIdPRouter parses path
// segments; apiBootstrapRouter delegates to its own state machine).
// Per the Bucket-D policy in C1.5, MethodAny is used only when explicit
// per-method entries cannot be safely derived.
const MethodAny = "*"

// uiRouteMethod captures the per-method contract for one route. All
// fields are SHADOW-MODE documentation; nothing in the request
// lifecycle reads them.
type uiRouteMethod struct {
	Method        string // "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS" | MethodAny
	MinRole       UIRole // intended minimum role for THIS method
	Mutating      bool   // intended state-changing classification (per method)
	AuditExpected bool   // handler is expected to call auditEvent on this method's success
	// Note is an optional human-readable comment explaining a non-obvious
	// classification (e.g. GET branch protected only by uiAuthMiddleware
	// without an explicit requireRole call).
	Note string
}

// uiRouteMetadata captures the intended contract of one admin-UI route.
// See the package-level comment above for SHADOW-MODE caveats.
type uiRouteMetadata struct {
	Path    string          // ServeMux pattern (exact path or trailing-slash prefix)
	Handler string          // handler function name, for documentation/tooling
	Domain  string          // panel grouping owning the route ("auth", "policy", ...)
	Public  bool            // intended public-allowlist membership (doc only)
	Methods []uiRouteMethod // per-method contract (length ≥ 1)
}

// uiRoutes is the alphabetised metadata table for all 137 admin-UI routes.
//
// MIGRATION BUCKETS (per the C1.5 schema-evolution decision):
//
//   - Bucket A — multi-method handlers with distinct roles per method:
//     one Methods entry per observed method, AST-derived role/audit.
//   - Bucket B — single-method handlers: one Methods entry.
//   - Bucket C — uniform multi-method handlers (same role on every
//     method): explicit per-method entries (Policy A — precision over
//     compactness for C2 enforcement).
//   - Bucket D — dynamic / internal-router handlers: a single
//     {Method: MethodAny, ...} entry. Role/Mutating/AuditExpected are
//     declared based on intended doctrine, not AST signal.
//
// GET-WITHOUT-REQUIREROLE policy: when the AST shows a `case http.MethodGet`
// branch with no requireRole call but the route is gated by
// uiAuthMiddleware (Public=false), the GET entry uses MinRole: RoleViewer
// with a Note explaining the AST observation.
var uiRoutes = []uiRouteMetadata{
	// ── Static SPA ────────────────────────────────────────────────────────
	{Path: "/", Handler: "serveUIShell", Domain: "static", Public: true,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RolePublic}}},

	// ── Setup bootstrap (public allowlist /api/setup) ─────────────────────
	{Path: "/api/setup/status", Handler: "apiSetupStatus", Domain: "setup", Public: true,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RolePublic}}},
	{Path: "/api/setup/complete", Handler: "apiSetupComplete", Domain: "setup", Public: true,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RolePublic, Mutating: true, AuditExpected: true}}},

	// ── Admin session auth ────────────────────────────────────────────────
	{Path: "/api/auth/login", Handler: "apiAuthLogin", Domain: "auth", Public: true,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RolePublic, Mutating: true, AuditExpected: true}}},
	{Path: "/api/auth/status", Handler: "apiAuthStatus", Domain: "auth", Public: true,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RolePublic}}},
	{Path: "/api/auth/logout", Handler: "apiAuthLogout", Domain: "auth", Public: true,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RolePublic, Mutating: true, AuditExpected: true}}},
	{Path: "/api/auth/users", Handler: "apiAuthUsers", Domain: "auth", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleAdmin},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/auth/change-password", Handler: "apiAuthChangePassword", Domain: "auth", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleViewer, Mutating: true, AuditExpected: true}}},
	{Path: "/api/auth/lockouts", Handler: "apiAuthLockouts", Domain: "auth", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleAdmin},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},

	// ── Generic IdP framework ─────────────────────────────────────────────
	{Path: "/api/idp", Handler: "apiIdPList", Domain: "auth", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/idp/discover", Handler: "apiIdPDiscover", Domain: "auth", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true}}},
	{Path: "/api/idp/", Handler: "apiIdPRouter", Domain: "auth", Public: false,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RoleViewer, Mutating: true, AuditExpected: true,
			Note: "C1.5 audit: dispatches to apiIdPItem (GET=viewer / PUT=admin / DELETE=admin) and apiIdPGroups; lowest accepted role is viewer (GET)"}}},

	// ── Auth callbacks (browser redirects from IdPs, public allowlist) ────
	{Path: "/auth/oidc/callback", Handler: "authOIDCCallback", Domain: "auth", Public: true,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RolePublic, Note: "IdP redirect target; method varies"}}},
	{Path: "/auth/saml/callback", Handler: "authSAMLCallback", Domain: "auth", Public: true,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RolePublic, Mutating: true, Note: "SAML POST binding"}}},
	{Path: "/auth/saml/metadata", Handler: "authSAMLMetadata", Domain: "auth", Public: true,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RolePublic, Note: "SP metadata import endpoint for IdP setup"}}},
	{Path: "/auth/select", Handler: "authSelectProvider", Domain: "auth", Public: true,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RolePublic}}},
	{Path: "/auth/logout", Handler: "authLogout", Domain: "auth", Public: true,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RolePublic, Note: "session clear; method-agnostic"}}},

	// ── Dashboard / live stats. The dashboard handlers do not gate on
	// method (no `switch r.Method`); the requireRole(viewer) call is
	// unconditional. Metadata uses MethodAny for these — Bucket D.
	// /api/audit explicitly checks GET and is therefore Bucket B. ─────────
	{Path: "/api/stats", Handler: "apiStats", Domain: "dashboard", Public: false,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RoleViewer}}},
	{Path: "/api/dashboard/health", Handler: "apiDashboardHealth", Domain: "dashboard", Public: false,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RoleViewer}}},
	{Path: "/api/dashboard/threats", Handler: "apiDashboardThreats", Domain: "dashboard", Public: false,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RoleViewer}}},
	{Path: "/api/dashboard/top-rules", Handler: "apiDashboardTopRules", Domain: "dashboard", Public: false,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RoleViewer}}},
	{Path: "/api/timeseries", Handler: "apiTimeseries", Domain: "dashboard", Public: false,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RoleViewer}}},
	{Path: "/api/logs", Handler: "apiLogs", Domain: "dashboard", Public: false,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RoleViewer}}},
	{Path: "/api/logs/retention", Handler: "apiLogsRetention", Domain: "dashboard", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/logs/purge", Handler: "apiLogsPurge", Domain: "dashboard", Public: false,
		Methods: []uiRouteMethod{
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/top-hosts", Handler: "apiTopHosts", Domain: "dashboard", Public: false,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RoleViewer}}},
	{Path: "/api/audit", Handler: "apiAudit", Domain: "dashboard", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/events", Handler: "apiEvents", Domain: "dashboard", Public: false,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RoleViewer, Note: "SSE stream"}}},
	{Path: "/api/country-traffic", Handler: "apiCountryTraffic", Domain: "dashboard", Public: false,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RoleViewer}}},

	// ── Policy / blocklist / filtering (Bucket A — multi-method distinct) ──
	{Path: "/api/blocklist", Handler: "apiBlocklist", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/fileblock", Handler: "apiFileblock", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "GET branch protected by uiAuthMiddleware; no explicit requireRole call observed"},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/fileblock/profiles", Handler: "apiFileblockProfiles", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "PUT", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/rewrite", Handler: "apiRewrite", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "GET branch protected by uiAuthMiddleware; no explicit requireRole call observed"},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/policy", Handler: "apiPolicy", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "GET branch protected by uiAuthMiddleware; no explicit requireRole call observed"},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "PUT", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/policy/reorder", Handler: "apiPolicyReorder", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
			Note: "access-only: permutes Stage-2 access rules among their own slots (PermutePriorities); rejects any Stage-1 auth priority, which is reordered via /api/authpolicy"}}},
	{Path: "/api/policy/move", Handler: "apiPolicyMove", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
			Note: "access-only: moves a Stage-2 access rule among access rules (PermutePriorities); an auth rule is not found among them and is rejected"}}},
	{Path: "/api/policy/test", Handler: "apiPolicyTest", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleViewer, Mutating: true, Note: "POST is read-only in spirit (dry-run policy match), no audit"}}},
	{Path: "/api/policy/draft", Handler: "apiPolicyDraft", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "draft state + candidate→running diff (policy-draft G2)"},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true, Note: "arm/disarm RequireCommit; disarm blocked (409) while a dirty draft exists"},
		}},
	{Path: "/api/policy/draft/commit", Handler: "apiPolicyDraftCommit", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
			Note: "validate + activate the candidate (running := candidate); required commit comment"}}},
	{Path: "/api/policy/draft/revert", Handler: "apiPolicyDraftRevert", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
			Note: "discard the candidate; running untouched"}}},
	{Path: "/api/objects/references", Handler: "apiObjectReferences", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer, Note: "read-only generic dependency walk (Where-Used); no audit, no mutation (policy-refs P0)"}}},
	{Path: "/api/authpolicy", Handler: "apiAuthPolicy", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/authpolicy/reorder", Handler: "apiAuthPolicyReorder", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true}}},
	{Path: "/api/default-action", Handler: "apiDefaultAction", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "GET branch protected by uiAuthMiddleware; no explicit requireRole call observed"},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/blocklist/mode", Handler: "apiBlocklistMode", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "GET branch protected by uiAuthMiddleware; no explicit requireRole call observed"},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/blocklist/feed", Handler: "apiBlocklistFeed", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/blocklist/feed/sync", Handler: "apiBlocklistFeedSync", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true}}},
	{Path: "/api/blocklist/exceptions", Handler: "apiBlocklistExceptions", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/category-groups", Handler: "apiCategoryGroups", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "PUT", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/decryption-profiles", Handler: "apiDecryptionProfiles", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "PUT", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/decryption/health", Handler: "apiDecryptionHealth", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "ADR-0011: read-only decryption coverage + failure-taxonomy aggregate (server-computed from culvert_decrypt_* counters); side-effect-free"},
		}},
	{Path: "/api/decryption/redaction", Handler: "apiDecryptionRedaction", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "ADR-0011 §4: read the host/SNI redaction posture"},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true, Note: "ADR-0011 §4: toggle host/SNI redaction; node-local (admin_settings-durable, off export/import/rollback/CP→DP)"},
		}},
	{Path: "/api/decryption-exclusions", Handler: "apiDecryptionExclusions", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "read-only list of the volatile auto-exclusion cache + posture"},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true, Note: "evict one (?host=) or clear all; volatile cache, no config-version"},
		}},
	{Path: "/api/decryption-exclusions/tunables", Handler: "apiDecryptionExclusionTunables", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "F10: defaults + bounds + schema (current values live on /api/decryption-exclusions)"},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true, Note: "F10: set auto-exclusion tunables; validate→persist→apply (persist-before-apply, no rollback branch); no config-version (off rollback surface)"},
		}},
	{Path: "/api/urlcat", Handler: "apiURLCat", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "GET branch protected by uiAuthMiddleware; no explicit requireRole call observed"},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "PUT", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/urlcat/host", Handler: "apiURLCatHost", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/urlcat/lookup", Handler: "apiURLCatLookup", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer, Note: "no direct requireRole; protected by uiAuthMiddleware"}}},
	{Path: "/api/blockpage", Handler: "apiBlockPage", Domain: "policy", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},

	// ── PAC file ──────────────────────────────────────────────────────────
	{Path: "/proxy.pac", Handler: "servePACFile", Domain: "pac", Public: true,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RolePublic, Note: "Windows PAC clients cannot send credentials"}}},
	{Path: "/pac/", Handler: "servePACProfileFile", Domain: "pac", Public: true,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RolePublic, Note: "per-profile PAC endpoints; PAC clients cannot send credentials"}}},
	{Path: "/api/pac-config", Handler: "apiPACConfig", Domain: "pac", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "no direct requireRole; protected by uiAuthMiddleware"},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/pac/profiles", Handler: "apiPACProfiles", Domain: "pac", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "no direct requireRole; protected by uiAuthMiddleware"},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/pac/profiles/", Handler: "apiPACProfileItem", Domain: "pac", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "no direct requireRole; protected by uiAuthMiddleware"},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true, Note: "/{id}/lifecycle sub-resource: save-draft/publish/rollback (initiative PR 3)"},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/pac/pools", Handler: "apiPACPools", Domain: "pac", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "no direct requireRole; protected by uiAuthMiddleware"},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/pac/pools/", Handler: "apiPACPoolItem", Domain: "pac", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "no direct requireRole; protected by uiAuthMiddleware"},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/pac/simulate", Handler: "apiPACSimulate", Domain: "pac", Public: false,
		Methods: []uiRouteMethod{
			// Semantically read-only (no state change, no live DNS); POST only
			// to carry a JSON body. Mutating flag follows the POST convention
			// (informational — CSRF/body-limit key on the method) and
			// AuditExpected stays false since nothing is mutated.
			{Method: "POST", MinRole: RoleViewer, Mutating: true, Note: "read-only PAC steering simulation; POST carries the query body"},
		}},
	{Path: "/api/pac/analyze", Handler: "apiPACAnalyze", Domain: "pac", Public: false,
		Methods: []uiRouteMethod{
			// Read-only diff/impact for a candidate draft. POST only to carry a
			// JSON body; Mutating follows the POST convention (informational).
			// AuditExpected stays false so C2c's audit-completion signal on the
			// mutating lifecycle route remains a meaningful drift indicator.
			{Method: "POST", MinRole: RoleViewer, Mutating: true, Note: "read-only PAC steering diff/impact analysis; POST carries the query body"},
		}},
	{Path: "/api/pac/posture/inventory", Handler: "apiPACPostureInventory", Domain: "pac", Public: false,
		Methods: []uiRouteMethod{
			// Read-only config-derived DIRECT (full-bypass) inventory (PAC
			// Exception Intelligence P0). Observable evidence class only.
			{Method: "GET", MinRole: RoleViewer, Note: "no direct requireRole; protected by uiAuthMiddleware"},
		}},
	{Path: "/api/pac/posture/exceptions", Handler: "apiPACExceptions", Domain: "pac", Public: false,
		Methods: []uiRouteMethod{
			// DIRECT-exception governance list (PAC Exception Intelligence P2).
			{Method: "GET", MinRole: RoleViewer, Note: "no direct requireRole; protected by uiAuthMiddleware"},
		}},
	{Path: "/api/pac/posture/exceptions/", Handler: "apiPACExceptionItem", Domain: "pac", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "no direct requireRole; protected by uiAuthMiddleware"},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},

	// ── Security: TLS inspect (CA, certs, SSL bypass) ─────────────────────
	{Path: "/api/security", Handler: "apiSecurity", Domain: "security", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/ca-cert", Handler: "apiCACert", Domain: "security", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/certs/upload", Handler: "apiCertsUpload", Domain: "security", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true}}},
	{Path: "/api/ssl-bypass", Handler: "apiSSLBypass", Domain: "security", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "GET branch protected by uiAuthMiddleware; no explicit requireRole call observed"},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/content-scan", Handler: "apiContentScan", Domain: "security", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "deprecated alias of /api/dpi (T-10); GET branch protected by uiAuthMiddleware; no explicit requireRole call observed"},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true, Note: "deprecated alias of /api/dpi (T-10)"},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true, Note: "deprecated alias of /api/dpi (T-10)"},
		}},
	{Path: "/api/dpi", Handler: "apiContentScan", Domain: "security", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "canonical path (T-10); GET branch protected by uiAuthMiddleware; no explicit requireRole call observed"},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},

	// ── Security: ClamAV / YARA / Threat Feeds ────────────────────────────
	{Path: "/api/security-scan/status", Handler: "apiSecScanStatus", Domain: "security", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/security-scan/feeds/sync", Handler: "apiSecFeedsSync", Domain: "security", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true,
			Note: "manual threat-feed sync; auditEvent added per C1.5 audit §3.2"}}},
	{Path: "/api/security-scan/feeds/domain-allowlist", Handler: "apiDomainAllowlist", Domain: "security", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/security-scan/yara/reload", Handler: "apiSecYARAReload", Domain: "security", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true}}},
	{Path: "/api/security-scan/yara/rules", Handler: "apiSecYARARules", Domain: "security", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/security-scan/yara/rules/", Handler: "apiSecYARARules", Domain: "security", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/security-scan/yara/validate", Handler: "apiSecYARAValidate", Domain: "security", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, Note: "dry-run validation; no audit"}}},
	{Path: "/api/security-scan/yara/settings", Handler: "apiSecYARASettings", Domain: "security", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/security-scan/exclusions", Handler: "apiSecScanExclusions", Domain: "security", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/security-scan/svc", Handler: "apiScanSvcConfig", Domain: "security", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/security-scan/cache", Handler: "apiScanCache", Domain: "security", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "DELETE", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/content-scan/bypass", Handler: "apiContentScanBypass", Domain: "security", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "deprecated alias of /api/dpi/bypass (T-10)"},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true, Note: "deprecated alias of /api/dpi/bypass (T-10)"},
		}},
	{Path: "/api/dpi/bypass", Handler: "apiContentScanBypass", Domain: "security", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},

	// ── Security: alert webhooks ──────────────────────────────────────────
	{Path: "/api/alerts/webhooks", Handler: "apiAlertsWebhooks", Domain: "security", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "PUT", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/alerts/webhooks/test", Handler: "apiAlertsWebhookTest", Domain: "security", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, Note: "test-fire only; no audit"}}},
	{Path: "/api/alerts/webhooks/history", Handler: "apiAlertsDeliveryHist", Domain: "security", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},

	// ── Security: CA management ───────────────────────────────────────────
	{Path: "/api/ca/status", Handler: "apiCAStatus", Domain: "security", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/ca/key-provider", Handler: "apiCAKeyProvider", Domain: "security", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/ca/download", Handler: "apiCADownload", Domain: "security", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/ca/cache-clear", Handler: "apiCACacheClear", Domain: "security", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true}}},
	{Path: "/api/ca/rotate", Handler: "apiCARotate", Domain: "security", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true}}},

	// ── Security: OCSP, GeoIP ─────────────────────────────────────────────
	{Path: "/api/ocsp", Handler: "apiOCSPConfig", Domain: "security", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "GET branch protected by uiAuthMiddleware; no explicit requireRole call observed"},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/geoip", Handler: "apiGeoIPConfig", Domain: "security", Public: false,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RoleViewer}}},

	// ── Settings panel (Option-A panel grouping) ──────────────────────────
	{Path: "/api/settings", Handler: "apiSettings", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "GET branch protected by uiAuthMiddleware; no explicit requireRole call observed"},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/export", Handler: "apiExport", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RoleViewer}}},
	{Path: "/api/config/export", Handler: "apiConfigExport", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleAdmin, AuditExpected: true}}},
	{Path: "/api/config/import", Handler: "apiConfigImport", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true}}},
	{Path: "/api/config/versions", Handler: "apiConfigVersions", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, Note: "rollback; audit delegated"},
		}},
	{Path: "/api/config/diff", Handler: "apiConfigDiff", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/settings/default-auth-outcome", Handler: "apiDefaultAuthOutcome", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true}}},
	{Path: "/api/settings/unauth-mode", Handler: "apiDefaultAuthOutcome", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true, Note: "legacy alias for /api/settings/default-auth-outcome"}}},
	{Path: "/api/settings/log-level", Handler: "apiLogLevel", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/settings/network", Handler: "apiNetworkSettings", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/session-timeout", Handler: "apiSessionTimeout", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/session-secret", Handler: "apiSessionSecret", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/ui-allow-ips", Handler: "apiUIAllowIPs", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleAdmin, Note: "AST shows requireRole(admin) for both methods (uniform)"},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/syslog", Handler: "apiSyslogConfig", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleAdmin, Note: "AST shows requireRole(admin) for both methods (uniform)"},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/syslog/test", Handler: "apiSyslogTest", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, Note: "test-fire only; no audit"}}},
	{Path: "/api/logger", Handler: "apiLoggerConfig", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/metrics-config", Handler: "apiMetricsConfig", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/otlp", Handler: "apiOTLPConfig", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleAdmin, Note: "AST shows requireRole(admin) for both methods (uniform)"},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/connlimit", Handler: "apiConnLimit", Domain: "settings", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},

	// ── Cluster: upstream proxy chain ─────────────────────────────────────
	{Path: "/api/upstream", Handler: "apiUpstream", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "GET branch protected by uiAuthMiddleware; no explicit requireRole call observed"},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/upstream/settings", Handler: "apiUpstreamSettings", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer, Note: "no direct requireRole; protected by uiAuthMiddleware"}}},
	{Path: "/api/upstream/health", Handler: "apiUpstreamHealth", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, Note: "force health check; no audit"}}},

	// ── Cluster: multi-node ───────────────────────────────────────────────
	{Path: "/api/cluster/status", Handler: "apiClusterStatus", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/cluster/mode", Handler: "apiClusterMode", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, Note: "switches CP/DP role; audit delegated"}}},
	{Path: "/api/cluster/tokens", Handler: "apiClusterTokens", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, Note: "audit delegated"},
			{Method: "DELETE", MinRole: RoleAdmin, Mutating: true, Note: "audit delegated"},
		}},
	{Path: "/api/cluster/nodes", Handler: "apiClusterNodes", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/cluster/revoke", Handler: "apiClusterRevoke", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true}}},
	{Path: "/api/cluster/labels", Handler: "apiClusterLabels", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true}}},
	{Path: "/api/cluster/node-groups", Handler: "apiNodeGroups", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, Note: "audit delegated"},
			{Method: "DELETE", MinRole: RoleAdmin, Mutating: true, Note: "audit delegated"},
		}},
	{Path: "/api/cluster/node-groups/membership", Handler: "apiNodeGroupMembership", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/cluster/drain", Handler: "apiClusterDrain", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true}}},
	{Path: "/api/cluster/metrics", Handler: "apiClusterMetrics", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/cluster/ca", Handler: "apiClusterCA", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/cluster/rate-limits", Handler: "apiClusterRateLimits", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/cluster/audit", Handler: "apiClusterAudit", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/cluster/revocations", Handler: "apiClusterRevocations", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/cluster/rotation", Handler: "apiClusterRotation", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/cluster/ha", Handler: "apiClusterHA", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, Note: "no direct auditEvent observed"},
		}},
	{Path: "/api/cluster/ha/promote", Handler: "apiClusterHAPromote", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/cluster/bandwidth", Handler: "apiBandwidthPolicies", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/cluster/bootstrap/", Handler: "apiBootstrapRouter", Domain: "cluster", Public: false,
		Methods: []uiRouteMethod{{Method: MethodAny, MinRole: RoleViewer, Note: "token-authed bootstrap dispatch; gating delegated to handler"}}},

	// ── CDR (Sluice) integration ──────────────────────────────────────────
	{Path: "/api/cdr/config", Handler: "apiCDRConfig", Domain: "cdr", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, Note: "no direct auditEvent observed"},
		}},
	{Path: "/api/cdr/instances", Handler: "apiCDRInstances", Domain: "cdr", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "DELETE", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/cdr/instances/enroll", Handler: "apiCDREnroll", Domain: "cdr", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true}}},
	{Path: "/api/cdr/instances/revoke", Handler: "apiCDRRevokeRPC", Domain: "cdr", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true}}},
	{Path: "/api/cdr/policies", Handler: "apiCDRPolicies", Domain: "cdr", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
			{Method: "DELETE", MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
		}},
	{Path: "/api/cdr/health", Handler: "apiCDRHealth", Domain: "cdr", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/cdr/test", Handler: "apiCDRTest", Domain: "cdr", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true}}},

	// ── Observability ─────────────────────────────────────────────────────
	{Path: "/api/diagnostics", Handler: "apiDiagnostics", Domain: "observability", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/healthz", Handler: "apiHealthz", Domain: "observability", Public: true,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RolePublic, Note: "LB probe"}}},

	// ── Governance (Phase C3 — read-only control-plane visibility) ───────
	{Path: "/api/governance/control-plane", Handler: "apiGovernanceControlPlane", Domain: "governance", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleAdmin, Note: "C3: read-only governance surface; admin-only by design"}}},

	// ── Release management (P1.6d-0; dispatch service backend, no GUI) ─────
	{Path: "/api/releases", Handler: "apiReleases", Domain: "release", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/releases/current", Handler: "apiReleaseCurrent", Domain: "release", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/releases/dispatch/status", Handler: "apiReleaseDispatchStatus", Domain: "release", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer}}},
	{Path: "/api/releases/dispatch", Handler: "apiReleaseDispatch", Domain: "release", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true,
			Note: "async dispatch; audited by DispatchService via auditAdd (not handler auditEvent), so AuditExpected stays false"}}},
	{Path: "/api/releases/dispatch/resume", Handler: "apiReleaseDispatchResume", Domain: "release", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true,
			Note: "re-poll existing op_id; never calls Apply; audited by DispatchService"}}},
	{Path: "/api/releases/catalog-refresh", Handler: "apiReleaseCatalogRefresh", Domain: "release", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true,
			Note: "re-fetch the catalog from the configured origin + reload; verification unchanged; audited via auditEvent"}}},

	// Supportability framework (M1) — redacted csb/1 diagnostic bundles.
	{Path: "/api/support/status", Handler: "apiSupportStatus", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer,
			Note: "read-only support subsystem inventory: engine/redaction versions + registered collectors"}}},
	{Path: "/api/health/explain", Handler: "apiHealthExplain", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer,
			Note: "explained operator-contract health verdict: per-check status + operator_action"}}},
	{Path: "/api/support/bundles", Handler: "apiSupportBundles", Domain: "support", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "list persisted bundles (id/created/sections/size)"},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true,
				Note: "create a redacted csb/1 support bundle over the registered collectors; admin (a standard bundle may contain INTERNAL sections)"}}},
	{Path: "/api/support/bundles/{id}", Handler: "apiSupportBundleItem", Domain: "support", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleOperator, AuditExpected: true,
				Note: "download a created bundle by id; operator+ (bundle may contain INTERNAL sections); audited as support.bundle.download (the exfil event)"},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
				Note: "delete a persisted bundle by id; operator+; in-product reclaim path; audited as support.bundle.delete"}}},
	{Path: "/api/support/bundles/{id}/redaction-report", Handler: "apiSupportBundleReport", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer,
			Note: "counts-only redaction report (masked/dropped/scrubbed + class_max per section); preview what a bundle redacted without downloading it"}}},
	{Path: "/api/support/bundles/{id}/approve", Handler: "apiSupportBundleApprove", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true,
			Note: "approve a pending bundle for download after redaction-report review (mandatory-preview gate); admin; audited as support.bundle.approve"}}},
	{Path: "/api/support/bundles/{id}/validate", Handler: "apiSupportBundleValidate", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer,
			Note: "re-derive + check the bundle's per-section SHA-256 against its manifest (tamper detection); viewer (integrity metadata only, no section content)"}}},
	{Path: "/api/support/bundles/{id}/download-encrypted", Handler: "apiSupportBundleExportEncrypted", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
			Note: "download a READY bundle wrapped in the PSCA passphrase envelope (AES-256-GCM); operator+ (approval-gated exfil, like plain download); POST carries the passphrase in the body (never logged); audited as support.bundle.download_encrypted"}}},
	{Path: "/api/support/bundles/{id}/download-sealed", Handler: "apiSupportBundleExportSealed", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
			Note: "download a READY bundle sealed to a recipient X25519 public key (NaCl anonymous box, E2E — appliance holds no decrypt key); operator+ (approval-gated exfil); public key or registered recipient name in body (not secret); audited as support.bundle.download_sealed"}}},
	{Path: "/api/support/bundles/{id}/exports", Handler: "apiSupportBundleExports", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer,
			Note: "recent export/exfiltration history for one bundle (actor/time/action) scanned from the audit ring; read-only, no bundle content; viewer+"}}},
	{Path: "/api/support/bundles/{id}/manifest", Handler: "apiSupportBundleManifest", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "GET", MinRole: RoleViewer,
			Note: "bundle manifest metadata (section inventory/sizes/classes/status + integrity hashes) without downloading the tarball; secret-free by construction; read-only; viewer+"}}},
	{Path: "/api/support/recipients", Handler: "apiSupportRecipients", Domain: "support", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "list registered sealing recipients (name + public key + fingerprint; nothing secret)"},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true,
				Note: "register a named recipient (validates the X25519 key against the low-order guard, stores its SHA-256 fingerprint); admin; audited as support.recipient.add"},
		}},
	{Path: "/api/support/recipients/{name}", Handler: "apiSupportRecipientItem", Domain: "support", Public: false,
		Methods: []uiRouteMethod{
			{Method: "PUT", MinRole: RoleAdmin, Mutating: true, AuditExpected: true,
				Note: "rotate a registered recipient's key in place (re-validated + re-fingerprinted); admin; audited as support.recipient.rotate"},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
				Note: "remove a registered recipient; operator+; audited as support.recipient.delete"},
		}},
	{Path: "/api/support/debug-level", Handler: "apiSupportDebugLevel", Domain: "support", Public: false,
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer, Note: "effective capture level + elevation state + remaining TTL"},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true, AuditExpected: true,
				Note: "elevate the default bundle capture depth for a bounded window (mandatory positive ttl_seconds); admin; audited as support.debug_level.set"},
			{Method: "DELETE", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
				Note: "revert the capture level to baseline immediately; operator+; audited as support.debug_level.clear"}}},
	{Path: "/api/diagnose/storage", Handler: "apiDiagnoseStorage", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
			Note: "local read-only storage diagnosis (writability probe + free space + data-dir stat); operator+; no network, no shell; audited as diagnose.storage"}}},
	{Path: "/api/diagnose/upstream", Handler: "apiDiagnoseUpstream", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
			Note: "upstream pool health/circuit diagnosis over the existing health-loop state (redacted List, no new dial); operator+; no shell; audited as diagnose.upstream"}}},
	{Path: "/api/diagnose/dns", Handler: "apiDiagnoseDNS", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
			Note: "bounded, SSRF-guarded DNS resolution probe of a bare hostname (private-resolving targets refused); operator+; no shell; audited as diagnose.dns"}}},
	{Path: "/api/diagnose/tls", Handler: "apiDiagnoseTLS", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
			Note: "bounded, SSRF-guarded TLS handshake + chain/expiry check of host:port (private targets refused; no MITM); operator+; no shell; audited as diagnose.tls"}}},
	{Path: "/api/diagnose/cluster", Handler: "apiDiagnoseCluster", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
			Note: "cluster/HA posture diagnosis over in-memory state (role, lease, node counts, write authority); no network, no shell, no secret/infra detail; operator+; audited as diagnose.cluster"}}},
	{Path: "/api/diagnose/config", Handler: "apiDiagnoseConfig", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
			Note: "live config-snapshot validity (same cap validation that gates a CP→DP sync) + non-secret collection sizes; no snapshot values; operator+; no network, no shell; audited as diagnose.config"}}},
	{Path: "/api/diagnose/all", Handler: "apiDiagnoseAll", Domain: "support", Public: false,
		Methods: []uiRouteMethod{{Method: "POST", MinRole: RoleOperator, Mutating: true, AuditExpected: true,
			Note: "aggregate of the no-input local verbs (storage+upstream+cluster+config) in one call; excludes dns/tls (need a host); operator+; no network, no shell; audited as diagnose.all"}}},
}
