package main

import (
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// ── Phase C2b — Metadata enforcement (ENFORCE by default) ────────────────
//
// C2b activates the enforcement branch in uiMetadataEnforcement. When
// the metadata says a request lacks the per-method MinRole, the
// middleware returns 403 BEFORE reaching the handler. Defense-in-depth
// is preserved: handler-level requireRole calls remain in place as the
// real backstop.
//
// Decision flow per request:
//
//   1. Look up route metadata for r.URL.Path.
//   2. If no metadata entry → soft-fail (handler-level requireRole stays
//      authoritative). Counter increments; request proceeds.
//   3. If route is public → C2 stays out (uiAuthMiddleware allowlist).
//   4. If method has no policy and no MethodAny fallback → soft-fail.
//   5. If session role meets MinRole → allow.
//   6. Otherwise:
//        - In c2ModeShadow: log + count would-deny, request proceeds.
//        - In c2ModeEnforce: log + count would-deny, increment
//          c2EnforceDeniedTotal, return 403.
//
// The shadow branch is preserved so operators can revert to dry-run
// at any time via CULVERT_C2_ENFORCE=false (no rebuild required).
//
// Defense-in-depth principle (per the maintainer's design sign-off):
//   • Existing handler-level requireRole calls remain in place.
//   • C2 is an ADDITIONAL gate, never a REPLACEMENT.
//   • Even when C2b activates, every handler keeps its own role check
//     as a backstop.
//
// Public routes are owned by uiAuthMiddleware's hand-coded allowlist;
// C2 deliberately stays out of public-route enforcement (RolePublic
// metadata is documentation only — see ui_routes_meta.go).
//
// Missing metadata → SOFT-FAIL: log + count, request still passes.
// This treats metadata drift as observability, not as a production
// outage. The handler-level requireRole remains the real backstop.

// ── Kill switch ───────────────────────────────────────────────────────────
//
// CULVERT_C2_ENFORCE controls whether the middleware enforces or only
// shadows. The variable is read once at process startup; runtime
// admin-API mutation is NOT supported (governance risk).
//
//	value             behavior
//	──────            ────────
//	"" (unset)        enforce (default in C2b — fail-closed)
//	"true" / "1"      enforce
//	"yes" / "on"      enforce
//	(any other)       enforce (anything not explicitly false-ish)
//	"false" / "0"     shadow (kill switch — log only, no blocking)
//	"no" / "off"      shadow (kill switch — log only, no blocking)
//
// Default is enforce so a missing/typo'd env var fails closed. Only
// the explicit false-ish set forces shadow.
const c2EnforceEnvVar = "CULVERT_C2_ENFORCE"

const (
	c2ModeShadow  = "shadow"
	c2ModeEnforce = "enforce"
)

// c2EnforceMode reflects the parsed CULVERT_C2_ENFORCE env var.
// Read via c2Mode() so the access point is uniform.
var c2EnforceMode = readC2EnforceMode()

// c2Mode returns the currently active C2 enforcement mode (one of
// c2ModeShadow / c2ModeEnforce). The middleware branches on this
// to decide whether a would-deny becomes a 403 or just a log line.
func c2Mode() string { return c2EnforceMode }

// readC2EnforceMode parses CULVERT_C2_ENFORCE. C2b inverts the C2a
// default: only explicit false-ish values force shadow; everything
// else (unset, unknown, or true-ish) resolves to enforce. This is
// fail-closed: a typo'd env var produces enforce, not shadow.
func readC2EnforceMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(c2EnforceEnvVar))) {
	case "false", "0", "no", "off":
		return c2ModeShadow
	default:
		return c2ModeEnforce
	}
}

// ── Counters (test-introspectable; Prometheus exposure deferred to C2b) ──

// c2ShadowWouldDenyTotal counts decisions where the session role was
// strictly lower than the metadata's per-method MinRole. Increments
// in BOTH shadow and enforce mode — it tracks the policy decision,
// not the action. In enforce mode every increment also produces a
// 403 (counted separately by c2EnforceDeniedTotal). The "Shadow"
// prefix is historical: the counter exists for both modes.
var c2ShadowWouldDenyTotal atomic.Int64

// c2EnforceDeniedTotal counts requests where the metadata-driven gate
// actually returned 403. In shadow mode this counter STAYS AT ZERO
// even when c2ShadowWouldDenyTotal increments; in enforce mode the
// two counters move in lock-step. The delta between them is the
// signal operators watch when flipping the kill switch.
var c2EnforceDeniedTotal atomic.Int64

// c2ShadowMissingMetaTotal counts requests whose path did not resolve
// to any uiRoutes entry (including the "/" catch-all). C1's reverse-
// inventory test is the structural backstop that keeps this at 0;
// non-zero increments at runtime indicate drift between the helpers
// and the metadata table that escaped the test gate. Static-asset
// traffic falls back to the "/" catch-all and does NOT increment this
// counter. Stays soft-fail in BOTH modes — never produces a 403.
var c2ShadowMissingMetaTotal atomic.Int64

// c2ShadowNoPolicyTotal counts requests whose route resolved but whose
// HTTP method has no Methods entry and no MethodAny fallback. Soft-fail
// per design — the request still proceeds in both modes.
var c2ShadowNoPolicyTotal atomic.Int64

// c2CounterSnapshot returns the current values of all C2 counters,
// useful for test introspection. Returned in a stable struct so test
// assertions don't have to load atomics individually.
type c2Counters struct {
	WouldDeny     int64 // policy says deny (any mode)
	EnforceDenied int64 // request actually 403'd (enforce mode only)
	MissingMeta   int64 // path resolves to nothing (soft-fail, both modes)
	NoPolicy      int64 // method has no policy + no MethodAny (soft-fail, both modes)
}

func c2CounterSnapshot() c2Counters {
	return c2Counters{
		WouldDeny:     c2ShadowWouldDenyTotal.Load(),
		EnforceDenied: c2EnforceDeniedTotal.Load(),
		MissingMeta:   c2ShadowMissingMetaTotal.Load(),
		NoPolicy:      c2ShadowNoPolicyTotal.Load(),
	}
}

// ── Metadata index (path → uiRouteMetadata) ───────────────────────────────

// metadataIndex is a fast-lookup structure built once from uiRoutes.
// It mirrors *http.ServeMux's longest-prefix match semantics so the
// C2 middleware sees the same route dispatch decision as the mux.
type metadataIndex struct {
	exact  map[string]uiRouteMetadata // exact path → metadata
	prefix []uiRouteMetadata          // sorted by len(Path) DESC for longest match
}

// buildMetadataIndex constructs the index from the global uiRoutes.
// Called once via sync.Once at first lookup.
//
// "/" is the catch-all pattern in *http.ServeMux: it matches an exact
// "/" request AND any path no more-specific pattern owns (e.g.
// "/index.html", "/static/logo.png", "/favicon.ico"). To mirror that
// resolution, the "/" entry is registered in BOTH the exact map (for
// the fast path on a direct "/" request) AND the prefix list (for the
// catch-all fallback on every other unmatched path). The prefix list
// is sorted by len(Path) DESC, so "/" is always tried LAST and never
// shadows a more-specific prefix.
func buildMetadataIndex() *metadataIndex {
	idx := &metadataIndex{
		exact:  make(map[string]uiRouteMetadata, len(uiRoutes)),
		prefix: make([]uiRouteMetadata, 0, 8),
	}
	for _, r := range uiRoutes {
		switch {
		case r.Path == "/":
			// Catch-all — register in BOTH maps.
			idx.exact[r.Path] = r
			idx.prefix = append(idx.prefix, r)
		case strings.HasSuffix(r.Path, "/"):
			idx.prefix = append(idx.prefix, r)
		default:
			idx.exact[r.Path] = r
		}
	}
	sort.Slice(idx.prefix, func(i, j int) bool {
		return len(idx.prefix[i].Path) > len(idx.prefix[j].Path)
	})
	return idx
}

// Lookup returns the uiRouteMetadata that owns path. It mirrors
// *http.ServeMux's resolution: try exact match first, then the longest
// trailing-slash prefix.
//
// Returns (zero, false) for unknown paths. Callers MUST NOT block the
// request on a miss — see c2EvaluateAndLog.
func (idx *metadataIndex) Lookup(path string) (uiRouteMetadata, bool) {
	if m, ok := idx.exact[path]; ok {
		return m, true
	}
	for _, m := range idx.prefix {
		if strings.HasPrefix(path, m.Path) {
			return m, true
		}
	}
	return uiRouteMetadata{}, false
}

// c2Index is the lazily-initialised package-level metadata index.
var (
	c2IndexOnce sync.Once
	c2Index     *metadataIndex
)

func getC2Index() *metadataIndex {
	c2IndexOnce.Do(func() { c2Index = buildMetadataIndex() })
	return c2Index
}

// PolicyForMethod resolves the per-method contract for an HTTP method.
// Resolution order:
//
//  1. Exact method match (e.g. "POST" against {Method: "POST"}).
//  2. MethodAny fallback ({Method: "*"}).
//  3. Not found.
//
// Specific-method takes precedence. Returns (zero, false) when neither
// is declared.
func (m uiRouteMetadata) PolicyForMethod(method string) (uiRouteMethod, bool) {
	var anyPolicy uiRouteMethod
	var hasAny bool
	for _, mm := range m.Methods {
		if mm.Method == method {
			return mm, true
		}
		if mm.Method == MethodAny {
			anyPolicy, hasAny = mm, true
		}
	}
	if hasAny {
		return anyPolicy, true
	}
	return uiRouteMethod{}, false
}

// ── Evaluation ────────────────────────────────────────────────────────────

// c2Decision summarises the outcome of evaluating one request against
// the metadata table. All fields are populated for diagnostic
// completeness even when matched is false.
type c2Decision struct {
	Matched      bool   // true if the path resolved AND a method policy was found
	WouldDeny    bool   // true if SessionRole strictly below RequiredRole
	Reason       string // human-readable label for the outcome
	Path         string
	Method       string
	SessionRole  UIRole
	RequiredRole UIRole
	MetaPath     string // the metadata Path that matched (may differ from request path under prefix routes)
}

// c2Evaluate computes the metadata-driven decision for a request.
// Pure function over (request, index) — no logging, no counters, no
// side effects. Used by both c2EvaluateAndLog and the test suite.
func c2Evaluate(r *http.Request, idx *metadataIndex) c2Decision {
	d := c2Decision{Path: r.URL.Path, Method: r.Method, SessionRole: uiRole(r)}

	meta, found := idx.Lookup(r.URL.Path)
	if !found {
		d.Reason = "no metadata entry"
		return d
	}
	d.MetaPath = meta.Path

	if meta.Public {
		// Public allowlist is owned by uiAuthMiddleware in C2. C2 stays
		// out — no decision to record.
		d.Matched = true
		d.Reason = "public route — owned by uiAuthMiddleware allowlist"
		return d
	}

	policy, hasPolicy := meta.PolicyForMethod(r.Method)
	if !hasPolicy {
		d.Reason = "no method policy (no exact match, no MethodAny fallback)"
		return d
	}
	d.Matched = true
	d.RequiredRole = policy.MinRole

	if !d.SessionRole.HasRole(policy.MinRole) {
		d.WouldDeny = true
		d.Reason = "session role below MinRole"
	} else {
		d.Reason = "ok"
	}
	return d
}

// c2EvaluateAndLog runs c2Evaluate, increments the appropriate counter,
// and emits a log line for would-deny / missing-metadata / no-policy
// outcomes. Returns the decision so middlewares can inspect it.
func c2EvaluateAndLog(r *http.Request, idx *metadataIndex) c2Decision {
	d := c2Evaluate(r, idx)

	switch {
	case !d.Matched && d.MetaPath == "":
		// Missing metadata entry entirely.
		c2ShadowMissingMetaTotal.Add(1)
		logger.Printf("C2-shadow: no metadata for path=%q method=%q (drift between helpers and uiRoutes)",
			d.Path, d.Method)
	case !d.Matched && d.MetaPath != "":
		// Path resolved but method had no policy.
		c2ShadowNoPolicyTotal.Add(1)
		logger.Printf("C2-shadow: no method policy for path=%q method=%q meta_path=%q",
			d.Path, d.Method, d.MetaPath)
	case d.WouldDeny:
		c2ShadowWouldDenyTotal.Add(1)
		logger.Printf("C2-shadow: WOULD-DENY path=%q method=%q session_role=%q required=%q meta_path=%q",
			d.Path, d.Method, d.SessionRole, d.RequiredRole, d.MetaPath)
	}
	return d
}

// ── Middleware ────────────────────────────────────────────────────────────

// uiMetadataEnforcement is the C2 metadata-driven enforcement
// middleware. The middleware sits between uiAuthMiddleware and the
// mux:
//
//	uiIPGuardMiddleware ∘ securityMiddleware ∘ uiAuthMiddleware
//	                   ∘ uiMetadataEnforcement ∘ mux
//
// uiAuthMiddleware has already either rejected the request (401) or
// injected uiRoleKey{} into the context. C2 reads that role and
// compares it against the per-method MinRole declared in uiRoutes.
//
// Decision summary:
//   - d.WouldDeny + c2Mode()==c2ModeEnforce → 403 (request blocked)
//   - d.WouldDeny + c2Mode()==c2ModeShadow  → log only, request proceeds
//   - !d.Matched (missing meta or no method policy) → soft-fail in
//     both modes; handler-level requireRole is the real backstop.
//   - Public routes → never blocked (uiAuthMiddleware allowlist).
//   - Otherwise → request proceeds.
func uiMetadataEnforcement(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := c2EvaluateAndLog(r, getC2Index())
		if d.WouldDeny && c2Mode() == c2ModeEnforce {
			c2EnforceDeniedTotal.Add(1)
			logger.Printf("C2-enforce: DENIED path=%q method=%q session_role=%q required=%q meta_path=%q",
				d.Path, d.Method, d.SessionRole, d.RequiredRole, d.MetaPath)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
