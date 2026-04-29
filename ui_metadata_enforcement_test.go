package main

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── Phase C2a — shadow / dry-run middleware tests ─────────────────────────
//
// These tests prove three properties of the C2a shadow middleware:
//
//   1. metadataIndex resolves every uiRoutes entry (exact + prefix).
//   2. c2Evaluate produces correct decisions for the canonical role
//      buckets (admin / operator / viewer / unknown / public).
//   3. uiMetadataEnforcement NEVER blocks a request in shadow mode —
//      even a "WOULD-DENY" decision passes through to the handler.
//      Counters increment on the appropriate paths.
//
// C2a is REPORT-ONLY. C2b will activate enforcement; until then, the
// existing handler-level requireRole calls remain the real gate.

// ── 1. metadataIndex lookup ───────────────────────────────────────────────

// TestC2_MetadataIndex_ResolvesEveryRoute confirms every uiRoutes entry
// is reachable through the index. This is the inverse of C1's forward
// test (which uses *http.ServeMux); here we use our own index, which
// must produce identical resolution results.
func TestC2_MetadataIndex_ResolvesEveryRoute(t *testing.T) {
	idx := buildMetadataIndex()
	for _, r := range uiRoutes {
		// For trailing-slash prefixes we must look up a path that
		// would match the prefix (not the bare prefix-with-slash,
		// which the index treats as the prefix root anyway).
		probe := r.Path
		got, ok := idx.Lookup(probe)
		if !ok {
			t.Errorf("%s (Path=%q): not resolved by metadataIndex", r.Handler, r.Path)
			continue
		}
		if got.Path != r.Path {
			t.Errorf("%s (Path=%q): index returned wrong entry Path=%q",
				r.Handler, r.Path, got.Path)
		}
	}
}

// TestC2_MetadataIndex_PrefixMatch confirms paths under a trailing-slash
// metadata Path resolve to that metadata.
func TestC2_MetadataIndex_PrefixMatch(t *testing.T) {
	idx := buildMetadataIndex()
	cases := []struct {
		probe    string
		wantPath string
	}{
		{"/api/cluster/bootstrap/abc123", "/api/cluster/bootstrap/"},
		{"/api/idp/some-id", "/api/idp/"},
		{"/api/idp/some-id/groups", "/api/idp/"},
		{"/api/security-scan/yara/rules/myrule.yar", "/api/security-scan/yara/rules/"},
	}
	for _, c := range cases {
		t.Run(c.probe, func(t *testing.T) {
			got, ok := idx.Lookup(c.probe)
			if !ok {
				t.Fatalf("Lookup(%q) returned !ok", c.probe)
			}
			if got.Path != c.wantPath {
				t.Errorf("Lookup(%q) Path=%q, want %q", c.probe, got.Path, c.wantPath)
			}
		})
	}
}

// TestC2_MetadataIndex_RootCatchAll confirms that paths owned by the
// "/" catch-all (SPA shell + static assets) resolve to the "/" entry,
// matching *http.ServeMux's behavior. Without this, normal UI page
// loads would falsely register as missing-metadata in production.
func TestC2_MetadataIndex_RootCatchAll(t *testing.T) {
	idx := buildMetadataIndex()
	for _, probe := range []string{
		"/",
		"/index.html",
		"/logo.png",
		"/static/css/main.css",
		"/favicon.ico",
	} {
		t.Run(probe, func(t *testing.T) {
			m, ok := idx.Lookup(probe)
			if !ok {
				t.Fatalf("Lookup(%q): expected catch-all match, got !ok", probe)
			}
			if m.Path != "/" {
				t.Errorf("Lookup(%q) Path=%q, want '/'", probe, m.Path)
			}
		})
	}
}

// TestC2_MetadataIndex_UnknownPathFallsToRoot confirms paths with no
// more-specific match also fall to the "/" catch-all (mirroring the
// mux). Previously this was tested as "expected not found" — that was
// wrong because *http.ServeMux always dispatches such paths to the
// "/" handler (which then returns 404 from staticServer).
func TestC2_MetadataIndex_UnknownPathFallsToRoot(t *testing.T) {
	idx := buildMetadataIndex()
	for _, p := range []string{
		"/totally-unknown",
		"/api/does/not/exist",
		"/api/policyy", // typo — must not collide with /api/policy
	} {
		m, ok := idx.Lookup(p)
		if !ok {
			t.Errorf("Lookup(%q): expected catch-all to '/'", p)
			continue
		}
		if m.Path != "/" {
			t.Errorf("Lookup(%q) Path=%q, want '/' (catch-all)", p, m.Path)
		}
	}
}

// ── 2. PolicyForMethod resolution ─────────────────────────────────────────

// TestC2_PolicyForMethod_SpecificWinsOverAny confirms that a specific
// HTTP method entry is preferred over MethodAny when both are declared.
func TestC2_PolicyForMethod_SpecificWinsOverAny(t *testing.T) {
	meta := uiRouteMetadata{
		Path: "/test",
		Methods: []uiRouteMethod{
			{Method: MethodAny, MinRole: RoleViewer},
			{Method: "POST", MinRole: RoleAdmin, Mutating: true},
		},
	}
	got, ok := meta.PolicyForMethod("POST")
	if !ok {
		t.Fatal("PolicyForMethod(POST) returned !ok")
	}
	if got.MinRole != RoleAdmin {
		t.Errorf("MinRole=%q, want admin (specific should win over MethodAny)", got.MinRole)
	}
}

// TestC2_PolicyForMethod_MethodAnyFallback confirms MethodAny is used
// when no specific entry matches.
func TestC2_PolicyForMethod_MethodAnyFallback(t *testing.T) {
	meta := uiRouteMetadata{
		Path: "/test",
		Methods: []uiRouteMethod{
			{Method: MethodAny, MinRole: RoleViewer},
		},
	}
	got, ok := meta.PolicyForMethod("DELETE")
	if !ok {
		t.Fatal("PolicyForMethod(DELETE) returned !ok with MethodAny present")
	}
	if got.MinRole != RoleViewer {
		t.Errorf("MinRole=%q, want viewer (MethodAny fallback)", got.MinRole)
	}
}

// TestC2_PolicyForMethod_NoMatch confirms (zero, false) when neither
// specific nor MethodAny matches.
func TestC2_PolicyForMethod_NoMatch(t *testing.T) {
	meta := uiRouteMetadata{
		Path: "/test",
		Methods: []uiRouteMethod{
			{Method: "GET", MinRole: RoleViewer},
		},
	}
	if _, ok := meta.PolicyForMethod("DELETE"); ok {
		t.Error("PolicyForMethod(DELETE): expected false (no match, no MethodAny)")
	}
}

// ── 3. c2Evaluate decisions ───────────────────────────────────────────────

// c2Req builds a request with the given method/path and role injected
// into the context (matching what uiAuthMiddleware does).
func c2Req(method, path string, role UIRole) *http.Request {
	r := httptest.NewRequest(method, path, http.NoBody)
	r.RemoteAddr = "198.51.100.60:0"
	if role != "" {
		r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
	}
	return r
}

// TestC2_Evaluate_AdminAccessesAdminRoute is the canonical happy-path
// case: an admin hitting an admin-only POST → no deny.
func TestC2_Evaluate_AdminAccessesAdminRoute(t *testing.T) {
	idx := buildMetadataIndex()
	d := c2Evaluate(c2Req(http.MethodPost, "/api/auth/users", RoleAdmin), idx)
	if !d.Matched {
		t.Fatalf("Matched=false; reason=%q", d.Reason)
	}
	if d.WouldDeny {
		t.Errorf("WouldDeny=true for admin role; reason=%q", d.Reason)
	}
}

// TestC2_Evaluate_ViewerHitsAdminRoute is the canonical would-deny case:
// a viewer hits an admin-only POST → WouldDeny=true with required=admin.
func TestC2_Evaluate_ViewerHitsAdminRoute(t *testing.T) {
	idx := buildMetadataIndex()
	d := c2Evaluate(c2Req(http.MethodPost, "/api/auth/users", RoleViewer), idx)
	if !d.Matched {
		t.Fatalf("Matched=false; reason=%q", d.Reason)
	}
	if !d.WouldDeny {
		t.Errorf("WouldDeny=false for viewer hitting admin route; reason=%q", d.Reason)
	}
	if d.RequiredRole != RoleAdmin {
		t.Errorf("RequiredRole=%q, want admin", d.RequiredRole)
	}
	if d.SessionRole != RoleViewer {
		t.Errorf("SessionRole=%q, want viewer", d.SessionRole)
	}
}

// TestC2_Evaluate_OperatorHitsViewerRoute is the comfortable case: an
// operator (priority 2) on a viewer-only route (priority 1) → no deny.
func TestC2_Evaluate_OperatorHitsViewerRoute(t *testing.T) {
	idx := buildMetadataIndex()
	d := c2Evaluate(c2Req(http.MethodGet, "/api/audit", RoleOperator), idx)
	if !d.Matched {
		t.Fatalf("Matched=false; reason=%q", d.Reason)
	}
	if d.WouldDeny {
		t.Errorf("WouldDeny=true for operator on viewer route; reason=%q", d.Reason)
	}
}

// TestC2_Evaluate_PublicRouteSkipped confirms C2 stays out of public-
// route enforcement (uiAuthMiddleware allowlist owns those).
func TestC2_Evaluate_PublicRouteSkipped(t *testing.T) {
	idx := buildMetadataIndex()
	d := c2Evaluate(c2Req(http.MethodPost, "/api/auth/login", ""), idx)
	if !d.Matched {
		t.Fatalf("Matched=false on public route; reason=%q", d.Reason)
	}
	if d.WouldDeny {
		t.Errorf("WouldDeny=true on public route — C2 must not own public; reason=%q", d.Reason)
	}
}

// TestC2_Evaluate_MissingMetadata confirms an empty index (simulating
// drift where the metadata table is missing entirely) is reported as
// Matched=false with empty MetaPath.
//
// We use a synthetic empty index instead of the real one because the
// real index includes the "/" catch-all, which means production
// traffic NEVER misses (every path falls back to "/"). The
// missing-meta path is a defense-in-depth check that fires only on
// genuine drift.
func TestC2_Evaluate_MissingMetadata(t *testing.T) {
	emptyIdx := &metadataIndex{
		exact:  map[string]uiRouteMetadata{},
		prefix: nil,
	}
	d := c2Evaluate(c2Req(http.MethodGet, "/api/no-such-endpoint", RoleAdmin), emptyIdx)
	if d.Matched {
		t.Errorf("Matched=true for unknown path; reason=%q", d.Reason)
	}
	if d.MetaPath != "" {
		t.Errorf("MetaPath=%q, want empty for unknown path", d.MetaPath)
	}
}

// TestC2_Evaluate_NoMethodPolicy confirms a route with metadata but
// no policy for the requested method falls into the "no method policy"
// soft-fail bucket.
func TestC2_Evaluate_NoMethodPolicy(t *testing.T) {
	// /api/audit's metadata declares only GET. PATCH on it has no
	// policy and no MethodAny fallback.
	idx := buildMetadataIndex()
	d := c2Evaluate(c2Req("PATCH", "/api/audit", RoleAdmin), idx)
	if d.Matched {
		t.Errorf("Matched=true for unsupported method; reason=%q", d.Reason)
	}
	if d.MetaPath != "/api/audit" {
		t.Errorf("MetaPath=%q, want /api/audit (path resolved, method did not)", d.MetaPath)
	}
}

// ── 4. Middleware shadow behavior ─────────────────────────────────────────

// c2NoopReachedHandler is a sentinel handler that records whether it
// was invoked. Used to assert the middleware NEVER blocks in C2a.
type c2NoopReachedHandler struct{ called bool }

func (h *c2NoopReachedHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h.called = true
	w.WriteHeader(http.StatusOK)
}

// TestC2_Middleware_ShadowAlwaysReachesHandler pins the shadow-mode
// invariant: even a request that WOULD be denied MUST still reach the
// handler when c2Mode() == c2ModeShadow. C2b's default is enforce, so
// this test forces shadow mode explicitly to keep the regression lock.
func TestC2_Middleware_ShadowAlwaysReachesHandler(t *testing.T) {
	withC2Mode(t, c2ModeShadow)
	resetC2Index()
	noop := &c2NoopReachedHandler{}
	mw := uiMetadataEnforcement(noop)

	// Viewer hitting admin-only route — would-deny.
	req := c2Req(http.MethodPost, "/api/auth/users", RoleViewer)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if !noop.called {
		t.Errorf("downstream handler NOT reached — shadow mode must let would-deny pass through")
	}
	if rec.Code == http.StatusForbidden {
		t.Errorf("got 403 — shadow mode must NOT block")
	}
}

// withC2Mode swaps c2EnforceMode for the duration of a test and
// restores the original value via t.Cleanup. Tests that need a
// specific mode must call this BEFORE constructing middleware.
func withC2Mode(t *testing.T, mode string) {
	t.Helper()
	oldMode := c2EnforceMode
	c2EnforceMode = mode
	t.Cleanup(func() { c2EnforceMode = oldMode })
}

// TestC2_Middleware_WouldDenyIncrementsCounter confirms the would-deny
// counter increments even though the request still proceeds.
func TestC2_Middleware_WouldDenyIncrementsCounter(t *testing.T) {
	resetC2Index()
	before := c2CounterSnapshot()

	noop := &c2NoopReachedHandler{}
	mw := uiMetadataEnforcement(noop)
	mw.ServeHTTP(httptest.NewRecorder(),
		c2Req(http.MethodPost, "/api/auth/users", RoleViewer))

	after := c2CounterSnapshot()
	if got, want := after.WouldDeny-before.WouldDeny, int64(1); got != want {
		t.Errorf("WouldDeny counter delta=%d, want %d", got, want)
	}
}

// TestC2_Middleware_MissingMetaIncrementsCounter confirms the
// missing-metadata counter still works when the index genuinely lacks
// an entry for the path. Production traffic never hits this path
// because uiRoutes contains the "/" catch-all; the counter exists for
// defense-in-depth against drift that would otherwise be silent.
//
// We swap the package-level c2Index for an empty one for the duration
// of this test, then restore.
func TestC2_Middleware_MissingMetaIncrementsCounter(t *testing.T) {
	_ = getC2Index() // ensure sync.Once has fired before we swap
	oldIdx := c2Index
	c2Index = &metadataIndex{
		exact:  map[string]uiRouteMetadata{},
		prefix: nil,
	}
	t.Cleanup(func() { c2Index = oldIdx })

	before := c2CounterSnapshot()

	noop := &c2NoopReachedHandler{}
	mw := uiMetadataEnforcement(noop)
	mw.ServeHTTP(httptest.NewRecorder(),
		c2Req(http.MethodGet, "/anything", RoleAdmin))

	after := c2CounterSnapshot()
	if got, want := after.MissingMeta-before.MissingMeta, int64(1); got != want {
		t.Errorf("MissingMeta counter delta=%d, want %d", got, want)
	}
	if !noop.called {
		t.Errorf("handler NOT reached on missing-metadata — must be soft-fail")
	}
}

// TestC2_Middleware_StaticAssetDoesNotIncrementMissingMeta is the
// regression lock for the chatgpt-codex review finding (PR #170): a
// production /index.html / /logo.png / /static/* request must NOT
// increment missing-metadata. Pre-fix this counter would jump on
// every page load, drowning real drift signal in noise.
func TestC2_Middleware_StaticAssetDoesNotIncrementMissingMeta(t *testing.T) {
	resetC2Index()
	before := c2CounterSnapshot()

	noop := &c2NoopReachedHandler{}
	mw := uiMetadataEnforcement(noop)
	for _, probe := range []string{
		"/",
		"/index.html",
		"/logo.png",
		"/static/css/main.css",
	} {
		mw.ServeHTTP(httptest.NewRecorder(),
			c2Req(http.MethodGet, probe, RolePublic))
	}

	after := c2CounterSnapshot()
	if got := after.MissingMeta - before.MissingMeta; got != 0 {
		t.Errorf("MissingMeta incremented on static-asset traffic: delta=%d", got)
	}
	if got := after.WouldDeny - before.WouldDeny; got != 0 {
		t.Errorf("WouldDeny incremented on static-asset traffic: delta=%d", got)
	}
}

// TestC2_Middleware_AdminPathDoesNotIncrementWouldDeny confirms a
// happy-path request leaves the would-deny counter alone.
func TestC2_Middleware_AdminPathDoesNotIncrementWouldDeny(t *testing.T) {
	resetC2Index()
	before := c2CounterSnapshot()

	noop := &c2NoopReachedHandler{}
	mw := uiMetadataEnforcement(noop)
	mw.ServeHTTP(httptest.NewRecorder(),
		c2Req(http.MethodPost, "/api/auth/users", RoleAdmin))

	after := c2CounterSnapshot()
	if got := after.WouldDeny - before.WouldDeny; got != 0 {
		t.Errorf("WouldDeny incremented for admin happy path: delta=%d", got)
	}
	if !noop.called {
		t.Error("handler not reached for admin happy path")
	}
}

// ── 5. Kill switch ────────────────────────────────────────────────────────

// TestC2_KillSwitch_DefaultIsEnforce confirms C2b's fail-closed default:
// the parsed mode is c2ModeEnforce when CULVERT_C2_ENFORCE is unset/empty.
// This was c2ModeShadow in C2a; the inversion is intentional so a
// missing/typo'd env var fails closed (enforce) rather than silently
// running in shadow.
//
// We invoke readC2EnforceMode directly (the public env var was already
// parsed at package init into c2EnforceMode; we re-parse to test the
// reader function in isolation).
func TestC2_KillSwitch_DefaultIsEnforce(t *testing.T) {
	t.Setenv(c2EnforceEnvVar, "")
	if got := readC2EnforceMode(); got != c2ModeEnforce {
		t.Errorf("default mode = %q, want %q (C2b is fail-closed)", got, c2ModeEnforce)
	}
}

// TestC2_Mode_AccessorReturnsParsedValue confirms c2Mode() exposes the
// value parsed at package init. C2a doesn't act on it; C2b will.
// Without this assertion the var would be unused (U1000) until C2b.
func TestC2_Mode_AccessorReturnsParsedValue(t *testing.T) {
	got := c2Mode()
	if got != c2ModeShadow && got != c2ModeEnforce {
		t.Errorf("c2Mode() = %q, want one of {%q, %q}", got, c2ModeShadow, c2ModeEnforce)
	}
}

// TestC2_KillSwitch_RecognisesEnforceValues — the CULVERT_C2_ENFORCE
// reader recognises common truthy strings and maps them to
// c2ModeEnforce. (In C2a the value is observed but not consumed by
// the middleware; C2b will activate the consumer.)
func TestC2_KillSwitch_RecognisesEnforceValues(t *testing.T) {
	for _, v := range []string{"true", "TRUE", "1", "yes", "on"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv(c2EnforceEnvVar, v)
			if got := readC2EnforceMode(); got != c2ModeEnforce {
				t.Errorf("%q parsed as %q, want %q", v, got, c2ModeEnforce)
			}
		})
	}
}

// TestC2_KillSwitch_FalseValuesForceShadow confirms ONLY the explicit
// false-ish set ("false"/"0"/"no"/"off") forces shadow. Anything else
// — unknown strings, typos — resolves to enforce (fail-closed).
func TestC2_KillSwitch_FalseValuesForceShadow(t *testing.T) {
	for _, v := range []string{"false", "FALSE", "False", "0", "no", "NO", "off", "OFF"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv(c2EnforceEnvVar, v)
			if got := readC2EnforceMode(); got != c2ModeShadow {
				t.Errorf("%q parsed as %q, want %q (kill switch must force shadow)", v, got, c2ModeShadow)
			}
		})
	}
}

// TestC2_KillSwitch_GarbageDefaultsEnforce confirms a typo'd env value
// resolves to enforce (fail-closed). Critical: this means
// CULVERT_C2_ENFORCE=falsy-typo cannot accidentally disable enforcement.
func TestC2_KillSwitch_GarbageDefaultsEnforce(t *testing.T) {
	for _, v := range []string{"garbage", "fals", "tru", "maybe"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv(c2EnforceEnvVar, v)
			if got := readC2EnforceMode(); got != c2ModeEnforce {
				t.Errorf("%q parsed as %q, want %q (typos must fail closed)", v, got, c2ModeEnforce)
			}
		})
	}
}

// resetC2Index clears the lazy-init index so tests that mutate
// uiRoutes (none today, but defensive) don't see a stale index.
// Cheap because building the index walks 131 entries.
func resetC2Index() {
	c2Index = buildMetadataIndex()
}

// ── 6. C2b enforcement tests ──────────────────────────────────────────────
//
// These tests pin the C2b enforcement contract — the moment shadow mode
// flips to actual 403s. The previous shadow-mode tests stay; this group
// adds the affirmative blocking behavior.

// TestC2_Enforce_ViewerHitsAdmin_403 is the central C2b invariant:
// in enforce mode, a session role below the per-method MinRole
// produces 403 BEFORE the handler runs.
func TestC2_Enforce_ViewerHitsAdmin_403(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	resetC2Index()

	noop := &c2NoopReachedHandler{}
	mw := uiMetadataEnforcement(noop)

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, c2Req(http.MethodPost, "/api/auth/users", RoleViewer))

	if rec.Code != http.StatusForbidden {
		t.Errorf("Viewer POST: got %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	if noop.called {
		t.Errorf("downstream handler reached — C2b must block in enforce mode")
	}
}

// TestC2_Enforce_AdminHitsAdmin_OK confirms the happy path is
// unaffected by enforcement: an admin role on an admin-only route
// passes through cleanly.
func TestC2_Enforce_AdminHitsAdmin_OK(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	resetC2Index()

	noop := &c2NoopReachedHandler{}
	mw := uiMetadataEnforcement(noop)

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, c2Req(http.MethodPost, "/api/auth/users", RoleAdmin))

	if rec.Code == http.StatusForbidden {
		t.Errorf("Admin POST blocked: got 403 (RBAC over-rejects admin); body=%s", rec.Body.String())
	}
	if !noop.called {
		t.Errorf("downstream handler not reached for admin happy path")
	}
}

// TestC2_Enforce_KillSwitchForcesShadow confirms CULVERT_C2_ENFORCE=false
// (parsed into c2ModeShadow) reverts to shadow behavior even on a
// would-deny request. Operators must be able to disable the enforcement
// gate without rebuilding.
func TestC2_Enforce_KillSwitchForcesShadow(t *testing.T) {
	// Force shadow mode (simulating CULVERT_C2_ENFORCE=false at startup).
	withC2Mode(t, c2ModeShadow)
	resetC2Index()

	noop := &c2NoopReachedHandler{}
	mw := uiMetadataEnforcement(noop)

	before := c2CounterSnapshot()

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, c2Req(http.MethodPost, "/api/auth/users", RoleViewer))

	if rec.Code == http.StatusForbidden {
		t.Errorf("kill switch failed: got 403 in shadow mode; body=%s", rec.Body.String())
	}
	if !noop.called {
		t.Errorf("downstream handler not reached in shadow mode — kill switch should let the request pass")
	}

	after := c2CounterSnapshot()
	if got := after.WouldDeny - before.WouldDeny; got != 1 {
		t.Errorf("WouldDeny counter delta=%d, want 1 (decision still recorded in shadow)", got)
	}
	if got := after.EnforceDenied - before.EnforceDenied; got != 0 {
		t.Errorf("EnforceDenied counter delta=%d, want 0 (no actual deny in shadow mode)", got)
	}
}

// TestC2_Enforce_PublicRouteNeverBlocked confirms public routes remain
// uiAuthMiddleware's domain. Even with C2 enforcing, a public POST
// (e.g. /api/auth/login with no role context) MUST proceed.
func TestC2_Enforce_PublicRouteNeverBlocked(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	resetC2Index()

	noop := &c2NoopReachedHandler{}
	mw := uiMetadataEnforcement(noop)

	rec := httptest.NewRecorder()
	// No role in context — uiAuthMiddleware's allowlist would let this
	// through in production. C2 must not block public routes.
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", http.NoBody)
	req.RemoteAddr = "198.51.100.70:0"
	mw.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Errorf("public route blocked by C2: got 403 — uiAuthMiddleware allowlist must remain authoritative")
	}
	if !noop.called {
		t.Errorf("downstream handler not reached for public route")
	}
}

// TestC2_Enforce_MissingMetadataNeverBlocks confirms missing metadata
// remains soft-fail in BOTH modes. Even in enforce mode, a path the
// metadata table doesn't know about must reach the handler — drift is
// observability, not a production outage; handler-level requireRole
// remains the real backstop.
func TestC2_Enforce_MissingMetadataNeverBlocks(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)

	// Swap c2Index for an empty one so the lookup genuinely misses
	// (the production catch-all "/" entry would otherwise resolve
	// every path).
	_ = getC2Index()
	oldIdx := c2Index
	c2Index = &metadataIndex{
		exact:  map[string]uiRouteMetadata{},
		prefix: nil,
	}
	t.Cleanup(func() { c2Index = oldIdx })

	noop := &c2NoopReachedHandler{}
	mw := uiMetadataEnforcement(noop)

	before := c2CounterSnapshot()

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, c2Req(http.MethodPost, "/api/some-drift-path", RoleViewer))

	if rec.Code == http.StatusForbidden {
		t.Errorf("missing-meta path blocked in enforce: got 403 — soft-fail invariant broken")
	}
	if !noop.called {
		t.Errorf("downstream handler not reached on missing meta — must be soft-fail in BOTH modes")
	}
	after := c2CounterSnapshot()
	if got := after.MissingMeta - before.MissingMeta; got != 1 {
		t.Errorf("MissingMeta delta=%d, want 1", got)
	}
	if got := after.EnforceDenied - before.EnforceDenied; got != 0 {
		t.Errorf("EnforceDenied delta=%d, want 0 (missing-meta must not increment enforce counter)", got)
	}
}

// TestC2_Enforce_NoMethodPolicyNeverBlocks confirms the no-policy
// soft-fail path also stays open in enforce mode. /api/audit declares
// only GET; a hypothetical PATCH must not be 403'd by C2 (the handler
// itself returns 405).
func TestC2_Enforce_NoMethodPolicyNeverBlocks(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	resetC2Index()

	noop := &c2NoopReachedHandler{}
	mw := uiMetadataEnforcement(noop)

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, c2Req("PATCH", "/api/audit", RoleViewer))

	if rec.Code == http.StatusForbidden {
		t.Errorf("no-policy path blocked in enforce: got 403 — soft-fail invariant broken")
	}
	if !noop.called {
		t.Errorf("downstream handler not reached on no-policy path")
	}
}

// TestC2_Enforce_DenyIncrementsBothCounters is the counters-sanity
// regression. In enforce mode, a would-deny MUST increment both
// counters by exactly one each — the policy decision and the
// enforcement action move in lock-step.
func TestC2_Enforce_DenyIncrementsBothCounters(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	resetC2Index()

	noop := &c2NoopReachedHandler{}
	mw := uiMetadataEnforcement(noop)

	before := c2CounterSnapshot()

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, c2Req(http.MethodPost, "/api/auth/users", RoleViewer))

	after := c2CounterSnapshot()
	if got := after.WouldDeny - before.WouldDeny; got != 1 {
		t.Errorf("WouldDeny delta=%d, want 1", got)
	}
	if got := after.EnforceDenied - before.EnforceDenied; got != 1 {
		t.Errorf("EnforceDenied delta=%d, want 1 (must lock-step with WouldDeny in enforce mode)", got)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("response code = %d, want 403", rec.Code)
	}
}

// TestC2_Enforce_ShadowDoesNotIncrementEnforceCounter confirms the
// EnforceDenied counter only moves in enforce mode. Shadow mode
// records the policy decision (WouldDeny) but never the action.
func TestC2_Enforce_ShadowDoesNotIncrementEnforceCounter(t *testing.T) {
	withC2Mode(t, c2ModeShadow)
	resetC2Index()

	noop := &c2NoopReachedHandler{}
	mw := uiMetadataEnforcement(noop)

	before := c2CounterSnapshot()

	mw.ServeHTTP(httptest.NewRecorder(),
		c2Req(http.MethodPost, "/api/auth/users", RoleViewer))

	after := c2CounterSnapshot()
	if got := after.WouldDeny - before.WouldDeny; got != 1 {
		t.Errorf("WouldDeny delta=%d, want 1 (decision recorded)", got)
	}
	if got := after.EnforceDenied - before.EnforceDenied; got != 0 {
		t.Errorf("EnforceDenied delta=%d, want 0 (no enforcement in shadow)", got)
	}
}

// TestC2_Enforce_DenyEmitsExactlyOneLogLine pins the regression for
// the chatgpt-codex P2 review on PR #171: in enforce mode, a denied
// request must produce exactly ONE log line ("C2-enforce: DENIED ...")
// and NOT the shadow-mode "WOULD-DENY" line. Pre-fix the middleware
// emitted both, mislabeling enforced denials as shadow decisions and
// doubling the deny-path log volume.
func TestC2_Enforce_DenyEmitsExactlyOneLogLine(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	resetC2Index()

	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	noop := &c2NoopReachedHandler{}
	mw := uiMetadataEnforcement(noop)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, c2Req(http.MethodPost, "/api/auth/users", RoleViewer))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
	out := buf.String()
	if !strings.Contains(out, "C2-enforce: DENIED") {
		t.Errorf("expected one C2-enforce DENIED line; got:\n%s", out)
	}
	if strings.Contains(out, "WOULD-DENY") {
		t.Errorf("enforce mode emitted shadow WOULD-DENY line — log dedup broken; got:\n%s", out)
	}
	if got := strings.Count(out, "C2-"); got != 1 {
		t.Errorf("expected exactly 1 C2-* line in enforce-mode deny, got %d:\n%s", got, out)
	}
}

// TestC2_Shadow_WouldDenyEmitsExactlyOneLogLine is the symmetric
// regression: in shadow mode, a would-deny request emits exactly ONE
// "C2-shadow: WOULD-DENY" line and NOT the enforce "DENIED" line.
func TestC2_Shadow_WouldDenyEmitsExactlyOneLogLine(t *testing.T) {
	withC2Mode(t, c2ModeShadow)
	resetC2Index()

	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	noop := &c2NoopReachedHandler{}
	mw := uiMetadataEnforcement(noop)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, c2Req(http.MethodPost, "/api/auth/users", RoleViewer))

	if rec.Code == http.StatusForbidden {
		t.Fatalf("shadow mode blocked: got 403")
	}
	if !noop.called {
		t.Fatalf("shadow mode did not reach handler")
	}
	out := buf.String()
	if !strings.Contains(out, "C2-shadow: WOULD-DENY") {
		t.Errorf("expected C2-shadow WOULD-DENY line; got:\n%s", out)
	}
	if strings.Contains(out, "DENIED") {
		t.Errorf("shadow mode emitted enforce DENIED line; got:\n%s", out)
	}
	if got := strings.Count(out, "C2-"); got != 1 {
		t.Errorf("expected exactly 1 C2-* line in shadow-mode would-deny, got %d:\n%s", got, out)
	}
}

// ── 7. C2c audit-completion observability tests ──────────────────────────
//
// These tests pin the C2c contract: a successful request whose
// metadata declares AuditExpected=true MUST emit at least one
// auditEvent / auditEventDiff call, or the middleware logs a single
// WARN line and increments c2AuditMissingTotal. Failed requests
// (4xx/5xx) and routes with AuditExpected=false produce no warning.
// C2c never blocks a request.

// c2RoleHandler returns an http.Handler that always returns 200 and
// optionally calls auditEvent on its way out. Used by C2c tests to
// simulate handlers that do or do not audit.
func c2RoleHandler(audit bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if audit {
			auditEvent(r, "test.audit", "c2c", "")
		}
		w.WriteHeader(http.StatusOK)
	})
}

// c2FailHandler returns a handler that responds with the given
// status. Used to verify failed requests skip the C2c warning.
func c2FailHandler(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	})
}

// TestC2c_AuditExpected_Emitted_NoWarning is the happy path: an
// admin POSTs to /api/auth/users (AuditExpected=true) and the
// handler emits an audit event. No warning, counter unchanged.
func TestC2c_AuditExpected_Emitted_NoWarning(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	resetC2Index()

	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	before := c2CounterSnapshot()

	mw := uiMetadataEnforcement(c2RoleHandler(true))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, c2Req(http.MethodPost, "/api/auth/users", RoleAdmin))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if strings.Contains(buf.String(), "audit missing") {
		t.Errorf("unexpected audit-missing warning when handler audited:\n%s", buf.String())
	}
	after := c2CounterSnapshot()
	if got := after.AuditMissing - before.AuditMissing; got != 0 {
		t.Errorf("AuditMissing delta=%d, want 0", got)
	}
}

// TestC2c_AuditExpected_NotEmitted_Warning is the central C2c
// invariant: AuditExpected=true on a successful request without an
// audit emission MUST log a warning and increment the counter.
func TestC2c_AuditExpected_NotEmitted_Warning(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	resetC2Index()

	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	before := c2CounterSnapshot()

	mw := uiMetadataEnforcement(c2RoleHandler(false))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, c2Req(http.MethodPost, "/api/auth/users", RoleAdmin))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	out := buf.String()
	if !strings.Contains(out, "C2: audit missing") {
		t.Errorf("expected C2 audit-missing warning; got:\n%s", out)
	}
	if !strings.Contains(out, "/api/auth/users") {
		t.Errorf("warning did not include the route path; got:\n%s", out)
	}
	if got := strings.Count(out, "audit missing"); got != 1 {
		t.Errorf("expected exactly 1 audit-missing line, got %d:\n%s", got, out)
	}
	after := c2CounterSnapshot()
	if got := after.AuditMissing - before.AuditMissing; got != 1 {
		t.Errorf("AuditMissing delta=%d, want 1", got)
	}
}

// TestC2c_AuditNotExpected_NoWarning confirms routes whose metadata
// declares AuditExpected=false produce no warning regardless of
// whether the handler audited.
func TestC2c_AuditNotExpected_NoWarning(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	resetC2Index()

	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	before := c2CounterSnapshot()

	// /api/audit GET is metadata-declared AuditExpected=false. The
	// handler does not audit; we must NOT log a warning.
	mw := uiMetadataEnforcement(c2RoleHandler(false))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, c2Req(http.MethodGet, "/api/audit", RoleViewer))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if strings.Contains(buf.String(), "audit missing") {
		t.Errorf("unexpected warning for AuditExpected=false route:\n%s", buf.String())
	}
	after := c2CounterSnapshot()
	if got := after.AuditMissing - before.AuditMissing; got != 0 {
		t.Errorf("AuditMissing delta=%d, want 0", got)
	}
}

// TestC2c_FailedRequest_NoWarning confirms failed requests (4xx/5xx)
// skip the audit-completion check entirely. Most error paths
// legitimately don't audit, and warning on every failure would drown
// real gaps in noise.
func TestC2c_FailedRequest_NoWarning(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	resetC2Index()

	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	before := c2CounterSnapshot()

	// Admin POSTs to /api/auth/users (AuditExpected=true). Handler
	// returns 400 without auditing. C2c must NOT warn — failed
	// requests are exempt.
	mw := uiMetadataEnforcement(c2FailHandler(http.StatusBadRequest))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, c2Req(http.MethodPost, "/api/auth/users", RoleAdmin))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if strings.Contains(buf.String(), "audit missing") {
		t.Errorf("unexpected warning on failed request:\n%s", buf.String())
	}
	after := c2CounterSnapshot()
	if got := after.AuditMissing - before.AuditMissing; got != 0 {
		t.Errorf("AuditMissing delta=%d, want 0 (failed requests must skip)", got)
	}
}

// TestC2c_NeverBlocksRequest pins the no-blocking invariant: even
// when the audit-completion check fires, the response code stays 200
// and the handler reaches its end. C2c is observability only.
func TestC2c_NeverBlocksRequest(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	resetC2Index()

	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	var handlerEnd bool
	mw := uiMetadataEnforcement(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// AuditExpected=true on this route, but handler does NOT audit.
		w.WriteHeader(http.StatusOK)
		handlerEnd = true
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, c2Req(http.MethodPost, "/api/auth/users", RoleAdmin))

	if rec.Code != http.StatusOK {
		t.Errorf("C2c blocked successful request: got %d, want 200", rec.Code)
	}
	if !handlerEnd {
		t.Errorf("handler did not reach end — C2c must never block")
	}
	if !strings.Contains(buf.String(), "audit missing") {
		t.Errorf("expected audit-missing warning regardless; got:\n%s", buf.String())
	}
}

// TestC2c_OneWarningPerRequest pins the no-double-log invariant.
// Even if the handler is invoked through several layers, the
// middleware emits at most one C2 audit-missing line per request.
func TestC2c_OneWarningPerRequest(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	resetC2Index()

	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	mw := uiMetadataEnforcement(c2RoleHandler(false))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, c2Req(http.MethodPost, "/api/auth/users", RoleAdmin))

	if got := strings.Count(buf.String(), "audit missing"); got != 1 {
		t.Errorf("expected exactly 1 audit-missing line, got %d:\n%s", got, buf.String())
	}
}

// TestC2c_PublicRoute_NoWarning confirms public routes are exempt
// from the audit-completion check (consistent with C2's overall
// "uiAuthMiddleware owns public routes" doctrine).
func TestC2c_PublicRoute_NoWarning(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	resetC2Index()

	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	before := c2CounterSnapshot()

	// /api/auth/login POST is Public=true with AuditExpected=true in
	// metadata. C2c does not own public routes; a public response
	// without audit must not warn.
	mw := uiMetadataEnforcement(c2RoleHandler(false))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", http.NoBody)
	req.RemoteAddr = "198.51.100.71:0"
	// no role context — public route
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if strings.Contains(buf.String(), "audit missing") {
		t.Errorf("public route emitted audit-missing warning — must be exempt:\n%s", buf.String())
	}
	after := c2CounterSnapshot()
	if got := after.AuditMissing - before.AuditMissing; got != 0 {
		t.Errorf("AuditMissing delta=%d, want 0 on public route", got)
	}
}
