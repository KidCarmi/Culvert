package main

import (
	"context"
	"net/http"
	"sync/atomic"
)

// ── Phase C4 — Role-divergence detector (REPORT-ONLY) ─────────────────────
//
// C4 surfaces the case where the C2 metadata is more permissive than the
// handler's actual contract for a given request. Concretely: C2's
// per-method MinRole says "viewer is enough," but the handler internally
// calls requireRole(RoleAdmin) and rejects the request with 403. This
// happens legitimately for dynamic-handler dispatchers like apiIdPRouter
// (one route, multiple sub-paths/methods with different roles) where the
// metadata can only declare the LOWEST accepted role. C4 records each
// divergence event so operators can see when and where the metadata is
// permissive enough that defense-in-depth is doing real work.
//
// SCOPE — strict invariants:
//   • REPORT-ONLY. C4 never blocks, never allows, never changes the
//     response. The handler-level requireRole call remains the real
//     backstop and produces the 403 itself; C4 only observes the
//     decision and increments a counter.
//   • No metadata schema change. uiRouteMetadata / uiRouteMethod are
//     untouched.
//   • No enforcement change. C2's enforce/shadow modes are unchanged.
//   • No new endpoints. The signal flows out via the existing
//     /api/governance/control-plane surface (C3) plus a structured
//     log line.
//   • No audit-ring writes. Divergence events are observability,
//     not admin-action audit; surfacing them through the audit ring
//     would dilute the audit trail.
//
// The detection narrows divergence to ONE specific case:
//
//   C2's evaluated MinRole was strictly LOWER than the role the handler
//   ultimately demanded, AND the handler's requireRole(higherRole)
//   returned false (403).
//
// The reverse case (metadata stricter than handler) cannot happen at
// runtime in enforce mode because C2 returns 403 before the handler
// runs. In shadow mode the handler runs, but if the handler accepts
// the (lower) role then there is no divergence to record — only the
// handler's contract was met. C4 therefore covers the privilege-
// escalation-prevention direction: "C2 said yes, handler said no."

// c2EvaluatedRoleKey is the request-context key under which
// uiMetadataEnforcement stores the per-method MinRole that C2
// evaluated for this request. recordRoleDivergence reads this value
// to decide whether a handler-side rejection counts as divergence.
//
// Using an unexported empty-struct key (matching c2AuditedKey,
// uiRoleKey) so no other package can accidentally collide.
type c2EvaluatedRoleKey struct{}

// withC2EvaluatedRole returns r with the C2-evaluated MinRole stored
// in its context. Callers (currently only uiMetadataEnforcement) MUST
// only set this when a per-method policy actually resolved — public
// routes, missing-metadata, and no-policy paths leave the context
// untouched, which makes recordRoleDivergence a no-op for them.
func withC2EvaluatedRole(r *http.Request, role UIRole) *http.Request {
	if role == "" {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), c2EvaluatedRoleKey{}, role))
}

// c2RoleDivergenceTotal counts requests where the handler's
// requireRole(R) returned false AND C2 had evaluated a strictly-lower
// MinRole for the same request — i.e. metadata was more permissive
// than the handler's actual contract. The counter increments at most
// ONCE per request (recordRoleDivergence is called from the failure
// path of requireRole; a single request that fails once does not
// trigger a second requireRole call against the same handler).
//
// The counter belongs to the c2* family for governance purposes
// (surfaced by the C3 governance endpoint), even though it is logged
// under the C4 layer.
var c2RoleDivergenceTotal atomic.Int64

// recordRoleDivergence is called from requireRole's failure branch.
// It compares the handler's requested role against the C2-evaluated
// MinRole stored in the request context, and increments
// c2RoleDivergenceTotal when the handler is strictly stricter.
//
// All exits are no-ops:
//   - r == nil (defensive; should not happen for HTTP handlers)
//   - no c2EvaluatedRoleKey in context (route was public, missing
//     meta, no policy, or the request bypassed uiMetadataEnforcement
//     entirely — e.g. a test calling requireRole directly without
//     mounting the middleware). Soft-fail; never blocks.
//   - C2's evaluated role is at-least-as-strict as the handler's
//     (ev priority >= handlerRole priority). This is the parity
//     case: metadata and handler agree, no divergence.
//
// On a true divergence event:
//   - c2RoleDivergenceTotal.Add(1)
//   - One structured log line via logger.Printf at INFO level. No
//     auditEvent call (per the C4 invariant: not an admin action).
//
// recordRoleDivergence does NOT touch the response writer and never
// returns a value — it is purely an observation hook.
func recordRoleDivergence(r *http.Request, handlerRole UIRole) {
	if r == nil {
		return
	}
	ev, ok := r.Context().Value(c2EvaluatedRoleKey{}).(UIRole)
	if !ok || ev == "" {
		return
	}
	// Divergence iff C2 was strictly more permissive than the handler.
	// "More permissive" means C2's role priority is strictly lower
	// than the handler's, i.e. C2 would have admitted a less-
	// privileged session than the handler accepts.
	if rolePriority[ev] >= rolePriority[handlerRole] {
		return
	}
	c2RoleDivergenceTotal.Add(1)
	logger.Printf("C2: role divergence path=%q method=%q metadata_min=%q handler_min=%q actor_role=%q",
		r.URL.Path, r.Method, ev, handlerRole, uiRole(r))
}
