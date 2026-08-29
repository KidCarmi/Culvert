package main

// MCP four-eyes principal resolution (SEC-MCP-4E-1).
//
// `internal/mcp/approval` enforces four-eyes by comparing the approver against the
// requester (`approval/store.go`, ReasonApprovalSelfApproval), and its PrincipalID is
// documented as "a STABLE authenticated principal identifier". Every admin-HTTP call
// site used to build that PrincipalID from `auditActor(r)`, which is an ATTRIBUTION
// string, not an identity: it is `realClientIP(r)`, prefixed with `"<sub>@"` only when a
// UI session cookie is present. That made the control key on NETWORK LOCATION:
//
//   - Fail-OPEN (the serious half): one human satisfies four-eyes alone by issuing the
//     approve from a different source address — a second workstation, a VPN, or, when a
//     trusted proxy is configured, a different X-Forwarded-For value, which realClientIP
//     honours by design. The four-eyes refusal never fires.
//   - Fail-CLOSED (the pressure that produces the bypass): on the HTTP Basic path — a
//     first-class programmatic admin path (uiAuthMiddleware) that carries NO session
//     cookie — the principal is the address ALONE and the username never appears, so two
//     genuinely different admins behind one bastion/NAT/reverse-proxy address are one
//     principal and a legitimate approval is refused as self-approval.
//
// mcpApprovalPrincipal resolves the principal from the AUTHENTICATED IDENTITY instead,
// and never includes the client address. `auditActor` is deliberately left alone: audit
// attribution genuinely wants the address, and every auditEvent call keeps using it.

import "net/http"

// mcpApprovalPrincipal returns the four-eyes principal for an MCP approval decision:
// who the caller IS, never where they connected from.
//
// Resolution mirrors uiAuthMiddleware's own precedence exactly, so the principal is
// always an identity the middleware actually authenticated:
//
//  1. the admin UI session cookie's subject (else its email) — the browser path;
//  2. the HTTP Basic username — the programmatic path. It is trusted ONLY when
//     cfg.IsConfigured(), because that is precisely when the middleware reached its
//     VerifyUIUser branch; the pre-setup bootstrap branch admits an UNVERIFIED Basic
//     header, so the username is not an authenticated identity there;
//  3. otherwise auditActor(r) — the pre-setup bootstrap path, where the admin API has no
//     authentication at all and four-eyes is meaningless regardless. Falling back keeps
//     that degenerate case byte-identical to the previous behaviour (never worse) rather
//     than introducing an empty principal the approval stores would reject.
//
// The returned value is compared for EQUALITY only; it is never rendered as an audit
// actor, never persisted as a credential, and never used for authorization (the role
// gate already ran).
func mcpApprovalPrincipal(r *http.Request) string {
	if sess, err := readUISessionCookie(r); err == nil && sess != nil {
		if sess.Sub != "" {
			return sess.Sub
		}
		if sess.Email != "" {
			return sess.Email
		}
	}
	if cfg.IsConfigured() {
		if user, _, ok := r.BasicAuth(); ok && user != "" {
			return user
		}
	}
	return auditActor(r)
}
