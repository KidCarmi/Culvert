package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// defaultPolicyAction controls what happens when no PBAC rule matches a request.
// "allow" = passthrough mode (initial setup), "deny" = zero-trust (production).
// Set by setDefaultPolicyAction() during startup based on config or rule count.
// Stored as 1 (allow) or 0 (deny) via atomic int32 to avoid data races.
var defaultPolicyActionAllow int32 // 0 = deny (default)

func setDefaultPolicyAction(action string) {
	if action == "allow" {
		atomic.StoreInt32(&defaultPolicyActionAllow, 1)
	} else {
		atomic.StoreInt32(&defaultPolicyActionAllow, 0)
	}
}

// defaultPolicyAction returns the current default action string ("allow"/"deny").
func defaultPolicyAction() string {
	if atomic.LoadInt32(&defaultPolicyActionAllow) == 1 {
		return "allow"
	}
	return "deny"
}

// scrubForwardedHeaders sanitises request headers before forwarding upstream:
//   - X-Forwarded-For: private/internal IPs are stripped; if all IPs were
//     private the header is removed entirely.
//   - X-Real-IP: removed when it contains a private address.
//   - X-User-Identity: always removed — set internally by auth context;
//     must not be trusted from downstream clients or leak upstream.
//
// This prevents internal network topology disclosure and stops clients from
// injecting identity claims.
func scrubForwardedHeaders(r *http.Request) {
	// Strip private IPs from X-Forwarded-For.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		var public []string
		for _, raw := range strings.Split(xff, ",") {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip != nil && !isPrivateIP(ip) {
				public = append(public, ip.String())
			}
		}
		if len(public) == 0 {
			r.Header.Del("X-Forwarded-For")
		} else {
			r.Header.Set("X-Forwarded-For", strings.Join(public, ", "))
		}
	}

	// Remove X-Real-IP if it resolves to a private address.
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := net.ParseIP(strings.TrimSpace(xri))
		if ip == nil || isPrivateIP(ip) {
			r.Header.Del("X-Real-IP")
		}
	}

	// Always remove internal identity header before forwarding.
	r.Header.Del("X-User-Identity")
}

// policyLogURI builds the URL stored in LogEntry.URI for the per-rule "log full
// URL" option: host + path only. The query string is intentionally dropped —
// it routinely carries auth tokens, session IDs, and PII (admin chose path-only
// capture). path is already query-free (r.URL.Path / req.URL.Path exclude the
// query); when it is empty (e.g. a CONNECT tunnel with no decrypted request)
// only the host is returned.
func policyLogURI(host, path string) string {
	// Defensive: guarantee no query is ever stored even if a crafted Host
	// header smuggled a '?' (path is already query-free).
	if i := strings.IndexByte(host, '?'); i >= 0 {
		host = host[:i]
	}
	if path == "" {
		return host
	}
	return host + path
}

// recordInspectBlock logs a block decision from the SSL-inspect inner loop,
// attaching the decrypted host+path as the URI when the matched rule has
// LogFullURI — so a blocked download keeps its full URL, the events that matter
// most for investigation. Blocks are always logged (no LogTraffic gate); only
// the URI is conditional. Counting matches the prior recordRequest path.
func recordInspectBlock(clientIP, status, ruleMatched, actionTaken, hostOnly, path string, match *PolicyMatch) {
	uri := ""
	auth := AuthLogFields{}
	if match != nil && match.Rule != nil {
		if match.Rule.LogFullURI {
			uri = policyLogURI(hostOnly, path)
		}
		// Stamp the governing rule's ULID only when THIS rule's own file profile
		// made the block (parity with the plain-HTTP file-block at
		// applyPolicyDecision). DPI/scan/global-extension blocks are scanner
		// decisions independent of the tunnel's allow rule, so they carry no
		// ruleId — attributing them to the allow rule would mislead the feed.
		if match.Rule.FileProfileBlocked(path) {
			auth.RuleID = match.Rule.ID
		}
	}
	recordRequestAuthURI(clientIP, "CONNECT", hostOnly, status, ruleMatched, actionTaken, "", "inspect", uri, auth)
}

// authOutcome carries the Stage-1 adaptive-auth result from
// resolveRequestAuth back to handleRequest.
type authOutcome struct {
	identity string
	groups   []string
	source   string
	log      AuthLogFields
}

// resolveRequestAuth runs the Stage-1 adaptive authentication pipeline
// (session cookie -> Proxy-Authorization Basic -> no-credential outcome
// dispatch). When it returns proceed=false it has ALREADY written a terminal
// response (407 / redirect / 403) and the caller MUST return immediately.
// Behaviour is identical to the previously-inlined pipeline; this is a
// structural extraction only (DEBT-002), no logic change.
func resolveRequestAuth(w http.ResponseWriter, r *http.Request, clientIP, reqID string) (authOutcome, bool) { //nolint:gocognit,cyclop,funlen // Stage-1 credential-resolution decision tree; complexity is inherent and now isolated/testable (DEBT-002; further sub-extraction tracked there)
	// ── Adaptive Authentication ───────────────────────────────────────────────
	// Resolution order:
	//  1. Signed session cookie (browser SSO — OIDC code flow or SAML).
	//  2. Proxy-Authorization Basic header (non-browser / API clients).
	//     a. Resolved via IdP registry (OIDC introspection) if providers exist.
	//     b. Legacy single LDAP/OIDC provider (cfg.ProviderEnabled).
	//     c. Local bcrypt auth.
	//  3. No credentials — redirect browser to captive portal or send 407.
	var authenticatedIdentity string
	var authenticatedGroups []string
	authenticatedSource := "unauth" // default: no credentials presented
	var authLog AuthLogFields       // Stage-1 auth observability; zero unless an exempt or credential-required rule matched

	// Slice 3 (S2): scoped auth rules evaluate first; the global
	// defaultAuthOutcome applies only on no-match. effectiveDefault is the global
	// default forced to Default when the Exempt kill switch is engaged.
	//
	// Two distinct backend predicates (both EXCLUDE the Exempt term, so the gate
	// never depends on the global default):
	//   - credCapable: a validator that can verify a PRESENTED Basic credential
	//     (local account, legacy provider, or enabled OIDC). SAML is browser-only
	//     and is EXCLUDED — otherwise a SAML-only deployment would enter the Basic
	//     branch, SAML ResolveIdentity would fail, and cfg.VerifyAuth with no local
	//     user accepts any creds → identity spoofing.
	//   - ssoCapable: any enabled interactive IdP (OIDC or SAML) that can drive the
	//     no-credentials SSO/captive path. SAML IS included here.
	// authRequired uses (credCapable || ssoCapable) — byte-identical to today's
	// backend term under Default — plus the Exempt-default term. Arm 2 (Basic
	// validation) gates on credCapable ONLY.
	//
	// Gate ENTRY keys on originalEffective (the PRE-kill-switch global default),
	// NOT on the kill-switched effectiveDefault. Otherwise a no-backend,
	// originally-Exempt deployment (credCapable==ssoCapable==false) would, once the
	// kill switch forces effectiveDefault→Default, drop the Exempt term, SKIP the
	// whole gate, and silently stop challenging scoped CredentialRequired rules —
	// the kill switch, which must be strictly MORE restrictive, would fail OPEN.
	// Entering on originalEffective keeps the gate armed so CR/SSO rules still
	// challenge; the kill-switched effectiveDefault below still governs the
	// no-credential DEFAULT outcome INSIDE the gate (scoped Exempt is suppressed and
	// falls to forced-Default). Backend-present behavior is byte-identical: with
	// credCapable or ssoCapable true, authRequired is already true regardless of
	// which default term is used.
	effectiveDefault := cfg.DefaultAuthOutcome()
	originalEffective := effectiveDefault
	if authExemptKillSwitchEngaged() {
		effectiveDefault = OutcomeDefault
	}
	credCapable := hasCredentialCapableProvider()
	ssoCapable := idpRegistry.HasEnabledProviders() // allocation-free probe — EnabledProviders() builds a slice per call, and this runs per request
	authRequired := credCapable || ssoCapable || originalEffective == OutcomeExempt

	if authRequired { //nolint:nestif // adaptive-auth decision tree is inherently nested (matches the if-match dispatch convention; DEBT-002 isolated it for testability)
		// ── 1. Session cookie (browser SSO) ──────────────────────────────────
		if sess, err := readSessionCookie(r); err == nil && sess != nil {
			id := sessionIdentity(sess)
			authenticatedIdentity = id.Sub
			if authenticatedIdentity == "" {
				authenticatedIdentity = id.Email
			}
			authenticatedGroups = id.Groups
			authenticatedSource = identityAuthSource(id, "local")
		} else {
			// ── 2. Basic Auth header ──────────────────────────────────────────
			// Credential validation runs ONLY when a credential-capable validator
			// exists (credCapable — SAML-only does NOT count). Without one,
			// presented credentials must not become an implicit allow path (e.g.
			// VerifyAuth accepting any creds when no user is set, or a SAML-only
			// deployment spoofing identities); they fall through to arm 3, where
			// resolveNoCredAuthOutcome returns Default for any Proxy-Authorization
			// header (never default-exempted).
			u, p, ok := parseProxyAuth(r)
			if ok && credCapable {
				// Try IdP registry providers first (OIDC introspection).
				authed := false
				for _, prov := range idpRegistry.EnabledProviders() {
					if id, resolved := prov.ResolveIdentity(u, p); resolved && id != nil {
						authenticatedIdentity = id.Sub
						if authenticatedIdentity == "" {
							authenticatedIdentity = u
						}
						authenticatedGroups = id.Groups
						authenticatedSource = identityAuthSource(id, prov.Name())
						authed = true
						break
					}
				}
				// Fall back to legacy single provider or local bcrypt.
				if !authed {
					if !cfg.VerifyAuth(u, p) {
						atomic.AddInt64(&statAuthFail, 1)
						w.Header().Set("Proxy-Authenticate", `Basic realm="Culvert"`)
						http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
						recordRequest(clientIP, r.Method, r.Host, "AUTH_FAIL", "", "", "", "")
						logger.Printf("AUTH_FAIL %s {req_id=%s action=block}", clientIP, reqID)
						return authOutcome{}, false
					}
					authenticatedIdentity = u
					authenticatedSource = "local"
				}
			} else {
				// ── 3. No credentials — resolve the Stage-1 outcome and dispatch.
				// A switch (not an if-else chain) keeps gocritic happy; cases 3a/3a'
				// fall through to Stage-2, 3b/3c/Default write a response and return.
				d := resolveNoCredAuthOutcome(r, clientIP, effectiveDefault)
				switch {
				case d.Outcome == OutcomeExempt && d.Rule != nil:
					// ── 3a. No credentials — SCOPED Exempt rule (Rule != nil) ────
					// An explicitly matched auth/exempt rule waives the challenge
					// for this request ONLY. No identity is created:
					// authenticatedIdentity stays empty, so X-User-Identity is
					// never set and groups stay nil. authenticatedSource becomes
					// "exempt" (NOT "unauth") so Stage-2 policy, request logs, and
					// SIEM can distinguish explicit exemptions from plain
					// unauthenticated traffic. Execution falls through to the same
					// blocklist/threat/policy pipeline as every other request —
					// default-deny still applies. Note: a stale/expired session
					// cookie with no Proxy-Authorization lands here too and is
					// treated as "no credentials" (exempt-eligible). Presented
					// credentials of ANY shape — valid, invalid, or malformed
					// (unsupported scheme / bad base64, where parseProxyAuth
					// returns ok=false) — are never exempted:
					// resolveNoCredAuthOutcome returns Default whenever a
					// Proxy-Authorization header is present, so malformed
					// credentials keep today's 407 below.
					authLog = authLogFieldsFor(d)
					authenticatedSource = authSourceExempt
					incAuthExempt()
					logger.Printf("AUTH_EXEMPT rule=%q id=%q %s -> %q {req_id=%s}",
						sanitizeLog(d.Rule.Name), sanitizeLog(d.Rule.ID), clientIP, sanitizeLog(r.Host), reqID)
				case d.Outcome == OutcomeExempt:
					// ── 3a'. No credentials — DEFAULT Exempt (no scoped match) ───
					// defaultAuthOutcome=Exempt opened this UNMATCHED request. This is
					// NOT a scoped exemption: no rule, no identity, authenticatedSource
					// stays "unauth" (distinct from a scoped Exempt rule's "exempt"),
					// and no exempt metric. Mirrors legacy open mode — falls through to
					// Stage-2, where default-deny still applies (open ≠ allow).
					logger.Printf("AUTH_DEFAULT_EXEMPT (open, no rule) %s -> %q {req_id=%s}",
						clientIP, sanitizeLog(r.Host), reqID)
				case d.Outcome == OutcomeCredentialRequired:
					// ── 3b. No credentials — Stage-1 CredentialRequired challenge ──
					// A matched CR rule demands a non-interactive credential
					// challenge. Unlike Exempt this is NOT a waiver: we return a
					// deterministic 407 immediately and DO NOT fall through to
					// Stage-2 — the request must authenticate first. No identity is
					// created (authenticatedIdentity stays empty → X-User-Identity is
					// never set), the SSO captive redirect is suppressed, and the CR
					// auth fields are attached to the request-log record. CRED_REQUIRED
					// is a policy-driven challenge, not a failed credential attempt;
					// statAuthFail is still bumped for 407-counter compatibility.
					// Reachable only with no presented credentials (failed/malformed
					// credentials 407 in arm 2 above; resolveNoCredAuthOutcome returns
					// Default whenever a Proxy-Authorization header is present). The
					// kill switch does NOT disable CR.
					authLog = authLogFieldsFor(d)
					atomic.AddInt64(&statAuthFail, 1)
					incAuthCredentialRequired()
					w.Header().Set("Proxy-Authenticate", `Basic realm="Culvert"`)
					http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
					recordRequestAuth(clientIP, r.Method, r.Host, "CRED_REQUIRED", d.Rule.Name, "", "", authLog)
					logger.Printf("AUTH_CR rule=%q id=%q %s -> %q {req_id=%s action=challenge}",
						sanitizeLog(d.Rule.Name), sanitizeLog(d.Rule.ID), clientIP, sanitizeLog(r.Host), reqID)
					return authOutcome{}, false
				case d.Outcome == OutcomeSSORequired:
					// ── 3c. No credentials — Stage-1 SSORequired challenge (Slice 4) ──
					// A matched SSORequired rule demands an INTERACTIVE browser SSO
					// flow. No identity is created (authenticatedIdentity stays empty →
					// X-User-Identity is never set), and the branch returns immediately
					// — Stage-2 never runs until the client completes SSO and a session
					// exists. classifyClient is consulted ONLY here (the Default path
					// below keeps browserRedirectEligibleLegacy). Reachable only with no
					// presented credentials (failed/malformed credentials 407 in arm 2;
					// resolveNoCredAuthOutcome returns Default whenever a
					// Proxy-Authorization header is present).
					authLog = authLogFieldsFor(d)
					// Only a browser can complete an interactive SSO flow. Resolving the
					// portal URL can ALLOCATE IdP callback state (PKCE / SAML stores) as a
					// side effect, so it is done ONLY for browser clients: a non-browser or
					// CONNECT request fails closed WITHOUT touching those capped stores
					// (otherwise a stream of denied requests could churn / evict legitimate
					// in-flight browser logins). classifyClient is consulted ONLY here.
					if classifyClient(r) == clientBrowser {
						if portalURL, eligible := resolveSSOPortalURL(r, d.Rule.Auth.ProviderRefs); eligible > 0 && portalURL != "" && isSafeCaptiveRedirect(portalURL) {
							// Browser + ≥1 eligible IdP → 302 to the captive portal /
							// provider flow scoped by providerRefs.
							incAuthSSORequired()
							recordRequestAuth(clientIP, r.Method, r.Host, "SSO_REDIRECT", d.Rule.Name, "", "", authLog)
							logger.Printf("AUTH_SSO rule=%q id=%q %s -> %q {req_id=%s action=redirect}",
								sanitizeLog(d.Rule.Name), sanitizeLog(d.Rule.ID), clientIP, sanitizeLog(r.Host), reqID)
							http.Redirect(w, r, portalURL, http.StatusFound) // #nosec G710 -- portalURL passed isSafeCaptiveRedirect (same-origin path or admin-configured http(s) URL)
							return authOutcome{}, false
						}
					}
					// DR-1 fail-closed: non-browser, CONNECT, or a browser with no eligible
					// IdP after providerRefs filtering. No Basic 407 (a false affordance —
					// the rule wants interactive SSO, not Basic), no identity, and no SSO
					// callback state was allocated for the rejected request.
					incAuthSSORequired()
					recordRequestAuth(clientIP, r.Method, r.Host, "SSO_DENIED", d.Rule.Name, "", "", authLog)
					logger.Printf("AUTH_SSO rule=%q id=%q %s -> %q {req_id=%s action=deny}",
						sanitizeLog(d.Rule.Name), sanitizeLog(d.Rule.ID), clientIP, sanitizeLog(r.Host), reqID)
					http.Error(w, "Forbidden: destination requires interactive SSO", http.StatusForbidden)
					return authOutcome{}, false
				default:
					// ── 3. No credentials ────────────────────────────────────────
					// No-backend inert guard. With neither a credential-capable
					// validator (credCapable) nor an interactive IdP (ssoCapable), a
					// 407 challenge or captive-portal redirect is UNFULFILLABLE — no
					// presented credential could ever be validated and no SSO flow
					// could complete. Emitting one would be a dangling affordance and,
					// worse, the kill switch (which reaches this arm only by forcing a
					// no-backend originally-Exempt deployment from Exempt→Default) would
					// then surface a 407 the operator can never satisfy. Per the frozen
					// spec's "no rule matches, Default, no auth backend → inert" row,
					// fall through to Stage-2 instead: no identity is created,
					// authenticatedSource stays "unauth", and the default-deny backstop
					// still applies (open ≠ allow). Backend-present behavior is
					// unchanged — this guard is skipped whenever a backend exists.
					if !credCapable && !ssoCapable {
						logger.Printf("AUTH_NO_BACKEND_INERT (no credential/SSO backend) %s -> %q {req_id=%s action=fallthrough}",
							clientIP, sanitizeLog(r.Host), reqID)
						break
					}
					// browserRedirectEligibleLegacy is the verbatim pre-Slice-1
					// predicate (Mozilla User-Agent && non-CONNECT) — the Default
					// compatibility path. It is intentionally NOT classifyClient:
					// classifyClient drives SSORequired (arm 3c) only; the Default path
					// stays legacy-pinned (DR-5).
					if browserRedirectEligibleLegacy(r) {
						// Route browser to appropriate IdP based on email domain hint.
						loginURL := resolveCaptivePortalURL(r)
						// Inline guard for static-analysis visibility:
						// resolveCaptivePortalURL returns either a same-origin
						// path ("/auth/select?relay=...") or an admin-configured
						// absolute http(s) IdP URL. isSafeCaptiveRedirect rejects
						// protocol-relative ("//evil"), data:/javascript:, and
						// any other shape (covered by TestIsSafeCaptiveRedirect).
						if loginURL != "" && isSafeCaptiveRedirect(loginURL) {
							// gosec G710's SSA pass cannot follow the
							// isSafeCaptiveRedirect predicate; the guard above is
							// the actual safety check.
							http.Redirect(w, r, loginURL, http.StatusFound) // #nosec G710 -- loginURL passed isSafeCaptiveRedirect (same-origin path or admin-configured http(s) URL)
							return authOutcome{}, false
						}
					}
					atomic.AddInt64(&statAuthFail, 1)
					w.Header().Set("Proxy-Authenticate", `Basic realm="Culvert"`)
					if u := cfg.OIDCLoginURL(); u != "" {
						w.Header().Set("Link", `<`+u+`>; rel="authorization_endpoint"`)
					}
					http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
					recordRequest(clientIP, r.Method, r.Host, "AUTH_FAIL", "", "", "", "")
					logger.Printf("AUTH_FAIL (no-credentials) %s {req_id=%s action=block}", clientIP, reqID)
					return authOutcome{}, false
				}
			}
		}
	}
	return authOutcome{identity: authenticatedIdentity, groups: authenticatedGroups, source: authenticatedSource, log: authLog}, true
}

// preDispatchBlocked runs the pre-policy content gates (legacy blocklist,
// threat-intel feed, plugin decision, file-extension profile) against an
// already-authenticated request. It returns true if it has written a terminal
// block response (403 / block page) and the caller must return. Behaviour is
// identical to the previously-inlined gates (DEBT-002 extraction; no logic change).
func preDispatchBlocked(w http.ResponseWriter, r *http.Request, clientIP, host, reqID, authenticatedIdentity string, authLog AuthLogFields) bool {
	// Legacy blocklist check (still active alongside policy engine).
	if bl.IsBlocked(host) {
		atomic.AddInt64(&statBlocked, 1)
		http.Error(w, "Forbidden by Culvert", http.StatusForbidden)
		recordRequestAuth(clientIP, r.Method, r.Host, "BLOCKED", "blocklist", "", authenticatedIdentity, authLog)
		logger.Printf("BLOCKED %s -> %q {req_id=%s identity=%s action=block source=blocklist}", clientIP, sanitizeLog(host), reqID, sanitizeLog(authenticatedIdentity))
		return true
	}

	// Threat intelligence feed check — covers both plain HTTP destinations
	// and CONNECT tunnel targets.
	if globalSecScanner.Enabled() {
		// Domain-level check (applies to CONNECT and plain HTTP).
		if result := globalSecScanner.CheckDomain(host); result != nil {
			atomic.AddInt64(&statBlocked, 1)
			recordRequestAuth(clientIP, r.Method, r.Host, "THREAT_BLOCKED", result.Source, result.Reason, authenticatedIdentity, authLog)
			logger.Printf("THREAT_BLOCKED domain %s -> %q (%q)", clientIP, sanitizeLog(host), sanitizeLog(result.Reason))
			serveBlockPage(w, r.Host, "Threat Intelligence", result.Reason)
			return true
		}
		// Full-URL check for non-CONNECT (plain HTTP) requests.
		if r.Method != http.MethodConnect && !isWebSocketUpgrade(r) {
			if result := globalSecScanner.CheckURL(r.URL.String()); result != nil {
				atomic.AddInt64(&statBlocked, 1)
				recordRequestAuth(clientIP, r.Method, r.Host, "THREAT_BLOCKED", result.Source, result.Reason, authenticatedIdentity, authLog)
				logger.Printf("THREAT_BLOCKED url %s -> %q (%q)", clientIP, sanitizeLog(r.Host), sanitizeLog(result.Reason))
				serveBlockPage(w, r.Host, "Threat Intelligence", result.Reason)
				return true
			}
		}
	}

	// Plugin check.
	if pluginDecision(clientIP, r.Method, host) == DecisionBlock {
		atomic.AddInt64(&statBlocked, 1)
		http.Error(w, "Forbidden by plugin", http.StatusForbidden)
		recordRequestAuth(clientIP, r.Method, r.Host, "BLOCKED", "plugin", "", authenticatedIdentity, authLog)
		return true
	}

	// File block profile — check URL path extension for non-tunnel requests.
	// CONNECT tunnels are opaque until SSL inspection; inner requests go through
	// handleRequest again and will be checked at that point.
	if r.Method != http.MethodConnect && !isWebSocketUpgrade(r) {
		if ext := fileBlocker.CheckPath(r.URL.Path); ext != "" {
			atomic.AddInt64(&statFileBlocked, 1)
			atomic.AddInt64(&statBlocked, 1)
			recordRequestAuth(clientIP, r.Method, r.Host, "FILE_BLOCKED", ext, "", authenticatedIdentity, authLog)
			logger.Printf("FILE_BLOCKED %s -> %q%q (ext=%q)", clientIP, sanitizeLog(host), sanitizeLog(r.URL.Path), sanitizeLog(ext))
			serveBlockPage(w, r.Host+r.URL.Path, "File Block", ext)
			return true
		}
	}
	return false
}

// applyPolicyDecision dispatches the matched policy action (drop / block page
// / redirect / allow-with-file-profile) or, on no match, the configured default
// (allow passthrough vs zero-trust deny). It returns true if it wrote a terminal
// response and the caller must return; false means the request proceeds to
// transport dispatch. Behaviour is identical to the previously-inlined switch
// (DEBT-002 extraction; no logic change).
func applyPolicyDecision(w http.ResponseWriter, r *http.Request, clientIP, host, reqID, authenticatedIdentity string, authLog AuthLogFields, match *PolicyMatch) bool { //nolint:gocognit,cyclop,funlen // policy-action dispatch is inherently branchy; isolated and independently testable (DEBT-002)
	if match != nil { //nolint:nestif // policy action dispatch is inherently branchy
		ruleMet.RecordHit(match.Rule.Name)
		// Rename-safe decision attribution: stamp the matched rule's stable ULID
		// onto every request-log entry this dispatch writes (§1 ruleId seam). The
		// carrier is a by-value copy, so this affects only these calls.
		authLog.RuleID = match.Rule.ID
		// Per-rule "log full URL": capture host+path (no query) when the matched
		// rule opts in. For a CONNECT tunnel the inner path is encrypted, so this
		// yields host:port here; the decrypted inner URLs are logged separately in
		// handleTunnelInspect when SSL inspection is on.
		ruleURI := ""
		if match.Rule.LogFullURI {
			ruleURI = policyLogURI(r.Host, r.URL.Path)
		}
		switch match.Action {
		case ActionDrop:
			atomic.AddInt64(&statBlocked, 1)
			recordRequestAuthURI(clientIP, r.Method, r.Host, "POLICY_DROP", match.Rule.Name, string(ActionDrop), authenticatedIdentity, "", ruleURI, authLog)
			logger.Printf("POLICY_DROP rule=%q pri=%s %s -> %q [%s] {req_id=%s identity=%s rule=%s action=drop}", sanitizeLog(match.Rule.Name), strings.ReplaceAll(fmt.Sprintf("%d", match.Rule.Priority), "\n", ""), clientIP, sanitizeLog(host), sanitizeLog(match.MatchedConditions), reqID, sanitizeLog(authenticatedIdentity), sanitizeLog(match.Rule.Name))
			// Silent TCP RST — hijack and close without sending an HTTP response.
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
			}
			return true

		case ActionBlockPage:
			atomic.AddInt64(&statBlocked, 1)
			recordRequestAuthURI(clientIP, r.Method, r.Host, "POLICY_BLOCK", match.Rule.Name, string(ActionBlockPage), authenticatedIdentity, "", ruleURI, authLog)
			logger.Printf("POLICY_BLOCK rule=%q pri=%s %s -> %q [%s] {req_id=%s identity=%s rule=%s action=block}", sanitizeLog(match.Rule.Name), strings.ReplaceAll(fmt.Sprintf("%d", match.Rule.Priority), "\n", ""), clientIP, sanitizeLog(host), sanitizeLog(match.MatchedConditions), reqID, sanitizeLog(authenticatedIdentity), sanitizeLog(match.Rule.Name))
			serveBlockPage(w, r.Host, string(match.Rule.DestCategory), match.Rule.Name)
			return true

		case ActionRedirect:
			atomic.AddInt64(&statBlocked, 1)
			recordRequestAuthURI(clientIP, r.Method, r.Host, "POLICY_REDIRECT", match.Rule.Name, string(ActionRedirect), authenticatedIdentity, "", ruleURI, authLog)
			if !isSafeRedirectURL(match.Rule.RedirectURL) {
				logger.Printf("POLICY_REDIRECT rule=%q: invalid redirect URL %q — blocking", sanitizeLog(match.Rule.Name), sanitizeLog(match.Rule.RedirectURL))
				http.Error(w, "Forbidden", http.StatusForbidden)
				return true
			}
			logger.Printf("POLICY_REDIRECT rule=%q pri=%s %s -> %q => %q [%s] {req_id=%s identity=%s rule=%s action=redirect}", sanitizeLog(match.Rule.Name), strings.ReplaceAll(fmt.Sprintf("%d", match.Rule.Priority), "\n", ""), clientIP, sanitizeLog(host), sanitizeLog(match.Rule.RedirectURL), sanitizeLog(match.MatchedConditions), reqID, sanitizeLog(authenticatedIdentity), sanitizeLog(match.Rule.Name))
			http.Redirect(w, r, match.Rule.RedirectURL, http.StatusFound)
			return true

		case ActionAllow:
			// Per-rule file profile: even when the policy allows the request,
			// the attached file-extension profile can still block specific
			// download types (e.g. "Allow github.com but block Executables").
			// CONNECT tunnels are handled inside handleTunnelInspect where
			// the inner URL is visible; here we only check plain HTTP.
			if r.Method != http.MethodConnect && !isWebSocketUpgrade(r) {
				if match.Rule != nil && match.Rule.FileProfileBlocked(r.URL.Path) {
					atomic.AddInt64(&statFileBlocked, 1)
					atomic.AddInt64(&statBlocked, 1)
					recordRequestAuthURI(clientIP, r.Method, r.Host, "FILE_BLOCKED", string(match.Rule.FileProfile), match.Rule.Name, authenticatedIdentity, "", ruleURI, authLog)
					logger.Printf("FILE_BLOCKED (policy profile) %s -> %q%q (profile=%q rule=%q)", clientIP, sanitizeLog(host), sanitizeLog(r.URL.Path), sanitizeLog(string(match.Rule.FileProfile)), sanitizeLog(match.Rule.Name))
					serveBlockPage(w, r.Host+r.URL.Path, "File Block (Policy)", string(match.Rule.FileProfile))
					return true
				}
			}
			if ruleLogsTraffic(match.Rule) {
				recordRequestAuthURI(clientIP, r.Method, r.Host, "OK", match.Rule.Name, string(ActionAllow), authenticatedIdentity, "", ruleURI, authLog)
			} else {
				// "Log traffic" off: count the request for stats/dashboards but
				// write no feed/history entry (volume control).
				recordStats(clientIP, r.Host, "OK", match.Rule.Name, string(ActionAllow))
			}
			logger.Printf("POLICY_ALLOW rule=%q pri=%s %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}", sanitizeLog(match.Rule.Name), strings.ReplaceAll(fmt.Sprintf("%d", match.Rule.Priority), "\n", ""), clientIP, r.Method, sanitizeLog(r.Host), sanitizeLog(match.MatchedConditions), reqID, sanitizeLog(authenticatedIdentity), sanitizeLog(match.Rule.Name))
			// Fall through to normal handling below.
		}
	} else {
		// No rule matched — apply the configured default action.
		if defaultPolicyAction() == "allow" {
			// Passthrough mode: allow all unmatched traffic (initial setup).
			recordRequestAuth(clientIP, r.Method, r.Host, "OK", "default-allow", "Allow", authenticatedIdentity, authLog)
		} else {
			// Zero Trust: deny by default. Serve the custom HTML block page so
			// end-users see a clear, branded explanation.
			atomic.AddInt64(&statBlocked, 1)
			recordRequestAuth(clientIP, r.Method, r.Host, "POLICY_DEFAULT_DENY", "", "", authenticatedIdentity, authLog)
			logger.Printf("POLICY_DEFAULT_DENY %s %s %q {req_id=%s identity=%s action=deny}", clientIP, r.Method, sanitizeLog(r.Host), reqID, sanitizeLog(authenticatedIdentity))
			serveBlockPage(w, r.Host, "Default Deny", "No matching policy rule")
			return true
		}
	}
	return false
}

// recordRequestTelemetry records per-request observability after dispatch:
// the Prometheus latency histogram and (when enabled) one OTLP span. Pure
// side-effects, no early returns. Extracted from handleRequest (DEBT-002).
func recordRequestTelemetry(r *http.Request, start time.Time, sslAction SSLAction, match *PolicyMatch, host, clientIP string) {
	// Record request latency for Prometheus histogram.
	latencyHist.Observe(time.Since(start).Seconds())

	// OTLP span export: record one span per proxied request for Jaeger/Tempo.
	// Only fires when the OTLP endpoint is configured; the Enabled() check
	// avoids constructing the SpanRecord struct on the common no-OTLP path.
	if globalOTLPTraces.Enabled() {
		traceID, spanID := parseTraceparent(r.Header.Get("Traceparent"))
		sslStr := ""
		if sslAction == SSLInspect {
			sslStr = "inspect"
		} else if r.Method == http.MethodConnect {
			sslStr = "bypass"
		}
		ruleName := ""
		if match != nil && match.Rule != nil {
			ruleName = match.Rule.Name
		}
		globalOTLPTraces.RecordSpan(SpanRecord{
			TraceID:   traceID,
			SpanID:    spanID,
			Name:      "proxy_request",
			Method:    r.Method,
			Host:      host,
			Status:    "OK",
			Rule:      ruleName,
			ClientIP:  clientIP,
			SSLAction: sslStr,
			StartNano: start.UnixNano(),
			EndNano:   time.Now().UnixNano(),
		})
	}
}

// setupRequestTracing ensures the request carries an X-Request-ID (CWE-117
// sanitised) and a W3C traceparent, mirroring the request ID onto the response.
// It returns the request ID. Extracted from handleRequest (DEBT-002).
func setupRequestTracing(w http.ResponseWriter, r *http.Request) string {
	// ── Request tracing: generate X-Request-ID if not present ────────────
	reqID := strings.ReplaceAll(strings.ReplaceAll(r.Header.Get("X-Request-ID"), "\n", ""), "\r", "") // sanitize for CWE-117
	if reqID == "" {
		reqID = generateRequestID()
		r.Header.Set("X-Request-ID", reqID)
	}
	w.Header().Set("X-Request-ID", reqID)

	// ── W3C Trace Context: propagate or generate traceparent ────────────
	if r.Header.Get("Traceparent") == "" {
		r.Header.Set("Traceparent", generateTraceparent())
	}
	return reqID
}

// resolveSSLAction computes the effective SSL action and per-rule TLS-verify
// option for a request, applying the smart-bypass pattern override. Extracted
// from handleRequest (DEBT-002).
func resolveSSLAction(match *PolicyMatch, host, clientIP string) (SSLAction, bool) {
	// Determine SSL action and per-rule TLS options for CONNECT tunnels.
	sslAction := SSLBypass
	tlsSkipVerify := false
	if match != nil {
		if match.SSLAction == SSLInspect {
			sslAction = SSLInspect
		}
		tlsSkipVerify = match.TLSSkipVerify
	}
	// Smart Bypass: explicit bypass-list patterns (glob or regex) always
	// override policy-based SSL inspection, regardless of rule SSLAction.
	if sslAction == SSLInspect && sslBypass.Matches(host) {
		sslAction = SSLBypass
		logger.Printf("SSL_BYPASS_PATTERN %s -> %q", clientIP, sanitizeLog(host))
	}
	// Adaptive decryption exclusion (fail-open self-heal): consult the learned
	// exclusion cache ONLY when the matched rule opts into fail-open, and only
	// within that rule's decryption-profile SCOPE. A fail-close rule never reads
	// the cache; a host learned under one fail-open profile can never bypass a
	// different profile's rule (scoped key), and critical hosts kept on fail-close
	// rules are un-poisonable by construction. Precedence: explicit operator
	// ssl-bypass (above) > learned auto-exclusion (same scope) > policy inspect.
	//
	// FailOpenScope is a no-copy accessor (one RLock + two field reads): the hot
	// path needs only the scope ID + the fail-open bool, so it avoids the profile
	// copyOut that a full resolve pays. A rule with no profile / a fail-close
	// profile returns ok=false and never touches the cache — feature-off stays
	// allocation-free here.
	if sslAction == SSLInspect && match != nil && match.Rule != nil {
		if scopeID, ok := failOpenScopeForRule(match.Rule); ok {
			if reason, hit := autoExclude.Contains(scopeID, host); hit {
				sslAction = SSLBypass
				recordAutoExcludeHit()
				logger.Printf("SSL_AUTOEXCLUDE_BYPASS %s -> %q (scope=%s reason=%s)",
					sanitizeLog(clientIP), sanitizeLog(host), sanitizeLog(scopeID), reason)
			}
		}
	}
	return sslAction, tlsSkipVerify
}

// failOpenScopeForRule resolves the autoexclude fail-open scope for a matched
// rule's decryption profile — ID-first (rename-safe), name fallback for
// un-migrated rules. Returns ok=false for a rule with no profile or a
// fail-close profile (the cache is never touched — feature-off stays
// allocation-free on this per-CONNECT path).
func failOpenScopeForRule(rule *PolicyRule) (scope string, ok bool) {
	if id := rule.DecryptionProfileID; id != "" {
		// ID is authoritative: if it resolves to a profile at all, that
		// profile's fail-open decision is final. Only fall back to the
		// name when the id resolves to NO profile (un-migrated / dangling),
		// mirroring resolveDecryptionProfile — a resolved fail-close profile
		// must NOT be rescued by a stale name pointing at a fail-open one.
		if s, resolved := globalDecryptionProfiles.FailOpenScopeByID(id); resolved {
			return s, s != ""
		}
	}
	if rule.DecryptionProfile != "" {
		return globalDecryptionProfiles.FailOpenScope(rule.DecryptionProfile)
	}
	return "", false
}

// resolveStripALPN and the DecryptionProfile-aware resolve* family live in
// decryptprofile_resolve.go (the "how to decrypt" hot-path resolvers).

// geoTrackSem bounds concurrent destination-country trackers. A tracker can
// block in DNS resolution (resolveHost — memoised per host with a TTL, so
// only cache misses resolve) for the full resolver timeout, and handleRequest
// fires one per proxied request — without a bound, a resolver brownout piles
// up one DNS-blocked goroutine per request with no backpressure, exactly when
// the proxy is already stressed.
var geoTrackSem = make(chan struct{}, 256)

// trackDestinationCountry records the destination country for the live
// dashboard. Runs in its own goroutine (fire-and-forget); extracted from
// handleRequest (DEBT-002). Dashboard stats are best-effort: when the tracker
// pool is saturated the sample is dropped rather than queued.
func trackDestinationCountry(host string) {
	select {
	case geoTrackSem <- struct{}{}:
	default:
		return
	}
	defer func() { <-geoTrackSem }()
	code, name := geo.LookupFull(host)
	if code != "" {
		countryTraffic.Record(code, name)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	reqID := setupRequestTracing(w, r)

	// ── Connection limit per IP ─────────────────────────────────────────
	if !connLimiter.Acquire(clientIP) {
		http.Error(w, "Too Many Connections", http.StatusServiceUnavailable)
		return
	}
	defer connLimiter.Release(clientIP)

	// IP filter check.
	if !ipf.Allowed(clientIP) {
		atomic.AddInt64(&statBlocked, 1)
		http.Error(w, "Forbidden", http.StatusForbidden)
		recordRequest(clientIP, r.Method, r.Host, "IP_BLOCKED", "", "", "", "")
		logger.Printf("IP_BLOCKED %s {req_id=%s action=block}", clientIP, reqID)
		return
	}

	// Rate limit check.
	if !rl.AllowAuto(clientIP) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		recordRequest(clientIP, r.Method, r.Host, "RATE_LIMITED", "", "", "", "")
		logger.Printf("RATE_LIMITED %s {req_id=%s action=block}", clientIP, reqID)
		return
	}

	// ── Adaptive Authentication (Stage-1) ──────────────────────────────────
	// Resolved by resolveRequestAuth (DEBT-002 extraction). It writes any
	// terminal 407/redirect/403 itself; proceed=false means "already handled".
	auth, proceed := resolveRequestAuth(w, r, clientIP, reqID)
	if !proceed {
		return
	}
	authenticatedIdentity := auth.identity
	authenticatedGroups := auth.groups
	authenticatedSource := auth.source
	authLog := auth.log

	// Set internal identity headers — scrubForwardedHeaders removes them
	// before forwarding upstream.
	if authenticatedIdentity != "" {
		r.Header.Set("X-User-Identity", authenticatedIdentity)
	}

	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// ── Host canonicalization gate (RISK-013, fail-closed) ─────────────────
	// A destination that cannot be IDNA-normalized (invalid punycode label)
	// would flow into every downstream matcher (blocklist, threat feed,
	// policy FQDN, category) un-normalized. No legitimate client emits
	// invalid punycode, so reject outright instead of failing open.
	if _, ok := normalizeHostStrict(host); !ok {
		atomic.AddInt64(&statBlocked, 1)
		http.Error(w, "Bad Request: invalid host", http.StatusBadRequest)
		recordRequestAuth(clientIP, r.Method, r.Host, "INVALID_HOST", "idna", "", authenticatedIdentity, authLog)
		logger.Printf("INVALID_HOST %s -> %q {req_id=%s action=block source=idna}", clientIP, sanitizeLog(host), reqID)
		return
	}

	// ── Pre-policy content blocks (blocklist / threat / plugin / file) ──────
	// Extracted to preDispatchBlocked (DEBT-002). Returns true if it already
	// wrote a terminal block response.
	if preDispatchBlocked(w, r, clientIP, host, reqID, authenticatedIdentity, authLog) {
		return
	}

	// ── Policy engine (PBAC) pre-check ───────────────────────────────────────
	// X-User-Identity is the authenticated identity set by the auth layer
	// (OIDC/LDAP); scrubForwardedHeaders already stripped any client-supplied
	// value, so this value is safe to use for policy matching.
	identity := r.Header.Get("X-User-Identity")
	match := policyStore.Evaluate(clientIP, identity, authenticatedSource, host, authenticatedGroups)

	// ── Policy action dispatch ──────────────────────────────────────────────
	// Extracted to applyPolicyDecision (DEBT-002). Returns true if it wrote a
	// terminal drop / block / redirect / deny response.
	if applyPolicyDecision(w, r, clientIP, host, reqID, authenticatedIdentity, authLog, match) {
		return
	}

	// ── Geo-IP tracking (async) ──────────────────────────────────────────────
	// Record destination country for the live dashboard without blocking.
	go trackDestinationCountry(host)

	sslAction, tlsSkipVerify := resolveSSLAction(match, host, clientIP)

	// Identity context forwarded to SSL-inspect (consumed by CDR today;
	// future audit enrichment can read this without re-parsing headers).
	proxyID := ProxyIdentity{
		ClientIP:   clientIP,
		Identity:   authenticatedIdentity,
		AuthSource: authenticatedSource,
		Groups:     authenticatedGroups,
	}

	switch {
	case r.Method == http.MethodConnect:
		handleTunnel(w, r, sslAction, tlsSkipVerify, match, proxyID)
	case isWebSocketUpgrade(r):
		handleWebSocket(w, r, match, proxyID)
	default:
		handleHTTP(w, r)
	}

	recordRequestTelemetry(r, start, sslAction, match, host, clientIP)
}

// sanitizeLog strips newlines, carriage returns, tabs, and all other C0
// control characters (plus DEL) from s to prevent log forging (CWE-117) and
// terminal-escape-sequence injection (CWE-150) via ESC (0x1B) into log
// viewers. Uses strings.ReplaceAll for the common newline/CR/tab cases so
// CodeQL (go/log-injection) recognises the sanitiser; a single final pass
// over remaining control bytes catches the rest with one allocation.
func sanitizeLog(s string) string {
	s = strings.ReplaceAll(s, "\n", "_")
	s = strings.ReplaceAll(s, "\r", "_")
	s = strings.ReplaceAll(s, "\t", "_")
	// Fast path: nothing else to scrub.
	if !containsControl(s) {
		return s
	}
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		// C0 controls (0x00-0x1F) and DEL (0x7F). \n, \r, \t already replaced above.
		if c < 0x20 || c == 0x7F {
			b[i] = '_'
			continue
		}
		b[i] = c
	}
	return string(b)
}

// containsControl reports whether s has any byte < 0x20 or == 0x7F.
func containsControl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7F {
			return true
		}
	}
	return false
}
