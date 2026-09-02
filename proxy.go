package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
	"github.com/KidCarmi/Culvert/internal/decryptobs"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// defaultPolicyActionState controls what happens when no PBAC rule matches a
// request: allow = passthrough mode (initial setup), deny = zero-trust
// (production). Set by setDefaultPolicyAction() during startup based on
// config or rule count. It packs the action value and its change signal into
// ONE atomic word: bit 0 = allow flag, bits 1+ = a set counter. The counter
// exists because the value alone is two-state, so "same value before and
// after" cannot prove it held throughout an interval (ABA); it shares the
// value's word because publishing them as two separate atomics left a window
// where a descheduled setter had published the new VALUE but not the new
// SIGNAL — enforcement could run under the new action while the policy-
// content memo still validated against the old key (Codex round 19). Every
// set strictly increases the word, so a loaded word is simultaneously the
// current action AND a fencing revision that any later set invalidates.
// Process-local change signal only (memo keys), never an identity.
// Zero value = deny, revision 0 (the fail-closed default).
var defaultPolicyActionState atomic.Uint64

func setDefaultPolicyAction(action string) {
	var allow uint64
	if action == "allow" {
		allow = 1
	}
	for {
		old := defaultPolicyActionState.Load()
		next := ((old>>1)+1)<<1 | allow
		if defaultPolicyActionState.CompareAndSwap(old, next) {
			return
		}
	}
}

// defaultPolicyAction returns the current default action string ("allow"/"deny").
func defaultPolicyAction() string {
	if defaultPolicyActionState.Load()&1 == 1 {
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
	// Strip private IPs from X-Forwarded-For. The header slice is read directly
	// (rather than via Get) because a request carrying MORE THAN ONE
	// X-Forwarded-For line must always be rewritten: Get reads only the first
	// line, and the Set below collapses the header to that one value — dropping
	// the trailing lines is part of the scrub, not an accident, so the
	// leave-untouched fast path must not be taken for a multi-line header.
	if vals := r.Header[hdrForwardedFor]; len(vals) > 0 && vals[0] != "" {
		out, changed := sanitizeForwardedFor(vals[0])
		switch {
		case !changed && len(vals) == 1:
			// Every hop is public and already in canonical form: the Set would
			// write back a byte-identical value, so skip it.
		case out == "":
			r.Header.Del(hdrForwardedFor)
		default:
			r.Header.Set(hdrForwardedFor, out)
		}
	}

	// Remove X-Real-IP if it resolves to a private address.
	if xri := r.Header.Get(hdrRealIP); xri != "" {
		if addr, ok := parsePublicAddr(xri); !ok || ssrf.PrivateAddr(addr) {
			r.Header.Del(hdrRealIP)
		}
	}

	// Always remove internal identity header before forwarding.
	r.Header.Del(hdrUserIdentity)

	// Trailer hardening: Go forwards declared request trailers on r.Write, and
	// the scrub above touches r.Header only (noted in the 2026-07-11 security
	// review). The same identity/topology keys must not ride through as
	// trailers either. The early deletion alone is NOT enough (Codex fix):
	// net/http merges the RECEIVED trailer fields back into r.Trailer when the
	// body reaches EOF — after this scrub ran — and both the upstream
	// transport (handleHTTP forwards r itself) and the WebSocket r.Write emit
	// trailers from that same map, so a client could smuggle the scrubbed
	// keys as LATE trailers. The body wrapper re-applies the deletion at EOF:
	// the outbound writer reads the body to EOF and only then writes the
	// trailer section, in the same goroutine, so the re-scrub is ordered
	// after the merge and before the forward.
	if r.Trailer != nil {
		scrubTrailerKeys(r.Trailer)
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = &trailerRescrubBody{body: r.Body, trailer: r.Trailer}
		}
	}
}

// scrubTrailerKeys removes the identity/topology keys the forward-path scrub
// bans from request trailers.
func scrubTrailerKeys(t http.Header) {
	t.Del(hdrForwardedFor)
	t.Del(hdrRealIP)
	t.Del(hdrUserIdentity)
}

// trailerRescrubBody re-applies the trailer scrub when the request body is
// fully read (see scrubForwardedHeaders — the server merges received trailer
// values into r.Trailer at body EOF, which would undo an early-only scrub).
//
// The rescrub runs ONLY from Read, and every outbound path writes the body
// with io.Copy, which prefers src.(io.WriterTo) over Read. Any copy fast path
// the wrapper exposes would therefore drain the body to EOF without this Read
// running once, leaving the merged trailer map — with the client's smuggled
// identity keys — to reach the upstream writer. Embedding io.ReadCloser
// promotes only that interface's own method set (Read, Close), so it would
// not expose one today; the wrapped body is a NAMED FIELD so that this stays
// true structurally rather than by that detail, and so a later switch to a
// concrete embedded body type cannot silently open the bypass. Pinned by
// TestIdentityIngress_TrailerRescrubBodyExposesNoBypassInterface.
type trailerRescrubBody struct {
	body    io.ReadCloser
	trailer http.Header
}

func (b *trailerRescrubBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	if err != nil {
		scrubTrailerKeys(b.trailer)
	}
	return n, err
}

func (b *trailerRescrubBody) Close() error { return b.body.Close() }

// Canonical header names, hoisted so the scrub does not re-derive them per
// request (they are also the exact map keys used for the direct slice read).
const (
	hdrForwardedFor = "X-Forwarded-For"
	hdrRealIP       = "X-Real-IP"
	hdrUserIdentity = "X-User-Identity"
)

// parsePublicAddr parses one X-Forwarded-For / X-Real-IP hop token.
//
// It uses netip.ParseAddr rather than net.ParseIP because the latter
// heap-allocates a 16-byte net.IP for every token of every scrubbed request,
// while netip.Addr is a value. Acceptance is deliberately narrowed back to
// net.ParseIP's: netip.ParseAddr also accepts a scoped address ("fe80::1%eth0"),
// which net.ParseIP rejected, so a zoned token is reported as unparseable here
// and dropped exactly as before. That keeps an attacker-supplied zone string out
// of the header value forwarded upstream.
//
// The returned address is unmapped so that its rendering matches what
// net.IP.String() produced: net.IP.String() prints an IPv4-mapped address in
// dotted-quad form, whereas netip.Addr.String() would print "::ffff:1.2.3.4".
func parsePublicAddr(token string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(token))
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// sanitizeForwardedFor filters an X-Forwarded-For value down to its public hops,
// returning the replacement value and whether it differs from in.
//
// changed=false means the input already IS the sanitized form byte for byte, so
// the caller can leave the header alone — the common load-balancer / proxy-chain
// shape, and the reason the whole scrub is allocation-free on it. An empty
// return with changed=true means every hop was private or unparseable and the
// header must be deleted.
//
// Semantics are those of the previous strings.Split + net.ParseIP + ip.String()
// + strings.Join implementation: hops are comma-separated, surrounding
// whitespace is ignored, any hop that does not parse or that lands in a
// private/internal range is dropped, and survivors are re-emitted in canonical
// form joined by ", ". Only the mechanics changed — no per-hop net.IP, no
// intermediate []string, and no Join.
func sanitizeForwardedFor(in string) (out string, changed bool) {
	// Single pass, rendering into a stack buffer. 256 bytes covers ~21 IPv4 or
	// ~11 IPv6 hops — far past any realistic chain — so the ordinary request
	// never touches the heap; append() grows onto it for a pathological chain.
	// The buffer does not escape: the comparison below reads it in place and the
	// string conversion copies.
	var scratch [256]byte
	buf := scratch[:0]
	for list := in; ; {
		token, rest, more := nextForwardedHop(list)
		if addr, ok := parsePublicAddr(token); ok && !ssrf.PrivateAddr(addr) {
			if len(buf) > 0 {
				buf = append(buf, ',', ' ')
			}
			buf = addr.AppendTo(buf)
		}
		if !more {
			break
		}
		list = rest
	}
	if len(buf) == 0 {
		return "", true // every hop private or unparseable: delete the header
	}
	// Comparing a []byte against a string does not allocate, so recognising the
	// already-sanitized value costs one memcmp and saves BOTH the string build
	// and the header write.
	if string(buf) == in {
		return in, false
	}
	return string(buf), true
}

// nextForwardedHop splits the leading hop off a comma-separated header value.
//
// more reports whether a separator was CONSUMED — not whether the remainder is
// non-empty. The distinction matters: "203.0.113.9," carries a second, empty
// hop, which must be dropped (so that value is NOT already sanitized).
func nextForwardedHop(list string) (token, rest string, more bool) {
	if i := strings.IndexByte(list, ','); i >= 0 {
		return list[:i], list[i+1:], true
	}
	return list, "", false
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
// id is the typed server-resolved identity context (F6): the row carries the
// authenticated identity and auth-source provenance — never a header value.
func recordInspectBlock(id ProxyIdentity, status, ruleMatched, actionTaken, hostOnly, path string, match *PolicyMatch, dec *DecryptionBlock) {
	uri := ""
	auth := AuthLogFields{Dec: dec, AuthSource: id.AuthSource} // ADR-0011: block rows carry the inspected dec block too
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
	recordRequestAuthURI(id.ClientIP, "CONNECT", hostOnly, status, ruleMatched, actionTaken, id.Identity, "inspect", uri, auth)
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
	ssoCapable := idpRegistry.HasEnabledInteractiveProvider() // allocation-free probe, INTERACTIVE types only (ADR-0027) — an enabled LDAP profile must not advertise an SSO flow it can never fulfil
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
				// Try IdP registry providers first (OIDC introspection, LDAP
				// bind). EnabledCredentialProviders excludes browser-only
				// types (SAML) structurally — the credential chain is the
				// capability-explicit accessor, not "everything enabled".
				authed := false
				for _, prov := range idpRegistry.EnabledCredentialProviders() {
					id, resolved := prov.ResolveIdentity(u, p)
					if !resolved || id == nil || strings.TrimSpace(id.Sub) == "" {
						continue
					}
					authenticatedIdentity = id.Sub
					authenticatedGroups = id.Groups
					authenticatedSource = identityAuthSource(id, prov.Name())
					authed = true
					break
				}
				// Fall back to the legacy single provider or local bcrypt. Identity-
				// capable legacy providers must supply the canonical authorization
				// subject; the Basic username is never substituted for them.
				if !authed {
					id, resolved := cfg.resolveAuthIdentity(u, p)
					if !resolved || id == nil || strings.TrimSpace(id.Sub) == "" {
						atomic.AddInt64(&statAuthFail, 1)
						w.Header().Set("Proxy-Authenticate", `Basic realm="Culvert"`)
						http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
						recordRequest(clientIP, r.Method, r.Host, "AUTH_FAIL", "", "", "", "")
						logger.Printf("AUTH_FAIL %s {req_id=%s action=block}", clientIP, reqID)
						return authOutcome{}, false
					}
					authenticatedIdentity = id.Sub
					authenticatedGroups = id.Groups
					authenticatedSource = identityAuthSource(id, "local")
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
					authLog.AuthSource = authenticatedSource // F5: server-side source (still "unauth" pre-credential)
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
					authLog.AuthSource = authenticatedSource // F5: server-side source (still "unauth" pre-credential)
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
					authLog.AuthSource = authenticatedSource // F5: server-side source (still "unauth" pre-credential)
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
// preDispatchBlocked returns the status it recorded ("" when nothing blocked)
// and whether it wrote a terminal block response — the status return is the
// single source of truth for the M3 pre-dispatch learning observation
// (negative/context evidence). Enforcement behavior is unchanged.
func preDispatchBlocked(w http.ResponseWriter, r *http.Request, clientIP, host, reqID, authenticatedIdentity string, authLog AuthLogFields) (string, bool) {
	// Legacy blocklist check (still active alongside policy engine).
	if bl.IsBlocked(host) {
		atomic.AddInt64(&statBlocked, 1)
		http.Error(w, "Forbidden by Culvert", http.StatusForbidden)
		recordRequestAuth(clientIP, r.Method, r.Host, "BLOCKED", "blocklist", "", authenticatedIdentity, authLog)
		logger.Printf("BLOCKED %s -> %q {req_id=%s identity=%s action=block source=blocklist}", clientIP, sanitizeLog(host), reqID, sanitizeLog(authenticatedIdentity))
		return "BLOCKED", true
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
			return "THREAT_BLOCKED", true
		}
		// Full-URL check for non-CONNECT (plain HTTP) requests.
		if r.Method != http.MethodConnect && !isWebSocketUpgrade(r) {
			if result := globalSecScanner.CheckURL(r.URL.String()); result != nil {
				atomic.AddInt64(&statBlocked, 1)
				recordRequestAuth(clientIP, r.Method, r.Host, "THREAT_BLOCKED", result.Source, result.Reason, authenticatedIdentity, authLog)
				logger.Printf("THREAT_BLOCKED url %s -> %q (%q)", clientIP, sanitizeLog(r.Host), sanitizeLog(result.Reason))
				serveBlockPage(w, r.Host, "Threat Intelligence", result.Reason)
				return "THREAT_BLOCKED", true
			}
		}
	}

	// Plugin check.
	if pluginDecision(clientIP, r.Method, host) == DecisionBlock {
		atomic.AddInt64(&statBlocked, 1)
		http.Error(w, "Forbidden by plugin", http.StatusForbidden)
		recordRequestAuth(clientIP, r.Method, r.Host, "BLOCKED", "plugin", "", authenticatedIdentity, authLog)
		return "BLOCKED", true
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
			return "FILE_BLOCKED", true
		}
	}
	return "", false
}

// applyPolicyDecision dispatches the matched policy action (drop / block page
// / redirect / allow-with-file-profile) or, on no match, the configured default
// (allow passthrough vs zero-trust deny). It returns true if it wrote a terminal
// response and the caller must return; false means the request proceeds to
// transport dispatch. Behaviour is identical to the previously-inlined switch
// (DEBT-002 extraction; no logic change).
// applyPolicyDecision returns the status it recorded for this decision (the
// request-log Status taxonomy: OK / POLICY_DROP / POLICY_BLOCK /
// POLICY_REDIRECT / FILE_BLOCKED / POLICY_DEFAULT_DENY) and whether it wrote
// a terminal response. The status return is the single source of truth for
// the M2 learning observation — reconstruction at the call site would
// duplicate this dispatch. The learning decision-identity bracket is captured
// by the CALLER before policy evaluation (learnDecisionKeySnapshot, Codex
// rounds 20/21) — it spans this whole dispatch, so no per-branch capture is
// needed here. Enforcement behavior is unchanged.
func applyPolicyDecision(w http.ResponseWriter, r *http.Request, clientIP, host, reqID, authenticatedIdentity string, authLog AuthLogFields, match *PolicyMatch) (string, bool) { //nolint:gocognit,cyclop,funlen // policy-action dispatch is inherently branchy; isolated and independently testable (DEBT-002)
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
				if conn, _, err := hj.Hijack(); err == nil && conn != nil {
					conn.Close() // intended silent RST
				} else {
					// Hijack unsupported (HTTP/2 CONNECT) / already flushed: use
					// net/http's own intentional silent-abort protocol instead of a
					// nil-deref. proxyCrashGuard re-panics ErrAbortHandler unchanged,
					// so the drop stays covert (no 502, no crash record).
					panic(http.ErrAbortHandler)
				}
			}
			return "POLICY_DROP", true

		case ActionBlockPage:
			atomic.AddInt64(&statBlocked, 1)
			recordRequestAuthURI(clientIP, r.Method, r.Host, "POLICY_BLOCK", match.Rule.Name, string(ActionBlockPage), authenticatedIdentity, "", ruleURI, authLog)
			logger.Printf("POLICY_BLOCK rule=%q pri=%s %s -> %q [%s] {req_id=%s identity=%s rule=%s action=block}", sanitizeLog(match.Rule.Name), strings.ReplaceAll(fmt.Sprintf("%d", match.Rule.Priority), "\n", ""), clientIP, sanitizeLog(host), sanitizeLog(match.MatchedConditions), reqID, sanitizeLog(authenticatedIdentity), sanitizeLog(match.Rule.Name))
			serveBlockPage(w, r.Host, string(match.Rule.DestCategory), match.Rule.Name)
			return "POLICY_BLOCK", true

		case ActionRedirect:
			atomic.AddInt64(&statBlocked, 1)
			recordRequestAuthURI(clientIP, r.Method, r.Host, "POLICY_REDIRECT", match.Rule.Name, string(ActionRedirect), authenticatedIdentity, "", ruleURI, authLog)
			if !isSafeRedirectURL(match.Rule.RedirectURL) {
				logger.Printf("POLICY_REDIRECT rule=%q: invalid redirect URL %q — blocking", sanitizeLog(match.Rule.Name), sanitizeLog(match.Rule.RedirectURL))
				http.Error(w, "Forbidden", http.StatusForbidden)
				return "POLICY_REDIRECT", true
			}
			logger.Printf("POLICY_REDIRECT rule=%q pri=%s %s -> %q => %q [%s] {req_id=%s identity=%s rule=%s action=redirect}", sanitizeLog(match.Rule.Name), strings.ReplaceAll(fmt.Sprintf("%d", match.Rule.Priority), "\n", ""), clientIP, sanitizeLog(host), sanitizeLog(match.Rule.RedirectURL), sanitizeLog(match.MatchedConditions), reqID, sanitizeLog(authenticatedIdentity), sanitizeLog(match.Rule.Name))
			http.Redirect(w, r, match.Rule.RedirectURL, http.StatusFound) // #nosec G710 -- admin-configured rule action target; the isSafeRedirectURL guard above blocks unsafe values
			return "POLICY_REDIRECT", true

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
					return "FILE_BLOCKED", true
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
		// No rule matched — apply the configured default action (one load of
		// the packed state word; the caller's pre-evaluation identity snapshot
		// brackets this read for the learning stamp).
		if defaultPolicyActionState.Load()&1 == 1 {
			// Passthrough mode: allow all unmatched traffic (initial setup).
			recordRequestAuth(clientIP, r.Method, r.Host, "OK", "default-allow", "Allow", authenticatedIdentity, authLog)
			return "OK", false
		}
		// Zero Trust: deny by default. Serve the custom HTML block page so
		// end-users see a clear, branded explanation.
		atomic.AddInt64(&statBlocked, 1)
		recordRequestAuth(clientIP, r.Method, r.Host, "POLICY_DEFAULT_DENY", "", "", authenticatedIdentity, authLog)
		logger.Printf("POLICY_DEFAULT_DENY %s %s %q {req_id=%s identity=%s action=deny}", clientIP, r.Method, sanitizeLog(r.Host), reqID, sanitizeLog(authenticatedIdentity))
		serveBlockPage(w, r.Host, "Default Deny", "No matching policy rule")
		return "POLICY_DEFAULT_DENY", true
	}
	return "OK", false
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
// sslResolution is the full CONNECT decryption decision: the action + per-rule TLS
// options PLUS the ADR-0011 decision source (which arm of the precedence chain chose
// the outcome) and the fail-open scope/reason when a learned exclusion drove a bypass.
// It is assembled from values already computed on the decision path, so the
// observability record it feeds adds no new probe.
type sslResolution struct {
	Action     SSLAction
	SkipVerify bool
	Source     decryptobs.DecisionSource // policy_inspect | manual_ssl_bypass | autoexclude_cache
	ExclReason autoexclude.Reason        // set only when the fail-open cache HIT
	ScopeID    string                    // decryption-profile scope id when a fail-open scope was consulted (hit OR miss)
	// Consulted is true when the fail-open auto-exclusion READ PATH ran (the rule opted
	// into fail-open and Contains was called), regardless of hit/miss. Distinguishes a
	// fail-open cache MISS from a fail-close / no-profile path in the observability
	// record — the two would otherwise both read cache_consulted=false (PR #795 review).
	Consulted bool
}

// resolveSSLAction returns just the SSL action; it is a thin, byte-identical wrapper
// over resolveSSLDecision retained for the autoexclude tests + the alloc benchgate
// (production dispatch uses resolveSSLDecision to also read the decision source). The
// per-rule TLS-skip flag now lives on the sslResolution the dispatcher consumes, so this
// wrapper does not re-return it.
func resolveSSLAction(match *PolicyMatch, host, clientIP string) SSLAction {
	return resolveSSLDecision(match, host, clientIP).Action
}

// resolveSSLDecision is resolveSSLAction plus the ADR-0011 decision source. The action
// logic and its side effects (pattern/autoexclude logging, recordAutoExcludeHit) are
// unchanged; it only additionally classifies WHY. Precedence: explicit operator
// ssl-bypass pattern > learned auto-exclusion (same scope) > policy inspect; a
// non-inspect rule is a policy bypass (classified manual_ssl_bypass).
func resolveSSLDecision(match *PolicyMatch, host, clientIP string) sslResolution {
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
	var exclReason autoexclude.Reason
	var exclScope string
	var consulted bool
	if sslAction == SSLInspect && match != nil && match.Rule != nil {
		if scopeID, gen, ok := failOpenScopeForRule(match.Rule); ok {
			// The fail-open read path runs here — record it (hit OR miss) and carry the
			// scope so a consulted-but-missed session is distinguishable in the record.
			// gen fences the lookup to the profile's CURRENT security posture: an entry
			// learned under a since-edited posture misses and the session re-inspects.
			consulted = true
			exclScope = scopeID
			if reason, hit := autoExclude().Contains(scopeID, gen, host); hit {
				sslAction = SSLBypass
				exclReason = reason
				recordAutoExcludeHit(scopeID)
				logger.Printf("SSL_AUTOEXCLUDE_BYPASS %s -> %q (scope=%s reason=%s)",
					sanitizeLog(clientIP), sanitizeLog(host), sanitizeLog(scopeID), reason)
			}
		}
	}
	source := decryptobs.DecisionManualSSLBypass // any bypass not driven by the cache
	switch {
	case sslAction == SSLInspect:
		source = decryptobs.DecisionPolicyInspect
	case exclReason != "":
		source = decryptobs.DecisionAutoexcludeCache
	}
	return sslResolution{Action: sslAction, SkipVerify: tlsSkipVerify, Source: source, ExclReason: exclReason, ScopeID: exclScope, Consulted: consulted}
}

// failOpenScopeForRule resolves the autoexclude fail-open scope for a matched
// rule's decryption profile — ID-first (rename-safe), name fallback for
// un-migrated rules. Returns ok=false for a rule with no profile or a
// fail-close profile (the cache is never touched — feature-off stays
// allocation-free on this per-CONNECT path).
func failOpenScopeForRule(rule *PolicyRule) (scope, gen string, ok bool) {
	if id := rule.DecryptionProfileID; id != "" {
		// ID is authoritative: if it resolves to a profile at all, that
		// profile's fail-open decision is final. Only fall back to the
		// name when the id resolves to NO profile (un-migrated / dangling),
		// mirroring resolveDecryptionProfile — a resolved fail-close profile
		// must NOT be rescued by a stale name pointing at a fail-open one.
		if s, g, resolved := globalDecryptionProfiles.FailOpenScopeByID(id); resolved {
			return s, g, s != ""
		}
	}
	if rule.DecryptionProfile != "" {
		return globalDecryptionProfiles.FailOpenScope(rule.DecryptionProfile)
	}
	return "", "", false
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

// maybeTrackDestinationCountry spawns the async destination-country tracker
// only when a GeoIP database is loaded, and reports whether it spawned one.
// The tracker's first observable action is a geoip.Enabled() check (inside
// geo.LookupFull), so on a non-GeoIP deployment — the default: no MaxMind DB
// configured, and Enabled() can only flip via an operator config change — the
// pre-gate `go trackDestinationCountry(host)` paid a heap-allocated closure,
// a goroutine spawn/schedule round, and two semaphore channel ops per allowed
// request for a guaranteed no-op. Hoisting the check makes the disabled path
// a single RLock probe with zero allocations (gated by
// TestBenchGate_GeoTrackDispatchDisabledAllocs); an enabled deployment spawns
// exactly as before. A DB swap between the probe and the goroutine's own
// re-check is benign: LookupFull returns "" and nothing is recorded.
func maybeTrackDestinationCountry(host string) bool {
	if !geoTrackEnabledFn() {
		return false
	}
	go trackDestinationCountry(host)
	return true
}

// geoTrackSpawnHook, when non-nil, is invoked on every tracker goroutine as it
// exits (both the recorded and the dropped-when-saturated paths). It exists
// solely so benchmarks can drain the goroutines they spawn; it stays nil in
// production, so the only added cost is one pointer compare on the tracker
// goroutine — the gated per-request path (maybeTrackDestinationCountry) is
// untouched.
var geoTrackSpawnHook func()

// trackDestinationCountry records the destination country for the live
// dashboard. Runs in its own goroutine (fire-and-forget); extracted from
// handleRequest (DEBT-002). Dashboard stats are best-effort: when the tracker
// pool is saturated the sample is dropped rather than queued.
func trackDestinationCountry(host string) {
	if geoTrackSpawnHook != nil {
		defer geoTrackSpawnHook()
	}
	select {
	case geoTrackSem <- struct{}{}:
	default:
		return
	}
	defer func() { <-geoTrackSem }()
	defer recoverGoroutine("geo") // detached goroutine: no request-plane recover reaches here
	code, name := geo.LookupFull(host)
	if code != "" {
		countryTraffic.Record(code, name)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	reqID := setupRequestTracing(w, r)

	// ── Ingress trust boundary (security review 2026-08-13) ─────────────────
	// X-User-Identity is an INTERNAL header: the auth layer below re-stamps it
	// for the plain-HTTP logging consumers (proxy_http.go). A client-supplied
	// value must never survive into authentication, policy evaluation, or log
	// attribution — on the identity-free paths (default-Exempt, scoped exempt,
	// no-backend inert) nothing below overwrites it, so delete it here
	// unconditionally, fail-closed for every downstream branch. The egress
	// scrubForwardedHeaders still strips it before any upstream forward.
	r.Header.Del("X-User-Identity")

	// PROXY-plane panic backstop (record-only; never writes an HTTP status, so a
	// hijacked CONNECT/WS tunnel is never corrupted and the happy path is
	// byte-identical). See crashguard.go.
	defer proxyCrashGuard(reqID)

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
	// F5: stamp the categorical auth source onto every log row this request
	// produces. Server-side resolved state only — never a header value.
	authLog.AuthSource = authenticatedSource

	// F6: identity travels as TYPED server-side values only (ProxyIdentity /
	// authOutcome) — the internal X-User-Identity header transport is removed.
	// The ingress delete above and the egress scrubForwardedHeaders remain as
	// defense-in-depth; nothing internal stamps or reads the header anymore.

	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// ── Host canonicalization gate (RISK-013, fail-closed) ─────────────────
	// A destination that cannot be IDNA-normalized (invalid punycode label)
	// would flow into every downstream matcher (blocklist, threat feed,
	// policy FQDN, category) un-normalized. No legitimate client emits
	// invalid punycode, so reject outright instead of failing open. The
	// canonical form is kept for the learning observations below (Codex fix:
	// spelling aliases like Example.COM / example.com. are ONE destination to
	// policy and category resolution, so they must be ONE evidence key — the
	// raw spelling made aliases consume separate TopHosts budget entries and
	// perturb evidence hashes). Matchers keep receiving the raw host: each
	// normalizes internally, and changing their input is out of scope here.
	normHost, ok := normalizeHostStrict(host)
	if !ok {
		atomic.AddInt64(&statBlocked, 1)
		http.Error(w, "Bad Request: invalid host", http.StatusBadRequest)
		recordRequestAuth(clientIP, r.Method, r.Host, "INVALID_HOST", "idna", "", authenticatedIdentity, authLog)
		logger.Printf("INVALID_HOST %s -> %q {req_id=%s action=block source=idna}", clientIP, sanitizeLog(host), reqID)
		return
	}

	// M2 decision context (Codex rounds 21/24/25): snapshot the FULL policy
	// identity key (rulebase generation, category-group revision, packed
	// default-action word — all monotonic) plus the engine and its
	// acceptance-window generation BEFORE the pre-dispatch gates run, so BOTH
	// learning emissions below — the pre-dispatch negative evidence and the
	// Stage-2 decision — bind to the session that was active when the request
	// was decided, and the identity stamps can prove the config was still
	// current at stamp time (or witness that it was not). Captured only while
	// learning is active (two atomic loads otherwise).
	learnCtx, learnHaveCtx := learnDecisionSnapshot()

	// ── Pre-policy content blocks (blocklist / threat / plugin / file) ──────
	// Extracted to preDispatchBlocked (DEBT-002). blocked=true means it already
	// wrote a terminal block response.
	if preStatus, blocked := preDispatchBlocked(w, r, clientIP, host, reqID, authenticatedIdentity, authLog); blocked {
		// M3: pre-dispatch blocks are context/negative learning evidence
		// (never blocks the request; bound to the captured session window).
		learnObservePreDispatch(auth, normHost, r.Method, preStatus, learnCtx, learnHaveCtx)
		return
	}

	// ── Policy engine (PBAC) pre-check ───────────────────────────────────────
	// The identity comes from the resolved auth context DIRECTLY — never from
	// the X-User-Identity request header. The header was deleted at ingress
	// above and re-stamped only when authentication produced an identity; it is
	// transport for the internal HTTP logging consumers, not an authority
	// boundary (see the note at the stamping site above).
	match := policyStore.Evaluate(clientIP, authenticatedIdentity, authenticatedSource, host, authenticatedGroups)

	// M3 (H2-drop gap closure): the ActionDrop branch's HTTP/2 fallback aborts
	// via panic(http.ErrAbortHandler) BEFORE applyPolicyDecision returns, which
	// would lose the observation. The Drop branch's recorded status is
	// deterministic (always POLICY_DROP), so emit it pre-abort here and skip
	// the duplicate on the normal terminal path below. Enforcement untouched.
	isDrop := match != nil && match.Rule != nil && match.Action == ActionDrop
	if isDrop {
		learnObserveDecision(auth, normHost, r.Method, match, "POLICY_DROP", "", learnCtx, learnHaveCtx)
	}

	// ── Policy action dispatch ──────────────────────────────────────────────
	// Extracted to applyPolicyDecision (DEBT-002). terminal=true means it wrote
	// a terminal drop / block / redirect / deny response.
	decisionStatus, terminal := applyPolicyDecision(w, r, clientIP, host, reqID, authenticatedIdentity, authLog, match)
	if terminal {
		// M2: one learning observation per policy decision (blocked branch;
		// the Drop case was already emitted pre-abort above). Non-blocking,
		// drop-on-full; a nil (disabled) engine costs one atomic load.
		// Learning has zero authority here — see ADR-0025.
		if !isDrop {
			learnObserveDecision(auth, normHost, r.Method, match, decisionStatus, "", learnCtx, learnHaveCtx)
		}
		return
	}

	// ── Geo-IP tracking (async) ──────────────────────────────────────────────
	// Record destination country for the live dashboard without blocking.
	// No-op (no goroutine, no allocation) when no GeoIP DB is loaded.
	maybeTrackDestinationCountry(host)

	sslDec := resolveSSLDecision(match, host, clientIP)
	sslAction := sslDec.Action

	// M2: one learning observation per policy decision (allowed branch, after
	// the SSL decision so the observation carries it). Same non-blocking,
	// advisory-only contract as the blocked branch above.
	learnObserveDecision(auth, normHost, r.Method, match, decisionStatus, string(sslAction), learnCtx, learnHaveCtx)

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
		handleTunnel(w, r, sslDec, match, proxyID)
	case isWebSocketUpgrade(r):
		handleWebSocket(w, r, match, proxyID)
	default:
		handleHTTP(w, r, proxyID)
	}

	recordRequestTelemetry(r, start, sslAction, match, host, clientIP)
}

// sanitizeLog strips newlines, carriage returns, tabs, and all other C0
// control characters (plus DEL) from s to prevent log forging (CWE-117) and
// terminal-escape-sequence injection (CWE-150) via ESC (0x1B) into log
// viewers. Uses strings.ReplaceAll for the newline case so CodeQL
// (go/log-injection) recognises the sanitiser; a single pass over the
// remaining control bytes catches the rest.
//
// ── Why one pass and not four ────────────────────────────────────────────────
//
// This is the most-called sanitiser in the tree (~377 call sites) and it is on
// the REQUEST path: handleRequest emits one POLICY_* line per proxied request
// that passes five values through it (rule name twice, host, matched
// conditions, identity), and the tunnel/relay paths add more. It ran FOUR full
// scans of every string — three strings.ReplaceAll plus a separate
// containsControl — and then, on a hit, a fifth pass to build the result.
//
// The three ReplaceAll scans were redundant with the fourth by construction:
// \n (0x0A), \r (0x0D) and \t (0x09) are all < 0x20, and every branch mapped
// its match to the SAME byte, '_'. So the whole function was only ever
// computing "every byte < 0x20 or == 0x7F becomes '_', length preserved" — a
// single predicate that one pass decides. Keeping the newline ReplaceAll as
// the first statement (and therefore on every return path) preserves the
// CodeQL barrier verbatim while the other two scans and containsControl fold
// into the scan below.
//
// Measured on this machine (Go 1.26, 4-core Xeon @ 2.80GHz, medians of
// n=3x1M, both forms timed in the same run — see the benchmarks):
//
//	shape                     before      after      delta
//	rule name   (15 B)        56.8 ns     28.0 ns    -51%
//	hostname    (15 B)        59.1 ns     28.5 ns    -52%
//	identity    (17 B)        60.6 ns     28.3 ns    -53%
//	conditions  (57 B)         103 ns     55.0 ns    -47%
//	long URL   (270 B)         267 ns      202 ns    -24%
//	empty                     39.7 ns     15.7 ns    -60%
//	with controls (28 B)       340 ns      147 ns    -57%  (4 -> 2 allocs)
//
// In situ, the five calls behind one POLICY_ALLOW line go 463 -> 284 ns, i.e.
// this takes ~180 ns of CPU off every allowed request, before counting the
// tunnel, block and audit paths.
//
// The clean path stays allocation-free, exactly as before; the control-byte
// path halves its allocations because it no longer builds an intermediate
// string per replaced class.
//
// A SWAR (8-bytes-per-word) scan was built and measured — it wins a further
// ~60 ns on 270-byte inputs and nothing on the short strings that dominate
// this call site — and was deliberately thrown away rather than carried: a
// word-at-a-time bit trick is the wrong kind of clever for the function whose
// bug class is log injection.
//
// Equivalence with the four-scan form is exact, not approximate, and is pinned
// by a differential test against a verbatim copy of the old implementation
// plus a fuzz target (proxy_sanitizelog_test.go).
func sanitizeLog(s string) string {
	// CWE-117 barrier CodeQL recognises. Also the only class common enough to
	// be worth a dedicated SIMD scan (strings.Count uses IndexByte); on a
	// string with no newline it returns s without allocating.
	s = strings.ReplaceAll(s, "\n", "_")
	// Find the first byte still needing a scrub. Nothing before i is a control
	// byte, so the prefix is already correct and needs no rewrite.
	i := 0
	for ; i < len(s); i++ {
		// C0 controls (0x00-0x1F) and DEL (0x7F).
		if c := s[i]; c < 0x20 || c == 0x7F {
			break
		}
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if c := b[i]; c < 0x20 || c == 0x7F {
			b[i] = '_'
		}
	}
	return string(b)
}
