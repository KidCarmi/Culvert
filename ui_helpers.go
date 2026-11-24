package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// auditEvent records a configuration change to the audit ring buffer.
// It extracts the caller's IP from the HTTP request as the actor identity.
// action follows "resource.verb" e.g. "policy.add", "blocklist.remove".
// Credentials must NEVER appear in object or detail.
func auditEvent(r *http.Request, action, object, detail string) {
	auditEventDiff(r, action, object, detail, nil, nil)
}

// auditActor derives the audit actor from a request: the client IP, enriched
// with the authenticated admin identity from the admin UI session cookie
// (ps_ui_session) — not the proxy-user ps_session, which belongs to a different
// identity and must not attribute admin actions. The IP is always kept for
// accountability; the username adds readability. Callers that drive a backend
// service (which audits via the headless auditAdd) use this to pass the same
// actor string the audit ring would record.
//
// It resolves the SAME identity family as sessionAdmin, in the same precedence
// order (UI session cookie Sub → Email → the HTTP Basic username the auth
// middleware authenticated into context). Keeping the two in step is the point:
// one admin action writes an actor to BOTH the audit ring (here) and the
// config-version store (sessionAdmin), so if only one of them learned the Basic
// fallback the same action would be attributed to two different identities —
// a bare IP in the audit trail next to a username in config history. The Basic
// username is only ever present after cfg.VerifyUIUser succeeded
// (uiAuthMiddleware), so it is authenticated, never request-asserted.
//
// The result is a PRINCIPAL and is deliberately NOT length-bounded. Non-audit
// callers compare it for identity — the MCP publication and approval handlers
// cast it to approval.PrincipalID, so four-eyes (approver == requester) is an
// equality test on it — and persist it in records written before this
// distinction existed. A lossy bound here made two distinct configured admins
// whose names share the bounded prefix and length compare equal, refusing the
// second one's legitimate approval as self-approval (Codex review, PR #1532).
// The CHAOS-63 bound applies to the RENDERED audit entry only, and it is
// applied in exactly one place: addAuditEntry (store.go), behind auditAdd,
// which every AuditEntry producer reaches. Hand auditActor's full value to the
// audit sink; never pre-bound it.
func auditActor(r *http.Request) string {
	// RISK-019: attribute to the real client behind a configured trusted proxy
	// so audit lines don't all name the reverse proxy (falls back to the peer).
	actor := realClientIP(r)
	name := ""
	if sess, err := readUISessionCookie(r); err == nil && sess != nil {
		name = sess.Sub
		if name == "" {
			name = sess.Email
		}
	}
	if name == "" {
		// Basic-auth fallback: programmatic/CLI admin access carries no session
		// cookie, so without this the audit ring records the bare IP for an
		// action whose actor the middleware already authenticated.
		name = uiUser(r)
	}
	if name != "" {
		actor = name + "@" + actor
	}
	return actor
}

// auditEventDiff records an audit event with optional before/after JSON snapshots.
func auditEventDiff(r *http.Request, action, object, detail string, before, after any) {
	auditEventDiffID(r, action, object, "", detail, before, after)
}

// auditEventDiffID is auditEventDiff plus the changed item's stable ULID
// (objectID), recorded in the structured ObjectID field so an object's audit
// trail survives a rename — history is correlatable by ID, not just by the
// mutable display name (§1 identity seam). objectID "" behaves exactly like
// auditEventDiff (the field is omitempty).
func auditEventDiffID(r *http.Request, action, object, objectID, detail string, before, after any) {
	// C2c — observability hook. When the request was wrapped by
	// uiMetadataEnforcement (the admin UI middleware chain), flip the
	// per-request audit-emission flag to true. Plain non-UI callers
	// have no flag in context and this is a no-op. See
	// ui_metadata_enforcement.go for the post-handler check.
	markAuditEmitted(r)

	entry := AuditEntry{
		TS:       time.Now().UnixMilli(),
		Time:     time.Now().Format("2006-01-02 15:04:05"),
		Actor:    auditActor(r), // bounded for rendering inside auditAdd (addAuditEntry)
		Action:   action,
		Object:   object,
		ObjectID: objectID,
		Detail:   detail,
	}
	if before != nil {
		if b, err := json.Marshal(before); err == nil {
			entry.Before = string(b)
		}
	}
	if after != nil {
		if a, err := json.Marshal(after); err == nil {
			entry.After = string(a)
		}
	}
	auditAdd(entry)
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Response headers already sent; can't write an HTTP error at this point.
		logger.Printf("ERROR: jsonOK encode failed: %v", err)
	}
}

// isValidBlocklistWildcard checks that a wildcard blocklist entry uses only the
// allowed *.example.com format. Rejects **.example.com, *.*.example.com,
// *example.com (no dot after star), and any other non-standard wildcard usage.
func isValidBlocklistWildcard(h string) bool {
	// Only a single leading "*." prefix is allowed.
	if !strings.HasPrefix(h, "*.") {
		return false // e.g. *example.com (no dot after star)
	}
	rest := h[2:] // everything after "*."
	if rest == "" {
		return false // "*." alone is not a valid domain
	}
	// No additional wildcards anywhere in the remainder.
	if strings.Contains(rest, "*") {
		return false // e.g. *.*.example.com or **.example.com
	}
	return true
}

// validateStoredPolicyRule is validatePolicyRule for a rule that ALREADY EXISTS
// in a persisted or published rulebase — a config-version snapshot being rolled
// back, or the running rule a draft candidate inherited. It applies every check
// validatePolicyRule does except one: an action this build does not dispatch is
// tolerated (POL-004).
//
// The ingress validator is exact on purpose: there is a caller to tell. Stored
// data has no caller, and refusing it here DROPS the rule — a rollback that
// silently removed a retained unknown-action rule let its traffic fall through
// to a lower Allow or the default, the same fail-open Load and ReplaceAll were
// just fixed for; and a draft commit that refused the inherited rule left the
// administrator unable to commit anything until they deleted the restriction.
//
// Only an UNKNOWN action is tolerated. A known action is validated exactly as
// at ingress, so this is never a way to store a sloppy spelling.
func validateStoredPolicyRule(rule PolicyRule, rules []PolicyRule, selfPriority int) error {
	if _, known := canonicalPolicyAction(rule.Action); known {
		return validatePolicyRule(rule, rules, selfPriority)
	}
	probe := rule
	probe.Action = ActionBlockPage // what a match on it does; lets every other check run
	return validatePolicyRule(probe, rules, selfPriority)
}

// validatePolicyRule checks that a rule has a valid action, a non-empty name,
// a safe redirect URL when required, a parseable timezone, and name uniqueness.
// existingRules is the current rule set; editPriority is the priority of the rule
// being edited (use -1 when adding a new rule) so its own name is not flagged as
// a duplicate.
func validatePolicyRule(rule PolicyRule, existingRules []PolicyRule, editPriority int) error {
	if err := validateRuleUniqueness(rule, existingRules, editPriority); err != nil {
		return err
	}
	return validateRuleShape(rule)
}

// validateRuleUniqueness is the STATE-DEPENDENT half of validatePolicyRule:
// the duplicate-name and duplicate-priority checks against an existing rule
// list. The API handlers run it INSIDE the coordinator fence against the
// authoritative snapshot (2E-C concurrency-status correction) — run outside
// it, a concurrent reorder or create between resolution and validation made
// a request that had merely lost a state race look malformed.
func validateRuleUniqueness(rule PolicyRule, existingRules []PolicyRule, editPriority int) error {
	if rule.Name == "" {
		return fmt.Errorf("name is required")
	}
	// Duplicate name check (Finding 2.2).
	for i := range existingRules {
		if strings.EqualFold(existingRules[i].Name, rule.Name) && existingRules[i].Priority != editPriority {
			return fmt.Errorf("rule name already exists")
		}
	}
	// Duplicate priority check. When rule.Priority > 0, the caller is
	// supplying an explicit slot; reject it if another rule already owns that
	// slot. For update operations editPriority is the current slot (excluded
	// from the check so keeping the same priority is always allowed).
	if rule.Priority > 0 {
		for i := range existingRules {
			if existingRules[i].Priority == rule.Priority && existingRules[i].Priority != editPriority {
				return fmt.Errorf("priority %d is already in use", rule.Priority)
			}
		}
	}
	return nil
}

// validateRuleShape is the STATE-INDEPENDENT half of validatePolicyRule: the
// structural checks a request fails on its own, whatever the rulebase holds.
// The API handlers run it BEFORE the fence (a 400 that no refresh can fix).
//
// It is the STRICT reading of checkRuleShape: a rule this node could not
// verify is refused like an invalid one, with its own typed error
// (errRuleUnverifiable).
func validateRuleShape(rule PolicyRule) error {
	return checkRuleShape(context.Background(), rule).strict()
}

// errRuleUnverifiable marks a finding that says nothing about the RULE: this
// node could not, right now, establish whether the rule is valid. Today that
// is exactly one thing: a Redirect host whose DNS lookup failed or was not
// made in time. Test with errors.Is. A rule that is positively invalid never
// carries it.
//
// THE PRINCIPLE for adding anything to this class: a rule may be installed
// with a warning (which is what a ruleset import does with an unverifiable
// finding) ONLY when enforcement of the unverified part is fail-closed at the
// point of use. A Redirect target is: the serve path re-checks it on every
// match and answers 403 (checkRedirectURL). A schedule timezone is not, so it
// is refused instead (checkScheduleTimezone).
var errRuleUnverifiable = errors.New("could not be verified on this node")

type ruleUnverifiableError struct{ msg string }

func (e *ruleUnverifiableError) Error() string        { return e.msg }
func (e *ruleUnverifiableError) Is(target error) bool { return target == errRuleUnverifiable }

// ruleCheck is the outcome of the state-independent validation of one rule.
// The two halves are kept apart because they are different facts:
//
//   - err: the rule is INVALID — a pure domain invariant, the same on every
//     node. Refused at every operator-facing door.
//   - unverifiable: the rule may be perfectly good, but this node cannot
//     confirm it. What a door does with that is the door's policy, stated once
//     in policy_ruleset_ingress.go.
type ruleCheck struct {
	unverifiable []error // each errors.Is(errRuleUnverifiable)
	err          error
}

// strict is the reading for a door that accepts only what it could verify.
func (c ruleCheck) strict() error {
	if c.err != nil {
		return c.err
	}
	if len(c.unverifiable) > 0 {
		return c.unverifiable[0]
	}
	return nil
}

func (c *ruleCheck) note(unverifiable, invalid error) {
	if c.err == nil {
		c.err = invalid
	}
	if unverifiable != nil {
		c.unverifiable = append(c.unverifiable, unverifiable)
	}
}

// checkRuleShape is the single definition of the state-independent rule
// checks. ctx bounds the one check that waits on the network (a Redirect
// host's DNS lookup).
func checkRuleShape(ctx context.Context, rule PolicyRule) (c ruleCheck) {
	if rule.Name == "" {
		c.err = fmt.Errorf("name is required")
		return c
	}
	if !knownRuleType(rule.RuleType) {
		c.err = fmt.Errorf("ruleType %q is not recognised (use %q or %q)", sanitizeLog(rule.RuleType), ruleTypeAccess, ruleTypeAuth)
		return c
	}
	// Schedule timezone is validated for both rule types.
	if rule.Schedule != nil && rule.Schedule.Timezone != "" {
		if c.err = checkScheduleTimezone(rule.Schedule.Timezone); c.err != nil {
			return c
		}
	}

	// ── Auth (Stage-1) rules validate via validateAuthRule and skip the
	// access-specific action/redirect checks (their decision is auth.outcome, not a
	// PolicyAction). Slice 3: VALID auth rules are accepted and persisted (Load /
	// ReplaceAll keep them; resolveAuthOutcome still returns Default, so they are
	// inert at runtime). Invalid auth rules are rejected here, fail-closed.
	if ruleTypeOf(&rule) == ruleTypeAuth {
		warnings, err := validateAuthRule(rule)
		if err != nil {
			c.err = err
			return c
		}
		for _, w := range warnings {
			logWarnf("Policy: auth rule %q: %s", sanitizeLog(rule.Name), strings.ReplaceAll(w, "\n", " "))
		}
		return c
	}
	c.note(checkAccessRule(ctx, rule))
	return c
}

// plausibleTimezoneName reports whether name could be an IANA zone name at
// all. It only matters on a node with no timezone database (see
// checkScheduleTimezone); a name that fails it is invalid on every node.
func plausibleTimezoneName(name string) bool {
	if len(name) > 64 || strings.HasPrefix(name, "/") || strings.Contains(name, "..") || strings.Contains(name, "//") {
		return false
	}
	const zoneNameChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-+"
	return strings.Trim(name, zoneNameChars) == ""
}

// nodeHasTimezoneDatabase reports whether this node can load IANA zones at
// all, probed once with two zones every database has. A var so tests can
// stand in for an image built without zoneinfo.
var nodeHasTimezoneDatabase = sync.OnceValue(func() bool {
	for _, zone := range []string{"Europe/London", "America/New_York"} {
		if _, err := time.LoadLocation(zone); err == nil {
			return true
		}
	}
	return false
})

// errNoTimezoneDatabase marks the refusal of a schedule timezone on a node
// that has no timezone database at all: the rule may be right, the node
// cannot enforce it. Test with errors.Is; it is still a refusal.
var errNoTimezoneDatabase = errors.New("this node has no timezone database")

type noTimezoneDatabaseError struct{ zone string }

func (e *noTimezoneDatabaseError) Error() string {
	return fmt.Sprintf("schedule timezone %q cannot be enforced here: this node has no timezone database, so the schedule cannot be evaluated as written; install tzdata (or use an image that embeds it) and submit the rule again",
		sanitizeLog(boundedRuleName(e.zone)))
}
func (e *noTimezoneDatabaseError) Is(target error) bool { return target == errNoTimezoneDatabase }

// checkScheduleTimezone refuses a schedule timezone this node cannot load, at
// every operator door and for every rule type. It is never "installed with a
// warning", because nothing downstream is fail-closed about it: an ACCESS
// rule's schedule would be evaluated in UTC (scheduleLocationResolved,
// policy.go: "falling back to UTC"), so an Allow window opens or a Block
// window lapses at the wrong hours; an AUTH rule would stop matching
// (authScheduleParseable, authpolicy.go), which silently removes an
// authentication requirement when the default outcome is Exempt.
//
//   - the node HAS a timezone database: the name is not a known timezone (a
//     typo: "Europe/Pariss", "garbage");
//   - the node has NO database: refused with errNoTimezoneDatabase, which says
//     what to install. The rule may be perfectly good.
func checkScheduleTimezone(name string) error {
	if _, err := time.LoadLocation(name); err == nil {
		return nil
	}
	if nodeHasTimezoneDatabase() || !plausibleTimezoneName(name) {
		return fmt.Errorf("invalid schedule timezone: %s is not a known timezone", sanitizeLog(boundedRuleName(name)))
	}
	return &noTimezoneDatabaseError{zone: name}
}

// checkAccessRule validates the Stage-2 subset of a policy rule (RuleType
// "" or "access" — named "access" rather than "policy" to stay distinct from
// the validatePolicyRule dispatcher above, which covers both Stage-1 and
// Stage-2). SubjectMatch and Auth specs are rejected here: SubjectMatch is
// not yet enforced by Evaluate (so it would fail open on an access rule), and
// an auth spec only belongs on auth rules.
func checkAccessRule(ctx context.Context, rule PolicyRule) (unverifiable, invalid error) {
	if rule.Auth != nil {
		return nil, fmt.Errorf(`auth spec is only valid on ruleType "auth" rules`)
	}
	if rule.SubjectMatch != nil {
		return nil, fmt.Errorf("subjectMatch is not yet enforced on access rules and cannot be set until the access matcher lands")
	}
	// Deliberately EXACT, not canonicalPolicyAction: the ingress validator
	// refuses sloppy input at the door, where there is a caller to tell. The
	// load gate (policyRulePersistable) is the tolerant one, because it decides
	// what to do with data already on disk. See canonicalPolicyAction.
	validActions := map[PolicyAction]bool{
		ActionAllow: true, ActionDrop: true,
		ActionBlockPage: true, ActionRedirect: true,
	}
	if !validActions[rule.Action] {
		return nil, fmt.Errorf("action must be Allow, Drop, Block_Page, or Redirect")
	}
	if rule.Action == ActionRedirect {
		return checkRedirectURL(ctx, rule.RedirectURL)
	}
	return nil, nil
}

// checkRedirectURL applies isSafeRedirectURL's rule to a Redirect target, but
// keeps apart the reasons that function folds into one "false":
//
//   - invalid: empty, not an absolute http/https URL, a host that IS a private
//     or internal address, or a name that RESOLVES to one;
//   - unverifiable: the host is a DNS name and its lookup failed, or was not
//     made within ctx. Nothing was learned about the destination.
//
// Only a DNS name can be unverifiable. Whether an address literal is internal
// is arithmetic, so it is decided first, with no lookup and no context
// (redirectHostLiteral): a cancelled request or a spent time budget can never
// turn `http://169.254.169.254/` into "could not be verified".
//
// Accepting an unverifiable target does not open a redirect to an internal
// address: the serve path re-runs isSafeRedirectURL on every match and answers
// 403 unless the host resolves to a public address at that moment
// (applyPolicyDecision, proxy.go).
func checkRedirectURL(ctx context.Context, raw string) (unverifiable, invalid error) {
	if raw == "" {
		return nil, fmt.Errorf("redirectURL is required when action is Redirect")
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("redirectURL must be an absolute http/https URL")
	}
	host := u.Hostname() // no port, no brackets: "[::1]" and "[::1]:80" are both "::1"
	if literal, internal := redirectHostLiteral(host); literal {
		if internal {
			return nil, fmt.Errorf("redirectURL must be an absolute http/https URL with a public host: %q is a private, internal or non-canonical address", host)
		}
		return nil, nil
	}
	err = isPrivateHostContext(ctx, host)
	switch {
	case err == nil:
		return nil, nil
	case errors.Is(err, errSSRFBlocked):
		return nil, fmt.Errorf("redirectURL must be an absolute http/https URL with a public host: %q resolves to a private or internal address", host)
	case ctx.Err() != nil:
		return &ruleUnverifiableError{fmt.Sprintf(
			"redirectURL host %q was not verified: the time allowed for verification ran out before its DNS lookup was made or answered; a request matching the rule is blocked until the host resolves to a public address",
			host)}, nil
	}
	return &ruleUnverifiableError{fmt.Sprintf(
		"redirectURL host %q could not be verified on this node (DNS lookup failed); a request matching the rule is blocked until the host resolves to a public address",
		host)}, nil
}

// redirectHostLiteral classifies a Redirect host that needs no DNS lookup.
// literal reports that the verdict is final; internal that it is refused.
//
//   - An IP literal (v4, v6, zoned v6): internal when it is private, loopback,
//     link-local, unspecified, a metadata address (the SSRF guard table,
//     isPrivateIP) or carries a zone, which is link-scoped by definition. A
//     public literal is valid.
//   - "localhost" and any name under it, with or without the root dot: always
//     loopback (RFC 6761), whatever the resolver says.
//   - A host that looks numeric but is not a canonical literal ("2130706433",
//     "0x7f.1", "127.1"): refused. Browsers and getaddrinfo read these as
//     IPv4 addresses (WHATWG URL: a host whose last label is a number is an
//     IPv4 address); Go's parser does not, so they would otherwise go to DNS as
//     names. No DNS name ends in a numeric label, so nothing legitimate is lost.
//   - Anything else holding a colon or a bracket is a malformed literal.
//
// The serve path is at least as strict for each: isSafeRedirectURL resolves
// the host, and every one of these either resolves to an internal address or
// does not resolve, which is a 403.
func redirectHostLiteral(host string) (literal, internal bool) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return true, addr.Zone() != "" || addr.IsUnspecified() || isPrivateIP(net.IP(addr.Unmap().WithZone("").AsSlice()))
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	if name == "localhost" || strings.HasSuffix(name, ".localhost") || strings.ContainsAny(name, ":[]%") {
		return true, true
	}
	last := name[strings.LastIndexByte(name, '.')+1:]
	if last == "" || strings.HasPrefix(last, "0x") || strings.Trim(last, "0123456789") == "" {
		return true, true
	}
	return false, false
}

// validateRuleIngress is the per-rule validation of a rule an operator SUBMITS
// through a single-rule door (the policy and auth-policy API handlers,
// policy-learning acceptance). It is the STRICT reading of checkRuleIngress,
// the one per-rule core every operator-facing door shares; see
// policy_ruleset_ingress.go for the doors and what each does with a rule this
// node could not verify.
//
// The STORED and WIRE doors (PolicyStore.Load and ReplaceAll, config-version
// rollback, control-plane snapshot publish and apply, a pending draft on disk)
// deliberately do not run it: they hold data that has no caller, they stay on
// the pure POL-005 gate (policy_ruletype_gate.go, storedRulesetError), and
// Load warns about an inert source literal instead (warnInertSourceIP).
func validateRuleIngress(rule PolicyRule) error {
	return checkRuleIngress(context.Background(), rule).strict()
}

// checkRuleIngress is checkRuleShape plus the source literal check for an
// access rule; an auth rule scopes clients with subjectMatch, which
// validateAuthRule covers.
func checkRuleIngress(ctx context.Context, rule PolicyRule) ruleCheck {
	c := checkRuleShape(ctx, rule)
	if c.err == nil && ruleTypeOf(&rule) != ruleTypeAuth {
		c.err = validateRuleSourceIP(rule.SourceIP)
	}
	return c
}

// validateRuleSourceIP reports whether a SourceIP is one the matcher can ever
// match: empty (any source), a CIDR net.ParseCIDR accepts (the form
// PolicyStore.sortLocked and matchIPOrCIDR parse), or a single address
// netip.ParseAddr accepts (zoned literals included; they keep their exact
// string comparison). Anything else (" 10.0.0.5", "10.0.0.1-10.0.0.9",
// "10.0.0.0/33") was accepted and never matched, which is fail-open for a Drop
// rule under first-match-wins.
func validateRuleSourceIP(sourceIP string) error {
	if sourceIP == "" {
		return nil
	}
	if strings.Contains(sourceIP, "/") {
		if _, _, err := net.ParseCIDR(sourceIP); err != nil {
			return fmt.Errorf("sourceIP %q is not a valid CIDR", sourceIP)
		}
		return nil
	}
	if _, err := netip.ParseAddr(sourceIP); err != nil {
		return fmt.Errorf("sourceIP %q must be a single IP address or a CIDR", sourceIP)
	}
	return nil
}

// decodeJSON decodes the request body into v using strict mode:
// unknown fields are rejected (prevents payload-inflation / field confusion).
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func parseTimestampParam(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	// Try Unix timestamp (integer seconds) first.
	if ts, err := strconv.ParseInt(s, 10, 64); err == nil {
		return ts, nil
	}
	// Try ISO 8601 / RFC 3339.
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t.Unix(), nil
	}
	// Try RFC 3339 without timezone (assume UTC).
	t, err = time.Parse("2006-01-02T15:04:05", s)
	if err == nil {
		return t.UTC().Unix(), nil
	}
	// Try date-only format.
	t, err = time.Parse("2006-01-02", s)
	if err == nil {
		return t.UTC().Unix(), nil
	}
	return 0, fmt.Errorf("unrecognized timestamp format: %s", s)
}
