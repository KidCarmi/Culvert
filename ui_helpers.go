package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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
func auditActor(r *http.Request) string {
	// RISK-019: attribute to the real client behind a configured trusted proxy
	// so audit lines don't all name the reverse proxy (falls back to the peer).
	actor := realClientIP(r)
	if sess, err := readUISessionCookie(r); err == nil && sess != nil {
		name := sess.Sub
		if name == "" {
			name = sess.Email
		}
		if name != "" {
			actor = name + "@" + actor
		}
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
		Actor:    auditActor(r),
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
func validateRuleShape(rule PolicyRule) error {
	if rule.Name == "" {
		return fmt.Errorf("name is required")
	}
	// Schedule timezone is validated for both rule types.
	if rule.Schedule != nil && rule.Schedule.Timezone != "" {
		if _, err := time.LoadLocation(rule.Schedule.Timezone); err != nil {
			return fmt.Errorf("invalid schedule timezone: %s", strings.ReplaceAll(rule.Schedule.Timezone, "\n", ""))
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
			return err
		}
		for _, w := range warnings {
			logWarnf("Policy: auth rule %q: %s", sanitizeLog(rule.Name), strings.ReplaceAll(w, "\n", " "))
		}
		return nil
	}
	return validateAccessRule(rule)
}

// validateAccessRule validates the Stage-2 subset of a policy rule (RuleType
// "" or "access" — named "access" rather than "policy" to stay distinct from
// the validatePolicyRule dispatcher above, which covers both Stage-1 and
// Stage-2). SubjectMatch and Auth specs are rejected here: SubjectMatch is
// not yet enforced by Evaluate (so it would fail open on an access rule), and
// an auth spec only belongs on auth rules.
func validateAccessRule(rule PolicyRule) error {
	if rule.Auth != nil {
		return fmt.Errorf(`auth spec is only valid on ruleType "auth" rules`)
	}
	if rule.SubjectMatch != nil {
		return fmt.Errorf("subjectMatch is not yet enforced on access rules and cannot be set until the access matcher lands")
	}
	validActions := map[PolicyAction]bool{
		ActionAllow: true, ActionDrop: true,
		ActionBlockPage: true, ActionRedirect: true,
	}
	if !validActions[rule.Action] {
		return fmt.Errorf("action must be Allow, Drop, Block_Page, or Redirect")
	}
	if rule.Action == ActionRedirect {
		if rule.RedirectURL == "" {
			return fmt.Errorf("redirectURL is required when action is Redirect")
		}
		if !isSafeRedirectURL(rule.RedirectURL) {
			return fmt.Errorf("redirectURL must be an absolute http/https URL")
		}
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
