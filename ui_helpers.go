package main

import (
	"encoding/json"
	"fmt"
	"net"
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

// auditEventDiff records an audit event with optional before/after JSON snapshots.
func auditEventDiff(r *http.Request, action, object, detail string, before, after any) {
	// C2c — observability hook. When the request was wrapped by
	// uiMetadataEnforcement (the admin UI middleware chain), flip the
	// per-request audit-emission flag to true. Plain non-UI callers
	// have no flag in context and this is a no-op. See
	// ui_metadata_enforcement.go for the post-handler check.
	markAuditEmitted(r)

	actor, _, _ := net.SplitHostPort(r.RemoteAddr)
	if actor == "" {
		actor = r.RemoteAddr
	}
	// Enrich actor with authenticated admin identity from session cookie.
	// The IP is always kept for accountability; the username adds readability.
	if sess, err := readSessionCookie(r); err == nil && sess != nil {
		name := sess.Sub
		if name == "" {
			name = sess.Email
		}
		if name != "" {
			actor = name + "@" + actor
		}
	}
	entry := AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Actor:  actor,
		Action: action,
		Object: object,
		Detail: detail,
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
	if rule.Name == "" {
		return fmt.Errorf("name is required")
	}
	// Duplicate name check (Finding 2.2).
	for i := range existingRules {
		if strings.EqualFold(existingRules[i].Name, rule.Name) && existingRules[i].Priority != editPriority {
			return fmt.Errorf("rule name already exists")
		}
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
	if rule.Schedule != nil && rule.Schedule.Timezone != "" {
		if _, err := time.LoadLocation(rule.Schedule.Timezone); err != nil {
			return fmt.Errorf("invalid schedule timezone: %s", strings.ReplaceAll(rule.Schedule.Timezone, "\n", ""))
		}
	}
	// SubjectMatch (§1.6) is a reserved schema seam in Phase 0: Stage-2
	// evaluation (matchSource) does NOT yet consult it. Accepting a non-nil
	// selector here would fail OPEN — a rule meant to be scoped to a CIDR
	// would match every client because the source predicate is silently
	// ignored, and there is no action-agnostic "inert" state (skipping the
	// rule under-denies a Drop/Block rule, which is also fail-open). So reject
	// any rule that SETS it until the matcher is wired (a later phase). Every
	// persistence path — admin POST/PUT (ui_policy.go), config import
	// (ui_config.go), and config-version restore (configversion.go) — funnels
	// through this function, so this single gate closes them all.
	if rule.SubjectMatch != nil {
		return fmt.Errorf("subjectMatch is reserved and not yet enforced; it cannot be set until the matcher lands in a later phase")
	}
	// Shape validator retained for the phase that wires the matcher (only a
	// nil selector reaches it today).
	if err := validateSubjectMatch(rule.SubjectMatch); err != nil {
		return err
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
