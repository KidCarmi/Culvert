package main

// rewrite_identity.go — durable rewrite-rule identity + the v2 management
// surface (2D-C.0C/0D).
//
// IDENTITY MODEL: RewriteRule.StableID (a server-owned UUID) is the durable
// object identity; the legacy integer `id` stays process-local compatibility
// metadata (reassigned on every SetRules — see internal/rewrite). AdminSettings
// is the persistence owner: every save snapshots the rules WITH their stable
// IDs, and the restore path backfills legacy persisted rules exactly once
// (admin_settings.go).
//
// WRITER DOMAIN (§25): adminSettingsMu is the single serialization domain for
// every rewrite writer. Interactive mutations run their read-current + fence +
// target build + durable write + runtime publication inside ONE
// saveAdminSettingsWithOverrides critical section (rewriteMutate). Bulk paths
// (config import, config-version rollback) install their whole target through
// installRewriteRulesDurable — the same domain, durable-or-nothing. The CP→DP
// snapshot apply and the startup/YAML seeds publish via publishRewriteRules
// (domain-held runtime publish, no settings write): the CP / YAML file is the
// source of truth there, mirroring the file-profile follower doctrine.
//
// TRUST SEMANTICS (§22): interactive create IGNORES any client-supplied
// stableId (the server generates identity); modern backups/snapshots preserve
// valid unique stableIds verbatim; legacy inputs without stableIds are
// server-generated during candidate migration; DUPLICATE stableIds reject the
// whole candidate at the validated doors (import / rollback / snapshot) —
// SetRules' defensive dedupe is a last resort for hand-edited files that
// bypassed every door, and it logs via the backfill count rather than
// pretending identity was preserved.

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/KidCarmi/Culvert/internal/rewrite"
)

// publishRewriteRules publishes a whole rule set to the live Rewriter INSIDE
// the settings writer domain, so a bulk publish can never interleave with an
// interactive mutation's read→persist→publish critical section. Returns the
// number of stable IDs backfilled (legacy input). Runtime-only — the caller
// owns persistence semantics (CP snapshot: CP-authoritative, deliberately not
// written to the follower's admin_settings; startup: YAML seed, durable at
// the first ordinary save).
func publishRewriteRules(rules []RewriteRule) int {
	adminSettingsMu.Lock()
	defer adminSettingsMu.Unlock()
	return rewriter.SetRules(rules)
}

// installRewriteRulesDurable installs a whole target rule set durable-or-
// nothing through the AdminSettings owner: persist the target first, publish
// to the Rewriter only after the write landed. Used by config import and
// config-version rollback (authoritative local nodes). Never call while
// holding adminSettingsMu.
func installRewriteRulesDurable(target []RewriteRule) error {
	return saveAdminSettingsWithOverrides(adminSaveOverrides{
		rewriteMutate: func([]RewriteRule) ([]RewriteRule, error) { return target, nil },
	})
}

// validateRewriteStableIDs rejects duplicate non-empty stable identities in a
// candidate rule set (§22): two rules claiming one identity is a corrupted
// candidate — regenerating one of them silently would pretend identity was
// preserved. Missing IDs are fine (legacy candidates — server-generated at
// install).
func validateRewriteStableIDs(rules []RewriteRule) error {
	seen := make(map[string]bool, len(rules))
	for i := range rules {
		id := rules[i].StableID
		if id == "" {
			continue
		}
		if seen[id] {
			return fmt.Errorf("duplicate rewrite rule stableId %q", id)
		}
		seen[id] = true
	}
	return nil
}

// validateIncomingRewriteRule enforces structural sanity on an interactive
// create (§28): a rule must carry at least one header operation — an empty
// rule matches traffic and does nothing, which is always operator error.
// Header/host SEMANTICS are deliberately unchanged (canonicalization happens
// at apply time via http.Header, host matching via Rule.matchesHost).
func validateIncomingRewriteRule(r RewriteRule) error {
	if len(r.ReqSet)+len(r.ReqAdd)+len(r.ReqRemove)+
		len(r.RespSet)+len(r.RespAdd)+len(r.RespRemove) == 0 {
		return fmt.Errorf("rewrite rule must carry at least one header operation")
	}
	return nil
}

// writeRewriteRevisionConflict renders the structured 409 for a stale
// ?ifRevision= assertion, carrying the CURRENT revision so the client
// refreshes instead of blind-retrying.
func writeRewriteRevisionConflict(w http.ResponseWriter, current string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // response write
		"error":    "rewrite rules changed since you loaded them — refresh and retry",
		"conflict": "revision",
		"revision": current,
	})
}

// errRewriteRevisionConflict carries a fence conflict out of a rewriteMutate
// closure so the handler can render the structured 409.
type errRewriteRevisionConflict struct{ current string }

func (e *errRewriteRevisionConflict) Error() string {
	return "rewrite revision conflict"
}

// rewriteFence returns a fence check against the CURRENT committed set for use
// at the top of a rewriteMutate closure; "" asserts nothing (legacy callers).
func rewriteFence(ifRevision string, current []RewriteRule) error {
	if ifRevision == "" {
		return nil
	}
	if cur := rewrite.FingerprintRules(current); cur != ifRevision {
		return &errRewriteRevisionConflict{current: cur}
	}
	return nil
}

// apiRewriteState — GET /api/rewrite/state: the v2 coherent management
// snapshot — ordered rules (evaluation order, §23) + the content-derived
// revision describing exactly them, from one lock hold.
func apiRewriteState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	rules, revision := rewriter.StateSnapshot()
	jsonOK(w, map[string]any{"rules": rules, "revision": revision, "count": len(rules)})
}

// errRewriteRuleNotFound is returned by a rewriteMutate closure whose
// addressed rule no longer exists (already deleted / never existed).
var errRewriteRuleNotFound = fmt.Errorf("rewrite rule not found")
