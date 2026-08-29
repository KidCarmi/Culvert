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
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/KidCarmi/Culvert/internal/fileutil"
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

// validateRewriteStableIDs enforces the StableID format contract at the
// trust doors (config import, config-version rollback, CP snapshot — 2D-C
// final §16): empty = legacy candidate (eligible for controlled one-time
// migration at install); non-empty MUST be a valid UUID (the contract has
// always said "server-owned UUID" — the validator now enforces what the
// prose promises); duplicates and malformed non-empty values reject the
// WHOLE candidate. Two rules claiming one identity, or an identity the
// server could never have minted, is a corrupted candidate — regenerating
// or accepting either silently would pretend identity was preserved.
func validateRewriteStableIDs(rules []RewriteRule) error {
	seen := make(map[string]bool, len(rules))
	for i := range rules {
		id := rules[i].StableID
		if id == "" {
			continue
		}
		if _, err := uuid.Parse(id); err != nil {
			return fmt.Errorf("malformed rewrite rule stableId %q (must be a UUID)", id)
		}
		if seen[id] {
			return fmt.Errorf("duplicate rewrite rule stableId %q", id)
		}
		seen[id] = true
	}
	return nil
}

// ─── Rewrite management-identity durability latch (recovery correction) ────

// rewriteIdentityDegradation records why the v2 rewrite MANAGEMENT identity
// is not trustworthy this boot: a refused settings-owned slice (corrupt
// identity in admin_settings.json) or a failed identity migration/ledger
// write (the generated StableIDs would re-mint on restart). While latched,
// traffic rewrite enforcement and legacy runtime semantics continue
// unchanged, but the v2 management surface fails closed: /api/rewrite/state
// returns the structured 503 (unstable IDs are never presented as durable
// management identities) and StableID-addressed mutations refuse. The latch
// is re-evaluated by every LoadAdminSettings (cleared at entry, set on this
// boot's failures); recovery is fixing the file/volume and restarting — no
// in-process retry loop, and mutations cannot clear it because they are
// refused while it holds.
type rewriteIdentityDegradation struct{ reason string }

var rewriteIdentityDegradedState atomic.Pointer[rewriteIdentityDegradation]

func rewriteIdentityDegraded() *rewriteIdentityDegradation {
	return rewriteIdentityDegradedState.Load()
}

func setRewriteIdentityDegraded(reason string) {
	rewriteIdentityDegradedState.Store(&rewriteIdentityDegradation{reason: reason})
	logger.Printf("WARN Rewrite: management identity DEGRADED — %s. Traffic rewrite enforcement continues; v2 rewrite management (state + StableID mutations) refuses until durable identity is established (fix the settings file/volume and restart).", reason)
}

func clearRewriteIdentityDegraded() { rewriteIdentityDegradedState.Store(nil) }

// writeRewriteIdentityDegraded renders the structured 503 for a management
// call made while rewrite identity is not durable.
func writeRewriteIdentityDegraded(w http.ResponseWriter, d *rewriteIdentityDegradation) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // response write
		"error":    "rewrite management identity is not durable on this node — stable rule identities cannot be trusted until the settings persistence issue is fixed and the node restarts",
		"degraded": "rewrite-identity",
		"reason":   d.reason,
	})
}

// ─── YAML-seed identity durability (2D-C final §7–§9) ──────────────────────

// rewriteRuleContentEqual reports whether two rules carry the same SEMANTIC
// content (host scope + every header operation), ignoring both identity
// fields. Used only for re-attaching persisted identities to YAML-seeded
// rules — never as identity itself (two identical rules stay two objects;
// position disambiguates them here).
func rewriteRuleContentEqual(a, b RewriteRule) bool {
	return a.Host == b.Host &&
		maps.Equal(a.ReqSet, b.ReqSet) &&
		maps.Equal(a.ReqAdd, b.ReqAdd) &&
		slices.Equal(a.ReqRemove, b.ReqRemove) &&
		maps.Equal(a.RespSet, b.RespSet) &&
		maps.Equal(a.RespAdd, b.RespAdd) &&
		slices.Equal(a.RespRemove, b.RespRemove)
}

// finalizeRewriteSeedIdentities is the single boot-time pass (called from
// LoadAdminSettings on BOTH the loaded and the file-absent paths) that makes
// rewrite stable identity durable BEFORE any admin listener exposes
// /api/rewrite/state:
//
//   - settings-OWNED rewrite surface (sentinel or legacy len>0 file): the
//     in-file legacy backfill that SetRules just performed is persisted
//     through the TARGETED writer — only rewrite_rules changes; every
//     unrelated field and ownership sentinel is preserved byte-for-byte
//     semantics (the pre-correction omnibus save stamped them all
//     saved-authoritative).
//   - YAML-seeded surface (settings do not own rewrite): the persisted
//     identity LEDGER is re-attached to the seeded rules per position+content
//     (an unchanged YAML file therefore presents the SAME StableIDs every
//     boot), fresh identities stay minted for changed/new positions, and the
//     updated ledger is persisted — creating a minimal settings file when
//     none exists, claiming ownership of nothing but the ledger itself.
func finalizeRewriteSeedIdentities() {
	owned := rewriteSettingsOwnedAtLoad
	refused := rewriteSettingsSliceRefusedAtLoad
	ledger := rewriteSeedLedgerAtLoad
	backfilled := rewriteIDsBackfilledAtLoad
	rewriteSettingsOwnedAtLoad = false
	rewriteSettingsSliceRefusedAtLoad = nil
	rewriteSeedLedgerAtLoad = nil
	rewriteIDsBackfilledAtLoad = 0

	if owned {
		if refused != nil {
			// The settings-owned slice carried malformed/ambiguous modern
			// identity and was NOT published (recovery correction §2). The
			// management surface must not present the surviving runtime
			// state (the pre-restore seed) as healthy owned identity.
			setRewriteIdentityDegraded(fmt.Sprintf("settings-owned rewrite rules refused: %v", refused))
			return
		}
		if backfilled > 0 {
			migrated := rewriter.List()
			if err := persistRewriteIdentityMutation(func(s *AdminSettings) {
				s.RewriteRules = migrated
			}); err != nil {
				// The backfilled identities exist only in memory — a restart
				// re-mints them, so they must not be presented as durable
				// management identity (recovery correction §4).
				setRewriteIdentityDegraded(fmt.Sprintf("legacy stable-ID backfill (%d rule(s)) could not persist: %v", backfilled, err))
			} else {
				logger.Printf("AdminSettings: migrated %d rewrite rule(s) to durable stable identities", backfilled)
			}
		}
		return
	}

	live := rewriter.List()
	if len(live) == 0 && len(ledger) == 0 {
		return // nothing seeded, nothing recorded — no write on a clean boot
	}

	// Re-attach persisted identities: position + content match. Ledger
	// validity is checked defensively (a hand-edited settings file could
	// carry junk); an unusable ledger is discarded, never trusted.
	if validateRewriteStableIDs(ledger) != nil {
		logger.Printf("AdminSettings: rewrite seed-identity ledger is invalid — re-minting seed identities")
		ledger = nil
	}
	attached := make([]RewriteRule, len(live))
	copy(attached, live)
	for i := range attached {
		if i < len(ledger) && ledger[i].StableID != "" && rewriteRuleContentEqual(attached[i], ledger[i]) {
			attached[i].StableID = ledger[i].StableID
		}
	}
	if !slices.EqualFunc(attached, live, func(a, b RewriteRule) bool { return a.StableID == b.StableID }) {
		publishRewriteRules(attached)
		attached = rewriter.List() // republished truth (legacy ints renumbered)
	}
	if rewriteSeedLedgerEqual(attached, ledger) {
		return // ledger already current — no boot-time write
	}
	if err := persistRewriteIdentityMutation(func(s *AdminSettings) {
		s.RewriteSeedIdentities = attached
	}); err != nil {
		// The seeded identities are ephemeral — a restart re-mints them.
		// KNOWN-non-durable identity must never be presented as normal
		// management identity (recovery correction §4): latch instead of
		// log-and-continue.
		setRewriteIdentityDegraded(fmt.Sprintf("YAML seed identity ledger could not persist: %v", err))
	} else {
		logger.Printf("AdminSettings: recorded %d YAML-seeded rewrite identit%s in the durable ledger", len(attached), pluralYIes(len(attached)))
	}
}

func pluralYIes(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// rewriteSeedLedgerEqual reports whether the persisted ledger already records
// exactly these rules (identity AND content, in order).
func rewriteSeedLedgerEqual(a, b []RewriteRule) bool {
	return slices.EqualFunc(a, b, func(x, y RewriteRule) bool {
		return x.StableID == y.StableID && rewriteRuleContentEqual(x, y)
	})
}

// persistRewriteIdentityMutation is the TARGETED migration writer (2D-C final
// §8): read the settings file as-is (zero value when absent), apply ONLY the
// given mutation, and write it back atomically under adminSettingsMu. Unlike
// the omnibus save it snapshots nothing from the runtime, so every unrelated
// field and ownership sentinel keeps exactly the value the operator's file
// carried — a rewrite-identity migration can never flip another surface to
// saved-authoritative. Never call while holding adminSettingsMu.
func persistRewriteIdentityMutation(mut func(*AdminSettings)) error {
	adminSettingsMu.Lock()
	defer adminSettingsMu.Unlock()
	path := adminSettingsPath
	if path == "" {
		return nil // no persistence configured (tests / ephemeral runs)
	}
	var s AdminSettings
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("existing settings unreadable (refusing to overwrite): %w", err)
		}
	case errors.Is(err, os.ErrNotExist):
		// First write: a minimal file carrying only the mutated fields.
	default:
		return err
	}
	mut(&s)
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return rewriteIdentityAtomicWrite(path, out, 0o600)
}

// rewriteIdentityAtomicWrite is the targeted migration writer's write seam —
// production is fileutil.AtomicWrite; the recovery-correction tests inject a
// hard persistence failure through it for the settings-owned backfill variant
// (the file-absent variant injects via a nonexistent parent directory, no
// seam needed).
var rewriteIdentityAtomicWrite = fileutil.AtomicWrite

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

// writeRewriteRevisionConflict renders the SHARED 2D-B structured revision
// 409 ({error, currentRevision, yourRevision} — one dialect across every
// fenced surface) so the client refreshes instead of blind-retrying.
func writeRewriteRevisionConflict(w http.ResponseWriter, current, asserted string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // response write
		"error":           "rewrite rules changed since you loaded them — refresh and retry",
		"currentRevision": current,
		"yourRevision":    asserted,
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
	// Recovery correction §5: while management identity is not durable, the
	// v2 state surface must not expose the ephemeral StableIDs at all — a
	// structured 503 names the degradation instead.
	if d := rewriteIdentityDegraded(); d != nil {
		writeRewriteIdentityDegraded(w, d)
		return
	}
	rules, revision := rewriter.StateSnapshot()
	jsonOK(w, map[string]any{"rules": rules, "revision": revision, "count": len(rules)})
}

// errRewriteRuleNotFound is returned by a rewriteMutate closure whose
// addressed rule no longer exists (already deleted / never existed).
var errRewriteRuleNotFound = fmt.Errorf("rewrite rule not found")
