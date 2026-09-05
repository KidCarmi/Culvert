package main

// ─── Config Versioning & Rollback ──────────────────────────────────────────
//
// Automatic snapshots of all non-secret configuration on every mutation.
// Stored as numbered JSON files in /data/config_versions/.
// Admin can list versions, view diffs, and one-click rollback.
//
// The numbered-file STORE (sequence counter, envelope write, prune,
// list/load) lives in internal/configver (ADR-0002); it crosses the boundary
// via json.RawMessage so the package never sees configBackup. This file
// keeps everything typed: capture/apply/validate, the diff engine, and the
// API handlers.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/configver"
	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// ConfigVersion is metadata for a stored config snapshot.
type ConfigVersion = configver.Meta

// configVersions is the process-wide snapshot store. Tests redirect it via
// SetDirForTest/SetSeqForTest (production code never does).
var configVersions = configver.New("/data/config_versions", 0)

func initConfigVersioning() {
	configVersions.Init()
}

// saveConfigVersion captures the current configuration state.
// Called after any mutating config operation.
// captureConfigBackup takes a point-in-time snapshot of all config stores.
func captureConfigBackup() *configBackup {
	pc := pacStore.Get()
	profCfg := pacProfiles.Get() // single Get: a torn two-call capture could carry dangling pool refs
	return &configBackup{
		Version:             configBackupVersion,
		ExportedAt:          time.Now().UTC().Format(time.RFC3339),
		BlocklistMode:       bl.Mode(),
		Blocklist:           bl.List(),
		PolicyRules:         policyStore.List(),
		DefaultAction:       defaultPolicyAction(),
		RewriteRules:        rewriter.List(),
		SSLBypass:           sslBypass.List(),
		ContentScanPatterns: dpiScanner.List(),
		FileBlockExtensions: fileBlocker.List(),
		IPFilterMode:        ipf.Mode(),
		IPList:              ipf.List(),
		RateLimitRPM:        rl.Limit(),
		PACProxyHost:        pc.ProxyHost,
		PACProxyPort:        pc.ProxyPort,
		PACExclusions:       pc.Exclusions,
		// CategoryGroups: rollback-surface extension per
		// roadmap/CATEGORYGROUPS-ROLLBACK-EXTENSION-SPEC.md. List()
		// returns a non-nil empty slice for an empty store
		// (categorygroup.go:144-158), so a zero-group state
		// serializes as "categoryGroups": [] and round-trips through
		// apply as a wipe — see spec §6.4.
		CategoryGroups: globalCategoryGroups.List(),
		// DecryptionProfiles: rollback-surface extension. List() returns a
		// non-nil empty slice for an empty store, so a zero-profile state
		// serializes as "decryptionProfiles": [] and round-trips as a wipe.
		DecryptionProfiles: globalDecryptionProfiles.List(),
		// URLCategories: rollback-surface extension per
		// roadmap/URL-CATEGORIES-ROLLBACK-EXTENSION-SPEC.md. catStore.All()
		// returns a non-nil empty slice for an empty store
		// (policy.go:174-184), so a zero-category state serializes as
		// "urlCategories": [] and round-trips through apply as a wipe.
		URLCategories: catStore.All(),
		// ContentScanBypassHosts: rollback-surface extension per
		// roadmap/SCANNER-ROLLBACK-EXTENSION-SPEC.md. BypassHosts()
		// returns a non-nil empty slice for an empty store
		// (scanner.go), so a zero-bypass state serializes as
		// "contentScanBypassHosts": [] and round-trips as a wipe.
		ContentScanBypassHosts: dpiScanner.BypassHosts(),
		// RateLimitExempt: rollback-surface extension (Finding 10.3 PR-2).
		// rl.ListExemptions() returns a non-nil empty slice (security.go:336),
		// so a zero-exemption state serializes as "rateLimitExempt": [] and
		// round-trips through apply as a wipe. Sibling RateLimitRPM is already
		// captured above (rl.Limit()).
		RateLimitExempt: rl.ListExemptions(),
		// PACProfiles/PACPools: rollback-surface extension (PAC initiative
		// PR 2). Captured non-nil so a zero-object state serializes as []
		// and round-trips through apply as a wipe (nil = pre-extension
		// snapshot, apply skips).
		PACProfiles: nonNilProfiles(profCfg.Profiles),
		PACPools:    nonNilPools(profCfg.Pools),
		// SaaS feed config (F3a-2). Captured RESOLVED so protocol/url are always
		// non-empty and a same-version rollback round-trips deterministically;
		// managed/enabled/refresh are captured RAW from the durable holder. A
		// pre-F3a-2 snapshot lacks the fields (protocol → "") so applyConfigBackup
		// skips the block (keeps current). No downloader is touched.
		SaaSFeedManaged:        captureSaaSFeedManaged(),
		SaaSFeedEnabled:        captureSaaSFeedEnabled(),
		SaaSFeedURL:            captureSaaSFeedURL(),
		SaaSFeedProtocol:       captureSaaSFeedProtocol(),
		SaaSFeedRefreshSeconds: getSaaSFeedDurable().RefreshSeconds,
		// CategoryOverrides: captured non-nil (pointer) so a zero-override state
		// round-trips as `{}` (a wipe on apply); nil = pre-extension snapshot, apply
		// skips.
		CategoryOverrides: captureCategoryOverrides(),
	}
}

// captureSaaSFeed* read the resolved/raw durable feed config for a config-version
// snapshot. Split into helpers so the CurrentConfigSnapshot capture-owner AST scan
// is unaffected and the resolution failure path is handled once.
func captureSaaSFeedManaged() bool { return getSaaSFeedDurable().Managed }
func captureSaaSFeedEnabled() bool { return getSaaSFeedDurable().Enabled }

func captureSaaSFeedURL() string {
	if resolved, err := resolvedSaaSFeedConfig(); err == nil {
		return resolved.URL
	}
	return getSaaSFeedDurable().URL
}

func captureSaaSFeedProtocol() string {
	if resolved, err := resolvedSaaSFeedConfig(); err == nil {
		return resolved.Protocol
	}
	return saasFeedProtocolV1
}

// captureCategoryOverrides returns a pointer to the current override set (always
// non-nil), so an empty set serializes as an explicit `{}` clear.
func captureCategoryOverrides() *CategoryOverrides {
	ov := globalCategoryOverrides.Get()
	return &ov
}

func nonNilProfiles(p []pac.Profile) []pac.Profile {
	if p == nil {
		return []pac.Profile{}
	}
	return p
}

func nonNilPools(p []pac.Pool) []pac.Pool {
	if p == nil {
		return []pac.Pool{}
	}
	return p
}

// saveConfigVersionMu serializes capture→Save so version numbers are
// assigned in capture order (PR #560 Codex review). Without it, two
// overlapping admin mutations could interleave: a slow request captures
// state A, a later request captures and saves A+B, then the first request
// persists its STALE snapshot under the HIGHER version number — making the
// UI's "latest" version silently omit the newer change. This restores the
// pre-extraction boundary (the old configVersionMu covered capture through
// write); the store's own mutex still guards its internals independently.
var saveConfigVersionMu sync.Mutex

func saveConfigVersion(actor, action string) {
	saveConfigVersionNote(actor, action, "")
}

// saveConfigVersionNote is saveConfigVersion with an optional free-text note
// recorded in the version metadata — used by the policy-draft commit path to
// persist the commit comment into the config-version timeline ("why this
// change"), so it survives alongside the rollback snapshot.
func saveConfigVersionNote(actor, action, note string) {
	_ = saveConfigVersionNoteResult(actor, action, note)
}

// errConfigVersionRefused marks a capture refused by a documented gate (the
// rewrite management-identity degradation), as opposed to a failed write.
var errConfigVersionRefused = errors.New("config version capture refused")

// saveConfigVersionNoteResult is the error-returning core of
// saveConfigVersionNote (2F-B correction round 2): callers that track the
// capture as a REQUIRED effect (the PAC lifecycle's post-commit progress)
// learn whether a version was actually written, instead of assuming it. The
// logging and every gate are unchanged; the compatibility wrapper above keeps
// every best-effort caller as it was.
func saveConfigVersionNoteResult(actor, action, note string) error {
	saveConfigVersionMu.Lock()
	defer saveConfigVersionMu.Unlock()

	// While the rewrite management-identity degradation is latched,
	// captureConfigBackup would record the KNOWN-ephemeral StableIDs into a
	// durable artifact a later rollback treats as authoritative (valid UUIDs
	// pass the rollback identity gate and install through
	// installRewriteRulesDurable). The triggering mutation itself has already
	// completed and stays best-effort-complete; only the version capture is
	// refused, with named operator evidence.
	if d := rewriteIdentityDegraded(); d != nil {
		logger.Printf("ConfigVersion: capture refused — rewrite identity non-durable (%s); actor=%q action=%q",
			d.reason, sanitizeLog(actor), sanitizeLog(action))
		return fmt.Errorf("%w: rewrite identity non-durable (%s)", errConfigVersionRefused, d.reason)
	}

	snap := captureConfigBackup()
	raw, err := json.Marshal(snap)
	if err != nil {
		logger.Printf("ConfigVersion: marshal error: %v", err)
		return fmt.Errorf("config version marshal: %w", err)
	}
	if _, err := configVersions.SaveWithNote(actor, action, snap.ExportedAt, note, raw); err != nil {
		logger.Printf("ConfigVersion: write error: %v", err)
		return fmt.Errorf("config version write: %w", err)
	}
	return nil
}

// ── API Handlers ───────────────────────────────────────────────────────────

// apiConfigVersions lists available config versions or rolls back to one.
// GET /api/config/versions — list versions (viewer)
// POST /api/config/versions — rollback to a version (admin)
func apiConfigVersions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		listConfigVersions(w)

	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		rollbackConfigVersion(w, r)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func listConfigVersions(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(configVersions.List()) //nolint:errcheck // best-effort HTTP response write; client disconnects are not actionable
}

func rollbackConfigVersion(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Version int  `json:"version"`
		DryRun  bool `json:"dry_run"` // F7: pre-flight validation only
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Version <= 0 {
		http.Error(w, "invalid version number", http.StatusBadRequest)
		return
	}

	meta, raw, err := configVersions.Load(req.Version)
	if err != nil {
		if errors.Is(err, configver.ErrCorrupt) {
			http.Error(w, "corrupt version file", http.StatusInternalServerError)
			return
		}
		http.Error(w, "version not found", http.StatusNotFound)
		return
	}
	var target configBackup
	if err := json.Unmarshal(raw, &target); err != nil {
		http.Error(w, "corrupt version file", http.StatusInternalServerError)
		return
	}

	// F7: Pre-flight validation — check snapshot before applying.
	warnings := validateConfigBackup(&target)

	if req.DryRun {
		// While the rewrite management-identity degradation is latched, the
		// preview would diff the target against captureConfigBackup()'s live
		// rewriter.List() — and diffRewriteRules is identity-aware, so the
		// KNOWN-ephemeral StableIDs would ride out in its added/removed/
		// changed arrays through a healthy 200. Answer the ONE structured
		// rewrite-identity 503 instead (authorization already happened in
		// apiConfigVersions); never blank IDs, substitute process-local
		// values, or emit a misleading partial diff. The REAL rollback below
		// stays available: it applies a durable historical artifact (a
		// legitimate recovery door) and its response carries no live-identity
		// diff.
		if d := rewriteIdentityDegraded(); d != nil {
			writeRewriteIdentityDegraded(w, d)
			return
		}
		// Compare against current config for a preview diff.
		current := captureConfigBackup()
		changes := diffConfigs(current, &target)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // best-effort HTTP response write; client disconnects are not actionable
			"status":   "dry_run",
			"version":  req.Version,
			"warnings": warnings,
			"changes":  changes,
			"valid":    len(warnings) == 0,
		})
		return
	}

	// URL-category hard gate (Blocker C): the stored version's taxonomy must
	// satisfy the canonical per-category host cap BEFORE anything applies —
	// the WHOLE rollback is refused (400, nothing mutated), never truncated
	// and never a partial taxonomy. A stored version can only carry an
	// over-cap category if it predates the cap (or was created through a
	// pre-correction bulk path); restoring it would have a runtime mutation
	// re-create what startup Load merely grandfathers. Remedy: split the
	// category, then re-capture.
	if err := urlcat.ValidateEntries(target.URLCategories); err != nil {
		http.Error(w, "rollback refused: "+sanitizeLog(err.Error()), http.StatusBadRequest)
		return
	}

	// Bulk candidate reference integrity (§17): construct the candidate this
	// rollback would restore — per-field nil-skip semantics, a nil section
	// keeps the live objects — and validate its whole object graph BEFORE any
	// apply. A dangling reference refuses the ENTIRE rollback (truthful 400,
	// nothing applied): a historical snapshot capturing rules whose referenced
	// group/profile/category section is absent from that version would
	// otherwise restore DENY/DROP rules that silently stop matching.
	if err := validateRestoredCandidateRefs(&target); err != nil {
		http.Error(w, "rollback refused, dangling object reference: "+sanitizeLog(err.Error()), http.StatusBadRequest)
		return
	}

	// Rewrite identity uniqueness (2D-C §22/§36): a historical candidate
	// carrying duplicate stable rewrite identities is corrupt — refuse the
	// WHOLE rollback before any slice applies rather than silently
	// re-identifying one of the claimants.
	if err := validateRewriteStableIDs(target.RewriteRules); err != nil {
		http.Error(w, "rollback refused: "+sanitizeLog(err.Error()), http.StatusBadRequest)
		return
	}

	// CHAOS-27 / F-12: the apply is unconditional, but a persistence failure
	// during it is no longer swallowed. The running config IS rolled back
	// either way; what changes is that the operator is told when the result
	// did not reach disk instead of receiving a 200 over a partial-durability
	// apply that silently reverts on the next restart.
	persistErr := applyConfigBackup(&target)

	// Feed scalars persist ONLY via admin_settings.json — and since the
	// Blocker E writer-domain correction the feed slice of applyConfigBackup
	// installs through installSaaSFeedDurable, which persists the target
	// INSIDE the same adminSettingsMu transaction that publishes it to the
	// holder (rollback runs on an authoritative CP/standalone node, so
	// admin_settings.json IS the source of truth here — unlike a follower
	// DP). The old post-apply SaveAdminSettings call here was the unlocked
	// second half of that write and is gone: a persist failure now means the
	// feed target was never applied at all, keeping runtime and disk in
	// agreement (the original Codex P2 durability concern stays closed).

	actor := sessionAdmin(r)
	auditDetail := fmt.Sprintf("rolled back to version %d (from %s by %s)",
		req.Version, meta.CreatedAt, sanitizeLog(meta.Actor))
	if persistErr != nil {
		// The partial-durability fact belongs in the audit trail: "who rolled
		// back to what" is incomplete without "and it did not persist".
		auditDetail += " — NOT DURABLE: " + sanitizeLog(persistErr.Error())
	}
	auditEvent(r, "config.rollback", "system", auditDetail)

	saveConfigVersion(actor, fmt.Sprintf("config.rollback v%d", req.Version))

	if globalConfigStore != nil {
		// A rolled-back config was valid when saved; if a cap was lowered since,
		// the commit-time rejection is logged + alerted + surfaced via
		// LastPublishError (the local rollback still applied).
		//
		// Still published on a persistence failure: the DP fleet must converge
		// on the config this node is actually ENFORCING, and the DP snapshot is
		// a separate durability path from the local store files.
		_ = globalConfigStore.Update(CurrentConfigSnapshot())
	}

	w.Header().Set("Content-Type", "application/json")
	if persistErr != nil {
		// CWE-117: nothing request-derived reaches this sink. The only
		// interpolated value is a count computed from the persistence failures
		// themselves (store paths, not request data).
		//
		// The version number is deliberately NOT logged here. CodeQL's
		// log-injection query flags any value that flows from the decoded
		// request body — it kept flagging this line through an inline
		// strings.ReplaceAll, through sanitizeLog, and finally through a plain
		// `%d` on the `int` version field, which cannot carry a control
		// character at all. Rather than carry a permanently-open security alert
		// for a value that provably cannot inject, the version is dropped from
		// this line: it is already recorded, for the same incident, in the
		// audit entry above ("rolled back to version N … NOT DURABLE") and in
		// the API response below. The file names likewise reach the operator
		// via the audit entry, the response, and the storage_path row of
		// /api/diagnostics — each sanitising at its own sink.
		logger.Printf("Config rollback applied in memory but FAILED to persist %d file(s) — see the config.rollback audit entry for the version and the storage_path row of /api/diagnostics for the file names",
			persistFailureCount(persistErr))
		// 500: the operation did not fully succeed. The body distinguishes it
		// from a rollback that did not happen at all — the caller must know the
		// running config HAS changed, so "retry the rollback" is not the fix;
		// fixing the disk and re-saving is.
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // best-effort HTTP response write; client disconnects are not actionable
			"status":           "rolled_back_not_durable",
			"version":          req.Version,
			"warnings":         warnings,
			"applied":          true,
			"stores_persisted": false,
			"persist_errors":   persistErr.Error(),
			"error":            "rollback applied to the running configuration but could not be written to disk; it will be lost on restart",
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // best-effort HTTP response write; client disconnects are not actionable
		"status":           "rolled_back",
		"version":          req.Version,
		"warnings":         warnings,
		"applied":          true,
		"stores_persisted": true,
		// Named for exactly what was verified, and paired with the surfaces
		// that are NOT covered. An earlier draft called this `durable`, which
		// an operator would reasonably read as "this rollback survives a
		// restart" — and for the surfaces below it does not (Codex P1).
		"runtime_only_surfaces": rollbackRuntimeOnlySurfaces,
	})
}

// rollbackRuntimeOnlySurfaces names the parts of a config snapshot that
// applyConfigBackup restores to the RUNNING configuration but never persists,
// so a restart re-reads them from admin_settings.json and they revert.
//
// This is pre-existing, deliberate behaviour — the config-version apply path
// restores live state only (see the RateLimitExempt comment in
// applyConfigBackup) — but the rollback response previously implied otherwise
// by reporting a flat `durable:true`. The scoped write observer can only see
// writes that were ATTEMPTED, so it cannot detect a surface that is never
// written at all; naming them is the honest alternative.
//
// Whether rollback SHOULD persist these (by extending the apply path to
// admin-settings durability) is an owner decision recorded as CHAOS-46, not a
// change to make silently inside an observability fix.
// rewrite_rules left this list in the 2D-C final correction (§17): the
// rollback rewrite slice installs through installRewriteRulesDurable (the
// AdminSettings owner, persist-before-publish), so a successful rewrite
// rollback DOES survive restart — reporting it runtime-only was stale
// operator information.
var rollbackRuntimeOnlySurfaces = []string{
	"default_action",
	"ip_filter_mode",
	"ip_list",
	"rate_limit_rpm",
	"rate_limit_exempt",
}

// validateConfigBackup performs pre-flight checks on a config snapshot (F7).
// Returns a list of human-readable warnings; empty slice means all checks pass.
func validateConfigBackup(b *configBackup) []string {
	var warnings []string

	// Check blocklist mode is valid.
	if b.BlocklistMode != "" && b.BlocklistMode != "allow" && b.BlocklistMode != "block" {
		warnings = append(warnings, fmt.Sprintf("invalid blocklist mode %q", b.BlocklistMode))
	}

	// "deny" is the canonical runtime value; "block" is accepted for legacy snapshots.
	if b.DefaultAction != "" && b.DefaultAction != "allow" && b.DefaultAction != "deny" && b.DefaultAction != "block" {
		warnings = append(warnings, fmt.Sprintf("invalid default action %q", b.DefaultAction))
	}

	// Validate each policy rule.
	var invalidRules int
	for i := range b.PolicyRules {
		if err := validatePolicyRule(b.PolicyRules[i], nil, -1); err != nil {
			invalidRules++
		}
	}
	if invalidRules > 0 {
		warnings = append(warnings, fmt.Sprintf("%d of %d policy rules are invalid (will be skipped)", invalidRules, len(b.PolicyRules)))
	}

	// Check IP filter mode is valid.
	if b.IPFilterMode != "" && b.IPFilterMode != "allow" && b.IPFilterMode != "block" {
		warnings = append(warnings, fmt.Sprintf("invalid IP filter mode %q", b.IPFilterMode))
	}

	// Check rate limit is non-negative.
	if b.RateLimitRPM < 0 {
		warnings = append(warnings, "negative rate limit RPM")
	}

	return warnings
}

// configRollbackMu serializes config rollback operations (B17) so concurrent
// rollback requests cannot interleave store mutations and leave partial state.
var configRollbackMu sync.Mutex

// restoreBlocklistFromBackup rebuilds the blocklist from a snapshot.
// Feed attribution is carried across the rebuild — the Remove/Add loops
// would otherwise strand every feed entry as unattributed, making it
// prey for the unattributed-cleanup operation (Codex P1, PR #447).
func restoreBlocklistFromBackup(b *configBackup) {
	feedSrcSnap := bl.SnapshotFeedSources()
	for _, h := range bl.List() {
		bl.Remove(h)
	}
	for _, h := range b.Blocklist {
		bl.Add(h)
	}
	bl.RestoreFeedSources(feedSrcSnap)
	bl.Save()
	if b.BlocklistMode == "allow" || b.BlocklistMode == "block" {
		bl.SetMode(b.BlocklistMode)
	}
}

// applyConfigBackup restores all config stores from a backup snapshot.
//
// It returns a non-nil error when one or more of the stores it wrote failed to
// reach disk (CHAOS-27 / F-12). The in-memory apply is unconditional and
// unchanged: every store is restored, and a persistence failure never aborts
// the remaining steps — a half-applied RUNNING config would be strictly worse
// than a fully-applied one that is not yet durable. What the error carries is
// the fact the caller previously had no way to learn: the rolled-back state is
// live but will NOT survive a restart.
//
// The stores' Save() methods return nothing and swallow their write errors, so
// the failures are collected from the fileutil durable-write observer via a
// scoped collector rather than from return values (see storage_health.go for
// the scope's time-window semantics).
func applyConfigBackup(b *configBackup) error {
	// Blocker B (exclusive side): a rollback both REMOVES shared objects and
	// INSTALLS references wholesale, so it must not interleave with either
	// side of the reference-integrity gate. Acquired OUTERMOST, before
	// configRollbackMu (gate → configRollbackMu → adminSettingsMu — acyclic;
	// nothing under those locks acquires the gate).
	refScanDeleteLock()
	defer refScanDeleteUnlock()
	configRollbackMu.Lock()
	defer configRollbackMu.Unlock()
	finishScope := beginStorageWriteScope()
	defer finishScope()
	restoreBlocklistFromBackup(b)

	// URLCategories MUST be applied before CategoryGroups (which may
	// reference categories by name) and before PolicyRules (which may
	// reference groups that reference categories). The full dependency
	// chain is PolicyRules → CategoryGroups → catStore; apply order
	// is the reverse — leaf dependencies first. See
	// roadmap/URL-CATEGORIES-ROLLBACK-EXTENSION-SPEC.md §4.4-§4.5.
	//
	// Layer 2 (communityDB) is intentionally NOT touched — rollback
	// restores admin-managed catStore only. communityDB lookups
	// continue across the apply window.
	//
	// Nil-skip vs explicit-empty (per spec §4.7):
	//   - b.URLCategories == nil → old snapshot (pre-extension) or
	//     explicit JSON null; leave live catStore untouched.
	//   - b.URLCategories == [] → new snapshot recorded with zero
	//     categories; ReplaceAll wipes the live store.
	//   - populated → wholesale replace.
	if b.URLCategories != nil {
		catStore.ReplaceAll(b.URLCategories)
		catStore.Save()
		// The rolled-back taxonomy's BuiltIn entries reach policy evaluation only through
		// the effective view. The CategoryOverrides block below recomposes too, but it is
		// nil-skipped on a pre-extension / no-override snapshot, so rollback needs its own.
		recomposeSignedFeedTaxonomy()
	}

	// CategoryGroups MUST be applied before PolicyRules. Policy rules
	// reference category groups by name (PolicyRule.DestCategoryGroup,
	// matched at runtime via globalCategoryGroups.MatchesHost which
	// fails closed for unknown groups). Restoring groups first ensures
	// the post-apply state has every restored rule sees its referenced
	// groups in their v2 form, not the pre-rollback form. See
	// roadmap/CATEGORYGROUPS-ROLLBACK-EXTENSION-SPEC.md §3.3-§3.4.
	//
	// Nil-skip vs explicit-empty (per spec §6.4):
	//   - b.CategoryGroups == nil → old snapshot (pre-extension) or
	//     explicit JSON null; leave live state untouched.
	//   - b.CategoryGroups == [] → new snapshot recorded with zero
	//     groups; ReplaceAll wipes the live store.
	//   - populated → wholesale replace.
	if b.CategoryGroups != nil {
		globalCategoryGroups.ReplaceAll(b.CategoryGroups)
		globalCategoryGroups.Save()
	}

	// DecryptionProfiles MUST be applied before PolicyRules (same reason as
	// CategoryGroups: rules reference profiles by name, fail-safe-to-strip at eval
	// on a dangling ref). nil → skip; [] → wipe; populated → replace.
	if b.DecryptionProfiles != nil {
		globalDecryptionProfiles.ReplaceAll(b.DecryptionProfiles)
		globalDecryptionProfiles.Save()
	}

	// Category overrides (F3a-2): admin overrides layered on the feed snapshot,
	// applied before PolicyRules (leaf-first, mirroring the ConfigSnapshot apply
	// ordering). nil → pre-extension snapshot, skip; non-nil (even empty) →
	// wholesale replace (a deliberate clear round-trips as a wipe). ReplaceAll
	// re-validates; an invalid historical set is tolerated (skipped) so rollback
	// never rejects.
	if b.CategoryOverrides != nil {
		if err := globalCategoryOverrides.ReplaceAll(*b.CategoryOverrides); err == nil {
			if serr := globalCategoryOverrides.Save(); serr != nil {
				logger.Printf("Rollback: category overrides save: %v", serr)
			}
			// F3b-4 finding #5: recompose the effective policy view for the rolled-back
			// override set (local, no network).
			recomposeSignedFeedOverrides()
		}
	}

	// Policy rules: bulk replace.
	var validRules []PolicyRule
	for i := range b.PolicyRules {
		if err := validatePolicyRule(b.PolicyRules[i], nil, -1); err != nil {
			continue
		}
		validRules = append(validRules, b.PolicyRules[i])
	}
	policyStore.ReplaceAll(validRules)
	policyStore.Save()
	setDefaultPolicyAction(b.DefaultAction)

	// Rewrite rules: replace all, DURABLY through the AdminSettings owner
	// (2D-C §24/§38 — the Blocker-E feed precedent): the restored set persists
	// INSIDE the same adminSettingsMu transaction that publishes it, so a
	// rollback's rewrite slice can no longer be runtime-only and silently
	// revert on restart. Restored stable IDs are preserved verbatim (a config
	// version must never create fresh rewrite identities merely because it was
	// restored); pre-2D-C captured versions without stable IDs are backfilled
	// at publication — the documented one-time legacy migration. A persist
	// failure means the slice was never applied (durable-or-nothing) and is
	// collected by the storage-write scope.
	if err := installRewriteRulesDurable(b.RewriteRules); err != nil {
		logger.Printf("ConfigVersion: rewrite slice not applied (persist failed): %v", err)
	}

	applyScanStoresFromBackup(b)

	applyFilterStoresFromBackup(b)

	if b.RateLimitRPM > 0 {
		rl.Configure(b.RateLimitRPM, time.Minute)
	}

	// RateLimitExempt: rollback-surface extension (Finding 10.3 PR-2). Mirrors
	// the CategoryGroups/URLCategories nil-skip contract exactly:
	//   nil       → old/pre-extension snapshot; leave live exemptions untouched.
	//   []        → snapshot recorded zero exemptions; wipe the live exempt list.
	//   populated → wholesale replace.
	// rl.ReplaceExemptions builds the new IP/CIDR sets outside the lock and
	// swaps under a single Lock, so there is never a partial/stale-exemption
	// window. No admin_settings persistence here — matches RateLimitRPM above;
	// the config-version apply path restores live state only.
	if b.RateLimitExempt != nil {
		rl.ReplaceExemptions(b.RateLimitExempt)
	}

	pacErr := applyPACFromBackup(b)

	// Close the scope here (not only via the defer) so its result is available
	// to the caller. finishScope is once-guarded; the deferred call above is
	// the panic-path safety net that guarantees the scope is unregistered.
	if failed := finishScope(); len(failed) > 0 {
		return &configPersistError{Files: failed}
	}
	// 2F-E correction round 7: a PAC profiles slice that was NOT applied
	// because a pending lifecycle intent of a profile it changes could not
	// be settled durably is reported to the caller (audit + response), the
	// same way a persistence failure is — the rollback is otherwise applied.
	return pacErr
}

// configPersistError reports the durable writes that failed while a config
// snapshot was applied. It carries the failing files as STRUCTURED data, not
// just a formatted string, so a caller can report a count without
// interpolating path-derived text into a log line (CWE-117). The file names
// still reach the operator — via the audit entry, the API response, and the
// storage_path diagnostics row — each sanitising at its own sink.
type configPersistError struct{ Files []string }

func (e *configPersistError) Error() string {
	return fmt.Sprintf("rollback applied to the running config but %d file(s) failed to persist: %s",
		len(e.Files), strings.Join(e.Files, "; "))
}

// persistFailureCount returns how many files a persistence error names, or 0
// for a nil / differently-typed error. Lets the log sink stay integers-only.
func persistFailureCount(err error) int {
	var pe *configPersistError
	if errors.As(err, &pe) {
		return len(pe.Files)
	}
	return 0
}

// applyFilterStoresFromBackup restores the file-extension blocker and the IP
// filter from a snapshot. Split out of applyConfigBackup for cyclop only —
// behaviour and ordering are unchanged. Callers must keep invoking it at the
// same point in the apply sequence.
//
// Both stores are runtime-only on this path: neither Add/Remove nor SetMode
// persists, so these surfaces revert on restart (CHAOS-46, surfaced to the
// caller as rollbackRuntimeOnlySurfaces).
func applyFilterStoresFromBackup(b *configBackup) {
	// File block extensions: remove all, then add.
	for _, ext := range fileBlocker.List() {
		fileBlocker.Remove(ext)
	}
	for _, ext := range b.FileBlockExtensions {
		fileBlocker.Add(ext)
	}

	// IP filter: remove all, set mode, then add. ClearAll is exactly the
	// List+Remove loop it replaces (Remove filters by the same canonical
	// strings List emits) minus the quadratic cost, and AddAll bulk-loads in
	// one pass with a single view publish — an Add loop is quadratic.
	ipf.SetMode(b.IPFilterMode)
	ipf.ClearAll()
	_ = ipf.AddAll(b.IPList)
}

// applyScanStoresFromBackup restores the SSL-bypass matcher and the content
// scanner from a snapshot. Split out of applyConfigBackup for cyclop only —
// the behaviour, and critically the ordering, is unchanged. Callers must keep
// invoking it at the same point in the apply sequence.
func applyScanStoresFromBackup(b *configBackup) {
	// SSL bypass + content scan: replace all.
	_ = sslBypass.Set(b.SSLBypass)
	sslBypass.Save()
	// dpiScanner bypass hosts + content scan patterns share a single
	// content_scan.json envelope (scanner.go Save). Apply both
	// in-memory first, then ONE Save() so the on-disk file is written
	// once and never persists an intermediate (bypass-restored,
	// patterns-stale) state.
	//
	// Patterns are applied (and validated) FIRST: dpiScanner.Set
	// returns an error and leaves the existing patterns unchanged when
	// a snapshot carries an invalid regex. Only on success do we mutate
	// bypass hosts and persist — otherwise a bad-pattern snapshot would
	// leave patterns at the old runtime value while bypass hosts were
	// already replaced, a silent mixed state matching neither the
	// snapshot nor the prior state. In-memory order does not affect the
	// single-envelope Save (both halves are applied before the one
	// Save). See roadmap/SCANNER-ROLLBACK-EXTENSION-SPEC.md §8.
	//
	// ContentScanBypassHosts is nil-skip:
	//   - nil   → old/absent snapshot; leave bypass list untouched.
	//   - []    → snapshot recorded zero bypass hosts; wipe.
	//   - [...] → wholesale replace.
	if err := dpiScanner.Set(b.ContentScanPatterns); err == nil {
		if b.ContentScanBypassHosts != nil {
			dpiScanner.SetBypassHosts(b.ContentScanBypassHosts)
		}
		dpiScanner.Save()
	}
}

// applyPACFromBackup restores PAC configuration and the PAC profile/pool set
// from a snapshot. Split out of applyConfigBackup for cyclop only — behaviour
// and ordering are unchanged.
func applyPACFromBackup(b *configBackup) error {
	// PAC configuration: replace entirely from snapshot.
	_ = pacStore.Set(PACConfig{
		ProxyHost:  b.PACProxyHost,
		ProxyPort:  b.PACProxyPort,
		Exclusions: b.PACExclusions,
	})

	// PAC profiles/pools (PAC initiative PR 2): nil → snapshot predates the
	// feature, skip; [] → explicit wipe; populated → wholesale replace.
	// Tolerant Set — rollback must never reject historical data.
	// 2F-E correction round 4: inside the shared PAC writer transaction
	// boundary (pacProfilesWriterLock — lock order gate → configRollbackMu →
	// pacProfilesAPIMu), so a lifecycle publish parked between its intent and
	// its commit can neither interleave with nor overwrite the restore.
	// 2F-E correction round 7: a pending lifecycle intent of every profile
	// the rollback CHANGES is settled durably before the write
	// (pacSettlePendingBeforeWrite); if that cannot be persisted the PAC
	// profiles slice is deferred (not applied) and reported.
	var pacErr error
	if b.PACProfiles != nil || b.PACPools != nil {
		pacErr = applyPACProfilesFromBackup(b)
	}

	// SaaS feed config (F3a-2): applied only when the snapshot carries it
	// (SaaSFeedProtocol set — capture always sets it, a pre-extension snapshot does
	// not), then unconditionally within that gate (like DefaultAction). This
	// restores the exact captured feed configuration WITHOUT touching the
	// node-local floor/active-generation state (those are off every surface).
	// Blocker E: the install goes through installSaaSFeedDurable — read,
	// durable AdminSettings write, and holder publish in ONE adminSettingsMu
	// transaction — so rollback serializes against the fenced settings PUT
	// (lock order configRollbackMu → adminSettingsMu, acyclic). A persist
	// failure means the target was never applied; the failed file is also
	// captured by the surrounding storage-write scope. No downloader/legacy-
	// syncer call.
	if b.SaaSFeedProtocol != "" {
		if err := installSaaSFeedDurable(func(cur saasFeedDurable) saasFeedDurable {
			cur.Managed = b.SaaSFeedManaged
			cur.Enabled = b.SaaSFeedEnabled
			cur.URL = b.SaaSFeedURL
			cur.Protocol = b.SaaSFeedProtocol
			cur.RefreshSeconds = b.SaaSFeedRefreshSeconds
			return cur
		}); err != nil {
			logger.Printf("ConfigRollback: saas feed settings persist failed, target never applied: %v", err)
		}
	}
	return pacErr
}

// applyPACProfilesFromBackup is the rollback's PAC profiles/pools write
// inside the shared writer boundary (the mutex is released before the
// SaaS-feed slice — lock order configRollbackMu → pacProfilesAPIMu, and
// adminSettingsMu is never taken under it).
func applyPACProfilesFromBackup(b *configBackup) error {
	unlock := pacProfilesWriterLock()
	defer unlock()
	before := pacProfiles.Get()
	cur := pacProfiles.Get()
	if b.PACProfiles != nil {
		cur.Profiles = b.PACProfiles
	}
	if b.PACPools != nil {
		cur.Pools = b.PACPools
	}
	if err := pacSettlePendingBeforeWrite(before, cur); err != nil {
		logger.Printf("ConfigRollback: PAC profiles slice not applied: %v", err)
		return fmt.Errorf("PAC profiles not applied: %w", err)
	}
	_ = pacProfiles.Set(cur)
	return nil
}

// configChange is a single field-level difference between two config versions.
type configChange struct {
	Field string `json:"field"`
	From  any    `json:"from"`
	To    any    `json:"to"`
}

// loadConfigVersion reads and parses a stored config version file.
func loadConfigVersion(ver int) (*configBackup, error) {
	_, raw, err := configVersions.Load(ver)
	if err != nil {
		return nil, err
	}
	var cb configBackup
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cb); err != nil {
			return nil, err
		}
	}
	return &cb, nil
}

// diffConfigs compares two config backups and returns field-level changes.
// F11: element-level diffs showing added/removed items, not just counts.
func diffConfigs(a, b *configBackup) []configChange {
	var changes []configChange
	cmp := func(field string, from, to any) {
		changes = append(changes, configChange{field, from, to})
	}
	if a.DefaultAction != b.DefaultAction {
		cmp("default_action", a.DefaultAction, b.DefaultAction)
	}
	if a.BlocklistMode != b.BlocklistMode {
		cmp("blocklist_mode", a.BlocklistMode, b.BlocklistMode)
	}
	if a.IPFilterMode != b.IPFilterMode {
		cmp("ip_filter_mode", a.IPFilterMode, b.IPFilterMode)
	}
	if a.RateLimitRPM != b.RateLimitRPM {
		cmp("rate_limit_rpm", a.RateLimitRPM, b.RateLimitRPM)
	}
	if a.PACProxyHost != b.PACProxyHost {
		cmp("pac_proxy_host", a.PACProxyHost, b.PACProxyHost)
	}
	if a.PACProxyPort != b.PACProxyPort {
		cmp("pac_proxy_port", a.PACProxyPort, b.PACProxyPort)
	}

	// Element-level diffs for list fields.
	diffStringList("blocklist", a.Blocklist, b.Blocklist, &changes)
	diffStringList("ssl_bypass", a.SSLBypass, b.SSLBypass, &changes)
	diffStringList("content_scan_patterns", a.ContentScanPatterns, b.ContentScanPatterns, &changes)

	// ContentScanBypassHosts mirrors applyConfigBackup's nil-skip (see the
	// scanner block there): a nil target is an old/pre-extension snapshot that
	// apply leaves untouched, so the dry-run diff must skip it too — otherwise
	// rolling back to a pre-extension snapshot reports every live bypass host
	// as "removed" while apply changes nothing. A non-nil [] still diffs (the
	// wipe). Same contract as RateLimitExempt/CategoryGroups/URLCategories
	// below; pinned by the config-surface registry (config_surfaces.go
	// DiffNilGuarded + TestConfigSurfaces_DiffNilGuardMirrorsApply).
	if b.ContentScanBypassHosts != nil {
		diffStringList("content_scan_bypass_hosts", a.ContentScanBypassHosts, b.ContentScanBypassHosts, &changes)
	}
	diffStringList("file_block_extensions", a.FileBlockExtensions, b.FileBlockExtensions, &changes)
	diffStringList("ip_list", a.IPList, b.IPList, &changes)
	diffStringList("pac_exclusions", a.PACExclusions, b.PACExclusions, &changes)

	// RateLimitExempt is nil-guarded (unlike the always-captured []string
	// fields above) because a pre-extension snapshot lacks the field → nil.
	// Mirror applyConfigBackup's nil-skip: a nil target means "leave live
	// exemptions untouched", so the diff must report nothing rather than flag
	// every live exemption as removed. A non-nil [] still diffs (the wipe).
	if b.RateLimitExempt != nil {
		diffStringList("rate_limit_exempt", a.RateLimitExempt, b.RateLimitExempt, &changes)
	}

	// Policy rules: diff by priority key.
	diffPolicyRules(a.PolicyRules, b.PolicyRules, &changes)

	// Rewrite rules: diff by host key.
	diffRewriteRules(a.RewriteRules, b.RewriteRules, &changes)

	// Category groups + URL categories: struct slices on the rollback
	// surface (captured via List()/All(), applied via ReplaceAll). The
	// nil guards MUST mirror applyConfigBackup exactly: a nil target slice
	// is an old/absent snapshot field that apply skips (no-op), so the
	// dry-run/preflight diff must skip it too — otherwise rolling back to
	// a pre-extension snapshot would report every live group/category as
	// "removed" while apply leaves them untouched. A non-nil empty slice
	// is an explicit wipe (ReplaceAll([])) and DOES diff (reports the
	// live entries as removed); hence the guard keys on nil, not len()==0.
	// An in-place edit of a group's Categories / a category's Hosts (or
	// BuiltIn flag) surfaces as "changed", not silently dropped.
	if b.CategoryGroups != nil {
		diffCategoryGroups(a.CategoryGroups, b.CategoryGroups, &changes)
	}
	if b.DecryptionProfiles != nil {
		diffDecryptionProfiles(a.DecryptionProfiles, b.DecryptionProfiles, &changes)
	}
	if b.URLCategories != nil {
		diffURLCategories(a.URLCategories, b.URLCategories, &changes)
	}
	if b.PACProfiles != nil {
		diffPACProfiles(a.PACProfiles, b.PACProfiles, &changes)
	}
	if b.PACPools != nil {
		diffPACPools(a.PACPools, b.PACPools, &changes)
	}

	// SaaS feed config (F3a-2).
	diffSaaSFeedConfig(a, b, cmp)

	// Category overrides (F3a-2). Nil-guarded on b to mirror applyConfigBackup: a
	// nil target is a pre-extension/absent snapshot apply leaves untouched, so the
	// diff must be silent; a non-nil (even empty) set diffs (a clear reports the
	// live entries as removed).
	if b.CategoryOverrides != nil {
		diffCategoryOverrides(a.CategoryOverrides, b.CategoryOverrides, &changes)
	}

	return changes
}

// diffSaaSFeedConfig emits scalar diffs for the SaaS feed configuration. The whole
// block is gated on b.SaaSFeedProtocol != "" to mirror applyConfigBackup's gate: a
// pre-extension target snapshot (protocol absent) is skipped by apply, so the
// dry-run diff must not report phantom feed-config changes it would never make.
func diffSaaSFeedConfig(a, b *configBackup, cmp func(string, any, any)) {
	if b.SaaSFeedProtocol == "" {
		return
	}
	if a.SaaSFeedManaged != b.SaaSFeedManaged {
		cmp("saas_feed_managed", a.SaaSFeedManaged, b.SaaSFeedManaged)
	}
	if a.SaaSFeedEnabled != b.SaaSFeedEnabled {
		cmp("saas_feed_enabled", a.SaaSFeedEnabled, b.SaaSFeedEnabled)
	}
	if a.SaaSFeedURL != b.SaaSFeedURL {
		cmp("saas_feed_url", a.SaaSFeedURL, b.SaaSFeedURL)
	}
	if a.SaaSFeedProtocol != b.SaaSFeedProtocol {
		cmp("saas_feed_protocol", a.SaaSFeedProtocol, b.SaaSFeedProtocol)
	}
	if a.SaaSFeedRefreshSeconds != b.SaaSFeedRefreshSeconds {
		cmp("saas_feed_refresh_seconds", a.SaaSFeedRefreshSeconds, b.SaaSFeedRefreshSeconds)
	}
}

// diffCategoryOverrides reports whether the effective admin override set changed.
// It compares the normalized JSON of both sides (order-insensitive via the engine
// maps) and emits a single "category_overrides" change when they differ. A nil
// source (a is the LIVE side, always captured non-nil, but be defensive) is
// treated as an empty set.
func diffCategoryOverrides(a, b *CategoryOverrides, changes *[]configChange) {
	var av, bv CategoryOverrides
	if a != nil {
		av = *a
	}
	if b != nil {
		bv = *b
	}
	aj, _ := json.Marshal(av)
	bj, _ := json.Marshal(bv)
	if !bytes.Equal(aj, bj) {
		*changes = append(*changes, configChange{Field: "category_overrides", From: av, To: bv})
	}
}

// sameStringSet reports whether two string slices contain the same
// elements (multiset equality; order-independent). Used by the
// struct-slice diff helpers to decide whether an entry's content
// changed. Case-sensitive, matching diffStringList's exact-match
// semantics.
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, v := range a {
		counts[v]++
	}
	for _, v := range b {
		counts[v]--
	}
	for _, n := range counts {
		if n != 0 {
			return false
		}
	}
	return true
}

// diffStringList produces added/removed element-level diffs for string slices.
func diffStringList(field string, a, b []string, out *[]configChange) {
	setA := make(map[string]struct{}, len(a))
	for _, v := range a {
		setA[v] = struct{}{}
	}
	setB := make(map[string]struct{}, len(b))
	for _, v := range b {
		setB[v] = struct{}{}
	}
	var added, removed []string
	for _, v := range b {
		if _, ok := setA[v]; !ok {
			added = append(added, v)
		}
	}
	for _, v := range a {
		if _, ok := setB[v]; !ok {
			removed = append(removed, v)
		}
	}
	if len(added) > 0 || len(removed) > 0 {
		*out = append(*out, configChange{
			Field: field,
			From:  map[string]any{"count": len(a), "removed": removed},
			To:    map[string]any{"count": len(b), "added": added},
		})
	}
}

// diffPolicyRules compares policy rules by priority.
func diffPolicyRules(a, b []PolicyRule, out *[]configChange) {
	mapA := make(map[int]string, len(a))
	for i := range a {
		mapA[a[i].Priority] = a[i].Name
	}
	mapB := make(map[int]string, len(b))
	for i := range b {
		mapB[b[i].Priority] = b[i].Name
	}
	var added, removed, changed []string
	for pri, name := range mapB {
		if oldName, ok := mapA[pri]; !ok {
			added = append(added, fmt.Sprintf("p%d:%s", pri, name))
		} else if oldName != name {
			changed = append(changed, fmt.Sprintf("p%d:%s->%s", pri, oldName, name))
		}
	}
	for pri, name := range mapA {
		if _, ok := mapB[pri]; !ok {
			removed = append(removed, fmt.Sprintf("p%d:%s", pri, name))
		}
	}
	if len(added) > 0 || len(removed) > 0 || len(changed) > 0 {
		*out = append(*out, configChange{
			Field: "policy_rules",
			From:  map[string]any{"count": len(a), "removed": removed, "changed": changed},
			To:    map[string]any{"count": len(b), "added": added},
		})
	}
}

// diffRewriteRules compares rewrite rules IDENTITY-aware (2D-C final §18):
// with StableID durable it detects add/remove by identity, operation/host
// changes on the SAME identity, and pure ordering changes (evaluation order
// is semantics). Legacy history entries without StableIDs get a CONSERVATIVE
// fallback — any difference in the ordered (host, operations) sequence is
// reported as changed, so a same-host operation-only edit can never read as
// "no change". Backend truth only; the change entry shape stays the existing
// {Field, From, To} envelope.
func diffRewriteRules(a, b []RewriteRule, out *[]configChange) {
	idsOf := func(rules []RewriteRule) (map[string]int, bool) {
		m := make(map[string]int, len(rules))
		for i := range rules {
			if rules[i].StableID == "" {
				return nil, false
			}
			m[rules[i].StableID] = i
		}
		return m, len(m) == len(rules) // duplicates ⇒ fall back conservatively
	}
	mapA, okA := idsOf(a)
	mapB, okB := idsOf(b)

	if !okA || !okB {
		// Legacy/partial identity: conservative ordered content comparison —
		// never claim "no change" when the actual rewrite set changed.
		same := len(a) == len(b)
		if same {
			for i := range a {
				if a[i].Host != b[i].Host || !rewriteRuleContentEqual(a[i], b[i]) {
					same = false
					break
				}
			}
		}
		if !same {
			*out = append(*out, configChange{
				Field: "rewrite_rules",
				From:  map[string]any{"count": len(a)},
				To:    map[string]any{"count": len(b), "note": "rewrite set changed (legacy entries without stable identity — content compared conservatively)"},
			})
		}
		return
	}

	var added, removed, changed []string
	for i := range b {
		id := b[i].StableID
		ai, ok := mapA[id]
		switch {
		case !ok:
			added = append(added, id)
		case a[ai].Host != b[i].Host || !rewriteRuleContentEqual(a[ai], b[i]):
			changed = append(changed, id)
		}
	}
	for i := range a {
		if _, ok := mapB[a[i].StableID]; !ok {
			removed = append(removed, a[i].StableID)
		}
	}
	reordered := false
	if len(added) == 0 && len(removed) == 0 && len(a) == len(b) {
		for i := range a {
			if a[i].StableID != b[i].StableID {
				reordered = true
				break
			}
		}
	}
	if len(added) > 0 || len(removed) > 0 || len(changed) > 0 || reordered {
		*out = append(*out, configChange{
			Field: "rewrite_rules",
			From:  map[string]any{"count": len(a), "removed": removed},
			To:    map[string]any{"count": len(b), "added": added, "changed": changed, "reordered": reordered},
		})
	}
}

// diffPACObjects is the shared ID-keyed differ for PAC profiles and pools
// (PAC initiative PR 2). ids/same abstract the concrete slice so the two
// surfaces cannot drift (and dupl stays quiet).
func diffPACObjects(field string, aIDs, bIDs []string, same func(ai, bi int) bool, out *[]configChange) {
	mapA := make(map[string]int, len(aIDs))
	for i, id := range aIDs {
		mapA[id] = i
	}
	var added, removed, changed []string
	seen := make(map[string]bool, len(bIDs))
	for i, id := range bIDs {
		seen[id] = true
		ai, ok := mapA[id]
		switch {
		case !ok:
			added = append(added, id)
		case !same(ai, i):
			changed = append(changed, id)
		}
	}
	for _, id := range aIDs {
		if !seen[id] {
			removed = append(removed, id)
		}
	}
	if len(added) > 0 || len(removed) > 0 || len(changed) > 0 {
		*out = append(*out, configChange{
			Field: field,
			From:  map[string]any{"count": len(aIDs), "removed": removed, "changed": changed},
			To:    map[string]any{"count": len(bIDs), "added": added},
		})
	}
}

// diffPACProfiles compares PAC steering profiles by ID.
func diffPACProfiles(a, b []pac.Profile, out *[]configChange) {
	aIDs := make([]string, len(a))
	for i := range a {
		aIDs[i] = a[i].ID
	}
	bIDs := make([]string, len(b))
	for i := range b {
		bIDs[i] = b[i].ID
	}
	diffPACObjects("pac_profiles", aIDs, bIDs, func(ai, bi int) bool { return samePACProfile(&a[ai], &b[bi]) }, out)
}

func samePACProfile(x, y *pac.Profile) bool {
	if x.Name != y.Name || x.Description != y.Description || x.Enabled != y.Enabled ||
		x.PoolID != y.PoolID || x.PrivateNetworks != y.PrivateNetworks ||
		x.AvailabilityMode != y.AvailabilityMode || len(x.Rules) != len(y.Rules) {
		return false
	}
	for i := range x.Rules {
		if x.Rules[i] != y.Rules[i] {
			return false
		}
	}
	return true
}

// diffPACPools compares PAC proxy pools by ID.
func diffPACPools(a, b []pac.Pool, out *[]configChange) {
	aIDs := make([]string, len(a))
	for i := range a {
		aIDs[i] = a[i].ID
	}
	bIDs := make([]string, len(b))
	for i := range b {
		bIDs[i] = b[i].ID
	}
	diffPACObjects("pac_pools", aIDs, bIDs, func(ai, bi int) bool { return samePACPool(&a[ai], &b[bi]) }, out)
}

func samePACPool(x, y *pac.Pool) bool {
	if x.Name != y.Name || len(x.Endpoints) != len(y.Endpoints) {
		return false
	}
	for i := range x.Endpoints {
		if x.Endpoints[i] != y.Endpoints[i] {
			return false
		}
	}
	return true
}

// diffCategoryGroups compares category groups by name (case-insensitive,
// matching the store's lowercase key convention). Reports added, removed,
// and changed (same name, different Categories membership). Mirrors
// diffPolicyRules' added/removed/changed shape.
func diffCategoryGroups(a, b []CategoryGroup, out *[]configChange) {
	mapA := make(map[string]CategoryGroup, len(a))
	for i := range a {
		mapA[strings.ToLower(a[i].Name)] = a[i]
	}
	mapB := make(map[string]CategoryGroup, len(b))
	for i := range b {
		mapB[strings.ToLower(b[i].Name)] = b[i]
	}
	var added, removed, changed []string
	for key, gb := range mapB {
		ga, ok := mapA[key]
		if !ok {
			added = append(added, gb.Name)
		} else if !sameStringSet(ga.Categories, gb.Categories) {
			changed = append(changed, gb.Name)
		}
	}
	for key, ga := range mapA {
		if _, ok := mapB[key]; !ok {
			removed = append(removed, ga.Name)
		}
	}
	if len(added) > 0 || len(removed) > 0 || len(changed) > 0 {
		*out = append(*out, configChange{
			Field: "category_groups",
			From:  map[string]any{"count": len(a), "removed": removed, "changed": changed},
			To:    map[string]any{"count": len(b), "added": added},
		})
	}
}

// sameDecryptionProfile reports whether two profiles have identical operator-facing
// content (ID/timestamps excluded — they are not config identity).
func sameDecryptionProfile(x, y *DecryptionProfile) bool {
	if (x.InspectHTTP2 == nil) != (y.InspectHTTP2 == nil) {
		return false
	}
	if x.InspectHTTP2 != nil && *x.InspectHTTP2 != *y.InspectHTTP2 {
		return false
	}
	return x.CertVerification == y.CertVerification &&
		x.OnUnsupported == y.OnUnsupported &&
		x.OnInspectError == y.OnInspectError &&
		x.MinTLSVersion == y.MinTLSVersion &&
		x.MaxTLSVersion == y.MaxTLSVersion &&
		x.StallTimeoutSecs == y.StallTimeoutSecs
}

// diffDecryptionProfiles compares decryption profiles by name (case-insensitive).
// Reports added, removed, and changed (same name, different content). Mirrors
// diffCategoryGroups. Index maps (not value maps) avoid copying the 144-byte
// DecryptionProfile per range iteration (gocritic rangeValCopy convention).
func diffDecryptionProfiles(a, b []DecryptionProfile, out *[]configChange) {
	idxA := make(map[string]int, len(a))
	for i := range a {
		idxA[strings.ToLower(a[i].Name)] = i
	}
	idxB := make(map[string]int, len(b))
	for i := range b {
		idxB[strings.ToLower(b[i].Name)] = i
	}
	var added, removed, changed []string
	for key, bi := range idxB {
		if ai, ok := idxA[key]; !ok {
			added = append(added, b[bi].Name)
		} else if !sameDecryptionProfile(&a[ai], &b[bi]) {
			changed = append(changed, b[bi].Name)
		}
	}
	for key, ai := range idxA {
		if _, ok := idxB[key]; !ok {
			removed = append(removed, a[ai].Name)
		}
	}
	if len(added) > 0 || len(removed) > 0 || len(changed) > 0 {
		*out = append(*out, configChange{
			Field: "decryption_profiles",
			From:  map[string]any{"count": len(a), "removed": removed, "changed": changed},
			To:    map[string]any{"count": len(b), "added": added},
		})
	}
}

// diffURLCategories compares URL categories by name (case-insensitive,
// matching catStore's lowercase index key). Reports added, removed, and
// changed (same name, different Hosts membership OR BuiltIn flag — both
// round-trip through rollback, so a flip is a real apply-time change).
func diffURLCategories(a, b []CategoryEntry, out *[]configChange) {
	mapA := make(map[string]CategoryEntry, len(a))
	for i := range a {
		mapA[strings.ToLower(a[i].Name)] = a[i]
	}
	mapB := make(map[string]CategoryEntry, len(b))
	for i := range b {
		mapB[strings.ToLower(b[i].Name)] = b[i]
	}
	var added, removed, changed []string
	for key, eb := range mapB {
		ea, ok := mapA[key]
		if !ok {
			added = append(added, eb.Name)
		} else if ea.BuiltIn != eb.BuiltIn || !sameStringSet(ea.Hosts, eb.Hosts) {
			changed = append(changed, eb.Name)
		}
	}
	for key, ea := range mapA {
		if _, ok := mapB[key]; !ok {
			removed = append(removed, ea.Name)
		}
	}
	if len(added) > 0 || len(removed) > 0 || len(changed) > 0 {
		*out = append(*out, configChange{
			Field: "url_categories",
			From:  map[string]any{"count": len(a), "removed": removed, "changed": changed},
			To:    map[string]any{"count": len(b), "added": added},
		})
	}
}

// apiConfigDiff returns the differences between two config versions.
// GET /api/config/diff?from=N&to=M
func apiConfigDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}

	from, _ := strconv.Atoi(r.URL.Query().Get("from"))
	to, _ := strconv.Atoi(r.URL.Query().Get("to"))
	if from <= 0 || to <= 0 {
		http.Error(w, "from and to must be positive integers", http.StatusBadRequest)
		return
	}

	fromCfg, err := loadConfigVersion(from)
	if err != nil {
		http.Error(w, fmt.Sprintf("version %d not found", from), http.StatusNotFound)
		return
	}
	toCfg, err := loadConfigVersion(to)
	if err != nil {
		http.Error(w, fmt.Sprintf("version %d not found", to), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"from":    from,
		"to":      to,
		"changes": diffConfigs(fromCfg, toCfg),
	})
}
