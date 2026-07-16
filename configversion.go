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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/configver"
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
	return &configBackup{
		Version:             1,
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
	}
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
	saveConfigVersionMu.Lock()
	defer saveConfigVersionMu.Unlock()

	snap := captureConfigBackup()
	raw, err := json.Marshal(snap)
	if err != nil {
		logger.Printf("ConfigVersion: marshal error: %v", err)
		return
	}
	if _, err := configVersions.SaveWithNote(actor, action, snap.ExportedAt, note, raw); err != nil {
		logger.Printf("ConfigVersion: write error: %v", err)
	}
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

	if err := applyConfigBackup(&target); err != nil {
		http.Error(w, "configuration changed in memory but policy save failed", http.StatusInternalServerError)
		return
	}

	actor := sessionAdmin(r)
	auditEvent(r, "config.rollback", "system",
		fmt.Sprintf("rolled back to version %d (from %s by %s)",
			req.Version, meta.CreatedAt, sanitizeLog(meta.Actor)))

	saveConfigVersion(actor, fmt.Sprintf("rollback to v%d", req.Version))

	if globalConfigStore != nil {
		globalConfigStore.Update(CurrentConfigSnapshot())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"status":   "rolled_back",
		"version":  req.Version,
		"warnings": warnings,
	})
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
func applyConfigBackup(b *configBackup) error {
	configRollbackMu.Lock()
	defer configRollbackMu.Unlock()
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

	// Policy rules: bulk replace.
	var validRules []PolicyRule
	for i := range b.PolicyRules {
		if err := validatePolicyRule(b.PolicyRules[i], nil, -1); err != nil {
			continue
		}
		validRules = append(validRules, b.PolicyRules[i])
	}
	policyStore.ReplaceAll(validRules)
	if err := policyStore.Save(); err != nil {
		return err
	}
	setDefaultPolicyAction(b.DefaultAction)

	// Rewrite rules: replace all.
	rewriter.SetRules(b.RewriteRules)

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

	// File block extensions: remove all, then add.
	for _, ext := range fileBlocker.List() {
		fileBlocker.Remove(ext)
	}
	for _, ext := range b.FileBlockExtensions {
		fileBlocker.Add(ext)
	}

	// IP filter: remove all, set mode, then add.
	ipf.SetMode(b.IPFilterMode)
	for _, ip := range ipf.List() {
		ipf.Remove(ip)
	}
	for _, ip := range b.IPList {
		_ = ipf.Add(ip)
	}

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

	// PAC configuration: replace entirely from snapshot.
	_ = pacStore.Set(PACConfig{
		ProxyHost:  b.PACProxyHost,
		ProxyPort:  b.PACProxyPort,
		Exclusions: b.PACExclusions,
	})
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

	return changes
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

// diffRewriteRules compares rewrite rules by host.
func diffRewriteRules(a, b []RewriteRule, out *[]configChange) {
	setA := make(map[string]struct{}, len(a))
	for i := range a {
		setA[a[i].Host] = struct{}{}
	}
	setB := make(map[string]struct{}, len(b))
	for i := range b {
		setB[b[i].Host] = struct{}{}
	}
	var added, removed []string
	for i := range b {
		if _, ok := setA[b[i].Host]; !ok {
			added = append(added, b[i].Host)
		}
	}
	for i := range a {
		if _, ok := setB[a[i].Host]; !ok {
			removed = append(removed, a[i].Host)
		}
	}
	if len(added) > 0 || len(removed) > 0 {
		*out = append(*out, configChange{
			Field: "rewrite_rules",
			From:  map[string]any{"count": len(a), "removed": removed},
			To:    map[string]any{"count": len(b), "added": added},
		})
	}
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
