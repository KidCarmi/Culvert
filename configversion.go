package main

// ─── Config Versioning & Rollback ──────────────────────────────────────────
//
// Automatic snapshots of all non-secret configuration on every mutation.
// Stored as numbered JSON files in /data/config_versions/.
// Admin can list versions, view diffs, and one-click rollback.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// configVersionsDir is a var (not const) so tests can redirect writes to a
// temp dir. Production code never reassigns it.
var configVersionsDir = "/data/config_versions"

const maxConfigVersions = 50

// ConfigVersion is metadata for a stored config snapshot.
type ConfigVersion struct {
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
	Actor     string `json:"actor"`
	Action    string `json:"action"` // what triggered the snapshot (e.g. "policy.update", "blocklist.import")
}

var (
	configVersionMu  sync.Mutex
	configVersionSeq int
)

func initConfigVersioning() {
	_ = os.MkdirAll(configVersionsDir, 0o750)
	// Find highest existing version number.
	entries, _ := os.ReadDir(configVersionsDir)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") || !strings.HasPrefix(e.Name(), "v") {
			continue
		}
		numStr := strings.TrimSuffix(strings.TrimPrefix(e.Name(), "v"), ".json")
		if n, err := strconv.Atoi(numStr); err == nil && n > configVersionSeq {
			configVersionSeq = n
		}
	}
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

func saveConfigVersion(actor, action string) {
	configVersionMu.Lock()
	defer configVersionMu.Unlock()

	configVersionSeq++
	seq := configVersionSeq

	snap := captureConfigBackup()

	meta := ConfigVersion{
		Version:   seq,
		CreatedAt: snap.ExportedAt,
		Actor:     actor,
		Action:    action,
	}

	envelope := struct {
		Meta   ConfigVersion `json:"meta"`
		Config configBackup  `json:"config"`
	}{Meta: meta, Config: *snap}

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		logger.Printf("ConfigVersion: marshal error: %v", err)
		return
	}

	path := filepath.Join(configVersionsDir, fmt.Sprintf("v%d.json", seq))
	if err := atomicWriteFile(path, data, 0o600); err != nil {
		logger.Printf("ConfigVersion: write error: %v", err)
		return
	}

	// Prune old versions beyond max.
	pruneConfigVersions()
}

func pruneConfigVersions() {
	entries, err := os.ReadDir(configVersionsDir)
	if err != nil {
		return
	}

	var versions []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "v") && strings.HasSuffix(e.Name(), ".json") {
			versions = append(versions, e.Name())
		}
	}

	if len(versions) <= maxConfigVersions {
		return
	}

	// Sort by version number.
	sort.Slice(versions, func(i, j int) bool {
		ni, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(versions[i], "v"), ".json"))
		nj, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(versions[j], "v"), ".json"))
		return ni < nj
	})

	// Remove oldest.
	for i := 0; i < len(versions)-maxConfigVersions; i++ {
		_ = os.Remove(filepath.Join(configVersionsDir, versions[i]))
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
	entries, err := os.ReadDir(configVersionsDir)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]ConfigVersion{}) //nolint:errcheck
		return
	}

	versions := make([]ConfigVersion, 0)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "v") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		fullPath := filepath.Join(configVersionsDir, e.Name())
		data, err := os.ReadFile(fullPath)
		if err != nil {
			// D1.1h: surface skipped files — the rollback UI never sees
			// them otherwise. Behavior unchanged.
			logger.Printf("Loader: config_versions: skipping unreadable %q: %v (D1.2-flag-F5)", sanitizeLog(fullPath), err)
			continue
		}
		var envelope struct {
			Meta ConfigVersion `json:"meta"`
		}
		if jerr := json.Unmarshal(data, &envelope); jerr != nil {
			logger.Printf("Loader: config_versions: skipping unparseable %q: %v (D1.2-flag-F5)", sanitizeLog(fullPath), jerr)
			continue
		}
		versions = append(versions, envelope.Meta)
	}

	// Sort descending by version number.
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Version > versions[j].Version
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(versions) //nolint:errcheck
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

	path := filepath.Join(configVersionsDir, fmt.Sprintf("v%d.json", req.Version))
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "version not found", http.StatusNotFound)
		return
	}

	var envelope struct {
		Meta   ConfigVersion `json:"meta"`
		Config configBackup  `json:"config"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		http.Error(w, "corrupt version file", http.StatusInternalServerError)
		return
	}

	// F7: Pre-flight validation — check snapshot before applying.
	warnings := validateConfigBackup(&envelope.Config)

	if req.DryRun {
		// Compare against current config for a preview diff.
		current := captureConfigBackup()
		changes := diffConfigs(current, &envelope.Config)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"status":   "dry_run",
			"version":  req.Version,
			"warnings": warnings,
			"changes":  changes,
			"valid":    len(warnings) == 0,
		})
		return
	}

	applyConfigBackup(&envelope.Config)

	actor := sessionAdmin(r)
	auditEvent(r, "config.rollback", "system",
		fmt.Sprintf("rolled back to version %d (from %s by %s)",
			req.Version, envelope.Meta.CreatedAt, sanitizeLog(envelope.Meta.Actor)))

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

// applyConfigBackup restores all config stores from a backup snapshot.
func applyConfigBackup(b *configBackup) {
	configRollbackMu.Lock()
	defer configRollbackMu.Unlock()
	// Blocklist: remove all, then add snapshot entries.
	for _, h := range bl.List() {
		bl.Remove(h)
	}
	for _, h := range b.Blocklist {
		bl.Add(h)
	}
	bl.Save()
	if b.BlocklistMode == "allow" || b.BlocklistMode == "block" {
		bl.SetMode(b.BlocklistMode)
	}

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
	//   []        → snapshot recorded zero exemptions; wipe the live whitelist.
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
}

// configChange is a single field-level difference between two config versions.
type configChange struct {
	Field string `json:"field"`
	From  any    `json:"from"`
	To    any    `json:"to"`
}

// loadConfigVersion reads and parses a stored config version file.
func loadConfigVersion(ver int) (*configBackup, error) {
	path := filepath.Join(configVersionsDir, fmt.Sprintf("v%d.json", ver))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Config configBackup `json:"config"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	return &envelope.Config, nil
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
	diffStringList("content_scan_bypass_hosts", a.ContentScanBypassHosts, b.ContentScanBypassHosts, &changes)
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
