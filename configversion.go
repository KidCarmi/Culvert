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

const configVersionsDir = "/data/config_versions"
const maxConfigVersions = 50

// ConfigVersion is metadata for a stored config snapshot.
type ConfigVersion struct {
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
	Actor     string `json:"actor"`
	Action    string `json:"action"` // what triggered the snapshot (e.g. "policy.update", "blocklist.import")
}

var (
	configVersionMu sync.Mutex
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
func saveConfigVersion(actor, action string) {
	configVersionMu.Lock()
	defer configVersionMu.Unlock()

	configVersionSeq++
	seq := configVersionSeq

	snap := configBackup{
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
	}

	meta := ConfigVersion{
		Version:   seq,
		CreatedAt: snap.ExportedAt,
		Actor:     actor,
		Action:    action,
	}

	envelope := struct {
		Meta   ConfigVersion `json:"meta"`
		Config configBackup  `json:"config"`
	}{Meta: meta, Config: snap}

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		logger.Printf("config versioning: marshal error: %v", err)
		return
	}

	path := filepath.Join(configVersionsDir, fmt.Sprintf("v%d.json", seq))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		logger.Printf("config versioning: write error: %v", err)
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

	var versions []ConfigVersion
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "v") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(configVersionsDir, e.Name()))
		if err != nil {
			continue
		}
		var envelope struct {
			Meta ConfigVersion `json:"meta"`
		}
		if json.Unmarshal(data, &envelope) == nil {
			versions = append(versions, envelope.Meta)
		}
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
		Version int `json:"version"`
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
		"status":  "rolled_back",
		"version": req.Version,
	})
}

// applyConfigBackup restores all config stores from a backup snapshot.
func applyConfigBackup(b *configBackup) {
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

	// Policy rules: bulk replace.
	var validRules []PolicyRule
	for i := range b.PolicyRules {
		if err := validatePolicyRule(b.PolicyRules[i]); err != nil {
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
	_ = dpiScanner.Set(b.ContentScanPatterns)
	dpiScanner.Save()

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

// diffConfigs compares two config backups and returns the field-level changes.
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
	if len(a.Blocklist) != len(b.Blocklist) {
		cmp("blocklist_count", len(a.Blocklist), len(b.Blocklist))
	}
	if len(a.PolicyRules) != len(b.PolicyRules) {
		cmp("policy_rules_count", len(a.PolicyRules), len(b.PolicyRules))
	}
	if len(a.RewriteRules) != len(b.RewriteRules) {
		cmp("rewrite_rules_count", len(a.RewriteRules), len(b.RewriteRules))
	}
	if len(a.SSLBypass) != len(b.SSLBypass) {
		cmp("ssl_bypass_count", len(a.SSLBypass), len(b.SSLBypass))
	}
	if len(a.ContentScanPatterns) != len(b.ContentScanPatterns) {
		cmp("content_scan_count", len(a.ContentScanPatterns), len(b.ContentScanPatterns))
	}
	if len(a.FileBlockExtensions) != len(b.FileBlockExtensions) {
		cmp("file_block_count", len(a.FileBlockExtensions), len(b.FileBlockExtensions))
	}
	if len(a.IPList) != len(b.IPList) {
		cmp("ip_list_count", len(a.IPList), len(b.IPList))
	}
	return changes
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
