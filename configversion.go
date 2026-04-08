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
		os.Remove(filepath.Join(configVersionsDir, versions[i]))
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

	b := envelope.Config

	// Apply config — use bulk-replace where available, individual remove+add otherwise.

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
	for _, rule := range b.PolicyRules {
		if err := validatePolicyRule(rule); err != nil {
			continue
		}
		validRules = append(validRules, rule)
	}
	policyStore.ReplaceAll(validRules)
	policyStore.Save()

	setDefaultPolicyAction(b.DefaultAction)

	// Rewrite rules: replace all.
	rewriter.SetRules(b.RewriteRules)

	// SSL bypass: replace all.
	_ = sslBypass.Set(b.SSLBypass)
	sslBypass.Save()

	// Content scan patterns: replace all.
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

	// Rate limiter.
	if b.RateLimitRPM > 0 {
		rl.Configure(b.RateLimitRPM, time.Minute)
	}

	actor := sessionAdmin(r)
	auditEvent(r, "config.rollback", "system",
		fmt.Sprintf("rolled back to version %d (from %s by %s)",
			req.Version, envelope.Meta.CreatedAt, sanitizeLog(envelope.Meta.Actor)))

	// Save a new version recording the rollback itself.
	saveConfigVersion(actor, fmt.Sprintf("rollback to v%d", req.Version))

	// Bump config store version to trigger DP sync.
	if globalConfigStore != nil {
		globalConfigStore.Update(CurrentConfigSnapshot())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"status":  "rolled_back",
		"version": req.Version,
	})
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

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	from, _ := strconv.Atoi(fromStr)
	to, _ := strconv.Atoi(toStr)
	if from <= 0 || to <= 0 {
		http.Error(w, "from and to must be positive integers", http.StatusBadRequest)
		return
	}

	loadConfig := func(ver int) (*configBackup, error) {
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

	fromCfg, err := loadConfig(from)
	if err != nil {
		http.Error(w, fmt.Sprintf("version %d not found", from), http.StatusNotFound)
		return
	}
	toCfg, err := loadConfig(to)
	if err != nil {
		http.Error(w, fmt.Sprintf("version %d not found", to), http.StatusNotFound)
		return
	}

	// Build diff as list of changes.
	type Change struct {
		Field string `json:"field"`
		From  any    `json:"from"`
		To    any    `json:"to"`
	}
	var changes []Change

	if fromCfg.DefaultAction != toCfg.DefaultAction {
		changes = append(changes, Change{"default_action", fromCfg.DefaultAction, toCfg.DefaultAction})
	}
	if fromCfg.BlocklistMode != toCfg.BlocklistMode {
		changes = append(changes, Change{"blocklist_mode", fromCfg.BlocklistMode, toCfg.BlocklistMode})
	}
	if fromCfg.IPFilterMode != toCfg.IPFilterMode {
		changes = append(changes, Change{"ip_filter_mode", fromCfg.IPFilterMode, toCfg.IPFilterMode})
	}
	if fromCfg.RateLimitRPM != toCfg.RateLimitRPM {
		changes = append(changes, Change{"rate_limit_rpm", fromCfg.RateLimitRPM, toCfg.RateLimitRPM})
	}
	if len(fromCfg.Blocklist) != len(toCfg.Blocklist) {
		changes = append(changes, Change{"blocklist_count", len(fromCfg.Blocklist), len(toCfg.Blocklist)})
	}
	if len(fromCfg.PolicyRules) != len(toCfg.PolicyRules) {
		changes = append(changes, Change{"policy_rules_count", len(fromCfg.PolicyRules), len(toCfg.PolicyRules)})
	}
	if len(fromCfg.RewriteRules) != len(toCfg.RewriteRules) {
		changes = append(changes, Change{"rewrite_rules_count", len(fromCfg.RewriteRules), len(toCfg.RewriteRules)})
	}
	if len(fromCfg.SSLBypass) != len(toCfg.SSLBypass) {
		changes = append(changes, Change{"ssl_bypass_count", len(fromCfg.SSLBypass), len(toCfg.SSLBypass)})
	}
	if len(fromCfg.ContentScanPatterns) != len(toCfg.ContentScanPatterns) {
		changes = append(changes, Change{"content_scan_count", len(fromCfg.ContentScanPatterns), len(toCfg.ContentScanPatterns)})
	}
	if len(fromCfg.FileBlockExtensions) != len(toCfg.FileBlockExtensions) {
		changes = append(changes, Change{"file_block_count", len(fromCfg.FileBlockExtensions), len(toCfg.FileBlockExtensions)})
	}
	if len(fromCfg.IPList) != len(toCfg.IPList) {
		changes = append(changes, Change{"ip_list_count", len(fromCfg.IPList), len(toCfg.IPList)})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"from":    from,
		"to":      to,
		"changes": changes,
	})
}
