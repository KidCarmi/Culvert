package main

// Docker self-update system — Culvert-side logic.
//
// Communicates with the culvert-updater sidecar (HTTP on :7123) for container
// lifecycle operations. Provides version checking, update API endpoints, and
// the standalone update flow.
//
// See roadmap/docker-system-update.md for full design.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// version is set via ldflags at build time: -X main.version=v1.2.3
var version = "dev"

// ── Update info (populated by background version check) ─────────────────────

type updateInfo struct {
	mu              sync.RWMutex
	currentVersion  string
	latestVersion   string
	updateAvailable bool
	lastChecked     time.Time
	updaterStatus   string // "connected", "unavailable", "token_pending"
}

var globalUpdateInfo updateInfo

func (u *updateInfo) snapshot() map[string]any {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return map[string]any{
		"current_version":  u.currentVersion,
		"latest_version":   u.latestVersion,
		"update_available": u.updateAvailable,
		"last_checked":     u.lastChecked.Format(time.RFC3339),
		"updater_status":   u.updaterStatus,
	}
}

// ── Updater client ──────────────────────────────────────────────────────────

var updaterURL = "http://culvert-updater:7123"

// updaterToken reads the shared secret from the token file.
func updaterToken() string {
	data, err := os.ReadFile("/data/updater_token.txt")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ensureUpdaterToken generates the token file if it doesn't exist.
func ensureUpdaterToken() {
	path := "/data/updater_token.txt"
	if _, err := os.Stat(path); err == nil {
		return // already exists
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		logger.Printf("updater token generation failed: %v", err)
		return
	}
	token := hex.EncodeToString(b)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		logger.Printf("updater token write failed: %v", err)
		return
	}
	logger.Printf("generated updater token at %s", path)
}

// updaterRequest makes an authenticated HTTP request to the updater sidecar.
func updaterRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	url := updaterURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	token := updaterToken()
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

// ── Background version check goroutine ──────────────────────────────────────

func startUpdateChecker(ctx context.Context) {
	globalUpdateInfo.mu.Lock()
	globalUpdateInfo.currentVersion = version
	globalUpdateInfo.updaterStatus = "checking"
	globalUpdateInfo.mu.Unlock()

	// Initial check after 30s (let everything start up).
	timer := time.NewTimer(30 * time.Second)
	select {
	case <-ctx.Done():
		timer.Stop()
		return
	case <-timer.C:
	}

	checkUpdateNow()

	// Then check every 6 hours.
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkUpdateNow()
		}
	}
}

func checkUpdateNow() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := updaterRequest(ctx, http.MethodGet, "/api/update/check", nil)
	if err != nil {
		globalUpdateInfo.mu.Lock()
		globalUpdateInfo.updaterStatus = "unavailable"
		globalUpdateInfo.lastChecked = time.Now()
		globalUpdateInfo.mu.Unlock()
		logger.Printf("update check failed: %v", sanitizeLog(err.Error()))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusServiceUnavailable {
		globalUpdateInfo.mu.Lock()
		globalUpdateInfo.updaterStatus = "token_pending"
		globalUpdateInfo.lastChecked = time.Now()
		globalUpdateInfo.mu.Unlock()
		return
	}

	if resp.StatusCode != 200 {
		globalUpdateInfo.mu.Lock()
		globalUpdateInfo.updaterStatus = "error"
		globalUpdateInfo.lastChecked = time.Now()
		globalUpdateInfo.mu.Unlock()
		return
	}

	var result struct {
		Current         string `json:"current"`
		Latest          string `json:"latest"`
		UpdateAvailable bool   `json:"update_available"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	globalUpdateInfo.mu.Lock()
	globalUpdateInfo.latestVersion = result.Latest
	globalUpdateInfo.updateAvailable = result.UpdateAvailable
	globalUpdateInfo.lastChecked = time.Now()
	globalUpdateInfo.updaterStatus = "connected"
	globalUpdateInfo.mu.Unlock()

	if result.UpdateAvailable {
		logger.Printf("update available: %s → %s", version, result.Latest)
	}
}

// ── API handlers ────────────────────────────────────────────────────────────

// apiUpdateStatus returns current version info and update availability.
// GET /api/update/status
func apiUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, "viewer") {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(globalUpdateInfo.snapshot()) //nolint:errcheck
}

// apiUpdateCheck triggers an immediate version check.
// POST /api/update/check
func apiUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}
	go checkUpdateNow()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "checking"}) //nolint:errcheck
}

// apiUpdateApply proxies the update request to the updater sidecar, streaming SSE.
// POST /api/update/apply
func apiUpdateApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}

	var req struct {
		TargetTag string `json:"target_tag"`
		Container string `json:"container"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.TargetTag == "" {
		http.Error(w, `{"error":"target_tag required"}`, http.StatusBadRequest)
		return
	}
	if req.Container == "" {
		req.Container = "culvert"
	}

	auditEvent(r, "update.apply", "system", fmt.Sprintf("update to %s initiated", sanitizeLog(req.TargetTag)))

	// Build request body for updater.
	body, _ := json.Marshal(map[string]string{
		"container":  req.Container,
		"target_tag": req.TargetTag,
	})

	// Proxy SSE from updater to client.
	ctx := r.Context()
	updaterReq, err := http.NewRequestWithContext(ctx, http.MethodPost, updaterURL+"/api/update/apply", strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token := updaterToken()
	if token != "" {
		updaterReq.Header.Set("Authorization", "Bearer "+token)
	}
	updaterReq.Header.Set("Content-Type", "application/json")

	// No timeout — image pull can take a long time.
	client := &http.Client{}
	resp, err := client.Do(updaterReq)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "updater unavailable: " + err.Error()}) //nolint:errcheck
		return
	}
	defer resp.Body.Close()

	// Stream SSE through to client.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n]) //nolint:errcheck
			flusher.Flush()
		}
		if err != nil {
			break
		}
	}
}

// apiUpdatePreview proxies preview request to updater.
// POST /api/update/preview
func apiUpdatePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	resp, err := updaterRequest(ctx, http.MethodPost, "/api/update/preview", r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "updater unavailable"}) //nolint:errcheck
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

// apiUpdateReports lists or downloads update reports.
// GET /api/update/reports
// GET /api/update/reports?id=<filename>
func apiUpdateReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, "viewer") {
		return
	}

	reportDir := "/data/update_reports"

	// If an ID is specified, return that specific report.
	// To avoid path traversal taint (gosec G703), we never use the user-supplied
	// value in a file path. Instead we list the directory and match by name.
	if id := r.URL.Query().Get("id"); id != "" {
		found := findReportFile(reportDir, id)
		if found == "" {
			http.Error(w, "report not found", http.StatusNotFound)
			return
		}
		raw, err := os.ReadFile(found)
		if err != nil {
			http.Error(w, "report not found", http.StatusNotFound)
			return
		}
		// Re-encode to break gosec XSS taint chain (os.ReadFile → w.Write).
		var parsed json.RawMessage
		if err := json.Unmarshal(raw, &parsed); err != nil {
			http.Error(w, "corrupt report", http.StatusInternalServerError)
			return
		}
		safe, _ := json.Marshal(parsed)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write(safe) //nolint:errcheck
		return
	}

	// List all reports.
	entries, err := os.ReadDir(reportDir)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]string{}) //nolint:errcheck
		return
	}

	var reports []map[string]string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		reports = append(reports, map[string]string{
			"id":         e.Name(),
			"created_at": info.ModTime().Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reports) //nolint:errcheck
}

// findReportFile lists the report directory and returns the full path of the
// file whose name matches id. Returns "" if no match.  This avoids using
// user-supplied values directly in file paths (gosec G703 path traversal).
func findReportFile(dir, id string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() && e.Name() == id {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

// apiUpdateRollbackStatus proxies rollback status from updater.
// GET /api/update/rollback/status
func apiUpdateRollbackStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, "viewer") {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, err := updaterRequest(ctx, http.MethodGet, "/api/update/rollback/status", nil)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"available": false, "error": "updater unavailable"}) //nolint:errcheck
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body) //nolint:errcheck
}

// apiUpdateRollback proxies rollback request to updater.
// POST /api/update/rollback
func apiUpdateRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}

	auditEvent(r, "update.rollback", "system", "rollback initiated")

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	resp, err := updaterRequest(ctx, http.MethodPost, "/api/update/rollback", r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "updater unavailable"}) //nolint:errcheck
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

// ── Registry settings ──────────────────────────────────────────────────────

const registrySettingsFile = "/data/registry_settings.json"

// RegistrySettings holds custom registry configuration for air-gapped/enterprise environments.
type RegistrySettings struct {
	RegistryURL string `json:"registry_url"`
	Username    string `json:"username,omitempty"`
	Credential  string `json:"credential,omitempty"`
}

// apiRegistrySettings handles GET (read) and POST (write) for registry configuration.
// GET /api/update/registry — returns settings with password masked.
// POST /api/update/registry — saves settings; if password is masked, preserves existing.
func apiRegistrySettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, "viewer") {
			return
		}
		data, err := os.ReadFile(registrySettingsFile)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"registry_url": "", "username": ""}) //nolint:errcheck
			return
		}
		var s map[string]string
		if err := json.Unmarshal(data, &s); err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"registry_url": "", "username": ""}) //nolint:errcheck
			return
		}
		masked := ""
		if s["credential"] != "" {
			masked = "••••••••"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"registry_url": s["registry_url"],
			"username":     s["username"],
			"credential":   masked,
		})

	case http.MethodPost:
		if !requireRole(w, r, "admin") {
			return
		}
		var incoming map[string]string
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		cred := incoming["credential"]
		// If credential is the masked placeholder, preserve existing.
		if cred == "••••••••" {
			existing, err := os.ReadFile(registrySettingsFile)
			if err == nil {
				var old map[string]string
				if json.Unmarshal(existing, &old) == nil {
					cred = old["credential"]
				}
			}
		}
		save := map[string]string{
			"registry_url": incoming["registry_url"],
			"username":     incoming["username"],
			"credential":   cred,
		}
		out, _ := json.MarshalIndent(save, "", "  ")
		if err := os.WriteFile(registrySettingsFile, out, 0o600); err != nil {
			http.Error(w, "write failed", http.StatusInternalServerError)
			return
		}
		auditEvent(r, "update.registry_settings", "system", "registry settings updated")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "saved"}) //nolint:errcheck

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
