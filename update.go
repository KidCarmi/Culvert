package main

// Docker self-update system — Culvert-side logic.
//
// Communicates with the culvert-updater sidecar (HTTP on :7123) for container
// lifecycle operations. Provides version checking, update API endpoints, and
// the standalone update flow.
//
// See roadmap/docker-system-update.md for full design.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
	pullTag         string // Docker tag to pull (may differ from latestVersion if semver tag missing)
	updateAvailable bool
	lastChecked     time.Time
	updaterStatus   string // "connected", "unavailable", "token_pending"
}

var globalUpdateInfo updateInfo

func (u *updateInfo) snapshot() map[string]any {
	u.mu.RLock()
	defer u.mu.RUnlock()
	pt := u.pullTag
	if pt == "" {
		pt = u.latestVersion
	}
	return map[string]any{
		"current_version":  u.currentVersion,
		"latest_version":   u.latestVersion,
		"pull_tag":         pt,
		"update_available": u.updateAvailable,
		"last_checked":     u.lastChecked.Format(time.RFC3339),
		"updater_status":   u.updaterStatus,
	}
}

// ── Updater client ──────────────────────────────────────────────────────────

var updaterURL = "http://culvert-updater:7123"

// validateUpdaterURL checks that the updater URL uses http/https and does not
// point at a private/internal IP (SSRF guard). Called at startup to reject
// misconfigured or malicious updater URLs from config files.
func validateUpdaterURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported scheme %q (must be http or https)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("empty hostname")
	}
	// Allow Docker internal DNS names (compose service names) — these won't
	// resolve from the host but are valid within a compose network.
	// Only block if the name resolves to a metadata/loopback address.
	if ip := net.ParseIP(host); ip != nil {
		// Bare IP: block metadata endpoint (169.254.169.254) and loopback.
		if ip.IsLoopback() {
			return nil // loopback is expected for local sidecar
		}
		if ip.Equal(net.ParseIP("169.254.169.254")) {
			return fmt.Errorf("metadata endpoint not allowed")
		}
	}
	return nil
}

// updaterToken reads the shared secret from the token file.
func updaterToken() string {
	data, err := os.ReadFile("/data/updater_token.txt")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ensureUpdaterToken generates the token file if it doesn't exist.
// Also verifies the file is readable and non-empty (handles permission/mount issues).
func ensureUpdaterToken() {
	path := "/data/updater_token.txt"
	// Check if token already exists and is readable.
	if data, err := os.ReadFile(path); err == nil {
		if strings.TrimSpace(string(data)) != "" {
			return // valid token exists
		}
		logger.Printf("Update: token file exists but is empty, regenerating")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		logger.Printf("Update: token generation failed: %v", err)
		return
	}
	token := hex.EncodeToString(b)
	// #nosec G306 -- 0644 required: updater sidecar runs with cap_drop:ALL (no DAC_OVERRIDE), so root cannot read 0600 files owned by the proxy user
	if err := os.WriteFile(path, []byte(token+"\n"), 0o644); err != nil {
		logger.Printf("Update: token write failed: %v", err)
		return
	}
	logger.Printf("Update: generated updater token at %s", path)
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
	globalUpdateInfo.currentVersion = cleanSemver(version)
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

	// If the updater is not yet ready (token_pending/unavailable), retry
	// every 15s for up to 3 minutes before falling back to the 6h cycle.
	globalUpdateInfo.mu.RLock()
	status := globalUpdateInfo.updaterStatus
	globalUpdateInfo.mu.RUnlock()
	if status == "token_pending" || status == "unavailable" {
		retryTicker := time.NewTicker(15 * time.Second)
		retryDeadline := time.After(3 * time.Minute)
	retryLoop:
		for {
			select {
			case <-ctx.Done():
				retryTicker.Stop()
				return
			case <-retryDeadline:
				retryTicker.Stop()
				break retryLoop
			case <-retryTicker.C:
				checkUpdateNow()
				globalUpdateInfo.mu.RLock()
				s := globalUpdateInfo.updaterStatus
				globalUpdateInfo.mu.RUnlock()
				if s == "connected" {
					retryTicker.Stop()
					break retryLoop
				}
			}
		}
	}

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

// ── GitHub tag fallback ─────────────────────────────────────────────────────
// When the Docker registry lacks semver tags (a known CI issue for v0.0.16+),
// query the GitHub API for git tags as a fallback. Git tags are always created
// by the auto-tag CI job even when Docker tagging fails.

// ghRepoOwner and ghRepoName identify the GitHub repo for tag queries.
const (
	ghRepoOwner = "KidCarmi"
	ghRepoName  = "Culvert"
)

// semverParts extracts major, minor, patch from a semver string like "v1.2.3".
var semverExtract = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// cleanSemver strips pre-release / git-describe suffixes from a version
// string.  e.g. "v0.0.19-4-g8ac6d14" → "v0.0.19", "v1.2.3-rc1" → "v1.2.3".
// Returns the input unchanged if no hyphen is found.
func cleanSemver(s string) string {
	m := semverExtract.FindString(s)
	if m != "" {
		return m
	}
	return s
}

func parseSemver(s string) (int, int, int, bool) {
	m := semverExtract.FindStringSubmatch(s)
	if len(m) < 4 {
		return 0, 0, 0, false
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	pat, _ := strconv.Atoi(m[3])
	return maj, min, pat, true
}

func semverGreater(a, b string) bool {
	a1, a2, a3, aOK := parseSemver(a)
	b1, b2, b3, bOK := parseSemver(b)
	if !aOK || !bOK {
		return false
	}
	if a1 != b1 {
		return a1 > b1
	}
	if a2 != b2 {
		return a2 > b2
	}
	return a3 > b3
}

// checkGitHubLatestTag queries the GitHub API for the latest semver tag.
// Returns the tag name (e.g. "v0.0.19") or "" on any error.
func checkGitHubLatestTag() string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// GitHub API: list tags sorted by creation date (newest first).
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/tags?per_page=20",
		ghRepoOwner, ghRepoName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Culvert-Update-Checker/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Printf("Update: GitHub tag check failed: %v", err)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}

	var tags []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return ""
	}

	// Find highest semver tag.
	var semverTags []string
	for _, t := range tags {
		if semverExtract.MatchString(t.Name) {
			semverTags = append(semverTags, t.Name)
		}
	}
	if len(semverTags) == 0 {
		return ""
	}
	sort.Slice(semverTags, func(i, j int) bool {
		return semverGreater(semverTags[i], semverTags[j])
	})
	return semverTags[0]
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
		// Log details: the updater can't read the shared token file.
		tok := updaterToken()
		if tok == "" {
			logger.Printf("Update: token_pending — proxy has no token (/data/updater_token.txt missing or empty)")
		} else {
			logger.Printf("Update: token_pending — proxy has token but updater returned 503 (check updater logs)")
		}
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

	// GitHub tag fallback: if the Docker registry reports no newer version,
	// check GitHub git tags. This handles the case where Docker images lack
	// semver tags but git tags exist (a known CI issue for v0.0.16-v0.0.19).
	// When this fallback activates, we tell the updater to pull ":latest"
	// (which IS always updated on ghcr.io) instead of the specific semver tag.
	cleanVer := cleanSemver(version)
	ghFallback := false
	if !result.UpdateAvailable && cleanVer != "dev" {
		if ghLatest := checkGitHubLatestTag(); ghLatest != "" && semverGreater(ghLatest, cleanVer) {
			result.Latest = ghLatest
			result.UpdateAvailable = true
			ghFallback = true
			logger.Printf("Update: Docker registry had no newer semver tag, but GitHub has %s (current: %s)",
				ghLatest, cleanVer)
		}
	}

	// Correct stale registry display: if the Docker registry's highest semver
	// tag is older than what we're currently running (e.g. registry has v0.0.15
	// but we're on v0.0.19 built from source/latest), show current version as
	// latest so the UI doesn't misleadingly display an ancient version.
	if !result.UpdateAvailable && cleanVer != "dev" && result.Latest != "" {
		if semverGreater(cleanVer, cleanSemver(result.Latest)) {
			result.Latest = cleanVer
		}
	}

	globalUpdateInfo.mu.Lock()
	prevLatest := globalUpdateInfo.latestVersion
	globalUpdateInfo.latestVersion = result.Latest
	globalUpdateInfo.updateAvailable = result.UpdateAvailable
	if ghFallback {
		globalUpdateInfo.pullTag = "latest"
	} else if result.Latest != "" {
		globalUpdateInfo.pullTag = result.Latest
	}
	globalUpdateInfo.lastChecked = time.Now()
	globalUpdateInfo.updaterStatus = "connected"
	globalUpdateInfo.mu.Unlock()

	if result.UpdateAvailable && result.Latest != prevLatest {
		go fireAlert("update_available", AlertPayload{
			Detail: fmt.Sprintf("New version available: %s (current: %s)", result.Latest, version),
			Source: "update_checker",
		})
		logger.Printf("Update: available %s -> %s", version, result.Latest)
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

// apiUpdateCheck triggers an immediate version check and waits for the result (U20).
// POST /api/update/check
func apiUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}
	done := make(chan struct{})
	go func() {
		checkUpdateNow()
		close(done)
	}()
	// Wait up to 35s for the check to complete (checkUpdateNow has 30s timeout).
	select {
	case <-done:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(globalUpdateInfo.snapshot()) //nolint:errcheck
	case <-time.After(35 * time.Second):
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "timeout"}) //nolint:errcheck
	case <-r.Context().Done():
		// Client disconnected.
	}
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
	// U6: Validate tag format (OCI tag spec).
	tagRe := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	if !tagRe.MatchString(req.TargetTag) {
		http.Error(w, `{"error":"invalid target_tag format"}`, http.StatusBadRequest)
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
	updateSucceeded := false
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			w.Write(chunk) //nolint:errcheck
			flusher.Flush()
			// Detect successful completion in the SSE stream.
			if bytes.Contains(chunk, []byte(`"step":"complete"`)) {
				updateSucceeded = true
			}
		}
		if err != nil {
			break
		}
	}

	// After proxy update succeeds, trigger updater self-update (fire-and-forget).
	if updateSucceeded {
		go triggerUpdaterSelfUpdate(req.TargetTag)
	}
}

// triggerUpdaterSelfUpdate asks the updater sidecar to update itself to the
// same tag the proxy was just updated to. Fire-and-forget — the updater uses
// a reaper container to restart itself.
func triggerUpdaterSelfUpdate(tag string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	body, _ := json.Marshal(map[string]string{"target_tag": tag})
	resp, err := updaterRequest(ctx, http.MethodPost, "/api/self-update", bytes.NewReader(body))
	if err != nil {
		logger.Printf("Update: updater self-update trigger failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		logger.Printf("Update: updater self-update triggered (tag=%s)", sanitizeLog(tag))
	} else {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		logger.Printf("Update: updater self-update returned HTTP %d: %s", resp.StatusCode, respBody)
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
	io.Copy(w, io.LimitReader(resp.Body, 10<<20)) //nolint:errcheck // U7: limit proxy responses to 10MB
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
	io.Copy(w, io.LimitReader(resp.Body, 10<<20)) //nolint:errcheck // U7: limit proxy responses to 10MB
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
	io.Copy(w, io.LimitReader(resp.Body, 10<<20)) //nolint:errcheck // U7: limit proxy responses to 10MB
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
		regVal := incoming["credential"]
		// S15: If masked placeholder sent back, preserve the existing stored value.
		// Check for any string consisting only of bullet characters to prevent
		// circumvention via different-length mask strings.
		isMasked := regVal != "" && strings.Trim(regVal, "•") == ""
		if isMasked {
			existing, err := os.ReadFile(registrySettingsFile)
			if err == nil {
				var old map[string]string
				if json.Unmarshal(existing, &old) == nil {
					regVal = old["credential"]
				}
			}
		}
		save := map[string]string{
			"registry_url": incoming["registry_url"],
			"username":     incoming["username"],
			"credential":   regVal,
		}
		out, _ := json.MarshalIndent(save, "", "  ")
		// U19: Atomic write via temp+rename to prevent corruption on crash.
		tmp := registrySettingsFile + ".tmp"
		if err := os.WriteFile(tmp, out, 0o600); err != nil {
			http.Error(w, "write failed", http.StatusInternalServerError)
			return
		}
		if err := os.Rename(tmp, registrySettingsFile); err != nil {
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
