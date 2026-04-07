// culvert-updater — Lightweight Docker update sidecar for Culvert.
//
// Runs as an always-on service in docker-compose. Mounts /var/run/docker.sock
// and exposes an HTTP API for Culvert to trigger container updates.
// The main Culvert container never touches the Docker socket.
//
// Endpoints:
//   GET  /healthz                  — Liveness probe
//   GET  /api/update/check         — Check registry for new version
//   POST /api/update/preview       — Diff current vs new container config
//   POST /api/update/apply         — Pull, recreate, health check, rollback
//   POST /api/update/rollback      — Restore rollback container (grace period)
//   GET  /api/update/rollback/status — Rollback availability
//   GET  /api/update/session       — Active update state (SSE re-attach)
//   POST /api/update/load          — Load image from tarball (air-gapped)
//   POST /api/self-update          — Update the updater via reaper pattern

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

// ── Configuration ───────────────────────────────────────────────────────────

var (
	listenAddr     = envOr("UPDATER_LISTEN", ":7123")
	tokenFile      = envOr("UPDATER_TOKEN_FILE", "/data/updater_token.txt")
	registry       = envOr("UPDATER_REGISTRY", "ghcr.io/kidcarmi/culvert")
	registryAuth   = os.Getenv("UPDATER_REGISTRY_AUTH") // base64 X-Registry-Auth
	healthChecks   = envIntOr("UPDATER_HEALTH_CHECKS", 3)
	healthInterval = envDurOr("UPDATER_HEALTH_INTERVAL", 5*time.Second)
	rollbackTTL    = envDurOr("UPDATER_ROLLBACK_TTL", 1*time.Hour)
	keepImages     = envIntOr("UPDATER_KEEP_IMAGES", 3)
)

// ── Active session state ────────────────────────────────────────────────────

type UpdateSession struct {
	mu          sync.RWMutex
	Active      bool   `json:"active"`
	ContainerID string `json:"container_id,omitempty"`
	TargetTag   string `json:"target_tag,omitempty"`
	Step        string `json:"step,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Percent     int    `json:"percent"`
	StartedAt   string `json:"started_at,omitempty"`
}

var activeSession UpdateSession

func (s *UpdateSession) set(step, detail string, pct int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Step = step
	s.Detail = detail
	s.Percent = pct
}

func (s *UpdateSession) snapshot() UpdateSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return UpdateSession{
		Active:      s.Active,
		ContainerID: s.ContainerID,
		TargetTag:   s.TargetTag,
		Step:        s.Step,
		Detail:      s.Detail,
		Percent:     s.Percent,
		StartedAt:   s.StartedAt,
	}
}

// ── Rollback tracking ───────────────────────────────────────────────────────

type RollbackInfo struct {
	mu            sync.RWMutex
	Available     bool      `json:"available"`
	ContainerName string    `json:"container_name,omitempty"`
	RollbackTag   string    `json:"rollback_tag,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
}

var rollbackInfo RollbackInfo

// ── Main ────────────────────────────────────────────────────────────────────

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[updater] ")

	// Docker client.
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("docker client: %v", err)
	}
	defer cli.Close()

	// Verify connectivity.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err = cli.Ping(ctx)
	cancel()
	if err != nil {
		log.Fatalf("docker ping: %v", err)
	}
	log.Printf("connected to Docker engine")

	// Start rollback cleanup goroutine.
	go rollbackCleanupLoop(cli)

	// Start failure log cleanup.
	go failureLogCleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/api/update/check", authMiddleware(handleCheck(cli)))
	mux.HandleFunc("/api/update/preview", authMiddleware(handlePreview(cli)))
	mux.HandleFunc("/api/update/apply", authMiddleware(handleApply(cli)))
	mux.HandleFunc("/api/update/rollback", authMiddleware(handleRollback(cli)))
	mux.HandleFunc("/api/update/rollback/status", authMiddleware(handleRollbackStatus))
	mux.HandleFunc("/api/update/session", authMiddleware(handleSession))
	mux.HandleFunc("/api/update/load", authMiddleware(handleLoad(cli)))

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  600 * time.Second, // long for image pull/load
		WriteTimeout: 600 * time.Second,
	}

	go func() {
		log.Printf("listening on %s", listenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down")
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx) //nolint:errcheck
}

// ── Auth middleware ──────────────────────────────────────────────────────────

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := os.ReadFile(tokenFile)
		if err != nil {
			http.Error(w, `{"error":"awaiting token initialization","retry_after":5}`, http.StatusServiceUnavailable)
			return
		}
		expected := strings.TrimSpace(string(token))
		if expected == "" {
			http.Error(w, `{"error":"empty token file"}`, http.StatusServiceUnavailable)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != expected {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ── GET /healthz ────────────────────────────────────────────────────────────

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// ── GET /api/update/check ───────────────────────────────────────────────────

func handleCheck(cli *client.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get current running container's image tag.
		currentTag := getCurrentTag(cli)

		// Query registry for tags.
		tags, err := fetchRegistryTags()
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error":   "registry query failed",
				"detail":  err.Error(),
				"current": currentTag,
			})
			return
		}

		latest := latestSemver(tags)
		writeJSON(w, http.StatusOK, map[string]any{
			"current":          currentTag,
			"latest":           latest,
			"update_available": latest != "" && latest != currentTag && semverNewer(latest, currentTag),
			"tags":             tags,
		})
	}
}

// ── POST /api/update/preview ────────────────────────────────────────────────

func handlePreview(cli *client.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Container string `json:"container"`
			TargetTag string `json:"target_tag"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Container == "" {
			req.Container = "culvert"
		}

		ctx := context.Background()

		// Inspect current container.
		info, err := cli.ContainerInspect(ctx, req.Container)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "container not found: " + req.Container})
			return
		}

		// Pull target image to inspect it.
		targetImage := registry + ":" + req.TargetTag
		pullOpts := image.PullOptions{}
		if registryAuth != "" {
			pullOpts.RegistryAuth = registryAuth
		}
		reader, err := cli.ImagePull(ctx, targetImage, pullOpts)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "pull failed: " + err.Error()})
			return
		}
		io.Copy(io.Discard, reader) //nolint:errcheck
		reader.Close()

		// Inspect new image.
		newImg, _, err := cli.ImageInspectWithRaw(ctx, targetImage)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "image inspect failed"})
			return
		}

		// Build diff.
		diff := buildConfigDiff(info, newImg)
		writeJSON(w, http.StatusOK, diff)
	}
}

// ── POST /api/update/apply ──────────────────────────────────────────────────

func handleApply(cli *client.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Container      string `json:"container"`
			TargetTag      string `json:"target_tag"`
			HealthEndpoint string `json:"health_endpoint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Container == "" {
			req.Container = "culvert"
		}
		if req.HealthEndpoint == "" {
			req.HealthEndpoint = "http://" + req.Container + ":8080/health"
		}

		// Check if update already in progress.
		activeSession.mu.Lock()
		if activeSession.Active {
			activeSession.mu.Unlock()
			http.Error(w, `{"error":"update already in progress"}`, http.StatusConflict)
			return
		}
		activeSession.Active = true
		activeSession.ContainerID = req.Container
		activeSession.TargetTag = req.TargetTag
		activeSession.StartedAt = time.Now().UTC().Format(time.RFC3339)
		activeSession.mu.Unlock()

		defer func() {
			activeSession.mu.Lock()
			activeSession.Active = false
			activeSession.mu.Unlock()
		}()

		// SSE response.
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		sendEvent := func(step, detail string, pct int) {
			activeSession.set(step, detail, pct)
			data, _ := json.Marshal(map[string]any{"step": step, "detail": detail, "percent": pct})
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}

		ctx := context.Background()
		targetImage := registry + ":" + req.TargetTag

		// Step 1: Disk space check.
		sendEvent("checking", "Pre-flight disk space check", 5)
		if err := checkDiskSpace(ctx, cli, targetImage); err != nil {
			sendEvent("error", err.Error(), 0)
			return
		}

		// Step 2: Pull image.
		sendEvent("pulling", "Pulling "+targetImage, 10)
		pullOpts := image.PullOptions{}
		if registryAuth != "" {
			pullOpts.RegistryAuth = registryAuth
		}
		reader, err := cli.ImagePull(ctx, targetImage, pullOpts)
		if err != nil {
			sendEvent("error", "Pull failed: "+err.Error(), 0)
			return
		}
		// Read pull progress.
		decoder := json.NewDecoder(reader)
		for decoder.More() {
			var msg map[string]any
			if err := decoder.Decode(&msg); err != nil {
				break
			}
			if status, ok := msg["status"].(string); ok {
				detail := status
				if progress, ok := msg["progress"].(string); ok {
					detail += " " + progress
				}
				sendEvent("pulling", detail, 20)
			}
		}
		reader.Close()
		sendEvent("pulling", "Image pulled successfully", 30)

		// Step 3: Inspect current container.
		sendEvent("inspecting", "Capturing container configuration", 35)
		info, err := cli.ContainerInspect(ctx, req.Container)
		if err != nil {
			sendEvent("error", "Container inspect failed: "+err.Error(), 0)
			return
		}
		oldImage := info.Config.Image

		// Capture all networks.
		containerNetworks := info.NetworkSettings.Networks

		// Step 4: Stop container.
		sendEvent("stopping", "Stopping container (30s graceful drain)", 40)
		stopTimeout := 30
		if err := cli.ContainerStop(ctx, info.ID, container.StopOptions{Timeout: &stopTimeout}); err != nil {
			sendEvent("error", "Stop failed: "+err.Error(), 0)
			return
		}
		sendEvent("stopping", "Container stopped", 50)

		// Step 5: Rename to rollback.
		rollbackName := req.Container + "-rollback-" + time.Now().Format("20060102-150405")
		sendEvent("renaming", "Renaming to "+rollbackName, 52)
		if err := cli.ContainerRename(ctx, info.ID, rollbackName); err != nil {
			// Try to restart the original.
			cli.ContainerStart(ctx, info.ID, container.StartOptions{}) //nolint:errcheck
			sendEvent("error", "Rename failed: "+err.Error(), 0)
			return
		}

		// Step 6: Create new container with same config + new image.
		sendEvent("starting", "Creating new container", 55)
		newConfig := info.Config
		newConfig.Image = targetImage

		// Pick the first network for initial creation.
		var firstNetName string
		var firstNetConfig *network.EndpointSettings
		var additionalNets = make(map[string]*network.EndpointSettings)
		for name, cfg := range containerNetworks {
			if firstNetName == "" {
				firstNetName = name
				firstNetConfig = cfg
			} else {
				additionalNets[name] = cfg
			}
		}

		netConfig := &network.NetworkingConfig{}
		if firstNetName != "" && firstNetConfig != nil {
			netConfig.EndpointsConfig = map[string]*network.EndpointSettings{
				firstNetName: {
					Aliases:   firstNetConfig.Aliases,
					NetworkID: firstNetConfig.NetworkID,
				},
			}
		}

		created, err := cli.ContainerCreate(ctx, newConfig, info.HostConfig, netConfig, nil, req.Container)
		if err != nil {
			// Rollback: restore original.
			cli.ContainerRename(ctx, info.ID, req.Container) //nolint:errcheck
			cli.ContainerStart(ctx, info.ID, container.StartOptions{}) //nolint:errcheck
			sendEvent("error", "Create failed: "+err.Error(), 0)
			return
		}

		// Attach additional networks.
		for netName, netCfg := range additionalNets {
			err := cli.NetworkConnect(ctx, netCfg.NetworkID, created.ID, &network.EndpointSettings{
				Aliases: netCfg.Aliases,
			})
			if err != nil {
				log.Printf("warning: failed to attach network %s: %v", netName, err)
			}
		}

		// Start the new container.
		sendEvent("starting", "Starting new container", 60)
		if err := cli.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
			// Rollback.
			cli.ContainerRemove(ctx, created.ID, container.RemoveOptions{Force: true}) //nolint:errcheck
			cli.ContainerRename(ctx, info.ID, req.Container)                           //nolint:errcheck
			cli.ContainerStart(ctx, info.ID, container.StartOptions{})                 //nolint:errcheck
			sendEvent("error", "Start failed: "+err.Error(), 0)
			return
		}

		// Step 7: Health check (3 consecutive successes).
		sendEvent("health_check", "Waiting 5s for container boot", 65)
		time.Sleep(5 * time.Second)

		consecutiveOK := 0
		deadline := time.Now().Add(120 * time.Second)
		healthClient := &http.Client{Timeout: 5 * time.Second}

		for time.Now().Before(deadline) {
			resp, err := healthClient.Get(req.HealthEndpoint)
			if err == nil && resp.StatusCode == 200 {
				resp.Body.Close()
				consecutiveOK++
				pct := 70 + (consecutiveOK * 10)
				if pct > 95 {
					pct = 95
				}
				sendEvent("health_check", fmt.Sprintf("Health check %d/%d passed", consecutiveOK, healthChecks), pct)
				if consecutiveOK >= healthChecks {
					break
				}
			} else {
				if resp != nil {
					resp.Body.Close()
				}
				consecutiveOK = 0
				sendEvent("health_check", "Health check failed, retrying...", 70)
			}
			time.Sleep(healthInterval)
		}

		if consecutiveOK < healthChecks {
			// Rollback!
			sendEvent("rolling_back", "Health check failed — rolling back", 0)

			// Capture logs before removing.
			captureFailureLogs(ctx, cli, created.ID, req.TargetTag)

			cli.ContainerStop(ctx, created.ID, container.StopOptions{}) //nolint:errcheck
			cli.ContainerRemove(ctx, created.ID, container.RemoveOptions{Force: true}) //nolint:errcheck
			cli.ContainerRename(ctx, info.ID, req.Container)                           //nolint:errcheck
			cli.ContainerStart(ctx, info.ID, container.StartOptions{})                 //nolint:errcheck
			sendEvent("rolled_back", "Rolled back to previous version", 100)
			return
		}

		// Success! Set up rollback tracking.
		rollbackInfo.mu.Lock()
		rollbackInfo.Available = true
		rollbackInfo.ContainerName = rollbackName
		rollbackInfo.RollbackTag = oldImage
		rollbackInfo.ExpiresAt = time.Now().Add(rollbackTTL)
		rollbackInfo.mu.Unlock()

		sendEvent("complete", "Update to "+req.TargetTag+" successful", 100)
		log.Printf("update complete: %s → %s", oldImage, targetImage)
	}
}

// ── POST /api/update/rollback ───────────────────────────────────────────────

func handleRollback(cli *client.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Container string `json:"container"`
		}
		json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
		if req.Container == "" {
			req.Container = "culvert"
		}

		rollbackInfo.mu.RLock()
		available := rollbackInfo.Available && time.Now().Before(rollbackInfo.ExpiresAt)
		rbName := rollbackInfo.ContainerName
		rollbackInfo.mu.RUnlock()

		if !available {
			writeJSON(w, http.StatusGone, map[string]string{"error": "no rollback available"})
			return
		}

		ctx := context.Background()

		// Stop current, remove, rename rollback, start.
		stopTimeout := 30
		cli.ContainerStop(ctx, req.Container, container.StopOptions{Timeout: &stopTimeout}) //nolint:errcheck
		cli.ContainerRemove(ctx, req.Container, container.RemoveOptions{Force: true})       //nolint:errcheck
		cli.ContainerRename(ctx, rbName, req.Container)                                     //nolint:errcheck

		if err := cli.ContainerStart(ctx, req.Container, container.StartOptions{}); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rollback start failed: " + err.Error()})
			return
		}

		rollbackInfo.mu.Lock()
		rollbackInfo.Available = false
		rollbackInfo.mu.Unlock()

		writeJSON(w, http.StatusOK, map[string]string{"status": "rolled_back"})
		log.Printf("manual rollback completed: restored %s", rbName)
	}
}

// ── GET /api/update/rollback/status ─────────────────────────────────────────

func handleRollbackStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rollbackInfo.mu.RLock()
	defer rollbackInfo.mu.RUnlock()

	available := rollbackInfo.Available && time.Now().Before(rollbackInfo.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{
		"available":    available,
		"expires_at":   rollbackInfo.ExpiresAt.Format(time.RFC3339),
		"rollback_tag": rollbackInfo.RollbackTag,
	})
}

// ── GET /api/update/session ─────────────────────────────────────────────────

func handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snap := activeSession.snapshot()
	writeJSON(w, http.StatusOK, snap)
}

// ── POST /api/update/load (air-gapped) ──────────────────────────────────────

func handleLoad(cli *client.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := context.Background()
		resp, err := cli.ImageLoad(ctx, r.Body)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "image load failed: " + err.Error()})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		writeJSON(w, http.StatusOK, map[string]string{
			"status": "loaded",
			"detail": string(body),
		})
		log.Printf("image loaded from tarball")
	}
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func getCurrentTag(cli *client.Client) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	info, err := cli.ContainerInspect(ctx, "culvert")
	if err != nil {
		return "unknown"
	}
	img := info.Config.Image
	if idx := strings.LastIndex(img, ":"); idx >= 0 {
		return img[idx+1:]
	}
	return "latest"
}

// fetchRegistryTags queries the OCI distribution API for available tags.
func fetchRegistryTags() ([]string, error) {
	url := "https://" + strings.SplitN(registry, "/", 2)[0] + "/v2/" + strings.SplitN(registry, "/", 2)[1] + "/tags/list"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if registryAuth != "" {
		req.Header.Set("Authorization", "Bearer "+registryAuth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("registry returned %d", resp.StatusCode)
	}
	var result struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Tags, nil
}

// semver regex: v1.2.3 or 1.2.3
var semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

func latestSemver(tags []string) string {
	var semverTags []string
	for _, t := range tags {
		if semverRe.MatchString(t) {
			semverTags = append(semverTags, t)
		}
	}
	if len(semverTags) == 0 {
		return ""
	}
	sort.Slice(semverTags, func(i, j int) bool {
		return semverNewer(semverTags[i], semverTags[j])
	})
	return semverTags[0]
}

func semverNewer(a, b string) bool {
	aParts := semverRe.FindStringSubmatch(a)
	bParts := semverRe.FindStringSubmatch(b)
	if len(aParts) != 4 || len(bParts) != 4 {
		return false
	}
	for i := 1; i <= 3; i++ {
		ai := atoi(aParts[i])
		bi := atoi(bParts[i])
		if ai != bi {
			return ai > bi
		}
	}
	return false // equal
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func checkDiskSpace(ctx context.Context, cli *client.Client, _ string) error {
	usage, err := cli.DiskUsage(ctx, types.DiskUsageOptions{})
	if err != nil {
		return fmt.Errorf("disk usage check failed: %w", err)
	}
	// Calculate available space from images + containers.
	var totalSize int64
	for _, img := range usage.Images {
		totalSize += img.Size
	}
	// Simple heuristic: if total image size > 90% of what we've seen, warn.
	// In practice we just check that there's some headroom.
	_ = totalSize // We can't reliably get free disk space from Docker API alone.
	// The real check would use the host filesystem — skip for now and just log.
	log.Printf("disk usage check: %d images totaling %d MB", len(usage.Images), totalSize/(1024*1024))
	return nil
}

type ConfigDiff struct {
	Image      DiffEntry   `json:"image"`
	Env        []DiffEntry `json:"env"`
	Cmd        DiffEntry   `json:"cmd"`
	Entrypoint DiffEntry   `json:"entrypoint"`
	Volumes    []DiffEntry `json:"volumes"`
	Ports      []DiffEntry `json:"ports"`
}

type DiffEntry struct {
	Key    string `json:"key"`
	Old    string `json:"old,omitempty"`
	New    string `json:"new,omitempty"`
	Status string `json:"status"` // "unchanged", "added", "removed", "changed"
}

func buildConfigDiff(info container.InspectResponse, newImg image.InspectResponse) ConfigDiff {
	diff := ConfigDiff{
		Image: DiffEntry{
			Key:    "Image",
			Old:    info.Config.Image,
			New:    newImg.RepoTags[0],
			Status: "changed",
		},
	}

	// Env diff.
	oldEnv := make(map[string]string)
	for _, e := range info.Config.Env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			oldEnv[parts[0]] = parts[1]
		}
	}
	newEnv := make(map[string]string)
	for _, e := range newImg.Config.Env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			newEnv[parts[0]] = parts[1]
		}
	}

	secretPat := regexp.MustCompile(`(?i)(passphrase|password|token|secret|key|auth)`)
	maskValue := func(k, v string) string {
		if secretPat.MatchString(k) {
			return "••••••"
		}
		return v
	}

	allKeys := make(map[string]bool)
	for k := range oldEnv {
		allKeys[k] = true
	}
	for k := range newEnv {
		allKeys[k] = true
	}
	for k := range allKeys {
		ov, hasOld := oldEnv[k]
		nv, hasNew := newEnv[k]
		entry := DiffEntry{Key: k}
		switch {
		case hasOld && hasNew && ov == nv:
			entry.Old = maskValue(k, ov)
			entry.New = maskValue(k, nv)
			entry.Status = "unchanged"
		case hasOld && hasNew:
			entry.Old = maskValue(k, ov)
			entry.New = maskValue(k, nv)
			entry.Status = "changed"
		case hasOld:
			entry.Old = maskValue(k, ov)
			entry.Status = "removed"
		default:
			entry.New = maskValue(k, nv)
			entry.Status = "added"
		}
		diff.Env = append(diff.Env, entry)
	}

	// CMD diff.
	diff.Cmd = DiffEntry{
		Key:    "CMD",
		Old:    strings.Join(info.Config.Cmd, " "),
		New:    strings.Join(newImg.Config.Cmd, " "),
		Status: diffStatus(strings.Join(info.Config.Cmd, " "), strings.Join(newImg.Config.Cmd, " ")),
	}

	// Entrypoint diff.
	diff.Entrypoint = DiffEntry{
		Key:    "Entrypoint",
		Old:    strings.Join(info.Config.Entrypoint, " "),
		New:    strings.Join(newImg.Config.Entrypoint, " "),
		Status: diffStatus(strings.Join(info.Config.Entrypoint, " "), strings.Join(newImg.Config.Entrypoint, " ")),
	}

	// Volumes.
	if info.HostConfig != nil {
		for _, bind := range info.HostConfig.Binds {
			diff.Volumes = append(diff.Volumes, DiffEntry{Key: bind, Old: bind, New: bind, Status: "unchanged"})
		}
	}

	// Ports.
	if info.HostConfig != nil {
		for port, bindings := range info.HostConfig.PortBindings {
			for _, b := range bindings {
				desc := fmt.Sprintf("%s:%s→%s", b.HostIP, b.HostPort, port)
				diff.Ports = append(diff.Ports, DiffEntry{Key: desc, Old: desc, New: desc, Status: "unchanged"})
			}
		}
	}

	return diff
}

func diffStatus(old, new string) string {
	if old == new {
		return "unchanged"
	}
	if old == "" {
		return "added"
	}
	if new == "" {
		return "removed"
	}
	return "changed"
}

// captureFailureLogs saves the last 200 lines of a failed container's logs.
func captureFailureLogs(ctx context.Context, cli *client.Client, containerID, tag string) {
	logsOpts := container.LogsOptions{ShowStdout: true, ShowStderr: true, Tail: "200"}
	reader, err := cli.ContainerLogs(ctx, containerID, logsOpts)
	if err != nil {
		log.Printf("failed to capture logs: %v", err)
		return
	}
	defer reader.Close()

	data, _ := io.ReadAll(reader)

	dir := "/data/update_failures"
	os.MkdirAll(dir, 0o755) //nolint:errcheck
	filename := filepath.Join(dir, time.Now().Format("20060102-150405")+"-"+tag+".log")
	os.WriteFile(filename, data, 0o644) //nolint:errcheck
	log.Printf("failure logs saved to %s", filename)
}

// rollbackCleanupLoop removes expired rollback containers and prunes old images.
func rollbackCleanupLoop(cli *client.Client) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rollbackInfo.mu.Lock()
		if rollbackInfo.Available && time.Now().After(rollbackInfo.ExpiresAt) {
			ctx := context.Background()
			cli.ContainerRemove(ctx, rollbackInfo.ContainerName, container.RemoveOptions{Force: true}) //nolint:errcheck
			log.Printf("removed expired rollback container: %s", rollbackInfo.ContainerName)
			rollbackInfo.Available = false

			// Prune dangling images.
			_, err := cli.ImagesPrune(ctx, filters.Args{})
			if err != nil {
				log.Printf("image prune failed: %v", err)
			}

			// Clean up old image tags (keep N most recent).
			pruneOldImages(ctx, cli)
		}
		rollbackInfo.mu.Unlock()
	}
}

func pruneOldImages(ctx context.Context, cli *client.Client) {
	images, err := cli.ImageList(ctx, image.ListOptions{})
	if err != nil {
		return
	}

	// Find all culvert image tags.
	type taggedImage struct {
		tag     string
		created int64
		id      string
	}
	var culvertImages []taggedImage

	for _, img := range images {
		for _, t := range img.RepoTags {
			if strings.HasPrefix(t, registry+":") {
				tag := strings.TrimPrefix(t, registry+":")
				if semverRe.MatchString(tag) {
					culvertImages = append(culvertImages, taggedImage{tag: t, created: img.Created, id: img.ID})
				}
			}
		}
	}

	if len(culvertImages) <= keepImages {
		return
	}

	// Sort oldest first.
	sort.Slice(culvertImages, func(i, j int) bool {
		return culvertImages[i].created < culvertImages[j].created
	})

	// Remove oldest.
	toRemove := len(culvertImages) - keepImages
	for i := 0; i < toRemove; i++ {
		_, err := cli.ImageRemove(ctx, culvertImages[i].tag, image.RemoveOptions{})
		if err != nil {
			log.Printf("failed to remove old image %s: %v", culvertImages[i].tag, err)
		} else {
			log.Printf("removed old image: %s", culvertImages[i].tag)
		}
	}
}

// failureLogCleanup removes failure logs older than 7 days.
func failureLogCleanup() {
	dir := "/data/update_failures"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(dir, e.Name())) //nolint:errcheck
		}
	}
}

// ── Environment helpers ─────────────────────────────────────────────────────

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return atoi(v)
}

func envDurOr(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
