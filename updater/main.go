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
	"crypto/subtle"
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

// tagRe validates OCI-compliant image tags: alphanumeric start, up to 128 chars.
var tagRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

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
	soakDuration   = envDurOr("UPDATER_SOAK_DURATION", 60*time.Second)
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

// rollbackInfoFile persists rollback metadata across updater restarts.
// This allows the proxy's rollback window to survive an updater self-update.
//
// Lives in /state (writable volume) — /data is mounted read-only because
// only the proxy is the source of truth for shared updater token + audit data.
const rollbackInfoFile = "/state/rollback.json"

// saveRollbackInfo writes current rollback state to disk.
func saveRollbackInfo() {
	rollbackInfo.mu.RLock()
	data, err := json.Marshal(map[string]any{
		"available":      rollbackInfo.Available,
		"container_name": rollbackInfo.ContainerName,
		"rollback_tag":   rollbackInfo.RollbackTag,
		"expires_at":     rollbackInfo.ExpiresAt,
	})
	rollbackInfo.mu.RUnlock()
	if err != nil {
		return
	}
	// Ensure parent directory exists (state volume should provide it, but be
	// defensive for fresh installs that haven't mounted /state yet).
	if err := os.MkdirAll(filepath.Dir(rollbackInfoFile), 0755); err != nil {
		log.Printf("save rollback info: mkdir: %v", err)
		return
	}
	tmp := rollbackInfoFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil { //nolint:gosec // not secret data
		log.Printf("save rollback info: %v", err)
		return
	}
	os.Rename(tmp, rollbackInfoFile) //nolint:errcheck
}

// loadRollbackInfo restores rollback state from disk on startup.
func loadRollbackInfo() {
	data, err := os.ReadFile(rollbackInfoFile)
	if err != nil {
		return // no file = no prior rollback state
	}
	var info struct {
		Available     bool      `json:"available"`
		ContainerName string    `json:"container_name"`
		RollbackTag   string    `json:"rollback_tag"`
		ExpiresAt     time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &info); err != nil {
		log.Printf("load rollback info: %v", err)
		return
	}
	// Only restore if not expired.
	if info.Available && time.Now().Before(info.ExpiresAt) {
		rollbackInfo.mu.Lock()
		rollbackInfo.Available = info.Available
		rollbackInfo.ContainerName = info.ContainerName
		rollbackInfo.RollbackTag = info.RollbackTag
		rollbackInfo.ExpiresAt = info.ExpiresAt
		rollbackInfo.mu.Unlock()
		log.Printf("restored rollback info: %s (expires %s)", info.ContainerName, info.ExpiresAt.Format(time.RFC3339))
	} else {
		// Expired — clean up the file.
		os.Remove(rollbackInfoFile) //nolint:errcheck
	}
}

// clearRollbackInfo removes the persisted rollback state.
func clearRollbackInfo() {
	os.Remove(rollbackInfoFile) //nolint:errcheck
}

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

	// Restore rollback info from disk (survives updater self-update restart).
	loadRollbackInfo()

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
	mux.HandleFunc("/api/self-update", authMiddleware(handleSelfUpdate(cli)))

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
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		// U5: constant-time comparison to prevent timing side-channel attacks.
		provided := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
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
			"update_available": latest != "" && cleanSemver(latest) != cleanSemver(currentTag) && semverNewer(latest, currentTag),
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
		// U6: Validate tag format before using in Docker API calls.
		if req.TargetTag == "" || !tagRe.MatchString(req.TargetTag) {
			http.Error(w, `{"error":"invalid target_tag format"}`, http.StatusBadRequest)
			return
		}

		// U4: Use request context so client disconnect cancels the operation.
		ctx := r.Context()

		// Inspect current container.
		info, err := cli.ContainerInspect(ctx, req.Container)
		if err != nil {
			// U8: Don't leak internal error details in HTTP response.
			log.Printf("container inspect failed for %s: %v", req.Container, err)
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "container not found"})
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
			// U8: Don't leak internal error details in HTTP response.
			log.Printf("image pull failed for %s: %v", targetImage, err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "image pull failed"})
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
		// U6: Validate tag format.
		if req.TargetTag == "" || !tagRe.MatchString(req.TargetTag) {
			http.Error(w, `{"error":"invalid target_tag format"}`, http.StatusBadRequest)
			return
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

		// U12: Use a background context for the update operation (must survive
		// client disconnect since the container gets recreated), but log disconnects.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
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
		saveRollbackInfo()

		sendEvent("complete", "Update to "+req.TargetTag+" successful", 100)
		log.Printf("update complete: %s → %s", oldImage, targetImage)

		// Post-update soak monitor: watch the container for soakDuration after
		// health checks pass. If it exits during the soak window, auto-rollback.
		// This catches containers that start and pass health checks but crash
		// shortly after (e.g. bad image, missing config, runtime errors).
		go soakMonitor(cli, req.Container, rollbackName, oldImage, targetImage)
	}
}

// soakMonitor watches a container after a successful update. If the container
// exits within the soak window (default 60s), it automatically rolls back to
// the previous version. This catches containers that pass health checks but
// crash shortly after (bad image, missing env vars, runtime panics).
func soakMonitor(cli *client.Client, containerName, rollbackName, oldImage, newImage string) {
	ctx := context.Background()
	checkInterval := 5 * time.Second
	deadline := time.Now().Add(soakDuration)

	log.Printf("soak monitor: watching %s for %s", containerName, soakDuration)

	for time.Now().Before(deadline) {
		time.Sleep(checkInterval)

		info, err := cli.ContainerInspect(ctx, containerName)
		if err != nil {
			// Container was removed (manual intervention) — stop monitoring.
			log.Printf("soak monitor: container %s gone, stopping watch", containerName)
			return
		}

		if !info.State.Running {
			log.Printf("soak monitor: container %s exited (code=%d) during soak — auto-rolling back",
				containerName, info.State.ExitCode)

			// Auto-rollback: stop failed container, restore rollback.
			rollbackInfo.mu.RLock()
			rbAvailable := rollbackInfo.Available
			rollbackInfo.mu.RUnlock()

			if !rbAvailable {
				log.Printf("soak monitor: rollback no longer available, cannot auto-rollback")
				return
			}

			stopTimeout := 10
			cli.ContainerStop(ctx, containerName, container.StopOptions{Timeout: &stopTimeout}) //nolint:errcheck — may already be stopped
			if err := cli.ContainerRemove(ctx, containerName, container.RemoveOptions{Force: true}); err != nil {
				log.Printf("soak monitor: remove %s failed: %v", containerName, err)
			}
			if err := cli.ContainerRename(ctx, rollbackName, containerName); err != nil {
				log.Printf("soak monitor: rename %s → %s failed: %v — cannot auto-rollback", rollbackName, containerName, err)
				return
			}

			if err := cli.ContainerStart(ctx, containerName, container.StartOptions{}); err != nil {
				log.Printf("soak monitor: auto-rollback start failed: %v", err)
				return
			}

			rollbackInfo.mu.Lock()
			rollbackInfo.Available = false
			rollbackInfo.mu.Unlock()
			clearRollbackInfo()

			log.Printf("soak monitor: auto-rollback complete — restored %s (%s)", containerName, oldImage)
			return
		}
	}

	log.Printf("soak monitor: %s stable for %s, soak complete", containerName, soakDuration)
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

		// Guard against concurrent operations (update or rollback already running).
		activeSession.mu.Lock()
		if activeSession.Active {
			activeSession.mu.Unlock()
			writeJSON(w, http.StatusConflict, map[string]string{"error": "operation already in progress"})
			return
		}
		activeSession.Active = true
		activeSession.mu.Unlock()
		defer func() {
			activeSession.mu.Lock()
			activeSession.Active = false
			activeSession.mu.Unlock()
		}()

		rollbackInfo.mu.RLock()
		available := rollbackInfo.Available && time.Now().Before(rollbackInfo.ExpiresAt)
		rbName := rollbackInfo.ContainerName
		rollbackInfo.mu.RUnlock()

		if !available {
			writeJSON(w, http.StatusGone, map[string]string{"error": "no rollback available"})
			return
		}

		// Use background context — rollback must complete even if the HTTP
		// client disconnects (browser tab close, SSE drop, etc.).
		// Previously used r.Context() which cancelled Docker ops on disconnect.
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		// Stop current, remove, rename rollback, start.
		// Each step is checked — partial failure leaves the system in an
		// inconsistent state (container name mismatch), so bail early.
		stopTimeout := 30
		cli.ContainerStop(ctx, req.Container, container.StopOptions{Timeout: &stopTimeout}) //nolint:errcheck — may already be stopped
		if err := cli.ContainerRemove(ctx, req.Container, container.RemoveOptions{Force: true}); err != nil {
			log.Printf("rollback: remove %s failed: %v (trying rename anyway)", req.Container, err)
		}
		if err := cli.ContainerRename(ctx, rbName, req.Container); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": fmt.Sprintf("rollback rename failed: %v — manual recovery: docker rename %s %s && docker start %s",
					err, rbName, req.Container, req.Container),
			})
			return
		}

		if err := cli.ContainerStart(ctx, req.Container, container.StartOptions{}); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rollback start failed: " + err.Error()})
			return
		}

		rollbackInfo.mu.Lock()
		rollbackInfo.Available = false
		rollbackInfo.mu.Unlock()
		clearRollbackInfo()

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

		// U2: Limit upload size to 5GB to prevent disk exhaustion.
		const maxLoadSize = 5 * 1024 * 1024 * 1024 // 5GB
		r.Body = http.MaxBytesReader(w, r.Body, maxLoadSize)
		ctx := r.Context()
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
	// Prefer the version file written by the proxy on startup — this works
	// even for local docker-compose builds where the image tag is "latest".
	if data, err := os.ReadFile("/data/version.txt"); err == nil {
		if v := strings.TrimSpace(string(data)); v != "" && v != "dev" {
			return v
		}
	}

	// Fall back to Docker image tag inspection.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	info, err := cli.ContainerInspect(ctx, "culvert")
	if err != nil {
		return "unknown"
	}
	img := info.Config.Image
	if idx := strings.LastIndex(img, ":"); idx >= 0 {
		tag := img[idx+1:]
		if tag != "latest" && tag != "" {
			return tag
		}
	}

	// Last resort: check container labels (set by docker/metadata-action in CI).
	for _, key := range []string{"org.opencontainers.image.version"} {
		if v, ok := info.Config.Labels[key]; ok && v != "" {
			return v
		}
	}
	return "latest"
}

// fetchRegistryTags queries the OCI distribution API for available tags.
// Handles the Docker registry v2 OAuth2 token exchange (required by ghcr.io
// even for public repositories).
func fetchRegistryTags() ([]string, error) {
	parts := strings.SplitN(registry, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid registry format: %s", registry)
	}
	host, repo := parts[0], parts[1]
	tagsURL := "https://" + host + "/v2/" + repo + "/tags/list"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// If explicit auth is configured, try it directly first.
	token := registryAuth
	if token == "" {
		// Obtain a bearer token via the registry's token endpoint.
		// Step 1: Probe /v2/ to get the Www-Authenticate challenge.
		var err error
		token, err = fetchRegistryToken(ctx, host, repo)
		if err != nil {
			return nil, fmt.Errorf("registry auth: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tagsURL, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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

// fetchRegistryToken obtains a bearer token from a Docker v2 registry.
// It probes /v2/ to discover the token endpoint from the Www-Authenticate
// header, then requests a pull-scoped token for the given repository.
func fetchRegistryToken(ctx context.Context, host, repo string) (string, error) {
	// Probe /v2/ to get the auth challenge.
	probeURL := "https://" + host + "/v2/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		// No auth required — unusual but handle gracefully.
		return "", nil
	}

	// Parse Www-Authenticate: Bearer realm="...",service="...",scope="..."
	authHeader := resp.Header.Get("Www-Authenticate")
	if authHeader == "" {
		return "", fmt.Errorf("no Www-Authenticate header from %s", host)
	}

	realm := extractAuthParam(authHeader, "realm")
	service := extractAuthParam(authHeader, "service")
	if realm == "" {
		return "", fmt.Errorf("no realm in Www-Authenticate: %s", authHeader)
	}

	// Request a token with pull scope for our repository.
	tokenURL := realm + "?service=" + service + "&scope=repository:" + repo + ":pull"
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}
	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 200 {
		return "", fmt.Errorf("token endpoint returned %d", tokenResp.StatusCode)
	}

	var tokenResult struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"` // some registries use this field
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenResult); err != nil {
		return "", fmt.Errorf("token decode: %w", err)
	}
	if tokenResult.Token != "" {
		return tokenResult.Token, nil
	}
	return tokenResult.AccessToken, nil
}

// extractAuthParam extracts a parameter value from a Www-Authenticate header.
// Example: Bearer realm="https://ghcr.io/token",service="ghcr.io"
func extractAuthParam(header, param string) string {
	key := param + "=\""
	idx := strings.Index(header, key)
	if idx < 0 {
		return ""
	}
	start := idx + len(key)
	end := strings.Index(header[start:], "\"")
	if end < 0 {
		return ""
	}
	return header[start : start+end]
}

// semver regex: v1.2.3 or 1.2.3
var semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// cleanSemver strips pre-release suffixes (e.g. "-dirty", "-rc1") for comparison.
func cleanSemver(s string) string {
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		return s[:idx]
	}
	return s
}

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
	aParts := semverRe.FindStringSubmatch(cleanSemver(a))
	bParts := semverRe.FindStringSubmatch(cleanSemver(b))
	if len(aParts) < 4 || len(bParts) < 4 {
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

// minDiskSpaceMB is the minimum free disk space (MB) required to proceed with
// an update. Docker image pulls can be 100-500 MB; 500 MB gives safe headroom.
const minDiskSpaceMB = 500

func checkDiskSpace(ctx context.Context, cli *client.Client, _ string) error {
	// Check Docker data root filesystem via Docker disk usage API.
	usage, err := cli.DiskUsage(ctx, types.DiskUsageOptions{})
	if err != nil {
		return fmt.Errorf("disk usage check failed: %w", err)
	}
	var totalImageMB int64
	for _, img := range usage.Images {
		totalImageMB += img.Size / (1024 * 1024)
	}

	// Check host filesystem free space via syscall.
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		log.Printf("disk space: syscall.Statfs failed: %v — proceeding anyway", err)
		return nil
	}
	freeMB := int64(stat.Bavail) * int64(stat.Bsize) / (1024 * 1024)
	log.Printf("disk space: %d MB free, %d MB in Docker images", freeMB, totalImageMB)

	if freeMB < minDiskSpaceMB {
		return fmt.Errorf("insufficient disk space: %d MB free (minimum %d MB required)", freeMB, minDiskSpaceMB)
	}
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
	// U16: Guard against images with no repo tags (pulled by digest).
	newImageRef := "(untagged)"
	if len(newImg.RepoTags) > 0 {
		newImageRef = newImg.RepoTags[0]
	}
	diff := ConfigDiff{
		Image: DiffEntry{
			Key:    "Image",
			Old:    info.Config.Image,
			New:    newImageRef,
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

	// U17: Limit log capture to 1MB to prevent excessive memory use.
	data, _ := io.ReadAll(io.LimitReader(reader, 1<<20))

	dir := "/data/update_failures"
	os.MkdirAll(dir, 0o755) //nolint:errcheck
	// U15: Sanitize tag to prevent path traversal in log filename.
	safeTag := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, tag)
	filename := filepath.Join(dir, time.Now().Format("20060102-150405")+"-"+safeTag+".log")
	os.WriteFile(filename, data, 0o644) //nolint:errcheck
	log.Printf("failure logs saved to %s", filename)
}

// rollbackCleanupLoop removes expired rollback containers and prunes old images.
func rollbackCleanupLoop(cli *client.Client) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// U18: Copy fields under lock, then operate lock-free to avoid
		// blocking rollback status queries during slow Docker API calls.
		rollbackInfo.mu.RLock()
		expired := rollbackInfo.Available && time.Now().After(rollbackInfo.ExpiresAt)
		containerName := rollbackInfo.ContainerName
		rollbackInfo.mu.RUnlock()

		if expired {
			ctx := context.Background()
			cli.ContainerRemove(ctx, containerName, container.RemoveOptions{Force: true}) //nolint:errcheck
			log.Printf("removed expired rollback container: %s", containerName)

			rollbackInfo.mu.Lock()
			rollbackInfo.Available = false
			rollbackInfo.mu.Unlock()
			clearRollbackInfo()

			// Prune dangling images (lock-free).
			if _, err := cli.ImagesPrune(ctx, filters.Args{}); err != nil {
				log.Printf("image prune failed: %v", err)
			}

			// Clean up old image tags (keep N most recent).
			pruneOldImages(ctx, cli)
		}
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

// ── Self-update via reaper pattern ──────────────────────────────────────────
//
// The updater can't restart itself (container suicide). Instead it spawns a
// short-lived "reaper" container that:
//   1. Sleeps 5s (let this response flush)
//   2. Stops the old updater container
//   3. Removes it
//   4. Creates + starts a new updater with the same config + new image
//   5. Exits (auto-removed by --rm)

func handleSelfUpdate(cli *client.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			TargetTag string `json:"target_tag"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TargetTag == "" {
			http.Error(w, `{"error":"target_tag required"}`, http.StatusBadRequest)
			return
		}
		// U6: Validate tag format.
		if !tagRe.MatchString(req.TargetTag) {
			http.Error(w, `{"error":"invalid target_tag format"}`, http.StatusBadRequest)
			return
		}

		// Guard against concurrent operations.
		activeSession.mu.Lock()
		if activeSession.Active {
			activeSession.mu.Unlock()
			writeJSON(w, http.StatusConflict, map[string]string{"error": "operation already in progress"})
			return
		}
		activeSession.Active = true
		activeSession.mu.Unlock()
		defer func() {
			activeSession.mu.Lock()
			activeSession.Active = false
			activeSession.mu.Unlock()
		}()

		// Use background context — self-update must complete even if the
		// HTTP client disconnects (the proxy's fire-and-forget POST returns
		// immediately, which would cancel r.Context()).
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		// Get our own container info.
		hostname, _ := os.Hostname()
		self, err := cli.ContainerInspect(ctx, hostname)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "inspect self failed"})
			return
		}

		currentImage := self.Config.Image
		newImage := imageWithTag(currentImage, req.TargetTag)

		// If the updater was built locally (no registry prefix), derive the
		// registry image name from the proxy registry config.
		if !strings.Contains(currentImage, "/") {
			newImage = registry + "-updater:" + req.TargetTag
		}

		// Pull the new image.
		pullOut, err := cli.ImagePull(ctx, newImage, image.PullOptions{})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "image pull failed"})
			return
		}
		io.Copy(io.Discard, pullOut) //nolint:errcheck
		pullOut.Close()

		// U1/U3: Build reaper script using environment variables instead of
		// string interpolation to prevent shell injection via container names
		// or volume bind paths. The reaper script *quotes* "$SELF_NAME" and
		// "$NEW_IMAGE", but $NETWORK_NAME is expanded unquoted to avoid passing
		// "" to `--network`, so we additionally validate it server-side.
		selfName := strings.TrimPrefix(self.Name, "/")
		if !dockerIdentRe.MatchString(selfName) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "self container name failed validation"})
			return
		}

		// Preserve ALL non-docker.sock binds (data, state, etc.) — joined with
		// newlines so the reaper can iterate them. Empty bind list means no
		// extra volumes (still safe — the new container just has the socket).
		volBinds := collectValidBinds(self.HostConfig.Binds)
		dataVolumeArgs := strings.Join(volBinds, "\n")

		// Determine the compose network to attach the new container to.
		// Without this, the new container lands on the default bridge and the
		// proxy can't reach it via service-name DNS (http://culvert-updater:7123).
		networkName := pickComposeNetwork(self.NetworkSettings.Networks)
		if networkName != "" && !dockerIdentRe.MatchString(networkName) {
			log.Printf("warning: discarding network name %q (failed validation)", networkName)
			networkName = ""
		}

		// U1: The reaper script references only env vars, never interpolated strings.
		// Reaper renames the old container (preserving it for rollback), creates the
		// new one on the same compose network, health-checks via `docker exec` (the
		// reaper itself is on a different network — localhost from inside the reaper
		// is NOT the new updater), and rolls back if the new updater fails to start.
		reaperScript := `
set -u
sleep 5
ROLLBACK_NAME="${SELF_NAME}-rollback-$(date +%s%N)"
docker stop -t 10 "$SELF_NAME" 2>/dev/null || true
docker rename "$SELF_NAME" "$ROLLBACK_NAME" 2>/dev/null || true

# Build optional --network flag.
NETWORK_ARG=""
if [ -n "${NETWORK_NAME:-}" ]; then
  NETWORK_ARG="--network ${NETWORK_NAME}"
fi

# Build -v args from newline-separated DATA_VOLUMES (each bind is pre-validated
# by the Go side via bindPathRe — safe to expand unquoted here).
VOL_ARGS=""
if [ -n "${DATA_VOLUMES:-}" ]; then
  OLDIFS="$IFS"
  IFS='
'
  for b in $DATA_VOLUMES; do
    [ -z "$b" ] && continue
    VOL_ARGS="$VOL_ARGS -v $b"
  done
  IFS="$OLDIFS"
fi

# shellcheck disable=SC2086
docker create --name "$SELF_NAME" \
  --restart unless-stopped \
  $NETWORK_ARG \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  $VOL_ARGS \
  -p 127.0.0.1:7123:7123 \
  "$NEW_IMAGE"
docker start "$SELF_NAME"

# Health check: probe the new updater from INSIDE its own container via
# docker exec. The reaper sits on a different network namespace, so a
# direct wget from the reaper to "localhost:7123" would hit the reaper itself.
HEALTHY=0
for i in 1 2 3 4 5 6; do
  sleep 5
  if docker exec "$SELF_NAME" wget -qO- http://127.0.0.1:7123/healthz >/dev/null 2>&1; then
    HEALTHY=$((HEALTHY+1))
    if [ "$HEALTHY" -ge 3 ]; then
      echo "updater healthy after $i checks — removing rollback"
      docker rm "$ROLLBACK_NAME" 2>/dev/null || true
      exit 0
    fi
  else
    HEALTHY=0
  fi
done

# Health check failed — rollback.
echo "updater health check failed — rolling back"
docker stop -t 10 "$SELF_NAME" 2>/dev/null || true
docker rm "$SELF_NAME" 2>/dev/null || true
docker rename "$ROLLBACK_NAME" "$SELF_NAME" 2>/dev/null || true
docker start "$SELF_NAME"
exit 1
`

		// U11: Use a unique reaper name to avoid collision with a still-running reaper.
		reaperName := fmt.Sprintf("culvert-updater-reaper-%d", time.Now().UnixNano())

		// Spawn the reaper container using the Docker CLI image (small, has docker binary).
		reaperCfg := &container.Config{
			Image: "docker:cli",
			Cmd:   []string{"sh", "-c", reaperScript},
			Env: []string{
				"SELF_NAME=" + selfName,
				"DATA_VOLUMES=" + dataVolumeArgs,
				"NEW_IMAGE=" + newImage,
				"NETWORK_NAME=" + networkName,
			},
		}
		reaperHostCfg := &container.HostConfig{
			AutoRemove: true,
			Binds:      []string{"/var/run/docker.sock:/var/run/docker.sock"},
		}

		reaperResp, err := cli.ContainerCreate(ctx, reaperCfg, reaperHostCfg, nil, nil, reaperName)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create reaper failed"})
			return
		}

		if err := cli.ContainerStart(ctx, reaperResp.ID, container.StartOptions{}); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "start reaper failed"})
			return
		}

		log.Printf("self-update: reaper started, will swap to %s", newImage)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"status":    "reaper_started",
			"new_image": newImage,
			"reaper_id": reaperResp.ID[:12],
		})
	}
}

// imageWithTag replaces the tag in an image reference.
func imageWithTag(img, tag string) string {
	if i := strings.LastIndex(img, ":"); i != -1 {
		return img[:i] + ":" + tag
	}
	return img + ":" + tag
}

// bindPathRe validates Docker bind mount strings (source:dest[:mode]).
// Disallows whitespace, quotes, $, &, |, ; and other shell metacharacters so
// the value is safe to expand unquoted inside the reaper shell script.
var bindPathRe = regexp.MustCompile(`^[a-zA-Z0-9/_.:-]+$`)

// dockerIdentRe matches the character set Docker permits in container and
// network names: [a-zA-Z0-9][a-zA-Z0-9_.-]*. We use it to defensively reject
// anything weird that could break the reaper shell script.
var dockerIdentRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// collectValidBinds returns all non-docker.sock binds that pass the safety
// regex, preserving order. The reaper script will iterate over this list and
// emit one `-v` arg per entry — so we MUST NOT silently drop volumes.
// U3: Validates each bind string to prevent shell metacharacter injection.
func collectValidBinds(binds []string) []string {
	out := make([]string, 0, len(binds))
	for _, b := range binds {
		if strings.Contains(b, "docker.sock") {
			continue
		}
		if !bindPathRe.MatchString(b) {
			log.Printf("warning: skipping bind with invalid chars: %q", b)
			continue
		}
		out = append(out, b)
	}
	return out
}

// pickComposeNetwork returns the first non-default network name from a
// container's network settings. The default `bridge` network is skipped
// because docker-compose service DNS only resolves on user-defined networks.
// Returns "" if only the default bridge is attached (caller will then create
// the new container without --network, which is the safest fallback).
func pickComposeNetwork(nets map[string]*network.EndpointSettings) string {
	if len(nets) == 0 {
		return ""
	}
	// Prefer the first non-bridge network. Compose creates one user-defined
	// network per project, so this is normally the only entry anyway.
	for name := range nets {
		if name == "bridge" || name == "host" || name == "none" {
			continue
		}
		return name
	}
	return ""
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
	// U22: Use proper integer parsing with validation instead of custom atoi.
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			log.Printf("warning: invalid integer for %s=%q, using default %d", key, v, fallback)
			return fallback
		}
		n = n*10 + int(c-'0')
	}
	if n <= 0 {
		return fallback
	}
	return n
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
