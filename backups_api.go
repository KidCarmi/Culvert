// Backup archive visibility (Enterprise Product Experience finding): a
// read-only admin surface for GET /v1/backups on the CP-local maintenance
// agent (see list_backups.go for the on-disk scan the agent shells out to,
// and cmd/culvert-maint/internal/server/handlers_d16b.go for the agent-side
// handler that already exists and is already validated/sanitized there).
//
// Today an admin can only learn "did last night's backup job actually
// produce a file, how big, how stale" by running
// `docker compose --profile cli run --rm cli --list-backups --backup-dir
// /backup` by hand, or by curling the agent's unix socket directly — both
// require SSH access to the host. This file adds no new agent capability
// (the endpoint already exists and is read-only); it only gives the CP admin
// GUI/API a way to reach it, matching the read pattern release_dispatch_exec.go
// / release_api.go already use to talk to the same maintenance agent.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// resolveLocalMaintAgentEndpoint reuses the SAME env var and default socket
// path Release Management resolves for its own agent client (envMaintAgentURL
// / defaultMaintAgentSocket / localAgentEndpoint, release_wiring.go) but is
// deliberately NOT gated on Release Management being configured — backup
// visibility must keep working even when catalog trust/verification is
// disabled, unconfigured, or in break-glass mode.
func resolveLocalMaintAgentEndpoint() (AgentEndpoint, bool) {
	raw := os.Getenv(envMaintAgentURL)
	if raw == "" {
		raw = defaultMaintAgentSocket
	}
	return localAgentEndpoint(raw)
}

// backupsAgentReadBound bounds the agent response read; a backup directory
// listing is small JSON (one entry per archive file).
const backupsAgentReadBound = 1 << 20 // 1 MiB

// fetchAgentBackups performs a GET /v1/backups against the maintenance agent
// and parses the response into the wire shape (backupListEntry,
// list_backups.go) the agent's --list-backups CLI already emits and the
// agent itself already shape-validates before returning it.
func fetchAgentBackups(ctx context.Context, ep AgentEndpoint) ([]backupListEntry, error) {
	u, err := url.Parse(ep.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse agent base URL: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/backups"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	client := ep.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("maintenance agent unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, backupsAgentReadBound))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("maintenance agent returned HTTP %d", resp.StatusCode)
	}
	var entries []backupListEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse agent response: %w", err)
	}
	return entries, nil
}

func registerBackupsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/backups", apiBackups)
}

// apiBackups is a read-only, viewer-role GET surfacing the backup archive
// directory (as scanned by the CP-local maintenance agent's GET /v1/backups)
// so an admin can answer "is my backup job actually working" from the GUI
// instead of SSHing in to run the CLI by hand. Newest-first so the question
// an admin actually has ("did the most recent backup happen") is the first
// row, not buried in a filename-sorted list.
func apiBackups(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ep, ok := resolveLocalMaintAgentEndpoint()
	if !ok {
		jsonOK(w, map[string]any{
			"available": false,
			"reason":    "maintenance agent not configured",
		})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	entries, err := fetchAgentBackups(ctx, ep)
	if err != nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{
			"available": false,
			"reason":    err.Error(),
		})
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ModifiedAt.After(entries[j].ModifiedAt) })
	out := map[string]any{
		"available": true,
		"count":     len(entries),
		"backups":   entries,
	}
	if len(entries) > 0 {
		out["newest_at"] = entries[0].ModifiedAt.UTC().Format(time.RFC3339)
	}
	jsonOK(w, out)
}
