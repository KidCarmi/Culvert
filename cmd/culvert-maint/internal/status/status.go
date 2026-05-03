// Package status implements the StatusProvider consumed by GET /v1/status.
//
// D1.6a behavior:
//   - calls runner.ComposeStatus to query the running compose stack
//   - parses `docker compose ps --format json` output (best effort) — if
//     parsing fails the agent surfaces the raw error in compose_error
//     and reports compose_stack_up=false rather than failing the request
//   - flags the docker_group_lab privilege mode in the response so the
//     GUI/CP can display a "broad privilege" warning
package status

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"culvert-maint/internal/config"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
	"culvert-maint/internal/server"
)

// Provider is the production StatusProvider.
type Provider struct {
	cfg    *config.Config
	mgr    *ops.Manager
	runner *runner.Runner
}

// New constructs a Provider.
func New(cfg *config.Config, mgr *ops.Manager, r *runner.Runner) (*Provider, error) {
	if cfg == nil {
		return nil, errors.New("status: cfg required")
	}
	if mgr == nil {
		return nil, errors.New("status: ops manager required")
	}
	if r == nil {
		return nil, errors.New("status: runner required")
	}
	return &Provider{cfg: cfg, mgr: mgr, runner: r}, nil
}

// Snapshot implements server.StatusProvider.
func (p *Provider) Snapshot(ctx context.Context) (server.Status, error) {
	st := server.Status{
		PrivilegeMode:     string(p.cfg.PrivilegeMode),
		ComposeProjectDir: p.cfg.ComposeProjectDir,
		ComposeFile:       p.cfg.ComposeFile,
	}
	if p.cfg.PrivilegeMode == config.PrivilegeDockerGroupLab {
		st.PrivilegeWarning = "docker_group_lab is dev/lab only and effectively root-equivalent; not for production"
	}

	// Lock holder, if any.
	if h := p.mgr.Holder(); h != nil {
		st.LockHeldBy = h
	}

	// Compose status — best effort. If `docker compose ps` errors (e.g.
	// stack not running, daemon down), we surface the error string but
	// keep the response 200 so the GUI can still render the rest.
	res, err := p.runner.ComposeStatus(ctx)
	if err != nil {
		st.ComposeError = err.Error()
		// Keep what stderr we got so operators can read it.
		if res != nil && len(res.Stderr) > 0 {
			st.ComposeError = strings.TrimSpace(string(res.Stderr))
			if st.ComposeError == "" {
				st.ComposeError = err.Error()
			}
		}
		return st, nil
	}
	services, perr := parseComposePS(res.Stdout)
	if perr != nil {
		st.ComposeError = "parse_compose_ps: " + perr.Error()
		return st, nil
	}
	st.ComposeServices = services
	for _, s := range services {
		if strings.EqualFold(s.State, "running") {
			st.ComposeStackUp = true
			break
		}
	}
	return st, nil
}

// parseComposePS parses `docker compose ps --format json` output.
// Compose v2 emits one JSON object per line (NDJSON-ish); we accept
// both NDJSON and a single JSON-array form.
func parseComposePS(stdout []byte) ([]server.ServiceStatus, error) {
	if len(stdout) == 0 {
		return nil, nil
	}
	// Try NDJSON first.
	var services []server.ServiceStatus
	dec := json.NewDecoder(strings.NewReader(string(stdout)))
	for dec.More() {
		var entry composePSEntry
		if err := dec.Decode(&entry); err != nil {
			// Maybe it's a single JSON array; retry once.
			return parseComposePSArray(stdout)
		}
		services = append(services, entry.toServiceStatus())
	}
	return services, nil
}

func parseComposePSArray(stdout []byte) ([]server.ServiceStatus, error) {
	var entries []composePSEntry
	if err := json.Unmarshal(stdout, &entries); err != nil {
		return nil, err
	}
	services := make([]server.ServiceStatus, 0, len(entries))
	for _, e := range entries {
		services = append(services, e.toServiceStatus())
	}
	return services, nil
}

// composePSEntry mirrors the relevant subset of `docker compose ps
// --format json` output.
type composePSEntry struct {
	Name    string `json:"Name"`
	Service string `json:"Service"`
	State   string `json:"State"`
	Status  string `json:"Status"`
	Image   string `json:"Image"`
}

func (e composePSEntry) toServiceStatus() server.ServiceStatus {
	name := e.Service
	if name == "" {
		name = e.Name
	}
	state := e.State
	if state == "" {
		state = e.Status
	}
	return server.ServiceStatus{
		Name:  name,
		State: state,
		Image: e.Image,
	}
}
