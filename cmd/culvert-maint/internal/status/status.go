// Package status implements the StatusProvider consumed by GET /v1/status.
//
// D1.6a behavior:
//   - calls runner.ComposeStatus to query the running compose stack;
//     the runner template runs `docker compose -f <compose_path> ps
//     --format json`
//   - parses Compose v2 NDJSON output line-by-line with bufio.Scanner;
//     also accepts the JSON-array form some Compose versions emit
//   - reports compose_stack_up=true ONLY when the `proxy` service is
//     in the "running" state — sidecar-only states (clamav up, proxy
//     down) do NOT count as stack-up to avoid overclaiming
//   - on parse or runner error, surfaces the cause in compose_error
//     and reports compose_stack_up=false rather than failing the
//     request
//   - flags the docker_group_lab privilege mode in the response so the
//     GUI/CP can display a "broad privilege" warning
package status

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"

	"culvert-maint/internal/config"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
	"culvert-maint/internal/server"
)

// proxyServiceName is the name of the Culvert proxy service inside the
// supplied docker-compose.yml. Its `running` state is the canonical
// signal for compose_stack_up=true.
const proxyServiceName = "proxy"

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
	// compose_stack_up is true only when the proxy service is running.
	// Sidecar-only states (clamav up, proxy down) deliberately do NOT
	// count — the operator-facing meaning of "stack up" is "the
	// product is reachable", which requires proxy.
	for _, s := range services {
		if s.Name == proxyServiceName && strings.EqualFold(s.State, "running") {
			st.ComposeStackUp = true
			break
		}
	}
	return st, nil
}

// parseComposePS parses `docker compose ps --format json` output.
// Compose v2 emits one JSON object per line (NDJSON). Some versions
// emit a single JSON array; we fall back to that shape if NDJSON
// parsing yields nothing usable.
//
// Mixed warning/log lines are tolerated — non-`{` lines and blank
// lines are skipped silently. Lines that DO start with `{` but fail
// to JSON-decode are tracked: if every `{`-prefixed line fails to
// parse, parseComposePS returns an error so the caller can surface
// "parse_compose_ps: …" in compose_error rather than reporting an
// empty stack (which would look identical to "compose stack down"
// to the GUI).
func parseComposePS(stdout []byte) ([]server.ServiceStatus, error) {
	if len(stdout) == 0 {
		return nil, nil
	}
	// Heuristic: if the first non-whitespace byte is '[' it's the
	// array form; otherwise treat as NDJSON.
	trimmed := bytes.TrimLeft(stdout, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return parseComposePSArray(stdout)
	}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var (
		services    []server.ServiceStatus
		candidates  int
		parsed      int
		firstParseE error
	)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		candidates++
		var entry composePSEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			if firstParseE == nil {
				firstParseE = err
			}
			continue
		}
		parsed++
		services = append(services, entry.toServiceStatus())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if candidates > 0 && parsed == 0 {
		return nil, errors.New("all NDJSON lines failed to decode: " + firstParseE.Error())
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
