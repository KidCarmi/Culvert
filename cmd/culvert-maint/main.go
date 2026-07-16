// culvert-maint is the host-side Maintenance Agent for Culvert.
//
// D1.6a foundation slice:
//   - reads /etc/culvert-maint/config.toml (or path from --config)
//   - listens on a Unix domain socket (default /run/culvert-maint/culvert-maint.sock)
//   - exposes the read-only API (/v1/health, /v1/status, /v1/audit,
//     /v1/operations/{id}, /v1/operations/{id}/logs)
//   - every state-changing endpoint (/v1/backups, /v1/restores/*, etc.)
//     returns HTTP 404 in this slice
//
// See roadmap/D1.6-maintenance-agent-implementation-plan.md for the
// staged scope of D1.6b–d.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/config"
	"culvert-maint/internal/health"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
	"culvert-maint/internal/server"
	"culvert-maint/internal/status"
)

func main() {
	var (
		configPath = flag.String("config", "/etc/culvert-maint/config.toml", "Path to config.toml")
		printVer   = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *printVer {
		fmt.Println(server.Version)
		return
	}

	if err := run(*configPath); err != nil {
		log.Fatalf("culvert-maint: %v", err)
	}
}

// newRunner builds the command runner from config.
//
// EnvAllow: CULVERT_BACKUP_PASSPHRASE is the encrypted backup/restore
// overlay. It is overlay-only (D1.6c privilege hardening): the agent only
// ever sets it via an explicit per-call overlay (the passphrase value read
// from the request's passphrase_ref), NEVER from the agent's ambient
// process env — so an ambient value can never leak onto a compose call
// that did not explicitly forward it. The sudo boundary is independently
// scoped per-command (env_keep via Defaults!<alias> in
// packaging/sudoers/culvert-maint).
//
// P1.4: the proxy image is NO LONGER selected by an env var. Image
// selection is bound at the sudo boundary via a repo-bound `docker pull
// <ProxyRepo>@sha256:<digest>` + retag to the fixed `culvert/proxy:pinned`
// tag, so CULVERT_PROXY_IMAGE and its env_keep are gone.
func newRunner(cfg *config.Config) (*runner.Runner, error) {
	return runner.New(runner.Options{
		ComposeProjectDir:   cfg.ComposeProjectDir,
		ComposeFile:         cfg.ComposeFile,
		ComposeOverrideFile: cfg.ComposeOverrideFile,
		UseSudo:             cfg.PrivilegeMode == config.PrivilegeSudoers,
		StageTimeout:        cfg.StageTimeout,
		ProxyRepo:           cfg.ProxyRepo,
		EnvAllow:            []string{runner.EnvCulvertBackupPassphrase},
		EnvOverlayOnly:      []string{runner.EnvCulvertBackupPassphrase},
	})
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	// Per § 4.5: surface a WARN line whenever docker_group_lab is active.
	if cfg.PrivilegeMode == config.PrivilegeDockerGroupLab {
		log.Printf("WARN: privilege_mode=docker_group_lab — effectively root-equivalent; not for production")
	}

	// Advisory pre-flight: the runner chdir's into ComposeProjectDir BEFORE
	// sudo, so if this service identity cannot traverse it, every operation
	// fails at chdir before sudo is reached. Warn loudly but do NOT fail
	// closed — the real authority boundary is sudoers + the actual compose run.
	if err := dirTraversable(cfg.ComposeProjectDir); err != nil {
		log.Printf("WARN: compose_project_dir %q is not traversable by this user (%v) — "+
			"operations will fail at chdir before sudo. Ensure it is 0750 root:culvert-maint "+
			"(or world-searchable) and every ancestor is searchable.", cfg.ComposeProjectDir, err)
	}

	pol, err := auth.NewPolicy(cfg.AllowPeers)
	if err != nil {
		return fmt.Errorf("auth policy: %w", err)
	}

	if err := os.MkdirAll(cfg.StateDir, 0o750); err != nil { //nolint:gosec // documented mode
		return fmt.Errorf("mkdir state_dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.StateDir, "operations"), 0o750); err != nil { //nolint:gosec // documented mode
		return fmt.Errorf("mkdir operations: %w", err)
	}

	auditPath := filepath.Join(cfg.StateDir, "audit.jsonl")
	al, err := audit.New(auditPath)
	if err != nil {
		return err
	}
	defer func() { _ = al.Close() }()

	// Idempotency-cache TTL is the larger of operation_timeout and
	// 24h: an operator retrying an in-flight or recently-completed op
	// MUST hit the dedupe path; anything older than that is almost
	// certainly fresh-intent retry that we want to admit as new work.
	idempTTL := ops.DefaultIdempCacheTTL
	if cfg.OperationTimeout > idempTTL {
		idempTTL = cfg.OperationTimeout
	}
	mgr := ops.NewManagerWithTTL(nil, idempTTL)
	// D1.6a: nothing on disk to scan, but the contract is in place for D1.6b/c.
	mgr.MarkAllInterrupted()

	r, err := newRunner(cfg)
	if err != nil {
		return fmt.Errorf("runner: %w", err)
	}

	stp, err := status.New(cfg, mgr, r)
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}

	srv, err := newServer(cfg, pol, al, mgr, stp, r, auditPath)
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}
	defer func() { _ = srv.Close() }()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	startOpLogRetention(ctx, cfg.StateDir, cfg.LogRetentionDays, mgr.IsRunning)

	log.Printf("culvert-maint: listening on %s (privilege_mode=%s)", cfg.SocketPath, cfg.PrivilegeMode)
	if err := srv.Serve(ctx); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	log.Printf("culvert-maint: shutdown")
	return nil
}

// newServer wires the agent HTTP server from its already-constructed
// dependencies. Extracted from run() to keep that function within the funlen
// budget; no behavior change.
func newServer(cfg *config.Config, pol *auth.Policy, al *audit.Logger, mgr *ops.Manager, stp server.StatusProvider, r *runner.Runner, auditPath string) (*server.Server, error) {
	return server.New(server.Options{
		Cfg:       cfg,
		Auth:      pol,
		Audit:     al,
		Ops:       mgr,
		Status:    stp,
		StateDir:  cfg.StateDir,
		AuditPath: auditPath,
		Runner:    r,
		HealthProbeFactory: func() health.Probe {
			return health.Probe{
				BaseURL:    cfg.HealthBaseURL,
				HealthPath: cfg.HealthPath,
				ReadyPath:  cfg.ReadyPath,
				// Defaults applied by Probe.withDefaults.
			}
		},
	})
}

// opLogRetentionInterval is how often the per-op transcript sweep runs after the
// startup sweep. A day is ample for a retention measured in days; the sweep is
// cheap (one readdir + stat per file).
const opLogRetentionInterval = 24 * time.Hour

// startOpLogRetention runs an immediate LogRetentionDays sweep of the per-op
// transcripts, then a periodic one until ctx is cancelled. retentionDays <= 0
// disables it (defensive; config validation already enforces > 0).
func startOpLogRetention(ctx context.Context, stateDir string, retentionDays int, isRunning func(opID string) bool) {
	if retentionDays <= 0 {
		return
	}
	maxAge := time.Duration(retentionDays) * 24 * time.Hour
	if removed := ops.SweepOpLogs(stateDir, maxAge, time.Now(), isRunning); removed > 0 {
		log.Printf("culvert-maint: op-log retention swept %d file(s) older than %d day(s)", removed, retentionDays)
	}
	go func() {
		t := time.NewTicker(opLogRetentionInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if removed := ops.SweepOpLogs(stateDir, maxAge, time.Now(), isRunning); removed > 0 {
					log.Printf("culvert-maint: op-log retention swept %d file(s)", removed)
				}
			}
		}
	}()
}
