// culvert-maint is the host-side Maintenance Agent for Culvert.
//
// D1.6a foundation slice:
//   - reads /etc/culvert-maint/config.toml (or path from --config)
//   - listens on a Unix domain socket (default /run/culvert-maint.sock)
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
// overlay. CULVERT_PROXY_IMAGE (D1.6c) is the precondition for the future
// upgrade-apply pull/up to forward a pinned digest — nothing forwards it
// yet (see the const doc / plan § 2.3.1). It is overlay-only so an
// ambient value never leaks onto an unrelated compose call.
func newRunner(cfg *config.Config) (*runner.Runner, error) {
	return runner.New(runner.Options{
		ComposeProjectDir: cfg.ComposeProjectDir,
		ComposeFile:       cfg.ComposeFile,
		UseSudo:           cfg.PrivilegeMode == config.PrivilegeSudoers,
		StageTimeout:      cfg.StageTimeout,
		EnvAllow:          []string{runner.EnvCulvertBackupPassphrase, runner.EnvCulvertProxyImage},
		EnvOverlayOnly:    []string{runner.EnvCulvertProxyImage},
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

	srv, err := server.New(server.Options{
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
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}
	defer func() { _ = srv.Close() }()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Printf("culvert-maint: listening on %s (privilege_mode=%s)", cfg.SocketPath, cfg.PrivilegeMode)
	if err := srv.Serve(ctx); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	log.Printf("culvert-maint: shutdown")
	return nil
}
