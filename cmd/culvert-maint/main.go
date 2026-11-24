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
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/config"
	"culvert-maint/internal/health"
	"culvert-maint/internal/idem"
	"culvert-maint/internal/journal"
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
	// CHAOS-122: the flag package stops at the first non-flag token and silently
	// drops every flag after it. For this agent the flag that would be dropped
	// is --config, so a mangled argv runs the PRIVILEGED maintenance agent
	// against the DEFAULT config path instead of the operator's — a different
	// journal, a different compose path and a different allowlist, chosen
	// silently. The agent takes no positional operands, so any tail is refused
	// before the config is read or the socket is bound.
	// Only the first token and the discarded flag NAMES are echoed: a value in
	// the tail may be a credential, and the journal collects stderr.
	if flag.NArg() > 0 {
		log.Fatalf("culvert-maint: unexpected argument(s) beginning with %q (discarded after it, values redacted: %q); "+
			"this agent takes flags only, and the flag package discards every flag after a non-flag token "+
			"(--config selects the config, journal and allowlist). Nothing was started.",
			flag.Arg(0), redactArgValues(flag.Args()[1:]))
	}

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
	initIdempotency(cfg.StateDir, mgr, idempTTL)

	jnl, diedIn, err := initJournal(cfg.StateDir, mgr, al, cfg.ProxyRepo)
	if err != nil {
		return err
	}

	r, err := newRunner(cfg)
	if err != nil {
		return fmt.Errorf("runner: %w", err)
	}

	stp, err := status.New(cfg, mgr, r)
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}
	stp.WithJournal(jnl).WithDiedInCommand(diedIn)

	srv, err := newServer(cfg, pol, al, mgr, stp, r, auditPath, jnl)
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}
	defer func() { _ = srv.Close() }()

	armStartupReconcile(cfg, stp, srv)

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

// initIdempotency opens the durable idempotency store (internal/idem) under
// state_dir and hands it to the manager, so a keyed request that already
// finished is answered from its record after a restart instead of running
// again, and one that was interrupted is reported as outcome unknown.
//
// Unlike the journal this does NOT stop the agent when it fails. A store that
// cannot be opened is replaced by one that refuses every keyed admission
// (503 idempotency_store_unavailable): the agent still serves status, reads
// and un-keyed requests, and never runs a keyed request it cannot record.
// Opening runs no docker command.
func initIdempotency(stateDir string, mgr *ops.Manager, ttl time.Duration) {
	store, err := idem.Open(stateDir, idem.Options{TTL: ttl, Logf: log.Printf})
	if err != nil {
		log.Printf("culvert-maint: WARN: idempotency store could not be opened (%v) — "+
			"requests that carry an idempotency_key are refused until this is fixed; other requests are served", err)
		store = idem.Unavailable(err)
	}
	mgr.SetIdempotencyStore(store)
}

// initJournal opens the crash-recovery journal (RISK-022) and reports every op
// that was in flight at the last stop. It reads the journal FAIL-CLOSED: a
// corrupt record means we cannot tell whether a destructive op was interrupted,
// so the agent refuses to serve rather than silently ignore it.
//
// What startup does with a record, and all it does (ADR-0061):
//   - marks the op failed(agent_restart_interrupted) with what the journal
//     knows about how far it got, so GET /v1/operations/{id} answers;
//   - writes ONE audit entry for the interruption, the first time the record
//     is found;
//   - counts the start in the record.
//
// It runs no docker command and removes no record. Docker is not consulted, so
// an unreachable daemon cannot delay or fail startup, and a record stays — and
// is reported again by every later start and by GET /v1/status — until a later
// image change succeeds or, for an interrupted restore, a later restore does
// (server/journal_retire.go). The same holds for every journaled kind: an
// interrupted restore.commit or data rollback is reported here exactly like an
// interrupted upgrade, and its stack is not started. Acting on a record at boot
// is the separate, opt-in reconcile (reconcile_on_startup = "converge",
// server/startup_reconcile.go), which runs only after this report is complete.
//
// diedIn is what this start, and only this start, may conclude about command
// attribution (journal/intent.go): op id → the docker command the previous
// agent process died inside. It lives in this process's memory and nowhere
// else.
func initJournal(stateDir string, mgr *ops.Manager, al *audit.Logger, proxyRepo string) (jnl *journal.Journal, diedIn map[string]string, err error) {
	jnl, err = journal.New(stateDir)
	if err != nil {
		return nil, nil, fmt.Errorf("journal: %w", err)
	}
	recs, err := jnl.List()
	if err != nil {
		return nil, nil, fmt.Errorf("journal: refusing to serve — %w", err)
	}
	// First, and before anything is audited, reported or counted: take every
	// open command intent, durably.
	diedIn, err = takeCommandIntents(jnl, recs)
	if err != nil {
		return nil, nil, fmt.Errorf("journal: refusing to serve — %w", err)
	}
	now := time.Now().UTC()
	orphans := make([]ops.InterruptedOp, 0, len(recs))
	for i := range recs {
		orphans = append(orphans, reportInterrupted(jnl, al, &recs[i], proxyRepo, now))
	}
	if n := mgr.MarkAllInterrupted(orphans); n > 0 {
		log.Printf("culvert-maint: %d operation(s) interrupted by a prior stop — marked failed(agent_restart_interrupted); "+
			"Docker was NOT changed. See GET /v1/status interrupted_operations.", n)
	}
	return jnl, diedIn, nil
}

// takeCommandIntents removes every open command intent from the journal and
// returns the ones that are evidence of a death inside the command.
//
// This is the one startup write that is NOT best-effort. "A start has looked"
// has to be on disk before this start says anything: otherwise it would
// report the interruption, an operator could react to the report (stop the
// stack, say), and the next start would find the same intent and take it for
// new. So a start that cannot remove an intent does not happen: nothing has
// been audited, counted or reported yet, and the agent exits. systemd starts
// it again; the first start that can write is the first start. With a state
// directory that cannot be written the agent could have run no operation
// anyway, only reported.
//
// All intents are taken before the first is acted on in any way, so a refusal
// leaves no audit entry behind for some other record.
func takeCommandIntents(jnl *journal.Journal, recs []journal.Record) (map[string]string, error) {
	diedIn := map[string]string{}
	for i := range recs {
		rec := &recs[i]
		command, attributed, had := rec.TakeIntent()
		if !had {
			continue
		}
		if werr := jnl.Write(*rec); werr != nil {
			if errors.Is(werr, journal.ErrNewerSchema) {
				return nil, fmt.Errorf("op %s died inside %s, and its journal record was written by a newer agent version that this version may not change; start that version (or a later one) again: %w",
					rec.OpID, command, werr)
			}
			return nil, fmt.Errorf("op %s died inside %s and that cannot be recorded in its journal record (is %s writable, and is there space?): %w",
				rec.OpID, command, jnl.Dir(), werr)
		}
		if attributed {
			diedIn[rec.OpID] = command
		}
	}
	return diedIn, nil
}

// armStartupReconcile wires the opt-in startup reconcile (contract AGT-900).
// With the default "off" it does nothing and startup changes nothing in Docker
// (AGT-004). With "converge", initJournal has already marked and audited every
// interrupted op; the reconcile is a separate op that takes the instance lock
// and the maintenance lock here and starts its work once Serve has bound the
// socket.
func armStartupReconcile(cfg *config.Config, stp *status.Provider, srv *server.Server) {
	if cfg.ReconcileOnStartup != config.ReconcileConverge {
		return
	}
	rt := server.NewReconcileTracker()
	stp.WithReconcile(rt)
	srv.PrepareStartupReconcile(rt)
}

// maxInterruptedSeen caps the per-record start counter. Reaching it means the
// agent has been restarted that many times with the record outstanding; the
// count stops, the reporting does not.
const maxInterruptedSeen = 1_000_000

// reportInterrupted does the per-record startup work and returns the op
// descriptor to mark. Every write here is best-effort: a full or read-only
// state_dir must not stop the agent from coming up and saying, in memory, what
// it found.
//
// Ordering: the audit entry is written before the record that remembers it. A
// crash between the two repeats the entry at the next start; the other order
// could lose it. So the audit trail carries the interruption at least once,
// and exactly once unless the agent dies inside that window.
func reportInterrupted(jnl *journal.Journal, al *audit.Logger, rec *journal.Record, proxyRepo string, now time.Time) ops.InterruptedOp {
	if rec.InterruptedAt == nil {
		rec.InterruptedAt = &now
	}
	if rec.InterruptedSeen < maxInterruptedSeen {
		rec.InterruptedSeen++
	}
	desc := server.DescribeInterrupted(rec, proxyRepo)
	actor := desc.Actor
	if actor == "" {
		actor = server.AuditActorStartup
	}
	if !rec.InterruptAudited {
		if err := al.Write(audit.Event{
			Actor:         actor,
			OpID:          rec.OpID,
			Kind:          desc.Kind,
			Params:        desc.AuditParams(),
			Outcome:       audit.OutcomeFailed,
			OutcomeAt:     rec.InterruptedAt,
			FailureReason: string(ops.ReasonAgentRestartInterrupted),
		}); err != nil {
			log.Printf("culvert-maint: WARN: could not audit interrupted op %s (will retry at the next start): %v", rec.OpID, err)
		} else {
			rec.InterruptAudited = true
		}
	}
	if err := jnl.Write(*rec); err != nil {
		log.Printf("culvert-maint: WARN: could not update the journal record of interrupted op %s: %v", rec.OpID, err)
	}
	log.Printf("culvert-maint: interrupted op %s kind=%s journal_phase=%s docker_state=%s starts_seen=%d",
		rec.OpID, desc.Kind, desc.JournalPhase, desc.DockerState, rec.InterruptedSeen)
	return ops.InterruptedOp{
		OpID:    rec.OpID,
		Kind:    desc.Kind,
		Actor:   actor,
		Started: rec.StartedAt,
		Result:  desc.ResultMap(),
	}
}

// newServer wires the agent HTTP server from its already-constructed
// dependencies. Extracted from run() to keep that function within the funlen
// budget; no behavior change.
func newServer(cfg *config.Config, pol *auth.Policy, al *audit.Logger, mgr *ops.Manager, stp server.StatusProvider, r *runner.Runner, auditPath string, jnl *journal.Journal) (*server.Server, error) {
	return server.New(server.Options{
		Cfg:       cfg,
		Auth:      pol,
		Audit:     al,
		Ops:       mgr,
		Status:    stp,
		StateDir:  cfg.StateDir,
		AuditPath: auditPath,
		Journal:   jnl,
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

// redactArgValues keeps each flag NAME in an argv tail and replaces every value
// — a token that is not a flag, or the part of `-flag=value` after "=" — with
// <value>, so a refusal says what was discarded without printing a secret.
func redactArgValues(args []string) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if len(a) < 2 || a[0] != '-' {
			out = append(out, "<value>")
			continue
		}
		if name, _, ok := strings.Cut(a, "="); ok {
			a = name + "=<value>"
		}
		out = append(out, a)
	}
	return strings.Join(out, " ")
}
