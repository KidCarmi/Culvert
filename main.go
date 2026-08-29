// Culvert — Enterprise-grade open source HTTP/HTTPS proxy
// https://github.com/KidCarmi/Claude-Test
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// caPassphraseEnv holds the name of the environment variable that supplies the
// CA private-key encryption passphrase. Using an env var keeps the passphrase
// out of CLI history and process listings (shift-left: secrets management).
// This is an env-var name, NOT a credential — the false-positive is suppressed.
const caPassphraseEnv = "CULVERT_CA_PASSPHRASE" // #nosec G101 -- env-var name, not a credential

const logStorePassphraseEnv = "CULVERT_LOG_PASSPHRASE" // #nosec G101 -- env-var name, not a credential

var logger *log.Logger

// appLifecycleCtx is the lifecycle context for all background goroutines.
// Cancelled on graceful shutdown. Exposed at package level so that API
// handlers (e.g. enabling CP mode at runtime) can start background tasks.
var appLifecycleCtx context.Context

var appLifecycleCancel context.CancelFunc

// blFeedSyncer is the process-wide blocklist feed syncer, set in main().
var blFeedSyncer *BlocklistSyncer

var clusterDBPathGlobal string // persisted cluster state path, set at startup

// dataDir is the base directory for persisted runtime state (node groups, bandwidth policies, etc.).
var dataDir = "/data"

// startupState carries locals across the extracted init functions so each
// one stays a simple `initX(s *startupState)` call. Private, plain struct,
// no methods — purely a mechanical scope-crossing device introduced by
// PR2's main() extraction.
type startupState struct {
	// ── CLI flag pointers (all set in parseFlags) ─────────────────────────
	configPath              *string
	proxyPort               *int
	uiPortFlag              *int
	user                    *string
	pass                    *string
	blockFile               *string
	logFilePath             *string
	logMaxMB                *int
	tlsCert                 *string
	tlsKey                  *string
	rateLimitRPM            *int
	ipMode                  *string
	socks5Port              *int
	metricsTok              *string
	cpGRPCAddr              *string
	cpGRPCCert              *string
	cpGRPCKey               *string
	cpGRPCCA                *string
	haJoin                  *string
	haToken                 *string
	haAutoFailover          *bool
	haEtcdEndpoints         *string
	haEtcdCert              *string
	haEtcdKey               *string
	haEtcdCA                *string
	haLeaseTTL              *int
	dpCPAddr                *string
	dpNodeID                *string
	dpCert                  *string
	dpKey                   *string
	dpCA                    *string
	policyFile              *string
	caPath                  *string
	auditLog                *string
	requestLogPath          *string
	requestLogMaxMB         *int
	syslogAddr              *string
	syslogFormat            *string
	otlpEndpoint            *string
	uiAllowIP               *string
	trustedProxyCIDRs       *string
	sessionHrs              *int
	geoIPDB                 *string
	clamavAddr              *string
	yaraRulesDir            *string
	threatFeedDB            *string
	uiUsersFile             *string
	fileProfilesFile        *string
	idpProfilesFile         *string
	uiNoTLS                 *bool
	catFeedDB               *string
	catFeedURL              *string
	catSyncIntvl            *string
	enrollURL               *string
	clusterDB               *string
	clusterInsecureFlag     *bool
	revocationsFile         *string
	scanSvcListen           *string
	scanSvcURL              *string
	updaterURLFlag          *string // deprecated: legacy updater removed; parsed-but-ignored
	updaterURLAllowFlag     *string // deprecated: legacy updater removed; parsed-but-ignored
	uiSANsFlag              *string
	trustFwdHeaders         *bool
	resetPwUser             *string
	supportBundleOut        *string
	backupOut               *string
	backupEncrypt           *bool
	restoreIn               *string
	restoreMode             *string
	restoreConfirm          *bool
	restoreAcceptDPReenroll *bool
	restoreAllowCounterRB   *bool
	listLeftovers           *bool
	cleanupLeftovers        *bool
	cleanupOlderThan        *string
	cleanupKeepLast         *int
	listBackups             *bool
	listBackupsDir          *string
	cdrEnabledFlag          *bool
	cdrEndpointFlag         *string
	cdrFailModeFlag         *string
	cdrProfileFlag          *string
	cdrModeFlag             *string
	cdrTimeoutFlag          *int
	cdrMaxSizeFlag          *int
	cdrFingerprintFlag      *string
	cdrCertsDirFlag         *string

	// ── Derived locals shared across init functions ──────────────────────
	fc             *FileConfig
	pPort          int
	uPort          int
	socks5PortVal  int // resolved in loadFileConfigAndFlags; reused by initSOCKS5 and validatePortCollisions
	lPath          string
	blPath         string
	lMaxMB         int
	authU          string
	authP          string
	cert           string
	key            string
	rlRPM          int
	ipModeVal      string
	enrolledConfig *dpEnrollmentConfig
	geoDBVal       string

	// ── Shutdown handles (carried to runProxyUntilShutdown) ──────────────
	logCloser       interface{ Close() error }
	rlCleanupCancel context.CancelFunc
	feedSyncer      *FeedSyncer
	scanSvc         *ScanService
	adminUISrv      *http.Server  // P1.1 / S4.AdminUI: graceful shutdown handle
	socks5Srv       *socks5Server // P1.5 / S4.SOCKS5: listener-close shutdown handle
}

func main() {
	// Positional subcommand: `culvert bootstrap-resolve ...` fetches + verifies the
	// signed release catalog and emits the fresh-install decision, then exits. It
	// must run BEFORE the global flag set is defined (it is not a flag).
	maybeRunBootstrapResolve(os.Args)

	s := &startupState{}
	parseFlags(s)
	handleOneShotCommands(s)
	// RISK-005: refuse to boot on a data dir left missing by a restore commit
	// that was killed mid-rename (would otherwise start empty + silently lose
	// data). Runs AFTER the one-shots so --list/--cleanup-restore-leftovers and
	// --restore can still operate on the orphaned state.
	if err := checkInterruptedRestore(dataDir); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	setInsecureFlag(s)
	runEnrollmentMode(s)
	loadFileConfigAndFlags(s)
	initUIExtras(s)
	initLogger(s)
	initMemoryBackstop() // P0-2: soft GOMEMLIMIT so a large config-apply degrades to GC, not OOM
	initLifecycleContext(s)
	defer appLifecycleCancel() // kept in main() for panic safety; initLifecycleContext only creates the context.

	initAuth(s)
	initSession(s)
	initObservability(s)
	initLogStore(s)
	initGeoIP(s)
	initUIAccessPolicy(s)
	initPAC(s)
	initLegacyAuthProviders(s)
	initMetricsToken(s)
	initCluster(s)
	initConnAndRateLimit(s)
	initBlocklist(s)
	initRootCA(s)
	initPolicy(s)
	initURLCategories(s)
	initFileBlocking(s)
	initSSLBypassAndDPI(s)
	initH2InspectServer() // PR3d: eager-build the shared graceful-shutdown H2 server
	initRewriteAndDefaultAction(s)
	initScanning(s)
	initUpstreamProxy(s)
	initCDR(s)
	initMTLSAndOCSP(s)
	initBackgroundServices(s)
	initSOCKS5(s)
	initPersistentAdminState(s)
	initPolicyLearning(s)  // ADR-0025: disabled-by-default advisory learning engine (governed via AdminSettings; no SWG effect when off)
	initMCPRuntime(s)      // PR-5: disabled-by-default MCP listener runtime (no SWG effect when off)
	initMCPToolTrust(s)    // ADR-0034: disabled-by-default tool-trust store + catalog Usable projection. MUST run after initMCPRuntime (needs the published inventory) and BEFORE initMCPRollout, whose restore() runs the Shadow preflight that reads catalog.Usable — otherwise a valid persisted Shadow rollout is clamped to Disabled every restart before approved tools are re-promoted.
	initMCPRollout(s)      // PR-11: disabled-by-default rollout composition (Gateway/Management isolated)
	initMCPDistribution(s) // PR-12: disabled-by-default DP applier composition (after rollout state is restored)
	loadReleaseManagement(resolveReleaseStartupConfig())
	startAdminUI(s)

	proxySrv := buildAndStartProxyServer(s)
	quit, _ := installSignalHandlers(s)
	runProxyUntilShutdown(s, proxySrv, quit)
}

// parseFlags reads every CLI flag into the shared startup state.
func parseFlags(s *startupState) {
	// ── CLI flags ────────────────────────────────────────────────────────────
	s.configPath = flag.String("config", "", "Path to config.yaml (optional)")
	s.proxyPort = flag.Int("port", 0, "Proxy port (overrides config)")
	s.uiPortFlag = flag.Int("ui-port", 0, "Web UI port (overrides config)")
	s.user = flag.String("user", "", "Basic auth username")
	s.pass = flag.String("pass", "", "Basic auth password")
	s.blockFile = flag.String("blocklist", "", "Blocklist file path")
	s.logFilePath = flag.String("logfile", "", "Log file path")
	s.logMaxMB = flag.Int("log-max-mb", 0, "Log rotation size in MB (default 50; overrides config)")
	s.tlsCert = flag.String("tls-cert", "", "TLS cert file for UI (optional)")
	s.tlsKey = flag.String("tls-key", "", "TLS key file for UI (optional)")
	s.rateLimitRPM = flag.Int("rate-limit", 0, "Max requests/min per IP (0=off)")
	s.ipMode = flag.String("ip-filter-mode", "", "IP filter mode: allow|block (empty=off)")
	s.socks5Port = flag.Int("socks5-port", 0, "SOCKS5 proxy port (0=disabled)")
	s.metricsTok = flag.String("metrics-token", "", "Bearer token for /metrics (empty=open)")
	s.cpGRPCAddr = flag.String("cp-grpc-addr", "", "ControlPlane gRPC listen addr e.g. :50051 (empty=off)")
	s.cpGRPCCert = flag.String("cp-grpc-cert", "", "ControlPlane gRPC TLS cert (mTLS)")
	s.cpGRPCKey = flag.String("cp-grpc-key", "", "ControlPlane gRPC TLS key")
	s.cpGRPCCA = flag.String("cp-grpc-ca", "", "ControlPlane gRPC CA for mTLS client validation")
	s.haJoin = flag.String("ha-join", "", "HA standby: leader CP gRPC address to sync from (e.g. cp1:50051)")
	s.haToken = flag.String("ha-token", "", "HA standby: authentication token (from leader's deploy command)")
	s.haAutoFailover = flag.Bool("ha-auto-failover", false, "HA: allow the standby to self-promote on leader loss. DEFAULT OFF — 2-node active/passive has no witness, so unattended auto-promotion can split-brain (ADR-0004/RISK-001). Off = manual failover. With -ha-etcd-endpoints the fencing lease arbitrates instead and this flag is ignored (ADR-0005).")
	s.haEtcdEndpoints = flag.String("ha-etcd-endpoints", "", "HA fencing lease: comma-separated etcd endpoints (e.g. https://etcd1:2379). Enables SAFE automatic failover — every path to leadership is lease-arbitrated (ADR-0005). Empty = legacy manual failover.")
	s.haEtcdCert = flag.String("ha-etcd-cert", "", "HA fencing lease: client certificate for etcd mTLS")
	s.haEtcdKey = flag.String("ha-etcd-key", "", "HA fencing lease: client key for etcd mTLS")
	s.haEtcdCA = flag.String("ha-etcd-ca", "", "HA fencing lease: CA certificate to validate the etcd server")
	s.haLeaseTTL = flag.Int("ha-lease-ttl", 0, "HA fencing lease TTL in seconds (failover latency ≈ TTL; minimum 3; 0 = cluster.lease_ttl_seconds from config, or 10)")
	s.dpCPAddr = flag.String("dp-cp-addr", "", "DataPlane: ControlPlane gRPC addr to connect to (comma-separated for HA failover)")
	s.dpNodeID = flag.String("dp-node-id", "", "DataPlane: node identifier (default=hostname)")
	s.dpCert = flag.String("dp-cert", "", "DataPlane gRPC client TLS cert")
	s.dpKey = flag.String("dp-key", "", "DataPlane gRPC client TLS key")
	s.dpCA = flag.String("dp-ca", "", "DataPlane gRPC CA cert")
	s.policyFile = flag.String("policy", "", "Policy rules JSON file path")
	s.caPath = flag.String("ca-path", "", "Path to persist encrypted Root CA bundle (optional)")
	s.auditLog = flag.String("audit-log", "", "Persistent audit log file path (JSONL, appended)")
	s.requestLogPath = flag.String("request-log", "", "Persistent request log file path (JSONL, rotated)")
	s.requestLogMaxMB = flag.Int("request-log-max-mb", 0, "Request log rotation size in MB (default 100; overrides config)")
	s.syslogAddr = flag.String("syslog", "", "Remote syslog addr e.g. udp://10.0.0.1:514 or tcp://host:601")
	s.syslogFormat = flag.String("syslog-format", "", "Syslog message format: rfc3164 (default) or rfc5424")
	s.otlpEndpoint = flag.String("otlp-endpoint", "", "OTLP/HTTP endpoint for metrics export (e.g. http://otel-collector:4318)")
	s.uiAllowIP = flag.String("ui-allow-ip", "", "Comma-separated CIDRs/IPs allowed to access admin UI (empty=all)")
	s.trustedProxyCIDRs = flag.String("trusted-proxy-cidrs", "", "Comma-separated CIDRs/IPs of reverse proxies whose X-Forwarded-For is trusted for admin-UI client-IP (empty=never trust XFF)")
	s.sessionHrs = flag.Int("session-timeout", 0, "Admin UI session lifetime in hours (1-168, 0=default 8h)")
	s.geoIPDB = flag.String("geoip-db", "", "Path to GeoLite2-Country.mmdb (empty=GeoIP disabled)")
	s.clamavAddr = flag.String("clamav-addr", "", "ClamAV address: unix:/run/clamav/clamd.sock or tcp:host:port")
	s.yaraRulesDir = flag.String("yara-rules-dir", "", "Directory containing *.yar/*.yara YARA rule files")
	s.threatFeedDB = flag.String("threat-feed-db", "", "Path for persisted threat feed JSON database")
	s.uiUsersFile = flag.String("ui-users-file", "", "Path to persist admin UI users across restarts (e.g. /data/ui_users.json)")
	s.fileProfilesFile = flag.String("fileprofiles-file", "", "Path to persist file extension profiles (e.g. /data/fileprofiles.json)")
	s.idpProfilesFile = flag.String("idp-profiles-file", "", "Path to persist IdP profiles (OIDC/SAML SSO) across restarts (e.g. /data/idp_profiles.json); overrides proxy.idp_profiles_file")
	s.uiNoTLS = flag.Bool("ui-no-tls", false, "Disable auto self-signed TLS; serve admin UI over plain HTTP")
	s.catFeedDB = flag.String("cat-feed-db", "", "Directory for BadgerDB URL category community feed (empty=disabled)")
	s.catFeedURL = flag.String("cat-feed-url", "", "Override URL for the UT1 category tarball (default: UT1 Capestat)")
	s.catSyncIntvl = flag.String("cat-sync-interval", "24h", "How often to re-sync the URL category feed (e.g. 12h, 24h)")
	s.enrollURL = flag.String("enroll", "", "Enrollment URL from Control Plane (e.g. culvert://enroll/host:50051/TOKEN?ca-fp=sha256:...)")
	s.clusterDB = flag.String("cluster-db", "", "Path to persist cluster state (e.g. /data/cluster.json)")
	s.clusterInsecureFlag = flag.Bool("cluster-insecure", false, "Allow insecure (non-TLS) gRPC for development — NEVER use in production")
	s.revocationsFile = flag.String("revocations-file", "", "Path to persist session revocations across restarts (e.g. /data/revocations.json)")
	s.scanSvcListen = flag.String("scan-svc-listen", "", "Run as scan microservice sidecar on this address (e.g. :8484)")
	s.scanSvcURL = flag.String("scan-svc-url", "", "Remote scan service URL (e.g. http://scan-svc:8484) — disables local ClamAV/YARA")
	s.updaterURLFlag = flag.String("updater-url", "", "deprecated: legacy updater sidecar removed; flag accepted but ignored")
	s.updaterURLAllowFlag = flag.String("updater-url-allowlist", "", "deprecated: legacy updater sidecar removed; flag accepted but ignored")
	s.uiSANsFlag = flag.String("ui-san", "", "Additional TLS SANs for self-signed cert (comma-separated IPs/hostnames)")
	s.trustFwdHeaders = flag.Bool("trust-forwarded-headers", false, "Trust X-Forwarded-* headers (enable when behind reverse proxy)")
	s.resetPwUser = flag.String("reset-password", "", "Reset admin password and exit (format: username:newpassword)")
	s.supportBundleOut = flag.String("support-bundle", "", "Write a redacted csb/1 support bundle to the given path and exit; runs headless (no server) over the minimal L0 collector set (M1 recovery one-shot)")
	s.backupOut = flag.String("backup", "", "Pack /data into a tar.gz at the given path and exit (D1.3a)")
	s.backupEncrypt = flag.Bool("encrypt", false, "Encrypt the --backup tarball with AES-256-GCM (D1.4); requires "+backupPassphraseEnv+" env var. Lose the passphrase, lose the backup.")
	s.restoreIn = flag.String("restore", "", "Validate a backup tarball and print restore plan (dry-run; D1.3b.1)")
	s.restoreMode = flag.String("mode", "", "Restore mode: full | trust-root-only | state-only (D1.3b.2a; default: full)")
	s.restoreConfirm = flag.Bool("confirm", false, "Commit the restore destructively (D1.3b.2b). Without --confirm, --restore is a dry-run.")
	s.restoreAcceptDPReenroll = flag.Bool("accept-dp-reenrollment", false, "Acknowledge that restoring will require enrolled DPs to re-enroll (D1.3b.2a/b)")
	s.restoreAllowCounterRB = flag.Bool("allow-counter-rollback", false, "Acknowledge that restoring will roll back TOTP counters for some users (D1.3b.2a/b)")
	s.listLeftovers = flag.Bool("list-restore-leftovers", false, "List restore leftover .bak/.staging dirs (siblings of dataDir) and exit (D1.3c)")
	s.cleanupLeftovers = flag.Bool("cleanup-restore-leftovers", false, "Plan/execute cleanup of restore leftover .bak/.staging dirs and exit; dry-run unless --confirm is set (D1.3c)")
	s.cleanupOlderThan = flag.String("older-than", "", "Cleanup filter: only candidates older than this duration (strict time.ParseDuration syntax, e.g. 168h, 720h) (D1.3c)")
	s.cleanupKeepLast = flag.Int("keep-last", 0, "Cleanup filter: always keep the N newest .bak directories; .staging is unaffected (D1.3c)")
	s.listBackups = flag.Bool("list-backups", false, "List backup archives in --backup-dir (default /backup) as a JSON array on stdout and exit (D1.6b)")
	s.listBackupsDir = flag.String("backup-dir", "/backup", "Directory scanned by --list-backups; must be an absolute path (D1.6b)")
	// CDR / Sluice integration (Phase 1: single-instance client with TOFU pinning).
	s.cdrEnabledFlag = flag.Bool("cdr-enabled", false, "Enable Sluice CDR integration (strip macros/JS/OLE from downloads)")
	s.cdrEndpointFlag = flag.String("cdr-endpoint", "", "Sluice gRPC endpoint (e.g. sluice:8443)")
	s.cdrFailModeFlag = flag.String("cdr-fail-mode", "", "Behaviour when Sluice is unreachable: open (default) | closed")
	s.cdrProfileFlag = flag.String("cdr-default-profile", "", "Sanitization profile name sent when no policy matches (default: \"default\")")
	s.cdrModeFlag = flag.String("cdr-default-mode", "", "Default Mode: ENFORCE (default) | REPORT_ONLY | BYPASS_WITH_REPORT")
	s.cdrTimeoutFlag = flag.Int("cdr-timeout-sec", 0, "Per-file CDR deadline in seconds (>=30, default 35)")
	s.cdrMaxSizeFlag = flag.Int("cdr-max-file-size-mb", 0, "Reject CDR payloads larger than this (default 50 MB)")
	s.cdrFingerprintFlag = flag.String("cdr-server-fingerprint", "", "TOFU-pinned SHA-256 of Sluice's server cert (hex; 'sha256:' prefix optional)")
	s.cdrCertsDirFlag = flag.String("cdr-certs-dir", "", "Directory holding Sluice mTLS client bundle (ca.pem, client.pem, client.key)")
	flag.Parse()
}

// handleOneShotCommands handles one-shot CLI commands that exit before starting the proxy.
//
// distinct os.Exit semantics and its own error reporting. Splitting per
// branch into helpers would scatter the exit codes and obscure the
// dispatcher shape — readability beats the metric here.
//
//nolint:cyclop,gocognit // Flat one-shot dispatch table: each branch has
func handleOneShotCommands(s *startupState) {
	// ── One-shot: recovery support bundle (M1) — headless, no server ──────
	if *s.supportBundleOut != "" {
		if err := runSupportBundleCommand(*s.supportBundleOut); err != nil {
			fmt.Fprintf(os.Stderr, "Support bundle error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	// ── One-shot: backup/export (D1.3a unencrypted; D1.4 encrypted) ───────
	if *s.backupOut != "" {
		if err := runBackupCommand(s); err != nil {
			fmt.Fprintf(os.Stderr, "Backup error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	// ── One-shot: restore (D1.3b.1 dry-run + D1.3b.2a analyzer + D1.3b.2b commit) ─
	//nolint:nestif // Same one-shot dispatch shape as --reset-password
	// and --backup; flattening into helpers would scatter the dry-run
	// vs commit branching and obscure the os.Exit semantics.
	if *s.restoreIn != "" {
		passphrase := os.Getenv(caPassphraseEnv)
		mode, merr := parseRestoreMode(*s.restoreMode)
		if merr != nil {
			fmt.Fprintf(os.Stderr, "Restore validation error: %v\n", merr)
			os.Exit(1)
		}
		opts := restoreOpts{
			Mode:                 mode,
			AcceptDPReenrollment: *s.restoreAcceptDPReenroll,
			AllowCounterRollback: *s.restoreAllowCounterRB,
			BackupPassphrase:     os.Getenv(backupPassphraseEnv),
		}
		if *s.restoreConfirm {
			if err := runRestoreCommit(*s.restoreIn, dataDir, passphrase, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Restore commit error: %v\n", err)
				os.Exit(1)
			}
		} else {
			if err := runRestoreDryRun(*s.restoreIn, dataDir, passphrase, opts); err != nil {
				fmt.Fprintf(os.Stderr, "Restore validation error: %v\n", err)
				os.Exit(1)
			}
		}
		os.Exit(0)
	}
	// ── One-shot: list restore leftovers (D1.3c) ───────────────────────────
	if *s.listLeftovers {
		if err := runListLeftovers(dataDir); err != nil {
			fmt.Fprintf(os.Stderr, "List leftovers error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	// ── One-shot: list backup archives (D1.6b) ─────────────────────────────
	if *s.listBackups {
		if err := runListBackups(*s.listBackupsDir, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "List backups error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	// ── One-shot: cleanup restore leftovers (D1.3c) ────────────────────────
	if *s.cleanupLeftovers {
		if err := runCleanupCommand(s); err != nil {
			fmt.Fprintf(os.Stderr, "Cleanup error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	// ── One-shot: password reset (Finding 5.1) ─────────────────────────────
	if *s.resetPwUser != "" {
		parts := strings.SplitN(*s.resetPwUser, ":", 2)
		if len(parts) != 2 || parts[0] == "" || len(parts[1]) < 8 {
			fmt.Fprintln(os.Stderr, "Usage: --reset-password username:newpassword (min 8 chars)")
			os.Exit(1)
		}
		usersPath := *s.uiUsersFile
		if usersPath == "" {
			usersPath = "/data/ui_users.json"
		}
		cfg.SetUIUsersFile(usersPath)
		_ = cfg.LoadUIUsersFile() // may not exist yet, that's fine
		if err := cfg.SetUIUser(parts[0], parts[1], RoleAdmin); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := cfg.SaveUIUsersFile(); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Password reset for %q (role=admin). You can now start the proxy.\n", parts[0])
		os.Exit(0)
	}
}

// runCleanupCommand parses cleanup-restore-leftovers flags and dispatches
// to runCleanupLeftovers. Extracted from handleOneShotCommands so the
// dispatch table stays flat (avoids nestif on the cleanup branch).
// runBackupCommand dispatches the --backup one-shot. Without --encrypt,
// produces a D1.3a unencrypted tar.gz. With --encrypt, demands the
// CULVERT_BACKUP_PASSPHRASE env var, warns on short passphrases, and
// produces a D1.4 AES-256-GCM-sealed blob. Refuses to overwrite an
// existing output path (matches D1.3a semantics).
func runBackupCommand(s *startupState) error {
	if *s.backupEncrypt {
		passphrase := os.Getenv(backupPassphraseEnv)
		if passphrase == "" {
			return fmt.Errorf("--encrypt requires %s env var (D1.4 does not support interactive prompts)", backupPassphraseEnv)
		}
		if len(passphrase) < backupPassphraseMinLen {
			fmt.Fprintf(os.Stderr, "WARN: backup passphrase is shorter than %d chars; AES-256 strength is gated by passphrase entropy\n", backupPassphraseMinLen)
		}
		if err := runBackupEncrypted(*s.backupOut, dataDir, passphrase); err != nil {
			return err
		}
		fmt.Printf("Backup written to %s (encrypted, AES-256-GCM, PBKDF2-SHA256/%d)\n", *s.backupOut, backupEncKDFIters)
		return nil
	}
	if err := runBackup(*s.backupOut, dataDir); err != nil {
		return err
	}
	fmt.Printf("Backup written to %s\n", *s.backupOut)
	return nil
}

func runCleanupCommand(s *startupState) error {
	var older time.Duration
	if *s.cleanupOlderThan != "" {
		d, perr := time.ParseDuration(*s.cleanupOlderThan)
		if perr != nil {
			return fmt.Errorf("invalid --older-than: %w", perr)
		}
		if d <= 0 {
			return fmt.Errorf("--older-than must be positive")
		}
		older = d
	}
	if *s.cleanupKeepLast < 0 {
		return fmt.Errorf("--keep-last must be >= 0")
	}
	return runCleanupLeftovers(dataDir, cleanupOpts{
		Confirm:   *s.restoreConfirm,
		OlderThan: older,
		KeepLast:  *s.cleanupKeepLast,
	})
}

// setInsecureFlag propagates the --cluster-insecure flag to the package global.
func setInsecureFlag(s *startupState) {
	clusterInsecure = *s.clusterInsecureFlag
}

// runEnrollmentMode enrolls with a Control Plane when --enroll is set.
func runEnrollmentMode(s *startupState) {
	// ── Enrollment mode — enroll then continue as DP ────────────────────
	if *s.enrollURL != "" {
		ec, err := runEnrollment(*s.enrollURL)
		if err != nil {
			log.Fatalf("Enrollment failed: %v", err)
		}
		s.enrolledConfig = ec
	}
}

// loadFileConfigAndFlags loads the config file and resolves CLI flag overrides.
func loadFileConfigAndFlags(s *startupState) {
	// ── Load file config (if provided) ──────────────────────────────────────
	s.fc = &FileConfig{}
	if *s.configPath != "" {
		loaded, err := loadFileConfig(*s.configPath)
		if err != nil {
			log.Fatalf("Cannot load config file: %v", err)
		}
		s.fc = loaded
		fmt.Printf("[Culvert] Loaded config from %s\n", *s.configPath)
	}

	// CLI flags override file config.
	s.pPort = firstNonZero(*s.proxyPort, s.fc.Proxy.Port, 8080)
	s.uPort = firstNonZero(*s.uiPortFlag, s.fc.Proxy.UIPort, 9090)
	s.socks5PortVal = firstNonZero(*s.socks5Port, s.fc.Proxy.SOCKS5Port)
	// Checked on the RESOLVED values (after CLI overrides and firstNonZero
	// defaults), not the raw config.yaml fields: a raw-field check would both
	// reject a config a CLI override later makes non-colliding, and miss a
	// collision created by an omitted field silently taking its default
	// (e.g. ui_port explicitly 8080 with port omitted, which defaults to
	// 8080 too). Must run before any of the three listeners bind, so a
	// collision fails fast here instead of deep into startup with a bare
	// OS-level "listen tcp :N: bind: address already in use".
	if err := validatePortCollisions(s.pPort, s.uPort, s.socks5PortVal); err != nil {
		log.Fatalf("Invalid port configuration: %v", err)
	}
	s.lPath = firstStr(*s.logFilePath, s.fc.Proxy.LogFile)
	s.blPath = firstStr(*s.blockFile, s.fc.Proxy.Blocklist)
	s.lMaxMB = firstNonZero(*s.logMaxMB, s.fc.Proxy.LogMaxMB, 50)
	s.authU = firstStr(*s.user, s.fc.Auth.User)
	s.authP = firstStr(*s.pass, s.fc.Auth.Pass)
	s.cert = firstStr(*s.tlsCert, s.fc.Proxy.TLSCert)
	s.key = firstStr(*s.tlsKey, s.fc.Proxy.TLSKey)
	s.cert, s.key = resolveUITLSCertKey(s.cert, s.key)
	s.rlRPM = firstNonZero(*s.rateLimitRPM, s.fc.Security.RateLimit)
	s.ipModeVal = firstStr(*s.ipMode, s.fc.Security.IPFilterMode)
}

// initUIExtras is the PR3 expansion shim: resolve the UI-extras slice
// (TLS SANs + trust-forwarded-headers) and apply it.
func initUIExtras(s *startupState) {
	loadUIExtras(resolveUIExtrasStartupConfig(s.fc, *s.uiSANsFlag, *s.trustFwdHeaders))
}

// initLogger sets up the rotating logger and stores the closer on startupState.
func initLogger(s *startupState) {
	// ── Logger ───────────────────────────────────────────────────────────────
	var err error
	logger, s.logCloser, err = setupLogger(s.lPath, s.lMaxMB, s.fc.LogFormat)
	if err != nil {
		log.Fatalf("Logger setup failed: %v", err)
	}
	SetLogLevel(ParseLogLevel(s.fc.LogLevel))
	// Route internal/* package logs (obs facade) into the same logger. Published
	// once here at startup, before any traffic is served (ADR-0003 seam).
	obs.SetSink(func(line string) { logger.Print(line) })
}

// initLifecycleContext creates the app-wide lifecycle context.
func initLifecycleContext(s *startupState) {
	// ── Lifecycle context for all background goroutines ─────────────────────
	appLifecycleCtx, appLifecycleCancel = context.WithCancel(context.Background()) // #nosec G118 -- cancel is deferred in main()
}

// initAuth wires basic auth and loads persisted UI users. P4.4 / S1:
// the implementation lives in auth_startup.go + auth_startup_config.go;
// this is a thin shim that resolves the slice config and hands it to
// the loader. All five inputs are already-resolved scalars from
// startupState (4 fields populated by loadFileConfigAndFlags, plus
// *s.uiUsersFile which is CLI-only). The `cfg` package-global
// singleton is unchanged — the loader only wraps existing cfg
// method calls.
func initAuth(s *startupState) {
	loadAuth(resolveAuthStartupConfig(
		s.pPort,
		s.uPort,
		s.authU,
		s.authP,
		*s.uiUsersFile,
	))
}

// initSession is the PR3 expansion shim: resolve the session slice
// (HMAC secret + revocations file + TTL) and apply it.
func initSession(s *startupState) {
	cfg := resolveSessionStartupConfig(s.fc, *s.revocationsFile, *s.sessionHrs)
	if err := loadSession(cfg); err != nil {
		logger.Printf("Session: failed to load revocations: %v", err)
	}
}

// initObservability configures syslog, OTLP export, and persistent
// audit/request logs. P4.3 / S1: the implementation lives in
// observability_startup.go + observability_startup_config.go; this is
// a thin shim that resolves the slice config and hands it to the
// loader. No carry to startupState — the file handles stay on their
// owning packages' state (globalSyslog, internal/audit, internal/reqlog)
// and continue to be released by the existing syslog-close / audit-log-
// close / request-log-close shutdown hooks.
func initObservability(s *startupState) {
	loadObservability(resolveObservabilityStartupConfig(
		s.fc,
		*s.syslogAddr,
		*s.syslogFormat,
		*s.otlpEndpoint,
		*s.auditLog,
		*s.requestLogPath,
		*s.requestLogMaxMB,
	))
}

// initGeoIP is the PR3 expansion shim: resolve the GeoIP DB slice, stash
// the resolved path on startupState for startAdminUI, and apply it.
func initGeoIP(s *startupState) {
	cfg := resolveGeoIPStartupConfig(s.fc, *s.geoIPDB)
	s.geoDBVal = cfg.DBPath
	loadGeoIP(cfg)
}

// initUIAccessPolicy is the PR3 expansion shim: resolve the UI access
// policy slice (IP allowlist + base URL + IdP registry) and apply it.
func initUIAccessPolicy(s *startupState) {
	cfg := resolveUIAccessPolicyStartupConfig(s.fc, *s.uiAllowIP, *s.trustedProxyCIDRs, *s.idpProfilesFile)
	if err := loadUIAccessPolicy(cfg); err != nil {
		log.Fatalf("%v", err)
	}
}

// initPAC is the PR3 expansion shim: resolve the PAC slice (config
// path + default proxy port) and apply it.
func initPAC(s *startupState) {
	cfg := resolvePACStartupConfig(dataDir, s.pPort)
	if err := loadPAC(cfg); err != nil {
		log.Fatalf("%v", err)
	}
}

// initLegacyAuthProviders is the PR3 expansion shim: resolve the legacy
// LDAP / OIDC-introspection provider slice and apply it.
func initLegacyAuthProviders(s *startupState) {
	c := resolveLegacyAuthProvidersStartupConfig(s.fc, s.authU)
	if err := loadLegacyAuthProviders(c); err != nil {
		log.Fatalf("%v", err)
	}
}

// initMetricsToken is the PR3 expansion shim: resolve the /metrics Bearer
// token slice and apply it.
func initMetricsToken(s *startupState) {
	loadMetricsToken(resolveMetricsTokenStartupConfig(s.fc, *s.metricsTok))
}

// initCluster starts Control Plane / Data Plane gRPC and HA failover.
// initCluster resolves the cluster slice config and hands it to the loader
// (cluster_startup*.go), which owns the CP/HA-standby/HA-resume boot flow
// (ADR-0004) and the 3-priority Data-Plane wiring. The fresh-enrollment
// result is a runtime input passed alongside the resolved config.
func initCluster(s *startupState) {
	loadCluster(
		resolveClusterStartupConfig(s.fc, clusterCLIFlags{
			ClusterDB:       *s.clusterDB,
			CPGRPCAddr:      *s.cpGRPCAddr,
			CPGRPCCert:      *s.cpGRPCCert,
			CPGRPCKey:       *s.cpGRPCKey,
			CPGRPCCA:        *s.cpGRPCCA,
			HAJoin:          *s.haJoin,
			HAToken:         *s.haToken,
			HAAutoFailover:  *s.haAutoFailover,
			HAEtcdEndpoints: *s.haEtcdEndpoints,
			HAEtcdCert:      *s.haEtcdCert,
			HAEtcdKey:       *s.haEtcdKey,
			HAEtcdCA:        *s.haEtcdCA,
			HALeaseTTLSec:   *s.haLeaseTTL,
			DPCPAddr:        *s.dpCPAddr,
			DPNodeID:        *s.dpNodeID,
			DPCert:          *s.dpCert,
			DPKey:           *s.dpKey,
			DPCA:            *s.dpCA,
		}),
		appLifecycleCtx,
		s.enrolledConfig,
	)
}

// initConnAndRateLimit configures per-IP connection limits, IP filter, and
// rate limiter. P4.2 / S1: the implementation lives in connlimit_startup.go
// + connlimit_startup_config.go; this is a thin shim that resolves the
// slice config, hands it to the loader, and stores the returned cancel
// func on startupState so the early-phase `rate-limit-cleanup-cancel`
// shutdown hook (main.go:1428–1430) can stop the cleanup goroutine.
// s.ipModeVal and s.rlRPM are the already-resolved values from
// loadFileConfigAndFlags — keep them as the single source of truth for
// the CLI / FileConfig precedence rules.
func initConnAndRateLimit(s *startupState) {
	s.rlCleanupCancel = loadConnAndRateLimit(
		resolveConnAndRateLimitStartupConfig(s.fc, s.ipModeVal, s.rlRPM),
		appLifecycleCtx,
	)
}

// initBlocklist loads the blocklist from disk and starts the blocklist feed
// syncer. P4.1 / S1: the implementation lives in blocklist_startup.go +
// blocklist_startup_config.go; this is a thin shim that resolves the slice
// config and hands it to the loader. s.blPath is the already-resolved path
// from loadFileConfigAndFlags — keep it as the single source of truth for
// path precedence.
func initBlocklist(s *startupState) {
	loadBlocklist(resolveBlocklistStartupConfig(s.fc, s.blPath), appLifecycleCtx)
}

// initRootCA resolves the Root-CA slice config and hands it to the loader
// (rootca_startup*.go). The passphrase is read from env HERE (never CLI —
// shift-left secret hygiene) and passed as a param so the resolver stays pure.
func initRootCA(s *startupState) {
	loadRootCA(
		resolveRootCAStartupConfig(s.fc, *s.caPath, os.Getenv(caPassphraseEnv)),
		appLifecycleCtx,
	)
}

// initPolicy loads the policy rules file into the global policy store.
func initPolicy(s *startupState) {
	// ── Policy engine ─────────────────────────────────────────────────────────
	polPath := firstStr(*s.policyFile, s.fc.Proxy.PolicyFile)
	if polPath != "" {
		if err := policyStore.Load(polPath); err != nil {
			logFatalf("Cannot load policy file: %v", err)
		}
		logger.Printf("Policy: %d rule(s) loaded from %s", len(policyStore.List()), polPath)
	} else {
		// Use an in-memory store (no persistence until a path is set).
		policyStore.path = ""
		logger.Printf("Policy: in-memory only (set -policy <file> for persistence)")
	}
	// policy-draft (G2): wire the candidate persistence path (sibling of the
	// policy file) and reload any draft a prior run left pending. In-memory
	// policy ⇒ in-memory draft.
	initPolicyDraft(polPath)
}

// initURLCategories loads URL categories, category groups, SaaS feed, and the community BadgerDB feed.
// initURLCategories resolves the URL-categories slice config and hands it to
// the loader (urlcategories_startup*.go); the returned UT1 feed syncer (nil
// when the community feed is disabled) is stashed on startupState.
func initURLCategories(s *startupState) {
	s.feedSyncer = loadURLCategories(
		resolveURLCategoriesStartupConfig(s.fc, dataDir, *s.catFeedDB, *s.catFeedURL, *s.catSyncIntvl),
		appLifecycleCtx,
	)
}

// initLogStore opens the Badger-backed request-log history store when a path is
// configured, wires it as the process-wide globalLogStore, and starts the size
// retention janitor parented to appLifecycleCtx. Disabled (no-op) when no path
// is set — the in-memory ring and optional JSONL writer still operate.
// initLogStore resolves the persistent log-store slice config and hands it to
// the loader. Implementation lives in logstore_startup_config.go (pure
// resolver + DTO) + logstore_startup.go (loader); env values are read HERE so
// the resolver stays pure (slice convention).
func initLogStore(s *startupState) {
	loadLogStore(
		resolveLogStoreStartupConfig(s.fc, dataDir,
			os.Getenv(logStorePassphraseEnv), os.Getenv(caPassphraseEnv)),
		appLifecycleCtx,
	)
}

// initFileBlocking sets up the file-extension blocker and named file-type profiles.
// initFileBlocking is the PR3 follow-up pilot shim: resolve the
// file-blocking slice of FileConfig and hand it to the domain loader.
// Behaviour is unchanged — loader errors are logged (non-fatal) so
// startup continues with in-memory defaults, matching the original body.
func initFileBlocking(s *startupState) {
	if err := loadFileBlocking(resolveFileBlockStartupConfig(s.fc, *s.fileProfilesFile, dataDir)); err != nil {
		logger.Printf("FileProfiles: load error (%v) — using in-memory defaults", err)
	}
}

// initSSLBypassAndDPI loads SSL bypass patterns and the DPI content scanner patterns.
// initSSLBypassAndDPI is the PR3 pilot shim: resolve the inspection-rules
// slice of FileConfig and hand it to the domain loader. Behaviour and fatal
// semantics are unchanged — the loader returns errors, main fails fast.
func initSSLBypassAndDPI(s *startupState) {
	if err := loadInspectionRules(resolveInspectionRulesConfig(s.fc)); err != nil {
		logFatalf("inspection rules: %v", err)
	}
}

// initRewriteAndDefaultAction is the PR3 expansion shim: resolve the
// header-rewrite + default-policy-action slice and apply it. Passes
// the current policy-rule count so the loader can derive the zero-
// trust-vs-passthrough default when fc.DefaultAction is unset.
func initRewriteAndDefaultAction(s *startupState) {
	cfg := resolveRewriteDefaultActionStartupConfig(s.fc)
	loadRewriteAndDefaultAction(cfg, len(policyStore.List()))
}

// initScanning wires up ClamAV, YARA, threat feeds, and the optional scan microservice sidecar.
// initScanning resolves the security-scanning slice config and hands it to
// the loader (scanning_startup*.go); the returned sidecar service (nil unless
// --scan-svc-listen) is stashed on startupState for graceful shutdown.
func initScanning(s *startupState) {
	s.scanSvc = loadScanning(
		resolveScanningStartupConfig(s.fc, scanningCLIFlags{
			ClamAVAddr:    *s.clamavAddr,
			YARARulesDir:  *s.yaraRulesDir,
			ThreatFeedDB:  *s.threatFeedDB,
			ScanSvcURL:    *s.scanSvcURL,
			ScanSvcListen: *s.scanSvcListen,
		}, dataDir),
		appLifecycleCtx,
	)
}

// initUpstreamProxy configures parent-proxy chaining. Runs even when the
// YAML seeds no proxies so the pool records the configured circuit-breaker
// parameters and the health-check loop starts — GUI-added proxies (restored
// from admin_settings.json or POSTed to /api/upstream) then inherit both.
func initUpstreamProxy(s *startupState) {
	initUpstreamPool(s.fc)
}

// initCDR wires Sluice CDR configuration, persistent state, client, and health poller.
// initCDR resolves the CDR (Sluice) slice config and hands it to the loader
// (cdr_startup*.go). CLI flag values are packed here; the runtime
// enable-sentinel is read by the loader (filesystem side effect).
func initCDR(s *startupState) {
	// Mirror config.yaml's cdr.fail_mode validation (validateCDR, config.go)
	// on the CLI path: an invalid -cdr-fail-mode value must fail loud at
	// startup, not silently reach CDRFailOpen() — which treats any value
	// other than the exact string "closed" as fail-OPEN.
	if fm := *s.cdrFailModeFlag; !validCDRFailMode(fm) {
		log.Fatalf("Invalid -cdr-fail-mode %q: must be \"open\" or \"closed\"", fm)
	}
	loadCDR(
		resolveCDRStartupConfig(s.fc, cdrCLIFlags{
			Enabled:     *s.cdrEnabledFlag,
			Endpoint:    *s.cdrEndpointFlag,
			FailMode:    *s.cdrFailModeFlag,
			Profile:     *s.cdrProfileFlag,
			Mode:        *s.cdrModeFlag,
			TimeoutSec:  *s.cdrTimeoutFlag,
			MaxSizeMB:   *s.cdrMaxSizeFlag,
			Fingerprint: *s.cdrFingerprintFlag,
			CertsDir:    *s.cdrCertsDirFlag,
		}),
		appLifecycleCtx,
	)
}

// initMTLSAndOCSP is the PR3 expansion shim: resolve the upstream
// mTLS + OCSP slice and apply it.
func initMTLSAndOCSP(s *startupState) {
	loadMTLSAndOCSP(resolveMTLSOCSPStartupConfig(s.fc))
}

// initBackgroundServices starts the SSE broadcaster and the alert-retry queue.
// It resolves the (now config-free) background-services slice and hands it to
// the loader (background_services_startup*.go).
func initBackgroundServices(s *startupState) {
	loadBackgroundServices(
		resolveBackgroundServicesStartupConfig(s.fc),
		appLifecycleCtx,
	)
}

// initSOCKS5 starts the optional SOCKS5 listener. The accept loop is owned
// by socks5Server (constructed inside startSOCKS5), which is Stop'able via
// runProxyUntilShutdown. P1.5 / S4.SOCKS5.
func initSOCKS5(s *startupState) {
	// ── SOCKS5 server (optional) ─────────────────────────────────────────────
	// s.socks5PortVal is resolved once in loadFileConfigAndFlags (and already
	// checked there for collisions against pPort/uPort) — reused here rather
	// than recomputed so the bound port is guaranteed to be the same value
	// that was validated.
	if s.socks5PortVal > 0 {
		s.socks5Srv = startSOCKS5(s.socks5PortVal)
	}
}

// initPersistentAdminState initializes config versioning, node groups, bandwidth, hit counters, and admin settings.
// initPersistentAdminState resolves the persistent-admin-state slice config
// and hands it to the loader (persistent_admin_state_startup*.go). The loader
// documents the ordering contract (probe → versioning → stores → hit counters
// → admin settings LAST).
func initPersistentAdminState(_ *startupState) {
	loadPersistentAdminState(resolvePersistentAdminStateStartupConfig(dataDir), appLifecycleCtx)
}

// initPolicyLearning resolves the policy-learning slice config and hands it to
// the loader (policy_learning_startup*.go). Enablement is AdminSettings-governed
// (ADR-0025 M5A) and OFF by default: with no admin ever having enabled the
// feature this is a true no-op — no engine, no file, no goroutine. There is
// deliberately no CLI/YAML/env enablement path, so the resolver reads only
// node-local paths.
func initPolicyLearning(s *startupState) {
	loadPolicyLearning(resolvePolicyLearningStartupConfig(s.fc, dataDir))
}

// startAdminUI wires UI globals and launches the admin UI server.
// The server's listen goroutine is spawned inside startUI; the returned
// *http.Server handle is stashed on startupState so runProxyUntilShutdown
// can call Shutdown(ctx) on it during graceful teardown. P1.1 / S4.AdminUI.
func startAdminUI(s *startupState) {
	// ── Web UI ────────────────────────────────────────────────────────────
	uiCfgGeoIPDB = s.geoDBVal
	uiCfgLogFile = s.lPath
	uiCfgLogMaxMB = s.lMaxMB
	uiCfgLogFormat = s.fc.LogFormat
	s.adminUISrv = startUI(s.uPort, s.cert, s.key, *s.uiNoTLS)
}

// buildAndStartProxyServer constructs the proxy HTTP server and logs startup.
func buildAndStartProxyServer(s *startupState) *http.Server {
	// ── Proxy server ─────────────────────────────────────────────────────────
	// NOTE: http.ServeMux cannot be used here because it "cleans" URLs and
	// issues a 301 redirect when the path is empty — which is always the case
	// for CONNECT requests (HTTPS tunnels). Using a plain HandlerFunc avoids
	// the redirect and lets handleRequest receive every proxy request directly.
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if routeProxyListenerBuiltin(w, r) {
			return
		}
		handleRequest(w, r)
	})

	proxySrv := &http.Server{
		Addr:         fmt.Sprintf(":%d", s.pPort),
		Handler:      proxyHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	logger.Printf("Proxy: http://localhost:%d", s.pPort)
	if s.authU != "" {
		logger.Printf("Auth: enabled (user: %s)", s.authU)
	}
	return proxySrv
}

// sighupReloader owns the SIGHUP hot-reload goroutine. The goroutine exits
// when ctx is cancelled (lifecycle shutdown); on exit it calls signal.Stop
// on the signal channel so the OS-level signal handler is detached cleanly.
// P1.4 / S4.SIGHUP.
//
// The signal channel is supplied by the caller — production wires a
// signal.Notify-registered channel; tests pass an unregistered channel
// (signal.Stop is documented as a no-op for channels that were never
// registered, so the production teardown path is safe to exercise from tests).
type sighupReloader struct {
	sigCh  chan os.Signal
	reload func()
	done   chan struct{}
}

// newSighupReloader wires a reloader to the given signal channel and reload
// callback. The reloader does not register the channel — it expects the
// caller to have done so (production) or to pass an unregistered channel
// (tests).
func newSighupReloader(sigCh chan os.Signal, reload func()) *sighupReloader {
	return &sighupReloader{
		sigCh:  sigCh,
		reload: reload,
		done:   make(chan struct{}),
	}
}

// Done returns a channel that is closed after run returns. The
// implementation defers close(r.done) first and signal.Stop second; defers
// run LIFO, so signal.Stop runs before close(done) — the signal handler is
// detached before Done closes.
func (r *sighupReloader) Done() <-chan struct{} { return r.done }

// run blocks until ctx is cancelled. On each SIGHUP received it invokes
// the reload callback. Non-SIGHUP values are ignored. A closed signal
// channel terminates the loop (ok == false) so a stale or test-controlled
// channel cannot spin the reload callback. Must not be called more than
// once on the same reloader.
func (r *sighupReloader) run(ctx context.Context) {
	defer close(r.done)
	defer signal.Stop(r.sigCh)
	for {
		select {
		case <-ctx.Done():
			return
		case sig, ok := <-r.sigCh:
			if !ok {
				return
			}
			if sig == syscall.SIGHUP {
				r.reload()
			}
		}
	}
}

// installSignalHandlers registers SIGINT/SIGTERM/SIGHUP handlers and spawns the SIGHUP
// hot-reload goroutine. Returns the quit and sighup channels (caller uses quit to block).
func installSignalHandlers(s *startupState) (quit, sighup chan os.Signal) {
	// ── Graceful shutdown ────────────────────────────────────────────────────
	quit = make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// ── Hot config reload (SIGHUP) ──────────────────────────────────────────
	// P1.4 / S4.SIGHUP: the SIGHUP loop is owned by sighupReloader and parented
	// to appLifecycleCtx. The reload behaviour (configPath → loadFileConfig →
	// applyHotReload) is preserved exactly.
	sighup = make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	reloader := newSighupReloader(sighup, func() {
		if *s.configPath == "" {
			logger.Println("SIGHUP received but no -config path set; ignoring")
			return
		}
		logger.Printf("SIGHUP received — reloading config from %s", *s.configPath)
		reloaded, err := loadFileConfig(*s.configPath)
		if err != nil {
			logger.Printf("Config reload error: %v — keeping current config", err)
			return
		}
		applyHotReload(reloaded)
		logger.Println("Config reloaded successfully")
	})
	go reloader.run(appLifecycleCtx)
	return quit, sighup
}

// runProxyUntilShutdown starts the proxy goroutine, blocks on quit, then
// runs the graceful shutdown sequence via shutdownRegistry. Hook execution
// order, per-hook log messages, and the 30s shutdown budget's start point
// are byte-equivalent to the previous hand-ordered body. P2.2 / S5.
//
// Two registries by design: the early registry (HA, gRPC, CDR, lifecycle
// cancel, rate-limit cleanup) runs with context.Background() — these calls
// pre-dated the 30s ctx in the original body and were never under any
// shutdown timeout. The late registry (scan-svc, admin UI, SOCKS5, proxy,
// tunnel drain, log/syslog/db closers) runs under a fresh 30s ctx whose
// `cancel` is deferred to the end. Splitting the sequence into two
// registries keeps the 30s budget scoped exactly as it was pre-PR.
func runProxyUntilShutdown(s *startupState, proxySrv *http.Server, quit chan os.Signal) {
	go func() {
		if err := proxySrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logFatalf("Proxy error: %v", err)
		}
	}()

	<-quit
	logger.Println("Shutting down gracefully…")

	// CHAOS-56: arm the escalation path BEFORE the sequence starts. Until
	// now signal.Notify had taken SIGINT/SIGTERM away from the Go runtime's
	// default terminate behaviour and nothing read `quit` again, so a second
	// signal — an impatient operator's Ctrl-C, an orchestrator escalating —
	// landed in the channel buffer and did nothing at all. The only way to
	// end a stalled shutdown was SIGKILL, which is exactly the outcome the
	// escalation is trying to avoid.
	stopEscalation := armShutdownEscalation(quit, os.Exit)
	defer stopEscalation()

	var early, late shutdownRegistry
	registerEarlyShutdownHooks(&early, s)
	registerLateShutdownHooks(&late, s, proxySrv)
	runShutdownSequence(&early, &late, defaultShutdownBudget)

	// Disarm as soon as the sequence is done, not at function exit: a stray
	// signal arriving in the gap would otherwise turn a shutdown that
	// COMPLETED into exit status 1. stop is idempotent, so the defer above
	// stays as the backstop for the paths that do not reach here.
	stopEscalation()

	// NOTE: the log sink is closed by the last flush hook, so this line
	// reaches stderr/stdout only if the process log has not been redirected
	// to a file-backed sink. The operator-visible completion record is the
	// "flushing durable state…" line runShutdownSequence emits BEFORE the
	// flush phase.
	logger.Println("Stopped.")
}

// armShutdownEscalation watches for a SECOND shutdown signal while the
// shutdown sequence runs and exits the process immediately when one arrives,
// flushing the process log first so the reason survives. Returns a function
// that stops the watcher.
//
// `exit` is injected so the escalation contract is testable without killing
// the test binary. CHAOS-56.
//
// A second signal is an explicit operator instruction to stop waiting, so it
// is honoured immediately rather than shortening a budget: the flush hooks
// that have already run are on disk, and the ones that have not are exactly
// what the operator has decided not to wait for. Exit code 1 (not 0) because
// the shutdown did not complete — an orchestrator reading the exit status
// must not record a forced teardown as a clean stop.
func armShutdownEscalation(quit <-chan os.Signal, exit func(int)) (stop func()) {
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case sig := <-quit:
			if !shouldEscalate(done) {
				return
			}
			logger.Printf("Second %v during shutdown — exiting immediately; in-flight tunnels and unflushed state are dropped", sig)
			flushLogSink()
			exit(1)
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

// shouldEscalate reports whether a signal just received on the quit channel
// should force an exit, given the escalation's disarm channel. False once the
// escalation has been disarmed.
//
// This exists as its own function because the case it guards is one Go makes
// NON-DETERMINISTIC: when the disarm and a second signal become ready at the
// same moment, the watcher's select picks uniformly between them, so half the
// time it took the signal branch and reported a shutdown that had COMPLETED as
// exit status 1 (Codex P2 on this PR). Re-checking the disarm makes
// "disarmed first" win every time.
//
// A gate that raced the scheduler to reproduce the tie could only ever be
// probabilistic, and this repo's rule is that a gate which can flake gets muted
// (see CHAOS-54's rejected scaling gates). Splitting the decision out makes it
// pin deterministically instead.
func shouldEscalate(done <-chan struct{}) bool {
	select {
	case <-done:
		return false
	default:
		return true
	}
}

// seedYARARules copies bundled starter rules from /app/yara to the target
// directory on first boot. Only copies if the target is empty or doesn't exist.
// This ensures starter rules are available when yaraDir points to a persistent
// volume (e.g. /data/yara) that starts empty on first deployment.
func seedYARARules(targetDir string) {
	const bundledDir = "/app/yara"
	if targetDir == bundledDir {
		return // same directory, no seeding needed
	}
	// Check if target already has rules.
	entries, _ := filepath.Glob(filepath.Join(targetDir, "*.yar"))
	yaraEntries, _ := filepath.Glob(filepath.Join(targetDir, "*.yara"))
	if len(entries)+len(yaraEntries) > 0 {
		return // already has rules, don't overwrite
	}
	// Check if bundled dir exists.
	bundled, _ := filepath.Glob(filepath.Join(bundledDir, "*.yar"))
	bundledYara, _ := filepath.Glob(filepath.Join(bundledDir, "*.yara"))
	bundled = append(bundled, bundledYara...)
	if len(bundled) == 0 {
		return // no bundled rules to seed
	}
	_ = os.MkdirAll(targetDir, 0o750)
	copied := 0
	for _, src := range bundled {
		data, err := os.ReadFile(src) // #nosec G304 -- src is from filepath.Glob on admin-configured bundledDir
		if err != nil {
			continue
		}
		// filepath.Base strips any directory component; filepath.Clean prevents traversal.
		safeName := filepath.Base(filepath.Clean(src))
		dst := filepath.Join(targetDir, safeName)
		// Verify the resolved path stays inside targetDir (defense-in-depth).
		if filepath.Dir(dst) != filepath.Clean(targetDir) {
			continue
		}
		if err := os.WriteFile(dst, data, 0o600); err == nil { // #nosec G703,G306 -- dst is validated by filepath.Dir containment check above
			copied++
		}
	}
	if copied > 0 {
		logger.Printf("YARA: seeded %d starter rule(s) from %s to %s", copied, bundledDir, targetDir)
	}
}

func firstNonZero(vals ...int) int {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}

// validatePortCollisions checks the three RESOLVED listener ports (proxy,
// admin UI, SOCKS5 — already merged through firstNonZero(CLI, config.yaml,
// default)) for duplicates. SOCKS5's documented "disabled" sentinel (0) is
// exempt. Returns an error naming the two colliding ports, or nil.
func validatePortCollisions(proxyPort, uiPort, socks5Port int) error {
	named := []struct {
		name string
		port int
	}{
		{"proxy port", proxyPort},
		{"UI port", uiPort},
		{"SOCKS5 port", socks5Port},
	}
	for i := range named {
		if named[i].port == 0 {
			continue
		}
		for j := i + 1; j < len(named); j++ {
			if named[j].port == 0 {
				continue
			}
			if named[i].port == named[j].port {
				return fmt.Errorf("%s and %s must not both be %d", named[i].name, named[j].name, named[i].port)
			}
		}
	}
	return nil
}

func firstStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// initUpstreamPool configures upstream proxy chaining from the file config.
// initUpstreamPool resolves the upstream-pool slice config and hands it to
// the loader (upstream_pool_startup*.go).
func initUpstreamPool(fc *FileConfig) {
	loadUpstreamPool(resolveUpstreamPoolStartupConfig(fc), appLifecycleCtx)
}

// initClusterCA initialises the cluster CA for node enrollment.
func initClusterCA(clusterDBPath string) {
	caDir := "."
	if idx := strings.LastIndex(clusterDBPath, "/"); idx >= 0 {
		caDir = clusterDBPath[:idx]
	}
	if err := globalClusterCA.InitOrLoad(caDir); err != nil {
		logger.Printf("ClusterCA: init error: %v — enrollment disabled", err)
	}
}

// enableControlPlane activates Control Plane mode: starts the gRPC server,
// initialises the cluster CA, and starts the heartbeat monitor.
// Safe to call at runtime from the admin API (idempotent — returns error if already CP).
func enableControlPlane(grpcAddr, certFile, keyFile, caFile, clusterDBPath string) error {
	clusterRoleMu.Lock()
	defer clusterRoleMu.Unlock()

	if clusterRole.role == "control-plane" {
		return fmt.Errorf("already running as control-plane")
	}
	if grpcAddr == "" {
		return fmt.Errorf("gRPC listen address is required")
	}

	// CHAOS-01: seed + arm the durable config-version floor BEFORE the first
	// publish so a restarted (or HA-promoted) CP never re-issues version
	// numbers at or below what running DPs have already seen.
	globalConfigStore.armVersionPersistence(filepath.Join(dataDir, cpConfigVersionFile))
	// Initial publish. A commit-time rejection (startup config already over a
	// cluster-sync cap) is logged + alerted + surfaced via LastPublishError;
	// the CP still serves locally, so boot continues.
	_ = globalConfigStore.Update(CurrentConfigSnapshot())
	initClusterCA(clusterDBPath)
	if err := StartControlPlaneGRPC(grpcAddr, certFile, keyFile, caFile); err != nil {
		return err
	}

	// Only set role after gRPC is successfully started.
	clusterRole.role = "control-plane"
	clusterRole.grpcAddr = grpcAddr
	clusterRole.certFile = certFile
	clusterRole.keyFile = keyFile
	clusterRole.caFile = caFile
	globalClusterStore.StartHeartbeatMonitor(appLifecycleCtx.Done())
	logger.Printf("ControlPlane: enabled via GUI (gRPC %s)", strings.ReplaceAll(grpcAddr, "\n", ""))
	return nil
}

// atomicWriteFile writes data to path durably: unique temp in same dir,
// chmod, fsync(file), close, rename, fsync(parent dir).
// Cleans up the temp file on any error after creation.
//
// Parent-dir fsync semantics (after the rename has succeeded):
//   - If the parent dir cannot be opened, skip silently (some filesystems and
//     Windows do not allow opening a directory for sync). The rename itself
//     has already published the new file.
//   - If d.Sync() returns EINVAL / ENOTSUP / EOPNOTSUPP, the filesystem does
//     not support fsync on directories — skip silently. The temp+rename above
//     already provides every durability guarantee that filesystem can offer.
//   - Any other Sync error is propagated as a real durability failure.
//   - The dir handle is always closed; a Close error is propagated only when
//     Sync did not already report an error.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	// Delegates to internal/fileutil (ADR-0003 seam). Kept as a thin wrapper so
	// all existing call sites stay unchanged.
	return fileutil.AtomicWrite(path, data, perm)
}

// applyHotReload applies safe-to-reload config values from a freshly parsed
// FileConfig. It only touches settings that can be changed without restarting
// listeners (blocklist, policy, rewrite rules, rate limit, default action, etc.).
func applyHotReload(fc *FileConfig) {
	// Blocklist
	if fc.Proxy.Blocklist != "" {
		if err := bl.Load(fc.Proxy.Blocklist); err != nil {
			logger.Printf("Reload: blocklist error: %v", err)
		} else {
			logger.Printf("Reload: blocklist %d entries", bl.Count())
		}
	}

	// Policy rules
	if fc.Proxy.PolicyFile != "" {
		if err := policyStore.Load(fc.Proxy.PolicyFile); err != nil {
			logger.Printf("Reload: policy error: %v", err)
		} else {
			logger.Printf("Reload: policy %d rules", len(policyStore.List()))
		}
	}

	// Default action
	if fc.DefaultAction != "" {
		setDefaultPolicyAction(fc.DefaultAction)
		logger.Printf("Reload: default action %s", fc.DefaultAction)
	}

	// Rate limit
	if fc.Security.RateLimit > 0 {
		rl.Configure(fc.Security.RateLimit, time.Minute)
		logger.Printf("Reload: rate limit %d req/min", fc.Security.RateLimit)
	}

	// IP filter
	if fc.Security.IPFilterMode != "" {
		ipf.SetMode(fc.Security.IPFilterMode)
		logger.Printf("Reload: IP filter mode %s", fc.Security.IPFilterMode)
	}

	// Rewrite rules
	if len(fc.Rewrite) > 0 {
		rewriter.SetRules(fc.Rewrite)
		logger.Printf("Reload: rewrite %d rules", len(fc.Rewrite))
	}

	// Upstream proxy pool. Gated on a non-empty YAML list so a reload with no
	// upstream section does not wipe GUI-configured proxies; resolution is
	// shared with the startup slice (resolveUpstreamPoolStartupConfig).
	if len(fc.Upstream.Proxies) > 0 {
		ucfg := resolveUpstreamPoolStartupConfig(fc)
		upstreamPool.Configure(ucfg.Proxies, ucfg.CBThreshold, ucfg.CBTimeout)
		applyUpstreamProxy()
		logger.Printf("Reload: upstream %s", formatUpstreamSummary(ucfg.Proxies))
	}
}
