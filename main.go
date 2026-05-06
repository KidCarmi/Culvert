// Culvert — Enterprise-grade open source HTTP/HTTPS proxy
// https://github.com/KidCarmi/Claude-Test
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// caPassphraseEnv holds the name of the environment variable that supplies the
// CA private-key encryption passphrase. Using an env var keeps the passphrase
// out of CLI history and process listings (shift-left: secrets management).
// This is an env-var name, NOT a credential — the false-positive is suppressed.
const caPassphraseEnv = "CULVERT_CA_PASSPHRASE" // #nosec G101 -- env-var name, not a credential

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
	sessionHrs              *int
	geoIPDB                 *string
	clamavAddr              *string
	yaraRulesDir            *string
	threatFeedDB            *string
	uiUsersFile             *string
	fileProfilesFile        *string
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
	updaterURLFlag          *string
	updaterURLAllowFlag     *string
	uiSANsFlag              *string
	trustFwdHeaders         *bool
	resetPwUser             *string
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
	adminUISrv      *http.Server // P1.1 / S4.AdminUI: graceful shutdown handle
}

func main() {
	s := &startupState{}
	parseFlags(s)
	handleOneShotCommands(s)
	setInsecureFlag(s)
	runEnrollmentMode(s)
	loadFileConfigAndFlags(s)
	initUIExtras(s)
	initLogger(s)
	initLifecycleContext(s)
	defer appLifecycleCancel() // kept in main() for panic safety; initLifecycleContext only creates the context.

	initAuth(s)
	initSession(s)
	initObservability(s)
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
	initRewriteAndDefaultAction(s)
	initScanning(s)
	initUpstreamProxy(s)
	initCDR(s)
	initMTLSAndOCSP(s)
	initBackgroundServices(s)
	initSOCKS5(s)
	initPersistentAdminState(s)
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
	s.logMaxMB = flag.Int("log-max-mb", 50, "Log rotation size in MB")
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
	s.dpCPAddr = flag.String("dp-cp-addr", "", "DataPlane: ControlPlane gRPC addr to connect to (comma-separated for HA failover)")
	s.dpNodeID = flag.String("dp-node-id", "", "DataPlane: node identifier (default=hostname)")
	s.dpCert = flag.String("dp-cert", "", "DataPlane gRPC client TLS cert")
	s.dpKey = flag.String("dp-key", "", "DataPlane gRPC client TLS key")
	s.dpCA = flag.String("dp-ca", "", "DataPlane gRPC CA cert")
	s.policyFile = flag.String("policy", "", "Policy rules JSON file path")
	s.caPath = flag.String("ca-path", "", "Path to persist encrypted Root CA bundle (optional)")
	s.auditLog = flag.String("audit-log", "", "Persistent audit log file path (JSONL, appended)")
	s.requestLogPath = flag.String("request-log", "", "Persistent request log file path (JSONL, rotated)")
	s.requestLogMaxMB = flag.Int("request-log-max-mb", 100, "Request log rotation size in MB")
	s.syslogAddr = flag.String("syslog", "", "Remote syslog addr e.g. udp://10.0.0.1:514 or tcp://host:601")
	s.syslogFormat = flag.String("syslog-format", "", "Syslog message format: rfc3164 (default) or rfc5424")
	s.otlpEndpoint = flag.String("otlp-endpoint", "", "OTLP/HTTP endpoint for metrics export (e.g. http://otel-collector:4318)")
	s.uiAllowIP = flag.String("ui-allow-ip", "", "Comma-separated CIDRs/IPs allowed to access admin UI (empty=all)")
	s.sessionHrs = flag.Int("session-timeout", 0, "Admin UI session lifetime in hours (1-168, 0=default 8h)")
	s.geoIPDB = flag.String("geoip-db", "", "Path to GeoLite2-Country.mmdb (empty=GeoIP disabled)")
	s.clamavAddr = flag.String("clamav-addr", "", "ClamAV address: unix:/run/clamav/clamd.sock or tcp:host:port")
	s.yaraRulesDir = flag.String("yara-rules-dir", "", "Directory containing *.yar/*.yara YARA rule files")
	s.threatFeedDB = flag.String("threat-feed-db", "", "Path for persisted threat feed JSON database")
	s.uiUsersFile = flag.String("ui-users-file", "", "Path to persist admin UI users across restarts (e.g. /data/ui_users.json)")
	s.fileProfilesFile = flag.String("fileprofiles-file", "", "Path to persist file extension profiles (e.g. /data/fileprofiles.json)")
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
	s.updaterURLFlag = flag.String("updater-url", "", "Updater sidecar URL (default http://culvert-updater:7123)")
	s.updaterURLAllowFlag = flag.String("updater-url-allowlist", "", "H4: comma-separated allowlist of permitted non-default updater URLs (empty ⇒ default + loopback only)")
	s.uiSANsFlag = flag.String("ui-san", "", "Additional TLS SANs for self-signed cert (comma-separated IPs/hostnames)")
	s.trustFwdHeaders = flag.Bool("trust-forwarded-headers", false, "Trust X-Forwarded-* headers (enable when behind reverse proxy)")
	s.resetPwUser = flag.String("reset-password", "", "Reset admin password and exit (format: username:newpassword)")
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
	s.lPath = firstStr(*s.logFilePath, s.fc.Proxy.LogFile)
	s.blPath = firstStr(*s.blockFile, s.fc.Proxy.Blocklist)
	s.lMaxMB = firstNonZero(*s.logMaxMB, s.fc.Proxy.LogMaxMB, 50)
	s.authU = firstStr(*s.user, s.fc.Auth.User)
	s.authP = firstStr(*s.pass, s.fc.Auth.Pass)
	s.cert = firstStr(*s.tlsCert, s.fc.Proxy.TLSCert)
	s.key = firstStr(*s.tlsKey, s.fc.Proxy.TLSKey)
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
}

// initLifecycleContext creates the app-wide lifecycle context.
func initLifecycleContext(s *startupState) {
	// ── Lifecycle context for all background goroutines ─────────────────────
	appLifecycleCtx, appLifecycleCancel = context.WithCancel(context.Background()) // #nosec G118 -- cancel is deferred in main()
}

// initAuth wires basic auth and loads persisted UI users.
func initAuth(s *startupState) {
	// ── Config ───────────────────────────────────────────────────────────────
	cfg.ProxyPort = s.pPort
	cfg.UIPort = s.uPort
	if err := cfg.SetAuth(s.authU, s.authP); err != nil {
		log.Fatalf("Failed to set auth: %v", err)
	}

	// ── UI user persistence ───────────────────────────────────────────────────
	// Load previously-created admin users from disk so auth survives restarts.
	// The file is written whenever a user is created/modified/deleted via the UI.
	if *s.uiUsersFile != "" {
		cfg.SetUIUsersFile(*s.uiUsersFile)
		if err := cfg.LoadUIUsersFile(); err != nil {
			logger.Printf("UIUsers: failed to load %s: %v", *s.uiUsersFile, err)
		} else if cfg.AuthEnabled() {
			logger.Printf("UIUsers: loaded from %s", *s.uiUsersFile)
		}
	}
}

// initSession is the PR3 expansion shim: resolve the session slice
// (HMAC secret + revocations file + TTL) and apply it.
func initSession(s *startupState) {
	cfg := resolveSessionStartupConfig(s.fc, *s.revocationsFile, *s.sessionHrs)
	if err := loadSession(cfg); err != nil {
		logger.Printf("Session: failed to load revocations: %v", err)
	}
}

// initObservability configures syslog, OTLP export, and persistent audit/request logs.
func initObservability(s *startupState) {
	// ── Syslog / SIEM forwarding ──────────────────────────────────────────────
	syslogVal := firstStr(*s.syslogAddr, s.fc.SyslogAddr)
	syslogFmtVal := firstStr(*s.syslogFormat, s.fc.SyslogFormat)
	if syslogVal != "" {
		if err := InitSyslog(syslogVal, syslogFmtVal); err != nil {
			logger.Printf("Syslog: connect failed (%v) — continuing without syslog", err)
		} else {
			syslogConfigured = syslogVal
		}
	}

	// ── OTLP export (metrics + traces) ──────────────────────────────────────
	otlpVal := firstStr(*s.otlpEndpoint, s.fc.OTLPEndpoint)
	if otlpVal != "" {
		globalOTLP.Configure(otlpVal, nil)
		globalOTLPTraces.Configure(otlpVal, nil)
	}

	// ── Persistent audit log ──────────────────────────────────────────────────
	auditLogVal := firstStr(*s.auditLog, s.fc.AuditLogFile)
	if auditLogVal != "" {
		if err := InitAuditLog(auditLogVal); err != nil {
			logger.Printf("Audit: log file error (%v) — falling back to in-memory", err)
		} else {
			logger.Printf("Audit: persisting to %s", auditLogVal)
		}
	}

	// ── Persistent request log (Finding 6.1) ────────────────────────────────
	reqLogVal := firstStr(*s.requestLogPath, s.fc.RequestLogFile)
	reqLogMB := firstNonZero(*s.requestLogMaxMB, s.fc.RequestLogMaxMB, 100)
	if reqLogVal != "" {
		if err := initRequestLog(reqLogVal, reqLogMB); err != nil {
			logger.Printf("RequestLog: file error (%v) — falling back to in-memory only", err)
		} else {
			logger.Printf("RequestLog: persisting to %s (max %d MB)", reqLogVal, reqLogMB)
		}
	}
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
	cfg := resolveUIAccessPolicyStartupConfig(s.fc, *s.uiAllowIP)
	if err := loadUIAccessPolicy(cfg); err != nil {
		log.Fatalf("%v", err)
	}
}

// initPAC is the PR3 expansion shim: resolve the PAC slice (config
// path + default proxy port) and apply it.
func initPAC(s *startupState) {
	cfg := resolvePACStartupConfig(s.pPort)
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
func initCluster(s *startupState) {
	// ── Control Plane / Data Plane gRPC ──────────────────────────────────────
	clusterRole.role = "standalone"
	if h, err2 := os.Hostname(); err2 == nil {
		clusterRole.nodeID = h
	}
	// ── Cluster state persistence ────────────────────────────────────────
	clusterDBPath := firstStr(*s.clusterDB, s.fc.Cluster.StateDB, "cluster.json")
	clusterDBPathGlobal = clusterDBPath
	if err := globalClusterStore.Load(clusterDBPath); err != nil {
		logger.Printf("ClusterDB: load error: %v — starting fresh", err)
	} else {
		nodes := globalClusterStore.ListNodes()
		if len(nodes) > 0 {
			logger.Printf("ClusterDB: loaded %d enrolled node(s) from %s", len(nodes), clusterDBPath)
		}
	}

	// Merge CLI flags with YAML cluster config (CLI wins).
	cpAddr := firstStr(*s.cpGRPCAddr, s.fc.Cluster.GRPCAddr)
	cpCert := firstStr(*s.cpGRPCCert, s.fc.Cluster.CertFile)
	cpKey := firstStr(*s.cpGRPCKey, s.fc.Cluster.KeyFile)
	cpCA := firstStr(*s.cpGRPCCA, s.fc.Cluster.CAFile)

	if *s.haJoin != "" && *s.haToken != "" {
		// ── HA Standby: sync state from leader, then stand by ────────
		initClusterCA(clusterDBPath)
		globalHA.StartAsStandby(appLifecycleCtx, *s.haJoin, *s.haToken,
			cpAddr, cpCert, cpKey, cpCA,
			func() error {
				return enableControlPlane(cpAddr, cpCert, cpKey, cpCA, clusterDBPath)
			},
		)
	} else if cpAddr != "" || s.fc.Cluster.Role == "control-plane" {
		// ── Normal CP startup ────────────────────────────────────────
		if err := enableControlPlane(cpAddr, cpCert, cpKey, cpCA, clusterDBPath); err != nil {
			logger.Fatalf("ControlPlane gRPC: %v", err)
		}
		// Check for persisted HA config (leader restart).
		if haCfg, err := loadHAConfig(); err == nil && haCfg.Enabled {
			globalHA.EnableAsLeader(haCfg.PeerAddr)
			globalHA.mu.Lock()
			globalHA.token = haCfg.Token // restore original token
			globalHA.mu.Unlock()
			logger.Printf("HA: restored leader state from %s (peer=%s)", haConfigFile, haCfg.PeerAddr)
		}
	}
	// ── Data Plane startup: from flags, enrollment, or saved config ─────────
	dpAddr, dpNID, dpCertF, dpKeyF, dpCAF := *s.dpCPAddr, *s.dpNodeID, *s.dpCert, *s.dpKey, *s.dpCA
	// Priority 1: fresh enrollment from this run.
	if s.enrolledConfig != nil && dpAddr == "" {
		dpAddr = s.enrolledConfig.CPAddr
		dpNID = s.enrolledConfig.NodeID
		dpCertF = s.enrolledConfig.CertFile
		dpKeyF = s.enrolledConfig.KeyFile
		dpCAF = s.enrolledConfig.CAFile
	}
	// Priority 2: saved enrollment config from a previous run.
	if dpAddr == "" {
		if ec, err := loadEnrollmentConfig(); err == nil {
			dpAddr = ec.CPAddr
			dpNID = ec.NodeID
			dpCertF = ec.CertFile
			dpKeyF = ec.KeyFile
			dpCAF = ec.CAFile
			logger.Printf("DataPlane: loaded enrollment config from %s", enrollmentConfigFile)
		}
	}
	if dpAddr != "" {
		startDataPlane(appLifecycleCtx, dpAddr, dpNID, dpCertF, dpKeyF, dpCAF)
	}
}

// initConnAndRateLimit configures per-IP connection limits, IP filter, and rate limiter.
func initConnAndRateLimit(s *startupState) {
	// ── Security: Connection limit per IP ────────────────────────────────────
	if s.fc.Security.MaxConnsPerIP > 0 {
		connLimiter.Enable(s.fc.Security.MaxConnsPerIP)
		logger.Printf("ConnLimit: max %d connections per IP", s.fc.Security.MaxConnsPerIP)
	}

	// ── Security: IP filter ──────────────────────────────────────────────────
	if s.ipModeVal != "" {
		ipf.SetMode(s.ipModeVal)
		for _, entry := range s.fc.Security.IPList {
			if err := ipf.Add(entry); err != nil {
				logger.Printf("IP filter: invalid entry %q: %v", entry, err)
			}
		}
		logger.Printf("IPFilter: mode=%s entries=%d", s.ipModeVal, len(s.fc.Security.IPList))
	}

	// ── Security: Rate limiter ───────────────────────────────────────────────
	if s.rlRPM > 0 {
		rl.Configure(s.rlRPM, time.Minute)
		logger.Printf("RateLimit: %d req/min per IP", s.rlRPM)
		var rlCtx context.Context
		rlCtx, s.rlCleanupCancel = context.WithCancel(appLifecycleCtx)
		go func() {
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-rlCtx.Done():
					return
				case <-t.C:
					rl.Cleanup()
					ssrfDNSCache.Cleanup()
				}
			}
		}()
	}
}

// initBlocklist loads the blocklist from disk and starts the blocklist feed syncer.
func initBlocklist(s *startupState) {
	// ── Blocklist ────────────────────────────────────────────────────────────
	if s.blPath != "" {
		if err := bl.Load(s.blPath); err != nil {
			if os.IsNotExist(err) {
				logger.Printf("Blocklist not found at %s — starting with empty list", s.blPath)
			} else {
				logger.Fatalf("Cannot load blocklist: %v", err)
			}
		} else {
			logger.Printf("Blocklist loaded: %d entries from %s", bl.Count(), s.blPath)
		}
	}

	// ── Blocklist feed sync ───────────────────────────────────────────────────
	blFeedURL := s.fc.Proxy.BlocklistFeedURL
	if blFeedURL != "" {
		blFeedInterval := blFeedDefaultInterval
		// Local name `iv` (not `s`) to avoid shadowing the *startupState parameter.
		if iv := s.fc.Proxy.BlocklistFeedInterval; iv != "" {
			if d, err := time.ParseDuration(iv); err == nil && d > 0 {
				blFeedInterval = d
			}
		}
		blFeedSyncer = newBlocklistSyncer(bl, blFeedURL, blFeedInterval)
		blFeedSyncer.Start(appLifecycleCtx)
		logger.Printf("BlocklistFeed: syncing from %s every %s", blFeedURL, blFeedInterval)
	} else {
		blFeedSyncer = newBlocklistSyncer(bl, "", blFeedDefaultInterval)
	}
}

// initRootCA loads or initialises the Root CA used for SSL inspection.
func initRootCA(s *startupState) {
	// ── Root CA for SSL inspection ────────────────────────────────────────────
	// Passphrase is read from env so it never appears in CLI history or
	// process listings (shift-left secret hygiene).
	caPassphrase := os.Getenv(caPassphraseEnv)
	caPathVal := firstStr(*s.caPath, s.fc.Proxy.CAPath)
	if caPathVal != "" {
		if err := certMgr.LoadOrInitCA(caPathVal, caPassphrase); err != nil {
			logger.Printf("Warning: Root CA load/init failed (%v) — SSL inspection disabled", err)
		} else {
			logger.Printf("SSLCA: Root CA ready (persisted at %s, encrypted=%v)", caPathVal, caPassphrase != "")
		}
	} else {
		if err := certMgr.InitCA(); err != nil {
			logger.Printf("Warning: Root CA init failed (%v) — SSL inspection disabled", err)
		} else {
			logger.Printf("SSLCA: Root CA ready in-memory (set -ca-path + %s for persistence)", caPassphraseEnv)
		}
	}
	// Store CA runtime config for API-driven rotation.
	caRuntime.path = caPathVal
	caRuntime.passphrase = caPassphrase
	// Start CA auto-rotation background check.
	if certMgr.Ready() {
		StartCAAutoRotation(appLifecycleCtx, caPathVal, caPassphrase)
	}
}

// initPolicy loads the policy rules file into the global policy store.
func initPolicy(s *startupState) {
	// ── Policy engine ─────────────────────────────────────────────────────────
	polPath := firstStr(*s.policyFile, s.fc.Proxy.PolicyFile)
	if polPath != "" {
		if err := policyStore.Load(polPath); err != nil {
			logger.Fatalf("Cannot load policy file: %v", err)
		}
		logger.Printf("Policy: %d rule(s) loaded from %s", len(policyStore.List()), polPath)
	} else {
		// Use an in-memory store (no persistence until a path is set).
		policyStore.path = ""
		logger.Printf("Policy: in-memory only (set -policy <file> for persistence)")
	}
}

// initURLCategories loads URL categories, category groups, SaaS feed, and the community BadgerDB feed.
func initURLCategories(s *startupState) {
	// ── URL Categories ────────────────────────────────────────────────────────
	catPath := s.fc.Proxy.URLCategoriesFile
	if catPath == "" {
		catPath = "categories.json"
	}
	if err := catStore.Load(catPath); err != nil {
		logger.Fatalf("Cannot load URL categories: %v", err)
	}
	logger.Printf("URLCat: %d categories loaded from %s", len(catStore.All()), catPath)

	// Seed empty catStore entries for all UT1 mapped category names so they
	// appear in the Category Groups dropdown. The names must exist in catStore
	// (Layer 1) for the GUI to list them, even though domains are in BadgerDB
	// (Layer 2). lookupHostCategory checks both layers for matching.
	ut1Seeded := 0
	seen := map[string]bool{}
	for _, mappedCat := range ut1CategoryMap {
		lc := strings.ToLower(mappedCat)
		if seen[lc] {
			continue
		}
		seen[lc] = true
		if catStore.GetByName(mappedCat) == nil {
			_ = catStore.Set(mappedCat, []string{}, true) // empty, built-in
			ut1Seeded++
		}
	}
	if ut1Seeded > 0 {
		catStore.Save()
		logger.Printf("URLCat: seeded %d UT1 category name(s) into catStore for GUI visibility", ut1Seeded)
	}

	// ── Category Groups ──────────────────────────────────────────────────────
	if err := globalCategoryGroups.Load(filepath.Join(dataDir, "category_groups.json")); err != nil {
		logger.Printf("CategoryGroups: load error: %v", err)
	}

	// ── SaaS category feed (dynamic updates from GitHub) ────────────────────
	// Auto-syncs curated SaaS categories (AI, Marketing, Messaging, etc.)
	// from the Culvert repo. Additive merge: new domains added, admin
	// removals preserved. Disabled by default; enable via admin GUI.
	globalSaaSFeed.Configure(defaultSaaSFeedURL, 24*time.Hour)

	// ── Community URL category feed (BadgerDB) ────────────────────────────────
	// When --cat-feed-db is set, open BadgerDB and start the UT1 FeedSyncer.
	// Layer 1 (catStore) remains the priority; BadgerDB is the fallback.
	if *s.catFeedDB == "" { //nolint:nestif // straightforward init block; nesting is necessary
		logger.Printf("CatFeedDB: disabled (set --cat-feed-db for community feed)")
	} else {
		var dbErr error
		communityDB, dbErr = openCommunityDB(*s.catFeedDB)
		if dbErr != nil {
			logger.Fatalf("CatFeedDB → cannot open BadgerDB at %s: %v", *s.catFeedDB, dbErr)
		}
		syncD := 24 * time.Hour
		if *s.catSyncIntvl != "" {
			if d, err2 := time.ParseDuration(*s.catSyncIntvl); err2 == nil {
				syncD = d
			}
		}
		s.feedSyncer = newFeedSyncer(communityDB, *s.catFeedURL, syncD)
		s.feedSyncer.Start(appLifecycleCtx)
		logger.Printf("CatFeedDB: BadgerDB at %s, sync every %s", *s.catFeedDB, syncD)
	}
}

// initFileBlocking sets up the file-extension blocker and named file-type profiles.
// initFileBlocking is the PR3 follow-up pilot shim: resolve the
// file-blocking slice of FileConfig and hand it to the domain loader.
// Behaviour is unchanged — loader errors are logged (non-fatal) so
// startup continues with in-memory defaults, matching the original body.
func initFileBlocking(s *startupState) {
	if err := loadFileBlocking(resolveFileBlockStartupConfig(s.fc, *s.fileProfilesFile)); err != nil {
		logger.Printf("FileProfiles: load error (%v) — using in-memory defaults", err)
	}
}

// initSSLBypassAndDPI loads SSL bypass patterns and the DPI content scanner patterns.
// initSSLBypassAndDPI is the PR3 pilot shim: resolve the inspection-rules
// slice of FileConfig and hand it to the domain loader. Behaviour and fatal
// semantics are unchanged — the loader returns errors, main fails fast.
func initSSLBypassAndDPI(s *startupState) {
	if err := loadInspectionRules(resolveInspectionRulesConfig(s.fc)); err != nil {
		logger.Fatalf("inspection rules: %v", err)
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
func initScanning(s *startupState) {
	// ── Security scanning: ClamAV + YARA + Threat Feeds ─────────────────────
	secCfg := s.fc.SecurityScan
	clamAddr := firstStr(*s.clamavAddr, secCfg.ClamAVAddr)
	yaraDir := firstStr(*s.yaraRulesDir, secCfg.YARARulesDir)
	feedDB := firstStr(*s.threatFeedDB, secCfg.ThreatFeedDB)

	// Remote scan service mode: delegate body scanning to a sidecar.
	remoteScanURL := firstStr(*s.scanSvcURL, secCfg.ScanSvcURL)
	if remoteScanURL != "" {
		globalRemoteScanner.Init(remoteScanURL)
		logger.Printf("ScanSvc: remote mode, delegating to %s", remoteScanURL)
		// Threat feeds still run locally (URL/domain checks are cheap).
		if feedDB != "" || secCfg.Enabled {
			syncInterval := 6 * time.Hour
			if secCfg.SyncInterval != "" {
				if d, err := time.ParseDuration(secCfg.SyncInterval); err == nil {
					syncInterval = d
				}
			}
			globalThreatFeed.Init(feedDB, syncInterval)
			globalThreatFeed.Start(appLifecycleCtx)
			logger.Printf("ThreatFeed: sync every %s, db=%q", syncInterval, feedDB)
		}
	} else if secCfg.Enabled || clamAddr != "" || yaraDir != "" || feedDB != "" {
		// Scan result cache TTL.
		cacheTTL := time.Hour
		if secCfg.CacheTTL != "" {
			if d, err := time.ParseDuration(secCfg.CacheTTL); err == nil {
				cacheTTL = d
			}
		}
		// Feed sync interval.
		syncInterval := 6 * time.Hour
		if secCfg.SyncInterval != "" {
			if d, err := time.ParseDuration(secCfg.SyncInterval); err == nil {
				syncInterval = d
			}
		}
		cacheSize := secCfg.CacheSize
		if cacheSize <= 0 {
			cacheSize = 10_000
		}
		var maxScanBytes int64
		if secCfg.MaxScanMB > 0 {
			maxScanBytes = int64(secCfg.MaxScanMB) << 20
		}

		// Initialise scanner and hash cache.
		globalSecScanner.cache = newHashCache(cacheSize, cacheTTL)
		globalSecScanner.Init(clamAddr, maxScanBytes)

		// YARA rules.
		if yaraDir != "" {
			// Seed the rules directory from the bundled /app/yara on first boot
			// so starter rules are available even when yaraDir points to a
			// persistent volume (e.g. /data/yara). Only copies if the target
			// directory is empty or doesn't exist.
			seedYARARules(yaraDir)
			if err := globalYARA.LoadDir(yaraDir); err != nil {
				logger.Printf("YARA: load error: %v", err)
			} else {
				logger.Printf("YARA: %d rule(s) from %s", globalYARA.Count(), yaraDir)
			}
		} else {
			logger.Printf("YARA: disabled (set -yara-rules-dir to enable)")
		}

		// Tier 3.3: admin-managed scan exclusion lists (hash + host allowlists).
		// Persisted under the same data directory as the rest of the state.
		if dataDir != "" {
			if err := globalScanExclusions.Load(filepath.Join(dataDir, "scan_exclusions.json")); err != nil {
				logger.Printf("ScanExclusions: load error: %v", err)
			}
		}

		// Threat feeds.
		if feedDB != "" || secCfg.Enabled {
			globalThreatFeed.Init(feedDB, syncInterval)
			globalThreatFeed.Start(appLifecycleCtx)
			logger.Printf("ThreatFeed: sync every %s, db=%q", syncInterval, feedDB)
		}
	}

	// Scan microservice sidecar: expose local scanners as an HTTP service.
	svcListenAddr := firstStr(*s.scanSvcListen, secCfg.ScanSvcListen)
	if svcListenAddr != "" {
		s.scanSvc = NewScanService(svcListenAddr)
		if err := s.scanSvc.Listen(); err != nil {
			logger.Printf("ScanSvc: listen error: %v", err)
		} else {
			go func() {
				if err := s.scanSvc.Start(); err != nil {
					logger.Printf("ScanSvc: error: %v", err)
				}
			}()
		}
	}
}

// initUpstreamProxy configures parent-proxy chaining when configured.
func initUpstreamProxy(s *startupState) {
	// ── Upstream proxy chaining ──────────────────────────────────────────────
	if len(s.fc.Upstream.Proxies) > 0 {
		initUpstreamPool(s.fc)
	}
}

// initCDR wires Sluice CDR configuration, persistent state, client, and health poller.
func initCDR(s *startupState) {
	// ── Sluice CDR integration (Phase 1: config plumbing only) ──────────────
	// Client wiring into the proxy pipeline (handleTunnelInspect) lands in a
	// follow-up phase.  For now we merge flags, validate, and log status so
	// operators can sanity-check their setup before Phase 2 ships.
	cdrCfg := s.fc.CDR
	if *s.cdrEnabledFlag {
		cdrCfg.Enabled = true
	}
	if ep := firstStr(*s.cdrEndpointFlag, cdrCfg.Endpoint); ep != "" {
		cdrCfg.Endpoint = ep
	}
	if fm := firstStr(*s.cdrFailModeFlag, cdrCfg.FailMode); fm != "" {
		cdrCfg.FailMode = fm
	}
	if pn := firstStr(*s.cdrProfileFlag, cdrCfg.DefaultProfile); pn != "" {
		cdrCfg.DefaultProfile = pn
	}
	if m := firstStr(*s.cdrModeFlag, cdrCfg.DefaultMode); m != "" {
		cdrCfg.DefaultMode = m
	}
	if t := firstNonZero(*s.cdrTimeoutFlag, cdrCfg.TimeoutSec); t != 0 {
		cdrCfg.TimeoutSec = t
	}
	if sz := firstNonZero(*s.cdrMaxSizeFlag, cdrCfg.MaxFileSizeMB); sz != 0 {
		cdrCfg.MaxFileSizeMB = sz
	}
	if fp := firstStr(*s.cdrFingerprintFlag, cdrCfg.ServerFingerprint); fp != "" {
		cdrCfg.ServerFingerprint = fp
	}
	if d := firstStr(*s.cdrCertsDirFlag, cdrCfg.CertsDir); d != "" {
		cdrCfg.CertsDir = d
	}
	// Runtime sentinel takes priority: if /data/cdr_enabled exists
	// (written by the admin GUI toggle or by the first enrollment
	// auto-enable path), CDR is on regardless of YAML/CLI.  This lets
	// operators enable CDR via the admin UI without editing config
	// files or restarting the proxy.
	if cdrRuntimeEnabled() {
		cdrCfg.Enabled = true
	}

	// Load persistent state unconditionally — the registry and policy
	// store must know their on-disk paths even when CDR is currently
	// disabled, otherwise Save() silently no-ops (see
	// CDRInstanceRegistry.Save: path=="" returns nil) and any enroll /
	// toggle done via the GUI lives only in RAM until the next restart
	// wipes it.  Missing files are tolerated (fresh install); malformed
	// files fail loudly so admins notice.
	const (
		cdrInstPath   = "/data/cdr_instances.json"
		cdrPolicyPath = "/data/cdr_policies.json"
	)
	if err := cdrInstances.Load(cdrInstPath); err != nil {
		logger.Printf("CDR: instance registry load failed: %v", err)
	}
	if err := cdrPolicyStore.Load(cdrPolicyPath); err != nil {
		logger.Printf("CDR: policy store load failed: %v", err)
	}

	if cdrCfg.Enabled {
		mode := cdrCfg.DefaultMode
		if mode == "" {
			mode = "ENFORCE"
		}
		profile := cdrCfg.DefaultProfile
		if profile == "" {
			profile = "default"
		}
		failSafe := "fail-open"
		if !cdrCfg.CDRFailOpen() {
			failSafe = "fail-closed"
		}

		if err := initCDRClient(cdrCfg); err != nil {
			// Non-fatal: CDR is opt-in.  If the dial fails we log + continue;
			// handleTunnelInspect (Phase 2b) will fail-open/closed per policy.
			logger.Printf("CDR: initial client dial failed, CDR effectively disabled: %v", err)
		}

		// Phase 2c: background Health poller — updates cached snapshot
		// every 15s so /api/cdr/health is cheap and the GUI sees instance
		// liveness without polling Sluice on every view.
		startCDRHealthPoller(appLifecycleCtx)

		logger.Printf("CDR: enabled — endpoint=%q profile=%q mode=%q %s (Phase 2c: client + policy engine + proxy wiring + admin API live)",
			sanitizeLog(cdrCfg.Endpoint), sanitizeLog(profile), sanitizeLog(mode), failSafe)
	}
}

// initMTLSAndOCSP is the PR3 expansion shim: resolve the upstream
// mTLS + OCSP slice and apply it.
func initMTLSAndOCSP(s *startupState) {
	loadMTLSAndOCSP(resolveMTLSOCSPStartupConfig(s.fc))
}

// initBackgroundServices starts SSE, alert retry, updater, and cluster recovery.
func initBackgroundServices(s *startupState) {
	// ── SSE live dashboard broadcaster ───────────────────────────────────────
	// P1.2 / S4.SSE: parented to appLifecycleCtx so the goroutine exits when
	// runProxyUntilShutdown calls appLifecycleCancel(). Handle discarded here;
	// Phase 2's shutdown registry will pick it up if needed.
	startSSEBroadcaster(appLifecycleCtx)

	// ── F16: Alert retry queue ──────────────────────────────────────────────
	go startAlertRetryLoop(appLifecycleCtx)

	// ── Docker self-update system ────────────────────────────────────────────
	// H4: install the operator-curated allowlist BEFORE validating the
	// configured updater URL — validateUpdaterURL consults it.
	allowlist := append([]string(nil), s.fc.Update.URLAllowlist...)
	if cli := strings.TrimSpace(*s.updaterURLAllowFlag); cli != "" {
		for _, entry := range strings.Split(cli, ",") {
			if e := strings.TrimSpace(entry); e != "" {
				allowlist = append(allowlist, e)
			}
		}
	}
	SetUpdaterURLAllowlist(allowlist)
	if u := firstStr(*s.updaterURLFlag, s.fc.Update.UpdaterURL); u != "" {
		if err := validateUpdaterURL(u); err != nil {
			logWarnf("Update: invalid updater URL %q: %v — using default", u, err)
		} else {
			updaterURL = u
		}
	}
	ensureUpdaterToken()
	// Write current version to shared volume so the updater sidecar can read
	// it without inspecting Docker image tags (which show "latest" for local builds).
	// cleanSemver strips git-describe suffixes (e.g. "v0.0.19-4-g8ac6d14" → "v0.0.19")
	// so the updater always sees a clean semver for comparison.
	if cv := cleanSemver(version); cv != "" && cv != "dev" {
		// #nosec G306 -- 0644 required: updater sidecar runs with cap_drop:ALL (no DAC_OVERRIDE)
		_ = os.WriteFile("/data/version.txt", []byte(cv+"\n"), 0o644)
	}
	go startUpdateChecker(appLifecycleCtx)
	recoverClusterUpdate()
}

// initSOCKS5 starts the optional SOCKS5 listener.
func initSOCKS5(s *startupState) {
	// ── SOCKS5 server (optional) ─────────────────────────────────────────────
	socks5PortVal := firstNonZero(*s.socks5Port, s.fc.Proxy.SOCKS5Port)
	if socks5PortVal > 0 {
		go startSOCKS5(socks5PortVal)
	}
}

// initPersistentAdminState initializes config versioning, node groups, bandwidth, hit counters, and admin settings.
func initPersistentAdminState(s *startupState) {
	// ── Storage writability probe (one-shot, startup-only) ──────────────
	// Result is cached for the diagnostics handler so /api/diagnostics
	// stays side-effect-free. Never retries; never blocks startup.
	probeStorageWritability()

	// ── Config versioning ────────────────────────────────────────────────
	initConfigVersioning()

	// ── Node Groups ─────────────────────────────────────────────────────
	globalNodeGroups = NewNodeGroupStore(filepath.Join(dataDir, "node_groups.json"))

	// ── Bandwidth / QoS ─────────────────────────────────────────────────
	globalBandwidth = NewBandwidthManager(filepath.Join(dataDir, "bandwidth.json"))

	// ── Hit counter persistence (Finding 2.3) ───────────────────────────
	startHitCounterPersistence(appLifecycleCtx, filepath.Join(dataDir, "hit_counters.json"))
	RestoreHitCounts() // copy persisted hit counters back into PolicyRule.HitCount

	// ── Admin settings persistence (restore GUI changes across restarts) ──
	LoadAdminSettings(filepath.Join(dataDir, "admin_settings.json"))
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
		switch r.URL.Path {
		case "/health":
			handleHealth(w, r)
		case "/ready":
			handleReady(w, r)
		case "/metrics":
			handleMetrics(w, r)
		case "/proxy.pac":
			// Serve PAC over plain HTTP so Windows/macOS clients can fetch it
			// without TLS — the proxy port is always HTTP.
			servePACFile(w, r)
		default:
			handleRequest(w, r)
		}
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

// installSignalHandlers registers SIGINT/SIGTERM/SIGHUP handlers and spawns the SIGHUP
// hot-reload goroutine. Returns the quit and sighup channels (caller uses quit to block).
func installSignalHandlers(s *startupState) (quit, sighup chan os.Signal) {
	// ── Graceful shutdown ────────────────────────────────────────────────────
	quit = make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// ── Hot config reload (SIGHUP) ──────────────────────────────────────────
	sighup = make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	go func() {
		for range sighup {
			if *s.configPath == "" {
				logger.Println("SIGHUP received but no -config path set; ignoring")
				continue
			}
			logger.Printf("SIGHUP received — reloading config from %s", *s.configPath)
			reloaded, err := loadFileConfig(*s.configPath)
			if err != nil {
				logger.Printf("Config reload error: %v — keeping current config", err)
				continue
			}
			applyHotReload(reloaded)
			logger.Println("Config reloaded successfully")
		}
	}()
	return quit, sighup
}

// runProxyUntilShutdown starts the proxy goroutine, blocks on quit, then runs
// the graceful shutdown sequence in its exact original order.
func runProxyUntilShutdown(s *startupState, proxySrv *http.Server, quit chan os.Signal) {
	go func() {
		if err := proxySrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Proxy error: %v", err)
		}
	}()

	<-quit
	logger.Println("Shutting down gracefully…")

	// Stop HA leader election and release lock before gRPC shutdown.
	globalHA.Stop()

	// Gracefully stop gRPC server first (drains in-flight RPCs).
	StopControlPlaneGRPC()

	// Close the CDR client before cancelling lifecycle context so any
	// in-flight Sanitize streams get a clean tear-down rather than a
	// context-cancelled transport error.
	shutdownCDRClient()

	// Cancel all background goroutines (feed syncers, CA rotation, health checks, etc.)
	appLifecycleCancel()

	if s.rlCleanupCancel != nil {
		s.rlCleanupCancel()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shut down scan microservice sidecar if running.
	if s.scanSvc != nil {
		s.scanSvc.Shutdown(ctx) //nolint:errcheck -- best-effort shutdown
	}

	// P1.1 / S4.AdminUI: stop accepting new admin UI requests before draining
	// the proxy so admins can no longer mutate config mid-shutdown. Admin UI
	// shutdown is capped at 5s (adminUIShutdownTimeout) so it cannot consume
	// the entire remaining shutdown budget before proxy drain — important
	// because admin UI WriteTimeout=0 (SSE long-lived streams) means Shutdown
	// would otherwise block on in-flight handlers until the parent ctx expires.
	// shutdownAdminUI is nil-safe for the early-fail path.
	if err := shutdownAdminUI(ctx, s.adminUISrv); err != nil {
		logger.Printf("Admin UI shutdown error: %v", err)
	}

	if err := proxySrv.Shutdown(ctx); err != nil {
		logger.Printf("Shutdown error: %v", err)
	}

	// Drain active tunnels (CONNECT/WebSocket). proxySrv.Shutdown only closes
	// HTTP/1.x idle connections; hijacked tunnels need time to finish.
	active := atomic.LoadInt64(&activeConns)
	if active > 0 {
		logger.Printf("Draining %d active tunnel(s)…", active)
		drainDeadline := time.After(15 * time.Second)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
	drainLoop:
		for {
			select {
			case <-drainDeadline:
				logger.Printf("Drain timeout: %d tunnel(s) still active", atomic.LoadInt64(&activeConns))
				break drainLoop
			case <-ticker.C:
				if atomic.LoadInt64(&activeConns) <= 0 {
					logger.Println("All tunnels drained")
					break drainLoop
				}
			}
		}
	}
	if globalSyslog != nil {
		globalSyslog.Close() //nolint:errcheck // best-effort flush on shutdown
	}
	if communityDB != nil {
		if err := communityDB.Close(); err != nil {
			logger.Printf("CatFeedDB: close error: %v", err)
		}
	}
	if requestLogCloser != nil {
		requestLogCloser.Close() //nolint:errcheck // best-effort flush on shutdown
	}
	if s.logCloser != nil {
		s.logCloser.Close()
	}
	logger.Println("Stopped.")
}

// handleHealth returns liveness + readiness details for monitoring tools.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// CA cert expiry
	caExpiresDays := -1
	if info := certMgr.CACertInfo(); info["ready"] == true {
		if notAfterStr, ok := info["notAfter"].(string); ok {
			if t, err := time.Parse("2006-01-02", notAfterStr); err == nil {
				caExpiresDays = int(time.Until(t).Hours() / 24)
			}
		}
	}

	// Threat feed entry count
	tfEntries, _, _ := globalThreatFeed.Stats()

	// ClamAV connectivity
	clamStatus := "disabled"
	if globalSecScanner != nil {
		clamStatus = globalSecScanner.ClamAVStatus()
	}

	type healthResponse struct {
		Status            string `json:"status"`
		Uptime            string `json:"uptime"`
		Version           string `json:"version"`
		ClamAV            string `json:"clamav"`
		CAExpiresDays     int    `json:"ca_expires_days"`
		ThreatFeedEntries int64  `json:"threat_feed_entries"`
	}
	resp := healthResponse{
		Status:            "ok",
		Uptime:            uptime(),
		Version:           version,
		ClamAV:            clamStatus,
		CAExpiresDays:     caExpiresDays,
		ThreatFeedEntries: tfEntries,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Printf("handleHealth encode: %v", err)
	}
}

// handleReady is a readiness probe — returns 200 only when all configured
// subsystems are operational. Use for Kubernetes readinessProbe / startup gate.
// Unlike /health (liveness), this returns 503 when dependencies are degraded.
// configSnapshotValidatorOK reports whether the config-snapshot
// validator accepts the empty baseline (its identity contract). Defined
// as a package-level variable so tests can swap in a stub that simulates
// a broken validator without mutating the per-slice caps in
// configversion / controlplane.
var configSnapshotValidatorOK = func() bool {
	return validateConfigSnapshot(ConfigSnapshot{}) == nil
}

func handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	type checkResult struct {
		Status string `json:"status"` // "ok" or "fail"
		Detail string `json:"detail,omitempty"`
	}
	checks := map[string]*checkResult{}
	allOK := true

	// 1. CA: report status but don't fail readiness — proxy still works
	// as a plain forward proxy if the CA didn't load.
	if certMgr.Ready() {
		checks["ca"] = &checkResult{Status: "ok"}
	}

	// 2. ClamAV: if scanner is initialised, verify connectivity.
	if globalSecScanner != nil {
		st := globalSecScanner.ClamAVStatus()
		switch st {
		case "disabled":
			// Not configured — skip.
		case "connected":
			checks["clamav"] = &checkResult{Status: "ok"}
		default:
			checks["clamav"] = &checkResult{Status: "fail", Detail: st}
			allOK = false
		}
	}

	// 3. GeoIP: if configured, verify DB is loaded.
	if geoEnabled() {
		checks["geoip"] = &checkResult{Status: "ok"}
	}
	// GeoIP is optional — absence is not a failure.

	// 4. YARA rules: if configured, verify loaded.
	if globalYARA.Enabled() {
		checks["yara"] = &checkResult{Status: "ok"}
	}

	// 5. Policy loaded (informational). Empty policy is a valid
	// Zero-Trust posture — default-deny applies — so this row does NOT
	// gate readiness. Surfaces "no rules yet" as a hint to operators
	// without flapping load balancers on a fresh install.
	if ver, _ := policyStore.policyVersion(); ver > 0 {
		checks["policy_loaded"] = &checkResult{Status: "ok"}
	} else {
		checks["policy_loaded"] = &checkResult{Status: "fail", Detail: "no rules"}
	}

	// 6. Admin session HMAC initialised. Without this, signed cookies
	// cannot be issued or verified — the admin UI is effectively
	// unmanageable. Fail readiness so traffic is held off until the
	// node is restarted with a valid secret.
	if sessionSecretSet() {
		checks["session_secret"] = &checkResult{Status: "ok"}
	} else {
		checks["session_secret"] = &checkResult{Status: "fail", Detail: "uninitialised"}
		allOK = false
	}

	// 7. ConfigSnapshot validator. The pure validateConfigSnapshot
	// function must accept the empty baseline (its identity contract).
	// If it ever rejects, the cluster control-plane apply path is
	// broken and we must shed load. configSnapshotValidatorOK is a
	// package-level seam so tests can simulate a broken validator
	// without mutating the per-slice caps.
	if configSnapshotValidatorOK() {
		checks["config_snapshot_validator"] = &checkResult{Status: "ok"}
	} else {
		checks["config_snapshot_validator"] = &checkResult{Status: "fail", Detail: "validator rejected empty baseline"}
		allOK = false
	}

	status := "ready"
	code := http.StatusOK
	if !allOK {
		status = "not_ready"
		code = http.StatusServiceUnavailable
	}

	resp := struct {
		Status  string                  `json:"status"`
		Uptime  string                  `json:"uptime"`
		Version string                  `json:"version"`
		Checks  map[string]*checkResult `json:"checks"`
	}{
		Status:  status,
		Uptime:  uptime(),
		Version: version,
		Checks:  checks,
	}

	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Printf("handleReady encode: %v", err)
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

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

func firstStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// initUpstreamPool configures upstream proxy chaining from the file config.
func initUpstreamPool(fc *FileConfig) {
	cbTimeout := 60 * time.Second
	if fc.Upstream.CircuitBreaker.Timeout != "" {
		if d, err := time.ParseDuration(fc.Upstream.CircuitBreaker.Timeout); err == nil {
			cbTimeout = d
		}
	}
	upstreamPool.Configure(fc.Upstream.Proxies, fc.Upstream.CircuitBreaker.Threshold, cbTimeout)
	applyUpstreamProxy()
	logger.Printf("Upstream: %s", formatUpstreamSummary(fc.Upstream.Proxies))

	// Start health check loop.
	hi := fc.Upstream.HealthInterval
	if hi == "" {
		return
	}
	d, err := time.ParseDuration(hi)
	if err != nil || d <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(d)
		defer t.Stop()
		for range t.C {
			upstreamPool.HealthCheck()
		}
	}()
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

	globalConfigStore.Update(CurrentConfigSnapshot())
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

// dpEnrollmentConfig is persisted to disk after successful enrollment so the
// DP can auto-start on subsequent restarts without manual cert flags.
type dpEnrollmentConfig struct {
	CPAddr   string `json:"cp_addr"`
	NodeID   string `json:"node_id"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	CAFile   string `json:"ca_file"`
}

const enrollmentConfigFile = "dp_enrollment.json"

// loadEnrollmentConfig reads a previously persisted enrollment config.
func loadEnrollmentConfig() (*dpEnrollmentConfig, error) {
	data, err := os.ReadFile(enrollmentConfigFile)
	if err != nil {
		return nil, err
	}
	var ec dpEnrollmentConfig
	if err := json.Unmarshal(data, &ec); err != nil {
		return nil, err
	}
	return &ec, nil
}

// runEnrollment handles the enrollment flow: generates a keypair+CSR,
// contacts the Control Plane, and persists the signed certificate.
// Returns the enrollment config so the caller can start as a DP node.
func runEnrollment(enrollURLStr string) (*dpEnrollmentConfig, error) {
	info, err := parseEnrollURL(enrollURLStr)
	if err != nil {
		return nil, err
	}
	nodeID, _ := os.Hostname()
	if nodeID == "" {
		nodeID = "dp-node"
	}
	fmt.Printf("[Culvert] Enrolling as node %q with Control Plane at %s\n", nodeID, info.CPAddr)

	privKey, csrPEM, err := generateCSR(nodeID)
	if err != nil {
		return nil, err
	}
	resp, err := callEnrollRPC(info.CPAddr, info.Token, nodeID, csrPEM)
	if err != nil {
		return nil, err
	}
	// Verify CA fingerprint from the enrollment URL matches the received CA cert.
	if info.CAFingerprint != "" {
		if err := verifyCAFingerprint([]byte(resp.CAPEM), info.CAFingerprint); err != nil {
			return nil, fmt.Errorf("CA fingerprint mismatch — possible MITM: %w", err)
		}
		fmt.Printf("[Culvert] CA fingerprint verified ✓\n")
	}
	ec, err := persistEnrollCerts(privKey, resp, info.CPAddr, nodeID)
	if err != nil {
		return nil, err
	}
	return ec, nil
}

// enrollmentInfo holds parsed enrollment URL components.
type enrollmentInfo struct {
	CPAddr        string
	Token         string
	CAFingerprint string // sha256:hex (from ?ca-fp= query param)
}

// parseEnrollURL extracts CP address, token, and CA fingerprint from the enrollment URL.
func parseEnrollURL(raw string) (*enrollmentInfo, error) {
	raw = strings.TrimPrefix(raw, "culvert://enroll/")
	parts := strings.SplitN(raw, "/", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid enrollment URL format — expected culvert://enroll/host:port/TOKEN")
	}
	info := &enrollmentInfo{CPAddr: parts[0]}
	info.Token = parts[1]
	if idx := strings.Index(info.Token, "?"); idx >= 0 {
		query := info.Token[idx+1:]
		info.Token = info.Token[:idx]
		// Parse ca-fp= parameter.
		for _, kv := range strings.Split(query, "&") {
			if strings.HasPrefix(kv, "ca-fp=") {
				info.CAFingerprint = strings.TrimPrefix(kv, "ca-fp=")
			}
		}
	}
	return info, nil
}

// generateCSR creates an ECDSA P-256 keypair and CSR for enrollment.
func generateCSR(nodeID string) (*ecdsa.PrivateKey, []byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: nodeID, Organization: []string{"Culvert Data Plane"}},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	return privKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// callEnrollRPC connects to the CP and calls the Enroll gRPC method.
// If caFingerprint is non-empty, the CP's TLS cert is verified against it.
func callEnrollRPC(cpAddr, token, nodeID string, csrPEM []byte) (*EnrollResponse, error) {
	conn, err := grpc.NewClient(cpAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("connect to CP: %w", err)
	}
	defer conn.Close() //nolint:errcheck // best-effort close

	reqBytes, _ := json.Marshal(EnrollRequest{Token: token, CSR: string(csrPEM), NodeID: nodeID})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var respRaw json.RawMessage
	if err := conn.Invoke(ctx, methodEnroll, json.RawMessage(reqBytes), &respRaw); err != nil {
		return nil, fmt.Errorf("enrollment RPC failed: %w", err)
	}
	var resp EnrollResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		return nil, fmt.Errorf("parse enrollment response: %w", err)
	}
	return &resp, nil
}

// verifyCAFingerprint checks that the CA cert PEM matches the expected SHA-256 fingerprint.
func verifyCAFingerprint(caPEM []byte, expected string) error {
	want := strings.TrimPrefix(expected, "sha256:")
	wantBytes, err := hex.DecodeString(want)
	if err != nil {
		return fmt.Errorf("invalid CA fingerprint hex: %w", err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return fmt.Errorf("no PEM block in CA cert")
	}
	fp := sha256.Sum256(block.Bytes)
	if !hmac.Equal(fp[:], wantBytes) {
		return fmt.Errorf("CA fingerprint sha256:%x does not match expected sha256:%s", fp, want)
	}
	return nil
}

// persistEnrollCerts saves the signed certificate, private key, CA cert, and
// enrollment config to disk. Returns the config so the caller can start as DP.
func persistEnrollCerts(privKey *ecdsa.PrivateKey, resp *EnrollResponse, cpAddr, nodeID string) (*dpEnrollmentConfig, error) {
	certPath, keyPath, caPath := "./dp-node.crt", "./dp-node.key", "./cluster-ca.crt"

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, []byte(resp.CertPEM), 0o600); err != nil {
		return nil, fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	if err := os.WriteFile(caPath, []byte(resp.CAPEM), 0o600); err != nil {
		return nil, fmt.Errorf("write CA: %w", err)
	}

	// Persist enrollment config for automatic restarts.
	ec := &dpEnrollmentConfig{
		CPAddr:   cpAddr,
		NodeID:   nodeID,
		CertFile: certPath,
		KeyFile:  keyPath,
		CAFile:   caPath,
	}
	ecJSON, _ := json.MarshalIndent(ec, "", "  ")
	if err := os.WriteFile(enrollmentConfigFile, ecJSON, 0o600); err != nil {
		return nil, fmt.Errorf("write enrollment config: %w", err)
	}

	fmt.Printf("[Culvert] Enrollment successful!\n")
	fmt.Printf("[Culvert] Certificate: %s\n", certPath)
	fmt.Printf("[Culvert] Key:         %s\n", keyPath)
	fmt.Printf("[Culvert] CA:          %s\n", caPath)
	fmt.Printf("[Culvert] Config:      %s\n", enrollmentConfigFile)
	fmt.Printf("[Culvert] Starting as Data Plane node — connecting to %s\n", cpAddr)
	return ec, nil
}

// startDataPlane initialises and runs the Data Plane client.
func startDataPlane(ctx context.Context, addr, nodeID, certFile, keyFile, caFile string) {
	clusterRole.role = "data-plane"
	clusterRole.grpcAddr = addr
	if nodeID == "" {
		nodeID = clusterRole.nodeID
	}
	clusterRole.nodeID = nodeID

	if certFile != "" {
		if err := checkDPCertExpiry(certFile); err != nil {
			logWarnf("ControlPlane: %v", err)
		}
	}
	dpClient, err := NewDataPlaneClient(nodeID, addr, certFile, keyFile, caFile)
	if err != nil {
		logger.Fatalf("DataPlane client: %v", err)
	}
	activeDPClient.Store(dpClient) // for HA address discovery
	clusterRoleIsDP.Store(true)
	dpClient.Run(ctx, 30*time.Second)
	go dpCertRenewalLoop(ctx, dpClient, nodeID, certFile, keyFile, caFile)
	logger.Printf("DataPlane: polling ControlPlane at %s every 30s", addr)
}

// checkDPCertExpiry warns if the DP node certificate is expired or near expiry.
func checkDPCertExpiry(certFile string) error {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("DP cert read: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("DP cert: no PEM block found in %s", certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("DP cert parse: %w", err)
	}
	now := time.Now()
	if now.After(cert.NotAfter) {
		return fmt.Errorf("DP certificate expired at %s — re-enroll to get a new cert", cert.NotAfter.Format(time.RFC3339))
	}
	remaining := time.Until(cert.NotAfter)
	if remaining < 30*24*time.Hour {
		return fmt.Errorf("DP certificate expires in %d days — auto-renewal will attempt before expiry", int(remaining.Hours()/24))
	}
	return nil
}

// dpCertRenewalLoop checks cert expiry periodically and requests a new cert
// from the CP before the current one expires. Also listens for CA rotation
// notifications to trigger immediate renewal (zero-touch CA rotation).
func dpCertRenewalLoop(ctx context.Context, client *DataPlaneClient, nodeID, certFile, keyFile, caFile string) {
	// Check every 6 hours.
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := tryRenewDPCert(ctx, client, nodeID, certFile, keyFile, caFile); err != nil {
				logger.Printf("DataPlane: cert renewal check: %v", err)
			}
		case <-caRotationNotify:
			// CP rotated its CA — renew immediately regardless of cert expiry.
			logger.Printf("DataPlane: CA rotation detected — initiating immediate cert renewal")
			if err := forceRenewDPCert(ctx, client, nodeID, certFile, keyFile, caFile); err != nil {
				logger.Printf("DataPlane: CA rotation renewal failed: %v", err)
			}
		}
	}
}

// certNeedsRenewal checks if a PEM cert file expires within 30 days.
// Returns days remaining, or -1 if the cert cannot be read.
func certNeedsRenewal(certFile string) (int, bool) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return -1, false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return -1, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return -1, false
	}
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	return days, days <= 30
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
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	f, err := os.CreateTemp(dir, base+".tmp.*")
	if err != nil {
		return fmt.Errorf("atomic write %s: create temp: %w", path, err)
	}
	tmp := f.Name()
	cleanup := func() { _ = os.Remove(tmp) } // #nosec G104 -- best-effort cleanup

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("atomic write %s: write: %w", path, err)
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("atomic write %s: chmod: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("atomic write %s: fsync: %w", path, err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("atomic write %s: close: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return fmt.Errorf("atomic write %s: rename: %w", path, err)
	}

	d, err := os.Open(dir)
	if err != nil {
		// Best-effort: opening a directory for sync is not portable.
		return nil
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil &&
		!errors.Is(syncErr, syscall.EINVAL) &&
		!errors.Is(syncErr, syscall.ENOTSUP) &&
		!errors.Is(syncErr, syscall.EOPNOTSUPP) {
		return fmt.Errorf("atomic write %s: parent dir fsync: %w", path, syncErr)
	}
	if closeErr != nil && syncErr == nil {
		return fmt.Errorf("atomic write %s: parent dir close: %w", path, closeErr)
	}
	return nil
}

// forceRenewDPCert renews the DP cert unconditionally (triggered by CA rotation).
func forceRenewDPCert(ctx context.Context, client *DataPlaneClient, nodeID, certFile, keyFile, caFile string) error {
	return renewDPCert(ctx, client, nodeID, certFile, keyFile, caFile, "CA rotation")
}

// tryRenewDPCert renews the DP cert if it expires within 30 days.
func tryRenewDPCert(ctx context.Context, client *DataPlaneClient, nodeID, certFile, keyFile, caFile string) error {
	days, needsRenewal := certNeedsRenewal(certFile)
	if !needsRenewal {
		return nil
	}
	return renewDPCert(ctx, client, nodeID, certFile, keyFile, caFile, fmt.Sprintf("cert expires in %d days", days))
}

// renewDPCert performs the actual cert renewal via RenewCert RPC.
func renewDPCert(ctx context.Context, client *DataPlaneClient, nodeID, certFile, keyFile, caFile, reason string) error {
	logger.Printf("DataPlane: requesting cert renewal (%s)", reason)

	privKey, csrPEM, err := generateCSR(nodeID)
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}

	reqBytes, _ := json.Marshal(map[string]string{"node_id": nodeID, "csr": string(csrPEM)})
	raw, err := client.call(ctx, methodRenewCert, json.RawMessage(reqBytes))
	if err != nil {
		return fmt.Errorf("RenewCert RPC: %w", err)
	}
	var resp struct {
		CertPEM string `json:"cert_pem"`
		CAPEM   string `json:"ca_pem"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("parse renewal response: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	if err := atomicWriteFile(certFile, []byte(resp.CertPEM), 0o600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := atomicWriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	if resp.CAPEM != "" {
		if err := atomicWriteFile(caFile, []byte(resp.CAPEM), 0o600); err != nil {
			return fmt.Errorf("write CA: %w", err)
		}
	}
	logger.Printf("DataPlane: certificate renewed successfully (%s)", reason)
	return nil
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

	// Upstream proxy pool
	if len(fc.Upstream.Proxies) > 0 {
		cbTimeout := 60 * time.Second
		if fc.Upstream.CircuitBreaker.Timeout != "" {
			if d, err := time.ParseDuration(fc.Upstream.CircuitBreaker.Timeout); err == nil {
				cbTimeout = d
			}
		}
		upstreamPool.Configure(fc.Upstream.Proxies, fc.Upstream.CircuitBreaker.Threshold, cbTimeout)
		applyUpstreamProxy()
		logger.Printf("Reload: upstream %s", formatUpstreamSummary(fc.Upstream.Proxies))
	}
}
