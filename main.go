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

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/geoip"
	"github.com/KidCarmi/Culvert/internal/obs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// caPassphraseEnv holds the name of the environment variable that supplies the
// CA private-key encryption passphrase. Using an env var keeps the passphrase
// out of CLI history and process listings (shift-left: secrets management).
// This is an env-var name, NOT a credential — the false-positive is suppressed.
const caPassphraseEnv = "CULVERT_CA_PASSPHRASE"        // #nosec G101 -- env-var name, not a credential
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
	adminUISrv      *http.Server  // P1.1 / S4.AdminUI: graceful shutdown handle
	socks5Srv       *socks5Server // P1.5 / S4.SOCKS5: listener-close shutdown handle
}

func main() {
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
	initRewriteAndDefaultAction(s)
	initScanning(s)
	initUpstreamProxy(s)
	initCDR(s)
	initMTLSAndOCSP(s)
	initBackgroundServices(s)
	initSOCKS5(s)
	initPersistentAdminState(s)
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
	s.haAutoFailover = flag.Bool("ha-auto-failover", false, "HA: allow the standby to self-promote on leader loss. DEFAULT OFF — 2-node active/passive has no witness, so unattended auto-promotion can split-brain (ADR-0004/RISK-001). Off = manual failover.")
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
// loader. No carry to startupState — the file-handle closers stay on
// their package globals (globalSyslog, auditCloser, requestLogCloser)
// and continue to be read by the existing syslog-close / audit-log-
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
	cfg := resolveUIAccessPolicyStartupConfig(s.fc, *s.uiAllowIP, *s.idpProfilesFile)
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
			cpAddr, cpCert, cpKey, cpCA, *s.haAutoFailover,
			func() error {
				return enableControlPlane(cpAddr, cpCert, cpKey, cpCA, clusterDBPath)
			},
		)
	} else if cpAddr != "" || s.fc.Cluster.Role == "control-plane" {
		// ── Normal CP startup ────────────────────────────────────────
		// Resolve the persisted HA role BEFORE asserting leadership (ADR-0004):
		// a node persisted as standby must NOT silently come up as a second
		// leader. A restarted leader cannot probe its peer (it never records
		// the standby's address — see ha.go), so it resumes leadership with an
		// honest split-brain-risk warning when auto-failover is enabled.
		haCfg, haErr := loadHAConfig()
		if haRestartAction(haCfg, haErr) == "standby" {
			// Re-enter standby instead of self-asserting leader. Mirrors the
			// --ha-join path; onPromote enables the CP gRPC server on promotion.
			initClusterCA(clusterDBPath)
			globalHA.StartAsStandby(appLifecycleCtx, haCfg.PeerAddr, haCfg.Token,
				cpAddr, cpCert, cpKey, cpCA, haCfg.AutoFailover,
				func() error {
					return enableControlPlane(cpAddr, cpCert, cpKey, cpCA, clusterDBPath)
				},
			)
			logger.Printf("HA: restarted as standby from %s (leader=%s) — not self-asserting leader (ADR-0004)",
				haConfigFile, sanitizeLog(haCfg.PeerAddr))
		} else {
			if err := enableControlPlane(cpAddr, cpCert, cpKey, cpCA, clusterDBPath); err != nil {
				logger.Fatalf("ControlPlane gRPC: %v", err)
			}
			// Persisted leader (or legacy config with no role) resumes leadership.
			if haErr == nil && haCfg.Enabled {
				globalHA.ResumeAsLeader(haCfg) // restores role+token+term+auto_failover (no term bump)
				if haCfg.AutoFailover {
					logger.Printf("HA: resumed as leader from %s after restart. WARNING: automatic failover is "+
						"enabled — if the standby promoted while this node was down, BOTH may now lead. Verify via "+
						"/healthz or the HA panel and reconcile (ADR-0004/RISK-001).", haConfigFile)
				} else {
					logger.Printf("HA: resumed as leader from %s after restart (peer=%s)", haConfigFile, haCfg.PeerAddr)
				}
			}
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

// initUpstreamProxy configures parent-proxy chaining when configured.
func initUpstreamProxy(s *startupState) {
	// ── Upstream proxy chaining ──────────────────────────────────────────────
	if len(s.fc.Upstream.Proxies) > 0 {
		initUpstreamPool(s.fc)
	}
}

// initCDR wires Sluice CDR configuration, persistent state, client, and health poller.
// initCDR resolves the CDR (Sluice) slice config and hands it to the loader
// (cdr_startup*.go). CLI flag values are packed here; the runtime
// enable-sentinel is read by the loader (filesystem side effect).
func initCDR(s *startupState) {
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

// initBackgroundServices starts SSE, alert retry, updater, and cluster recovery.
// initBackgroundServices resolves the background-services slice config and
// hands it to the loader (background_services_startup*.go).
func initBackgroundServices(s *startupState) {
	loadBackgroundServices(
		resolveBackgroundServicesStartupConfig(s.fc, *s.updaterURLAllowFlag, *s.updaterURLFlag, version),
		appLifecycleCtx,
	)
}

// initSOCKS5 starts the optional SOCKS5 listener. The accept loop is owned
// by socks5Server (constructed inside startSOCKS5), which is Stop'able via
// runProxyUntilShutdown. P1.5 / S4.SOCKS5.
func initSOCKS5(s *startupState) {
	// ── SOCKS5 server (optional) ─────────────────────────────────────────────
	socks5PortVal := firstNonZero(*s.socks5Port, s.fc.Proxy.SOCKS5Port)
	if socks5PortVal > 0 {
		s.socks5Srv = startSOCKS5(socks5PortVal)
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
			logger.Fatalf("Proxy error: %v", err)
		}
	}()

	<-quit
	logger.Println("Shutting down gracefully…")

	var early, late shutdownRegistry
	registerEarlyShutdownHooks(&early, s)
	registerLateShutdownHooks(&late, s, proxySrv)
	runShutdownSequence(&early, &late, 30*time.Second)

	logger.Println("Stopped.")
}

// runShutdownSequence runs the early registry with context.Background()
// (no shutdown budget), then creates a fresh ctx with the supplied late
// budget and runs the late registry. The late ctx's cancel is deferred so
// it runs at function exit, mirroring the original
// `defer cancel()` placement in runProxyUntilShutdown.
//
// Extracted so the budget-vs-no-budget contract — the entire reason this
// PR splits into two registries — is unit-testable end to end without
// touching production globals. P2.2 / S5.
func runShutdownSequence(early, late *shutdownRegistry, lateBudget time.Duration) {
	if err := early.RunAll(context.Background()); err != nil {
		logger.Printf("Early shutdown error(s): %v", err)
	}

	// 30s shutdown budget begins HERE — same point as the original
	// `ctx, cancel := context.WithTimeout(...)` in the pre-P2.2 body,
	// after the rate-limit cleanup cancel and before scanSvc.Shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), lateBudget)
	defer cancel()

	if err := late.RunAll(ctx); err != nil {
		// All late hooks currently log per-hook on failure and return nil,
		// so this branch is unreachable today. Kept as a backstop for
		// future hooks that opt into registry-level error aggregation.
		logger.Printf("Shutdown error(s): %v", err)
	}
}

// shutdown hook order constants. Gaps of 10 leave room for future inserts
// without renumbering. Hooks at or below shutdownEarlyLateBoundary belong
// in registerEarlyShutdownHooks (no shutdown budget); hooks above it belong
// in registerLateShutdownHooks (under the 30s budget). P2.2 / S5.
const (
	shutdownOrderHAStop                 = 10
	shutdownOrderControlPlaneGRPCStop   = 20
	shutdownOrderCDRClientShutdown      = 30
	shutdownOrderAppLifecycleCancel     = 40
	shutdownOrderRateLimitCleanupCancel = 50

	// shutdownEarlyLateBoundary is the cut-line: orders <= this run in
	// the early phase (bg ctx, no budget); orders > this run in the late
	// phase (30s ctx). Encoded as a constant so the test suite can pin
	// the split structurally.
	shutdownEarlyLateBoundary = 50

	// shutdownOrderClusterStoreFlush runs first in the late phase. CL-2:
	// closes the heartbeat-throttle window. UpdateNodeSeen only persists
	// every 10th heartbeat (enrollment.go) and checkHeartbeats persists
	// only when liveness/GC change something. Anything mutated in-memory
	// since the last Save() is otherwise lost on shutdown. By this point
	// in the sequence the gRPC server has stopped (no new heartbeats) and
	// appLifecycleCancel has stopped the heartbeat monitor, so the Save
	// races with nothing.
	shutdownOrderClusterStoreFlush   = 55
	shutdownOrderScanSvcShutdown     = 60
	shutdownOrderAdminUIShutdown     = 70
	shutdownOrderSOCKS5ListenerStop  = 80
	shutdownOrderProxyServerShutdown = 90
	shutdownOrderTunnelDrain         = 100
	shutdownOrderSyslogClose         = 110
	shutdownOrderCommunityDBClose    = 120
	shutdownOrderLogStoreClose       = 125
	shutdownOrderRequestLogClose     = 130
	shutdownOrderAuditLogClose       = 135
	shutdownOrderLogCloser           = 140
)

// registerEarlyShutdownHooks registers the pre-budget shutdown hooks: HA,
// control-plane gRPC, CDR client, app lifecycle cancel, rate-limit cleanup
// cancel. These ran BEFORE the 30s ctx in the pre-P2.2 hand-ordered body
// and continue to run with context.Background() — they are not subject to
// any shutdown timeout. None of them observe ctx; they ignore the parameter.
// P2.2 / S5.
func registerEarlyShutdownHooks(reg *shutdownRegistry, s *startupState) {
	// Stop HA leader election and release lock before gRPC shutdown.
	reg.Register("ha-stop", shutdownOrderHAStop, func(context.Context) error {
		globalHA.Stop()
		return nil
	})
	// Gracefully stop gRPC server (drains in-flight RPCs).
	reg.Register("control-plane-grpc-stop", shutdownOrderControlPlaneGRPCStop, func(context.Context) error {
		StopControlPlaneGRPC()
		return nil
	})
	// Close the CDR client before cancelling lifecycle context so any
	// in-flight Sanitize streams get a clean tear-down rather than a
	// context-cancelled transport error.
	reg.Register("cdr-client-shutdown", shutdownOrderCDRClientShutdown, func(context.Context) error {
		shutdownCDRClient()
		return nil
	})
	// Cancel all background goroutines (feed syncers, CA rotation, health checks, etc.).
	reg.Register("app-lifecycle-cancel", shutdownOrderAppLifecycleCancel, func(context.Context) error {
		appLifecycleCancel()
		return nil
	})
	reg.Register("rate-limit-cleanup-cancel", shutdownOrderRateLimitCleanupCancel, func(context.Context) error {
		if s.rlCleanupCancel != nil {
			s.rlCleanupCancel()
		}
		return nil
	})
}

// drainActiveTunnels drains in-flight CONNECT/WebSocket tunnels after the
// proxy server's HTTP listener has shut down. proxySrv.Shutdown only closes
// HTTP/1.x idle connections; hijacked tunnels need time to finish. The 15s
// drain budget is independent of the parent ctx — extracted as a named
// function (rather than an inline closure inside registerLateShutdownHooks)
// to keep the wiring function's cognitive complexity low. P2.2 / S5.
func drainActiveTunnels(context.Context) error {
	active := atomic.LoadInt64(&activeConns)
	if active <= 0 {
		return nil
	}
	logger.Printf("Draining %d active tunnel(s)…", active)
	drainDeadline := time.After(15 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-drainDeadline:
			logger.Printf("Drain timeout: %d tunnel(s) still active", atomic.LoadInt64(&activeConns))
			return nil
		case <-ticker.C:
			if atomic.LoadInt64(&activeConns) <= 0 {
				logger.Println("All tunnels drained")
				return nil
			}
		}
	}
}

// registerLateShutdownHooks registers the budget-bound shutdown hooks: scan
// service, Admin UI, SOCKS5 listener, proxy server, tunnel drain, syslog
// close, community DB close, request log close, log closer. These run under
// the 30s ctx that runShutdownSequence creates after the early phase
// completes; the ctx is observed by hooks that take it (scanSvc, adminUI,
// socks5, proxySrv) and ignored by io.Closer-style hooks.
//
// Per-hook log messages and best-effort error suppression are byte-
// equivalent to the previous hand-ordered body. Hooks return nil today;
// registry-level error aggregation is reserved for a future PR. P2.2 / S5.
func registerLateShutdownHooks(reg *shutdownRegistry, s *startupState, proxySrv *http.Server) {
	// CL-2: flush in-memory cluster state to disk once at shutdown so the
	// heartbeat-throttle gap (UpdateNodeSeen saves every 10th tick) cannot
	// drop LastSeen/Status mutations on a graceful stop. Save() is RLock +
	// atomicWriteFile; no path → no-op.
	reg.Register("cluster-store-flush", shutdownOrderClusterStoreFlush, func(context.Context) error {
		if globalClusterStore == nil {
			return nil
		}
		if err := globalClusterStore.Save(); err != nil {
			logger.Printf("Cluster store flush error: %v", err)
		}
		return nil
	})
	// Shut down scan microservice sidecar if running. Best-effort: error suppressed.
	reg.Register("scan-svc-shutdown", shutdownOrderScanSvcShutdown, func(ctx context.Context) error {
		if s.scanSvc != nil {
			_ = s.scanSvc.Shutdown(ctx)
		}
		return nil
	})
	// P1.1 / S4.AdminUI: stop accepting new admin UI requests before draining
	// the proxy. shutdownAdminUI builds a 5s sub-context internally so an
	// active SSE stream cannot consume the entire shutdown budget.
	reg.Register("admin-ui-shutdown", shutdownOrderAdminUIShutdown, func(ctx context.Context) error {
		if err := shutdownAdminUI(ctx, s.adminUISrv); err != nil {
			logger.Printf("Admin UI shutdown error: %v", err)
		}
		return nil
	})
	// P1.5 / S4.SOCKS5: close the SOCKS5 listener. Bounded to 2s via a
	// sub-context. Does NOT drain in-flight SOCKS5 tunnels — they keep
	// their per-conn 30s deadlines (set in handleSOCKS5).
	reg.Register("socks5-listener-stop", shutdownOrderSOCKS5ListenerStop, func(ctx context.Context) error {
		if s.socks5Srv == nil {
			return nil
		}
		socksCtx, socksCancel := context.WithTimeout(ctx, 2*time.Second)
		defer socksCancel()
		if err := s.socks5Srv.Stop(socksCtx); err != nil {
			logger.Printf("SOCKS5 shutdown error: %v", err)
		}
		return nil
	})
	reg.Register("proxy-server-shutdown", shutdownOrderProxyServerShutdown, func(ctx context.Context) error {
		if err := proxySrv.Shutdown(ctx); err != nil {
			logger.Printf("Shutdown error: %v", err)
		}
		return nil
	})
	// Drain active tunnels (CONNECT/WebSocket). proxySrv.Shutdown only
	// closes HTTP/1.x idle connections; hijacked tunnels need time to
	// finish. 15s drain budget is independent of the parent ctx, matching
	// the original behaviour exactly.
	reg.Register("tunnel-drain", shutdownOrderTunnelDrain, drainActiveTunnels)
	reg.Register("syslog-close", shutdownOrderSyslogClose, func(context.Context) error {
		if globalSyslog != nil {
			_ = globalSyslog.Close() // best-effort flush
		}
		return nil
	})
	reg.Register("community-db-close", shutdownOrderCommunityDBClose, func(context.Context) error {
		if communityDB != nil {
			if err := communityDB.Close(); err != nil {
				logger.Printf("CatFeedDB: close error: %v", err)
			}
		}
		return nil
	})
	reg.Register("log-store-close", shutdownOrderLogStoreClose, func(context.Context) error {
		if ls := globalLogStore.Load(); ls != nil {
			if err := ls.Close(); err != nil {
				logger.Printf("LogStore: close error: %v", err)
			}
		}
		return nil
	})
	reg.Register("request-log-close", shutdownOrderRequestLogClose, func(context.Context) error {
		if requestLogCloser != nil {
			_ = requestLogCloser.Close() // best-effort flush
		}
		return nil
	})
	// P3.3 / S7. Release the audit-log file descriptor. Writes are
	// synchronous, unbuffered, kernel-side already on disk — this closes
	// the OS handle to eliminate the FD leak flagged as Risk #6 in
	// ARCH_DISCOVERY. Best-effort, byte-equivalent to request-log-close.
	reg.Register("audit-log-close", shutdownOrderAuditLogClose, func(context.Context) error {
		if auditCloser != nil {
			_ = auditCloser.Close() // best-effort FD release
		}
		return nil
	})
	reg.Register("log-closer", shutdownOrderLogCloser, func(context.Context) error {
		if s.logCloser != nil {
			_ = s.logCloser.Close()
		}
		return nil
	})
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
	if geoip.Enabled() {
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

	// Bucket-4 durability hardening: atomicWriteFile gives unique
	// tmp + chmod + fsync(file) + rename + best-effort fsync(parent
	// dir) — replaces the previous plain os.WriteFile which left a
	// non-durable / potentially-truncated file on crash. Sibling
	// follow-up to CL-7 / PR #244 (which hardened the
	// dp_enrollment.json branch a few lines below).
	if err := atomicWriteFile(certPath, []byte(resp.CertPEM), 0o600); err != nil {
		return nil, fmt.Errorf("write cert: %w", err)
	}
	// CA-3: encrypt the DP node key at rest when enabled; plaintext otherwise.
	// Cert and CA cert remain plaintext PEM.
	if err := writeDPNodeKey(keyPath, keyPEM); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	if err := atomicWriteFile(caPath, []byte(resp.CAPEM), 0o600); err != nil {
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
	// CL-7: atomicWriteFile gives unique tmp + chmod + fsync(file) +
	// rename + best-effort fsync(parent dir) — replaces the previous
	// plain os.WriteFile which left a non-durable / potentially-
	// truncated file on crash. The sibling cert/key/CA writes above
	// (lines ~1953/1956/1959) share the same pre-existing defect but
	// are intentionally out of CL-7 scope; flagged in the PR body as
	// a deferred follow-up.
	if err := atomicWriteFile(enrollmentConfigFile, ecJSON, 0o600); err != nil {
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
	// CA-3: opt-in one-time migration of an existing plaintext DP node key to
	// encrypted-at-rest, at the single startup load point (not on reconnect).
	// Fails closed if an encrypted key is present but unreadable.
	if keyFile != "" {
		if err := maybeMigrateDPNodeKey(keyFile); err != nil {
			logger.Fatalf("DataPlane: DP node key at-rest: %v", err)
		}
	}
	if snap, err := applyDPLastGoodConfigSnapshot(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logger.Printf("DataPlane: last-known-good config unavailable: %v", err)
		} else {
			logger.Printf("DataPlane: no last-known-good config at %s", dpLastGoodConfigSnapshotPath())
		}
	} else if mergedAddr := mergeCPAddresses(addr, snap.CPAddresses); mergedAddr != addr {
		logger.Printf("DataPlane: seeded CP failover addresses from last-known-good config: %s", sanitizeLog(mergedAddr))
		addr = mergedAddr
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
	// Delegates to internal/fileutil (ADR-0003 seam). Kept as a thin wrapper so
	// all existing call sites stay unchanged.
	return fileutil.AtomicWrite(path, data, perm)
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
	// CA-3: renewal rewrites the private key (fresh CSR keypair); encrypt at
	// rest when enabled, plaintext otherwise. Cert/CA remain plaintext PEM.
	if err := writeDPNodeKey(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
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
