// Culvert — Enterprise-grade open source HTTP/HTTPS proxy
// https://github.com/KidCarmi/Claude-Test
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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

func main() { //nolint:gocognit,cyclop // main wires everything; refactoring deferred
	// ── CLI flags ────────────────────────────────────────────────────────────
	configPath := flag.String("config", "", "Path to config.yaml (optional)")
	proxyPort := flag.Int("port", 0, "Proxy port (overrides config)")
	uiPortFlag := flag.Int("ui-port", 0, "Web UI port (overrides config)")
	user := flag.String("user", "", "Basic auth username")
	pass := flag.String("pass", "", "Basic auth password")
	blockFile := flag.String("blocklist", "", "Blocklist file path")
	logFilePath := flag.String("logfile", "", "Log file path")
	logMaxMB := flag.Int("log-max-mb", 50, "Log rotation size in MB")
	tlsCert := flag.String("tls-cert", "", "TLS cert file for UI (optional)")
	tlsKey := flag.String("tls-key", "", "TLS key file for UI (optional)")
	rateLimitRPM := flag.Int("rate-limit", 0, "Max requests/min per IP (0=off)")
	ipMode := flag.String("ip-filter-mode", "", "IP filter mode: allow|block (empty=off)")
	socks5Port := flag.Int("socks5-port", 0, "SOCKS5 proxy port (0=disabled)")
	metricsTok := flag.String("metrics-token", "", "Bearer token for /metrics (empty=open)")
	cpGRPCAddr := flag.String("cp-grpc-addr", "", "ControlPlane gRPC listen addr e.g. :50051 (empty=off)")
	cpGRPCCert := flag.String("cp-grpc-cert", "", "ControlPlane gRPC TLS cert (mTLS)")
	cpGRPCKey := flag.String("cp-grpc-key", "", "ControlPlane gRPC TLS key")
	cpGRPCCA := flag.String("cp-grpc-ca", "", "ControlPlane gRPC CA for mTLS client validation")
	dpCPAddr := flag.String("dp-cp-addr", "", "DataPlane: ControlPlane gRPC addr to connect to")
	dpNodeID := flag.String("dp-node-id", "", "DataPlane: node identifier (default=hostname)")
	dpCert := flag.String("dp-cert", "", "DataPlane gRPC client TLS cert")
	dpKey := flag.String("dp-key", "", "DataPlane gRPC client TLS key")
	dpCA := flag.String("dp-ca", "", "DataPlane gRPC CA cert")
	policyFile := flag.String("policy", "", "Policy rules JSON file path")
	caPath := flag.String("ca-path", "", "Path to persist encrypted Root CA bundle (optional)")
	auditLog := flag.String("audit-log", "", "Persistent audit log file path (JSONL, appended)")
	syslogAddr := flag.String("syslog", "", "Remote syslog addr e.g. udp://10.0.0.1:514 or tcp://host:601")
	syslogFormat := flag.String("syslog-format", "", "Syslog message format: rfc3164 (default) or rfc5424")
	otlpEndpoint := flag.String("otlp-endpoint", "", "OTLP/HTTP endpoint for metrics export (e.g. http://otel-collector:4318)")
	uiAllowIP := flag.String("ui-allow-ip", "", "Comma-separated CIDRs/IPs allowed to access admin UI (empty=all)")
	sessionHrs := flag.Int("session-timeout", 0, "Admin UI session lifetime in hours (1-168, 0=default 8h)")
	geoIPDB := flag.String("geoip-db", "", "Path to GeoLite2-Country.mmdb (empty=GeoIP disabled)")
	clamavAddr := flag.String("clamav-addr", "", "ClamAV address: unix:/run/clamav/clamd.sock or tcp:host:port")
	yaraRulesDir := flag.String("yara-rules-dir", "", "Directory containing *.yar/*.yara YARA rule files")
	threatFeedDB := flag.String("threat-feed-db", "", "Path for persisted threat feed JSON database")
	uiUsersFile := flag.String("ui-users-file", "", "Path to persist admin UI users across restarts (e.g. /data/ui_users.json)")
	fileProfilesFile := flag.String("fileprofiles-file", "", "Path to persist file extension profiles (e.g. /data/fileprofiles.json)")
	uiNoTLS := flag.Bool("ui-no-tls", false, "Disable auto self-signed TLS; serve admin UI over plain HTTP")
	catFeedDB := flag.String("cat-feed-db", "", "Directory for BadgerDB URL category community feed (empty=disabled)")
	catFeedURL := flag.String("cat-feed-url", "", "Override URL for the UT1 category tarball (default: UT1 Capestat)")
	catSyncIntvl := flag.String("cat-sync-interval", "24h", "How often to re-sync the URL category feed (e.g. 12h, 24h)")
	enrollURL := flag.String("enroll", "", "Enrollment URL from Control Plane (e.g. culvert://enroll/host:50051/TOKEN?ca-fp=sha256:...)")
	clusterDB := flag.String("cluster-db", "", "Path to persist cluster state (e.g. /data/cluster.json)")
	clusterInsecureFlag := flag.Bool("cluster-insecure", false, "Allow insecure (non-TLS) gRPC for development — NEVER use in production")
	revocationsFile := flag.String("revocations-file", "", "Path to persist session revocations across restarts (e.g. /data/revocations.json)")
	flag.Parse()

	clusterInsecure = *clusterInsecureFlag

	// ── Enrollment mode (one-shot, exits after enrolling) ────────────────
	if *enrollURL != "" {
		if err := runEnrollment(*enrollURL); err != nil {
			log.Fatalf("Enrollment failed: %v", err)
		}
		return
	}

	// ── Load file config (if provided) ──────────────────────────────────────
	fc := &FileConfig{}
	if *configPath != "" {
		loaded, err := loadFileConfig(*configPath)
		if err != nil {
			log.Fatalf("Cannot load config file: %v", err)
		}
		fc = loaded
		fmt.Printf("[Culvert] Loaded config from %s\n", *configPath)
	}

	// CLI flags override file config.
	pPort := firstNonZero(*proxyPort, fc.Proxy.Port, 8080)
	uPort := firstNonZero(*uiPortFlag, fc.Proxy.UIPort, 9090)
	lPath := firstStr(*logFilePath, fc.Proxy.LogFile)
	blPath := firstStr(*blockFile, fc.Proxy.Blocklist)
	lMaxMB := firstNonZero(*logMaxMB, fc.Proxy.LogMaxMB, 50)
	authU := firstStr(*user, fc.Auth.User)
	authP := firstStr(*pass, fc.Auth.Pass)
	cert := firstStr(*tlsCert, fc.Proxy.TLSCert)
	key := firstStr(*tlsKey, fc.Proxy.TLSKey)
	rlRPM := firstNonZero(*rateLimitRPM, fc.Security.RateLimit)
	ipModeVal := firstStr(*ipMode, fc.Security.IPFilterMode)

	// ── Logger ───────────────────────────────────────────────────────────────
	var err error
	var logCloser interface{ Close() error }
	logger, logCloser, err = setupLogger(lPath, lMaxMB, fc.LogFormat)
	if err != nil {
		log.Fatalf("Logger setup failed: %v", err)
	}

	// ── Lifecycle context for all background goroutines ─────────────────────
	appLifecycleCtx, appLifecycleCancel = context.WithCancel(context.Background()) // #nosec G118 -- cancel is deferred on the next line
	defer appLifecycleCancel()

	// ── Config ───────────────────────────────────────────────────────────────
	cfg.ProxyPort = pPort
	cfg.UIPort = uPort
	if err := cfg.SetAuth(authU, authP); err != nil {
		log.Fatalf("Failed to set auth: %v", err)
	}

	// ── UI user persistence ───────────────────────────────────────────────────
	// Load previously-created admin users from disk so auth survives restarts.
	// The file is written whenever a user is created/modified/deleted via the UI.
	if *uiUsersFile != "" {
		cfg.SetUIUsersFile(*uiUsersFile)
		if err := cfg.LoadUIUsersFile(); err != nil {
			logger.Printf("UI users → failed to load %s: %v", *uiUsersFile, err)
		} else if cfg.AuthEnabled() {
			logger.Printf("UI users → loaded from %s", *uiUsersFile)
		}
	}

	// ── Session secret ───────────────────────────────────────────────────────
	initSessionSecret()
	initSessionSecretFromConfig(fc.SessionSecret) // overrides random if config provides one

	// ── Session revocation persistence ──────────────────────────────────────
	if *revocationsFile != "" {
		revocationFilePath = *revocationsFile
		if err := sessionRevoked.LoadRevocations(); err != nil {
			logger.Printf("Session  → failed to load revocations: %v", err)
		}
	}

	// ── Session timeout ───────────────────────────────────────────────────────
	hrs := firstNonZero(*sessionHrs, fc.SessionTimeoutHours)
	if hrs > 0 {
		SetSessionTTL(time.Duration(hrs) * time.Hour)
		logger.Printf("Session  → timeout %dh", hrs)
	}

	// ── Syslog / SIEM forwarding ──────────────────────────────────────────────
	syslogVal := firstStr(*syslogAddr, fc.SyslogAddr)
	syslogFmtVal := firstStr(*syslogFormat, fc.SyslogFormat)
	if syslogVal != "" {
		if err := InitSyslog(syslogVal, syslogFmtVal); err != nil {
			logger.Printf("Syslog   → connect failed (%v) — continuing without syslog", err)
		} else {
			syslogConfigured = syslogVal
		}
	}

	// ── OTLP metrics export ─────────────────────────────────────────────────
	otlpVal := firstStr(*otlpEndpoint, fc.OTLPEndpoint)
	if otlpVal != "" {
		globalOTLP.Configure(otlpVal, nil)
	}

	// ── Persistent audit log ──────────────────────────────────────────────────
	auditLogVal := firstStr(*auditLog, fc.AuditLogFile)
	if auditLogVal != "" {
		if err := InitAuditLog(auditLogVal); err != nil {
			logger.Printf("Audit    → log file error (%v) — falling back to in-memory", err)
		} else {
			logger.Printf("Audit    → persisting to %s", auditLogVal)
		}
	}

	// ── GeoIP database ───────────────────────────────────────────────────────
	geoDBVal := firstStr(*geoIPDB, fc.Proxy.GeoIPDB)
	if geoDBVal != "" {
		if err := InitGeoDB(geoDBVal); err != nil {
			logger.Printf("GeoIP    → failed to open %s (%v) — GeoIP disabled", geoDBVal, err)
		} else {
			logger.Printf("GeoIP    → loaded %s", geoDBVal)
		}
	} else {
		logger.Printf("GeoIP    → disabled (no -geoip-db set; destCountry rules will be skipped)")
	}

	// ── Admin UI IP allowlist ─────────────────────────────────────────────────
	uiAllowIPVal := firstStr(*uiAllowIP, "")
	uiAllowList := fc.UIAllowIPs
	if uiAllowIPVal != "" {
		for _, cidr := range strings.Split(uiAllowIPVal, ",") {
			uiAllowList = append(uiAllowList, strings.TrimSpace(cidr))
		}
	}
	if len(uiAllowList) > 0 {
		if err := SetUIAllowedCIDRs(uiAllowList); err != nil {
			logger.Printf("UI guard → invalid IP/CIDR (%v) — allowing all IPs", err)
		} else {
			logger.Printf("UI guard → admin panel restricted to %v", uiAllowList)
		}
	}

	// ── External base URL (for OIDC/SAML callbacks) ──────────────────────────
	if fc.Proxy.BaseURL != "" {
		SetProxyBaseURL(fc.Proxy.BaseURL)
		logger.Printf("BaseURL  → %s", fc.Proxy.BaseURL)
	}

	// ── Generic IdP Registry ─────────────────────────────────────────────────
	if fc.Proxy.IdPProfilesFile != "" {
		if err := idpRegistry.Load(fc.Proxy.IdPProfilesFile); err != nil {
			log.Fatalf("IdP profiles load error: %v", err)
		}
		logger.Printf("IdP      → loaded from %s (%d profiles)", fc.Proxy.IdPProfilesFile, len(idpRegistry.All()))
	}

	// ── PAC file configuration ────────────────────────────────────────────────
	pacCfgPath := "pac_config.json"
	if err := pacStore.Load(pacCfgPath); err != nil {
		log.Fatalf("PAC config load error: %v", err)
	}
	// Tell the PAC generator the real proxy port so /proxy.pac auto-generates
	// the correct PROXY directive even when the admin hasn't explicitly set it.
	pacDefaultProxyPort = pPort

	// ── Legacy external auth provider (LDAP / OIDC introspection) ────────────
	// LDAP takes precedence when URL is configured.
	// The generic IdP registry is preferred; the legacy providers remain for
	// backwards-compatibility.
	if fc.LDAP.URL != "" {
		ldapProvider, err := NewLDAPAuth(fc.LDAP)
		if err != nil {
			log.Fatalf("LDAP config error: %v", err)
		}
		cfg.SetProvider(ldapProvider)
		logger.Printf("Auth     → LDAP (%s, base=%s)", fc.LDAP.URL, fc.LDAP.BaseDN)
	} else if fc.OIDC.IntrospectionURL != "" {
		oidcProvider, err := NewOIDCAuth(fc.OIDC)
		if err != nil {
			log.Fatalf("OIDC config error: %v", err)
		}
		cfg.SetProvider(oidcProvider)
		if fc.OIDC.LoginURL != "" {
			SetOIDCLoginURL(fc.OIDC.LoginURL)
			logger.Printf("Auth     → OIDC login redirect: %s", fc.OIDC.LoginURL)
		}
		logger.Printf("Auth     → OIDC introspection (%s)", fc.OIDC.IntrospectionURL)
	} else if authU != "" {
		logger.Printf("Auth     → local bcrypt (user=%s)", authU)
	}

	// ── Metrics token ────────────────────────────────────────────────────────
	metricsToken = firstStr(*metricsTok, fc.Proxy.MetricsToken)
	if metricsToken != "" {
		logger.Printf("Metrics  → /metrics protected by Bearer token")
	} else {
		logger.Printf("Metrics  → /metrics open (set -metrics-token to restrict)")
	}

	// ── Control Plane / Data Plane gRPC ──────────────────────────────────────
	clusterRole.role = "standalone"
	if h, err2 := os.Hostname(); err2 == nil {
		clusterRole.nodeID = h
	}
	// ── Cluster state persistence ────────────────────────────────────────
	clusterDBPath := firstStr(*clusterDB, fc.Cluster.StateDB, "cluster.json")
	clusterDBPathGlobal = clusterDBPath
	if err := globalClusterStore.Load(clusterDBPath); err != nil {
		logger.Printf("ClusterDB → load error: %v — starting fresh", err)
	} else {
		nodes := globalClusterStore.ListNodes()
		if len(nodes) > 0 {
			logger.Printf("ClusterDB → loaded %d enrolled node(s) from %s", len(nodes), clusterDBPath)
		}
	}

	// Merge CLI flags with YAML cluster config (CLI wins).
	cpAddr := firstStr(*cpGRPCAddr, fc.Cluster.GRPCAddr)
	cpCert := firstStr(*cpGRPCCert, fc.Cluster.CertFile)
	cpKey := firstStr(*cpGRPCKey, fc.Cluster.KeyFile)
	cpCA := firstStr(*cpGRPCCA, fc.Cluster.CAFile)

	if cpAddr != "" || fc.Cluster.Role == "control-plane" {
		if err := enableControlPlane(cpAddr, cpCert, cpKey, cpCA, clusterDBPath); err != nil {
			logger.Fatalf("ControlPlane gRPC: %v", err)
		}
	}
	if *dpCPAddr != "" {
		// This process is a Data Plane node.
		clusterRole.role = "data-plane"
		clusterRole.grpcAddr = *dpCPAddr
		nodeID := *dpNodeID
		if nodeID == "" {
			nodeID = clusterRole.nodeID
		}
		clusterRole.nodeID = nodeID
		dpClient, err := NewDataPlaneClient(nodeID, *dpCPAddr, *dpCert, *dpKey, *dpCA)
		if err != nil {
			logger.Fatalf("DataPlane client: %v", err)
		}
		clusterRoleIsDP.Store(true)
		dpClient.Run(appLifecycleCtx, 30*time.Second)
		logger.Printf("DataPlane: polling ControlPlane at %s every 30s", *dpCPAddr)
	}

	// ── Security: Connection limit per IP ────────────────────────────────────
	if fc.Security.MaxConnsPerIP > 0 {
		connLimiter.Enable(fc.Security.MaxConnsPerIP)
		logger.Printf("ConnLimit → max %d connections per IP", fc.Security.MaxConnsPerIP)
	}

	// ── Security: IP filter ──────────────────────────────────────────────────
	if ipModeVal != "" {
		ipf.SetMode(ipModeVal)
		for _, entry := range fc.Security.IPList {
			if err := ipf.Add(entry); err != nil {
				logger.Printf("IP filter: invalid entry %q: %v", entry, err)
			}
		}
		logger.Printf("IP filter → mode=%s entries=%d", ipModeVal, len(fc.Security.IPList))
	}

	// ── Security: Rate limiter ───────────────────────────────────────────────
	var rlCleanupCancel context.CancelFunc
	if rlRPM > 0 {
		rl.Configure(rlRPM, time.Minute)
		logger.Printf("Rate limit → %d req/min per IP", rlRPM)
		var rlCtx context.Context
		rlCtx, rlCleanupCancel = context.WithCancel(appLifecycleCtx)
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

	// ── Blocklist ────────────────────────────────────────────────────────────
	if blPath != "" {
		if err := bl.Load(blPath); err != nil {
			if os.IsNotExist(err) {
				logger.Printf("Blocklist not found at %s — starting with empty list", blPath)
			} else {
				logger.Fatalf("Cannot load blocklist: %v", err)
			}
		} else {
			logger.Printf("Blocklist loaded: %d entries from %s", bl.Count(), blPath)
		}
	}

	// ── Blocklist feed sync ───────────────────────────────────────────────────
	blFeedURL := fc.Proxy.BlocklistFeedURL
	if blFeedURL != "" {
		blFeedInterval := blFeedDefaultInterval
		if s := fc.Proxy.BlocklistFeedInterval; s != "" {
			if d, err := time.ParseDuration(s); err == nil && d > 0 {
				blFeedInterval = d
			}
		}
		blFeedSyncer = newBlocklistSyncer(bl, blFeedURL, blFeedInterval)
		blFeedSyncer.Start(appLifecycleCtx)
		logger.Printf("BlocklistFeed → syncing from %s every %s", blFeedURL, blFeedInterval)
	} else {
		blFeedSyncer = newBlocklistSyncer(bl, "", blFeedDefaultInterval)
	}

	// ── Root CA for SSL inspection ────────────────────────────────────────────
	// Passphrase is read from env so it never appears in CLI history or
	// process listings (shift-left secret hygiene).
	caPassphrase := os.Getenv(caPassphraseEnv)
	caPathVal := firstStr(*caPath, fc.Proxy.CAPath)
	if caPathVal != "" {
		if err := certMgr.LoadOrInitCA(caPathVal, caPassphrase); err != nil {
			logger.Printf("Warning: Root CA load/init failed (%v) — SSL inspection disabled", err)
		} else {
			logger.Printf("SSL CA   → Root CA ready (persisted at %s, encrypted=%v)", caPathVal, caPassphrase != "")
		}
	} else {
		if err := certMgr.InitCA(); err != nil {
			logger.Printf("Warning: Root CA init failed (%v) — SSL inspection disabled", err)
		} else {
			logger.Printf("SSL CA   → Root CA ready in-memory (set -ca-path + %s for persistence)", caPassphraseEnv)
		}
	}
	// Store CA runtime config for API-driven rotation.
	caRuntime.path = caPathVal
	caRuntime.passphrase = caPassphrase
	// Start CA auto-rotation background check.
	if certMgr.Ready() {
		StartCAAutoRotation(appLifecycleCtx, caPathVal, caPassphrase)
	}

	// ── Policy engine ─────────────────────────────────────────────────────────
	polPath := firstStr(*policyFile, fc.Proxy.PolicyFile)
	if polPath != "" {
		if err := policyStore.Load(polPath); err != nil {
			logger.Fatalf("Cannot load policy file: %v", err)
		}
		logger.Printf("Policy   → %d rule(s) loaded from %s", len(policyStore.List()), polPath)
	} else {
		// Use an in-memory store (no persistence until a path is set).
		policyStore.path = ""
		logger.Printf("Policy   → in-memory only (set -policy <file> for persistence)")
	}

	// ── URL Categories ────────────────────────────────────────────────────────
	catPath := fc.Proxy.URLCategoriesFile
	if catPath == "" {
		catPath = "categories.json"
	}
	if err := catStore.Load(catPath); err != nil {
		logger.Fatalf("Cannot load URL categories: %v", err)
	}
	logger.Printf("URLCat   → %d categories loaded from %s", len(catStore.All()), catPath)

	// ── Community URL category feed (BadgerDB) ────────────────────────────────
	// When --cat-feed-db is set, open BadgerDB and start the UT1 FeedSyncer.
	// Layer 1 (catStore) remains the priority; BadgerDB is the fallback.
	var feedSyncer *FeedSyncer
	if *catFeedDB == "" { //nolint:nestif // straightforward init block; nesting is necessary
		logger.Printf("CatFeedDB → disabled (set --cat-feed-db for community feed)")
	} else {
		var dbErr error
		communityDB, dbErr = openCommunityDB(*catFeedDB)
		if dbErr != nil {
			logger.Fatalf("CatFeedDB → cannot open BadgerDB at %s: %v", *catFeedDB, dbErr)
		}
		syncD := 24 * time.Hour
		if *catSyncIntvl != "" {
			if d, err2 := time.ParseDuration(*catSyncIntvl); err2 == nil {
				syncD = d
			}
		}
		feedSyncer = newFeedSyncer(communityDB, *catFeedURL, syncD)
		feedSyncer.Start(appLifecycleCtx)
		logger.Printf("CatFeedDB → BadgerDB at %s, sync every %s", *catFeedDB, syncD)
	}

	// ── File block profile ───────────────────────────────────────────────────
	if len(fc.FileBlock.Extensions) > 0 {
		for _, ext := range fc.FileBlock.Extensions {
			fileBlocker.Add(ext)
		}
	} else {
		for _, ext := range defaultBlockedExts {
			fileBlocker.Add(ext)
		}
	}
	logger.Printf("FileBlock → %d extension(s) in profile", fileBlocker.Count())

	// ── File extension profiles (for per-rule policy blocking) ────────────────
	fpPath := firstStr(*fileProfilesFile, fc.Proxy.FileProfilesFile)
	if fpPath == "" {
		fpPath = "fileprofiles.json"
	}
	if err := globalProfileStore.Load(fpPath); err != nil {
		logger.Printf("FileProfiles → load error (%v) — using in-memory defaults", err)
	} else {
		logger.Printf("FileProfiles → %d profile(s) loaded from %s", len(globalProfileStore.List()), fpPath)
	}

	// ── SSL Bypass patterns ───────────────────────────────────────────────────
	// If ssl_bypass_file is set, load from the JSON file (dynamic — managed via
	// /api/ssl-bypass without restart). On first run, seed it from ssl_bypass_patterns.
	bypassFilePath := firstStr(fc.Proxy.SSLBypassFile)
	if bypassFilePath != "" {
		if err := sslBypass.Load(bypassFilePath); err != nil {
			logger.Fatalf("SSL bypass file error: %v", err)
		}
		if len(sslBypass.List()) == 0 && len(fc.Proxy.SSLBypassPatterns) > 0 {
			if err := sslBypass.Set(fc.Proxy.SSLBypassPatterns); err != nil {
				logger.Fatalf("SSL bypass pattern error: %v", err)
			}
			sslBypass.Save() // persist seed patterns on first run
		}
		logger.Printf("SSL Bypass → %d pattern(s) (file: %s)", len(sslBypass.List()), bypassFilePath)
	} else if len(fc.Proxy.SSLBypassPatterns) > 0 {
		if err := sslBypass.Set(fc.Proxy.SSLBypassPatterns); err != nil {
			logger.Fatalf("SSL bypass pattern error: %v", err)
		}
		logger.Printf("SSL Bypass → %d pattern(s) (in-memory; set ssl_bypass_file for dynamic management)", len(sslBypass.List()))
	}

	// ── DPI Content Scanner ──────────────────────────────────────────────────
	// If content_scan_file is set, patterns are loaded from JSON and can be
	// managed at runtime via /api/content-scan without restarting.
	// On first run, content_scan_patterns from YAML seeds the file.
	scanFilePath := firstStr(fc.Proxy.ContentScanFile)
	if scanFilePath != "" {
		if err := dpiScanner.Load(scanFilePath); err != nil {
			logger.Fatalf("Content scan file error: %v", err)
		}
		if len(dpiScanner.List()) == 0 && len(fc.Proxy.ContentScanPatterns) > 0 {
			if err := dpiScanner.Set(fc.Proxy.ContentScanPatterns); err != nil {
				logger.Fatalf("Content scan pattern error: %v", err)
			}
			dpiScanner.Save()
		}
		logger.Printf("DPI Scan → %d pattern(s) (file: %s)", len(dpiScanner.List()), scanFilePath)
	} else if len(fc.Proxy.ContentScanPatterns) > 0 {
		if err := dpiScanner.Set(fc.Proxy.ContentScanPatterns); err != nil {
			logger.Fatalf("Content scan pattern error: %v", err)
		}
		logger.Printf("DPI Scan → %d pattern(s) (in-memory; set content_scan_file for persistence)", len(dpiScanner.List()))
	}

	// ── Rewrite rules ────────────────────────────────────────────────────────
	if len(fc.Rewrite) > 0 {
		rewriter.SetRules(fc.Rewrite)
		logger.Printf("Rewrite  → %d rule(s) loaded", len(fc.Rewrite))
	}

	// ── Default policy action ────────────────────────────────────────────────
	// "allow" = passthrough mode (good for initial setup); "deny" = zero-trust.
	// Defaults to "deny" when rules are configured, "allow" when no rules exist.
	defaultAction := firstStr(fc.DefaultAction)
	if defaultAction == "" {
		if len(policyStore.List()) == 0 {
			defaultAction = "allow"
			logger.Printf("Policy   → no rules configured; defaulting to Allow (passthrough). Add rules and set default_action: deny for Zero Trust.")
		} else {
			defaultAction = "deny"
		}
	}
	setDefaultPolicyAction(defaultAction)
	logger.Printf("Policy   → default action: %s", defaultAction)

	// ── Security scanning: ClamAV + YARA + Threat Feeds ─────────────────────
	secCfg := fc.SecurityScan
	clamAddr := firstStr(*clamavAddr, secCfg.ClamAVAddr)
	yaraDir := firstStr(*yaraRulesDir, secCfg.YARARulesDir)
	feedDB := firstStr(*threatFeedDB, secCfg.ThreatFeedDB)

	if secCfg.Enabled || clamAddr != "" || yaraDir != "" || feedDB != "" {
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
			if err := globalYARA.LoadDir(yaraDir); err != nil {
				logger.Printf("YARA     → load error: %v", err)
			} else {
				logger.Printf("YARA     → %d rule(s) from %s", globalYARA.Count(), yaraDir)
			}
		} else {
			logger.Printf("YARA     → disabled (set -yara-rules-dir to enable)")
		}

		// Threat feeds.
		if feedDB != "" || secCfg.Enabled {
			globalThreatFeed.Init(feedDB, syncInterval)
			globalThreatFeed.Start(appLifecycleCtx)
			logger.Printf("ThreatFeed → sync every %s, db=%q", syncInterval, feedDB)
		}
	}

	// ── Upstream proxy chaining ──────────────────────────────────────────────
	if len(fc.Upstream.Proxies) > 0 {
		initUpstreamPool(fc)
	}

	// ── Client certificate (mTLS) for upstream servers ───────────────────────
	if fc.Proxy.ClientCertFile != "" && fc.Proxy.ClientKeyFile != "" {
		clientCert, err := tls.LoadX509KeyPair(fc.Proxy.ClientCertFile, fc.Proxy.ClientKeyFile)
		if err != nil {
			logger.Printf("mTLS     → failed to load client cert: %v", err)
		} else {
			if upstreamTransport.TLSClientConfig == nil {
				upstreamTransport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			}
			upstreamTransport.TLSClientConfig.Certificates = []tls.Certificate{clientCert}
			logger.Printf("mTLS     → client cert loaded (%s)", fc.Proxy.ClientCertFile)
		}
	}

	// ── OCSP/CRL revocation checking ─────────────────────────────────────────
	if fc.Proxy.OCSPCheck {
		globalOCSP.Enable()
		ConfigureTransportOCSP(upstreamTransport)
		logger.Printf("OCSP     → upstream certificate revocation checking enabled")
	}

	// ── SSE live dashboard broadcaster ───────────────────────────────────────
	startSSEBroadcaster()

	// ── SOCKS5 server (optional) ─────────────────────────────────────────────
	s5Port := firstNonZero(*socks5Port, fc.Proxy.SOCKS5Port)
	if s5Port > 0 {
		go startSOCKS5(s5Port)
	}

	// ── Web UI ────────────────────────────────────────────────────────────
	uiCfgGeoIPDB = geoDBVal
	uiCfgLogFile = lPath
	uiCfgLogMaxMB = lMaxMB
	uiCfgLogFormat = fc.LogFormat
	go startUI(uPort, cert, key, *uiNoTLS)

	// ── Proxy server ─────────────────────────────────────────────────────────
	// NOTE: http.ServeMux cannot be used here because it "cleans" URLs and
	// issues a 301 redirect when the path is empty — which is always the case
	// for CONNECT requests (HTTPS tunnels). Using a plain HandlerFunc avoids
	// the redirect and lets handleRequest receive every proxy request directly.
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			handleHealth(w, r)
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
		Addr:         fmt.Sprintf(":%d", pPort),
		Handler:      proxyHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	logger.Printf("Proxy   → http://localhost:%d", pPort)
	if authU != "" {
		logger.Printf("Auth    → enabled (user: %s)", authU)
	}

	// ── Graceful shutdown ────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// ── Hot config reload (SIGHUP) ──────────────────────────────────────────
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	go func() {
		for range sighup {
			if *configPath == "" {
				logger.Println("SIGHUP received but no -config path set; ignoring")
				continue
			}
			logger.Printf("SIGHUP received — reloading config from %s", *configPath)
			reloaded, err := loadFileConfig(*configPath)
			if err != nil {
				logger.Printf("Config reload error: %v — keeping current config", err)
				continue
			}
			applyHotReload(reloaded)
			logger.Println("Config reloaded successfully")
		}
	}()

	go func() {
		if err := proxySrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Proxy error: %v", err)
		}
	}()

	<-quit
	logger.Println("Shutting down gracefully…")

	// Gracefully stop gRPC server first (drains in-flight RPCs).
	StopControlPlaneGRPC()

	// Cancel all background goroutines (feed syncers, CA rotation, health checks, etc.)
	appLifecycleCancel()

	if rlCleanupCancel != nil {
		rlCleanupCancel()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
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
			logger.Printf("CatFeedDB → close error: %v", err)
		}
	}
	if logCloser != nil {
		logCloser.Close()
	}
	_ = feedSyncer // suppress unused warning; it runs as a goroutine
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
		Version:           "1.0.0",
		ClamAV:            clamStatus,
		CAExpiresDays:     caExpiresDays,
		ThreatFeedEntries: tfEntries,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Printf("handleHealth encode: %v", err)
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

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
	logger.Printf("Upstream → %s", formatUpstreamSummary(fc.Upstream.Proxies))

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
	if clusterRole.role == "control-plane" {
		return fmt.Errorf("already running as control-plane")
	}
	if grpcAddr == "" {
		return fmt.Errorf("gRPC listen address is required")
	}
	clusterRole.role = "control-plane"
	clusterRole.grpcAddr = grpcAddr
	globalConfigStore.Update(CurrentConfigSnapshot())
	initClusterCA(clusterDBPath)
	if err := StartControlPlaneGRPC(grpcAddr, certFile, keyFile, caFile); err != nil {
		clusterRole.role = "standalone" // rollback
		return err
	}
	globalClusterStore.StartHeartbeatMonitor(appLifecycleCtx.Done())
	logger.Printf("ControlPlane: enabled via GUI (gRPC %s)", strings.ReplaceAll(grpcAddr, "\n", ""))
	return nil
}

// runEnrollment handles the one-shot enrollment flow: generates a keypair+CSR,
// contacts the Control Plane, and persists the signed certificate.
func runEnrollment(enrollURLStr string) error {
	cpAddr, token, err := parseEnrollURL(enrollURLStr)
	if err != nil {
		return err
	}
	nodeID, _ := os.Hostname()
	if nodeID == "" {
		nodeID = "dp-node"
	}
	fmt.Printf("[Culvert] Enrolling as node %q with Control Plane at %s\n", nodeID, cpAddr)

	privKey, csrPEM, err := generateCSR(nodeID)
	if err != nil {
		return err
	}
	resp, err := callEnrollRPC(cpAddr, token, nodeID, csrPEM)
	if err != nil {
		return err
	}
	return persistEnrollCerts(privKey, resp, cpAddr, nodeID)
}

// parseEnrollURL extracts CP address and token from the enrollment URL.
func parseEnrollURL(raw string) (cpAddr, token string, err error) {
	raw = strings.TrimPrefix(raw, "culvert://enroll/")
	parts := strings.SplitN(raw, "/", 2)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid enrollment URL format — expected culvert://enroll/host:port/TOKEN")
	}
	token = parts[1]
	if idx := strings.Index(token, "?"); idx >= 0 {
		token = token[:idx]
	}
	return parts[0], token, nil
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

// persistEnrollCerts saves the signed certificate, private key, and CA cert to disk.
func persistEnrollCerts(privKey *ecdsa.PrivateKey, resp *EnrollResponse, cpAddr, nodeID string) error {
	certPath, keyPath, caPath := "./dp-node.crt", "./dp-node.key", "./cluster-ca.crt"

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, []byte(resp.CertPEM), 0o600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	if err := os.WriteFile(caPath, []byte(resp.CAPEM), 0o600); err != nil {
		return fmt.Errorf("write CA: %w", err)
	}

	fmt.Printf("[Culvert] Enrollment successful!\n")
	fmt.Printf("[Culvert] Certificate: %s\n", certPath)
	fmt.Printf("[Culvert] Key:         %s\n", keyPath)
	fmt.Printf("[Culvert] CA:          %s\n", caPath)
	fmt.Printf("[Culvert]\n")
	fmt.Printf("[Culvert] Start this node with:\n")
	fmt.Printf("[Culvert]   ./culvert -port 8080 -dp-cp-addr %s -dp-node-id %s -dp-cert %s -dp-key %s -dp-ca %s\n",
		cpAddr, nodeID, certPath, keyPath, caPath)
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
			logger.Printf("Reload: blocklist → %d entries", bl.Count())
		}
	}

	// Policy rules
	if fc.Proxy.PolicyFile != "" {
		if err := policyStore.Load(fc.Proxy.PolicyFile); err != nil {
			logger.Printf("Reload: policy error: %v", err)
		} else {
			logger.Printf("Reload: policy → %d rules", len(policyStore.List()))
		}
	}

	// Default action
	if fc.DefaultAction != "" {
		setDefaultPolicyAction(fc.DefaultAction)
		logger.Printf("Reload: default action → %s", fc.DefaultAction)
	}

	// Rate limit
	if fc.Security.RateLimit > 0 {
		rl.Configure(fc.Security.RateLimit, time.Minute)
		logger.Printf("Reload: rate limit → %d req/min", fc.Security.RateLimit)
	}

	// IP filter
	if fc.Security.IPFilterMode != "" {
		ipf.SetMode(fc.Security.IPFilterMode)
		logger.Printf("Reload: IP filter mode → %s", fc.Security.IPFilterMode)
	}

	// Rewrite rules
	if len(fc.Rewrite) > 0 {
		rewriter.SetRules(fc.Rewrite)
		logger.Printf("Reload: rewrite → %d rules", len(fc.Rewrite))
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
		logger.Printf("Reload: upstream → %s", formatUpstreamSummary(fc.Upstream.Proxies))
	}
}
