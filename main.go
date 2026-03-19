// ProxyShield — Enterprise-grade open source HTTP/HTTPS proxy
// https://github.com/KidCarmi/Claude-Test
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// caPassphraseEnv holds the name of the environment variable that supplies the
// CA private-key encryption passphrase. Using an env var keeps the passphrase
// out of CLI history and process listings (shift-left: secrets management).
// This is an env-var name, NOT a credential — the false-positive is suppressed.
const caPassphraseEnv = "PROXYSHIELD_CA_PASSPHRASE" // #nosec G101 -- env-var name, not a credential

var logger *log.Logger

// blFeedSyncer is the process-wide blocklist feed syncer, set in main().
var blFeedSyncer *BlocklistSyncer

func main() {
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
	uiAllowIP := flag.String("ui-allow-ip", "", "Comma-separated CIDRs/IPs allowed to access admin UI (empty=all)")
	sessionHrs := flag.Int("session-timeout", 0, "Admin UI session lifetime in hours (1-168, 0=default 8h)")
	geoIPDB := flag.String("geoip-db", "", "Path to GeoLite2-Country.mmdb (empty=GeoIP disabled)")
	clamavAddr := flag.String("clamav-addr", "", "ClamAV address: unix:/run/clamav/clamd.sock or tcp:host:port")
	yaraRulesDir := flag.String("yara-rules-dir", "", "Directory containing *.yar/*.yara YARA rule files")
	threatFeedDB := flag.String("threat-feed-db", "", "Path for persisted threat feed JSON database")
	uiUsersFile := flag.String("ui-users-file", "", "Path to persist admin UI users across restarts (e.g. /data/ui_users.json)")
	uiNoTLS := flag.Bool("ui-no-tls", false, "Disable auto self-signed TLS; serve admin UI over plain HTTP")
	catFeedDB := flag.String("cat-feed-db", "", "Directory for BadgerDB URL category community feed (empty=disabled)")
	catFeedURL := flag.String("cat-feed-url", "", "Override URL for the UT1 category tarball (default: UT1 Capestat)")
	catSyncIntvl := flag.String("cat-sync-interval", "24h", "How often to re-sync the URL category feed (e.g. 12h, 24h)")
	flag.Parse()

	// ── Load file config (if provided) ──────────────────────────────────────
	fc := &FileConfig{}
	if *configPath != "" {
		loaded, err := loadFileConfig(*configPath)
		if err != nil {
			log.Fatalf("Cannot load config file: %v", err)
		}
		fc = loaded
		fmt.Printf("[ProxyShield] Loaded config from %s\n", *configPath)
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

	// ── Session timeout ───────────────────────────────────────────────────────
	hrs := firstNonZero(*sessionHrs, fc.SessionTimeoutHours)
	if hrs > 0 {
		SetSessionTTL(time.Duration(hrs) * time.Hour)
		logger.Printf("Session  → timeout %dh", hrs)
	}

	// ── Syslog / SIEM forwarding ──────────────────────────────────────────────
	syslogVal := firstStr(*syslogAddr, fc.SyslogAddr)
	if syslogVal != "" {
		if err := InitSyslog(syslogVal); err != nil {
			logger.Printf("Syslog   → connect failed (%v) — continuing without syslog", err)
		} else {
			syslogConfigured = syslogVal
		}
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
	if *cpGRPCAddr != "" {
		// This process is (also) a Control Plane.
		globalConfigStore.Update(CurrentConfigSnapshot())
		if err := StartControlPlaneGRPC(*cpGRPCAddr, *cpGRPCCert, *cpGRPCKey, *cpGRPCCA); err != nil {
			logger.Fatalf("ControlPlane gRPC: %v", err)
		}
	}
	if *dpCPAddr != "" {
		// This process is a Data Plane node.
		nodeID := *dpNodeID
		if nodeID == "" {
			if h, err2 := os.Hostname(); err2 == nil {
				nodeID = h
			}
		}
		dpClient, err := NewDataPlaneClient(nodeID, *dpCPAddr, *dpCert, *dpKey, *dpCA)
		if err != nil {
			logger.Fatalf("DataPlane client: %v", err)
		}
		dpClient.Run(context.Background(), 30*time.Second)
		logger.Printf("DataPlane: polling ControlPlane at %s every 30s", *dpCPAddr)
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
		rlCtx, rlCleanupCancel = context.WithCancel(context.Background())
		go func() {
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-rlCtx.Done():
					return
				case <-t.C:
					rl.Cleanup()
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
		blFeedSyncer.Start(context.Background())
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
		feedSyncer.Start(context.Background())
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
			globalThreatFeed.Start(context.Background())
			logger.Printf("ThreatFeed → sync every %s, db=%q", syncInterval, feedDB)
		}
	}

	// ── SSE live dashboard broadcaster ───────────────────────────────────────
	startSSEBroadcaster()

	// ── SOCKS5 server (optional) ─────────────────────────────────────────────
	s5Port := firstNonZero(*socks5Port, fc.Proxy.SOCKS5Port)
	if s5Port > 0 {
		go startSOCKS5(s5Port)
	}

	// ── Web UI ────────────────────────────────────────────────────────────
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

	go func() {
		if err := proxySrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Proxy error: %v", err)
		}
	}()

	<-quit
	logger.Println("Shutting down gracefully…")

	if rlCleanupCancel != nil {
		rlCleanupCancel()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := proxySrv.Shutdown(ctx); err != nil {
		logger.Printf("Shutdown error: %v", err)
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
