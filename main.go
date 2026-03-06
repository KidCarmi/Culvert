// ProxyShield — Enterprise-grade open source HTTP/HTTPS proxy
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
	"syscall"
	"time"
)

// caPassphraseEnv holds the name of the environment variable that supplies the
// CA private-key encryption passphrase. Using an env var keeps the passphrase
// out of CLI history and process listings (shift-left: secrets management).
// This is an env-var name, NOT a credential — the false-positive is suppressed.
const caPassphraseEnv = "PROXYSHIELD_CA_PASSPHRASE" // #nosec G101 -- env-var name, not a credential

var logger *log.Logger

func main() {
	// ── CLI flags ────────────────────────────────────────────────────────────
	configPath   := flag.String("config",        "",     "Path to config.yaml (optional)")
	proxyPort    := flag.Int("port",             0,    "Proxy port (overrides config)")
	uiPortFlag   := flag.Int("ui-port",          0,    "Web UI port (overrides config)")
	user         := flag.String("user",          "",   "Basic auth username")
	pass         := flag.String("pass",          "",   "Basic auth password")
	blockFile    := flag.String("blocklist",     "",   "Blocklist file path")
	logFilePath  := flag.String("logfile",       "",   "Log file path")
	logMaxMB     := flag.Int("log-max-mb",       50,   "Log rotation size in MB")
	tlsCert      := flag.String("tls-cert",      "",   "TLS cert file for UI (optional)")
	tlsKey       := flag.String("tls-key",       "",   "TLS key file for UI (optional)")
	rateLimitRPM := flag.Int("rate-limit",       0,    "Max requests/min per IP (0=off)")
	ipMode       := flag.String("ip-filter-mode","",   "IP filter mode: allow|block (empty=off)")
	socks5Port  := flag.Int("socks5-port",      0,  "SOCKS5 proxy port (0=disabled)")
	metricsTok  := flag.String("metrics-token", "", "Bearer token for /metrics (empty=open)")
	cpGRPCAddr  := flag.String("cp-grpc-addr",  "", "ControlPlane gRPC listen addr e.g. :50051 (empty=off)")
	cpGRPCCert  := flag.String("cp-grpc-cert",  "", "ControlPlane gRPC TLS cert (mTLS)")
	cpGRPCKey   := flag.String("cp-grpc-key",   "", "ControlPlane gRPC TLS key")
	cpGRPCCA    := flag.String("cp-grpc-ca",    "", "ControlPlane gRPC CA for mTLS client validation")
	dpCPAddr    := flag.String("dp-cp-addr",    "", "DataPlane: ControlPlane gRPC addr to connect to")
	dpNodeID    := flag.String("dp-node-id",    "", "DataPlane: node identifier (default=hostname)")
	dpCert      := flag.String("dp-cert",       "", "DataPlane gRPC client TLS cert")
	dpKey       := flag.String("dp-key",        "", "DataPlane gRPC client TLS key")
	dpCA        := flag.String("dp-ca",         "", "DataPlane gRPC CA cert")
	policyFile  := flag.String("policy",        "", "Policy rules JSON file path")
	caPath      := flag.String("ca-path",       "", "Path to persist encrypted Root CA bundle (optional)")
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
	pPort  := firstNonZero(*proxyPort,  fc.Proxy.Port,   8080)
	uPort  := firstNonZero(*uiPortFlag, fc.Proxy.UIPort, 9090)
	lPath  := firstStr(*logFilePath, fc.Proxy.LogFile)
	blPath := firstStr(*blockFile,   fc.Proxy.Blocklist)
	lMaxMB := firstNonZero(*logMaxMB, fc.Proxy.LogMaxMB, 50)
	authU  := firstStr(*user, fc.Auth.User)
	authP  := firstStr(*pass, fc.Auth.Pass)
	cert   := firstStr(*tlsCert, fc.Proxy.TLSCert)
	key    := firstStr(*tlsKey,  fc.Proxy.TLSKey)
	rlRPM  := firstNonZero(*rateLimitRPM, fc.Security.RateLimit)
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
	cfg.UIPort    = uPort
	if err := cfg.SetAuth(authU, authP); err != nil {
		log.Fatalf("Failed to set auth: %v", err)
	}

	// ── External auth provider (LDAP / OIDC) ─────────────────────────────────
	// LDAP takes precedence when URL is configured.
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
	if rlRPM > 0 {
		rl.Configure(rlRPM, time.Minute)
		logger.Printf("Rate limit → %d req/min per IP", rlRPM)
		go func() {
			t := time.NewTicker(5 * time.Minute)
			for range t.C {
				rl.Cleanup()
			}
		}()
	}

	// ── Blocklist ────────────────────────────────────────────────────────────
	if blPath != "" {
		if err := bl.Load(blPath); err != nil {
			logger.Fatalf("Cannot load blocklist: %v", err)
		}
		logger.Printf("Blocklist loaded: %d entries from %s", bl.Count(), blPath)
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

	// ── Rewrite rules ────────────────────────────────────────────────────────
	if len(fc.Rewrite) > 0 {
		rewriter.SetRules(fc.Rewrite)
		logger.Printf("Rewrite  → %d rule(s) loaded", len(fc.Rewrite))
	}

	// ── SOCKS5 server (optional) ─────────────────────────────────────────────
	s5Port := firstNonZero(*socks5Port, fc.Proxy.SOCKS5Port)
	if s5Port > 0 {
		go startSOCKS5(s5Port)
	}

	// ── Web UI (HTTPS with self-signed cert by default) ───────────────────
	go startUI(uPort, cert, key)

	// ── Proxy server ─────────────────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/", handleRequest)

	proxySrv := &http.Server{
		Addr:         fmt.Sprintf(":%d", pPort),
		Handler:      mux,
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := proxySrv.Shutdown(ctx); err != nil {
		logger.Printf("Shutdown error: %v", err)
	}
	if logCloser != nil {
		logCloser.Close()
	}
	logger.Println("Stopped.")
}

// handleHealth is a simple liveness probe.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","uptime":"%s","version":"1.0.0"}`, uptime())
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
