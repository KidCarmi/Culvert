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

var logger *log.Logger

func main() {
	// ── CLI flags ────────────────────────────────────────────────────────────
	configPath  := flag.String("config",    "",      "Path to config.yaml (optional)")
	proxyPort   := flag.Int("port",         0,       "Proxy port (overrides config)")
	uiPortFlag  := flag.Int("ui-port",      0,       "Web UI port (overrides config)")
	user        := flag.String("user",      "",      "Basic auth username")
	pass        := flag.String("pass",      "",      "Basic auth password")
	blockFile   := flag.String("blocklist", "",      "Blocklist file path")
	logFilePath := flag.String("logfile",   "",      "Log file path")
	logMaxMB    := flag.Int("log-max-mb",   50,      "Log rotation size in MB")
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

	// ── Logger ───────────────────────────────────────────────────────────────
	var err error
	var logCloser interface{ Close() error }
	logger, logCloser, err = setupLogger(lPath, lMaxMB)
	if err != nil {
		log.Fatalf("Logger setup failed: %v", err)
	}

	// ── Config ───────────────────────────────────────────────────────────────
	cfg.ProxyPort = pPort
	cfg.UIPort    = uPort
	cfg.SetAuth(authU, authP)

	// ── Blocklist ────────────────────────────────────────────────────────────
	if blPath != "" {
		if err := bl.Load(blPath); err != nil {
			logger.Fatalf("Cannot load blocklist: %v", err)
		}
		logger.Printf("Blocklist loaded: %d entries from %s", bl.Count(), blPath)
	}

	// ── Web UI ───────────────────────────────────────────────────────────────
	go startUI(uPort)
	logger.Printf("Web UI  → http://localhost:%d", uPort)

	// ── Proxy server ─────────────────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
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

// handleHealth is a simple liveness probe used by load balancers and Docker.
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
