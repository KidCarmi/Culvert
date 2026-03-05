// ProxyShield - Enterprise-grade open source HTTP/HTTPS proxy
// https://github.com/KidCarmi/Claude-Test
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

var logger *log.Logger

func main() {
	proxyPort := flag.Int("port", 8080, "Proxy port")
	uiPortFlag := flag.Int("ui-port", 9090, "Web UI port")
	user := flag.String("user", "", "Basic auth username (empty = disabled)")
	pass := flag.String("pass", "", "Basic auth password")
	blockFile := flag.String("blocklist", "", "Path to blocklist file (one host/wildcard per line)")
	logFilePath := flag.String("logfile", "", "Log file path (stdout if empty)")
	flag.Parse()

	// Logger.
	writers := []io.Writer{os.Stdout}
	if *logFilePath != "" {
		f, err := os.OpenFile(*logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Cannot open log file: %v", err)
		}
		defer f.Close()
		writers = append(writers, f)
	}
	logger = log.New(io.MultiWriter(writers...), "[proxysheild] ", log.LstdFlags)

	// Config.
	cfg.ProxyPort = *proxyPort
	cfg.UIPort = *uiPortFlag
	cfg.SetAuth(*user, *pass)

	// Blocklist.
	if *blockFile != "" {
		if err := bl.Load(*blockFile); err != nil {
			logger.Fatalf("Cannot load blocklist: %v", err)
		}
		logger.Printf("Blocklist loaded: %d entries", bl.Count())
	}

	// Start Web UI.
	go startUI(*uiPortFlag)
	logger.Printf("Web UI  → http://localhost:%d", *uiPortFlag)

	// Start proxy.
	addr := fmt.Sprintf(":%d", *proxyPort)
	logger.Printf("Proxy   → http://localhost:%d", *proxyPort)
	if *user != "" {
		logger.Printf("Auth    → enabled (user: %s)", *user)
	}

	srv := &http.Server{
		Addr:         addr,
		Handler:      http.HandlerFunc(handleRequest),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		logger.Fatalf("Proxy error: %v", err)
	}
}
