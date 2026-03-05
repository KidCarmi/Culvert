package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	port        = flag.Int("port", 8080, "Port to listen on")
	verbose     = flag.Bool("verbose", false, "Enable verbose logging")
	proxyUser   = flag.String("user", "", "Basic auth username (leave empty to disable auth)")
	proxyPass   = flag.String("pass", "", "Basic auth password")
	blockFile   = flag.String("blocklist", "", "Path to blocklist file (one host per line)")
	logFile     = flag.String("logfile", "", "Path to log file (leave empty for stdout only)")

	blocklist = map[string]bool{}
	logger    *log.Logger
)

func main() {
	flag.Parse()

	// Set up logger (stdout + optional file).
	writers := []io.Writer{os.Stdout}
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Cannot open log file: %v", err)
		}
		defer f.Close()
		writers = append(writers, f)
	}
	logger = log.New(io.MultiWriter(writers...), "", log.LstdFlags)

	// Load blocklist if provided.
	if *blockFile != "" {
		if err := loadBlocklist(*blockFile); err != nil {
			logger.Fatalf("Cannot load blocklist: %v", err)
		}
		logger.Printf("Loaded %d blocked hosts", len(blocklist))
	}

	addr := fmt.Sprintf(":%d", *port)
	logger.Printf("Starting HTTP/HTTPS proxy on %s", addr)
	if *proxyUser != "" {
		logger.Printf("Basic auth enabled (user: %s)", *proxyUser)
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      http.HandlerFunc(handleRequest),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}

func loadBlocklist(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		blocklist[strings.ToLower(line)] = true
	}
	return scanner.Err()
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Basic auth check.
	if *proxyUser != "" {
		user, pass, ok := parseProxyAuth(r)
		if !ok || user != *proxyUser || pass != *proxyPass {
			w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			logger.Printf("AUTH FAIL %s", clientIP)
			return
		}
	}

	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Blocklist check.
	if blocklist[strings.ToLower(host)] {
		http.Error(w, "Forbidden", http.StatusForbidden)
		logger.Printf("BLOCKED %s -> %s", clientIP, host)
		return
	}

	logger.Printf("%s %s %s %s", clientIP, r.Method, r.Host, r.URL)

	if r.Method == http.MethodConnect {
		handleTunnel(w, r)
	} else {
		handleHTTP(w, r)
	}
}

// parseProxyAuth decodes the Proxy-Authorization header.
func parseProxyAuth(r *http.Request) (string, string, bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// handleHTTP proxies plain HTTP requests.
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	removeHopHeaders(r.Header)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}

	r.RequestURI = ""
	resp, err := client.Do(r)
	if err != nil {
		http.Error(w, "Bad Gateway: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopHeaders(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleTunnel establishes a raw TCP tunnel for HTTPS (CONNECT method).
func handleTunnel(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "Bad Gateway: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		logger.Printf("Hijack error: %v", err)
		return
	}
	defer clientConn.Close()

	done := make(chan struct{}, 2)
	relay := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- struct{}{}
	}

	go relay(destConn, clientConn)
	go relay(clientConn, destConn)
	<-done
}

func removeHopHeaders(h http.Header) {
	for _, hdr := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailers",
		"Transfer-Encoding", "Upgrade",
	} {
		h.Del(hdr)
	}
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, v := range values {
			dst.Add(key, v)
		}
	}
}
