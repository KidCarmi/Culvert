package main

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

func handleRequest(w http.ResponseWriter, r *http.Request) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Basic auth check.
	if cfg.AuthEnabled() {
		user, pass := cfg.GetAuth()
		u, p, ok := parseProxyAuth(r)
		if !ok || u != user || p != pass {
			atomic.AddInt64(&statAuthFail, 1)
			w.Header().Set("Proxy-Authenticate", `Basic realm="ProxyShield"`)
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			recordRequest(clientIP, r.Method, r.Host, "AUTH_FAIL")
			logger.Printf("AUTH_FAIL %s", clientIP)
			return
		}
	}

	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Blocklist check.
	if bl.IsBlocked(host) {
		atomic.AddInt64(&statBlocked, 1)
		http.Error(w, "Forbidden by ProxyShield", http.StatusForbidden)
		recordRequest(clientIP, r.Method, r.Host, "BLOCKED")
		logger.Printf("BLOCKED %s -> %s", clientIP, host)
		return
	}

	recordRequest(clientIP, r.Method, r.Host, "OK")
	logger.Printf("OK %s %s %s", clientIP, r.Method, r.Host)

	if r.Method == http.MethodConnect {
		handleTunnel(w, r)
	} else {
		handleHTTP(w, r)
	}
}

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
	relay := func(dst, src net.Conn) { io.Copy(dst, src); done <- struct{}{} }
	go relay(destConn, clientConn)
	go relay(clientConn, destConn)
	<-done
}

func removeHopHeaders(h http.Header) {
	for _, hdr := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailers", "Transfer-Encoding", "Upgrade",
	} {
		h.Del(hdr)
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
