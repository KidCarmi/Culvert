package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

var (
	port    = flag.Int("port", 8080, "Port to listen on")
	verbose = flag.Bool("verbose", false, "Enable verbose logging")
)

func main() {
	flag.Parse()

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Starting HTTP/HTTPS proxy on %s", addr)

	server := &http.Server{
		Addr:         addr,
		Handler:      http.HandlerFunc(handleRequest),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	if *verbose {
		log.Printf("%s %s %s", r.Method, r.Host, r.URL)
	}

	if r.Method == http.MethodConnect {
		handleTunnel(w, r)
	} else {
		handleHTTP(w, r)
	}
}

// handleHTTP proxies plain HTTP requests.
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip hop-by-hop headers before forwarding.
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
		log.Printf("Hijack error: %v", err)
		return
	}
	defer clientConn.Close()

	// Relay data in both directions concurrently.
	done := make(chan struct{}, 2)
	relay := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- struct{}{}
	}

	go relay(destConn, clientConn)
	go relay(clientConn, destConn)
	<-done
}

// removeHopHeaders deletes hop-by-hop headers that must not be forwarded.
func removeHopHeaders(h http.Header) {
	hopHeaders := []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailers",
		"Transfer-Encoding", "Upgrade",
	}
	for _, hdr := range hopHeaders {
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

