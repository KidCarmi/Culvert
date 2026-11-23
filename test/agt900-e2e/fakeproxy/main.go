//go:build ignore

// Fake Culvert proxy for the AGT-900 real-Docker e2e (test/agt900-e2e/run.sh).
// It serves only what the maintenance agent probes: GET /health and GET /ready
// on :8080. run.sh builds it FROM scratch in three variants with
// -ldflags "-X main.version=<v> -X main.ready=<ok|fail>":
//
//	prior  (ready=ok)   the image running before the upgrade
//	good   (ready=ok)   a target that passes the agent's health gate
//	bad    (ready=fail) a target whose /ready always answers 503, so the gate fails
//
// The compose file bind-mounts a harness-owned directory at /ctl. While
// /ctl/hang_ready exists, /ready writes /ctl/ready_hit and then stalls longer
// than the agent's per-request timeout: that is how the harness lands a kill
// inside the health gate deterministically. `app -probe` is the container
// healthcheck (the image has no shell or wget).
//
// The `ignore` build tag keeps this file out of the root module's
// go build / go vet; run.sh compiles it in a scratch module.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

var (
	version = "dev"
	ready   = "ok"
)

func readyHandler(w http.ResponseWriter, _ *http.Request) {
	if _, err := os.Stat("/ctl/hang_ready"); err == nil {
		_ = os.WriteFile("/ctl/ready_hit", []byte(version+"\n"), 0o644) // #nosec G306 -- test fixture
		time.Sleep(10 * time.Second)
	}
	if ready != "ok" {
		http.Error(w, "not ready ("+version+")", http.StatusServiceUnavailable)
		return
	}
	_, _ = fmt.Fprintln(w, "ready", version)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-probe" {
		c := &http.Client{Timeout: 2 * time.Second}
		resp, err := c.Get("http://127.0.0.1:8080/health")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		_ = resp.Body.Close()
		return
	}
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprintln(w, "ok", version) })
	http.HandleFunc("/ready", readyHandler)
	http.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprintln(w, version) })
	srv := &http.Server{Addr: ":8080", ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
