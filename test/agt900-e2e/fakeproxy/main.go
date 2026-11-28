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
// inside the health gate deterministically. While /ctl/fail_ready_<version>
// exists, that version's /ready answers 503 (a target that passed its gate
// and fails it when the gate is run again; the other images are unaffected).
// `app -probe` is the container
// healthcheck of the root-mode compose file (the image has no shell).
//
// The sudoers mode runs the SHIPPED docker-compose.yml, whose healthchecks and
// profiles call other programs, so the same binary is multi-call (by the base
// name it is invoked as, or by a flag):
//
//	wget -qO- <url>       the proxy healthcheck: GET <url>, exit 0 on 2xx
//	clamdscan --ping <n>  the clamav stub's healthcheck: exit 0
//	app -idle             the clamav stub's daemon: wait for SIGTERM
//	app ... --list-backups ...
//	                      the `cli` profile's backup list (the agent's data
//	                      rollback preflight): print one fixed backup entry
//	app --print-data-epoch
//	                      the `cli` profile's data-epoch report (ADR-0062 slice
//	                      6a), read from /data/.data-epoch exactly as the real
//	                      binary reads it: absent is epoch 1, a marker this
//	                      build cannot read exits 1. build_max is the epochMax
//	                      the image was built with (its labels say the same).
//	app -set-data-epoch <content>
//	                      write <content> verbatim as /data/.data-epoch (empty:
//	                      remove it). The harness runs it with `docker exec` in
//	                      the proxy container: the marker a migrating image
//	                      would leave, or a malformed one.
//
// Any other argument list (the shipped proxy command's -port/-ui-port/... flags)
// is ignored and the server runs.
//
// The `ignore` build tag keeps this file out of the root module's
// go build / go vet; run.sh compiles it in a scratch module.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var (
	version  = "dev"
	ready    = "ok"
	epochMax = "1"
)

const dataEpochMarker = "/data/.data-epoch"

// printDataEpoch is `--print-data-epoch`: the one-line report the agent parses
// (internal/runner/data_epoch.go), strict like the real binary's.
func printDataEpoch() {
	epoch, present := 1, false
	if b, err := os.ReadFile(dataEpochMarker); err == nil {
		var m struct {
			Schema int `json:"schema"`
			Epoch  int `json:"epoch"`
		}
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&m); err != nil || m.Schema != 1 || m.Epoch < 1 {
			fmt.Fprintln(os.Stderr, "fakeproxy: unreadable data epoch marker")
			os.Exit(1)
		}
		epoch, present = m.Epoch, true
	} else if !os.IsNotExist(err) {
		os.Exit(1)
	}
	fmt.Printf("{\"schema\":1,\"epoch\":%d,\"marker_present\":%t,\"build_min\":1,\"build_max\":%s}\n", epoch, present, epochMax)
	os.Exit(0)
}

func readyHandler(w http.ResponseWriter, _ *http.Request) {
	if _, err := os.Stat("/ctl/hang_ready"); err == nil {
		_ = os.WriteFile("/ctl/ready_hit", []byte(version+"\n"), 0o644) // #nosec G306 -- test fixture
		time.Sleep(10 * time.Second)
	}
	if _, err := os.Stat("/ctl/fail_ready_" + version); err == nil || ready != "ok" {
		http.Error(w, "not ready ("+version+")", http.StatusServiceUnavailable)
		return
	}
	_, _ = fmt.Fprintln(w, "ready", version)
}

// get exits 0 when url answers 2xx within 2s, else 1.
func get(url string) {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		os.Exit(1)
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		os.Exit(1)
	}
	os.Exit(0)
}

// multiCall handles every invocation that is not the proxy server itself.
func multiCall() {
	args := os.Args[1:]
	switch filepath.Base(os.Args[0]) {
	case "wget": // wget -qO- <url>
		if len(args) > 0 {
			get(args[len(args)-1])
		}
		os.Exit(1)
	case "clamdscan": // clamdscan --ping <n>
		os.Exit(0)
	}
	if len(args) > 0 && args[0] == "-probe" {
		get("http://127.0.0.1:8080/health")
	}
	if len(args) > 0 && args[0] == "-idle" {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		<-ch
		os.Exit(0)
	}
	if len(args) > 0 && args[0] == "--print-data-epoch" {
		printDataEpoch()
	}
	if len(args) == 2 && args[0] == "-set-data-epoch" {
		if args[1] == "" {
			_ = os.Remove(dataEpochMarker)
			os.Exit(0)
		}
		if err := os.WriteFile(dataEpochMarker, []byte(args[1]), 0o644); err != nil { // #nosec G306 -- test fixture
			os.Exit(1)
		}
		os.Exit(0)
	}
	for _, a := range args {
		if a == "--list-backups" {
			fmt.Println(`[{"filename":"agt900-e2e.tar.gz","path":"/backup/agt900-e2e.tar.gz","size_bytes":1,"modified_at":"2026-11-23T00:00:00Z","encrypted":false}]`)
			os.Exit(0)
		}
	}
	for _, a := range args {
		if strings.HasPrefix(a, "--restore") || strings.HasPrefix(a, "--backup") || strings.HasPrefix(a, "--cleanup") {
			fmt.Fprintln(os.Stderr, "fakeproxy: the cli operations are not implemented")
			os.Exit(1)
		}
	}
}

func main() {
	multiCall()
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprintln(w, "ok", version) })
	http.HandleFunc("/ready", readyHandler)
	http.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprintln(w, version) })
	srv := &http.Server{Addr: ":8080", ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
