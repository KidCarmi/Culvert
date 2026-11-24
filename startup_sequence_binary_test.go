//go:build proxybinload

package main

// startup_sequence_binary_test.go — the start-up order, validated on the REAL
// BINARY: each test starts the shipped executable for one cluster role against
// a temp data dir and loopback listeners, so the sequence under test is
// main()'s own (runStartupSequence), not a hand-ordered replay of its pieces.
//
// Same `proxybinload` convention as the other real-binary gates
// (proxy_restart_test.go, argv_positional_refusal_binary_chaos122_test.go):
//
//	go test -tags proxybinload -run 'TestBinaryStartup_' -v -timeout 10m .
//
// CULVERT_BIN=<path> runs them against a prebuilt binary — pointing it at a
// build of the previous order is the negative control (the control-plane and
// data-plane restart tests fail there).
//
// Not covered here, and why: HA leader resume in LEASE mode needs an etcd
// fencing backend, which this harness does not start; it is driven in-process
// with the in-memory lease backend by
// TestClusterHalves_ControlPlane_LeaseLeaderResumeCommitsItsEpoch.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ── harness ─────────────────────────────────────────────────────────────────

type suBinNode struct {
	t       *testing.T
	bin     string
	dataDir string
	logPath string
	args    []string
	cmd     *exec.Cmd
}

func suBinPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick a port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// suBinNewNode prepares a node: its data dir, its ports, and the flags every
// role shares. extra are the role's own flags.
func suBinNewNode(t *testing.T, bin string, extra ...string) (n *suBinNode, proxyPort int) {
	t.Helper()
	dir := t.TempDir()
	proxyPort = suBinPort(t)
	n = &suBinNode{t: t, bin: bin, dataDir: dir, logPath: filepath.Join(dir, "culvert.log")}
	n.args = append([]string{
		"-port", fmt.Sprint(proxyPort), "-ui-port", fmt.Sprint(suBinPort(t)), "-ui-no-tls",
		"-cluster-db", filepath.Join(dir, "cluster.json"), "-cluster-insecure",
	}, extra...)
	t.Cleanup(func() {
		n.stop()
		if t.Failed() {
			if b, err := os.ReadFile(n.logPath); err == nil {
				t.Logf("culvert log (%s):\n%s", n.logPath, suBinTail(string(b), 6000))
			}
		}
	})
	return n, proxyPort
}

func suBinTail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

func (n *suBinNode) start() {
	n.t.Helper()
	logFile, err := os.OpenFile(n.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		n.t.Fatalf("open log: %v", err)
	}
	n.cmd = exec.Command(n.bin, n.args...) //nolint:gosec // the binary under test
	n.cmd.Env = append(os.Environ(), "CULVERT_DATA_DIR="+n.dataDir)
	n.cmd.Stdout, n.cmd.Stderr = logFile, logFile
	if err := n.cmd.Start(); err != nil {
		_ = logFile.Close()
		n.t.Fatalf("start culvert: %v", err)
	}
	_ = logFile.Close() // the child holds its own descriptor
}

func (n *suBinNode) stop() {
	if n.cmd == nil || n.cmd.Process == nil {
		return
	}
	_ = n.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = n.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = n.cmd.Process.Kill()
		<-done
	}
	n.cmd = nil
}

func (n *suBinNode) log() string {
	b, _ := os.ReadFile(n.logPath)
	return string(b)
}

// waitLog waits for a line containing want.
func (n *suBinNode) waitLog(want string, d time.Duration) {
	n.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(n.log(), want) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	n.t.Fatalf("the log never showed %q within %s", want, d)
}

// wantLogOrder requires each marker to appear, in this order.
func (n *suBinNode) wantLogOrder(markers ...string) {
	n.t.Helper()
	log, at := n.log(), 0
	for _, m := range markers {
		i := strings.Index(log[at:], m)
		if i < 0 {
			if strings.Contains(log, m) {
				n.t.Errorf("start-up order: %q was logged BEFORE the preceding marker (want order %q)", m, markers)
			} else {
				n.t.Errorf("start-up order: %q was never logged", m)
			}
			return
		}
		at += i + len(m)
	}
}

// suBinGet fetches target through the node's proxy: the status code, or 0 when
// the connection was refused/dropped.
func suBinGet(proxyPort int, target string) int {
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", proxyPort)})},
		Timeout:   3 * time.Second,
	}
	resp, err := client.Get(target) //nolint:noctx // bounded by the client timeout
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// suBinWaitProxy waits until the node's proxy listener accepts connections —
// the LAST step of the start-up sequence.
func suBinWaitProxy(t *testing.T, proxyPort int) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), time.Second)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the proxy listener on :%d never came up", proxyPort)
}

func suBinWrite(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func suBinUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(up.Close)
	return up
}

// suBinPoller polls a control plane's GetConfig over real gRPC, as a data
// plane with no version would, from BEFORE the control plane starts. It keeps
// every reply, so "what was the first thing a poller was ever served" and
// "was anything else ever served" are both answerable.
type suBinPoller struct {
	mu      sync.Mutex
	replies []ConfigSnapshot
	refused int
	stop    context.CancelFunc
	done    chan struct{}
}

func suBinStartPoller(t *testing.T, addr string) *suBinPoller {
	t.Helper()
	prev := clusterInsecure
	clusterInsecure = true // this test process is the "data plane" on a loopback, certificate-less link
	c, err := NewDataPlaneClient("first-poller", addr, "", "", "")
	if err != nil {
		clusterInsecure = prev
		t.Fatalf("poller client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &suBinPoller{stop: cancel, done: make(chan struct{})}
	go func() {
		defer close(p.done)
		for ctx.Err() == nil {
			callCtx, callCancel := context.WithTimeout(ctx, 2*time.Second)
			raw, err := c.call(callCtx, methodGetConfig, json.RawMessage(`{}`))
			callCancel()
			p.mu.Lock()
			if err != nil {
				p.refused++
			} else {
				var snap ConfigSnapshot
				if json.Unmarshal(raw, &snap) == nil {
					p.replies = append(p.replies, snap)
				}
			}
			p.mu.Unlock()
			time.Sleep(20 * time.Millisecond)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-p.done
		c.mu.Lock()
		if c.conn != nil {
			_ = c.conn.Close()
		}
		c.mu.Unlock()
		clusterInsecure = prev
	})
	return p
}

func (p *suBinPoller) snapshot() (replies []ConfigSnapshot, refused int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]ConfigSnapshot(nil), p.replies...), p.refused
}

func (p *suBinPoller) waitReplies(t *testing.T, more int, d time.Duration) []ConfigSnapshot {
	t.Helper()
	start, _ := p.snapshot()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if r, _ := p.snapshot(); len(r) >= len(start)+more {
			return r
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the control plane never answered %d more poll(s) within %s", more, d)
	return nil
}

const suBinPolicy = `[{"priority":1,"name":"cp-rule-a","destFQDN":"a.example.com","action":"Allow"},` +
	`{"priority":2,"name":"cp-rule-b","destFQDN":"b.example.com","action":"Drop"}]`

func suBinWantLoaded(t *testing.T, when string, replies []ConfigSnapshot) {
	t.Helper()
	for i := range replies {
		s := &replies[i]
		names := make([]string, 0, len(s.PolicyRules))
		for j := range s.PolicyRules {
			names = append(names, s.PolicyRules[j].Name)
		}
		if strings.Join(names, ",") != "cp-rule-a,cp-rule-b" || len(s.BlockedHosts) != 1 || s.DefaultAction != "allow" {
			t.Fatalf("%s: reply #%d (v%d) served rules=%v blocked_hosts=%v default_action=%q — a poller must only ever be "+
				"served the control plane's LOADED configuration (2 rules, 1 blocked host, allow)",
				when, i+1, s.Version, names, s.BlockedHosts, s.DefaultAction)
		}
	}
}

// ── control plane ───────────────────────────────────────────────────────────

// TestBinaryStartup_ControlPlane_PollerOnlyEverSeesLoadedConfig starts a real
// control plane with a policy file, a blocklist and a configured default
// action, while a poller hammers its gRPC address from before the process
// exists. Before the listener binds the poller is refused; from the first
// reply on it is served the loaded configuration — never the empty blocklist,
// zero rules and default deny the old order published before its stores
// loaded. Then the control plane RESTARTS on the same data directory (the
// upgrade case: existing policy file, cluster DB, cluster CA and config
// version floor) with the poller still running: refused again, then loaded
// configuration again, at a strictly higher version.
func TestBinaryStartup_ControlPlane_PollerOnlyEverSeesLoadedConfig(t *testing.T) {
	bin := buildOrFindBinary(t)
	grpcAddr := fmt.Sprintf("127.0.0.1:%d", suBinPort(t))
	cfgDir := t.TempDir()
	n, proxyPort := suBinNewNode(t, bin,
		"-cp-grpc-addr", grpcAddr,
		"-policy", suBinWrite(t, filepath.Join(cfgDir, "policy.json"), suBinPolicy),
		"-blocklist", suBinWrite(t, filepath.Join(cfgDir, "blocklist.txt"), "blocked-by-cp.example\n"),
		"-config", suBinWrite(t, filepath.Join(cfgDir, "config.yaml"), "default_action: allow\n"),
	)
	poller := suBinStartPoller(t, grpcAddr)

	n.start()
	first := poller.waitReplies(t, 3, 90*time.Second)
	suBinWaitProxy(t, proxyPort)
	_, refused := poller.snapshot()
	if refused == 0 {
		t.Error("control: the poller was never refused, so it was not polling before the listener bound")
	}
	suBinWantLoaded(t, "first start", first)
	n.wantLogOrder("Blocklist loaded: 1 entries", "Policy: 2 rule(s) loaded", "Policy: default action: allow",
		"ControlPlane: config v", "ControlPlane: enabled (gRPC")
	firstVersion := first[len(first)-1].Version

	// Restart on the same data directory, the poller still polling.
	n.stop()
	before, refusedBefore := poller.snapshot()
	n.start()
	all := poller.waitReplies(t, 3, 90*time.Second)
	suBinWaitProxy(t, proxyPort)
	after := all[len(before):]
	if _, refusedAfter := poller.snapshot(); refusedAfter == refusedBefore {
		t.Error("control: the poller was never refused across the restart")
	}
	suBinWantLoaded(t, "after restart", after)
	if after[0].Version <= firstVersion {
		t.Errorf("the restarted control plane serves v%d, not above the v%d it served before the restart", after[0].Version, firstVersion)
	}
	for _, f := range []string{"cluster-ca.crt", "cp_config_version.json"} {
		if matches, _ := filepath.Glob(filepath.Join(n.dataDir, "*", f)); len(matches) == 0 {
			if _, err := os.Stat(filepath.Join(n.dataDir, f)); err != nil {
				t.Logf("note: %s not found directly under the data dir (layout-dependent)", f)
			}
		}
	}
}

// ── data plane ──────────────────────────────────────────────────────────────

func suBinLastGood(t *testing.T, dataDir string, snap ConfigSnapshot) {
	t.Helper()
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	suBinWrite(t, filepath.Join(dataDir, dpLastGoodConfigSnapshotFile), string(raw))
}

// TestBinaryStartup_DataPlane_RestartKeepsControlPlaneState starts a real data
// plane whose control plane is unreachable, on a data directory holding a
// last-good snapshot (v7: default action ALLOW, one rule dropping "localhost")
// and a STALE policy file (one unrelated rule). With traffic through its real
// proxy listener:
//
//   - a host no rule matches is ALLOWED — the control plane's default action,
//     not the "rules exist ⇒ deny" boot derivation that used to overwrite it;
//   - the last-good rule is enforced, and the policy file on disk now holds
//     it — the newer last-good won over the stale file, durably.
//
// The log shows the order the real sequence ran them in.
func TestBinaryStartup_DataPlane_RestartKeepsControlPlaneState(t *testing.T) {
	bin := buildOrFindBinary(t)
	up := suBinUpstream(t)
	upPort := strings.TrimPrefix(up.URL, "http://127.0.0.1:")
	deadCP := fmt.Sprintf("127.0.0.1:%d", suBinPort(t))
	cfgDir := t.TempDir()
	policyPath := suBinWrite(t, filepath.Join(cfgDir, "policy.json"),
		`[{"priority":1,"name":"stale-rule","destFQDN":"stale.example.com","action":"Allow"}]`)
	socksPort := suBinPort(t)
	n, proxyPort := suBinNewNode(t, bin, "-dp-cp-addr", deadCP, "-dp-node-id", "dp-under-test",
		"-policy", policyPath, "-socks5-port", fmt.Sprint(socksPort))
	suBinLastGood(t, n.dataDir, ConfigSnapshot{
		Version: 7, DefaultAction: "allow",
		PolicyRules: []PolicyRule{{Priority: 1, Name: "from-control-plane", DestFQDN: "localhost", Action: ActionDrop}},
	})

	n.start()
	suBinWaitProxy(t, proxyPort)

	if code := suBinGet(proxyPort, "http://127.0.0.1:"+upPort+"/"); code != http.StatusOK {
		t.Errorf("a host no rule matches answered %d through the restarted data plane, want 200: the control plane's "+
			"default action (allow) must survive the restart, not be re-derived to deny", code)
	}
	if code := suBinGet(proxyPort, "http://localhost:"+upPort+"/"); code == http.StatusOK {
		t.Error("the last-good snapshot's Drop rule for localhost is not enforced after the restart")
	}
	onDisk, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(onDisk), "from-control-plane") || strings.Contains(string(onDisk), "stale-rule") {
		t.Errorf("the policy file was not rewritten with the last-good snapshot's rules:\n%s", onDisk)
	}
	n.wantLogOrder("Policy: 1 rule(s) loaded", "Policy: default action: deny",
		"DataPlane: applied last-known-good config snapshot v7")
	// The SOCKS5 listener is open for business (its gate was released), and it
	// was released after the replay — the release is the step after it.
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 2*time.Second)
	if err != nil {
		t.Fatalf("SOCKS5 listener: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte{0x05, 0x01, 0x00}) // greeting: no-auth
	reply := make([]byte, 2)
	if _, err := c.Read(reply); err != nil || reply[0] != 0x05 {
		t.Errorf("the SOCKS5 listener does not serve after start-up (gate never released?): %v %v", reply, err)
	}
	_ = c.Close()
}

// TestBinaryStartup_DataPlane_FirstEnrolmentNoLastGood: a data plane with no
// last-good snapshot starts, serves on its own file policy, and says so.
func TestBinaryStartup_DataPlane_FirstEnrolmentNoLastGood(t *testing.T) {
	bin := buildOrFindBinary(t)
	up := suBinUpstream(t)
	cfgDir := t.TempDir()
	n, proxyPort := suBinNewNode(t, bin, "-dp-cp-addr", fmt.Sprintf("127.0.0.1:%d", suBinPort(t)), "-dp-node-id", "dp-new",
		"-policy", suBinWrite(t, filepath.Join(cfgDir, "policy.json"), `[{"priority":1,"name":"allow-all","destFQDN":"*","action":"Allow"}]`))
	n.start()
	suBinWaitProxy(t, proxyPort)
	if code := suBinGet(proxyPort, up.URL+"/"); code != http.StatusOK {
		t.Errorf("a first-enrolment data plane answered %d on its own allow-all policy, want 200", code)
	}
	n.wantLogOrder("Policy: 1 rule(s) loaded", "DataPlane: no last-known-good config", "DataPlane: polling ControlPlane")
}

// ── the other roles ─────────────────────────────────────────────────────────

// TestBinaryStartup_Standalone: no cluster wiring — the sequence runs to the
// proxy listener and forwards.
func TestBinaryStartup_Standalone(t *testing.T) {
	bin := buildOrFindBinary(t)
	up := suBinUpstream(t)
	cfgDir := t.TempDir()
	n, proxyPort := suBinNewNode(t, bin,
		"-policy", suBinWrite(t, filepath.Join(cfgDir, "policy.json"), `[{"priority":1,"name":"allow-all","destFQDN":"*","action":"Allow"}]`))
	n.start()
	suBinWaitProxy(t, proxyPort)
	if code := suBinGet(proxyPort, up.URL+"/"); code != http.StatusOK {
		t.Errorf("standalone node answered %d, want 200", code)
	}
	if log := n.log(); strings.Contains(log, "ControlPlane: config v") || strings.Contains(log, "DataPlane: polling") {
		t.Error("a standalone node activated a cluster role")
	}
}

// TestBinaryStartup_BothWired_ControlPlaneWinsTheRole: wired as a control plane
// AND a data plane. The control plane activates, the data plane is refused,
// and the node serves.
func TestBinaryStartup_BothWired_ControlPlaneWinsTheRole(t *testing.T) {
	bin := buildOrFindBinary(t)
	grpcAddr := fmt.Sprintf("127.0.0.1:%d", suBinPort(t))
	n, proxyPort := suBinNewNode(t, bin, "-cp-grpc-addr", grpcAddr,
		"-dp-cp-addr", fmt.Sprintf("127.0.0.1:%d", suBinPort(t)), "-dp-node-id", "dp")
	n.start()
	suBinWaitProxy(t, proxyPort)
	n.wantLogOrder("ControlPlane: enabled (gRPC", "DataPlane: NOT starting the Data Plane client")
}

// TestBinaryStartup_HAStandby_JoinsAfterItsStoresLoad: a standby whose leader
// is unreachable. It must start (the join is retried, not fatal), serve its
// proxy, and enter standby only after its own stores loaded.
func TestBinaryStartup_HAStandby_JoinsAfterItsStoresLoad(t *testing.T) {
	bin := buildOrFindBinary(t)
	cfgDir := t.TempDir()
	n, proxyPort := suBinNewNode(t, bin,
		"-cp-grpc-addr", fmt.Sprintf("127.0.0.1:%d", suBinPort(t)),
		"-ha-join", fmt.Sprintf("127.0.0.1:%d", suBinPort(t)), "-ha-token", "standby-test-token-0123456789",
		"-policy", suBinWrite(t, filepath.Join(cfgDir, "policy.json"), suBinPolicy))
	n.start()
	suBinWaitProxy(t, proxyPort)
	n.waitLog("HA:", 30*time.Second)
	n.wantLogOrder("Policy: 2 rule(s) loaded", "HA:")
	if strings.Contains(n.log(), "ControlPlane: config v") {
		t.Error("a standby published a configuration snapshot at boot")
	}
}
