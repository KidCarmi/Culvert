//go:build agt900_e2e

package main

// agt900_realdocker_e2e_test.go — the opt-in startup reconcile
// (reconcile_on_startup = "converge", contract AGT-900) against a REAL Docker
// daemon. Driven by test/agt900-e2e/run.sh, which builds a TLS registry, three
// FROM-scratch proxy images (prior / good / bad, the last one never ready) and
// a private dockerd per image store, then runs this test once per store. It is
// behind the agt900_e2e build tag: no plain go build / vet / test compiles it.
//
// It mirrors the kill points of startup_crash_recovery_test.go and
// startup_reconcile_converge_test.go, but nothing is modelled: the agent's
// `docker` is a pass-through shim in front of the real CLI. The shim records
// every invocation and can hold one at a named point ("<cmd>_before:<n>" or
// "<cmd>_after:<n>", counted per agent process), which is how a SIGKILL lands
// at a known place deterministically. The kill inside the health gate stalls
// the fake proxy's /ready instead. The only kill point that has no Docker call
// to hold on to is the window between the journal's `verified` write and the
// record's retirement; it is hit by polling the journal and SIGKILLing on
// sight (retried), and reported as such.
//
// Every converge case is checked twice: against the expectation of the
// fake-Docker suite for the same kill point, and against the AGT-900
// invariants evaluated on real Docker state (`docker inspect` of the
// container, the image id the fixed tag resolves to, /ready).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	e2eProject  = "agt900"
	e2ePinned   = "culvert/proxy:pinned"
	e2eReconcTO = 4 * time.Minute
)

// e2eEnv is one store's run, from run.sh.
type e2eEnv struct {
	store, host, realDocker, repo, ca, proj, port string
	dockerdStart, dockerdStop, agentBin, results  string
	logs                                          string
	dig                                           map[string]string // role -> bare manifest digest
	id                                            map[string]string // role -> local image id (bare hex)
	only                                          *regexp.Regexp
}

func loadE2EEnv(t *testing.T) *e2eEnv {
	t.Helper()
	if os.Getenv("AGT900_E2E") != "1" {
		t.Skip("run through test/agt900-e2e/run.sh")
	}
	e := &e2eEnv{
		store: os.Getenv("AGT900_STORE"), host: os.Getenv("AGT900_DOCKER_HOST"),
		realDocker: os.Getenv("AGT900_REAL_DOCKER"), repo: os.Getenv("AGT900_REPO"),
		ca: os.Getenv("AGT900_CA"), proj: os.Getenv("AGT900_PROJECT"), port: os.Getenv("AGT900_PROXY_PORT"),
		dockerdStart: os.Getenv("AGT900_DOCKERD_START"), dockerdStop: os.Getenv("AGT900_DOCKERD_STOP"),
		agentBin: os.Getenv("AGT900_AGENT_BIN"), results: os.Getenv("AGT900_RESULTS"), logs: os.Getenv("AGT900_LOGS"),
		dig: map[string]string{
			"prior": os.Getenv("AGT900_DIGEST_PRIOR"), "good": os.Getenv("AGT900_DIGEST_GOOD"), "bad": os.Getenv("AGT900_DIGEST_BAD"),
		},
		id: map[string]string{},
	}
	for k, v := range map[string]string{"AGT900_STORE": e.store, "AGT900_DOCKER_HOST": e.host, "AGT900_REAL_DOCKER": e.realDocker,
		"AGT900_REPO": e.repo, "AGT900_PROJECT": e.proj, "AGT900_PROXY_PORT": e.port, "AGT900_RESULTS": e.results} {
		if v == "" {
			t.Fatalf("%s is not set", k)
		}
	}
	if e.agentBin == "" {
		e.agentBin = agentBinary(t)
	}
	if c := os.Getenv("AGT900_CASES"); c != "" {
		e.only = regexp.MustCompile(c)
	}
	tmpl, err := os.ReadFile(os.Getenv("AGT900_COMPOSE_TEMPLATE"))
	if err != nil {
		t.Fatalf("compose template: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(e.proj, "ctl"), 0o755); err != nil {
		t.Fatal(err)
	}
	compose := strings.ReplaceAll(string(tmpl), "@@PROXY_PORT@@", e.port)
	if err := os.WriteFile(e.composeFile(), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	// Local image id of each role, as the daemon reports it (classic store: the
	// config digest; containerd store: the registry index digest).
	for _, role := range []string{"prior", "good", "bad"} {
		if _, err := e.docker("pull", "-q", e.ref(role)); err != nil {
			t.Fatalf("pull %s: %v", role, err)
		}
		out, err := e.docker("image", "inspect", "--format", "{{.Id}}", e.ref(role))
		if err != nil {
			t.Fatalf("inspect %s: %v", role, err)
		}
		e.id[role] = e2eNormID(strings.TrimSpace(out))
	}
	t.Logf("agt900 store=%s repo=%s ids prior=%.12s good=%.12s bad=%.12s", e.store, e.repo, e.id["prior"], e.id["good"], e.id["bad"])
	return e
}

func (e *e2eEnv) composeFile() string    { return filepath.Join(e.proj, "docker-compose.yml") }
func (e *e2eEnv) ref(role string) string { return e.repo + "@sha256:" + e.dig[role] }
func (e *e2eEnv) ctlFile(n string) string {
	return filepath.Join(e.proj, "ctl", n)
}

// docker runs the REAL docker CLI against the store's daemon (never the shim).
func (e *e2eEnv) docker(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.realDocker, args...)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "DOCKER_HOST=" + e.host}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return string(out), fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

func (e *e2eEnv) daemon(script string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", filepath.Base(script), err, out)
	}
	return nil
}

// ready reports whether the published proxy answers /ready with 2xx now.
func (e *e2eEnv) ready() bool {
	c := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: nil}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:"+e.port+"/ready", http.NoBody)
	if err != nil {
		return false
	}
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// reset puts Docker in the pre-upgrade state: the proxy runs the prior image
// under the fixed tag, the target images are not local (the upgrade pulls).
func (e *e2eEnv) reset() error {
	_, _ = e.docker("compose", "-f", e.composeFile(), "down", "--remove-orphans")
	for _, f := range []string{"hang_ready", "ready_hit"} {
		_ = os.Remove(e.ctlFile(f))
	}
	if _, err := e.docker("image", "inspect", e.ref("prior")); err != nil {
		if _, err := e.docker("pull", "-q", e.ref("prior")); err != nil {
			return err
		}
	}
	if _, err := e.docker("tag", e.ref("prior"), e2ePinned); err != nil {
		return err
	}
	for _, role := range []string{"good", "bad"} {
		_, _ = e.docker("image", "rm", e.ref(role))
		if _, err := e.docker("image", "inspect", e.ref(role)); err == nil {
			return fmt.Errorf("could not remove the %s image", role)
		}
	}
	if _, err := e.docker("compose", "-f", e.composeFile(), "up", "-d"); err != nil {
		return err
	}
	return e.waitReady(60 * time.Second)
}

func (e *e2eEnv) waitReady(d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if e.ready() {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("the proxy did not answer /ready")
}

// dockerSnap is what real Docker says about the proxy and the fixed tag.
type dockerSnap struct {
	ContainerID string // full id, "" = no proxy container
	Image       string // bare image id the container runs
	Status      string // .State.Status
	Tag         string // bare image id culvert/proxy:pinned resolves to
	Ready       bool
	Err         string
}

func (e *e2eEnv) snap() dockerSnap {
	var s dockerSnap
	out, err := e.docker("ps", "-aq", "--no-trunc", "--filter", "label=com.docker.compose.project="+e2eProject,
		"--filter", "label=com.docker.compose.service=proxy")
	if err != nil {
		s.Err = err.Error()
		return s
	}
	if ids := strings.Fields(out); len(ids) > 0 {
		if len(ids) > 1 {
			s.Err = fmt.Sprintf("%d proxy containers", len(ids))
		}
		out, err = e.docker("inspect", "--format", "{{.Id}}|{{.Image}}|{{.State.Status}}", ids[0])
		if err != nil {
			s.Err = err.Error()
			return s
		}
		f := strings.Split(strings.TrimSpace(out), "|")
		if len(f) == 3 {
			s.ContainerID, s.Image, s.Status = f[0], e2eNormID(f[1]), f[2]
		}
	}
	if out, err = e.docker("image", "inspect", "--format", "{{.Id}}", e2ePinned); err == nil {
		s.Tag = e2eNormID(strings.TrimSpace(out))
	}
	if s.Status == "running" {
		s.Ready = e.ready()
	}
	return s
}

// class names an image id: prior / good / bad / none / other.
func (e *e2eEnv) class(id string) string {
	if id == "" {
		return "none"
	}
	for _, role := range []string{"prior", "good", "bad"} {
		if id == e.id[role] {
			return role
		}
	}
	return "other:" + id[:min(12, len(id))]
}

func (e *e2eEnv) describe(s dockerSnap) string {
	r := ""
	if s.Ready {
		r = ",ready"
	}
	return fmt.Sprintf("tag=%s run=%s(%s%s)", e.class(s.Tag), e.class(s.Image), s.Status, r)
}

// ── the agent ────────────────────────────────────────────────────────────────

// lockedBuffer is a bytes.Buffer safe for the exec copier and a reader.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// e2eShim is the agent's `docker`: log, optionally hold, then the real CLI.
const e2eShim = `#!/bin/sh
# Pass-through docker for the AGT-900 real-Docker e2e. Every argv is logged; a
# call can be held at "<key>_before:<n>" or "<key>_after:<n>" (key = the compose
# subcommand, else the docker subcommand; n counts per agent process) until the
# harness kills the agent or releases it. The real CLI talks to the store's
# private daemon and trusts the e2e registry's certificate.
C='__CTL__'
echo "$*" >> "$C/calls.log"
DOCKER_HOST='__HOST__'; export DOCKER_HOST
SSL_CERT_FILE='__CA__'; export SSL_CERT_FILE
if [ "$1" = compose ]; then k="$4"; else k="$1"; fi
blk() {
  n=$(cat "$C/count.$1" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$C/count.$1"
  if [ -f "$C/block_on" ] && [ "$(cat "$C/block_on")" = "$1:$n" ]; then
    echo $$ > "$C/blocked.tmp"; mv "$C/blocked.tmp" "$C/blocked"
    i=0
    while [ ! -f "$C/release" ] && [ $i -lt 12000 ]; do sleep 0.05; i=$((i+1)); done
    rm -f "$C/release" "$C/blocked" "$C/block_on"
  fi
}
blk "${k}_before"
'__REAL__' "$@"
rc=$?
blk "${k}_after"
exit $rc
`

// agentProc is one running agent process with its own shim.
type agentProc struct {
	cmd    *exec.Cmd
	logs   *lockedBuffer
	sock   string
	ctl    string
	client *http.Client
}

// e2eRig is one case: a state_dir and at most two agent processes.
type e2eRig struct {
	t     *testing.T
	e     *e2eEnv
	name  string
	dir   string
	state string
	a     *agentProc
	alive []*agentProc
	seq   int
	res   *e2eResult         // where jcheck reports
	hist  map[string]e2eHist // journal fields last seen, per record
}

func newE2ERig(t *testing.T, e *e2eEnv, name string) *e2eRig {
	t.Helper()
	dir, err := os.MkdirTemp("", "a9-")
	if err != nil {
		t.Fatal(err)
	}
	r := &e2eRig{t: t, e: e, name: name, dir: dir, state: filepath.Join(dir, "state"), hist: map[string]e2eHist{}}
	t.Cleanup(func() {
		for _, p := range r.alive {
			r.killProc(p)
		}
		_ = os.RemoveAll(dir)
	})
	return r
}

// newProc prepares (not starts) an agent process with its own socket, shim
// and config. mode is "converge" or "off".
func (r *e2eRig) newProc(tag, mode, stageTimeout string) *agentProc {
	r.t.Helper()
	p := &agentProc{sock: filepath.Join(r.dir, tag+".sock"), ctl: filepath.Join(r.dir, "ctl-"+tag)}
	bin := filepath.Join(r.dir, "bin-"+tag)
	for _, d := range []string{p.ctl, bin} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			r.t.Fatal(err)
		}
	}
	shim := strings.NewReplacer("__CTL__", p.ctl, "__HOST__", r.e.host, "__CA__", r.e.ca, "__REAL__", r.e.realDocker).Replace(e2eShim)
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(shim), 0o700); err != nil { // #nosec G306 -- must be executable
		r.t.Fatal(err)
	}
	cfg := fmt.Sprintf(`compose_project_dir = %q
compose_file = "docker-compose.yml"
socket_path = %q
state_dir = %q
privilege_mode = "docker_group_lab"
health_base_url = "http://127.0.0.1:%s"
operation_timeout = "15m"
stage_timeout = %q
allowed_backup_dir = "/backup"
image_allowlist = '^%s(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$'
proxy_repo = %q
allow_peers = [%q]
`, r.e.proj, p.sock, r.state, r.e.port, stageTimeout, regexp.QuoteMeta(r.e.repo), r.e.repo, strconv.Itoa(os.Geteuid()))
	if mode == "converge" {
		cfg += "reconcile_on_startup = \"converge\"\n"
	}
	cfgPath := filepath.Join(r.dir, tag+".toml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		r.t.Fatal(err)
	}
	p.cmd = exec.CommandContext(context.Background(), r.e.agentBin, "--config", cfgPath) // #nosec G204 -- harness-built binary and config
	p.cmd.Env = []string{"PATH=" + bin + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C.UTF-8"}
	p.logs = &lockedBuffer{}
	p.cmd.Stdout, p.cmd.Stderr = p.logs, p.logs
	p.client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", p.sock)
		}}}
	return p
}

// start launches p and waits until it serves.
func (r *e2eRig) startProc(p *agentProc) {
	r.t.Helper()
	ents, _ := os.ReadDir(p.ctl)
	for _, en := range ents { // counts are per agent process
		if strings.HasPrefix(en.Name(), "count.") {
			_ = os.Remove(filepath.Join(p.ctl, en.Name()))
		}
	}
	if err := p.cmd.Start(); err != nil {
		r.t.Fatalf("start agent: %v", err)
	}
	r.alive = append(r.alive, p)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if code, _ := p.get("/v1/health", nil); code == http.StatusOK {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	r.t.Fatalf("agent did not serve; output:\n%s", p.logs.String())
}

// start replaces the rig's main agent with a fresh process.
func (r *e2eRig) start(mode, stageTimeout string) *agentProc {
	r.t.Helper()
	r.seq++ // a fresh socket, shim and call log per process
	p := r.newProc(fmt.Sprintf("a%d", r.seq), mode, stageTimeout)
	r.startProc(p)
	r.a = p
	return p
}

// killProc is the crash: SIGKILL, plus the shim the agent was held in (the
// kernel reparents it rather than killing it).
func (r *e2eRig) killProc(p *agentProc) {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGKILL)
	_, _ = p.cmd.Process.Wait()
	if b, err := os.ReadFile(filepath.Join(p.ctl, "blocked")); err == nil { // #nosec G304 -- harness-owned dir
		if pid, perr := strconv.Atoi(strings.TrimSpace(string(b))); perr == nil && pid > 1 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	for _, f := range []string{"blocked", "block_on", "release"} {
		_ = os.Remove(filepath.Join(p.ctl, f))
	}
	for i, q := range r.alive {
		if q == p {
			r.alive = append(r.alive[:i], r.alive[i+1:]...)
			break
		}
	}
	if r.e.logs != "" {
		_ = os.WriteFile(filepath.Join(r.e.logs, fmt.Sprintf("%s-%s-%s.log", strings.NewReplacer("/", "_", ":", "_").Replace(r.e.store), r.name, filepath.Base(p.sock))),
			[]byte(p.logs.String()+"\n--- calls ---\n"+readFile(filepath.Join(p.ctl, "calls.log"))), 0o600)
	}
}

func readFile(p string) string {
	b, err := os.ReadFile(p) // #nosec G304 -- harness-owned paths
	if err != nil {
		return ""
	}
	return string(b)
}

func (p *agentProc) get(path string, out interface{}) (int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://agent"+path, http.NoBody)
	if err != nil {
		return 0, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil {
		if derr := json.NewDecoder(resp.Body).Decode(out); derr != nil {
			return resp.StatusCode, derr
		}
	}
	return resp.StatusCode, nil
}

func (p *agentProc) post(path string, body map[string]interface{}, out interface{}) (int, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://agent"+path, bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}

func (p *agentProc) calls() []string {
	var out []string
	for _, l := range strings.Split(readFile(filepath.Join(p.ctl, "calls.log")), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// mutating renders every state-changing docker call p issued: anything that is
// not compose ps, (container) inspect, image inspect or manifest inspect.
// Tags and pulls are named by the role of their source reference.
func (r *e2eRig) mutating(p *agentProc) []string {
	out := []string{}
	for _, l := range p.calls() {
		f := strings.Fields(l)
		switch {
		case len(f) > 3 && f[0] == "compose" && f[3] == "ps":
		case f[0] == "inspect":
		case len(f) > 1 && (f[0] == "image" || f[0] == "manifest") && f[1] == "inspect":
		case len(f) == 3 && f[0] == "tag" && f[2] == e2ePinned:
			out = append(out, "tag:"+r.roleOfRef(f[1]))
		case len(f) == 2 && f[0] == "pull":
			out = append(out, "pull:"+r.roleOfRef(f[1]))
		case len(f) > 3 && f[0] == "compose":
			out = append(out, f[3])
		default:
			out = append(out, l)
		}
	}
	return out
}

func (r *e2eRig) roleOfRef(ref string) string {
	for _, role := range []string{"prior", "good", "bad"} {
		if ref == r.e.ref(role) {
			return role
		}
	}
	return ref
}

func (r *e2eRig) apply(p *agentProc, role string) (string, error) {
	var op opView
	code, err := p.post("/v1/upgrades/apply", map[string]interface{}{"image_ref": r.e.ref(role)}, &op)
	if err != nil || code != http.StatusAccepted {
		return "", fmt.Errorf("apply: HTTP %d %v", code, err)
	}
	return op.OpID, nil
}

func (r *e2eRig) recordPath(opID string) string {
	return filepath.Join(r.state, "reconcile", opID+".json")
}

func (r *e2eRig) record(opID string) map[string]interface{} {
	raw := readFile(r.recordPath(opID))
	if raw == "" {
		return nil
	}
	m := map[string]interface{}{}
	if json.Unmarshal([]byte(raw), &m) != nil {
		return nil
	}
	return m
}

func recStr(m map[string]interface{}, k string) string {
	s, _ := m[k].(string) //nolint:errcheck // absent → ""
	return s
}

// waitFile polls for a file.
func waitFile(path string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// crash drives a real upgrade to target role and kills the agent at point:
//
//	"<key>:<n>"          hold that docker call, then SIGKILL
//	"ready@<key>:<n>"    hold that call, stall /ready, release, SIGKILL once
//	                     the agent's health probe hits /ready
//	"verified"           SIGKILL as soon as the journal says phase verified
//
// It returns the op id and how the kill was made.
func (r *e2eRig) crash(target, point string) (string, string, error) {
	p := r.a
	switch {
	case point == "verified":
		return r.crashOnVerified(target)
	case strings.HasPrefix(point, "ready@"):
		if err := os.WriteFile(filepath.Join(p.ctl, "block_on"), []byte(strings.TrimPrefix(point, "ready@")+"\n"), 0o600); err != nil {
			return "", "", err
		}
	default:
		if err := os.WriteFile(filepath.Join(p.ctl, "block_on"), []byte(point+"\n"), 0o600); err != nil {
			return "", "", err
		}
	}
	opID, err := r.apply(p, target)
	if err != nil {
		return "", "", err
	}
	if !waitFile(filepath.Join(p.ctl, "blocked"), 150*time.Second) {
		return opID, "", fmt.Errorf("the apply never reached %s; calls:\n%s", point, strings.Join(p.calls(), "\n"))
	}
	how := "held at " + point
	if strings.HasPrefix(point, "ready@") {
		_ = os.Remove(r.e.ctlFile("ready_hit"))
		if err := os.WriteFile(r.e.ctlFile("hang_ready"), []byte("1\n"), 0o644); err != nil {
			return opID, "", err
		}
		if err := os.WriteFile(filepath.Join(p.ctl, "release"), []byte("1\n"), 0o600); err != nil {
			return opID, "", err
		}
		if !waitFile(r.e.ctlFile("ready_hit"), 60*time.Second) {
			return opID, "", fmt.Errorf("the health probe never reached /ready after %s", point)
		}
		how = "killed inside the health probe after " + strings.TrimPrefix(point, "ready@")
	}
	r.killProc(p)
	_ = os.Remove(r.e.ctlFile("hang_ready"))
	_ = os.Remove(r.e.ctlFile("ready_hit"))
	r.jcheck("after the crash")
	return opID, how, nil
}

// crashOnVerified SIGKILLs the agent the moment the journal record reaches
// phase `verified` (there is no Docker call in that window to hold). If the
// op retired the record first, it reports errMissedWindow.
var errMissedWindow = errors.New("the op finished before the kill landed")

func (r *e2eRig) crashOnVerified(target string) (string, string, error) {
	p := r.a
	opID, err := r.apply(p, target)
	if err != nil {
		return "", "", err
	}
	path := r.recordPath(opID)
	needle := []byte(`"phase": "verified"`)
	deadline := time.Now().Add(120 * time.Second)
	nextOpCheck := time.Now()
	for time.Now().Before(deadline) {
		b, rerr := os.ReadFile(path) // #nosec G304 -- harness-owned dir
		if rerr == nil && bytes.Contains(b, needle) {
			_ = p.cmd.Process.Signal(syscall.SIGKILL) // first, before anything else
			r.killProc(p)
			if m := r.record(opID); m != nil && recStr(m, "phase") == "verified" {
				r.jcheck("after the crash")
				return opID, "SIGKILL on journal phase verified (polled)", nil
			}
			return opID, "", errMissedWindow
		}
		if time.Now().After(nextOpCheck) { // the record may already be gone
			nextOpCheck = time.Now().Add(100 * time.Millisecond)
			var op opView
			if code, _ := p.get("/v1/operations/"+opID, &op); code == http.StatusOK && (op.State == "succeeded" || op.State == "failed") {
				r.killProc(p)
				return opID, "", errMissedWindow
			}
		}
	}
	return opID, "", errors.New("never reached phase verified")
}

// reconcileFinished polls GET /v1/status until the reconcile is no longer
// running.
func (p *agentProc) waitReconcile(d time.Duration) (reconcileView, map[string]json.RawMessage, error) {
	deadline := time.Now().Add(d)
	var v reconcileView
	for time.Now().Before(deadline) {
		v = reconcileView{}
		if code, _ := p.get("/v1/status", &v); code == http.StatusOK && v.Reconcile != nil &&
			v.Reconcile.State != "in_progress" && v.Reconcile.State != "not_started" {
			raw := map[string]json.RawMessage{}
			_, _ = p.get("/v1/status", &raw)
			return v, raw, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return v, nil, fmt.Errorf("the reconcile did not finish; last %+v", v.Reconcile)
}

type e2eAudit struct {
	Events []struct {
		OpID    string `json:"op_id"`
		Kind    string `json:"kind"`
		Actor   string `json:"actor"`
		Outcome string `json:"outcome"`
	} `json:"events"`
}

// reconciledAudits counts `<kind>:reconciled` entries for opID by outcome.
func (p *agentProc) reconciledAudits(opID string) map[string]int {
	var av e2eAudit
	_, _ = p.get("/v1/audit?limit=1000", &av)
	n := map[string]int{}
	for _, ev := range av.Events {
		if ev.OpID == opID && strings.HasSuffix(ev.Kind, ":reconciled") && ev.Actor == "agent:reconcile" {
			n[ev.Outcome]++
		}
	}
	return n
}

// ── results ──────────────────────────────────────────────────────────────────

type e2eCheck struct {
	name, want, got string
	ok              bool
	gap             bool // an owner-requested property the AGT-900 contract does not promise
}

type e2eResult struct {
	name, how, expected, observed string
	checks                        []e2eCheck
	err                           string
	prefix                        string // names the restart a check belongs to
}

func (res *e2eResult) check(name string, ok bool, want, got string) {
	res.checks = append(res.checks, e2eCheck{res.prefix + name, want, got, ok, false})
}

func (res *e2eResult) eq(name, want, got string) { res.check(name, want == got, want, got) }

// gapCheck records an owner-requested property that is stricter than the
// AGT-900 contract. A violation is reported as GAP, never hidden as PASS.
func (res *e2eResult) gapCheck(name string, ok bool, want, got string) {
	res.checks = append(res.checks, e2eCheck{res.prefix + name, want, got, ok, true})
}

// verdict: FAIL (a contract check or the harness failed), GAP (only an
// owner-requested property failed), or PASS.
func (res *e2eResult) verdict() string {
	if res.err != "" || len(res.checks) == 0 {
		return "FAIL"
	}
	gap := false
	for _, c := range res.checks {
		switch {
		case !c.ok && !c.gap:
			return "FAIL"
		case !c.ok:
			gap = true
		}
	}
	if gap {
		return "GAP"
	}
	return "PASS"
}

func (e *e2eEnv) record(t *testing.T, res *e2eResult) {
	t.Helper()
	verdict := res.verdict()
	var bad []string
	if res.err != "" {
		bad = append(bad, "error: "+res.err)
	}
	for _, c := range res.checks {
		if !c.ok {
			tag := ""
			if c.gap {
				tag = "GAP "
			}
			bad = append(bad, fmt.Sprintf("%s%s: want %s, got %s", tag, c.name, c.want, c.got))
		}
	}
	obs := res.observed
	if res.how != "" {
		obs += " [" + res.how + "]"
	}
	clean := func(s string) string { return strings.NewReplacer("\t", " ", "\n", " ").Replace(s) }
	line := strings.Join([]string{e.store, res.name, clean(res.expected), clean(obs), verdict, clean(strings.Join(bad, ";;"))}, "\t") + "\n"
	f, err := os.OpenFile(e.results, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		_, _ = f.WriteString(line)
		_ = f.Close()
	}
	t.Logf("agt900 %s %-32s %s | expected %s | observed %s", verdict, res.name, e.store, res.expected, obs)
	for _, c := range res.checks {
		mark := "ok  "
		switch {
		case !c.ok && c.gap:
			mark = "GAP "
		case !c.ok:
			mark = "FAIL"
		}
		t.Logf("agt900     %s %-28s want %-40s got %s", mark, c.name, c.want, c.got)
	}
	if verdict == "FAIL" {
		t.Errorf("%s: %s", res.name, strings.Join(bad, "; "))
	}
}

// ── converge cases ───────────────────────────────────────────────────────────

// e2eExpect is what converge must do at one kill point: the fake-Docker
// suite's expectation (convergeExpect) for the same point.
type e2eExpect struct {
	decision, reason string
	actions          []string // the restart's state-changing docker calls ("tag:prior", "up")
	tag, run         string   // roles after the reconcile
	retired          bool
	state            string // reconcile state: done / recovery_required / deferred
	outcome          string // per-record outcome, when it is not implied (converged_not_retired)
}

func (x e2eExpect) String() string {
	return fmt.Sprintf("%s/%s actions=[%s] tag=%s run=%s retired=%v", x.decision, x.reason, strings.Join(x.actions, ","), x.tag, x.run, x.retired)
}

// e2eConverge is one kill-point case.
type e2eConverge struct {
	name   string
	target string // good | bad
	point  string
	// mutate, if set, changes the state after the crash and before the restart
	// (simulating an operator, or a journal the kill could not reach).
	mutate func(r *e2eRig, opID string) (string, error)
	expect e2eExpect
}

func noop(dec, reason string) e2eExpect {
	return e2eExpect{dec, reason, []string{}, "prior", "prior", true, "done", ""}
}

func rrKeep(reason, tag, run string) e2eExpect {
	return e2eExpect{"recovery_required", reason, []string{}, tag, run, false, "recovery_required", ""}
}

func e2eConvergeCases() []e2eConverge {
	return []e2eConverge{
		// the eight kill points of killPoints() / convergeExpect
		{name: "admitted_at_capture", target: "good", point: "ps_before:1", expect: noop("noop", "safe_boundary_unchanged")},
		{name: "captured_at_resolve", target: "good", point: "manifest_before:1", expect: noop("noop", "safe_boundary_unchanged")},
		{name: "resolved_at_pull", target: "good", point: "pull_before:1", expect: noop("noop", "safe_boundary_unchanged")},
		{name: "barrier_before_tag", target: "good", point: "tag_before:1", expect: noop("noop", "already_on_prior")},
		{name: "tag_moved_before_up", target: "good", point: "up_before:1",
			expect: e2eExpect{"realign", "tag_ahead_container_on_prior", []string{"tag:prior"}, "prior", "prior", true, "done", ""}},
		{name: "up_done_unrecorded", target: "good", point: "up_after:1", expect: rrKeep("target_live_ungated", "good", "good")},
		{name: "restarted_at_health_gate", target: "good", point: "ready@up_after:1", expect: rrKeep("target_live_ungated", "good", "good")},
		{name: "restarted_at_verify", target: "good", point: "ps_before:3", expect: rrKeep("target_live_ungated", "good", "good")},
		// A10: killed after the durable `verified` write, before retirement
		{name: "verified_adopt", target: "good", point: "verified",
			expect: e2eExpect{"adopt", "verified_target_live", []string{}, "good", "good", true, "done", ""}},
		{name: "verified_target_not_ready_now", target: "good", point: "verified", mutate: stallReady,
			expect: rrKeep("verified_target_not_ready", "good", "good")},
		// inline rollback of a target that failed its health gate (bad: /ready 503)
		{name: "rb_armed_before_tag", target: "bad", point: "tag_before:2", expect: rrKeep("rollback_armed_target_live", "bad", "bad")},
		{name: "rb_tag_moved_before_up", target: "bad", point: "up_before:2",
			expect: e2eExpect{"finish_rollback", "rollback_interrupted", []string{"up"}, "prior", "prior", true, "done", ""}},
		{name: "rb_up_done", target: "bad", point: "up_after:2", expect: noop("noop", "already_on_prior")},
		{name: "rb_in_rollback_health", target: "bad", point: "ready@up_after:2", expect: noop("noop", "already_on_prior")},
		{name: "rb_at_rollback_verify", target: "bad", point: "ps_before:3", expect: noop("noop", "already_on_prior")},
		// the same Docker state as rb_tag_moved_before_up, but an operator moved
		// the tag: nothing proves the agent did, so it is only reported
		{name: "operator_retag_unarmed", target: "good", point: "up_after:1", mutate: operatorRetag,
			expect: rrKeep("tag_on_prior_rollback_unproven", "prior", "good")},
		// a record whose prior reference fails the repo binding is never acted on
		{name: "forged_prior_ref", target: "good", point: "up_before:1", mutate: forgePriorRef,
			expect: rrKeep("invalid_record_ref", "good", "prior")},
	}
}

func stallReady(r *e2eRig, _ string) (string, error) {
	return "/ready stalled during the restart", os.WriteFile(r.e.ctlFile("hang_ready"), []byte("1\n"), 0o644)
}

func operatorRetag(r *e2eRig, _ string) (string, error) {
	_, err := r.e.docker("tag", r.e.ref("prior"), e2ePinned)
	return "operator ran `docker tag <prior> " + e2ePinned + "`", err
}

func forgePriorRef(r *e2eRig, opID string) (string, error) {
	path := r.recordPath(opID)
	raw := readFile(path)
	forged := strings.Replace(raw, `"prior_ref": "`+r.e.repo+"@", `"prior_ref": "`+r.e.repo+"-evil@", 1)
	if forged == raw {
		return "", errors.New("record has no prior_ref to forge")
	}
	return "journal prior_ref rewritten to another repository", os.WriteFile(path, []byte(forged), 0o600)
}

// restartObs is everything observed around one converge restart.
type restartObs struct {
	before, after dockerSnap
	recBefore     map[string]interface{}
	view          reconcileView
	raw           map[string]json.RawMessage
	mutating      []string
	allCalls      []string
	opState       string
	recOpState    string
	retired       bool
	audits        map[string]int
	recAfter      map[string]interface{}
	err           error
}

// restartConverge snapshots Docker, starts a converge agent and observes.
func (r *e2eRig) restartConverge(opID, stageTimeout string) restartObs {
	var o restartObs
	o.before = r.e.snap()
	o.recBefore = r.record(opID)
	p := r.start("converge", stageTimeout)
	o.view, o.raw, o.err = p.waitReconcile(e2eReconcTO)
	r.observe(p, opID, &o)
	r.jcheck(fmt.Sprintf("after restart %d", r.seq))
	return o
}

func (r *e2eRig) observe(p *agentProc, opID string, o *restartObs) {
	_ = os.Remove(r.e.ctlFile("hang_ready"))
	o.after = r.e.snap()
	o.mutating = r.mutating(p)
	o.allCalls = p.calls()
	var op opView
	if code, _ := p.get("/v1/operations/"+opID, &op); code == http.StatusOK {
		o.opState = op.State + "(" + op.FailureReason + ")"
	}
	if o.view.Reconcile != nil && o.view.Reconcile.OpID != "" {
		var rop opView
		if code, _ := p.get("/v1/operations/"+o.view.Reconcile.OpID, &rop); code == http.StatusOK {
			o.recOpState = rop.Kind + ":" + rop.State + "(" + rop.FailureReason + ")"
		}
	}
	o.recAfter = r.record(opID)
	o.retired = o.recAfter == nil
	o.audits = p.reconciledAudits(opID)
}

// assertConvergeObs checks one restart against x and the AGT-900 invariants.
func (r *e2eRig) assertConvergeObs(res *e2eResult, opID string, x e2eExpect, o *restartObs) {
	e := r.e
	if o.err != nil {
		res.err = o.err.Error()
		return
	}
	var rec struct{ Decision, Reason, Outcome string }
	if v := o.view.Reconcile; v != nil && len(v.Records) == 1 && v.Records[0].OpID == opID {
		rec.Decision, rec.Reason, rec.Outcome = v.Records[0].Decision, v.Records[0].Reason, v.Records[0].Outcome
	}
	state := ""
	if o.view.Reconcile != nil {
		state = o.view.Reconcile.State
	}
	res.observed = fmt.Sprintf("%s/%s actions=[%s] tag=%s run=%s retired=%v", rec.Decision, rec.Reason, strings.Join(o.mutating, ","),
		e.class(o.after.Tag), e.class(o.after.Image), o.retired)
	// expectation (the fake-Docker suite's table for this kill point)
	res.eq("decision", x.decision+"/"+x.reason, rec.Decision+"/"+rec.Reason)
	res.eq("docker commands", "["+strings.Join(x.actions, ",")+"]", "["+strings.Join(o.mutating, ",")+"]")
	res.eq("tag after", x.tag, e.class(o.after.Tag))
	res.eq("container after", x.run+"(running)", e.class(o.after.Image)+"("+o.after.Status+")")
	res.eq("record retired", strconv.FormatBool(x.retired), strconv.FormatBool(o.retired))
	res.eq("reconcile state", x.state, state)
	if x.outcome != "" {
		res.eq("record outcome", x.outcome, rec.Outcome)
	}
	wantOp := "reconcile.startup:succeeded()"
	if x.state != "done" {
		wantOp = "reconcile.startup:failed(recovery_required)"
	}
	res.eq("reconcile op", wantOp, o.recOpState)
	if x.state == "recovery_required" || x.state == "done" {
		got := "<absent>"
		if o.view.RecoveryRequired != nil {
			got = strconv.FormatBool(*o.view.RecoveryRequired)
		}
		res.eq("status.recovery_required", strconv.FormatBool(x.state == "recovery_required"), got)
	}
	r.assertInvariants(res, opID, x, rec.Decision, rec.Outcome, o)
}

// assertInvariants: AGT-900 / AGT-004 / AGT-005 on real Docker state,
// independent of the expectation table.
func (r *e2eRig) assertInvariants(res *e2eResult, opID string, x e2eExpect, decision, outcome string, o *restartObs) {
	e := r.e
	converged := outcome == "converged"
	// Docker-converged: converged_not_retired changed Docker and verified it,
	// but could not retire the record (its audit write failed).
	dockerConverged := converged || outcome == "converged_not_retired"
	// I1: the only Docker changes a reconcile may make: tag to the recorded
	// prior reference; `up` only with the tag already on the prior image. Never
	// pull, down, or a tag to anything else.
	okCmds := true
	for _, m := range o.mutating {
		switch {
		case m == "tag:prior":
		case m == "up" && o.before.Tag == e.id["prior"]:
		default:
			okCmds = false
		}
	}
	res.check("I1 only permitted docker changes", okCmds, "tag:prior | up(tag already prior)", "["+strings.Join(o.mutating, ",")+"]")
	// I2: a converged record leaves tag and container on the same image, running
	// and ready: the prior image, or a target the journal proved verified.
	if dockerConverged {
		phase := recStr(o.recBefore, "phase")
		img := e.class(o.after.Image)
		ok := o.after.Tag == o.after.Image && o.after.Status == "running" && o.after.Ready &&
			(img == "prior" || (decision == "adopt" && phase == "verified" && img == x.run))
		res.check("I2 converged = same image, gated, ready", ok, "tag==run, running, ready, prior|verified target",
			fmt.Sprintf("%s phase_before=%s", e.describe(o.after), phase))
	} else {
		// I3: anything else changes nothing in Docker.
		same := o.after.ContainerID == o.before.ContainerID && o.after.Image == o.before.Image &&
			o.after.Status == o.before.Status && o.after.Tag == o.before.Tag
		res.check("I3 not converged = Docker unchanged", same, e.describe(o.before)+" id="+short(o.before.ContainerID),
			e.describe(o.after)+" id="+short(o.after.ContainerID))
	}
	// I4: an image that never passed the gate (any target) is never STARTED by
	// the reconcile: if a target runs afterwards, the reconcile ran no `up` and
	// the container is the one that was there before.
	if img := e.class(o.after.Image); img == "good" || img == "bad" {
		started := false
		for _, m := range o.mutating {
			if m == "up" {
				started = true
			}
		}
		ok := !started && o.after.ContainerID == o.before.ContainerID &&
			((decision == "adopt" && converged) || outcome == "recovery_required")
		res.check("I4 no ungated image started", ok, "no up, same container, adopt|recovery_required",
			fmt.Sprintf("up=%v same_container=%v decision=%s outcome=%s", started, o.after.ContainerID == o.before.ContainerID, decision, outcome))
		// OWNER (stricter than the contract, which only forbids STARTING one):
		// no image that has not passed its health gate is left running.
		gated := (decision == "adopt" && converged) || recStr(o.recBefore, "phase") == "verified"
		res.gapCheck("OWNER no ungated image left running", gated, "no ungated target running after the reconcile",
			fmt.Sprintf("%s runs (phase %s, outcome %s; already running before this restart: %v)",
				img, recStr(o.recBefore, "phase"), outcome, o.before.ContainerID == o.after.ContainerID))
	}
	// I5: the image that failed its health gate is never left running by a
	// reconcile that reports success.
	if e.class(o.after.Image) == "bad" {
		res.check("I5 failed-gate image not accepted", outcome != "converged", "outcome != converged", outcome)
	}
	// I6: the interrupted op is never flipped.
	res.eq("I6 interrupted op", "failed(agent_restart_interrupted)", o.opState)
	// I7: retired iff converged, and only after an audit entry.
	res.check("I7 retired iff converged", o.retired == converged, "retired="+strconv.FormatBool(converged), "retired="+strconv.FormatBool(o.retired))
	if o.retired {
		// AGT-005: never retired without its audit entry (FAIL). Exactly one entry
		// is the owner's stricter item-3 property (GAP): the agent writes the
		// audit entry and then removes the record, so a kill between the two is
		// audited again by the next start.
		n := o.audits["succeeded"]
		res.check("I7 audit before retire", n >= 1, ">= 1 succeeded", fmt.Sprintf("%d succeeded", n))
		res.gapCheck("OWNER exactly one audit entry per retirement", n == 1, "1 succeeded", fmt.Sprintf("%d succeeded", n))
	} else if o.recAfter != nil {
		res.eq("I7 kept record carries outcome", outcome, recStr(o.recAfter, "reconcile_outcome"))
	}
	// AGT-004: no pull at startup in any mode.
	for _, c := range o.allCalls {
		if strings.HasPrefix(c, "pull ") {
			res.check("AGT-004 no pull at startup", false, "no pull", c)
		}
	}
}

func short(id string) string { return id[:min(12, len(id))] }

func (e *e2eEnv) want(name string) bool { return e.only == nil || e.only.MatchString(name) }

// runConvergeCase runs one kill-point case.
func (e *e2eEnv) runConvergeCase(t *testing.T, c e2eConverge) {
	res := &e2eResult{name: c.name, expected: c.expect.String()}
	defer e.record(t, res)
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return
	}
	var r *e2eRig
	var opID, how string
	var err error
	for attempt := 1; attempt <= 6; attempt++ { // only the polled `verified` kill can miss
		if attempt > 1 {
			if err = e.reset(); err != nil {
				res.err = "reset: " + err.Error()
				return
			}
		}
		r = newE2ERig(t, e, c.name)
		r.res = res
		r.start("converge", "2m")
		opID, how, err = r.crash(c.target, c.point)
		if !errors.Is(err, errMissedWindow) {
			if attempt > 1 {
				how += fmt.Sprintf(", attempt %d", attempt)
			}
			break
		}
	}
	if err != nil {
		res.err = "crash: " + err.Error()
		return
	}
	res.how = how
	if c.mutate != nil {
		note, merr := c.mutate(r, opID)
		if merr != nil {
			res.err = "mutate: " + merr.Error()
			return
		}
		res.how += "; then " + note
	}
	o := r.restartConverge(opID, "2m")
	r.assertConvergeObs(res, opID, c.expect, &o)
	if c.name == "forged_prior_ref" {
		forged := false
		for _, l := range o.allCalls {
			if strings.Contains(l, "-evil@") {
				forged = true
			}
		}
		res.check("forged ref never reaches docker", !forged, "absent from argv", strconv.FormatBool(forged))
	}
	r.killProc(r.a)
}

// ── special cases ────────────────────────────────────────────────────────────

// caseControl: an uninterrupted upgrade, as a baseline of the real flow.
func (e *e2eEnv) caseControl(t *testing.T, name, target string) {
	want := "op succeeded, tag=good run=good, journal empty"
	if target == "bad" {
		want = "op failed(health) + rollback succeeded, tag=prior run=prior, journal empty"
	}
	res := &e2eResult{name: name, expected: want}
	defer e.record(t, res)
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return
	}
	r := newE2ERig(t, e, name)
	p := r.start("converge", "2m")
	opID, err := r.apply(p, target)
	if err != nil {
		res.err = err.Error()
		return
	}
	var op opView
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		op = opView{}
		if code, _ := p.get("/v1/operations/"+opID, &op); code == http.StatusOK && (op.State == "succeeded" || op.State == "failed") {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	s := e.snap()
	ents, _ := os.ReadDir(filepath.Join(r.state, "reconcile"))
	nrec := 0
	for _, en := range ents {
		if strings.HasSuffix(en.Name(), ".json") {
			nrec++
		}
	}
	res.observed = fmt.Sprintf("op %s(%s) rollback_succeeded=%v %s journal=%d", op.State, op.FailureReason, op.Result["rollback_succeeded"], e.describe(s), nrec)
	t.Logf("agt900 %s docker calls:\n    %s", name, strings.Join(p.calls(), "\n    "))
	if target == "good" {
		res.eq("op", "succeeded", op.State)
		res.eq("docker", "tag=good run=good(running,ready)", e.describe(s))
	} else {
		res.eq("op", "failed", op.State)
		res.eq("rollback_succeeded", "true", fmt.Sprint(op.Result["rollback_succeeded"]))
		res.eq("docker", "tag=prior run=prior(running,ready)", e.describe(s))
	}
	res.eq("journal records", "0", strconv.Itoa(nrec))
	r.killProc(p)
}

// e2eHold is one restart whose reconcile is SIGKILLed at a point:
// "<key>:<n>" / "ready@<key>:<n>" as in crash, or "audit" (polled: the
// moment the record's `:reconciled` audit entry is on disk).
type e2eHold struct {
	point    string
	attempts int    // reconcile_attempts the record must hold after the kill
	docker   string // "unchanged" (vs before this restart) or "tag=<role> run=<role>"
}

// e2eKillSeq: crash an upgrade, then kill the reconcile at each hold in turn
// (one restart per hold), then restart to completion `finals` times. Every
// completed restart must match final; attempts must persist across restarts.
type e2eKillSeq struct {
	name, target, crashAt string
	holds                 []e2eHold
	final                 e2eExpect
	finals                int
	finalAttempts         int // reconcile_attempts of a kept record after the finals
}

func (s e2eKillSeq) expected() string {
	var hs []string
	for _, h := range s.holds {
		hs = append(hs, fmt.Sprintf("kill@%s->attempts=%d,docker %s", h.point, h.attempts, h.docker))
	}
	n := s.finals
	if n == 0 {
		n = 1
	}
	return fmt.Sprintf("%s; then %dx %s", strings.Join(hs, "; "), n, s.final)
}

var (
	xRealign = e2eExpect{"realign", "tag_ahead_container_on_prior", []string{"tag:prior"}, "prior", "prior", true, "done", ""}
	xFinish  = e2eExpect{"finish_rollback", "rollback_interrupted", []string{"up"}, "prior", "prior", true, "done", ""}
	xOnPrior = noop("noop", "already_on_prior")
)

// caseKillSeq runs s, retrying from scratch if a polled kill missed its window.
func (e *e2eEnv) caseKillSeq(t *testing.T, s e2eKillSeq) {
	res := &e2eResult{name: s.name, expected: s.expected()}
	defer e.record(t, res)
	for attempt := 1; attempt <= 6; attempt++ {
		res.checks, res.err, res.how, res.prefix = nil, "", "", ""
		err := e.runKillSeq(t, s, res)
		if !errors.Is(err, errMissedWindow) {
			if err != nil {
				res.err = err.Error()
			}
			if attempt > 1 {
				res.how += fmt.Sprintf(" (attempt %d)", attempt)
			}
			return
		}
	}
	res.err = "the polled kill missed its window 6 times"
}

func (e *e2eEnv) runKillSeq(t *testing.T, s e2eKillSeq, res *e2eResult) error {
	if err := e.reset(); err != nil {
		return fmt.Errorf("reset: %w", err)
	}
	r := newE2ERig(t, e, s.name)
	r.res = res
	r.start("converge", "2m")
	opID, how, err := r.crash(s.target, s.crashAt)
	if err != nil {
		return fmt.Errorf("crash: %w", err)
	}
	res.how = how
	for i, h := range s.holds {
		res.prefix = fmt.Sprintf("k%d ", i+1)
		before := e.snap()
		p := r.newProc(fmt.Sprintf("h%d", i+1), "converge", "2m")
		if h.point != "audit" {
			if err := os.WriteFile(filepath.Join(p.ctl, "block_on"), []byte(strings.TrimPrefix(h.point, "ready@")+"\n"), 0o600); err != nil {
				return err
			}
		}
		r.startProc(p)
		r.a = p
		if h.point == "audit" {
			if err := r.killOnReconciledAudit(p, opID); err != nil {
				return err
			}
		} else {
			if !waitFile(filepath.Join(p.ctl, "blocked"), 2*time.Minute) {
				return fmt.Errorf("the reconcile never reached %s; calls:\n%s", h.point, strings.Join(p.calls(), "\n"))
			}
			if i == 0 {
				var conflict struct {
					Holder struct {
						Kind string `json:"kind"`
					} `json:"holder_op"`
				}
				code, _ := p.post("/v1/upgrades/apply", map[string]interface{}{"image_ref": e.ref("good")}, &conflict)
				res.eq("apply during reconcile", "409 reconcile.startup", fmt.Sprintf("%d %s", code, conflict.Holder.Kind))
				var v reconcileView
				_, _ = p.get("/v1/status", &v)
				st := "<none>"
				if v.Reconcile != nil {
					st = v.Reconcile.State
				}
				res.eq("status during reconcile", "in_progress", st)
			}
			if strings.HasPrefix(h.point, "ready@") {
				_ = os.Remove(e.ctlFile("ready_hit"))
				if err := os.WriteFile(e.ctlFile("hang_ready"), []byte("1\n"), 0o644); err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(p.ctl, "release"), []byte("1\n"), 0o600); err != nil {
					return err
				}
				if !waitFile(e.ctlFile("ready_hit"), 60*time.Second) {
					return fmt.Errorf("the reconcile's probe never reached /ready after %s", h.point)
				}
			}
			r.killProc(p)
			_ = os.Remove(e.ctlFile("hang_ready"))
			_ = os.Remove(e.ctlFile("ready_hit"))
		}
		r.jcheck(fmt.Sprintf("after reconcile kill %d", i+1))
		held := e.snap()
		if h.docker == "unchanged" {
			res.check("Docker after the kill", held.Image == before.Image && held.Tag == before.Tag && held.ContainerID == before.ContainerID,
				"unchanged: "+e.describe(before), e.describe(held))
		} else {
			res.eq("Docker after the kill", h.docker, fmt.Sprintf("tag=%s run=%s", e.class(held.Tag), e.class(held.Image)))
		}
		res.eq("attempts after the kill", strconv.Itoa(h.attempts), strconv.Itoa(recInt(r.record(opID), "reconcile_attempts")))
		res.how += "; reconcile killed at " + h.point
	}
	n := s.finals
	if n == 0 {
		n = 1
	}
	var o restartObs
	for k := 0; k < n; k++ {
		res.prefix = fmt.Sprintf("r%d ", k+1)
		o = r.restartConverge(opID, "2m")
		r.assertConvergeObs(res, opID, s.final, &o)
		r.killProc(r.a)
	}
	res.prefix = ""
	if m := r.record(opID); m != nil {
		res.eq("attempts at the end", strconv.Itoa(s.finalAttempts), strconv.Itoa(recInt(m, "reconcile_attempts")))
	}
	return nil
}

// killOnReconciledAudit SIGKILLs p as soon as the record's `:reconciled`
// audit entry is on disk, i.e. after the verify and the audit write and before
// (or after) the record's removal. A kill that lands after the removal is a
// missed window.
func (r *e2eRig) killOnReconciledAudit(p *agentProc, opID string) error {
	path := filepath.Join(r.state, "audit.jsonl")
	want := []byte(`"op_id":"` + opID + `"`)
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(path) // #nosec G304 -- harness-owned dir
		for _, line := range bytes.Split(b, []byte("\n")) {
			if bytes.Contains(line, want) && bytes.Contains(line, []byte(`:reconciled"`)) {
				_ = p.cmd.Process.Signal(syscall.SIGKILL)
				r.killProc(p)
				if r.record(opID) == nil {
					return errMissedWindow
				}
				return nil
			}
		}
	}
	return errors.New("no `:reconciled` audit entry appeared")
}

// caseAuditWriteFails: the reconcile's audit write fails (audit.jsonl made
// immutable while the reconcile is held at its first Docker read). Docker is
// realigned and verified, but the record must be KEPT (converged_not_retired):
// a record is never retired without its audit entry. Once the audit log is
// writable again, the next start retires it with exactly one entry.
func (e *e2eEnv) caseAuditWriteFails(t *testing.T, name string) {
	x1 := e2eExpect{"realign", "tag_ahead_container_on_prior", []string{"tag:prior"}, "prior", "prior", false, "recovery_required", "converged_not_retired"}
	res := &e2eResult{name: name, expected: "audit unwritable: " + x1.String() + " outcome=converged_not_retired; audit writable again: " + xOnPrior.String()}
	defer e.record(t, res)
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return
	}
	r := newE2ERig(t, e, name)
	r.res = res
	r.start("converge", "2m")
	opID, how, err := r.crash("good", "up_before:1")
	if err != nil {
		res.err = "crash: " + err.Error()
		return
	}
	res.how = how + "; audit.jsonl made immutable during the reconcile"
	auditPath := filepath.Join(r.state, "audit.jsonl")
	defer func() { _ = exec.CommandContext(context.Background(), "chattr", "-i", auditPath).Run() }()
	var o restartObs
	o.before = e.snap()
	o.recBefore = r.record(opID)
	p := r.newProc("immutable", "converge", "2m")
	if err := os.WriteFile(filepath.Join(p.ctl, "block_on"), []byte("ps_before:1\n"), 0o600); err != nil {
		res.err = err.Error()
		return
	}
	r.startProc(p)
	r.a = p
	if !waitFile(filepath.Join(p.ctl, "blocked"), time.Minute) {
		res.err = "the reconcile never reached its first read"
		return
	}
	if out, err := exec.CommandContext(context.Background(), "chattr", "+i", auditPath).CombinedOutput(); err != nil {
		res.err = fmt.Sprintf("chattr +i: %v %s", err, out)
		return
	}
	if err := os.WriteFile(filepath.Join(p.ctl, "release"), []byte("1\n"), 0o600); err != nil {
		res.err = err.Error()
		return
	}
	res.prefix = "r1 "
	o.view, o.raw, o.err = p.waitReconcile(e2eReconcTO)
	r.observe(p, opID, &o)
	r.jcheck("after the failed audit")
	r.assertConvergeObs(res, opID, x1, &o)
	r.killProc(p)
	if out, err := exec.CommandContext(context.Background(), "chattr", "-i", auditPath).CombinedOutput(); err != nil {
		res.err = fmt.Sprintf("chattr -i: %v %s", err, out)
		return
	}
	res.prefix = "r2 "
	o2 := r.restartConverge(opID, "2m")
	r.assertConvergeObs(res, opID, xOnPrior, &o2)
	res.prefix = ""
	r.killProc(r.a)
}

// caseDockerDown: Docker cannot be read at start (its daemon is stopped):
// defer, nothing changed, no attempt counted, record kept; once the daemon is
// back the next start converges. With second=true a second agent process is
// started on the same state_dir while the first holds the instance lock.
func (e *e2eEnv) caseDockerDown(t *testing.T, name string, second bool) {
	x := e2eExpect{"realign", "tag_ahead_container_on_prior", []string{"tag:prior"}, "prior", "prior", true, "done", ""}
	exp := "dockerd stopped: deferred, no attempt, record kept, no docker change; dockerd back: " + x.String()
	if second {
		exp = "instance 2 on the same state_dir: skipped_second_instance, no docker change, record kept; after both die: " + x.String()
	}
	res := &e2eResult{name: name, expected: exp}
	defer e.record(t, res)
	daemonDown := false
	defer func() {
		if daemonDown {
			_ = e.daemon(e.dockerdStart)
		}
	}()
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return
	}
	r := newE2ERig(t, e, name)
	r.res = res
	r.start("converge", "2m")
	opID, how, err := r.crash("good", "up_before:1")
	if err != nil {
		res.err = "crash: " + err.Error()
		return
	}
	res.how = how + "; dockerd stopped"
	before := e.snap()
	if err := e.daemon(e.dockerdStop); err != nil {
		res.err = err.Error()
		return
	}
	daemonDown = true
	p1 := r.start("converge", "5s")
	v, _, err := p1.waitReconcile(e2eReconcTO)
	if err != nil {
		res.err = err.Error()
		return
	}
	outcome := ""
	if len(v.Reconcile.Records) == 1 {
		outcome = v.Reconcile.Records[0].Decision + "/" + v.Reconcile.Records[0].Reason + ":" + v.Reconcile.Records[0].Outcome
	}
	res.eq("docker down: reconcile", "deferred defer/docker_unavailable:deferred", v.Reconcile.State+" "+outcome)
	res.eq("docker down: docker changes", "[]", "["+strings.Join(r.mutating(p1), ",")+"]")
	rec := r.record(opID)
	res.check("docker down: record kept", rec != nil, "kept", fmt.Sprint(rec != nil))
	_, counted := rec["reconcile_attempts"]
	res.check("docker down: no attempt counted", !counted, "no reconcile_attempts", fmt.Sprint(rec["reconcile_attempts"]))
	r.jcheck("after the deferral (dockerd down)")
	if err := e.daemon(e.dockerdStart); err != nil {
		res.err = err.Error()
		return
	}
	daemonDown = false
	if err := e.waitReady(90 * time.Second); err != nil {
		res.err = "after dockerd restart: " + err.Error()
		return
	}
	back := e.snap()
	res.check("dockerd back: Docker as before", back.Image == before.Image && back.Tag == before.Tag && back.ContainerID == before.ContainerID,
		e.describe(before), e.describe(back))
	if second {
		p2 := r.newProc("second", "converge", "2m")
		r.startProc(p2)
		var v2 reconcileView
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			v2 = reconcileView{}
			if code, _ := p2.get("/v1/status", &v2); code == http.StatusOK && v2.Reconcile != nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		st := "<none>"
		if v2.Reconcile != nil {
			st = v2.Reconcile.State
		}
		res.eq("instance 2 reconcile", "skipped_second_instance", st)
		time.Sleep(3 * time.Second)
		res.eq("instance 2 docker changes", "[]", "["+strings.Join(r.mutating(p2), ",")+"]")
		now := e.snap()
		res.check("instance 2: Docker unchanged", now.Image == back.Image && now.Tag == back.Tag && now.ContainerID == back.ContainerID,
			e.describe(back), e.describe(now))
		res.check("instance 2: record kept", r.record(opID) != nil, "kept", fmt.Sprint(r.record(opID) != nil))
		r.jcheck("after instance 2")
		r.killProc(p2)
		res.how += "; instance 2 started while instance 1 held the lock; both SIGKILLed"
	}
	r.killProc(p1)
	o := r.restartConverge(opID, "2m")
	r.assertConvergeObs(res, opID, x, &o)
	r.killProc(r.a)
}

// caseOffMode: AGT-004 negative control. With the default "off" the restart
// changes nothing in Docker, keeps the record and reports it.
func (e *e2eEnv) caseOffMode(t *testing.T, name, target, point string) {
	res := &e2eResult{name: name, expected: "no docker change, no reconcile in status, op failed(agent_restart_interrupted), record kept"}
	defer e.record(t, res)
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return
	}
	r := newE2ERig(t, e, name)
	r.res = res
	r.start("off", "2m")
	opID, how, err := r.crash(target, point)
	if err != nil {
		res.err = "crash: " + err.Error()
		return
	}
	res.how = how
	before := e.snap()
	p := r.start("off", "2m")
	time.Sleep(5 * time.Second)
	after := e.snap()
	raw := map[string]json.RawMessage{}
	_, _ = p.get("/v1/status", &raw)
	_, hasReconcile := raw["reconcile"]
	var v reconcileView
	_, _ = p.get("/v1/status", &v)
	var op opView
	_, _ = p.get("/v1/operations/"+opID, &op)
	res.observed = fmt.Sprintf("docker calls=[%s] %s", strings.Join(r.mutating(p), ","), e.describe(after))
	res.eq("docker changes", "[]", "["+strings.Join(r.mutating(p), ",")+"]")
	res.check("Docker unchanged", after.ContainerID == before.ContainerID && after.Image == before.Image && after.Tag == before.Tag,
		e.describe(before), e.describe(after))
	res.check("no reconcile in status", !hasReconcile, "absent", fmt.Sprint(hasReconcile))
	res.eq("op", "failed(agent_restart_interrupted)", op.State+"("+op.FailureReason+")")
	res.check("record kept", r.record(opID) != nil, "kept", fmt.Sprint(r.record(opID) != nil))
	listed := false
	for _, i := range v.Interrupted {
		if i.OpID == opID && !i.DockerReconciled {
			listed = true
		}
	}
	res.check("listed in interrupted_operations", listed, "listed, docker_reconciled=false", fmt.Sprint(listed))
	r.jcheck("after the off-mode restart")
	_, lockErr := os.Stat(filepath.Join(r.state, "reconcile", ".lock"))
	res.check("no instance lock in off mode", os.IsNotExist(lockErr), "absent", fmt.Sprint(lockErr))
	r.killProc(p)
}

// TestAGT900RealDocker is the e2e entry point (one image store per run).
func TestAGT900RealDocker(t *testing.T) {
	e := loadE2EEnv(t)
	type named struct {
		name string
		run  func()
	}
	all := []named{
		{"control_good_upgrade", func() { e.caseControl(t, "control_good_upgrade", "good") }},
		{"control_bad_upgrade_rolls_back", func() { e.caseControl(t, "control_bad_upgrade_rolls_back", "bad") }},
	}
	for _, c := range e2eConvergeCases() {
		c := c
		all = append(all, named{c.name, func() { e.runConvergeCase(t, c) }})
	}
	all = append(all,
		named{"audit_write_fails_keeps_record", func() { e.caseAuditWriteFails(t, "audit_write_fails_keeps_record") }},
	)
	for _, s := range e2eKillSeqs() {
		s := s
		all = append(all, named{s.name, func() { e.caseKillSeq(t, s) }})
	}
	all = append(all,
		named{"docker_unavailable_defers", func() { e.caseDockerDown(t, "docker_unavailable_defers", false) }},
		named{"second_instance_skips", func() { e.caseDockerDown(t, "second_instance_skips", true) }},
		named{"off_mode_tag_ahead", func() { e.caseOffMode(t, "off_mode_tag_ahead", "good", "up_before:1") }},
		named{"off_mode_target_live", func() { e.caseOffMode(t, "off_mode_target_live", "good", "up_after:1") }},
	)
	names := make([]string, 0, len(all))
	ran := 0
	for _, c := range all {
		names = append(names, c.name)
		if !e.want(c.name) {
			continue
		}
		ran++
		c.run()
	}
	sort.Strings(names)
	if ran == 0 {
		t.Fatalf("AGT900_CASES matched no case; cases: %s", strings.Join(names, " "))
	}
	_, _ = e.docker("compose", "-f", e.composeFile(), "down", "--remove-orphans")
}

// e2eNormID strips a sha256: prefix.
func e2eNormID(s string) string { return strings.TrimPrefix(s, "sha256:") }

// ── durable journal consistency ──────────────────────────────────────────────

var e2ePhaseOrder = map[string]int{"admitted": 0, "captured": 1, "resolved": 2, "pulled": 3, "restarting": 4, "restarted": 5, "verified": 6}

// e2eHist is what jcheck last saw of one record.
type e2eHist struct {
	phase, attempts, seen int
	retired               bool
}

func recInt(m map[string]interface{}, k string) int {
	f, _ := m[k].(float64) //nolint:errcheck // absent → 0
	return int(f)
}

// jcheck reads the journal directory and audit.jsonl directly (not through
// the agent) and records one check: every record file parses and names its
// own op; nothing but the lock and the journal's own temp files is there;
// phase, attempts and start counts never go backwards and attempts stay within
// the cap; a record's image ids are the real ones; a record at a safe phase
// agrees with Docker (tag and container on the prior image); a retired record
// has exactly one `:reconciled` succeeded audit entry and a kept one has none;
// an interruption is audited at most once.
func (r *e2eRig) jcheck(label string) {
	if r.res == nil {
		return
	}
	var probs []string
	dir := filepath.Join(r.state, "reconcile")
	ents, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		probs = append(probs, "readdir: "+err.Error())
	}
	snap := r.e.snap()
	present := map[string]map[string]interface{}{}
	temps := 0
	for _, en := range ents {
		n := en.Name()
		switch {
		case n == ".lock":
		case strings.HasPrefix(n, ".journal-") && strings.HasSuffix(n, ".tmp"):
			temps++ // a write the kill interrupted; never read as a record
		case strings.HasSuffix(n, ".json"):
			id := strings.TrimSuffix(n, ".json")
			m := map[string]interface{}{}
			if err := json.Unmarshal([]byte(readFile(filepath.Join(dir, n))), &m); err != nil {
				probs = append(probs, n+" does not parse: "+err.Error())
				continue
			}
			present[id] = m
			probs = append(probs, r.checkRecord(id, m, snap)...)
		default:
			probs = append(probs, "unexpected file "+n)
		}
	}
	for id, h := range r.hist {
		if _, ok := present[id]; !ok && !h.retired {
			h.retired = true
			r.hist[id] = h
		}
	}
	auditProbs, auditGaps := r.checkAudit(present)
	probs = append(probs, auditProbs...)
	got := fmt.Sprintf("%d record(s), %d temp file(s); %s", len(present), temps, r.e.describe(snap))
	if len(probs) > 0 {
		got = strings.Join(probs, "; ")
	}
	r.res.check("J "+label, len(probs) == 0, "journal parses, monotonic, matches Docker, retired only with an audit entry", got)
	r.res.gapCheck("OWNER J "+label+": audit 1:1", len(auditGaps) == 0, "kept: at most 1 `:reconciled` entry; retired: exactly 1", strings.Join(auditGaps, "; "))
}

func (r *e2eRig) checkRecord(id string, m map[string]interface{}, snap dockerSnap) []string {
	e := r.e
	var probs []string
	bad := func(f string, a ...interface{}) { probs = append(probs, short(id)+": "+fmt.Sprintf(f, a...)) }
	if recStr(m, "op_id") != id {
		bad("op_id %q differs from the file name", recStr(m, "op_id"))
	}
	if recStr(m, "kind") == "" {
		bad("no kind")
	}
	phase, ok := e2ePhaseOrder[recStr(m, "phase")]
	if !ok {
		bad("invalid phase %q", recStr(m, "phase"))
	}
	att, seen := recInt(m, "reconcile_attempts"), recInt(m, "interrupted_seen")
	if h, had := r.hist[id]; had {
		if h.retired {
			bad("a retired record reappeared")
		}
		if phase < h.phase {
			bad("phase went backwards (%d -> %d)", h.phase, phase)
		}
		if att < h.attempts {
			bad("reconcile_attempts went backwards (%d -> %d)", h.attempts, att)
		}
		if seen < h.seen {
			bad("interrupted_seen went backwards (%d -> %d)", h.seen, seen)
		}
	}
	r.hist[id] = e2eHist{phase: phase, attempts: att, seen: seen}
	if att > 2 {
		bad("reconcile_attempts %d above the cap 2", att)
	}
	if v := e2eNormID(recStr(m, "prior_image_id")); v != "" && v != e.id["prior"] {
		bad("prior_image_id %.12s is not the prior image", v)
	}
	if v := e2eNormID(recStr(m, "target_image_id")); v != "" {
		if role := r.roleOfRef(recStr(m, "target_ref")); v != e.id[role] {
			bad("target_image_id %.12s is not the %s image", v, role)
		}
	}
	if m["rollback_armed"] == true && phase < e2ePhaseOrder["restarting"] {
		bad("rollback_armed at a safe phase")
	}
	// The write-ahead barrier precedes every tag move: at a safe phase Docker
	// must still be on the prior image (not checkable while the daemon is down).
	if snap.Err == "" && ok && phase < e2ePhaseOrder["restarting"] {
		if snap.Tag != e.id["prior"] || (snap.Image != "" && snap.Image != e.id["prior"]) {
			bad("phase %s but Docker is %s", recStr(m, "phase"), e.describe(snap))
		}
	}
	return probs
}

// checkAudit returns contract problems (a record retired with no audit entry, an
// unparsable line, an interruption marked audited with no entry) and owner-strict gaps (a
// kept record audited as reconciled more than once, a retirement or an interruption audited
// twice). A kept record with ONE entry is the crash window between the audit and the removal.
func (r *e2eRig) checkAudit(present map[string]map[string]interface{}) (probs, gaps []string) {
	reconciled, interrupted := map[string]int{}, map[string]int{}
	for i, line := range strings.Split(readFile(filepath.Join(r.state, "audit.jsonl")), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev struct {
			Actor         string `json:"actor"`
			Kind          string `json:"kind"`
			Outcome       string `json:"outcome"`
			OpID          string `json:"op_id"`
			FailureReason string `json:"failure_reason"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			probs = append(probs, fmt.Sprintf("audit line %d does not parse", i+1))
			continue
		}
		if ev.Actor == "agent:reconcile" && strings.HasSuffix(ev.Kind, ":reconciled") && ev.Outcome == "succeeded" {
			reconciled[ev.OpID]++
		}
		if ev.Outcome == "failed" && ev.FailureReason == "agent_restart_interrupted" {
			interrupted[ev.OpID]++
		}
	}
	for id, h := range r.hist {
		switch {
		case h.retired && reconciled[id] == 0:
			probs = append(probs, fmt.Sprintf("%s retired with no `:reconciled` audit entry", short(id)))
		case h.retired && reconciled[id] > 1:
			gaps = append(gaps, fmt.Sprintf("%s retired with %d `:reconciled` audit entries", short(id), reconciled[id]))
		case !h.retired && reconciled[id] > 1:
			// One entry on a KEPT record is the expected state of a kill between
			// retire()'s fsynced audit write and the record removal (AGT-005
			// orders audit before removal). Exactly-once is then judged when the
			// next start retires it: the "retired with N entries" rule above.
			gaps = append(gaps, fmt.Sprintf("%s kept but already audited as reconciled %d times", short(id), reconciled[id]))
		}
		if interrupted[id] > 1 {
			gaps = append(gaps, fmt.Sprintf("%s interruption audited %d times", short(id), interrupted[id]))
		}
		if m := present[id]; m != nil && m["interrupt_audited"] == true && interrupted[id] == 0 {
			probs = append(probs, fmt.Sprintf("%s interrupt_audited but %d audit entries", short(id), interrupted[id]))
		}
	}
	return probs, gaps
}

// e2eKillSeqs: crashes inside the reconcile itself (item 1) and repeated
// restarts on one record (item 2). Reconcile call numbering (per process):
// its Docker reads are ps:1 (wait for Docker), ps:2 (facts), ps:3 (TOCTOU
// re-read after the write-ahead attempt), then the action (tag:1 or up:1),
// then ps:4 (verify); each read is compose ps + inspect + 1 or 4 image
// inspects, so image:13 is the verify's last read.
func e2eKillSeqs() []e2eKillSeq {
	unchanged := func(point string, attempts int) e2eHold { return e2eHold{point, attempts, "unchanged"} }
	onPrior := func(point string, attempts int) e2eHold { return e2eHold{point, attempts, "tag=prior run=prior"} }
	return []e2eKillSeq{
		// item 1, realign (tag ahead, container on prior)
		{name: "rc_after_writeahead", target: "good", crashAt: "up_before:1",
			holds: []e2eHold{unchanged("ps_before:3", 1)}, final: xRealign},
		{name: "kill_in_reconcile_tag", target: "good", crashAt: "up_before:1",
			holds: []e2eHold{unchanged("tag_before:1", 1)}, final: xRealign},
		{name: "rc_after_tag_before_verify", target: "good", crashAt: "up_before:1",
			holds: []e2eHold{onPrior("ps_before:4", 1)}, final: xOnPrior},
		{name: "rc_in_verify_last_read", target: "good", crashAt: "up_before:1",
			holds: []e2eHold{onPrior("image_after:13", 1)}, final: xOnPrior},
		{name: "rc_after_audit_before_retire", target: "good", crashAt: "up_before:1",
			holds: []e2eHold{onPrior("audit", 1)}, final: xOnPrior},
		// item 1, finish_rollback (armed, tag already on prior, bad target running)
		{name: "kill_in_reconcile_up", target: "bad", crashAt: "up_before:2",
			holds: []e2eHold{unchanged("up_before:1", 1)}, final: xFinish},
		{name: "kill_in_reconcile_after_up", target: "bad", crashAt: "up_before:2",
			holds: []e2eHold{onPrior("up_after:1", 1)}, final: xOnPrior},
		{name: "rc_in_post_up_probe", target: "bad", crashAt: "up_before:2",
			holds: []e2eHold{onPrior("ready@up_after:1", 1)}, final: xOnPrior},
		{name: "rc_fr_in_verify_last_read", target: "bad", crashAt: "up_before:2",
			holds: []e2eHold{onPrior("image_after:13", 1)}, final: xOnPrior},
		// item 2, repeated restarts on one record
		{name: "repeat_tag_ahead_exhaust", target: "good", crashAt: "up_before:1",
			holds: []e2eHold{unchanged("tag_before:1", 1), unchanged("tag_before:1", 2)},
			final: rrKeep("reconcile_exhausted", "good", "prior"), finals: 2, finalAttempts: 2},
		{name: "repeat_rollback_exhaust", target: "bad", crashAt: "up_before:2",
			holds: []e2eHold{unchanged("up_before:1", 1), unchanged("up_before:1", 2)},
			final: rrKeep("reconcile_exhausted", "prior", "bad"), finals: 2, finalAttempts: 2},
		{name: "repeat_mixed_then_converge", target: "good", crashAt: "up_before:1",
			holds: []e2eHold{unchanged("ps_before:2", 0), unchanged("tag_before:1", 1), unchanged("ps_before:2", 1)},
			final: xRealign},
		{name: "repeat_rr_stable", target: "good", crashAt: "up_after:1",
			holds: []e2eHold{unchanged("ps_before:2", 0), unchanged("image_before:3", 0)},
			final: rrKeep("target_live_ungated", "good", "good"), finals: 2, finalAttempts: 0},
	}
}
