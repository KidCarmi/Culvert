package main

// startup_crash_recovery_test.go — crash / restart lifecycle of the journal.
//
// These tests run the REAL agent binary: a real upgrades.apply is driven over
// the real Unix socket, the process is SIGKILLed at a chosen point of the
// apply flow, and a new process is started against the same state_dir, so the
// startup path under test is main()'s own, not a copy of it.
//
// Docker is the only substitute. `docker` is resolved through PATH, so the
// agent is started with a small shell script first on PATH that models the
// three facts the lifecycle depends on — which image the proxy container runs,
// which image the fixed tag resolves to, and which images are local — and can
// stop at a named command so the kill lands at a known phase. The model
// records every invocation, which is how "startup issued no state-changing
// docker command" is asserted rather than assumed.
//
// Contract pinned here (docs/adr/0061):
//   - an interrupted op is reported, durably, with how far it got;
//   - startup never changes Docker;
//   - the report survives further restarts and is audited exactly once;
//   - a later successful image change retires it.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	crashRepo = "registry.test/agentb/proxy"
	// Image config ids and manifest digests of the two images in the model.
	imgA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	imgB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	digA = "1111111111111111111111111111111111111111111111111111111111111111"
	digB = "2222222222222222222222222222222222222222222222222222222222222222"
	refA = crashRepo + "@sha256:" + digA
	refB = crashRepo + "@sha256:" + digB
)

// fakeDockerScript is the process-level Docker model. __STATE__ and __REPO__
// are substituted when it is written.
const fakeDockerScript = `#!/bin/sh
S='__STATE__'
REPO='__REPO__'
echo "$*" >> "$S/calls.log"
blk() {
  n=$(cat "$S/count.$1" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$S/count.$1"
  if [ -f "$S/block_on" ] && [ "$(cat "$S/block_on")" = "$1:$n" ]; then
    echo $$ > "$S/blocked.tmp"; mv "$S/blocked.tmp" "$S/blocked"
    exec sleep 300
  fi
}
if [ -f "$S/docker_down" ]; then
  echo "Cannot connect to the Docker daemon" >&2; exit 1
fi
case "$1" in
compose)
  shift 3
  case "$1" in
  ps)
    blk ps
    if [ -f "$S/running" ]; then
      printf '{"Service":"proxy","State":"running","ID":"c0ffee000001"}\n'
    fi ;;
  up)
    blk up_before
    # up_cleanup_only: real Compose, after a recreate interrupted between its stop and
    # its delete, spends one pass tidying up and exits 0 with nothing started. The file
    # holds how many such passes are left. Inert unless a test writes it.
    c=$(cat "$S/up_cleanup_only" 2>/dev/null || echo 0)
    if [ "$c" -gt 0 ]; then
      echo $((c-1)) > "$S/up_cleanup_only"; rm -f "$S/running"
    else
      cp "$S/pinned" "$S/running.tmp" && mv "$S/running.tmp" "$S/running"
    fi
    blk up_after ;;
  down)
    # The restore flow's stop. Inert for every test that never restores.
    blk down_before
    rm -f "$S/running"
    blk down_after ;;
  --profile)
    # The cli service: a restore dry-run (the preflight) or a restore commit.
    # The commit replaces the model's data directory content marker.
    case " $* " in
    *" --confirm "*)
      blk commit_before
      echo restored > "$S/data.tmp" && mv "$S/data.tmp" "$S/data"
      blk commit_after ;;
    *" --restore "*)
      blk dryrun ;;
    esac ;;
  esac ;;
inspect)
  printf '"sha256:%s"\n' "$(cat "$S/running")" ;;
image)
  ref="$3"
  case "$ref" in
  culvert/proxy:pinned) id=$(cat "$S/pinned" 2>/dev/null) || { echo "No such image" >&2; exit 1; } ;;
  sha256:*) id=${ref#sha256:} ;;
  *@sha256:*) id=$(cat "$S/by_digest/${ref##*@sha256:}" 2>/dev/null) || { echo "No such image" >&2; exit 1; } ;;
  *) echo "No such image" >&2; exit 1 ;;
  esac
  [ -f "$S/images/$id" ] || { echo "No such image" >&2; exit 1; }
  printf '[{"Id":"sha256:%s","RepoDigests":["%s@sha256:%s"]}]\n' "$id" "$REPO" "$(cat "$S/images/$id")" ;;
manifest)
  blk manifest
  printf '{"Descriptor":{"digest":"sha256:%s"}}\n' "${4##*@sha256:}" ;;
pull)
  blk pull
  if [ -f "$S/pull_fail" ]; then echo "manifest unknown" >&2; exit 1; fi ;;
tag)
  blk tag_before
  cat "$S/by_digest/${2##*@sha256:}" > "$S/pinned.tmp" && mv "$S/pinned.tmp" "$S/pinned" ;;
esac
exit 0
`

var (
	agentBuildOnce sync.Once
	agentBinPath   string
	errAgentBuild  error
)

// TestMain removes the agent binary built for the crash tests.
func TestMain(m *testing.M) {
	code := m.Run()
	if agentBinPath != "" {
		_ = os.RemoveAll(filepath.Dir(agentBinPath))
	}
	os.Exit(code)
}

// agentBinary builds the agent once per test binary.
func agentBinary(t *testing.T) string {
	t.Helper()
	agentBuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "culvert-maint-crash-bin-")
		if err != nil {
			errAgentBuild = err
			return
		}
		agentBinPath = filepath.Join(dir, "culvert-maint")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-o", agentBinPath, ".") // #nosec G204 -- constant argv plus a temp output path
		if out, berr := cmd.CombinedOutput(); berr != nil {
			errAgentBuild = fmt.Errorf("go build: %w\n%s", berr, out)
		}
	})
	if errAgentBuild != nil {
		t.Fatalf("build agent: %v", errAgentBuild)
	}
	return agentBinPath
}

// crashRig owns one appliance: a state_dir, a Docker model, a health endpoint
// and at most one running agent process.
type crashRig struct {
	t       *testing.T
	dir     string // root
	model   string // Docker model state
	state   string // agent state_dir
	sock    string
	cfgPath string
	shimDir string
	cmd     *exec.Cmd
	logs    *bytes.Buffer
	client  *http.Client

	healthMu   sync.Mutex
	healthHang bool
	healthHit  chan struct{}
}

func newCrashRig(t *testing.T) *crashRig {
	t.Helper()
	if testing.Short() {
		t.Skip("builds and runs the agent binary")
	}
	if runtime.GOOS != "linux" {
		t.Skip("peer authentication on the agent socket is Linux-only")
	}
	// A short root: a Unix socket path is limited to ~104 bytes.
	dir, err := os.MkdirTemp("", "cmr-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	r := &crashRig{
		t: t, dir: dir,
		model:     filepath.Join(dir, "docker"),
		state:     filepath.Join(dir, "state"),
		sock:      filepath.Join(dir, "a.sock"),
		cfgPath:   filepath.Join(dir, "config.toml"),
		shimDir:   filepath.Join(dir, "bin"),
		healthHit: make(chan struct{}, 16),
	}
	for _, d := range []string{r.model, filepath.Join(r.model, "images"), filepath.Join(r.model, "by_digest"), r.shimDir, filepath.Join(dir, "compose")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	// Two local images; the proxy runs A and the fixed tag is on A.
	r.put("images/"+imgA, digA)
	r.put("images/"+imgB, digB)
	r.put("by_digest/"+digA, imgA)
	r.put("by_digest/"+digB, imgB)
	r.put("running", imgA)
	r.put("pinned", imgA)

	script := strings.NewReplacer("__STATE__", r.model, "__REPO__", crashRepo).Replace(fakeDockerScript)
	if err := os.WriteFile(filepath.Join(r.shimDir, "docker"), []byte(script), 0o700); err != nil { // #nosec G306 -- must be executable
		t.Fatal(err)
	}

	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.healthMu.Lock()
		hang := r.healthHang
		r.healthMu.Unlock()
		if hang {
			select {
			case r.healthHit <- struct{}{}:
			default:
			}
			time.Sleep(4 * time.Second) // longer than the probe's per-request timeout
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(hs.Close)

	cfg := fmt.Sprintf(`compose_project_dir = %q
compose_file = "docker-compose.yml"
socket_path = %q
state_dir = %q
privilege_mode = "docker_group_lab"
health_base_url = %q
operation_timeout = "2m"
stage_timeout = "1m"
interrupted_settle = "0s"
allowed_backup_dir = "/backup"
image_allowlist = '^registry\.test/agentb/proxy(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$'
proxy_repo = %q
allow_peers = [%q]
`, filepath.Join(dir, "compose"), r.sock, r.state, hs.URL, crashRepo, strconv.Itoa(os.Geteuid()))
	if err := os.WriteFile(r.cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	r.client = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", r.sock)
			},
		},
	}
	t.Cleanup(r.kill)
	return r
}

func (r *crashRig) put(name, content string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.model, name), []byte(content+"\n"), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *crashRig) read(name string) string {
	b, err := os.ReadFile(filepath.Join(r.model, name)) // #nosec G304 -- test-owned temp dir
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// launch starts the agent without waiting for it to serve.
func (r *crashRig) launch() {
	r.t.Helper()
	r.logs = &bytes.Buffer{}
	// Background context on purpose: the process is ended by kill(), which is the
	// crash under test, not by a deadline.
	cmd := exec.CommandContext(context.Background(), agentBinary(r.t), "--config", r.cfgPath) // #nosec G204 -- test-built binary, test-owned config
	cmd.Env = append(os.Environ(), "PATH="+r.shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.Stdout = r.logs
	cmd.Stderr = r.logs
	if err := cmd.Start(); err != nil {
		r.t.Fatalf("start agent: %v", err)
	}
	r.cmd = cmd
}

// start launches the agent and waits until it answers on the socket.
func (r *crashRig) start() {
	r.t.Helper()
	r.launch()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if code, _ := r.tryGet("/v1/health", nil); code == http.StatusOK {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	r.t.Fatalf("agent did not serve within the budget; output:\n%s", r.logs.String())
}

// kill is the crash: SIGKILL, no drain, no deferred cleanup. It also reaps the
// model command the agent was blocked in, which the kernel reparents rather
// than kills.
func (r *crashRig) kill() {
	if r.cmd != nil && r.cmd.Process != nil {
		_ = r.cmd.Process.Signal(syscall.SIGKILL)
		_ = r.cmd.Wait()
		r.cmd = nil
	}
	if pid, err := strconv.Atoi(r.read("blocked")); err == nil && pid > 1 {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	_ = os.Remove(filepath.Join(r.model, "blocked"))
	_ = os.Remove(filepath.Join(r.model, "block_on"))
}

func (r *crashRig) tryGet(path string, out interface{}) (int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://agent"+path, http.NoBody)
	if err != nil {
		return 0, err
	}
	resp, err := r.client.Do(req)
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

func (r *crashRig) get(path string, out interface{}) int {
	r.t.Helper()
	code, err := r.tryGet(path, out)
	if err != nil {
		r.t.Fatalf("GET %s: %v", path, err)
	}
	return code
}

func (r *crashRig) post(path string, body map[string]interface{}, out interface{}) int {
	r.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		r.t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://agent"+path, bytes.NewReader(raw))
	if err != nil {
		r.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		r.t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil {
		if derr := json.NewDecoder(resp.Body).Decode(out); derr != nil {
			r.t.Fatalf("POST %s: decode: %v", path, derr)
		}
	}
	return resp.StatusCode
}

type opView struct {
	OpID          string                 `json:"op_id"`
	Kind          string                 `json:"kind"`
	State         string                 `json:"state"`
	FailureReason string                 `json:"failure_reason"`
	StartedAt     time.Time              `json:"started_at"`
	Result        map[string]interface{} `json:"result"`
}

// applyUpgrade submits an upgrade to image B and returns the op id.
func (r *crashRig) applyUpgrade() string {
	r.t.Helper()
	var op opView
	if code := r.post("/v1/upgrades/apply", map[string]interface{}{"image_ref": refB}, &op); code != http.StatusAccepted {
		r.t.Fatalf("apply: HTTP %d; agent output:\n%s", code, r.logs.String())
	}
	return op.OpID
}

// crashAt drives a real upgrade to image B, lets it run until `point`, and
// SIGKILLs the agent there. point is "<command>:<nth>" for the Docker model, or
// "health" for the health gate.
func (r *crashRig) crashAt(point string) string {
	r.t.Helper()
	if point == "health" {
		r.healthMu.Lock()
		r.healthHang = true
		r.healthMu.Unlock()
	} else {
		r.put("block_on", point)
	}
	opID := r.applyUpgrade()
	deadline := time.Now().Add(30 * time.Second)
	reached := false
	for !reached && time.Now().Before(deadline) {
		if point == "health" {
			select {
			case <-r.healthHit:
				reached = true
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		if _, err := os.Stat(filepath.Join(r.model, "blocked")); err == nil {
			reached = true
			continue
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !reached {
		r.t.Fatalf("the apply flow never reached %q; agent output:\n%s\ncalls:\n%s", point, r.logs.String(), r.read("calls.log"))
	}
	r.kill()
	r.healthMu.Lock()
	r.healthHang = false
	r.healthMu.Unlock()
	return opID
}

// waitOp polls an op to a terminal state.
func (r *crashRig) waitOp(opID string) opView {
	r.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var op opView
	for time.Now().Before(deadline) {
		op = opView{}
		if code := r.get("/v1/operations/"+opID, &op); code == http.StatusOK && (op.State == "succeeded" || op.State == "failed") {
			return op
		}
		time.Sleep(50 * time.Millisecond)
	}
	r.t.Fatalf("op %s did not finish (last state %q); agent output:\n%s", opID, op.State, r.logs.String())
	return op
}

// mutatingCalls returns the state-changing docker commands the model saw.
func (r *crashRig) mutatingCalls() []string {
	var out []string
	for _, line := range strings.Split(r.read("calls.log"), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch {
		case f[0] == "pull", f[0] == "tag":
			out = append(out, line)
		case f[0] == "compose" && len(f) > 3 && (f[3] == "up" || f[3] == "down"):
			out = append(out, line)
		}
	}
	return out
}

func (r *crashRig) clearCalls() { _ = os.Remove(filepath.Join(r.model, "calls.log")) }

// waitJournal polls until the journal holds exactly the wanted op ids. An op is
// visible as terminal a moment before its own record is removed, so a check
// made right after waitOp has to allow for that.
func (r *crashRig) waitJournal(want ...string) []string {
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := r.journalFiles()
		if strings.Join(got, ",") == strings.Join(want, ",") {
			return got
		}
		if time.Now().After(deadline) {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// journalFiles lists the op ids with a live journal record.
func (r *crashRig) journalFiles() []string {
	ents, _ := os.ReadDir(filepath.Join(r.state, "reconcile"))
	var out []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".json") {
			out = append(out, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	return out
}

type interruptedView struct {
	OpID            string `json:"op_id"`
	Kind            string `json:"kind"`
	JournalPhase    string `json:"journal_phase"`
	DockerState     string `json:"docker_state"`
	TargetRef       string `json:"target_ref"`
	PriorRef        string `json:"prior_ref"`
	RefsValid       bool   `json:"refs_valid"`
	AgentStartsSeen int    `json:"agent_starts_seen"`
	RunningImage    string `json:"running_image"`
	DockerActed     *bool  `json:"docker_reconciled"`
	OperatorAction  string `json:"operator_action"`
}

type statusView struct {
	Interrupted []interruptedView `json:"interrupted_operations"`
	PinnedTag   *struct {
		ImageID        string `json:"image_id"`
		MatchesRunning *bool  `json:"matches_running"`
	} `json:"pinned_tag"`
}

type auditView struct {
	Events []struct {
		OpID          string                 `json:"op_id"`
		Outcome       string                 `json:"outcome"`
		FailureReason string                 `json:"failure_reason"`
		Params        map[string]interface{} `json:"params"`
	} `json:"events"`
}

func (r *crashRig) interruptedAudits(opID string) int {
	r.t.Helper()
	var av auditView
	if code := r.get("/v1/audit?limit=1000", &av); code != http.StatusOK {
		r.t.Fatalf("audit: HTTP %d", code)
	}
	n := 0
	for _, e := range av.Events {
		if e.OpID == opID && e.Outcome == "failed" && e.FailureReason == "agent_restart_interrupted" {
			n++
		}
	}
	return n
}

// killPoint is one place the apply flow can be killed, and what must be true
// afterwards.
type killPoint struct {
	name        string
	point       string
	phase       string
	dockerState string
	wantPinned  string // image the fixed tag is on after the crash
	wantRunning string // image the container runs after the crash
	runningIs   string // how the report must classify the running image
	refs        bool   // a prior ref is known by this point
	target      bool   // a target ref is known by this point
}

func killPoints() []killPoint {
	return []killPoint{
		{"admitted_at_capture", "ps:1", "admitted", "unchanged", imgA, imgA, "unknown", false, false},
		{"captured_at_resolve", "manifest:1", "captured", "unchanged", imgA, imgA, "prior", true, false},
		{"resolved_at_pull", "pull:1", "resolved", "unchanged", imgA, imgA, "prior", true, true},
		{"barrier_before_tag", "tag_before:1", "restarting", "indeterminate", imgA, imgA, "prior", true, true},
		{"tag_moved_before_up", "up_before:1", "restarting", "indeterminate", imgB, imgA, "prior", true, true},
		{"up_done_unrecorded", "up_after:1", "restarting", "indeterminate", imgB, imgB, "target", true, true},
		{"restarted_at_health_gate", "health", "restarted", "indeterminate", imgB, imgB, "target", true, true},
		{"restarted_at_verify", "ps:3", "restarted", "indeterminate", imgB, imgB, "target", true, true},
	}
}

// assertInterruptedOp: the op answers, as failed and never as succeeded, and
// says how far it got.
func assertInterruptedOp(t *testing.T, r *crashRig, opID, phase, dockerState string) {
	t.Helper()
	var op opView
	if code := r.get("/v1/operations/"+opID, &op); code != http.StatusOK {
		t.Fatalf("GET op after restart: HTTP %d", code)
	}
	if op.State != "failed" || op.FailureReason != "agent_restart_interrupted" {
		t.Errorf("op = %s(%s), want failed(agent_restart_interrupted)", op.State, op.FailureReason)
	}
	intr, _ := op.Result["interrupted"].(map[string]interface{}) //nolint:errcheck // absent → nil map, asserted below
	if intr["journal_phase"] != phase {
		t.Errorf("op.result.interrupted.journal_phase = %v, want %q", intr["journal_phase"], phase)
	}
	if intr["docker_state"] != dockerState {
		t.Errorf("op.result.interrupted.docker_state = %v, want %q", intr["docker_state"], dockerState)
	}
}

// assertInterruptedStatus: /v1/status carries the same report from the journal,
// plus what Docker says now.
func assertInterruptedStatus(t *testing.T, r *crashRig, opID string, tc *killPoint) {
	t.Helper()
	var st statusView
	if code := r.get("/v1/status", &st); code != http.StatusOK {
		t.Fatalf("status: HTTP %d", code)
	}
	if len(st.Interrupted) != 1 {
		t.Fatalf("status.interrupted_operations has %d entries, want 1", len(st.Interrupted))
	}
	got := st.Interrupted[0]
	if got.OpID != opID || got.JournalPhase != tc.phase || got.DockerState != tc.dockerState {
		t.Errorf("status entry = %+v, want op %s phase %s docker_state %s", got, opID, tc.phase, tc.dockerState)
	}
	if got.DockerActed == nil || *got.DockerActed {
		t.Errorf("status entry must state docker_reconciled=false, got %v", got.DockerActed)
	}
	if got.OperatorAction == "" {
		t.Error("status entry carries no operator_action")
	}
	if got.RefsValid != tc.refs {
		t.Errorf("refs_valid = %v, want %v", got.RefsValid, tc.refs)
	}
	if tc.refs && got.PriorRef != refA {
		t.Errorf("prior_ref = %q, want %q (what a rollback would name)", got.PriorRef, refA)
	}
	if tc.target && got.TargetRef != refB {
		t.Errorf("target_ref = %q, want %q", got.TargetRef, refB)
	}
	if got.RunningImage != tc.runningIs {
		t.Errorf("running_image = %q, want %q", got.RunningImage, tc.runningIs)
	}
	if st.PinnedTag == nil || st.PinnedTag.MatchesRunning == nil {
		t.Fatalf("status.pinned_tag missing while an interrupted op is outstanding")
	}
	if want := tc.wantPinned == tc.wantRunning; *st.PinnedTag.MatchesRunning != want {
		t.Errorf("pinned_tag.matches_running = %v, want %v", *st.PinnedTag.MatchesRunning, want)
	}
}

// TestCrashRecovery_EveryKillPoint SIGKILLs a real upgrade at each reachable
// point of the apply flow and restarts the agent. Per point it asserts what the
// operator can then see, and that the restart itself left Docker alone.
func TestCrashRecovery_EveryKillPoint(t *testing.T) {
	cases := killPoints()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newCrashRig(t)
			r.start()
			opID := r.crashAt(tc.point)

			if got := r.read("pinned"); got != tc.wantPinned {
				t.Fatalf("model: fixed tag on %.8s, want %.8s", got, tc.wantPinned)
			}
			if got := r.read("running"); got != tc.wantRunning {
				t.Fatalf("model: container on %.8s, want %.8s", got, tc.wantRunning)
			}
			if files := r.journalFiles(); len(files) != 1 || files[0] != opID {
				t.Fatalf("journal after the crash = %v, want exactly [%s]", files, opID)
			}

			r.clearCalls()
			r.start()
			assertInterruptedOp(t, r, opID, tc.phase, tc.dockerState)
			assertInterruptedStatus(t, r, opID, &tc)

			// One durable audit entry for the interruption.
			if n := r.interruptedAudits(opID); n != 1 {
				t.Errorf("audit has %d failed(agent_restart_interrupted) entries for the op, want 1", n)
			}
			// Startup, and the reads above, changed nothing in Docker.
			if m := r.mutatingCalls(); len(m) != 0 {
				t.Errorf("restart issued state-changing docker commands: %v", m)
			}
			if r.read("pinned") != tc.wantPinned || r.read("running") != tc.wantRunning {
				t.Errorf("Docker changed across the restart: tag %.8s container %.8s", r.read("pinned"), r.read("running"))
			}
		})
	}
}

// TestCrashRecovery_RepeatedRestartsAreIdempotent: the agent crashes again
// (twice) after the interruption was reported. The report must survive, count
// the starts, and the audit trail must not grow.
func TestCrashRecovery_RepeatedRestartsAreIdempotent(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	opID := r.crashAt("up_before:1")
	r.clearCalls()

	for i := 1; i <= 3; i++ {
		r.start()
		var st statusView
		r.get("/v1/status", &st)
		if len(st.Interrupted) != 1 || st.Interrupted[0].OpID != opID {
			t.Fatalf("start %d: status.interrupted_operations = %+v, want the one interrupted op", i, st.Interrupted)
		}
		if st.Interrupted[0].AgentStartsSeen != i {
			t.Errorf("start %d: agent_starts_seen = %d", i, st.Interrupted[0].AgentStartsSeen)
		}
		if n := r.interruptedAudits(opID); n != 1 {
			t.Errorf("start %d: %d interruption audit entries, want exactly 1", i, n)
		}
		var op opView
		if code := r.get("/v1/operations/"+opID, &op); code != http.StatusOK || op.State != "failed" {
			t.Errorf("start %d: op HTTP %d state %q, want 200 failed", i, code, op.State)
		}
		r.kill()
	}
	if m := r.mutatingCalls(); len(m) != 0 {
		t.Errorf("state-changing docker commands across three restarts: %v, want none", m)
	}
}

// TestCrashRecovery_StartedAtIsTheOperationsOwn: the reported op keeps the time
// it was actually started, not the time of the restart that found it.
func TestCrashRecovery_StartedAtIsTheOperationsOwn(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	before := time.Now()
	opID := r.crashAt("pull:1")
	time.Sleep(1200 * time.Millisecond)
	restartAt := time.Now()
	r.start()
	var op opView
	r.get("/v1/operations/"+opID, &op)
	if op.StartedAt.Before(before.Add(-time.Second)) || !op.StartedAt.Before(restartAt) {
		t.Errorf("started_at = %s, want the original admission time (between %s and %s)",
			op.StartedAt.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano), restartAt.Format(time.RFC3339Nano))
	}
}

// TestCrashRecovery_NewUpgradeConvergesAndRetiresTheRecord: after a crash that
// left the fixed tag ahead of the container, the operator re-submits. The new
// op must be admitted, must converge Docker under the health gate, and its
// success must retire the old record so later restarts stop reporting it.
func TestCrashRecovery_NewUpgradeConvergesAndRetiresTheRecord(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	oldOp := r.crashAt("up_before:1")
	r.start()

	newOp := r.applyUpgrade()
	if newOp == oldOp {
		t.Fatal("the re-submitted upgrade reused the interrupted op id")
	}
	if op := r.waitOp(newOp); op.State != "succeeded" {
		t.Fatalf("re-submitted upgrade = %s(%s); agent output:\n%s", op.State, op.FailureReason, r.logs.String())
	}
	if r.read("running") != imgB || r.read("pinned") != imgB {
		t.Fatalf("after the re-submitted upgrade: tag %.8s container %.8s, want both on the target", r.read("pinned"), r.read("running"))
	}
	if files := r.waitJournal(); len(files) != 0 {
		t.Errorf("journal still holds %v after a later upgrade succeeded", files)
	}
	var st statusView
	r.get("/v1/status", &st)
	if len(st.Interrupted) != 0 {
		t.Errorf("status still lists %d interrupted op(s) after a later upgrade succeeded", len(st.Interrupted))
	}

	// A later restart must not resurrect the old op as a fresh failure.
	r.kill()
	r.start()
	if code := r.get("/v1/operations/"+oldOp, nil); code != http.StatusNotFound {
		t.Errorf("superseded op after a later restart: HTTP %d, want 404 (not re-reported)", code)
	}
	if n := r.interruptedAudits(oldOp); n != 1 {
		t.Errorf("superseded op has %d interruption audit entries, want the original 1", n)
	}
}

// TestCrashRecovery_RollbackToPriorRepinsTheTag: the other operator answer to a
// tag left ahead of the container. An image rollback to the reported prior_ref
// must put the tag back and retire the record.
func TestCrashRecovery_RollbackToPriorRepinsTheTag(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	r.crashAt("up_before:1")
	r.start()

	var st statusView
	r.get("/v1/status", &st)
	if len(st.Interrupted) != 1 || st.Interrupted[0].PriorRef != refA {
		t.Fatalf("status does not name the rollback target: %+v", st.Interrupted)
	}
	var op opView
	if code := r.post("/v1/rollbacks", map[string]interface{}{"mode": "image", "image_ref": st.Interrupted[0].PriorRef}, &op); code != http.StatusAccepted {
		t.Fatalf("rollback: HTTP %d", code)
	}
	if done := r.waitOp(op.OpID); done.State != "succeeded" {
		t.Fatalf("rollback = %s(%s); agent output:\n%s", done.State, done.FailureReason, r.logs.String())
	}
	if r.read("pinned") != imgA || r.read("running") != imgA {
		t.Errorf("after rollback: tag %.8s container %.8s, want both on the prior image", r.read("pinned"), r.read("running"))
	}
	if files := r.waitJournal(); len(files) != 0 {
		t.Errorf("journal still holds %v after the rollback succeeded", files)
	}
}

// TestCrashRecovery_AlreadyCurrentUpgradeDoesNotRetire: with the tag ahead of
// the container, "upgrading" to the image that is already running is a no-op
// success that never re-pins the tag. It must NOT retire the record: the
// hazard it reports is still there.
func TestCrashRecovery_AlreadyCurrentUpgradeDoesNotRetire(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	oldOp := r.crashAt("up_before:1")
	r.start()

	var op opView
	if code := r.post("/v1/upgrades/apply", map[string]interface{}{"image_ref": refA}, &op); code != http.StatusAccepted {
		t.Fatalf("apply: HTTP %d", code)
	}
	if done := r.waitOp(op.OpID); done.State != "succeeded" {
		t.Fatalf("already-current upgrade = %s(%s)", done.State, done.FailureReason)
	}
	if r.read("pinned") != imgB || r.read("running") != imgA {
		t.Fatalf("model: tag %.8s container %.8s; this case needs the tag still ahead", r.read("pinned"), r.read("running"))
	}
	if files := r.waitJournal(oldOp); len(files) != 1 || files[0] != oldOp {
		t.Errorf("journal = %v, want the interrupted record kept (the tag is still ahead of the container)", files)
	}
	var st statusView
	r.get("/v1/status", &st)
	if len(st.Interrupted) != 1 || st.PinnedTag == nil || st.PinnedTag.MatchesRunning == nil || *st.PinnedTag.MatchesRunning {
		t.Errorf("status must keep reporting the interrupted op and the tag/container mismatch: %+v pinned=%+v", st.Interrupted, st.PinnedTag)
	}
}

// TestCrashRecovery_DockerUnavailableAtStartup: the daemon is down when the
// agent comes back (host reboot ordering). Startup must not depend on it.
func TestCrashRecovery_DockerUnavailableAtStartup(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	opID := r.crashAt("up_before:1")
	r.put("docker_down", "1")
	r.start()

	var op opView
	if code := r.get("/v1/operations/"+opID, &op); code != http.StatusOK || op.FailureReason != "agent_restart_interrupted" {
		t.Errorf("op with Docker down: HTTP %d reason %q", code, op.FailureReason)
	}
	var st statusView
	if code := r.get("/v1/status", &st); code != http.StatusOK {
		t.Fatalf("status with Docker down: HTTP %d", code)
	}
	if len(st.Interrupted) != 1 || st.Interrupted[0].JournalPhase != "restarting" {
		t.Errorf("status with Docker down must still list the interrupted op from the journal: %+v", st.Interrupted)
	}
	if len(st.Interrupted) == 1 && st.Interrupted[0].RunningImage != "unknown" {
		t.Errorf("running_image with Docker down = %q, want \"unknown\" (never a guess)", st.Interrupted[0].RunningImage)
	}
}

// TestCrashRecovery_ForgedRecordRefsAreNotRepeated: the journal is a file on
// disk. A record whose refs do not pass the repo-bound digest gate must be
// reported without echoing them as a rollback target.
func TestCrashRecovery_ForgedRecordRefsAreNotRepeated(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	opID := r.crashAt("up_before:1")

	path := filepath.Join(r.state, "reconcile", opID+".json")
	raw, err := os.ReadFile(path) // #nosec G304 -- test-owned temp dir
	if err != nil {
		t.Fatal(err)
	}
	forged := strings.ReplaceAll(string(raw), crashRepo+"@sha256:"+digA, "evil.example/malware@sha256:"+digA)
	if forged == string(raw) {
		t.Fatal("the record did not carry the prior ref to forge")
	}
	if err := os.WriteFile(path, []byte(forged), 0o600); err != nil { // #nosec G703 -- test-owned temp dir
		t.Fatal(err)
	}
	r.start()

	var st statusView
	r.get("/v1/status", &st)
	if len(st.Interrupted) != 1 {
		t.Fatalf("status.interrupted_operations = %+v", st.Interrupted)
	}
	got := st.Interrupted[0]
	if got.RefsValid || got.PriorRef != "" || got.TargetRef != "" {
		t.Errorf("a record that fails the ref gate must report refs_valid=false and no refs; got valid=%v prior=%q target=%q", got.RefsValid, got.PriorRef, got.TargetRef)
	}
	body, _ := json.Marshal(st)
	if strings.Contains(string(body), "evil.example") {
		t.Errorf("status repeated a ref that failed validation: %s", body)
	}
}

// TestCrashRecovery_CorruptRecordRefusesToServe pins the existing fail-closed
// posture: an unreadable record stops startup with a message naming the file.
// (Whether to quarantine instead is an open owner decision, ADR-0061.)
func TestCrashRecovery_CorruptRecordRefusesToServe(t *testing.T) {
	for name, content := range map[string]string{
		"truncated":     `{"op_id":"01HZZZZZZZZZZZZZZZZZZZZZZZ","kind":"upgrades.apply","pha`,
		"empty":         ``,
		"unknown_phase": `{"op_id":"01HZZZZZZZZZZZZZZZZZZZZZZZ","kind":"upgrades.apply","phase":"reconciling"}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := newCrashRig(t)
			if err := os.MkdirAll(filepath.Join(r.state, "reconcile"), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(r.state, "reconcile", "01HZZZZZZZZZZZZZZZZZZZZZZZ.json"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			r.launch()
			done := make(chan error, 1)
			go func() { done <- r.cmd.Wait() }()
			select {
			case err := <-done:
				r.cmd = nil
				if err == nil {
					t.Fatalf("agent exited 0 on a corrupt record; output:\n%s", r.logs.String())
				}
			case <-time.After(20 * time.Second):
				t.Fatalf("agent kept running on a corrupt record; output:\n%s", r.logs.String())
			}
			if out := r.logs.String(); !strings.Contains(out, "refusing to serve") || !strings.Contains(out, "01HZZZZZZZZZZZZZZZZZZZZZZZ.json") {
				t.Errorf("refusal must say so and name the file; got:\n%s", out)
			}
			if m := r.mutatingCalls(); len(m) != 0 {
				t.Errorf("a refused start issued docker commands: %v", m)
			}
		})
	}
}

// TestCrashRecovery_StrayFilesDoNotBlockStartup: leftovers that are not records
// (a temp file from a write the crash cut short, an editor backup) are ignored.
func TestCrashRecovery_StrayFilesDoNotBlockStartup(t *testing.T) {
	r := newCrashRig(t)
	dir := filepath.Join(r.state, "reconcile")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".journal-123.tmp", "notes.txt", "01HZZZZZZZZZZZZZZZZZZZZZZZ.json.bak"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r.start()
	var st statusView
	if code := r.get("/v1/status", &st); code != http.StatusOK || len(st.Interrupted) != 0 {
		t.Errorf("status HTTP %d interrupted=%+v, want 200 and none", code, st.Interrupted)
	}
}

// rewritePhase sets the phase of opID's record, for the two phases no kill
// point can freeze: both are followed by another journal write with no docker
// command in between.
func (r *crashRig) rewritePhase(opID, from, to string) {
	r.t.Helper()
	path := filepath.Join(r.state, "reconcile", opID+".json")
	raw, err := os.ReadFile(path) // #nosec G304 -- test-owned temp dir
	if err != nil {
		r.t.Fatal(err)
	}
	out := strings.Replace(string(raw), `"phase": "`+from+`"`, `"phase": "`+to+`"`, 1)
	if out == string(raw) {
		r.t.Fatalf("record is not at phase %q:\n%s", from, raw)
	}
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil { // #nosec G703 -- test-owned temp dir
		r.t.Fatal(err)
	}
}

// TestCrashRecovery_PulledAndVerifiedPhases covers the last safe boundary and
// the last phase before success.
func TestCrashRecovery_PulledAndVerifiedPhases(t *testing.T) {
	for _, tc := range []struct{ name, point, from, to, dockerState string }{
		{"pulled", "pull:1", "resolved", "pulled", "unchanged"},
		{"verified", "ps:3", "restarted", "verified", "indeterminate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newCrashRig(t)
			r.start()
			opID := r.crashAt(tc.point)
			r.rewritePhase(opID, tc.from, tc.to)
			r.clearCalls()
			r.start()
			var st statusView
			r.get("/v1/status", &st)
			if len(st.Interrupted) != 1 || st.Interrupted[0].JournalPhase != tc.to || st.Interrupted[0].DockerState != tc.dockerState {
				t.Errorf("status = %+v, want phase %s docker_state %s", st.Interrupted, tc.to, tc.dockerState)
			}
			var op opView
			r.get("/v1/operations/"+opID, &op)
			if op.State != "failed" {
				t.Errorf("a %s op must be reported failed, never succeeded; got %q", tc.to, op.State)
			}
			if m := r.mutatingCalls(); len(m) != 0 {
				t.Errorf("restart issued state-changing docker commands: %v", m)
			}
		})
	}
}

// TestCrashRecovery_InterruptedImageRollback: an image rollback records no
// phase beyond admission although it moves the tag, so its report must not
// claim Docker is unchanged.
func TestCrashRecovery_InterruptedImageRollback(t *testing.T) {
	r := newCrashRig(t)
	r.put("running", imgB)
	r.put("pinned", imgB)
	r.start()
	r.put("block_on", "up_before:1")
	var op opView
	if code := r.post("/v1/rollbacks", map[string]interface{}{"mode": "image", "image_ref": refA}, &op); code != http.StatusAccepted {
		t.Fatalf("rollback: HTTP %d", code)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(r.model, "blocked")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rollback never reached the restart; agent output:\n%s", r.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.kill()
	if r.read("pinned") != imgA || r.read("running") != imgB {
		t.Fatalf("model: tag %.8s container %.8s; want the tag moved and the container not", r.read("pinned"), r.read("running"))
	}
	r.start()

	var st statusView
	r.get("/v1/status", &st)
	if len(st.Interrupted) != 1 {
		t.Fatalf("status.interrupted_operations = %+v", st.Interrupted)
	}
	got := st.Interrupted[0]
	if got.Kind != "rollbacks.create" || got.JournalPhase != "admitted" || got.DockerState != "indeterminate" {
		t.Errorf("entry = %+v, want rollbacks.create at admitted reported indeterminate", got)
	}
	if got.TargetRef != refA || got.RunningImage != "other" {
		t.Errorf("target_ref = %q running_image = %q, want the rollback target and \"other\"", got.TargetRef, got.RunningImage)
	}
	if st.PinnedTag == nil || st.PinnedTag.MatchesRunning == nil || *st.PinnedTag.MatchesRunning {
		t.Errorf("pinned_tag must report the mismatch: %+v", st.PinnedTag)
	}
}

// TestCrashRecovery_FailedRecoveryKeepsTheRecord: the operator's rollback after
// a crash fails (the previous image is gone and cannot be pulled). The
// interrupted record must stay, and nothing may have been moved.
func TestCrashRecovery_FailedRecoveryKeepsTheRecord(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	oldOp := r.crashAt("up_before:1")
	r.put("pull_fail", "1")
	r.start()
	r.clearCalls()

	var op opView
	if code := r.post("/v1/rollbacks", map[string]interface{}{"mode": "image", "image_ref": refA}, &op); code != http.StatusAccepted {
		t.Fatalf("rollback: HTTP %d", code)
	}
	if done := r.waitOp(op.OpID); done.State != "failed" {
		t.Fatalf("rollback with an unpullable image = %q, want failed", done.State)
	}
	if files := r.waitJournal(oldOp); len(files) != 1 || files[0] != oldOp {
		t.Errorf("journal = %v, want the interrupted record kept after a failed recovery", files)
	}
	if r.read("pinned") != imgB || r.read("running") != imgA {
		t.Errorf("a failed rollback moved Docker: tag %.8s container %.8s", r.read("pinned"), r.read("running"))
	}
	var st statusView
	r.get("/v1/status", &st)
	if len(st.Interrupted) != 1 || st.Interrupted[0].OpID != oldOp {
		t.Errorf("status must keep listing the interrupted op: %+v", st.Interrupted)
	}
}

// setSettle rewrites interrupted_settle in the rig's config. The rig runs with
// the wait off (0s) so that the crash tests measure what they are about; a
// test of the wait itself turns it on before the agent is (re)started.
func (r *crashRig) setSettle(d string) {
	r.t.Helper()
	b, err := os.ReadFile(r.cfgPath)
	if err != nil {
		r.t.Fatal(err)
	}
	const off = `interrupted_settle = "0s"`
	if !strings.Contains(string(b), off) {
		r.t.Fatal("rig config has no interrupted_settle line to rewrite")
	}
	out := strings.Replace(string(b), off, `interrupted_settle = "`+d+`"`, 1)
	if err := os.WriteFile(r.cfgPath, []byte(out), 0o600); err != nil { // #nosec G703 -- the rig's own config under t.TempDir
		r.t.Fatal(err)
	}
}
