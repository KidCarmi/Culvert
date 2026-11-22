//go:build lifecycle_conformance

// Model-to-implementation conformance for the maintenance agent's upgrade lifecycle.
//
// SHADOW / NON-BLOCKING. This file is test-only and changes no production behaviour. The
// `lifecycle_conformance` build tag keeps it out of every existing gate: a plain `go test ./...`
// neither compiles nor runs it. It is driven by test/lifecycle-conformance/run.sh.
//
// It replays deterministic sequences derived in-process from an abstract model
// (internal/lifecyclemodel, same build tag) against the REAL Server, journal,
// orchestrator and runner, with only the process-exec layer and the health HTTP client faked.
// Fault injection happens only in that fake layer. The fake Docker is an ASSUMPTION about how
// Docker behaves (see test/lifecycle-conformance/README.md); a pass here is evidence about the
// agent's own logic, not about Docker.
//
// Reuses existing test helpers of this package: udsClient, pollOpOnce, waitTerminalAudit,
// fakeStatus, roundTripFunc, and the constants digOld/digNew/cfgOld/cfgNew/repo.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/config"
	"culvert-maint/internal/health"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/lifecyclemodel"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

const (
	digX = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	cfgX = "3333333333333333333333333333333333333333333333333333333333333333"
)

// The vectors come straight from the model: nothing is read from disk, so a suite can
// never be skipped (or look like a pass) for want of an input file.
type (
	planEntry  = lifecyclemodel.PlanEntry
	confParams = lifecyclemodel.Params
)

// confRig is a real Server over a fake Docker world: (running image, pinned tag).
type confRig struct {
	sock, stateDir, auditPath string
	jnl                       *journal.Journal

	mu        sync.Mutex
	running   string // digest hex, "" = no container
	tag       string
	nodigest  bool
	unhealthy map[string]bool
	counts    map[string]int
	plan      []planEntry
	tokens    []string
	failNext  bool

	block     *planEntry
	blocked   chan struct{}
	release   chan struct{}
	blockOnce sync.Once
	stop      func()
}

func role(d string) string {
	switch strings.TrimPrefix(d, "sha256:") {
	case digOld, cfgOld:
		return "P"
	case digNew, cfgNew:
		return "T"
	case "":
		return "none"
	}
	return "?"
}

func cfgOf(d string) string {
	if d == digNew {
		return cfgNew
	}
	return cfgOld
}

func classify(argv []string) string {
	has := func(tok string) bool {
		for _, a := range argv {
			if a == tok {
				return true
			}
		}
		return false
	}
	for _, a := range argv {
		if strings.Contains(a, "{{json .Image}}") {
			return "cinspect"
		}
	}
	switch {
	case has("ps"):
		return "ps"
	case has("manifest"):
		return "manifest"
	case has("image") && has("inspect"):
		return "iinspect"
	case has("pull"):
		return "pull"
	case has("tag"):
		return "tag"
	case has("up"):
		return "up"
	case has("backup") || has("--backup"):
		return "backup"
	}
	return ""
}

func argvDigest(argv []string) string {
	for _, a := range argv {
		if d := digestRE.FindString(a); d != "" {
			return strings.TrimPrefix(d, "sha256:")
		}
	}
	return ""
}

func (r *confRig) mode(key string, n int) string {
	for _, p := range r.plan {
		if p.Cmd == key && p.N == n {
			return p.Mode
		}
	}
	return ""
}

func (r *confRig) hold() {
	r.blockOnce.Do(func() { close(r.blocked) })
	<-r.release
}

// onStart emulates the command. Returns canned stdout.
func (r *confRig) onStart(cmd *exec.Cmd) error {
	key := classify(cmd.Args)
	r.mu.Lock()
	r.counts[key]++
	n := r.counts[key]
	dg := argvDigest(cmd.Args)
	switch key {
	case "ps":
		if len(r.tokens) == 0 || r.tokens[len(r.tokens)-1] != "capture" {
			r.tokens = append(r.tokens, "capture")
		}
	case "pull", "tag":
		r.tokens = append(r.tokens, key+":"+role(dg))
	case "manifest", "backup", "up":
		r.tokens = append(r.tokens, key)
	}
	blockHere := r.block != nil && r.block.Cmd == key && r.block.N == n
	r.mu.Unlock()
	if blockHere {
		r.hold()
		r.mu.Lock()
		r.failNext = true
		r.mu.Unlock()
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.mode(key, n)
	var out string
	switch key {
	case "ps":
		if m == "fail" {
			r.failNext = true
		} else if r.running == "" {
			out = `[]`
		} else {
			out = `{"Service":"proxy","State":"running","ID":"abcdef012345"}`
		}
	case "cinspect":
		out = `"sha256:` + cfgOf(r.running) + `"`
	case "iinspect":
		if r.nodigest && r.running == digOld {
			out = `[{"RepoDigests":[]}]`
		} else {
			out = `[{"RepoDigests":["` + repo + `@sha256:` + r.running + `"]}]`
		}
	case "manifest":
		out = `{"Descriptor":{"digest":"sha256:` + argvDigest(cmd.Args) + `"}}`
		if m == "fail" {
			r.failNext = true
		}
	case "backup":
		if m == "fail" {
			r.failNext = true
		}
	case "pull":
		if m == "fail" {
			r.failNext = true
		}
		if m == "corrupt_journal" {
			ents, _ := os.ReadDir(r.jnl.Dir())
			for _, e := range ents {
				_ = os.WriteFile(filepath.Join(r.jnl.Dir(), e.Name()), []byte("{not json"), 0o600)
			}
		}
	case "tag":
		if m == "fail" {
			r.failNext = true
		} else {
			r.tag = dg
		}
	case "up":
		switch m {
		case "fail_stale":
			r.failNext = true
		case "fail_recreated":
			r.running = r.tag
			r.failNext = true
		case "ok_stale":
		default:
			r.running = r.tag
		}
	}
	if out != "" {
		_, _ = cmd.Stdout.Write([]byte(out))
	}
	return nil
}

func (r *confRig) onWait(_ *exec.Cmd) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failNext {
		r.failNext = false
		return errors.New("simulated non-zero exit")
	}
	return nil
}

func (r *confRig) healthClient() *http.Client {
	return &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		r.mu.Lock()
		blockHere := r.block != nil && r.block.Cmd == "health" && r.block.N == r.counts["up"]
		r.mu.Unlock()
		if blockHere {
			r.hold()
		}
		r.mu.Lock()
		status := 200
		if blockHere || r.running == "" || r.unhealthy[r.running] {
			status = 503
		}
		r.mu.Unlock()
		return &http.Response{StatusCode: status, Status: strconv.Itoa(status) + " test",
			Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
	})}
}

func startConfRig(t *testing.T, p confParams, plan []planEntry, block *planEntry) *confRig {
	t.Helper()
	tmp, err := os.MkdirTemp("", "conf")
	if err != nil {
		t.Fatal(err)
	}
	r := &confRig{sock: filepath.Join(tmp, "a.sock"), stateDir: tmp, auditPath: filepath.Join(tmp, "audit.jsonl"),
		running: digOld, tag: digOld, nodigest: p.Prior == "nodigest", unhealthy: map[string]bool{},
		counts: map[string]int{}, plan: plan, block: block, blocked: make(chan struct{}), release: make(chan struct{})}
	if p.Prior == "down" {
		r.running = ""
	}
	if !p.TH && !p.Same {
		r.unhealthy[digNew] = true
	}
	if !p.PH {
		r.unhealthy[digOld] = true
	}
	al, err := audit.New(r.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := auth.NewPolicy([]string{strconv.Itoa(os.Geteuid())})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{ComposeProjectDir: tmp, ComposeFile: "docker-compose.yml", SocketPath: r.sock, StateDir: tmp,
		PrivilegeMode: config.PrivilegeSudoers, AllowedBackupDir: "/backup", StageTimeout: 20 * time.Second,
		OperationTimeout: 60 * time.Second,
		ImageAllowlist:   regexp.MustCompile(`^ghcr\.io/kidcarmi/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$`)}
	rn, err := runner.New(runner.Options{ComposeProjectDir: tmp, ComposeFile: "docker-compose.yml",
		StageTimeout: 20 * time.Second, ProxyRepo: repo, EnvAllow: []string{runner.EnvCulvertBackupPassphrase},
		EnvOverlayOnly: []string{runner.EnvCulvertBackupPassphrase}, DockerBinary: "/usr/bin/docker"})
	if err != nil {
		t.Fatal(err)
	}
	rn.SetExecHooksForTest(r.onStart, r.onWait)
	jnl, err := journal.New(tmp)
	if err != nil {
		t.Fatal(err)
	}
	r.jnl = jnl
	srv, err := New(Options{Cfg: cfg, Auth: pol, Audit: al, Ops: ops.NewManager(nil), Status: &fakeStatus{},
		StateDir: tmp, AuditPath: r.auditPath, Runner: rn, Journal: jnl,
		HealthProbeFactory: func() health.Probe {
			u, _ := url.Parse("http://127.0.0.1:8080")
			return health.Probe{BaseURL: u, HealthPath: "/health", ReadyPath: "/ready", Budget: 80 * time.Millisecond,
				PollInterval: 20 * time.Millisecond, RequestTimeout: 10 * time.Second, Client: r.healthClient()}
		}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	for i := 0; i < 100; i++ {
		if _, e := os.Stat(r.sock); e == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.stop = func() {
		cancel()
		_ = srv.Close()
		_ = al.Close()
		_ = os.RemoveAll(tmp)
	}
	return r
}

func (r *confRig) submit(t *testing.T, p confParams) string {
	t.Helper()
	target := digNew
	if p.Same {
		target = digOld
	}
	body := map[string]interface{}{"image_ref": repo + "@sha256:" + target, "rollback_on_failure": p.RB}
	if p.Backup {
		body["pre_backup"] = true
		body["passphrase_ref"] = "env:" + runner.EnvCulvertBackupPassphrase
	}
	bb, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://unix/v1/upgrades/apply", strings.NewReader(string(bb)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := udsClient(r.sock).Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d: %s", resp.StatusCode, rb)
	}
	var ack map[string]interface{}
	_ = json.Unmarshal(rb, &ack)
	id, _ := ack["op_id"].(string)
	return id
}

func (r *confRig) wait(t *testing.T, opID string) map[string]interface{} {
	t.Helper()
	cli := udsClient(r.sock)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if op := pollOpOnce(cli, opID); op != nil {
			waitTerminalAudit(t, r.auditPath, opID)
			return op
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("op %s did not finish", opID)
	return nil
}

func (r *confRig) world() (running, tag string, tokens []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return role(r.running), role(r.tag), append([]string(nil), r.tokens...)
}

// ───────────────────────── apply flow: every fault path to a terminal state

type applyExpectation = lifecyclemodel.ApplyExpectation

func scriptString(s []lifecyclemodel.ScriptStep) string {
	parts := make([]string, 0, len(s))
	for _, st := range s {
		if st[1] != "ok" && st[1] != "skip" {
			parts = append(parts, st[0]+"="+st[1])
		}
	}
	if len(parts) == 0 {
		return "no faults"
	}
	return strings.Join(parts, " -> ")
}

func TestModelConformance_ApplyFlow(t *testing.T) {
	vs, _ := lifecyclemodel.Vectors()
	if len(vs) == 0 {
		t.Fatal("no vectors: refusing to pass an empty conformance run")
	}
	_ = os.Setenv(runner.EnvCulvertBackupPassphrase, "test-pass")
	var mu sync.Mutex
	misreported, tagAhead := []string{}, 0
	t.Run("vectors", func(t *testing.T) {
		for i := range vs {
			v := vs[i]
			name := fmt.Sprintf("%03d", i)
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				r := startConfRig(t, v.Params, v.Plan, nil)
				defer r.stop()
				op := r.wait(t, r.submit(t, v.Params))
				running, tag, tokens := r.world()
				res, _ := op["result"].(map[string]interface{})
				reason, _ := op["failure_reason"].(string)
				got := applyExpectation{Op: fmt.Sprint(op["state"]), Reason: reason, Running: running, Tag: tag, Cmds: tokens,
					UpgradeSucceeded: res["upgrade_succeeded"] == true, RollbackAttempted: res["rollback_attempted"] == true,
					RollbackSucceeded:     res["rollback_succeeded"] == true,
					RollbackSkippedReason: fmt.Sprint(res["rollback_skipped_reason"]), TagAhead: v.Expect.TagAhead,
					JournalEmpty: v.Expect.JournalEmpty} // the journal itself is checked just below
				if !reflect.DeepEqual(got, v.Expect) {
					t.Errorf("MODEL/IMPLEMENTATION MISMATCH\n params: %+v\n faults: %s\n model : %+v\n actual: %+v",
						v.Params, scriptString(v.Script), v.Expect, got)
				}
				recs, lerr := r.jnl.List()
				if lerr != nil || len(recs) != 0 {
					t.Errorf("journal not empty at terminal (faults: %s): %d records, err=%v", scriptString(v.Script), len(recs), lerr)
				}
				rep := role(fmt.Sprint(res["final_running_digest"]))
				mu.Lock()
				if rep != running && !v.Params.Same {
					misreported = append(misreported, fmt.Sprintf("%s | prior=%s rb=%v | reported=%s actual=%s",
						scriptString(v.Script), v.Params.Prior, v.Params.RB, rep, running))
				}
				if tag == "T" && running != "T" && !v.Params.Same {
					tagAhead++
				}
				mu.Unlock()
			})
		}
	})
	writeReport(t, "apply", map[string]interface{}{"vectors": len(vs), "terminal_states_with_tag_ahead_of_container": tagAhead,
		"final_running_digest_differs_from_actual": misreported})
}

// ───────────────────────── crash points: journal record + reconcile verdict

func idRole(id string) string {
	if id == "" {
		return ""
	}
	return role(id)
}

func TestModelConformance_CrashPoints(t *testing.T) {
	_, vs := lifecyclemodel.Vectors()
	if len(vs) == 0 {
		t.Fatal("no vectors: refusing to pass an empty conformance run")
	}
	_ = os.Setenv(runner.EnvCulvertBackupPassphrase, "test-pass")
	var mu sync.Mutex
	adoptNotTarget := []string{}
	t.Run("vectors", func(t *testing.T) {
		for i := range vs {
			v := vs[i]
			t.Run(fmt.Sprintf("%03d", i), func(t *testing.T) {
				t.Parallel()
				blk := planEntry{Cmd: v.Block.Cmd, N: v.Block.N}
				r := startConfRig(t, v.Params, v.Plan, &blk)
				defer r.stop()
				opID := r.submit(t, v.Params)
				select {
				case <-r.blocked:
				case <-time.After(15 * time.Second):
					close(r.release)
					t.Fatalf("crash point never reached (faults: %s, block %+v)", scriptString(v.Script), v.Block)
				}
				// The agent is now frozen exactly where the model says it crashed.
				running, tag, tokens := r.world()
				if n := len(tokens); n > 0 && v.Block.Cmd != "health" { // the blocked command itself was recorded
					tokens = tokens[:n-1]
					if v.Block.Cmd == "ps" && (len(v.Expect.CmdsBeforeBlock) == 0 || v.Expect.CmdsBeforeBlock[len(v.Expect.CmdsBeforeBlock)-1] == "capture") &&
						len(tokens) < len(v.Expect.CmdsBeforeBlock) {
						tokens = append(tokens, "capture")
					}
				}
				recs, lerr := r.jnl.List()
				if lerr != nil || len(recs) != 1 {
					close(r.release)
					t.Fatalf("expected exactly one journal record at the crash point, got %d err=%v", len(recs), lerr)
				}
				rec := recs[0]
				valid, _ := validateReconcileRefs(&rec, repo)
				in := reconcileInputs{Kind: rec.Kind, Mode: rec.Mode, Phase: rec.Phase, Attempts: 0, MaxAttempts: 3, RefValid: valid,
					TargetImageID: rec.TargetImageID, PriorImageID: rec.PriorImageID}
				r.mu.Lock()
				if r.running != "" {
					in.RunningImageID = "sha256:" + cfgOf(r.running)
					if !(r.nodigest && r.running == digOld) {
						in.RunningDigests = []string{r.running}
					}
				}
				in.TagDigests = []string{r.tag}
				r.mu.Unlock()
				if rec.TargetDigest != "" {
					in.TargetDigests = []string{rec.TargetDigest}
				}
				if rec.PriorDigest != "" {
					in.PriorDigests = []string{rec.PriorDigest}
				}
				verdict := reconcileDecision(in)
				close(r.release)
				_ = r.wait(t, opID)

				type obs struct {
					Phase, Tag, Run, PriorID, TargetID, Action, Reason string
					PriorRef, TargetRef                                bool
				}
				got := obs{string(rec.Phase), tag, running, idRole(rec.PriorImageID), idRole(rec.TargetImageID),
					verdict.Action.String(), verdict.Reason, rec.PriorRef != "", rec.TargetRef != ""}
				want := obs{v.Expect.Phase, v.Expect.Tag, v.Expect.Running, v.Expect.Record.PriorID, v.Expect.Record.TargetID,
					v.Expect.ReconcileAction, v.Expect.ReconcileReason, v.Expect.Record.PriorRef, v.Expect.Record.TargetRef}
				if got != want {
					t.Errorf("MODEL/IMPLEMENTATION MISMATCH at crash point\n params: %+v\n trace : %s\n block : %+v\n model : %+v\n actual: %+v",
						v.Params, scriptString(v.Script), v.Block, want, got)
				}
				if verdict.Action == actVerifyAdoptElseRollback && running != "T" && !v.Params.Same {
					mu.Lock()
					adoptNotTarget = append(adoptNotTarget, fmt.Sprintf("%s | running=%s tag=%s TargetImageID=%s reason=%s",
						scriptString(v.Script), running, tag, idRole(rec.TargetImageID), verdict.Reason))
					mu.Unlock()
				}
			})
		}
	})
	writeReport(t, "crash", map[string]interface{}{"vectors": len(vs),
		"reconcile_says_target_live_but_container_is_not_on_target": adoptNotTarget})
}

// ───────────────────────── reconcile decision: full bounded input space

func symID(s string) string {
	switch s {
	case "P":
		return "sha256:" + cfgOld
	case "T":
		return "sha256:" + cfgNew
	case "X":
		return "sha256:" + cfgX
	}
	return ""
}

func symDigests(syms []string) []string {
	out := make([]string, 0, len(syms))
	for _, s := range syms {
		out = append(out, map[string]string{"P": digOld, "T": digNew, "X": digX}[s])
	}
	return out
}

// realReconcileInputs maps the model's symbolic input (P/T/X) onto the real function's input.
func realReconcileInputs(m lifecyclemodel.ReconcileInputs) reconcileInputs {
	return reconcileInputs{Kind: m.Kind, Mode: m.Mode, Phase: journal.Phase(m.Phase), Attempts: m.Attempts,
		MaxAttempts: m.MaxAttempts, RefValid: m.RefValid, RunningImageID: symID(m.RunningID),
		TargetImageID: symID(m.TargetID), PriorImageID: symID(m.PriorID), RunningDigests: symDigests(m.RunningDigests),
		TargetDigests: symDigests(m.TargetDigests), PriorDigests: symDigests(m.PriorDigests),
		TagDigests: symDigests(m.TagDigests)}
}

func flipPrefixes(in reconcileInputs) reconcileInputs {
	strip := func(s string) string { return strings.TrimPrefix(s, "sha256:") }
	add := func(ds []string) []string {
		out := make([]string, len(ds))
		for i, d := range ds {
			out[i] = "sha256:" + d
		}
		return out
	}
	in.RunningImageID, in.TargetImageID, in.PriorImageID = strip(in.RunningImageID), strip(in.TargetImageID), strip(in.PriorImageID)
	in.RunningDigests, in.TargetDigests, in.PriorDigests, in.TagDigests = add(in.RunningDigests), add(in.TargetDigests), add(in.PriorDigests), add(in.TagDigests)
	return in
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func TestModelConformance_ReconcileDecision(t *testing.T) {
	// Memory-light: one byte of expectation per input; each input is decoded on the fly.
	rv := lifecyclemodel.GenReconcileVectors()
	total := 1
	for _, d := range rv.Domains {
		total *= len(d.Values)
	}
	if total == 0 || total != len(rv.Expected) {
		t.Fatalf("vector table incomplete: %d inputs, %d expectations", total, len(rv.Expected))
	}
	idx := make([]int, len(rv.Domains))
	mismatches, propFails := 0, 0
	seen := map[string]int{}
	for n := 0; n < total; n++ {
		in := realReconcileInputs(lifecyclemodel.ReconcileInputAt(idx))
		v := reconcileDecision(in)
		seen[v.Reason]++
		// The verdict is the pair: a right reason with a wrong action is a mismatch.
		if wantAction, wantReason := rv.Verdict(n); v.Action.String() != wantAction || v.Reason != wantReason {
			if mismatches < 5 {
				t.Errorf("MODEL/IMPLEMENTATION MISMATCH #%d: input=%+v model=%s/%s actual=%s/%s",
					n, in, wantAction, wantReason, v.Action, v.Reason)
			}
			mismatches++
		}
		// Proposed properties, checked on the REAL function over the whole bounded space.
		fail := func(id, msg string) {
			if propFails < 10 {
				t.Errorf("PROPERTY %s violated: %s\n input=%+v verdict=%s/%s", id, msg, in, v.Action, v.Reason)
			}
			propFails++
		}
		data := in.Kind == ops.KindRollbackCreate && in.Mode == "data"
		exhausted := in.MaxAttempts > 0 && in.Attempts >= in.MaxAttempts
		tagOnTarget := intersects(in.TagDigests, in.TargetDigests)
		liveTarget := (in.RunningImageID != "" && in.RunningImageID == in.TargetImageID) || intersects(in.RunningDigests, in.TargetDigests)
		priorKnown := in.PriorImageID != "" || len(in.PriorDigests) > 0
		switch {
		case data && v.Action != actDataManual:
			fail("RP1", "a data rollback must never enter the image table")
		case !data && !in.RefValid && v.Action != actLoudStop:
			fail("RP2", "an unvalidated record must never drive a Docker action")
		case !data && in.RefValid && exhausted && v.Action != actLoudStop:
			fail("RP3", "exhausted reconcile attempts must stop loudly")
		}
		if v.Action == actRollbackToPrior && (!priorKnown || liveTarget || tagOnTarget) {
			fail("RP4", "rollback only with a known prior, target not live, tag not on target")
		}
		if v.Action == actNoop && tagOnTarget {
			fail("RP5", "never no-op while the tag is on the target")
		}
		if v.Action == actNoop && liveTarget {
			fail("RP6", "never no-op while the target is live")
		}
		if w := reconcileDecision(flipPrefixes(in)); w != v {
			fail("RP7", "verdict must not depend on sha256: prefixes")
		}
		rv.Advance(idx)
	}
	for _, r := range rv.Reasons { // vacuity: every verdict of the table must have been exercised
		if seen[r] == 0 {
			t.Errorf("VACUOUS: verdict %q never produced over the input space", r)
		}
	}
	writeReport(t, "reconcile", map[string]interface{}{"inputs": total, "mismatches": mismatches,
		"property_violations": propFails, "verdict_counts": seen})
}

func writeReport(t *testing.T, name string, body map[string]interface{}) {
	t.Helper()
	dir := os.Getenv("CULVERT_CONFORMANCE_REPORT")
	if dir == "" {
		return
	}
	for k, v := range body { // lists are reported unique and sorted, so the report is deterministic
		if l, ok := v.([]string); ok {
			set := map[string]bool{}
			for _, x := range l {
				set[x] = true
			}
			u := make([]string, 0, len(set))
			for x := range set {
				u = append(u, x)
			}
			sort.Strings(u)
			body[k] = u
		}
	}
	b, _ := json.MarshalIndent(body, "", " ")
	_ = os.WriteFile(filepath.Join(dir, "conformance_"+name+".json"), b, 0o600)
}
