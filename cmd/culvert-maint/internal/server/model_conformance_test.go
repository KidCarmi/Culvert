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
	"net"
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

	store string // imageStoreClassic | imageStoreContainerd: how Docker reports image identity

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

// Docker reports image identity differently per image store; both were measured on real
// Docker 29.10 with test/lifecycle-conformance/docker-probe.sh:
//   - classic (overlay2 graph driver; hosts upgraded from older Docker): container .Image is
//     the image CONFIG digest, distinct from the registry digest; a local tag whose registry
//     reference is gone has no RepoDigests at all.
//   - containerd image store (default for fresh Docker 29 installs): container .Image is the
//     registry (index) digest itself, and every local tag adds a synthetic
//     `<local repo>@sha256:<digest>` RepoDigest, so RepoDigests is never empty.
//
// The model's expectations are store-independent, so every apply and crash vector runs under
// both stores: a store-dependent decision in the agent is a MISMATCH. Observations made under
// the containerd store carry the "[containerd] " prefix in observed.json.
const (
	imageStoreClassic    = "classic"
	imageStoreContainerd = "containerd"
)

var imageStores = []string{imageStoreClassic, imageStoreContainerd}

func storePrefix(store string) string {
	if store == imageStoreContainerd {
		return "[containerd] "
	}
	return ""
}

func cfgOf(d string) string {
	if d == digNew {
		return cfgNew
	}
	return cfgOld
}

// imageID is what `docker inspect --format {{json .Image}}` reports for digest d.
func (r *confRig) imageID(d string) string {
	if r.store == imageStoreContainerd {
		return d
	}
	return cfgOf(d)
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

// record appends the command to the observed sequence. Caller holds r.mu.
func (r *confRig) record(key, dg string) {
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
}

// onStart emulates the command. Returns canned stdout.
func (r *confRig) onStart(cmd *exec.Cmd) error {
	key := classify(cmd.Args)
	dg := argvDigest(cmd.Args)
	r.mu.Lock()
	r.counts[key]++
	n := r.counts[key]
	r.record(key, dg)
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
	if out := r.emulate(key, r.mode(key, n), dg); out != "" {
		_, _ = cmd.Stdout.Write([]byte(out))
	}
	return nil
}

// emulate applies the command's effect on the fake Docker world under fault mode m and returns
// its stdout. Caller holds r.mu.
func (r *confRig) emulate(key, m, dg string) string {
	if m == "fail" { // the command exits non-zero and changes nothing
		r.failNext = true
		if key != "manifest" {
			return ""
		}
	}
	switch key {
	case "ps":
		if r.running == "" {
			return `[]`
		}
		return `{"Service":"proxy","State":"running","ID":"abcdef012345"}`
	case "cinspect":
		return `"sha256:` + r.imageID(r.running) + `"`
	case "iinspect":
		if r.store == imageStoreContainerd {
			local := `"culvert/proxy@sha256:` + r.running + `"`
			if r.nodigest && r.running == digOld { // built locally: only the synthetic local ref
				return `[{"RepoDigests":[` + local + `]}]`
			}
			return `[{"RepoDigests":[` + local + `,"` + repo + `@sha256:` + r.running + `"]}]`
		}
		if r.nodigest && r.running == digOld {
			return `[{"RepoDigests":[]}]`
		}
		return `[{"RepoDigests":["` + repo + `@sha256:` + r.running + `"]}]`
	case "manifest":
		return `{"Descriptor":{"digest":"sha256:` + dg + `"}}`
	case "pull":
		if m == "corrupt_journal" {
			r.corruptJournal()
		}
	case "tag":
		r.tag = dg
	case "up":
		r.emulateUp(m)
	}
	return ""
}

func (r *confRig) corruptJournal() {
	ents, _ := os.ReadDir(r.jnl.Dir())
	for _, e := range ents {
		_ = os.WriteFile(filepath.Join(r.jnl.Dir(), e.Name()), []byte("{not json"), 0o600)
	}
}

func (r *confRig) emulateUp(m string) {
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

func startConfRig(t *testing.T, store string, p confParams, plan []planEntry, block *planEntry) *confRig {
	t.Helper()
	tmp, err := os.MkdirTemp("", "conf")
	if err != nil {
		t.Fatal(err)
	}
	r := &confRig{store: store, sock: filepath.Join(tmp, "a.sock"), stateDir: tmp, auditPath: filepath.Join(tmp, "audit.jsonl"),
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
	// Wait until the agent ACCEPTS connections, not merely until the socket file exists: the
	// file appears at bind(), before listen(), and a connect in that window is refused. With
	// hundreds of rigs in parallel the window is hit (observed: "connect: connection refused").
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		dctx, dcancel := context.WithTimeout(context.Background(), time.Second)
		c, e := (&net.Dialer{}).DialContext(dctx, "unix", r.sock)
		dcancel()
		if e == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			_ = srv.Close()
			_ = al.Close()
			t.Fatalf("INCOMPLETE: agent socket %s never appeared", r.sock)
		}
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
	misreported, results, tagAhead := []string{}, []string{}, map[string]int{}
	acc := &applyObservations{misreported: &misreported, results: &results, tagAhead: tagAhead}
	for _, store := range imageStores {
		t.Run(store, func(t *testing.T) { applyVectorsUnder(t, store, vs, &mu, acc) })
	}
	if got, want := len(uniqueSorted(results)), len(vs)*len(imageStores); got != want {
		t.Errorf("INCOMPLETE: %d distinct result lines for %d vectors: the observation key is not unique", got, want)
	}
	drift := checkObserved(t, uniqueSorted(misreported), uniqueSorted(results))
	writeReport(t, "apply", map[string]interface{}{"vectors_per_image_store": len(vs),
		"terminal_states_with_tag_ahead_of_container":                  tagAhead[imageStoreClassic],
		"terminal_states_with_tag_ahead_of_container_containerd_store": tagAhead[imageStoreContainerd],
		"final_running_digest_differs_from_actual":                     misreported, "observed_drift": drift})
}

// applyObservations collects what the apply vectors observe on the real code, per store.
type applyObservations struct {
	misreported, results *[]string
	tagAhead             map[string]int
}

// applyVectorsUnder replays every apply vector under one Docker image store.
func applyVectorsUnder(t *testing.T, store string, vs []lifecyclemodel.ApplyVector, mu *sync.Mutex, acc *applyObservations) {
	pfx := storePrefix(store)
	for i := range vs {
		v := vs[i]
		name := fmt.Sprintf("%03d", i)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := startConfRig(t, store, v.Params, v.Plan, nil)
			defer r.stop()
			op := r.wait(t, r.submit(t, v.Params))
			running, tag, tokens := r.world()
			res, _ := op["result"].(map[string]interface{})
			reason, _ := op["failure_reason"].(string)
			fState, _ := res["final_running_state"].(string)
			got := applyExpectation{FinalState: fState, FinalDigest: role(fmt.Sprint(res["final_running_digest"])),
				FinalImage: role(fmt.Sprint(res["final_running_image_id"])),
				Op:         fmt.Sprint(op["state"]), Reason: reason, Running: running, Tag: tag, Cmds: tokens,
				UpgradeSucceeded: res["upgrade_succeeded"] == true, RollbackAttempted: res["rollback_attempted"] == true,
				RollbackSucceeded:     res["rollback_succeeded"] == true,
				RollbackSkippedReason: fmt.Sprint(res["rollback_skipped_reason"]), TagAhead: v.Expect.TagAhead}
			// Observed, not copied: since ADR-0062 slice 1 a failure that did not
			// prove its end state safe KEEPS its record, so the model predicts it.
			recs, lerr := r.jnl.List()
			if lerr != nil {
				t.Errorf("journal unreadable at terminal (faults: %s): %v", scriptString(v.Script), lerr)
			}
			got.JournalEmpty = lerr == nil && len(recs) == 0
			if !got.JournalEmpty && lerr == nil && (len(recs) != 1 || recs[0].TerminalOutcome != "failed:"+reason || !recs[0].TerminalAudited) {
				t.Errorf("journal at terminal (faults: %s) = %+v, want only the op's own record, kept as failed:%s and audited",
					scriptString(v.Script), recs, reason)
			}
			if !reflect.DeepEqual(got, v.Expect) {
				t.Errorf("MODEL/IMPLEMENTATION MISMATCH\n params: %+v\n faults: %s\n model : %+v\n actual: %+v",
					v.Params, scriptString(v.Script), v.Expect, got)
			}
			rep := role(fmt.Sprint(res["final_running_digest"]))
			// The observation key is the concrete input: every parameter and the fault plan.
			params := fmt.Sprintf("prior=%s same=%v backup=%v rb=%v th=%v ph=%v%s",
				v.Params.Prior, v.Params.Same, v.Params.Backup, v.Params.RB, v.Params.TH, v.Params.PH, planString(v.Plan))
			mu.Lock()
			// Every vector, the already-current ones included: an empty or wrong digest there
			// is as much a change as anywhere else.
			*acc.results = append(*acc.results, fmt.Sprintf("%s%s | %s | upgrade_digest=%s rollback_digest=%s final_running_digest=%s",
				pfx, scriptString(v.Script), params, role(fmt.Sprint(res["upgrade_digest"])),
				role(fmt.Sprint(res["rollback_digest"])), rep))
			// A misreport is a VERIFIED result naming an image that does not run (by registry
			// digest, or by image id when the image has no registry digest). An unverified
			// result names nothing, so it cannot misreport.
			named := rep
			if named == "none" {
				named = role(fmt.Sprint(res["final_running_image_id"]))
			}
			if fState == "verified" && named != running {
				*acc.misreported = append(*acc.misreported, fmt.Sprintf("%s%s | %s | reported=%s actual=%s",
					pfx, scriptString(v.Script), params, rep, running))
			}
			if tag == "T" && running != "T" && !v.Params.Same {
				acc.tagAhead[store]++
			}
			mu.Unlock()
		})
	}
}

// checkObserved compares what the real code reported with the reviewed observed.json: the
// model does not predict final_running_digest, so without this a change to that API field
// passes every vector. With CULVERT_CONFORMANCE_WRITE_OBSERVED=<path> it records instead
// (run.sh unsets it). It returns the drift lines ("+" newly differing, "-" no longer).
func checkObserved(t *testing.T, got, gotResults []string) []string {
	t.Helper()
	drift := []string{}
	if t.Failed() {
		return drift // a mismatch already fails the suite; do not record or compare a broken run
	}
	if path := os.Getenv("CULVERT_CONFORMANCE_WRITE_OBSERVED"); path != "" {
		b, err := lifecyclemodel.MarshalReviewable(lifecyclemodel.Observed{Note: lifecyclemodel.ObservedNote,
			FinalRunningDigestDiffers: got, ResultDigests: gotResults})
		if err == nil {
			err = os.WriteFile(path, b, 0o600) //nolint:gosec // G703: path from the developer's own update script
		}
		if err != nil {
			t.Fatalf("observed.json not written: %v", err)
		}
		return drift
	}
	want, err := lifecyclemodel.EmbeddedObserved()
	if err != nil {
		t.Fatalf("INCOMPLETE: %v", err)
	}
	drift = append(drift, observedDrift(t, "final_running_digest differs from the running image", want.FinalRunningDigestDiffers, got)...)
	drift = append(drift, observedDrift(t, "result digests", want.ResultDigests, gotResults)...)
	return drift
}

// observedDrift reports one list's difference from the reviewed observed.json. Every drift
// line goes into the t.Errorf message on its own line, prefixed "DRIFT-LINE", so run.sh and
// update-baseline.sh can show the reviewer WHICH vectors changed, not only how many.
func observedDrift(t *testing.T, what string, want, got []string) []string {
	t.Helper()
	if reflect.DeepEqual(got, want) {
		return nil
	}
	var drift []string
	added, removed := diffSorted(want, got)
	for _, x := range added {
		drift = append(drift, "+ "+x)
	}
	for _, x := range removed {
		drift = append(drift, "- "+x)
	}
	t.Errorf("DRIFT (real code): %s: %d lines now, %d reviewed; intended? run test/lifecycle-conformance/update-baseline.sh "+
		"and review observed.json\n DRIFT-LINE %s", what, len(got), len(want), strings.Join(drift, "\n DRIFT-LINE "))
	return drift
}

func uniqueSorted(l []string) []string {
	set := map[string]bool{}
	for _, x := range l {
		set[x] = true
	}
	out := make([]string, 0, len(set))
	for x := range set {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

// diffSorted returns the members of got missing from want, and of want missing from got.
func diffSorted(want, got []string) (added, removed []string) {
	in := func(l []string, x string) bool {
		i := sort.SearchStrings(l, x)
		return i < len(l) && l[i] == x
	}
	for _, x := range got {
		if !in(want, x) {
			added = append(added, x)
		}
	}
	for _, x := range want {
		if !in(got, x) {
			removed = append(removed, x)
		}
	}
	return added, removed
}

// ───────────────────────── crash points: journal record + reconcile verdict

func idRole(id string) string {
	if id == "" {
		return ""
	}
	return role(id)
}

// commandsBeforeBlock drops the blocked command itself from the observed sequence (a blocked health
// probe is never recorded). Consecutive captures are recorded once, so a blocked capture that
// directly follows another one must be put back.
func commandsBeforeBlock(tokens []string, blockCmd string, want []string) []string {
	n := len(tokens)
	if n == 0 || blockCmd == "health" {
		return tokens
	}
	tokens = tokens[:n-1]
	wantEndsInCapture := len(want) == 0 || want[len(want)-1] == "capture"
	if blockCmd == "ps" && wantEndsInCapture && len(tokens) < len(want) {
		tokens = append(tokens, "capture")
	}
	return tokens
}

// reconcileInputsAtCrash builds the decision input a startup reconciler would have: the REAL
// journal record (validated by the real validateReconcileRefs) plus the fake Docker's truth.
func (r *confRig) reconcileInputsAtCrash(rec *journal.Record) reconcileInputs {
	valid, _ := validateReconcileRefs(rec, repo)
	in := reconcileInputs{Kind: rec.Kind, Mode: rec.Mode, Phase: rec.Phase, Attempts: 0, MaxAttempts: 3, RefValid: valid,
		TargetImageID: rec.TargetImageID, PriorImageID: rec.PriorImageID}
	r.mu.Lock()
	if r.running != "" {
		in.RunningImageID = "sha256:" + r.imageID(r.running)
		if !r.nodigest || r.running != digOld {
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
	return in
}

// reconcileV2InputsAtCrash builds the converge (V2) decision input a converge start would
// have: the REAL record mapping (reconcileInputsFor: validation, rollback_armed, attempts)
// plus the fake Docker's truth, and a readiness probe exactly when the real reconcile runs
// one (reconcileNeedsProbe), answered by the fake health endpoint. The fake has no image
// store: a reference the record names is local (TargetRef: pulled before any danger phase).
func (r *confRig) reconcileV2InputsAtCrash(rec *journal.Record) reconcileInputsV2 {
	s := &Server{opts: Options{Cfg: &config.Config{ProxyRepo: repo}}}
	in := s.reconcileInputsFor(rec)
	r.mu.Lock()
	in.DockerReadable = true
	if r.running != "" {
		in.RunningImageID, in.ContainerRunning = "sha256:"+r.imageID(r.running), true
		if !r.nodigest || r.running != digOld {
			in.RunningDigests = []string{repo + "@sha256:" + r.running}
		}
	}
	if r.tag != "" {
		in.TagImageID = "sha256:" + r.imageID(r.tag)
	}
	ready := r.running != "" && !r.unhealthy[r.running]
	if in.RefValid && rec.TargetRef != "" {
		in.TargetLocalID = "sha256:" + r.imageID(digNew)
	}
	if in.RefValid && rec.PriorRef != "" {
		in.PriorLocalID = "sha256:" + r.imageID(digOld)
	}
	r.mu.Unlock()
	if reconcileNeedsProbe(in) {
		in.Probe = probeNotReady
		if ready {
			in.Probe = probeReady
		}
	}
	return in
}

func TestModelConformance_CrashPoints(t *testing.T) {
	_, vs := lifecyclemodel.Vectors()
	if len(vs) == 0 {
		t.Fatal("no vectors: refusing to pass an empty conformance run")
	}
	_ = os.Setenv(runner.EnvCulvertBackupPassphrase, "test-pass")
	var mu sync.Mutex
	adoptNotTarget := []string{}
	for _, store := range imageStores {
		t.Run(store, func(t *testing.T) { crashVectorsUnder(t, store, vs, &mu, &adoptNotTarget) })
	}
	writeReport(t, "crash", map[string]interface{}{"vectors_per_image_store": len(vs),
		"reconcile_says_target_live_but_container_is_not_on_target": adoptNotTarget})
}

// crashVectorsUnder replays every crash vector under one Docker image store.
func crashVectorsUnder(t *testing.T, store string, vs []lifecyclemodel.CrashVector, mu *sync.Mutex, adoptNotTarget *[]string) {
	for i := range vs {
		v := vs[i]
		t.Run(fmt.Sprintf("%03d", i), func(t *testing.T) {
			t.Parallel()
			blk := planEntry{Cmd: v.Block.Cmd, N: v.Block.N}
			r := startConfRig(t, store, v.Params, v.Plan, &blk)
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
			tokens = commandsBeforeBlock(tokens, v.Block.Cmd, v.Expect.CmdsBeforeBlock)
			recs, lerr := r.jnl.List()
			if lerr != nil || len(recs) != 1 {
				close(r.release)
				t.Fatalf("expected exactly one journal record at the crash point, got %d err=%v", len(recs), lerr)
			}
			rec := recs[0]
			in := r.reconcileInputsAtCrash(&rec)
			verdict := reconcileDecision(in)
			verdict2 := reconcileDecisionV2(r.reconcileV2InputsAtCrash(&rec))
			close(r.release)
			if !reflect.DeepEqual(tokens, v.Expect.CmdsBeforeBlock) {
				t.Errorf("MODEL/IMPLEMENTATION MISMATCH (commands before the crash point)\n faults: %s\n model : %v\n actual: %v",
					scriptString(v.Script), v.Expect.CmdsBeforeBlock, tokens)
			}
			_ = r.wait(t, opID)

			type obs struct {
				Phase, Tag, Run, PriorID, TargetID, Action, Reason string
				PriorRef, TargetRef, Armed                         bool
				V2Action, V2Reason                                 string
			}
			got := obs{string(rec.Phase), tag, running, idRole(rec.PriorImageID), idRole(rec.TargetImageID),
				verdict.Action.String(), verdict.Reason, rec.PriorRef != "", rec.TargetRef != "", rec.RollbackArmed,
				verdict2.Action.String(), verdict2.Reason}
			want := obs{v.Expect.Phase, v.Expect.Tag, v.Expect.Running, v.Expect.Record.PriorID, v.Expect.Record.TargetID,
				v.Expect.ReconcileAction, v.Expect.ReconcileReason, v.Expect.Record.PriorRef, v.Expect.Record.TargetRef,
				v.Expect.Record.Armed, v.Expect.ReconcileV2Action, v.Expect.ReconcileV2Reason}
			if got != want {
				t.Errorf("MODEL/IMPLEMENTATION MISMATCH at crash point\n params: %+v\n trace : %s\n block : %+v\n model : %+v\n actual: %+v",
					v.Params, scriptString(v.Script), v.Block, want, got)
			}
			if verdict.Action == actVerifyAdoptElseRollback && running != "T" && !v.Params.Same {
				mu.Lock()
				*adoptNotTarget = append(*adoptNotTarget, fmt.Sprintf("%s%s | running=%s tag=%s TargetImageID=%s reason=%s",
					storePrefix(store), scriptString(v.Script), running, tag, idRole(rec.TargetImageID), verdict.Reason))
				mu.Unlock()
			}
		})
	}
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

// reconcilePropertyViolations checks the proposed properties RP1..RP7 for one input and returns
// one "RPn violated: ..." line per violation.
func reconcilePropertyViolations(in reconcileInputs, v reconcileVerdict) []string {
	var out []string
	fail := func(id, msg string) { out = append(out, id+" violated: "+msg) }
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
	return out
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
		for _, viol := range reconcilePropertyViolations(in, v) {
			if propFails < 10 {
				t.Errorf("PROPERTY %s\n input=%+v verdict=%s/%s", viol, in, v.Action, v.Reason)
			}
			propFails++
		}
		rv.Advance(idx)
	}
	for _, r := range rv.Reasons { // vacuity: every verdict of the table must have been exercised
		if seen[r] == 0 {
			t.Errorf("VACUOUS: verdict %q never produced over the input space", r)
		}
	}
	v2Inputs, v2Mismatches, v2Seen := reconcileV2Differential(t)
	writeReport(t, "reconcile", map[string]interface{}{"inputs": total, "mismatches": mismatches,
		"property_violations": propFails, "verdict_counts": seen,
		"v2_inputs": v2Inputs, "v2_mismatches": v2Mismatches, "v2_verdict_counts": v2Seen})
}

// realReconcileV2Inputs maps the model's symbolic converge input onto the real one.
func realReconcileV2Inputs(m lifecyclemodel.ReconcileV2Inputs) reconcileInputsV2 {
	in := reconcileInputsV2{Kind: ops.KindUpgradeApply, Phase: journal.Phase(m.Phase), RefValid: m.RefValid,
		TargetRefPresent: m.TargetRefPresent, PriorRefPresent: m.PriorRefPresent, TargetDigest: digNew,
		TargetImageID: symID(m.TargetID), PriorImageID: symID(m.PriorID), RollbackArmed: m.Armed,
		Attempts: m.Attempts, MaxAttempts: maxReconcileAttempts, DockerReadable: true,
		RunningImageID: symID(m.RunningID), ContainerRunning: m.RunningID != "", TagImageID: symID(m.TagID),
		TargetLocalID: symID(m.TargetLocal), PriorLocalID: symID(m.PriorLocal)}
	if m.RunningID != "" {
		in.RunningDigests = []string{repo + "@sha256:" + symDigests([]string{m.RunningID})[0]}
	}
	switch m.Probe {
	case "ready":
		in.Probe = probeReady
	case "not_ready":
		in.Probe = probeNotReady
	}
	if m.Kind == lifecyclemodel.KindRuntimeRecover {
		in.Kind = ops.KindRuntimeRecover
		switch m.Compat {
		case "ok":
			in.Compat = compatOK
		case "incompatible":
			in.Compat = compatIncompatible
		default:
			in.Compat = compatUnknown
		}
	}
	return in
}

// reconcileV2Differential: the model's converge decision (lifecyclemodel ReconcileV2Spec,
// which the converge steps of the model use) equals the REAL reconcileDecisionV2 on every
// input of the model's bounded V2 space, and every model verdict is exercised.
func reconcileV2Differential(t *testing.T) (total, mismatches int, seen map[string]int) {
	t.Helper()
	rv := lifecyclemodel.GenReconcileV2Vectors()
	total = len(rv.Expected)
	if total == 0 {
		t.Fatal("V2 vector table is empty: refusing to pass")
	}
	seen = map[string]int{}
	idx := make([]int, len(rv.Domains))
	for n := 0; n < total; n++ {
		m := lifecyclemodel.ReconcileV2InputAt(idx)
		v := reconcileDecisionV2(realReconcileV2Inputs(m))
		got := v.Action.String() + "/" + v.Reason
		seen[got]++
		if want := rv.Verdict(n); got != want {
			if mismatches < 5 {
				t.Errorf("MODEL/IMPLEMENTATION MISMATCH (converge V2) #%d: input=%+v model=%s actual=%s", n, m, want, got)
			}
			mismatches++
		}
		rv.Advance(idx)
	}
	for _, w := range rv.Verdicts {
		if seen[w] == 0 {
			t.Errorf("VACUOUS: converge verdict %q never produced over the input space", w)
		}
	}
	return total, mismatches, seen
}

func writeReport(t *testing.T, name string, body map[string]interface{}) {
	t.Helper()
	dir := os.Getenv("CULVERT_CONFORMANCE_REPORT")
	if dir == "" {
		return
	}
	for k, v := range body { // lists are reported unique and sorted, so the report is deterministic
		l, ok := v.([]string)
		if !ok {
			continue
		}
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
	b, err := json.MarshalIndent(body, "", " ")
	if err == nil {
		// dir comes from the test driver's own environment and name is a literal at each call site.
		err = os.WriteFile(filepath.Join(dir, "conformance_"+name+".json"), b, 0o600) //nolint:gosec // G703: test-only report path, see above
	}
	if err != nil {
		// A missing report reads as INCOMPLETE in the summary; say why here instead of hiding it.
		t.Errorf("conformance report %q not written: %v", name, err)
	}
}

// planString renders a fault plan for an observation key ("" when there is none).
func planString(plan []planEntry) string {
	if len(plan) == 0 {
		return ""
	}
	parts := make([]string, 0, len(plan))
	for _, p := range plan {
		parts = append(parts, fmt.Sprintf("%s#%d=%s", p.Cmd, p.N, p.Mode))
	}
	return " plan=" + strings.Join(parts, ",")
}
