package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

// reconWorld is a small stateful Docker model for the startup reconcile: which
// image the proxy runs, where the fixed tag is, and which images are local
// (cfgOld <-> digOld, cfgNew <-> digNew). onPS runs before the n-th
// `compose ps` answers, so a test can change the world between the reads.
type reconWorld struct {
	mu       sync.Mutex
	running  string // image id hex; "" = no proxy container
	pinned   string
	mutating []string
	failed   map[*exec.Cmd]bool
	psCount  int
	onPS     func(n int)
	down     bool   // Docker does not answer: every command fails
	onUp     func() // called while `up` runs (outside the lock)
	onDown   func() // called while `down` runs (outside the lock)
}

func (w *reconWorld) idFor(ref string) string {
	switch {
	case ref == "culvert/proxy:pinned":
		return w.pinned
	case strings.HasPrefix(ref, "sha256:"):
		return strings.TrimPrefix(ref, "sha256:")
	case strings.HasSuffix(ref, "@sha256:"+digOld):
		return cfgOld
	case strings.HasSuffix(ref, "@sha256:"+digNew):
		return cfgNew
	}
	return ""
}

func digestOf(id string) string {
	if id == cfgOld {
		return digOld
	}
	return digNew
}

func (w *reconWorld) start(cmd *exec.Cmd) error {
	args := cmd.Args
	has := func(tok string) bool { return argvHas(args, tok) }
	if has("ps") {
		w.mu.Lock()
		w.psCount++
		n, hook := w.psCount, w.onPS
		w.mu.Unlock()
		if hook != nil {
			hook(n)
		}
	}
	if has("down") {
		w.mu.Lock()
		hook := w.onDown
		w.mu.Unlock()
		if hook != nil {
			hook()
		}
	}
	if has("up") {
		w.mu.Lock()
		hook := w.onUp
		w.mu.Unlock()
		if hook != nil {
			hook()
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.down {
		// Docker does not answer: every command fails. An attempted mutation
		// is still recorded, so a test can assert that none was even tried.
		for _, m := range []string{"tag", "up", "down"} {
			if has(m) {
				w.mutating = append(w.mutating, m+":attempted-while-docker-down")
			}
		}
		w.failed[cmd] = true
		return nil
	}
	switch {
	case has("ps"):
		if w.running != "" {
			_, _ = cmd.Stdout.Write([]byte(`{"Service":"proxy","State":"running","ID":"abcdef012345"}`))
		}
	case has("{{json .Image}}"):
		_, _ = cmd.Stdout.Write([]byte(`"sha256:` + w.running + `"`))
	case has("image") && has("inspect"):
		id := w.idFor(args[len(args)-1])
		if id == "" {
			w.failed[cmd] = true
			return nil
		}
		_, _ = cmd.Stdout.Write([]byte(`[{"Id":"sha256:` + id + `","RepoDigests":["` + repo + `@sha256:` + digestOf(id) + `"]}]`))
	case has("tag"):
		w.mutating = append(w.mutating, "tag:"+w.idFor(args[len(args)-2]))
		w.pinned = w.idFor(args[len(args)-2])
	case has("up"):
		w.mutating = append(w.mutating, "up")
		w.running = w.pinned
	}
	return nil
}

func (w *reconWorld) wait(cmd *exec.Cmd) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed[cmd] {
		return errors.New("No such image")
	}
	return nil
}

func (w *reconWorld) calls() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.mutating...)
}

type reconRig struct {
	srv   *Server
	jnl   *journal.Journal
	mgr   *ops.Manager
	al    *audit.Logger
	world *reconWorld
	rt    *ReconcileTracker
}

func newReconRig(t *testing.T, ready bool) *reconRig {
	t.Helper()
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")
	al, err := audit.New(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := auth.NewPolicy([]string{strconv.Itoa(os.Geteuid())})
	if err != nil {
		t.Fatal(err)
	}
	jnl, err := journal.New(tmp)
	if err != nil {
		t.Fatal(err)
	}
	rn, err := runner.New(runner.Options{ComposeProjectDir: tmp, ComposeFile: "docker-compose.yml", StageTimeout: 5 * time.Second,
		ProxyRepo: repo, DockerBinary: "/usr/bin/docker",
		EnvAllow: []string{runner.EnvCulvertBackupPassphrase}, EnvOverlayOnly: []string{runner.EnvCulvertBackupPassphrase}})
	if err != nil {
		t.Fatal(err)
	}
	w := &reconWorld{running: cfgOld, pinned: cfgOld, failed: map[*exec.Cmd]bool{}}
	rn.SetExecHooksForTest(w.start, w.wait)
	hs := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		if !ready {
			rw.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(hs.Close)
	hu, _ := url.Parse(hs.URL)
	mgr := ops.NewManager(nil)
	srv, err := New(Options{
		Cfg: &config.Config{ComposeProjectDir: tmp, ComposeFile: "docker-compose.yml", SocketPath: filepath.Join(tmp, "s.sock"),
			StateDir: tmp, PrivilegeMode: config.PrivilegeSudoers, OperationTimeout: 30 * time.Second, StageTimeout: 5 * time.Second, ProxyRepo: repo},
		Auth: pol, Audit: al, Ops: mgr, Status: &fakeStatus{}, StateDir: tmp, AuditPath: auditPath, Journal: jnl, Runner: rn,
		HealthProbeFactory: func() health.Probe {
			return health.Probe{BaseURL: hu, HealthPath: "/health", ReadyPath: "/ready", Budget: 300 * time.Millisecond, PollInterval: 50 * time.Millisecond}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close(); _ = al.Close() })
	return &reconRig{srv: srv, jnl: jnl, mgr: mgr, al: al, world: w, rt: NewReconcileTracker()}
}

// seed writes an interrupted upgrade record from cfgOld (digOld) to cfgNew (digNew).
func (r *reconRig) seed(t *testing.T, phase journal.Phase, mod func(*journal.Record)) {
	t.Helper()
	now := time.Now().UTC()
	rec := journal.Record{OpID: testOpULID, Kind: ops.KindUpgradeApply, Phase: phase, Actor: "cp", StartedAt: now, UpdatedAt: now,
		TargetRef: repo + "@sha256:" + digNew, TargetDigest: digNew, PriorRef: repo + "@sha256:" + digOld, PriorDigest: digOld,
		PriorImageID: "sha256:" + cfgOld}
	if mod != nil {
		mod(&rec)
	}
	if err := r.jnl.Write(rec); err != nil {
		t.Fatal(err)
	}
}

// run prepares and runs the reconcile synchronously (no socket needed).
func (r *reconRig) run(t *testing.T) ReconcileRecord {
	t.Helper()
	r.srv.PrepareStartupReconcile(r.rt)
	r.srv.mu.Lock()
	work := r.srv.startupWork
	r.srv.startupWork = nil
	r.srv.mu.Unlock()
	if work == nil {
		t.Fatalf("no reconcile work armed (state %s)", r.rt.Snapshot().State)
	}
	work()
	got, ok := r.rt.RecordFor(testOpULID)
	if !ok {
		t.Fatalf("no reconcile result for the record: %+v", r.rt.Snapshot())
	}
	return got
}

func (r *reconRig) recordOnDisk(t *testing.T) *journal.Record {
	t.Helper()
	rec, found, err := r.jnl.Read(testOpULID)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		return nil
	}
	return rec
}

// TestStartupReconcile_RealignConvergesAndRetires: tag ahead, container on the
// prior image: one retag to the prior ref, verified by id, audited, retired.
func TestStartupReconcile_RealignConvergesAndRetires(t *testing.T) {
	r := newReconRig(t, true)
	r.world.pinned = cfgNew
	r.seed(t, journal.PhaseRestarting, nil)
	got := r.run(t)
	if got.Outcome != OutcomeConverged || !got.DockerReconciled || got.Decision != "realign" {
		t.Fatalf("result = %+v", got)
	}
	if c := r.world.calls(); len(c) != 1 || c[0] != "tag:"+cfgOld {
		t.Errorf("mutating calls = %v, want exactly [tag:prior]", c)
	}
	if r.recordOnDisk(t) != nil {
		t.Error("record not retired after verified convergence")
	}
	if op := r.mgr.Get(r.rt.Snapshot().OpID); op == nil || op.State != ops.StateSucceeded {
		t.Errorf("reconcile op = %+v, want succeeded", op)
	}
}

// TestStartupReconcile_AuditFailureKeepsRecord: retirement needs the audit
// entry first. With the audit log failing, Docker converges but the record
// stays, and the outcome says so.
func TestStartupReconcile_AuditFailureKeepsRecord(t *testing.T) {
	for name, pinned := range map[string]string{"realign": cfgNew, "noop": cfgOld} {
		t.Run(name, func(t *testing.T) {
			r := newReconRig(t, true)
			r.world.pinned = pinned
			r.seed(t, journal.PhaseRestarting, nil)
			_ = r.al.Close() // every later audit write fails
			got := r.run(t)
			if got.Outcome != OutcomeConvergedNotRetired {
				t.Fatalf("outcome = %q, want %q (%+v)", got.Outcome, OutcomeConvergedNotRetired, got)
			}
			rec := r.recordOnDisk(t)
			if rec == nil {
				t.Fatal("record removed although the audit entry could not be written")
			}
			if rec.ReconcileOutcome != OutcomeConvergedNotRetired {
				t.Errorf("record outcome = %q", rec.ReconcileOutcome)
			}
			if op := r.mgr.Get(r.rt.Snapshot().OpID); op == nil || op.FailureReason != string(ops.ReasonRecoveryRequired) {
				t.Errorf("reconcile op = %+v, want failed(recovery_required)", op)
			}
		})
	}
}

// TestStartupReconcile_WriteAheadFailureMeansNoAction: the attempt is
// persisted before any Docker change; when that write fails, nothing changes.
func TestStartupReconcile_WriteAheadFailureMeansNoAction(t *testing.T) {
	r := newReconRig(t, true)
	r.world.pinned = cfgNew
	r.seed(t, journal.PhaseRestarting, nil)
	dir := r.jnl.Dir()
	r.world.onPS = func(n int) {
		if n == 2 { // the record's fact read: the record is already in memory
			if err := os.Rename(dir, dir+".gone"); err != nil {
				t.Errorf("rename: %v", err)
			}
		}
	}
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "journal_write_failed" {
		t.Errorf("result = %+v, want recovery_required/journal_write_failed", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("Docker changed without a durable attempt: %v", c)
	}
}

// TestStartupReconcile_DockerChangedBeforeActionIsNotActedOn: the decision is
// re-checked against a fresh read right before acting (TOCTOU).
func TestStartupReconcile_DockerChangedBeforeActionIsNotActedOn(t *testing.T) {
	r := newReconRig(t, true)
	r.world.pinned = cfgNew
	r.seed(t, journal.PhaseRestarting, nil)
	r.world.onPS = func(n int) {
		if n == 3 { // the pre-action re-read
			r.world.mu.Lock()
			r.world.pinned = cfgOld // someone else moved the tag back
			r.world.mu.Unlock()
		}
	}
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "docker_changed_before_action" {
		t.Errorf("result = %+v", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("acted on a stale decision: %v", c)
	}
	if rec := r.recordOnDisk(t); rec == nil || rec.ReconcileAttempts != 1 {
		t.Errorf("record = %+v, want kept with the write-ahead attempt counted", rec)
	}
}

// TestStartupReconcile_TargetLiveUngatedIsReportedOnly: A6/A7 under converge:
// the ungated target is neither adopted nor restarted.
func TestStartupReconcile_TargetLiveUngatedIsReportedOnly(t *testing.T) {
	r := newReconRig(t, true)
	r.world.running, r.world.pinned = cfgNew, cfgNew
	r.seed(t, journal.PhaseRestarted, func(rec *journal.Record) { rec.TargetImageID = "sha256:" + cfgNew })
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "target_live_ungated" {
		t.Errorf("result = %+v", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("mutating calls = %v", c)
	}
	if r.recordOnDisk(t) == nil {
		t.Error("record retired although nothing converged")
	}
	if !r.rt.RecoveryRequired() {
		t.Error("tracker does not report recovery_required")
	}
}

// TestStartupReconcile_VerifiedAdoptNeedsReady: A10. Adopt is a no-mutation
// verdict that still needs a fresh ReadyOK.
func TestStartupReconcile_VerifiedAdoptNeedsReady(t *testing.T) {
	for _, ready := range []bool{true, false} {
		t.Run(strconv.FormatBool(ready), func(t *testing.T) {
			r := newReconRig(t, ready)
			r.world.running, r.world.pinned = cfgNew, cfgNew
			r.seed(t, journal.PhaseVerified, func(rec *journal.Record) { rec.TargetImageID = "sha256:" + cfgNew })
			got := r.run(t)
			if ready && (got.Decision != "adopt" || got.Outcome != OutcomeConverged || r.recordOnDisk(t) != nil) {
				t.Errorf("ready: result = %+v, want adopt converged and retired", got)
			}
			if !ready && (got.Reason != "verified_target_not_ready" || r.recordOnDisk(t) == nil) {
				t.Errorf("not ready: result = %+v, want recovery_required kept", got)
			}
			if c := r.world.calls(); len(c) != 0 {
				t.Errorf("adopt changed Docker: %v", c)
			}
		})
	}
}

// TestStartupReconcile_FinishArmedRollback: R2. The tag is on the prior image,
// the container still on the target, and the record proves the rollback was
// armed: `up`, gate, verify, retire. Unhealthy prior: kept, recovery_required.
func TestStartupReconcile_FinishArmedRollback(t *testing.T) {
	for _, ready := range []bool{true, false} {
		t.Run(strconv.FormatBool(ready), func(t *testing.T) {
			r := newReconRig(t, ready)
			r.world.running, r.world.pinned = cfgNew, cfgOld
			r.seed(t, journal.PhaseRestarted, func(rec *journal.Record) { rec.RollbackArmed = true })
			got := r.run(t)
			if c := r.world.calls(); len(c) != 1 || c[0] != "up" {
				t.Fatalf("mutating calls = %v, want exactly [up]", c)
			}
			if ready && (got.Outcome != OutcomeConverged || !got.DockerReconciled || r.recordOnDisk(t) != nil) {
				t.Errorf("result = %+v, want converged and retired", got)
			}
			if !ready && (got.Outcome != OutcomeRecoveryRequired || got.Reason != "prior_not_ready" || r.recordOnDisk(t) == nil) {
				t.Errorf("result = %+v, want recovery_required/prior_not_ready, kept", got)
			}
		})
	}
}

// TestStartupReconcile_SecondInstanceSkips: the instance lock is held by
// another holder: no op is begun and nothing is decided.
func TestStartupReconcile_SecondInstanceSkips(t *testing.T) {
	r := newReconRig(t, true)
	r.world.pinned = cfgNew
	r.seed(t, journal.PhaseRestarting, nil)
	held, err := r.jnl.LockReconcile()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Release() }()
	r.srv.PrepareStartupReconcile(r.rt)
	if st := r.rt.Snapshot().State; st != ReconcileSkippedInstance {
		t.Errorf("state = %q, want %q", st, ReconcileSkippedInstance)
	}
	if r.srv.startupWork != nil || r.mgr.Holder() != nil {
		t.Error("a reconcile was armed although another instance holds the lock")
	}
}

// TestStartupReconcile_ExhaustedAttemptsReportOnly: the persisted cap holds
// across starts; a forged negative count is treated as exhausted.
func TestStartupReconcile_ExhaustedAttemptsReportOnly(t *testing.T) {
	for _, n := range []int{maxReconcileAttempts, -1} {
		r := newReconRig(t, true)
		r.world.pinned = cfgNew
		r.seed(t, journal.PhaseRestarting, func(rec *journal.Record) { rec.ReconcileAttempts = n })
		got := r.run(t)
		if got.Reason != "reconcile_exhausted" || len(r.world.calls()) != 0 {
			t.Errorf("attempts=%d: result = %+v calls=%v", n, got, r.world.calls())
		}
	}
}
