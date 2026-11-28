package server

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/config"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runtimehealth"
)

// The fake world's proxy container id (`compose ps`).
const rtContainerID = "abcdef012345"

// recoveryRig is the reconcile rig with runtime recovery on and the world an
// install of this agent left behind: the installed image (cfgNew) runs under
// the tag, installed.json names it as having replaced cfgOld, and cfgOld was
// gated, carries data-epoch labels and is compatible with the data.
type recoveryRig struct {
	*reconRig
	st *runtimehealth.Store
}

func newRecoveryRig(t *testing.T) *recoveryRig {
	t.Helper()
	r := newReconRig(t, true)
	st, err := runtimehealth.Open(r.opts.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	r.opts.Cfg.RuntimeHealthInterval = time.Minute
	r.opts.Cfg.RuntimeRecovery = config.RecoveryRestoreLastGated
	r.opts.Cfg.ImageAllowlist = regexp.MustCompile(`^` + regexp.QuoteMeta(repo) + `@sha256:[0-9a-f]{64}$`)
	r.opts.RuntimeHealth = st
	r.opts.RuntimeRecovery = NewRuntimeRecoveryTracker()
	r.restart(t)
	r.world.running, r.world.pinned = cfgNew, cfgNew
	r.world.priorEpochLabels, r.world.dataEpoch = true, 1
	now := time.Now().UTC()
	if err := st.WriteInstalled(runtimehealth.Installed{OpID: "01JINSTALLEDOP000000000000", Kind: ops.KindUpgradeApply,
		ImageID: "sha256:" + cfgNew, Ref: repo + "@sha256:" + digNew, Digest: "sha256:" + digNew,
		ReplacedImageID: "sha256:" + cfgOld, ReplacedRef: repo + "@sha256:" + digOld, InstalledAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.NoteGated(runtimehealth.GatedEntry{ImageID: "sha256:" + cfgOld, Ref: repo + "@sha256:" + digOld,
		Digest: "sha256:" + digOld, GatedAt: now}); err != nil {
		t.Fatal(err)
	}
	return &recoveryRig{reconRig: r, st: st}
}

func (r *recoveryRig) trig() runtimeTrigger {
	return runtimeTrigger{containerID: rtContainerID, imageID: "sha256:" + cfgNew}
}

// auditKinds lists "kind/outcome/actor" of every audit entry.
func (r *recoveryRig) auditKinds(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(r.opts.AuditPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var ev struct {
			Kind, Outcome, Actor string
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev.Kind+"/"+ev.Outcome+"/"+ev.Actor)
	}
	return out
}

func (r *recoveryRig) records(t *testing.T) []journal.Record {
	t.Helper()
	recs, err := r.jnl.List()
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// The main case: an upgrade this agent installed later fails its health check;
// the image it replaced comes back with the startup reconcile's own plan, the
// record is retired and the attempt counted.
func TestRuntimeRecovery_RestoresTheReplacedImage(t *testing.T) {
	r := newRecoveryRig(t)
	att := r.srv.runtimeRecoverOnce(r.trig())
	if att.Outcome != RecoveryRecovered || att.OpID == "" || att.RestoreImageID != "sha256:"+cfgOld {
		t.Fatalf("attempt = %+v", att)
	}
	if m := strings.Join(r.world.mutating, ","); m != "tag:"+cfgOld+",up" {
		t.Fatalf("docker changes = %s, want the retag to the restore image and one up", m)
	}
	if r.world.running != cfgOld || r.world.pinned != cfgOld {
		t.Fatalf("world = run %s tag %s, want the restore image", r.world.running, r.world.pinned)
	}
	if recs := r.records(t); len(recs) != 0 {
		t.Fatalf("records left: %+v", recs)
	}
	a, err := r.st.ReadRecoverAttempts()
	if err != nil || a.For("01JINSTALLEDOP000000000000", "sha256:"+cfgNew) != 1 {
		t.Fatalf("attempts = %+v, %v", a, err)
	}
	want := []string{
		"runtime.recover/started/" + AuditActorRuntimeRecovery,
		"runtime.recover:reconciled/succeeded/" + AuditActorRuntimeRecovery,
		"runtime.recover/succeeded/" + AuditActorRuntimeRecovery,
	}
	if got := r.auditKinds(t); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("audit = %v\nwant    %v", got, want)
	}
	if op := r.mgr.Get(att.OpID); op == nil || op.Kind != ops.KindRuntimeRecover || op.State != ops.StateSucceeded {
		t.Fatalf("op = %+v", op)
	}
	if r.mgr.Holder() != nil {
		t.Fatal("the maintenance lock was not released")
	}
	if st := r.opts.RuntimeRecovery.Snapshot("x"); st.Last == nil || st.Last.Outcome != RecoveryRecovered || st.Running {
		t.Fatalf("status = %+v", st)
	}
}

// Every admission condition, one at a time: refused with its reason, and
// nothing begun, written or changed.
func TestRuntimeRecovery_RefusesWithoutEveryCondition(t *testing.T) {
	cases := map[string]struct {
		mod    func(t *testing.T, r *recoveryRig)
		trig   func(r *recoveryRig) runtimeTrigger
		reason string
	}{
		"no install of this agent": {mod: func(t *testing.T, r *recoveryRig) {
			_ = os.Remove(r.st.Dir() + "/installed.json")
		}, reason: rrNoProvenance},
		"another image was installed": {mod: func(t *testing.T, r *recoveryRig) {
			r.world.running, r.world.pinned = cfgOld, cfgOld
		}, trig: func(r *recoveryRig) runtimeTrigger {
			return runtimeTrigger{containerID: rtContainerID, imageID: "sha256:" + cfgOld}
		}, reason: rrNoProvenance},
		"provenance unreadable": {mod: func(t *testing.T, r *recoveryRig) {
			writeFile(t, r.st.Dir()+"/installed.json", "{")
		}, reason: rrProvenanceUnread},
		"restore image never gated": {mod: func(t *testing.T, r *recoveryRig) {
			_ = os.Remove(r.st.Dir() + "/gated.json")
		}, reason: rrNotGated},
		"restore reference not allow-listed": {mod: func(t *testing.T, r *recoveryRig) {
			r.opts.Cfg.ImageAllowlist = regexp.MustCompile(`^nothing$`)
		}, reason: rrRestoreRefBad},
		"restore image not local": {mod: func(t *testing.T, r *recoveryRig) {
			r.world.priorRefGone = true
		}, reason: rrRestoreNotLocal},
		"data newer than the restore image reads": {mod: func(t *testing.T, r *recoveryRig) {
			r.world.dataEpoch = 2
		}, reason: "restore_incompatible"},
		"restore image unlabelled": {mod: func(t *testing.T, r *recoveryRig) {
			r.world.priorEpochLabels = false
		}, reason: "restore_compatibility_unknown"},
		"data epoch unreadable": {mod: func(t *testing.T, r *recoveryRig) {
			r.world.dataEpoch = 0
		}, reason: "restore_compatibility_unknown"},
		"hand retag": {mod: func(t *testing.T, r *recoveryRig) {
			r.world.pinned = cfgOld
		}, reason: rrTagDiffers},
		"another container now": {trig: func(r *recoveryRig) runtimeTrigger {
			return runtimeTrigger{containerID: "0123456789ab", imageID: "sha256:" + cfgNew}
		}, reason: rrIdentityChanged},
		"stack down": {mod: func(t *testing.T, r *recoveryRig) {
			r.world.running = ""
		}, reason: rrNotRunning},
		"docker unreadable": {mod: func(t *testing.T, r *recoveryRig) {
			r.world.down = true
		}, reason: rrDockerUnreadable},
		"cap reached": {mod: func(t *testing.T, r *recoveryRig) {
			if err := r.st.WriteRecoverAttempts(runtimehealth.RecoverAttempts{Entries: []runtimehealth.RecoverAttempt{{
				SourceOpID: "01JINSTALLEDOP000000000000", ImageID: "sha256:" + cfgNew, Begun: runtimehealth.MaxRecoverAttempts}}}); err != nil {
				t.Fatal(err)
			}
		}, reason: rrAttemptsExhausted},
		"counter unreadable": {mod: func(t *testing.T, r *recoveryRig) {
			writeFile(t, r.st.Dir()+"/recover_attempts.json", "{")
		}, reason: rrAttemptsUnread},
		"an operation holds the lock": {mod: func(t *testing.T, r *recoveryRig) {
			if _, err := r.mgr.Begin(ops.KindUpgradeApply, "cp", "", nil); err != nil {
				t.Fatal(err)
			}
		}, reason: rrLockHeld},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRecoveryRig(t)
			if c.mod != nil {
				c.mod(t, r)
			}
			trig := r.trig()
			if c.trig != nil {
				trig = c.trig(r)
			}
			att := r.srv.runtimeRecoverOnce(trig)
			if att.Outcome != RecoveryRefused || att.Reason != c.reason {
				t.Fatalf("attempt = %+v, want refused/%s", att, c.reason)
			}
			if att.OpID != "" {
				t.Fatalf("an operation was begun for a refusal: %s", att.OpID)
			}
			if len(r.world.mutating) != 0 {
				t.Fatalf("docker changed: %v", r.world.mutating)
			}
			if recs := r.records(t); len(recs) != 0 {
				t.Fatalf("a record was written: %+v", recs)
			}
			if got := r.auditKinds(t); len(got) != 0 {
				t.Fatalf("audit entries for a refusal: %v", got)
			}
		})
	}
}

// What admission saw can change before the lock is taken: the second check,
// under the lock, refuses, and the operation ends failed with nothing written
// ahead and nothing changed.
func TestRuntimeRecovery_AdmissionRepeatedUnderTheLock(t *testing.T) {
	r := newRecoveryRig(t)
	r.world.onPS = func(n int) {
		if n == 2 { // the second admission's first read
			r.world.mu.Lock()
			r.world.pinned = cfgOld // a hand retag between the two checks
			r.world.mu.Unlock()
		}
	}
	att := r.srv.runtimeRecoverOnce(r.trig())
	if att.Outcome != RecoveryRefused || att.Reason != rrTagDiffers || att.OpID == "" {
		t.Fatalf("attempt = %+v", att)
	}
	if len(r.world.mutating) != 0 || len(r.records(t)) != 0 {
		t.Fatalf("docker %v, records %v", r.world.mutating, r.records(t))
	}
	if a, _ := r.st.ReadRecoverAttempts(); a != nil {
		t.Fatalf("an attempt was counted: %+v", a)
	}
	if op := r.mgr.Get(att.OpID); op == nil || op.State != ops.StateFailed {
		t.Fatalf("op = %+v", op)
	}
	want := "runtime.recover/started/" + AuditActorRuntimeRecovery + "|runtime.recover/failed/" + AuditActorRuntimeRecovery
	if got := strings.Join(r.auditKinds(t), "|"); got != want {
		t.Fatalf("audit = %s", got)
	}
}

// The cap outlives the record: a restore whose gate fails is counted, kept
// and reported; after MaxRecoverAttempts the next trigger is refused.
func TestRuntimeRecovery_TheCapIsDurable(t *testing.T) {
	r := newRecoveryRig(t)
	r.ready.Store(false) // the restore image does not answer ready either
	for i := 1; i <= runtimehealth.MaxRecoverAttempts; i++ {
		r.world.running, r.world.pinned = cfgNew, cfgNew
		att := r.srv.runtimeRecoverOnce(r.trig())
		if att.Outcome != RecoveryFailed || att.Reason != "prior_not_ready" {
			t.Fatalf("attempt %d = %+v", i, att)
		}
		if a, _ := r.st.ReadRecoverAttempts(); a.For("01JINSTALLEDOP000000000000", "sha256:"+cfgNew) != i {
			t.Fatalf("attempt %d counted %+v", i, a)
		}
	}
	if n := len(r.records(t)); n != runtimehealth.MaxRecoverAttempts {
		t.Fatalf("%d records kept, want %d", n, runtimehealth.MaxRecoverAttempts)
	}
	r.restart(t) // a new agent process: memory forgets, the counter does not
	r.world.running, r.world.pinned = cfgNew, cfgNew
	if att := r.srv.runtimeRecoverOnce(r.trig()); att.Outcome != RecoveryRefused || att.Reason != rrAttemptsExhausted {
		t.Fatalf("after the cap: %+v", att)
	}
}

// The second source: an upgrade record of this agent, kept, whose target is
// the unhealthy image. The recovery restores its prior and leaves that record
// to the rules that retire it.
func TestRuntimeRecovery_FromAKeptUpgradeRecord(t *testing.T) {
	r := newRecoveryRig(t)
	_ = os.Remove(r.st.Dir() + "/installed.json")
	r.seed(t, journal.PhaseRestarted, func(rec *journal.Record) { rec.TargetImageID = "sha256:" + cfgNew })
	att := r.srv.runtimeRecoverOnce(r.trig())
	if att.Outcome != RecoveryRecovered {
		t.Fatalf("attempt = %+v", att)
	}
	recs := r.records(t)
	if len(recs) != 1 || recs[0].OpID != testOpULID || recs[0].Kind != ops.KindUpgradeApply {
		t.Fatalf("records = %+v, want only the kept upgrade record", recs)
	}
	if a, _ := r.st.ReadRecoverAttempts(); a.For(testOpULID, "sha256:"+cfgNew) != 1 {
		t.Fatalf("attempts = %+v", a)
	}
}

// The trigger counts, and only counts: consecutive not_ready samples of one
// container and image; anything else starts again; at the threshold one
// trigger is queued and the count restarts.
func TestRuntimeRecovery_TriggerCountsConsecutiveNotReady(t *testing.T) {
	r := newRecoveryRig(t)
	t0 := time.Now().UTC()
	nr := func(img string) *runtimehealth.Sample {
		return &runtimehealth.Sample{State: runtimehealth.StateUnhealthy, Reason: obsReasonNotReady, ObservedAt: t0,
			ContainerID: rtContainerID, ImageID: img}
	}
	gated := &runtimehealth.Sample{State: runtimehealth.StateGated, Reason: obsReasonGateOK, ObservedAt: t0,
		ContainerID: rtContainerID, ImageID: "sha256:" + cfgNew}
	other := &runtimehealth.Sample{State: runtimehealth.StateUnhealthy, Reason: obsReasonNotRunning, ObservedAt: t0}
	x, y := "sha256:"+cfgNew, "sha256:"+cfgOld
	tr := r.opts.RuntimeRecovery
	pending := func() bool {
		select {
		case <-tr.kick:
			return true
		default:
			return false
		}
	}
	for _, seq := range [][]*runtimehealth.Sample{
		{nr(x), nr(x), gated, nr(x), nr(x)},
		{nr(x), nr(x), other, nr(x), nr(x)},
		{nr(x), nr(y), nr(x), nr(y)},
	} {
		for _, smp := range seq {
			r.srv.noteRuntimeSample(smp)
		}
		if pending() {
			t.Fatal("a broken streak triggered")
		}
		r.srv.noteRuntimeSample(gated)
	}
	for i := 0; i < RuntimeRecoveryStreak; i++ {
		r.srv.noteRuntimeSample(nr(x))
	}
	if !pending() {
		t.Fatal("three consecutive not_ready samples did not trigger")
	}
	if tr.Snapshot("x").NotReadyStreak != 0 {
		t.Fatal("the streak did not restart")
	}
	r.opts.Cfg.RuntimeRecovery = config.RecoveryOff
	for i := 0; i < RuntimeRecoveryStreak; i++ {
		r.srv.noteRuntimeSample(nr(x))
	}
	if pending() {
		t.Fatal("triggered with runtime_recovery off")
	}
	if len(r.world.mutating) != 0 {
		t.Fatalf("counting changed docker: %v", r.world.mutating)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Through the observer itself: three ticks of a running image that is not
// ready queue one trigger, and the observer changes nothing on its way.
func TestRuntimeRecovery_ObserverTicksTrigger(t *testing.T) {
	r := newRecoveryRig(t)
	r.ready.Store(false)
	for i := 0; i < RuntimeRecoveryStreak; i++ {
		if out := r.srv.observeOnce(t.Context()); out != obsRecorded {
			t.Fatalf("tick %d = %s", i, out)
		}
	}
	select {
	case trig := <-r.opts.RuntimeRecovery.kick:
		if trig.imageID != "sha256:"+cfgNew || trig.containerID == "" {
			t.Fatalf("trigger = %+v", trig)
		}
	default:
		t.Fatal("no trigger after three not_ready ticks")
	}
	if len(r.world.mutating) != 0 || len(r.records(t)) != 0 {
		t.Fatalf("the observer acted: docker %v records %v", r.world.mutating, r.records(t))
	}
}

// The worker: a queued trigger is evaluated by the loop the server starts, and
// the loop ends with its context. It runs nothing when the policy is off.
func TestRuntimeRecovery_WorkerRunsATriggerAndStops(t *testing.T) {
	r := newRecoveryRig(t)
	ctx, cancel := context.WithCancel(t.Context())
	r.srv.startRuntimeRecovery(ctx)
	r.opts.RuntimeRecovery.kick <- r.trig()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if st := r.opts.RuntimeRecovery.Snapshot("x"); st.Last != nil && !st.Running {
			if st.Last.Outcome != RecoveryRecovered {
				t.Fatalf("last = %+v", st.Last)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the worker never evaluated the trigger")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	done := make(chan struct{})
	go func() { r.srv.opWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker did not stop with its context")
	}

	off := newRecoveryRig(t)
	off.opts.Cfg.RuntimeRecovery = config.RecoveryOff
	if off.srv.runtimeRecoveryEnabled() {
		t.Fatal("enabled with runtime_recovery off")
	}
}

// Codex review on #2140: two sources that each authorize the other direction
// (installed.json: B replaced A; a kept upgrade record: A replaced B) with both
// images unhealthy. Each recovery changes the running image, so the trigger
// fires the other way. The cap must hold for every source still in force, or
// the agent alternates the images forever.
func TestRuntimeRecovery_NoPingPongBetweenTwoSources(t *testing.T) {
	r := newRecoveryRig(t)
	r.ready.Store(false) // neither image answers ready
	r.world.targetEpochLabels = true
	if err := r.st.NoteGated(runtimehealth.GatedEntry{ImageID: "sha256:" + cfgNew, Ref: repo + "@sha256:" + digNew,
		Digest: "sha256:" + digNew, GatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	r.seed(t, journal.PhaseRestarted, func(rec *journal.Record) { // a failed upgrade B -> A, kept
		rec.TargetRef, rec.TargetDigest, rec.TargetImageID = repo+"@sha256:"+digOld, digOld, "sha256:"+cfgOld
		rec.PriorRef, rec.PriorDigest, rec.PriorImageID = repo+"@sha256:"+digNew, digNew, "sha256:"+cfgNew
	})
	begun := 0
	for i := 0; i < 10; i++ {
		trig := runtimeTrigger{containerID: rtContainerID, imageID: "sha256:" + r.world.running}
		att := r.srv.runtimeRecoverOnce(trig)
		if att.Outcome == RecoveryRefused {
			if att.Reason != rrAttemptsExhausted {
				t.Fatalf("trigger %d refused for %s", i, att.Reason)
			}
			break
		}
		begun++
	}
	if limit := 2 * runtimehealth.MaxRecoverAttempts; begun > limit {
		t.Fatalf("%d recoveries begun across two sources, want at most %d", begun, limit)
	}
	if begun == 0 {
		t.Fatal("vacuous: no recovery was begun")
	}
}
