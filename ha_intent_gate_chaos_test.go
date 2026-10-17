package main

// ha_intent_gate_chaos_test.go — Codex P1 4303122583 on #1556: a read of the
// persisted HA intent that fails is never "HA disabled". The deferred
// leadership resume (the listener's one-shot onActivated) used to map a
// transient read/decode failure to "none" and return for good, so the
// listener served with globalHA disabled: every leader-gated RPC and CA
// issuance was allowed with no fencing lease.

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// haIntentHarness controls the resume retry loop: the loop parks at each
// backoff; step lets one more attempt run (true) or stops it (false), and
// reports whether the loop parked again (true) or exited (false).
type haIntentHarness struct {
	t       *testing.T
	parked  chan struct{}
	gate    chan bool
	done    chan struct{}
	spawned atomic.Int32
	mu      sync.Mutex
	pages   int
}

func newHAIntentHarness(t *testing.T) *haIntentHarness {
	t.Helper()
	tempHADir(t)
	cpWithGlobalHARole(t, "", "")
	globalHA.clearIntentUnknown()
	t.Cleanup(globalHA.clearIntentUnknown)
	h := &haIntentHarness{t: t, parked: make(chan struct{}), gate: make(chan bool), done: make(chan struct{})}

	prevSleep, prevSpawn, prevFire := haIntentRetrySleep, haIntentRetrySpawn, fireAlert
	haIntentRetrySleep = func(time.Duration) bool {
		h.parked <- struct{}{}
		return <-h.gate
	}
	haIntentRetrySpawn = func(loop func()) {
		h.spawned.Add(1)
		go func() {
			defer close(h.done)
			loop()
		}()
	}
	fireAlert = func(event string, _ AlertPayload) {
		if event == "ha_resume_unfenced" {
			h.mu.Lock()
			h.pages++
			h.mu.Unlock()
		}
	}
	t.Cleanup(func() {
		if h.spawned.Load() > 0 {
			select {
			case <-h.done:
			default:
				h.stop() // never leave the loop parked past the test
			}
		}
		haIntentRetrySleep, haIntentRetrySpawn, fireAlert = prevSleep, prevSpawn, prevFire
	})
	return h
}

func (h *haIntentHarness) awaitParked() {
	h.t.Helper()
	select {
	case <-h.parked:
	case <-h.done:
		h.t.Fatal("the retry loop exited; want it parked for another attempt")
	case <-time.After(10 * time.Second):
		h.t.Fatal("the retry loop never parked")
	}
}

// step runs one more attempt and reports whether the loop parked again.
func (h *haIntentHarness) step() (parkedAgain bool) {
	h.t.Helper()
	h.gate <- true
	select {
	case <-h.parked:
		return true
	case <-h.done:
		return false
	case <-time.After(10 * time.Second):
		h.t.Fatal("the retry attempt never finished")
		return false
	}
}

func (h *haIntentHarness) stop() {
	select {
	case h.gate <- false:
	case <-time.After(10 * time.Second):
	}
	<-h.done
}

func (h *haIntentHarness) pageCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pages
}

func haIntentCorrupt(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(haConfigPath(), []byte(`{"enabled": true, "role": "lea`), 0o600); err != nil {
		t.Fatal(err)
	}
}

var haIntentLeader = &haConfig{Enabled: true, Role: "leader", PeerAddr: "10.0.0.9:50051", Token: "tok", Term: 3}

// haIntentAssertGated: every HA-gated sink refuses, /healthz included.
func haIntentAssertGated(t *testing.T, why string) {
	t.Helper()
	if ok, _ := haServingAllowed(); ok {
		t.Errorf("%s: haServingAllowed permits leader-gated RPCs", why)
	}
	if ok, _ := haIssuanceAllowed(); ok {
		t.Errorf("%s: haIssuanceAllowed permits CA issuance", why)
	}
	if effectiveWriteAuthority(globalHA.Status(), true) {
		t.Errorf("%s: diagnostics report write authority", why)
	}
	rec := httptest.NewRecorder()
	apiHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "ha_intent_unknown") {
		t.Errorf("%s: /healthz = %d %s, want 503 ha_intent_unknown", why, rec.Code, rec.Body.String())
	}
}

func haIntentAssertUngated(t *testing.T, why string) {
	t.Helper()
	if _, gated := globalHA.intentGate(); gated {
		t.Errorf("%s: the node is still HA-gated", why)
	}
	if ok, reason := haServingAllowed(); !ok {
		t.Errorf("%s: haServingAllowed refuses (%s)", why, reason)
	}
	if ok, reason := haIssuanceAllowed(); !ok {
		t.Errorf("%s: haIssuanceAllowed refuses (%s)", why, reason)
	}
}

// TestChaos71_UnreadableHAIntentOnTheResumeReadKeepsTheNodeGated is the
// finding: boot read a persisted leader, the bind was delayed, and the
// resume's re-read hits a transient decode error. Serving and issuance stay
// gated, the attempt is re-armed, a persisting failure pages once, and a
// later successful read resumes and ungates.
func TestChaos71_UnreadableHAIntentOnTheResumeReadKeepsTheNodeGated(t *testing.T) {
	h := newHAIntentHarness(t)
	resumes := cpRecordBootResumes(t)
	haIntentCorrupt(t)

	resumeLeadershipIfStillPersisted() // the listener's one-shot onActivated
	if resumes.Load() != 0 {
		t.Fatal("resumed leadership from an unreadable config")
	}
	if h.spawned.Load() != 1 {
		t.Fatalf("the one-shot callback spent its only chance: %d retry loop(s) armed, want 1", h.spawned.Load())
	}
	haIntentAssertGated(t, "after the failed resume read")
	h.awaitParked()
	if h.pageCount() != 0 {
		t.Errorf("a single transient failure paged %d time(s), want 0", h.pageCount())
	}

	for i := 0; i < 2; i++ {
		if !h.step() {
			t.Fatal("the retry loop gave up while the config was still unreadable")
		}
		haIntentAssertGated(t, "while the config stays unreadable")
	}
	if got := h.pageCount(); got != 1 {
		t.Errorf("a persisting failure paged %d time(s) in one episode, want 1", got)
	}

	if err := saveHAConfig(haIntentLeader); err != nil {
		t.Fatal(err)
	}
	if h.step() {
		t.Fatal("the retry loop kept running after a successful read")
	}
	if resumes.Load() != 1 {
		t.Errorf("a later successful read resumed %d time(s), want 1", resumes.Load())
	}
	haIntentAssertUngated(t, "after the successful resume")
}

// TestChaos71_FailedRevalidationReadKeepsTheNodeGated: the read that fails is
// the resume's post-acquisition revalidation (haConfigStillResumable). The
// resume is not applied, and that must not read as "decided".
func TestChaos71_FailedRevalidationReadKeepsTheNodeGated(t *testing.T) {
	h := newHAIntentHarness(t)
	if err := saveHAConfig(haIntentLeader); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	prev := haBootResumeAsLeader
	haBootResumeAsLeader = func(cfg *haConfig) bool {
		if calls.Add(1) == 1 {
			haIntentCorrupt(t) // a transient failure during the lease acquisition
		}
		return haConfigStillResumable(cfg)
	}
	t.Cleanup(func() { haBootResumeAsLeader = prev })

	resumeLeadershipIfStillPersisted()
	if h.spawned.Load() != 1 {
		t.Fatal("a resume whose revalidation read failed was treated as decided")
	}
	haIntentAssertGated(t, "after the failed revalidation read")
	h.awaitParked()

	if err := saveHAConfig(haIntentLeader); err != nil {
		t.Fatal(err)
	}
	if h.step() {
		t.Fatal("the retry loop kept running after the revalidation succeeded")
	}
	if calls.Load() != 2 {
		t.Errorf("resume attempted %d time(s), want 2", calls.Load())
	}
	haIntentAssertUngated(t, "after the revalidated resume")
}

// TestChaos71_UnreadableHAIntentRetryStopsOnShutdownStillGated: the HA
// shutdown latch interrupts the retry, and the node stays gated (fail closed).
func TestChaos71_UnreadableHAIntentRetryStopsOnShutdownStillGated(t *testing.T) {
	h := newHAIntentHarness(t)
	_ = cpRecordBootResumes(t)
	haIntentCorrupt(t)
	resumeLeadershipIfStillPersisted()
	h.awaitParked()
	h.stop()
	haIntentAssertGated(t, "after the retry was interrupted by shutdown")
}

// TestChaos71_PersistedStandbyAfterAnUnreadableBootStaysGated: the intent
// was unreadable, and the read that finally succeeds says standby. This
// process came up as a plain Control Plane and cannot re-enter standby at
// runtime: it stays gated rather than serving as an ungated one.
func TestChaos71_PersistedStandbyAfterAnUnreadableBootStaysGated(t *testing.T) {
	h := newHAIntentHarness(t)
	resumes := cpRecordBootResumes(t)
	haIntentCorrupt(t)
	resumeLeadershipIfStillPersisted()
	h.awaitParked()
	if err := saveHAConfig(&haConfig{Enabled: true, Role: "standby", PeerAddr: "10.0.0.9:50051", Token: "tok"}); err != nil {
		t.Fatal(err)
	}
	if h.step() {
		t.Fatal("a decided standby read kept the retry running")
	}
	if resumes.Load() != 0 {
		t.Error("resumed leadership from a standby record")
	}
	haIntentAssertGated(t, "a persisted standby this process could not read at start")
}

// TestChaos71_ExplicitNoHAIntentIsUngated is the negative control: an
// explicit, decoded "HA not configured" (no file, or enabled=false) is a
// standalone Control Plane — ungated, as on main, with nothing re-armed.
func TestChaos71_ExplicitNoHAIntentIsUngated(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *haConfig // nil: no file
	}{
		{"no_file", nil},
		{"ha_disabled", &haConfig{Enabled: false, Role: "leader"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHAIntentHarness(t)
			resumes := cpRecordBootResumes(t)
			if tc.cfg != nil {
				if err := saveHAConfig(tc.cfg); err != nil {
					t.Fatal(err)
				}
			}
			resumeLeadershipIfStillPersisted()
			if h.spawned.Load() != 0 || resumes.Load() != 0 {
				t.Errorf("spawned=%d resumes=%d, want neither for an explicit no-HA intent", h.spawned.Load(), resumes.Load())
			}
			haIntentAssertUngated(t, "an explicit no-HA intent")
		})
	}
}

// TestChaos71_HAPersistedActionNeverMapsAnErrorToNone pins the classifier.
func TestChaos71_HAPersistedActionNeverMapsAnErrorToNone(t *testing.T) {
	decodeErr := errors.New("unexpected end of JSON input")
	for _, tc := range []struct {
		name    string
		cfg     *haConfig
		loadErr error
		want    string
		wantErr bool
	}{
		{"no_file_is_none", nil, &fs.PathError{Op: "open", Path: haConfigFile, Err: fs.ErrNotExist}, "none", false},
		{"disabled_is_none", &haConfig{Enabled: false}, nil, "none", false},
		{"standby", &haConfig{Enabled: true, Role: "standby"}, nil, "standby", false},
		{"leader", &haConfig{Enabled: true, Role: "leader"}, nil, "leader", false},
		{"decode_error_is_undecided", nil, decodeErr, "", true},
		{"permission_error_is_undecided", nil, &fs.PathError{Op: "open", Path: haConfigFile, Err: fs.ErrPermission}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := haPersistedAction(tc.cfg, tc.loadErr)
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Errorf("haPersistedAction = (%q, %v), want (%q, err=%v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// TestChaos71_Wall_HAIntentDecisionsUseTheStrictClassifier: in production,
// haRestartAction (which maps an error to "none") is reached only through
// haPersistedAction, or by the resume's revalidation guard, whose false is
// "not confirmed" and keeps the node gated (resumeLeadershipAttempt).
func TestChaos71_Wall_HAIntentDecisionsUseTheStrictClassifier(t *testing.T) {
	allowed := map[string]bool{"haPersistedAction": true, "haConfigStillResumable": true}
	found := map[string]int{}
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range f.Decls {
			owner := cpTopLevelName(decl)
			ast.Inspect(decl, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "haRestartAction" {
						found[owner]++
						if !allowed[owner] {
							t.Errorf("%s: %s decides from haRestartAction, which maps a read error to \"none\" — use haPersistedAction", fset.Position(call.Pos()), owner)
						}
					}
				}
				return true
			})
		}
	}
	for owner := range allowed {
		if found[owner] == 0 {
			t.Errorf("the wall found no haRestartAction call in %s — its selector has gone stale", owner)
		}
	}
}
