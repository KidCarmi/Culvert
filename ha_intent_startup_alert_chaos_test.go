package main

// ha_intent_startup_alert_chaos_test.go — Codex P2 4303320660 on #1556:
// "Defer HA-intent pages until webhooks load".
//
// When ha_config.json is unreadable at boot and the activation callback's
// second read also fails, the once-per-episode HA-intent page was fired
// directly inside initCluster — before initPersistentAdminState loads the
// persisted webhooks — so it fanned out to an empty store, and the latch then
// silenced every retry while the node stayed HA-gated. Same class as the boot
// address-rejection page (4299279051). The fix routes every page this PR adds
// or changes that can be raised during initCluster through the startup queue
// (deferStartupAlertWhile + an episode predicate), and the wall below keeps it
// that way.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// startupPages captures one event on BOTH delivery paths: direct fires
// (fireAlert — before the startup flush that reaches an empty webhook list and
// is lost) and deliveries made by the startup flush (startupAlertFire). The
// startup queue starts unflushed and empty, as at boot.
func startupPages(t *testing.T, event string) (direct, flushed func() int) {
	t.Helper()
	cpStartupAlertsLoaded(t, false)
	var mu sync.Mutex
	nDirect, nFlushed := 0, 0
	prevFire, prevStartup := fireAlert, startupAlertFire
	fireAlert = func(e string, _ AlertPayload) {
		if e == event {
			mu.Lock()
			nDirect++
			mu.Unlock()
		}
	}
	startupAlertFire = func(e string, _ AlertPayload) {
		if e == event {
			mu.Lock()
			nFlushed++
			mu.Unlock()
		}
	}
	t.Cleanup(func() { fireAlert, startupAlertFire = prevFire, prevStartup })
	return func() int { mu.Lock(); defer mu.Unlock(); return nDirect },
		func() int { mu.Lock(); defer mu.Unlock(); return nFlushed }
}

// haIntentBootRead is startControlPlaneWithHAResume's boot read of the HA
// config, through the same classifier and the same recorder.
func haIntentBootRead(t *testing.T) {
	t.Helper()
	cfg, err := loadHAConfig()
	if _, unreadable := haPersistedAction(cfg, err); unreadable == nil {
		t.Fatal("precondition: the boot read decided the HA intent")
	} else {
		noteHAIntentUnreadable(unreadable)
	}
}

// TestChaos71_BootUnreadableHAIntentIsPagedOnceAfterTheWebhooksLoad is the
// finding: the boot read and the activation callback's re-read both fail
// inside initCluster. Nothing is fired into the empty webhook list, the
// startup flush delivers exactly one page, and no retry — before or after the
// flush — pages again while the node stays gated.
func TestChaos71_BootUnreadableHAIntentIsPagedOnceAfterTheWebhooksLoad(t *testing.T) {
	h := newHAIntentHarness(t)
	direct, flushed := startupPages(t, "ha_resume_unfenced")
	_ = cpRecordBootResumes(t)
	haIntentCorrupt(t)

	haIntentBootRead(t)                // initCluster: the boot read fails
	resumeLeadershipIfStillPersisted() // the listener's onActivated: the second read fails
	h.awaitParked()
	for i := 0; i < 3; i++ { // retries before the webhooks load
		if !h.step() {
			t.Fatal("the retry loop gave up while the config was still unreadable")
		}
	}
	if d, f := direct(), flushed(); d != 0 || f != 0 {
		t.Fatalf("before the webhooks loaded: %d direct and %d flushed page(s), want 0 and 0 — a direct page here reaches an empty webhook list while the latch silences every retry", d, f)
	}

	flushStartupAlerts() // initPersistentAdminState: the webhooks are loaded
	if f := flushed(); f != 1 {
		t.Fatalf("the startup flush delivered %d ha_resume_unfenced page(s), want exactly 1", f)
	}
	for i := 0; i < 3; i++ { // retries after the flush, same episode
		if !h.step() {
			t.Fatal("the retry loop gave up while the config was still unreadable")
		}
	}
	if d, f := direct(), flushed(); d != 0 || f != 1 {
		t.Errorf("retries in the same episode paged again (direct=%d flushed=%d), want 0 and 1", d, f)
	}
	haIntentAssertGated(t, "after the flush, the config still unreadable")
}

// TestChaos71_BootUnreadableHAIntentDecidedBeforeTheFlushIsDropped is the
// negative control: an episode that a read decided before the webhooks loaded
// is not paged late — not even when a NEW episode is open at the flush (the
// queued page belongs to the old one). After the flush the new episode's page
// fires at once: nothing is held back.
func TestChaos71_BootUnreadableHAIntentDecidedBeforeTheFlushIsDropped(t *testing.T) {
	h := newHAIntentHarness(t)
	direct, flushed := startupPages(t, "ha_resume_unfenced")
	_ = cpRecordBootResumes(t)
	haIntentCorrupt(t)

	haIntentBootRead(t)
	resumeLeadershipIfStillPersisted() // second failed read: the episode's page is queued
	h.awaitParked()
	if err := saveHAConfig(&haConfig{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if h.step() {
		t.Fatal("a decided read kept the retry running")
	}
	haIntentAssertUngated(t, "a decided no-HA read")

	haIntentCorrupt(t)
	haIntentBootRead(t) // a NEW episode, one failure: not yet paged
	flushStartupAlerts()
	if d, f := direct(), flushed(); d != 0 || f != 0 {
		t.Fatalf("an episode decided before the webhooks loaded was paged late (direct=%d flushed=%d)", d, f)
	}

	haIntentBootRead(t) // the new episode keeps failing, after the flush
	if d, f := direct(), flushed(); d != 1 || f != 0 {
		t.Errorf("the new episode's page after the flush: direct=%d flushed=%d, want 1 and 0", d, f)
	}
	globalHA.clearIntentUnknown()
}

// TestChaos71_BootUnfencedResumePageQueuesUntilTheWebhooksLoad: the
// read-only resume page (a persisted leader whose lease acquisition is denied
// by a live holder) is raised by the boot resume inside initCluster. It
// queues, is delivered once at the flush while the node is still an unfenced
// leader, and is dropped when that state ended before the flush.
func TestChaos71_BootUnfencedResumePageQueuesUntilTheWebhooksLoad(t *testing.T) {
	for _, tc := range []struct {
		name        string
		endBefore   bool
		wantFlushed int
	}{
		{"still_unfenced_at_the_flush", false, 1},
		{"role_ended_before_the_flush", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tempHADir(t)
			direct, flushed := startupPages(t, "ha_resume_unfenced")
			f := halease.NewFake(time.Minute)
			if granted, _, _ := f.Acquire(context.Background(), "cp-usurper"); !granted {
				t.Fatal("seed acquire")
			}
			h := &HAState{}
			h.SetLeaseProvider(f, "cp-me")
			h.ResumeAsLeader(&haConfig{Enabled: true, Token: "tok", PeerAddr: "peer:50051", Role: "leader", Term: 9})
			defer h.Stop()
			if !h.IsLeader() || h.WriteAllowed() {
				t.Fatal("precondition: not a read-only (unfenced) leader")
			}
			if d := direct(); d != 0 {
				t.Fatalf("the unfenced resume paged %d time(s) directly before the webhooks loaded", d)
			}
			if tc.endBefore {
				h.mu.Lock()
				h.role = ""
				h.mu.Unlock()
			}
			flushStartupAlerts()
			if d, fl := direct(), flushed(); d != 0 || fl != tc.wantFlushed {
				t.Errorf("direct=%d flushed=%d, want 0 and %d", d, fl, tc.wantFlushed)
			}
		})
	}
}

// ── The wall ────────────────────────────────────────────────────────────────

// startupQueuedEvents are the events whose producers this PR adds or changes
// and that can be raised during initCluster — before initPersistentAdminState
// loads the webhooks — each with the producers that raise it:
//
//   - ha_resume_unfenced: the HA-intent page (pageHAIntentUnreadable — the boot
//     read and the activation callback's re-read) and the read-only resume
//     page (pageUnfencedLeader — the boot resume, which this PR moved into the
//     listener's activation callback).
//   - cp_grpc_listener_down: the listener's threshold and terminal pages,
//     role_conflict included (fireCPGRPCListenerAlert).
//   - config_snapshot_rejected: the address kind (pageCPAddrRejection).
//
// storage_write_failed is NOT in the set: this PR only extracted its goroutine
// launch into a seam (goStorageWriteAlert); its delivery and its rate gate
// (an interval, not an episode latch) are main's.
var startupQueuedEvents = map[string]bool{
	"ha_resume_unfenced":       true,
	"cp_grpc_listener_down":    true,
	"config_snapshot_rejected": true,
}

// startupQueuedProducers must each queue through deferStartupAlertWhile. A
// producer missing from the source means the wall's selector went stale.
var startupQueuedProducers = []string{
	"pageHAIntentUnreadable", "pageUnfencedLeader", "fireCPGRPCListenerAlert",
	"pageCPAddrRejection",
}

// startupQueueExceptions are the direct dispatch sites of a
// startupQueuedEvents event that the wall tolerates, keyed "<owner>:<event>",
// each with its reason. Each key must match EXACTLY ONE dispatch site, so a
// second direct fire added to an excepted owner still fails the wall, and an
// exception whose site is gone is reported as stale.
var startupQueueExceptions = map[string]string{
	"rejectPublish:config_snapshot_rejected": "the FULL-kind rejection page predates #1556 and its text and " +
		"delivery are main's; this PR routed only the address kind away from it (pageCPAddrRejection). A " +
		"rejected initial publish at boot still reaches an empty store, as on main — the recorded round-15 " +
		"follow-up in roadmap/CHAOS-ENGINEERING-REVIEW.md, not part of this PR.",
	"handleForeignFenceHolder:ha_resume_unfenced": "the recovery loop's foreign-holder stance predates #1556 " +
		"and is unchanged by it (the boot resume does not arm the loop when the resume itself saw a foreign " +
		"holder). Its boot-time exposure is main's and is out of this PR's scope.",
}

// startupQueueWallViolations reports every dispatch of a startupQueuedEvents
// event that does not go through the startup queue: a direct fireAlert /
// alerts.Fire / startupAlertFire call that is not the post-flush branch of an
// `if !startupAlertsFlushed() { deferStartupAlertWhile(<event>, …, pred); return }`
// guard earlier in the same function, a deferStartupAlert (no episode
// predicate) or a deferStartupAlertWhile with a nil predicate. It also returns
// the owners that queue (for the stale-selector check) and how many direct
// sites each exception covered.
func startupQueueWallViolations(fset *token.FileSet, files []*ast.File) (violations []string, queuing map[string]bool, excepted map[string]int) {
	queuing, excepted = map[string]bool{}, map[string]int{}
	for _, f := range files {
		for _, decl := range f.Decls {
			owner := cpTopLevelName(decl)
			bodies := startupWallBodies(decl)
			ast.Inspect(decl, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					v, queues, exc := startupWallClassify(owner, bodies, call)
					if v != "" {
						violations = append(violations, fset.Position(call.Pos()).String()+": "+v)
					}
					if queues {
						queuing[owner] = true
					}
					if exc != "" {
						excepted[exc]++
					}
				}
				return true
			})
		}
	}
	for key, n := range excepted {
		if n != 1 {
			violations = append(violations, "startup-queue exception "+key+" covers "+strconv.Itoa(n)+
				" direct dispatch sites, want exactly 1 — a new direct fire in an excepted owner must queue")
		}
	}
	return violations, queuing, excepted
}

// startupWallBodies lists every function body in decl.
func startupWallBodies(decl ast.Decl) []*ast.BlockStmt {
	var bodies []*ast.BlockStmt
	ast.Inspect(decl, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			bodies = append(bodies, fn.Body)
		case *ast.FuncLit:
			bodies = append(bodies, fn.Body)
		}
		return true
	})
	return bodies
}

// startupWallClassify judges one call: a violation message (or ""), whether
// it is a queuing deferStartupAlertWhile with a predicate, and the exception
// key it was excused by (or "").
func startupWallClassify(owner string, bodies []*ast.BlockStmt, call *ast.CallExpr) (violation string, queues bool, excepted string) {
	name, event := startupWallCallee(call), startupWallEvent(call)
	if name == "" || !startupQueuedEvents[event] {
		return "", false, ""
	}
	switch name {
	case "deferStartupAlert":
		return owner + " queues " + event + " with no episode predicate (deferStartupAlert) — a recovered condition would be paged late", false, ""
	case "deferStartupAlertWhile":
		if len(call.Args) < 3 || startupWallIsNil(call.Args[2]) {
			return owner + " queues " + event + " with a nil predicate", false, ""
		}
		return "", true, ""
	}
	if startupWallGuarded(startupWallInnermost(bodies, call), call, event) {
		return "", false, ""
	}
	if key := owner + ":" + event; startupQueueExceptions[key] != "" {
		return "", false, key
	}
	return owner + " dispatches " + event + " directly (" + name + ") — before the startup flush that reaches an empty webhook list; queue it through deferStartupAlertWhile", false, ""
}

// startupWallCallee names a dispatch call, or "".
func startupWallCallee(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		switch fn.Name {
		case "fireAlert", "startupAlertFire", "deferStartupAlert", "deferStartupAlertWhile":
			return fn.Name
		}
	case *ast.SelectorExpr:
		if x, ok := fn.X.(*ast.Ident); ok && x.Name == "alerts" && fn.Sel.Name == "Fire" {
			return "alerts.Fire"
		}
	}
	return ""
}

// startupWallEvent is the call's literal event argument, or "".
func startupWallEvent(call *ast.CallExpr) string {
	if len(call.Args) == 0 {
		return ""
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return s
}

func startupWallIsNil(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "nil"
}

// startupWallInnermost is the smallest function body containing call.
func startupWallInnermost(bodies []*ast.BlockStmt, call *ast.CallExpr) *ast.BlockStmt {
	var best *ast.BlockStmt
	for _, b := range bodies {
		if b == nil || b.Pos() > call.Pos() || b.End() < call.End() {
			continue
		}
		if best == nil || b.Pos() >= best.Pos() {
			best = b
		}
	}
	return best
}

// startupWallGuarded reports whether body, before call, has the statement
// `if !startupAlertsFlushed() { …deferStartupAlertWhile(event, …)…; return }`.
func startupWallGuarded(body *ast.BlockStmt, call *ast.CallExpr, event string) bool {
	if body == nil {
		return false
	}
	for _, st := range body.List {
		ifs, ok := st.(*ast.IfStmt)
		if !ok || ifs.End() > call.Pos() || !startupWallIsUnflushedCond(ifs.Cond) || len(ifs.Body.List) == 0 {
			continue
		}
		if _, ok := ifs.Body.List[len(ifs.Body.List)-1].(*ast.ReturnStmt); !ok {
			continue
		}
		queued := false
		ast.Inspect(ifs.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok && startupWallCallee(c) == "deferStartupAlertWhile" && startupWallEvent(c) == event {
				queued = true
			}
			return true
		})
		if queued {
			return true
		}
	}
	return false
}

func startupWallIsUnflushedCond(e ast.Expr) bool {
	u, ok := e.(*ast.UnaryExpr)
	if !ok || u.Op != token.NOT {
		return false
	}
	c, ok := u.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := c.Fun.(*ast.Ident)
	return ok && id.Name == "startupAlertsFlushed"
}

// startupWallPackageFiles parses the package's production files.
func startupWallPackageFiles(t *testing.T) (*token.FileSet, []*ast.File) {
	t.Helper()
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		files = append(files, f)
	}
	return fset, files
}

// TestChaos71_Wall_StartupCapablePagesQueueUntilTheWebhooksLoad: no producer
// of an event this PR adds or changes that can fire during initCluster
// dispatches it without the startup-queue wrapper.
func TestChaos71_Wall_StartupCapablePagesQueueUntilTheWebhooksLoad(t *testing.T) {
	fset, files := startupWallPackageFiles(t)
	violations, queuing, excepted := startupQueueWallViolations(fset, files)
	for _, v := range violations {
		t.Error(v)
	}
	for _, owner := range startupQueuedProducers {
		if !queuing[owner] {
			t.Errorf("the wall found no deferStartupAlertWhile in %s — its selector has gone stale", owner)
		}
	}
	for key, reason := range startupQueueExceptions {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("startup-queue exception %s has no reason", key)
		}
		if excepted[key] == 0 {
			t.Errorf("startup-queue exception %s matched no dispatch site — remove the stale exception", key)
		}
	}
}

// TestChaos71_Wall_StartupQueueWallCatchesADirectFire is the wall's mutation
// check: each way of dispatching a queued event without the wrapper is
// reported, and the wrapper itself is not.
func TestChaos71_Wall_StartupQueueWallCatchesADirectFire(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want int
	}{
		{"direct_fireAlert", `func pageX() { fireAlert("ha_resume_unfenced", AlertPayload{}) }`, 1},
		{"go_alerts_Fire", `func (h *HAState) pageX() { go alerts.Fire("ha_resume_unfenced", alerts.Payload{}) }`, 1},
		{"var_func_literal", `var pageX = func() { go fireAlert("cp_grpc_listener_down", AlertPayload{}) }`, 1},
		{"no_predicate", `func pageX() { deferStartupAlert("config_snapshot_rejected", AlertPayload{}) }`, 1},
		{"nil_predicate", `func pageX() { deferStartupAlertWhile("config_snapshot_rejected", AlertPayload{}, nil) }`, 1},
		{"guard_after_the_fire", `func pageX(p AlertPayload) {
			fireAlert("ha_resume_unfenced", p)
			if !startupAlertsFlushed() { deferStartupAlertWhile("ha_resume_unfenced", p, ok); return }
		}`, 1},
		{"guard_for_another_event", `func pageX(p AlertPayload) {
			if !startupAlertsFlushed() { deferStartupAlertWhile("cp_grpc_listener_down", p, ok); return }
			fireAlert("ha_resume_unfenced", p)
		}`, 1},
		{"guard_without_return", `func pageX(p AlertPayload) {
			if !startupAlertsFlushed() { deferStartupAlertWhile("ha_resume_unfenced", p, ok) }
			fireAlert("ha_resume_unfenced", p)
		}`, 1},
		{"wrapped_ok", `func pageX(p AlertPayload) {
			if !startupAlertsFlushed() { deferStartupAlertWhile("ha_resume_unfenced", p, ok); return }
			go fireAlert("ha_resume_unfenced", p)
		}`, 0},
		{"other_event_ok", `func pageX() { fireAlert("policy_block", AlertPayload{}) }`, 0},
		// The pre-PR HA-intent page, verbatim in shape: the finding itself.
		{"old_ha_intent_page", `func pageHAIntentUnreadable(err error, episode uint64) {
			fireAlert("ha_resume_unfenced", AlertPayload{Event: "ha_resume_unfenced", Source: "ha"})
		}`, 1},
		{"exception_is_per_event", `func rejectPublish() { fireAlert("ha_resume_unfenced", AlertPayload{}) }`, 1},
		{"exception_covers_one_site", `func rejectPublish(p AlertPayload) {
			fireAlert("config_snapshot_rejected", p)
			go fireAlert("config_snapshot_rejected", p)
		}`, 1},
		{"exception_one_site_ok", `func rejectPublish(p AlertPayload) { fireAlert("config_snapshot_rejected", p) }`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "mutant.go", "package main\n"+tc.src, 0)
			if err != nil {
				t.Fatal(err)
			}
			got, _, _ := startupQueueWallViolations(fset, []*ast.File{f})
			if len(got) != tc.want {
				t.Errorf("the wall reported %d violation(s), want %d: %v", len(got), tc.want, got)
			}
		})
	}
}

// TestChaos71_Wall_HAIntentLatchArmsOnlyWithItsPage: the once-per-episode
// latch (noteIntentUnreadable) is armed only by noteHAIntentUnreadable, which
// hands the page to the queued producer in the same call.
func TestChaos71_Wall_HAIntentLatchArmsOnlyWithItsPage(t *testing.T) {
	fset, files := startupWallPackageFiles(t)
	var callers []string
	for _, f := range files {
		for _, decl := range f.Decls {
			owner := cpTopLevelName(decl)
			ast.Inspect(decl, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "noteIntentUnreadable" {
						callers = append(callers, owner)
						if owner != "noteHAIntentUnreadable" {
							t.Errorf("%s: %s arms the HA-intent page latch outside noteHAIntentUnreadable", fset.Position(call.Pos()), owner)
						}
					}
				}
				return true
			})
		}
	}
	sort.Strings(callers)
	if len(callers) != 1 {
		t.Errorf("noteIntentUnreadable callers = %v, want exactly [noteHAIntentUnreadable]", callers)
	}
}
