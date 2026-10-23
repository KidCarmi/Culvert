package main

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// Gates for Codex P2 4326470080 on PR #1601 and its class: the
// admin_roster_durability row shows one state, chosen by walking
// rosterRowPrecedence, for admins and viewers alike. A refused first save
// after a restart used to be hidden behind "not verified yet" because each
// renderer ordered states pairwise on its own.

// rosterStateCase is what the pair test knows about one state, independently
// of the production table: how to make it active on top of healthy facts,
// and what each rendering must show while it is the highest active state.
type rosterStateCase struct {
	set         func(f *rosterDurabilityFacts)
	adminStatus string
	// adminPrefix is the start of the admin message; it may depend on the
	// other facts (the missing-file message depends on landed).
	adminPrefix func(f rosterDurabilityFacts) string
	// viewer is the fixed viewer message, or "" for an admin-only state that
	// a viewer must not be able to tell apart from the state below it.
	viewer       string
	viewerStatus string
}

func fixedPrefix(msg string) func(rosterDurabilityFacts) string {
	return func(rosterDurabilityFacts) string { return msg }
}

// rosterHealthyFacts is a node whose last landed save is on disk, unchanged:
// only rosterStateOK is active.
func rosterHealthyFacts() rosterDurabilityFacts {
	return rosterDurabilityFacts{configured: true, persisted: true, localAdmin: true, landed: true}
}

// rosterStateCases has one entry per state. Each setter touches only its own
// fact, so every pair of states can be made active together; that is what
// lets the pair test pin every adjacent pair of the precedence list.
var rosterStateCases = map[rosterRowState]rosterStateCase{
	rosterStateSetupIncomplete: {func(f *rosterDurabilityFacts) { f.configured = false },
		diagOK, fixedPrefix(rosterDurabilitySetupIncomplete), rosterDurabilitySetupIncomplete, diagOK},
	rosterStateNoRosterFile: {func(f *rosterDurabilityFacts) { f.persisted = false },
		diagWarn, fixedPrefix("no admin roster file is configured"), rosterDurabilityViewerNotDurable, diagWarn},
	rosterStateNotResponding: {func(f *rosterDurabilityFacts) { f.notResponding = true },
		diagWarn, fixedPrefix(rosterTargetNotResponding), rosterDurabilityViewerNotDurable, diagWarn},
	rosterStateRefused: {func(f *rosterDurabilityFacts) { f.refused, f.refusedTotal = 2, 5 },
		diagWarn, fixedPrefix("2 admin account change(s) were refused"), rosterDurabilityViewerRefused, diagWarn},
	rosterStateLoginWritesFailed: {func(f *rosterDurabilityFacts) { f.degraded, f.degradedTotal = 3, 4 },
		diagWarn, fixedPrefix("3 login-time write(s) failed"), "", ""},
	rosterStateTargetUnusable: {func(f *rosterDurabilityFacts) { f.unusable = "the configured roster path is not a regular file" },
		diagWarn, fixedPrefix("the configured roster path is not a regular file"), rosterDurabilityViewerNotDurable, diagWarn},
	rosterStateTargetMissing: {func(f *rosterDurabilityFacts) { f.missing = true },
		diagWarn, func(f rosterDurabilityFacts) string {
			if f.landed {
				return rosterTargetDisappeared
			}
			return rosterTargetFirstWritePending
		}, rosterDurabilityViewerNotDurable, diagWarn},
	rosterStateReplaced: {func(f *rosterDurabilityFacts) { f.replaced = true },
		diagWarn, fixedPrefix(rosterTargetReplaced), rosterDurabilityViewerNotDurable, diagWarn},
	rosterStateOwnerChanged: {func(f *rosterDurabilityFacts) { f.ownerRefusing = true },
		diagWarn, fixedPrefix(rosterTargetOwnerChanged), rosterDurabilityViewerNotDurable, diagWarn},
	rosterStateImmutable: {func(f *rosterDurabilityFacts) { f.blocked = true },
		diagWarn, fixedPrefix(rosterTargetImmutable), rosterDurabilityViewerNotDurable, diagWarn},
	rosterStateParentNotWritable: {func(f *rosterDurabilityFacts) { f.parentNotWritable = true },
		diagWarn, fixedPrefix(rosterParentNotWritable), rosterDurabilityViewerNotDurable, diagWarn},
	rosterStateChangedExternally: {func(f *rosterDurabilityFacts) { f.changedExternally = true },
		diagWarn, fixedPrefix(rosterTargetChangedExternally), rosterDurabilityViewerNotDurable, diagWarn},
	rosterStateDirNotSynced: {func(f *rosterDurabilityFacts) { f.dirUnsynced = true },
		diagWarn, fixedPrefix(rosterTargetDirNotSynced), rosterDurabilityViewerNotDurable, diagWarn},
	rosterStateNotYetVerified: {func(f *rosterDurabilityFacts) { f.landed = false },
		diagWarn, fixedPrefix(rosterTargetNotYetVerified), rosterDurabilityViewerNotYetVerified, diagWarn},
	rosterStateOK: {func(*rosterDurabilityFacts) {},
		diagOK, fixedPrefix(rosterDurabilityLandedOK), rosterDurabilityViewerConfigured, diagOK},
}

// rosterExpectedOrder is the reviewed ranking, written out independently of
// rosterRowPrecedence so that reordering the production list is caught: the
// pair test generates its pairs from the production list and decides the
// winner of each from this one.
var rosterExpectedOrder = []rosterRowState{
	rosterStateSetupIncomplete,
	rosterStateNoRosterFile,
	rosterStateNotResponding,
	rosterStateRefused,
	rosterStateLoginWritesFailed,
	rosterStateTargetUnusable,
	rosterStateTargetMissing,
	rosterStateReplaced,
	rosterStateOwnerChanged,
	rosterStateImmutable,
	rosterStateParentNotWritable,
	rosterStateChangedExternally,
	rosterStateDirNotSynced,
	rosterStateNotYetVerified,
	rosterStateOK,
}

// expectedRank is s's position in rosterExpectedOrder (-1 if absent).
func expectedRank(s rosterRowState) int {
	for i, e := range rosterExpectedOrder {
		if e == s {
			return i
		}
	}
	return -1
}

// rosterStateName is s's name in the production list.
func rosterStateName(s rosterRowState) string {
	for _, r := range rosterRowPrecedence {
		if r.state == s {
			return r.name
		}
	}
	return fmt.Sprint(int(s))
}

// activeRosterStates lists the states f makes active, in precedence order.
func activeRosterStates(f rosterDurabilityFacts) []rosterRowState {
	var out []rosterRowState
	for _, r := range rosterRowPrecedence {
		if f.stateActive(r.state) {
			out = append(out, r.state)
		}
	}
	return out
}

// TestRosterRowPrecedence_IsCompleteAndEndsInOK: every state has a case here
// and exactly one entry in the list, and ok is last (it is always active).
func TestRosterRowPrecedence_IsCompleteAndEndsInOK(t *testing.T) {
	seen := map[rosterRowState]bool{}
	for _, r := range rosterRowPrecedence {
		if seen[r.state] {
			t.Errorf("state %q is listed twice", r.name)
		}
		seen[r.state] = true
		if _, ok := rosterStateCases[r.state]; !ok {
			t.Errorf("state %q has no rosterStateCases entry: add one so the pair test covers it", r.name)
		}
		if expectedRank(r.state) < 0 {
			t.Errorf("state %q is missing from rosterExpectedOrder: rank it there", r.name)
		}
	}
	for s := range rosterStateCases {
		if !seen[s] {
			t.Errorf("rosterStateCases has state %d, which rosterRowPrecedence does not list", s)
		}
	}
	if last := rosterRowPrecedence[len(rosterRowPrecedence)-1]; last.state != rosterStateOK {
		t.Errorf("the last state is %q, want ok", last.name)
	}
	if got := activeRosterStates(rosterHealthyFacts()); len(got) != 1 || got[0] != rosterStateOK {
		t.Errorf("healthy facts activate %v, want only ok", got)
	}
}

// checkRosterRendering asserts both renderings of f show state want, and
// that a viewer sees want or — want being admin-only — the next active state
// in rosterExpectedOrder that has a viewer rendering.
func checkRosterRendering(t *testing.T, label string, f rosterDurabilityFacts, want rosterRowState) {
	t.Helper()
	wc := rosterStateCases[want]
	admin := f.adminRow()
	if admin.Status != wc.adminStatus || !strings.HasPrefix(admin.Message, wc.adminPrefix(f)) {
		t.Errorf("%s: admin row = %s %q, want %s %q (%s)", label, admin.Status, admin.Message,
			wc.adminStatus, wc.adminPrefix(f), rosterStateName(want))
	}
	if admin.Code != adminRosterDurabilityCode || (admin.Status != diagOK && admin.OperatorAction == "") {
		t.Errorf("%s: admin row %+v lost its code or remedy", label, admin)
	}
	vs := want
	for _, s := range rosterExpectedOrder[expectedRank(want):] {
		if rosterStateCases[s].viewer != "" && f.stateActive(s) {
			vs = s
			break
		}
	}
	vc := rosterStateCases[vs]
	viewer := f.viewerRow()
	if viewer.Status != vc.viewerStatus || viewer.Message != vc.viewer {
		t.Errorf("%s: viewer row = %s %q, want %s %q (%s)", label, viewer.Status, viewer.Message,
			vc.viewerStatus, vc.viewer, rosterStateName(vs))
	}
	wantAction := ""
	if vc.viewerStatus != diagOK {
		wantAction = diagnosticsRedactedAction
	}
	if viewer.OperatorAction != wantAction || viewer.Code != adminRosterDurabilityCode {
		t.Errorf("%s: viewer row %+v, want code %s and action %q", label, viewer, adminRosterDurabilityCode, wantAction)
	}
}

// TestRosterRowPrecedence_EveryPairShowsTheHigherState: for every state
// alone, and for every pair (A, B) of states with A ranked above B, both
// active at once, the admin row shows A and the viewer row shows A — or, A
// being admin-only, what B shows. The pairs come from rosterRowPrecedence,
// so a new state is covered as soon as it is listed (and the completeness
// test forces it a case). Swapping any two adjacent entries, or a renderer
// that does not walk the list, fails it.
func TestRosterRowPrecedence_EveryPairShowsTheHigherState(t *testing.T) {
	n := len(rosterRowPrecedence)
	pairs := 0
	for i := 0; i < n; i++ {
		a := rosterRowPrecedence[i].state
		f := rosterHealthyFacts()
		rosterStateCases[a].set(&f)
		checkRosterRendering(t, rosterStateName(a)+" alone", f, a)
		for j := 0; j < n; j++ {
			b := rosterRowPrecedence[j].state
			if j == i || b == rosterStateOK || a == rosterStateOK {
				continue // ok is always active: its pairs are the "alone" cases
			}
			f := rosterHealthyFacts()
			rosterStateCases[a].set(&f)
			rosterStateCases[b].set(&f)
			label := rosterStateName(a) + " + " + rosterStateName(b)
			if got := activeRosterStates(f); len(got) != 3 {
				t.Fatalf("%s: setters activate %v, want exactly those two and ok", label, got)
			}
			want := a
			if expectedRank(b) < expectedRank(a) {
				want = b
			}
			checkRosterRendering(t, label, f, want)
			pairs++
		}
	}
	if want := (n - 1) * (n - 2); pairs != want {
		t.Errorf("checked %d ordered pairs, want %d", pairs, want)
	}
}

// TestRosterDurability_RefusedFirstSaveAfterRestartIsNotHidden is the exact
// Codex case through the real save path and handler: a fresh boot (the
// roster loaded, nothing written yet) whose first admin change is refused
// shows the refusal with its count — not "not verified yet" with "No action
// is needed now" — to admins, and the fixed refused message to viewers.
func TestRosterDurability_RefusedFirstSaveAfterRestartIsNotHidden(t *testing.T) {
	snapshotAuthGlobals(t)
	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	setupRosterLoadedNotWritten(t, c)
	if row := checkAdminRosterDurability(); row.Message != rosterTargetNotYetVerified {
		t.Fatalf("fresh boot: row = %+v, want not yet verified", row)
	}

	prev := rosterAtomicWrite
	rosterAtomicWrite = func(p string, _ []byte, _ os.FileMode) (fileutil.WriteResult, error) {
		return fileutil.WriteResult{}, fmt.Errorf("atomic write %s: create temp: %w", p,
			&fs.PathError{Op: "open", Path: p + ".tmp.0", Err: syscall.EACCES})
	}
	t.Cleanup(func() { rosterAtomicWrite = prev })
	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, "/api/auth/users", map[string]any{
		"username": "newviewer", "password": "Sup3rSecret9!", "role": string(RoleViewer),
	}))
	if w.Code < 500 {
		t.Fatalf("POST with the save refused: status = %d, want 5xx", w.Code)
	}

	row := checkAdminRosterDurability()
	if row.Status != diagWarn || !strings.HasPrefix(row.Message, "1 admin account change(s) were refused") ||
		strings.Contains(row.OperatorAction, "No action is needed") {
		t.Errorf("after the refused first save: row = %+v, want the refusal with its count", row)
	}
	if _, v := durabilityRowAt(t, RoleViewer); v.Status != diagWarn || v.Message != rosterDurabilityViewerRefused {
		t.Errorf("viewer row = %+v, want %q", v, rosterDurabilityViewerRefused)
	}

	// The refusal stays until a later save lands, then clears.
	rosterAtomicWrite = prev
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	if row := checkAdminRosterDurability(); row.Status != diagOK {
		t.Errorf("after a later landed save: row = %+v, want ok", row)
	}
}

// TestRosterDurability_RefusalAfterALandedSaveStaysUntilTheNextOne: after a
// landed save, a refused change is shown, a second refusal adds to it, and
// only the next landed save clears it — while the since-startup totals keep
// counting.
func TestRosterDurability_RefusalAfterALandedSaveStaysUntilTheNextOne(t *testing.T) {
	c, _ := savedRosterCfg(t)
	rosterPersistRefused.Add(1)
	if row := checkAdminRosterDurability(); !strings.HasPrefix(row.Message, "1 admin account change(s) were refused") {
		t.Fatalf("after one refusal: row = %+v", row)
	}
	rosterPersistRefused.Add(1)
	row := checkAdminRosterDurability()
	if !strings.HasPrefix(row.Message, "2 admin account change(s) were refused") || !strings.Contains(row.Message, "since startup: 2 refused") {
		t.Fatalf("after two refusals: row = %+v", row)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	if row := checkAdminRosterDurability(); row.Status != diagOK {
		t.Fatalf("after a landed save: row = %+v, want ok", row)
	}
	rosterPersistRefused.Add(1)
	if row := checkAdminRosterDurability(); !strings.HasPrefix(row.Message, "1 admin account change(s) were refused") ||
		!strings.Contains(row.Message, "since startup: 3 refused") {
		t.Errorf("a refusal after the landed save: row = %+v, want 1 since it and 3 since startup", row)
	}
}

// TestRosterDurability_RefusalNamesTheProbedCause: ranking the refusal first
// keeps the cause the live check sees in its remedy.
func TestRosterDurability_RefusalNamesTheProbedCause(t *testing.T) {
	f := rosterHealthyFacts()
	f.refused, f.refusedTotal, f.parentNotWritable = 1, 1, true
	if row := f.adminRow(); !strings.Contains(row.OperatorAction, rosterParentNotWritable) {
		t.Errorf("remedy = %q, want it to name the directory problem", row.OperatorAction)
	}
	f.parentNotWritable, f.landed = false, false
	if row := f.adminRow(); strings.Contains(row.OperatorAction, "also reports") {
		t.Errorf("remedy = %q names the not-yet-verified boot state as a cause", row.OperatorAction)
	}
}
