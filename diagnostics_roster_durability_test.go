package main

// Gates for the admin_roster_durability operator-contract row (CHAOS-70
// evidence) and its role redaction (SEC-DIAG-ROSTER-1 policy, PR #1545):
//
//	fact                              viewer/operator                   admin
//	roster not durable                status + fixed message            + count + action
//	refused admin-change count        status + fixed message, no count  count + remedy
//	degraded login-write posture      nothing (not even the status)     count + remedy
//
// The degraded row is the one that needs care: it can be the row's ONLY reason
// to warn, so a viewer rendering that kept the admin status would itself be the
// replay-window oracle the policy withholds.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// checkAdminRosterDurability is the admin_roster_durability row as
// buildOperatorContract renders it for an admin (one read of the facts).
func checkAdminRosterDurability() OperatorContractCheck {
	return readRosterDurabilityFacts().adminRow()
}

func swapCfgForRosterDurability(t *testing.T, c *Config) {
	t.Helper()
	prev := cfg
	cfg = c
	t.Cleanup(func() { cfg = prev })
	resetRosterPersistCountersForTest()
	t.Cleanup(resetRosterPersistCountersForTest)
}

// pinRosterDurabilityBaseline makes the shared cfg's admin_roster_durability
// row deterministic for a test that expects a default report: a usable
// roster target (an existing roster file with a landed write recorded) and
// zeroed CHAOS-70 counters, regardless of what an earlier shuffled test left
// in the process-global cfg. It deliberately does not LOAD or SAVE the
// shared cfg (that would merge or overwrite accounts); it records a landed
// write of the fixture's exact bytes and owner. Restored on cleanup.
func pinRosterDurabilityBaseline(t *testing.T) {
	t.Helper()
	p := writeRosterFixture(t)
	data, err := os.ReadFile(p) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg.mu.Lock()
	prevFile, prevErr := cfg.uiUsersFile, cfg.uiUsersLoadErr
	prevLanded, prevWritten, prevSynced := cfg.uiUsersWriteLanded, cfg.uiUsersWritten, cfg.uiUsersWriteSynced
	cfg.uiUsersFile, cfg.uiUsersLoadErr = p, nil
	cfg.uiUsersWriteLanded, cfg.uiUsersWriteSynced = true, true
	cfg.uiUsersWritten = digestRosterWrite(p, data, fi)
	cfg.mu.Unlock()
	resetRosterPersistCountersForTest()
	t.Cleanup(func() {
		cfg.mu.Lock()
		cfg.uiUsersFile, cfg.uiUsersLoadErr = prevFile, prevErr
		cfg.uiUsersWriteLanded, cfg.uiUsersWritten, cfg.uiUsersWriteSynced = prevLanded, prevWritten, prevSynced
		cfg.mu.Unlock()
		resetRosterPersistCountersForTest()
	})
}

// configuredRosterCfg returns a set-up node, optionally with a roster file.
func configuredRosterCfg(t *testing.T, withFile bool) *Config {
	t.Helper()
	c := &Config{}
	if err := c.SetAuth("admin", "Or1ginalPass!"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	if withFile {
		p := filepath.Join(t.TempDir(), "ui_users.json")
		c.SetUIUsersFile(p)
		// A landed save is the evidence persistence works.
		if err := c.SaveUIUsersFile(); err != nil {
			t.Fatalf("SaveUIUsersFile: %v", err)
		}
	}
	return c
}

// durabilityRowAt drives the real /api/diagnostics handler at role.
func durabilityRowAt(t *testing.T, role UIRole) (OperatorContract, *OperatorContractCheck) {
	t.Helper()
	r := roleCtx(httptest.NewRequest(http.MethodGet, "/api/diagnostics", http.NoBody), role)
	w := httptest.NewRecorder()
	apiDiagnostics(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("role %q: status = %d, want 200", role, w.Code)
	}
	c := decodeContract(t, w)
	row := findDiagnosticCheck(c, adminRosterDurabilityCode)
	if row == nil {
		t.Fatalf("role %q: admin_roster_durability row missing", role)
	}
	return c, row
}

func TestCheckAdminRosterDurability_WarnsWhenMemoryOnly(t *testing.T) {
	swapCfgForRosterDurability(t, configuredRosterCfg(t, false))
	noteRosterNotDurable()

	got := checkAdminRosterDurability()
	if got.Code != adminRosterDurabilityCode || got.Status != diagWarn {
		t.Fatalf("got %+v, want warn admin_roster_durability", got)
	}
	if !strings.Contains(got.Message, "LOST on restart") || !strings.Contains(got.Message, "1 in-memory-only account change") {
		t.Errorf("message = %q, want loss statement and change count", got.Message)
	}
	if !strings.Contains(got.OperatorAction, "-ui-users-file") {
		t.Errorf("operator_action = %q, want remedy naming -ui-users-file", got.OperatorAction)
	}
	// TestApiDiagnostics_NoSensitiveValues forbids /data/ paths on the contract.
	if strings.Contains(got.Message+got.OperatorAction, "/data/") {
		t.Errorf("row names a /data/ path: %+v", got)
	}
}

// rosterDurabilityStubProvider makes a node "set up" through a legacy
// identity provider alone, with no local account.
type rosterDurabilityStubProvider struct{}

func (rosterDurabilityStubProvider) Verify(string, string) bool { return false }
func (rosterDurabilityStubProvider) Name() string               { return "stub" }

// TestCheckAdminRosterDurability_ProviderOnlyNamesBreakGlassGap pins the owner
// decision answering Codex's P2 on #1601: a provider-only node with no local
// administrator still warns, and the admin rendering says WHY — an IdP outage
// locks everyone out — and names the break-glass remedy in the console's own
// term ("Administrators"). Below admin the fixed not-durable message is
// unchanged: whether a local admin exists is roster-derived.
func TestCheckAdminRosterDurability_ProviderOnlyNamesBreakGlassGap(t *testing.T) {
	c := &Config{}
	c.SetProvider(rosterDurabilityStubProvider{})
	swapCfgForRosterDurability(t, c)
	if !cfg.IsConfigured() || cfg.hasLocalAdministrator() {
		t.Fatal("precondition: provider-only node must be set up with no local administrator")
	}

	got := checkAdminRosterDurability()
	if got.Status != diagWarn {
		t.Fatalf("provider-only: status = %q, want warn", got.Status)
	}
	if !strings.Contains(got.Message, "No local administrator account: if the identity provider is unavailable, nobody can sign in.") {
		t.Errorf("message = %q, want the break-glass rationale", got.Message)
	}
	if !strings.Contains(got.OperatorAction, "Create a local break-glass administrator in Administrators") ||
		!strings.Contains(got.OperatorAction, "-ui-users-file") {
		t.Errorf("operator_action = %q, want the break-glass remedy plus the roster file", got.OperatorAction)
	}

	// Control: a node WITH a local admin keeps the plain durability message.
	swapCfgForRosterDurability(t, configuredRosterCfg(t, false))
	if got := checkAdminRosterDurability(); strings.Contains(got.Message, "No local administrator") {
		t.Errorf("node with a local admin got the break-glass message: %q", got.Message)
	}

	// Below admin: the same fixed message as any non-durable node.
	swapCfgForRosterDurability(t, c)
	_, row := durabilityRowAt(t, RoleViewer)
	assertRedactedRowIsFixed(t, "provider-only viewer", row)
	if row.Message != rosterDurabilityViewerNotDurable {
		t.Errorf("viewer message = %q, want the fixed not-durable message", row.Message)
	}
}

func TestHasLocalAdministrator(t *testing.T) {
	c := &Config{}
	if c.hasLocalAdministrator() {
		t.Error("empty config reports a local administrator")
	}
	if err := c.SetAuth("legacy", "Or1ginalPass!"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	if !c.hasLocalAdministrator() {
		t.Error("an unshadowed legacy login is a local administrator (VerifyUIUser grants RoleAdmin)")
	}
	c.mu.Lock()
	c.uiUsers = map[string]*uiAdminUser{"legacy": {role: RoleViewer}}
	c.mu.Unlock()
	if c.hasLocalAdministrator() {
		t.Error("a legacy login shadowed by a viewer roster entry is not an administrator")
	}
	c.mu.Lock()
	c.uiUsers["root"] = &uiAdminUser{role: RoleAdmin}
	c.mu.Unlock()
	if !c.hasLocalAdministrator() {
		t.Error("a roster admin is a local administrator")
	}
}

func TestCheckAdminRosterDurability_OKWhenPersistedOrNotSetUp(t *testing.T) {
	swapCfgForRosterDurability(t, configuredRosterCfg(t, true))
	if got := checkAdminRosterDurability(); got.Status != diagOK {
		t.Errorf("persisted roster: status = %q, want ok", got.Status)
	}

	cfg = &Config{} // setup not complete: no credential to lose
	if got := checkAdminRosterDurability(); got.Status != diagOK {
		t.Errorf("not set up: status = %q, want ok", got.Status)
	}
	cfg = nil
	if got := checkAdminRosterDurability(); got.Status != diagOK {
		t.Errorf("nil cfg: status = %q, want ok", got.Status)
	}
}

// TestCheckAdminRosterDurability_UnusableRosterTarget answers Codex's P2 on
// #1601: a CONFIGURED but unusable -ui-users-file must not read as persisted.
// Startup continues after LoadUIUsersFile fails, and the failure counters stay
// zero until a mutation is attempted, so the recorded load outcome and a
// read-only stat of the target are what make the gap visible.
func TestCheckAdminRosterDurability_UnusableRosterTarget(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, c *Config) // configures and loads the roster path
		warn  bool
	}{
		{"directory-as-path", setupRosterDirectoryAsPath, true},
		{"missing-parent", setupRosterMissingParent, true},
		{"unreadable-file", setupRosterUnreadableFile, true},
		// Deterministic twin of unreadable-file for privileged runners: the
		// read error a mode-000 file produces, recorded as the load outcome.
		{"unreadable-file-recorded", setupRosterRecordedReadError, true},
		// Codex P2 on #1601: readable roster, unwritable directory. Both stats
		// pass; the live probe's faccessat refuses. Skipped where the
		// runner's privileges bypass the mode bits (root, CAP_DAC_OVERRIDE).
		{"read-only-parent", setupRosterReadOnlyParent, true},
		// Deterministic twin for privileged runners (CI runs as root): a
		// read-only remount after a landed save, injected at faccessat.
		{"read-only-volume-injected", setupRosterReadOnlyVolumeInjected, true},
		// A configured path with no write since startup: not verified yet.
		{"never-written", setupRosterNeverWritten, true},
		{"loaded-not-yet-written", setupRosterLoadedNotWritten, true},
		// Nothing exists yet, so nothing is proven until a save.
		{"missing-file-first-run", setupRosterFirstRun, true},
		{"missing-file-then-saved", setupRosterFirstRunThenSaved, false},
		{"symlink", setupRosterSymlink, true},
		{"healthy-file", setupRosterHealthyFile, false},
		// Codex P2 4317024199 on #1601: a write landed, then the file was
		// removed externally. The stale evidence must not read ok.
		{"healthy-file-then-deleted", thenRosterDeleted(setupRosterHealthyFile), true},
		{"missing-file-saved-then-deleted", thenRosterDeleted(setupRosterFirstRunThenSaved), true},
		// Codex P2 4317365500 on #1601: a write landed, then the file was
		// replaced or edited outside Culvert. A restart would load it.
		{"healthy-file-then-replaced", thenRosterReplacedExternally(setupRosterHealthyFile), true},
		{"healthy-file-then-edited-in-place", thenRosterEditedInPlace(setupRosterHealthyFile), true},
		{"saved-file-then-replaced", thenRosterReplacedExternally(setupRosterFirstRunThenSaved), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := configuredRosterCfg(t, false)
			swapCfgForRosterDurability(t, c)
			tc.setup(t, c)
			assertRosterTargetRow(t, c, tc.name, tc.warn)
		})
	}
}

func setupRosterDirectoryAsPath(t *testing.T, c *Config) {
	c.SetUIUsersFile(t.TempDir())
	if err := c.LoadUIUsersFile(); err == nil {
		t.Fatal("precondition: loading a directory must fail")
	}
}

func setupRosterMissingParent(t *testing.T, c *Config) {
	c.SetUIUsersFile(filepath.Join(t.TempDir(), "missing", "ui_users.json"))
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("precondition: a missing file loads as first run, got %v", err)
	}
}

func writeRosterFixture(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ui_users.json")
	if err := os.WriteFile(p, []byte(`{"users":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func setupRosterUnreadableFile(t *testing.T, c *Config) {
	p := writeRosterFixture(t)
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	c.SetUIUsersFile(p)
	if err := c.LoadUIUsersFile(); err == nil {
		t.Skip("running with privileges that read a mode-000 file; unreadable case not reproducible here")
	}
}

func setupRosterRecordedReadError(t *testing.T, c *Config) {
	p := writeRosterFixture(t)
	c.SetUIUsersFile(p)
	c.mu.Lock()
	c.uiUsersLoadErr = &os.PathError{Op: "open", Path: p, Err: os.ErrPermission}
	c.mu.Unlock()
}

// setupRosterReadOnlyParent loads a readable roster from a mode-0555
// directory. It first proves the directory really refuses writes here (else
// the runner bypasses mode bits, e.g. as root, and the case is skipped in
// favour of read-only-parent-recorded), and that a real roster save there
// fails — the write the stat-only check claimed would succeed.
func setupRosterReadOnlyParent(t *testing.T, c *Config) {
	p := writeRosterFixture(t)
	dir := filepath.Dir(p)
	if err := os.Chmod(dir, 0o555); err != nil { // #nosec G302 -- deliberately read-only fixture dir
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- restore so TempDir cleanup can remove it
	if f, err := os.CreateTemp(dir, "privcheck.*"); err == nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		t.Skip("runner bypasses directory mode bits (root or CAP_DAC_OVERRIDE); " +
			"read-only-parent-recorded covers this state")
	}
	c.SetUIUsersFile(p)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("precondition: a readable roster in a read-only directory must load, got %v", err)
	}
	if err := c.SaveUIUsersFile(); err == nil {
		t.Fatal("precondition: a roster save in a read-only directory must fail")
	}
	if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("precondition: the roster must still stat as a regular file (err %v)", err)
	}
}

// setupRosterReadOnlyVolumeInjected: a landed save, then the volume goes
// read-only (faccessat's EROFS, injected).
func setupRosterReadOnlyVolumeInjected(t *testing.T, c *Config) {
	setupRosterHealthyFile(t, c)
	injectParentAccess(t, errEROFS)
}

func setupRosterNeverWritten(t *testing.T, c *Config) {
	c.SetUIUsersFile(writeRosterFixture(t))
}

// setupRosterLoadedNotWritten is a fresh boot: an existing roster loaded,
// nothing written yet.
func setupRosterLoadedNotWritten(t *testing.T, c *Config) {
	c.SetUIUsersFile(writeRosterFixture(t))
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile: %v", err)
	}
}

func setupRosterFirstRun(t *testing.T, c *Config) {
	c.SetUIUsersFile(filepath.Join(t.TempDir(), "ui_users.json"))
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("first-run load: %v", err)
	}
}

// setupRosterFirstRunThenSaved: the first roster save after a first-run boot
// creates the file, and that landed write is the evidence.
func setupRosterFirstRunThenSaved(t *testing.T, c *Config) {
	setupRosterFirstRun(t, c)
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}
}

func setupRosterSymlink(t *testing.T, c *Config) {
	target := writeRosterFixture(t)
	link := filepath.Join(t.TempDir(), "ui_users.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	c.SetUIUsersFile(link)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("a symlinked roster must still load: %v", err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("loading replaced the symlink (err %v)", err)
	}
}

// setupRosterHealthyFile: a roster saved by an earlier boot, this boot's
// load, and an admin account change that lands.
func setupRosterHealthyFile(t *testing.T, c *Config) {
	c.SetUIUsersFile(filepath.Join(t.TempDir(), "ui_users.json"))
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile: %v", err)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}
}

// thenRosterDeleted runs setup (which must leave a landed write) and then
// removes the roster file, as an external cleanup job would.
func thenRosterDeleted(setup func(t *testing.T, c *Config)) func(t *testing.T, c *Config) {
	return func(t *testing.T, c *Config) {
		setup(t, c)
		if !c.rosterWriteLanded() {
			t.Fatal("precondition: no landed write recorded")
		}
		path, _ := c.rosterPersistTarget()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}

// externalRoster is a different, valid roster an external writer installs.
var externalRoster = []byte(`{"users":[{"username":"restored-by-cm","pass_hash":"00","role":"admin"}]}`)

// thenRosterReplacedExternally runs setup (which must leave a landed write)
// and then atomically replaces the roster with different content, as a
// configuration manager would (a new inode renamed over it).
func thenRosterReplacedExternally(setup func(t *testing.T, c *Config)) func(t *testing.T, c *Config) {
	return func(t *testing.T, c *Config) {
		setup(t, c)
		path, _ := c.rosterPersistTarget()
		side := path + ".cm"
		if err := os.WriteFile(side, externalRoster, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(side, path); err != nil {
			t.Fatal(err)
		}
	}
}

// thenRosterEditedInPlace runs setup and then rewrites the roster's bytes in
// place (same inode, same size), as an editor that writes through the file
// would: only a content comparison sees this.
func thenRosterEditedInPlace(setup func(t *testing.T, c *Config)) func(t *testing.T, c *Config) {
	return func(t *testing.T, c *Config) {
		setup(t, c)
		path, _ := c.rosterPersistTarget()
		before, err := os.ReadFile(path) // #nosec G304 -- test temp path
		if err != nil || len(before) == 0 {
			t.Fatalf("read roster: %v", err)
		}
		edited := bytes.Clone(before)
		edited[len(edited)-1] ^= 0x20               // same length, different content
		f, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- test temp path
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteAt(edited, 0); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRosterDurability_ExternalReplaceWarnsUntilReconciled: after a landed
// save the row is ok; an external replacement makes it warn with its own
// message and remedy; Culvert's own save (which writes the roster in use
// back) clears it and does not trip it; a touch alone reports changed
// externally where the inode stamp is known; an in-place same-size edit
// reports replaced. Removing the comparison, or not recording
// the digest on a save, fails this test.
func TestRosterDurability_ExternalReplaceWarnsUntilReconciled(t *testing.T) {
	c, path := savedRosterCfg(t)
	wantOK := func(stage string) {
		t.Helper()
		if row := checkAdminRosterDurability(); row.Status != diagOK {
			t.Errorf("%s: row = %+v, want ok", stage, row)
		}
	}
	wantReplaced := func(stage string) {
		t.Helper()
		row := checkAdminRosterDurability()
		if row.Status != diagWarn || row.Message != rosterTargetReplaced {
			t.Fatalf("%s: row = %+v, want warn %q", stage, row, rosterTargetReplaced)
		}
		if !strings.Contains(row.OperatorAction, "Reconcile") || !strings.Contains(row.OperatorAction, "restart") {
			t.Errorf("%s: action = %q, want the reconcile-then-save-or-restart remedy", stage, row.OperatorAction)
		}
	}
	wantOK("after a landed save")

	thenRosterReplacedExternally(func(*testing.T, *Config) {})(t, c)
	wantReplaced("after an external replace")
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}
	wantOK("after Culvert's own save")

	// A touch leaves the bytes alone but is not the untouched inode the save
	// landed (Codex P2 4325019932): changed outside Culvert, until the next
	// save re-verifies. Platforms without an inode stamp compare bytes only.
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if row := checkAdminRosterDurability(); c.uiUsersWritten.stamp.known && row.Message != rosterTargetChangedExternally {
		t.Errorf("after a touch: row = %+v, want %q", row, rosterTargetChangedExternally)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}
	wantOK("after the save that re-verifies")

	thenRosterEditedInPlace(func(*testing.T, *Config) {})(t, c)
	wantReplaced("after an in-place edit")
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}
	wantOK("after the next save")
}

// TestRosterDurability_DeletedAfterWriteWarnsUntilRecreated: the deleted
// roster gets its own message and remedy, and the next save, which recreates
// the file, clears it. Dropping the missing-file override fails this test.
func TestRosterDurability_DeletedAfterWriteWarnsUntilRecreated(t *testing.T) {
	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	thenRosterDeleted(setupRosterHealthyFile)(t, c)

	row := checkAdminRosterDurability()
	if row.Status != diagWarn || row.Message != rosterTargetDisappeared {
		t.Fatalf("row = %+v, want warn %q", row, rosterTargetDisappeared)
	}
	if !strings.Contains(row.OperatorAction, "recreates the file") ||
		!strings.Contains(row.OperatorAction, "Before the next restart") {
		t.Errorf("action = %q, want the save-or-restore-before-restart remedy", row.OperatorAction)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}
	path, _ := c.rosterPersistTarget()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the save did not recreate the roster: %v", err)
	}
	if row := checkAdminRosterDurability(); row.Status != diagOK {
		t.Errorf("after the save recreated the file: row = %+v, want ok", row)
	}
}

// assertRosterTargetRow checks the admin and viewer renderings for one
// roster-target state.
func assertRosterTargetRow(t *testing.T, c *Config, name string, warn bool) {
	t.Helper()
	path, _ := c.rosterPersistTarget()
	got := checkAdminRosterDurability()
	if (got.Status == diagWarn) != warn {
		t.Fatalf("admin: %+v, want warn=%v", got, warn)
	}
	if strings.Contains(got.Message+got.OperatorAction, path) {
		t.Errorf("admin row names the roster path: %+v", got)
	}
	_, viewer := durabilityRowAt(t, RoleViewer)
	assertRedactedRowIsFixed(t, "viewer "+name, viewer)
	wantViewer, wantMsg := diagOK, rosterDurabilityViewerConfigured
	if warn {
		wantViewer, wantMsg = diagWarn, rosterDurabilityViewerNotDurable
		if got.Message == rosterTargetNotYetVerified {
			wantMsg = rosterDurabilityViewerNotYetVerified
		}
		if !strings.Contains(got.OperatorAction, "-ui-users-file") || !strings.Contains(got.OperatorAction, "restart") {
			t.Errorf("admin operator_action = %q, want the fix-path-and-restart remedy", got.OperatorAction)
		}
	}
	if viewer.Status != wantViewer || viewer.Message != wantMsg {
		t.Errorf("viewer: %+v, want %s with %q", viewer, wantViewer, wantMsg)
	}
}

// TestRosterTargetProblem_IsReadOnly pins that the diagnostics probe never
// creates the roster file or its directory.
func TestRosterTargetProblem_IsReadOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	p := filepath.Join(dir, "ui_users.json")
	f := rosterDurabilityFacts{configured: true, persisted: true, landed: true}
	f.applyProbe(probeRosterTarget(p, rosterWrittenDigest{}))
	if f.unusable == "" {
		t.Fatal("missing parent reported as usable")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the probe created %s (stat err %v)", dir, err)
	}
}

// TestCheckAdminRosterDurability_ReportsWriteFailuresToAdmin ports #1553's
// refused/degraded counters: an admin sees both counts and the remedy.
func TestCheckAdminRosterDurability_ReportsWriteFailuresToAdmin(t *testing.T) {
	c := configuredRosterCfg(t, true)
	swapCfgForRosterDurability(t, c)
	rosterPersistRefused.Add(2)
	rosterPersistBestEffort.Add(1)

	got := checkAdminRosterDurability()
	if got.Status != diagWarn {
		t.Fatalf("status = %q, want warn", got.Status)
	}
	if !strings.Contains(got.Message, "2 admin account change(s)") || !strings.Contains(got.Message, "1 login-time") {
		t.Errorf("message = %q, want both counts", got.Message)
	}
	if !strings.Contains(got.OperatorAction, "re-apply the refused change") {
		t.Errorf("operator_action = %q, want the re-apply remedy", got.OperatorAction)
	}
	if strings.Contains(got.Message+got.OperatorAction, c.uiUsersFile) {
		t.Fatal("row must not leak the roster path")
	}
}

// TestApiDiagnostics_RosterDurabilityIsAdminOnlyDetail is the redaction gate,
// driven through the real handler for every state the row can be in.
func TestApiDiagnostics_RosterDurabilityIsAdminOnlyDetail(t *testing.T) {
	cases := []struct {
		name       string
		withFile   bool
		notDurable int64
		refused    int64
		degraded   int64
		viewerWarn bool
		viewerMsg  string
	}{
		{"memory-only", false, 3, 0, 0, true, rosterDurabilityViewerNotDurable},
		{"refused", true, 0, 4, 0, true, rosterDurabilityViewerRefused},
		{"refused+degraded", true, 0, 4, 5, true, rosterDurabilityViewerRefused},
		{"degraded-only", true, 0, 0, 5, false, rosterDurabilityViewerConfigured},
		{"healthy", true, 0, 0, 0, false, rosterDurabilityViewerConfigured},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			swapCfgForRosterDurability(t, configuredRosterCfg(t, tc.withFile))
			rosterNotDurable.Store(tc.notDurable)
			rosterPersistRefused.Store(tc.refused)
			rosterPersistBestEffort.Store(tc.degraded)

			_, adminRow := durabilityRowAt(t, RoleAdmin)
			if wantWarn := tc.notDurable+tc.refused+tc.degraded > 0 || !tc.withFile; (adminRow.Status == diagWarn) != wantWarn {
				t.Fatalf("admin: status = %q, want warn=%v", adminRow.Status, wantWarn)
			}
			if adminRow.Status == diagWarn && adminRow.OperatorAction == "" {
				t.Fatal("admin: warn row lost its operator action")
			}

			for _, role := range []UIRole{RoleViewer, RoleOperator, UIRole("")} {
				if !role.HasRole(RoleViewer) {
					continue // the handler refuses such a role before rendering
				}
				_, row := durabilityRowAt(t, role)
				label := "/api/diagnostics " + string(role) + " " + tc.name
				assertRedactedRowIsFixed(t, label, row)
				if (row.Status == diagWarn) != tc.viewerWarn {
					t.Errorf("%s: status = %q, want warn=%v", label, row.Status, tc.viewerWarn)
				}
				if row.Message != tc.viewerMsg {
					t.Errorf("%s: message = %q, want %q", label, row.Message, tc.viewerMsg)
				}
			}
		})
	}
}

// TestApiDiagnostics_DegradedRosterWriteIsNotAViewerOracle pins the subtle
// half: below admin, a node whose ONLY roster problem is a degraded login-path
// write must render byte-identically to a healthy node — row AND verdict.
// Keeping the admin status (the #1545 username-row convention) would tell a
// viewer that a backup-code or TOTP replay window may be open.
func TestApiDiagnostics_DegradedRosterWriteIsNotAViewerOracle(t *testing.T) {
	swapCfgForRosterDurability(t, configuredRosterCfg(t, true))
	healthy, healthyRow := durabilityRowAt(t, RoleViewer)

	rosterPersistBestEffort.Store(7)
	degraded, degradedRow := durabilityRowAt(t, RoleViewer)
	if *degradedRow != *healthyRow {
		t.Errorf("viewer row differs between healthy and degraded-only: %+v vs %+v", healthyRow, degradedRow)
	}
	if degraded.Verdict != healthy.Verdict {
		t.Errorf("viewer verdict moved %q -> %q on a degraded-only roster write", healthy.Verdict, degraded.Verdict)
	}

	// Control: the admin does see it, so the fixture really is degraded.
	_, adminRow := durabilityRowAt(t, RoleAdmin)
	if adminRow.Status != diagWarn || !strings.Contains(adminRow.Message, "7 login-time") {
		t.Fatalf("admin: %+v, want the degraded count", adminRow)
	}
}

// TestApiHealthExplain_RosterDurabilityIsRedacted covers the second renderer.
func TestApiHealthExplain_RosterDurabilityIsRedacted(t *testing.T) {
	swapCfgForRosterDurability(t, configuredRosterCfg(t, true))
	rosterPersistRefused.Store(2)
	rosterPersistBestEffort.Store(3)

	r := roleCtx(httptest.NewRequest(http.MethodGet, "/api/health/explain", http.NoBody), RoleViewer)
	w := httptest.NewRecorder()
	apiHealthExplain(w, r)
	row := findDiagnosticCheck(decodeContract(t, w), adminRosterDurabilityCode)
	assertRedactedRowIsFixed(t, "/api/health/explain viewer", row)
	if row.Message != rosterDurabilityViewerRefused {
		t.Errorf("message = %q, want the fixed refused message", row.Message)
	}
}

// TestApiAuthUsers_CarriesRosterPersistCounters ports #1574's Users-panel
// feed onto the ADMIN-ONLY users payload.
func TestApiAuthUsers_CarriesRosterPersistCounters(t *testing.T) {
	snapshotCfgUIUsers(t)
	resetRosterPersistCountersForTest()
	t.Cleanup(resetRosterPersistCountersForTest)
	rosterPersistRefused.Store(2)
	rosterPersistBestEffort.Store(5)

	w := httptest.NewRecorder()
	apiAuthUsers(w, adminCtx(httptest.NewRequest(http.MethodGet, "/api/auth/users", http.NoBody)))
	if w.Code != http.StatusOK {
		t.Fatalf("admin GET /api/auth/users = %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, _ := body["adminRosterPersistFailures"].(float64); got != 2 {
		t.Errorf("adminRosterPersistFailures = %v, want 2", body["adminRosterPersistFailures"])
	}
	if got, _ := body["adminRosterPersistDegraded"].(float64); got != 5 {
		t.Errorf("adminRosterPersistDegraded = %v, want 5", body["adminRosterPersistDegraded"])
	}

	// The same counters must not reach a viewer through the users route.
	w = httptest.NewRecorder()
	apiAuthUsers(w, viewerCtx(httptest.NewRequest(http.MethodGet, "/api/auth/users", http.NoBody)))
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "adminRosterPersist") {
		t.Errorf("viewer GET /api/auth/users = %d %q, want refused without counters", w.Code, w.Body.String())
	}
}

// TestApiStats_DoesNotCarryRosterPersistCounters is the negative for #1574's
// original shape: /api/stats is viewer-readable, so the counts stay off it.
func TestApiStats_DoesNotCarryRosterPersistCounters(t *testing.T) {
	resetRosterPersistCountersForTest()
	t.Cleanup(resetRosterPersistCountersForTest)
	rosterPersistRefused.Store(2)
	rosterPersistBestEffort.Store(5)

	w := httptest.NewRecorder()
	r := viewerCtx(httptest.NewRequest(http.MethodGet, "/api/stats", http.NoBody))
	r.RemoteAddr = "198.51.100.8:9999"
	apiStats(w, r)
	if strings.Contains(w.Body.String(), "adminRosterPersist") || strings.Contains(w.Body.String(), "rosterPersist") {
		t.Errorf("/api/stats carries roster-persist counters: %s", w.Body.String())
	}
}

// TestUI_RosterPersistHintReadsTheUsersPayload pins that the legacy SPA hint
// is fed from the admin-only users payload, not from the /api/stats poll.
func TestUI_RosterPersistHintReadsTheUsersPayload(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(pkgSourceDir(), "static", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"roster-persist-hint", "renderRosterPersistHint(d)", "adminRosterPersistFailures", "adminRosterPersistDegraded"} {
		if !strings.Contains(s, want) {
			t.Errorf("static/index.html does not reference %q", want)
		}
	}
	start := strings.Index(s, "async function fetchUsers()")
	if start < 0 {
		t.Fatal("fetchUsers not found")
	}
	fetchUsers := s[start:]
	if end := strings.Index(fetchUsers, "\n}\n"); end >= 0 {
		fetchUsers = fetchUsers[:end]
	}
	if !strings.Contains(fetchUsers, "'/api/auth/users'") || !strings.Contains(fetchUsers, "renderRosterPersistHint(d)") {
		t.Errorf("the hint must be rendered from the /api/auth/users response inside fetchUsers:\n%s", fetchUsers)
	}
	statsAt := strings.Index(s, "async function fetchStats()")
	if statsAt >= 0 {
		stats := s[statsAt:]
		if end := strings.Index(stats, "\nasync function "); end >= 0 {
			stats = stats[:end]
		}
		if strings.Contains(stats, "adminRosterPersist") || strings.Contains(stats, "roster-persist-hint") {
			t.Error("fetchStats (the viewer-readable /api/stats poll) must not feed the roster-persist hint")
		}
	}
}
