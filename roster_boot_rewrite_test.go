package main

// Gates for the boot rewrite that is admin_roster_durability's write evidence
// (Codex P2 4313653877 on PR #1601). A scratch-file probe passed in a sticky
// directory where the roster belongs to another user, because only the rename
// over THAT file is refused; so the evidence is now a real rewrite of the real
// file, and these tests pin that it is exact, harmless and not a mutation.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// seedRosterFileForBoot writes a roster that an earlier boot saved (through
// the real save path, with one uniquely named account), then re-renders it in
// a form SaveUIUsersFile never produces — the legacy bare array, indented
// with tabs and carrying an unknown field — at mode 0640. A rewrite that
// re-serialised, or forced the usual 0600, cannot leave it byte-identical.
func seedRosterFileForBoot(t *testing.T) (path, user string, data []byte) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "ui_users.json")
	user = fmt.Sprintf("boot-rewrite-%d", time.Now().UnixNano())
	seed := &Config{}
	seed.SetUIUsersFile(path)
	if err := seed.SetUIUser(user, "Or1ginalPass!", RoleAdmin); err != nil {
		t.Fatalf("SetUIUser: %v", err)
	}
	if err := seed.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}
	seed.mu.RLock()
	hash := fmt.Sprintf("%x", seed.uiUsers[user].passHash)
	seed.mu.RUnlock()
	data = []byte(fmt.Sprintf("[\n\t{\"username\": %q, \"pass_hash\": %q, \"role\": \"admin\", \"x_unknown\": 1}\n]\n", user, hash))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil { // #nosec G302 -- fixture mode under test
		t.Fatal(err)
	}
	return path, user, data
}

func loadedHasUser(c *Config, user string) bool {
	for _, u := range c.ListUIUsers() {
		if u.Username == user {
			return true
		}
	}
	return false
}

// TestLoadUIUsersFile_BootRewriteIsExact: the success case. Same bytes (by
// hash), same mode, a new inode (the rename over the real file happened), the
// roster loaded, and the row reports it persisting.
func TestLoadUIUsersFile_BootRewriteIsExact(t *testing.T) {
	path, user, data := seedRosterFileForBoot(t)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile: %v", err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != sha256.Sum256(data) {
		t.Errorf("boot rewrite changed the roster bytes:\n%q\n->\n%q", data, got)
	}
	if after.Mode() != before.Mode() {
		t.Errorf("boot rewrite changed the mode: %v -> %v", before.Mode(), after.Mode())
	}
	if os.SameFile(before, after) {
		t.Error("same inode after load: the roster was not rewritten in place")
	}
	if !loadedHasUser(c, user) {
		t.Errorf("roster account %q not loaded", user)
	}
	if tried, werr := c.rosterWriteEvidence(); !tried || werr != nil {
		t.Errorf("evidence = (%v, %v), want a landed write", tried, werr)
	}
	if row := checkAdminRosterDurability(); row.Status != diagOK || row.Message != "admin roster is persisting to disk" {
		t.Errorf("row = %+v, want ok/persisting", row)
	}
}

// TestLoadUIUsersFile_BootRewriteIsNotAMutation: no audit entry, no
// configuration version and no roster-write counter comes from the rewrite.
func TestLoadUIUsersFile_BootRewriteIsNotAMutation(t *testing.T) {
	versionsDir := snapshotConfigVersionsDir(t)
	path, user, _ := seedRosterFileForBoot(t)
	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	since := time.Now().Add(-time.Second).Unix()

	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile: %v", err)
	}
	if tried, werr := c.rosterWriteEvidence(); !tried || werr != nil {
		t.Fatalf("precondition: the rewrite must have landed, got (%v, %v)", tried, werr)
	}

	for _, e := range auditGet() {
		if e.TS < since {
			continue
		}
		blob := e.Action + " " + e.Object + " " + e.Detail
		if strings.Contains(blob, user) || strings.Contains(blob, path) || strings.Contains(blob, "ui_users") {
			t.Errorf("boot rewrite produced an audit entry: %+v", e)
		}
	}
	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("boot rewrite produced %d configuration-version file(s)", len(entries))
	}
	if n := rosterPersistRefused.Load() + rosterPersistBestEffort.Load() + rosterNotDurable.Load(); n != 0 {
		t.Errorf("boot rewrite moved the roster-write counters by %d", n)
	}
}

// TestLoadUIUsersFile_RefusedBootRewriteKeepsServing: the refusal a non-owner
// gets renaming over a roster in a sticky directory (EPERM; CI runs as root,
// so it is injected at the write step). Boot continues with the roster loaded,
// the file is untouched, one log line names the path (sanitised, %q), and the
// row warns: the fix-path-and-restart remedy for admins, not-durable below.
func TestLoadUIUsersFile_RefusedBootRewriteKeepsServing(t *testing.T) {
	path, user, data := seedRosterFileForBoot(t)
	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	injectRosterRewriteFailure(t, syscall.EPERM, "rename")

	c.SetUIUsersFile(path)
	out := captureLogger(t, func() {
		if err := c.LoadUIUsersFile(); err != nil {
			t.Fatalf("a refused boot rewrite must not fail the load: %v", err)
		}
	})

	if !loadedHasUser(c, user) {
		t.Errorf("roster account %q not served after a refused rewrite", user)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, data) { // #nosec G304 -- test temp path
		t.Errorf("roster changed after a refused rewrite: %q", got)
	}
	if n := strings.Count(out, "could not be rewritten in place at startup"); n != 1 {
		t.Errorf("logged %d refusal line(s), want exactly 1:\n%s", n, out)
	}
	if want := fmt.Sprintf("%q", sanitizeLog(path)); !strings.Contains(out, want) {
		t.Errorf("log does not name the path as %s:\n%s", want, out)
	}

	row := checkAdminRosterDurability()
	if row.Status != diagWarn || !strings.Contains(row.Message, "could not be rewritten in place at startup") {
		t.Errorf("admin row = %+v, want warn naming the refused rewrite", row)
	}
	if !strings.Contains(row.OperatorAction, "-ui-users-file") || !strings.Contains(row.OperatorAction, "restart") {
		t.Errorf("admin action = %q, want the fix-path-and-restart remedy", row.OperatorAction)
	}
	_, viewer := durabilityRowAt(t, RoleViewer)
	if viewer.Status != diagWarn || viewer.Message != rosterDurabilityViewerNotDurable {
		t.Errorf("viewer row = %+v, want the fixed not-durable message", viewer)
	}

	// A later save that lands is exact evidence too, and supersedes the
	// refusal (the operator fixed the directory without restarting).
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}
	if row := checkAdminRosterDurability(); row.Status != diagOK {
		t.Errorf("after a landed save: row = %+v, want ok", row)
	}
}

// TestRewriteLoadedRoster_RefusesAChangedFile: a file replaced between read
// and rewrite is not clobbered with the older bytes.
func TestRewriteLoadedRoster_RefusesAChangedFile(t *testing.T) {
	path := writeRosterFixture(t)
	loaded, err := readRosterFile(path)
	if err != nil {
		t.Fatal(err)
	}
	newer := []byte(`{"users":[],"default_auth_outcome":"Default"}`)
	if err := os.WriteFile(path, newer, 0o600); err != nil {
		t.Fatal(err)
	}
	captureLogger(t, func() {
		if err := rewriteLoadedRoster(path, loaded); !errors.Is(err, errRosterChangedDuringLoad) {
			t.Errorf("err = %v, want errRosterChangedDuringLoad", err)
		}
	})
	if got, _ := os.ReadFile(path); !bytes.Equal(got, newer) { // #nosec G304 -- test temp path
		t.Errorf("a changed roster was overwritten: %q", got)
	}
}

// TestLoadUIUsersFile_RewriteSerialisesWithSaves: the read-and-rewrite runs
// under saveUIUsersMu, so a concurrent save cannot land between the read and
// the rewrite and then be overwritten by the older bytes.
func TestLoadUIUsersFile_RewriteSerialisesWithSaves(t *testing.T) {
	path, _, _ := seedRosterFileForBoot(t)
	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	inRewrite, release := make(chan struct{}), make(chan struct{})
	prev := rosterRewriteInPlace
	rosterRewriteInPlace = func(p string, d []byte, fi os.FileInfo) error {
		close(inRewrite)
		<-release
		return prev(p, d, fi)
	}
	t.Cleanup(func() { rosterRewriteInPlace = prev })

	c.SetUIUsersFile(path)
	loadDone := make(chan error, 1)
	go func() { loadDone <- c.LoadUIUsersFile() }()
	select {
	case <-inRewrite:
	case err := <-loadDone:
		t.Fatalf("LoadUIUsersFile returned (%v) without rewriting the roster", err)
	}
	saveDone := make(chan error, 1)
	go func() { saveDone <- c.SaveUIUsersFile() }()
	select {
	case err := <-saveDone:
		t.Fatalf("a save completed while the boot rewrite held the roster (err %v)", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-loadDone; err != nil {
		t.Fatalf("LoadUIUsersFile: %v", err)
	}
	if err := <-saveDone; err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}
}

// TestLoadUIUsersFile_BootRewriteNeverDestroysAConcurrentChange is the Codex
// P2 4315243806 gate at the row's level: an external writer replaces the
// roster after checkRosterUnchanged passed and before the write step runs.
// saveUIUsersMu cannot stop it. The newer roster must survive on disk, the
// row must not read "persisting", and one log line must say what happened.
// Replacing the exchange with a rename, or dropping the compare-and-exchange-
// back, fails both cases.
func TestLoadUIUsersFile_BootRewriteNeverDestroysAConcurrentChange(t *testing.T) {
	cases := map[string]func(t *testing.T, path string, newer []byte){
		"configuration manager replaces the file": func(t *testing.T, path string, newer []byte) {
			side := path + ".cm-new"
			if err := os.WriteFile(side, newer, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(side, path); err != nil {
				t.Fatal(err)
			}
		},
		"operator edits the file in place": func(t *testing.T, path string, newer []byte) {
			if err := os.WriteFile(path, newer, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, write := range cases {
		t.Run(name, func(t *testing.T) { assertBootRewriteKeepsNewer(t, write) })
	}
}

// assertBootRewriteKeepsNewer boots a roster while write lands an external
// change just before the rewrite's write step, and checks the outcome.
func assertBootRewriteKeepsNewer(t *testing.T, write func(t *testing.T, path string, newer []byte)) {
	t.Helper()
	path, user, _ := seedRosterFileForBoot(t)
	newer := []byte(`{"users":[],"default_auth_outcome":"Default"}`) // the revocation of user
	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	prev := rosterRewriteInPlace
	rosterRewriteInPlace = func(p string, d []byte, fi os.FileInfo) error {
		write(t, p, newer)
		return prev(p, d, fi)
	}
	t.Cleanup(func() { rosterRewriteInPlace = prev })

	c.SetUIUsersFile(path)
	out := captureLogger(t, func() {
		if err := c.LoadUIUsersFile(); err != nil {
			t.Fatalf("LoadUIUsersFile: %v", err)
		}
	})

	if got, _ := os.ReadFile(path); !bytes.Equal(got, newer) { // #nosec G304 -- test temp path
		t.Fatalf("the newer roster was overwritten by the boot rewrite: disk holds %q", got)
	}
	if !loadedHasUser(c, user) {
		t.Errorf("the roster loaded before the change is not the one in use")
	}
	if _, werr := c.rosterWriteEvidence(); !errors.Is(werr, fileutil.ErrConcurrentChange) {
		t.Errorf("evidence error = %v, want ErrConcurrentChange", werr)
	}
	row := checkAdminRosterDurability()
	if row.Status != diagWarn || row.Message != rosterTargetChangedAtBoot {
		t.Errorf("row = %+v, want warn %q", row, rosterTargetChangedAtBoot)
	}
	if !strings.Contains(row.OperatorAction, "Restart") {
		t.Errorf("action = %q, want the restart-to-load remedy", row.OperatorAction)
	}
	if n := strings.Count(out, "changed on disk while it was loaded at startup"); n != 1 {
		t.Errorf("logged %d concurrent-change line(s), want exactly 1:\n%s", n, out)
	}
	if want := fmt.Sprintf("%q", sanitizeLog(path)); !strings.Contains(out, want) {
		t.Errorf("log does not name the path as %s:\n%s", want, out)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("%d directory entries after the rewrite, want only the roster", len(entries))
	}
}

// TestLoadUIUsersFile_UnsupportedExchangeIsUnverified: where no atomic
// exchange exists the roster is not rewritten (same inode, same bytes) and the
// row is warn/unverified with the first-save remedy, until a save lands.
func TestLoadUIUsersFile_UnsupportedExchangeIsUnverified(t *testing.T) {
	path, user, data := seedRosterFileForBoot(t)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	prev := rosterRewriteInPlace
	rosterRewriteInPlace = func(p string, _ []byte, _ os.FileInfo) error {
		return fmt.Errorf("rewrite in place %s: %w", p, fileutil.ErrRewriteUnsupported)
	}
	t.Cleanup(func() { rosterRewriteInPlace = prev })

	c.SetUIUsersFile(path)
	out := captureLogger(t, func() {
		if err := c.LoadUIUsersFile(); err != nil {
			t.Fatalf("LoadUIUsersFile: %v", err)
		}
	})
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Error("the roster was replaced although the exchange is unsupported")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, data) { // #nosec G304 -- test temp path
		t.Errorf("roster bytes changed: %q", got)
	}
	if !loadedHasUser(c, user) {
		t.Errorf("roster account %q not loaded", user)
	}
	row := checkAdminRosterDurability()
	if row.Status != diagWarn || row.Message != rosterTargetRewriteUnsupported {
		t.Errorf("row = %+v, want warn %q", row, rosterTargetRewriteUnsupported)
	}
	if !strings.Contains(row.OperatorAction, "first admin account change") {
		t.Errorf("action = %q, want the first-save remedy", row.OperatorAction)
	}
	if n := strings.Count(out, "no atomic exchange"); n != 1 {
		t.Errorf("logged %d unsupported line(s), want exactly 1:\n%s", n, out)
	}
	_, viewer := durabilityRowAt(t, RoleViewer)
	if viewer.Status != diagWarn || viewer.Message != rosterDurabilityViewerNotDurable {
		t.Errorf("viewer row = %+v, want the fixed not-durable message", viewer)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}
	if row := checkAdminRosterDurability(); row.Status != diagOK {
		t.Errorf("after a landed save: row = %+v, want ok", row)
	}
}

// TestLoadUIUsersFile_FailedRestoreIsReportedLoudly: if the exchange back
// fails, the row and the log both say the newer roster is in a preserved temp
// file and the roster in use is the older one.
func TestLoadUIUsersFile_FailedRestoreIsReportedLoudly(t *testing.T) {
	path, _, _ := seedRosterFileForBoot(t)
	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	preserved := path + ".tmp.12345"
	prev := rosterRewriteInPlace
	rosterRewriteInPlace = func(p string, _ []byte, _ os.FileInfo) error {
		return fmt.Errorf("rewrite in place %s: the newer content is preserved at %s: %w", p, preserved,
			fileutil.ErrExchangeBackFailed)
	}
	t.Cleanup(func() { rosterRewriteInPlace = prev })

	c.SetUIUsersFile(path)
	out := captureLogger(t, func() {
		if err := c.LoadUIUsersFile(); err != nil {
			t.Fatalf("LoadUIUsersFile: %v", err)
		}
	})
	row := checkAdminRosterDurability()
	if row.Status != diagWarn || row.Message != rosterTargetRestoreFailed {
		t.Errorf("row = %+v, want warn %q", row, rosterTargetRestoreFailed)
	}
	if !strings.Contains(row.OperatorAction, "Do not make admin account changes") {
		t.Errorf("action = %q, want the recover-the-preserved-file remedy", row.OperatorAction)
	}
	if strings.Contains(row.Message+row.OperatorAction, path) {
		t.Errorf("row names the path: %+v", row)
	}
	if n := strings.Count(out, "CHANGED ON DISK during the startup rewrite"); n != 1 {
		t.Errorf("logged %d restore-failure line(s), want exactly 1:\n%s", n, out)
	}
	if !strings.Contains(out, sanitizeLog(preserved)) {
		t.Errorf("log does not name the preserved file %q:\n%s", preserved, out)
	}
}
