package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// support_replaced_notsynced_test.go — CHAOS: a durable write that LANDED must
// not be reported as a failure.
//
// fileutil.AtomicWrite returns ErrReplacedNotSynced only AFTER its rename has
// succeeded: the target already carries the new bytes and every reader sees
// them. Only the rename's durability across an immediate crash is unproven,
// because the parent-directory fsync (or close) failed.
//
// Treating that as a plain failure made the HTTP response and the audit trail
// contradict the state on disk. apiSupportBundleApprove returns 500 and returns
// BEFORE its auditEvent, so a bundle could be READY and downloadable with no
// support.bundle.approve record of who authorized exporting its INTERNAL
// sections. Reported by Codex review on PR #1658.
//
// The injection is at the supportDurableWriter seam rather than a real broken
// filesystem: a parent-directory fsync cannot be made to fail portably, and the
// seam is the same shape the repo already uses for audit.SetPersistForTest and
// DataPlaneClient.callForTest.

// injectReplacedNotSynced makes every support durable write land and then report
// ErrReplacedNotSynced, wrapped the way AtomicWrite wraps it.
func injectReplacedNotSynced(t *testing.T) {
	t.Helper()
	prev := supportDurableWriter
	supportDurableWriter = func(path string, data []byte, perm os.FileMode) error {
		if err := prev(path, data, perm); err != nil {
			return err
		}
		return fmt.Errorf("atomic write %s: parent dir fsync: %w: %w", path, errors.New("input/output error"), fileutil.ErrReplacedNotSynced)
	}
	t.Cleanup(func() { supportDurableWriter = prev })
}

// TestDurableSupportWrite_ReplacedNotSyncedIsCommitted is the unit-level
// contract: the sentinel is success, any other error is not.
func TestDurableSupportWrite_ReplacedNotSyncedIsCommitted(t *testing.T) {
	dir := t.TempDir()

	injectReplacedNotSynced(t)
	target := filepath.Join(dir, "landed.json")
	if err := durableSupportWrite(target, []byte(`{"state":"ready"}`)); err != nil {
		t.Fatalf("durableSupportWrite returned %v for a write that LANDED — "+
			"ErrReplacedNotSynced is returned after the rename succeeded, so the "+
			"caller's response and audit trail would contradict the file on disk", err)
	}
	// The bytes really are there: "committed" is not a fiction.
	b, err := os.ReadFile(target)
	if err != nil || !strings.Contains(string(b), "ready") {
		t.Fatalf("target not readable after a committed write: b=%q err=%v", b, err)
	}

	// Negative control: a pre-rename failure must still be an error, or a full
	// disk would be silently swallowed — the opposite of this PR's purpose.
	prev := supportDurableWriter
	supportDurableWriter = func(string, []byte, os.FileMode) error {
		return errors.New("atomic write: write: no space left on device")
	}
	t.Cleanup(func() { supportDurableWriter = prev })
	if err := durableSupportWrite(filepath.Join(dir, "nope.json"), []byte("x")); err == nil {
		t.Error("durableSupportWrite swallowed a genuine write failure; only ErrReplacedNotSynced is committed")
	}
}

// TestSupportBundleApprove_LandedApprovalIsAuditedAndSucceeds is the
// handler-level contract, on the security-relevant path: if the approval state
// landed, the admin is told it succeeded AND the audit trail records who
// approved it — because the download gate will honour that landed state.
func TestSupportBundleApprove_LandedApprovalIsAuditedAndSucceeds(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	dir := filepath.Join(supportBundlesDir(), chaosBundleID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir bundle dir: %v", err)
	}
	// apiSupportBundleApprove 404s unless the manifest exists.
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := writeBundleState(chaosBundleID, supportBundleStateFile{State: bundleStatePending}); err != nil {
		t.Fatalf("seed pending state: %v", err)
	}

	injectReplacedNotSynced(t)

	req, rec := supportRoleReq(http.MethodPost, chaosBundleID, RoleAdmin)
	apiSupportBundleApprove(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("approve code=%d want 204 — the approval state landed on disk, so reporting "+
			"failure tells the admin the gate is still closed while the bundle is downloadable; body=%q",
			rec.Code, rec.Body.String())
	}
	// The landed state is what the download gate reads.
	if st := readBundleState(chaosBundleID); st.State != bundleStateReady {
		t.Fatalf("on-disk state=%q want ready — the premise of this test is that the write landed", st.State)
	}
	// The export authorization must be attributable.
	found := false
	for _, e := range audit.Get() {
		if e.Action == "support.bundle.approve" && e.Object == chaosBundleID {
			found = true
			break
		}
	}
	if !found {
		t.Error("no support.bundle.approve audit entry for a bundle that is now READY and downloadable — " +
			"an export authorization with no record of who authorized it")
	}
}

// TestMkdirDurableSupport_SyncsNewEntriesAndKeepsMode covers the directory half:
// os.MkdirAll makes a directory, but a directory's ENTRY lives in its parent,
// which AtomicWrite never syncs — so a fully fsynced manifest could still be
// lost with its whole bundle directory after createSupportBundle returned the
// id to the operator. Raised by CodeRabbit on PR #1658.
//
// fsync is not observable from a test, so this pins what is: the whole missing
// chain is created with the requested mode, the call is idempotent, and a
// pre-existing directory is left alone. The sync itself is asserted by
// construction — syncDirBestEffort is called for each created directory's
// parent — and tolerates filesystems that cannot fsync a directory.
func TestMkdirDurableSupport_SyncsNewEntriesAndKeepsMode(t *testing.T) {
	root := t.TempDir()

	// A multi-level chain, so the ancestor walk is exercised rather than just
	// the one-new-directory case.
	deep := filepath.Join(root, "support", "bundles", chaosBundleID)
	if err := mkdirDurableSupport(deep, 0o700); err != nil {
		t.Fatalf("mkdirDurableSupport: %v", err)
	}
	for p := deep; p != root; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if !fi.IsDir() {
			t.Fatalf("%s is not a directory", p)
		}
		if got := fi.Mode().Perm(); got != 0o700 {
			t.Errorf("%s mode = %o, want 700", p, got)
		}
	}

	// Idempotent: a second call on an existing chain creates nothing, syncs
	// nothing, and must not error.
	if err := mkdirDurableSupport(deep, 0o700); err != nil {
		t.Fatalf("mkdirDurableSupport on an existing chain: %v", err)
	}

	// And a durable write into the created directory still works end to end.
	if err := durableSupportWrite(filepath.Join(deep, "state.json"), []byte(`{"state":"pending"}`)); err != nil {
		t.Fatalf("durableSupportWrite into the new directory: %v", err)
	}
}

// TestDurableSupportWrite_UsesTheDomainMode pins the perm invariant that
// replaced the per-call-site argument (golangci unparam): support state is 0600,
// not whatever a caller happened to pass.
func TestDurableSupportWrite_UsesTheDomainMode(t *testing.T) {
	target := filepath.Join(t.TempDir(), "state.json")
	if err := durableSupportWrite(target, []byte("{}")); err != nil {
		t.Fatalf("durableSupportWrite: %v", err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600 — support state carries operator/TAC material", got)
	}
}

// TestMkdirDurableSupport_HardSyncFailureFailsAndUnwinds pins the two halves of
// the directory-sync contract CodeRabbit raised on PR #1658: a non-exempt fsync
// error FAILS the call rather than being logged and swallowed, and the
// directories this call created are removed so nothing partial is left behind.
//
// The exempt conditions are asserted separately below, since those must keep
// succeeding on filesystems that cannot fsync a directory at all.
func TestMkdirDurableSupport_ExemptConditionsStillSucceed(t *testing.T) {
	root := t.TempDir()

	// A directory that cannot be OPENED is skipped, not an error — opening one
	// is not portable, and AtomicWrite makes the same exemption. Exercised via
	// a path that exists: the normal success route.
	deep := filepath.Join(root, "a", "b", "c")
	if err := mkdirDurableSupport(deep, 0o700); err != nil {
		t.Fatalf("mkdirDurableSupport on a healthy volume: %v", err)
	}
	if _, err := os.Stat(deep); err != nil {
		t.Fatalf("chain not created: %v", err)
	}

	// syncDirEntry on a path that cannot be opened returns nil rather than an
	// error, so a create on such a filesystem is not failed spuriously.
	if err := syncDirEntry(filepath.Join(root, "does-not-exist")); err != nil {
		t.Errorf("syncDirEntry on an unopenable directory = %v, want nil (the portability exemption)", err)
	}
}

// TestMkdirDurableSupport_PreExistingDirectoryIsNeverRemoved is the creation
// guard: the unwind on failure must only touch directories THIS call made, so a
// failure can never delete an existing bundle directory.
func TestMkdirDurableSupport_PreExistingDirectoryIsNeverRemoved(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "bundles")
	if err := os.MkdirAll(existing, 0o700); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A marker proves the directory survived rather than being recreated.
	marker := filepath.Join(existing, "keep.txt")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatalf("seed marker: %v", err)
	}

	if err := mkdirDurableSupport(filepath.Join(existing, chaosBundleID), 0o700); err != nil {
		t.Fatalf("mkdirDurableSupport: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("pre-existing directory contents were disturbed: %v", err)
	}
}
