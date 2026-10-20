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

// Gates for Codex P2 4326010251 on PR #1601. A read-only probe cannot
// authorise the next save (an SELinux add_name/remove_name denial, an NFSv4
// or server-side ACL or a quota can refuse it while faccessat passes), so the
// row's ok states evidence of Culvert's own last write, never a capability;
// and a refused save is what reports the problem, at once.

// futureCapabilityWording is wording that promises the next save will land.
var futureCapabilityWording = []string{
	"persisting", "will persist", "persists", "can save", "can be saved", "will be saved",
	"will land", "can write", "is writable", "will survive", "survives", "is durable",
}

// TestWall_RosterOKMessagesStateEvidenceNotCapability: the ok messages a
// landed save produces, admin and viewer, contain no future-capability
// wording, and do state the evidence. Restoring "admin roster is persisting
// to disk" fails it.
func TestWall_RosterOKMessagesStateEvidenceNotCapability(t *testing.T) {
	f := rosterDurabilityFacts{configured: true, persisted: true, localAdmin: true}
	admin, viewer := f.adminRow(), f.viewerRow()
	degradedViewer := rosterDurabilityFacts{configured: true, persisted: true, localAdmin: true, degraded: 3}.viewerRow()
	for name, row := range map[string]OperatorContractCheck{
		"admin": admin, "viewer": viewer, "viewer, degraded login writes": degradedViewer,
	} {
		if row.Status != diagOK {
			t.Fatalf("%s: status = %q, want ok", name, row.Status)
		}
		msg := strings.ToLower(row.Message)
		for _, w := range futureCapabilityWording {
			if strings.Contains(msg, w) {
				t.Errorf("%s ok message %q promises capability (%q); state the evidence of the last write instead", name, row.Message, w)
			}
		}
		if !strings.Contains(msg, "unchanged since") {
			t.Errorf("%s ok message %q does not state that the file is unchanged since Culvert's last write", name, row.Message)
		}
	}
	if admin.Message != rosterDurabilityLandedOK {
		t.Errorf("admin ok message = %q, want rosterDurabilityLandedOK", admin.Message)
	}
}

// TestRosterDurability_RefusedSaveAfterOKIsReportedOnNextRead: with the row
// ok, a save whose temp-file creation fails with EACCES (as an SELinux or
// NFSv4 ACL denial the probe cannot predict would) is refused, and the very
// next read of the row reports the refusal, for admins with the count and for
// viewers with the fixed refused message. The parent probe still passes
// throughout: the refusal, not the probe, is what reports it.
func TestRosterDurability_RefusedSaveAfterOKIsReportedOnNextRead(t *testing.T) {
	snapshotAuthGlobals(t)
	c, _ := savedRosterCfg(t) // the shared cfg: set up, roster saved, counters zeroed
	if row := checkAdminRosterDurability(); row.Status != diagOK || row.Message != rosterDurabilityLandedOK {
		t.Fatalf("before the refused save: row = %+v, want ok %q", row, rosterDurabilityLandedOK)
	}

	prev := rosterAtomicWrite
	rosterAtomicWrite = func(p string, _ []byte, _ os.FileMode) (fileutil.WriteResult, error) {
		// fileutil.AtomicWriteInfo's own shape for a refused os.CreateTemp.
		return fileutil.WriteResult{}, fmt.Errorf("atomic write %s: create temp: %w", p,
			&fs.PathError{Op: "open", Path: p + ".tmp.0", Err: syscall.EACCES})
	}
	t.Cleanup(func() { rosterAtomicWrite = prev })

	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, "/api/auth/users", map[string]any{
		"username": "newviewer", "password": "Sup3rSecret9!", "role": string(RoleViewer),
	}))
	if w.Code < 500 {
		t.Fatalf("POST with the save refused: status = %d, want 5xx (body %s)", w.Code, w.Body.String())
	}

	if c.UIUserExists("newviewer") {
		t.Errorf("the refused change was not rolled back")
	}
	row := checkAdminRosterDurability()
	if row.Status != diagWarn || !strings.Contains(row.Message, "1 admin account change(s) were refused") {
		t.Errorf("after the refused save: row = %+v, want warn with the refused count", row)
	}
	if _, viewerRow := durabilityRowAt(t, RoleViewer); viewerRow.Status != diagWarn || viewerRow.Message != rosterDurabilityViewerRefused {
		t.Errorf("viewer row after the refused save = %+v, want warn %q", viewerRow, rosterDurabilityViewerRefused)
	}
}
