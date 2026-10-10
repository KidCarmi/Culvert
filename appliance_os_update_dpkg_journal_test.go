package main

// culvert-os-update repairs an interrupted dpkg before any apt step.
//
// Lab run 38016152802 (retained 91e05872 OVA, root filesystem full during
// `culvert-os-update os`): the unpack failed AND dpkg's own status write
// failed ("failed to write status database stanza ... No space left on
// device"), leaving numbered entries in /var/lib/dpkg/updates. Once space was
// back, every apt call answered "dpkg was interrupted, you must manually run
// 'sudo dpkg --configure -a'", so the documented recovery — run the command
// again — failed (rc 100) until someone with a shell ran dpkg by hand.
// unattended-upgrades already repairs this itself (AutoFixInterruptedDpkg:
// the same journal check, the same command); the operator path now does too.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withDirtyDpkgJournal leaves dpkg "interrupted" for the next script run.
func withDirtyDpkgJournal(t *testing.T, names ...string) {
	t.Helper()
	osUpdateDpkgHook = func(dir string) {
		for _, n := range names {
			if err := os.WriteFile(filepath.Join(dir, n), []byte("Package: netbase\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() { osUpdateDpkgHook = nil })
}

// DEFECT GATE: an interrupted dpkg is replayed BEFORE apt runs, and the run
// then proceeds and succeeds.
func TestOSUpdate_InterruptedDpkgIsRepairedBeforeApt(t *testing.T) {
	for _, mode := range []string{"os", "security", "docker"} {
		t.Run(mode, func(t *testing.T) {
			withDirtyDpkgJournal(t, "0000", "0001")
			out, calls, code := runOSUpdate(t, mode)
			if code != 0 {
				t.Fatalf("an interrupted dpkg must be repaired, then the %s run must succeed (code %d):\n%s\ncalls:\n%s", mode, code, out, calls)
			}
			heal := strings.Index(calls, "dpkg --force-confold --configure -a")
			apt := strings.Index(calls, "apt-get")
			if heal < 0 {
				t.Fatalf("dpkg --configure -a was never run:\n%s", calls)
			}
			if apt >= 0 && apt < heal {
				t.Fatalf("apt ran before the dpkg journal was replayed (apt would refuse):\n%s", calls)
			}
			if !strings.Contains(out, "dpkg was interrupted") || !strings.Contains(out, "dpkg journal replayed") {
				t.Fatalf("the repair must be logged:\n%s", out)
			}
		})
	}
}

// DEFECT GATE: if the replay itself fails (the disk is still full), the run
// stops before apt with a message naming the cause, never a silent success.
func TestOSUpdate_FailedDpkgRepairStopsBeforeApt(t *testing.T) {
	withDirtyDpkgJournal(t, "0000")
	out, calls, code := runOSUpdate(t, "os", "FAIL_DPKG_CONFIGURE=1")
	if code == 0 {
		t.Fatalf("a failed dpkg --configure -a must exit non-zero:\n%s", out)
	}
	if strings.Contains(calls, "apt-get") {
		t.Fatalf("apt must not run after a failed dpkg repair:\n%s", calls)
	}
	if !strings.Contains(out, "dpkg --configure -a failed") || !strings.Contains(out, "df -i") {
		t.Fatalf("the failure must name the repair and point at space and inodes:\n%s", out)
	}
}

// CONTROL: a clean journal costs nothing — no dpkg call, apt runs as before.
func TestOSUpdate_CleanDpkgJournalTakesNoRepair(t *testing.T) {
	out, calls, code := runOSUpdate(t, "os")
	if code != 0 {
		t.Fatalf("clean run failed (code %d):\n%s", code, out)
	}
	if strings.Contains(calls, "dpkg ") || strings.Contains(out, "dpkg was interrupted") {
		t.Fatalf("no repair may run on a clean journal:\nout=%s\ncalls=%s", out, calls)
	}
	if !strings.Contains(calls, "apt-get") {
		t.Fatalf("apt must still run:\n%s", calls)
	}
}

// CONTROL: the detection is unattended-upgrades' own (is_dpkg_journal_dirty:
// a NUMBERED entry). dpkg's other files in that directory (e.g. tmp.i) are
// not an interrupted run and must not trigger a repair.
func TestOSUpdate_NonNumberedJournalFileIsNotInterrupted(t *testing.T) {
	withDirtyDpkgJournal(t, "tmp.i")
	out, calls, code := runOSUpdate(t, "os")
	if code != 0 || strings.Contains(calls, "dpkg ") {
		t.Fatalf("a non-numbered file is not an interrupted dpkg (code %d):\nout=%s\ncalls=%s", code, out, calls)
	}
}

// `check` reports an interrupted dpkg and changes nothing.
func TestOSUpdateCheck_ReportsInterruptedDpkgWithoutRepairing(t *testing.T) {
	withDirtyDpkgJournal(t, "0000")
	out, calls, _ := runOSUpdate(t, "check")
	if !strings.Contains(out, "dpkg: INTERRUPTED") {
		t.Fatalf("check must report the interrupted dpkg:\n%s", out)
	}
	if strings.Contains(calls, "dpkg ") {
		t.Fatalf("check must not repair anything:\n%s", calls)
	}
}
