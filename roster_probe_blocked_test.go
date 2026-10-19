package main

import (
	"fmt"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// Gates for Codex P2 4319694761 on PR #1601: the live probe rechecks whether
// the roster can be replaced at all, with the boot rewrite's own predicate.

// TestRosterProbe_UsesTheRewritePredicate pins that the probe's check IS
// fileutil.ReplacementBlocked — the predicate RewriteInPlace's precheck
// applies (TestReplacementBlocked_SamePredicateAsTheRewrite pins that side) —
// not a copy that could drift.
func TestRosterProbe_UsesTheRewritePredicate(t *testing.T) {
	if reflect.ValueOf(rosterReplacementBlocked).Pointer() != reflect.ValueOf(fileutil.ReplacementBlocked).Pointer() {
		t.Fatal("rosterReplacementBlocked is not fileutil.ReplacementBlocked")
	}
}

func injectReplacementBlocked(t *testing.T, err error) {
	t.Helper()
	prev := rosterReplacementBlocked
	rosterReplacementBlocked = func(string) error { return err }
	t.Cleanup(func() { rosterReplacementBlocked = prev })
}

// TestRosterProbe_BlockedReplacementWarns: after a landed save, the roster
// becomes immutable or append-only. The live probe reports it with its own
// message and remedy. Dropping the check from the probe fails this test.
func TestRosterProbe_BlockedReplacementWarns(t *testing.T) {
	for name, errno := range map[string]syscall.Errno{"immutable": syscall.EPERM, "append-only": syscall.EPERM, "mount point": syscall.EBUSY} {
		t.Run(name, func(t *testing.T) {
			savedRosterCfg(t)
			if row := checkAdminRosterDurability(); row.Status != diagOK {
				t.Fatalf("precondition: row = %+v, want ok", row)
			}
			injectReplacementBlocked(t, fmt.Errorf("%w: it is %s: %w", fileutil.ErrReplacementBlocked, name, errno))
			assertRosterImmutableRow(t)
		})
	}
}

func assertRosterImmutableRow(t *testing.T) {
	t.Helper()
	row := checkAdminRosterDurability()
	if row.Status != diagWarn || row.Message != rosterTargetImmutable {
		t.Fatalf("row = %+v, want warn %q", row, rosterTargetImmutable)
	}
	if !strings.Contains(row.OperatorAction, "chattr -i") || !strings.Contains(row.OperatorAction, "-ui-users-file") {
		t.Errorf("action = %q, want the clear-the-flag remedy", row.OperatorAction)
	}
}
