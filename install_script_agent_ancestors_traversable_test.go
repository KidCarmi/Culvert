package main

// install_script_agent_ancestors_traversable_test.go — regression coverage for
// the agent_ancestors_traversable() helper in scripts/install.sh.
//
// This is the "Agent unreachable" root cause. The maintenance agent runs as the
// unprivileged culvert-maint service user, which must be able to chdir into the
// stack directory (the runner sets cmd.Dir before every sudo). The installer's
// LEAF-group grant gives traversal into the stack dir itself, but if any
// ANCESTOR we do not modify is not world-searchable (a 0700 home — the default
// for a CULVERT_DIR under ~, or /root), the agent can never reach the stack.
// install.sh calls agent_ancestors_traversable BEFORE wiring so it can skip the
// agent FAIL-CLOSED with a clear message instead of installing a guaranteed-
// broken agent that surfaces as "Agent unreachable" in the UI.
//
// The field bug: a fresh install landed in ~/Culvert under a 0700 home, the
// agent was skipped, and the UI showed "Agent unreachable" with no obvious
// cause. This pins the traversability decision so a regression in the ancestor
// walk (or the world-search-bit check) fails HERE, deterministically, with no
// Docker required.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// searchableTempRoot creates a fresh directory directly under /tmp and makes it
// world-searchable (0755). /tmp is 1777 and / is 0755, so EVERY ancestor of the
// returned dir is world-searchable — the injected permission on a child we build
// under it is then the ONLY thing that can block traversal. This is deliberately
// NOT t.TempDir(): Go creates the t.TempDir() parent 0700, which would itself
// block the walk and make these tests pass for the wrong reason.
func searchableTempRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "culvert-trav-")
	if err != nil {
		t.Fatalf("mkdir temp root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	// Sanity: if the environment's /tmp ancestry is somehow not world-searchable,
	// the premise doesn't hold — skip rather than report a misleading failure.
	if got := runAgentAncestorsTraversable(t, filepath.Join(root, "probe")); got != "TRAVERSABLE" {
		t.Skipf("environment /tmp ancestry is not world-searchable (probe=%q); skipping", got)
	}
	return root
}

// chmod0755Chain makes leaf and every ancestor up to (and including) root
// world-searchable (0755), so a test's outcome does not depend on the process
// umask that os.MkdirAll applied to intermediate dirs.
func chmod0755Chain(t *testing.T, root, leaf string) {
	t.Helper()
	p := leaf
	for {
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatalf("chmod %s: %v", p, err)
		}
		if p == root {
			return
		}
		parent := filepath.Dir(p)
		if parent == p { // reached filesystem root without hitting `root` — stop
			return
		}
		p = parent
	}
}

// runAgentAncestorsTraversable extracts the REAL agent_ancestors_traversable()
// function body and runs it against path, returning "TRAVERSABLE" or "BLOCKED".
func runAgentAncestorsTraversable(t *testing.T, path string) string {
	t.Helper()
	fn := extractShellFunction(t, "scripts/install.sh", "agent_ancestors_traversable")
	script := fn + "\nif agent_ancestors_traversable \"$1\"; then echo TRAVERSABLE; else echo BLOCKED; fi\n"
	// $0 is a label; $1 is the path under test.
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script, "agent-traversable-test", path) //nolint:gosec // fixed script, path is a test tempdir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shell script failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestInstallScript_AgentAncestorsTraversable_AllSearchable proves the baseline:
// when every ancestor of the stack dir is world-searchable (0755), the agent
// user can traverse in and the helper reports the path as traversable.
func TestInstallScript_AgentAncestorsTraversable_AllSearchable(t *testing.T) {
	root := searchableTempRoot(t)
	stack := filepath.Join(root, "srv", "culvert")
	// 0o750 keeps gosec G301 happy; the world-search (0755) bits that actually
	// matter are set explicitly below (chmod0755Chain / the per-test chmod).
	if err := os.MkdirAll(stack, 0o750); err != nil {
		t.Fatalf("mkdir stack: %v", err)
	}
	// MkdirAll applies the process umask, so under umask 027 the intermediate
	// dirs would be 0750 (no world-search bit) and blow up this test. chmod the
	// whole created chain to 0755 so the outcome is umask-independent.
	chmod0755Chain(t, root, stack)
	if got := runAgentAncestorsTraversable(t, stack); got != "TRAVERSABLE" {
		t.Fatalf("agent_ancestors_traversable(%s) = %q, want TRAVERSABLE when every ancestor is 0755", stack, got)
	}
}

// TestInstallScript_AgentAncestorsTraversable_Blocked0700Home is the field-bug
// regression: an ancestor directory with a 0700 mode (a private home dir) has
// no world-search bit, so the unprivileged agent user cannot chdir through it.
// The helper MUST report the path as NOT traversable, which is what makes
// install.sh skip the agent fail-closed instead of shipping "Agent unreachable".
func TestInstallScript_AgentAncestorsTraversable_Blocked0700Home(t *testing.T) {
	root := searchableTempRoot(t)
	home := filepath.Join(root, "home0700")
	stack := filepath.Join(home, "Culvert")
	// 0o750 keeps gosec G301 happy; the world-search (0755) bits that actually
	// matter are set explicitly below (chmod0755Chain / the per-test chmod).
	if err := os.MkdirAll(stack, 0o750); err != nil {
		t.Fatalf("mkdir stack: %v", err)
	}
	// The private home: 0700 = owner rwx, no group/other search bit — exactly the
	// default of a user home dir a CULVERT_DIR=~/Culvert lands under. This is the
	// ONLY non-searchable dir in the chain (the /tmp root above is 0755).
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatalf("chmod home: %v", err)
	}
	if got := runAgentAncestorsTraversable(t, stack); got != "BLOCKED" {
		t.Fatalf("agent_ancestors_traversable(%s) = %q, want BLOCKED when the %s ancestor is 0700 "+
			"(the 'Agent unreachable' root cause — the agent user cannot traverse a 0700 home)", stack, got, home)
	}
}

// TestInstallScript_AgentAncestorsTraversable_Blocked0750Home guards the group-
// only (0750) case too: 0's last octal digit is 0 (no OTHER search bit), and the
// agent user is not in the dir's group, so a 0750 ancestor is also impassable.
// The installer's own warning text calls out 0700/0750 homes specifically.
func TestInstallScript_AgentAncestorsTraversable_Blocked0750Home(t *testing.T) {
	root := searchableTempRoot(t)
	home := filepath.Join(root, "home0750")
	stack := filepath.Join(home, "Culvert")
	// 0o750 keeps gosec G301 happy; the world-search (0755) bits that actually
	// matter are set explicitly below (chmod0755Chain / the per-test chmod).
	if err := os.MkdirAll(stack, 0o750); err != nil {
		t.Fatalf("mkdir stack: %v", err)
	}
	if err := os.Chmod(home, 0o750); err != nil {
		t.Fatalf("chmod home: %v", err)
	}
	if got := runAgentAncestorsTraversable(t, stack); got != "BLOCKED" {
		t.Fatalf("agent_ancestors_traversable(%s) = %q, want BLOCKED when the %s ancestor is 0750 "+
			"(no world-search bit, agent user not in group)", stack, got, home)
	}
}
