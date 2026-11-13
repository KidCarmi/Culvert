package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/contracts"
)

// The protected paths of the checked-in registry, restated here so the test
// does not depend on the registry's current contents.
var protected = []string{
	"internal/contracts/**",
	".github/workflows/product-contracts.yml",
	".github/CODEOWNERS",
}

func git(t *testing.T, args ...string) {
	t.Helper()
	args = append([]string{"-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"}, args...)
	if out, err := exec.CommandContext(context.Background(), "git", args...).CombinedOutput(); err != nil { // #nosec G204 -- fixed binary, arguments written in this test
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func write(t *testing.T, name, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// repoWithBase creates a repository holding the protected files, commits it as
// the base, and makes it the working directory for the rest of the test.
func repoWithBase(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
	git(t, "init", "-q")
	// A body long enough that git's rename detection pairs a moved copy.
	body := strings.Repeat("a line of the protected file\n", 20)
	write(t, ".github/workflows/product-contracts.yml", body+"workflow\n")
	write(t, ".github/CODEOWNERS", body+"owners\n")
	write(t, "internal/contracts/contracts.go", "package contracts\n")
	write(t, "docs/readme.md", "docs\n")
	git(t, "add", "-A")
	git(t, "commit", "-q", "-m", "base")
}

// needsApproval runs the same two steps runImpact does: list the changed files,
// then assess them against a base registry that protects the gate's own files.
func needsApproval(t *testing.T) []string {
	t.Helper()
	changed, err := changedFiles("HEAD")
	if err != nil {
		t.Fatal(err)
	}
	reg := &contracts.Registry{Version: 1, Approvers: []string{"owner"}, Protected: protected}
	return contracts.Assess(reg, reg, os.DirFS("."), changed).NeedsApproval
}

func wantFlagged(t *testing.T, got []string, path string) {
	t.Helper()
	for _, g := range got {
		if g == "protected path changed: "+path {
			return
		}
	}
	t.Errorf("%s was changed but not reported as a protected path; got %q", path, got)
}

// Moving a protected file elsewhere removes it from its protected path. With
// rename detection git names only the destination, which is not protected.
func TestChangedFiles_MovingAProtectedFileIsReported(t *testing.T) {
	repoWithBase(t)
	git(t, "mv", ".github/workflows/product-contracts.yml", "docs/old-gate.yml")
	git(t, "mv", ".github/CODEOWNERS", "docs/OLD-CODEOWNERS")

	got := needsApproval(t)
	wantFlagged(t, got, ".github/workflows/product-contracts.yml")
	wantFlagged(t, got, ".github/CODEOWNERS")
}

// A file added to the checker package can change the checker (an init() that
// replaces a package variable). git C-quotes a non-ASCII path unless asked not
// to, and the quoted form does not match the protected glob.
func TestChangedFiles_NonASCIIAndSpacedNamesAreReportedVerbatim(t *testing.T) {
	repoWithBase(t)
	const accented, spaced = "internal/contracts/zé.go", "internal/contracts/a b.go"
	write(t, accented, "package contracts\n")
	write(t, spaced, "package contracts\n")
	git(t, "add", "-A")

	got := needsApproval(t)
	wantFlagged(t, got, accented)
	wantFlagged(t, got, spaced)
}

// Negative control: a change outside every protected path asks for nothing.
func TestChangedFiles_UnprotectedChangeNeedsNoApproval(t *testing.T) {
	repoWithBase(t)
	write(t, "docs/readme.md", "docs, edited\n")
	write(t, "docs/new.md", "new\n")
	git(t, "add", "-A")

	if got := needsApproval(t); len(got) != 0 {
		t.Errorf("an unprotected change was reported: %q", got)
	}
	changed, err := changedFiles("HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(changed, ",") != "docs/new.md,docs/readme.md" {
		t.Errorf("changed files = %q", changed)
	}
}

func TestChangedFiles_UnknownRevisionIsAnError(t *testing.T) {
	repoWithBase(t)
	if _, err := changedFiles("no-such-revision"); err == nil {
		t.Error("an unresolvable base revision produced no error")
	}
}
