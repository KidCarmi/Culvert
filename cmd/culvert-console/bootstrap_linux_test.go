//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const bootstrapFixturePassword = "AbCdEfGh23456789"

func bootstrapFixture(t *testing.T) (store bootstrapStore, complete string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned safe ancestor checks")
	}
	dir, err := os.MkdirTemp("/run", "culvert-bootstrap-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	s := bootstrapStore{filepath.Join(dir, "private"), filepath.Join(dir, "shadow")}
	bootstrapShadowFixture(t, s, "$6$fixture$original", "0")
	return s, filepath.Join(dir, "console.done")
}

func bootstrapShadowFixture(t *testing.T, s bootstrapStore, hash, changed string) {
	t.Helper()
	if err := os.WriteFile(s.shadow, []byte("culvert:"+hash+":"+changed+":0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func bootstrapSaveFixture(t *testing.T, s bootstrapStore) {
	t.Helper()
	if err := s.withLock(true, func() error { return s.save(bootstrapFixturePassword) }); err != nil {
		t.Fatal(err)
	}
}

func bootstrapCommitFixture(t *testing.T, s bootstrapStore, complete string) {
	t.Helper()
	if err := os.WriteFile(complete, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.withLock(false, func() error { return s.commit(complete) }); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapDelayedAttachmentAndInterruptedPublication(t *testing.T) {
	s, complete := bootstrapFixture(t)
	bootstrapSaveFixture(t, s)
	if got := s.visible(complete); got != "" {
		t.Fatal("uncommitted provisioning exposed credential")
	}
	if err := os.WriteFile(complete, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := s.visible(complete); got != "" {
		t.Fatal("checkpoint touch exposed credential before durable handoff commit")
	}
	bootstrapCommitFixture(t, s, complete)
	// A killed writer's unfinished temporary file is never the committed record.
	if err := os.WriteFile(filepath.Join(s.directory, ".pending-interrupted"), []byte(`{"password":"unfinished`), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		fresh := bootstrapStore{s.directory, s.shadow}
		if got := fresh.visible(complete); got != bootstrapFixturePassword {
			t.Fatal("delayed or repeated attachment lost committed credential")
		}
	}
	for path, want := range map[string]os.FileMode{s.directory: 0o700, filepath.Join(s.directory, "credential.json"): 0o600} {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != want {
			t.Fatalf("private mode: %v, %v", st, err)
		}
	}
}

func TestBootstrapPasswordChangeClearsRecordButUnreadableShadowPreservesIt(t *testing.T) {
	for _, mode := range []string{"changed_hash", "changed_age", "unreadable"} {
		t.Run(mode, func(t *testing.T) {
			s, complete := bootstrapFixture(t)
			bootstrapSaveFixture(t, s)
			if err := os.WriteFile(complete, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			bootstrapCommitFixture(t, s, complete)
			switch mode {
			case "changed_hash":
				bootstrapShadowFixture(t, s, "$6$fixture$new", "0")
			case "changed_age":
				bootstrapShadowFixture(t, s, "$6$fixture$original", "20000")
			case "unreadable":
				if err := os.Remove(s.shadow); err != nil {
					t.Fatal(err)
				}
			}
			if got := s.visible(complete); got != "" {
				t.Fatal("stale credential exposed")
			}
			_, err := os.Stat(filepath.Join(s.directory, "credential.json"))
			if mode == "unreadable" && err != nil {
				t.Fatal("unknown account state destroyed handoff")
			}
			if mode != "unreadable" && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("changed credential record retained")
			}
		})
	}
}

func TestBootstrapRejectsUnsafePendingFilesAndFailedReplacement(t *testing.T) {
	for _, mode := range []string{"public", "symlink", "hardlink", "malformed", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			s, complete := bootstrapFixture(t)
			bootstrapSaveFixture(t, s)
			if err := os.WriteFile(complete, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			bootstrapCommitFixture(t, s, complete)
			path := filepath.Join(s.directory, "credential.json")
			var err error
			switch mode {
			case "public":
				err = os.Chmod(path, 0o644)
			case "symlink":
				if err = os.Remove(path); err == nil {
					err = os.Symlink(s.shadow, path)
				}
			case "hardlink":
				err = os.Link(path, filepath.Join(s.directory, "alias"))
			case "malformed":
				err = os.WriteFile(path, []byte("{"), 0o600)
			case "oversized":
				err = os.WriteFile(path, []byte(strings.Repeat("x", 2049)), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := s.visible(complete); got != "" {
				t.Fatal("unsafe file exposed credential")
			}
			if mode != "malformed" && s.withLock(false, func() error { return s.save(bootstrapFixturePassword) }) == nil {
				t.Fatal("unsafe replacement accepted")
			}
		})
	}
}

func TestBootstrapRejectsAmbiguousShadowTarget(t *testing.T) {
	for _, first := range []string{"culvert::0:0:99999:7:::", "culvert:malformed"} {
		t.Run(first, func(t *testing.T) {
			s, _ := bootstrapFixture(t)
			data := first + "\nculvert:$6$fixture$original:0:0:99999:7:::\n"
			if err := os.WriteFile(s.shadow, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.shadowHash(); err == nil {
				t.Fatal("ambiguous account accepted")
			}
		})
	}
}

func TestBootstrapLockAndImportedCredential(t *testing.T) {
	s, _ := bootstrapFixture(t)
	bootstrapSaveFixture(t, s)
	if err := s.withLock(false, func() error {
		if s.withLock(false, func() error { t.Fatal("contending writer entered"); return nil }) == nil {
			t.Fatal("lock contention accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	bootstrapShadowFixture(t, s, "$6$fixture$imported", "20000")
	if err := s.withLock(false, func() error { return s.save(bootstrapFixturePassword) }); err == nil {
		t.Fatal("non-forced imported credential recorded")
	}
}

func TestBootstrapInputIsBoundedAndCancelled(t *testing.T) {
	for _, input := range []string{bootstrapFixturePassword + "\n", "short\n", bootstrapFixturePassword + "extra\n", "ABCDEFGHIJKLMNOP\n"} {
		t.Run(input, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if _, err := w.WriteString(input); err != nil {
				t.Fatal(err)
			}
			w.Close()
			got, err := bootstrapInput(t.Context(), int(r.Fd()))
			if input == bootstrapFixturePassword+"\n" {
				if err != nil || got != bootstrapFixturePassword {
					t.Fatal("valid handoff rejected")
				}
			} else if err == nil || got != "" {
				t.Fatal("invalid input accepted")
			}
		})
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if _, err := bootstrapInput(ctx, int(r.Fd())); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked input ignored cancellation")
	}
}

func TestBootstrapSmallScreenKeepsFullPassword(t *testing.T) {
	rows := bootstrapRows(bootstrapFixturePassword, 6, 18)
	if rows[3].Text != bootstrapFixturePassword {
		t.Fatal("small screen truncated credential")
	}
	for _, row := range bootstrapRows(bootstrapFixturePassword, 5, 17) {
		if strings.Contains(row.Text, bootstrapFixturePassword[:8]) {
			t.Fatal("undersized screen exposed partial credential")
		}
	}
}

func TestBootstrapRejectsRelativePaths(t *testing.T) {
	if err := bootstrapAncestors("."); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestBootstrapHelpersRequireRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged process")
	}
	if err := recordBootstrap(t.Context()); err == nil {
		t.Fatal("unprivileged record accepted")
	}
	if err := recordBootstrapCommit(t.Context()); err == nil {
		t.Fatal("unprivileged commit accepted")
	}
}

func TestBootstrapRejectsSymlinkAncestorBeforeCreatingPrivateDirectory(t *testing.T) {
	s, _ := bootstrapFixture(t)
	outside := filepath.Join(filepath.Dir(s.directory), "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(s.directory), "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	s.directory = filepath.Join(link, "private")
	if err := s.withLock(true, func() error { return nil }); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "private")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created private directory through unsafe ancestor")
	}
	// Keep the imported unix package exercised against actual owner metadata.
	var st unix.Stat_t
	if err := unix.Stat(outside, &st); err != nil || st.Uid != 0 {
		t.Fatal("fixture is not root-owned")
	}
}
