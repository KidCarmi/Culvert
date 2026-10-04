//go:build linux

package appliancehost

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func rootDirectory(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root ownership and secure ancestor checks need isolated root test")
	}
	dir, err := os.MkdirTemp("/run", "culvert-store-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func TestStoreDurableEvidenceAndLock(t *testing.T) {
	dir := rootDirectory(t)
	previous := unix.Umask(0o077)
	t.Cleanup(func() { unix.Umask(previous) })
	store := Store{Directory: filepath.Join(dir, "private")}
	err := store.WithLock(func(s *Session) error {
		s.Identity = Identity{Boot: "boot-before", Machine: "machine-before"}
		if err := store.WithLock(func(*Session) error { t.Error("concurrent lock entered"); return nil }); err == nil {
			t.Error("contention ignored")
		}
		_, err := s.Append("reboot", "intent", "failed/failed result=exit-code")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	err = store.WithLock(func(s *Session) error {
		if len(s.State.Records) != 1 || s.State.Records[0].Boot != "boot-before" || s.State.Records[0].Machine != "machine-before" || s.State.Records[0].Phase != "intent" {
			t.Fatalf("pre-action evidence lost: %+v", s.State)
		}
		return store.Publish(s.State, filepath.Join(dir, "status.json"))
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{".": 0o755, "private": 0o700, "private/state.json": 0o600, "status.json": 0o644} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Mode().Perm() != mode {
			t.Fatalf("mode %s: %v %v", name, st, err)
		}
	}
}

func TestStoreRefusesCorruptAndUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"corrupt", "version", "empty", "null", "symlink", "fifo", "permissions", "hardlink", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			dir := rootDirectory(t)
			store := Store{Directory: filepath.Join(dir, "private")}
			if err := store.WithLock(func(*Session) error { return nil }); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(store.Directory, "state.json")
			unsafeFixture(t, dir, path, kind)
			if err := store.WithLock(func(*Session) error { t.Error("unsafe state entered"); return nil }); err == nil {
				t.Fatal("unsafe state accepted")
			}
		})
	}
}

func TestNetplanRestoresAbsenceAndOriginalMode(t *testing.T) {
	dir := rootDirectory(t)
	n := Netplan{Target: filepath.Join(dir, "60-culvert.yaml"), Directories: []string{dir}}
	original := File{Data: []byte("original\n"), Exists: true, Mode: 0o640}
	if err := n.Write(original); err != nil {
		t.Fatal(err)
	}
	got, _, err := n.Read()
	if err != nil || !same(got, original) {
		t.Fatalf("original not preserved: %+v %v", got, err)
	}
	if err := n.Write(File{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(n.Target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("absence not restored")
	}
}

func TestPublishUsesDurablePhaseAndSkipsUnchangedWrites(t *testing.T) {
	dir := rootDirectory(t)
	store := Store{Directory: filepath.Join(dir, "private")}
	path := filepath.Join(dir, "status.json")
	err := store.WithLock(func(s *Session) error {
		if _, err := s.Append("reboot", "intent", ""); err != nil {
			return err
		}
		if err := store.PublishCurrent(path); err != nil {
			return err
		}
		before, err := os.Stat(path)
		if err != nil {
			return err
		}
		s.State.Records[0].Phase = "uncommitted"
		if err := store.PublishCurrent(path); err != nil {
			return err
		}
		after, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !os.SameFile(before, after) {
			t.Error("unchanged snapshot rewritten")
		}
		data, err := os.ReadFile(path)
		if strings.Contains(string(data), "uncommitted") || !strings.Contains(string(data), "intent") {
			t.Error("published uncommitted phase")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNetplanPreflightPreservesEffectiveDHCP6AndRejectsLaterBase(t *testing.T) {
	dir := rootDirectory(t)
	devices, err := net.Interfaces()
	if err != nil || len(devices) == 0 {
		t.Fatal("no kernel interface for adapter test")
	}
	iface := devices[0].Name
	base := filepath.Join(dir, "50-cloud-init.yaml")
	config := fmt.Sprintf("network:\n  version: 2\n  ethernets:\n    %s:\n      dhcp4: true\n      dhcp6: true\n", iface)
	if err := os.WriteFile(base, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	n := Netplan{Target: filepath.Join(dir, "60-culvert.yaml"), Directories: []string{dir}}
	value, err := n.Preflight(iface)
	if err != nil || !value {
		t.Fatalf("DHCPv6 base lost: %t %v", value, err)
	}
	if err := n.Write(File{Exists: true, Mode: 0o600, Data: []byte(strings.ReplaceAll(config, "dhcp6: true", "dhcp6: false"))}); err != nil {
		t.Fatal(err)
	}
	value, err = n.Preflight(iface)
	if err != nil || value {
		t.Fatalf("explicit managed false lost: %t %v", value, err)
	}
	if err := os.Rename(base, filepath.Join(dir, "90-later.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Preflight(iface); err == nil {
		t.Fatal("base sorting after managed override accepted")
	}
}

func unsafeFixture(t *testing.T, dir, path, kind string) {
	t.Helper()
	var err error
	switch kind {
	case "symlink":
		err = os.Symlink(filepath.Join(dir, "missing"), path)
	case "fifo":
		err = unix.Mkfifo(path, 0o600)
	default:
		fixtures := map[string]string{"empty": "{}", "null": "null", "corrupt": "{", "version": `{"version":99}`, "oversize": strings.Repeat("x", stateLimit+1)}
		data, ok := fixtures[kind]
		if !ok {
			data = `{"version":1}`
		}
		err = os.WriteFile(path, []byte(data), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if kind == "permissions" {
			err = os.Chmod(path, 0o644)
		}
		if kind == "hardlink" {
			err = os.Link(path, filepath.Join(dir, "alias"))
		}
	}
	if err != nil {
		t.Fatal(err)
	}
}
