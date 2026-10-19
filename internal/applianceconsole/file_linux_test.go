//go:build linux

package applianceconsole

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPublicFileRejectsFIFOWithoutWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() { done <- readPublicFile(path) }()
	select {
	case data := <-done:
		if data != "" {
			t.Fatal("nonregular metadata accepted")
		}
	case <-time.After(time.Second):
		// Unblock a regressed blocking open before failing the test.
		fd, err := unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK, 0)
		if err == nil {
			unix.Close(fd)
		}
		t.Fatal("FIFO blocked collection")
	}
	if readPublicFile("/dev/zero") != "" || readPublicFile(filepath.Dir(path)) != "" {
		t.Fatal("device or directory accepted")
	}
}

func TestPublicFileAllowsResolverSymlink(t *testing.T) {
	dir := t.TempDir()
	target, link := filepath.Join(dir, "resolver"), filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(target, []byte("nameserver 192.0.2.53\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if got := readDNS(link); len(got) != 1 || got[0] != "192.0.2.53" {
		t.Fatal(got)
	}
}
