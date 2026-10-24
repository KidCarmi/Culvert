//go:build linux

package main

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRosterProbe_RealChattrWarns: a real chattr +i or +a on the saved
// roster (root here) makes the live probe warn. Skips where the filesystem
// or privileges do not allow the flag.
func TestRosterProbe_RealChattrWarns(t *testing.T) {
	const fsImmutableFL, fsAppendFL = 0x10, 0x20
	for name, flag := range map[string]int{"+i": fsImmutableFL, "+a": fsAppendFL} {
		t.Run(name, func(t *testing.T) {
			_, path := savedRosterCfg(t)
			f, err := os.Open(path) // #nosec G304 -- test temp path
			if err != nil {
				t.Fatal(err)
			}
			cur, err := unix.IoctlGetUint32(int(f.Fd()), unix.FS_IOC_GETFLAGS)
			if err == nil {
				err = unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, int(cur)|flag)
			}
			_ = f.Close()
			if err != nil {
				t.Skipf("cannot chattr %s on the test filesystem (%v)", name, err)
			}
			t.Cleanup(func() {
				if g, err := os.Open(path); err == nil { // #nosec G304 -- test temp path
					_ = unix.IoctlSetPointerInt(int(g.Fd()), unix.FS_IOC_SETFLAGS, int(cur))
					_ = g.Close()
				}
			})
			assertRosterImmutableRow(t)
		})
	}
}
