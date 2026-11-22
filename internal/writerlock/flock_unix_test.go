//go:build unix

package writerlock

import (
	"os"
	"path/filepath"
	"testing"
)

// A descriptor the kernel will not lock is "cannot tell", never "somebody
// else has it": only EWOULDBLOCK means a live holder.
func TestFlock_AnErrorOtherThanWouldBlockIsNotAHolder(t *testing.T) {
	f, err := os.OpenFile(filepath.Join(t.TempDir(), "f"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	held, lockErr := flockExclusiveNonBlocking(f)
	if lockErr == nil {
		t.Fatal("locking a closed descriptor must report an error")
	}
	if held {
		t.Fatal("an error must not report the lock as taken")
	}
}

func TestFlock_ALiveHolderIsNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	open := func() *os.File {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	if held, err := flockExclusiveNonBlocking(open()); !held || err != nil {
		t.Fatalf("first: held=%v err=%v, want true, nil", held, err)
	}
	if held, err := flockExclusiveNonBlocking(open()); held || err != nil {
		t.Fatalf("second: held=%v err=%v, want false, nil", held, err)
	}
}
