//go:build !linux

package storeguard

import "testing"

// syntheticFault carries Addr() exactly like the runtime's error for a
// SetPanicOnFault-converted fault, so the non-Linux branch can be exercised on
// platforms where a real mapping fault cannot be produced portably.
type syntheticFault struct{ addr uintptr }

func (f syntheticFault) Error() string { return "synthetic fault" }
func (f syntheticFault) Addr() uintptr { return f.addr }

// Off Linux, containment is unavailable by design: it is reported as such, and
// a fault re-panics (the behaviour before containment existed) instead of
// being swallowed without evidence of its origin.
func TestContainFault_UnsupportedPlatformRePanics(t *testing.T) {
	if FaultContainmentSupported {
		t.Fatal("FaultContainmentSupported must be false off Linux")
	}
	var got any
	func() {
		defer func() { got = recover() }()
		_ = ContainFault(t.TempDir(), func() error {
			panic(syntheticFault{addr: 0x1000})
		})
	}()
	if got == nil {
		t.Fatal("a fault was contained on a platform that cannot verify its origin")
	}
	if _, ok := got.(syntheticFault); !ok {
		t.Fatalf("re-panicked with %T, want the original value", got)
	}
}
