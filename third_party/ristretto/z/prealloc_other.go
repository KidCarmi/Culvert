//go:build !linux

// CULVERT PATCH (F-DISK-1, CULVERT-PATCH.md) — not part of upstream ristretto.

package z

import "os"

// preallocate is a no-op off Linux: the appliance runs on Linux, and other
// platforms keep upstream's behaviour.
func preallocate(_ *os.File, _, _ int64) error { return nil }
