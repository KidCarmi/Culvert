// CULVERT PATCH (scanner, CULVERT-PATCH.md) — not part of upstream badger.

package table

import (
	"math"
	"testing"
)

// Every id ParseFileID accepts must be usable by blockCacheKey, which packs it
// into 4 bytes and asserts id < MaxUint32 (a fatal log.Fatalf otherwise).
func TestParseFileIDBoundaryReachesBlockCacheKey(t *testing.T) {
	for name, wantOK := range map[string]bool{
		"4294967294.sst": true,  // largest id the cache key can hold
		"4294967295.sst": false, // MaxUint32: reserved by blockCacheKey
		"4294967296.sst": false,
		"-1.sst":         false,
	} {
		id, ok := ParseFileID(name)
		if ok != wantOK {
			t.Fatalf("ParseFileID(%q) ok=%v, want %v", name, ok, wantOK)
		}
		if ok {
			if id >= math.MaxUint32 {
				t.Fatalf("accepted id %d does not fit the cache key", id)
			}
			key := (&Table{id: id}).blockCacheKey(0)
			if len(key) != 8 {
				t.Fatalf("cache key %x", key)
			}
		}
	}
}
