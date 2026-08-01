package policy

import (
	"sync"
	"testing"
)

func snapRev(t *testing.T, capName string, rev int) *Snapshot {
	t.Helper()
	doc := `{"schema_version":1,"capability":"` + capName + `","policy_revision":` + itoaS(rev) + `,"default_action":"DENY","rules":[]}`
	return mustCompile(t, doc)
}

func itoaS(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestStore_PublishMonotonic(t *testing.T) {
	st := NewStore(CapGateway)
	if st.Current() != nil || st.CurrentRevision() != 0 {
		t.Fatal("empty store must have no current snapshot")
	}
	// First publish from base 0.
	s1 := snapRev(t, "gateway", 1)
	if err := st.Publish(0, s1); err != nil {
		t.Fatalf("publish v1: %v", err)
	}
	if st.Current() != s1 || st.CurrentRevision() != 1 {
		t.Fatal("v1 not current")
	}
	// A stale base is rejected.
	s2 := snapRev(t, "gateway", 2)
	if err := st.Publish(0, s2); err == nil {
		t.Fatal("stale base must be rejected")
	}
	if st.CurrentRevision() != 1 {
		t.Fatal("rejected publish must not change current")
	}
	// Correct base succeeds.
	if err := st.Publish(1, s2); err != nil {
		t.Fatalf("publish v2: %v", err)
	}
	// A non-increasing revision is rejected.
	s2b := snapRev(t, "gateway", 2)
	if err := st.Publish(2, s2b); err == nil {
		t.Fatal("non-increasing revision must be rejected")
	}
}

func TestStore_RejectsWrongCapability(t *testing.T) {
	st := NewStore(CapGateway)
	mg := snapRev(t, "management", 1)
	if err := st.Publish(0, mg); err == nil {
		t.Fatal("publishing a management snapshot into a gateway store must fail")
	}
	if err := st.Publish(0, nil); err == nil {
		t.Fatal("publishing a nil snapshot must fail")
	}
}

// TestStore_ConcurrentReadersSeeConsistentSnapshot: lock-free reads never observe a
// partial snapshot under concurrent publishes.
func TestStore_ConcurrentReadersSeeConsistentSnapshot(t *testing.T) {
	st := NewStore(CapGateway)
	if err := st.Publish(0, snapRev(t, "gateway", 1)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Readers.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if c := st.Current(); c != nil {
						_ = c.Revision()
						_ = c.Capability()
					}
				}
			}
		}()
	}
	// Serial publisher (only one writer, optimistic base).
	for rev := 2; rev <= 200; rev++ {
		_ = st.Publish(Revision(rev-1), snapRev(t, "gateway", rev))
	}
	close(stop)
	wg.Wait()
	if st.CurrentRevision() != 200 {
		t.Fatalf("final revision = %d, want 200", st.CurrentRevision())
	}
}
