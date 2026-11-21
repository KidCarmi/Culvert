package keyedmutex

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// entries and refs read the table the way Lock does, under the table lock.
func (k *Mutex) entries() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}

func (k *Mutex) refs(key string) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	if e := k.m[key]; e != nil {
		return e.refs
	}
	return 0
}

// waitRefs blocks until key has exactly n holders+waiters registered. The
// count is published before a waiter parks on the entry, so this is how a test
// knows a goroutine is committed to waiting without sleeping for a guess.
func waitRefs(t *testing.T, k *Mutex, key string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for k.refs(key) != n {
		if time.Now().After(deadline) {
			t.Fatalf("key %q: refs=%d, want %d", key, k.refs(key), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// Same key: one holder at a time. The counter is a plain int on purpose, so
// the race detector fails the test if two holders ever overlap.
func TestLock_SameKeyIsMutuallyExclusive(t *testing.T) {
	k := New()
	const workers, rounds = 16, 300
	counter, inside := 0, 0
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				unlock := k.Lock("gen-42")
				inside++
				if inside != 1 {
					t.Errorf("%d holders inside the critical section", inside)
				}
				counter++
				inside--
				unlock()
			}
		}()
	}
	wg.Wait()
	if counter != workers*rounds {
		t.Fatalf("counter=%d, want %d", counter, workers*rounds)
	}
	if n := k.entries(); n != 0 {
		t.Fatalf("%d entries left after every holder released", n)
	}
}

// Different keys do not wait for one another: a second key is acquired while
// the first is still held. A single shared lock would deadlock here.
func TestLock_DifferentKeysAreIndependent(t *testing.T) {
	k := New()
	unlockA := k.Lock("a")
	done := make(chan struct{})
	go func() {
		defer close(done)
		k.Lock("b")()
		k.Lock("")() // the empty key is a key like any other
		k.Lock("op:a")()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a held key blocked a different key")
	}
	if got := k.refs("a"); got != 1 {
		t.Fatalf("refs(a)=%d while held, want 1", got)
	}
	unlockA()
	if n := k.entries(); n != 0 {
		t.Fatalf("%d entries left, want 0", n)
	}
}

// A waiter on a held key does not get in until the holder releases, and the
// entry lives exactly as long as someone holds or waits for it.
func TestLock_WaiterBlocksUntilReleaseAndEntryIsCollected(t *testing.T) {
	k := New()
	unlock := k.Lock("inst-1")
	const waiters = 5
	entered := make(chan int, waiters)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := k.Lock("inst-1")
			entered <- i
			<-release
			u()
		}(i)
	}
	waitRefs(t, k, "inst-1", 1+waiters)
	select {
	case i := <-entered:
		t.Fatalf("waiter %d entered while the key was held", i)
	case <-time.After(50 * time.Millisecond):
	}
	if n := k.entries(); n != 1 {
		t.Fatalf("entries=%d with one contended key, want 1", n)
	}

	unlock()
	// Exactly one waiter is inside at a time: each must be released before
	// the next can enter.
	for got := 0; got < waiters; got++ {
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatalf("waiter %d never entered after release", got)
		}
		select {
		case i := <-entered:
			t.Fatalf("waiter %d entered while another waiter held the key", i)
		case <-time.After(10 * time.Millisecond):
		}
		if want := waiters - got; k.refs("inst-1") != want {
			t.Fatalf("refs=%d with %d still holding or waiting", k.refs("inst-1"), want)
		}
		release <- struct{}{}
	}
	wg.Wait()
	if n := k.entries(); n != 0 {
		t.Fatalf("entry not collected after the last waiter released: %d left", n)
	}
}

// The table does not grow with the number of keys ever used.
func TestLock_UncontendedKeysLeaveNothingBehind(t *testing.T) {
	k := New()
	for i := 0; i < 2000; i++ {
		unlock := k.Lock(fmt.Sprintf("gen-%d", i))
		if n := k.entries(); n != 1 {
			t.Fatalf("iteration %d: %d entries while one key is held", i, n)
		}
		unlock()
	}
	if n := k.entries(); n != 0 {
		t.Fatalf("%d entries left after 2000 distinct keys", n)
	}
	// A key is reusable after its entry was collected.
	k.Lock("gen-7")()
	k.Lock("gen-7")()
}

// Two Mutex values share nothing: the same key held in one does not block,
// and is not visible in, the other.
func TestNew_InstancesAreIndependent(t *testing.T) {
	a, b := New(), New()
	if a == b {
		t.Fatal("New returned a shared instance")
	}
	unlockA := a.Lock("same")
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.Lock("same")()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a key held in one Mutex blocked another Mutex")
	}
	if a.refs("same") != 1 || b.refs("same") != 0 || b.entries() != 0 {
		t.Fatalf("state crossed instances: a.refs=%d b.refs=%d b.entries=%d", a.refs("same"), b.refs("same"), b.entries())
	}
	unlockA()
}

// Many keys, many goroutines: per-key counters stay exact and nothing is left.
func TestLock_ConcurrentMixedKeys(t *testing.T) {
	k := New()
	const keys, workers, rounds = 8, 24, 200
	counters := make([]int, keys)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				n := (w + i) % keys
				unlock := k.Lock(fmt.Sprintf("k%d", n))
				counters[n]++
				unlock()
			}
		}(w)
	}
	wg.Wait()
	total := 0
	for _, c := range counters {
		total += c
	}
	if total != workers*rounds {
		t.Fatalf("total=%d, want %d", total, workers*rounds)
	}
	if n := k.entries(); n != 0 {
		t.Fatalf("%d entries left", n)
	}
}
