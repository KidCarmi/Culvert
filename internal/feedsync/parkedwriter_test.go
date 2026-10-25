package feedsync

// parkedwriter_test.go — shared control of a BulkWrite parked inside the catdb
// write-fault hook (ASTRA d75afe85 audit, items 1 and 3).
//
// Quiescence of an abandoned writer is proven by JOINING the writer's actual
// return (Syncer.writeReturnedForTest), never inferred from visible keys. The
// helper registers its own teardown — release, then a bounded join — so a test
// that fails before it releases still leaves no parked writer behind. Callers
// register their DB Close BEFORE creating the helper: t.Cleanup runs LIFO, so
// the release+join runs first and the database is never closed under an
// in-flight write, including on fatal paths and under -race/-shuffle repeats.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const parkedJoinTimeout = 10 * time.Second

type parkedWriter struct {
	t        *testing.T
	rel      chan struct{}
	relOnce  sync.Once
	returned chan error // the Syncer's writeReturnedForTest
	started  atomic.Bool

	joinOnce sync.Once
	joinErr  error
	joinOK   bool
}

func newParkedWriter(t *testing.T) *parkedWriter {
	t.Helper()
	// Buffered beyond one so a defective (pre-fix) second writer can never block
	// the first writer's report and leak its goroutine.
	p := &parkedWriter{t: t, rel: make(chan struct{}), returned: make(chan error, 4)}
	t.Cleanup(func() {
		p.release()
		if !p.started.Load() {
			return // no writer ever reached the hook: nothing to join
		}
		if _, ok := p.wait(); !ok {
			t.Errorf("teardown: the parked BulkWrite did not return within %s after release", parkedJoinTimeout)
		}
	})
	return p
}

// hook parks the FIRST write that reaches entry n==1 until release. extra (if
// non-nil) runs on every n==1 entry — before parking — so a test can count
// writers or latch a fault exactly where the write is held.
func (p *parkedWriter) hook(extra func()) func(int) error {
	return func(n int) error {
		if n == 1 {
			if extra != nil {
				extra()
			}
			if p.started.CompareAndSwap(false, true) {
				<-p.rel
			}
		}
		return nil
	}
}

// attach wires the join signal into the Syncer. Must run before the first sync.
func (p *parkedWriter) attach(s *Syncer) { s.writeReturnedForTest = p.returned }

// release unparks the writer. Idempotent.
func (p *parkedWriter) release() { p.relOnce.Do(func() { close(p.rel) }) }

func (p *parkedWriter) wait() (error, bool) {
	p.joinOnce.Do(func() {
		select {
		case err := <-p.returned:
			p.joinErr, p.joinOK = err, true
		case <-time.After(parkedJoinTimeout):
		}
	})
	return p.joinErr, p.joinOK
}

// join waits (bounded) for the parked BulkWrite's actual return and returns
// its result. It fails the test if the writer does not return in time.
func (p *parkedWriter) join() error {
	p.t.Helper()
	err, ok := p.wait()
	if !ok {
		p.t.Fatalf("the parked BulkWrite did not return within %s of release (writer not quiescent)", parkedJoinTimeout)
	}
	return err
}
