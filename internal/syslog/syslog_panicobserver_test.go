package syslog

// Panic-observer tests (CHAOS-24 extension): deliverGuarded's recover branch
// forwards the recovered value to an optional observer since this package
// cannot log for itself (stdlib-only leaf). No production code path exercised
// this before — these are the first tests to actually trigger a delivery
// panic and drive it through deliverGuarded.

import (
	"net"
	"testing"
	"time"
)

// panickingConn is a net.Conn whose Write always panics, used to drive a real
// panic through deliverLine -> writeLine without a fake network dependency.
type panickingConn struct{ net.Conn }

func (c *panickingConn) Write([]byte) (int, error)        { panic("simulated formatting bug") }
func (c *panickingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *panickingConn) Close() error                     { return nil }

func TestDeliverGuarded_NotifiesPanicObserver(t *testing.T) {
	w := &Writer{conn: &panickingConn{}}
	var calls int
	var got any
	w.SetPanicObserver(func(recovered any) {
		calls++
		got = recovered
	})

	w.deliverGuarded("test line")

	if calls != 1 {
		t.Fatalf("observer called %d times, want 1", calls)
	}
	if got == nil {
		t.Fatal("observer received a nil recovered value")
	}
	if w.Panics() != 1 {
		t.Errorf("Panics() = %d, want 1", w.Panics())
	}
	if w.Drops() != 1 {
		t.Errorf("Drops() = %d, want 1", w.Drops())
	}
}

// A Writer with no observer wired (the zero-value / pre-SetPanicObserver
// state) must keep containing panics exactly as before - the observer is
// additive, never required.
func TestDeliverGuarded_NilObserverStillContainsPanic(t *testing.T) {
	w := &Writer{conn: &panickingConn{}}

	w.deliverGuarded("test line")

	if w.Panics() != 1 || w.Drops() != 1 {
		t.Errorf("Panics()=%d Drops()=%d, want 1,1", w.Panics(), w.Drops())
	}
}

// A panicking observer must never propagate out of deliverGuarded - the same
// containment contract fileutil.SetWriteFailureObserver and
// audit.SetWriteFailureObserver document for their observers.
func TestDeliverGuarded_ObserverPanicIsContained(t *testing.T) {
	w := &Writer{conn: &panickingConn{}}
	w.SetPanicObserver(func(any) { panic("observer exploded") })

	w.deliverGuarded("test line") // must not panic the test

	if w.Panics() != 1 || w.Drops() != 1 {
		t.Errorf("Panics()=%d Drops()=%d, want 1,1", w.Panics(), w.Drops())
	}
}

func TestSetPanicObserver_NilClears(t *testing.T) {
	w := &Writer{conn: &panickingConn{}}
	var calls int
	w.SetPanicObserver(func(any) { calls++ })
	w.SetPanicObserver(nil)

	w.deliverGuarded("test line")

	if calls != 0 {
		t.Errorf("observer called %d times after clearing, want 0", calls)
	}
}
