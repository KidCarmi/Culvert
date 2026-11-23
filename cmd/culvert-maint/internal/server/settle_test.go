package server

import (
	"context"
	"testing"
	"time"

	"culvert-maint/internal/config"
)

func settleServer(window time.Duration, startedAgo time.Duration) *Server {
	return &Server{opts: Options{Cfg: &config.Config{InterruptedSettle: window}}, startedAt: time.Now().Add(-startedAgo)}
}

// TestSettleRemaining_FromProcessStart: the window is counted from the start of
// this process; once it is over nothing waits; 0 turns the wait off.
func TestSettleRemaining_FromProcessStart(t *testing.T) {
	if r := settleServer(time.Minute, 10*time.Second).settleRemaining(); r < 49*time.Second || r > 50*time.Second {
		t.Errorf("10s into a 1m window: remaining = %v, want about 50s", r)
	}
	if r := settleServer(time.Minute, 2*time.Minute).settleRemaining(); r > 0 {
		t.Errorf("after the window: remaining = %v, want none", r)
	}
	if r := settleServer(0, 0).settleRemaining(); r != 0 {
		t.Errorf("interrupted_settle=0: remaining = %v, want 0 (off)", r)
	}
}

// TestSettleRemaining_RestartsAfterACutMutation: a compose up/down of this
// process that ended in an error may have left a container stop in dockerd,
// exactly as a dead predecessor would. The window starts again from there, so
// the inline rollback that follows a failed `up` cannot judge a container that
// stop is still about to kill.
func TestSettleRemaining_RestartsAfterACutMutation(t *testing.T) {
	s := settleServer(time.Minute, time.Hour) // long past the start window
	if r := s.settleRemaining(); r > 0 {
		t.Fatalf("precondition: remaining = %v", r)
	}
	s.noteMutationCut()
	if r := s.settleRemaining(); r < 59*time.Second {
		t.Errorf("right after a cut mutation: remaining = %v, want about the whole window", r)
	}
}

// TestSettleInterrupted_WaitsAndHonoursContext: the wait lasts until the window
// is over, returns a note for the operation log, does nothing afterwards, and
// fails rather than passes when its context ends first.
func TestSettleInterrupted_WaitsAndHonoursContext(t *testing.T) {
	s := settleServer(300*time.Millisecond, 0)
	began := time.Now()
	note, err := s.settleInterrupted(context.Background())
	if err != nil || len(note) == 0 {
		t.Fatalf("note=%q err=%v, want a note and no error", note, err)
	}
	if took := time.Since(began); took < 250*time.Millisecond {
		t.Errorf("returned after %v, before the window was over", took)
	}
	if note, err := s.settleInterrupted(context.Background()); err != nil || note != nil {
		t.Errorf("after the window: note=%q err=%v, want nothing", note, err)
	}

	s = settleServer(time.Minute, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := s.settleInterrupted(ctx); err == nil {
		t.Error("a context that ended inside the window must fail the wait, not pass it")
	}
}
