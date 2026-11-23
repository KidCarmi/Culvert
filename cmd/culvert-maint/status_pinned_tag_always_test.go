package main

import "testing"

// TestStatus_PinnedTagReportedWithoutInterruptedOperation: the fixed tag and
// the running container can be apart with no journal record — an apply that
// went terminal with the tag left on the target, or a tag moved by hand. The
// status must say so; before, pinned_tag was reported only while an
// interrupted operation was outstanding, and this state showed nothing.
func TestStatus_PinnedTagReportedWithoutInterruptedOperation(t *testing.T) {
	r := newCrashRig(t)
	r.put("running", imgA)
	r.put("pinned", imgA)
	r.start()

	var st statusView
	r.get("/v1/status", &st)
	if len(st.Interrupted) != 0 {
		t.Fatalf("clean start reported interrupted operations: %+v", st.Interrupted)
	}
	if st.PinnedTag == nil || st.PinnedTag.MatchesRunning == nil || !*st.PinnedTag.MatchesRunning {
		t.Fatalf("pinned_tag must be reported, and match, with nothing interrupted: %+v", st.PinnedTag)
	}

	// The tag moves with no operation behind it.
	r.put("pinned", imgB)
	st = statusView{}
	r.get("/v1/status", &st)
	if len(st.Interrupted) != 0 {
		t.Fatalf("a tag move must not invent an interrupted operation: %+v", st.Interrupted)
	}
	if st.PinnedTag == nil || st.PinnedTag.MatchesRunning == nil || *st.PinnedTag.MatchesRunning {
		t.Errorf("pinned_tag must report the mismatch with no interrupted operation: %+v", st.PinnedTag)
	}
	if calls := r.mutatingCalls(); len(calls) != 0 {
		t.Errorf("reading the status changed Docker: %v", calls)
	}
}
