package alerts

import "testing"

// saveSink snapshots and restores the package-global sink so tests don't
// contaminate each other (the sink is process-global, publish-once in prod).
func saveSink(t *testing.T) {
	t.Helper()
	old := sink.Load()
	t.Cleanup(func() { sink.Store(old) })
}

func TestFire_NoSink_IsNoop(t *testing.T) {
	saveSink(t)
	sink.Store(nil)
	// Must not panic when no sink is installed.
	Fire("anything", Payload{Detail: "x"})
}

func TestSetSink_Fire_Delivers(t *testing.T) {
	saveSink(t)

	var gotEvent string
	var gotPayload Payload
	SetSink(func(event string, p Payload) {
		gotEvent = event
		gotPayload = p
	})

	Fire("threat_detected", Payload{Source: "yara", Detail: "rule-x", Host: "h"})

	if gotEvent != "threat_detected" {
		t.Errorf("event = %q, want threat_detected", gotEvent)
	}
	if gotPayload.Source != "yara" || gotPayload.Detail != "rule-x" || gotPayload.Host != "h" {
		t.Errorf("payload not delivered intact: %+v", gotPayload)
	}
}

func TestSetSink_ReplacesPrevious(t *testing.T) {
	saveSink(t)

	first := 0
	second := 0
	SetSink(func(string, Payload) { first++ })
	SetSink(func(string, Payload) { second++ }) // publish-once: last wins

	Fire("e", Payload{})
	if first != 0 {
		t.Errorf("first sink fired %d times, want 0 (replaced)", first)
	}
	if second != 1 {
		t.Errorf("second sink fired %d times, want 1", second)
	}
}
