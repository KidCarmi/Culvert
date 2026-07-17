package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/redaction"
)

// TestTimelineSortKey pins the deterministic, wall-clock-free ordering key: a
// valid RFC3339 stamp parses to its millis; anything else sorts last (0).
func TestTimelineSortKey(t *testing.T) {
	a := timelineSortKey("2026-07-17T10:00:00Z")
	b := timelineSortKey("2026-07-17T11:00:00Z")
	if !(b > a) {
		t.Fatalf("later stamp should sort higher: a=%d b=%d", a, b)
	}
	if got := timelineSortKey("not-a-time"); got != 0 {
		t.Fatalf("unparseable stamp key=%d want 0", got)
	}
	if got := timelineSortKey(""); got != 0 {
		t.Fatalf("empty stamp key=%d want 0", got)
	}
}

// TestTimelineEvent_ActorMasked proves the only identifying field — the config
// actor — is masked to a salted token, never emitted raw. Time/Kind/Ref/Label are
// low-cardinality labels that stay clear.
func TestTimelineEvent_ActorMasked(t *testing.T) {
	rd := redaction.NewWithSalt([]byte("fixed-salt"))
	ev := timelineEvent{
		Time:  "2026-07-17T10:00:00Z",
		Kind:  "config_version",
		Ref:   "42",
		Actor: "203.0.113.7",
		Label: "policy.update",
	}
	out, _ := json.Marshal(rd.Struct(ev))
	if strings.Contains(string(out), "203.0.113.7") {
		t.Fatalf("timeline actor leaked unmasked: %s", out)
	}
	// Non-identifying labels are preserved for triage.
	for _, keep := range []string{"config_version", "policy.update", "42"} {
		if !strings.Contains(string(out), keep) {
			t.Fatalf("timeline label %q was dropped: %s", keep, out)
		}
	}
}
