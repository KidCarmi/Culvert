package catalog

// Isolated deterministic fixture for a path whose coverage previously depended
// on timing; see roadmap/CI-REDESIGN.md stage 5B.
//
// DisableServer's `continue` (skip an entry of ANOTHER server, or one already
// ServerDisabled) was reached only by TestConcurrentIngestAndDisable, and only
// when one DisableServer call landed after another with no Ingest between them.
// Every other caller disables the only server of a freshly ingested catalog,
// where every entry matches and none is disabled yet. Stage 5B qualification
// round 5 found the block covered by the unsharded reference and not by the
// lane, which runs the same command. The fixture takes both skip arms
// synchronously.

import "testing"

// Pins catalog.go DisableServer's `continue`: disabling one server leaves a
// second server's entry untouched, and a repeat disable is a no-op that
// publishes no new revision.
func TestIsolation_DisableServerSkipsOtherAndAlreadyDisabled(t *testing.T) {
	l := lim(t)
	c := New(l)
	reg := regWith(t, l, [2]string{"srv-A", "spiffe://culvert/A"}, [2]string{"srv-B", "spiffe://culvert/B"})
	ingest(t, c, reg, "srv-A", "spiffe://culvert/A", result(`{"name":"a","inputSchema":{}}`))
	ingest(t, c, reg, "srv-B", "spiffe://culvert/B", result(`{"name":"b","inputSchema":{}}`))
	before, _ := c.Current().Get(ToolKey{Server: "srv-B", Name: "b"})

	// First disable: srv-B's entry is skipped (another server).
	first, err := c.DisableServer("srv-A")
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if a, _ := first.Get(ToolKey{Server: "srv-A", Name: "a"}); a.Eligibility != ServerDisabled {
		t.Fatalf("srv-A entry eligibility = %v, want server_disabled", a.Eligibility)
	}
	if b, _ := first.Get(ToolKey{Server: "srv-B", Name: "b"}); b.Eligibility != before.Eligibility || b.Revision != before.Revision {
		t.Fatalf("srv-B entry changed by disabling srv-A: %v/%d -> %v/%d",
			before.Eligibility, before.Revision, b.Eligibility, b.Revision)
	}

	// Second disable: srv-A's entry is already disabled and srv-B's is another
	// server, so nothing is touched and the current snapshot is returned as is.
	second, err := c.DisableServer("srv-A")
	if err != nil {
		t.Fatalf("repeat disable: %v", err)
	}
	if second != first || c.Current() != first {
		t.Fatal("a repeat disable published a new snapshot; want a no-op")
	}
}
