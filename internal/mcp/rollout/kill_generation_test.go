package rollout

import (
	"sync"
	"testing"
)

// TestKillGenerationMonotonicSemantics pins the Model B contract of the kill generation:
// it starts at 0, advances by one per DISTINCT engage transition (idempotent engage does
// not advance), is NEVER rolled back by a clear (the engage→clear ABA case), advances again
// on re-engage, and is carried FORWARD (never reset) across a config apply.
func TestKillGenerationMonotonicSemantics(t *testing.T) {
	st := NewState(CapabilityGateway, testLimits(t))
	if g := st.KillGeneration(); g != 0 {
		t.Fatalf("initial generation = %d, want 0", g)
	}
	st.EngageKillSwitch("oncall", 1)
	if g := st.KillGeneration(); g != 1 {
		t.Fatalf("generation after engage = %d, want 1", g)
	}
	st.EngageKillSwitch("oncall", 2) // idempotent — already killed
	if g := st.KillGeneration(); g != 1 {
		t.Fatalf("idempotent engage advanced generation to %d, want 1", g)
	}
	st.ClearKillSwitch()
	if st.Killed() {
		t.Fatal("clear should clear killed")
	}
	if g := st.KillGeneration(); g != 1 {
		t.Fatalf("clear rolled the generation back to %d, want 1 (Model B never decrements)", g)
	}
	st.EngageKillSwitch("oncall", 3) // re-engage after clear (the ABA case)
	if g := st.KillGeneration(); g != 2 {
		t.Fatalf("re-engage generation = %d, want 2", g)
	}

	// A config apply must carry the generation forward, never reset it — otherwise a request
	// admitted before the apply would read a lower boundary generation and miss the kill.
	cfg := SignedConfig{SelectorSchema: selectorSchema, Capability: CapabilityGateway, Mode: ModeShadow, ScopeRevision: 1,
		Scope: ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}}, ConnectorMode: ConnectorLocalClient}
	if err := st.SetConfig(cfg, "admin", 4); err != nil {
		t.Fatal(err)
	}
	if g := st.KillGeneration(); g != 2 {
		t.Fatalf("config apply changed the generation to %d, want 2 (must carry forward)", g)
	}
}

// TestKillSnapshotPublishedAtomically is the regression guard for the Codex P1 on PR #1248:
// the emergency-kill generation must be published in the SAME atomic snapshot as the `killed`
// flag. If they were split across two independently-published atomics, a lock-free reader
// could observe killed==true while still reading the pre-engage generation — the window in
// which the side-effect boundary (which re-reads only the generation) would permit an upstream
// call during an in-flight engage. This hammers EngageKillSwitch/ClearKillSwitch against
// lock-free snapshot readers and asserts, per whitebox snapshot, that killed==true always
// carries a non-zero generation. Meaningful under -race.
func TestKillSnapshotPublishedAtomically(t *testing.T) {
	st := NewState(CapabilityGateway, testLimits(t))
	done := make(chan struct{})
	var wg sync.WaitGroup

	const readers = 8
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				// One atomic load = one consistent snapshot. killed and killGen come from the
				// SAME activeState, so an engaged kill can never be seen with generation 0.
				a := st.cur.Load()
				if a.killed && a.killGen == 0 {
					t.Errorf("SPLIT PUBLICATION: observed killed=true with generation 0 — killed and killGen are not one atomic snapshot")
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 3000; i++ {
			st.EngageKillSwitch("oncall", int64(i))
			st.ClearKillSwitch()
		}
		close(done)
	}()
	wg.Wait()
}
