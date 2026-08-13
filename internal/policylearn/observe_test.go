package policylearn

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// collectSink is a deterministic sink: it records delivered observations and
// can be gated (blocking) or armed to panic.
type collectSink struct {
	mu       sync.Mutex
	got      []Observation
	gate     chan struct{} // non-nil: each delivery waits for one token
	panicOn  map[int]bool  // delivery ordinal (1-based) → panic
	delivery int
}

func (c *collectSink) sink(o Observation) {
	if c.gate != nil {
		<-c.gate
	}
	c.mu.Lock()
	c.delivery++
	n := c.delivery
	shouldPanic := c.panicOn[n]
	if !shouldPanic {
		c.got = append(c.got, o)
	}
	c.mu.Unlock()
	if shouldPanic {
		panic("sink boom")
	}
}

func (c *collectSink) observations() []Observation {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Observation(nil), c.got...)
}

func newObserveEngine(t *testing.T, clk *testClock, sink *collectSink) *Engine {
	t.Helper()
	e, err := New(Config{Now: clk.now, Sink: sink.sink})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func startLearning(t *testing.T, e *Engine) {
	t.Helper()
	if _, err := e.StartSession("test"); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
}

func obs(host string) Observation {
	return Observation{Subject: "alice", AuthSource: "test-idp", Host: host, Method: "GET", Action: "Allow", Status: "OK"}
}

func TestObserve_InactiveIgnored(t *testing.T) {
	sink := &collectSink{}
	e := newObserveEngine(t, newTestClock(), sink)
	e.Observe(obs("h.example")) // no active session
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	st := e.ObservationStats()
	if st.Accepted != 0 || st.Dropped != 0 || st.Rejected != 0 || st.Delivered != 0 {
		t.Fatalf("inactive engine counted something: %+v", st)
	}
	if len(sink.observations()) != 0 {
		t.Fatal("sink received an observation with no active session")
	}
}

func TestObserve_DeliveredWithCopiedGroups(t *testing.T) {
	sink := &collectSink{}
	clk := newTestClock()
	e := newObserveEngine(t, clk, sink)
	startLearning(t, e)

	callerGroups := []string{"eng", "sec"}
	o := obs("h.example")
	o.Groups = callerGroups
	e.Observe(o)
	callerGroups[0] = "MUTATED" // request-owned slice reused after emit

	if err := e.Close(); err != nil { // drains deterministically
		t.Fatal(err)
	}
	got := sink.observations()
	if len(got) != 1 {
		t.Fatalf("delivered = %d, want 1", len(got))
	}
	if got[0].Groups[0] != "eng" || got[0].Groups[1] != "sec" {
		t.Fatalf("groups not copied at the boundary: %v", got[0].Groups)
	}
	if got[0].At == 0 {
		t.Fatal("At not stamped from the injected clock")
	}
	st := e.ObservationStats()
	if st.Accepted != 1 || st.Delivered != 1 || st.Dropped != 0 {
		t.Fatalf("counters: %+v", st)
	}
}

func TestObserve_RejectedEmptyHost(t *testing.T) {
	sink := &collectSink{}
	e := newObserveEngine(t, newTestClock(), sink)
	startLearning(t, e)
	e.Observe(Observation{Subject: "alice"})
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	st := e.ObservationStats()
	if st.Rejected != 1 || st.Accepted != 0 {
		t.Fatalf("counters: %+v", st)
	}
}

func TestObserve_GroupsTruncatedDeterministically(t *testing.T) {
	sink := &collectSink{}
	e := newObserveEngine(t, newTestClock(), sink)
	startLearning(t, e)
	o := obs("h.example")
	for i := 0; i < 40; i++ {
		o.Groups = append(o.Groups, fmt.Sprintf("g%02d", i))
	}
	e.Observe(o)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	got := sink.observations()
	if len(got) != 1 || len(got[0].Groups) != MaxObservationGroups {
		t.Fatalf("groups = %d, want %d", len(got[0].Groups), MaxObservationGroups)
	}
	if got[0].Groups[0] != "g00" || got[0].Groups[MaxObservationGroups-1] != fmt.Sprintf("g%02d", MaxObservationGroups-1) {
		t.Fatalf("truncation not deterministic prefix: %v", got[0].Groups)
	}
}

func TestObserve_QueueFullDropsNeverBlocks(t *testing.T) {
	sink := &collectSink{gate: make(chan struct{})}
	e := newObserveEngine(t, newTestClock(), sink)
	startLearning(t, e)

	// One observation is pulled by the drain and parks on the gate; the queue
	// then holds observationQueueCap more. Overfill by 10 — every extra MUST
	// return immediately and count as dropped.
	total := observationQueueCap + 1 + 10
	for i := 0; i < total; i++ {
		e.Observe(obs(fmt.Sprintf("h%d.example", i)))
	}
	st := e.ObservationStats()
	if st.Dropped == 0 {
		t.Fatalf("overfill did not drop: %+v", st)
	}
	if st.Accepted+st.Dropped != int64(total) {
		t.Fatalf("accounting mismatch: accepted %d + dropped %d != %d", st.Accepted, st.Dropped, total)
	}
	// Release the consumer and shut down: every accepted event is delivered.
	go func() {
		for i := 0; i < total; i++ {
			sink.gate <- struct{}{}
		}
	}()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	st = e.ObservationStats()
	if st.Delivered != st.Accepted {
		t.Fatalf("close did not drain: delivered %d, accepted %d", st.Delivered, st.Accepted)
	}
}

func TestObserve_ConsumerPanicContained(t *testing.T) {
	sink := &collectSink{panicOn: map[int]bool{1: true}}
	e := newObserveEngine(t, newTestClock(), sink)
	startLearning(t, e)
	e.Observe(obs("boom.example"))
	e.Observe(obs("ok.example"))
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	st := e.ObservationStats()
	if st.ConsumerPanics != 1 {
		t.Fatalf("panics = %d, want 1", st.ConsumerPanics)
	}
	if st.Delivered != 1 {
		t.Fatalf("delivered = %d, want 1 (the panicked event is lost, accounted)", st.Delivered)
	}
	got := sink.observations()
	if len(got) != 1 || got[0].Host != "ok.example" {
		t.Fatalf("drain did not continue past the panic: %v", got)
	}
	if st.Accepted != st.Delivered+st.ConsumerPanics {
		t.Fatalf("loss accounting must balance: %+v", st)
	}
}

func TestObserve_StopSessionClosesGate(t *testing.T) {
	sink := &collectSink{}
	e := newObserveEngine(t, newTestClock(), sink)
	startLearning(t, e)
	e.Observe(obs("h.example"))
	if _, err := e.StopSession("test"); err != nil {
		t.Fatal(err)
	}
	e.Observe(obs("after-stop.example")) // gate closed: ignored
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if st := e.ObservationStats(); st.Accepted != 1 {
		t.Fatalf("post-stop observation was accepted: %+v", st)
	}
}

func TestObserve_ConcurrentProducersRace(t *testing.T) {
	sink := &collectSink{}
	e := newObserveEngine(t, newTestClock(), sink)
	startLearning(t, e)
	var wg sync.WaitGroup
	const producers, per = 16, 200
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				e.Observe(obs(fmt.Sprintf("h%d-%d.example", p, i)))
			}
		}(p)
	}
	wg.Wait()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	st := e.ObservationStats()
	if st.Accepted+st.Dropped != producers*per {
		t.Fatalf("accounting under race: %+v (want sum %d)", st, producers*per)
	}
	if st.Delivered != st.Accepted {
		t.Fatalf("drain lost events: %+v", st)
	}
}

func TestObserve_CloseIsIdempotentAndBoundedTime(t *testing.T) {
	sink := &collectSink{}
	e := newObserveEngine(t, newTestClock(), sink)
	startLearning(t, e)
	for i := 0; i < 100; i++ {
		e.Observe(obs(fmt.Sprintf("h%d.example", i)))
	}
	start := time.Now()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil { // second close: no-op, no deadlock
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("close not bounded: %v", elapsed)
	}
	if st := e.ObservationStats(); st.Delivered != 100 {
		t.Fatalf("delivered = %d, want 100", st.Delivered)
	}
}
