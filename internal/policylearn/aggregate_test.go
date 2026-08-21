package policylearn

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// aggEngine builds a durable engine with deterministic clock and injected
// category resolver/epoch, starts a session, and returns everything the M3
// tests need.
type aggHarness struct {
	e     *Engine
	clk   *testClock
	dir   string
	epoch string // mutable injected epoch value
	cats  map[string]string
}

func newAggHarness(t *testing.T, mutate func(*Config)) *aggHarness {
	t.Helper()
	h := &aggHarness{clk: newTestClock(), dir: t.TempDir(), epoch: "epoch-1",
		cats: map[string]string{"code.example": "Dev Tools", "pay.example": "Finance"}}
	cfg := Config{
		Now:            h.clk.now,
		StorePath:      filepath.Join(h.dir, "policy_learning.json"),
		SubjectKeyPath: filepath.Join(h.dir, "subject.key"),
		Categories: func(host string) (string, string) {
			if c, ok := h.cats[host]; ok {
				return c, "admin"
			}
			return "", "none"
		},
		CategoryEpoch: func() string { return h.epoch },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	h.e = e
	if _, err := e.StartSession("m3"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return h
}

func (h *aggHarness) observe(t *testing.T, subject, source string, groups []string, host, status string) {
	t.Helper()
	h.e.Observe(Observation{Subject: subject, AuthSource: source, Groups: groups,
		Host: host, Method: "GET", Status: status, Action: "x"})
}

// aggSnapshot drains (via Close is terminal, so use a flush handshake through
// StopSession? No — read the aggregate under the engine lock after a bounded
// wait for delivery) and returns the active session's aggregate.
func (h *aggHarness) drainWait(t *testing.T, wantDelivered int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.e.ObservationStats().Delivered >= wantDelivered {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("drain did not deliver %d observations: %+v", wantDelivered, h.e.ObservationStats())
}

func (h *aggHarness) cell(t *testing.T, scope, category string) *Cell {
	t.Helper()
	h.e.mu.Lock()
	defer h.e.mu.Unlock()
	s := h.e.aggSession
	if s == nil || s.Agg == nil {
		t.Fatal("no aggregate")
	}
	c := s.Agg.Cells[CellKey(scope, category)]
	if c == nil {
		keys := make([]string, 0, len(s.Agg.Cells))
		for k := range s.Agg.Cells {
			ks, kc := SplitCellKey(k)
			keys = append(keys, ks+"|"+kc)
		}
		t.Fatalf("cell (%s, %s) missing; have %v", scope, category, keys)
	}
	return c
}

func TestAggregate_GroupCategoryCellFacts(t *testing.T) {
	h := newAggHarness(t, nil)
	h.observe(t, "alice", "oidc:okta", []string{"eng"}, "code.example", "OK")
	h.observe(t, "bob", "oidc:okta", []string{"eng"}, "code.example", "OK")
	h.observe(t, "alice", "oidc:okta", []string{"eng"}, "code.example", "OK") // repeat subject
	h.observe(t, "carol", "oidc:okta", []string{"eng"}, "code.example", "POLICY_BLOCK")
	h.drainWait(t, 4)

	c := h.cell(t, "g:eng", "Dev Tools")
	if c.Requests != 4 || c.Allowed != 3 || c.Blocked != 1 || c.ThreatBlocked != 0 {
		t.Fatalf("counters: %+v", c)
	}
	if c.DistinctSubjects() != 2 {
		t.Fatalf("distinct subjects = %d, want 2 (alice, bob; carol was BLOCKED)", c.DistinctSubjects())
	}
	if c.FirstSeen == 0 || c.LastSeen < c.FirstSeen {
		t.Fatalf("first/last seen: %d %d", c.FirstSeen, c.LastSeen)
	}
	if c.TopHosts["code.example"] != 3 { // allowed-only evidence
		t.Fatalf("top hosts: %v", c.TopHosts)
	}
	if len(c.Days) != 1 {
		t.Fatalf("days: %v", c.Days)
	}
	if c.TierHits["admin"] != 4 { // tier breakdown covers all directions
		t.Fatalf("tier hits: %v", c.TierHits)
	}
}

func TestAggregate_BlockedNeverPositiveEvidence(t *testing.T) {
	h := newAggHarness(t, nil)
	for i := 0; i < 5; i++ {
		h.observe(t, fmt.Sprintf("user%d", i), "idp", []string{"fin"}, "pay.example", "POLICY_DEFAULT_DENY")
	}
	h.observe(t, "mallory", "idp", []string{"fin"}, "pay.example", "THREAT_BLOCKED")
	h.drainWait(t, 6)

	c := h.cell(t, "g:fin", "Finance")
	if c.Allowed != 0 || c.Blocked != 5 || c.ThreatBlocked != 1 {
		t.Fatalf("split: %+v", c)
	}
	if c.DistinctSubjects() != 0 || len(c.Days) != 0 || len(c.TopHosts) != 0 || c.FirstSeen != 0 {
		t.Fatalf("blocked traffic produced positive evidence: subjects=%d days=%v hosts=%v first=%d",
			c.DistinctSubjects(), c.Days, c.TopHosts, c.FirstSeen)
	}
}

func TestAggregate_MultiGroupContributesPerCellOnce(t *testing.T) {
	h := newAggHarness(t, nil)
	h.observe(t, "alice", "idp", []string{"eng", "sec"}, "code.example", "OK")
	h.drainWait(t, 1)

	for _, scope := range []string{"g:eng", "g:sec"} {
		c := h.cell(t, scope, "Dev Tools")
		if c.Requests != 1 || c.Allowed != 1 || c.DistinctSubjects() != 1 {
			t.Fatalf("%s: %+v", scope, c)
		}
	}
	// One network observation = one session observation (transport accounting
	// counts it once, regardless of contributing cells).
	if st := h.e.ObservationStats(); st.Accepted != 1 {
		t.Fatalf("accepted = %d, want 1", st.Accepted)
	}
}

func TestAggregate_SyntheticScopesNeverCollideWithGroups(t *testing.T) {
	h := newAggHarness(t, nil)
	// A real IdP group literally named "unauth".
	h.observe(t, "alice", "idp", []string{"unauth"}, "code.example", "OK")
	// Genuinely unauthenticated traffic.
	h.observe(t, "", "unauth", nil, "code.example", "OK")
	// Authenticated but groupless.
	h.observe(t, "bob", "local", nil, "code.example", "OK")
	h.drainWait(t, 3)

	realGrp := h.cell(t, "g:unauth", "Dev Tools")
	synth := h.cell(t, ScopeUnauth, "Dev Tools")
	groupless := h.cell(t, ScopeGroupless, "Dev Tools")
	if realGrp.Requests != 1 || synth.Requests != 1 || groupless.Requests != 1 {
		t.Fatalf("scope collision: real=%d synth=%d groupless=%d", realGrp.Requests, synth.Requests, groupless.Requests)
	}
	if synth.DistinctSubjects() != 0 {
		t.Fatal("unauthenticated traffic must not mint subject tokens")
	}
	if groupless.DistinctSubjects() != 1 {
		t.Fatal("authenticated groupless traffic keeps subject evidence")
	}
}

func TestAggregate_SameSubjectDifferentSourceDistinctTokens(t *testing.T) {
	h := newAggHarness(t, nil)
	h.observe(t, "alice", "oidc:okta", []string{"eng"}, "code.example", "OK")
	h.observe(t, "alice", "saml:corp", []string{"eng"}, "code.example", "OK")
	h.drainWait(t, 2)
	c := h.cell(t, "g:eng", "Dev Tools")
	if c.DistinctSubjects() != 2 {
		t.Fatalf("distinct = %d, want 2 — (AuthSource, Subject) is the identity tuple", c.DistinctSubjects())
	}
}

func TestAggregate_CategoryEpochChurnRecorded(t *testing.T) {
	h := newAggHarness(t, nil)
	// Baseline pinned at start.
	act, _ := h.e.ActiveSession()
	if act.Baseline.CategoryEpoch != "epoch-1" {
		t.Fatalf("baseline epoch = %q", act.Baseline.CategoryEpoch)
	}
	// Flip the epoch mid-session; churn is detected on the drain cadence.
	h.epoch = "epoch-2"
	for i := 0; i < epochCheckEvery+1; i++ {
		h.observe(t, "alice", "idp", []string{"eng"}, "code.example", "OK")
	}
	h.drainWait(t, int64(epochCheckEvery+1))
	if _, err := h.e.StopSession("m3"); err != nil { // stop also checks
		t.Fatal(err)
	}
	all := h.e.Sessions()
	churn := all[len(all)-1].CategoryChurn
	if len(churn) != 1 || churn[0].To != "epoch-2" {
		t.Fatalf("churn = %+v, want one record to epoch-2", churn)
	}
}

func TestAggregate_CellCapDegradesNeverInflates(t *testing.T) {
	h := newAggHarness(t, nil)
	// Unique group per observation → unique cell each time; exceed the cap.
	// Produce in drained chunks so the bounded transport queue (smaller than
	// the cell cap) never sheds — this test targets the AGGREGATION bound.
	over := 25
	total := maxCells + over
	const chunk = 1024
	for done := 0; done < total; {
		n := chunk
		if total-done < n {
			n = total - done
		}
		for i := done; i < done+n; i++ {
			h.observe(t, "alice", "idp", []string{fmt.Sprintf("grp-%05d", i)}, "code.example", "OK")
		}
		done += n
		h.drainWait(t, int64(done))
	}
	h.e.mu.Lock()
	agg := h.e.aggSession.Agg
	cells, dropped := len(agg.Cells), agg.CellsDropped
	h.e.mu.Unlock()
	if cells != maxCells {
		t.Fatalf("cells = %d, want cap %d", cells, maxCells)
	}
	if dropped != int64(over) {
		t.Fatalf("cells_dropped = %d, want %d (every refused contribution counted)", dropped, over)
	}
}

func TestAggregate_SubjectBoundsExactThenOverflow(t *testing.T) {
	h := newAggHarness(t, nil)
	over := 30
	for i := 0; i < maxSubjectsPerCell+over; i++ {
		h.observe(t, fmt.Sprintf("user-%05d", i), "idp", []string{"big"}, "code.example", "OK")
	}
	h.drainWait(t, int64(maxSubjectsPerCell+over))
	c := h.cell(t, "g:big", "Dev Tools")
	if c.DistinctSubjects() != maxSubjectsPerCell {
		t.Fatalf("subjects = %d, want exact cap %d", c.DistinctSubjects(), maxSubjectsPerCell)
	}
	if c.SubjectOverflow != int64(over) {
		t.Fatalf("subject_overflow = %d, want %d — the loss is counted, never estimated upward", c.SubjectOverflow, over)
	}
	// Repeats of an ALREADY-TRACKED subject never count as overflow.
	h.observe(t, "user-00001", "idp", []string{"big"}, "code.example", "OK")
	h.drainWait(t, int64(maxSubjectsPerCell+over+1))
	c = h.cell(t, "g:big", "Dev Tools")
	if c.SubjectOverflow != int64(over) {
		t.Fatalf("tracked-subject repeat inflated overflow: %d", c.SubjectOverflow)
	}
}

func TestAggregate_TopHostAndRuleBounds(t *testing.T) {
	h := newAggHarness(t, nil)
	total := maxTopHosts + 7
	for i := 0; i < total; i++ {
		o := Observation{Subject: "alice", AuthSource: "idp", Groups: []string{"eng"},
			Host: fmt.Sprintf("h%02d.code.example", i), Method: "GET", Status: "OK",
			RuleID: fmt.Sprintf("rule-%02d", i%12)}
		h.e.Observe(o)
	}
	h.drainWait(t, int64(total))
	c := h.cell(t, "g:eng", "")
	if len(c.TopHosts) != maxTopHosts || c.OtherHosts != 7 {
		t.Fatalf("top hosts %d other %d, want %d/%d", len(c.TopHosts), c.OtherHosts, maxTopHosts, 7)
	}
	if len(c.RuleHits) != maxRuleHits || c.OtherRules != int64(total-getRuleHitSum(c)) {
		t.Fatalf("rule bounds: %d tracked (%v), other %d", len(c.RuleHits), c.RuleHits, c.OtherRules)
	}
}

func getRuleHitSum(c *Cell) int {
	n := 0
	for _, v := range c.RuleHits {
		n += int(v)
	}
	return n
}

func TestAggregate_DayBucketsFollowInjectedClock(t *testing.T) {
	h := newAggHarness(t, nil)
	h.observe(t, "alice", "idp", []string{"eng"}, "code.example", "OK")
	h.clk.advance(26 * time.Hour) // next UTC day
	h.observe(t, "alice", "idp", []string{"eng"}, "code.example", "OK")
	h.drainWait(t, 2)
	c := h.cell(t, "g:eng", "Dev Tools")
	if len(c.Days) != 2 {
		t.Fatalf("days = %v, want 2 distinct UTC dates", c.Days)
	}
}

func TestAggregate_PersistedAcrossRestartNoRawSubjects(t *testing.T) {
	h := newAggHarness(t, nil)
	h.observe(t, "alice-rawname@corp.example", "oidc:okta", []string{"eng"}, "code.example", "OK")
	h.drainWait(t, 1)
	if err := h.e.Close(); err != nil { // flush
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(h.dir, "policy_learning.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "alice-rawname") {
		t.Fatal("raw subject persisted — pseudonymization contract violated")
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["schema_version"] != float64(SchemaVersion) {
		t.Fatalf("schema_version = %v, want %d", doc["schema_version"], SchemaVersion)
	}

	// Restart: aggregate + tokens recover; the SAME subject maps to the SAME
	// token (durable key), so distinct-subject identity is stable.
	cfg := Config{Now: h.clk.now,
		StorePath:      filepath.Join(h.dir, "policy_learning.json"),
		SubjectKeyPath: filepath.Join(h.dir, "subject.key")}
	e2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e2.Close() })
	e2.Observe(Observation{Subject: "alice-rawname@corp.example", AuthSource: "oidc:okta",
		Groups: []string{"eng"}, Host: "code.example", Method: "GET", Status: "OK"})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && e2.ObservationStats().Delivered < 1 {
		time.Sleep(time.Millisecond)
	}
	e2.mu.Lock()
	c := e2.aggSession.Agg.Cells[CellKey("g:eng", "")] // no resolver on e2: category ""
	var distinctAcross int
	if c != nil {
		distinctAcross = len(c.Subjects)
	}
	// The original cell (category "Dev Tools") still holds one token; the same
	// subject re-observed lands in a different category cell but with the SAME
	// token value — assert token equality across restart directly.
	tok1 := ""
	for k := range e2.aggSession.Agg.Cells[CellKey("g:eng", "Dev Tools")].Subjects {
		tok1 = k
	}
	tok2 := ""
	if c != nil {
		for k := range c.Subjects {
			tok2 = k
		}
	}
	e2.mu.Unlock()
	if distinctAcross != 1 || tok1 == "" || tok1 != tok2 {
		t.Fatalf("subject token not stable across restart: %q vs %q", tok1, tok2)
	}
}

func TestAggregate_SubjectKeyLossRecordedHonestly(t *testing.T) {
	h := newAggHarness(t, nil)
	h.observe(t, "alice", "idp", []string{"eng"}, "code.example", "OK")
	h.drainWait(t, 1)
	if err := h.e.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate key loss.
	if err := os.Remove(filepath.Join(h.dir, "subject.key")); err != nil {
		t.Fatal(err)
	}
	e2, err := New(Config{Now: h.clk.now,
		StorePath:      filepath.Join(h.dir, "policy_learning.json"),
		SubjectKeyPath: filepath.Join(h.dir, "subject.key")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e2.Close() })
	act, ok := e2.ActiveSession()
	if !ok {
		t.Fatal("session not recovered")
	}
	found := false
	for _, g := range act.Gaps {
		if g.Reason == "subject_key_changed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("key loss not recorded as a gap: %+v", act.Gaps)
	}
	e2.mu.Lock()
	flagged := e2.aggSession.Agg.SubjectKeyChanged
	e2.mu.Unlock()
	if !flagged {
		t.Fatal("aggregate not flagged subject_key_changed")
	}
}

func TestAggregate_PerSessionTransportDeltas(t *testing.T) {
	h := newAggHarness(t, nil)
	h.observe(t, "alice", "idp", []string{"eng"}, "code.example", "OK")
	h.observe(t, "", "unauth", nil, "", "OK") // rejected: empty host
	h.drainWait(t, 1)
	if _, err := h.e.StopSession("m3"); err != nil {
		t.Fatal(err)
	}
	all := h.e.Sessions()
	w := all[len(all)-1].Transport
	if w.Accepted != 1 || w.Rejected != 1 || w.Dropped != 0 {
		t.Fatalf("session window: %+v", w)
	}

	// A SECOND session sees only its own deltas — never lifetime totals.
	if _, err := h.e.StartSession("m3b"); err != nil {
		t.Fatal(err)
	}
	h.observe(t, "bob", "idp", []string{"eng"}, "code.example", "OK")
	h.drainWait(t, 2)
	if _, err := h.e.StopSession("m3b"); err != nil {
		t.Fatal(err)
	}
	all = h.e.Sessions()
	w2 := all[len(all)-1].Transport
	if w2.Accepted != 1 || w2.Rejected != 0 {
		t.Fatalf("second session window carries prior totals: %+v", w2)
	}
	if !all[0].Transport.Degraded() {
		t.Fatal("first window (with a rejection) must report degraded")
	}
}

func TestPseudonym_FramingCannotCollide(t *testing.T) {
	sk := newSubjectKey(make([]byte, subjectKeyLen)) // fixed key: determinism
	// Ambiguous concatenations must yield different tokens.
	pairs := [][2][2]string{
		{{"ab", "c"}, {"a", "bc"}},
		{{"", "abc"}, {"abc", ""}}, // second has empty subject → empty token; still not equal
		{{"oidc:x", "y"}, {"oidc", ":xy"}},
	}
	for _, p := range pairs {
		t1 := sk.token(p[0][0], p[0][1])
		t2 := sk.token(p[1][0], p[1][1])
		if t1 != "" && t1 == t2 {
			t.Fatalf("framing collision: %v vs %v", p[0], p[1])
		}
	}
	if sk.token("idp", "alice") == sk.token("idp2", "alice") {
		t.Fatal("AuthSource must partition token space")
	}
	if sk.token("idp", "") != "" {
		t.Fatal("empty subject must not tokenize")
	}
}

// TestAggregate_RestartResumeBeforeFirstCellDoesNotPanic pins the
// qualification-drill regression: a Learning session persisted BEFORE any
// cell exists round-trips its aggregate as {} (every field omitempty), which
// decodes to a non-nil Aggregate with a NIL Cells map. The consume path must
// treat that shape like the other decoded-empty maps (lazy init), not panic —
// a mid-Learning crash/restart would otherwise lose EVERY post-restart
// observation of the recovered session to per-event panic containment
// (counted, degraded, zero cells, zero recommendations).
func TestAggregate_RestartResumeBeforeFirstCellDoesNotPanic(t *testing.T) {
	h := newAggHarness(t, nil)
	// Persisted state now holds the Learning session with an EMPTY aggregate
	// (StartSession persisted it; no observation has been drained).
	if err := h.e.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Now: h.clk.now,
		StorePath:      filepath.Join(h.dir, "policy_learning.json"),
		SubjectKeyPath: filepath.Join(h.dir, "subject.key")}
	e2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e2.Close() })
	e2.Observe(Observation{Subject: "alice", AuthSource: "oidc:okta",
		Groups: []string{"eng"}, Host: "code.example", Method: "GET", Status: "OK"})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && e2.ObservationStats().Delivered < 1 {
		time.Sleep(time.Millisecond)
	}
	st := e2.ObservationStats()
	if st.ConsumerPanics != 0 {
		t.Fatalf("consumer panicked on resumed empty aggregate: %+v", st)
	}
	e2.mu.Lock()
	defer e2.mu.Unlock()
	if e2.aggSession == nil || e2.aggSession.Agg == nil ||
		e2.aggSession.Agg.Cells[CellKey("g:eng", "")] == nil {
		t.Fatalf("observation after resume did not aggregate; agg=%+v", e2.aggSession)
	}
}
