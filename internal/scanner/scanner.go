// Package scanner is the DPI content scanner: a set of pre-compiled regex
// signatures applied to HTTP response bodies flowing through SSL-Inspect
// tunnels, with a per-host bypass list and atomic persistence. It is extracted
// from the flat package main per ADR-0002; its only Culvert dependencies are
// the obs / fileutil / hostutil seams.
//
// Patterns are standard Go regex strings. Matching is byte-level. Each match is
// bounded by a timeout to prevent ReDoS from pathological patterns or input.
package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/hostutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// ContentScanner holds pre-compiled DPI regex patterns and applies them to
// HTTP response bodies.
type ContentScanner struct {
	mu sync.RWMutex
	// set is the immutable, atomically-published pattern set. Readers (Scan,
	// Enabled, List, Save) load the pointer and never take mu for it; the config
	// mutators (Set/Add/Remove) still serialize their read-modify-write under mu
	// and publish a REPLACEMENT set rather than mutating the one in place.
	//
	// Immutability is load-bearing, not stylistic: Scan's timeout-bounded worker
	// can outlive the Scan call (a match that blows the ReDoS budget is abandoned,
	// never killed — re.Match is not interruptible). Such a worker keeps reading
	// its own snapshot indefinitely, so the slices it walks must never be written
	// again. The pre-snapshot code mutated the shared backing array in place
	// (Remove's append-shift), which an abandoned worker would have raced.
	set      atomic.Pointer[patternSet]
	path     string // optional JSON file path for persistence
	maxBytes int64  // max bytes buffered per response (default 1 MiB)

	// Tier 3.4: per-host DPI bypass list. Hosts in this map skip DPI regex
	// scanning entirely even when the scanner has patterns loaded. Used for
	// internal content mirrors, CI artifact servers, etc. where DPI false
	// positives would otherwise block legitimate traffic.
	bypassHosts map[string]bool
}

// patternSet is an immutable snapshot of the compiled pattern list: raw[i] is
// the source string for compiled[i]. Never mutated after publication — see the
// ContentScanner.set field comment for why that is a correctness requirement.
type patternSet struct {
	raw      []string
	compiled []*regexp.Regexp

	// matcher overrides the match step. nil in production (⇒ re.Match); set only
	// by tests, so the timeout branch can be driven by a genuinely-blocking match.
	// re.Match always terminates, so exercising the timeout with a real regex means
	// racing it against a short timer — and on a loaded machine the parent can be
	// descheduled past the match, leaving BOTH select cases ready and the outcome
	// decided by Go's random pick. That is a ~50% flake, and it is the same one
	// runWithTimeout's test was restructured to avoid (see its comment below).
	matcher func(*regexp.Regexp, []byte) bool
}

// matchOne runs a single pattern against data, honouring the test seam.
func (ps *patternSet) matchOne(re *regexp.Regexp, data []byte) bool {
	if ps.matcher != nil {
		return ps.matcher(re, data)
	}
	return re.Match(data)
}

// New returns a ContentScanner with the given per-response buffer cap and an
// empty bypass-host set.
func New(maxBytes int64) *ContentScanner {
	s := &ContentScanner{maxBytes: maxBytes, bypassHosts: map[string]bool{}}
	s.set.Store(&patternSet{})
	return s
}

// patterns returns the live pattern set, never nil (New seeds it, but a
// zero-value ContentScanner is constructed directly by some tests).
func (s *ContentScanner) patterns() *patternSet {
	if ps := s.set.Load(); ps != nil {
		return ps
	}
	return &patternSet{}
}

// MaxBytes returns the per-response buffering cap.
func (s *ContentScanner) MaxBytes() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxBytes
}

// Path returns the configured persistence file path ("" when unset).
func (s *ContentScanner) Path() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.path
}

// SetPath sets the persistence file path without loading from it. Used by the
// test suite (and any caller wanting Save to target a specific file) in place
// of reaching into the unexported field after the ADR-0002 extraction.
func (s *ContentScanner) SetPath(path string) {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
}

// dpiContentFile is the on-disk JSON envelope supporting both legacy
// (array-of-patterns) and new ({patterns, bypass_hosts}) formats.
type dpiContentFile struct {
	Patterns    []string `json:"patterns"`
	BypassHosts []string `json:"bypass_hosts,omitempty"`
}

// Enabled returns true when at least one pattern is loaded.
func (s *ContentScanner) Enabled() bool {
	return len(s.patterns().compiled) > 0
}

// Set atomically replaces the full pattern list.  Returns an error if any
// pattern fails to compile; on error the existing patterns are unchanged.
func (s *ContentScanner) Set(patterns []string) error {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("invalid DPI pattern %q: %w", p, err)
		}
		compiled = append(compiled, re)
	}
	s.mu.Lock()
	s.set.Store(&patternSet{raw: append([]string(nil), patterns...), compiled: compiled})
	s.mu.Unlock()
	return nil
}

// Load reads a JSON array of regex strings (legacy format) or a dpiContentFile
// envelope ({patterns, bypass_hosts}) from path. If the file does not exist,
// Load succeeds (empty scanner — no patterns active).
func (s *ContentScanner) Load(path string) error {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()

	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("content-scan file read error: %w", err)
	}
	// Detect envelope vs legacy array.
	trimmed := strings.TrimLeft(string(data), " \t\r\n")
	if strings.HasPrefix(trimmed, "{") {
		var env dpiContentFile
		if err := json.Unmarshal(data, &env); err != nil {
			return fmt.Errorf("content-scan JSON parse error: %w", err)
		}
		if err := s.Set(env.Patterns); err != nil {
			return err
		}
		s.SetBypassHosts(env.BypassHosts)
		return nil
	}
	var patterns []string
	if err := json.Unmarshal(data, &patterns); err != nil {
		return fmt.Errorf("content-scan JSON parse error: %w", err)
	}
	return s.Set(patterns)
}

// Save persists the current pattern list and bypass host list to the
// configured file path. Uses an atomic write (tmp + rename) so a crash never
// leaves a partial file. No-op if no path is configured. Writes the envelope
// format when bypass hosts are present, otherwise the legacy array format so
// existing tooling keeps working. Tier 3.4.
//
// Returns the write error (2E-A durability truth): the admin handlers must
// not report a durable configuration change that never reached disk. Callers
// on bulk/best-effort paths may keep ignoring it (statement call).
func (s *ContentScanner) Save() error {
	s.mu.RLock()
	// Loaded inside the RLock purely to keep the persisted (patterns, bypassHosts)
	// pair as close to a single instant as it was before the snapshot change.
	// patterns() takes no lock of its own, so this cannot deadlock.
	raw := s.patterns().raw
	path := s.path
	bypass := make([]string, 0, len(s.bypassHosts))
	for h := range s.bypassHosts {
		bypass = append(bypass, h)
	}
	var data []byte
	if len(bypass) > 0 {
		env := dpiContentFile{
			Patterns:    append([]string(nil), raw...),
			BypassHosts: bypass,
		}
		data, _ = json.MarshalIndent(env, "", "  ")
	} else {
		data, _ = json.MarshalIndent(raw, "", "  ")
	}
	s.mu.RUnlock()

	if path == "" || data == nil {
		return nil
	}
	// Bucket-4 durability hardening: AtomicWrite gives unique tmp + chmod +
	// fsync(file) + rename + best-effort fsync(parent dir).
	return fileutil.AtomicWrite(path, data, 0o600)
}

// SetBypassHosts atomically replaces the DPI bypass host list. Hosts are
// lower-cased and trimmed. Tier 3.4.
func (s *ContentScanner) SetBypassHosts(hosts []string) {
	m := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		h = hostutil.StripHostPort(strings.TrimSpace(strings.ToLower(h)))
		if h != "" {
			m[h] = true
		}
	}
	s.mu.Lock()
	s.bypassHosts = m
	s.mu.Unlock()
}

// BypassHosts returns a sorted copy of the current DPI bypass host list.
// Tier 3.4.
func (s *ContentScanner) BypassHosts() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.bypassHosts))
	for h := range s.bypassHosts {
		out = append(out, h)
	}
	// tiny insertion sort — list is short
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// IsBypassHost reports whether the given host is on the DPI bypass list.
// Hot path: called once per inspected tunnel response. Tier 3.4.
func (s *ContentScanner) IsBypassHost(host string) bool {
	if s == nil || host == "" {
		return false
	}
	host = hostutil.StripHostPort(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bypassHosts[strings.ToLower(host)]
}

// Add compiles and appends a single pattern. Copy-on-write: the existing set is
// never appended to in place, so a Scan worker already walking it is unaffected.
func (s *ContentScanner) Add(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid DPI pattern %q: %w", pattern, err)
	}
	s.mu.Lock()
	cur := s.patterns()
	s.set.Store(&patternSet{
		raw:      append(append([]string(nil), cur.raw...), pattern),
		compiled: append(append([]*regexp.Regexp(nil), cur.compiled...), re),
	})
	s.mu.Unlock()
	return nil
}

// Remove deletes the first occurrence of pattern from the list.
// Returns true if a pattern was removed. Copy-on-write, for the same reason as
// Add: the pre-snapshot version shifted the shared backing array in place, which
// an abandoned (timed-out) Scan worker still reading that array would have raced.
func (s *ContentScanner) Remove(pattern string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.patterns()
	for i, p := range cur.raw {
		if p != pattern {
			continue
		}
		next := &patternSet{
			raw:      make([]string, 0, len(cur.raw)-1),
			compiled: make([]*regexp.Regexp, 0, len(cur.compiled)-1),
		}
		next.raw = append(append(next.raw, cur.raw[:i]...), cur.raw[i+1:]...)
		next.compiled = append(append(next.compiled, cur.compiled[:i]...), cur.compiled[i+1:]...)
		s.set.Store(next)
		return true
	}
	return false
}

// List returns a snapshot of all raw pattern strings.
func (s *ContentScanner) List() []string {
	raw := s.patterns().raw
	out := make([]string, len(raw))
	copy(out, raw)
	return out
}

// dpiRegexTimeout limits how long a single DPI regex match may run.
// Prevents ReDoS from pathological patterns or crafted input.
const dpiRegexTimeout = 5 * time.Second

// Scan checks data against all compiled patterns.
// Returns the first matching raw pattern string and true, or ("", false).
// Each regex match is bounded by dpiRegexTimeout to prevent ReDoS hangs.
func (s *ContentScanner) Scan(data []byte) (string, bool) {
	ps := s.patterns()
	if len(ps.compiled) == 0 {
		return "", false
	}
	return ps.scan(data, dpiRegexTimeout)
}

// scan walks the whole pattern list inside ONE timeout-bounded worker goroutine
// instead of spawning one per pattern.
//
// Why: re.Match is not interruptible, so a hard per-match deadline needs a
// goroutine to abandon. Paying for that goroutine + channel + timer PER PATTERN
// made the fixed overhead scale with the pattern count — 60 allocs/4.6 KB for 10
// patterns, 120 allocs/9.1 KB for 20 — on the SSL-inspect response path, where it
// is charged to every inspected body. Most operator patterns carry a literal
// prefix and match in a few hundred nanoseconds, so for them the timeout harness
// cost more than the work it guarded (measured 26–35% of total Scan time on small
// bodies). Hoisting it makes the overhead CONSTANT in pattern count: 7 allocs /
// 480 B at 1, 10, 20 and 50 patterns, pinned by TestBenchGate_DPIScanAllocs*.
//
// The PER-PATTERN budget is preserved exactly — this is a cost change, not a
// policy change. The worker stamps a start time before each match; when the timer
// fires, the parent charges the elapsed time against the pattern that is actually
// running and, if that pattern still has budget left, extends the timer by the
// remainder rather than declaring a timeout. So a scan of P patterns still
// tolerates up to P*dpiRegexTimeout in total, exactly as it did when each pattern
// carried its own timer. (A whole-scan budget would have been simpler and equally
// fast, but it would fail closed — block legitimate traffic — on a large body with
// many patterns that are each individually well inside the budget.)
//
// On timeout the verdict is unchanged: fail closed (S17 / Zero Trust), reporting
// the pattern that overran. The abandoned worker cannot be killed, but it checks
// the abandoned flag between patterns so it stops burning CPU on the REMAINING
// patterns — strictly less waste than the per-pattern version, which left the
// overrunning match running and then continued the loop on the calling goroutine.
func (ps *patternSet) scan(data []byte, budget time.Duration) (string, bool) {
	// One allocation for all shared state: the three fields are captured by the
	// worker closure, so as separate locals they would escape as three separate
	// heap objects and give back part of the win at low pattern counts.
	st := &scanState{done: make(chan scanVerdict, 1)}
	st.startedAt.Store(time.Now().UnixNano())
	go ps.match(data, st, budget)

	timer := time.NewTimer(budget)
	defer timer.Stop()
	for {
		select {
		case v := <-st.done:
			if v.timedOut {
				// The worker caught its own overrun (see match): a match that blew the
				// budget but finished before this goroutine got scheduled. Same verdict
				// as the timer branch below.
				obs.Warnf("DPI: regex timeout after %s on pattern %q", budget, obs.Sanitize(v.pattern))
			}
			return v.pattern, v.hit
		case <-timer.C:
			// The timer is armed against the whole scan, but the budget belongs to
			// the individual match. Charge only the time the CURRENT pattern has
			// been running; if it still has budget, re-arm for the remainder.
			if remaining, exhausted := budgetRemaining(budget, st.startedAt.Load(), time.Now().UnixNano()); !exhausted {
				timer.Reset(remaining)
				continue
			}
			st.abandoned.Store(true)
			pattern := ""
			if i := int(st.current.Load()); i >= 0 && i < len(ps.raw) {
				pattern = ps.raw[i]
			}
			obs.Warnf("DPI: regex timeout after %s on pattern %q", budget, obs.Sanitize(pattern))
			return pattern, true // S17: fail-closed — a timeout is a suspicious match
		}
	}
}

// budgetRemaining converts the whole-scan timer firing into a per-pattern
// verdict. startedAt is when the currently-running match began (Unix nanos) and
// now is the current time; the returned duration is how much of budget that match
// still has, and exhausted reports that it has overrun and must be failed closed.
//
// This is what keeps the single hoisted timer equivalent to one timer per
// pattern: the timer fires on total scan time, but the budget is only ever
// charged against one match at a time.
func budgetRemaining(budget time.Duration, startedAt, now int64) (remaining time.Duration, exhausted bool) {
	elapsed := time.Duration(now - startedAt)
	if elapsed >= budget {
		return 0, true
	}
	if elapsed < 0 {
		return budget, false // clock stepped backwards — re-arm for a full budget
	}
	return budget - elapsed, false
}

// match is the worker half of scan: walk every pattern, publishing progress so
// the parent can attribute the budget to the pattern actually running. It may
// outlive its scan (re.Match cannot be interrupted), which is why it reads only
// the immutable patternSet and its own scanState.
//
// The worker also enforces the budget on matches it has ALREADY finished, which
// the parent structurally cannot. The parent decides "did this overrun" by
// inspecting the currently-running match; if it is descheduled (GC pause, CPU
// contention) past the moment the overrunning match completes and the worker
// advances, startedAt now belongs to the NEXT pattern, budgetRemaining re-arms,
// and the overrun is forgotten — suspicious input would be admitted instead of
// failing closed. Timing each match here removes that window: whether a match
// stayed inside its budget is decided by the goroutine that ran it, and so does
// not depend on when the parent happens to be scheduled. The two halves are
// complementary — the parent catches a match still RUNNING past budget (the
// genuine-hang case, where the worker never gets to report anything), the worker
// catches one that FINISHED past budget.
func (ps *patternSet) match(data []byte, st *scanState, budget time.Duration) {
	// One clock read per pattern, not two: a match ends where the next one begins,
	// so the reading that closes pattern i also opens pattern i+1. The sliver of
	// loop overhead this folds into the next pattern's elapsed time is charged
	// AGAINST that pattern, i.e. conservatively (toward failing closed), never in
	// favour of admitting an overrun.
	started := time.Now()
	for i, re := range ps.compiled {
		if st.abandoned.Load() {
			return // parent already failed closed; don't scan the rest
		}
		st.current.Store(int64(i))
		st.startedAt.Store(started.UnixNano())
		if ps.matchOne(re, data) {
			st.done <- scanVerdict{pattern: ps.raw[i], hit: true}
			return
		}
		finished := time.Now()
		if finished.Sub(started) >= budget {
			st.done <- scanVerdict{pattern: ps.raw[i], hit: true, timedOut: true}
			return
		}
		started = finished
	}
	st.done <- scanVerdict{}
}

// scanState is the shared state between a scan and its worker goroutine.
type scanState struct {
	done chan scanVerdict
	// startedAt is wall-clock UnixNano, not a monotonic reading: it is written by
	// the worker and read by the parent, and Go's monotonic clock rides on
	// time.Time values rather than on a plain int64 that can be stored atomically.
	// A backwards clock step therefore only costs one extra budget extension —
	// budgetRemaining treats negative elapsed time as "re-arm for a full budget",
	// which errs toward NOT failing closed on legitimate traffic.
	startedAt atomic.Int64
	current   atomic.Int64 // index of the pattern currently being matched
	abandoned atomic.Bool  // set when the parent has given up (fail-closed)
}

// scanVerdict is the worker → parent result for patternSet.scan. timedOut marks
// a hit the worker produced because the match overran its budget rather than
// because the pattern actually matched; the verdict is identical (fail closed),
// it only changes the log line.
type scanVerdict struct {
	pattern  string
	hit      bool
	timedOut bool
}

// MatchRegexWithTimeout runs re.Match(data) with a deadline.
// Returns false if the match does not complete in time (ReDoS prevention);
// on timeout it fails closed (treats a timeout as a suspicious match).
func MatchRegexWithTimeout(re *regexp.Regexp, data []byte, timeout time.Duration) bool {
	matched, timedOut := runWithTimeout(func() bool { return re.Match(data) }, timeout)
	if timedOut {
		obs.Warnf("DPI: regex timeout after %s on pattern %q", timeout, obs.Sanitize(re.String()))
		return true // S17: fail-closed — treat timeout as suspicious match (Zero Trust)
	}
	return matched
}

// runWithTimeout runs fn in a goroutine and returns (fn's result, false), or
// (false, true) if fn does not finish within timeout. The result channel is
// buffered so the goroutine never leaks on timeout.
//
// Extracted from MatchRegexWithTimeout so the timeout branch can be tested
// DETERMINISTICALLY with a genuinely-blocking fn. The previous test raced Go's
// (fast, RE2, non-backtracking) re.Match goroutine against a near-zero timer:
// under -race both select cases could become ready at once, and Go picks a ready
// case at random — a ~50% flake (observed in CI).
func runWithTimeout(fn func() bool, timeout time.Duration) (result, timedOut bool) {
	ch := make(chan bool, 1)
	go func() { ch <- fn() }()
	select {
	case r := <-ch:
		return r, false
	case <-time.After(timeout):
		return false, true
	}
}
