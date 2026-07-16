package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/secscan"
)

// ─── Per-rule hit counter ────────────────────────────────────────────────────
// Cardinality is capped at maxRuleMetrics to prevent unbounded label growth.

const maxRuleMetrics = 200

type ruleMetrics struct {
	mu            sync.RWMutex
	hits          map[string]*int64               // rule name → hit count
	last          map[string]*int64               // rule name → unix-seconds of last hit (policy-metadata P1)
	byID          map[string]persistedRuleCounter // stable rule ID → persisted accounting
	loadedByName  map[string]persistedRuleCounter // immutable legacy persistence baseline
	appliedByName map[string]int64                // greatest persisted hit baseline merged into telemetry
	order         []string                        // insertion order for cap enforcement
}

var ruleMet = &ruleMetrics{hits: make(map[string]*int64), last: make(map[string]*int64), byID: make(map[string]persistedRuleCounter), loadedByName: make(map[string]persistedRuleCounter), appliedByName: make(map[string]int64)}

// RecordHit increments the telemetry counter for the given policy rule name and
// stamps its last-hit time. Live policy accounting is maintained by Evaluate;
// saveHitCounters overlays that rename-safe accounting before persistence.
func (rm *ruleMetrics) RecordHit(ruleName string) {
	if ruleName == "" {
		return
	}
	now := time.Now().Unix()
	rm.mu.RLock()
	ctr, ok := rm.hits[ruleName]
	lastPtr := rm.last[ruleName]
	rm.mu.RUnlock()
	if ok {
		atomic.AddInt64(ctr, 1)
		if lastPtr != nil {
			atomicStoreMax(lastPtr, now)
		}
		return
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.last == nil { // defensive: literals built with only `hits` set
		rm.last = make(map[string]*int64)
	}
	// Double-check after acquiring write lock.
	if ctr, ok = rm.hits[ruleName]; ok {
		atomic.AddInt64(ctr, 1)
		if lp := rm.last[ruleName]; lp != nil {
			atomicStoreMax(lp, now)
		}
		return
	}
	if len(rm.hits) >= maxRuleMetrics {
		return // cardinality cap reached; ignore new rules
	}
	v := int64(1)
	rm.hits[ruleName] = &v
	lv := now
	rm.last[ruleName] = &lv
	rm.order = append(rm.order, ruleName)
}

// persistedRuleCounter is the on-disk shape of one rule's persisted counters
// (policy-metadata P1: lastHit joined the long-standing hit count). LastHit is
// omitempty so a never-matched rule and the legacy loader stay compatible.
type persistedRuleCounter struct {
	Name    string `json:"name,omitempty"`
	ID      string `json:"id,omitempty"`
	Hits    int64  `json:"hits"`
	LastHit int64  `json:"lastHit,omitempty"` // unix seconds; 0 = never
}

type persistedRuleCounterWire struct {
	Name    string `json:"name,omitempty"`
	ID      string `json:"id,omitempty"`
	Hits    *int64 `json:"hits"`
	LastHit int64  `json:"lastHit,omitempty"`
}

const hitCounterFormatVersion = 2

type persistedRuleCounterFile struct {
	Version int                    `json:"version"`
	Rules   []persistedRuleCounter `json:"rules"`
}

type hitCounterLoadStatus uint8

const (
	hitCounterLoadMissing hitCounterLoadStatus = iota
	hitCounterLoadOK
	hitCounterLoadInvalid
)

// saveHitCounters marshals the current hit counters + lastHit to JSON and
// writes them to path using a temp-file-then-rename pattern for crash safety.
func saveHitCounters(path string) {
	// Current policy definitions are authoritative for persisted accounting.
	// Version 2 is an array so duplicate rule names cannot collapse stable IDs.
	records := make([]persistedRuleCounter, 0, maxRuleMetrics)
	rules := policyStore.List()
	for i := range rules {
		rule := &rules[i]
		if rule.Name == "" || (rule.HitCount == 0 && rule.lastHitUnix == 0) || len(records) >= maxRuleMetrics {
			continue
		}
		records = append(records, persistedRuleCounter{
			Name: rule.Name, ID: rule.ID, Hits: rule.HitCount, LastHit: rule.lastHitUnix,
		})
	}

	// An empty policy store remains compatible with callers/tests that use
	// ruleMet before policy initialization. Sort names for deterministic output.
	if len(rules) == 0 {
		ruleMet.mu.RLock()
		names := make([]string, 0, len(ruleMet.hits))
		for name := range ruleMet.hits {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if len(records) >= maxRuleMetrics {
				break
			}
			rec := persistedRuleCounter{Name: name, Hits: atomic.LoadInt64(ruleMet.hits[name])}
			if lp := ruleMet.last[name]; lp != nil {
				rec.LastHit = atomic.LoadInt64(lp)
			}
			records = append(records, rec)
		}
		ruleMet.mu.RUnlock()
	}

	b, err := json.MarshalIndent(persistedRuleCounterFile{Version: hitCounterFormatVersion, Rules: records}, "", "  ")
	if err != nil {
		logger.Printf("HitCounters: marshal error: %v", err)
		return
	}
	if err := fileutil.AtomicWrite(path, b, 0o600); err != nil {
		logger.Printf("HitCounters: write error: %v", err)
	}
}

// loadHitCounters reads persisted counters and classifies the result so startup
// never overwrites unreadable or malformed evidence. It accepts version 2 plus
// both historical name-keyed formats.
func loadHitCounters(path string) hitCounterLoadStatus {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return hitCounterLoadMissing
		}
		logger.Printf("HitCounters: read error from %s: %v", path, err)
		return hitCounterLoadInvalid
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		logger.Printf("HitCounters: ambiguous JSON from %s: %v — preserving file", path, err)
		return hitCounterLoadInvalid
	}
	current, versioned, err := decodeVersionedRuleCounterFile(data)
	if versioned {
		if err != nil {
			logger.Printf("HitCounters: invalid versioned data from %s: %v — preserving file", path, err)
			return hitCounterLoadInvalid
		}
		if err := validatePersistedCounterRecords(current.Rules, true); err != nil {
			logger.Printf("HitCounters: invalid version %d data from %s: %v — preserving file", current.Version, path, err)
			return hitCounterLoadInvalid
		}
		ruleMet.restoreCounterRecords(current.Rules)
		logger.Printf("HitCounters: restored %d counter(s) from %s", len(current.Rules), path)
		return hitCounterLoadOK
	}
	records, structured, err := decodeHistoricalRuleCounters(data)
	if structured {
		if err != nil {
			logger.Printf("HitCounters: invalid historical data from %s: %v — preserving file", path, err)
			return hitCounterLoadInvalid
		}
		if err := validatePersistedCounterRecords(records, false); err != nil {
			logger.Printf("HitCounters: invalid historical data from %s: %v — preserving file", path, err)
			return hitCounterLoadInvalid
		}
		ruleMet.restoreCounterRecords(records)
		logger.Printf("HitCounters: restored %d counter(s) from %s", len(records), path)
		return hitCounterLoadOK
	}
	var counts map[string]int64
	if json.Unmarshal(data, &counts) != nil || counts == nil {
		logger.Printf("HitCounters: unmarshal error from %s — preserving file", path)
		return hitCounterLoadInvalid
	}
	legacy := make(map[string]persistedRuleCounter, len(counts))
	for name, c := range counts {
		legacy[name] = persistedRuleCounter{Hits: c}
	}
	records = persistedCounterRecordsFromMap(legacy)
	if err := validatePersistedCounterRecords(records, false); err != nil {
		logger.Printf("HitCounters: invalid legacy data from %s: %v — preserving file", path, err)
		return hitCounterLoadInvalid
	}
	ruleMet.restoreCounterRecords(records)
	logger.Printf("HitCounters: restored %d counter(s) from %s (legacy format)", len(counts), path)
	return hitCounterLoadOK
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("non-string object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	_, err = decoder.Token()
	return err
}

func decodeVersionedRuleCounterFile(data []byte) (persistedRuleCounterFile, bool, error) {
	var topLevel map[string]json.RawMessage
	if json.Unmarshal(data, &topLevel) != nil {
		return persistedRuleCounterFile{}, false, nil
	}
	if _, present := topLevel["version"]; !present {
		return persistedRuleCounterFile{}, false, nil
	}
	file, err := decodePersistedRuleCounterFile(data)
	return file, true, err
}

func decodePersistedRuleCounterFile(data []byte) (persistedRuleCounterFile, error) {
	var wire struct {
		Version int                         `json:"version"`
		Rules   []*persistedRuleCounterWire `json:"rules"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return persistedRuleCounterFile{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return persistedRuleCounterFile{}, errors.New("multiple JSON values")
		}
		return persistedRuleCounterFile{}, err
	}
	file := persistedRuleCounterFile{Version: wire.Version}
	if wire.Version != hitCounterFormatVersion {
		return file, fmt.Errorf("unsupported version %d", wire.Version)
	}
	if wire.Rules == nil {
		return file, errors.New("missing or null rules array")
	}
	file.Rules = make([]persistedRuleCounter, len(wire.Rules))
	for i, rec := range wire.Rules {
		if rec == nil {
			return file, fmt.Errorf("record %d is null", i)
		}
		if rec.Hits == nil {
			return file, fmt.Errorf("record %d is missing hits", i)
		}
		file.Rules[i] = persistedRuleCounter{Name: rec.Name, ID: rec.ID, Hits: *rec.Hits, LastHit: rec.LastHit}
	}
	return file, nil
}

func decodeHistoricalRuleCounters(data []byte) ([]persistedRuleCounter, bool, error) {
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, false, nil
	}
	if decoded == nil {
		return nil, true, errors.New("null historical counter map")
	}
	recs := make(map[string]persistedRuleCounter, len(decoded))
	for name, raw := range decoded {
		trimmed := bytes.TrimSpace(raw)
		if bytes.Equal(trimmed, []byte("null")) {
			return nil, true, fmt.Errorf("null historical record %q", name)
		}
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return nil, false, nil
		}
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		decoder.DisallowUnknownFields()
		var wire persistedRuleCounterWire
		if err := decoder.Decode(&wire); err != nil {
			return nil, true, fmt.Errorf("historical record %q: %w", name, err)
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return nil, true, fmt.Errorf("historical record %q has trailing data", name)
		}
		if wire.Hits == nil {
			return nil, true, fmt.Errorf("historical record %q is missing hits", name)
		}
		recs[name] = persistedRuleCounter{Name: wire.Name, ID: wire.ID, Hits: *wire.Hits, LastHit: wire.LastHit}
	}
	return persistedCounterRecordsFromMap(recs), true, nil
}

func persistedCounterRecordsFromMap(recs map[string]persistedRuleCounter) []persistedRuleCounter {
	records := make([]persistedRuleCounter, 0, len(recs))
	for name, rec := range recs {
		rec.Name = name
		records = append(records, rec)
	}
	return records
}

func validatePersistedCounterRecords(records []persistedRuleCounter, strictIDs bool) error {
	if len(records) > maxRuleMetrics {
		return fmt.Errorf("record count %d exceeds limit %d", len(records), maxRuleMetrics)
	}
	seenIDs := make(map[string]struct{}, len(records))
	seenNames := make(map[string]bool, len(records)) // value reports a prior name-only record
	for i, rec := range records {
		if rec.Name == "" {
			return fmt.Errorf("record %d has empty name", i)
		}
		if rec.Hits < 0 || rec.LastHit < 0 {
			return fmt.Errorf("record %q has negative telemetry", rec.Name)
		}
		priorNameOnly, nameSeen := seenNames[rec.Name]
		if rec.ID == "" {
			if nameSeen {
				return fmt.Errorf("name-only record %q is ambiguous", rec.Name)
			}
			seenNames[rec.Name] = true
			continue
		}
		if priorNameOnly {
			return fmt.Errorf("name-only record %q is ambiguous", rec.Name)
		}
		seenNames[rec.Name] = false
		if !validRuleID(rec.ID) {
			if strictIDs {
				return fmt.Errorf("record %q has malformed stable ID", rec.Name)
			}
			continue
		}
		if _, duplicate := seenIDs[rec.ID]; duplicate {
			return fmt.Errorf("stable ID %q appears more than once", rec.ID)
		}
		seenIDs[rec.ID] = struct{}{}
	}
	return nil
}

// restoreRecords converts historical name-keyed snapshots into records.
func (rm *ruleMetrics) restoreRecords(recs map[string]persistedRuleCounter) {
	rm.restoreCounterRecords(persistedCounterRecordsFromMap(recs))
}

// restoreCounterRecords indexes stable identities independently of names; the
// name-keyed metrics remain a compatibility/Prometheus projection.
func (rm *ruleMetrics) restoreCounterRecords(records []persistedRuleCounter) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.last == nil {
		rm.last = make(map[string]*int64)
	}
	if rm.appliedByName == nil {
		rm.appliedByName = make(map[string]int64, min(len(records), maxRuleMetrics))
	}
	rm.byID = make(map[string]persistedRuleCounter, min(len(records), maxRuleMetrics))
	rm.loadedByName = make(map[string]persistedRuleCounter, min(len(records), maxRuleMetrics))
	for _, rec := range records {
		if rec.Name != "" && rm.restoreRecordLocked(rec.Name, rec) && !validRuleID(rec.ID) {
			rm.loadedByName[rec.Name] = rec
		}
		if _, exists := rm.byID[rec.ID]; exists || len(rm.byID) < maxRuleMetrics {
			mergePersistedCounterByID(rm.byID, rec)
		}
	}
}

func (rm *ruleMetrics) restoreRecordLocked(name string, rec persistedRuleCounter) bool {
	ptr := rm.hits[name]
	if ptr == nil {
		if len(rm.hits) >= maxRuleMetrics {
			return false
		}
		h := rec.Hits
		rm.hits[name] = &h
		rm.appliedByName[name] = rec.Hits
		l := rec.LastHit
		rm.last[name] = &l
		rm.order = append(rm.order, name)
		return true
	}

	// Add only growth in the immutable persisted baseline. Live RecordHit
	// increments may proceed through an already-obtained pointer while this lock
	// is held and must never be overwritten by a repeated runtime load.
	if delta := rec.Hits - rm.appliedByName[name]; delta > 0 {
		atomic.AddInt64(ptr, delta)
		rm.appliedByName[name] = rec.Hits
	}
	if lp := rm.last[name]; lp != nil {
		atomicStoreMax(lp, rec.LastHit)
		return true
	}
	l := rec.LastHit
	rm.last[name] = &l
	return true
}

func mergePersistedCounterByID(byID map[string]persistedRuleCounter, rec persistedRuleCounter) {
	if !validRuleID(rec.ID) {
		return
	}
	if prior, exists := byID[rec.ID]; exists {
		if prior.Hits > rec.Hits {
			rec.Hits = prior.Hits
		}
		if prior.LastHit > rec.LastHit {
			rec.LastHit = prior.LastHit
		}
	}
	byID[rec.ID] = rec
}

// startHitCounterPersistence restores persisted counters before publishing any
// saver. This ordering prevents an already-cancelled startup context from
// overwriting loaded telemetry with zero-valued policy cells.
func startHitCounterPersistence(ctx context.Context, path string) {
	// Ensure the directory exists.
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		os.MkdirAll(dir, 0o750) //nolint:errcheck // best-effort
	}

	loadStatus := loadHitCounters(path)
	if loadStatus == hitCounterLoadInvalid {
		logger.Printf("HitCounters: persistence disabled to preserve unreadable or malformed evidence at %s", path)
		return
	}
	RestoreHitCounts()
	// Rewrite legacy name-only records immediately with stable rule IDs before
	// either periodic or shutdown persistence can observe the store.
	saveHitCounters(path)
	if ctx.Err() != nil {
		return
	}

	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				saveHitCounters(path)
				return
			case <-t.C:
				saveHitCounters(path)
			}
		}
	}()
}

// RestoreHitCounts copies persisted hit counter values + lastHit from ruleMet
// back into the matching PolicyRule fields. Called once at startup after both
// policyStore.Load() and loadHitCounters() have run. Lock order (ruleMet then
// policyStore) is the ONLY nesting of these two mutexes — List() reads the
// rule's own atomics and never touches ruleMet, so no reverse-order path exists.
func RestoreHitCounts() {
	ruleMet.mu.RLock()
	defer ruleMet.mu.RUnlock()
	policyStore.mu.Lock()
	defer policyStore.mu.Unlock()
	next := make([]*PolicyRule, len(policyStore.rules))
	nameCounts := make(map[string]int, len(policyStore.rules))
	for _, rule := range policyStore.rules {
		nameCounts[rule.Name]++
	}
	for i, rule := range policyStore.rules {
		// Restore can run safely even if an evaluator still holds the current
		// revision. Never fill a nil cell on a published definition in place.
		next[i] = clonePolicyRuleForPublication(rule)
		counters := next[i].counters
		if rec, ok := ruleMet.byID[rule.ID]; ok {
			restorePolicyHitCount(counters, rec.Hits)
			atomicStoreMax(&counters.lastHitUnix, rec.LastHit)
			continue
		}
		// Backward-compatible fallback uses the immutable loaded snapshot, not
		// live telemetry that RecordHit continues to increment after startup.
		if rec, ok := ruleMet.loadedByName[rule.Name]; ok && nameCounts[rule.Name] == 1 {
			restorePolicyHitCount(counters, rec.Hits)
			atomicStoreMax(&counters.lastHitUnix, rec.LastHit)
		}
	}
	policyStore.rules = next
	policyStore.sortLocked()
}

// restorePolicyHitCount adds only the not-yet-restored persisted baseline. The
// caller serializes restorations under policyStore.mu; Evaluate can increment the
// total concurrently without being overwritten.
func restorePolicyHitCount(counters *policyRuleCounters, persisted int64) {
	restored := atomic.LoadInt64(&counters.restoredHitCount)
	if persisted <= restored {
		return
	}
	atomic.AddInt64(&counters.hitCount, persisted-restored)
	atomic.StoreInt64(&counters.restoredHitCount, persisted)
}

func atomicStoreMax(dst *int64, value int64) {
	for current := atomic.LoadInt64(dst); value > current; current = atomic.LoadInt64(dst) {
		if atomic.CompareAndSwapInt64(dst, current, value) {
			return
		}
	}
}

// WritePrometheus writes per-rule metrics lines to the given builder.
func (rm *ruleMetrics) WritePrometheus(w *strings.Builder) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if len(rm.hits) == 0 {
		return
	}
	w.WriteString("\n# HELP culvert_policy_rule_hits_total Per-rule hit count (capped at 200 rules)\n")
	w.WriteString("# TYPE culvert_policy_rule_hits_total counter\n")
	for _, name := range rm.order {
		ctr := rm.hits[name]
		// Sanitise label value: escape backslash, double-quote, newline.
		safe := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(name)
		fmt.Fprintf(w, "culvert_policy_rule_hits_total{rule=%q} %d\n", safe, atomic.LoadInt64(ctr))
	}
}

// ─── Latency histogram ──────────────────────────────────────────────────────
// Fixed-bucket histogram in Prometheus text format. Generalized so multiple
// metrics can reuse the same lock-free implementation (CA-2 PR2): the name,
// help text, and bucket layout are per-instance. newLatencyHistogram preserves
// the original request-latency metric byte-for-byte.

type latencyHistogram struct {
	name    string    // metric name, e.g. culvert_request_duration_seconds
	help    string    // HELP text
	buckets []float64 // upper bounds (immutable after init)
	counts  []int64   // per-bucket atomic counter
	sumBits int64     // atomic float64 stored as int64 bits
	total   int64     // atomic total observations
}

// newHistogram builds a histogram with a custom name, help text, and bucket
// upper bounds (seconds). Buckets should be ≥ 0.0001 so %g renders them as
// plain decimals rather than scientific notation.
func newHistogram(name, help string, buckets []float64) *latencyHistogram {
	return &latencyHistogram{
		name:    name,
		help:    help,
		buckets: buckets,
		counts:  make([]int64, len(buckets)+1), // +1 for +Inf
	}
}

var latencyHist = newLatencyHistogram()

// newLatencyHistogram returns the request-latency histogram.
// Buckets: 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s, +Inf.
func newLatencyHistogram() *latencyHistogram {
	return newHistogram(
		"culvert_request_duration_seconds",
		"Request latency histogram",
		[]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	)
}

// certSignHist records leaf-certificate signing latency (CA-2 PR2). Signing is
// an ECDSA P-256 keygen + x509.CreateCertificate — sub-millisecond to a few ms
// — so the buckets are finer at the low end than the request histogram.
var certSignHist = newHistogram(
	"culvert_cert_sign_duration_seconds",
	"Leaf certificate signing latency",
	[]float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1},
)

// Observe records a latency observation in seconds (lock-free).
func (h *latencyHistogram) Observe(seconds float64) {
	// Atomic float64 add via CAS loop — bit reinterpretation, not numeric conversion.
	for {
		old := atomic.LoadInt64(&h.sumBits)
		newVal := math.Float64frombits(uint64(old)) + seconds                             // #nosec G115 -- bit reinterpret, not numeric conversion
		if atomic.CompareAndSwapInt64(&h.sumBits, old, int64(math.Float64bits(newVal))) { // #nosec G115 -- bit reinterpret, not numeric conversion
			break
		}
	}
	atomic.AddInt64(&h.total, 1)
	for i, bound := range h.buckets {
		if seconds <= bound {
			atomic.AddInt64(&h.counts[i], 1)
			return
		}
	}
	atomic.AddInt64(&h.counts[len(h.buckets)], 1) // +Inf bucket
}

// WritePrometheus writes the histogram in Prometheus text exposition format.
func (h *latencyHistogram) WritePrometheus(w *strings.Builder) { //nolint:errcheck // strings.Builder.Write never returns an error
	fmt.Fprintf(w, "\n# HELP %s %s\n", h.name, h.help)
	fmt.Fprintf(w, "# TYPE %s histogram\n", h.name)
	var cumulative int64
	for i, bound := range h.buckets {
		cumulative += atomic.LoadInt64(&h.counts[i])
		fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", h.name, bound, cumulative)
	}
	cumulative += atomic.LoadInt64(&h.counts[len(h.buckets)])
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", h.name, cumulative)
	fmt.Fprintf(w, "%s_sum %f\n", h.name, math.Float64frombits(uint64(atomic.LoadInt64(&h.sumBits)))) // #nosec G115 -- bit reinterpret
	fmt.Fprintf(w, "%s_count %d\n", h.name, atomic.LoadInt64(&h.total))
}

// metricsToken is the Bearer token required to access /metrics.
// Empty string = open access (backward-compatible default; not recommended).
var metricsToken string

// handleMetrics serves Prometheus-compatible text metrics on GET /metrics.
// If metricsToken is set, the request must carry: Authorization: Bearer <token>
func handleMetrics(w http.ResponseWriter, r *http.Request) { //nolint:errcheck // writes to http.ResponseWriter; errors mean client disconnected
	if metricsToken != "" {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(metricsToken)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}
	total := atomic.LoadInt64(&statTotal)
	blocked := atomic.LoadInt64(&statBlocked)
	authFail := atomic.LoadInt64(&statAuthFail)
	fileBlocked := atomic.LoadInt64(&statFileBlocked)
	allowed := total - blocked - authFail
	if allowed < 0 {
		allowed = 0
	}

	rlLimit := int64(rl.Limit())
	rlEnabled := int64(0)
	if rl.Enabled() {
		rlEnabled = 1
	}

	scanCounters := secscan.Counters()
	clamBlocked := scanCounters.ClamBlocked
	yaraBlocked := scanCounters.YARABlocked
	feedBlocked := scanCounters.ThreatFeedBlocked
	dpiBlocked := atomic.LoadInt64(&statDPIBlocked)
	bytesSent := atomic.LoadInt64(&statBytesSent)
	bytesRecv := atomic.LoadInt64(&statBytesRecv)
	feedEntries, _, _ := globalThreatFeed.Stats()
	cacheHits, cacheMisses, cacheSize := globalSecScanner.CacheStats()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// Per-rule metrics (appended after the main block).
	var ruleMetBuf strings.Builder

	fmt.Fprintf(w, `# HELP culvert_requests_total Total proxy requests
# TYPE culvert_requests_total counter
culvert_requests_total %d

# HELP culvert_requests_allowed Total allowed requests
# TYPE culvert_requests_allowed counter
culvert_requests_allowed %d

# HELP culvert_requests_blocked Total blocked requests (domain + IP)
# TYPE culvert_requests_blocked counter
culvert_requests_blocked %d

# HELP culvert_requests_auth_fail Total auth failures
# TYPE culvert_requests_auth_fail counter
culvert_requests_auth_fail %d

# HELP culvert_blocklist_size Current number of blocked domains
# TYPE culvert_blocklist_size gauge
culvert_blocklist_size %d

# HELP culvert_uptime_seconds Proxy uptime in seconds
# TYPE culvert_uptime_seconds gauge
culvert_uptime_seconds %.0f

# HELP culvert_rate_limit_rpm Configured rate limit (requests per minute, 0=disabled)
# TYPE culvert_rate_limit_rpm gauge
culvert_rate_limit_rpm %d

# HELP culvert_rate_limit_enabled Whether rate limiting is active
# TYPE culvert_rate_limit_enabled gauge
culvert_rate_limit_enabled %d

# HELP culvert_file_blocked_total Total requests blocked by file-extension profile
# TYPE culvert_file_blocked_total counter
culvert_file_blocked_total %d

# HELP culvert_file_block_profile_size Number of blocked file extensions
# TYPE culvert_file_block_profile_size gauge
culvert_file_block_profile_size %d

# HELP culvert_dpi_blocked_total Total requests blocked by DPI content signatures
# TYPE culvert_dpi_blocked_total counter
culvert_dpi_blocked_total %d

# HELP culvert_clamav_blocked_total Total requests blocked by ClamAV antivirus
# TYPE culvert_clamav_blocked_total counter
culvert_clamav_blocked_total %d

# HELP culvert_yara_blocked_total Total requests blocked by YARA rules
# TYPE culvert_yara_blocked_total counter
culvert_yara_blocked_total %d

# HELP culvert_threat_feed_blocked_total Total requests blocked by threat intelligence feeds
# TYPE culvert_threat_feed_blocked_total counter
culvert_threat_feed_blocked_total %d

# HELP culvert_threat_feed_entries Total URLs in threat feed database
# TYPE culvert_threat_feed_entries gauge
culvert_threat_feed_entries %d

# HELP culvert_threat_feed_allowlist_masked_total Domain-level threat hits suppressed by the domain allowlist
# TYPE culvert_threat_feed_allowlist_masked_total counter
culvert_threat_feed_allowlist_masked_total %d

# HELP culvert_scan_cache_hits_total Total SHA256 scan-cache hits (decision reused without rescanning)
# TYPE culvert_scan_cache_hits_total counter
culvert_scan_cache_hits_total %d

# HELP culvert_scan_cache_misses_total Total SHA256 scan-cache misses (required a fresh scan)
# TYPE culvert_scan_cache_misses_total counter
culvert_scan_cache_misses_total %d

# HELP culvert_scan_cache_size Current number of entries in the SHA256 scan result cache
# TYPE culvert_scan_cache_size gauge
culvert_scan_cache_size %d

# HELP culvert_bytes_sent_total Total bytes sent upstream (request bodies)
# TYPE culvert_bytes_sent_total counter
culvert_bytes_sent_total %d

# HELP culvert_bytes_recv_total Total bytes received from upstream (response bodies)
# TYPE culvert_bytes_recv_total counter
culvert_bytes_recv_total %d

# HELP culvert_auth_exempt_decisions_total Total Stage-1 authentication-policy Exempt decisions
# TYPE culvert_auth_exempt_decisions_total counter
culvert_auth_exempt_decisions_total %d

# HELP culvert_auth_credential_required_total Total Stage-1 authentication-policy CredentialRequired decisions
# TYPE culvert_auth_credential_required_total counter
culvert_auth_credential_required_total %d

# HELP culvert_auth_sso_required_total Total Stage-1 authentication-policy SSORequired decisions
# TYPE culvert_auth_sso_required_total counter
culvert_auth_sso_required_total %d
`,
		total, allowed, blocked, authFail,
		int64(bl.Count()),
		time.Since(startTime).Seconds(),
		rlLimit, rlEnabled,
		fileBlocked, int64(fileBlocker.Count()),
		dpiBlocked,
		clamBlocked,
		yaraBlocked,
		feedBlocked,
		feedEntries,
		globalThreatFeed.AllowlistMaskedTotal(),
		cacheHits,
		cacheMisses,
		int64(cacheSize),
		bytesSent,
		bytesRecv,
		atomic.LoadInt64(&statAuthExempt),
		atomic.LoadInt64(&statAuthCredentialRequired),
		atomic.LoadInt64(&statAuthSSORequired),
	)

	// PR3d — inspected native-HTTP/2 tunnel drain observability. activeConns above
	// conflates H1-inspect, H2-inspect, and raw-bypass tunnels; these disambiguate
	// the H2-inspect subset so an operator can confirm a node GOAWAY'd cleanly on
	// shutdown. goaway = tunnels active when the drain STARTED (one-shot snapshot;
	// late registrants caught by the re-fire are not counted), forced = backstop
	// closes at the deadline. `goaway - forced` APPROXIMATES graceful drains but is
	// not an exact identity (a late-registered, force-closed tunnel is in forced but
	// not goaway), so treat it as an operator heuristic.
	_, _ = fmt.Fprintf(w, `# HELP culvert_h2_inspect_active Currently active inspected native-HTTP/2 tunnels
# TYPE culvert_h2_inspect_active gauge
culvert_h2_inspect_active %d

# HELP culvert_h2_inspect_drain_goaway_total Inspected H2 tunnels signaled with GOAWAY at shutdown-drain start
# TYPE culvert_h2_inspect_drain_goaway_total counter
culvert_h2_inspect_drain_goaway_total %d

# HELP culvert_h2_inspect_drain_forced_total Inspected H2 tunnels force-closed by the drain-deadline backstop
# TYPE culvert_h2_inspect_drain_forced_total counter
culvert_h2_inspect_drain_forced_total %d
`,
		atomic.LoadInt64(&statH2InspectActive),
		atomic.LoadInt64(&statH2InspectGoaway),
		atomic.LoadInt64(&statH2InspectForced),
	)

	// Decryption-profile success delta: which protocol inspected tunnels negotiated
	// on the upstream leg (h2 = Inspect-as-HTTP/2 working; http/1.1 = strip/downgrade).
	_, _ = fmt.Fprintf(w, `# HELP culvert_inspect_upstream_alpn_total Inspected-tunnel upstream (origin) leg negotiated protocol
# TYPE culvert_inspect_upstream_alpn_total counter
culvert_inspect_upstream_alpn_total{protocol="h2"} %d
culvert_inspect_upstream_alpn_total{protocol="http/1.1"} %d
`,
		atomic.LoadInt64(&statInspectUpstreamH2),
		atomic.LoadInt64(&statInspectUpstreamH1),
	)

	// Adaptive decryption-exclusion (fail-open) observability: sessions bypassed
	// because of a learned exclusion, and current cache occupancy (inspection-
	// coverage erosion the operator can alert on). Learn events (by reason) append
	// via autoExcludeLearns.writePrometheus below.
	aeStats := autoExclude().Stats()
	_, _ = fmt.Fprintf(w, `# HELP culvert_decrypt_autoexclude_hit_total Sessions that bypassed SSL inspection because of a learned decryption exclusion
# TYPE culvert_decrypt_autoexclude_hit_total counter
culvert_decrypt_autoexclude_hit_total %d
# HELP culvert_decrypt_autoexclude_active Current count of active learned decryption exclusions (hosts inspection is OFF for)
# TYPE culvert_decrypt_autoexclude_active gauge
culvert_decrypt_autoexclude_active %d
# HELP culvert_decrypt_autoexclude_pending Current count of in-progress (unconfirmed) exclusion observations
# TYPE culvert_decrypt_autoexclude_pending gauge
culvert_decrypt_autoexclude_pending %d
# HELP culvert_decrypt_autoexclude_rescue_total Sessions live-bypassed on the first client_cert_required signal (confirm-count-exempt, before any persistent promotion)
# TYPE culvert_decrypt_autoexclude_rescue_total counter
culvert_decrypt_autoexclude_rescue_total %d
# HELP culvert_decrypt_autoexclude_surge_total Abnormal-learning-rate alerts fired (promotion rate crossed the surge threshold within a window) — a poisoning-campaign indicator
# TYPE culvert_decrypt_autoexclude_surge_total counter
culvert_decrypt_autoexclude_surge_total %d
`,
		atomic.LoadInt64(&autoExcludeHitCounter),
		aeStats.Active,
		aeStats.Pending,
		atomic.LoadInt64(&autoExcludeRescueCounter),
		atomic.LoadInt64(&autoExcludeSurgeCounter),
	)

	// Append per-rule hit counters, latency histogram, and CDR metrics.
	ruleMet.WritePrometheus(&ruleMetBuf)
	decProfMintlsRejects.writePrometheus(&ruleMetBuf)
	autoExcludeLearns.writePrometheus(&ruleMetBuf)
	latencyHist.WritePrometheus(&ruleMetBuf)
	urlcatWritePrometheus(&ruleMetBuf)
	caWritePrometheus(&ruleMetBuf)
	certSignHist.WritePrometheus(&ruleMetBuf)
	clusterWritePrometheus(&ruleMetBuf)
	cdrWritePrometheus(&ruleMetBuf)
	liveFeedWritePrometheus(&ruleMetBuf)
	releaseCatalogWritePrometheus(&ruleMetBuf)
	fmt.Fprint(w, ruleMetBuf.String()) //nolint:errcheck
}
