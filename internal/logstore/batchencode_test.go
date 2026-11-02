package logstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// ── fixtures ────────────────────────────────────────────────────────────────
//
// Two realistic shapes, mixed 1:3 in a batch: the plain allowed request that
// is ~all production traffic, and a decisioned one carrying the identity, URI
// and auth_* block. A batch of only-plain entries would understate the encode
// cost; a batch of only-rich ones would overstate it.

func entryPlain() Entry {
	return Entry{
		TS: 1762070000123, Time: "2026-11-02 22:13:20", IP: "198.51.100.17",
		Method: "GET", Host: "cdn.example.com", Status: "OK", Level: "INFO",
		RuleMatched: "allow-general-web", ActionTaken: "allow",
		BytesSent: 812, BytesRecv: 48213,
	}
}

func entryRich() Entry {
	e := entryPlain()
	e.Identity = "alice.hernandez@corp.example.com"
	e.URI = "cdn.example.com/assets/app/bundle/main.chunk.js"
	e.RuleID = "01JBQ7W2M6X8A9C0D1E2F3G4H5"
	e.SSLAction = "inspect"
	e.DurationMs = 37
	e.SchemaVersion = 1
	e.AuthSource = "oidc:corp-okta"
	e.AuthOutcome = "Allow"
	e.AuthPolicyRuleID = "01JBQ7W2M6X8A9C0D1E2F3G4H6"
	e.AuthPolicyRuleName = "corp-employees-standard"
	e.AuthSubjectMatchTypes = []string{"cidr", "group"}
	e.AuthSchemaVersion = 2
	return e
}

func encodeBatchFixture(n int) []Entry {
	b := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		if i%4 == 0 {
			b = append(b, entryRich())
		} else {
			b = append(b, entryPlain())
		}
	}
	return b
}

// ── the differential oracle ─────────────────────────────────────────────────

// TestFlushEncodeByteIdentity is what makes the allocation win safe to ship:
// the persisted value must be byte-for-byte what the replaced json.Marshal
// produced, or the change silently rewrites records already on disk and the
// SIEM/drill-down contract with them.
//
// The cases are chosen for the ways the two APIs could diverge rather than for
// coverage of the struct: encoding/json HTML-escapes <, > and & by DEFAULT in
// both Marshal and Encoder, escapes U+2028/U+2029, and coerces invalid UTF-8
// to U+FFFD — all three are behaviours this test pins, alongside the zero
// Entry (every omitempty field absent), the nested dec block, and an empty vs
// populated slice field. It also pins the trailing-newline strip: if Encode
// ever stopped appending it, every record here would lose its final byte.
func TestFlushEncodeByteIdentity(t *testing.T) {
	withDec := entryRich()
	withDec.Dec = &DecryptionBlock{SchemaVersion: 1, Outcome: "bypass", DecisionSource: "rule"}

	cases := []Entry{
		{},                                  // zero value: every omitempty field absent
		entryPlain(),                        // the common-case record
		entryRich(),                         // identity + URI + auth_* block
		withDec,                             // nested dec object
		{AuthSubjectMatchTypes: []string{}}, // empty slice
		{AuthSubjectMatchTypes: []string{"<cidr>", "&group"}}, // escaped in a slice
		{
			Host:        "<script>alert(1)</script>&  ",
			URI:         "a/b?x=1&y=2<>",
			Identity:    "emoji \U0001F600 \"quoted\" back\\slash\ttab\nnewline",
			RuleMatched: string([]byte{0xff, 0xfe, 'a'}), // invalid UTF-8
		},
		{URI: strings.Repeat("x", 64<<10)}, // forces buffer growth mid-batch
	}

	enc := newBatchEncoder()
	enc.reset()
	for i := range cases {
		if !enc.add(i, &cases[i]) {
			t.Fatalf("case %d: add reported failure", i)
		}
	}
	if len(enc.recs) != len(cases) {
		t.Fatalf("recs=%d want %d", len(enc.recs), len(cases))
	}
	// Subslices are read only now that the whole batch is encoded (invariant 1).
	for i := range cases {
		want, err := json.Marshal(cases[i])
		if err != nil {
			t.Fatalf("case %d: json.Marshal: %v", i, err)
		}
		if got := enc.at(i); !bytes.Equal(got, want) {
			t.Errorf("case %d not byte-identical to json.Marshal\n got %q\nwant %q", i, got, want)
		}
	}
}

// TestFlushEncodeReuseAcrossBatches is the negative control for invariant 2:
// a reset must not leave a previous batch's bytes visible, and the second
// batch's records must be correct even though they reuse the first's memory.
func TestFlushEncodeReuseAcrossBatches(t *testing.T) {
	enc := newBatchEncoder()
	for round := 0; round < 3; round++ {
		batch := make([]Entry, 8)
		for i := range batch {
			batch[i] = entryRich()
			batch[i].Host = fmt.Sprintf("round%d-host%d.example.com", round, i)
		}
		enc.reset()
		for i := range batch {
			if !enc.add(i, &batch[i]) {
				t.Fatalf("round %d: add %d failed", round, i)
			}
		}
		for i := range batch {
			want, _ := json.Marshal(batch[i])
			if got := enc.at(i); !bytes.Equal(got, want) {
				t.Fatalf("round %d rec %d: got %q want %q", round, i, got, want)
			}
		}
	}
}

// TestFlushEncodeBufferReclaim pins the memory bound: an outsized batch must
// not leave its buffer pinned for the life of the process.
func TestFlushEncodeBufferReclaim(t *testing.T) {
	enc := newBatchEncoder()
	big := Entry{URI: strings.Repeat("y", encoderBufReclaim+1)}
	enc.reset()
	if !enc.add(0, &big) {
		t.Fatal("add of oversized entry failed")
	}
	if cap(enc.buf) <= encoderBufReclaim {
		t.Fatalf("fixture did not exceed the reclaim threshold (cap=%d)", cap(enc.buf))
	}
	enc.reset()
	if cap(enc.buf) > encoderBufReclaim {
		t.Errorf("oversized buffer still pinned after reset: cap=%d", cap(enc.buf))
	}
}

// ── end-to-end: the buffer reuse must survive a real Badger store ───────────

// TestFlushBatchRoundTripMultiFlush is the test that would actually catch an
// aliasing bug. It drives MORE than one flush worth of entries through the
// live store, each with a unique host, then reads every one back and compares
// it to the entry that was written. A buffer reset before Badger had copied
// the values, or a subslice taken before the buffer stopped growing, shows up
// here as a record carrying another record's bytes.
func TestFlushBatchRoundTripMultiFlush(t *testing.T) {
	s, err := OpenTTL(t.TempDir(), 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("OpenTTL: %v", err)
	}
	defer func() { _ = s.Close() }()

	const n = flushBatchSize*2 + 37 // spans three flushes, not on a boundary
	want := make(map[string]Entry, n)
	for i := 0; i < n; i++ {
		e := entryRich()
		if i%4 != 0 {
			e = entryPlain()
		}
		e.Host = fmt.Sprintf("h%05d.example.com", i)
		// Vary the length so a stale subslice cannot coincidentally match.
		e.URI = e.Host + "/" + strings.Repeat("p", i%97)
		want[e.Host] = e
		s.Add(e)
	}
	got := drainLogStore(t, s, n)
	if len(got) != n {
		t.Fatalf("read back %d entries, wrote %d", len(got), n)
	}
	for i := range got {
		w, ok := want[got[i].Host]
		if !ok {
			t.Fatalf("unknown host %q read back", got[i].Host)
		}
		gb, _ := json.Marshal(got[i])
		wb, _ := json.Marshal(w)
		if !bytes.Equal(gb, wb) {
			t.Errorf("host %q round-tripped wrong\n got %s\nwant %s", got[i].Host, gb, wb)
		}
		delete(want, got[i].Host)
	}
	if len(want) != 0 {
		t.Errorf("%d entries never read back (first missing keys are a lost-write bug)", len(want))
	}
}

// TestFlushBatchConcurrentAdd is the concurrency control: many producers feed
// Add (the proxy hot path's shape) while the single write loop flushes. It
// asserts no entry is corrupted — a dropped entry is legitimate here, because
// Add deliberately drops rather than blocking when the queue is full.
func TestFlushBatchConcurrentAdd(t *testing.T) {
	s, err := OpenTTL(t.TempDir(), 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("OpenTTL: %v", err)
	}
	defer func() { _ = s.Close() }()

	const workers, per = 8, 200
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				e := entryRich()
				e.Host = fmt.Sprintf("w%02d-%04d.example.com", w, i)
				e.URI = e.Host + "/" + strings.Repeat("q", i%53)
				s.Add(e)
			}
		}(w)
	}
	wg.Wait()
	// workers*per stays well inside the 4096-deep write queue, so Add's
	// drop-rather-than-block path is not reached and the full count is
	// assertable: a short read here is a lost write, not backpressure.
	got := drainLogStore(t, s, workers*per)
	for i := range got {
		// Every stored record must be internally consistent: the URI is
		// derived from the Host, so a crossed buffer is detectable without
		// needing to know which entries were dropped.
		if !strings.HasPrefix(got[i].URI, got[i].Host+"/") {
			t.Fatalf("corrupt record: host=%q uri=%q", got[i].Host, got[i].URI)
		}
	}
	if len(got) != workers*per {
		t.Fatalf("persisted %d entries, wrote %d", len(got), workers*per)
	}
}
