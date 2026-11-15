package syslog

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// lineformat_bench_test.go — what one logged request costs the goroutine that
// logged it, and the gate that keeps it there.
//
// Run:
//
//	go test ./internal/syslog -run '^$' -bench 'FormatLine|WriteRequest_Real' -benchmem -count=6
//
// WHY A SECOND FIXTURE. syslog_bench_test.go's benchEntry is a 13-key
// map[string]any, chosen when the question was async vs sync delivery, where
// the body shape did not matter. It is the wrong shape for measuring assembly
// cost and it misreports it in BOTH directions: a map is already a pointer, so
// it never pays the interface box a struct body pays, and encoding one walks
// and sorts its keys, so it reports 33 allocations per record where the struct
// shape reports 2 (BenchmarkWriteRequest_AsyncHealthyCollector, same run). What
// the request path actually hands this sink is logstore.Entry — a 25-field,
// 352-byte struct that serializes to ~375 bytes of JSON. benchRealEntry
// mirrors it field for field (the package is a stdlib-only leaf by contract
// and cannot import it), so the arms below measure the production shape.
//
// Measured (Go 1.27.4, linux/amd64, 4 vCPU Xeon @2.10GHz, -benchtime=2s
// -count=3..4, medians). The BEFORE row is THIS benchmark run against the
// pristine parent commit in a git worktree, so both rows are the same fixture
// through the same arm:
//
//	BenchmarkWriteRequest_RealEntry   allocs/op   B/op     ns/op
//	  before (parent commit)              10     1 665     3 420
//	  after                                2       768     2 720
//
// and the two stages, both arms in one binary:
//
//	                                  allocs/op   B/op     ns/op
//	WriteRequest body, legacy arm           4     1 536     2 888
//	WriteRequest body, current              2       768     2 421
//	formatLine rfc3164, legacy arm          6       240       463
//	formatLine rfc3164, current             1       128       211
//	formatLine rfc5424, legacy arm          7       304       475
//	formatLine rfc5424, current             1       144       205
//	writeLine, legacy arm                   1        16       136
//	writeLine, current                      0         0        93
//
// ns/op for the WriteRequest arms includes the drain goroutine's delivery
// against an instantly-draining collector, so it is throughput rather than
// pure caller latency; allocs/op and B/op are the numbers to read, and the
// stage arms isolate each change on one goroutine. The legacy arms restore
// only their own stage — the WriteRequest legacy arm still formats and
// delivers through the new path, which is why it reports 4 and not the parent
// commit's 10. The two allocations that remain are named in lineformat.go: the
// caller's `any` box and the one string the queued line is made of.

// benchDecFixture mirrors logstore.DecryptionBlock's leading fields: the
// nested pointer block, nil on the common record.
type benchDecFixture struct {
	SchemaVersion int    `json:"schema_version"`
	Outcome       string `json:"outcome"`
}

// benchRealEntry mirrors logstore.Entry field for field — same fields, same
// order, same json tags, same omitempty — so its encode cost and its wire
// bytes are the ones production pays. Duplicated rather than imported: this
// package is a stdlib-only leaf (see the package header).
type benchRealEntry struct {
	TS                    int64            `json:"ts"`
	Time                  string           `json:"time"`
	IP                    string           `json:"ip"`
	Identity              string           `json:"identity,omitempty"`
	Method                string           `json:"method"`
	Host                  string           `json:"host"`
	URI                   string           `json:"uri,omitempty"`
	Status                string           `json:"status"`
	Level                 string           `json:"level"`
	RuleMatched           string           `json:"ruleMatched"`
	RuleID                string           `json:"ruleId,omitempty"`
	ActionTaken           string           `json:"actionTaken"`
	BytesSent             int64            `json:"bytesSent,omitempty"`
	BytesRecv             int64            `json:"bytesRecv,omitempty"`
	SSLAction             string           `json:"sslAction,omitempty"`
	DurationMs            int64            `json:"durationMs,omitempty"`
	SchemaVersion         int              `json:"schema_version,omitempty"`
	AuthSource            string           `json:"auth_source,omitempty"`
	AuthOutcome           string           `json:"auth_outcome,omitempty"`
	AuthPolicyRuleID      string           `json:"auth_policy_rule_id,omitempty"`
	AuthPolicyRuleName    string           `json:"auth_policy_rule_name,omitempty"`
	AccessRuleID          string           `json:"access_rule_id,omitempty"`
	AuthSubjectMatchTypes []string         `json:"auth_subject_match_types,omitempty"`
	AuthSchemaVersion     int              `json:"auth_schema_version,omitempty"`
	Dec                   *benchDecFixture `json:"dec,omitempty"`
}

// realEntryFixture is an allowed, authenticated, SSL-inspected request — the
// highest-volume record this sink forwards.
func realEntryFixture() benchRealEntry {
	return benchRealEntry{
		TS: 1752700000000, Time: "2026-11-14T12:34:56Z", IP: "203.0.113.7",
		Identity: "alice@corp.example", Method: "GET", Host: "www.example.com",
		Status: "OK", Level: "INFO", RuleMatched: "allow-web",
		RuleID: "01JABCDEF0000000000000000", ActionTaken: "allow",
		BytesSent: 1234, BytesRecv: 56789, SSLAction: "inspect",
		SchemaVersion: 1, AuthSource: "idp", AuthOutcome: "Exempt",
	}
}

// recordingConn is an instantly-draining collector that keeps what it was
// sent, so a test can assert on the exact lines that reached the wire.
type recordingConn struct{ deadlineRecordingConn }

// raw returns every byte the collector received, unsplit — see
// TestLineFormat_UnencodableBodyDeliversNothing for why splitting first would
// hide the regression it checks for.
func (c *recordingConn) raw() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// legacyWriteRequest is the pre-change WriteRequest: marshal to a fresh slice,
// copy into a string, hand that to send. Retained as the benchmark baseline
// and as the shape TestBenchGate_SyslogLineAllocs compares against.
func legacyWriteRequest(s *Writer, e any) {
	body, ok := legacyMarshalBody(e)
	if !ok {
		return
	}
	s.send(14, body)
}

func BenchmarkWriteRequest_RealEntry(b *testing.B) {
	w := newBenchWriter(&discardConn{}, true)
	defer func() { _ = w.Close() }()
	e := realEntryFixture()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.WriteRequest(e)
	}
}

func BenchmarkWriteRequest_RealEntryLegacy(b *testing.B) {
	w := newBenchWriter(&discardConn{}, true)
	defer func() { _ = w.Close() }()
	e := realEntryFixture()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		legacyWriteRequest(w, e)
	}
}

// The formatLine arms isolate header assembly: no encoding, no queue, no
// drain goroutine — only what the caller's goroutine spends building a line
// around a body it already has.
func benchFormatLine(b *testing.B, format string, legacy bool) {
	w := &Writer{host: "gw-1", tag: "culvert", pid: "4242", format: format}
	msg := `{"ts":1752700000000,"ip":"203.0.113.7","host":"www.example.com","status":"OK"}`
	at := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if legacy {
			_ = legacyFormatLine(w, 14, msg, at)
			continue
		}
		_ = w.formatLine(14, msg, at)
	}
}

// legacyWriteLine is the pre-change delivery write: fmt.Fprint over the line
// string. Retained as the baseline for the drain goroutine's per-line cost.
func legacyWriteLine(s *Writer, line string) error {
	s.conn.SetWriteDeadline(time.Now().Add(writeTimeout)) //nolint:errcheck // mirrors the production call site
	_, err := fmt.Fprint(s.conn, line)
	return err
}

// The writeLine arms are the DRAIN goroutine's per-line cost — the single
// goroutine that has to keep up with the whole gateway's entry rate before
// tryEnqueue starts counting drops.
func benchWriteLine(b *testing.B, legacy bool) {
	w := newBenchWriter(&discardConn{}, false)
	line := "<14>Nov 14 12:34:56 gw-1 culvert: " + strings.Repeat("x", 375) + "\n"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		if legacy {
			err = legacyWriteLine(w, line)
		} else {
			err = w.writeLine(line)
		}
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteLine(b *testing.B)       { benchWriteLine(b, false) }
func BenchmarkWriteLineLegacy(b *testing.B) { benchWriteLine(b, true) }

func BenchmarkFormatLine_RFC3164(b *testing.B)       { benchFormatLine(b, "rfc3164", false) }
func BenchmarkFormatLine_RFC3164Legacy(b *testing.B) { benchFormatLine(b, "rfc3164", true) }
func BenchmarkFormatLine_RFC5424(b *testing.B)       { benchFormatLine(b, "rfc5424", false) }
func BenchmarkFormatLine_RFC5424Legacy(b *testing.B) { benchFormatLine(b, "rfc5424", true) }

// raceDetectorOn is set true by the //go:build race companion file
// (race_on_test.go).
var raceDetectorOn = false

// TestBenchGate_SyslogLineAllocs bounds the per-record cost this sink charges
// the goroutine that logged the record, and asserts it stays cheaper than the
// shape it replaced.
//
// It is gated as a CEILING on allocs/op and B/op rather than on ns/op, for the
// usual reason: those two are deterministic and hardware-independent, and this
// cost is paid inside the request goroutine once per logged request on every
// protocol whenever a SIEM collector is configured.
//
// The legacy comparison is the load-bearing half. An absolute bound alone
// would still pass if someone reinstated the intermediate json.Marshal slice
// and the string copy while the bound happened to be generous; comparing
// against legacyWriteRequest/legacyFormatLine fails the moment the fused
// builder stops being used.
func TestBenchGate_SyslogLineAllocs(t *testing.T) {
	if testing.Short() {
		t.Skip("benchmark gate")
	}
	if raceDetectorOn {
		// The detector allocates per instrumented access, which both inflates
		// the bounds and reverses the legacy comparison (the pooled writeLine
		// measured 251 B/op against fmt.Fprint's 164 under -race), so the
		// verdict here would be about instrumentation rather than about the
		// code. Nothing is lost on this lane: the byte-identity and pool-bound
		// tests in lineformat_test.go are not timing or allocation gates and
		// run everywhere.
		t.Skip("allocation gate: -race instrumentation allocates more than the difference being bounded")
	}
	// Steady state at the time of measurement, with headroom:
	//
	//	WriteRequest  3 allocs / 1 120 B   (legacy 11 / 2 017)
	//	formatLine    1 alloc  /   480 B   (legacy  6 /   528)
	cases := []struct {
		name          string
		cur, legacy   func(*testing.B)
		allocs, bytes int64
	}{
		{"WriteRequest", BenchmarkWriteRequest_RealEntry, BenchmarkWriteRequest_RealEntryLegacy, 4, 1280},
		{"formatLine/rfc3164", BenchmarkFormatLine_RFC3164, BenchmarkFormatLine_RFC3164Legacy, 1, 640},
		{"formatLine/rfc5424", BenchmarkFormatLine_RFC5424, BenchmarkFormatLine_RFC5424Legacy, 1, 640},
		{"writeLine", BenchmarkWriteLine, BenchmarkWriteLineLegacy, 0, 0},
	}
	for _, c := range cases {
		cur := testing.Benchmark(c.cur)
		legacy := testing.Benchmark(c.legacy)
		if cur.N == 0 || legacy.N == 0 {
			t.Errorf("%s: a benchmark arm did not run (current N=%d, legacy N=%d), so the bounds below measured nothing", c.name, cur.N, legacy.N)
			continue
		}
		t.Logf("%s: %d allocs/op (bound %d), %d B/op (bound %d), %d ns/op — legacy %d allocs/op, %d B/op, %d ns/op",
			c.name, cur.AllocsPerOp(), c.allocs, cur.AllocedBytesPerOp(), c.bytes, cur.NsPerOp(),
			legacy.AllocsPerOp(), legacy.AllocedBytesPerOp(), legacy.NsPerOp())

		if got := cur.AllocsPerOp(); got > c.allocs {
			t.Errorf("REGRESSION: %s allocates %d/op, exceeding the bound %d — line assembly (internal/syslog/lineformat.go) "+
				"has regained a per-record allocation. This is paid inside the request goroutine on every logged request, "+
				"on every protocol, whenever a SIEM collector is configured. Most likely a body is being marshalled into an "+
				"intermediate slice or copied into an intermediate string again instead of being encoded into the line buffer.",
				c.name, got, c.allocs)
		}
		if got := cur.AllocedBytesPerOp(); got > c.bytes {
			t.Errorf("REGRESSION: %s allocates %d B/op, exceeding the bound %d — re-measure BenchmarkWriteRequest_RealEntry "+
				"and the BenchmarkFormatLine arms before moving this bound.", c.name, got, c.bytes)
		}
		if cur.AllocsPerOp() >= legacy.AllocsPerOp() {
			t.Errorf("%s is no cheaper than the shape it replaced (%d vs %d allocs/op): the fused line builder is no longer "+
				"on this path. See lineformat.go for what it removes and legacyWriteRequest/legacyFormatLine for what it replaced.",
				c.name, cur.AllocsPerOp(), legacy.AllocsPerOp())
		}
	}
}
