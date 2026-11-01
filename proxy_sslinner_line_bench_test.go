package main

// Before/after evidence for the SSL_INNER inner-request trace line
// (proxy_sslinner_line.go), the highest-frequency log site in the product when
// TLS inspection is on: once per inner request of every decrypted tunnel, on
// both the H1 keep-alive loop and the H2 stream handler.
//
//	go test -run '^$' -bench 'BenchmarkSSLInnerLine' -benchmem -count=6 .
//	go test -run '^$' -bench 'BenchmarkSSLInnerLine_Parallel' -benchmem -cpu=1,2,4 .
//
// THREE forms are measured in one run, on the same hardware, under the same
// allocator state, against the same sink:
//
//   - before — the logger.Printf format string this change replaced.
//   - after  — the shipped pooled-carrier + "%s"-on-[]byte emitter.
//   - rejected — the emitPolicyDecision shape (appends into a stack scratch,
//     handed to logger.Output as a string). It is kept here because it is the
//     obvious move and it LOSES; a measurement that only compared the winner
//     would leave the next pass to rediscover that the hard way. See the
//     rationale block in proxy_sslinner_line.go.
//
// Both frozen forms are verbatim copies of code that is not in production and
// must NOT be "kept in sync" with the emitter — their whole value is that they
// do not move.
//
// THE SWEEP IS OVER REQUEST-PATH LENGTH, because that is the operand that
// varies in size (bounded at 2 KiB by boundRetainedPath) and it is what decides
// which form wins. A single "typical" shape would have hidden the rejected
// form's regression entirely.
//
// All forms write to a DISCARDING sink. That is deliberate: the sink cost
// (rotating file, JSON re-encode, the logsink queue) is identical for all three
// and is not what this change touches, so including it would dilute the delta
// with noise this change cannot affect.

import (
	"io"
	"log"
	"strconv"
	"strings"
	"testing"
)

// sslInnerNullSink discards without allocating.
type sslInnerNullSink struct{}

func (sslInnerNullSink) Write(p []byte) (int, error) { return len(p), nil }

// benchSSLInnerLogger points the process logger at a discarding sink with the
// SHIPPED flags (LstdFlags), so the measured path includes the same timestamp
// formatting every form pays.
func benchSSLInnerLogger(b *testing.B) {
	b.Helper()
	prev := logger
	logger = log.New(sslInnerNullSink{}, "[Culvert] ", log.LstdFlags)
	b.Cleanup(func() { logger = prev })
}

// sslInnerLineLegacyEmit is the pre-change emit, frozen: the format string, the
// argument list and the per-call filter/profile derivation exactly as
// proxy_tunnel.go and proxy_tunnel_h2.go each held them. Do not update it.
func sslInnerLineLegacyEmit(clientIP, method, hostOnly, path string, match *PolicyMatch) {
	filterStr := "off"
	profileStr := ""
	if match != nil && match.Rule != nil && match.Rule.FileFiltering {
		filterStr = "on"
		profileStr = sanitizeLog(string(match.Rule.FileProfile))
	}
	logger.Printf("SSL_INNER %s %s %s%s (profile=%q filter=%s)", sanitizeLog(clientIP), sanitizeLog(method), sanitizeLog(hostOnly), sanitizeLog(boundRetainedPath(path)), profileStr, filterStr)
}

// sslInnerLineRejectedScratchBufSize is the stack scratch the rejected form used
// — generous enough that a typical line never spills, so the form is measured at
// its best rather than strawmanned.
const sslInnerLineRejectedScratchBufSize = 512

// sslInnerLineRejectedEmit is the emitPolicyDecision shape applied to this line:
// appends into a stack scratch, then logger.Output(depth, string(b)). Frozen as
// the REJECTED alternative. The `string(b)` is the whole story — it allocates
// and copies the entire line, which log.Logger.Printf never does because it
// appends into its own reused buffer.
func sslInnerLineRejectedEmit(clientIP, method, hostOnly, path string, match *PolicyMatch) {
	filter := "off"
	profile := ""
	if match != nil && match.Rule != nil && match.Rule.FileFiltering {
		filter = "on"
		profile = sanitizeLog(string(match.Rule.FileProfile))
	}
	var scratch [sslInnerLineRejectedScratchBufSize]byte
	b := scratch[:0]
	b = append(b, "SSL_INNER "...)
	b = append(b, sanitizeLog(clientIP)...)
	b = append(b, ' ')
	b = append(b, sanitizeLog(method)...)
	b = append(b, ' ')
	b = append(b, sanitizeLog(hostOnly)...)
	b = append(b, sanitizeLog(boundRetainedPath(path))...)
	b = append(b, " (profile="...)
	b = appendQuotedForLog(b, profile)
	b = append(b, " filter="...)
	b = append(b, filter...)
	b = append(b, ')')
	_ = logger.Output(2, string(b))
}

// sslInnerPathLengths spans the live range of the one variable-size operand: a
// short API path, an ordinary CDN asset path, a long asset path, and the 2 KiB
// retention bound itself.
var sslInnerPathLengths = []int{8, 40, 200, 500, 2048}

func sslInnerBenchPath(n int) string {
	if n <= 1 {
		return "/"
	}
	// Dot-and-slash dense, like a real asset path, rather than one long run.
	return "/" + strings.Repeat("seg/", (n-1)/4)
}

const (
	benchSSLInnerIP     = "192.168.11.207"
	benchSSLInnerMethod = "GET"
	benchSSLInnerHost   = "cdn.jsdelivr.net"
)

// BenchmarkSSLInnerLine is the before/after/rejected comparison, swept over
// request-path length.
func BenchmarkSSLInnerLine(b *testing.B) {
	benchSSLInnerLogger(b)
	match := ruleWithProfile("executables")
	for _, n := range sslInnerPathLengths {
		path := sslInnerBenchPath(n)
		name := "Path" + strconv.Itoa(n)
		b.Run(name+"/after", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				logSSLInnerRequest(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, match)
			}
		})
		b.Run(name+"/before", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sslInnerLineLegacyEmit(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, match)
			}
		})
		b.Run(name+"/rejectedStringForm", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sslInnerLineRejectedEmit(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, match)
			}
		})
	}
}

// BenchmarkSSLInnerLine_FilterOff measures the default posture — no file
// filtering on the matched rule, so the profile operand is the empty string and
// the quoting fast path is trivial. Reported separately rather than folded in,
// because it is the shape most deployments actually run.
func BenchmarkSSLInnerLine_FilterOff(b *testing.B) {
	benchSSLInnerLogger(b)
	path := sslInnerBenchPath(40)
	b.Run("after", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			logSSLInnerRequest(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, nil)
		}
	})
	b.Run("before", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sslInnerLineLegacyEmit(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, nil)
		}
	})
}

// BenchmarkSSLInnerLine_NonASCIIProfile exercises the appendQuotedForLog
// FALLBACK (strconv.AppendQuote), so the quoting fast path is not the only
// quoting arm measured.
func BenchmarkSSLInnerLine_NonASCIIProfile(b *testing.B) {
	benchSSLInnerLogger(b)
	match := ruleWithProfile("exé-cutables")
	path := sslInnerBenchPath(40)
	b.Run("after", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			logSSLInnerRequest(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, match)
		}
	})
	b.Run("before", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sslInnerLineLegacyEmit(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, match)
		}
	})
}

// BenchmarkSSLInnerLine_Parallel is the CONCURRENCY shape: an inspecting gateway
// emits this line from one goroutine per inner request (per H1 tunnel loop, per
// H2 stream), so the question is whether the win survives contention — and
// whether the sync.Pool carrier, which is per-P, holds up under it. Run with
// -cpu=1,2,4 to read the scaling rather than a point value.
//
// Neither form scales with cores: both serialise on the same log.Logger mutex,
// and that ceiling belongs to log.Logger, not to this change. What the
// comparison shows is that fewer objects per line means less work inside and
// around that critical section, and that the pool does not add contention of its
// own.
func BenchmarkSSLInnerLine_Parallel(b *testing.B) {
	benchSSLInnerLogger(b)
	match := ruleWithProfile("executables")
	path := sslInnerBenchPath(200)
	b.Run("after", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				logSSLInnerRequest(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, match)
			}
		})
	})
	b.Run("before", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				sslInnerLineLegacyEmit(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, match)
			}
		})
	})
}

// BenchmarkSSLInnerLine_MixedLengths is the STRESS shape: path lengths rotate so
// the pooled carrier is repeatedly grown and reused rather than settling at one
// size. It is the case a fixed-size measurement cannot see — a pool that
// thrashed on a mixed working set would show up here and nowhere else.
func BenchmarkSSLInnerLine_MixedLengths(b *testing.B) {
	benchSSLInnerLogger(b)
	match := ruleWithProfile("executables")
	paths := make([]string, 0, len(sslInnerPathLengths))
	for _, n := range sslInnerPathLengths {
		paths = append(paths, sslInnerBenchPath(n))
	}
	b.Run("after", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			logSSLInnerRequest(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, paths[i%len(paths)], match)
		}
	})
	b.Run("before", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sslInnerLineLegacyEmit(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, paths[i%len(paths)], match)
		}
	})
}

// BenchmarkSSLInnerLine_Render removes the timestamp both forms pay (no flags)
// to show the delta is in the operand formatting, not in the clock or the sink.
func BenchmarkSSLInnerLine_Render(b *testing.B) {
	prev := logger
	logger = log.New(io.Discard, "", 0)
	b.Cleanup(func() { logger = prev })
	match := ruleWithProfile("executables")
	path := sslInnerBenchPath(40)
	b.Run("after", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			logSSLInnerRequest(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, match)
		}
	})
	b.Run("before", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sslInnerLineLegacyEmit(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, match)
		}
	})
}
