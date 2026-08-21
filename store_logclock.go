package main

// store_logclock.go — the per-request wall-clock stamp for LogEntry.Time.
//
// persistLogEntry is the single chokepoint every request-log record flows
// through: every proxied request that writes a feed entry (HTTP, CONNECT,
// WebSocket, SOCKS5), every TUNNEL_CLOSED accounting row, and every
// SSL-inspected inner request. It rendered the human-readable clock field with
// time.Now().Format("15:04:05") on each call.
//
// That render is the most expensive thing in the function and it is redundant:
// the layout has ONE-SECOND resolution, so at any traffic rate above 1 req/s
// every call inside the same wall-clock second re-derives a string it has
// already produced. Format has to decompose the absolute time into a
// date/clock triple and build a fresh string, and that string is the ONLY
// remaining heap allocation on the whole entry-building path.
//
// Measured on this machine (Go 1.26, 4-core Xeon @ 2.10 GHz, redaction off —
// the default posture):
//
//	time.Now().Format("15:04:05")          117 ns/op    8 B/op    1 alloc/op
//	persistLogEntry (serial)               277 ns/op    8 B/op    1 alloc/op
//	persistLogEntry (4x parallel)          461 ns/op    8 B/op    1 alloc/op
//
// i.e. the clock render alone was ~42% of the serial cost of recording a
// request, for a value that changes once a second.
//
// logClockStamp memoises the render for the current wall-clock second. The
// output is EXACT, not approximate: for a given location, the unix second
// fully determines the "15:04:05" rendering, so a hit returns the identical
// bytes Format would have produced. This is a COST change, not a semantic one.
//
// The cached entry carries its location alongside the second so a caller
// passing a UTC instant can never be served a Local render (or vice versa) —
// the guard costs one pointer compare and removes the whole misuse class.
//
// Cost of a miss: one Format plus one small allocation, at most once per
// wall-clock second per location — negligible GC pressure against the
// per-request allocation it removes.

import (
	"sync/atomic"
	"time"
)

// logEntryTimeLayout is the LogEntry.Time rendering. One-second resolution is
// what makes the memo below exact; changing it to a sub-second layout would
// invalidate the caching contract and must be done at the same time.
const logEntryTimeLayout = "15:04:05"

// logClock is one memoised render of a wall-clock second.
type logClock struct {
	sec int64          // unix second the string renders
	loc *time.Location // location the string was rendered in
	str string         // the rendered logEntryTimeLayout value
}

// logClockCache holds the most recent render. A pointer swap keeps readers
// lock-free on the request path; concurrent misses may both render and both
// store, which is harmless because the value they compute is identical.
var logClockCache atomic.Pointer[logClock]

// logClockStamp renders now in logEntryTimeLayout, reusing the previous render
// when now falls in the same wall-clock second and location. The result is
// byte-identical to now.Format(logEntryTimeLayout).
func logClockStamp(now time.Time) string {
	sec := now.Unix()
	loc := now.Location()
	if c := logClockCache.Load(); c != nil && c.sec == sec && c.loc == loc {
		return c.str
	}
	s := now.Format(logEntryTimeLayout)
	logClockCache.Store(&logClock{sec: sec, loc: loc, str: s})
	return s
}

// resetLogClockCacheForTest drops the memoised render so a test can measure the
// cold path deterministically.
func resetLogClockCacheForTest() { logClockCache.Store(nil) }
