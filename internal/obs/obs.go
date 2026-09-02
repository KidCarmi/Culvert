// Package obs is the shared logging facade for internal/* packages (ADR-0003).
// It lets leaf packages emit log lines and sanitise user input without importing
// package main. package main wires the sink once at startup (SetSink) so these
// lines flow into the same rotating/JSON logger; before that, and in unit tests,
// the default sink writes to stderr.
package obs

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
)

// sink is the destination for formatted log lines. Published once at startup by
// package main; read on the proxy hot path, so guarded by an atomic pointer
// (publish-once, mirroring the upstreamTransport pattern) rather than a mutex.
var sink atomic.Pointer[func(string)]

func init() {
	def := func(line string) { fmt.Fprintln(os.Stderr, line) }
	sink.Store(&def)
}

// SetSink publishes the log destination. Call once at startup, before serving
// traffic. A nil fn is ignored. Subsequent calls replace the sink atomically.
func SetSink(fn func(line string)) {
	if fn == nil {
		return
	}
	sink.Store(&fn)
}

func emit(line string) {
	if p := sink.Load(); p != nil {
		(*p)(line)
	}
}

// Printf formats at INFO level and sends the line to the configured sink.
func Printf(format string, args ...any) { emit(fmt.Sprintf(format, args...)) }

// Warnf formats with a WARN prefix and sends the line to the configured sink.
// Note: unlike package main's logWarnf, this does not apply main's runtime
// log-level filter (that state lives in main); internal warnings always emit.
func Warnf(format string, args ...any) { emit("WARN " + fmt.Sprintf(format, args...)) }

// debugEnabled mirrors "main's log level is DEBUG". The level state itself
// stays in package main (same stance as Warnf's note above); main publishes
// the boolean from SetLogLevel. Default is off, so Debugf lines are dropped
// until main first publishes — in production that happens at startup before
// any internal engine runs.
var debugEnabled atomic.Bool

// SetDebugEnabled publishes whether debug-level lines should emit. Called by
// package main's SetLogLevel on every level change.
func SetDebugEnabled(on bool) { debugEnabled.Store(on) }

// Debugf formats with a DEBUG prefix and sends the line to the configured
// sink, but only while debug logging is enabled (SetDebugEnabled).
func Debugf(format string, args ...any) {
	if debugEnabled.Load() {
		emit("DEBUG " + fmt.Sprintf(format, args...))
	}
}

// Sanitize strips control characters from s to prevent log injection (CWE-117).
//
// This is an INDEPENDENT copy of package main's sanitizeLog (proxy.go), kept
// separate on purpose: CodeQL's CWE-117 query recognises the inline
// strings.ReplaceAll sanitiser at each call site, and delegating across a
// package boundary risks losing that recognition. The two copies are tiny and
// each behaviour-tested; the property (no control byte survives) is the contract.
//
// Single-pass for the same reason as its twin: \n, \r and \t are all < 0x20
// and every branch mapped its match to the SAME byte, '_', so the four scans
// were only ever computing "every byte < 0x20 or == 0x7F becomes '_'". The
// newline ReplaceAll stays first — and therefore on every return path — so the
// CodeQL barrier this copy exists to preserve is unchanged. See the extended
// rationale and measurements on sanitizeLog in proxy.go.
func Sanitize(s string) string {
	s = strings.ReplaceAll(s, "\n", "_")
	i := 0
	for ; i < len(s); i++ {
		// C0 controls (0x00-0x1F) and DEL (0x7F).
		if c := s[i]; c < 0x20 || c == 0x7F {
			break
		}
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if c := b[i]; c < 0x20 || c == 0x7F {
			b[i] = '_'
		}
	}
	return string(b)
}
