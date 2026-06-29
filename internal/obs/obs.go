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

// Sanitize strips control characters from s to prevent log injection (CWE-117).
//
// This is an INDEPENDENT copy of package main's sanitizeLog (proxy.go), kept
// separate on purpose: CodeQL's CWE-117 query recognises the inline
// strings.ReplaceAll sanitiser at each call site, and delegating across a
// package boundary risks losing that recognition. The two copies are tiny and
// each behaviour-tested; the property (no control byte survives) is the contract.
func Sanitize(s string) string {
	s = strings.ReplaceAll(s, "\n", "_")
	s = strings.ReplaceAll(s, "\r", "_")
	s = strings.ReplaceAll(s, "\t", "_")
	// Fast path: nothing else to scrub.
	if !containsControl(s) {
		return s
	}
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		// C0 controls (0x00-0x1F) and DEL (0x7F). \n, \r, \t already replaced above.
		if c < 0x20 || c == 0x7F {
			b[i] = '_'
			continue
		}
		b[i] = c
	}
	return string(b)
}

func containsControl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7F {
			return true
		}
	}
	return false
}
