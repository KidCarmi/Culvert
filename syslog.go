package main

// syslog.go — package-main bootstrap for SIEM syslog forwarding. The Writer
// engine moved to internal/syslog (ADR-0002); this file keeps the global, the
// shim alias + constructor, and InitSyslog (URL parsing + startup logging) where
// the logger/sanitizeLog coupling belongs.

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/syslog"
)

// syslogWriter is the package-main alias for the relocated engine so existing
// unqualified references (the globalSyslogHandle declaration, the coverage test's
// constructor) stay unchanged.
type syslogWriter = syslog.Writer

// newSyslogWriter constructs a syslog Writer. Thin wrapper over syslog.NewWriter
// kept for InitSyslog and the integration test that builds a writer directly.
// Wires the panic observer here (the internal/syslog package is a stdlib-only
// leaf and cannot log for itself) so every Writer this process constructs —
// startup and runtime reconfigure alike — reports a recovered delivery panic
// to the process log, which is what the SIEM-forwarding admin panel's warning
// tells the operator to check.
func newSyslogWriter(network, addr, format string) (*syslogWriter, error) {
	sw, err := syslog.NewWriter(network, addr, format)
	if err != nil {
		return nil, err
	}
	sw.SetPanicObserver(func(recovered any) {
		logger.Printf("ERROR syslog: recovered panic in delivery goroutine (line dropped): %q", sanitizeLog(fmt.Sprintf("%v", recovered)))
	})
	return sw, nil
}

// globalSyslogHandle holds the active syslog writer; nil when syslog is not
// configured. It is an atomic.Pointer, not a plain variable, for two reasons
// that the plain variable got wrong (CHAOS-78, closing §42 OBS-1).
//
// It is WRITTEN at runtime from the admin handler goroutine (InitSyslog below,
// via the apiSyslogConfig POST; the disable branch stores nil) and READ on the
// proxy request path at every request-log record (store.go's persistLogEntry
// chokepoint) and on the audit SIEM hook (store.go's audit.SetSIEM closure).
// As a plain variable the nil check and the dereference were two separate
// unsynchronized loads of the same global, so a request goroutine could pass
// the check and then dereference the nil the disable branch had just stored —
// a data race whose crash the proxy crash guard contains per request, but
// which still aborts an in-flight request or tunnel over a routine
// "disable SIEM forwarding" click.
//
// The second reason is the one a nil guard would NOT have fixed. The engine
// sets its queue in startAsync, AFTER the struct literal (internal/syslog), and
// treats a nil queue as "deliver synchronously" — a path that holds the
// writer's mutex across up to two 5 s dials and two 5 s writes. A plain
// pointer write carries no release edge, so on a weakly ordered target (this
// appliance ships linux/arm64) a request goroutine could observe a non-nil
// writer whose queue was still zero, fall into that synchronous path, and pay
// ~15 s on the data path with every other logging caller queued behind it —
// precisely the proxy-wide stall the async design and the engine's own
// TestAsync_WedgedCollectorNeverBlocksCaller exist to prevent, reached not
// through the engine but through the pointer holding it.
//
// atomic.Pointer's Store/Load is the release/acquire edge that closes both, and
// it is what this codebase already does for every other hot-path-read,
// runtime-reconfigured global: globalLogStore (logstore.go), logSink
// (logger.go), obs.sink (internal/obs) and the syslog engine's own
// panicObserver. The pointer holding the engine was the one left plain.
//
// Access it through syslogHandle/setSyslogHandle, never directly: a caller that
// needs both a nil check and a method call must hold ONE loaded value in a
// local, which is what those helpers make the natural thing to write.
// TestChaos78_Wall_SyslogHandleIsAtomic pins the declaration.
var globalSyslogHandle atomic.Pointer[syslogWriter]

// syslogHandle loads the active syslog writer, or nil when forwarding is off.
//
// Read it ONCE into a local and use that local for both the nil test and every
// subsequent call. Two syslogHandle() calls in one expression are two separate
// loads and reintroduce exactly the window this type exists to close.
func syslogHandle() *syslogWriter { return globalSyslogHandle.Load() }

// setSyslogHandle publishes sw as the active writer and returns the writer it
// displaced, or nil if there was none. The caller owns closing the returned
// writer: the engine's drainLoop exits ONLY via Close, so a displaced writer
// that is never closed leaks its delivery goroutine and its collector socket
// for the life of the process (CHAOS-78).
func setSyslogHandle(sw *syslogWriter) (displaced *syslogWriter) {
	return globalSyslogHandle.Swap(sw)
}

// InitSyslog parses addr and initialises the global syslog writer.
// Supported addr formats:
//
//	udp://10.0.0.1:514       (default protocol when scheme is omitted)
//	tcp://logs.corp.com:601
//
// syslogFmt selects the message format: "rfc3164" (default) or "rfc5424".
func InitSyslog(addr, syslogFmt string) error {
	if addr == "" {
		return nil
	}
	network := "udp"
	target := addr
	switch {
	case strings.HasPrefix(addr, "tcp://"):
		network = "tcp"
		target = strings.TrimPrefix(addr, "tcp://")
	case strings.HasPrefix(addr, "udp://"):
		target = strings.TrimPrefix(addr, "udp://")
	}
	sw, err := newSyslogWriter(network, target, syslogFmt)
	if err != nil {
		return err
	}
	// Publish first, then release the writer this one displaces, so request
	// goroutines move to the new writer before the old one is torn down and no
	// line is delivered to a writer already past Close. Closing it is not
	// optional: drainLoop exits only via Close, so the previous
	// writer's goroutine and collector socket would otherwise leak on every
	// runtime SIEM retarget (CHAOS-78). Post-Close sends are already safe —
	// the engine drops and counts them rather than touching a closed channel.
	if displaced := setSyslogHandle(sw); displaced != nil {
		_ = displaced.Close() // best-effort flush; bounded by the engine's closeWait
	}
	logger.Printf("Syslog: forwarding to %s://%q (format=%s)", network, sanitizeLog(target), sanitizeLog(sw.Format()))
	return nil
}
