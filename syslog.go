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
// unqualified references (the writer handle, the coverage test's constructor)
// stay unchanged.
type syslogWriter = syslog.Writer

// syslogDeliveryOutcome is the package-main alias for the engine's delivery
// event (CHAOS-66), so syslog_health.go need not import internal/syslog.
type syslogDeliveryOutcome = syslog.DeliveryOutcome

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
	// CHAOS-66: the engine is a stdlib-only leaf that can neither log nor alert,
	// so the health plane learns about a dead collector through this seam —
	// from the delivery EVENT, not from whoever happens to scrape next. Wired
	// here rather than at each call site so every Writer this process builds,
	// startup and runtime reconfigure alike, reports.
	sw.SetDeliveryObserver(noteSyslogDelivery)
	return sw, nil
}

// activeSyslogPtr holds the active syslog writer; nil when syslog is not
// configured.
//
// An ATOMIC pointer rather than a plain global (CHAOS-66). `recordRequest` and
// `auditEvent` read this on the REQUEST path, while `apiSyslogConfig` replaces
// it from an admin HTTP goroutine — an unsynchronised write against a
// per-request read, and the disable branch (`Close()` then nil) makes the
// window one where a request goroutine can be holding the pointer being
// retired. The practical outcome was benign (a line delivered to a Closed
// Writer is counted as a drop), but it is a data race by the memory model, and
// this sweep adds three more readers (the contract row, /metrics, /healthz) to
// it. Widening a known race to report on the subsystem that owns it is not an
// acceptable trade.
var activeSyslogPtr atomic.Pointer[syslogWriter]

// activeSyslog returns the current writer, or nil when forwarding is off.
func activeSyslog() *syslogWriter { return activeSyslogPtr.Load() }

// setActiveSyslog publishes a writer (nil disables forwarding).
func setActiveSyslog(sw *syslogWriter) { activeSyslogPtr.Store(sw) }

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
	// Publish the target to the health record and clear its latches before the
	// writer goes live, so the first delivery event already has somewhere to
	// land (see armSyslogFeedHealth).
	armSyslogFeedHealth(addr)
	setActiveSyslog(sw)
	logger.Printf("Syslog: forwarding to %s://%q (format=%s)", network, sanitizeLog(target), sanitizeLog(sw.Format()))
	return nil
}
