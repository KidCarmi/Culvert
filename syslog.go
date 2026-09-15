package main

// syslog.go — package-main bootstrap for SIEM syslog forwarding. The Writer
// engine moved to internal/syslog (ADR-0002); this file keeps the global, the
// shim alias + constructor, and InitSyslog (URL parsing + startup logging) where
// the logger/sanitizeLog coupling belongs.

import (
	"fmt"
	"strings"

	"github.com/KidCarmi/Culvert/internal/syslog"
)

// syslogWriter is the package-main alias for the relocated engine so existing
// unqualified references (the globalSyslog declaration, the coverage test's
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
	// CHAOS-66: the delivery-transition observer, wired at the same single
	// construction chokepoint and for the same leaf-package-cannot-log reason.
	// Without it a collector that dies after a successful connect drops every
	// audit and request record with no log line, no metric movement and no
	// alert — see syslog_health.go.
	sw.SetDeliveryObserver(noteSyslogDelivery)
	return sw, nil
}

// globalSyslog is the active syslog writer; nil when syslog is not configured.
var globalSyslog *syslogWriter

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
	globalSyslog = sw
	// Arms the health plane for this Writer. A reconfigure builds a NEW Writer,
	// so the episode gates are reset with it: the previous collector's episode
	// says nothing about the new one.
	noteSyslogConfigured(sw)
	logger.Printf("Syslog: forwarding to %s://%q (format=%s)", network, sanitizeLog(target), sanitizeLog(sw.Format()))
	if !sw.DeliveryConfirmable() {
		// Said once, at the one moment an operator is looking at this decision.
		// A UDP feed cannot report a dead collector: NewWriter succeeds against
		// one, and every line is written into the void with no error and no
		// drop counted. The health plane reports this honestly rather than
		// claiming a delivery guarantee it cannot make.
		logger.Printf("Syslog: WARNING — UDP cannot confirm delivery; a dead collector accepts every line silently and no drop is counted. Use tcp:// if the audit trail needs delivery assurance.")
	}
	return nil
}
