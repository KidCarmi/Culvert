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
	releaseReplacedSyslogWriter(globalSyslog)
	globalSyslog = sw
	noteSyslogWriterInstalled(sw, addr)
	logger.Printf("Syslog: forwarding to %s://%q (format=%s)", network, sanitizeLog(target), sanitizeLog(sw.Format()))
	return nil
}

// releaseReplacedSyslogWriter closes the Writer that InitSyslog is about to
// replace (CHAOS-66).
//
// Overwriting globalSyslog used to be the whole handover, which stranded the
// old Writer's drain goroutine parked forever on a queue nobody can reach any
// more, holding its collector socket OPEN. Measured against the pre-fix tree:
// +1 goroutine and +1 file descriptor per re-init, with the connection to the
// abandoned collector still ESTABLISHED (no EOF at the far end) — a phantom
// session that many SIEMs count against a per-source connection licence.
//
// This is NOT only an admin-triggered path. main.go runs initObservability
// (YAML/flags) at step 206 and initPersistentAdminState → LoadAdminSettings →
// applyAdminServices at step 240, and snapshotAdminEndpoints persists
// syslogConfigured into admin_settings.json — so once an operator saves any
// admin setting, EVERY SUBSEQUENT BOOT calls InitSyslog twice and leaks the
// first Writer. FD exhaustion is the recorded terminal state of WK-11/PX-6.
//
// The close is ASYNCHRONOUS on purpose. Writer.Close is self-bounded (it waits
// at most closeWait for the drain to flush) but that bound is ~7s against a
// wedged collector, and the collector being replaced is — by the nature of the
// operation — the one the operator has decided is broken. Paying that
// synchronously would let a dead SIEM stall the boot (before the proxy
// listener is up) or the admin request that is fixing it. Close is idempotent
// and releases the socket itself when its write deadline fires, so nothing
// here needs to wait for it.
func releaseReplacedSyslogWriter(old *syslogWriter) {
	if old == nil {
		return
	}
	go func() { _ = old.Close() }()
}
