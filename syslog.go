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
	// CHAOS-66: the delivery observer is wired for the same leaf-package-cannot-
	// log reason as the panic observer, and on every Writer this process builds
	// (startup and runtime reconfigure alike) so a reconfigure never silently
	// drops the health plane. It is edge-triggered, so a healthy feed pays
	// nothing; see internal/syslog.SetDeliveryObserver.
	sw.SetDeliveryObserver(noteSyslogDelivery)
	return sw, nil
}

// globalSyslog is the active syslog writer; nil when syslog is not configured.
var globalSyslog *syslogWriter

// retireSyslogWriter releases a writer that is being REPLACED.
//
// InitSyslog used to overwrite globalSyslog without closing the previous
// writer, leaking its drain goroutine, its collector socket and up to queueCap
// queued lines on every re-point. That is reachable on an ordinary boot, not
// just an admin edit: observability initialises from YAML/flags and admin
// settings then applies a persisted override, so a node with a saved SIEM
// target constructed two writers and kept both.
//
// With CHAOS-66's delivery observer that stopped being merely a leak and became
// a CORRECTNESS bug: a superseded writer still pointed at a dead collector keeps
// failing, keeps calling noteSyslogDelivery, and would drive the health plane —
// which now describes the NEW writer — into a permanent failure episode,
// reporting a healthy feed as down. So the observers are cleared FIRST, and
// clearing them is the load-bearing half; closing the socket is hygiene.
//
// Close is asynchronous because it blocks for up to closeWait (~7s) draining
// against a collector that may be exactly the wedged one being replaced, and
// the caller here is an admin request. Nothing depends on the old writer's
// flush completing: its lines are best-effort by contract, and the operator has
// just asked for a different destination.
func retireSyslogWriter(old *syslogWriter) {
	if old == nil {
		return
	}
	old.SetDeliveryObserver(nil)
	old.SetPanicObserver(nil)
	go old.Close() //nolint:errcheck // best-effort release; the new writer is already live
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
	retireSyslogWriter(globalSyslog)
	globalSyslog = sw
	// Arm the delivery health plane before announcing success: the writer is
	// already draining, so a collector that fails on the very first line must
	// find the episode state initialised.
	noteSyslogConfigured()
	logger.Printf("Syslog: forwarding to %s://%q (format=%s)", network, sanitizeLog(target), sanitizeLog(sw.Format()))
	// A UDP dial sends nothing and succeeds against an address where nothing is
	// listening, so "connected" is not evidence of anything on the default
	// transport (CHAOS-66). Say so once, at the point the operator chose it,
	// rather than letting every later surface imply a delivery guarantee the
	// transport cannot provide. Same shape as the OCSP coverage warning.
	if network == "udp" {
		logger.Printf("WARN syslog: the collector is addressed over UDP — delivery is UNVERIFIABLE (a write to an unreachable collector succeeds forever, so loss cannot be counted). Use tcp:// for a feed whose health this appliance can actually report; confirm receipt at the collector after POST /api/syslog/test.")
	}
	return nil
}
