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
	wireSyslogObservers(sw)
	return sw, nil
}

// wireSyslogObservers attaches the process-log and health-plane seams every
// Writer this process constructs must carry. internal/syslog is a stdlib-only
// leaf (its header contract) and can neither log nor alert for itself, so a
// Writer built without this is a forwarder whose failures are invisible —
// which is why it is one function called from every constructor rather than
// repeated at each call site.
func wireSyslogObservers(sw *syslogWriter) {
	sw.SetPanicObserver(func(recovered any) {
		logger.Printf("ERROR syslog: recovered panic in delivery goroutine (line dropped): %q", sanitizeLog(fmt.Sprintf("%v", recovered)))
	})
	sw.SetStateObserver(func(up bool, reason string, changed bool) {
		noteSyslogDeliveryState(sw, up, reason, changed)
	})
}

// activeSyslog holds the active syslog writer; nil when syslog is not
// configured.
//
// CHAOS-66: this was a plain package-level pointer, WRITTEN from the admin
// goroutine (`POST /api/syslog` and the boot-time admin-settings apply) and
// READ from the request path on every proxied request (store.go's
// recordRequest) and every audit event (store.go's audit SIEM hook). That is
// an unsynchronised concurrent read/write of a pointer — a data race by the
// Go memory model, confirmed by the race detector against the real
// InitSyslog. It survived because no test drove a reconfigure and traffic at
// the same time, which is exactly the shape of an ordinary SIEM migration on
// a live gateway.
//
// An atomic pointer costs the request path the same instruction as the plain
// load it replaces. Read through activeSyslog(), write through
// setActiveSyslog() — there is deliberately no exported variable, so the
// racy form cannot be reintroduced by a new caller.
var activeSyslogPtr atomic.Pointer[syslogWriter]

// activeSyslog returns the live syslog writer, or nil when forwarding is off.
func activeSyslog() *syslogWriter { return activeSyslogPtr.Load() }

// setActiveSyslog installs w as the live writer and returns the predecessor it
// displaced, which the caller MUST release (see releaseSyslogWriter).
func setActiveSyslog(w *syslogWriter) *syslogWriter { return activeSyslogPtr.Swap(w) }

// releaseSyslogWriter closes a displaced writer.
//
// CHAOS-66: InitSyslog used to assign over globalSyslog without closing what
// it replaced, so every install leaked the predecessor's drain goroutine AND
// its open collector connection — permanently, because nothing else held the
// pointer and the goroutine parks forever on a queue nobody sends to.
// Measured: five InitSyslog calls, five leaked goroutines and five still-open
// TCP connections. It is reachable twice on an ordinary boot (the YAML slice
// then the persisted admin settings) and once per `POST /api/syslog`, i.e.
// unbounded by operator action — the WK-11 descriptor-exhaustion class on an
// admin-reachable path.
//
// The close runs on its own goroutine because Close waits up to closeWait
// (~7s) for the drain to flush what is already queued. Doing that inline
// would put a wedged collector's flush window on the BOOT path and on an
// admin request; dropping the flush instead would discard queued compliance
// lines that are still deliverable. The goroutine count is bounded by the
// number of reconfigures and each one is bounded by closeWait.
func releaseSyslogWriter(old *syslogWriter) {
	if old == nil {
		return
	}
	go func() { _ = old.Close() }()
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
	network, target := parseSyslogAddr(addr)
	sw, err := newSyslogWriter(network, target, syslogFmt)
	if err != nil {
		return err
	}
	installSyslogWriter(sw)
	logger.Printf("Syslog: forwarding to %s://%q (format=%s)", network, sanitizeLog(target), sanitizeLog(sw.Format()))
	return nil
}

// InitSyslogResilient installs a SELF-HEALING forwarder for addr: the first
// dial is attempted but is not required to succeed, and a failure is returned
// for logging rather than leaving forwarding off.
//
// CHAOS-66: this is the boot path. InitSyslog fails closed on the first dial
// and both boot callers (loadObservability, applyAdminServices) log-and-
// continue with no writer, and nothing ever constructs another one — so a
// collector that was down at boot, or merely slower to start than the proxy
// beside it in the same compose file, meant SIEM forwarding was OFF for the
// entire life of the process. Detection existed (the `syslog_feed` contract
// row); recovery did not, and the row's own remedy was "re-save the target or
// restart the proxy". Every other periodic or listening subsystem in this
// tree now retries at a bounded rate (CHAOS-54, -55, -57, -59); the SIEM feed
// was the one that gave up permanently on a single transient fault.
//
// Validating an operator's TYPED target is a separate question and keeps its
// own answer: `POST /api/syslog` probes before installing, so a typo is still
// refused up front (see apiSyslogConfig).
func InitSyslogResilient(addr, syslogFmt string) error {
	if addr == "" {
		return nil
	}
	network, target := parseSyslogAddr(addr)
	sw, dialErr := syslog.NewWriterDeferred(network, target, syslogFmt)
	wireSyslogObservers(sw)
	installSyslogWriter(sw)
	if dialErr != nil {
		return dialErr
	}
	logger.Printf("Syslog: forwarding to %s://%q (format=%s)", network, sanitizeLog(target), sanitizeLog(sw.Format()))
	return nil
}

// installSyslogWriter publishes w and releases whatever it displaced.
func installSyslogWriter(w *syslogWriter) {
	releaseSyslogWriter(setActiveSyslog(w))
}

// parseSyslogAddr splits an operator-supplied target into transport + address.
// A bare host:port means UDP — the historical default, and the reason
// DeliveryVerifiable exists.
func parseSyslogAddr(addr string) (network, target string) {
	network, target = "udp", addr
	switch {
	case strings.HasPrefix(addr, "tcp://"):
		return "tcp", strings.TrimPrefix(addr, "tcp://")
	case strings.HasPrefix(addr, "udp://"):
		return "udp", strings.TrimPrefix(addr, "udp://")
	}
	return network, target
}
