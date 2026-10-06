package main

// listener_error_class.go — the ONE socket-error classifier shared by every
// listener health plane (CHAOS-73).
//
// Why this file exists.
//
// Three listener planes in this tree answer the same question — "why could this
// TCP listener not come up?" — and until this file there were two independent
// copies of the answer, with a third about to be written:
//
//	classifyAdminUIListenError  (admin_ui_health.go, CHAOS-57)
//	classifySOCKS5BindError     (socks5_health.go,   CHAOS-66)
//
// The duplication is not hypothetical harm. CHAOS-66 found the SAME defect in
// BOTH copies and had to fix it twice in one change: `*net.OpError` satisfies
// `net.Error` UNCONDITIONALLY (`Timeout()` is false for a bind EINVAL), so an
// unqualified `errors.As(err, &ne)` branch reported every unrecognised errno as
// a network fault — sending an operator down a network-troubleshooting path for
// a socket or permission fault — while making `listen_failed` reachable only by
// an error the net package had NOT produced. Both shipped gates passed exactly
// that one unreachable shape. `classifySOCKS5BindError`'s own comment records
// the intent that makes a shared implementation the right answer: *"The class
// set deliberately mirrors classifyAdminUIListenError's — it is the same fault
// on the same kind of socket, and one vocabulary across both listeners is what
// lets an operator read either runbook."*
//
// So this is the `internal/storeguard` lesson applied one subsystem over: when
// a fault→message table has been got wrong once in every copy of it, a further
// copy is how the protection rots. The errno switch and the `network_error`
// timeout rule live here ONCE; each plane keeps only the branch that is
// genuinely its own (the admin UI's operator-supplied TLS pair, the Control
// Plane's gRPC credentials) and delegates the rest.
//
// The class set is a BOUNDED vocabulary and that is a security property, not
// tidiness. Every one of these strings reaches an alert `Detail`, which
// `alerts.Store.Dispatch` dedups on `event + ":" + Detail` — a raw error embeds
// the listener address, so an unbounded class mints one dedup key per failure
// and the fan-out evicts real threat alerts from the retry queue (the
// WK-12/RS-5 defect). They also reach the VIEWER-role `/api/diagnostics` rows,
// which must not carry internal addresses. The full error goes to the
// rate-limited log line and nowhere else.
//
// Matched with `errors.As` on `syscall.Errno`, never by string: net wraps a
// bind failure as `*net.OpError{Err: *os.SyscallError{Err: syscall.Errno}}` and
// the text is platform-specific (the CHAOS-54 rule).

import (
	"errors"
	"net"
	"syscall"
)

// classifyListenerSocketError maps a TCP listener bind/serve failure to a
// bounded reason class, or returns ("", false) when the error is not one of the
// socket faults this vocabulary covers — which is the caller's cue to try its
// own domain-specific branches before falling back to `listen_failed`.
//
// The two-value return is deliberate. A single-value form would have to pick
// between returning `listen_failed` (which swallows the caller's chance to
// classify its own TLS-material error — the admin UI plane's one real branch)
// and returning "" (which is not a class any surface should ever print). The
// boolean keeps the composition explicit at each call site.
func classifyListenerSocketError(err error) (string, bool) {
	if err == nil {
		return "none", true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EADDRINUSE:
			return "port_in_use", true
		case syscall.EACCES, syscall.EPERM:
			return "permission_denied", true
		case syscall.EADDRNOTAVAIL:
			return "address_unavailable", true
		case syscall.EMFILE, syscall.ENFILE:
			return "descriptors_exhausted", true
		}
	}
	return "", false
}

// classifyListenerNetworkError reports whether err is a genuine network
// TIMEOUT, the one condition that earns the `network_error` class.
//
// Kept as its own function, and applied LAST by every caller, because this is
// precisely the predicate CHAOS-66 had to narrow in two files: the test for
// `net.Error` must be qualified by `Timeout()`, or `*net.OpError`'s
// unconditional satisfaction of that interface makes this branch absorb every
// unrecognised errno.
func classifyListenerNetworkError(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
