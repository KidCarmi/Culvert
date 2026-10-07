package main

// listener_fault_class.go — CHAOS-71: ONE bounded fault vocabulary for every
// TCP listener this process binds.
//
// Why this file exists.
//
// Culvert supervises three listeners whose bind can fail for the same reasons
// on the same kind of socket — the admin UI (CHAOS-57), SOCKS5 (CHAOS-66) and
// now the Control Plane gRPC server (CHAOS-71) — and each had, or was about to
// get, its own verbatim copy of the same classifier. `classifySOCKS5BindError`
// says so in its own comment:
//
//	The class set deliberately mirrors classifyAdminUIListenError's — it is
//	the same fault on the same kind of socket, and one vocabulary across both
//	listeners is what lets an operator read either runbook.
//
// That intent is right and a copy is the wrong way to hold it. The two copies
// already share a defect history: CHAOS-66 found that the `network_error`
// branch was unreachable-by-accident in the permissive direction —
// `*net.OpError` satisfies `net.Error` UNCONDITIONALLY (`Timeout()` is false
// for a bind EINVAL), so every unrecognised errno was reported as a network
// fault, sending an operator down a network-troubleshooting path for a socket
// or permission fault, while `listen_failed` could only be reached by an error
// the net package had NOT produced. Both copies carried it and both had to be
// fixed in the same change. A third copy triples that exposure, and the
// repository has already recorded the general rule for exactly this shape when
// `internal/storeguard` was extracted so `internal/logstore` could reuse
// `internal/catdb`'s recovery engine: *do not re-inline or re-copy the engine*
// — an empirical fault table is pinned by a test precisely so a dependency
// change that reworded a message fails the build, and a second copy is how that
// protection rots.
//
// So the mapping lives here ONCE and the three planes delegate to it. What each
// plane keeps is its own PRE-CHECK for faults only it can have (the admin UI's
// certificate material, the CP's TLS material), because those are genuinely
// per-plane and must not leak into a shared table.
//
// Three rules the shared form must keep.
//
//  1. The vocabulary is BOUNDED and the set is CLOSED. These strings reach an
//     alert's Detail, and `Store.Dispatch` dedups on `event + ":" + Detail`, so
//     an unbounded reason gives the dedup key one value per failure and the
//     fan-out evicts real threat alerts from the 500-entry retry queue (the
//     WK-12/RS-5 defect). They also reach viewer-role surfaces, so a class must
//     never embed the listener address or a server-supplied string.
//
//  2. Matching is `errors.As` on `syscall.Errno`, NEVER on the error text. net
//     wraps as `*net.OpError{*os.SyscallError{syscall.Errno}}` and the text is
//     platform-specific — the CHAOS-54 rule.
//
//  3. `network_error` requires an actual TIMEOUT. See the defect above; the
//     qualified form is the whole reason this branch can be trusted, and the
//     gate that missed it passed a bare `errors.New`, which is the one shape
//     that does reach `listen_failed`.

import (
	"errors"
	"net"
	"syscall"
)

// listenerFaultClasses is the CLOSED set of classes classifyListenerFault can
// return. It exists so a test can assert the vocabulary is bounded without
// re-deriving the switch — a reviewer reading a runbook and a reviewer reading
// the classifier must be looking at the same list.
//
// `none` is included because every caller's "no error" path maps here, and
// omitting it would make the closed-set gate reject a legitimate return.
var listenerFaultClasses = []string{
	"none",
	"port_in_use",
	"permission_denied",
	"address_unavailable",
	"descriptors_exhausted",
	"network_error",
	"listen_failed",
}

// classifyListenerFault maps a listener bind/serve error onto one of
// listenerFaultClasses.
//
// It deliberately knows nothing about any individual plane: a plane with a
// fault only it can have (TLS material, for instance) tests for that FIRST and
// calls this for everything else. Adding a plane-specific class here would put
// one listener's vocabulary on another's runbook.
func classifyListenerFault(err error) string {
	if err == nil {
		return "none"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EADDRINUSE:
			return "port_in_use"
		case syscall.EACCES, syscall.EPERM:
			return "permission_denied"
		case syscall.EADDRNOTAVAIL:
			return "address_unavailable"
		case syscall.EMFILE, syscall.ENFILE:
			return "descriptors_exhausted"
		}
	}
	// Qualified with Timeout() — see rule 3 in the file header. An unqualified
	// errors.As(&ne) here swallows every unrecognised errno into a class that
	// names the wrong subsystem.
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "network_error"
	}
	return "listen_failed"
}
