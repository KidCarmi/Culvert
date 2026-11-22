package listenfault

import (
	"errors"
	"net"
	"syscall"
)

// Reason maps a bind or serve error to a bounded reason class: "none" for a
// nil error, the errno class when the error's chain carries a recognised errno
// (see ErrnoReason), "network_error" when it timed out (see TimedOut), and
// "listen_failed" otherwise. The errno is tested before the timeout.
//
// A listener with stage tags of its own composes ErrnoReason and TimedOut
// with its tag tests in the order its contract requires.
func Reason(err error) string {
	if err == nil {
		return "none"
	}
	if reason, ok := ErrnoReason(err); ok {
		return reason
	}
	if TimedOut(err) {
		return "network_error"
	}
	return "listen_failed"
}

// ErrnoReason reports the class of the first syscall.Errno in err's chain:
// "port_in_use" (EADDRINUSE), "permission_denied" (EACCES, EPERM),
// "address_unavailable" (EADDRNOTAVAIL) or "descriptors_exhausted" (EMFILE,
// ENFILE). ok is false when the chain carries no errno or the errno is none of
// these; a later errno in the chain is not consulted.
func ErrnoReason(err error) (reason string, ok bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return "", false
	}
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
	return "", false
}

// TimedOut reports whether err's chain carries a net.Error whose Timeout() is
// true. Being a net.Error is not enough: see the package comment.
func TimedOut(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
