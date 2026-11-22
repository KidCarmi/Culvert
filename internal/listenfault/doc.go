// Package listenfault names why a listener could not bind or stopped serving
// (ADR-0058). It maps an error to one of a small fixed set of reason classes.
// It holds no state, performs no I/O and does no logging.
//
// Ownership: package main owns each listener's supervisor, its health record,
// the alert, the log line and the operator remedy text. Each listener keeps
// its own classifier function, which decides the order in which its own stage
// tags (a certificate-load failure, a rejected address publish) are tested
// against the rules here. This package owns the two rules every listener
// shares: which errno is which class, and what counts as a network timeout.
//
// # Why the class is bounded
//
// The reason reaches two places that must not carry a raw error. The alert
// store deduplicates on the event and its detail, and a bind error's text
// embeds the listener address, so a raw error would create one alert key per
// failure. The operator-contract row is readable by the viewer role and must
// not carry internal addresses or configured paths. The full error goes to a
// rate-limited log line in main and nowhere else.
//
// # Errnos are matched by value
//
// The net package wraps a bind failure as *net.OpError over *os.SyscallError
// over syscall.Errno, and the message text differs by platform. The class is
// found with errors.As on syscall.Errno and never by matching text.
//
// # A timeout is required for network_error
//
// *net.OpError satisfies net.Error for every bind failure, with Timeout()
// false for an errno such as EINVAL. Testing only for net.Error would report
// every unrecognised errno as a network fault and make listen_failed
// unreachable for any error the net package produced. TimedOut therefore
// requires Timeout() to be true.
package listenfault
