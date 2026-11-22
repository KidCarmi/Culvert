package listenfault

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
)

// timeoutErr is a net.Error that timed out; plainNetErr is one that did not.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

type plainNetErr struct{}

func (plainNetErr) Error() string   { return "not a timeout" }
func (plainNetErr) Timeout() bool   { return false }
func (plainNetErr) Temporary() bool { return true }

var (
	_ net.Error = timeoutErr{}
	_ net.Error = plainNetErr{}
)

// bindErr is the shape net.Listen returns for a failed bind.
func bindErr(e syscall.Errno) error {
	return &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", e)}
}

// referenceReason is the classifier as it stood in package main before the
// move (socks5_health.go classifySOCKS5BindError and scan_svc_listener.go
// classifyScanSvcBindError on main ef9431189, which were identical). It is
// the oracle the differential test compares Reason against.
func referenceReason(err error) string {
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
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "network_error"
	}
	return "listen_failed"
}

// corpus is every errno 0..4095 in the shapes a listener sees, plus the
// timeout and non-errno shapes.
func corpus() []error {
	errs := []error{
		nil,
		errors.New("something else entirely"),
		timeoutErr{},
		plainNetErr{},
		&net.OpError{Op: "accept", Net: "tcp", Err: timeoutErr{}},
		&net.OpError{Op: "accept", Net: "tcp", Err: plainNetErr{}},
		os.ErrDeadlineExceeded,
		context.DeadlineExceeded,
		context.Canceled,
		net.ErrClosed,
		fmt.Errorf("%w: %w", timeoutErr{}, bindErr(syscall.EADDRINUSE)),
		fmt.Errorf("%w: %w", bindErr(syscall.EINVAL), timeoutErr{}),
	}
	for n := 0; n < 4096; n++ {
		e := syscall.Errno(n)
		errs = append(errs,
			e,
			bindErr(e),
			&os.PathError{Op: "open", Path: "/etc/culvert/tls.key", Err: e},
			fmt.Errorf("serve: %w", bindErr(e)),
			fmt.Errorf("%w: %w", errors.New("stage tag"), bindErr(e)),
		)
	}
	return errs
}

func TestReason_AgreesWithThePreMoveClassifier(t *testing.T) {
	seen := map[string]int{}
	for i, err := range corpus() {
		got, want := Reason(err), referenceReason(err)
		if got != want {
			t.Errorf("case %d: Reason(%v) = %q, pre-move classifier says %q", i, err, got, want)
		}
		seen[got]++
	}
	for _, class := range []string{
		"none", "port_in_use", "permission_denied", "address_unavailable",
		"descriptors_exhausted", "network_error", "listen_failed",
	} {
		if seen[class] == 0 {
			t.Errorf("the corpus never produced %q, so the comparison does not cover it", class)
		}
	}
	if len(seen) != 7 {
		t.Errorf("classes produced = %v, want exactly the seven documented ones", seen)
	}
}

func TestReason_Classes(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "none"},
		{"in use", bindErr(syscall.EADDRINUSE), "port_in_use"},
		{"denied", bindErr(syscall.EACCES), "permission_denied"},
		{"not permitted", bindErr(syscall.EPERM), "permission_denied"},
		{"no addr", bindErr(syscall.EADDRNOTAVAIL), "address_unavailable"},
		{"process fds", bindErr(syscall.EMFILE), "descriptors_exhausted"},
		{"system fds", bindErr(syscall.ENFILE), "descriptors_exhausted"},
		{"bare errno", syscall.EADDRINUSE, "port_in_use"},
		{"timeout", &net.OpError{Op: "accept", Err: timeoutErr{}}, "network_error"},
		{"unrecognised errno", bindErr(syscall.EINVAL), "listen_failed"},
		{"no errno", errors.New("something else entirely"), "listen_failed"},
		{"net error without timeout", plainNetErr{}, "listen_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Reason(tc.err); got != tc.want {
				t.Errorf("Reason(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestReason_UnrecognisedErrnoIsNotANetworkError carries the premise check of
// the root CHAOS-66 gate: if a Go release changes either fact about
// *net.OpError, this says which.
func TestReason_UnrecognisedErrnoIsNotANetworkError(t *testing.T) {
	err := bindErr(syscall.EINVAL)
	var ne net.Error
	if !errors.As(err, &ne) {
		t.Fatal("premise changed: *net.OpError no longer satisfies net.Error")
	}
	if ne.Timeout() {
		t.Fatal("premise changed: a bind EINVAL now reports Timeout() true")
	}
	if TimedOut(err) {
		t.Error("TimedOut(bind EINVAL) = true: a net.Error that did not time out was called a timeout")
	}
	if got := Reason(err); got != "listen_failed" {
		t.Errorf("Reason(bind EINVAL) = %q, want %q", got, "listen_failed")
	}
}

func TestReason_ErrnoWinsOverTimeout(t *testing.T) {
	err := fmt.Errorf("%w: %w", timeoutErr{}, bindErr(syscall.EADDRINUSE))
	if !TimedOut(err) {
		t.Fatal("fixture does not time out")
	}
	if got := Reason(err); got != "port_in_use" {
		t.Errorf("Reason = %q, want the errno class %q", got, "port_in_use")
	}
}

func TestErrnoReason_ReportsOnlyRecognisedErrnos(t *testing.T) {
	recognised := map[syscall.Errno]string{
		syscall.EADDRINUSE:    "port_in_use",
		syscall.EACCES:        "permission_denied",
		syscall.EPERM:         "permission_denied",
		syscall.EADDRNOTAVAIL: "address_unavailable",
		syscall.EMFILE:        "descriptors_exhausted",
		syscall.ENFILE:        "descriptors_exhausted",
	}
	for n := 0; n < 4096; n++ {
		e := syscall.Errno(n)
		got, ok := ErrnoReason(bindErr(e))
		want, known := recognised[e]
		if ok != known || got != want {
			t.Errorf("ErrnoReason(errno %d) = %q, %v; want %q, %v", n, got, ok, want, known)
		}
	}
	for _, err := range []error{nil, errors.New("no errno"), timeoutErr{}} {
		if got, ok := ErrnoReason(err); ok || got != "" {
			t.Errorf("ErrnoReason(%v) = %q, %v; want \"\", false", err, got, ok)
		}
	}
}

// TestErrnoReason_ConsultsTheFirstErrnoOnly pins the chain rule each root
// classifier had: errors.As stops at the first errno, and an unrecognised
// first errno is not skipped in favour of a recognised later one.
func TestErrnoReason_ConsultsTheFirstErrnoOnly(t *testing.T) {
	first := fmt.Errorf("%w: %w", bindErr(syscall.EINVAL), bindErr(syscall.EADDRINUSE))
	if got, ok := ErrnoReason(first); ok {
		t.Errorf("ErrnoReason = %q, true; want false because the first errno is EINVAL", got)
	}
	second := fmt.Errorf("%w: %w", bindErr(syscall.EACCES), bindErr(syscall.EADDRINUSE))
	if got, _ := ErrnoReason(second); got != "permission_denied" {
		t.Errorf("ErrnoReason = %q, want the first errno's class %q", got, "permission_denied")
	}
}

func TestTimedOut(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"timeout", timeoutErr{}, true},
		{"wrapped timeout", fmt.Errorf("accept: %w", &net.OpError{Op: "accept", Err: timeoutErr{}}), true},
		{"deadline", os.ErrDeadlineExceeded, true},
		{"net error, no timeout", plainNetErr{}, false},
		{"bind errno", bindErr(syscall.EADDRINUSE), false},
		{"closed listener", net.ErrClosed, false},
		{"plain", errors.New("plain"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := TimedOut(tc.err); got != tc.want {
				t.Errorf("TimedOut(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestReason_ConcurrentCallersAgree runs the classifier from many goroutines
// under -race: the package holds no state, so every caller sees the same
// answer for the same error.
func TestReason_ConcurrentCallersAgree(t *testing.T) {
	errs := corpus()[:512]
	want := make([]string, len(errs))
	for i, err := range errs {
		want[i] = Reason(err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i, err := range errs {
				if got := Reason(err); got != want[i] {
					t.Errorf("case %d: concurrent Reason = %q, want %q", i, got, want[i])
				}
			}
		}()
	}
	wg.Wait()
}
