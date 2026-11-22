package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
)

// listenerBindReasonCases is the error corpus the four listener classifiers
// are compared over: every errno 0..255 in the shapes a bind, an accept and a
// certificate-file read produce, each of the three stage tags wrapping those
// shapes, and the timeout and non-errno shapes. The order is fixed, so the
// digest below is reproducible.
func listenerBindReasonCases() []error {
	sys := func(e syscall.Errno) error {
		return &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", e)}
	}
	file := func(e syscall.Errno) error {
		return &os.PathError{Op: "open", Path: "/etc/culvert/tls.key", Err: e}
	}
	tags := []error{errAdminUITLSMaterial, errCPGRPCTLSMaterial, errCPGRPCAddressPublish}
	cases := []error{nil, errors.New("something else entirely")}
	for n := 0; n < 256; n++ {
		e := syscall.Errno(n)
		cases = append(cases, e, sys(e), file(e), fmt.Errorf("serve: %w", sys(e)))
		for _, tag := range tags {
			cases = append(cases,
				fmt.Errorf("%w: %w", tag, file(e)),
				fmt.Errorf("load: %w", fmt.Errorf("%w: %w", tag, sys(e))))
		}
	}
	timeouts := []error{
		cpTimeoutErr{},
		&net.OpError{Op: "accept", Net: "tcp", Err: cpTimeoutErr{}},
		os.ErrDeadlineExceeded,
		context.DeadlineExceeded,
		// A timeout whose chain also carries a known errno: the errno wins.
		fmt.Errorf("%w: %w", cpTimeoutErr{}, sys(syscall.EADDRINUSE)),
	}
	for _, te := range timeouts {
		cases = append(cases, te)
		for _, tag := range tags {
			cases = append(cases, tag, fmt.Errorf("%w: %w", tag, te))
		}
	}
	return cases
}

// TestListenerBindReasons_VerdictTableUnchanged pins every verdict of the four
// listener classifiers over the corpus above. The digest and the per-class
// counts were captured by running this same test over the four root
// classifiers on main ef9431189, before their shared errno and timeout rules
// moved to internal/listenfault, so a changed verdict on any listener for any
// case fails here.
func TestListenerBindReasons_VerdictTableUnchanged(t *testing.T) {
	classifiers := []struct {
		name string
		fn   func(error) string
	}{
		{"admin_ui", classifyAdminUIListenError},
		{"socks5", classifySOCKS5BindError},
		{"scan_svc", classifyScanSvcBindError},
		{"cp_grpc", classifyCPGRPCBindError},
	}
	h := sha256.New()
	counts := map[string]int{}
	cases := listenerBindReasonCases()
	for i, err := range cases {
		for _, c := range classifiers {
			got := c.fn(err)
			counts[c.name+"/"+got]++
			fmt.Fprintf(h, "%d|%s|%s\n", i, c.name, got)
		}
	}
	if runtime.GOOS != "linux" {
		t.Skip("errno numbering is platform-specific; the digest is pinned for linux")
	}
	const wantDigest = "ef44677296e7572e49892882110a1dcf94f90c191ec671ab9286a498ed97225e"
	if got := hex.EncodeToString(h.Sum(nil)); got != wantDigest {
		t.Errorf("verdict digest over %d cases = %s, want %s\ncounts: %v", len(cases), got, wantDigest, counts)
	}
	for k, want := range listenerBindReasonWantCounts {
		if counts[k] != want {
			t.Errorf("count[%s] = %d, want %d", k, counts[k], want)
		}
	}
	if len(counts) != len(listenerBindReasonWantCounts) {
		t.Errorf("classes seen = %v, want exactly %v", counts, listenerBindReasonWantCounts)
	}
}

// listenerBindReasonWantCounts is the per-listener class histogram of the
// corpus, captured with the digest. The admin UI and Control Plane rows differ
// on purpose: the admin UI classifier tests the errno before its stage tag and
// the Control Plane classifier tests its tags first (see each binding).
var listenerBindReasonWantCounts = map[string]int{
	"admin_ui/none": 1, "admin_ui/port_in_use": 14, "admin_ui/permission_denied": 20,
	"admin_ui/address_unavailable": 10, "admin_ui/descriptors_exhausted": 20,
	"admin_ui/tls_certificate": 509, "admin_ui/network_error": 28, "admin_ui/listen_failed": 1995,

	"socks5/none": 1, "socks5/port_in_use": 14, "socks5/permission_denied": 20,
	"socks5/address_unavailable": 10, "socks5/descriptors_exhausted": 20,
	"socks5/network_error": 36, "socks5/listen_failed": 2496,

	"scan_svc/none": 1, "scan_svc/port_in_use": 14, "scan_svc/permission_denied": 20,
	"scan_svc/address_unavailable": 10, "scan_svc/descriptors_exhausted": 20,
	"scan_svc/network_error": 36, "scan_svc/listen_failed": 2496,

	"cp_grpc/none": 1, "cp_grpc/port_in_use": 8, "cp_grpc/permission_denied": 12,
	"cp_grpc/address_unavailable": 6, "cp_grpc/descriptors_exhausted": 12,
	"cp_grpc/tls_certificate": 522, "cp_grpc/address_publish_rejected": 522,
	"cp_grpc/network_error": 20, "cp_grpc/listen_failed": 1494,
}
