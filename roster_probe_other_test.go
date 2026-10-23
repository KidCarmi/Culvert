//go:build !unix

package main

import "testing"

var errEACCES, errEROFS error

func injectParentAccess(t *testing.T, _ error) {
	t.Skip("no live parent write-capability check on this platform (roster_probe_other.go)")
}

func injectParentReadOnly(t *testing.T) {
	t.Skip("no live parent write-capability check on this platform (roster_probe_other.go)")
}
