//go:build unix

package main

import (
	"syscall"
	"testing"
)

var errEACCES, errEROFS error = syscall.EACCES, syscall.EROFS

func injectParentAccess(t *testing.T, err error) {
	t.Helper()
	prev := rosterParentAccess
	rosterParentAccess = func(string) error { return err }
	t.Cleanup(func() { rosterParentAccess = prev })
}

func injectParentReadOnly(t *testing.T) {
	t.Helper()
	prev := rosterParentReadOnly
	rosterParentReadOnly = func(string) (bool, error) { return true, nil }
	t.Cleanup(func() { rosterParentReadOnly = prev })
}
