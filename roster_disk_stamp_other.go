//go:build !linux && !darwin

package main

import "os"

// inodeStamp is never known here: on Windows and the other platforms the row
// compares the roster's size and SHA-256 (and owner, on Unix) only, so a
// change that leaves the bytes identical — a touch, a chmod, an identical
// re-copy, an ACL or label change — is not detected on them.
type inodeStamp struct{ known bool }

func stampOf(os.FileInfo) inodeStamp { return inodeStamp{} }
