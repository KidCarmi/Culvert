//go:build unix && !linux && !darwin

package main

// statfsReadOnly: the statfs flag layout differs across the BSDs, so the
// read-only mount is detected here only through faccessat's EROFS.
func statfsReadOnly(string) (bool, error) { return false, nil }
