//go:build !unix

package main

// probeRosterParent: there is no side-effect-free write-capability check
// (faccessat, statfs) here, so the parent is not re-checked live on this
// platform — a known gap. The row still reports a refused save through the
// write evidence, which the next refused admin change records.
func probeRosterParent(string) string { return "" }
