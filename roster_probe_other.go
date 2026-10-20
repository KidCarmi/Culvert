//go:build !unix

package main

// probeRosterParent: there is no side-effect-free write-capability check
// (faccessat, statfs) here, so the parent is not re-checked live on this
// platform. The probe is advisory everywhere (see roster_probe_unix.go): a
// refused save is reported through the refused/degraded counters, which the
// next read of the row shows.
func probeRosterParent(string) string { return "" }
