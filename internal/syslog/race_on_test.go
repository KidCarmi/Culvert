//go:build race

package syslog

// Sets raceDetectorOn when the package's tests are built with -race, so the
// allocation gate can step aside (see TestBenchGate_SyslogLineAllocs).
// Compiled only under -race — the internal/reqlog race_on_test.go pattern.

func init() { raceDetectorOn = true }
