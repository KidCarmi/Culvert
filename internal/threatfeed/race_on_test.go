//go:build race

package threatfeed

// Sets raceDetectorOn when the package's tests are built with -race, so the
// ns/op timing gate can step aside (see TestBenchGate_CheckRequestURLBeatsLegacy).
// Compiled only under -race — the stress_helpers_race_test.go pattern.

func init() { raceDetectorOn = true }
