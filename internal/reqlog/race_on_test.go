//go:build race

package reqlog

// Sets raceDetectorOn when the package's tests are built with -race, so the
// ns/op timing gate can step aside (see TestBenchGate_PersistGateBeatsLegacy).
// Compiled only under -race — the internal/threatfeed race_on_test.go pattern.

func init() { raceDetectorOn = true }
