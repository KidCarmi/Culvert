//go:build race

package threatfeed

// Sets raceDetectorOn when the package is built with -race, so the
// CheckRequestURL timing gate is skipped — its ~2.3x margin is smaller than the
// variance race instrumentation adds. Compiled only under -race.

func init() { raceDetectorOn = true }
