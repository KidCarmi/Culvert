package threatfeed

// raceDetectorOn is set true by the //go:build race companion file
// racedetector_race_test.go. The race detector inflates timing measurements by
// roughly an order of magnitude and widens their variance past the margin the
// CheckRequestURL timing gate measures, so that gate is skipped under -race
// while the deterministic allocation gate beside it still applies.
//
// Same shape as stress_helpers_test.go in package main, which skips its
// RSS-based leak assertion under -race for the same reason.
var raceDetectorOn = false
