//go:build race && (proxystress || proxybinload || benchgate)

package main

// Sets raceDetectorOn when the suite is built with -race, so the RSS-based leak
// assertion is skipped (the race detector's shadow memory makes RSS growth
// meaningless). Compiled only under -race.

func init() { raceDetectorOn = true }
