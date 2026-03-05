package main

import (
	"log"
	"os"
	"testing"
)

// TestMain initializes globals that proxy code expects before any test runs.
func TestMain(m *testing.M) {
	logger = log.New(os.Stderr, "[test] ", 0)
	os.Exit(m.Run())
}
