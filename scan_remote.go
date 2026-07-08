package main

// scan_remote.go — package-main glue for the remote scan client, moved to
// internal/secscan (ADR-0006). The alias shim keeps the proxy pipeline, the
// sidecar server (scan_svc.go shares the ScanResponse wire type), and the
// test suite using the original unqualified names.

import "github.com/KidCarmi/Culvert/internal/secscan"

// RemoteScanner / ScanResponse re-exposed unqualified (engine types are
// secscan.RemoteScanner / .ScanResponse).
type (
	RemoteScanner = secscan.RemoteScanner
	ScanResponse  = secscan.ScanResponse
)

// globalRemoteScanner is the process-wide remote scanner, disabled until the
// scanning startup slice calls Init.
var globalRemoteScanner = &RemoteScanner{}
