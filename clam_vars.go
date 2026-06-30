package main

import "github.com/KidCarmi/Culvert/internal/clamav"

// The ClamAV INSTREAM client moved to internal/clamav (ADR-0002, first scan
// engine out of the cluster). package main keeps the unqualified names here so
// the sole consumer — SecurityScanner.clam (security_scan.go) — stays unchanged.
// The package type is clamav.Client and constructor clamav.New (revive:
// clamav.ClamAV would be repetitive).
type ClamAV = clamav.Client

var NewClamAV = clamav.New
