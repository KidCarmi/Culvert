package main

// threatfeed.go — package-main glue for the local threat-feed manager, moved
// to internal/threatfeed (ADR-0002). The alias shim keeps the scanning
// startup slice, the secscan ThreatChecker wiring, the Control Plane config
// sync, the admin API handlers, and the metrics surfaces using the original
// unqualified names. The engine is a pure leaf: internal/ssrf supplies the
// private-IP table, internal/fileutil the durable writes, and the obs facade
// the logging (obs.Debugf carries the sync-start debug line, gated by main's
// log level via SetLogLevel → obs.SetDebugEnabled).

import "github.com/KidCarmi/Culvert/internal/threatfeed"

// ThreatFeed is re-exposed unqualified (engine type is threatfeed.Feed).
type ThreatFeed = threatfeed.Feed

// globalThreatFeed is the process-wide threat feed instance.
var globalThreatFeed = threatfeed.New()
