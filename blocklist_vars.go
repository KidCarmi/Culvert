package main

// blocklist_vars.go — package-main glue for the host blocklist engine, moved
// to internal/blocklist (ADR-0002, store.go decomposition Phase A). The alias
// shim keeps the proxy/SOCKS5 hot path, the admin API handlers, the cluster
// snapshot apply, config versioning/export, and the blocklistfeed Merger
// adapter using the original unqualified names.

import "github.com/KidCarmi/Culvert/internal/blocklist"

// Blocklist and BlocklistEntry are re-exposed unqualified (engine types are
// blocklist.Store / blocklist.Entry).
type (
	Blocklist      = blocklist.Store
	BlocklistEntry = blocklist.Entry
)

// bl is the process-wide blocklist.
var bl = blocklist.New()
