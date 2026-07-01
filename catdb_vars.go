package main

import "github.com/KidCarmi/Culvert/internal/catdb"

// CommunityDB (Layer-2 community URL category store, BadgerDB-backed) moved to
// internal/catdb (ADR-0002), which contains the Badger dependency. package main
// keeps the process-wide singleton and the unqualified names here so the
// consumers — policy.go (Lookup), feedsync.go (*CommunityDB field, BulkWrite),
// main.go (open/close), ui_policy.go (nil check) — and the black-box tests stay
// unchanged. No new exported API.
type CommunityDB = catdb.CommunityDB

// communityDB is the process-wide community category store.
// Nil when disabled (no --cat-feed-db flag supplied).
var communityDB *CommunityDB

// openCommunityDB is re-exposed unqualified (the package constructor is
// catdb.Open, renamed from openCommunityDB for idiomatic catdb.Open usage).
func openCommunityDB(dir string) (*CommunityDB, error) {
	return catdb.Open(dir)
}
