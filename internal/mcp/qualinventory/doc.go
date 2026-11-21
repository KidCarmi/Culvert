// Package qualinventory owns the QUAL-2 qualification inventory document: the
// bounded read of the operator-supplied file, the strict decode, the field
// validation and the seeding of one Gateway qualification fleet into a FRESH
// registry/catalog pair (IM-023, ADR-0055).
//
// Seeding never writes Registry or Catalog internals. Every server goes
// through registry.Register and registry.VerifyIdentity (which must confirm
// the exact accepted VerifyVerified state), and every tool through
// catalog.Ingest, the operator-seeded entrypoint: it recomputes the existing
// fingerprint from the tool's own bounded schema and lands the tool
// Quarantined. A seeded tool is KNOWN inventory, never automatically trusted
// for execution, and it carries no peer observation. This package must never
// name catalog.IngestObserved; the root provenance wall
// (TestPeerWall_SeedReachesOnlyTheSeededEntrypoint) pins that.
//
// Loading is ALL-OR-NOTHING: Seed returns either a complete pair or an error
// and no pair. Errors are fixed phrases; they never carry a path, an
// identity, a credential or file content.
//
// Ownership: package main owns the startup configuration that names the
// file, the decision that a disabled or file-less listener gets an empty
// pair, the not_configured / loaded / invalid state, the published holder,
// the Admin API adapters and the fail-closed activation. This package owns
// only the document and the pair it returns to the caller. It holds no
// package-level state, starts no goroutine, logs nothing, and its only I/O is
// the one bounded read of the path it is handed.
package qualinventory
