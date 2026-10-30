# ADR-0042: The ClientHello ALPN parser is owned by internal/alpnpeek

- Status: Proposed for review with the implementation PR (IM-001, 2026-10-30).
- Numbering: checked `docs/adr/`, `docs/support/rfc/` and the open-PR file
  inventories; ADR-0040 is held by the open #1526 and 0041 is merged, so this
  takes 0042.
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), internal
  migration program, task IM-001. Related: ADR-0002 (stdlib leaves), ADR-0037
  and ADR-0041 (engine extraction pattern).

## Context

`inspect_h2_alpn.go` held a read-only, bounds-checked parser that extracts the
offered ALPN list from a buffered plaintext TLS ClientHello, plus the `h2`
membership predicate. It had no state, no I/O, no logging and imported nothing,
yet its white-box tests and fuzz target compiled the whole application package.

## Decision

Move the parser into `internal/alpnpeek` with two exported identifiers:
`Parse(buf) (protos, ok)` and `OffersH2(protos)`. The parser logic, its security
posture comment (moved into `doc.go`), its tests (names unchanged) and
`FuzzParseClientHelloALPN` move without change.

- **Main keeps the decision.** `peekClientALPN` in `proxy_tunnel_h2.go` owns the
  `bufio.Peek` window and the `["http/1.1"]` fail-closed fallback. The two call
  sites use `alpnpeek.Parse` and `alpnpeek.OffersH2`. No root alias is kept: no
  other production or test code referenced the old names.
- **The package is an import-free leaf.** `TestAlpnpeekBoundary_*` fails on any
  import, package variable or `init`, with negative controls.

## Consequences

- `go test ./internal/alpnpeek` runs the parser gates and the fuzz target without
  the application. The non-root lane finds the package through `go list ./...`.
- No behavior, wire or persistence change.
- Owner follow-up (outside the pilot's no-gate-change rule): `fuzz-nightly.yml`
  is a hand-maintained matrix that never included this target; add
  `{ target: FuzzParseClientHelloALPN, pkg: "./internal/alpnpeek" }`.

## Alternatives

- **Leave it in main.** Rejected: it is an engine-only leaf and the cheapest
  proof of the extraction mechanism.
