# API Deprecation Policy

How to retire an operation, field, or behavior without breaking consumers.

## Lifecycle

`stable` → `deprecated` → `removed`

An element must be **deprecated for at least one MINOR release** (and appear in
one CHANGELOG) before it can be removed. Removal is a breaking change and follows
the exception process in `API-VERSIONING-POLICY.md`.

## Marking something deprecated

- Set `deprecated: true` on the operation or schema/property in the contract.
- Add a `x-culvert-deprecated-since` (contract version) and, where known,
  `x-culvert-removal-target` (earliest version it may be removed).
- Update the `description` with the replacement and migration steps.
- Add a CHANGELOG entry under a `Deprecated` heading.
- The style-lint gate requires deprecation metadata on any `deprecated: true`
  element (deep-lane rule; see follow-up backlog).

## Runtime signalling (recommended, additive)

When a deprecated endpoint is served, emit a `Deprecation: true` response header
(RFC 8594) and, if a removal date is known, a `Sunset` header. This is additive
and backward-compatible; add it via middleware, not per-handler.

## Legacy aliases

Culvert has intentional legacy path aliases (e.g. `/api/content-scan` →
`/api/dpi`, `/proxy.pac` → `/pac/default.pac`). These are **documented, not
deprecated for removal** — they exist for compatibility. Classify them in the
manifest and, if documented, note the canonical path in the operation description.

## Removal checklist

- [ ] Deprecated for ≥1 MINOR release with CHANGELOG evidence.
- [ ] Consumers notified / migration guide published.
- [ ] `api-breaking-approved` label + named CODEOWNERS approver.
- [ ] MAJOR contract version bump.
- [ ] Route removed from `uiRoutes`, the contract, and the classification manifest
      in the same PR (the coverage gate enforces consistency).
