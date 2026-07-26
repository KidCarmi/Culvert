# M7 telemetry golden fixture — `v1` inner plaintext (producer-owned)

`inner_sample.json` is the versioned golden fixture for the **inner sealed
plaintext** of the M7 telemetry wire contract
(`roadmap/M7-proactive-telemetry-plan.md` §3.3).

## Ownership

**Culvert produces this shape, so Culvert owns this fixture.**

The bytes are the exact output of Culvert's real production serialization path —
nothing here is hand-written or re-implemented:

```go
supportmetrics.Registry.BuildSample(now, epoch, sequence)   // internal/supportmetrics/sample.go
json.Marshal(supportmetrics.Sample)                         // → Sample.MarshalJSON
```

`Sample.MarshalJSON` is the authoritative producer of the complete §3.3 inner
plaintext. The fixture is generated from a **clone of the live production
registry** (`supportMetricRegistry`, `support_telemetry_registry.go`) with every
governed descriptor field preserved — id, type, privacy class, telemetry
eligibility, justification, bucket ladders — and **only** each descriptor's
`Read` callback replaced with a fixed deterministic value. That is why the
fixture's `registry_hash` is the **real** production hash: `Registry.Hash()`
never invokes `Read`, so swapping `Read` cannot move the hash.

> The hash covers the §8 subset of the governed schema — `ID`, `Type`,
> `PrivacyClass`, `TelemetryEligible`, `Buckets`. `InSupportBundle` and
> `TelemetryReason` are preserved by the clone and asserted separately, but are
> deliberately **not** hashed: editing a justification string is not a
> wire-contract change.

`KidCarmi/tac-platform` **consumes a copy** of these exact bytes in its
telemetry-gateway contract work (TAC `2.5-A`). It must never invent its own
inner-plaintext fixture.

## Recorded contract metadata

This metadata is deliberately **outside** the fixture JSON — none of it is part
of the wire protocol. It is mirrored as test-owned constants in
`support_telemetry_golden_fixture_test.go`, and
`TestTelemetryGoldenFixtureREADMEMatchesRecordedMetadata` asserts this table
against those constants and against the real bytes, so this document cannot go
stale while the suite is green.

| Field | Value |
|---|---|
| Fixture version | `v1` |
| Producer repository | `KidCarmi/Culvert` |
| Producer baseline SHA | `a689cc59cf9e62955338026a85e3b1dcf104ae12` |
| `schema_version` | `3` |
| `registry_hash` | `061fe684aaabb895e87130943649ef37e450cc62e9d63c6c9d7fddfce73b15a7` |
| Fixture SHA-256 | `22df6ee3b323b46332e0073be7925886d6d15121a781165f8ba79b6657549005` |
| Size | 476 bytes, compact JSON, **no trailing newline** |

The baseline SHA identifies the `main` commit whose **registry schema** produced
these bytes (it is the branch point, so it does not itself contain the fixture).
`registry_hash` is the reproducible schema identity; the SHA is the
human-readable pointer to it.

Fixed inputs used to generate it:

| Input | Value |
|---|---|
| `generated_at` | `2026-07-24T12:00:00Z` |
| `sample_epoch` | `0123456789abcdef0123456789abcdef` |
| `sequence` | `42` |

## What the vector does and does not cover

The eight metric values exercise mixed valid states — health gauges at both `1`
and `0`, and non-zero coarse bucket indices. All are **small integral**
`float64`, which is everything the current registry can emit (boolean health
gauges plus bucket indices).

A consumer should therefore **not** read this vector as evidence that fractional
values (`0.5`), exponent-form numbers (`1e+21`), or negative values are
untested — they are simply not reachable from the v1 registry. `metrics` values
are JSON numbers, not integers: a consumer must parse them as floating point.

Byte-exactness is defined by `json.Marshal` (**476 bytes, no trailing
newline**), not by `json.Encoder.Encode`, which appends `\n`. Any future
component that must reproduce this plaintext byte-for-byte has to use
`json.Marshal`.

## Scope — what this fixture is NOT

`v1` is the **inner plaintext only**. It deliberately contains no outer
transport-envelope fields (`envelope_version`, `key_id`, `algorithm`,
`ciphertext`, `ciphertext_sha256`, `sample_id`), no encryption, no TAC key, and
no credential.

**Sealed outer-envelope fixtures remain deferred to TAC `2.5-C`.** Culvert
**Slice 3** (the only egress slice) stays **blocked** until the full TAC
telemetry gateway ships and the cross-repository golden test passes
(`M7-proactive-telemetry-plan.md` §13). Landing this fixture does not unblock
Slice 3.

## Cross-repository copy contract

Both repositories stay **hermetic**: no git submodule, no runtime dependency, no
network fetch, no cross-repository test dependency. `tac-platform` copies the
**exact bytes** of `inner_sample.json` into its own tree and verifies the
recorded SHA-256 above.

Consequently, any change that alters these bytes — the wire shape, a field
spelling, the JSON number or timestamp representation, `supportmetrics.SchemaVersion`,
the registry schema (a descriptor added/removed, a type/privacy/eligibility
flip, a bucket-threshold edit), or the telemetry-eligible metric set — is a
**cross-repository contract change**, not a local edit. It must be made as one
coordinated change in both repositories.

## Regenerating (explicit developer opt-in only)

Ordinary test runs never rewrite this file. To regenerate deliberately:

```bash
CULVERT_TELEMETRY_FIXTURE_REGENERATE=1 go test -run TestTelemetryGoldenFixtureRegenerate .
go test -run TestTelemetryGoldenFixture .   # that command runs the WRITER ONLY — verify separately
```

The regeneration path refuses to run when `CI`, `GITHUB_ACTIONS`,
`CONTINUOUS_INTEGRATION`, or `BUILD_NUMBER` is set, refuses to write
non-deterministic bytes, and prints the follow-up checklist (update the recorded
constants, this table, and the coordinated `tac-platform` copy).
