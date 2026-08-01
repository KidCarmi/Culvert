# M7 Slice 2.5-C3 — sealed telemetry golden interoperability vector (`v1`)

> **PUBLIC TEST VECTOR — NOT A SECRET — NEVER USE IN PRODUCTION.**
> The recipient private key in this directory is a deliberately obvious, published
> test scalar (32 bytes of `0x42`). It grants access to nothing, is never loaded by
> production configuration, and is never copied into a production image. It exists
> only to prove cross-repository sealed-box interoperability.

Culvert is the **producer** of the M7 telemetry contract. This directory wraps the
producer-owned §3.3 inner plaintext (`../inner_sample.json`, unchanged) in the §3.2
outer transport envelope, sealed to the public test recipient key above. The
consuming `KidCarmi/tac-platform` repository copies these exact bytes hermetically
(M7 Slice 2.5-C3 PR B) and proves:

```
outer_envelope.json bytes
  → telemetrycontract.DecodeOuter
  → telemetryrecipient.FileRecipientKeyProvider (loads recipient_private_key.bin)
  → telemetrycontract.VerifyAndOpen
  → the exact VerifiedSampleHandle values (== the inner fixture)
```

## Algorithm: raw libsodium `crypto_box_seal`

`algorithm = "x25519-sealbox"` is libsodium `crypto_box_seal`: a **raw** anonymous
X25519 sealed box (`nacl/box.SealAnonymous` — 32-byte ephemeral public key ‖ 16-byte
Poly1305 tag ‖ encrypted plaintext, 48-byte overhead), with **no `CVRTSB01` magic or
version prefix**. The
`CVRTSB01`-framed `internal/sealbox` envelope is the separate M4 support-bundle
export; telemetry uses the raw box, which the merged TAC consumer opens directly
with `box.OpenAnonymous`. Reconciled in roadmap §3.2 in this same change.

## Artifacts

| File | Bytes | SHA-256 |
|---|---|---|
| `outer_envelope.json` | 1036 | `1da22ba2a447dcd8146402cd0623ee97725dcd9a39d218009787c4c8b14fa606` |
| `recipient_private_key.bin` | 32 | `425ed4e4a36b30ea21b90e21c712c649e8214c29b7eaf68089d1039c6e55384c` |
| `recipient_public_key.bin` | 32 | `82dab32a9aedffb4925a762f879f6fdd05b8ba0aa825a6986a85b751ff3b21e4` |
| `manifest.json` | — | (records all of the above; not self-referential) |

The inner plaintext (`../inner_sample.json`) is **476 bytes**, SHA-256
`22df6ee3b323b46332e0073be7925886d6d15121a781165f8ba79b6657549005`.

## Recorded contract

| Field | Value |
|---|---|
| Fixture version | `v1` |
| Producer repository | `KidCarmi/Culvert` |
| `key_id` | `tac-test-telemetry-v1` |
| `algorithm` | `x25519-sealbox` (raw `crypto_box_seal`) |
| `envelope_version` | `1` |
| `schema_version` | `3` |
| `registry_hash` | `061fe684aaabb895e87130943649ef37e450cc62e9d63c6c9d7fddfce73b15a7` |
| `sample_id` | `a1b2c3d4e5f60718293a4b5c6d7e8f90` |
| recipient public key (hex) | `132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472` |
| ciphertext | 524 bytes, SHA-256 `2a664536aea5b4b72abdcd5dc160963c495a9385e27ee9c9ec9235ebb4358eea` |

## Regeneration

The vector is deterministic: the only randomness (the 32-byte ephemeral scalar) is a
fixed documented value (sequential `0x00..0x1f`); the recipient scalar is `32×0x42`.
Regeneration is explicit developer opt-in and never runs in CI:

```
CULVERT_TELEMETRY_SEALED_REGENERATE=1 go test -run TestSealedGoldenRegenerate .
```

`support_telemetry_sealed_golden_test.go` seals the inner fixture in-memory with the
production `nacl/box.SealAnonymous` primitive and compares byte-for-byte with these
checked-in artifacts, so any change to the sealing algorithm, entropy, key, field
order, or JSON encoding fails the golden test.
