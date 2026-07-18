# TLS inspection administration

TLS inspection lets Culvert decrypt HTTPS so policy and content scanning can see
inside the tunnel. It is **opt-in per policy rule** (`sslAction: Inspect`) and is
a deliberate act of interception with real legal, privacy, and operational
obligations. This guide covers enabling it safely: the CA lifecycle, client
trust distribution, per-host bypass, Decryption Profiles, and the failure modes
to watch.

Prerequisite reading: [Policy engine](../03-policy/policy-engine.md) (the rule's
`Inspect`/`Bypass` decision) and [Architecture → TLS inspection](../01-overview/architecture.md#tls-inspection-internals).

---

## Purpose

- Decrypt selected HTTPS traffic so DPI, ClamAV, YARA, file-type, and threat
  checks can run on otherwise-encrypted content.
- Keep sensitive destinations (banking, health) private via `Bypass`.
- Manage the internal CA whose leaf certificates make interception possible.

## How inspection works

When a policy rule's TLS action is `Inspect`, Culvert terminates the client TLS
session with an on-the-fly leaf certificate signed by its internal CA, decrypts,
scans, then re-originates TLS to the origin.

- **Leaf certificates:** ECDSA P-256, minted per SNI, cached in a bounded LRU
  (10,000 entries, 1h TTL). The leaf signing key is process-wide, memory-only —
  generated once, never persisted or sent on the wire
  (`internal/ca/ca.go:78-79,763`).
- **CA key at rest:** AES-256-GCM with PBKDF2-SHA256 (600,000 iterations, NIST
  SP 800-132), unlocked by `CULVERT_CA_PASSPHRASE`
  (`internal/ca/ca.go:138,352,358`).

For the full request path, see the sequence diagram in
[Architecture](../01-overview/architecture.md#tls-inspection-internals).

## Prerequisites

- A CA passphrase in `CULVERT_CA_PASSPHRASE` (**required** for the CA to persist
  across restarts; without a path + passphrase the root CA is in-memory only and
  regenerates on restart).
- A CA bundle path (`-ca-path /data/ca.bundle` in the shipped compose file).
- The ability to distribute Culvert's CA certificate to client trust stores.
- An admin/operator account for CA and bypass management.

---

## Configuration procedure

### 1. Provision the CA

Set the passphrase and CA path, then start Culvert:

```bash
export CULVERT_CA_PASSPHRASE='choose-a-strong-passphrase'
./culvert -port 8080 -ui-port 9090 -ca-path /data/ca.bundle
```

The shipped Docker image supplies `-ca-path /data/ca.bundle` on the container
command line; provide `CULVERT_CA_PASSPHRASE` via the environment/`.env`.

Inspect CA status at any time:

| Route | Method | Purpose |
|---|---|---|
| `/api/ca/status` | GET | CA info, leaf-cache stats, rotation and dual-CA state |
| `/api/ca/download` | GET | Download the CA certificate (PEM) |
| `/api/ca-cert` | GET | CA certificate for client distribution |
| `/api/ca/key-provider` | GET | Key-provider status |
| `/api/certs/upload` | POST | Upload a custom CA bundle |
| `/api/ca/cache-clear` | POST | Clear the leaf-certificate cache |
| `/api/ca/rotate` | POST | Force CA rotation |

(Registered in `ui_security.go:1323-1354`.)

### 2. Distribute the CA to clients

Every client whose traffic will be inspected must trust Culvert's CA, or it will
see certificate errors. Download the CA (`/api/ca/download` or the **Security**
panel) and install it into the OS/browser trust store or push it via MDM/GPO.
Clients that pin certificates (some apps, mobile) will still fail — bypass those
destinations.

### 3. Enable inspection on a policy rule

Inspection is turned on per rule, not globally. Set `sslAction: Inspect` on the
rules whose traffic you want decrypted (see [Policy engine](../03-policy/policy-engine.md)):

```json
{ "priority": 10, "name": "inspect-web", "destFQDN": "*",
  "action": "Allow", "sslAction": "Inspect" }
```

### 4. Bypass sensitive destinations

Rules can carry `sslAction: Bypass` to tunnel a destination without decryption.
Global per-host bypass patterns are managed via `/api/ssl-bypass`
(`ui_security.go:1325`) and the **Security** panel. Scope bypass narrowly
(exact/wildcard FQDNs) — a broad bypass creates an inspection blind spot.

---

## Decryption Profiles — the "how"

A **Decryption Profile** is a named, reusable object a rule references to control
*how* a tunnel is inspected: native HTTP/2 vs HTTP/1.1 downgrade, upstream
certificate verification, TLS floor/cap, and per-stream stall timeout. Every
field defaults to **inherit**, so a rule with no profile behaves exactly as
before. Manage them at `/api/decryption-profiles` (`ui_policy.go:2171`).

Full field reference and honest scope notes (including anti-bot caveats and the
TLS-floor drop behavior) are in the operator guide
[`../../../docs/operator/decryption-profiles.md`](../../../docs/operator/decryption-profiles.md)
and [`../../../docs/operator/http2-inspection.md`](../../../docs/operator/http2-inspection.md).

> **Some profile postures are Planned.** `permissive` certificate verification
> and `fail-open` on unsupported TLS are marked *coming soon* in the code; today
> the postures are `strict`/`skip` verification and `fail-close`
> (`docs/operator/decryption-profiles.md`, `internal/decryptprofile/decryptprofile.go:50-76`).

## Adaptive decryption exclusions (fail-open, opt-in)

When a Decryption Profile opts into `OnInspectError: fail-open`, Culvert keeps a
bounded, **volatile in-memory** cache of hosts it could not decrypt, so
subsequent CONNECTs to those hosts bypass inspection instead of failing. The
cache is scoped per profile, learns only from narrow, specific signals, and is
never persisted or synced. This is off by default (the default is `fail-close`).

Manage and observe it at `/api/decryption-exclusions` (list/evict) and
`/api/decryption/health` (coverage aggregate); tuning is at
`/api/decryption-exclusions/tunables` (`ui_policy.go:2172-2174`). Full behavior:
[`../../../docs/operator/decryption-auto-exclusions.md`](../../../docs/operator/decryption-auto-exclusions.md).

## CA rotation

- **Automatic:** a background loop checks CA expiry and rotates before it lapses,
  for both the local and cluster CA (`StartCAAutoRotation`, `ca.go:59-63`). A
  rotation increments `culvert_ca_rotations_total`.
- **Forced:** `POST /api/ca/rotate` rotates on demand (break-glass / key
  compromise).
- On any root-CA change the client-facing TLS ticket key rotates, ending the
  prior resumption epoch — clients must full-handshake and are re-presented a
  leaf signed by the new CA (`docs/architecture.md` §2). After rotation,
  redistribute the new CA if you rotated the root identity.

---

## Validation steps

With an `Inspect` rule active and the CA trusted by the client:

```bash
# Through the proxy; -v shows the presented cert issuer = Culvert's CA
curl -x http://localhost:8080 https://example.com -o /dev/null -w '%{http_code}\n'
```

Confirm via `/api/ca/status` that the leaf cache is populating, and check
`culvert_decrypt_*` metrics / `/api/decryption/health` for inspection coverage.

## Failure modes

| Condition | Behavior | Watch |
|---|---|---|
| Client does not trust Culvert's CA | Client-side certificate error | Distribute the CA |
| Origin pins certificates (app/mobile) | Handshake fails under inspection | Bypass the destination |
| Origin TLS can't be inspected, profile `fail-close` (default) | Tunnel dropped (`502`) | `culvert_decrypt_*` |
| `Min TLS Version` floor above what the origin offers | Inspect handshake fails; tunnel dropped | `culvert_decrypt_profile_mintls_reject_total{profile}` |
| Upstream cert untrusted/expired, `strict` verification | Blocked | — |
| No CA passphrase / path | Root CA is in-memory only; regenerates on restart | Set `CULVERT_CA_PASSPHRASE` + `-ca-path` |

## Security implications

- Inspection reads decrypted user traffic. Ensure legal/HR sign-off, user
  notice, and scoped bypass for regulated categories (banking, health).
- The CA is a trust anchor installed on clients — protect the passphrase and CA
  bundle; treat `/api/ca/download` and `/api/certs/upload` as sensitive admin
  operations.
- `tlsSkipVerify` (per rule) disables upstream verification — use only for
  known-broken internal origins.

## Known limitations

- `permissive` certificate verification and `fail-open`-on-unsupported-TLS are
  *coming soon* (see above); today's postures are `strict`/`skip` and
  `fail-close`.
- Adaptive exclusion entries are volatile — cleared on restart, never synced
  CP→DP.
- Inspection re-originates TLS with Go's stack, so it does not preserve the
  client's TLS fingerprint (JA3/JA4); destinations that fingerprint the
  ClientHello may still challenge even under native HTTP/2 inspection
  (`docs/operator/decryption-profiles.md`).

## Related documentation

- [Policy engine](../03-policy/policy-engine.md) · [Architecture](../01-overview/architecture.md).
- In-repo operator guides:
  [`decryption-profiles.md`](../../../docs/operator/decryption-profiles.md),
  [`http2-inspection.md`](../../../docs/operator/http2-inspection.md),
  [`decryption-auto-exclusions.md`](../../../docs/operator/decryption-auto-exclusions.md),
  [`key-at-rest.md`](../../../docs/operator/key-at-rest.md).

## Source evidence

Claim-evidence ledger: [`tls-inspection.evidence.md`](tls-inspection.evidence.md).
