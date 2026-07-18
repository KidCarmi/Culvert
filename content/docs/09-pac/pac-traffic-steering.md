# PAC traffic steering

A Proxy Auto-Configuration (PAC) file tells browsers and OS proxy clients which
requests to send through Culvert and which to send direct. Culvert generates and
serves a PAC file from your configuration, so you can steer traffic —
including bypassing internal destinations — without touching every client.

Prerequisite reading: [Quick start](../02-getting-started/quick-start.md).

---

## Purpose

Distribute a single, authoritative proxy-routing policy to clients via a URL,
and exclude destinations (internal domains, RFC 1918 ranges) that should go
direct.

## How it works

Clients fetch `FindProxyForURL(url, host)` from Culvert and evaluate it per
request. Culvert compiles the PAC from your config
(`internal/pac/compile.go`), with these deliberate properties:

- **Only `PROXY` and `DIRECT` directives** are emitted — the broadly compatible
  subset understood by Windows WinINET/WinHTTP's JScript engine
  (`compile.go:13`).
- **DNS is resolved at most once per evaluation**, after the DNS-free rules run
  (`compile.go:14`) — keeping client-side evaluation cheap.
- **Exclusions steer to `DIRECT`:** configured domain and CIDR exclusions bypass
  the proxy (`compile.go:154-164`).
- **Fail-open in the degenerate case:** with no proxy host resolvable, the PAC
  emits `DIRECT` rather than black-holing traffic (`compile.go:86-87`).

## The endpoint

The PAC file is served at `/proxy.pac`, unauthenticated by design so clients
(including Windows PAC fetchers that cannot present credentials) can retrieve it
(`pac.go:162-166`). It is served on both the proxy port and the UI port; point
clients at the proxy port URL (`http://<host>:8080/proxy.pac`).

## Configuration

Manage the PAC at `/api/pac-config` (`pac.go:167`). The configuration is:

| Field | Meaning |
|---|---|
| Proxy host | The proxy host clients should use (empty = derived from the request) |
| Proxy port | The proxy port (empty/zero = the startup-resolved listener port) |
| Exclusions | Domain and CIDR patterns that evaluate to `DIRECT` |

Deeper field-level behavior is in the in-repo operator guide
[`../../../docs/operator/pac-traffic-steering.md`](../../../docs/operator/pac-traffic-steering.md).

## Configuration procedure

1. Set the proxy host/port clients should use via `/api/pac-config` (or the
   admin UI PAC panel).
2. Add exclusions for destinations that must go direct — internal domains and
   RFC 1918 CIDRs.
3. Point clients at `http://<host>:8080/proxy.pac` (browser proxy settings,
   GPO/MDM, or DHCP/WPAD).

## Validation steps

```bash
curl -s http://<host>:8080/proxy.pac
# Confirm it defines FindProxyForURL and emits PROXY <host>:<port> with DIRECT
# for your configured exclusions.
```

## Failure modes

| Condition | Behavior |
|---|---|
| No proxy host resolvable | PAC emits `DIRECT` (fail-open, not a black hole) |
| Destination matches an exclusion | Client goes `DIRECT` (bypasses the proxy) |
| Client cannot fetch `/proxy.pac` | Client falls back to its own proxy setting |

## Security implications

- `/proxy.pac` is intentionally unauthenticated — do not put secrets in it; it
  is a routing hint, not an access control.
- Exclusions bypass the proxy entirely, so excluded destinations receive **no**
  policy, inspection, or scanning. Keep exclusions to genuinely internal or
  trusted ranges.

## Known limitations

- Only `PROXY` and `DIRECT` are emitted (no `SOCKS`/`HTTPS` PAC directives) for
  maximum client compatibility.
- PAC steers clients that honor it; it is not an enforcement mechanism — pair it
  with network controls if clients could route around the proxy.

## Related documentation

- [Quick start](../02-getting-started/quick-start.md) ·
  [Policy engine](../03-policy/policy-engine.md).
- In-repo: [`../../../docs/operator/pac-traffic-steering.md`](../../../docs/operator/pac-traffic-steering.md).

## Source evidence

Claim-evidence ledger: [`pac-traffic-steering.evidence.md`](pac-traffic-steering.evidence.md).
