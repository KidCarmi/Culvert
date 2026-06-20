# Spec: HTTP(S) endpoint for the maintenance agent (Release Management)

Status: **DESIGN / NOT IMPLEMENTED.** Follow-up to the UDS opt-in
(`docs/operator/release-management-agent.md`, `docker-compose.maint-agent.yml`).

## Motivation

The Release Management client (`release_wiring.go:localAgentEndpoint`) already
accepts an `http(s)://` agent URL via `CULVERT_MAINT_AGENT_URL`. The **agent
server listens on a Unix-domain socket only** (`server.go` → `lc.Listen(ctx,
"unix", path)`), authenticated with `SO_PEERCRED`. That works only when the
caller shares the host kernel (the CP-local case). It cannot serve:

- a control plane reaching a **remote** node's agent, or
- deployments that prefer a network endpoint over cross-namespace UID/GID
  alignment.

## Why this is a non-trivial change (not the minimal fix)

`SO_PEERCRED` is UDS-only — there is no peer-UID over TCP. A network endpoint
needs a **new authentication scheme** and a **new listener**, plus TLS. The UDS
path stays the default and lowest-surface option; this is opt-in for remote use.

## Proposed design

### Listener
- New optional config keys (all absent ⇒ today's UDS-only behavior, unchanged):
  - `listen_https` — `host:port` to bind a TLS listener (e.g. `0.0.0.0:8443`).
  - `tls_cert_file`, `tls_key_file` — server certificate/key.
  - `client_ca_file` — CA bundle for **mTLS** (required when `listen_https` set).
- The agent serves the **same** `/v1` mux on both the UDS and the HTTPS listener.
- Bind explicit; never default to a wildcard address. Refuse to start
  `listen_https` without `client_ca_file` (fail closed — no unauthenticated TCP).

### Authentication (TCP has no SO_PEERCRED)
Primary: **mutual TLS.** The agent verifies the client cert against
`client_ca_file`; the authorization key is the client-cert **Subject / SAN**,
matched against a new `allow_clients` allowlist (mirrors `allow_peers`, but for
cert identities). SO_PEERCRED remains the gate on the UDS path unchanged.

Rejected alternative: bearer tokens. Simpler but introduces a shared secret to
distribute/rotate and is replayable without channel binding. mTLS reuses the
cluster CA Culvert already operates (`controlplane.go` / cluster CA), so cert
issuance/rotation has an existing home.

### Authorization
- `auth.Allow()` stays UID-based for UDS.
- Add a parallel cert-identity check for the HTTPS path. The handler must know
  which transport a request arrived on (UDS vs mTLS) and apply the matching gate
  — never accept a TCP request through the UID path or vice-versa.

### Wiring
- `release_wiring.go` already supports `CULVERT_MAINT_AGENT_URL=https://host:8443`;
  it needs an option to present a **client cert** (CP identity) for mTLS — today
  the `http(s)` branch builds a plain `http.Client` with no TLS client cert.
- Compose: a second override that publishes the agent port and mounts the CP
  client cert into the proxy. The CP connects over the compose network or to a
  remote host:port.

## Security review checklist (for the implementation PR)
- [ ] `listen_https` without `client_ca_file` fails closed at startup.
- [ ] No default/wildcard bind; explicit `host:port` only.
- [ ] mTLS verify is mandatory; cert identity matched against `allow_clients`.
- [ ] UDS (UID) and HTTPS (cert) authz paths cannot be crossed.
- [ ] TLS min version 1.2+, modern cipher suites, `HandshakeContext` not bare.
- [ ] Cert rotation story documented (reuse cluster CA where possible).
- [ ] The sudoers allowlist remains the Docker boundary regardless of transport.
- [ ] govulncheck/gosec/CodeQL clean; `-race` clean; new listener has a goroutine
      stop/shutdown test.

## Scope boundary
The UDS opt-in already shipped makes the **CP-local** feature usable. This spec
covers only the **remote/network** case and should not regress the UDS default.
