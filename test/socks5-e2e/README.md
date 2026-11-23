# SOCKS5 real-network end-to-end suite (SWG-901)

Verification only. Not a required CI gate, and it changes no production code.

It runs the **real `culvert` binary**, built from this checkout, and drives it
over real TCP sockets. It checks that SOCKS5 enforces the same security policy
as HTTP/CONNECT for:

- authentication,
- threat-feed protection,
- access policy,
- refusal of destinations that need TLS inspection.

It also runs negative controls, which show that the suite fails against
intentionally unsafe binaries. Operator contract:
[docs/operator/socks5-policy.md](../../docs/operator/socks5-policy.md).

## Topology

```
                       ┌──────────── private mount namespace (unshare -m) ────────────┐
 driver (Go, this module)│  /etc/hosts override: *.e2e.test -> <upstream IP>           │
   raw RFC1928/1929 ─────┼─► culvert  SOCKS5 :rand ─┐                                   │
   raw HTTP CONNECT ─────┼─► culvert  HTTP   :rand ─┼─► upstreams on <upstream IP>      │
   x/net/proxy, curl ────┘   culvert  admin  :rand  │     tcp echo / http / https       │
                             │ LDAP bind+search      │                                   │
                             ▼                       │                                   │
                        ldapserver (gldap) 127.0.0.1 │                                   │
                        └──────────────────────────────────────────────────────────────┘
```

Every process in the run is local. Culvert gets a minimal environment with no
proxy variables. Its threat feed comes from a local database file, and a check
fails the run if Culvert syncs the public feeds.

## Prerequisites

- Go at the root `go.mod` toolchain.
- Module-proxy access the first time, to fetch `github.com/jimlambrt/gldap`.
  The fetch is pinned by `go.sum`.
- Root, or `CAP_SYS_ADMIN`, plus `unshare` from util-linux. The hostnames are
  mapped by bind-mounting a hosts file over `/etc/hosts` inside a private mount
  namespace. The driver will not mount it anywhere else.
- **A local IPv4 address that the SSRF guard classifies as public.** The guard
  refuses loopback and RFC 1918 destinations by design, and the suite does not
  weaken it. By default the driver uses the first such interface address; the
  Claude Code container has `192.0.2.2` (TEST-NET-1) on `eth0`. On a host that
  has none, add one yourself and pass it in, for example:
  `ip addr add 198.51.100.10/32 dev lo` then
  `run.sh --upstream-ip 198.51.100.10`.
- `curl` is optional. Without it, rows C3 and C4 are skipped.
- `patch` is needed for `--negative-control`.

## How to run

```
test/socks5-e2e/run.sh                      # checkout, modes enforce,shadow,legacy
test/socks5-e2e/run.sh --negative-control   # + every mutant in mutants/ (each must be CAUGHT)
test/socks5-e2e/run.sh --modes enforce --work /tmp/s5   # one mode, chosen work dir
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Every row passed. With `--negative-control`, every mutant was also caught. |
| 1 | A row failed, or a mutant survived. |
| 2 | Harness or setup error. Nothing was judged. |

The work directory keeps the following for each mode:

- `results-*.md` and `results-*.json`;
- the generated `config.yaml`, `policy.json`, `idp_profiles.json` and `threatfeed.json`;
- `culvert.log` and the JSONL request log;
- the directory's `ldap-events.jsonl`.

`GOMAXPROCS=2` throughout. The cases run serially, because each SOCKS5 probe is
judged on metric deltas.

Static checks: `cd test/socks5-e2e && gofmt -l . && go vet -tags socks5_e2e ./...`,
and `bash -n run.sh`.

## What is exercised, and how

Each case runs over SOCKS5 first. It then runs as an HTTP CONNECT through the
same Culvert, with the same principal, to the same destination. Each probe is
judged on four things:

1. **The exact protocol outcome:**
   - SOCKS5: the reply byte, the RFC 1929 status, or method `0xFF`;
   - CONNECT: the HTTP status;
   - a Drop must close the connection without any reply;
   - after a success, an echo round trip or an HTTPS GET must go through the tunnel.
2. **The request-log entry:** status, rule, action, identity and `auth_source`.
3. **Exact metric deltas** across the probe. The metrics are scraped from
   `/metrics` before and after.
4. **Directory events, where relevant.** These come from the LDAP server's own
   log.

A third row then compares the normalised verdicts across the two protocols.

| Requirement | Cases | How it is real |
|---|---|---|
| Authentication | A1–A4, plus identity on every P row | Culvert's IdP-registry **LDAP profile** points at a real LDAP server process: [gldap](https://github.com/jimlambrt/gldap) v0.1.14, an independent LDAPv3 implementation. Culvert performs a service bind, a search and a user bind for every credential. The directory's event log shows each bind (A1, P1) and search (A2). |
| Admin-console credential | A2, C2 | The YAML `auth.user/pass` local account is refused over SOCKS5 (`AUTH_FAIL invalid_credentials`). Its current HTTP behaviour is recorded: HTTP proxy Basic accepts it (`auth_source=local`). This row is "documented HTTP behaviour", not parity. |
| No NO-AUTH when auth is required | A4 | A client that offers only `0x00` gets `0xFF`. CONNECT without credentials gets 407. |
| Threat feed | T1, C4 | Culvert loads a feed database that lists `malware.e2e.test`, through `security_scan.threat_feed_db`. An Allow rule for that host exists and must lose. The feed refuses in **every mode**, before policy: the decisions counters do not move and the Allow rule's hit counter does not move. CONNECT gets 403 `THREAT_BLOCKED`. The clean domain connects (P1, C1, C3). |
| Policy enforcement | P1–P4, P6–P11 | Allow, Drop (RST), Block_Page (`0x02`), Redirect (`0x02`; CONNECT 302), default deny when rules exist, group+authSource and identity rules (full LDAP DNs), and an IPv4-literal ATYP. In enforce, `rule_hits` and `decisions{enforce,…}` move by exactly one. In shadow, `decisions{shadow,would_block,…}` moves, `rule_hits` stays at 0, the connection is served and no `POLICY_*` log entry is written. In legacy, the decisions family is absent. |
| Inspect refusal | P5 | Allow + SSL Inspect. SOCKS5 enforce gets `0x02` and `POLICY_BLOCK inspection_unsupported`. The same CONNECT is **really inspected**: the driver fetches Culvert's root CA from the admin API and verifies that the leaf the client receives chains to that CA, not to the upstream's own test CA, and that the HTTPS body came from the upstream. Any enforce run where SOCKS5 shows the client the upstream's own certificate fails. |
| HTTP parity | the "SOCKS5 vs CONNECT" rows | The normalised verdicts must be equal: ALLOW, DROP, REFUSE or AUTH_REFUSED. There are three recorded exceptions:<br>• the inspect contract: SOCKS5 REFUSE against CONNECT INSPECT;<br>• the expected shadow/legacy gap: SOCKS5 is not enforced;<br>• A2. |
| Real clients | C1–C4 | The raw clients assert exact bytes. On top of that, `golang.org/x/net/proxy` and `curl --socks5-hostname` must work end to end, and must be refused where expected. |

## What is simplified compared with production, and why

- **DNS.** A hosts file is bind-mounted in a private mount namespace. This
  keeps the run hermetic, and Culvert's resolver path (Go reads `/etc/hosts`)
  is otherwise unchanged.
- **Upstream address.** The upstream address is a local TEST-NET address, not
  the public internet. The SSRF guard admits it because it is not in the
  guard's ranges. The guard, `isPrivateHost` and `ssrfControl` are unchanged,
  and the Allow rows prove that Culvert's own guard agreed.
- **Directory.**
  - The LDAP directory is a minimal gldap server holding two users. It is not
    AD or OpenLDAP.
  - Its semantics are deliberately strict:
    - exact-DN simple bind, otherwise result 49;
    - search only when bound as the service account;
    - one equality filter on `uid`;
    - the password is never returned.
  - The connection is plaintext `ldap://` on loopback. Culvert logs its
    plaintext warning. StartTLS and LDAPS are not exercised.
- **Threat feed.**
  - The feed comes from a local database file. The public sources (URLhaus,
    OpenPhish) are hard-coded and cannot be configured.
  - The database also carries one URL entry. The feed counts only URLs as
    entries, and with zero entries it would sync the public feeds at startup.
    That behaviour is a quirk of `internal/threatfeed`, not a SOCKS5 issue.
- **Clients.** All clients connect from `127.0.0.1`. IP filter, rate limit and
  the per-IP connection limit are left at their defaults and are not judged.
- **Admin account.** The admin-console account comes from YAML `auth.user/pass`,
  so the roster is in memory. It is used only to fetch the inspection CA and
  for case A2.
- **Deployment.** A single node: no cluster, no HA, no Docker image.

## Negative controls

`--negative-control` copies the tree to a temporary directory, without `.git`.
It then applies one patch from `mutants/` and builds that copy with
`-buildvcs=false`. The checkout is never patched, and `run.sh` checks that its
Go files did not change during the run. Finally, it runs the enforce suite
against the mutant binary. A mutant counts as CAUGHT only if the suite exits 1.

| Mutant | Unsafe change |
|---|---|
| `a-skip-threat-feed` | SOCKS5 skips the threat-feed check. |
| `b-inspect-tunnels-uninspected` | An Allow that requires inspection is tunnelled uninspected over SOCKS5. |
| `c-admin-credential-on-socks5` | SOCKS5 falls back to the local admin-console account. |
| `d-skip-enforce` | `enforce` evaluates nothing. |
| `e-drop-identity` | Enforce evaluates without the resolved identity and groups. |

## What remains uncovered

- An IPv6 destination (ATYP `0x04`).
- BIND and UDP ASSOCIATE. Both are unsupported (reply `0x07`) and are not probed.
- OIDC and SAML profiles refused as `provider_not_supported_for_socks5`. The
  run has no real OIDC or SAML IdP. Unit and parity tests cover this.
- The legacy YAML `ldap:` provider path. Only the registry profile is exercised.
- The two documented exceptions to Inspect refusal: the SSL bypass list and
  hosts learned by a fail-open decryption profile.
- Category, geo and schedule conditions.
- IP filter, rate limit and the connection limit.
- The startup posture gate.
- The shadow log sampling lines (`POLICY_WOULD_BLOCK`).
- An Allow rule with "log traffic" turned off.
- `TUNNEL_CLOSED` byte accounting.
- LDAPS/StartTLS, directory outages (the CHAOS-47 cooldown), and the LDAP result cache.
- Cluster, HA and container packaging.

## Recorded results

### 2026-11-23

Run against `socks5-stage3-parity` at `33a621341` (PR #2046, on #2045):

- Command: `run.sh --negative-control`, which exited **0**.
- Result: **162/162 rows PASS** across the three modes, and **5/5 mutants
  CAUGHT**.
- Environment: Claude Code container, upstream address 192.0.2.2.

The complete generated table, the evidence for every row and the failure
details for each mutant are in [results/2026-11-23.md](results/2026-11-23.md).

Condensed (SOCKS5 outcome in each mode; CONNECT is identical in all modes):

| Case | enforce | shadow | legacy | HTTP CONNECT | Enforce relation |
|---|---|---|---|---|---|
| P1 Allow (alice) | tunnel | tunnel | tunnel | tunnel | same |
| P2 Drop | drop-rst | tunnel | tunnel | drop-eof | same (DROP) |
| P3 Block_Page | 0x02 | tunnel | tunnel | 403 | same (REFUSE) |
| P4 Redirect | 0x02 | tunnel | tunnel | 302 | same (REFUSE) |
| P5 Allow + Inspect | 0x02 `inspection_unsupported` | uninspected TLS (upstream cert) | uninspected TLS | inspected (Culvert CA) | inspect contract |
| P6 default deny | 0x02 | tunnel | tunnel | 403 | same |
| P7 group allow (alice ∈ engineering) | tunnel | tunnel | tunnel | tunnel | same |
| P8 group → Block_Page (bob) | 0x02 | tunnel | tunnel | 403 | same |
| P9 identity allow (bob DN) | tunnel | tunnel | tunnel | tunnel | same |
| P10 identity → Block_Page (alice) | 0x02 | tunnel | tunnel | 403 | same |
| P11 IPv4 literal → default deny | 0x02 | tunnel | tunnel | 403 | same |
| T1 threat feed (with Allow rule) | 0x02 | 0x02 | 0x02 | 403 | same, every mode |
| A1 wrong LDAP password | auth 0x01 | auth 0x01 | auth 0x01 | 407 | same |
| A2 admin-console credential | auth 0x01 | auth 0x01 | auth 0x01 | **tunnel** (`auth_source=local`) | documented HTTP behaviour |
| A3 unknown user | auth 0x01 | auth 0x01 | auth 0x01 | 407 | same |
| A4 NO-AUTH only / no credential | method 0xFF | method 0xFF | method 0xFF | 407 | same |
| C1–C4 x/net/proxy and curl | pass | pass | pass | — | — |

Shadow and legacy behave as the operator document says:

- policy cases are served there, which is the gap that `enforce` closes;
- shadow moves `decisions{shadow,…}` but never the rule hit counters or the
  request log;
- in legacy the policy metric families are absent.

Negative controls (enforce suite against each mutant):

| Mutant | Verdict | Caught by |
|---|---|---|
| a-skip-threat-feed | CAUGHT | T1 SOCKS5 (tunnel instead of 0x02; no THREAT_BLOCKED; Allow rule hit; decisions moved), T1 parity, C4 curl |
| b-inspect-tunnels-uninspected | CAUGHT | P5 SOCKS5 (client received the upstream's own certificate), P5 inspect contract |
| c-admin-credential-on-socks5 | CAUGHT | A2 SOCKS5 (tunnel as `admin`/`local`), A2 relation, C2 x/net |
| d-skip-enforce | CAUGHT | P1–P11 SOCKS5 (P2–P6, P8, P10, P11 tunnel; P1, P7, P9 lose rule attribution and counters) and their parity rows |
| e-drop-identity | CAUGHT | P7 and P9 SOCKS5: the group and identity allows fall through to Block_Page; parity rows |

No production bug was found. One non-SOCKS5 observation:
`internal/threatfeed` counts only URL entries. A feed database that holds only
domains therefore reads as empty, and the public feeds are synced at startup.
