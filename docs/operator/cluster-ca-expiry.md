# Runbook — Cluster CA expiry and control-plane trust outage

**Applies to:** the **cluster enrollment CA** (the CA that signs data-plane node certificates for
CP↔DP mTLS), not the SSL-inspection Root CA. For that one see
[`root-ca-expiry.md`](root-ca-expiry.md).
**Symptom class:** data-plane nodes stop receiving configuration; enrollment and cert renewal fail.
Fleet-wide, all at once.
**Posture:** fail closed — the control plane refuses to issue a node certificate rather than handing
out one that cannot authenticate.

---

## 1. What happens when the cluster CA goes out of its validity window

Every enrolled node authenticates to the control plane with a client certificate signed by the
cluster CA. Certificate path validation checks the validity window of **every** certificate in the
chain, the root included — so the moment the cluster CA passes its `NotAfter`, every node's
certificate stops verifying, however much life its own `NotAfter` claims.

Consequences, in the order you will notice them:

- **Config sync stops.** DP nodes keep enforcing the last-good snapshot they already have (that is
  by design — see HA-1), so proxying continues, but no policy change, blocklist update, or threat
  feed reaches the fleet.
- **Enrollment and certificate renewal are refused.** Culvert will not sign a node certificate with
  an unusable CA: the RPC returns an error naming the violated bound.
- **Proxying itself is unaffected** on nodes that already hold a config. The cluster CA governs the
  *control* plane only.

> **Expect a fleet-wide, simultaneous onset.** Every node was issued from the same root.

> **Why refusal is the right answer.** Before this was fail-closed, `SignCSR` happily signed with an
> expired CA, and because enrollment does not require a client certificate the obvious recovery —
> re-enroll the node — *appeared to succeed*: a `200`, a fresh certificate on disk, and the same
> opaque handshake failure on reconnect. Operators could loop there indefinitely. The certificate was
> unusable from birth, so refusing costs no availability; it just stops the appliance lying about it.

## 2. How to confirm it

Any one of these is conclusive:

| Surface | What you'll see |
|---|---|
| `GET /healthz` | `"cluster_ca": "expired"` (or `"rotation_failing"` — see §4) |
| `GET /readyz` | `checks.cluster_ca.status = "fail"` (report-only — it does **not** flip the node to `not_ready` unless you probe `/readyz?strict=1`) |
| `GET /metrics` | `culvert_cluster_ca_usable 0`, `culvert_cluster_ca_expires_in_seconds` negative, `culvert_cluster_ca_sign_refused_total` climbing |
| `GET /api/diagnostics` | operator-contract row `cluster_ca` = **fail**, with the remediation |
| `GET /api/cluster/ca` | `usable: false` plus `unusableReason` — the only place the exact cause is readable without going to the logs |
| Admin UI → Cluster → Cluster CA | red banner: *Cluster CA is UNUSABLE*, and the status card reads `EXPIRED (enrollment blocked)` |
| Alerts | `cert_expiry` with host `culvert-cluster-ca` and detail `Cluster CA is UNUSABLE — node enrollment and certificate renewal are refused: …` |
| Node side | `x509: certificate has expired` on the DP's gRPC dial; the DP's own `cert renewal check` log line reports the CP refusing |
| Logs (CP) | `ClusterCA: node-certificate issuance REFUSED …` (rate-limited to once per 5 minutes; the counters carry the true volume) |

## 3. Recovery

1. **Check the clock first.** If `unusableReason` says
   `not valid until <timestamp> (system clock may have rolled back)`, this is an NTP/RTC problem,
   not a certificate problem. Fix time sync; issuance resumes on its own once this node's clock
   reaches the CA's `NotBefore`.

   There is deliberately **no** skew tolerance on this end. The control plane verifies node
   certificates against this same CA using this same clock, so tolerating a future `NotBefore`
   would let it hand out certificates its own verifier rejects — a "successful" enrollment that
   cannot authenticate. Refusing is bounded and self-clearing; the data plane's reconnect backoff
   covers the gap.

2. **Import a replacement cluster CA.**
   Admin UI → **Cluster → Cluster CA → Import Custom Cluster CA**, or:

   ```
   POST /api/cluster/ca   {"cert": "<PEM>", "key": "<PEM, ECDSA P-256>"}
   ```

   The import is never blocked by the fail-closed gate — recovery does not go through the signer.
   It persists the pair, keeps the old CA as a dual-CA secondary, rebuilds the CP's TLS client pool,
   and publishes a config-version bump so nodes pick up the new fingerprint.

3. **Nodes with a still-valid certificate renew automatically.** They see the CA-rotation
   notification on their next poll and request a new certificate immediately (zero-touch).

4. **Nodes whose own certificate already expired must re-enroll.** Issue an enrollment token
   (Cluster → Enrollment) and run the node's enrollment step. This is unavoidable: an expired client
   certificate cannot authenticate the renewal RPC.

5. **Confirm recovery on evidence.** `culvert_cluster_ca_usable` returns to `1`,
   `/healthz cluster_ca` returns to `ready`, and the diagnostics row clears. The degraded state is
   cleared only by an **observed** successful verification — never by elapsed time — so if the row is
   still failing, issuance genuinely has not succeeded yet.

## 4. The two warnings that arrive *before* the outage

Both exist so this runbook is something you read early rather than during an incident.

### `rotation_failing` — the automatic remedy is not working

The cluster CA auto-rotates 30 days before expiry. If that keeps failing (a read-only CA directory,
a full disk, wrong permissions), you get:

- `/healthz cluster_ca: "rotation_failing"`, `/readyz cluster_ca: fail`
- `culvert_cluster_ca_rotation_failures_total` climbing
- a `cert_expiry` alert per failed attempt: *Cluster CA auto-rotation failed …*
- `/api/diagnostics cluster_ca` = **fail**, and an amber banner in the Cluster CA panel

**Act on this.** Rotation is the CA's only automatic recovery. Restore write access to the cluster CA
directory (`<dataDir>/cluster-ca.crt` / `.key`), or import a replacement CA yourself.

The warning is keyed on the *current* state, not a cumulative counter: once a rotation lands, it
clears. `culvert_cluster_ca_rotation_failures_total` keeps its history, as a counter should.

### Clamped node certificates — the CA is in its final window

Node certificates are clamped so they can never outlive their issuer. If you see
`culvert_cluster_ca_node_certs_clamped_total` rising, or the amber *"Cluster CA expires in N days and
has not rotated"* banner, the CA is inside its last 30 days and has not been replaced. Affected nodes
will renew repeatedly (harmless, ~one CSR per node per 6h) until it is.

On a healthy fleet this counter stays at zero: the CA rotates before any certificate can be clamped.

## 5. Recommended alerting rules

```
# The cliff — page immediately.
culvert_cluster_ca_usable == 0

# The slide — page well before it. 30 days is where auto-rotation should already have run.
culvert_cluster_ca_expires_in_seconds < 30 * 86400

# The automatic remedy is not working. This is the one that actually needs a human.
increase(culvert_cluster_ca_rotation_failures_total[1h]) > 0
```

Both `culvert_cluster_ca_usable` and `culvert_cluster_ca_expires_in_seconds` are **omitted
entirely** on a node with no cluster CA (the ordinary single-node appliance, and every data-plane
node), so these rules do not fire outside a cluster. The counters stay present at 0, which is their
normal non-alerting state.

## 6. What this runbook does not cover

- **Inspection Root CA expiry** — different CA, different blast radius:
  [`root-ca-expiry.md`](root-ca-expiry.md).
- **A CP that is simply unreachable** (process down, network partition). DPs serve last-good config
  indefinitely; see the HA runbooks.
- **Client trust redistribution.** Nothing in band can make a data-plane node trust a new root before
  it has fetched it; that is what re-enrollment is for.
