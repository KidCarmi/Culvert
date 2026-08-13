# Runbook — Cluster CA expiry and node-enrollment outage

**Applies to:** the **cluster enrollment CA** — the authority that signs the node
certificates carrying Control-Plane ↔ Data-Plane mTLS. This is **not** the SSL-inspection
Root CA; for that see [`root-ca-expiry.md`](root-ca-expiry.md).
**Symptom class:** data-plane nodes cannot enroll or renew; enrolled nodes drop off the
control plane and stop receiving configuration.
**Posture:** fail closed — Culvert refuses to issue a node certificate rather than handing
out one that cannot complete a handshake.

---

## 1. What happens when the cluster CA goes out of its validity window

Every enrolled data-plane node holds a client certificate signed by the cluster CA, and the
control plane trusts that CA to authenticate them. Certificate path validation checks
**every** certificate in the chain, so once the cluster CA is expired (or, after a clock
rollback, not yet valid), no certificate it signed can authenticate anything.

Culvert therefore **refuses to issue** in that state:

- `Enroll` and `RenewCert` fail with `FailedPrecondition` naming the validity window.
  The refusal happens **before** the one-time enrollment token is consumed, so a retry
  against an expired CA does not burn a fresh token on every attempt.
- A node whose renewal is refused **keeps its current certificate**. It retries on its
  normal cadence, so the fleet self-heals as soon as you rotate — you do not have to touch
  each node.

> **Expect a fleet-wide, simultaneous onset**, exactly as with the Root CA: every node's
> certificate chains to the same CA, so they are all ejected at the same `NotAfter`.

### Why this is not recoverable in-band

Once the CA has expired, every data-plane node has lost the mTLS channel it would use to
ask for a replacement — and `RenewCert` itself requires mTLS. This is inherent to mutual
TLS bootstrapped from a single root. **The remedy is prevention, and Culvert gives you
roughly a year of warning** (see §4).

## 2. How to confirm it

| Surface | What you'll see |
|---|---|
| `GET /healthz` | `"cluster_ca": "expired"` |
| `GET /readyz` | `checks.cluster_ca.status = "fail"` — **report-only**, it does not flip the node to `not_ready`. That is deliberate: gating would eject the control plane from its load balancer exactly when you need its admin UI to import a replacement CA |
| `GET /metrics` | `culvert_cluster_ca_usable 0`, `culvert_cluster_ca_expires_in_seconds` negative, `culvert_cluster_ca_sign_refused_total` climbing |
| `GET /api/cluster/ca` | `usable: false` plus `unusableReason` and `signRefusals` |
| Admin UI | Cluster → CA panel shows a red **Cluster CA is UNUSABLE** banner |
| Alerts | `cert_expiry` with `source: "cluster-ca"`, rate-limited to one per 5 minutes |
| Logs | `ClusterCA: node-certificate issuance is DOWN …` |

## 3. Recovery

Auto-rotation should have prevented this 30 days earlier. If it did not, check §5 first —
the reason it did not run is usually the thing you actually need to fix.

1. **Import a replacement CA** (admin, Cluster → CA panel, or
   `POST /api/cluster/ca` with `{"cert": "<PEM>", "key": "<PEM>"}`).
   The previous CA is preserved as a **secondary** for its remaining lifetime so nodes
   signed by it stay acceptable during the overlap — but note that an *expired* CA has no
   remaining lifetime, so in this scenario there is no useful overlap.
2. **Confirm** `culvert_cluster_ca_usable` returns to `1` and `/healthz` reads
   `cluster_ca: ready`.
3. **Re-enroll the nodes.** Because the overlap window is gone, each node needs a fresh
   enrollment token and a re-enroll on the node itself. Nodes that were still inside their
   own certificate's validity when you imported will renew on their own.

## 4. Preventing it — the signals that fire early

Alert on these, in this order of usefulness:

| Signal | Fires | Meaning |
|---|---|---|
| `culvert_cluster_ca_cert_clamped_total > 0` | **~1 year out** | Node certificates are being shortened to fit inside the CA's remaining life. The CA is now within one node-certificate lifetime of expiry. This is the earliest honest warning. |
| `culvert_cluster_ca_expires_in_seconds < 60*86400` | 60 days out | Rotation window opens at 30 days; you still have slack. |
| `culvert_cluster_ca_rotation_failures_total > 0` | any failed rotation | **The automatic recovery is not working.** See §5. |
| `culvert_cluster_ca_usable == 0` | at the cliff | The outage has started. |
| Admin UI | ≤90 days | Amber expiry banner on the cluster CA panel. |

## 5. When auto-rotation is failing

`culvert_cluster_ca_rotation_failures_total` climbing, or a `cert_expiry` alert reading
`Cluster CA auto-rotation failed at <stage>`, means the CA will expire on schedule with
nothing preventing it. The alert and the `lastRotationError` field on
`GET /api/cluster/ca` both name the stage.

Common causes, in rough order of frequency:

- **The data directory is read-only or full.** Rotation generates a new CA and must persist
  `cluster-ca.crt` / `cluster-ca.key`; a failure at the `import` stage is almost always
  this. Check free space and mount options on the data volume.
- **Permissions.** The files are written `0600`; a directory the process cannot write
  produces the same stage failure.
- **Key-at-rest misconfiguration.** If cluster-CA key encryption is enabled, a KEK that
  cannot be resolved fails the key write. See [`key-at-rest.md`](key-at-rest.md).

Retry cadence is **once per 24 hours** — there is no backoff and no faster retry. After
fixing the underlying cause you can force the issue immediately by importing a CA manually
(§3.1), or by restarting the node: the rotation check runs once immediately at startup, not
only on the first tick.

> **Note:** auto-rotation covers **both** CAs from a single daily loop, and that loop is
> started unconditionally. An SSL-inspection CA that fails to load no longer prevents
> cluster-CA rotation from running (it did before — see CHAOS-50 / register row CA-19).

## 6. Node-side symptoms and what they mean

| What the node reports | Cause | Action |
|---|---|---|
| Renewal fails with `FailedPrecondition … cluster CA cannot issue` | CP-side cluster CA is unusable | Fix the CP (§3). The node keeps its working certificate; no node-side action needed. |
| `DP certificate expired at … — re-enroll` | This node's own certificate lapsed | Re-enroll this node. |
| mTLS handshake fails but the node's certificate looks valid | The node's **issuer** is gone — it missed the dual-CA overlap window (typically because it was offline for ≥30 days) | Re-enroll this node. Certificates issued by current builds are clamped to their issuer, so the node's own renewal fires inside the overlap and this should not recur. |

## 7. Related

- [`root-ca-expiry.md`](root-ca-expiry.md) — the SSL-inspection CA. Different CA, different
  blast radius, same fail-closed posture.
- [`ha-lease-failover.md`](ha-lease-failover.md) — issuance is additionally fenced by the HA
  lease; a zombie leader is refused before the CA is ever consulted.
- `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-13.md` — the failure-mode analysis this
  runbook comes from.
