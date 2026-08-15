# Runbook — Cluster CA degraded, expired, or failing to rotate

**Applies to:** the **cluster CA** (`cluster-ca.crt` / `cluster-ca.key` in the data directory),
which signs the client certificate every Data Plane node presents on the mTLS control channel.
It is **not** the SSL-inspection Root CA — for that, see `root-ca-expiry.md`.
**Symptom class:** nodes cannot enroll, and enrolled nodes stop receiving configuration.
Proxy traffic on already-running nodes keeps flowing.
**Posture:** fail closed. Culvert refuses to issue a node certificate rather than issuing one
that no peer will accept.

---

## 1. What the cluster CA does, and what happens when it goes bad

Every Data Plane authenticates to the Control Plane with a certificate signed by the cluster CA.
That certificate is obtained at enrollment and renewed automatically by the node (checked every
6 hours, renewed when it has under 30 days left, and renewed immediately when the CP signals a
CA rotation).

The Control Plane auto-rotates the cluster CA when it is within 30 days of expiring, keeping the
old CA as a **secondary** so that nodes still holding certificates signed by it keep working
until those certificates expire.

Two things can break that chain:

1. **Rotation keeps failing** (most commonly a read-only or full data volume, or wrong ownership
   on the CA directory). The CA then rides to its own expiry.
2. **The CA is outside its validity window** (expired, or after a clock rollback, not yet valid).
   In that state Culvert **refuses to sign** node certificates. This is deliberate: a certificate
   signed by an out-of-window CA fails path validation in every TLS stack, so signing it would
   only move the failure to the node, where nothing can explain it.

What is *not* affected: proxying on nodes that are already running. Their existing certificates
remain valid until they expire, and the data path does not touch the cluster CA. This is a
control-plane outage, which is why it does not show up in proxy traffic metrics.

## 2. How to confirm it

| Surface | What you will see |
|---|---|
| `GET /api/cluster/ca` | `usable: false` plus `usableError`, and/or `lastRotationError`; `daysRemaining`, `rotationFailures`, `signRefusals` |
| `GET /metrics` | `culvert_cluster_ca_usable 0`, `culvert_cluster_ca_expires_in_seconds` at or below zero, `culvert_cluster_ca_rotation_failures_total` or `culvert_cluster_ca_sign_refused_total` climbing |
| Admin UI | Cluster → **Cluster CA** panel shows a red banner naming the condition |
| Alerts | `cluster_ca_degraded` (subscribe to it in the webhook panel) |
| Logs | `ClusterCA: DEGRADED — …`, rate-limited to one line per 5 minutes |
| On a node | enrollment fails with `cluster CA unusable: expired at <time>` |

**Expect a fleet-wide onset.** Every node trusts the same CA, so when it expires, every renewal
and every new enrollment fails at once. Nodes fail at different moments only because their own
certificates expire at different times.

## 3. Alert on it before the cliff

The series to watch is `culvert_cluster_ca_expires_in_seconds`. Auto-rotation triggers at 30
days, so this staying below roughly 30 days means rotation is not working, whatever the reason:

```
# cluster CA inside the rotation window and not renewing
culvert_cluster_ca_expires_in_seconds < 2592000

# rotation actively failing
increase(culvert_cluster_ca_rotation_failures_total[1h]) > 0

# already refusing enrollments
culvert_cluster_ca_usable == 0
```

The gauges are not emitted at all on a node with no cluster CA, so a Data-Plane-only node will
never trip these rules.

## 4. Fixing a rotation that keeps failing

The rotation error names the failing operation. Almost always it is persistence:

1. Read `lastRotationError` on `GET /api/cluster/ca` (or the Cluster CA panel banner).
2. Check the data volume: free space, mounted read-write, and ownership of the CA directory.
   A `storage_write_failed` alert firing at the same time confirms the volume.
3. Fix the volume. The next rotation check (every 24 hours) will retry on its own; to recover
   immediately, import a CA as in section 5, which is the same code path and clears the degraded
   state as soon as it succeeds.

You do not need to restart the Control Plane. Recovery is reported on evidence: the degraded
state clears when a CA is actually installed and persisted, not after a timer.

## 5. Recovering an expired cluster CA

An expired trust root cannot renew itself, so this step is manual.

**Option A — import a replacement CA (no downtime for running nodes).**

1. Admin UI → Cluster → **Cluster CA** → *Import Custom Cluster CA*, or
   `POST /api/cluster/ca` with `{"cert": "<PEM>", "key": "<PEM>"}`.
2. The certificate must be an ECDSA P-256 CA certificate with a matching `EC PRIVATE KEY` PEM.
3. On success the old CA is retained as a secondary for the remainder of its own validity, the
   CP TLS pool is rebuilt, and the new fingerprint is published to nodes on their next config
   poll. Nodes renew against the new CA automatically.

**Option B — re-bootstrap (only if no CA material can be recovered).**

1. Stop the Control Plane.
2. Remove **both** `cluster-ca.crt` and `cluster-ca.key` from the data directory. Removing only
   one is refused on purpose: Culvert will not regenerate over a surviving half.
3. Start the Control Plane. A fresh cluster CA is generated.
4. **Every node must re-enroll**, because nothing in the fleet trusts the new CA. Issue new
   enrollment tokens and run the enrollment command on each node.

## 6. Clock problems

The usability check tolerates 5 minutes of clock skew in either direction. A Control Plane whose
clock has rolled back further than that will treat its own CA as not yet valid and refuse to sign,
with `usableError` naming a `NotBefore` in the future. Fix the clock (NTP) rather than the CA;
enrollment resumes on its own once the clock is correct, with no restart and no re-import.

## 7. What this state does not require

- **Do not restart the Control Plane to "clear" an expired CA.** Restarting does not renew it,
  and it drops the config-sync channel for the whole fleet. This is why cluster CA health is
  reported on `/metrics` and the admin API rather than as a `/healthz` failure.
- **Do not delete node certificates on the data planes.** They are still valid until their own
  expiry, and nodes renew automatically once the CP can sign again.
