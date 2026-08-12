# Runbook — Cluster CA expiry and node-enrollment outage

**Applies to:** the **cluster enrollment CA** — the CA that signs Data Plane node
certificates for Control-Plane↔Data-Plane mTLS. Not the SSL-inspection Root CA; for that see
[`root-ca-expiry.md`](root-ca-expiry.md).
**Symptom class:** node enrollment and certificate renewal stop working; eventually every
Data Plane node loses mTLS trust and drops out of the cluster.
**Posture:** fail closed — the Control Plane refuses to issue a certificate rather than
handing back one no peer would accept.

> **The proxy data path is not affected.** An expired cluster CA does not stop a node from
> proxying traffic it already has policy for. What breaks is the *cluster*: enrollment,
> certificate renewal, and — once node certs are no longer trusted — config distribution from
> the Control Plane.

---

## 1. What happens when the cluster CA goes out of its validity window

Node certificates chain to the cluster CA. RFC 5280 path validation evaluates every
certificate in the chain at time of use, so once the CA is past its `NotAfter`, **every** node
certificate it ever signed stops validating — including ones that are, on their own terms,
still months from expiry.

Culvert therefore refuses to sign in that state:

- `Enroll` and `RenewCert` RPCs return an error naming the violated bound, instead of
  returning a certificate that is guaranteed to fail.
- The refusal is **not** a trust downgrade. No unauthenticated peer is admitted and mTLS is
  not relaxed — a refused signing simply means the node does not join.
- Node certificates are clamped to the issuer's window, so a node's own expiry never claims
  more life than its chain has.

## 2. How to confirm it

Any one of these is conclusive:

| Surface | What you'll see |
|---|---|
| `GET /healthz` | `"cluster_ca": "expired"` |
| `GET /metrics` | `culvert_cluster_ca_usable 0`; `culvert_cluster_ca_expires_in_seconds` negative; `culvert_cluster_ca_sign_refused_total` climbing |
| `GET /api/diagnostics` | `cluster_ca` row, status `fail` — "node enrollment and cert renewal are BLOCKED" |
| `GET /api/cluster/ca` | `"usable": false` with `unusableReason` naming the bound and timestamp |
| Admin UI | Cluster → CA Management shows **EXPIRED — enrollment blocked** with a red banner |
| Alerts | `cert_expiry` on host `culvert-cluster-ca` (the inspection CA uses `culvert-ca`) |
| Logs | `ClusterCA: node enrollment and certificate renewal are BLOCKED …` (rate-limited to one line per 5 min; the counters carry the true magnitude) |

**Node-side symptom, and why it misleads.** A Data Plane node reports
`x509: certificate has expired or is not yet valid` — pointing at the *node's* certificate,
which may have been issued minutes ago and is perfectly valid on its own terms. The expired
certificate in the chain is the CA's. Check the Control Plane, not the node.

## 3. Recovery

**Rotation restores signing. It does not restore trust.** Certificates issued under the old CA
no longer chain to anything, so after a *post-expiry* rotation every enrolled node must
re-enroll. Plan for that; it is the expensive part.

### 3a. If the CA has NOT yet expired (the good case)

Let auto-rotation do it, or force it. Culvert auto-rotates when the cluster CA has 30 days
left, and `StartCAAutoRotation` runs one round immediately at startup as well as every 24h.
Because the old CA is still valid, it is preserved as a **secondary** for the remainder of its
life, so existing node certs keep validating and the Data Plane's rotation notification
triggers a zero-touch renewal on each node. No re-enrollment needed.

If auto-rotation is failing (see §4), import a replacement manually before expiry —
Cluster → CA Management → *Import Custom Cluster CA* — which takes the same dual-CA overlap
path.

### 3b. If the CA has ALREADY expired

1. Import a replacement cluster CA (Cluster → CA Management → *Import Custom Cluster CA*), or
   restart the Control Plane so the startup rotation round generates one.
2. Confirm recovery: `/healthz` → `"cluster_ca": "ready"`, `culvert_cluster_ca_usable 1`, and
   the `cluster_ca` diagnostics row back to `ok`.
3. **Re-enroll every Data Plane node.** Issue a fresh enrollment token per node and re-run the
   enrollment command. The old certificates cannot be renewed — renewal requires an mTLS
   handshake that the dead chain can no longer complete.

## 4. Auto-rotation is failing

Auto-rotation is the cluster CA's only automatic recovery, and it gets one attempt per 24h
tick. A persistent cause — a read-only CA directory, a full volume, a key-encryption key that
no longer decrypts — will burn the entire 30-day window silently if nobody is watching.

Signals:

| Surface | What you'll see |
|---|---|
| `GET /metrics` | `culvert_cluster_ca_rotation_failures_total` > 0 |
| `GET /api/diagnostics` | `cluster_ca` row, status `warn` — "auto-rotation is failing" |
| `GET /api/cluster/ca` | `lastRotationError` / `lastRotationErrorAt` |
| Admin UI | Cluster → CA Management rotation-failure banner |
| Alerts | `cert_expiry` on `culvert-cluster-ca` — "auto-rotation failed (N failures since boot)" |

Fix the underlying cause (usually write access to the data directory), then confirm the next
rotation succeeds — the warning clears on an **observed** successful rotation, not on a timer,
so if it is still showing, the rotation still has not worked.

## 5. Prevention

Alert on the leading indicator, not the cliff:

```promql
# Page well before auto-rotation's own 30-day window, so a failing
# rotation still leaves time to intervene manually.
culvert_cluster_ca_expires_in_seconds < 60 * 24 * 3600

# Auto-rotation is the only automatic recovery — treat any failure as actionable.
increase(culvert_cluster_ca_rotation_failures_total[1d]) > 0

# Should never be non-zero on a healthy Control Plane.
increase(culvert_cluster_ca_sign_refused_total[1h]) > 0
```

> `culvert_cluster_ca_usable` and `culvert_cluster_ca_expires_in_seconds` are **omitted** on
> nodes that hold no cluster CA — every standalone and every Data Plane node. Write alert
> rules so an absent series is not treated as a failure.

## 6. Clock skew, not expiry

Because usability is evaluated against wall-clock time, a system clock stepped *forward* past
the CA's `NotAfter` presents exactly like expiry. This is the correct direction to fail — a
peer with the same wrong clock would reject the chain anyway — but before rotating, check that
the Control Plane's clock is right. The `unusableReason` on `/api/cluster/ca` names the
violated bound and its timestamp, which is what distinguishes the two: a CA "expired 40 years
ago" is a clock fault, not a certificate fault.

A clock rolled *backwards* is tolerated up to 5 minutes, matching the inspection CA, so a
CA handed over from an HA peer with a slightly fast clock does not take enrollment down.
