# Runbook — Cluster CA expiry and Control Plane / Data Plane trust loss

**Applies to:** clustered deployments (a Control Plane with enrolled Data Plane nodes).
Standalone proxies have no cluster CA and are unaffected — the metrics below are deliberately
absent on those nodes.

**Companion runbook:** `root-ca-expiry.md` covers the *inspection* CA (SSL inspection). This
one covers the *cluster* CA (node enrollment and CP↔DP mTLS). They are different certificates
with different lifecycles, different blast radii, and different recovery paths. Read the one
matching the symptom.

---

## 1. What happens when the cluster CA goes out of its validity window

The cluster CA anchors mutual TLS between the Control Plane and every enrolled Data Plane node.
When it expires (or is not yet valid — a clock rollback does this too):

- **Config sync stops.** DP nodes cannot establish the gRPC stream; policy, blocklist, and feed
  updates stop reaching them.
- **Heartbeats stop.** The Cluster panel shows nodes going stale.
- **Centralised audit aggregation stops.**
- **Proxied traffic keeps flowing.** Data Plane nodes continue serving on their last-good
  config. This is the intended degradation — and the reason the failure can run for a long time
  before anyone notices.

**The trap this runbook exists for:** re-enrolling a node does *not* fix it. Enrollment is the
documented recovery for a broken node certificate, and it will run to completion, report
success, and hand back a certificate signed by the same expired CA — which fails exactly as the
old one did. Before Culvert gained the fail-closed sign gate, an operator could run the correct
runbook repeatedly and make no progress, with nothing in the output saying why.

Current builds refuse instead: signing is blocked, counted, and alerted, and the failure names
itself.

---

## 2. How to confirm it

```bash
# On the Control Plane. 1 = healthy; 0 = cannot sign a usable node cert.
curl -s localhost:9090/metrics | grep culvert_cluster_ca_

# The operator-contract row (viewer role is enough):
curl -s localhost:9090/api/diagnostics | jq '.checks[] | select(.code=="cluster_ca")'

# Full detail (admin role):
curl -s localhost:9090/api/cluster/ca | jq '{usable, unusableReason, expires, expiresInDays}'
```

In the admin UI: **Cluster → Cluster CA**. Status reads `UNUSABLE` with a red banner naming the
remediation; the Expires card shows a day countdown that turns red inside 30 days.

Log line to grep for:

```
ClusterCA: node enrollment/renewal is DOWN — the cluster CA cannot sign a usable node certificate
```

If instead you see this, rotation is failing and you have time to fix it before the cliff:

```
ClusterCA: auto-rotation FAILED (N since boot): ...
```

---

## 3. Recovery

An expired cluster CA requires a new trust anchor, which means new credentials for every node.
There is no in-band shortcut — automating it would mean accepting unauthenticated
re-enrollment, which trades an availability incident for a security one.

1. **Import a replacement cluster CA** — admin UI **Cluster → Cluster CA → Import Custom
   Cluster CA**, or `POST /api/cluster/ca` with a PEM cert + ECDSA P-256 key.
   Import rejects a CA that is already expired *or* not yet valid, so a bad clock on the CP will
   surface here rather than three days later.
2. **Re-enroll every Data Plane node** against the new CA. Nodes whose certificates were signed
   by the old CA are not covered by dual-CA overlap once the old CA is past its `NotAfter` — an
   expired secondary is not a trust anchor.
3. **Confirm** `culvert_cluster_ca_usable 1` and watch nodes return to `connected` in the
   Cluster panel.

**If `InitOrLoad` failed at boot** (log: `ClusterCA: init error: ... — enrollment disabled`),
the node is running with no cluster CA at all. Fix the underlying cause first — the CA directory
is usually read-only, out of space, or owned by the wrong user — then import as above. Importing
into a node in this state is supported and completes normally.

---

## 4. Preventing it

The cluster CA is a 10-year certificate and rotation begins automatically at 30 days. The
failure modes that actually reach production are therefore *rotation stopped* and *clock
skew* — not "ten years elapsed". Alert on both:

```yaml
# Page well before the cliff. Rotation starts at 30 days; re-enrolling a fleet
# takes planning, so 45 days gives you room.
- alert: ClusterCAExpiringSoon
  expr: culvert_cluster_ca_expires_in_seconds < 45 * 86400
  for: 1h

# The cliff itself. Enrollment and renewal are already blocked at this point.
- alert: ClusterCAUnusable
  expr: culvert_cluster_ca_usable == 0
  for: 5m

# Rotation is stalling — this becomes ClusterCAUnusable within 30 days.
# Cumulative counter: use a rate/increase window, not `> 0`, or the rule latches
# forever after a single historical failure. The live "is rotation currently
# broken?" state is the `cluster_ca` row on /api/diagnostics and the CA panel
# banner, both of which clear once a rotation actually succeeds.
- alert: ClusterCARotationFailing
  expr: increase(culvert_cluster_ca_rotation_failures_total[6h]) > 0

# Something is asking for a node cert and being refused.
- alert: ClusterCASignRefusals
  expr: increase(culvert_cluster_ca_sign_refused_total[15m]) > 0
```

`culvert_cluster_ca_usable` and `culvert_cluster_ca_expires_in_seconds` are **omitted entirely**
on nodes with no cluster CA, so these rules are safe to deploy fleet-wide without first
enumerating which nodes are Control Planes.

---

## 5. Node certificates and the renewal clock

Data Plane node certificates are issued for one year, **clamped to the cluster CA's own
expiry**. The clamp matters operationally: the DP renewal loop measures its 30-day window
against the *node* certificate, so without it a node enrolled against a CA with less than a year
left would sit quietly on a "healthy" certificate while its trust anchor expired underneath it.

Practical consequence you may notice: nodes enrolled while the cluster CA is inside its final
year receive **shorter** certificates than a year. That is intended — it brings their renewal
in front of the CA's expiry, so rotation's dual-CA overlap has something to hand them.

---

## 6. Related

- `root-ca-expiry.md` — the inspection CA (SSL inspection), the other CA in the appliance.
- `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-10.md` — the sweep that produced this
  runbook, including why re-enrollment used to be a treadmill.
- `roadmap/CHAOS-ENGINEERING-REVIEW.md` §17 — register rows CA-13, CA-17, CA-18, CA-19.
