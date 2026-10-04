# Disposable b579 ESXi lab registry

Run the frozen controller helper only after the exact b579 default-import
candidate has completed bootstrap and local PAM authentication:

```text
python test/e2e/appliance/esxi/prepare-lab-registry.py --scope PRIVATE_SCOPE --bind CONTROLLER_IP
```

The scope must identify source `b579ca28c9d936e9141292ce5ec564a26feeae86`,
OVA SHA256 `1a713a9bedc4ee50ac4212c12048924e03abe6b8f04cb82d4d0ef95e33ef4775`
and image `sha256:24b37bc217691058e56a838821b86dfbd45b927b1c0ea8ea867a28c54d4bcc47`.
The helper independently checks the installed build metadata and running image
through authenticated local root console. It never uses administrative SSH.

Preparation holds both existing host-maintenance locks, rejects interrupted
operations, existing fixture paths/containers and preexisting localhost registry
trust, and writes an exclusive private controller attempt marker. Any failure
is BLOCKED; preserve the partial state and do not rerun or delete its marker.

The guest runs a disposable `registry:2` resolved from Docker Hub, with its actual
image ID and repository digests retained in the receipt. It binds only guest
loopback `127.0.0.1:443` and uses a fresh root-private TLS key and self-signed
certificate for `ghcr.io`, `localhost` and `127.0.0.1`. Only Docker's
`/etc/docker/certs.d/localhost:443/ca.crt` trust is installed during preparation.
No global system CA, DNS configuration, agent keyring or product verifier is
changed by this phase. Certificate/data files stay under the private guest
`/var/lib/culvert-lab-registry` directory. The registry has bounded CPU/memory
inside the existing VM; no second VM or host configuration is created.

The baseline is tagged and pushed to that registry. Returned manifest **bytes**
and the `Docker-Content-Digest` header must both match the exact OVA image index;
a registry representation change fails qualification. The target is created by
`docker create` from the baseline, `docker commit --change LABEL org.culvert.lab-target=1`,
and removal of that exact stopped temporary container and its anonymous volumes.
The temporary container must never start. Its pushed manifest must have a
different digest, and the running application must remain on the baseline.

The authenticated transport exports only the public certificate, manifest
bytes and structured observations. It never exports the registry private TLS
key. Controller validation repeats manifest hashing and certificate-name checks.
Only public `ca.crt` and `target-digest` are initially written to a fresh private
`secrets/signed-update`. The helper then invokes the existing exact-source Go
fixture generator through `prepare-signed-fixture.py`; its Ed25519 private key
remains ephemeral in generator memory.

The resulting `refs.env` uses `ghcr.io/kidcarmi/culvert@sha256:...` for baseline
and target, with `REGISTRY_ADDR=127.0.0.1`. Existing shared lifecycle step 6c
later installs the separate test-only `ghcr.io` Docker CA, hosts mapping and
agent public trust keyring. `evidence/registry-test-trust.json` records both the
preparation trust and the pending step-6c changes. Neither phase modifies the
retained OVA, and neither is a production trust posture or release publication.

All raw transport/registry receipts remain private. The source guest and its
registry are destroyed only after the parent completes required evidence and
external backup/escrow retention; the fresh disaster-recovery appliance is
imported from the original unchanged OVA.

Offline validation uses `test_prepare_lab_registry.py`. These synthetic tests
exercise exact manifest binding, loopback restriction, rejected key export,
missing safety evidence and generated Python syntax without contacting a VM,
Docker daemon or registry. Runtime qualification remains a separate lab result.
