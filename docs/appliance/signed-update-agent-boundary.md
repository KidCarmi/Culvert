# Host-agent signed update boundary

The maintenance socket authenticates the caller process, but an allowed proxy
process must not thereby gain permission to select arbitrary images from an
allowed repository. The host agent now checks signed release evidence itself.
The repository allowlist and constrained sudo commands remain additional gates.

`pkg/releaseproof` is a pure Go module. It verifies the existing signed catalog
index bytes, binds the selected manifest by SHA-256, and binds the manifest's
repository and digest to the exact requested image reference. It uses the same
baked public Sigstore trusted root and pinned GitHub release workflow identity
as the catalog consumer. An optional host-installed Ed25519 public keyring
supports the existing offline catalog signature envelope. No signing secret,
candidate exception, caller-supplied trust root, or unsigned mode is introduced.

Apply requests carry `release_proof` and, when the baseline is not already in
the host ledger, `prior_release_proof`. Evidence contains a selected release ID
and base64-encoded exact index, manifest, Sigstore bundle and/or Ed25519 envelope
bytes. Each document is bounded to 1 MiB. Apply and rollback routes accept at
most 12 MiB JSON; other routes retain their 16 KiB limit.

The agent first verifies the target, then captures the actually running digest
from the host's exact `proxy_repo`; unrelated upstream repository digests on a
mirrored image are not candidate baselines. Missing or conflicting references
within the configured repository refuse authorization.
Both target and observed baseline must be signed. Missing, ambiguous, unsigned,
or unverifiable baselines refuse an upgrade before backup, pull or retag. A
healthy running candidate does not establish release trust. A signed current
baseline must be available before such an appliance can use this upgrade path.
The release catalog supplies it: each catalog carries its supported
predecessors byte-identical from their own verified signed catalogs (release
lineage, `release_lineage.go`), so the proxy can send `prior_release_proof` for
the release a node runs, including a skipped one. A proof covers exactly one
digest; it never authorizes a different running image.

When the signed target declares `min_upgrade_from`, both apply and standalone
image rollback compare that floor with the independently verified version of
the actually observed baseline. Malformed floors and unverifiable baseline
versions refuse before backup, pull, retag or durable target authorization.
An empty floor preserves the existing unconstrained legacy contract. A cached
target does not bypass this check on a new standalone request. Explicit rollback
also accepts `prior_release_proof` when its observed baseline is not cached.

The private agent-state ledger records evidence and a monotonic catalog version
and generation-time floor after the read-only disk-space preflight and before
backup, pull or retag. A space-preflight refusal can be retried after freeing
capacity without restarting the agent. The ledger uses file fsync, atomic rename,
and parent-directory fsync. A failed durability barrier disables authorization
in that agent process until restart; corrupt persisted state refuses startup
instead of silently resetting the replay floor (see "Recovering a refused
release-trust ledger" below). All state ancestors must be
root- or agent-owned and protected against replacement. A root-owned sticky
ancestor is allowed for isolated tests. The ledger file must be agent-owned.

## Recovering a refused release-trust ledger

Startup stays fail-closed: the agent refuses to start on a ledger it cannot
trust, and the error names one class and this procedure.

- `reason=unsafe`: the file is not a regular, agent-owned, mode-0600 file within
  the size bound. Fix ownership/mode, for example
  `chown culvert-maint: /var/lib/culvert-maint/release-trust/ledger.json` and
  `chmod 0600` on it. Then restart the agent. Recovery never rewrites an
  unsafe ledger, so its content is preserved.
- `reason=policy_mismatch`: the replay floor is readable, but cached evidence no
  longer verifies under the current host policy. A legitimate rotation of
  `release_trust_keys`, `release_trust_root` or `release_catalog_repo` causes
  this. Inconsistent cached entries cause it too.
- `reason=corrupt`: the document, or its floor, cannot be decoded.

For `policy_mismatch` and `corrupt`, recover offline as root:

```
systemctl stop culvert-maint
culvert-maint --recover-release-trust            # dry run: prints the plan
culvert-maint --recover-release-trust --confirm  # applies it
systemctl start culvert-maint
```

Recovery refuses unless it runs as root and no agent answers on the socket. It
also requires the shared `host-maintenance.lock`, so it cannot overlap an agent
operation or `culvert-os-update`. It never erases trust history:

- The old ledger is preserved byte-for-byte as
  `ledger.json.quarantine.<UTC timestamp>`. It is hard-linked aside before the
  replacement is atomically renamed in, so the ledger is never absent. An
  absent ledger would load as an empty floor.
- The recorded floor (`catalog_version` and `generated_at`) is kept and can
  only rise. Cached entries are re-verified under the current policy exactly as
  startup does. Only the entries that fail are dropped. If none remain, the
  result is a valid floor-only ledger: replay protection holds, and an offline
  rollback needs fresh signed evidence.
- A corrupt ledger is replaced only with an explicit floor:
  `--floor-catalog-version N --floor-generated-at <RFC 3339>`. Take it from the
  last signed catalog this appliance accepted. A stated floor below a readable
  recorded floor is refused.

The summary lists the kept entries, the dropped entries with a reason, and the
resulting floor. It prints no evidence bytes. The replacement passes the same
load check as startup before the command reports success. Tests:
`cmd/culvert-maint/internal/releasetrust/recover_linux_test.go` and
`cmd/culvert-maint/recover_trust_linux_test.go`.

Offline rollback is restricted to exact references already authorized in that
ledger. Their signatures and digest binding are checked again, while expiration
and the newer catalog floor are waived only for those cached references.
Caller-supplied expired evidence never receives this exception. Standalone
rollback may also admit fresh evidence under the current replay floor, but a
target's signed minimum still applies before activation. If that target has a
floor and the stack is down so no current image can be identified, standalone
activation refuses. Inline and journal-directed recovery retain their exact
previously authorized target/prior recovery contract rather than becoming new
caller-selected release transitions. Shared
pull and retag paths enforce ledger membership for standalone, inline and
reconcile recovery; reconcile adoption also requires authorization.

The ledger is bounded to four entries and 24 MiB. An apply preserves its new
target and captured prior; other entries are pruned deterministically. An older
evicted rollback requires fresh signed catalog evidence. This is a bounded
recovery cache, not an unlimited release archive.

Host settings are `release_catalog_repo` (signed manifest repository), existing
`proxy_repo` (authorized local mirror repository), optional `release_trust_root`,
and optional `release_trust_keys`. Policy files and every ancestor must be root
owned, not group/world writable, and not symlinks. The Ed25519 keyring is a JSON
object mapping key ID to a standard-base64 32-byte public key. Public fixture
keys belong under `/etc/culvert-maint`, never a runner-owned checkout. Private
fixture keys must remain ephemeral and are not deployed to the agent.

This changes compatibility intentionally: old proofless clients and unsigned
candidate baselines cannot apply arbitrary images. Existing orchestration unit
tests explicitly inject a policy fake; dedicated crypto, durable-ledger and
real-agent fixtures exercise the actual boundary. Windows native checks cover
the pure verifier and request/shared mutation refusal tests; Linux runtime CI
is required for filesystem ownership, fsync, socket integration and recovery.
No new OVA or ESXi qualification is implied by these code changes.
