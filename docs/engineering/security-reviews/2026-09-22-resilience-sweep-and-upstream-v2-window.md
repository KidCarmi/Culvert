# Security regression review — resilience-sweep + upstream-v2 + PAC-lifecycle window

**Date:** 2026-09-22
**Scope:** every change merged to `main` between `290e376` (PR #1306, *canary
physical-effect truth* — the commit the previous review closed at) and `3a673ea`
(PR #1463, *E2E image at production parity*) — 678 commits, 517 files,
+109 558 / −3 805.
**Branch:** `claude/epic-bardeen-kjbsd6`
**Predecessor:** `2026-09-05-mcp-canary-physical-effect-window.md`
**Method:** classify the window by security surface; read the production diff on
every surface that decides authentication, authorization, policy, trust
material or persistence; reproduce each candidate finding against the pre-fix
tree before writing a patch; mutation-verify every new guard by reverting the
fix and requiring the guard to fail.

---

## 1. Executive summary

This window is three bodies of work rather than one: the **CHAOS-50…65
resilience sweep** (boot-path store recovery, bounded shutdown, listener
recovery, DNS/GeoIP resolution, OCSP revocation, credential-verification cost),
the **Upstream v2 / 2F-C…2F-G credential programme**, and the **PAC lifecycle +
object-reference integrity** work, with a CI-restructuring tail (stages 1–4).

The overwhelming majority of the window **strengthens** security posture. It
closes five silent fail-open shapes that a security appliance must not have: an
expired or unloadable inspection CA that kept minting leaves clients reject; an
OCSP checker that accepted a borrowed `good`, an unauthorized signer and an
`unknown` as verdicts; a frozen cluster rate-limit broadcast that blackholed a
NAT egress forever; an unauthenticated login endpoint that could rotate away the
entire retained audit trail in under two minutes; and a SOCKS5 destination that
forged whole records into the forensic log.

**One security regression was found and fixed: SEC-SECRETWRITE-1** — four
writers of node-local key material introduced in this window use `os.WriteFile`
on a *predictable* path, which follows a planted symlink and inherits a planted
file's mode. §5 records every other surface that was reviewed and why it is
sound.

| ID | Severity | Reachable in the stock container? | State |
|---|---|---|---|
| SEC-SECRETWRITE-1 | **Medium** | No — needs write access to the state root | **Fixed** here: 1 new `fileutil` primitive, 4 call sites, 20 gates |
| SEC-CDRTMP-2 | Informational | No | Fixed as part of the above (fsync) |
| SEC-AGENTERR-3 | Informational | Yes (viewer) | Recorded, not fixed — see §6 |

---

## 2. SEC-SECRETWRITE-1 — node-local key material is written through a
predictable path with `os.WriteFile`

**CWE-59 (Link Following) · CWE-377 (Insecure Temporary File) · CWE-276
(Incorrect Default Permissions) · OWASP A02:2021 Cryptographic Failures ·
Medium.**

### What changed

Four writers of node-local secret material landed in this window:

| Asset | Site | What it protects |
|---|---|---|
| Upstream credential KEK | `internal/upstream/credkey.go` `OpenKey` | AES-GCM key that unseals **every** parent-proxy password (2F-C) |
| Webhook KEK | `internal/alerts/secret.go` `webhookSecretKey` | AES-GCM key that unwraps every webhook HMAC secret (RISK-003 / SEC-WHSIGN-1) |
| Request-history KDF salt | `internal/logstore/logstore.go` `EncKey` | The PBKDF2 salt without which encrypted history can never be re-derived (CHAOS-62) |
| CDR client bundle | `cdr_health.go` `installRenewedPEMs` | The renewed **mTLS client private key** staged at `<bundle>.key.tmp` |

All four write with `os.WriteFile(path, secret, 0o600)`. The repository's own
convention for durable state is `fileutil.AtomicWrite`, and
`internal/policylearn/pseudonym.go` — the *fifth* node-local key, written in an
earlier window — already uses it. These four are the deviation.

### Why `os.WriteFile` is the wrong primitive for a secret on a fixed path

Two properties, both reproduced against this tree:

**(a) It follows symlinks.** `O_CREATE` without `O_EXCL` opens the link's
*target*. And the read that precedes every mint makes this worse rather than
better: `os.ReadFile` on a **dangling** link reports `fs.ErrNotExist`, which is
exactly the condition all three KEK/salt mints treat as *"no key yet, create
one"*. So planting a dangling link at the key path does not merely redirect a
write — it **steers control flow into the mint branch** and then redirects it.

**(b) Its `perm` argument applies only on creation.** Writing over a file that
already exists keeps that file's mode. A `0666` file planted at
`<bundle>.key.tmp` receives the CDR client private key and stays world-readable,
however carefully `0600` was passed. This variant needs no symlink at all.

Measured against the verbatim pre-fix shapes:

```
dangling read IsNotExist=true -> mint branch
KEK landed OUTSIDE the data dir: .../attacker/stolen2 mode=-rw------- content="0123...cdef"
CDR client key tmp mode after WriteFile(...,0600) = -rw-rw-rw- (world-readable)
```

### Attack scenario

*Preconditions.* A local principal that can create directory entries in the
persisted-state root (or in a CDR bundle directory) **before** the corresponding
first write. Not reachable in the shipped `docker-compose.yml`, where `/data` is
a root-owned named volume. It becomes reachable wherever the state root is not
exclusively the appliance's: a host install under `/srv/culvert` with a loose
parent, a bind-mounted or shared volume, a co-tenant uid — and notably via
**`CULVERT_DATA_DIR`, which landed in this same window** and lets an operator
(and the e2e harness, deliberately) point the whole state root at a temp
directory. A tmp-rooted state directory is the classic setting for this class.

*Exploitation.*
1. **Disclosure (no symlink needed).** Plant a `0666` file at
   `<dataDir>/integrations/sluice/<inst>/client.key.tmp`. The next scheduled CDR
   certificate renewal writes the new client private key into it and the file
   keeps mode `0666`. The attacker now holds the mTLS identity the appliance
   uses against Sluice. The same shape applies to `<history>.salt`.
2. **Escape + arbitrary write.** Plant a dangling symlink at
   `<dataDir>/.upstream_cred_key` (or `.alert_webhook_key`) pointing anywhere the
   appliance can write. The read reports absent, the mint fires, and the 32-byte
   KEK is deposited at the attacker's chosen path. Where the target pre-exists
   as a file the attacker owns, it is written into that file at *that* file's
   mode — direct key disclosure.
3. **Fail-open consequence.** In the escape case the appliance believes it
   persisted a key. Delete or replace the target and every sealed upstream
   credential becomes permanently un-unsealable — `credentialState: unusable`,
   which makes each credentialed parent **ineligible**. With no eligible parent,
   `Pool.noteDirectFallback` fails the pool **open to DIRECT egress**: client
   traffic that policy says must traverse the parent-proxy chain bypasses it.
   The same primitive against `<history>.salt` renders encrypted request history
   unreadable for good.

*Exploitability.* Low — requires local write access at the right moment and, for
the KEK escape, either a pre-existing attacker-owned target or a second step.
*Likelihood.* Low in the default container posture; **moderate** in host and
overridden-`CULVERT_DATA_DIR` deployments.
*Impact.* High — parent-proxy credentials, webhook HMAC authenticity, the CDR
mTLS client identity, and a documented path to parent-proxy bypass.
*Affected assets.* `.upstream_cred_key`, `.alert_webhook_key`, `<history>.salt`,
`<bundle>.crt/.key` and their `.tmp` staging files.

### The fix

Two shapes, because the four sites do not have the same requirement.

**Three of them have no rendezvous requirement**, so they simply join the
repository's existing durable-write chokepoint, `fileutil.AtomicWrite`:
a random `O_EXCL` temp beside the target, chmod, fsync, then `rename` over the
target. `rename(2)` does **not** follow a symlink at its destination, so a
planted link is *replaced* rather than written through, and the mode can never
be inherited. This is the convention `internal/policylearn` already follows —
the fix makes the four key writers agree rather than inventing a fifth pattern.

**`installRenewedPEMs` cannot use a random temp name.** The `<bundle>.tmp` paths
are a deliberate rendezvous: `finishStagedRenewal` (`cdr_lineage.go`) looks them
up by exactly that path at the next boot to finish an interrupted swap.
Randomising them would delete the crash-recovery contract. So this window adds
one primitive:

```go
// internal/fileutil
func WriteFileExclusive(path string, data []byte, perm os.FileMode) error
```

It removes any pre-existing entry — link or file, which is what makes the create
exclusive rather than merely racy — then creates with `O_CREATE|O_EXCL|O_WRONLY`
at `perm`, writes, **fsyncs** and closes. Removing first preserves
`os.WriteFile`'s drop-in semantics exactly: a stale rendezvous file from an
interrupted predecessor is superseded, as a truncating write superseded it
before. `O_EXCL` then guarantees the descriptor refers to a file *this* call
created, at *this* mode, at *this* path.

**Deliberately NOT wired to the CHAOS-45 `AtomicWrite` observers.** This is not
that chokepoint, and all four call sites check the returned error themselves.
Notifying only the failure seam would degrade the storage operator-contract row
with no success seam able to clear it by evidence — the recovery-by-evidence
rule `storage_health.go` and `ca_health.go` share.

### Safe-implementation notes for anyone extending this

- **A secret on a predictable path needs `WriteFileExclusive`; a secret anywhere
  else needs `AtomicWrite`. `os.WriteFile` is never correct for either.**
- The dangerous read is the one *before* the write: any mint keyed on
  `os.IsNotExist` / `fs.ErrNotExist` is steerable by a dangling link.
- `perm` on a write is a *creation* argument, not an assertion. If the mode
  matters, the call must be the one that created the file.

### Files

| File | Change |
|---|---|
| `internal/fileutil/fileutil.go` | new `WriteFileExclusive` + the contract that explains when each primitive applies |
| `internal/upstream/credkey.go` | KEK mint → `AtomicWrite` |
| `internal/alerts/secret.go` | webhook KEK mint → `AtomicWrite` |
| `internal/logstore/logstore.go` | salt mint → `AtomicWrite` |
| `cdr_health.go` | both staged bundle writes → `WriteFileExclusive` |

### Required tests — all present, all mutation-verified

`internal/fileutil/writeexclusive_test.go` (10), `internal/upstream/credkey_secretwrite_test.go` (4),
`internal/logstore/salt_secretwrite_test.go` (3), `internal/alerts/webhook_key_secretwrite_test.go` (3),
`cdr_secretwrite_test.go` (6).

- **Positive:** content, mode and readback at every call site; mint-then-load is
  stable and the key id does not change (a second generation would strand every
  sealed credential).
- **Negative / defect gates:** dangling symlink, existing-target symlink, and
  planted-mode variants at each site. **Each was verified failing against the
  verbatim pre-fix `os.WriteFile` shape** — the failures are quoted in the PR.
- **Regression / controls:** the cheapest way to pass every defect gate is to
  refuse whenever anything occupies the path, which would wedge CDR renewals
  permanently after the first crash. `SupersedesAStaleRendezvousFile` and
  `SupersedesStaleStagingFiles` forbid that. `ReadPathStillNeverMints` pins
  SEC-WHSIGN-1's rule; `ContractsUnchanged` pins CHAOS-62's `ErrSaltUnusable`
  refusal *and* that the refused mint leaves the operator's sidecar untouched.
- **Boundary:** empty payload, 64 KiB payload, `0o400`, NUL/newline bytes,
  missing parent directory, a directory occupying the path, an unwritable bundle
  directory (fails closed, previous key intact).
- **Malformed input:** wrong-length key files are refused, never overwritten.
- **Concurrency:** 120 racing writers against one path must leave one payload
  intact — never a torn or mixed file.
- **Authentication / authorization:** not applicable — these are node-local
  boot/renewal paths with no request-derived input. The reachability question is
  filesystem access, and it is stated in the attack scenario rather than
  assumed away.
- **Leftovers:** every site asserts that no temp artifact survives a successful
  write; a leftover would itself be a predictable path holding key material.

### Residual risk

An attacker who already has write access to the persisted-state root can still
**delete** key material (denial of service) or read files the appliance created
world-readable *before* this change on an existing install. Operators who
suspect exposure should rotate: re-enter upstream credentials (T2), re-enter
webhook secrets, and re-enroll affected CDR instances. This change removes the
write primitive; it does not retroactively tighten modes on files already on
disk, and deliberately does not chmod files it did not create.

---

## 3. SEC-CDRTMP-2 — the staged CDR bundle was not fsynced (Informational)

`installRenewedPEMs`' own comment promised *"a crash mid-swap leaves either the
old or the new material intact — never a half-written file"*. That was not true:
neither staging write was fsynced before the rename, so a crash could publish a
renamed-but-empty key. `WriteFileExclusive` fsyncs, which makes the existing
documented contract true rather than likely. No behaviour change on the happy
path; pinned by `TestInstallRenewedPEMs_HappyPathSwapsAndLeavesNoStagingFiles`.

---

## 4. Regression analysis

Nothing in this change alters a security *decision*. It changes only *how* four
files reach the disk:

- **No posture moved.** Every refusal the four sites made before, they make now:
  `ErrKeyMissing` on a read with no key, `ErrSaltUnusable` on a populated store,
  the wrong-length refusals, and SEC-WHSIGN-1's "a failed decrypt never mints".
- **No new failure mode on the happy path.** `AtomicWrite` is already the
  durable-write path for ~50 call sites; `WriteFileExclusive` differs from
  `os.WriteFile` only in refusing to follow a link, refusing to inherit a mode,
  and fsyncing.
- **The one behavioural difference is a strict improvement**: a write that fails
  now leaves nothing at the path, where `os.WriteFile` could leave a truncated
  file. Both `AtomicWrite` and `WriteFileExclusive` clean up on every error path.
- **Backward compatibility:** unchanged on disk. Same paths, same contents, same
  `0600`. An existing key file is loaded exactly as before — this only affects
  the branch that *creates* one.
- **CP→DP and export surfaces:** untouched. None of these four files is on any
  `configSurfaces` row (all are node-local by design, and the `.upstream_cred_key`
  / `.alert_webhook_key` exclusion from backups is unchanged).

---

## 5. What else was reviewed, and why it is sound

Read in full; no regression found.

- **Admin-plane RBAC (C1/C1.5/C2).** Every route added in the window carries
  `uiRoutes` metadata and the handler-level `requireRole` that metadata claims.
  The two `requireRole(RoleAdmin)` deletions in the diff are the v1 upstream
  handlers *moving* to `ui_upstream.go`, where both re-appear. The public-route
  allowlist in `uiAuthMiddleware` gained nothing.
- **Upstream v2 credential model.** `Pool.List` serialises `DisplayURL()`, which
  is `scheme://host:port` by construction; `authenticatedURL` is the only
  constructor of a credential-bearing URL and is AST-walled to two selectors.
  The read model reaches viewers credential-free.
- **Object-reference integrity.** All five rule/group write doors take the shared
  side of `objectReferenceMutationGate` and validate *after* server
  canonicalisation, so a client-supplied object ID can never satisfy validation
  of a name the server cannot resolve. `apiPolicyUpdateByID` validates without
  taking the gate itself — correct: its only caller, `apiPolicyUpdate`, holds it,
  and shared holds must not nest.
- **PAC DIRECT-path confirmation ceremony.** The challenge is explicitly a
  content digest and not a secret, so its non-constant-time comparison carries no
  side channel. The ceremony is an anti-mistake gate behind an authenticated
  admin, and the server recomputes the binding under the publish lock on every
  retry.
- **`prefixSet` (shared by the IP filter and the rate-limit exempt list).** The
  family normalisation mirrors `net.networkNumberAndMask` including the
  `::ffff:10.0.0.0/104` case, and a mask the conversion cannot represent falls
  back to a linear `IPNet.Contains` rather than being dropped — the fail-open
  direction is closed by construction, and a differential test against the
  verbatim pre-index scan pins it.
- **`restore.go` tarball ingestion.** Absolute paths, any `..`, entries outside
  `data/`, duplicates and per-entry/cumulative size are all refused before any
  body is read; entries are collected as bytes, so no archive entry can create a
  link on extraction.
- **`CULVERT_DATA_DIR`.** Read once before flag parsing, absolute-and-cleaned or
  fatal, `/` refused, and `rebindDataDirPaths` moves *all* persisted state rather
  than part of it.
- **New outbound HTTP.** Three new clients: the OCSP responder client (inline
  scheme allow-list + `ssrf.PrivateHost` + `SafeDialContext` + redirects
  refused), the upstream probe (a compile-time constant URL through the parent
  being probed), and the maintenance-agent status read (a CP-local endpoint
  resolved from env, never request-derived).
- **Destination-privacy pseudonym key (2E-B).** The key lives in
  `admin_settings.json`, which is written by `fileutil.AtomicWrite` at `0600` —
  the precedent that makes the four SEC-SECRETWRITE-1 sites outliers rather than
  the norm. Its `configSurfaces` row is `Sensitive` + `AdminDurable`, so it is
  off export/import, version rollback and CP→DP, and `config_surfaces_test.go`
  enforces that. The exposed `key_id` is minted from the CSPRNG *independently*
  of the key rather than derived from it, so the rotation-resolution surface
  leaks nothing about the key; on an entropy failure it falls back to a
  monotonic counter, not to key material.
- **Custom UI TLS upload.** Both halves go through `fileutil.AtomicWrite`, the
  cert half is rolled back when the key write fails so the admin is never told
  "unchanged" about a file that changed, and `ErrReplacedNotSynced` is
  deliberately exempted from that rollback because restoring the old cert would
  pair it with the new key — the mismatch the function exists to prevent.
- **CI restructuring (stages 1–4).** The release verdict is unchanged: both
  `qa-gate.yml` and `security-release-gate.yml` remain `mandatory` rows in
  `.github/release-evidence.txt`, bound by workflow file path, exact head SHA,
  `event=push` and `head_branch==main`. Moving the main-push race run between
  those two conjuncts does not move it out of the conjunction.

---

## 6. Recorded, not fixed

**SEC-AGENTERR-3 (Informational).** `apiMaintAgentStatus` and `apiBackups` both
return the raw `err.Error()` from a failed maintenance-agent read as `reason` to
a **viewer**. On a transport failure that is a `*url.Error` carrying the agent's
base URL. The disclosure is a CP-local address, the two handlers agree with each
other, and `apiBackups` established the pattern before this window — so this is
a convention question, not a regression introduced here. The right fix is a
bounded reason class with the cause in a rate-limited log, matching the rule
this repository already applies to alert `Detail` fields; it should be done to
both handlers at once.

---

## 7. Attack scenarios exercised

| Scenario | Result |
|---|---|
| Dangling symlink at `.upstream_cred_key`, then trigger first credential seal | KEK escaped the state root **before**; refused **after** |
| Dangling symlink at `.alert_webhook_key`, then save a webhook secret | KEK escaped **before**; refused **after** |
| Dangling symlink at `<history>.salt`, then enable encrypted history | salt stranded, history permanently underivable **before**; refused **after** |
| `0666` file planted at `<bundle>.key.tmp`, then wait for CDR renewal | client private key world-readable **before**; `0600` **after** |
| Symlinks at both `<bundle>.{crt,key}.tmp` | bundle escaped the instance directory **before**; refused **after** |
| Stale `.tmp` left by an interrupted renewal | superseded **before and after** (control — the fix must not wedge renewals) |
| Unwritable bundle directory | fails closed, running key intact (control) |
| 120 racing writers on one path | exactly one intact payload, never torn (control) |
