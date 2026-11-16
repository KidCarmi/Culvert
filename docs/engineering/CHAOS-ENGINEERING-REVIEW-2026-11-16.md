# Chaos engineering review — 2026-11-16

Reviewer: Culvert Chaos Engineer (automated round). Base revision `51996b9`
(`origin/main`), clean worktree at branch point. Recorded separately for the
reason the previous rounds were; [the register](../../roadmap/CHAOS-ENGINEERING-REVIEW.md)
stays the index.

Id claimed: **CHAOS-121**, in a committed placeholder row as commit one, before
any code, checked against `origin/main` rather than the working tree per the
register's 2026-09-25 amendment. `CHAOS-120` was the highest id anywhere on
`origin/main` at `51996b9`, and no open PR held a new chaos id (#1922, #1921,
#1920, #1917, #1916, #1915, #1914, #1913, #1911, #1904, #1901, #1705, #1549,
#1548, #1536, #1528, #1526 — #1911 is a rider on CHAOS-120, not a claim).

---

## CHAOS-121 — The deployment artifact: 120 rounds of resilience delivered through a compose file that never handed the binary its flags

Scope: **the artifacts the resilience work ships inside.** Every preceding round
in this family has reasoned about the binary — containment, bounded envelopes,
fail-closed startup, who tells the operator. All of it is conditional on one
thing nobody had gated: that the compose file which starts and stops the
container actually *starts* it with the configuration it declares, and actually
gives it time to stop.

For `docker-compose.ha.yml` — the shipped Control Plane + standby + Data Plane
topology — neither was true, and it had never been true.

---

## 1. Executive summary

**CHAOS-121a (CRITICAL) — the HA compose file's `command:` never reached the
binary. Every flag it declares was silently discarded, and the container still
reported healthy.**

The image declares an exec-form entrypoint (`Dockerfile:200`):

```dockerfile
ENTRYPOINT ["./culvert"]
```

Docker **appends** a container's command to an exec-form entrypoint; it does not
replace it. `docker-compose.ha.yml`'s `proxy` and `dp` services both passed a
shell:

```yaml
    command: >
      sh -c '
        ARGS="-port 8080 … -cluster-db /data/cluster.json"
        …
        exec ./culvert $$ARGS
      '
```

so the container's real argv — confirmed by resolving the artifact with
`docker compose -f docker-compose.ha.yml config`, and reproduced verbatim by the
gate this round ships — was:

```
./culvert sh -c ' ARGS="-port 8080 … -cluster-db /data/cluster.json" … exec ./culvert $ARGS '
```

Go's `flag` package stops parsing at the first token that does not begin with
`-`. `main.go:387` calls the package-level `flag.Parse()`; there is **no**
`flag.NArg()` guard anywhere in `main` (the only two in the tree are
`cmd/catalogfetch` and the downgrade-confirm word), and `handleOneShotCommands`
(`main.go:413`) dispatches on **flags** only — so nothing matched, nothing
errored, and the process fell straight through into normal startup with every
flag at its zero default. `docker-compose.yml`'s own `cli` service already
states the consequence, for a different reason:

> `./culvert` with no arguments at all falls straight through into normal
> startup — a full second proxy + admin UI against the same shared proxy-data
> volume

What "all defaults" costs, flag by flag, with the defaults read at `main.go:296-350`:

| Dropped flag | Default | Consequence on an HA/DP node |
|---|---|---|
| `-ca-path /data/ca.bundle` | `""` | the Root CA is **not persisted** — a new one every boot, so every client's installed trust anchor breaks and all inspected HTTPS fails after any restart |
| `-policy /data/policy.json` | `""` | policy rules not persisted. The Dockerfile's own comment: *"CRITICAL: without this, rules are lost on restart"* |
| `-audit-log /data/audit.jsonl` | `""` | no persistent audit log — the compliance record of what the gateway allowed |
| `-cluster-db /data/cluster.json` | `""` | no cluster state persistence: the roster, enrolment and lease state the HA plane is built on |
| `-cp-grpc-addr :50051` | `""` (off) | the Control Plane gRPC listener **never opens**, so no Data Plane can ever reach it |
| `--ha-join` / `--ha-token` | `""` | the standby never joins. `clusterStartupConfig.haJoinMode()` requires both non-empty, so Server B comes up as an **independent, ACTIVE Control Plane** |
| `--enroll $ENROLL_URL` | `""` | a Data Plane node never enrols |
| `-clamav-addr tcp:clamav:3310` | `""` | ClamAV is not wired at all — no antivirus leg on any body scan |
| `-yara-rules-dir`, `-threat-feed-db`, `-cat-feed-db`, `-blocklist`, `-ui-users-file`, `-fileprofiles-file`, `-idp-profiles-file`, `-logfile` | `""` | no YARA rules, no threat-feed or category persistence, no blocklist, no persisted admin roster, profiles or process log |

**The split-brain is the sharpest part, because this file already contains a
guard against exactly it.** The script carries a twelve-line comment and a
`exit 1` added by Codex review on PR #1337, whose stated purpose is that an
empty `--ha-token` must not let the container *"come up HEALTHY as an
independent, ACTIVE Control Plane that never joins or replicates from Server A
(a silent split-brain, worse than the crash it replaces)."* That guard lives
**inside a script that never executed.** The failure it was written to prevent
was the unconditional behaviour of the file it was written in.

`-port` and `-ui-port` default to `0`, documented as *"overrides config"*, so
they fall back to the built-in ports — which is why the container passes its
`/health` check. `/health` is liveness, and the process is alive. Nothing in
the readiness surface is reached by an operator doing `docker compose up -d` and
seeing `healthy`.

**This had never worked, in any revision.** It is not drift from a working
state; it is an artifact that cannot do what its own header comment documents in
five numbered deployment steps. **No CI job has ever brought this file up** —
nothing outside the four root-level tests that read it as *text* references it,
and the e2e stacks use their own files. Four tests read it: one checks the
enrol-URL example parses, one checks `CULVERT_SESSION_SECRET` is forwarded, and
two extract the embedded script and run it under `sh -c` to assert the argv it
builds. That last pair is the instructive one — **it validated the script's
contents while assuming the premise that the script runs.**

**CHAOS-121b (HIGH) — the HA nodes had no stop grace, so Docker SIGKILLed them
at 10s against a 51s enforced envelope.**

CHAOS-56 made the shutdown sequence bounded end to end: three phases, a
durability reserve carved out up front, a per-hook watchdog, worst case
`Total + 2×shutdownHookGrace` = **51s**. It pinned that to the container with a
cross-artifact gate — `TestChaos56_EnvelopeFitsTheContainerStopGrace`, which
reads `docker-compose.yml` by name. `docker-compose.ha.yml` declared **no**
`stop_grace_period` on either service, so Docker's default **10s** applied.

The harm is not hypothetical and is not this round's words — it is
`docker-compose.yml`'s own comment, on the very line the HA file lacks:

> Docker's DEFAULT grace is only 10s, which would SIGKILL the proxy mid-drain
> and turn the client GOAWAY cosmetic. … Past the grace below the container is
> SIGKILLed, which skips the durable flushes — the cluster store, the
> request-log queue, a clean badger close — so this value must stay ABOVE that
> worst case.

At 10s the kill lands inside or at the boundary of the **early** phase (budget
12s). Everything after it is skipped:

| Order | Hook | What the SIGKILL costs |
|---|---|---|
| 66/67 | MCP telemetry drain, policy-learning flush | lazily-flipped session state lost |
| 80/90 | SOCKS5 + proxy listener stop | abrupt |
| 94/95 | tunnel establish fence, H2 GOAWAY | no fence, no GOAWAY wave |
| **100** | **tunnel drain** | **every in-flight client tunnel severed instead of drained** |
| 110-140 | syslog, community DB, log store, request log, **audit log**, log closer | the whole durability reserve |

An unclean badger close is precisely the torn `MANIFEST` that CHAOS-50's
boot-path quarantine exists to survive — so a 10s grace *manufactures* the
corruption an earlier round had to build recovery for. And with
`restart: unless-stopped`, this happened on every `compose restart`, every node
reboot and every out-of-band HA upgrade the file's own header prescribes.

**CHAOS-121c (MEDIUM) — the HA nodes started before ClamAV was healthy, so
every boot had an unscanned window.**

Both services used the short form `depends_on: [clamav]`. `docker-compose.yml`
uses the long form and says why:

> Long-form `condition: service_healthy` is required here — the short-form list
> (`- clamav`) only waits for the clamav container to START, not for its
> healthcheck to pass, which would silently break this comment's promise during
> the ~2-5 min first-boot signature-download window.

ClamAV's healthcheck in the HA file carries `start_period: 300s`. An unreachable
ClamAV is **fail-open** — `diagnostics_clamav_scan.go:48` words it as *"scanned
content is being forwarded WITHOUT an antivirus verdict (fail-open); YARA rules
and threat feeds still apply"*. So on every HA/DP first boot and every node
reboot, bodies were forwarded with no antivirus verdict for up to five minutes,
with the gateway reporting healthy throughout. (In the shipped state this was
academic, because 121a meant `-clamav-addr` was never set and the AV leg was
absent *permanently* — fixing 121a is what makes 121c live.)

**The common cause, which is the finding behind the three findings.** Every one
of these contracts already existed in `docker-compose.yml`, with a comment
explaining the failure it prevents. None reached `docker-compose.ha.yml`. This
is the third recorded instance of the same drift in this one pair of files:
`docker_compose_ha_session_secret_test.go`'s own header says *"the fix was never
carried over to docker-compose.ha.yml's proxy service"* about
`CULVERT_SESSION_SECRET`. **Each instance was fixed by naming the file; none was
fixed by gating the class.** The three gates this round ships *discover* compose
artifacts rather than naming them, so the next artifact is in scope the moment
it is added — which is the only form of fix this particular defect has.

---

## 2. Failure scenarios

| # | Scenario | Pre-fix behavior | Expected | Failure mode | Detected by |
|---|---|---|---|---|---|
| 1 | `docker compose -f docker-compose.ha.yml up -d` on Server A | boots with all flag defaults; no CP listener, no persisted CA/policy/audit/cluster state; reports `healthy` | boots as a Control Plane with the declared paths | silent misconfiguration | nothing |
| 2 | Server B with `HA_JOIN` + `HA_TOKEN` set | never joins; comes up as an independent ACTIVE Control Plane | joins as a replicating standby | **split brain** | nothing |
| 3 | DP node with `ENROLL_URL` set | never enrols; runs as a standalone proxy with default config | enrols against the CP | silent misconfiguration | nothing |
| 4 | `HA_JOIN` set, `HA_TOKEN` empty | the `exit 1` guard never runs; same as #2 | refuse to start | the guard is unreachable | its own test, which assumed the script runs |
| 5 | Restart of any HA/DP node | fresh Root CA, policy rules lost, audit log gone | state restored from `/data` | **state loss on every restart** | nothing |
| 6 | `docker compose stop` / node reboot / HA upgrade | SIGKILL at 10s inside the early phase | 51s envelope: drain, then durable flush | tunnels severed, durability reserve skipped, badger quarantine on next boot | nothing (CHAOS-56's gate reads another file) |
| 7 | First boot, or any reboot, with the ClamAV sidecar re-downloading signatures | proxy serves immediately; AV leg unreachable; fail-open | wait for ClamAV healthy | **unscanned window, up to 5 min** | nothing |
| 8 | Operator reads `/health` after any of the above | `200`, container `healthy` | — | the reassuring surface is the one they look at | — |

## 3. Risk matrix

| Finding | Likelihood | Blast radius | Severity | Status |
|---|---|---|---|---|
| 121a — command never reaches the binary | **certain** (unconditional, every HA/DP deployment) | whole node: security posture, persistence, cluster membership | **CRITICAL** | fixed |
| 121a′ — split brain via the unreachable `HA_TOKEN` guard | certain, given an HA standby | cluster: two active Control Planes | **CRITICAL** | fixed with 121a |
| 121b — no stop grace on HA/DP | certain, every stop | durability + in-flight tunnels, per node | **HIGH** | fixed |
| 121c — ClamAV not awaited | certain, every boot | one node, bounded by `start_period` | **MEDIUM** | fixed |
| 121d — e2e fixtures run at the 10s default | certain in CI | CI fidelity, not customers | LOW | recorded, §7.2 |
| 121e — `cli` in `backup-e2e.yml` uses `command: []` | low (needs an accidental `up`) | a second daemon on a shared volume | LOW | recorded, §7.1 |
| 121f — HA/DP keep no request log | certain | observability/forensics on HA nodes | LOW | recorded, §7.3 |

## 4. Recovery assessment

**Automatic recovery: none, for any of them.** That is what makes this class
different from everything the preceding rounds dealt with. A contained panic has
a crash record, a counter and (since CHAOS-120) an alert. A misconfigured
container has *nothing to recover from* — it is operating exactly as its argv
instructs, and every internal invariant holds. There is no fault for a
supervisor to retry, no degraded state for a health probe to notice, and no log
line that says anything is wrong.

**Manual recovery:** 121a and 121c require editing the artifact and recreating
the containers; 121b requires the same plus accepting that the next stop is the
first clean one. For 121a the recovery is not complete even then — a node that
has been running without `-ca-path` has been issuing leaf certificates from a
Root CA that exists only in memory, so the operator must redistribute the trust
anchor after the fix, and any `/data` the node wrote is not the state the file
intended it to write.

**Detectability before this round: zero.** Not "poor" — zero. No metric, no log
line, no diagnostics row and no health signal distinguishes a node that dropped
every flag from one that applied them. `/health` is `200` and `/ready` has no
notion of "the configuration you meant". The only detectable symptom is
downstream and much later: inspected HTTPS breaking after a restart, or a second
Control Plane appearing in the cluster.

## 5. Operational impact

- The documented five-step HA deployment in the file's own header could not
  produce the topology it describes. Steps 3-5 ("Enable Control Plane", "Enable
  HA", enrol the DP) configure through the GUI, against a node whose CP listener
  was never opened.
- `restart: unless-stopped` plus a 10s grace meant every supervised restart was
  an unclean one, and the log lines explaining a stalled shutdown died with the
  process that stalled — the specific reason CHAOS-56's envelope exists.
- The HA file's day-2 update path is explicitly out-of-band (`build` + `up -d`
  per node), so each upgrade was a SIGKILL of a node mid-drain.
- The cost of the *fix* is one planned recreate per node, which the file's own
  update procedure already performs.

## 6. Security impact

- **Antivirus absent.** `-clamav-addr` unset is not a degraded AV; it is no AV
  leg at all, with no diagnostics row, because `diagnostics_clamav_scan.go`
  *"contributes nothing when ClamAV is not configured"* — correct behaviour for
  an operator who chose not to configure it, and indistinguishable from one who
  configured it in a file that never applied.
- **Root CA not persisted.** A fresh CA each boot means clients' installed trust
  anchors stop matching, and the operator's remedy under pressure is usually to
  redistribute a new anchor — the CA key material itself was never at rest, so
  nothing leaked, but the trust distribution is destroyed on every restart.
- **No persistent audit log.** The record of what the gateway allowed did not
  survive the process.
- **No policy, blocklist, threat feed, YARA rules or category DB persistence.**
  The enforcement posture after a restart was whatever the defaults are, not
  what the operator configured.
- **Split brain.** Two active Control Planes serving divergent configuration to
  a fleet is the worst available cluster state, and the guard against it was
  inside unreachable code.
- **Unscanned window on every boot** (121c), fail-open by design and invisible.

## 7. Also reached this round, NOT fixed

**7.1 `test/e2e/maint-agent/docker-compose.backup-e2e.yml`'s `cli` service uses
`command: []`.** `docker-compose.yml`'s production `cli` deliberately uses
`["-h"]` instead, with a comment explaining that an empty command does **not**
prevent an accidental `docker compose --profile cli up -d` from starting *"a
full second proxy + admin UI against the same shared proxy-data volume"* —
because `./culvert` with no arguments falls through into normal startup. The
fixture has the shape the production file was fixed away from. Not changed: it
is a CI fixture this round cannot execute, the e2e flow invokes it only through
`compose run` (which replaces the command), and a fixture edit is a worse trade
than a recorded observation. It is the same drift class as 121a-c and is the
honest statement that the class is not fully swept.

**7.2 The e2e fixtures run at Docker's 10s default grace, and the maint-agent
one is testing an upgrade restart.** Registered in `chaos121GraceKnownGaps`
with that reason. The upgrade path those fixtures exercise recreates the
container — i.e. a stop with a grace — so they test that restart at 10s while
production now uses 60s. The fidelity gap is recorded rather than closed,
because changing a CI fixture's timing without being able to run it trades a
known gap for an unknown flake. The catalog-update fixture is a genuine
exception rather than a gap: its header says the scenario *deliberately*
SIGKILLs its own dispatcher mid-flight, so a grace would change what it tests.

**7.3 HA and Data Plane nodes keep no request log.** `docker-compose.yml`
passes `-request-log /data/requests.jsonl`; `docker-compose.ha.yml` does not, on
either service. That is a retention and disk-capacity decision with a real cost
on a Data Plane carrying fleet traffic, and it is an operator's call rather than
a chaos round's — but it means the shutdown reserve's `request-log-close` hook
has nothing to flush on exactly the nodes 121b was killing, and an HA deployment
has less forensic record than a single-node one. Recorded for an owner.

**7.4 No systemd or Kubernetes manifest is shipped, so
`docs/operator/graceful-shutdown.md`'s "set the equivalent grace above 51s"
(`TimeoutStopSec=60`, `terminationGracePeriodSeconds: 60`) is prose with no
artifact to gate.** That is the right state today — the guidance exists and
nothing contradicts it — but it is the identical shape as 121b one layer out: a
number that must track `defaultShutdownBudget` and has no mechanical link to it.
The moment a unit file or chart lands in this repository, gate 2's discovery
must be widened to it, and the gate's doc comment says so.

## 8. Verified correct, and why — the parts that already held

Recorded because an audit that only reports defects cannot be told from one that
stopped looking.

- **The envelope itself is enforced, not described.** `runShutdownSequence`
  (`main_shutdown.go:86`) gives every phase a real deadline, `PartitionAt`
  carves the flush reserve up front at `shutdownFlushBoundary` (105), and
  `shutdown.DefaultGrace` (3s) is folded into one shared phase horizon. 121b
  was never a defect in the envelope; it was the orchestrator not being told
  about it.
- **The Dockerfile's entrypoint is exec-form**, which is what makes `./culvert`
  PID 1 and able to receive SIGTERM at all. Had it been shell-form, 121b would
  have been unreachable because SIGTERM would have died in the shell — so the
  Dockerfile is correct and the compose file was wrong about it. The fix keeps
  that property: the HA services' shell `exec`s the binary, and gate 1 asserts
  that any shell entrypoint does.
- **Every other compose artifact hands the entrypoint a flag list** —
  `docker-compose.yml`, `docker-compose.ci.yml` and all three e2e files. The
  repo's own convention was already right, in five of six artifacts, which is
  what made the sixth findable as a differential.
- **Outbound HTTP is bounded everywhere.** Each `http.Client` literal in the
  tree sets `Timeout` except `internal/ocsp`'s `responderClient`, and that one
  is bounded by `context.WithTimeout(…, queryBudget)` at `ocsp.go:539` before
  `queryOCSP` builds the request — a context budget rather than a client
  timeout, which is the stronger form because it covers the whole query.
- **Retry schedules are decorrelated where a dependency is shared.** The
  DP→CP ladder jitters **per attempt** (`controlplane_client.go:120-147`), with
  CHAOS-89's reasoning recorded for why a per-node stable offset is wrong for a
  herd triggered by one shared instant, while `internal/feedsched` uses exactly
  that stable offset for a steady-state cadence. Both choices are stated and
  correct; this round found no fleet-shared schedule that was neither.
- **Disk exhaustion is classified rather than guessed at.**
  `internal/storeguard` matches `EROFS`/`ENOSPC`/`EACCES` explicitly, the MCP
  spool maps `ENOSPC` to a deterministic commit failure, and `logguard.go`
  drives `disk_critical` cleanup — which CHAOS-120 made subscribable.
- **The HA `HA_TOKEN` guard is correct, and its test is correct.** Both now do
  what they were written to do, because the script they live in runs.

## 9. Required tests — what shipped

`docker_compose_entrypoint_argv_chaos121_test.go`, three gates and four
negative-control tests. All three gates **discover** artifacts
(`docker-compose*.yml` at the root plus a walk of `test/`) rather than naming
them, and each fails if fewer artifacts or culvert services are found than the
repository has, so a broken walk is a failure rather than a silent pass.

1. `TestChaos121_ComposeCommandReachesTheBinaryAsFlags` — composes each
   service's effective argv exactly as Docker does (service `entrypoint`/
   `command` overriding the image's, command appended to entrypoint) and asserts
   the minimal true property: if the culvert binary is `argv[0]`, then `argv[1]`
   must begin with `-`. That is precisely the condition under which
   `flag.Parse` sees any flag at all. A shell entrypoint is permitted and must
   `exec` the binary, so PID 1 and SIGTERM delivery are preserved.
2. `TestChaos121_ComposeStopGraceCoversTheShutdownEnvelope` — CHAOS-56's
   contract, derived from `defaultShutdownBudget` and `shutdownHookGrace` rather
   than restated, applied to every supervised culvert service in every artifact.
   `chaos121GraceKnownGaps` is the registered-exception map in the shape
   CHAOS-113 established: removing an entry is the fix, adding one is a written
   statement that this container may be SIGKILLed mid-drain, and a **stale**
   entry is itself a failure — which it caught, on this round's own first draft.
3. `TestChaos121_ComposeWaitsForClamAVHealth` — every culvert service that
   depends on clamav must use `condition: service_healthy`. Rejects the
   short-form list *and* the long-form `service_started`, which is the same
   defect spelled out.

**Mutation-verified against the real artifact, not only synthetic input.**
Reverting `docker-compose.ha.yml` alone — leaving the gates untouched — fails
all three with six named violations (two services × three contracts), and the
121a message prints the full `./culvert sh -c '…'` argv it would have produced.
That reverted-artifact run is the measurement behind every claim in §1.

Each checker is a pure function over parsed services, so the pre-fix shapes are
fed to it directly: `TestChaos121_CommandCheckRejectsThePreFixShape` covers the
shipped shell shape, a shell entrypoint that **forks** instead of exec'ing (a
different defect in the same place), and a plain flag list as the positive
control; `TestChaos121_StopGraceCheckRejectsTheDockerDefault` covers the absent
key, a present-but-too-small grace, and a one-shot service that correctly needs
none; `TestChaos121_ClamAVDependencyCheckRejectsTheShortForm` covers both
spellings.

The existing `extractHAProxyCommandScript` follows the artifact's new command
shape, and its `sh -c script` invocation now mirrors what the container really
runs rather than what the file hoped it ran.

## 10. Suggested improvements not taken

- **A `flag.NArg()` guard in `main`.** `./culvert <positional>` could refuse to
  start, which would have turned 121a from a silent misconfiguration into a
  crash loop — loud, and far better. It is deliberately **not** done here:
  it is a runtime-behaviour change to the startup path, outside the scope of a
  deployment-artifact round, it would need its own audit of every invocation
  shape (the `cli` service, `compose run`, the maintenance agent's allowlisted
  commands, the appliance tree in #1528), and the artifact gate removes the
  defect at the source rather than making it survivable. Recommended as its own
  change, with that audit; recorded here so the next round does not have to
  rediscover the argument.
- **A smoke CI job that brings `docker-compose.ha.yml` up.** The real remedy for
  "no CI job has ever brought this file up" is a CI job that does. It is a
  separate build with its own cost and its own flake surface (two CPs, a DP, a
  ClamAV sidecar with a 300s start period), and a static gate that runs in
  milliseconds on every PR closes the *specific* class found here. The honest
  statement is that gate 1 proves the argv composes, not that the stack
  converges.
- **A one-shot/daemon distinction in the image.** A `culvert daemon` subcommand
  would make "no flags" unambiguous and retire both the `["-h"]` workaround and
  the `command: []` fixture shape (§7.1). Wire-compatibility change; out of
  scope.

## 11. Residual risk

1. **Gate 1 proves the argv, not the boot.** It asserts that the flags reach
   `flag.Parse`; it cannot assert that the resulting node converges into a
   cluster, that the volumes mount, or that the image builds. The HA topology
   is still only validated statically, and the finding this round opened with is
   what happens when static validation is all there is. §10's smoke job remains
   the real answer.
2. **The shell-entrypoint check keys on the literal `exec ./culvert`.** A script
   that execs through a variable, a helper or an absolute path satisfies the
   intent and fails the gate, and one that writes `exec ./culvert` in a dead
   branch while forking in the live one passes it. This is the same structural-
   versus-behavioural limitation CHAOS-118 residual `3` recorded for the IdP
   lock-release fix, and it is accepted for the same reason: there is no
   in-artifact seam to observe, and the shape it pins is the one in the tree.
3. **`command:` and `entrypoint:` string forms are split on whitespace, not
   lexed.** Every gate only inspects the leading token, so this is sufficient
   today and is documented as such in the helper. An artifact whose first token
   is produced by quoting would be read wrongly.
4. **`chaos121GraceKnownGaps` has three entries and they are all CI fixtures.**
   The map is the mechanism, but a map with entries is a list of places the
   contract does not hold. §7.2 states what each one costs; none is a shipped
   deployment, and that is the whole of the defence.
5. **The drift class is gated for three properties, not for drift.** Gates 1-3
   assert three specific contracts across all artifacts. They would not catch a
   fourth contract added to `docker-compose.yml` and not carried over — which is
   exactly how 121a, 121b, 121c and the earlier `CULVERT_SESSION_SECRET` gap all
   arose. A true fix is a differential gate over the two files' *service-level
   intent*, and the obstacle is that their divergences are mostly legitimate
   (`build` vs `image`, ports, volumes, the HA env block), so such a gate needs
   an allowlist of intended differences — which is a bigger build with its own
   correctness question. Recorded as the honest limit of this round.
6. **121f is unowned.** HA and DP nodes keeping no request log is recorded in
   §7.3 and changes nothing by itself; it needs a retention decision from the
   owner of that surface, not a chaos round.
7. **Nothing surfaces "my configuration did not apply" in the product.**
   CHAOS-120 residual `4` observed that the crash plane has no admin-UI panel;
   this is the same shape at the configuration layer. A node that dropped its
   flags is indistinguishable, from inside, from one configured that way on
   purpose — so no diagnostics row could have caught 121a without the product
   knowing what it was *meant* to be configured with. That is a real gap and
   not obviously one a gateway should try to close.
