# Restore probe (real Docker)

`probe.py` runs `restore.commit` through the real maintenance agent, with the
real proxy binary, on a real `dockerd`, on the topology the product ships: the
named volume `proxy-data` mounted at `/data` in both the `proxy` and the `cli`
service. It is manual and never a PR gate, like `../docker-probe.sh` and
`../orphan-probe/`.

It exists because nothing else runs a restore the way an appliance does. The
restore's unit tests use a temporary directory, which is neither a mount point
nor owned by another user; the agent's tests use a fake exec layer. Measured
before the in-place swap (`restore_inplace.go`): 6 of 6 restores through the
agent failed at `mkdir /data.staging.…: permission denied`, after the proxy
had been stopped.

## What it checks

Every property is checked against `dockerd` and the volume, read directly from
`/var/lib/docker/volumes`. The agent's own reports are recorded, never trusted.

| Scenario | Property |
|---|---|
| `success` | The restored files are byte-identical to the archive's; a file added after the backup is gone; the previous content is kept complete; no intent record remains and the outcome record says `committed`; every path is still owned by the proxy user with no mode wider than `0640`; the proxy answers ready |
| `refused` | A truncated archive fails the preflight and the proxy container is the same container with the same start time; no `down`, `up` or commit was run |
| `commit_fails` | The archive is damaged after the preflight passed and the stack is down: the operation fails, the data directory is unchanged, no record or backup directory is left, and the proxy is serving again |
| `kill_sweep` | The restore process is SIGKILLed during the swap, at a moment taken from the volume (the intent record appearing) plus a small delay. At death, no previous file is lost (live + set aside = all). After the next start of the real proxy: died mid-swap → all previous files are back and the outcome says `rolled_back`; otherwise all of one state or all of the other, never a mixture; the proxy is ready and no intent record remains |
| `agent_crash_*` | The agent is killed between stages. What it reports afterwards is recorded beside what Docker says. **Recorded, not judged**: what an interrupted `restore.commit` must report is not a contract yet |

The sweep reports which phases the kills actually landed in (`phases_hit`). A
phase that was not hit was not tested by that run; the deterministic matrix
for every step is `TestRestoreInPlace_CrashAtEveryStep_NextStartHoldsThePreviousContent`.

## Running

```bash
# Go 1.27.4; from the repository root
CGO_ENABLED=0 go build -o test/lifecycle-conformance/restore-probe/culvert .
(cd cmd/culvert-maint && go build -o /tmp/culvert-maint .)
docker build -t culvert/proxy:pinned test/lifecycle-conformance/restore-probe
rm test/lifecycle-conformance/restore-probe/culvert

sudo python3 test/lifecycle-conformance/restore-probe/probe.py \
    --agent /tmp/culvert-maint --out /tmp/restore-probe.json --i-own-this-daemon
```

About 4 minutes with the defaults (2 runs of each scenario, 40 sweep trials).

| Exit | Meaning |
|---|---|
| 0 | Every scenario ran to its end and every property held |
| 1 | A property was violated (listed per scenario in the output and the JSON) |
| 2 | Incomplete: a scenario did not run to its end, or a prerequisite is missing. Never a pass |

`--i-own-this-daemon` is required: the probe retags `culvert/proxy:pinned` and
deletes its own volumes.

Negative control, measured: with the proxy and agent built from the commit
before the fix, `success` reports 6 violations and `refused` 3 (the proxy was
stopped for a restore that could not start).

## Limits

- Process death only. No host power loss, no `dockerd` crash, no storage fault;
  a SIGKILLed process's completed renames are in the page cache either way.
- No systemd. The unit's control-group kill is emulated for the agent-crash
  scenarios (SIGKILL the agent, SIGTERM what it started, SIGKILL after 10 s).
- `privilege_mode = "docker_group_lab"`: the agent calls `docker` directly.
  The sudoers wrapper passes the same restore arguments (no new flag was
  added), but this probe does not go through it.
- The image is Alpine plus the real binary and the release image's `proxy`
  user, not the release image's layers. Unencrypted archives only.
- One Docker and Compose version per run; the versions are in the JSON.
