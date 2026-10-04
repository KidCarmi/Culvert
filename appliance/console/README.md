# Culvert boot console and local recovery worker

## Durable recovery and confirmed network changes

The same Go executable now supplies `culvert-console-host.service`, a separate
root worker with no socket/listener and no Docker or network-online dependency.
`install.sh` atomically publishes its unit alongside the binary/profile/getty
bundle, then enables it for the next boot. For an already running disposable
guest, run `systemctl daemon-reload` and `systemctl start culvert-console-host`
after installation. Updating a running worker also requires restarting that
unit; do this only with no pending transaction. No sudo permissions are added.

Authenticated network screen `[E]` invokes `sudo .../culvert-console --host=network`.
It requires `ovf.done`, an active worker, one physical en*/eth* interface, one
unambiguous DHCP base file and a compatible managed `60-culvert.yaml`.
DHCP or IPv4 static address/prefix, same-subnet gateway and 1–3 DNS servers are
supported. Bonds, bridges, VLANs, IPv6 configuration, wildcard/renaming ambiguity,
and merged base address/route/DNS lists are refused before queueing. MAC matches
must identify the chosen physical device. Existing complex layouts remain an
administrator recovery task; the console does not flatten them.

`APPLY` saves the previous file's exact bytes, mode or absence and a digest of
the other Netplan files before the worker changes anything. The 120-second
confirmation window starts when queued, uses kernel BOOTTIME, and cannot be
extended by a wall-clock correction. Verify management access from another
client, then type `CONFIRM`; after reconnecting, reopen `[E]` to confirm the same
operation. Local service response is not proof of client reachability.

Loss of the terminal does not stop the worker. Expiry starts rollback; an
interrupted apply or different boot also rolls back. Normal worker polls are
one second, with bounded observations and commands; restoration can take longer
than the confirmation window. Failed attempts back off to 30 seconds. The unit
restarts on failure and starts at boot, but does not promise restoration before
the first network packet. A permanently stopped worker cannot recover until
restarted. Read-only/full storage, unusable Netplan or host damage can prevent
restoration; these cases retain the backup and never claim `rolled_back`.

Private state is `/var/lib/culvert-console/private/state.json` (root:root 0600,
directory 0700), with an exclusive nonblocking flock, bounded regular-file reads,
symlink/hardlink refusal, atomic replacement and file/directory fsync. Corrupt or
unknown-version state is not reset. A sanitized public observation appears at
`/var/lib/culvert-console/status.json`; it excludes Netplan contents and is not a
liveness guarantee. Up to 64 operation/checkpoint records include operation ID,
boot ID, machine ID, UTC time, coarse phase and allowlisted firstboot observations.
Power/retry intent is saved before dispatch. `submitted` means systemd accepted
the request, not that reboot or provisioning succeeded. Boot observations and
before/after IDs remain available even when a caller disconnects.

Managed edits serialize with this worker only. Do not run legacy `culvert-net`,
manual Netplan edits or other privileged network writers during a pending test.
Unexpected file drift enters `conflict` without overwriting it. Preserve the
private state/backup and reconcile through authenticated root recovery; do not
delete the record to hide the conflict. Firstboot/maintenance lifecycle ownership
is unchanged; this worker does not restart stopped application containers.

Read-only diagnostics now show available filesystem bytes/inodes, reported clock
synchronization, resolution of a configured FQDN only, the loopback setup leaf
certificate's dates/SHA256 and the firstboot systemd Job field. Missing data is
`unknown`, not healthy. No Internet prerequisite is invented. Storage warnings
use Culvert reserves of 2 GiB or 10% available space, and 5% free inodes; they do
not delete data or block provisioning. Certificate inspection explicitly does
not establish chain/hostname trust. These checks add no Go module dependencies.

Vendor principles adopted: [Juniper confirmed commits](https://www.juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/junos-configuration-commit.html),
[TrueNAS timed network tests](https://www.truenas.com/docs/scale/25.10/scaleuireference/network/networkinterfacescreens/),
[VMware firstboot prerequisite failures](https://knowledge.broadcom.com/external/article/324989/firstboot-failed-during-install-deployme.html),
and [Netplan's merged input semantics](https://netplan.readthedocs.io/en/stable/netplan-get/).
This is a candidate implementation, not completed enterprise qualification.

This additive component provides an ESXi-style local console after power-on.
It is a static Go host binary built with the root `go.mod` toolchain,
independent of Docker and the Culvert application. There is no new network
listener. The displayed application URL remains `https://<address>:9090` and is
explicitly labelled unavailable until the application starts.

The public screen shows version/candidate status, assigned IPv4/IPv6 addresses,
recorded firstboot checkpoints and live service observations. `F2` or `L` starts
normal Linux/PAM login as `culvert`; `F4` or `3` shows sanitized diagnostics.
Number keys work when a browser console intercepts function keys.

After authenticating, the operator gets network information, setup-token access
through the existing privileged status command, diagnostics, a confirmed retry
of incomplete provisioning, confirmed reboot/shutdown and a recovery shell.
The menu logs out after five minutes without input. An explicitly opened shell
retains normal shell behavior. Key-only installations still require the imported
SSH key; the menu never unlocks the account or invents a default password.
An administrator can set a console password through their authenticated SSH
session with `sudo passwd culvert`.

## Integration boundary with Opus

The Go command lives in `cmd/culvert-console`, with domain logic and white-box
tests in `internal/applianceconsole` and `internal/appliancehost`. Packaging files stay here to avoid
conflicts with the ongoing firstboot/image fix. This slice does **not** modify
`build-ova.sh`, `prepare-guest.sh`, firstboot,
the network helper, the existing status CLI, or the application UI. It does not
change the existing application readiness contract.

Two build hooks are needed when this component is accepted:

1. In `build-ova.sh`, beside the provision/os-maintenance overlay copy, copy
   `appliance/console` to `$OV/opt/culvert-appliance/console`, then build from the
   repository root using its pinned Go compiler:

   ```bash
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
     -o "$OV/opt/culvert-appliance/console/culvert-console" ./cmd/culvert-console
   ```

   The executable must be copied with mode 0755. It is a build artifact and is
   ignored by Git; no compiler or Python runtime is needed in the guest.
2. In `prepare-guest.sh`, after the `culvert` account and existing helpers have
   been installed, run:

   ```bash
   bash /opt/culvert-appliance/console/install.sh
   ```

The installer checks that the binary executes, PAM login, sudo and the account before
installing the tty1 getty override and root-owned login profile hook. It does
not restart a live console, add sudo rules, change the firewall or configure
autologin. Normal tty2/serial/SSH login remains available. Do not add an ordering
dependency on Docker, network-online or culvert-firstboot: an unavailable
dependency must not prevent the menu appearing.

To evaluate in an **owned disposable guest** after copying this directory:

```bash
sudo bash /tmp/culvert-console-dev/install.sh
sudo systemctl daemon-reload
sudo systemctl restart getty@tty1.service
```

The latter command ends any tty1 session; run it through authenticated SSH only
in the disposable qualification VM. Reboot validation must then prove the same
menu appears without manually restarting getty.

To remove the menu through SSH or tty2, first resolve pending network transactions. Keep the recovery worker running until rollback completes:

```bash
sudo rm /etc/systemd/system/getty@tty1.service.d/culvert-console.conf
sudo rm /etc/profile.d/culvert-console.sh
sudo systemctl daemon-reload
sudo systemctl restart getty@tty1.service
```

## Shared status contract (schema version 1)

```bash
/opt/culvert-appliance/bin/culvert-console --json
/opt/culvert-appliance/bin/culvert-console --text
```

These are read-only and never include a setup token, `.env`, raw journals or
OVF data. Seven fixed probes execute concurrently with four-second subprocess
timeouts (HTTP probes have two-second deadlines). Requests use loopback only,
disable curl's default configuration files and proxies, do not follow redirects,
and reject oversized output instead of accepting a truncated response. Only the
self-signed loopback setup-status read uses a TLS verification exception.
No Docker API or command is required to render the display.

- `phase`: `unknown`, `waiting`, `running`, `failed`, `provisioned`, `ready`.
- `reason`: stable reason code; `message`: operator explanation.
- `steps`: each existing checkpoint is `recorded` or `not_recorded`. This is
  deliberately evidence of a marker, not a fabricated current step or percentage.
- `firstboot`: allowlisted systemd fields. A previous failure remains visible
  during automatic retry. An inactive incomplete unit is explicitly not running.
- `administrator_enrolled`: true only on HTTP 200 and an explicit `needsSetup: false`.
- `ready`: requires application health HTTP 200, explicit enrollment, readiness
  HTTP 200 and `ok` for policy_loaded, policy_posture, ca and setup_complete.
  It also requires the completion marker and a loaded, settled firstboot oneshot
  with `Result=success` and `ExecMainStatus=0`. The accepted states are
  active/exited or inactive/dead (the normal condition-skipped state after reboot).
  Missing observations and transitioning services cannot become ready. Independent
  management availability still permits setup access. This is a conservative console summary.
- `traffic_verified`: always false; local health probes cannot prove a client
  successfully passes through the proxy.

Terminal text is restricted to printable ASCII so untrusted metadata cannot
inject terminal controls. The installed binary and hooks are root-owned.
Public key presses can only refresh,
view this sanitized status, or invoke `/bin/login culvert` without `-f`.
Recovery actions additionally check the effective Unix identity, use fixed argv
and existing sudo authorization. No password is captured by the console program.
Setup-token output stays on the authenticated terminal and is not a diagnostic
export. The public root-owned process is a narrow getty/login wrapper, not an
HTTP server and not an unauthenticated shell.

## Package boundary design

This records the new boundary required by `CLAUDE.md` and the package-isolation
roadmap. `internal/applianceconsole` owns status interpretation, display layout,
key-to-action policy and recovery guards. `NewCollector` and `NewActions` copy
explicit dependencies into private fields. The package does not depend on the
application's main package, singletons, Docker or a generic common service.

`cmd/culvert-console` owns process startup, fixed production paths, signal
cancellation, bounded subprocess probes, effective-identity checks, Linux
terminal I/O and concrete command wiring. It uses the existing `x/sys/unix`
dependency. No module dependencies are added. Terminal text is CLI output, not
application logging; raw probe stderr and credential-bearing output never enter
the public status snapshot.

Collection is read-only: existing firstboot code owns marker persistence and
the application owns enrollment/readiness. A collection call starts seven bounded
probes and joins them before returning. There are no detached background workers.
The command owns cancellation; child processes use that context. Menu input uses
bounded polling, never a background stdin reader that could consume a later
PAM password. Terminal modes/cursor are restored before login, confirmation or
recovery actions; those actions synchronously own input until they exit. systemd
owns the getty process and its shutdown process group. The console adds no
network listener; its separate recovery worker owns bounded persistent state.

GUI parity scope: `--login` and `--admin` select getty/PAM process roles, while
`--json` and `--text` serialize the same read-only host status. They introduce no
application configuration knobs. This first slice is explicitly local recovery;
host recovery API/UI and browser wizard parity remain follow-on work. Existing
application setup continues at the displayed management URL. This is not a claim
that the complete provisioning experience or its GUI parity has shipped.

## Tests and remaining work

```bash
go test -race -shuffle=on -count=2 ./internal/applianceconsole ./cmd/culvert-console
go vet ./internal/applianceconsole ./cmd/culvert-console
golangci-lint run ./internal/applianceconsole/... ./cmd/culvert-console/...
CGO_ENABLED=0 go build -trimpath -o appliance/console/culvert-console ./cmd/culvert-console
bash -n appliance/console/install.sh
bash -n appliance/console/profile.sh
```

Tests cover absent/broken services, malformed observations, stale checkpoints,
readiness/enrollment distinctions, terminal escape filtering, secret exclusion,
unauthenticated action refusal and retry/power confirmation boundaries.

Real ESXi smoke results are recorded separately; unit tests do not establish
PAM/getty/keyboard behavior. The incomplete ClamAV image remains a product
failure even if the console handles it correctly.

The [Go ESXi smoke report](evidence/esxi-go-smoke.json) identifies implementation
commit `654af2fe`, compiler, base OVA and installed binary/hook hashes. Both Go
test packages passed twice with shuffled execution inside Ubuntu. Linux race
CI, vet, the static build/compiler check and focused repository lint passed.
Real PAM password rejection, authenticated login/logout, Docker-independent
operation and automatic console startup after reboot passed. Machine identity
was retained. The owned VM was deleted and per-run private files removed.

![Go authenticated recovery menu on ESXi](evidence/esxi-go-admin.png)

The [retained reboot screenshot](evidence/esxi-go-boot-partial.png) is partial,
even after a tty2/tty1 redraw. It is **not** full visual proof of the boot screen.
The complete public menu was separately verified in the guest's `/dev/vcs1`
buffer after reboot. This capture limitation remains open. The Go console
service reported 10,149,888 bytes at one observation, not a peak or whole-VM
resource qualification. This was a development overlay, not a rebuilt OVA.

The [historical Python ESXi smoke report](evidence/esxi-smoke.json) records the exact base OVA
and installed overlay hashes. All 26 tests passed in the Ubuntu guest; real
VMware keyboard/PAM login, invalid-password refusal, logout, stopped-Docker
operation and automatic console startup after reboot passed. The owned VM was
deleted afterward. This is development-overlay evidence, not a rebuilt OVA.
These results and the image below apply only to the superseded Python prototype,
not the Go implementation. The prototype service reported about 14.1 MiB at one observation; this is not a
peak or whole-appliance resource qualification.

![Historical Python console after reboot](evidence/esxi-boot-menu.png)

Some ESXi screenshot captures were partial even though the guest's virtual
terminal buffer held the complete menu. The retained reboot capture follows a
tty2/tty1 switch to force a redraw; no image editing was used. This capture
limitation remains recorded rather than counting a partial image as visual proof.

Follow-on work: persistent explicit firstboot step/error events, guided network
editing with host-side rollback (the current menu provides information/recovery
only), independent browser bootstrap service, and application wizard integration.
No network Apply button is offered before rollback is implemented. The proposed
full browser setup experience is not delivered by this console slice.


## Visual console integration

The [visual-console ESXi report](evidence/esxi-ui-smoke.json) records implementation
`6c7e7927`, the exact guest overlay hashes and focused Linux race CI. Real PTY
tests cover 80x25/80x24, linux/vt100/dumb, keyboard navigation, resize, bracketed
paste and termios restoration on exit/SIGTERM. Native guest tests and real
VMware keyboard navigation, PAM rejection/login/logout, Docker-down operation
and automatic startup after reboot passed. The disposable VM was deleted.

The known candidate provisioning failure remains visible as a blocker. The
retained [public capture](evidence/esxi-ui-public-partial.png) and
[authenticated capture](evidence/esxi-ui-admin-partial.png) from the ESXi API are
partial and are not full visual proof. Complete frames were visually inspected
earlier; final live terminal content and all four views were separately checked
in `/dev/vcs1`. Captures were not edited or reconstructed; this limitation
remains open. Older evidence above
belongs to the implementation revisions recorded in those reports.

The home view follows the supplied 80-column terminal composition: cyan brand
and selection, appliance/network identity, a scoped status and next action,
browser handoff, four visible choices, and an authentication footer. Both 80x25
and 80x24 preserve the bottom margin. Larger terminals center an 80x25 panel. Smaller terminals show a compact paged
view; details wrap long values and support Up/Down or PageUp/PageDown. Terminals
smaller than 20x7 request resizing. Numbers open views immediately; arrows/Tab
select only the four visible entries, and Enter opens. B/Escape returns home.

1. Network information: read-only observed addresses, links, gateways and DNS.
2. Setup access: existing web onboarding; S invokes the existing privileged
   setup-status helper only after PAM authentication.
3. Diagnose readiness: observed failure, source/time and recorded checkpoints.
4. Installation report: current build, setup and check observations, with the
   JSON equivalent available through `culvert-console --json` over SSH.

L/F2 signs in; Q logs out of the authenticated menu. 0 opens authenticated
recovery (retry, confirmed power operations, shell). Public recovery requests
only enter normal login; they do not queue an action to run after login. Network
E opens authenticated recovery. No new network writer or rollback claim is
introduced. Mode remains unknown instead of inferring DHCP/static from an IP.
The report is a current observation, not a persisted receipt or attestation;
configuration revision and external traffic verification are not collected.

| Display fact | Authoritative observation |
| --- | --- |
| Host / build | Bounded `/etc/hostname` and existing build-info JSON |
| Interfaces / addresses / link | Fixed `ip -j address show scope global`; sysfs physical/lower interfaces; IPv4 and IPv6 |
| Gateways | Fixed IPv4/IPv6 `ip -j route show default` |
| DNS | IP-only nameserver entries from `/run/systemd/resolve/resolv.conf`; absent means unknown |
| Setup availability / enrollment | HTTP 200 plus typed `needsSetup` boolean from the existing loopback 9090 setup endpoint |
| Status / checkpoints | Existing systemd fields and firstboot marker files |
| Application checks | Existing health/readiness endpoints; no traffic verification inferred |

The management URL uses observed addresses and the existing appliance's
published 9090 port contract (`appliance/provision/culvert-status` and firstboot),
not the reference demo's 8443 placeholder. The URL is offered only after the
local management probe succeeds. This does not prove a browser can reach it,
verify a certificate from that browser, or discover custom listener bindings.

Rendering supports basic ANSI colors on known compatible terminals, monochrome
on vt100 or with NO_COLOR, and printable line-oriented output for TERM=dumb or
unknown terminals. Plain mode rechecks status every five seconds, prints changed
frames with an observation timestamp, and suppresses identical frames. Bracketed paste is discarded; queued input is flushed before
PAM/recovery handoff. ASCII sanitization precedes the addition of renderer-owned
escape sequences. No external UI library or module dependency is introduced.

Tests include deterministic readiness fixtures, layout/long-field/paging checks,
privilege boundaries and real Linux pseudo-terminal navigation, resize, paste
and termios restoration. Fixture addresses in tests are never production data.
Historical smoke evidence above applies to its recorded implementation commit;
new visual verification is recorded separately.

## Failure handling and hardening contract

The [hardening ESXi report](evidence/esxi-hardening-smoke.json) records runtime
`f64e9ec1`, guest binary/hook hashes, native shuffled tests, PAM rejection/login/
logout, live terminal views, mismatched-terminal rejection and reboot checks.
[Linux race and fuzz CI passed](https://github.com/KidCarmi/Culvert/actions/runs/37156507792).
The owned VM was deleted, an independent inventory found zero matching lab VMs,
and private run files were removed. This remains a development overlay on the
recorded candidate OVA; no new full-appliance qualification is claimed.

The terminal adapter has a single input owner. A bracketed paste must terminate
within two seconds; incomplete/unsupported escape sequences end the menu instead
of treating their remaining bytes as commands. This can require signing in again
after an unsupported terminal key. Input disconnection, output failure, failed
termios restoration or failed input flushing also end the session without an
automatic PAM/recovery handoff. Input and output must refer to the same terminal.
The getty service can start a fresh public console; normal tty2/SSH recovery
remains available. The console never keeps a background password reader.

Confirmation input has a one-minute absolute deadline, a 128-byte limit and
cancellation-aware polling, including while waiting for an unfinished canonical
line. Queued input is drained before prompting and after a complete answer.
Each recovery command rechecks cancellation and effective identity. Retry needs
a loaded unit in failed/inactive state and a positively absent completion marker,
then rechecks that state after confirmation and after `reset-failed` returns,
before requesting a start. A missing observation, inaccessible
marker, symlink or nonregular marker does not authorize retry. These checks do
not make observation and systemd dispatch atomic; firstboot still owns its
idempotency and concurrency protection.

Public metadata reads accept bounded regular files only. Linux opens them with
O_NONBLOCK before checking the descriptor, so a FIFO with no writer cannot stall
collection; resolver symlinks to regular files remain supported. This is a local
filesystem guarantee, not a deadline for an unresponsive remote filesystem.

Network addresses require an explicit valid prefix and matching address family.
Tentative, DAD-failed and deprecated addresses are excluded from setup URL
candidates. The boolean fields follow
[iproute2's address JSON output](https://github.com/iproute2/iproute2/blob/main/ip/ipaddress.c).
The home screen resolves its displayed NIC from the displayed address; default
routes, which can belong to another NIC, are shown separately in network details.
Rendering bounds dimensions before arithmetic and bounds pagination to prevent
overflow or oversized allocations from invalid terminal sizes.

Regression coverage includes malformed/unterminated input with termios
restoration and no dispatch, cancellation during confirmation, disconnected
input, cancellation between retry commands, uncertain completion markers,
FIFO/device metadata, mismatched NIC/address observations and bounded layout
fuzzing. These tests establish specific behavior, not a production certification.
The earlier ESXi reports apply only to their recorded revisions.

Remaining release work includes integrated OVA qualification, network changes
with independent rollback, durable audit retention/forwarding, session policy for
external PAM/sudo/recovery-shell children, and a completed security review. The
menu idle timeout does not govern an interactive shell once it has been handed
off. The firstboot archive-content blocker and ESXi screenshot capture limitation
remain separate open issues. This PR stays draft until the integration and
qualification evidence support promotion.

## Recovery lifecycle, journal records and installation

The [lifecycle ESXi report](evidence/esxi-lifecycle-smoke.json) records exact bundle
`0e0e5d7b`, native tests and installer fault injection, real PAM/shell handoffs,
verified journal UID/correlation with output excluded, live views and reboot.
[Final-bundle Linux CI passed](https://github.com/KidCarmi/Culvert/actions/runs/37158252080).
Both disposable validation VMs were deleted; independent inventory found zero
matching lab VMs and private run files were removed. Test-fixture corrections and
the fresh-run validation are recorded in the report, not hidden as product passes.

The Linux execution adapter accepts an exact allowlist of commands and argv.
It snapshots/restores terminal modes around every child, including unsuccessful
commands and cancellation; restoration failure ends the menu. Cancellation first
sends SIGTERM so PAM/sudo can perform cleanup, then forces termination of the
direct child after two seconds. TERM is preserved only for supported, printable
terminal names, and the child environment excludes inherited credentials.
The getty override explicitly uses `KillMode=control-group`, `SendSIGHUP=yes` and
a five-second stop timeout. This covers processes still in that service cgroup;
it is not containment of processes moved into separate PAM/logind session scopes
or a replacement for logind's session policy. Recovery shells remain privileged
operator tools with their existing permissions.

Each allowlisted child has paired attempt/result records sent through the
[native systemd journal protocol](https://systemd.io/JOURNAL_NATIVE_PROTOCOL/).
Records contain a random correlation ID, fixed action name, phase, coarse outcome,
effective UID and UTC timestamp. Application fields contain no argv, keystrokes, credentials,
child output or raw errors. `returned` means the command exited successfully;
it does not assert successful login, completed provisioning or verified traffic.
Inspect with `journalctl -t culvert-console -o json`; journald also attaches
trusted process/UID metadata. PAM/sudo retain their own authentication logs.

Each send is bounded to 300 ms, and result logging gets a separate budget after
cancellation. If delivery fails the operator sees an explicit coverage warning;
recovery remains available and commands are never repeated for logging. A Unix
datagram send acknowledges transport only: journal storage, rate limiting,
retention, forwarding and power-loss durability remain host policy. Missing result
records can indicate an interrupted process, host shutdown or delivery loss.

The installer validates the binary under a ten-second timeout and checks profile
syntax before changing destinations. A local lock excludes concurrent installs.
All three files are staged and backed up before publication; same-filesystem
renames replace the binary and profile, then activate getty last. Ordinary errors
and catchable signals roll back published files; symlink/nonregular targets are
refused. Atomic binary replacement supports upgrading a running executable.
If rollback itself fails, backup files are retained with an explicit error.
This is atomic per file, not a power-loss-safe transaction across filesystems;
SIGKILL/power loss may leave a mixed bundle or staging files. The installer never
restarts getty, changes sudo policy or adds network configuration.

Tests inject failure at every publication step, failed staging, failed first
installation, symlink targets and lock contention; verify rollback, ownership,
modes and repeated installation. Linux PTYs verify terminal restoration after
child success, termination and forced termination. Unix socket tests exercise
journal serialization, pairing, cancellation, missing transport and backpressure.

## Observation integrity and retry rechecks

HTTP probes put `--disable` first, as required by
[curl's configuration-file opt-out](https://curl.se/docs/manpage.html#-q).
This prevents an account's curl configuration from changing the request method,
headers or destinations despite the restricted process environment. A Linux
regression uses a real curl and an isolated local server: the control request
loads a hostile configuration, while all three production probe argument lists
remain GET requests without its injected header.

Subprocess output above 64 KiB is rejected in full. A valid JSON/status prefix
followed by excess data cannot become a successful observation through truncation.
Memory retention and execution deadlines remain bounded.

A completion marker cannot hide an unknown, unloading or restarting firstboot
unit. Readiness additionally requires the known successful oneshot states
documented above. The setup endpoint remains independently observable so an
uncertain provisioning summary does not suppress working management access.
Retry rechecks state after clearing a failure; a new completion marker, running
unit or missing observation prevents this console from requesting a start.
These are observation checks, not a cross-process provisioning lock.

The [observation-integrity report](evidence/esxi-observations-smoke.json) records
runtime `6f40e5b4`. [Linux CI passed](https://github.com/KidCarmi/Culvert/actions/runs/37182487320)
with race tests, 204,040 fuzz executions, vet, static compiler checks and root
installer fault tests. Both test packages passed twice in ESXi Ubuntu. A real
temporary systemd oneshot confirmed active/exited completion and inactive/dead
condition skipping. Installation, PAM/shell/journal checks and all four live
views passed; the owned VM and private run files were removed.

**Reboot qualification remains open for this run.** Guest access did not return
within the helper's 150-second deadline. A later bounded observation found the
public console automatically active and verified installed hashes, but does not
erase the timeout failure or establish a boot-time guarantee. The interrupted
helper did not retain the prior machine ID, so this run does not claim machine-ID
continuity. Earlier boot/access waits and the incomplete first authentication
attempt are recorded in the report. No host policy was bypassed to proceed.

Opus's separate [maintenance-reboot finding F-OSU-REBOOT-1](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-5974258410)
also remains an appliance qualification concern. This older baseline overlay
does not validate that candidate or its proposed fix.
