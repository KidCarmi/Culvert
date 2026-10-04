# Routine SSH and local administrative recovery

This change is for newly built appliances. It does not update deployed guests or
move existing credentials. Qualify a new candidate before changing deployment
guidance; the previously qualified OVA retains its previous access policy.

## Operator workflow

Connect with the imported key as `culvert-operator`, not `culvert`. An interactive
SSH session offers `help`, `status`, `status-json`, `diagnostics` and `exit`.
Automation may request an exact command, for example:

```text
ssh culvert-operator@appliance status-json
```

These are read-only, credential-free console observations. There is no remote
shell, SFTP/SCP, forwarding, setup-token display, direct maintenance-agent access,
Docker access, reboot, or password reset. A noninteractive connection without a
command prints help. Input is literal: shell syntax and extra arguments are
rejected. An interactive session has a five-minute input timeout, a thirty-minute
lifetime and a 256-command limit. Each observation has a fifteen-second bound and
a 256 KiB output limit.

Administrative recovery remains on the VM console: authenticate through PAM as
the separate local `culvert` account, then use the existing recovery menu and
password-gated sudo. This is an explicit out-of-band privilege boundary, not an
SSH command named “recover.” The imported SSH key authorizes the operator role;
it does not grant root. First boot must establish a usable local administrative
password (including the existing generated initial-password handoff when none
was imported), before declaring the appliance ready. Local recovery retains its
existing audit behavior; journal delivery failure is not claimed to produce a
durable audit record.

## Enforcement and ownership

`internal/applianceaccess` owns the fixed command/identity policy. It has no
mutable state, network client or privileged operation. `cmd/culvert-access` owns
the Linux login-shell adapter, bounded terminal input, process cancellation and
fixed child execution. Only the adapter performs OS identity lookup. The
existing `culvert-console --text`, `--json` and `--report` paths own public
observations. No credential enters that read model.

Provisioning must install the matching pieces together:

- Root-owned static `/opt/culvert-appliance/bin/culvert-access`, executable and
  not writable by the operator, is the operator's actual login shell. No Bash
  login shell, profile or `BASH_ENV` hook precedes the forced command.
- `culvert-operator` has its own primary group only and no sudo rule, root
  membership, `adm`, `docker`, maintenance-agent or other supplemental group.
  The adapter independently refuses mismatched IDs or supplementary groups.
- SSH admits only `culvert-operator`, requires public-key authentication, forces
  the Go interface and disables user rc/environment hooks, tunnels and all
  forwarding, including Unix sockets. An authorized-key command cannot replace
  the server's forced command. SFTP and legacy SCP requests are rejected as
  unsupported commands.
- SSH reads only `/etc/ssh/culvert-authorized-keys/culvert-operator`, a root-owned
  file outside either user's home. The root-only `--import-keys` provisioning
  entry point reads the fixed imported key path as the local culvert UID/GID
  with no supplementary groups, a three-second deadline and a 64 KiB limit.
  It accepts at most 64 valid public-key lines, rejects options-bearing or
  malformed entries without publishing a partial result, removes comments and
  atomically publishes canonical keys. Missing input publishes an empty file.
  First boot's durable `access.done` checkpoint prevents automatic re-import
  after success. No key content is printed.
- Children run with fixed argv, working directory `/`, stdin `/dev/null` and a
  fresh minimal environment. No original command is evaluated or echoed. Root
  filesystem ownership and maintenance socket permissions remain independent
  requirements; this interface does not change them.
- The local `culvert` administrator is not admitted over SSH. Its existing
  tty1/PAM workflow remains separate; routine operator login never enters it.

`--version` prints a fixed packaging identifier without a host probe. It is not
an SSH command or an administrative escape. These internal account/login-shell
entry points are not a new remotely configurable product setting; browser
administration and existing console recovery remain their established surfaces.

## Verification and limits

Unit tests exercise exact commands, alternate login-shell argv, PTY/non-PTY
selection, shell/subsystem injection, root/group rejection, environment isolation,
bounded input/output and the SSH configuration contract. They do not establish
the deployed account's groups, effective sudo policy, native sshd configuration,
file ownership or socket permissions. New-candidate qualification must inspect
those properties, plus local PAM recovery with both imported-password and
key-only provisioning. No production-hardening claim follows from unit tests
alone.

An explicitly opted-in disposable Linux CI fixture also runs a real loopback
sshd with a locked operator account and `UsePAM yes`. It checks effective sshd
configuration and actual PTY/non-PTY commands, input isolation, exec/SFTP/SCP
refusals, Unix/TCP forwarding, rc/environment injection, a key placed in the
user-owned authorization file and local-administrator SSH refusal. It uses the
real Go access binary and a read-only console stub; it does not qualify the
complete appliance or local PAM recovery. It refuses existing operator
accounts/groups or its fixed installation paths before creating anything.
Run only on a disposable runner, with openssh-server/client installed:

```sh
CGO_ENABLED=0 go build -o /tmp/culvert-access ./cmd/culvert-access
go test -c -o /tmp/culvert-access.test ./cmd/culvert-access
cd cmd/culvert-access
sudo env CULVERT_ACCESS_SSH_FIXTURE=1 \
  CULVERT_ACCESS_TEST_BINARY=/tmp/culvert-access \
  /tmp/culvert-access.test -test.run '^TestAccess' -test.count=1
```

The same root run covers isolated key publication, symlink refusal,
unprivileged source reads and blocked-reader cancellation. Windows execution
can check portable policy/parser tests and cross-compile these Linux tests; it
cannot establish a passing native SSH/PAM result.

OpenSSH documents that ForceCommand is invoked through the user's login shell,
and that `DisableForwarding` disables all forwarding features. Its documentation
also warns that environment acceptance can bypass restricted environments:
[sshd_config(5)](https://man.openbsd.org/sshd_config).
