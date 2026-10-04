#!/usr/bin/env bash
# External ESXi qualification through operator SSH and authenticated tty1 sudo.
# This owns no VM lifecycle. Enrollment/pinning must already be independently
# recorded. Invoke directly, never under esxi-lab.py's operation.lock.
set -euo pipefail
set +x
ADAPTER_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${ESXI_SHARED_LAB:?explicit pinned shared appliance-lab.sh path required}"
: "${ESXI_SHARED_SHA256:?expected shared source SHA256 required}"
: "${ESXI_PYTHON:?}" "${ESXI_ADAPTER:?}" "${ESXI_SCOPE:?}"
: "${ESXI_HOST_KEY_ALIAS:?}" "${LAB_DIR:?}" "${LAB_HOST:?}" "${LAB_PRIV_CMD:?}"
[[ ${ESXI_OPERATOR_ENROLLED:-0} == 1 && ${ESXI_HOST_KEY_PINNED:-0} == 1 ]] || {
  echo 'Operator enrollment and authenticated console host-key pin are required.' >&2; exit 90;
}
[[ $ESXI_SHARED_SHA256 =~ ^[a-f0-9]{64}$ ]]
[[ $(sha256sum "$ESXI_SHARED_LAB" | cut -d' ' -f1) == "$ESXI_SHARED_SHA256" ]]
[[ -d $LAB_DIR/secrets && ! -e $LAB_DIR/operation.lock ]]
[[ -s $LAB_DIR/secrets/id_ed25519 && -s $LAB_DIR/secrets/known_hosts ]]
[[ -s $LAB_DIR/secrets/bootstrap-console-password ]]
ssh-keygen -F "$ESXI_HOST_KEY_ALIAS" -f "$LAB_DIR/secrets/known_hosts" >/dev/null

python3() { "$ESXI_PYTHON" "$@"; }
export -f python3
# Read-only ownership, placement and current guest-address checks. Errors remain
# generic: scope configuration and hypervisor output can contain private data.
esxi_owned_target() {
  python3 - "$ESXI_ADAPTER" "$ESXI_SCOPE" "$LAB_HOST" "$LAB_DIR" "$ESXI_HOST_KEY_ALIAS" <<'PY'
import importlib.util, pathlib, sys
try:
    spec = importlib.util.spec_from_file_location('esxi_lab_access', sys.argv[1])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    lab = module.Lab(pathlib.Path(sys.argv[2]))
    module.validate_scope(lab.c)
    module.require(lab.run == pathlib.Path(sys.argv[4]).resolve(), 'run directory mismatch')
    module.require(lab.state.get('name') == sys.argv[5], 'host-key alias mismatch')
    module.require(lab.vm(timeout=15).get('runtime', {}).get('powerState') == 'poweredOn', 'not powered on')
    module.require(lab.guest_ip(timeout=30) == sys.argv[3], 'guest address changed')
except Exception:
    print('Owned ESXi target/address verification failed; qualification stopped.', file=sys.stderr)
    sys.exit(90)
PY
}
esxi_owned_target
mkdir "$LAB_DIR/access-aware-qualify.lock" || {
  echo 'Qualification lock exists; reconcile the prior run before proceeding.' >&2; exit 90;
}
trap 'rc=$?; if declare -F redact_tree >/dev/null; then redact_tree || true; fi; rmdir "$LAB_DIR/access-aware-qualify.lock" 2>/dev/null || true; exit "$rc"' EXIT

export LAB_EXTERNAL=1 LAB_LIBRARY_ONLY=1
source "$ESXI_SHARED_LAB"
SECRET_FILES+=(bootstrap-console-password)
source "$ADAPTER_HERE/restore-checks.sh"

# OpenSSH uses the first value supplied for these options. Prefixing the pins
# protects even the shared function-local SCP_OPTS, which otherwise says "no".
ssh() { command ssh -F none -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$SEC/known_hosts" -o "HostKeyAlias=$ESXI_HOST_KEY_ALIAS" "$@"; }
scp() { command scp -F none -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$SEC/known_hosts" -o "HostKeyAlias=$ESXI_HOST_KEY_ALIAS" "$@"; }
sftp() { command sftp -F none -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$SEC/known_hosts" -o "HostKeyAlias=$ESXI_HOST_KEY_ALIAS" "$@"; }
# timeout executes external commands, not shell functions. Preserve the same
# pin when the shared refusal checks use `timeout N ssh/scp/sftp ...`.
timeout() {
  local duration=${1:?}; shift
  case ${1:-} in
    ssh|scp|sftp)
      local program=$1; shift
      command timeout "$duration" "$program" -F none -o StrictHostKeyChecking=yes \
        -o "UserKnownHostsFile=$SEC/known_hosts" -o "HostKeyAlias=$ESXI_HOST_KEY_ALIAS" "$@" ;;
    *) command timeout "$duration" "$@" ;;
  esac
}
# During a reboot VMware Tools may temporarily report no guest IP. Power and
# ownership alone are the liveness predicate; gpriv rechecks the address later.
qemu_alive() { python3 "$ESXI_ADAPTER" --scope "$ESXI_SCOPE" alive >/dev/null 2>&1; }
gpriv() {
  esxi_owned_target || return 90
  # LAB_PRIV_CMD is the shared library's explicit word-list contract.
  # shellcheck disable=SC2086
  $LAB_PRIV_CMD "$@"
}

# Defer the shared unguarded compose down/restore/up block to the stronger
# ESXi restore fixture, which owns both maintenance locks and validates volumes.
eval "$(declare -f gate | sed '1s/^gate /esxi_shared_gate /')"
gate() { [[ $1 != 6b ]] || return 1; esxi_shared_gate "$@"; }
eval "$(declare -f check | sed '1s/^check /esxi_shared_check /')"
check() {
  if [[ $1 == 6b && $2 == restore-commit && $3 == not-run ]]; then
    esxi_shared_check "$1" "$2" not-run 'deferred to the guarded ESXi actual-restore fixture'
  else esxi_shared_check "$@"; fi
}
esxi_restore_target_allowed() { [[ $1 == "$LAB_HOST" ]] && esxi_owned_target; }
esxi_restore_transport() {
  local archive=${1:?}
  esxi_restore_valid_backup "$archive" || return 90
  {
    printf "timeout --signal=TERM --kill-after=10s 570s bash -s -- %q <<'CULVERT_ESXI_RESTORE_SCRIPT'\n" "$archive"
    esxi_restore_guest_script
    printf '\nCULVERT_ESXI_RESTORE_SCRIPT\n'
  } | gpriv --timeout 600
}
lab_before_signed_update() {
  # A plain function call preserves the restore fixture's errexit semantics.
  esxi_actual_restore
}

# The shared 6b restore is disabled above, so its post-reboot sentinel cannot
# establish persistence of our step-9 mutation. Both fresh and resumed runs use
# the guarded restore's exact recorded marker and the post-reboot policy.
esxi_restore_persistence() {
  if python3 "$ADAPTER_HERE/restore-persistence.py" "$EV/08-policy.json" "$EV/09-post-backup-mutation-name.txt"; then
    check 8 restore-persisted pass 'The exact post-backup mutation remains absent and the original allow rule remains enabled after signed lifecycle and maintenance reboot.'
  else
    check 8 restore-persisted fail 'Restored policy persistence could not be established.'
  fi
}

if [[ ${ESXI_EXTENDED_CAMPAIGN:-0} == 1 ]]; then
  source "$ADAPTER_HERE/candidate-hooks.sh"
fi
if [[ ${ESXI_ADAPTER_LIBRARY_ONLY:-0} == 1 ]]; then return 0; fi
check ESXi access-aware-harness info "shared source SHA256 $ESXI_SHARED_SHA256; operator SSH pinned to $ESXI_HOST_KEY_ALIAS; privileged commands use authenticated tty1"
gpriv <<<'cat /proc/sys/kernel/random/boot_id' > "$EV/esxi-boot-id-before.txt"
cmd_qualify
gpriv <<<'cat /proc/sys/kernel/random/boot_id' > "$EV/esxi-boot-id-after.txt"
if [[ -s $EV/esxi-boot-id-before.txt && -s $EV/esxi-boot-id-after.txt ]] &&
   ! cmp -s "$EV/esxi-boot-id-before.txt" "$EV/esxi-boot-id-after.txt"; then
  check 7 esxi-boot-id-changed pass 'guest boot ID changed'
else check 7 esxi-boot-id-changed fail 'reboot not proven by a changed boot ID'; fi
esxi_restore_persistence
# Shared signed-update stays BLOCKED unless LAB_UPDATE_DIR contains a real
# separately prepared registry/evidence fixture. Never manufacture a PASS.
redact_tree
[[ $(failures) == 0 ]]
