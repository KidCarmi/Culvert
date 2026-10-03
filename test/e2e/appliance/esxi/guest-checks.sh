#!/usr/bin/env bash
# Reuse the pinned QEMU lab's guest assertions over a real ESXi guest.
set -euo pipefail
: "${ESXI_PYTHON:?}"
python3() { "$ESXI_PYTHON" "$@"; }
export -f python3
export LAB_LIBRARY_ONLY=1
source "$(dirname "$0")/../lab/appliance-lab.sh"
: "${ESXI_GUEST_IP:?}" "${ESXI_ADAPTER:?}" "${ESXI_SCOPE:?}" "${ESXI_PYTHON:?}"
SSH_OPTS=(-F none -i "$SEC/id_ed25519" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new
  -o "UserKnownHostsFile=$SEC/known_hosts" -o ConnectTimeout=10
  -o BatchMode=yes -o LogLevel=ERROR -o ServerAliveInterval=15 -o ServerAliveCountMax=2)
gssh() { timeout 120 ssh "${SSH_OPTS[@]}" "culvert@$ESXI_GUEST_IP" "$@"; }
# Shared OS-update code also calls ssh directly, so it uses a localhost tunnel
# to guest:22 with the SAME pinned host key and key file.
qemu_alive() { "$ESXI_PYTHON" "$ESXI_ADAPTER" --scope "$ESXI_SCOPE" alive >/dev/null 2>&1; }
BOOT_STARTED=1
case "${1:?qualify}" in
  qualify)
    gssh 'cat /proc/sys/kernel/random/boot_id' > "$EV/esxi-boot-id-before.txt"
    # cmd_qualify's one direct ssh invocation targets localhost:LAB_SSH_PORT.
    SSH_OPTS+=(-p "$LAB_SSH_PORT" -o "HostKeyAlias=$ESXI_GUEST_IP")
    gssh() { timeout 120 ssh "${SSH_OPTS[@]}" culvert@127.0.0.1 "$@"; }
    cmd_qualify
    gssh 'cat /proc/sys/kernel/random/boot_id' > "$EV/esxi-boot-id-after.txt"
    if [[ -s "$EV/esxi-boot-id-before.txt" && -s "$EV/esxi-boot-id-after.txt" ]] &&
       ! cmp -s "$EV/esxi-boot-id-before.txt" "$EV/esxi-boot-id-after.txt"; then
      check 7 esxi-boot-id-changed pass 'guest boot ID changed'
    else check 7 esxi-boot-id-changed fail 'reboot not proven by a changed boot ID'; fi
    redact_tree
    [[ "$(failures)" == 0 ]]
    ;;
  *) exit 2 ;;
esac
