#!/usr/bin/env bash
# Explicit continuation after the preserved immediate network rollback check.
set -euo pipefail
set +x
export ESXI_ADAPTER_LIBRARY_ONLY=1 ESXI_P1_CAMPAIGN=confirmation
source "$(dirname "${BASH_SOURCE[0]}")/access-aware-qualify.sh"
python3 "$ADAPTER_HERE/post-os-resume.py" --scope "$ESXI_SCOPE" \
  --shared "$ESXI_SHARED_LAB" --output "$WORK/post-os-tail.sh"
# Load the exact pinned tail before dispatching any guest mutation.
source "$WORK/post-os-tail.sh"
esxi_restore_valid_backup "${BACKUP_FILE:-}"
JSONL="$EV/checks-post-os-resume.jsonl"
RUN_ID="${RUN_ID}-post-os-resume"
STOP=0
check ESXi post-os-resume info 'Original network immediate postcheck failure retained. Explicit confirmatory test uses separate evidence and scratch state; completed setup/restore/update are not repeated.'
gpriv <<<'cat /proc/sys/kernel/random/boot_id' > "$EV/post-os-resume-boot-id.txt"
cmp -s "$EV/esxi-boot-id-before.txt" "$EV/post-os-resume-boot-id.txt" || {
  check ESXi resume-boot-identity fail 'Unexpected reboot before continuation'; exit 1;
}
lab_before_reboot
post_os_tail
gpriv <<<'cat /proc/sys/kernel/random/boot_id' > "$EV/esxi-boot-id-after.txt"
if [[ -s $EV/esxi-boot-id-before.txt && -s $EV/esxi-boot-id-after.txt ]] &&
   ! cmp -s "$EV/esxi-boot-id-before.txt" "$EV/esxi-boot-id-after.txt"; then
  check 7 esxi-boot-id-changed pass 'Guest boot ID changed during the maintenance reboot.'
else check 7 esxi-boot-id-changed fail 'Changed guest boot ID not proven.'; fi
esxi_restore_persistence
redact_tree
[[ $(failures) == 0 ]]
