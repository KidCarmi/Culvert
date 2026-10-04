#!/usr/bin/env bash
# Resume only the observed pre-dry-run console-observer interruption. Never
# restart setup, an ambiguous restore, a dispatched update or a reboot.
set -euo pipefail
set +x
export ESXI_ADAPTER_LIBRARY_ONLY=1
source "$(dirname "${BASH_SOURCE[0]}")/access-aware-qualify.sh"
[[ $ESXI_SHARED_SHA256 == 693fd936ab88670b2e7ad4465ded22c5259ac376758db995b74af4d0cc0b7a96 ]]
[[ ! -e $EV/checks-resume.jsonl ]]
python3 - "$EV/observer-resume-evidence.json" "$LAB_DIR/owned.json" <<'PY'
import json,sys
proof=json.load(open(sys.argv[1],encoding='utf-8'))
owner=json.load(open(sys.argv[2],encoding='utf-8'))
assert proof['uuid']==owner['uuid'] and proof['restore_dryrun_dispatched'] is False
assert proof['latest_transport_creation'] < proof['dryrun_output_creation']
assert proof['observation']=='kernel output displaced shell prompt; no transport created for dry run'
PY
python3 - "$EV/checks.jsonl" <<'PY'
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1],encoding='utf-8')]
failed=[r for r in rows if r['result']=='fail']
assert len(failed)==1 and failed[0]['step']=='6' and failed[0]['check']=='restore-dry-run'
assert 'Authenticated console transport blocked' in failed[0]['detail']
assert not any(r['step'] in ('6c','7','8') for r in rows)
for name in ('firstboot-steps','console-login','image-identity','admin-login','agent-backup','backup-listed'):
    assert any(r['check']==name and r['result']=='pass' for r in rows)
PY
esxi_restore_valid_backup "${BACKUP_FILE:-}"
JSONL="$EV/checks-resume.jsonl"
RUN_ID="${RUN_ID}-resume1"
STOP=0
check ESXi observer-resume info 'Prior attempt retained; restore dry run had not started because kernel messages obscured the shell prompt. Resume uses explicit console redraw; no setup or mutation is replayed.'

# Reuse the exact shared step 7/8 function body, without rerunning completed
# setup and enrollment. The source hash above binds both extraction markers.
python3 - "$ESXI_SHARED_LAB" "$WORK/lifecycle-tail.sh" <<'PY'
import pathlib,sys
text=pathlib.Path(sys.argv[1]).read_text(encoding='utf-8')
start='  # Step 7 — OS update + reboot, kernel BEFORE → AFTER.\n'
end='# ── signed update + rollback (step 6c), TEST-ONLY trust'
assert text.count(start)==1 and text.count(end)==1
tail=text.split(start,1)[1].split(end,1)[0]
assert tail.rstrip().endswith('}')
result='lifecycle_tail() {\n  local c rc pass\n  pass="$(cat "$SEC/admin-pass")"\n'+start+tail
with pathlib.Path(sys.argv[2]).open('x',encoding='utf-8',newline='\n') as f:f.write(result)
PY
source "$WORK/lifecycle-tail.sh"
gpriv <<<'test "$(id -u)" = 0 && echo root' > "$EV/resume-console-root.txt"
grep -qx root "$EV/resume-console-root.txt"
rc=0
groot "cd /srv/culvert && docker compose --profile cli run --rm -T cli --restore /backup/$BACKUP_FILE --mode full" 900 > "$EV/06-restore-dryrun-resume.txt" 2>&1 || rc=$?
if [[ $rc != 0 ]] || ! grep -qx 'Validation: PASS' "$EV/06-restore-dryrun-resume.txt" ||
   ! grep -q 'This was a dry-run. No files were written.' "$EV/06-restore-dryrun-resume.txt" ||
   grep -q 'Validation: FAIL' "$EV/06-restore-dryrun-resume.txt"; then
  check 6 restore-dry-run fail 'Resumed dry run did not prove success; inspect private evidence.'
  exit 1
fi
check 6 restore-dry-run pass 'Actual CLI dry run completed through authenticated local recovery after the observer correction.'
esxi_actual_restore
signed_update_rollback
[[ $(failures) == 0 ]]
lifecycle_tail
gpriv <<<'cat /proc/sys/kernel/random/boot_id' > "$EV/esxi-boot-id-after.txt"
if [[ -s $EV/esxi-boot-id-before.txt && -s $EV/esxi-boot-id-after.txt ]] && ! cmp -s "$EV/esxi-boot-id-before.txt" "$EV/esxi-boot-id-after.txt"; then
  check 7 esxi-boot-id-changed pass 'Guest boot ID changed during maintenance reboot.'
else check 7 esxi-boot-id-changed fail 'Changed guest boot ID not proven.'; fi
esxi_restore_persistence
redact_tree
[[ $(failures) == 0 ]]
