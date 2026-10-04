#!/usr/bin/env bash
# Source after the pinned shared cmd_qualify succeeds. This adds one real,
# offline same-volume restore on the caller's owned disposable ESXi guest.
# It does not recover interrupted restores, delete leftovers, or own the VM.
# Invoke esxi_actual_restore directly, not as an if/&&/|| condition: Bash
# disables errexit within functions invoked in those conditional contexts.

esxi_restore_valid_backup() {
  local name=${1:-}
  [[ ${#name} -le 200 && $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.tar\.gz$ && $name != *..* ]]
}

esxi_restore_guest_script() {
  cat <<'GUEST'
set +x
set -euo pipefail
umask 077
archive=${1:?backup basename}
[[ ${#archive} -le 200 && $archive =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.tar\.gz$ && $archive != *..* ]]
[[ $(id -u) == 0 ]]
work=$(mktemp -d /var/tmp/culvert-esxi-restore.XXXXXXXX)
exec 3>&1
exec >>"$work/session.log" 2>&1
stage=preflight
emit() { printf 'RESTORE %s %s\n' "$1" "$2" >&3; }
trap 'rc=$?; if (( rc != 0 )); then emit "$stage" fail; fi' EXIT
trap 'exit 143' TERM HUP INT
cd /srv/culvert
[[ -f docker-compose.yml && -f .env ]]
[[ -f /var/lib/culvert-appliance/state/complete.done ]]
[[ -d /var/lib/culvert-maint ]]
exec 9>/run/culvert-os-update.lock
flock -n 9
exec 8>>/var/lib/culvert-maint/host-maintenance.lock
flock -n 8
# A missing lock holder does not establish that a previous operation finished.
for pending in /var/lib/culvert-maint/host-shutdown.pending /var/lib/culvert-appliance/state/stack-resume-on-boot; do
  [[ ! -e $pending && ! -L $pending ]]
done
if [[ -e /var/lib/culvert-maint/reconcile || -L /var/lib/culvert-maint/reconcile ]]; then
  [[ -d /var/lib/culvert-maint/reconcile && ! -L /var/lib/culvert-maint/reconcile ]]
  find /var/lib/culvert-maint/reconcile -maxdepth 1 \( -name '*.json' -o -name '*.corrupt.*' \) -print >"$work/agent-journal"
  [[ ! -s $work/agent-journal ]]
fi
system_state=$(systemctl is-system-running || true)
[[ $system_state == running || $system_state == degraded ]]
compose=(-f docker-compose.yml)
# Preserve the installed agent socket override when recreating the stack.
[[ -f docker-compose.maint-agent.yml ]]
grep -q '^CULVERT_MAINT_GID=' .env
compose+=(-f docker-compose.maint-agent.yml)
dc() { docker compose "${compose[@]}" "$@"; }
[[ $(docker inspect -f '{{.State.Running}}' culvert) == true ]]
image_before=$(docker inspect -f '{{.Image}}' culvert)
[[ $image_before == "$(docker image inspect -f '{{.Id}}' culvert/proxy:pinned)" ]]
data_volume=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{if eq .Type "volume"}}{{.Name}}{{end}}{{end}}{{end}}' culvert)
[[ $data_volume =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]
data_dir=$(docker volume inspect -f '{{.Mountpoint}}' "$data_volume")
[[ -d $data_dir && ! -L $data_dir ]]
[[ ! -e $data_dir/.restore-journal.json && ! -L $data_dir/.restore-journal.json ]]
# Resolve the actual CLI volume mapping before running any --confirm command.
# The private config contains environment values; it never leaves this directory.
dc --profile cli config --format json >"$work/compose.json"
backup_volume=$(python3 - "$work/compose.json" "$data_volume" <<'PY'
import json,re,sys
d=json.load(open(sys.argv[1])); mounts=d['services']['cli']['volumes']
def volume(target):
    m=[m for m in mounts if m.get('target')==target]
    assert len(m)==1 and m[0].get('type')=='volume'
    name=d['volumes'][m[0]['source']]['name']
    assert re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',name)
    return name
assert volume('/data')==sys.argv[2]
print(volume('/backup'))
PY
)
backup_dir=$(docker volume inspect -f '{{.Mountpoint}}' "$backup_volume")
[[ -d $backup_dir && -s $backup_dir/$archive && -f $backup_dir/$archive && ! -L $backup_dir/$archive ]]
backup_before=$(sha256sum "$backup_dir/$archive" | cut -d' ' -f1)
emit preflight pass

stage=live-refusal
live_rc=0
dc --profile cli run --rm -T --no-deps cli --restore "/backup/$archive" --confirm --mode full --accept-dp-reenrollment >"$work/live-refusal.log" 2>&1 || live_rc=$?
[[ $live_rc != 0 ]]
grep -q 'locked by another Culvert process' "$work/live-refusal.log"
! grep -q 'Restore committed' "$work/live-refusal.log"
[[ $(docker inspect -f '{{.State.Running}}' culvert) == true ]]
[[ ! -e $data_dir/.restore-journal.json && ! -L $data_dir/.restore-journal.json ]]
emit live-refusal pass

stage=stop
dc stop >"$work/stop.log" 2>&1
[[ $(docker inspect -f '{{.State.Running}}' culvert) == false ]]
emit stop pass

stage=commit
# No EXIT trap starts the stack. Failure, disconnect, timeout or an unexpected
# journal leaves it stopped for explicit inspection rather than guessing.
dc --profile cli run --rm -T --no-deps cli --restore "/backup/$archive" --confirm --mode full --accept-dp-reenrollment >"$work/commit.log" 2>&1
grep -qx 'Restore committed\.' "$work/commit.log"
[[ ! -e $data_dir/.restore-journal.json && ! -L $data_dir/.restore-journal.json ]]
[[ $backup_before == "$(sha256sum "$backup_dir/$archive" | cut -d' ' -f1)" ]]
find "$data_dir" -maxdepth 1 -type d -name '.restore-bak.*' -print >"$work/leftovers"
[[ -s $work/leftovers ]]
emit commit pass

stage=start
dc up -d >"$work/start.log" 2>&1
[[ $(docker inspect -f '{{.State.Running}}' culvert) == true ]]
[[ $image_before == "$(docker inspect -f '{{.Image}}' culvert)" ]]
[[ $data_volume == "$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' culvert)" ]]
emit start pass
GUEST
}

esxi_actual_restore() (
  set +x
  set -euo pipefail
  local step=9 filename=${BACKUP_FILE:-} response c payload mutation before_allowed before_denied rc=0
  : "${SEC:?}" "${EV:?}" "${ADMIN_USER:?}" "${LAB_HOST:?}" "${JAR:?}" "${P:?}"
  if [[ ${STOP:-0} != 0 || $(failures) != 0 ]]; then
    check "$step" actual-restore not-run 'shared qualification did not finish successfully'
    return 1
  fi
  if ! esxi_restore_valid_backup "$filename" || [[ $LAB_HOST != 127.0.0.1 && $LAB_HOST != localhost ]]; then
    check "$step" actual-restore fail 'invalid backup basename or non-local SSH tunnel target'
    return 1
  fi
  if [[ ! -s $SEC/admin-pass || ! -s $EV/05-ca-fingerprint.txt || ! -s $EV/05b-lookups-before.txt ]]; then
    check "$step" actual-restore fail 'private administrator credential or baseline identity evidence unavailable'
    return 1
  fi
  # Unexpected transport/parser failures must also leave a failed check, rather
  # than an apparently green partial report. Explicit failed checks already count.
  trap 'rc=$?; if (( rc != 0 )) && [[ $(failures) == 0 ]]; then check 9 restore-harness fail "restore qualification stopped unexpectedly; private diagnostics retained"; fi' EXIT
  declare -p SSH_OPTS >/dev/null
  mkdir -p "$SEC/actual-restore"
  chmod 0700 "$SEC/actual-restore"
  payload=$(python3 - "$SEC/admin-pass" "$ADMIN_USER" <<'PY'
import json,sys
password=open(sys.argv[1]).read().rstrip('\r\n')
assert password and sys.argv[2]
print(json.dumps({'user':sys.argv[2],'pass':password}))
PY
  )
  : >"$JAR"
  response=$(api POST /api/auth/login "$payload")
  c=$(printf '%s\n' "$response" | code)
  if [[ $c != 200 ]]; then
    check "$step" restore-login-before fail 'fresh administrator login failed before restore'
    return 1
  fi
  before_allowed=$(through_proxy http://example.com/)
  before_denied=$(through_proxy http://example.org/)
  if [[ "$before_allowed $before_denied" != '200 403' ]]; then
    check "$step" restore-baseline fail 'baseline allow/deny traffic did not match successful shared qualification'
    return 1
  fi
  mutation="esxi-post-backup-block-$(date +%s)-$RANDOM"
  response=$(api POST /api/policy "{\"name\":\"$mutation\",\"priority\":1,\"action\":\"Block_Page\",\"destFQDN\":\"example.com\",\"sslAction\":\"Bypass\",\"enabled\":true}")
  c=$(printf '%s\n' "$response" | code)
  if [[ $c != 200 && $c != 201 ]]; then
    check "$step" post-backup-mutation fail 'policy mutation was not accepted'
    return 1
  fi
  local deadline=$(( $(date +%s) + 45 )) traffic
  while :; do
    traffic=$(through_proxy http://example.com/)
    [[ $traffic != 403 ]] || break
    if (( $(date +%s) >= deadline )); then
      check "$step" post-backup-mutation fail 'post-backup block was not proven through traffic'
      return 1
    fi
    sleep 2
  done
  check "$step" post-backup-mutation pass 'example.com changed from 200 to 403 after the archived backup'

  # gssh is capped at 120s. This single 600s session owns both maintenance locks
  # through all disruptive phases; a guest 570s budget leaves time to terminate.
  esxi_restore_guest_script | timeout 600 ssh "${SSH_OPTS[@]}" "culvert@$LAB_HOST" \
    "sudo -n timeout --signal=TERM --kill-after=10s 570s bash -s -- '$filename'" \
    >"$SEC/actual-restore/remote.txt" 2>&1 || rc=$?
  grep -E '^RESTORE (preflight|live-refusal|stop|commit|start) (pass|fail)$' "$SEC/actual-restore/remote.txt" >"$EV/09-restore-phases.txt" || true
  local phase
  for phase in preflight live-refusal stop commit start; do
    if [[ $rc != 0 ]] || ! grep -qx "RESTORE $phase pass" "$EV/09-restore-phases.txt"; then
      check "$step" actual-restore fail 'remote restore did not prove every phase; no automatic recovery or restart was attempted after failure'
      return 1
    fi
  done
  if grep -q ' fail$' "$EV/09-restore-phases.txt"; then
    check "$step" actual-restore fail 'remote restore recorded a failed phase'
    return 1
  fi
  check "$step" actual-restore pass 'live commit refused; offline full restore committed on the same volume; stack restarted under both maintenance locks'

  deadline=$(( $(date +%s) + 240 ))
  until [[ $(curl -sS -m 5 -o /dev/null -w '%{http_code}' "$P/ready" 2>/dev/null || true) == 200 ]]; do
    if (( $(date +%s) >= deadline )); then
      check "$step" restore-ready fail 'ready did not return200 within240s after restore'
      return 1
    fi
    sleep 3
  done
  : >"$JAR"
  response=$(api POST /api/auth/login "$payload")
  unset payload
  c=$(printf '%s\n' "$response" | code)
  unset response
  if [[ $c != 200 ]]; then
    check "$step" restore-admin-login fail 'original administrator could not log in after restore'
    return 1
  fi
  check "$step" restore-admin-login pass 'original administrator authenticated after restore'
  api GET /api/policy >"$SEC/actual-restore/policy.txt"
  if ! body <"$SEC/actual-restore/policy.txt" | python3 -c 'import json,sys
d=json.load(sys.stdin); rules=d if isinstance(d,list) else d["rules"]
assert isinstance(rules,list)
assert not any(r.get("name")==sys.argv[1] for r in rules)
assert any(r.get("name")=="lab-allow-example" and r.get("enabled") is True for r in rules)' "$mutation" 2>/dev/null; then
    check "$step" restore-policy fail 'post-backup mutation remained or original enabled allow rule was missing'
    return 1
  fi
  before_allowed=$(through_proxy http://example.com/)
  before_denied=$(through_proxy http://example.org/)
  if [[ "$before_allowed $before_denied" != '200 403' ]]; then
    check "$step" restore-enforcement fail 'restored policy did not enforce example.com200 and example.org403'
    return 1
  fi
  check "$step" restore-enforcement pass 'post-backup mutation absent; original allow rule restored; traffic200/403'
  api GET /api/ca-cert | body | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 >"$EV/09-ca-fingerprint.txt"
  if [[ ! -s $EV/09-ca-fingerprint.txt ]] || ! cmp -s "$EV/05-ca-fingerprint.txt" "$EV/09-ca-fingerprint.txt"; then
    check "$step" restore-ca fail 'inspection root CA differs from the archived baseline'
    return 1
  fi
  check "$step" restore-ca pass 'inspection root CA fingerprint unchanged'
  lookups >"$EV/09-category-lookups.txt"
  if ! grep -q 'tier=community' "$EV/09-category-lookups.txt" || ! cmp -s "$EV/05b-lookups-before.txt" "$EV/09-category-lookups.txt"; then
    check "$step" restore-categories fail 'community category lookups differ from baseline'
    return 1
  fi
  check "$step" restore-categories pass 'community category lookups identical to baseline'
  api GET /api/maintenance-agent >"$SEC/actual-restore/agent.txt"
  local verdict
  verdict=$(agent_status_verdict "$SEC/actual-restore/agent.txt")
  if [[ $verdict != pass\|* ]]; then
    check "$step" restore-agent fail 'maintenance agent socket availability and stack health were not proven'
    return 1
  fi
  check "$step" restore-agent pass 'agent reachable over its socket with stack up after restore'
  check "$step" restore-complete pass 'same-volume actual restore and all post-restore assertions completed'
)

esxi_restore_selftest() {
  local name
  for name in culvert-20261004T120000Z.tar.gz backup_012345.tar.gz; do
    esxi_restore_valid_backup "$name" || return 1
  done
  for name in '' ../archive.tar.gz /tmp/archive.tar.gz '--flag.tar.gz' 'a;b.tar.gz' 'a b.tar.gz' archive.tar.gz.enc a..b.tar.gz $'a\nb.tar.gz' "a'b.tar.gz"; do
    if esxi_restore_valid_backup "$name"; then return 1; fi
  done
  printf 'PASS: restore backup basename validation\n'
}
