#!/usr/bin/env bash
# Exercise the real maintenance power flow with relocated files and PATH stubs.
# No host Docker, systemctl, package manager, or privileged filesystem is touched.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
command -v flock >/dev/null || { echo 'Linux flock is required.' >&2; exit 1; }
command -v timeout >/dev/null || { echo 'timeout is required.' >&2; exit 1; }
command -v setsid >/dev/null || { echo 'setsid is required for isolated signal tests.' >&2; exit 1; }
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT

fail() { echo "FAIL: ${case_name:-setup}: $*" >&2; [[ ! -f ${output:-} ]] || cat "$output" >&2; exit 1; }
contains() { grep -Fq -- "$1" "$CALLS" || fail "missing call: $1"; }
absent() { if grep -Fq -- "$1" "$CALLS"; then fail "unexpected call: $1"; fi; }
status_is() { [[ $status == "$1" ]] || fail "exit $status, wanted $1"; }
marker_present() { [[ -f $RESUME_MARKER ]] || fail 'resume marker missing'; }
marker_absent() { [[ ! -e $RESUME_MARKER ]] || fail 'resume marker unexpectedly retained'; }

new_case() {
    case_name=$1
    case_dir=$TEST_ROOT/$case_name
    mkdir -p "$case_dir/bin" "$case_dir/stack" "$case_dir/agent/reconcile" "$case_dir/state"
    printf 'services: {}\n' >"$case_dir/stack/docker-compose.yml"
    export CALLS=$case_dir/calls RESUME_MARKER=$case_dir/state/stack-resume-on-boot
    export TEST_OS_LOCK=$case_dir/os-update.lock TEST_AGENT_LOCK=$case_dir/agent/host-maintenance.lock
    export SCRIPT_PID_FILE=$case_dir/script-pid
    output=$case_dir/output
    : >"$CALLS"
    # Fail closed if production defaults move: all five declarations must exist
    # exactly once before any copied script can execute.
    for declaration in 'STACK=/srv/culvert' 'LOG=/var/log/culvert-os-update.log' \
        'MAINT_STATE=/var/lib/culvert-maint' 'LOCK=/run/culvert-os-update.lock' \
        'STACK_RESUME=/var/lib/culvert-appliance/state/stack-resume-on-boot'; do
        [[ $(grep -Fxc "$declaration" "$HERE/culvert-os-update") == 1 ]] || fail "cannot relocate $declaration"
    done
    sed -e "s|^STACK=/srv/culvert$|STACK='$case_dir/stack'|" \
        -e "s|^LOG=/var/log/culvert-os-update.log$|LOG='$case_dir/log'|" \
        -e "s|^MAINT_STATE=/var/lib/culvert-maint$|MAINT_STATE='$case_dir/agent'|" \
        -e "s|^LOCK=/run/culvert-os-update.lock$|LOCK='$TEST_OS_LOCK'|" \
        -e "s|^STACK_RESUME=/var/lib/culvert-appliance/state/stack-resume-on-boot$|STACK_RESUME='$RESUME_MARKER'|" \
        -e '/^set -euo pipefail$/a echo "$BASHPID" > "$SCRIPT_PID_FILE"' \
        "$HERE/culvert-os-update" >"$case_dir/script"
    cat >"$case_dir/bin/id" <<'STUB'
#!/usr/bin/env bash
echo 0
STUB
    cat >"$case_dir/bin/assert-locks" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
for lock in "$TEST_OS_LOCK" "$TEST_AGENT_LOCK"; do
    status=0
    flock -n "$lock" -c 'exit 0' || status=$?
    if [[ $status == 0 ]]; then
        echo "UNGUARDED: $lock" >>"$CALLS"
        exit 95
    fi
    [[ $status == 1 ]] || { echo 'UNGUARDED: lock observation failed' >>"$CALLS"; exit 95; }
done
STUB
    cat >"$case_dir/bin/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
assert-locks
echo "docker $*" >>"$CALLS"
case "$*" in
    'compose stop')
        [[ -f $RESUME_MARKER ]] || { echo 'MISSING MARKER BEFORE STOP' >>"$CALLS"; exit 96; }
        if [[ ${TERM_DURING_STOP:-0} == 1 ]]; then
            # Signal only the bash process recorded by this isolated script.
            # Never signal the harness group or a system process.
            pid=$(cat "$SCRIPT_PID_FILE")
            [[ $pid =~ ^[0-9]+$ && $pid -gt 1 ]] || exit 98
            if [[ ${SIGNAL_SCOPE:-leader} == group ]]; then
                pgid=$(ps -o pgid= -p "$pid")
                [[ ${pgid// /} == "$pid" ]] || exit 98
                kill -TERM -- "-$pid"
            else
                kill -TERM "$pid"
            fi
            exit 0
        fi
        [[ ${FAIL_STOP:-0} == 0 ]] || exit 41
        ;;
    'compose up -d') [[ ${FAIL_START:-0} == 0 ]] || exit 42 ;;
    *) echo 'UNEXPECTED DOCKER COMMAND' >>"$CALLS"; exit 97 ;;
esac
STUB
    cat >"$case_dir/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
assert-locks
echo "systemctl $*" >>"$CALLS"
[[ $* == reboot || $* == poweroff ]] || exit 97
[[ -f $RESUME_MARKER ]] || { echo 'MISSING MARKER BEFORE POWER' >>"$CALLS"; exit 96; }
[[ ${FAIL_POWER:-0} == 0 ]] || exit 43
STUB
    chmod 700 "$case_dir/bin/"*
}

run_case() {
    status=0
    timeout 10 setsid env PATH="$case_dir/bin:$PATH" bash "$case_dir/script" "$@" >"$output" 2>&1 || status=$?
    [[ $status != 124 ]] || fail 'test command timed out'
    absent UNGUARDED
    absent 'MISSING MARKER'
    absent 'UNEXPECTED DOCKER'
}

for mode in reboot poweroff; do
    new_case "$mode-success-resume"
    run_case "$mode"
    status_is 0
    [[ $(cat "$CALLS") == $'docker compose stop\nsystemctl '"$mode" ]] || fail 'stop/power order differs'
    marker_present
    run_case resume-stack
    status_is 0
    contains 'docker compose up -d'
    marker_absent

    new_case "$mode-stop-failure"
    FAIL_STOP=1 run_case "$mode"
    status_is 1
    absent systemctl
    contains 'docker compose up -d'
    marker_absent

    new_case "$mode-interrupted-stop"
    TERM_DURING_STOP=1 run_case "$mode"
    status_is 1
    [[ $(cat "$CALLS") == $'docker compose stop\ndocker compose up -d' ]] || fail 'SIGTERM during stop did not recover without power dispatch'
    marker_absent

    new_case "$mode-interrupted-stop-group"
    TERM_DURING_STOP=1 SIGNAL_SCOPE=group run_case "$mode"
    status_is 1
    [[ $(cat "$CALLS") == $'docker compose stop\ndocker compose up -d' ]] || fail 'group SIGTERM during stop did not recover (including logging pipe)'
    marker_absent

    new_case "$mode-interrupted-stop-recovery-failure"
    TERM_DURING_STOP=1 FAIL_START=1 run_case "$mode"
    status_is 1
    absent systemctl
    contains 'docker compose up -d'
    marker_present
    run_case resume-stack
    status_is 0
    marker_absent

    new_case "$mode-power-failure"
    FAIL_POWER=1 run_case "$mode"
    status_is 1
    [[ $(cat "$CALLS") == $'docker compose stop\nsystemctl '"$mode"$'\ndocker compose up -d' ]] || fail 'failed power did not restart after dispatch'
    marker_absent

    new_case "$mode-recovery-failure"
    FAIL_POWER=1 FAIL_START=1 run_case "$mode"
    status_is 1
    contains 'docker compose up -d'
    marker_present
    run_case resume-stack
    status_is 0
    marker_absent

    new_case "$mode-interrupted-journal"
    printf '{}\n' >"$case_dir/agent/reconcile/interrupted.json"
    run_case "$mode"
    status_is 3
    [[ ! -s $CALLS ]] || fail 'journal refusal changed the stack'
    marker_absent

    for lock_kind in os agent; do
        new_case "$mode-$lock_kind-contention"
        locked=$TEST_OS_LOCK
        [[ $lock_kind != agent ]] || locked=$TEST_AGENT_LOCK
        exec 19>"$locked"
        flock -n 19 || fail 'could not take test lock'
        run_case "$mode"
        status_is 3
        [[ ! -s $CALLS ]] || fail 'lock refusal changed the stack'
        marker_absent
        # --force must not weaken mutual exclusion even with no journal.
        run_case "$mode" --force
        status_is 3
        [[ ! -s $CALLS ]] || fail '--force bypassed an active operation'
        exec 19>&-
    done
done
echo 'PASS: guarded reboot/poweroff, contention, journal and resume recovery'
