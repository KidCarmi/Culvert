#!/usr/bin/env bash
# Fault injection only in a newly created disposable directory; no host install.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$HERE/install-lib.sh"
[[ $(id -u) == 0 ]] || { echo 'Test requires root for ownership checks.' >&2; exit 1; }
TEST_ROOT=$(mktemp -d)
child=''
trap 'if [[ -n $child ]]; then kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi; rm -rf -- "$TEST_ROOT"' EXIT
mkdir "$TEST_ROOT/source" "$TEST_ROOT/dest"
src=$TEST_ROOT/source
bin=$TEST_ROOT/dest/binary
profile=$TEST_ROOT/dest/profile
getty=$TEST_ROOT/dest/getty
printf 'new binary\n' >"$src/culvert-console"
printf 'new profile\n' >"$src/profile.sh"
printf 'new getty\n' >"$src/getty-override.conf"
reset_targets() {
    printf 'old binary\n' >"$bin"
    printf 'old profile\n' >"$profile"
    printf 'old getty\n' >"$getty"
}
assert_old() {
    [[ $(cat "$bin") == 'old binary' && $(cat "$profile") == 'old profile' && $(cat "$getty") == 'old getty' ]]
}
reset_targets
# Inject a one-shot failure at each rename, including getty activation.
for fail_at in 1 2 3; do
    reset_targets
    if (
        count=0
        mv() { count=$((count+1)); [[ $count != "$fail_at" ]] || return 99; command mv "$@"; }
        install_console_bundle "$src" "$bin" "$profile" "$getty"
    ); then echo 'Injected rename failure was ignored.' >&2; exit 1; fi
    assert_old
done
# A termination immediately after the first rename must also restore the bundle.
if (
    count=0
    mv() {
        command mv "$@" || return
        count=$((count+1))
        if [[ $count == 1 ]]; then kill -TERM "$BASHPID"; fi
    }
    install_console_bundle "$src" "$bin" "$profile" "$getty"
); then exit 1; fi
assert_old
# A failed first installation must leave no newly activated hooks or binary.
rm "$bin" "$profile" "$getty"
if (
    count=0
    mv() { count=$((count+1)); [[ $count != 3 ]] || return 99; command mv "$@"; }
    install_console_bundle "$src" "$bin" "$profile" "$getty"
); then exit 1; fi
[[ ! -e $bin && ! -e $profile && ! -e $getty ]]
reset_targets
# Preparation failure must not publish even the first file.
rm "$src/profile.sh"
if install_console_bundle "$src" "$bin" "$profile" "$getty"; then exit 1; fi
assert_old
printf 'new profile\n' >"$src/profile.sh"
# Reject symlink targets without changing their referent.
rm "$profile"
ln -s "$getty" "$profile"
if install_console_bundle "$src" "$bin" "$profile" "$getty"; then exit 1; fi
[[ $(cat "$getty") == 'old getty' ]]
rm "$profile"
reset_targets
# Lock contention must leave existing files intact.
(
    exec 8>"$TEST_ROOT/dest/.culvert-console-install.lock"
    flock -n 8
    if install_console_bundle "$src" "$bin" "$profile" "$getty"; then exit 1; fi
)
assert_old
install_console_bundle "$src" "$bin" "$profile" "$getty"
install_console_bundle "$src" "$bin" "$profile" "$getty"
cmp "$bin" "$src/culvert-console"
cmp "$profile" "$src/profile.sh"
cmp "$getty" "$src/getty-override.conf"
[[ $(stat -c '%a:%u:%g' "$bin") == '755:0:0' ]]
[[ $(stat -c '%a:%u:%g' "$getty") == '644:0:0' ]]
[[ -z $(find "$TEST_ROOT/dest" -name '.culvert-stage.*' -o -name '.culvert-backup.*') ]]
# Replacing an executing binary must use a new inode, never truncate its image.
cp /bin/sleep "$bin"
"$bin" 30 &
child=$!
for ((attempt=0; attempt<200; attempt++)); do
    [[ /proc/$child/exe -ef $bin ]] && break
    sleep 0.01
done
[[ /proc/$child/exe -ef $bin ]]
old_inode=$(stat -c '%i' "$bin")
install_console_bundle "$src" "$bin" "$profile" "$getty"
[[ $(stat -c '%i' "$bin") != "$old_inode" ]]
kill -0 "$child"
kill "$child"
wait "$child" || true
child=''
# The worker unit belongs to the same transaction and publishes before getty.
worker=$TEST_ROOT/dest/worker
printf 'new worker\n' >"$src/culvert-console-host.service"
for fail_at in 1 2 3 4; do
    reset_targets
    printf 'old worker\n' >"$worker"
    if (
        count=0
        mv() { count=$((count+1)); [[ $count != "$fail_at" ]] || return 99; command mv "$@"; }
        install_console_bundle "$src" "$bin" "$profile" "$getty" "$worker"
    ); then echo 'Four-file rollback failure ignored.' >&2; exit 1; fi
    assert_old
    [[ $(cat "$worker") == 'old worker' ]]
done
install_console_bundle "$src" "$bin" "$profile" "$getty" "$worker"
cmp "$worker" "$src/culvert-console-host.service"
[[ $(stat -c '%a:%u:%g' "$worker") == '644:0:0' ]]
# If both publication and rollback fail, keep named backups for manual recovery.
reset_targets
if (
    count=0
    mv() { count=$((count+1)); [[ $count == 1 ]] || return 99; command mv "$@"; }
    install_console_bundle "$src" "$bin" "$profile" "$getty"
); then exit 1; fi
[[ $(find "$TEST_ROOT/dest" -name '.culvert-backup.binary.*' | wc -l) == 1 ]]
[[ $(find "$TEST_ROOT/dest" -name '.culvert-backup.profile.*' | wc -l) == 1 ]]
[[ $(find "$TEST_ROOT/dest" -name '.culvert-backup.getty.*' | wc -l) == 1 ]]
echo 'PASS: staged installation, rollback, symlink refusal, locking and idempotency'
