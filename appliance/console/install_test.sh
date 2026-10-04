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

# Exercise the complete production entrypoint with isolated destination paths.
# Only account/PAM availability is stubbed; binary/profile validation, directory
# creation, staging, activation, rollback and cleanup are the production path.
full_source=$TEST_ROOT/full-source
full_dest=$TEST_ROOT/full-dest
mkdir "$full_source" "$full_dest"
cp /bin/true "$full_source/culvert-console"
printf 'true\n' >"$full_source/profile.sh"
cp "$src/getty-override.conf" "$full_source/getty-override.conf"
cp "$HERE/culvert-console-host.service" "$full_source/culvert-console-host.service"
full_binary=$full_dest/bin/culvert-console
full_profile=$full_dest/profile/console.sh
full_getty=$full_dest/getty/console.conf
full_worker=$full_dest/system/culvert-console-host.service
activation=$full_dest/system/multi-user.target.wants/culvert-console-host.service
mkdir -p "${full_binary%/*}" "${full_profile%/*}" "${full_getty%/*}" "${activation%/*}"
console_install_prerequisites() { [[ $(id -u) == 0 ]]; }
# Any newly introduced live systemctl call must fail this test.
systemctl() { echo 'Installer must not invoke live service management.' >&2; return 99; }
reset_full_targets() {
    printf 'previous binary\n' >"$full_binary"
    printf 'previous profile\n' >"$full_profile"
    printf 'previous getty\n' >"$full_getty"
    printf 'previous worker\n' >"$full_worker"
    rm -f -- "$activation"
}
assert_full_previous() {
    [[ $(cat "$full_binary") == 'previous binary' && $(cat "$full_profile") == 'previous profile' ]]
    [[ $(cat "$full_getty") == 'previous getty' && $(cat "$full_worker") == 'previous worker' ]]
    [[ -z $(find "$full_dest" -name '.culvert-stage.*' -o -name '.culvert-backup.*') ]]
}
full_install() {
    install_console "$full_source" "$full_binary" "$full_profile" "$full_getty" "$full_worker" "$activation"
}
for previous in disabled enabled; do
    # Failure while publishing enablement and after enablement both restore the
    # exact previous files/link. The latter models the original partial install.
    for fail_at in 4 5; do
        reset_full_targets
        [[ $previous != enabled ]] || ln -s -- "$full_worker" "$activation"
        if (
            count=0
            mv() { count=$((count+1)); [[ $count != "$fail_at" ]] || return 99; command mv "$@"; }
            full_install
        ); then echo 'Full installer ignored activation failure.' >&2; exit 1; fi
        assert_full_previous
        if [[ $previous == enabled ]]; then
            [[ -L $activation && $(readlink -- "$activation") == "$full_worker" ]]
        else
            [[ ! -e $activation && ! -L $activation ]]
        fi
    done
done
# Catchable interruption immediately after creating the activation link is also
# rolled back, without leaving a previously disabled service enabled.
reset_full_targets
if (
    count=0
    mv() {
        command mv "$@" || return
        count=$((count+1))
        if [[ $count == 4 ]]; then kill -TERM "$BASHPID"; fi
    }
    full_install
); then exit 1; fi
assert_full_previous
[[ ! -L $activation && ! -e $activation ]]
# Failed symlink preparation cannot publish even the first regular file.
if (
    ln() { return 99; }
    full_install
); then exit 1; fi
assert_full_previous
# Refuse activation paths we do not own rather than clobber an administrator's
# custom unit or enablement link. Include a dangling foreign link.
for kind in regular foreign; do
    reset_full_targets
    if [[ $kind == regular ]]; then
        printf 'administrator activation file\n' >"$activation"
    else
        ln -s -- "$full_dest/other.service" "$activation"
    fi
    if full_install; then exit 1; fi
    assert_full_previous
    if [[ $kind == regular ]]; then
        [[ $(cat "$activation") == 'administrator activation file' ]]
    else
        [[ $(readlink -- "$activation") == "$full_dest/other.service" ]]
    fi
done
# First-install failure after enabling leaves neither an enabled broken worker
# nor any newly installed binary/profile/getty/unit.
reset_full_targets
rm -- "$full_binary" "$full_profile" "$full_getty" "$full_worker"
if (
    count=0
    mv() { count=$((count+1)); [[ $count != 5 ]] || return 99; command mv "$@"; }
    full_install
); then exit 1; fi
[[ ! -e $full_binary && ! -e $full_profile && ! -e $full_getty && ! -e $full_worker ]]
[[ ! -e $activation && ! -L $activation ]]
# Successful/repeated installs create the persistent WantedBy link without
# changing an unrelated existing runtime enablement link.
runtime_link=$full_dest/runtime-enabled
ln -s -- "$full_worker" "$runtime_link"
full_install
full_install
cmp "$full_binary" "$full_source/culvert-console"
cmp "$full_worker" "$full_source/culvert-console-host.service"
[[ $(readlink -- "$activation") == "$full_worker" && $(readlink -- "$runtime_link") == "$full_worker" ]]
[[ $(stat -c '%u:%g' "$activation") == '0:0' ]]
[[ -z $(find "$full_dest" -name '.culvert-stage.*' -o -name '.culvert-backup.*') ]]

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
