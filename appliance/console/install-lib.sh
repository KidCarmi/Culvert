#!/usr/bin/env bash
# Internal packaging helper. Callers supply root-controlled destination directories.

console_install_prerequisites() {
    [[ $(id -u) -eq 0 ]] || { echo 'Run as root inside the appliance guest.' >&2; return 1; }
    id culvert >/dev/null || return 1
    [[ -x /bin/login && -x /usr/bin/sudo ]]
}

# Full entrypoint with explicit root-controlled paths for image preparation and
# isolated tests. This publishes next-boot files only: it never reloads/restarts
# systemd or changes a running worker. The activation link is part of the bundle.
install_console() (
    set -euo pipefail
    local source=$1 binary=$2 profile=$3 getty=$4 worker=$5 activation=$6
    console_install_prerequisites || exit 1
    # Wrong-architecture/missing binaries must not replace working login.
    timeout --kill-after=2s 10s "$source/culvert-console" --json >/dev/null || exit 1
    [[ -r $source/profile.sh && -r $source/getty-override.conf && -r $source/culvert-console-host.service ]] || exit 1
    bash -n "$source/profile.sh" || exit 1
    install -d -o root -g root -m 0755 "${binary%/*}" "${profile%/*}" \
        "${getty%/*}" "${worker%/*}" "${activation%/*}" || exit 1
    install_console_bundle "$source" "$binary" "$profile" "$getty" "$worker" "$activation" || exit 1
    echo 'Console installed and worker enabled for next boot. Running services were not restarted.'
)

# A subshell confines traps/lock descriptors to this installation transaction.
install_console_bundle() (
    set -euo pipefail
    umask 077
    local source=$1 binary=$2 profile=$3 getty=$4 index target stage backup
    local committed=false rollback_failed=false status=0
    local -a targets=("$binary" "$profile" "$getty")
    local -a sources=("$source/culvert-console" "$source/profile.sh" "$source/getty-override.conf")
    local -a modes=(0755 0644 0644) staged=() backups=() published=()
    if [[ -n ${5:-} ]]; then
        targets=("$binary" "$profile" "$5" "$getty")
        sources=("$source/culvert-console" "$source/profile.sh" "$source/culvert-console-host.service" "$source/getty-override.conf")
        modes=(0755 0644 0644 0644)
    fi
    if [[ -n ${6:-} ]]; then
        [[ -n ${5:-} ]] || exit 1
        targets=("$binary" "$profile" "$5" "$6" "$getty")
        sources=("$source/culvert-console" "$source/profile.sh" "$source/culvert-console-host.service" "$5" "$source/getty-override.conf")
        modes=(0755 0644 0644 symlink 0644)
    fi

    console_install_cleanup() {
        status=$?
        trap - EXIT
        set +e
        if [[ $committed != true ]]; then
            for ((index=${#published[@]}-1; index>=0; index--)); do
                if [[ -n ${backups[index]} ]]; then
                    if ! mv -fT -- "${backups[index]}" "${targets[index]}"; then
                        echo "Could not restore ${targets[index]} from ${backups[index]}" >&2
                        rollback_failed=true
                    fi
                elif ! rm -f -- "${targets[index]}"; then
                    rollback_failed=true
                fi
            done
        fi
        for stage in "${staged[@]}"; do rm -f -- "$stage"; done
        if [[ $rollback_failed == true ]]; then
            echo 'Console rollback incomplete; preserve .culvert-backup files for recovery.' >&2
            status=1
        else
            for backup in "${backups[@]}"; do
                [[ -z $backup ]] || rm -f -- "$backup"
            done
        fi
        exit "$status"
    }
    trap console_install_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP

    for index in "${!targets[@]}"; do
        target=${targets[index]}
        if [[ ${modes[index]} == symlink ]]; then
            # Own only the explicit persistent WantedBy link. Existing runtime
            # links and other administrator enablement are never disabled.
            [[ ( ! -e $target && ! -L $target ) || ( -L $target && $(readlink -- "$target") == "${sources[index]}" ) ]] || {
                echo 'Refusing unexpected worker activation target.' >&2; exit 1;
            }
        else
            [[ ! -L $target && ( ! -e $target || -f $target ) ]] || {
                echo 'Refusing nonregular console installation target.' >&2; exit 1;
            }
        fi
        [[ -d ${target%/*} && ! -L ${target%/*} ]] || exit 1
    done
    local lock=${binary%/*}/.culvert-console-install.lock
    [[ ! -L $lock && ( ! -e $lock || -f $lock ) ]] || exit 1
    exec 9>"$lock" || exit 1
    flock -n 9 || { echo 'Another console installation is running.' >&2; exit 1; }
    for index in "${!targets[@]}"; do
        target=${targets[index]}
        stage=$(mktemp "${target%/*}/.culvert-stage.XXXXXX") || exit 1
        staged+=("$stage")
        if [[ ${modes[index]} == symlink ]]; then
            ln -sfn -- "${sources[index]}" "$stage" || exit 1
        else
            install -o root -g root -m "${modes[index]}" -- "${sources[index]}" "$stage" || exit 1
        fi
        backup=''
        if [[ -e $target || -L $target ]]; then
            backup=$(mktemp "${target%/*}/.culvert-backup.${target##*/}.XXXXXX") || exit 1
            backups+=("$backup")
            cp -Pp --remove-destination -- "$target" "$backup" || exit 1
        else
            backups+=('')
        fi
    done
    # Each rename is atomic in its destination filesystem. Enablement publishes
    # only after the worker unit; getty publishes LAST. All backups remain until
    # activation and getty publication both succeed.
    # Existing running executables retain their inode; there is no ETXTBSY write.
    for index in "${!targets[@]}"; do
        # Include this target before mv: a signal between mv and bookkeeping must
        # still restore it. Restoring an unchanged target is harmless.
        published+=("$index")
        mv -fT -- "${staged[index]}" "${targets[index]}" || exit 1
    done
    committed=true
)
