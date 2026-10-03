#!/usr/bin/env bash
# Internal packaging helper. Callers supply root-controlled destination directories.
# A subshell confines traps/lock descriptors to this installation transaction.
install_console_bundle() (
    set -euo pipefail
    umask 077
    local source=$1 binary=$2 profile=$3 getty=$4 index target stage backup
    local committed=false rollback_failed=false status=0
    local -a targets=("$binary" "$profile" "$getty")
    local -a sources=("$source/culvert-console" "$source/profile.sh" "$source/getty-override.conf")
    local -a modes=(0755 0644 0644) staged=() backups=() published=()

    console_install_cleanup() {
        status=$?
        trap - EXIT
        set +e
        if [[ $committed != true ]]; then
            for ((index=${#published[@]}-1; index>=0; index--)); do
                if [[ -n ${backups[index]} ]]; then
                    if ! mv -fT -- "${backups[index]}" "${targets[index]}"; then
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

    for target in "${targets[@]}"; do
        [[ ! -L $target && ( ! -e $target || -f $target ) ]] || {
            echo 'Refusing nonregular console installation target.' >&2; exit 1;
        }
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
        install -o root -g root -m "${modes[index]}" -- "${sources[index]}" "$stage" || exit 1
        backup=''
        if [[ -e $target ]]; then
            backup=$(mktemp "${target%/*}/.culvert-backup.XXXXXX") || exit 1
            backups+=("$backup")
            cp -p -- "$target" "$backup" || exit 1
        else
            backups+=('')
        fi
    done
    # Each rename is atomic in its destination filesystem. Publish getty LAST.
    # Existing running executables retain their inode; there is no ETXTBSY write.
    for index in "${!targets[@]}"; do
        # Include this target before mv: a signal between mv and bookkeeping must
        # still restore it. Restoring an unchanged target is harmless.
        published+=("$index")
        mv -fT -- "${staged[index]}" "${targets[index]}" || exit 1
    done
    committed=true
)
