#!/bin/bash
# Genuine-disappearance receipt for the m2-guest.sh census functions.
# The census functions are taken verbatim from m2-guest.sh (sed ranges below).
# Three real `sleep` processes are started; wrappers around `ls` and `readlink`
# kill one of them at the exact moment the census reaches it, so the process
# really is gone when its read fails. Nothing else is altered.
G="$1"
eval "$(sed -n '/^alive() {/,/^  ! grep/p' "$G")"
eval "$(sed -n '/^fd_census() {/,/^  echo "summary /p' "$G")"
eval "$(sed -n '/^netns_census() {/,/^  echo "summary /p' "$G")"
sleep 300 & A=$!   # killed when the fd census lists its fd directory -> "exited"
sleep 300 & B=$!   # killed when the fd census reads its first descriptor -> "fd-vanished"
sleep 300 & C=$!   # killed when the netns census reads its namespace -> "exited"
trap "kill $A $B $C 2>/dev/null" EXIT
gone() { kill -9 "$1" 2>/dev/null; wait "$1" 2>/dev/null; }
ls() { [ "$2" = "/proc/$A/fd" ] && gone "$A"; command ls "$@"; }
readlink() { case "$1" in "/proc/$B/fd/"*) gone "$B";; "/proc/$C/ns/net") gone "$C";; esac; command readlink "$@"; }
echo "# targets: A=$A (fd dir) B=$B (descriptor) C=$C (netns)"
# Every non-success line is printed, not only the targets': the same run also
# shows this sandbox's PID 1, whose entries still exist but cannot be read.
echo "## fd_census: every recorded outcome line, then the summary"
fd_census
echo "## netns_census: every line except successful reads, then the summary"
netns_census | grep -v '^ns '
echo "## targets' namespaces were read only if they appear here: $(netns_census | grep -cE "^ns [^ ]+ ($A|$B|$C)$") (0 expected)"
echo "## targets still present afterwards: $(for p in $A $B $C; do [ -d /proc/$p ] && echo -n "$p "; done)(none expected)"
