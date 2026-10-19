#!/usr/bin/env bash
# Offline guest-image installation; no running services or tty writes.
set -euo pipefail
[[ $(id -u) -eq 0 ]] || { echo 'Boot splash installation requires guest root.' >&2; exit 1; }
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=install-lib.sh
source "$HERE/install-lib.sh"
install_boot_splash "$HERE" /
