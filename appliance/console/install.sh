#!/usr/bin/env bash
# Run inside the guest during image preparation. Does not restart a live console.
set -euo pipefail
[[ $(id -u) -eq 0 ]] || { echo 'Run as root inside the appliance guest.' >&2; exit 1; }
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=install-lib.sh
source "$HERE/install-lib.sh"
install_console "$HERE" /opt/culvert-appliance/bin/culvert-console \
    /etc/profile.d/culvert-console.sh \
    /etc/systemd/system/getty@tty1.service.d/culvert-console.conf \
    /etc/systemd/system/culvert-console-host.service \
    /etc/systemd/system/multi-user.target.wants/culvert-console-host.service
