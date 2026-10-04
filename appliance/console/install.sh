#!/usr/bin/env bash
# Run inside the guest during image preparation. Does not restart a live console.
set -euo pipefail
[[ $(id -u) -eq 0 ]] || { echo 'Run as root inside the appliance guest.' >&2; exit 1; }
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=install-lib.sh
source "$HERE/install-lib.sh"
DEST=/opt/culvert-appliance/bin
id culvert >/dev/null
[[ -x /bin/login && -x /usr/bin/sudo ]] || exit 1
# The build host supplies a CGO_ENABLED=0 linux/amd64 binary beside this script.
# Validate it BEFORE changing getty; a missing/wrong-architecture binary must
# never replace working login. No Go compiler or Python is needed in the guest.
timeout --kill-after=2s 10s "$HERE/culvert-console" --json >/dev/null
[[ -r $HERE/profile.sh && -r $HERE/getty-override.conf ]] || exit 1
bash -n "$HERE/profile.sh"
install -d -o root -g root -m 0755 "$DEST"
install -d -m 0755 /etc/systemd/system/getty@tty1.service.d
install_console_bundle "$HERE" "$DEST/culvert-console" \
    /etc/profile.d/culvert-console.sh \
    /etc/systemd/system/getty@tty1.service.d/culvert-console.conf \
    /etc/systemd/system/culvert-console-host.service
systemctl enable culvert-console-host.service
echo 'Console installed for next boot. tty2 and SSH retain normal login.'
