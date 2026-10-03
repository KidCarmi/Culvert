#!/usr/bin/env bash
# Run inside the guest during image preparation. Does not restart a live console.
set -euo pipefail
[[ $(id -u) -eq 0 ]] || { echo 'Run as root inside the appliance guest.' >&2; exit 1; }
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DEST=/opt/culvert-appliance/bin
id culvert >/dev/null
[[ -x /bin/login && -x /usr/bin/sudo ]] || exit 1
# The build host supplies a CGO_ENABLED=0 linux/amd64 binary beside this script.
# Validate it BEFORE changing getty; a missing/wrong-architecture binary must
# never replace working login. No Go compiler or Python is needed in the guest.
"$HERE/culvert-console" --json >/dev/null
install -d -o root -g root -m 0755 "$DEST"
install -o root -g root -m 0755 "$HERE/culvert-console" "$DEST/culvert-console"
install -d -m 0755 /etc/systemd/system/getty@tty1.service.d
install -o root -g root -m 0644 "$HERE/getty-override.conf" /etc/systemd/system/getty@tty1.service.d/culvert-console.conf
install -o root -g root -m 0644 "$HERE/profile.sh" /etc/profile.d/culvert-console.sh
echo 'Console installed for next boot. tty2 and SSH retain normal login.'
