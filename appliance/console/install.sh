#!/usr/bin/env bash
# Run inside the guest during image preparation. Does not restart a live console.
set -euo pipefail
[[ $(id -u) -eq 0 ]] || { echo 'Run as root inside the appliance guest.' >&2; exit 1; }
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DEST=/opt/culvert-appliance/console
id culvert >/dev/null
/usr/bin/python3 -I -c 'import curses'
[[ -x /bin/login && -x /usr/bin/sudo ]] || exit 1
install -d -o root -g root -m 0755 "$DEST"
for file in console_status.py culvert_console.py launch.py; do
  if [[ "$HERE/$file" != "$DEST/$file" ]]; then
    install -o root -g root -m 0644 "$HERE/$file" "$DEST/$file"
  else
    chown root:root "$DEST/$file"
    chmod 0644 "$DEST/$file"
  fi
done
install -d -m 0755 /etc/systemd/system/getty@tty1.service.d
install -o root -g root -m 0644 "$HERE/getty-override.conf" /etc/systemd/system/getty@tty1.service.d/culvert-console.conf
install -o root -g root -m 0644 "$HERE/profile.sh" /etc/profile.d/culvert-console.sh
echo 'Console installed for next boot. tty2 and SSH retain normal login.'
