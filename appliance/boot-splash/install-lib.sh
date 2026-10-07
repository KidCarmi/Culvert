#!/usr/bin/env bash
# The root argument is a filesystem seam for isolated tests. The production
# entry point always passes / inside virt-customize; never run on the host.
install_boot_splash() (
    set -euo pipefail
    local source=$1 root=${2%/} theme initrd listing
    theme="$root/usr/share/plymouth/themes/culvert/culvert.plymouth"
    [[ -f "$root/usr/lib/x86_64-linux-gnu/plymouth/ubuntu-text.so" ]] || {
        echo 'Culvert boot splash: packaged ubuntu-text renderer missing.' >&2; exit 1;
    }
    install -d -m 0755 "$root/usr/share/plymouth/themes/culvert" "$root/etc/default/grub.d"
    install -m 0644 "$source/culvert.plymouth" "$theme"
    install -m 0644 "$source/99-culvert-splash.cfg" "$root/etc/default/grub.d/99-culvert-splash.cfg"
    # The splash's message line (initramfs) and the kernel-log console (tty12).
    install -d -m 0755 "$root/etc/initramfs-tools/scripts/init-premount" "$root/opt/culvert-appliance/bin" \
        "$root/etc/systemd/system/sysinit.target.wants" "$root/etc/plymouth"
    # Daemon settings: draw the text splash at once (see the file). Ubuntu's
    # plymouth hook copies this into the initramfs; verified below.
    install -m 0644 "$source/plymouthd.conf" "$root/etc/plymouth/plymouthd.conf"
    install -m 0755 "$source/culvert-splash-message" "$root/etc/initramfs-tools/scripts/init-premount/culvert-splash-message"
    install -m 0755 "$source/culvert-kernel-log-vt" "$root/opt/culvert-appliance/bin/culvert-kernel-log-vt"
    install -m 0644 "$source/culvert-kernel-log-vt.service" "$root/etc/systemd/system/culvert-kernel-log-vt.service"
    ln -sfn ../culvert-kernel-log-vt.service "$root/etc/systemd/system/sysinit.target.wants/culvert-kernel-log-vt.service"
    # Ubuntu's initramfs hook follows BOTH alternatives. Explicit --set also
    # replaces a base image's manual choice; package-owned themes remain intact.
    local name
    for name in default.plymouth text.plymouth; do
        update-alternatives --install "$root/usr/share/plymouth/themes/$name" "$name" "$theme" 200
        update-alternatives --set "$name" "$theme"
    done
    update-initramfs -u -k all
    shopt -s nullglob
    local images=("$root"/boot/initrd.img-*)
    ((${#images[@]} > 0)) || { echo 'Culvert boot splash: no initramfs to verify.' >&2; exit 1; }
    for initrd in "${images[@]}"; do
        listing=$(lsinitramfs "$initrd")
        grep -qx 'usr/share/plymouth/themes/culvert/culvert.plymouth' <<< "$listing" || {
            echo 'Culvert boot splash: theme absent from initramfs.' >&2; exit 1;
        }
        grep -Eq '^(usr/)?lib/x86_64-linux-gnu/plymouth/ubuntu-text\.so$' <<< "$listing" || {
            echo 'Culvert boot splash: renderer absent from initramfs.' >&2; exit 1;
        }
        grep -qx 'scripts/init-premount/culvert-splash-message' <<< "$listing" || {
            echo 'Culvert boot splash: message script absent from initramfs.' >&2; exit 1;
        }
        grep -qx 'etc/plymouth/plymouthd.conf' <<< "$listing" || {
            echo 'Culvert boot splash: plymouthd.conf absent from initramfs.' >&2; exit 1;
        }
    done
    update-grub
)
