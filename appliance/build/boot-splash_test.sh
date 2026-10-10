#!/usr/bin/env bash
# Mocked offline image installation only: no root, VM, initramfs or host writes.
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
SOURCE="$REPO/appliance/boot-splash"
TEMP_BASE=$(realpath -- "${TMPDIR:-/tmp}")
[[ $TEMP_BASE == /* && $TEMP_BASE != / ]]
TEST_DIR=$(mktemp -d "$TEMP_BASE/culvert-boot-splash.XXXXXXXX")
TEST_DIR=$(realpath -- "$TEST_DIR")
[[ $TEST_DIR == "$TEMP_BASE"/culvert-boot-splash.* && $TEST_DIR != "$TEMP_BASE" ]]
cleanup() {
    local resolved
    resolved=$(realpath -m -- "$TEST_DIR") || return 1
    [[ $resolved == "$TEST_DIR" && $resolved == "$TEMP_BASE"/culvert-boot-splash.* && $resolved != / ]] || return 1
    rm -rf -- "$resolved"
}
trap cleanup EXIT
mkdir -p "$TEST_DIR/bin"
export BOOT_SPLASH_ROOT="$TEST_DIR/guest root" BOOT_SPLASH_TRACE="$TEST_DIR/trace"
export BOOT_SPLASH_FAIL='' BOOT_SPLASH_MODULE=usr/lib

cat >"$TEST_DIR/mock" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
name=${0##*/}
printf '%s' "$name" >>"$BOOT_SPLASH_TRACE"
if (( $# > 0 )); then printf ' <%s>' "$@" >>"$BOOT_SPLASH_TRACE"; fi
printf '\n' >>"$BOOT_SPLASH_TRACE"
theme="$BOOT_SPLASH_ROOT/usr/share/plymouth/themes/culvert/culvert.plymouth"
case "$name" in
update-alternatives)
    [[ -f $theme && -f "$BOOT_SPLASH_ROOT/etc/default/grub.d/99-culvert-splash.cfg" ]]
    case "$1" in
    --install)
        [[ $# == 5 && $2 == "$BOOT_SPLASH_ROOT/usr/share/plymouth/themes/$3" && $4 == "$theme" && $5 == 200 ]]
        [[ $BOOT_SPLASH_FAIL != alternatives-install ]] || exit 41
        ;;
    --set)
        [[ $# == 3 && $3 == "$theme" ]]
        [[ $BOOT_SPLASH_FAIL != alternatives-set ]] || exit 42
        ;;
    *) exit 90 ;;
    esac
    ;;
update-initramfs)
    [[ $# == 3 && $1 == -u && $2 == -k && $3 == all ]]
    [[ $BOOT_SPLASH_FAIL != initramfs ]] || exit 43
    ;;
lsinitramfs)
    [[ $# == 1 && -f $1 && $1 == "$BOOT_SPLASH_ROOT/boot/"initrd.img-* ]]
    [[ $BOOT_SPLASH_FAIL != listing ]] || exit 44
    if [[ $1 == *initrd.img-2 ]]; then
        [[ $BOOT_SPLASH_FAIL != listing-second ]] || exit 45
        case "$BOOT_SPLASH_FAIL" in
        missing-theme-second) printf '%s\n' "$BOOT_SPLASH_MODULE/x86_64-linux-gnu/plymouth/ubuntu-text.so" scripts/init-premount/culvert-splash-message etc/plymouth/plymouthd.conf; exit 0 ;;
        missing-module-second) printf '%s\n' usr/share/plymouth/themes/culvert/culvert.plymouth scripts/init-premount/culvert-splash-message etc/plymouth/plymouthd.conf; exit 0 ;;
        missing-message-second) printf '%s\n' usr/share/plymouth/themes/culvert/culvert.plymouth "$BOOT_SPLASH_MODULE/x86_64-linux-gnu/plymouth/ubuntu-text.so" etc/plymouth/plymouthd.conf; exit 0 ;;
        missing-daemon-conf-second) printf '%s\n' usr/share/plymouth/themes/culvert/culvert.plymouth "$BOOT_SPLASH_MODULE/x86_64-linux-gnu/plymouth/ubuntu-text.so" scripts/init-premount/culvert-splash-message; exit 0 ;;
        false-daemon-conf-second) printf '%s\n' usr/share/plymouth/themes/culvert/culvert.plymouth "$BOOT_SPLASH_MODULE/x86_64-linux-gnu/plymouth/ubuntu-text.so" scripts/init-premount/culvert-splash-message usr/share/plymouth/plymouthd.defaults; exit 0 ;;
        false-theme-second) printf '%s\n' usr/share/plymouth/themes/other/culvert.plymouth "$BOOT_SPLASH_MODULE/x86_64-linux-gnu/plymouth/ubuntu-text.so" scripts/init-premount/culvert-splash-message etc/plymouth/plymouthd.conf; exit 0 ;;
        false-module-second) printf '%s\n' usr/share/plymouth/themes/culvert/culvert.plymouth "$BOOT_SPLASH_MODULE/x86_64-linux-gnu/plymouth/ubuntu-textXso" scripts/init-premount/culvert-splash-message etc/plymouth/plymouthd.conf; exit 0 ;;
        false-message-second) printf '%s\n' usr/share/plymouth/themes/culvert/culvert.plymouth "$BOOT_SPLASH_MODULE/x86_64-linux-gnu/plymouth/ubuntu-text.so" scripts/init-premount/culvert-splash-message.orig etc/plymouth/plymouthd.conf; exit 0 ;;
        esac
    fi
    printf '%s\n' usr/share/plymouth/themes/culvert/culvert.plymouth "$BOOT_SPLASH_MODULE/x86_64-linux-gnu/plymouth/ubuntu-text.so" scripts/init-premount/culvert-splash-message etc/plymouth/plymouthd.conf
    ;;
update-grub)
    [[ $# == 0 ]]
    [[ $BOOT_SPLASH_FAIL != grub ]] || exit 46
    ;;
*) exit 91 ;;
esac
MOCK
for command in update-alternatives update-initramfs lsinitramfs update-grub; do
    cp "$TEST_DIR/mock" "$TEST_DIR/bin/$command"
    chmod +x "$TEST_DIR/bin/$command"
done
export PATH="$TEST_DIR/bin:$PATH"

reset_guest() {
    local resolved
    resolved=$(realpath -m -- "$BOOT_SPLASH_ROOT")
    [[ $resolved == "$TEST_DIR/guest root" && $resolved == "$TEST_DIR"/* && $resolved != / ]]
    rm -rf -- "$resolved"
    mkdir -p "$BOOT_SPLASH_ROOT/usr/lib/x86_64-linux-gnu/plymouth" "$BOOT_SPLASH_ROOT/boot"
    touch "$BOOT_SPLASH_ROOT/usr/lib/x86_64-linux-gnu/plymouth/ubuntu-text.so"
    touch "$BOOT_SPLASH_ROOT/boot/initrd.img-1" "$BOOT_SPLASH_ROOT/boot/initrd.img-2"
    : >"$BOOT_SPLASH_TRACE"
}

# A fresh shell preserves errexit semantics even when its exit is inspected.
invoke_installer() {
    bash -euo pipefail -c 'source "$1/install-lib.sh"; install_boot_splash "$1" "$2"' _ "$SOURCE" "$BOOT_SPLASH_ROOT"
}

for BOOT_SPLASH_MODULE in lib usr/lib; do
    export BOOT_SPLASH_MODULE
    reset_guest
    invoke_installer
    cmp "$SOURCE/culvert.plymouth" "$BOOT_SPLASH_ROOT/usr/share/plymouth/themes/culvert/culvert.plymouth"
    cmp "$SOURCE/99-culvert-splash.cfg" "$BOOT_SPLASH_ROOT/etc/default/grub.d/99-culvert-splash.cfg"
    cmp "$SOURCE/culvert-splash-message" "$BOOT_SPLASH_ROOT/etc/initramfs-tools/scripts/init-premount/culvert-splash-message"
    cmp "$SOURCE/culvert-kernel-log-vt" "$BOOT_SPLASH_ROOT/opt/culvert-appliance/bin/culvert-kernel-log-vt"
    cmp "$SOURCE/culvert-kernel-log-vt.service" "$BOOT_SPLASH_ROOT/etc/systemd/system/culvert-kernel-log-vt.service"
    cmp "$SOURCE/plymouthd.conf" "$BOOT_SPLASH_ROOT/etc/plymouth/plymouthd.conf"
    cmp "$SOURCE/culvert-has-display" "$BOOT_SPLASH_ROOT/opt/culvert-appliance/bin/culvert-has-display"
    [[ -x "$BOOT_SPLASH_ROOT/opt/culvert-appliance/bin/culvert-has-display" ]]
    for unit in plymouth-start plymouth-reboot plymouth-poweroff plymouth-halt plymouth-kexec; do
        cmp "$SOURCE/plymouth-headless.conf" "$BOOT_SPLASH_ROOT/etc/systemd/system/$unit.service.d/culvert-headless.conf"
    done
    [[ -x "$BOOT_SPLASH_ROOT/etc/initramfs-tools/scripts/init-premount/culvert-splash-message" && -x "$BOOT_SPLASH_ROOT/opt/culvert-appliance/bin/culvert-kernel-log-vt" ]]
    [[ $(readlink "$BOOT_SPLASH_ROOT/etc/systemd/system/sysinit.target.wants/culvert-kernel-log-vt.service") == ../culvert-kernel-log-vt.service ]]
    {
        for alternative in default.plymouth text.plymouth; do
            printf 'update-alternatives <--install> <%s> <%s> <%s> <200>\n' \
                "$BOOT_SPLASH_ROOT/usr/share/plymouth/themes/$alternative" "$alternative" "$BOOT_SPLASH_ROOT/usr/share/plymouth/themes/culvert/culvert.plymouth"
            printf 'update-alternatives <--set> <%s> <%s>\n' "$alternative" "$BOOT_SPLASH_ROOT/usr/share/plymouth/themes/culvert/culvert.plymouth"
        done
        printf '%s\n' 'update-initramfs <-u> <-k> <all>'
        printf 'lsinitramfs <%s>\n' "$BOOT_SPLASH_ROOT/boot/initrd.img-1" "$BOOT_SPLASH_ROOT/boot/initrd.img-2"
        printf '%s\n' update-grub
    } >"$TEST_DIR/expected"
    cmp "$BOOT_SPLASH_TRACE" "$TEST_DIR/expected"
done

for BOOT_SPLASH_FAIL in missing-plugin no-initrds alternatives-install alternatives-set initramfs listing listing-second missing-theme-second missing-module-second missing-message-second missing-daemon-conf-second false-daemon-conf-second false-theme-second false-module-second false-message-second grub; do
    export BOOT_SPLASH_FAIL
    reset_guest
    case "$BOOT_SPLASH_FAIL" in
    missing-plugin) rm "$BOOT_SPLASH_ROOT/usr/lib/x86_64-linux-gnu/plymouth/ubuntu-text.so" ;;
    no-initrds) rm "$BOOT_SPLASH_ROOT/boot/initrd.img-1" "$BOOT_SPLASH_ROOT/boot/initrd.img-2" ;;
    esac
    if invoke_installer >"$TEST_DIR/failure" 2>&1; then
        echo "FAIL: $BOOT_SPLASH_FAIL was accepted" >&2; exit 1
    fi
    if [[ $BOOT_SPLASH_FAIL != grub ]]; then
        ! grep -q '^update-grub' "$BOOT_SPLASH_TRACE" || fail "$BOOT_SPLASH_FAIL still ran update-grub"
    fi
    case "$BOOT_SPLASH_FAIL" in
    missing-plugin)
        [[ ! -s $BOOT_SPLASH_TRACE && ! -e "$BOOT_SPLASH_ROOT/etc/default/grub.d/99-culvert-splash.cfg" ]]
        ;;
    alternatives-*) { ! grep -q '^update-initramfs' "$BOOT_SPLASH_TRACE" || fail "$BOOT_SPLASH_FAIL still rebuilt the initramfs"; } ;;
    initramfs) { ! grep -q '^lsinitramfs' "$BOOT_SPLASH_TRACE" || fail "$BOOT_SPLASH_FAIL still listed the initramfs"; } ;;
    esac
done
unset BOOT_SPLASH_FAIL

# Source the real GRUB drop-in twice; root/recovery and serial arguments survive,
# Ubuntu's bootloader identity is untouched, and `quiet` never reaches the
# kernel (it would silence ttyS0, the boot-failure evidence channel).
bash -euo pipefail -c '
    GRUB_DISTRIBUTOR="Ubuntu"
    GRUB_CMDLINE_LINUX="root=UUID=fixture recovery console=ttyS0,115200n8"
    GRUB_CMDLINE_LINUX_DEFAULT="console=tty0 console=ttyS0,115200n8 splash quiet"
    preserved=$GRUB_CMDLINE_LINUX
    source "$1"
    once=$GRUB_CMDLINE_LINUX_DEFAULT
    source "$1"
    [[ $GRUB_CMDLINE_LINUX == "$preserved" && $GRUB_CMDLINE_LINUX_DEFAULT == "$once" && $GRUB_DISTRIBUTOR == Ubuntu ]]
    [[ " $once " == *" console=tty0 "* && " $once " == *" console=ttyS0,115200n8 "* ]]
    [[ " $once " != *" quiet "* && " $once " != *" systemd.show_status="* ]]
    for wanted in splash plymouth.ignore-serial-consoles nomodeset; do
        count=0
        for value in $once; do if [[ $value == "$wanted" ]]; then count=$((count+1)); fi; done
        [[ $count == 1 ]]
    done
    unset GRUB_CMDLINE_LINUX_DEFAULT
    source "$1"
    [[ $GRUB_CMDLINE_LINUX_DEFAULT == "splash plymouth.ignore-serial-consoles nomodeset" ]]
    ! grep -Eq "^[[:space:]]*(export[[:space:]]+)?GRUB_DISTRIBUTOR=" "$1"
' _ "$SOURCE/99-culvert-splash.cfg"

# grub-mkconfig sources grub.d drop-ins with /bin/sh (dash on Ubuntu): the
# drop-in must work there too, with the same result.
sh -euc '
    GRUB_CMDLINE_LINUX_DEFAULT="console=tty1 console=ttyS0 quiet"
    . "$1"
    [ "$GRUB_CMDLINE_LINUX_DEFAULT" = "console=tty1 console=ttyS0 splash plymouth.ignore-serial-consoles nomodeset" ]
' _ "$SOURCE/99-culvert-splash.cfg"

# Execute only the actual overlay copy loop against a fixture repository, with
# decoy docs/tests present. The guest installer and build are never executed.
mkdir -p "$TEST_DIR/repo/appliance/boot-splash" "$TEST_DIR/overlay/opt/culvert-appliance/boot-splash"
for asset in install.sh install-lib.sh culvert.plymouth 99-culvert-splash.cfg culvert-splash-message culvert-kernel-log-vt culvert-kernel-log-vt.service plymouthd.conf culvert-has-display plymouth-headless.conf; do
    cp "$SOURCE/$asset" "$TEST_DIR/repo/appliance/boot-splash/$asset"
done
touch "$TEST_DIR/repo/appliance/boot-splash/README.md" "$TEST_DIR/repo/appliance/boot-splash/private_test.sh"
copy_loop=$(sed -n '/^for splash_file in /,/^done$/p' "$HERE/build-ova.sh")
[[ -n $copy_loop ]]
REPO="$TEST_DIR/repo" OV="$TEST_DIR/overlay" bash -euo pipefail -c "$copy_loop"
actual=$(find "$TEST_DIR/overlay/opt/culvert-appliance/boot-splash" -type f -printf '%f\n' | sort)
expected=$(printf '%s\n' install.sh install-lib.sh culvert.plymouth 99-culvert-splash.cfg culvert-splash-message culvert-kernel-log-vt culvert-kernel-log-vt.service plymouthd.conf culvert-has-display plymouth-headless.conf | sort)
[[ $actual == "$expected" ]]
for asset in install.sh install-lib.sh culvert.plymouth 99-culvert-splash.cfg culvert-splash-message culvert-kernel-log-vt culvert-kernel-log-vt.service plymouthd.conf culvert-has-display plymouth-headless.conf; do
    cmp "$SOURCE/$asset" "$TEST_DIR/overlay/opt/culvert-appliance/boot-splash/$asset"
done

# Verify the installer runs after the console and before package evidence.
line() { grep -nF -- "$2" "$1" | head -1 | cut -d: -f1; }
packages=$(line "$HERE/prepare-guest.sh" 'plymouth plymouth-theme-ubuntu-text plymouth-label fontconfig')
console=$(line "$HERE/prepare-guest.sh" 'bash "$APPL/console/install.sh"')
splash=$(line "$HERE/prepare-guest.sh" 'bash "$APPL/boot-splash/install.sh"')
evidence=$(line "$HERE/prepare-guest.sh" 'sort > "$STATE/dpkg-list.txt"')
[[ -n $packages && -n $console && -n $splash && -n $evidence ]]
((packages < console && console < splash && splash < evidence))
grep -qx 'ModuleName=ubuntu-text' "$SOURCE/culvert.plymouth"
# nomodeset means no DRM device ever appears: plymouth must not wait for one
# (Ubuntu's 8 s default leaves tty1 in graphics mode on a fast boot), the file
# must not pick a theme (the alternative does), and no message is "keys:".
[[ $(sed -n 's/^DeviceTimeout=//p' "$SOURCE/plymouthd.conf") == 0.1 ]]
grep -qx '\[Daemon\]' "$SOURCE/plymouthd.conf"
! grep -Eq '^(Theme|ThemeDir|ShowDelay)=' "$SOURCE/plymouthd.conf" || fail 'plymouthd.conf must not choose a theme or delay'
! grep -q 'keys:' <(grep -v '^#' "$SOURCE/culvert-splash-message") || fail 'splash message uses a keys: prefix'
grep -q -- '--text="Starting system services' "$SOURCE/culvert-splash-message"
grep -qx 'install_boot_splash "$HERE" /' "$SOURCE/install.sh"
# The kernel-log VT script under the shell that runs it (/bin/sh is dash on
# Ubuntu): routes to tty12 when the VT opens, and degrades to exit 0 without
# touching the kernel's console routing when it cannot be opened.
klvt_shell=$(command -v dash || command -v sh)
mkdir -p "$TEST_DIR/klvt/bin"
printf '#!/bin/sh\necho "setlogcons $*" >>"%s/klvt/trace"\n' "$TEST_DIR" >"$TEST_DIR/klvt/bin/setlogcons"
printf '#!/bin/sh\necho kernel-line\n' >"$TEST_DIR/klvt/bin/dmesg"
chmod +x "$TEST_DIR/klvt/bin/setlogcons" "$TEST_DIR/klvt/bin/dmesg"
grep -qF '"/dev/tty$vt"' "$SOURCE/culvert-kernel-log-vt" || fail 'kernel-log VT path changed; update this test'
sed "s|/dev/tty\$vt|$TEST_DIR/klvt/tty\$vt|" "$SOURCE/culvert-kernel-log-vt" >"$TEST_DIR/klvt/open.sh"
PATH="$TEST_DIR/klvt/bin:$PATH" "$klvt_shell" "$TEST_DIR/klvt/open.sh" || fail 'kernel-log VT script failed with an openable VT'
[[ $(cat "$TEST_DIR/klvt/trace") == 'setlogcons 12' ]] || fail 'kernel-log VT not routed to tty12'
grep -qx kernel-line "$TEST_DIR/klvt/tty12" || fail 'kernel log not seeded on tty12'
rm -f "$TEST_DIR/klvt/trace"
sed "s|/dev/tty\$vt|$TEST_DIR/klvt/absent/tty\$vt|" "$SOURCE/culvert-kernel-log-vt" >"$TEST_DIR/klvt/closed.sh"
PATH="$TEST_DIR/klvt/bin:$PATH" "$klvt_shell" "$TEST_DIR/klvt/closed.sh" 2>/dev/null || fail 'kernel-log VT script did not degrade when the VT cannot be opened'
[[ ! -e "$TEST_DIR/klvt/trace" ]] || fail 'console routing changed although the VT could not be opened'

# Headless boots get no splash. The message script (initramfs) and
# culvert-has-display (real root, ExecCondition of the Plymouth boot and shutdown
# units) must reach the same verdict on the same sysfs. Both read /sys directly;
# the test runs copies pointed at a fixture tree.
hd_shell=$(command -v dash || command -v sh)
mkdir -p "$TEST_DIR/hd/bin"
for hd_script in culvert-has-display culvert-splash-message; do
    grep -qF '/sys/bus/pci/devices/*/class' "$SOURCE/$hd_script" || fail "$hd_script no longer reads /sys/bus/pci/devices; update this test"
    sed "s|/sys/bus/pci/devices/|$TEST_DIR/hd/sys/bus/pci/devices/|" "$SOURCE/$hd_script" >"$TEST_DIR/hd/$hd_script"
done
# quit logs late: a quit sent to the background (racing the rest of the boot)
# has not logged when the script returns, and the trace check below fails.
printf '#!/bin/sh\n[ "$1" != quit ] || sleep 0.3\necho "plymouth $*" >>"%s/hd/trace"\n[ "$1" != --ping ] || exit "${HD_PING_RC:-0}"\n' "$TEST_DIR" >"$TEST_DIR/hd/bin/plymouth"
chmod +x "$TEST_DIR/hd/bin/plymouth"
hd_sysfs() { rm -rf "$TEST_DIR/hd/sys"; mkdir -p "$TEST_DIR/hd/sys/bus/pci/devices"; local dev
    for dev in "$@"; do mkdir -p "$TEST_DIR/hd/sys/bus/pci/devices/${dev%%=*}"
        printf '%s\n' "${dev#*=}" >"$TEST_DIR/hd/sys/bus/pci/devices/${dev%%=*}/class"; done; }
hd_verdict() { local want=$1 label=$2 rc=0
    "$hd_shell" "$TEST_DIR/hd/culvert-has-display" || rc=$?
    rm -f "$TEST_DIR/hd/trace"
    PATH="$TEST_DIR/hd/bin:$PATH" "$hd_shell" "$TEST_DIR/hd/culvert-splash-message" || fail "splash message script failed ($label)"
    if [[ $want == display ]]; then
        [[ $rc == 0 ]] || fail "culvert-has-display: no display reported for $label"
        [[ $(cat "$TEST_DIR/hd/trace") == $'plymouth --ping\nplymouth display-message --text=Starting system services  -  Esc: boot messages' ]] \
            || fail "display boot: unexpected plymouth calls ($label): $(tr '\n' '|' <"$TEST_DIR/hd/trace")"
    else
        [[ $rc == 1 ]] || fail "culvert-has-display: display reported (rc=$rc) for $label"
        [[ $(cat "$TEST_DIR/hd/trace") == $'plymouth --ping\nplymouth quit' ]] \
            || fail "headless boot: unexpected plymouth calls ($label): $(tr '\n' '|' <"$TEST_DIR/hd/trace")"
    fi; }
hd_case() { local want=$1; shift; hd_sysfs "$@"; hd_verdict "$want" "${*:-no devices}"; }
hd_case display 0000:00:0f.0=0x030000                              # VGA (ESXi SVGA II, QEMU std/vmware/qxl)
hd_case display 0000:00:01.0=0x060100 0000:00:04.0=0x038000        # other display controller among bridges
hd_case display 0000:00:02.0=0x030000 0000:00:03.0=0x030000        # two VGA devices
hd_case headless 0000:00:01.0=0x060100 0000:00:03.0=0x020000      # bridge + NIC only (serial-only VM)
hd_case headless 0000:00:05.0=0x030200 0000:00:06.0=0x030100      # 3D controller + XGA: no console
hd_case headless                                                   # no PCI devices
rm -rf "$TEST_DIR/hd/sys"; hd_verdict headless 'no PCI tree'       # no sysfs PCI tree at all
# Plymouth not running: the message script does nothing but ask.
hd_sysfs 0000:00:02.0=0x030000; rm -f "$TEST_DIR/hd/trace"
HD_PING_RC=1 PATH="$TEST_DIR/hd/bin:$PATH" "$hd_shell" "$TEST_DIR/hd/culvert-splash-message" || fail 'message script failed without plymouth'
[[ $(cat "$TEST_DIR/hd/trace") == 'plymouth --ping' ]] || fail 'message script acted although plymouth is not running'
# The two scripts carry the same display test, byte for byte.
[[ $(grep -o 'case "$(cat "$class" 2>/dev/null)" in [^)]*)' "$SOURCE/culvert-has-display") == \
   $(grep -o 'case "$(cat "$class" 2>/dev/null)" in [^)]*)' "$SOURCE/culvert-splash-message") ]] || fail 'display tests differ between the two scripts'
grep -qx 'ExecCondition=/opt/culvert-appliance/bin/culvert-has-display' "$SOURCE/plymouth-headless.conf" || fail 'Plymouth drop-in lost its display condition'
grep -qx '\[Service\]' "$SOURCE/plymouth-headless.conf" || fail 'Plymouth drop-in has no [Service] section'

echo 'PASS: splash staging, alternatives/initramfs/GRUB ordering, failure fences, GRUB preservation, runtime-only overlay'
