#!/usr/bin/env bash
# Mocked offline image installation only: no root, VM, initramfs or host writes.
set -euo pipefail
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
        missing-theme-second) printf '%s\n' "$BOOT_SPLASH_MODULE/x86_64-linux-gnu/plymouth/ubuntu-text.so"; exit 0 ;;
        missing-module-second) printf '%s\n' usr/share/plymouth/themes/culvert/culvert.plymouth; exit 0 ;;
        false-theme-second) printf '%s\n' usr/share/plymouth/themes/other/culvert.plymouth "$BOOT_SPLASH_MODULE/x86_64-linux-gnu/plymouth/ubuntu-text.so"; exit 0 ;;
        false-module-second) printf '%s\n' usr/share/plymouth/themes/culvert/culvert.plymouth "$BOOT_SPLASH_MODULE/x86_64-linux-gnu/plymouth/ubuntu-textXso"; exit 0 ;;
        esac
    fi
    printf '%s\n' usr/share/plymouth/themes/culvert/culvert.plymouth "$BOOT_SPLASH_MODULE/x86_64-linux-gnu/plymouth/ubuntu-text.so"
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

for BOOT_SPLASH_FAIL in missing-plugin no-initrds alternatives-install alternatives-set initramfs listing listing-second missing-theme-second missing-module-second false-theme-second false-module-second grub; do
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
        ! grep -q '^update-grub' "$BOOT_SPLASH_TRACE"
    fi
    case "$BOOT_SPLASH_FAIL" in
    missing-plugin)
        [[ ! -s $BOOT_SPLASH_TRACE && ! -e "$BOOT_SPLASH_ROOT/etc/default/grub.d/99-culvert-splash.cfg" ]]
        ;;
    alternatives-*) ! grep -q '^update-initramfs' "$BOOT_SPLASH_TRACE" ;;
    initramfs) ! grep -q '^lsinitramfs' "$BOOT_SPLASH_TRACE" ;;
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
    for wanted in splash plymouth.ignore-serial-consoles; do
        count=0
        for value in $once; do if [[ $value == "$wanted" ]]; then count=$((count+1)); fi; done
        [[ $count == 1 ]]
    done
    unset GRUB_CMDLINE_LINUX_DEFAULT
    source "$1"
    [[ $GRUB_CMDLINE_LINUX_DEFAULT == "splash plymouth.ignore-serial-consoles" ]]
    ! grep -Eq "^[[:space:]]*(export[[:space:]]+)?GRUB_DISTRIBUTOR=" "$1"
' _ "$SOURCE/99-culvert-splash.cfg"

# grub-mkconfig sources grub.d drop-ins with /bin/sh (dash on Ubuntu): the
# drop-in must work there too, with the same result.
sh -euc '
    GRUB_CMDLINE_LINUX_DEFAULT="console=tty1 console=ttyS0 quiet"
    . "$1"
    [ "$GRUB_CMDLINE_LINUX_DEFAULT" = "console=tty1 console=ttyS0 splash plymouth.ignore-serial-consoles" ]
' _ "$SOURCE/99-culvert-splash.cfg"

# Execute only the actual overlay copy loop against a fixture repository, with
# decoy docs/tests present. The guest installer and build are never executed.
mkdir -p "$TEST_DIR/repo/appliance/boot-splash" "$TEST_DIR/overlay/opt/culvert-appliance/boot-splash"
for asset in install.sh install-lib.sh culvert.plymouth 99-culvert-splash.cfg; do
    cp "$SOURCE/$asset" "$TEST_DIR/repo/appliance/boot-splash/$asset"
done
touch "$TEST_DIR/repo/appliance/boot-splash/README.md" "$TEST_DIR/repo/appliance/boot-splash/private_test.sh"
copy_loop=$(sed -n '/^for splash_file in /,/^done$/p' "$HERE/build-ova.sh")
[[ -n $copy_loop ]]
REPO="$TEST_DIR/repo" OV="$TEST_DIR/overlay" bash -euo pipefail -c "$copy_loop"
actual=$(find "$TEST_DIR/overlay/opt/culvert-appliance/boot-splash" -type f -printf '%f\n' | sort)
expected=$(printf '%s\n' install.sh install-lib.sh culvert.plymouth 99-culvert-splash.cfg | sort)
[[ $actual == "$expected" ]]
for asset in install.sh install-lib.sh culvert.plymouth 99-culvert-splash.cfg; do
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
grep -qx 'install_boot_splash "$HERE" /' "$SOURCE/install.sh"
echo 'PASS: splash staging, alternatives/initramfs/GRUB ordering, failure fences, GRUB preservation, runtime-only overlay'
