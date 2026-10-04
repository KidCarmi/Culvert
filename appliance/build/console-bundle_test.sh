#!/usr/bin/env bash
# Isolated packaging tests: fake compiler, temporary overlay, no guest or Docker.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=appliance/build/console-bundle.sh
source "$HERE/console-bundle.sh"
TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEST_DIR"' EXIT
mkdir -p "$TEST_DIR/bin" "$TEST_DIR/repo/appliance/console/evidence"
cp "$REPO/go.mod" "$TEST_DIR/repo/go.mod"
export MOCK_COMPILER
MOCK_COMPILER=$(awk '$1 == "toolchain" { print $2 }' "$REPO/go.mod")
export MOCK_REPO="$TEST_DIR/repo" MOCK_TRACE="$TEST_DIR/trace"
for file in install.sh install-lib.sh profile.sh getty-override.conf culvert-console-host.service; do
    cp "$REPO/appliance/console/$file" "$MOCK_REPO/appliance/console/$file"
done
touch "$MOCK_REPO/appliance/console/evidence/private.txt" \
    "$MOCK_REPO/appliance/console/leftover.test" "$MOCK_REPO/appliance/console/README.md"
printf 'stale ignored development binary\n' > "$MOCK_REPO/appliance/console/culvert-console"
cat > "$TEST_DIR/bin/go" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MOCK_TRACE"
case "$1" in
env)
    [[ $PWD == "$MOCK_REPO" && ${GOENV:-} == off && ${GOWORK:-} == off && -z ${GOFLAGS:-} ]]
    if [[ ${MOCK_MODE:-} == wrong_compiler ]]; then echo go0.0.0; else echo "$MOCK_COMPILER"; fi
    ;;
build)
    [[ ${MOCK_MODE:-} != build_failure ]]
    [[ $PWD == "$MOCK_REPO" && $CGO_ENABLED == 0 && $GOOS == linux && $GOARCH == amd64 && $GOAMD64 == v1 ]]
    [[ ${GOENV:-} == off && ${GOWORK:-} == off && -z ${GOFLAGS:-} && ${GO111MODULE:-} == on && -z ${GOEXPERIMENT:-} ]]
    [[ $* == *'-mod=readonly -buildmode=exe -trimpath -buildvcs=true -o '* && ${!#} == ./cmd/culvert-console ]]
    while [[ $1 != -o ]]; do shift; done
    printf '#!/bin/sh\n# Fake compiler output; never executed by this test.\n' > "$2"
    ;;
version)
    [[ $2 == -m && -f $3 ]]
    [[ ${MOCK_MODE:-} != invalid_binary ]]
    if [[ ${MOCK_MODE:-} == wrong_binary_compiler ]]; then
        printf '%s: go0.0.0\n' "$3"
    else
        printf '%s: %s\n' "$3" "$MOCK_COMPILER"
    fi
    printf '\tbuild\t-buildmode=exe\n\tbuild\tGOOS=linux\n\tbuild\tGOAMD64=v1\n'
    if [[ ${MOCK_MODE:-} == wrong_arch ]]; then printf '\tbuild\tGOARCH=arm64\n'; else printf '\tbuild\tGOARCH=amd64\n'; fi
    if [[ ${MOCK_MODE:-} == dynamic_binary ]]; then printf '\tbuild\tCGO_ENABLED=1\n'; else printf '\tbuild\tCGO_ENABLED=0\n'; fi
    ;;
*) exit 1 ;;
esac
MOCK
chmod +x "$TEST_DIR/bin/go"
export PATH="$TEST_DIR/bin:$PATH"
for mode in wrong_compiler build_failure invalid_binary wrong_binary_compiler wrong_arch dynamic_binary; do
    export MOCK_MODE=$mode
    : > "$MOCK_TRACE"
    if bash -euo pipefail -c 'source "$1"; build_console_bundle "$2" "$3"' \
        _ "$HERE/console-bundle.sh" "$MOCK_REPO" "$TEST_DIR/$mode/console" >"$TEST_DIR/error" 2>&1; then
        echo "FAIL: $mode was accepted" >&2; exit 1
    fi
    [[ ! -e $TEST_DIR/$mode/console ]]
    [[ -z $(find "$TEST_DIR/$mode" -name '.console-bundle.*' -print 2>/dev/null || true) ]]
    if [[ $mode == wrong_compiler ]]; then
        ! grep -q '^build ' "$MOCK_TRACE"
        [[ ! -e $TEST_DIR/$mode ]]
    fi
done
unset MOCK_MODE
build_console_bundle "$MOCK_REPO" "$TEST_DIR/success/console"
actual=$(find "$TEST_DIR/success/console" -type f -printf '%f\n' | sort)
expected=$(printf '%s\n' culvert-console install.sh install-lib.sh profile.sh getty-override.conf culvert-console-host.service | sort)
[[ $actual == "$expected" ]]
[[ -x $TEST_DIR/success/console/culvert-console ]]
! cmp -s "$MOCK_REPO/appliance/console/culvert-console" "$TEST_DIR/success/console/culvert-console"
for file in install.sh install-lib.sh profile.sh getty-override.conf culvert-console-host.service; do
    cmp "$MOCK_REPO/appliance/console/$file" "$TEST_DIR/success/console/$file"
done

# Structural guards cover the real orchestration, without executing guest writes.
line() { grep -nF -- "$2" "$1" | head -1 | cut -d: -f1; }
preflight=$(line "$HERE/build-ova.sh" 'CONSOLE_GO_VERSION="$(console_go_version "$REPO")"')
bundle=$(line "$HERE/build-ova.sh" 'build_console_bundle "$REPO" "$OV/opt/culvert-appliance/console"')
disk=$(line "$HERE/build-ova.sh" 'qemu-img convert -q -O qcow2')
guest=$(line "$HERE/build-ova.sh" 'virt-customize -a "$DISK"')
account=$(line "$HERE/prepare-guest.sh" 'visudo -c -q -f /etc/sudoers.d/50-culvert-console')
installer=$(line "$HERE/prepare-guest.sh" 'bash "$APPL/console/install.sh"')
[[ -n $preflight && -n $bundle && -n $disk && -n $guest && -n $account && -n $installer ]]
((preflight < bundle && bundle < disk && disk < guest && account < installer))
echo 'PASS: compiler/binary failure fences, runtime-only overlay, and guest installation ordering'
