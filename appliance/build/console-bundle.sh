#!/usr/bin/env bash
# Build-host helpers; never run guest commands or copy a development directory.

console_go_version() (
    set -euo pipefail
    local repo=$1 want actual
    repo=$(cd "$repo" && pwd)
    want=$(awk '$1 == "toolchain" { print $2 }' "$repo/go.mod")
    [[ $want =~ ^go[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
        echo 'console bundle: root go.mod must pin an exact Go compiler' >&2; exit 1;
    }
    cd "$repo"
    actual=$(GOENV=off GOWORK=off GOFLAGS= go env GOVERSION)
    [[ $actual == "$want" ]] || {
        echo "console bundle: compiler is $actual, root go.mod requires $want" >&2; exit 1;
    }
    printf '%s\n' "$actual"
)

build_console_bundle() (
    set -euo pipefail
    local repo=$1 destination=$2 compiler stage metadata file binary
    repo=$(cd "$repo" && pwd)
    compiler=$(console_go_version "$repo")
    [[ ! -e $destination && ! -L $destination ]] || {
        echo 'console bundle: destination already exists' >&2; exit 1;
    }
    mkdir -p "$(dirname -- "$destination")"
    destination="$(cd "$(dirname -- "$destination")" && pwd)/$(basename -- "$destination")"
    stage=$(mktemp -d "$(dirname -- "$destination")/.console-bundle.XXXXXX")
    trap 'rm -rf -- "$stage"' EXIT
    # Explicit flags prevent inherited overlays, alternate workspaces, build modes
    # or CPU targets from changing which source/architecture goes into the OVA.
    for binary in culvert-console culvert-access; do
    (
        cd "$repo"
        GOENV=off GOWORK=off GOFLAGS= GO111MODULE=on GOEXPERIMENT= \
            CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
            go build -mod=readonly -buildmode=exe -trimpath -buildvcs=true \
            -o "$stage/$binary" "./cmd/$binary"
    )
    metadata=$(GOENV=off GOWORK=off GOFLAGS= go version -m "$stage/$binary")
    [[ $(awk 'NR == 1 { print $NF }' <<< "$metadata") == "$compiler" ]] || {
        echo 'console bundle: binary compiler does not match the pinned compiler' >&2; exit 1;
    }
    for file in 'CGO_ENABLED=0' 'GOOS=linux' 'GOARCH=amd64' 'GOAMD64=v1' '-buildmode=exe'; do
        grep -Fqx -- $'\tbuild\t'"$file" <<< "$metadata" || {
            echo "console bundle: binary lacks required build setting $file" >&2; exit 1;
        }
    done
    chmod 0755 "$stage/$binary"
    done
    for file in install.sh install-lib.sh profile.sh getty-override.conf culvert-console-host.service; do
        [[ -f $repo/appliance/console/$file && ! -L $repo/appliance/console/$file ]] || {
            echo "console bundle: missing or symlinked runtime input $file" >&2; exit 1;
        }
        install -m 0644 "$repo/appliance/console/$file" "$stage/$file"
    done
    # All validation precedes publishing the overlay used by virt-customize.
    mv -- "$stage" "$destination"
)
