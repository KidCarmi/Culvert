#!/usr/bin/env bash
# console-reference.sh SHA TREE OUTDIR [REPO]
#
# The EXPECTED culvert-console / culvert-access SHA-256 of a candidate build,
# derived independently of that build from the exact frozen source (owner
# decision of 8 Nov 2026, item 3). Twice a producer computed these in a clone
# that carried release tags: Go then stamps a tag-derived module version
# (v1.0.N-0.<time>-<rev>) where the build's tag-free checkout stamps
# v0.0.0-<time>-<rev>, so the references were wrong (0981ff3d: 063faebd/6a3a66fa;
# fdcb02a5: c327b387/7a2b3403). This script cannot do that:
#
#   - a NEW repository that never has a tag: `git init` + `git fetch --no-tags
#     --depth=1 REPO SHA`; the commit and its tree must equal SHA and TREE, the
#     tag list must be empty and the worktree clean;
#   - the compiler must be the source's own go.mod `toolchain` (no override);
#   - the binaries are built by the source's OWN appliance/build/console-bundle.sh
#     (build_console_bundle), i.e. the build recipe itself, not a copy of it;
#   - every binary must carry vcs.revision=SHA, vcs.modified=false and the
#     tag-free module version v0.0.0-<14 digits>-<SHA[:12]>, or nothing is printed.
#
# Output, only once BOTH binaries pass: OUTDIR/references.txt (and stdout), one "<sha256>  <name>" line per
# binary plus the module version and toolchain. Exit non-zero on any refusal.
set -euo pipefail
die() { echo "console-reference: $*" >&2; exit 1; }
[[ $# -ge 3 ]] || die "usage: console-reference.sh SHA TREE OUTDIR [REPO]"
sha=$1 tree=$2 out=$3 repo=${4:-https://github.com/KidCarmi/Culvert}
[[ $sha =~ ^[0-9a-f]{40}$ ]] || die "SHA must be 40 lowercase hex characters"
[[ $tree =~ ^[0-9a-f]{40}$ ]] || die "TREE must be 40 lowercase hex characters"
[[ ! -e $out ]] || die "OUTDIR $out already exists (no reuse of an earlier checkout or build)"
mkdir -p "$out"; out=$(cd "$out" && pwd); src="$out/src"

git init -q "$src"
git -C "$src" fetch -q --no-tags --depth=1 "$repo" "$sha"
git -C "$src" -c advice.detachedHead=false checkout -q --detach FETCH_HEAD
[[ "$(git -C "$src" rev-parse HEAD)" == "$sha" ]] || die "fetched commit is $(git -C "$src" rev-parse HEAD), not $sha"
[[ "$(git -C "$src" rev-parse 'HEAD^{tree}')" == "$tree" ]] || die "tree is $(git -C "$src" rev-parse 'HEAD^{tree}'), not $tree"
[[ -z "$(git -C "$src" tag)" ]] || die "the reference checkout has tags"
[[ -z "$(git -C "$src" status --porcelain)" ]] || die "the reference checkout is not clean"

want=$(awk '$1 == "toolchain" { print $2 }' "$src/go.mod")
have=$(cd "$src" && GOENV=off GOWORK=off GOFLAGS='' go env GOVERSION)
[[ -n "$want" && "$want" == "$have" ]] || die "compiler is ${have:-none}, the source's go.mod toolchain is ${want:-unset}"

(cd "$src" && bash -c '. appliance/build/console-bundle.sh && build_console_bundle "$1" "$2"' _ "$src" "$out/bundle")
[[ -z "$(git -C "$src" status --porcelain)" ]] || die "the build modified the reference checkout"

# Validate BOTH binaries before anything is published (ASTRA R3): a refusal of
# either prints no hash and leaves no references.txt.
lines=""
for b in culvert-console culvert-access; do
  f="$out/bundle/$b"; [[ -f "$f" ]] || die "$b was not built"
  info=$(go version -m "$f")
  mod=$(awk '$1 == "mod" { print $3 }' <<<"$info")
  [[ "$mod" =~ ^v0\.0\.0-[0-9]{14}-${sha:0:12}$ ]] || die "$b module version is '$mod', not the tag-free v0.0.0-<time>-${sha:0:12}"
  grep -qx $'\tbuild\tvcs.revision='"$sha" <<<"$info" || die "$b vcs.revision is not $sha"
  grep -qx $'\tbuild\tvcs.modified=false' <<<"$info" || die "$b is stamped vcs.modified=true"
  lines+="$(sha256sum < "$f" | cut -d' ' -f1)  $b"$'\n'
done
lines+="# source $sha tree $tree, module version $mod, $have, appliance/build/console-bundle.sh of that source, tag-free --depth=1 fetch"$'\n'
printf '%s' "$lines" > "$out/references.txt.tmp"
mv -f "$out/references.txt.tmp" "$out/references.txt"
cat "$out/references.txt"
