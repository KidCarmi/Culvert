#!/bin/sh
# FE-1A determinism harness (FE-1A directive §8). Builds the frontend N times
# (default 2 in CI; 5 for release evidence) in isolated clean directories from
# identical source + lockfiles + toolchain, then requires every output tree —
# complete relative-path inventory, size, and SHA-256 of EVERY file, plus the
# generated types file — to be byte-identical. Fails on any added, missing,
# renamed, or changed file.
set -eu
N="${1:-2}"
SRC_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "determinism: $N isolated clean builds (work dir $WORK)"

i=1
while [ "$i" -le "$N" ]; do
  BUILD="$WORK/build$i"
  mkdir -p "$BUILD/api/openapi"
  # Copy only the inputs a clean checkout would have: frontend sources
  # (without node_modules and without any pre-existing dist) + the OpenAPI
  # document the generator consumes.
  (cd "$SRC_ROOT" && tar -cf - \
      --exclude frontend/node_modules \
      --exclude frontend/tools/openapi-gen/node_modules \
      --exclude frontend/dist \
      frontend) | (cd "$BUILD" && tar -xf -)
  cp "$SRC_ROOT/api/openapi/openapi.json" "$BUILD/api/openapi/openapi.json"

  (
    cd "$BUILD/frontend"
    sh scripts/assert-toolchain.sh >/dev/null
    npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1
    (cd tools/openapi-gen && npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1)
    node tools/openapi-gen/generate.mjs >/dev/null
    npm run build >/dev/null 2>&1
  )

  # Full-tree fingerprint: path inventory + size + sha256 for every dist file
  # and the generated types file. LC_ALL=C for stable sort order.
  (
    cd "$BUILD/frontend"
    {
      cd dist
      find . -type f | LC_ALL=C sort | while IFS= read -r f; do
        printf '%s %s %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" \
          "$(wc -c <"$f" | tr -d ' ')" "$f"
      done
      cd ..
      printf '%s %s %s\n' "$(sha256sum src/api/types.gen.ts | cut -d' ' -f1)" \
        "$(wc -c <src/api/types.gen.ts | tr -d ' ')" "./src/api/types.gen.ts"
    } >"$WORK/SHA256SUMS.build$i"
  )
  echo "build $i root hash: $(sha256sum "$WORK/SHA256SUMS.build$i" | cut -d' ' -f1)"
  i=$((i + 1))
done

i=2
while [ "$i" -le "$N" ]; do
  if ! diff -u "$WORK/SHA256SUMS.build1" "$WORK/SHA256SUMS.build$i"; then
    echo "determinism: build $i differs from build 1 (see diff above)" >&2
    exit 1
  fi
  i=$((i + 1))
done

cp "$WORK/SHA256SUMS.build1" "${SHA256SUMS_OUT:-/dev/null}" 2>/dev/null || true
echo "determinism: all $N build trees byte-identical"
echo "SHA256SUMS.frontend (canonical inventory):"
cat "$WORK/SHA256SUMS.build1"
