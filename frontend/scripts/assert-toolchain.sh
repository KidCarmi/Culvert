#!/bin/sh
# FE-1A toolchain identity gate: the exact Node/npm pins (ADR-FE-001) are a
# contract. CI and developers must not silently build with whatever Node the
# machine happens to provide.
set -eu
cd "$(dirname "$0")/.."

want_node="v$(tr -d '[:space:]' <.node-version)"
want_npm="$(node -p "require('./package.json').engines.npm")"
have_node="$(node --version)"
have_npm="$(npm --version)"

if [ "$have_node" != "$want_node" ]; then
  echo "toolchain: node is $have_node, pinned $want_node (frontend/.node-version)" >&2
  exit 1
fi
if [ "$have_npm" != "$want_npm" ]; then
  echo "toolchain: npm is $have_npm, pinned $want_npm (frontend/package.json engines)" >&2
  exit 1
fi
echo "toolchain: node $have_node / npm $have_npm OK"
