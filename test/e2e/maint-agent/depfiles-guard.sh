#!/bin/sh
# depfiles-guard.sh — prove a build step did not change go.mod or go.sum.
#
# Used by Dockerfile.e2e around BOTH `go mod download` and `go build`. The image
# must build from the committed dependency graph; a step that silently rewrites
# go.mod/go.sum would build something no reviewer approved.
#
# The check has to run in the SAME RUN as the step it guards. The builder does
# `COPY . .` after the download, which overwrites go.mod/go.sum with the
# committed copies, so a download-induced edit checked any later would already
# be concealed.
#
#   depfiles-guard.sh snapshot            record go.mod + go.sum in the cwd
#   depfiles-guard.sh verify <step-name>  fail (exit 1, diff on stderr) if either changed
#
# POSIX sh + busybox cmp/diff only: it runs inside golang:*-alpine.
set -eu

snap="${DEPFILES_GUARD_DIR:-/tmp/depfiles-guard}"

case "${1:-}" in
snapshot)
	mkdir -p "$snap"
	for f in go.mod go.sum; do
		if [ ! -f "$f" ]; then
			echo "depfiles-guard: $f is missing in $(pwd) — nothing to protect" >&2
			exit 1
		fi
		cp "$f" "$snap/$f"
	done
	;;
verify)
	step="${2:?usage: depfiles-guard.sh verify <step-name>}"
	changed=""
	for f in go.mod go.sum; do
		if [ ! -f "$snap/$f" ]; then
			echo "depfiles-guard: no snapshot of $f — run 'snapshot' before '$step'" >&2
			exit 1
		fi
		if [ ! -f "$f" ] || ! cmp -s "$snap/$f" "$f"; then
			changed="$changed $f"
		fi
	done
	if [ -n "$changed" ]; then
		{
			echo "FATAL: '$step' changed the committed dependency files:$changed"
			echo "The E2E image builds ONLY from the committed module graph (no 'go mod tidy'"
			echo "at build time). This build needs dependency-file changes that were never"
			echo "committed: run 'go mod tidy' in the repository, review the diff, and commit"
			echo "go.mod and go.sum. What '$step' changed:"
			for f in go.mod go.sum; do
				diff -u "$snap/$f" "$f" 2>&1 | sed "s|^|  |" || true
			done
		} >&2
		exit 1
	fi
	;;
*)
	echo "usage: depfiles-guard.sh snapshot | verify <step-name>" >&2
	exit 2
	;;
esac
