#!/usr/bin/env bash
# base-signature-check.sh KEYRING SUMS SIG EXPECTED_FPR IMAGE_SHA256 IMAGE_NAME
#
# Positive, signer-exact verification of the base cloud image's signed
# SHA256SUMS, run BEFORE the build-only route builds anything. The frozen
# builder treats gpgv/the keyring as optional and records
# base_image_gpg="skipped (...)" without them; this check makes both
# prerequisites mandatory and requires the signature to be made by exactly
# EXPECTED_FPR (the BOM signer), not merely by some key in the keyring.
#
# Refuses (exit 1) when: gpgv is not on PATH; the keyring is missing, empty
# or lacks EXPECTED_FPR; SUMS or SIG is missing or empty; gpgv rejects the
# signature; the status output carries no VALIDSIG, more than one, or one by
# another key; SUMS has no "<IMAGE_SHA256> *<IMAGE_NAME>" line. Offline and
# side-effect free apart from a temporary GNUPGHOME.
set -euo pipefail
keyring="${1:?KEYRING}" sums="${2:?SUMS}" sig="${3:?SIG}" want="${4:?EXPECTED_FPR}" img_sha="${5:?IMAGE_SHA256}" img_name="${6:?IMAGE_NAME}"
fail() { echo "::error::base signature: $*" >&2; exit 1; }

[[ "$want" =~ ^[0-9A-F]{40}$ ]] || fail "expected signer '$want' is not a 40-hex fingerprint"
command -v gpgv >/dev/null 2>&1 || fail "gpgv is not installed"
command -v gpg >/dev/null 2>&1 || fail "gpg is not installed"
[[ -s "$keyring" ]] || fail "keyring $keyring is missing or empty"
[[ -s "$sums" ]] || fail "SHA256SUMS $sums is missing or empty"
[[ -s "$sig" ]] || fail "signature $sig is missing or empty"

gh="$(mktemp -d)"; trap 'rm -rf "$gh"' EXIT
fprs="$(GNUPGHOME="$gh" gpg --batch --no-default-keyring --keyring "$keyring" --with-colons \
          --with-subkey-fingerprints --list-keys 2>/dev/null | awk -F: '$1=="fpr"{print $10}')"
grep -qx "$want" <<<"$fprs" || fail "keyring $keyring does not contain $want"

status="$gh/status"
gpgv --status-fd 3 --keyring "$keyring" "$sig" "$sums" 3>"$status" 2>"$gh/gpgv.log" \
  || fail "gpgv rejected the signature: $(tr '\n' ' ' <"$gh/gpgv.log")"
mapfile -t valid < <(awk '$1=="[GNUPG:]" && $2=="VALIDSIG"{print $3}' "$status")
[[ "${#valid[@]}" -eq 1 ]] || fail "expected exactly one VALIDSIG, got ${#valid[@]}"
[[ "${valid[0]}" == "$want" ]] || fail "signed by ${valid[0]}, not the BOM signer $want"
grep -qx "${img_sha} \*${img_name}" "$sums" || fail "SHA256SUMS has no line for ${img_name} with sha256 ${img_sha}"

echo "base signature: VALIDSIG ${valid[0]} over SHA256SUMS sha256 $(sha256sum "$sums" | cut -d' ' -f1); ${img_name} = ${img_sha}"
