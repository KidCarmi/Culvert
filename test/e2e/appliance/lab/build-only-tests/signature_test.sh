#!/usr/bin/env bash
# Offline tests for base-signature-check.sh with generated keys. Requires gpg.
set -uo pipefail
C="$1"; S="$2"
T=$(mktemp -d -p "$S" sigtest.XXXX); export GNUPGHOME="$T/gh"; mkdir -m700 "$GNUPGHOME"
gpgconf --create-socketdir 2>/dev/null || true
for n in A B; do gpg --batch -q --pinentry-mode loopback --passphrase '' --quick-gen-key "lab-test-$n <$n@example.invalid>" rsa2048 sign never || exit 2; done
fpr() { gpg --with-colons --list-keys "lab-test-$1" | awk -F: '$1=="fpr"{print $10; exit}'; }
FA=$(fpr A); FB=$(fpr B); [[ ${#FA} == 40 && ${#FB} == 40 && $FA != "$FB" ]] || { echo "fixture keys not generated"; exit 2; }
gpg --batch -q --export "$FA" > "$T/kA.gpg"; gpg --batch -q --export "$FB" > "$T/kB.gpg"; cat "$T/kA.gpg" "$T/kB.gpg" > "$T/kAB.gpg"; : > "$T/empty.gpg"
IMG=ubuntu-24.04-server-cloudimg-amd64.img; SHA=6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2
printf '%s *%s\n%s *other.img\n' "$SHA" "$IMG" "$(printf x | sha256sum | cut -d' ' -f1)" > "$T/SUMS"
sign() { gpg --batch -q --yes -u "$1" --detach-sign -o "$3" "$2" || exit 2; }
sign "$FA" "$T/SUMS" "$T/SUMS.A.gpg"; sign "$FB" "$T/SUMS" "$T/SUMS.B.gpg"
sed 's/other/tampered/' "$T/SUMS" > "$T/SUMS.tampered"
grep -v "$IMG" "$T/SUMS" > "$T/SUMS.noimg"; sign "$FA" "$T/SUMS.noimg" "$T/SUMS.noimg.gpg"
mkdir "$T/nogpgv"; for t in bash env gpg gpgconf mktemp awk grep sha256sum tr cut rm cat; do ln -s "$(command -v $t)" "$T/nogpgv/$t"; done
gpgconf --kill gpg-agent; unset GNUPGHOME
pass=0; tot=0
run() { local name="$1" want="$2"; shift 2; tot=$((tot+1)); out="$("$@" 2>&1)"; rc=$?
  if [ $rc -eq "$want" ]; then pass=$((pass+1)); r=PASS; else r=WRONG; fi
  echo "$r $name: exit=$rc $(echo "$out" | tail -1 | sed "s#$T#T#g" | cut -c1-110)"; }
run "control: signed by A, expect A"              0 bash "$C" "$T/kA.gpg"  "$T/SUMS" "$T/SUMS.A.gpg" "$FA" $SHA $IMG
run "control: two-key keyring, signed by A"       0 bash "$C" "$T/kAB.gpg" "$T/SUMS" "$T/SUMS.A.gpg" "$FA" $SHA $IMG
run "wrong signer: B signed, expect A (AB ring)"  1 bash "$C" "$T/kAB.gpg" "$T/SUMS" "$T/SUMS.B.gpg" "$FA" $SHA $IMG
run "wrong signer: ring lacks expected A"         1 bash "$C" "$T/kB.gpg"  "$T/SUMS" "$T/SUMS.B.gpg" "$FA" $SHA $IMG
run "missing keyring"                             1 bash "$C" "$T/nope.gpg" "$T/SUMS" "$T/SUMS.A.gpg" "$FA" $SHA $IMG
run "empty keyring"                               1 bash "$C" "$T/empty.gpg" "$T/SUMS" "$T/SUMS.A.gpg" "$FA" $SHA $IMG
run "missing gpgv"                                1 env PATH="$T/nogpgv" bash "$C" "$T/kA.gpg" "$T/SUMS" "$T/SUMS.A.gpg" "$FA" $SHA $IMG
run "missing signature file"                      1 bash "$C" "$T/kA.gpg"  "$T/SUMS" "$T/nope.gpg" "$FA" $SHA $IMG
run "missing SHA256SUMS"                          1 bash "$C" "$T/kA.gpg"  "$T/nope" "$T/SUMS.A.gpg" "$FA" $SHA $IMG
run "tampered SHA256SUMS"                         1 bash "$C" "$T/kA.gpg"  "$T/SUMS.tampered" "$T/SUMS.A.gpg" "$FA" $SHA $IMG
run "signed SUMS lacks the image line"            1 bash "$C" "$T/kA.gpg"  "$T/SUMS.noimg" "$T/SUMS.noimg.gpg" "$FA" $SHA $IMG
run "image sha differs from pin"                  1 bash "$C" "$T/kA.gpg"  "$T/SUMS" "$T/SUMS.A.gpg" "$FA" ${SHA/6a81/0000} $IMG
run "expected signer malformed"                   1 bash "$C" "$T/kA.gpg"  "$T/SUMS" "$T/SUMS.A.gpg" "d2eb4462" $SHA $IMG
echo "$pass/$tot"; rm -rf "$T"; [ $pass -eq $tot ]
