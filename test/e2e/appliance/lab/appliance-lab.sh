#!/usr/bin/env bash
# appliance-lab.sh — boot the Culvert appliance OVA under QEMU and qualify the
# GUEST OS end to end. A disposable lab, never a release or a deployment.
#
#   test/e2e/appliance/lab/appliance-lab.sh preflight | up | qualify | collect | down | all
#   test/e2e/appliance/lab/appliance-lab.sh fingerprint OVA OUT.tsv
#   test/e2e/appliance/lab/appliance-lab.sh compare REFERENCE.tsv CANDIDATE.tsv
#
# EXTERNAL target (the same guest checks against an appliance some other tool
# deployed — e.g. an ESXi import; that tool owns the VM and its credentials):
#   LAB_EXTERNAL=1 LAB_HOST=<vm address> LAB_SSH_KEY=<key the VM was given>
#   [LAB_SSH_PORT=22 LAB_PROXY_PORT=8080 LAB_UI_PORT=9090] appliance-lab.sh qualify ; ... collect
#   `up`/`down` are QEMU-only; with LAB_EXTERNAL=1 `down` removes only the
#   lab's own disposable admin password and cookies, never the VM or its key.
#
# What it boots: the VMDK inside the OVA, after verifying the OVA's SHA-256
# (LAB_OVA_SHA256) and every digest in its .mf. The VMDK is converted ONCE to
# a read-only qcow2 base; the guest writes only to a disposable qcow2 overlay
# on top of it. Nothing in the appliance is modified or pre-seeded: no
# first-boot step is skipped and no completion flag is created.
#
# What it substitutes (and therefore does NOT qualify):
#   * hypervisor: QEMU (KVM when /dev/kvm is usable, TCG otherwise), not ESXi;
#   * disk bus: virtio-scsi instead of VMware LSI Logic (the guest sees /dev/sda
#     either way); NIC: e1000, as the OVF declares; firmware: BIOS (SeaBIOS), as
#     the OVF declares (no EFI setting);
#   * OVF properties: delivered by the OVF ISO transport (an ovf-env.xml on a
#     CD-ROM — the transport the OVF declares alongside guestinfo, and the one
#     VirtualBox uses). vSphere's guestinfo transport, vApp property UI,
#     ovftool import, datastore behaviour and VMware Tools are NOT exercised;
#   * network: QEMU user-mode NAT; the guest's 22/8080/9090 are forwarded to
#     127.0.0.1 only. The guest reaches the internet through the host (real
#     ClamAV signatures, the category feed, Ubuntu archives).
#
# The checks mirror docs/appliance/vsphere-qualification.md steps 1 and 3–8
# (same commands where the transport allows), with results in checks.jsonl:
# pass | fail | blocked | not-run | known-failure | info. F-DISK-1 is not
# exercised here: the bounded nested-Docker harness
# (test/e2e/appliance/upgrade-enospc-qualify.sh, QUAL_ENOSPC_SCENARIO=midwrite)
# owns it, so no fill ever touches the guest disk or the host filesystem.
#
# Credentials are disposable and per run (SSH key, admin password); they live
# in $LAB_DIR/secrets, which collect never copies. The setup token and the
# admin password are redacted from every evidence file.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
LAB_DIR="${LAB_DIR:-$ROOT/.appliance-lab}"
WORK="$LAB_DIR/work"; EV="$LAB_DIR/evidence"; SEC="$LAB_DIR/secrets"; STATEF="$LAB_DIR/state.env"
JSONL="$EV/checks.jsonl"
LAB_MEM_MB="${LAB_MEM_MB:-4096}"; LAB_CPUS="${LAB_CPUS:-2}"; LAB_ACCEL="${LAB_ACCEL:-auto}"
LAB_MIN_FREE_GB="${LAB_MIN_FREE_GB:-20}"; LAB_MIN_MEM_MB="${LAB_MIN_MEM_MB:-6144}"
LAB_EXTERNAL="${LAB_EXTERNAL:-0}"; LAB_HOST="${LAB_HOST:-127.0.0.1}"
if [[ "$LAB_EXTERNAL" == 1 ]]; then dssh=22 dproxy=8080 dui=9090; else dssh=2222 dproxy=18080 dui=19090; fi
LAB_SSH_PORT="${LAB_SSH_PORT:-$dssh}"; LAB_PROXY_PORT="${LAB_PROXY_PORT:-$dproxy}"; LAB_UI_PORT="${LAB_UI_PORT:-$dui}"
LAB_FIRSTBOOT_TIMEOUT="${LAB_FIRSTBOOT_TIMEOUT:-2400}"; LAB_KERNEL_TIMEOUT="${LAB_KERNEL_TIMEOUT:-}"; LAB_FEED_TIMEOUT="${LAB_FEED_TIMEOUT:-1500}"
LAB_EXPECT_IMAGE_ID="${LAB_EXPECT_IMAGE_ID:-}"
ADMIN_USER=labadmin

log()  { printf '%s [lab] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }
mkdir -p "$WORK" "$EV" "$SEC"; chmod 0700 "$SEC"
# shellcheck source=/dev/null
[[ -f "$STATEF" ]] && . "$STATEF"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
save_state() { printf '%s=%q\n' "$1" "$2" >> "$STATEF"; eval "$1=\$2"; }

check() { local st="$1" n="$2" r="$3" d="${4:-}"
  d="$(redact_str "$d")"
  python3 -c 'import json,sys; print(json.dumps({"run":sys.argv[1],"step":sys.argv[2],"check":sys.argv[3],"result":sys.argv[4],"detail":sys.argv[5]},separators=(",",":")))' \
    "$RUN_ID" "$st" "$n" "$r" "$d" >> "$JSONL"
  log "$r [$st] $n: $d"; }

# Every secret this run holds, replaced wherever it appears.
redact_str() { local s="$1" v
  for f in "$SEC/setup-token" "$SEC/admin-pass"; do
    [[ -s "$f" ]] || continue; v="$(cat "$f")"; s="${s//"$v"/[REDACTED]}"
  done; printf '%s' "$s"; }
redact_tree() { local f v
  for f in "$SEC/setup-token" "$SEC/admin-pass"; do
    [[ -s "$f" ]] || continue; v="$(cat "$f")"
    grep -rlF -- "$v" "$EV" 2>/dev/null | while read -r p; do sed -i "s|$(printf '%s' "$v" | sed 's/[.[\*^$/|]/\\&/g')|[REDACTED]|g" "$p"; done
  done; }

# ── access helpers (vsphere-qualification.md step 4 shapes) ──────────────────
LAB_SSH_KEY="${LAB_SSH_KEY:-$SEC/id_ed25519}"
SSH_OPTS=(-i "$LAB_SSH_KEY" -p "$LAB_SSH_PORT" -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$SEC/known_hosts"
          -o ConnectTimeout=10 -o BatchMode=yes -o LogLevel=ERROR -o ServerAliveInterval=15)
gssh() { ssh "${SSH_OPTS[@]}" "culvert@$LAB_HOST" "$@"; }
UI="https://$LAB_HOST:$LAB_UI_PORT"; P="http://$LAB_HOST:$LAB_PROXY_PORT"; JAR="$SEC/cookies"
ensure_admin_pass() { [[ -s "$SEC/admin-pass" ]] || { head -c 4096 /dev/urandom | tr -dc 'A-Za-z0-9' | cut -c1-24 > "$SEC/admin-pass"; chmod 0600 "$SEC/admin-pass"; }; }
api() { curl -ksS -m 30 -X "$1" "$UI$2" -H "Origin: $UI" -H 'Content-Type: application/json' -b "$JAR" -c "$JAR" ${3:+-d "$3"} -w '\n%{http_code}\n'; }
body() { sed '$d'; }; code() { tail -n1; }
through_proxy() { curl -sS -m 20 -x "$P" -o /dev/null -w '%{http_code}' "$1" 2>/dev/null || echo 000; }
# Monitor socket: a short fixed path (AF_UNIX paths are limited to 108 bytes).
MON_SOCK="/tmp/culvert-lab-$(printf '%s' "$WORK" | sha256sum | cut -c1-12).sock"
qemu_alive() { [[ -f "$WORK/qemu.pid" ]] && kill -0 "$(cat "$WORK/qemu.pid")" 2>/dev/null; }
# screendump NAME — the VGA screen as PNG in the evidence (firmware and GRUB
# write there, not to the serial console). Stdlib only: monitor socket + PPM→PNG.
screendump() { qemu_alive && [[ -S "$MON_SOCK" ]] || return 0
  python3 - "$MON_SOCK" "$WORK/screen.ppm" "$EV/$1.png" <<'PY' || true
import socket,struct,sys,time,zlib
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); time.sleep(0.3); s.recv(65536)
s.send(f"screendump {sys.argv[2]}\n".encode()); time.sleep(1.5); s.close()
d=open(sys.argv[2],"rb").read(); p=d.split(b"\n",3); w,h=map(int,p[1].split()); px=p[3]
raw=b"".join(b"\x00"+px[y*w*3:(y+1)*w*3] for y in range(h))
c=lambda t,b: struct.pack(">I",len(b))+t+b+struct.pack(">I",zlib.crc32(t+b)&0xffffffff)
open(sys.argv[3],"wb").write(b"\x89PNG\r\n\x1a\n"+c(b"IHDR",struct.pack(">IIBBBBB",w,h,8,2,0,0,0))+c(b"IDAT",zlib.compress(raw))+c(b"IEND",b""))
PY
}

# ── preflight: KVM, RAM, free disk, tools — measured, recorded, enforced ─────
cmd_preflight() {
  local kvm=no accel mem_mb free_gb missing=()
  if [[ -c /dev/kvm ]] && { exec 7<>/dev/kvm; } 2>/dev/null; then exec 7>&-; kvm=yes; fi
  case "$LAB_ACCEL" in auto) accel=$([[ $kvm == yes ]] && echo kvm || echo tcg) ;; kvm|tcg) accel="$LAB_ACCEL" ;; *) die "LAB_ACCEL=$LAB_ACCEL" ;; esac
  mem_mb=$(( $(awk '/MemAvailable/{print $2}' /proc/meminfo) / 1024 ))
  free_gb=$(( $(df -Pk "$LAB_DIR" | awk 'NR==2{print $4}') / 1048576 ))
  for t in qemu-system-x86_64 qemu-img ssh ssh-keygen curl python3 openssl tar sha256sum; do command -v "$t" >/dev/null || missing+=("$t"); done
  command -v genisoimage >/dev/null || command -v xorriso >/dev/null || missing+=("genisoimage|xorriso")
  python3 - "$EV/preflight.json" "$kvm" "$accel" "$mem_mb" "$free_gb" "$(nproc)" "$(uname -r)" "$(qemu-system-x86_64 --version 2>/dev/null | head -1)" "$LAB_DIR" "${missing[*]:-}" <<'PY'
import json,sys
k=["kvm_usable","accel","mem_available_mb","free_gb_at_lab_dir","cpus","host_kernel","qemu","lab_dir","missing_tools"]
json.dump(dict(zip(k,sys.argv[2:])),open(sys.argv[1],"w"),indent=1)
PY
  local ok=1
  [[ ${#missing[@]} -eq 0 ]] && check P tools pass "qemu, qemu-img, ssh, curl, python3, openssl, iso tool present" || { check P tools blocked "missing: ${missing[*]}"; ok=0; }
  (( mem_mb >= LAB_MIN_MEM_MB )) && check P memory pass "${mem_mb} MiB available (need ${LAB_MIN_MEM_MB})" || { check P memory blocked "${mem_mb} MiB available, need ${LAB_MIN_MEM_MB}"; ok=0; }
  (( free_gb >= LAB_MIN_FREE_GB )) && check P disk pass "${free_gb} GiB free at $LAB_DIR (need ${LAB_MIN_FREE_GB}: OVA + VMDK + base + overlay growth)" || { check P disk blocked "${free_gb} GiB free at $LAB_DIR, need ${LAB_MIN_FREE_GB}"; ok=0; }
  if [[ $accel == kvm && $kvm != yes ]]; then check P accel blocked "LAB_ACCEL=kvm but /dev/kvm is not usable"; ok=0
  else check P accel "$([[ $accel == kvm ]] && echo pass || echo info)" "accel=$accel (kvm usable: $kvm)"; fi
  save_state RUN_ID "$RUN_ID"; save_state ACCEL "$accel"
  [[ $ok == 1 ]] || { log "preflight BLOCKED — see $EV/preflight.json"; return 3; }
}

# ── fingerprint: the guest content an OVA ships, comparable across builds ───
FP_DIRS=(/var/lib/culvert-appliance /opt/culvert-appliance /usr/local/sbin /etc/systemd/system /etc/sudoers.d /etc/cloud/cloud.cfg.d)
# Files whose BYTES legitimately differ between two builds of the same inputs:
# build timestamps/transcripts, and `docker save` tarballs (byte layout depends
# on the build host's Docker; the image IDENTITY is compared separately, from
# manifest.env and the image the booted guest runs).
FP_VOLATILE='^/var/lib/culvert-appliance/(build-info\.json|prepare-guest\.(log|done)|images/(culvert|clamav)\.tar\.gz)$'
fingerprint_disk() { local disk="$1" out="$2"
  LIBGUESTFS_BACKEND="${LIBGUESTFS_BACKEND:-direct}" virt-ls -a "$disk" --csv -lR --checksum=sha256 "${FP_DIRS[@]}" \
    | awk -F, '$1=="-"{print $5"\t"$2"\t"$3"\t"$4}' | LC_ALL=C sort > "$out"
  local nft; nft="$(LIBGUESTFS_BACKEND="${LIBGUESTFS_BACKEND:-direct}" virt-cat -a "$disk" /etc/nftables.conf | sha256sum | cut -d' ' -f1)"
  printf '/etc/nftables.conf\t-\t-\t%s\n' "$nft" >> "$out"; LC_ALL=C sort -o "$out" "$out"; }
extract_ova() { local ova="$1" dir="$2"
  mkdir -p "$dir"; tar -xf "$ova" -C "$dir"
  local mf; mf="$(ls "$dir"/*.mf)"
  (cd "$dir" && python3 - "$(basename "$mf")" <<'PY'
import hashlib,re,sys
bad=[]
for line in open(sys.argv[1]):
    m=re.match(r'SHA256\((.+)\)= ([0-9a-f]{64})',line.strip())
    if not m: continue
    h=hashlib.sha256(open(m.group(1),'rb').read()).hexdigest()
    if h!=m.group(2): bad.append(m.group(1))
sys.exit("mf mismatch: "+",".join(bad) if bad else 0)
PY
  ); }
cmd_fingerprint() { local ova="$1" out="$2" t
  t="$(mktemp -d "$WORK/fp.XXXX")"; extract_ova "$ova" "$t"
  fingerprint_disk "$(ls "$t"/*.vmdk)" "$out"; rm -rf "$t"; log "fingerprint: $out ($(wc -l < "$out") files)"; }
cmd_compare() { local ref="$1" cand="$2" out rc=0
  out="$(compare_py "$ref" "$cand")" || rc=$?
  if [[ $rc == 0 ]]; then check F guest-content pass "$out vs $(basename "$ref") (volatile = build timestamps/transcript and docker-save tar bytes; image identity is checked at boot)"
  else check F guest-content fail "$out vs $(basename "$ref") — see fingerprint-diff.txt"; fi
  return "$rc"; }
compare_py() {
  python3 - "$1" "$2" "$FP_VOLATILE" "$EV/fingerprint-diff.txt" <<'PY' ; }
import re,sys
def load(p): return {l.split('\t')[0]:l.rstrip('\n').split('\t') for l in open(p)}
r,c,vol,out=load(sys.argv[1]),load(sys.argv[2]),re.compile(sys.argv[3]),sys.argv[4]
lines=[];same=diff=volat=0
for p in sorted(set(r)|set(c)):
    if p not in c: lines.append(f"MISSING  {p}"); diff+=1; continue
    if p not in r: lines.append(f"EXTRA    {p}"); diff+=1; continue
    if r[p][1:]==c[p][1:]: same+=1; continue
    if vol.search(p): lines.append(f"VOLATILE {p} {r[p][3][:12]} -> {c[p][3][:12]}"); volat+=1
    else: lines.append(f"DIFFERS  {p} {r[p][3][:12]} -> {c[p][3][:12]}"); diff+=1
open(out,"w").write(f"identical={same} volatile={volat} differing={diff}\n"+"\n".join(lines)+"\n")
print(f"identical={same} volatile={volat} differing={diff}")
sys.exit(1 if diff else 0)
PY

# ── up: verify → extract → immutable base + overlay → OVF ISO → boot ────────
cmd_up() {
  [[ -n "${ACCEL:-}" ]] || die "run preflight first"
  local ova="${LAB_OVA:?LAB_OVA=path to the .ova}" want="${LAB_OVA_SHA256:?LAB_OVA_SHA256=expected sha256}"
  local got; got="$(sha256sum "$ova" | cut -d' ' -f1)"
  [[ "$got" == "$want" ]] && check 1 ova-sha256 pass "$(basename "$ova") sha256 $got" || { check 1 ova-sha256 fail "got $got want $want"; return 1; }
  save_state OVA_NAME "$(basename "$ova")"; save_state OVA_SHA256 "$got"
  rm -rf "$WORK/ova"; extract_ova "$ova" "$WORK/ova" && check 1 ova-manifest pass "every .mf digest matches" || { check 1 ova-manifest fail ".mf mismatch"; return 1; }
  grep -oE 'CANDIDATE[^<]*|<Version>[^<]*' "$WORK/ova/"*.ovf | head -3 > "$EV/01-ovf-head.txt" || true
  local vmdk; vmdk="$(ls "$WORK/ova/"*.vmdk)"
  log "converting $(basename "$vmdk") → immutable qcow2 base"
  qemu-img convert -p -O qcow2 "$vmdk" "$WORK/base.qcow2" >/dev/null; rm -f "$vmdk"; chmod 0444 "$WORK/base.qcow2"
  qemu-img create -q -f qcow2 -F qcow2 -b "$WORK/base.qcow2" "$WORK/overlay.qcow2"
  qemu-img info "$WORK/base.qcow2" > "$EV/01-base-qcow2-info.txt"
  check 1 disk-chain pass "base.qcow2 (0444, from the OVA's own VMDK) ← overlay.qcow2 (disposable)"
  # Disposable credentials.
  rm -f "$SEC/id_ed25519"*; ssh-keygen -q -t ed25519 -N '' -C "culvert-lab-$RUN_ID" -f "$SEC/id_ed25519"
  rm -f "$SEC/admin-pass"; ensure_admin_pass
  # OVF environment (ISO transport): the same properties ovftool's --prop sets.
  mkdir -p "$WORK/ovfenv"
  python3 - "$WORK/ovfenv/ovf-env.xml" "lab-$RUN_ID" "$(cat "$SEC/id_ed25519.pub")" <<'PY'
import sys
from xml.sax.saxutils import quoteattr
props={"instance-id":sys.argv[2],"hostname":"culvert-lab","public-keys":sys.argv[3],"culvert.net.mode":"dhcp"}
p="\n".join(f'    <Property oe:key={quoteattr(k)} oe:value={quoteattr(v)}/>' for k,v in props.items())
open(sys.argv[1],"w").write(f'''<?xml version="1.0" encoding="UTF-8"?>
<Environment xmlns="http://schemas.dmtf.org/ovf/environment/1" xmlns:oe="http://schemas.dmtf.org/ovf/environment/1" oe:id="">
  <PropertySection>
{p}
  </PropertySection>
</Environment>
''')
PY
  sed 's/oe:value="ssh-ed25519 [^"]*"/oe:value="ssh-ed25519 <lab key>"/' "$WORK/ovfenv/ovf-env.xml" > "$EV/02-ovf-env.xml"
  if command -v genisoimage >/dev/null; then genisoimage -quiet -o "$WORK/ovfenv.iso" -V OVFENV -r -J "$WORK/ovfenv"
  else xorriso -as mkisofs -quiet -o "$WORK/ovfenv.iso" -V OVFENV -r -J "$WORK/ovfenv"; fi
  local acc=(-machine "pc,accel=tcg" -cpu max)
  [[ "$ACCEL" == kvm ]] && acc=(-machine "pc,accel=kvm" -cpu host)
  : > "$WORK/console.log"
  qemu-system-x86_64 -name culvert-lab "${acc[@]}" -smp "$LAB_CPUS" -m "$LAB_MEM_MB" \
    -drive "file=$WORK/overlay.qcow2,if=none,id=d0,format=qcow2,cache=writeback" \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=d0,bus=scsi0.0 \
    -drive "file=$WORK/ovfenv.iso,if=none,id=cd0,media=cdrom,readonly=on" -device ide-cd,drive=cd0 \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$LAB_SSH_PORT-:22,hostfwd=tcp:127.0.0.1:$LAB_PROXY_PORT-:8080,hostfwd=tcp:127.0.0.1:$LAB_UI_PORT-:9090" \
    -device e1000,netdev=n0 -display none -serial "file:$WORK/console.log" \
    -monitor "unix:$MON_SOCK,server,nowait" -pidfile "$WORK/qemu.pid" -daemonize
  printf 'qemu-system-x86_64 %s -smp %s -m %s virtio-scsi(overlay.qcow2) ide-cd(ovfenv.iso) e1000 user-net hostfwd 127.0.0.1:{%s,%s,%s} SeaBIOS\n' \
    "${acc[*]}" "$LAB_CPUS" "$LAB_MEM_MB" "$LAB_SSH_PORT" "$LAB_PROXY_PORT" "$LAB_UI_PORT" > "$EV/02-qemu-command.txt"
  save_state BOOT_STARTED "$(date +%s)"
  check 2 boot-started pass "qemu pid $(cat "$WORK/qemu.pid") accel=$ACCEL"
  # Bounded: SSH, then first boot to completion (the guest's own marker).
  local deadline=$(( $(date +%s) + LAB_FIRSTBOOT_TIMEOUT )) t0; t0=$(date +%s)
  # The guest kernel logs to ttyS0 (cloud image cmdline): no "Linux version"
  # within the bound means firmware/bootloader never handed over — fail fast
  # with the VGA screen as evidence instead of waiting out the SSH bound.
  local kt="${LAB_KERNEL_TIMEOUT:-$([[ "$ACCEL" == kvm ]] && echo 300 || echo 1800)}"
  until grep -qa 'Linux version' "$WORK/console.log" 2>/dev/null; do
    qemu_alive || { check 2 kernel-started fail "qemu exited before the kernel started"; return 1; }
    if (( $(date +%s) - t0 > kt )); then screendump 02-screen-no-kernel
      check 2 kernel-started fail "no kernel output on ttyS0 within ${kt}s — bootloader/firmware stopped; see 02-screen-no-kernel.png"; return 1; fi
    sleep 5; done
  check 2 kernel-started pass "$(grep -am1 'Linux version' "$WORK/console.log" | cut -c1-90) after $(( $(date +%s) - t0 ))s"
  until gssh true 2>/dev/null; do
    qemu_alive || { check 2 ssh-up fail "qemu exited during boot (see console.log)"; return 1; }
    (( $(date +%s) < deadline )) || { screendump 02-screen-no-ssh; check 2 ssh-up fail "no SSH within ${LAB_FIRSTBOOT_TIMEOUT}s"; return 1; }
    sleep 10; done
  check 2 ssh-up pass "SSH with the OVF-delivered key after $(( $(date +%s) - t0 ))s"
  until gssh 'sudo test -f /var/lib/culvert-appliance/state/complete.done' 2>/dev/null; do
    # systemd deletes a unit's start job to break an ordering cycle: first boot
    # will then never run, so report it now rather than after the full bound.
    if grep -qa 'Ordering cycle found, skipping.*culvert-firstboot' "$WORK/console.log" 2>/dev/null; then
      check 2 firstboot-complete fail "systemd skipped culvert-firstboot.service (ordering cycle; see console.log)"; return 1; fi
    (( $(date +%s) < deadline )) || { check 2 firstboot-complete fail "first boot not complete within ${LAB_FIRSTBOOT_TIMEOUT}s"; return 1; }
    sleep 15; done
  check 2 firstboot-complete pass "complete.done after $(( $(date +%s) - t0 ))s from power-on"
}

# ── qualify: vsphere-qualification.md steps 3–8 ─────────────────────────────
STOP=0
gate() { [[ $STOP == 0 ]] || { check "$1" "$2" not-run "an earlier step failed"; return 1; }; }
cmd_qualify() {
  if [[ "$LAB_EXTERNAL" == 1 ]]; then
    [[ -r "$LAB_SSH_KEY" ]] || die "LAB_EXTERNAL=1 needs LAB_SSH_KEY (the key the VM was given)"
    gssh true || die "cannot reach culvert@$LAB_HOST:$LAB_SSH_PORT"
    [[ -n "${ACCEL:-}" ]] || { save_state RUN_ID "$RUN_ID"; save_state ACCEL "external ($LAB_HOST)"; }
    check 2 target info "external appliance at $LAB_HOST (deployed and owned by another tool; up/down not used)"
  else [[ -n "${BOOT_STARTED:-}" ]] || die "run up first"; fi
  ensure_admin_pass
  : > "$JAR"
  # Step 3 — first-boot evidence, kernel BEFORE, image identity, token.
  gssh 'uname -r; uname -v' > "$EV/03-kernel-before.txt" 2>&1 || true
  gssh 'sudo culvert-status' > "$EV/03-status-firstboot.txt" 2>&1 || true
  gssh 'cat /var/lib/culvert-appliance/build-info.json' > "$EV/03-build-info.json" 2>&1 || true
  gssh 'ls /var/lib/culvert-appliance/state/' > "$EV/03-state-files.txt" 2>&1 || true
  gssh 'sudo docker compose -f /srv/culvert/docker-compose.yml ps --format "{{.Name}} {{.Image}} {{.Status}}"' > "$EV/03-stack.txt" 2>&1 || true
  gssh 'sudo docker inspect -f "{{.Image}}" culvert; dpkg -l "linux-image-*" | awk "/^ii/{print \$2, \$3}"; apt-mark showhold' > "$EV/03-images-kernels-holds.txt" 2>&1 || true
  grep -q 'setup pending' "$EV/03-status-firstboot.txt" && check 3 status-setup-pending pass "$(grep -m1 -i 'State:' "$EV/03-status-firstboot.txt")" || check 3 status-setup-pending fail "$(grep -m1 -i 'State:' "$EV/03-status-firstboot.txt" || echo 'no State line')"
  local want_steps="agent complete console images install ovf" got_steps
  got_steps="$(sed -n 's/\.done$//p' "$EV/03-state-files.txt" | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
  [[ "$got_steps" == "$want_steps" ]] && check 3 firstboot-steps pass "$got_steps" || check 3 firstboot-steps fail "got '$got_steps' want '$want_steps'"
  local img; img="$(head -1 "$EV/03-images-kernels-holds.txt")"; save_state IMAGE_ID "$img"
  if [[ -n "$LAB_EXPECT_IMAGE_ID" ]]; then [[ "$img" == "$LAB_EXPECT_IMAGE_ID" ]] && check 3 image-identity pass "culvert runs $img" || check 3 image-identity fail "culvert runs $img, want $LAB_EXPECT_IMAGE_ID"
  else check 3 image-identity info "culvert runs $img"; fi
  gssh 'sudo culvert-status' | awk -F': *' '/Setup token:/{print $2}' | awk '{print $1}' | tr -d '\n' > "$SEC/setup-token"
  [[ $(wc -c < "$SEC/setup-token") -eq 32 ]] && check 3 setup-token pass "32 characters, read from culvert-status over SSH" || { check 3 setup-token fail "token length $(wc -c < "$SEC/setup-token")"; STOP=1; }

  # Step 4 — first administrator; the token is REQUIRED.
  local pass c; pass="$(cat "$SEC/admin-pass")"
  if gate 4 setup-without-token; then
    c="$(api POST /api/setup/complete "{\"user\":\"$ADMIN_USER\",\"pass\":\"$pass\"}" | tee "$EV/04-setup-without-token.txt" | code)"
    [[ $c == 403 ]] && check 4 setup-without-token pass "403" || { check 4 setup-without-token fail "http $c (want 403)"; STOP=1; }
    c="$(curl -ksS -m 30 -X POST "$UI/api/setup/complete" -H "Origin: $UI" -H 'Content-Type: application/json' -H "X-Culvert-Setup-Token: $(cat "$SEC/setup-token")" \
          -d "{\"user\":\"$ADMIN_USER\",\"pass\":\"$pass\"}" -w '\n%{http_code}\n' | tee "$EV/04-setup-with-token.txt" | code)"
    [[ $c == 200 ]] && check 4 setup-with-token pass "200" || { check 4 setup-with-token fail "http $c"; STOP=1; }
    c="$(api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$pass\"}" | tee "$EV/04-login.txt" | code)"
    [[ $c == 200 ]] && check 4 admin-login pass "200" || { check 4 admin-login fail "http $c"; STOP=1; }
    gssh 'sudo culvert-status' > "$EV/04-status-after-setup.txt" 2>&1 || true
    grep -qi 'setup complete' "$EV/04-status-after-setup.txt" && check 4 status-setup-complete pass "culvert-status: setup complete" || check 4 status-setup-complete fail "$(grep -m1 -i 'State:' "$EV/04-status-after-setup.txt")"
  fi

  # Step 5 — enforcement: default deny, one allow rule, real traffic.
  if gate 5 enforcement; then
    c="$(api PUT /api/settings/default-auth-outcome '{"defaultAuthOutcome":"Exempt"}' | tee "$EV/05-auth-exempt.txt" | code)"
    [[ $c == 200 ]] && check 5 auth-exempt pass "200" || check 5 auth-exempt fail "http $c"
    api GET /api/default-action > "$EV/05-default-action.txt"
    grep -q '"deny"' "$EV/05-default-action.txt" && check 5 default-deny pass "$(body < "$EV/05-default-action.txt")" || check 5 default-deny fail "$(body < "$EV/05-default-action.txt")"
    local b a o
    b="$(through_proxy http://example.com/)"
    api POST /api/policy '{"name":"lab-allow-example","priority":10,"action":"Allow","destFQDN":"example.com","sslAction":"Bypass","enabled":true}' > "$EV/05-rule.txt"
    a="$(through_proxy http://example.com/)"; o="$(through_proxy http://example.org/)"
    printf 'before-rule %s\nafter-rule %s\nother-host %s\n' "$b" "$a" "$o" > "$EV/05-traffic.txt"
    [[ "$b $a $o" == "403 200 403" ]] && check 5 traffic pass "example.com 403 → rule → 200; example.org 403 (real egress through the guest proxy)" || check 5 traffic fail "before=$b after=$a other=$o (want 403 200 403)"
    curl -sS -m 20 "$P/ready" > "$EV/05-ready.json" || true
    python3 - "$EV/05-ready.json" <<'PY' > "$EV/05-ready-rows.txt" || true
import json,sys
d=json.load(open(sys.argv[1])); ch=d.get("checks",d)
for k in sorted(ch):
    v=ch[k]; print(k, v.get("status") if isinstance(v,dict) else v)
PY
    local bad; bad="$(awk '$1~/^(policy_loaded|policy_posture|ca)$/ && $2!="ok"' "$EV/05-ready-rows.txt")"
    [[ -s "$EV/05-ready-rows.txt" && -z "$bad" ]] && check 5 ready-rows pass "$(grep -E '^(policy_loaded|policy_posture|ca) ' "$EV/05-ready-rows.txt" | tr '\n' ';')" || check 5 ready-rows fail "${bad:-no /ready rows}"
    # Real ClamAV (the OVA's pinned sidecar with signatures downloaded at first boot).
    local cv; cv="$(awk '$1=="clamav"{print $2}' "$EV/05-ready-rows.txt")"
    [[ "$cv" == ok ]] && check 5 clamav-real pass "/ready clamav ok — the REAL clamav/clamav sidecar from the OVA, signatures fetched by the guest" || check 5 clamav-real fail "/ready clamav=${cv:-absent}"
    gssh 'sudo culvert-status' > "$EV/05-status.txt" 2>&1 || true
    grep -qi 'ready to enforce' "$EV/05-status.txt" && check 5 status-ready-to-enforce pass "culvert-status: ready to enforce" || check 5 status-ready-to-enforce fail "$(grep -m1 -i 'State:' "$EV/05-status.txt")"
    api GET /api/ca-cert | body | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 > "$EV/05-ca-fingerprint.txt" || true
    [[ -s "$EV/05-ca-fingerprint.txt" ]] && check 5 ca-identity pass "root CA sha256 $(cat "$EV/05-ca-fingerprint.txt")" || check 5 ca-identity fail "no CA certificate"
  fi

  # Step 5b — community category data (the boot-time feed sync), for the persistence check.
  if gate 5b category-data; then
    local deadline=$(( $(date +%s) + LAB_FEED_TIMEOUT )) fl=""
    until fl="$(gssh 'sudo docker logs culvert 2>&1 | grep -oE "FeedSync: (sync complete[^\"]*|download/parse failed[^\"]*|bulk write failed[^\"]*|write REFUSED[^\"]*)" | tail -1')" && [[ -n "$fl" ]]; do
      (( $(date +%s) < deadline )) || break; sleep 20; done
    echo "${fl:-no feed completion line within ${LAB_FEED_TIMEOUT}s}" > "$EV/05b-feed.txt"
    lookups > "$EV/05b-lookups-before.txt"
    if [[ "$fl" == *"sync complete"* ]] && grep -q 'category=[^ ]' "$EV/05b-lookups-before.txt"; then
      check 5b category-data pass "$fl; $(grep -c 'category=[^ ]' "$EV/05b-lookups-before.txt") of $(wc -l < "$EV/05b-lookups-before.txt") probe hosts categorized"
    else check 5b category-data fail "${fl:-feed did not complete}; lookups: $(tr '\n' ' ' < "$EV/05b-lookups-before.txt")"; fi
  fi

  # Step 6 — maintenance agent: backup through the product, restore DRY RUN.
  if gate 6 agent-backup; then
    api GET /api/maintenance-agent > "$EV/06-agent-status.txt" || true
    local opjson op fn st=""
    opjson="$(api POST /api/backups '{"encrypt":false}' | tee "$EV/06-backup-trigger.txt")"
    op="$(printf '%s\n' "$opjson" | body | python3 -c 'import json,sys;print(json.load(sys.stdin).get("opId",""))' 2>/dev/null || true)"
    fn="$(printf '%s\n' "$opjson" | body | python3 -c 'import json,sys;print(json.load(sys.stdin).get("filename",""))' 2>/dev/null || true)"
    if [[ -n "$op" ]]; then
      for _ in $(seq 1 90); do st="$(api GET "/api/backups/operations/$op" | body | python3 -c 'import json,sys;print(json.load(sys.stdin).get("state",""))' 2>/dev/null || true)"
        case "$st" in succeeded|failed) break ;; esac; sleep 2; done
    fi
    [[ "$st" == succeeded ]] && check 6 agent-backup pass "op $op → $fn succeeded (proxy → agent socket → sudoers → cli container)" || check 6 agent-backup fail "op=${op:-none} state=${st:-none}: $(body < "$EV/06-backup-trigger.txt" | head -c 300)"
    api GET /api/backups > "$EV/06-backups.txt" || true
    if [[ -n "$fn" ]]; then
      gssh "cd /srv/culvert && sudo docker compose --profile cli run --rm -T cli --restore /backup/$fn --mode full" > "$EV/06-restore-dryrun.txt" 2>&1 || true
      grep -qi 'validation passed' "$EV/06-restore-dryrun.txt" && check 6 restore-dry-run pass "validation passed (no --confirm; nothing restored)" || check 6 restore-dry-run fail "$(tail -3 "$EV/06-restore-dryrun.txt" | tr '\n' ' ')"
    else check 6 restore-dry-run not-run "no backup file"; fi
    save_state BACKUP_FILE "$fn"
  fi

  # Step 7 — OS update + reboot, kernel BEFORE → AFTER.
  if gate 7 os-update; then
    gssh 'sudo culvert-os-update check' > "$EV/07-check-before.txt" 2>&1 || true
    local rc=0; timeout 2400 ssh "${SSH_OPTS[@]}" "culvert@$LAB_HOST" 'sudo culvert-os-update os' > "$EV/07-os-update.txt" 2>&1 || rc=$?
    [[ $rc == 0 ]] && check 7 os-update pass "culvert-os-update os exit 0 ($(grep -cE '^(Setting up|Unpacking) ' "$EV/07-os-update.txt" || true) package actions)" || check 7 os-update fail "exit $rc: $(tail -3 "$EV/07-os-update.txt" | tr '\n' ' ')"
    gssh 'sudo culvert-os-update check; ls -l /var/run/reboot-required 2>/dev/null; dpkg -l "linux-image-*" | awk "/^ii/{print \$2, \$3}"; apt-mark showhold; sudo docker version --format "{{.Server.Version}}"' > "$EV/07-check-after-update.txt" 2>&1 || true
    gssh 'sudo culvert-os-update reboot' > "$EV/07-reboot.txt" 2>&1 || true
    local deadline=$(( $(date +%s) + LAB_FIRSTBOOT_TIMEOUT )) t0; t0=$(date +%s); sleep 20
    until curl -fsS -m 3 "$P/health" >/dev/null 2>&1 && gssh true 2>/dev/null; do
      qemu_alive || { check 7 reboot fail "qemu exited during the reboot"; STOP=1; break; }
      (( $(date +%s) < deadline )) || { check 7 reboot fail "not back within ${LAB_FIRSTBOOT_TIMEOUT}s"; STOP=1; break; }
      sleep 10; done
    if [[ $STOP == 0 ]]; then
      check 7 reboot pass "proxy /health and SSH back $(( $(date +%s) - t0 ))s after the reboot command"
      gssh 'uname -r; uname -v' > "$EV/07-kernel-after.txt" 2>&1 || true
      local kb ka; kb="$(head -1 "$EV/03-kernel-before.txt")"; ka="$(head -1 "$EV/07-kernel-after.txt")"
      local newer; newer="$(awk -v run="linux-image-$kb" '$1 ~ /^linux-image-[0-9]/ && $1 != run {print $1}' "$EV/07-check-after-update.txt" | tr '\n' ' ')"
      if [[ "$kb" != "$ka" ]]; then check 7 kernel pass "kernel CHANGED $kb → $ka"
      elif [[ -n "$newer" ]]; then check 7 kernel fail "installed ${newer}but $kb still runs after the reboot"
      else check 7 kernel info "kernel unchanged ($kb): no newer linux-image was installed"; fi
      local holds; holds="$(grep -cE '^(docker-ce|docker-ce-cli|containerd.io|docker-compose-plugin)$' "$EV/07-check-after-update.txt" || true)"
      [[ "$holds" -ge 4 ]] && check 7 docker-held pass "Docker packages still held; engine $(tail -1 "$EV/07-check-after-update.txt")" || check 7 docker-held fail "holds found: $holds"
    fi
  fi

  # Step 8 — persistence and readiness after the reboot.
  if gate 8 persistence; then
    gssh 'sudo culvert-status; ls /var/lib/culvert-appliance/state/' > "$EV/08-status-after-reboot.txt" 2>&1 || true
    : > "$JAR"; c="$(api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$pass\"}" | tee "$EV/08-login.txt" | code)"
    [[ $c == 200 ]] && check 8 admin-login pass "200 after reboot" || check 8 admin-login fail "http $c"
    api GET /api/policy | body > "$EV/08-policy.json" || true
    python3 -c 'import json,sys;print(" ".join(r["name"] for r in json.load(open(sys.argv[1]))["rules"]))' "$EV/08-policy.json" > "$EV/08-rules.txt" 2>/dev/null || true
    grep -qw lab-allow-example "$EV/08-rules.txt" && check 8 policy-persisted pass "rules: $(cat "$EV/08-rules.txt")" || check 8 policy-persisted fail "rules: $(cat "$EV/08-rules.txt")"
    local a o; a="$(through_proxy http://example.com/)"; o="$(through_proxy http://example.org/)"
    printf 'allowed %s\ndenied %s\n' "$a" "$o" > "$EV/08-enforce.txt"
    [[ "$a $o" == "200 403" ]] && check 8 enforcement pass "example.com 200, example.org 403 (also proves Exempt auth survived)" || check 8 enforcement fail "allowed=$a denied=$o"
    c="$(curl -sS -m 20 -o /dev/null -w '%{http_code}' "$P/ready" || echo 000)"
    [[ $c == 200 ]] && check 8 ready pass "/ready 200" || check 8 ready fail "/ready $c"
    api GET /api/ca-cert | body | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 > "$EV/08-ca-fingerprint.txt" || true
    [[ -s "$EV/08-ca-fingerprint.txt" ]] && cmp -s "$EV/05-ca-fingerprint.txt" "$EV/08-ca-fingerprint.txt" && check 8 ca-identity pass "unchanged $(cat "$EV/08-ca-fingerprint.txt")" || check 8 ca-identity fail "before=$(cat "$EV/05-ca-fingerprint.txt" 2>/dev/null) after=$(cat "$EV/08-ca-fingerprint.txt" 2>/dev/null)"
    lookups > "$EV/08-lookups-after.txt"
    cmp -s "$EV/05b-lookups-before.txt" "$EV/08-lookups-after.txt" && check 8 category-data pass "category lookups identical before/after reboot" || check 8 category-data fail "$(diff "$EV/05b-lookups-before.txt" "$EV/08-lookups-after.txt" | tr '\n' ' ' | head -c 300)"
    api GET /api/backups > "$EV/08-backups.txt" || true
    [[ -n "${BACKUP_FILE:-}" ]] && grep -qF "$BACKUP_FILE" "$EV/08-backups.txt" && check 8 backup-listed pass "$BACKUP_FILE still listed" || check 8 backup-listed fail "backup ${BACKUP_FILE:-?} not listed"
    c="$(api GET /api/maintenance-agent | tee "$EV/08-agent-status.txt" | code)"
    [[ $c == 200 ]] && check 8 agent-reachable pass "$(body < "$EV/08-agent-status.txt" | head -c 200)" || check 8 agent-reachable fail "http $c"
    gssh 'sudo journalctl -b -u culvert-firstboot --no-pager | tail -20' > "$EV/08-firstboot-journal.txt" 2>&1 || true
    grep -q 'step .*: done' "$EV/08-firstboot-journal.txt" && check 8 firstboot-not-rerun fail "a first-boot step ran again" || check 8 firstboot-not-rerun pass "no first-boot step ran on the second boot"
    cmp -s <(sed -n '/\.done$/p' "$EV/03-state-files.txt") <(sed -n '/\.done$/p' "$EV/08-status-after-reboot.txt") && check 8 state-files pass "first-boot state files unchanged" || check 8 state-files info "state listing changed — see 08-status-after-reboot.txt"
  fi
  redact_tree
}
# Probe hosts for the community category layer (UT1 feed): recorded before and
# after the reboot; the comparison, not any one verdict, is the persistence check.
LAB_CAT_HOSTS="${LAB_CAT_HOSTS:-pokerstars.com bet365.com pornhub.com thepiratebay.org 888casino.com}"
lookups() { local h
  for h in $LAB_CAT_HOSTS; do
    api GET "/api/urlcat/lookup?host=$h" | body | python3 -c 'import json,sys
h=sys.argv[1]
try: d=json.load(sys.stdin)
except Exception: print(f"{h} error"); sys.exit()
print("%s category=%s matchedBy=%s" % (h, d.get("category") or "", d.get("matchedBy") or ""))' "$h"
  done; }

# ── collect: guest diagnostics + identities → REPORT.md (redacted) ──────────
cmd_collect() {
  mkdir -p "$EV/guest"
  if qemu_alive && gssh true 2>/dev/null; then
    gssh 'sudo culvert-status --json' > "$EV/guest/culvert-status.json" 2>&1 || true
    gssh 'sudo journalctl -u culvert-firstboot --no-pager' > "$EV/guest/firstboot-journal.txt" 2>&1 || true
    gssh 'sudo cat /var/log/culvert-firstboot.log' > "$EV/guest/firstboot.log" 2>&1 || true
    gssh 'cloud-init status --long; sudo cloud-init query ds 2>/dev/null | head -5' > "$EV/guest/cloud-init.txt" 2>&1 || true
    gssh 'sudo docker ps -a --format "{{.Names}} {{.Image}} {{.Status}}"; df -h / /var/lib/docker; uname -a' > "$EV/guest/runtime.txt" 2>&1 || true
    gssh 'sudo docker logs --tail 200 culvert 2>&1' > "$EV/guest/proxy-log-tail.txt" 2>&1 || true
  else check C guest-reachable info "guest not reachable at collect time; console log only"; fi
  [[ -f "$WORK/console.log" ]] && tr -d '\r' < "$WORK/console.log" | tail -c 2000000 > "$EV/guest/console.log"
  redact_tree
  # Belt and braces: nothing private may leave the lab.
  if grep -rlE 'BEGIN [A-Z ]*PRIVATE KEY|X-Culvert-Setup-Token: [0-9a-f]{32}' "$EV" >/dev/null 2>&1; then check C redaction fail "private material found in evidence"; fi
  local lab_sha; lab_sha="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  {
    echo "# Appliance lab — guest boot qualification (run $RUN_ID)"; echo
    echo "| identity | value |"; echo "|---|---|"
    echo "| lab/harness commit | \`$lab_sha\` |"
    echo "| OVA | \`${OVA_NAME:-?}\` sha256 \`${OVA_SHA256:-?}\` |"
    echo "| appliance source (guest build-info) | \`$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["source"]["git_commit"])' "$EV/03-build-info.json" 2>/dev/null || echo '?')\` |"
    echo "| application image in the guest | \`${IMAGE_ID:-?}\` |"
    echo "| accelerator | ${ACCEL:-?} (preflight: \`preflight.json\`) |"
    echo; echo "| step | check | result | detail |"; echo "|---|---|---|---|"
    python3 - "$JSONL" <<'PY'
import json,sys
for l in open(sys.argv[1]):
    d=json.loads(l); print(f"| {d['step']} | {d['check']} | **{d['result'].upper()}** | {d['detail'].replace('|','/')[:300]} |")
PY
    echo; python3 - "$JSONL" <<'PY'
import json,sys,collections
c=collections.Counter(json.loads(l)["result"] for l in open(sys.argv[1])); print("Totals: "+", ".join(f"{k}={v}" for k,v in sorted(c.items())))
PY
    echo; echo "Not qualified by this lab: vSphere/ESXi import (ovftool), the guestinfo OVF transport, VMware Tools, LSI Logic SCSI, datastore/thin-provisioning behaviour, and F-DISK-1 (owned by the bounded nested-Docker harness; still OPEN)."
  } > "$EV/REPORT.md"
  log "evidence: $EV/REPORT.md"
}

# ── down: stop the guest, remove the disposable disks (evidence stays) ──────
cmd_down() {
  if [[ "$LAB_EXTERNAL" == 1 ]]; then
    rm -f "$SEC/admin-pass" "$SEC/setup-token" "$SEC/cookies"
    log "down (external): removed the lab's own disposable secrets; the VM and its key belong to the deploying tool"; return 0
  fi
  if qemu_alive; then
    gssh 'sudo systemctl poweroff' >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do qemu_alive || break; sleep 2; done
    qemu_alive && kill "$(cat "$WORK/qemu.pid")" 2>/dev/null; sleep 3
    qemu_alive && kill -9 "$(cat "$WORK/qemu.pid")" 2>/dev/null || true
  fi
  rm -f "$MON_SOCK"
  [[ "${LAB_KEEP_DISKS:-0}" == 1 ]] || rm -rf "$WORK/overlay.qcow2" "$WORK/base.qcow2" "$WORK/ova" "$WORK/ovfenv" "$WORK/ovfenv.iso"
  rm -rf "$SEC"; log "down: guest stopped, disposable disks and credentials removed (evidence kept in $EV)"
}

failures() { grep -c '"result":"fail"' "$JSONL" 2>/dev/null || true; }
# Transport adapters may reuse the guest checks without dispatching QEMU.
[[ "${LAB_LIBRARY_ONLY:-0}" == 1 ]] && return 0
case "${1:-}" in
  preflight) cmd_preflight ;;
  fingerprint) cmd_fingerprint "${2:?OVA}" "${3:?OUT.tsv}" ;;
  compare) cmd_compare "${2:?REF}" "${3:?CAND}" ;;
  up) cmd_up ;;
  qualify) cmd_qualify; [[ "$(failures)" == 0 ]] ;;
  collect) cmd_collect ;;
  down) cmd_down ;;
  all)
    trap 'cmd_collect || true; cmd_down || true' EXIT
    cmd_preflight; cmd_up; cmd_qualify; n="$(failures)"; log "failures: $n"; [[ "$n" == 0 ]] ;;
  *) sed -n '2,32p' "$0"; exit 2 ;;
esac
