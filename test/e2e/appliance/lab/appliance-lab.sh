#!/usr/bin/env bash
# appliance-lab.sh — boot the Culvert appliance OVA under QEMU and qualify the
# GUEST OS end to end. A disposable lab, never a release or a deployment.
#
#   test/e2e/appliance/lab/appliance-lab.sh preflight | up | qualify | collect | down | all
#   test/e2e/appliance/lab/appliance-lab.sh fingerprint OVA OUT.tsv
#   test/e2e/appliance/lab/appliance-lab.sh compare REFERENCE.tsv CANDIDATE.tsv
#
# ACCESS MODEL (docs/appliance/ssh-access-boundary.md) — the lab uses exactly
# the two paths an operator has, and never a third:
#   * observation: SSH as the read-only `culvert-operator` with the imported
#     key (`help`, `status`, `status-json`, `diagnostics`; nothing else);
#   * privileged work: a PAM login as the local administrator `culvert` on the
#     VM console, then `sudo` with that password. Under QEMU the console is
#     ttyS0 (console-session.py drives the real getty: the one-time password
#     first boot printed → the forced change → sudo). No key, sudoers drop-in
#     or other bypass is added to the guest.
#
# EXTERNAL target (the same guest checks against an appliance some other tool
# deployed — e.g. an ESXi import; that tool owns the VM and its credentials):
#   LAB_EXTERNAL=1 LAB_HOST=<vm address> LAB_SSH_KEY=<key the VM was given>
#   LAB_PRIV_CMD='<command>'  [LAB_SSH_PORT=22 LAB_PROXY_PORT=8080 LAB_UI_PORT=9090]
#   appliance-lab.sh qualify ; ... collect
# LAB_PRIV_CMD is that tool's authenticated-console transport: it reads a bash
# script on stdin, runs it as root through the local `culvert` login + sudo
# (or as `culvert` itself when given --as-user), prints the script's output
# and exits with its status; `--timeout N` and `--nowait` (start, do not wait:
# reboot) may be passed. `up`/`down` are QEMU-only; with LAB_EXTERNAL=1 `down`
# removes only the lab's own disposable secrets, never the VM or its key.
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
#   * the VM console: ttyS0 (serial getty) instead of the hypervisor's tty1;
#     the same PAM stack and account, a different terminal;
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
# SIGNED UPDATE / ROLLBACK (step 6c) runs only with LAB_UPDATE_DIR, prepared by
# the lab workflow OUTSIDE the OVA: a disposable TLS registry the guest reaches
# as ghcr.io, the OVA's own image (same index digest) as the baseline, a
# relabelled target, and evidence from test/e2e/release-proof-fixture (ephemeral
# key, never saved; only its PUBLIC keyring reaches the guest). The guest-side
# trust configuration it adds is TEST-ONLY and recorded in 06c-test-only-trust.txt.
#
# Credentials are disposable and per run (SSH key, console password, admin
# password); they live in $LAB_DIR/secrets, which collect never copies. Every
# secret is redacted from every evidence file.
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
LAB_EXPECT_IMAGE_ID="${LAB_EXPECT_IMAGE_ID:-}"; LAB_UPDATE_DIR="${LAB_UPDATE_DIR:-}"
# Disk model. overlay (default): qcow2 overlay over the read-only base, host page
# cache on — the qualification lab. dm: a disposable raw copy of the OVA's VMDK
# behind a device-mapper target, cache=none + a direct-I/O loop, so every guest
# read reaches the device and latency can be injected (dm-delay) while the guest
# runs. `recovery` requires dm.
LAB_DISK="${LAB_DISK:-overlay}"
# Maintenance-reboot recovery (cmd_recovery): N reboots per profile; a profile is
# name:read_ms:write_ms:budget_s (the injected per-I/O latency and the recovery
# budget each reboot of that profile must meet).
LAB_RECOVERY_REBOOTS="${LAB_RECOVERY_REBOOTS:-0}"
LAB_RECOVERY_PROFILES="${LAB_RECOVERY_PROFILES:-fast:0:0:60 esxi110:110:18:300}"
LAB_RECOVERY_TIMEOUT="${LAB_RECOVERY_TIMEOUT:-1800}"
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
SECRET_FILES=(setup-token admin-pass console-pass console-onetime)
redact_str() { local s="$1" v f
  for f in "${SECRET_FILES[@]}"; do
    [[ -s "$SEC/$f" ]] || continue; v="$(cat "$SEC/$f")"; s="${s//"$v"/[REDACTED]}"
  done; printf '%s' "$s"; }
# A secret that appears in NO evidence file is the good case, not an error:
# under pipefail grep's "no match" used to fail the function, which ended
# cmd_qualify (its last call) before the failure count — so an all-PASS run
# exited 1 (run 37195991070: 48 pass, 0 fail). Redaction itself is unchanged
# and collect still refuses evidence that carries private material.
redact_tree() { local f v
  for f in "${SECRET_FILES[@]}"; do
    [[ -s "$SEC/$f" ]] || continue; v="$(cat "$SEC/$f")"
    { grep -rlF -- "$v" "$EV" 2>/dev/null || true; } | while read -r p; do sed -i "s|$(printf '%s' "$v" | sed 's/[.[\*^$/|]/\\&/g')|[REDACTED]|g" "$p"; done
  done
  return 0; }

# ── access helpers ───────────────────────────────────────────────────────────
LAB_SSH_KEY="${LAB_SSH_KEY:-$SEC/id_ed25519}"
SSH_OPTS=(-i "$LAB_SSH_KEY" -p "$LAB_SSH_PORT" -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$SEC/known_hosts"
          -o ConnectTimeout=10 -o BatchMode=yes -o LogLevel=ERROR -o ServerAliveInterval=15 -o IdentitiesOnly=yes)
# gop CMD — the read-only operator interface (exact command, nothing else).
gop() { ssh "${SSH_OPTS[@]}" "culvert-operator@$LAB_HOST" "$@"; }
# Serial console socket (QEMU chardev; its logfile is console.log). Short fixed
# path: AF_UNIX paths are limited to 108 bytes.
SER_SOCK="/tmp/culvert-lab-ser-$(printf '%s' "$WORK" | sha256sum | cut -c1-12).sock"
DM_NAME="culvert-lab-$(printf '%s' "$WORK" | sha256sum | cut -c1-8)"
# gpriv [--as-user] [--timeout N] [--nowait] < script — authenticated local
# administration: PAM login as culvert on the console, then sudo (root).
gpriv() {
  if [[ -n "${LAB_PRIV_CMD:-}" ]]; then
    # shellcheck disable=SC2086 # the adapter command is a word list by contract
    $LAB_PRIV_CMD "$@"
  else
    python3 "$HERE/console-session.py" --sock "$SER_SOCK" --secrets "$SEC" --console-log "$WORK/console.log" \
      --trace "$WORK/console-session-trace.txt" "$@"
  fi; }
# groot 'command line' — one privileged command line (convenience over gpriv).
groot() { printf '%s\n' "$1" | gpriv --timeout "${2:-600}"; }
UI="https://$LAB_HOST:$LAB_UI_PORT"; P="http://$LAB_HOST:$LAB_PROXY_PORT"; JAR="$SEC/cookies"
ensure_admin_pass() { [[ -s "$SEC/admin-pass" ]] || { head -c 4096 /dev/urandom | tr -dc 'A-Za-z0-9' | cut -c1-24 > "$SEC/admin-pass"; chmod 0600 "$SEC/admin-pass"; }; }
# api METHOD PATH [BODY] — JAR may be overridden per call (JAR=… api …) for a
# second administrator session.
api() { curl -ksS -m 30 -X "$1" "$UI$2" -H "Origin: $UI" -H 'Content-Type: application/json' -b "$JAR" -c "$JAR" ${3:+-d "$3"} -w '\n%{http_code}\n'; }
body() { sed '$d'; }; code() { tail -n1; }
# status_field FILE KEY — one field of a status-json snapshot.
status_field() { python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get(sys.argv[2],""))
except Exception: print("")' "$1" "$2"; }
# recorded_steps FILE — the first-boot steps a status-json snapshot reports recorded.
recorded_steps() { python3 -c 'import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: sys.exit(0)
print(" ".join(sorted(s["id"] for s in d.get("steps",[]) if s.get("state")=="recorded")))' "$1"; }
# agent_status_verdict FILE — FILE is `api GET /api/maintenance-agent` output
# (JSON body, then the HTTP code). That endpoint answers 200 EVEN WHEN THE
# AGENT IS DOWN ({available:false, reason}) so the GUI can show why: HTTP 200
# alone proves nothing (run 37159302279 recorded PASS with available:false and
# a missing socket). PASS needs a real reachable agent: HTTP 200, available
# === true (a JSON boolean), a release-shaped agent_version and the compose
# stack up. Prints "pass|<detail>" or "fail|<detail>".
agent_status_verdict() {
  python3 - "$1" <<'PY'
import json, re, sys
lines = open(sys.argv[1]).read().rstrip("\n").split("\n")
code, body = (lines[-1].strip() if lines else ""), "\n".join(lines[:-1])
def out(r, d): print(f"{r}|{d}"); sys.exit(0)
if code != "200": out("fail", f"http {code or '?'}")
try: j = json.loads(body)
except Exception: out("fail", "unparseable body: " + body[:120])
if not isinstance(j, dict) or j.get("available") is not True:
    out("fail", "agent not available: " + str((j or {}).get("reason", body[:160]) if isinstance(j, dict) else body[:160]))
v = j.get("agent_version", "")
if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?", v or ""): out("fail", f"agent_version {v!r} is not a release-shaped version")
if j.get("compose_stack_up") is not True: out("fail", f"agent {v}: compose stack not up ({j.get('compose_error', '')})")
out("pass", f"agent {v} reachable over its socket, privilege_mode={j.get('privilege_mode', '?')}, compose stack up")
PY
}
# The oracle's own proof: a known-unavailable response must FAIL it, or a
# PASS from it means nothing.
cmd_selftest() { local d rc=0 got; d="$(mktemp -d)"
  verdict_case() { printf '%s\n%s\n' "$2" "$3" > "$d/r"; got="$(agent_status_verdict "$d/r")"
    if [[ "${got%%|*}" == "$1" ]]; then log "selftest ok: $4 -> $got"; else log "selftest FAILED: $4 -> $got (want $1)"; rc=1; fi; }
  verdict_case fail '{"available":false,"reason":"maintenance agent unreachable: dial unix /run/culvert-maint/culvert-maint.sock: connect: no such file or directory"}' 200 "run 37159302279's response"
  verdict_case fail '{"available":false,"reason":"maintenance agent not configured"}' 200 "not configured"
  verdict_case fail '{"available":false,"agent_version":"v1.0.260-candidate.gc5551a18da30","compose_stack_up":true}' 200 "available:false with otherwise healthy fields"
  verdict_case fail '{"available":"true","agent_version":"v1.0.260-candidate.gc5551a18da30","compose_stack_up":true}' 200 "available as a string"
  verdict_case fail '{"available":true,"agent_version":"dev","compose_stack_up":true}' 200 "dev agent"
  verdict_case fail '{"available":true,"agent_version":"v1.0.260-candidate.gc5551a18da30","compose_stack_up":false}' 200 "stack down"
  verdict_case fail '{"error":"forbidden"}' 403 "http 403"
  verdict_case fail 'not json' 200 "unparseable"
  verdict_case pass '{"available":true,"agent_version":"v1.0.260-candidate.gc5551a18da30","privilege_mode":"sudoers","compose_stack_up":true}' 200 "healthy agent"
  # redact_tree: nothing to redact is success; a present secret is replaced.
  if ( SEC="$d/sec" EV="$d/ev"; mkdir -p "$SEC" "$EV"; printf 'S3cretValue42' > "$SEC/admin-pass"; echo clean > "$EV/a.txt"; redact_tree ); then
    log "selftest ok: redact_tree with nothing to redact -> success"; else log "selftest FAILED: redact_tree with nothing to redact failed"; rc=1; fi
  if ( SEC="$d/sec2" EV="$d/ev2"; mkdir -p "$SEC" "$EV"; printf 'S3cretValue42' > "$SEC/admin-pass"; echo 'pw=S3cretValue42' > "$EV/b.txt"; redact_tree && grep -qx 'pw=\[REDACTED\]' "$EV/b.txt" && ! grep -rq S3cretValue42 "$EV" ); then
    log "selftest ok: redact_tree replaces a present secret"; else log "selftest FAILED: redact_tree left a secret in the evidence"; rc=1; fi
  if ( SEC="$d/sec3" EV="$d/ev3"; mkdir -p "$SEC" "$EV"; printf 'Cons0leSecret_9a' > "$SEC/console-pass"; printf 'OneT1meSecret' > "$SEC/console-onetime"
       printf "login ok Cons0leSecret_9a\npassword: OneT1meSecret\n" > "$EV/c.txt"; redact_tree && ! grep -rqE 'Cons0leSecret_9a|OneT1meSecret' "$EV" ); then
    log "selftest ok: redact_tree removes the console passwords"; else log "selftest FAILED: a console password survived redaction"; rc=1; fi
  # The console helper must refuse to run without any credential (exit 91),
  # never guess or fall back to another account.
  local hrc=0; printf 'id\n' | python3 "$HERE/console-session.py" --sock "$d/none.sock" --secrets "$d" --console-log "$d/none.log" --timeout 5 >/dev/null 2>&1 || hrc=$?
  if [[ $hrc == 99 || $hrc == 91 ]]; then log "selftest ok: console-session without a console/credential -> exit $hrc"; else log "selftest FAILED: console-session exit $hrc"; rc=1; fi
  rm -rf "$d"; return "$rc"; }
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
# ── device-mapper disk (LAB_DISK=dm) ─────────────────────────────────────────
# The guest disk is a raw file on a direct-I/O loop device under a dm target, so
# neither the host page cache nor QEMU's (cache=none) hides a read: what the guest
# reads after a reboot is what the device serves, as on a hypervisor datastore.
# set_disk_latency swaps the live table between `linear` and `delay` (dm-delay:
# a fixed per-I/O delay, reads and writes separately, unlimited concurrency).
dm_attach() { local loop sectors dev
  sudo modprobe dm_delay 2>/dev/null || log "dm_delay module not loaded — latency injection will be unavailable"
  loop="$(sudo losetup --find --show --direct-io=on "$1")" || return 1
  sectors="$(sudo blockdev --getsz "$loop")" || return 1
  echo "0 $sectors linear $loop 0" | sudo dmsetup create "$DM_NAME" || return 1
  dev="$(readlink -f "/dev/mapper/$DM_NAME")"
  sudo chown "$(id -u):$(id -g)" "$dev"
  save_state DM_LOOP "$loop"; save_state DM_SECTORS "$sectors"; save_state DM_DEV "$(basename "$dev")"
}
set_disk_latency() { local r="$1" w="$2" t
  if (( r == 0 && w == 0 )); then t="0 $DM_SECTORS linear $DM_LOOP 0"
  else t="0 $DM_SECTORS delay $DM_LOOP 0 $r $DM_LOOP 0 $w"; fi
  sudo dmsetup suspend "$DM_NAME" && echo "$t" | sudo dmsetup reload "$DM_NAME" && sudo dmsetup resume "$DM_NAME" || return 1
  sudo dmsetup table "$DM_NAME"
}
dm_detach() {
  [[ -n "${DM_LOOP:-}" ]] || return 0
  sudo dmsetup remove "$DM_NAME" 2>/dev/null || true
  sudo losetup -d "$DM_LOOP" 2>/dev/null || true
}
# Host-side view of the guest disk: /sys/block/<dm>/stat (reads, merged,
# sectors, ms reading, writes, merged, sectors, ms writing, in flight, io ticks,
# time in queue).
host_disk_stat() { cat "/sys/block/${DM_DEV:?}/stat"; }

cmd_up() {
  [[ -n "${ACCEL:-}" ]] || die "run preflight first"
  local ova="${LAB_OVA:?LAB_OVA=path to the .ova}" want="${LAB_OVA_SHA256:?LAB_OVA_SHA256=expected sha256}"
  local got; got="$(sha256sum "$ova" | cut -d' ' -f1)"
  [[ "$got" == "$want" ]] && check 1 ova-sha256 pass "$(basename "$ova") sha256 $got" || { check 1 ova-sha256 fail "got $got want $want"; return 1; }
  save_state OVA_NAME "$(basename "$ova")"; save_state OVA_SHA256 "$got"
  rm -rf "$WORK/ova"; extract_ova "$ova" "$WORK/ova" && check 1 ova-manifest pass "every .mf digest matches" || { check 1 ova-manifest fail ".mf mismatch"; return 1; }
  grep -oE 'CANDIDATE[^<]*|<Version>[^<]*' "$WORK/ova/"*.ovf | head -3 > "$EV/01-ovf-head.txt" || true
  local vmdk drive; vmdk="$(ls "$WORK/ova/"*.vmdk)"
  if [[ "$LAB_DISK" == dm ]]; then
    log "converting $(basename "$vmdk") → disposable raw disk behind device-mapper"
    qemu-img convert -p -O raw "$vmdk" "$WORK/disk.raw" >/dev/null; rm -f "$vmdk"
    qemu-img info "$WORK/disk.raw" > "$EV/01-base-qcow2-info.txt"
    dm_attach "$WORK/disk.raw" || { check 1 disk-chain blocked "device-mapper disk unavailable (see log)"; return 1; }
    drive="file=/dev/mapper/$DM_NAME,if=none,id=d0,format=raw,cache=none,aio=native"
    check 1 disk-chain pass "disk.raw (disposable copy of the OVA's own VMDK) → direct-I/O loop $DM_LOOP → dm $DM_NAME (linear; latency injectable); QEMU cache=none"
  else
    log "converting $(basename "$vmdk") → immutable qcow2 base"
    qemu-img convert -p -O qcow2 "$vmdk" "$WORK/base.qcow2" >/dev/null; rm -f "$vmdk"; chmod 0444 "$WORK/base.qcow2"
    qemu-img create -q -f qcow2 -F qcow2 -b "$WORK/base.qcow2" "$WORK/overlay.qcow2"
    qemu-img info "$WORK/base.qcow2" > "$EV/01-base-qcow2-info.txt"
    drive="file=$WORK/overlay.qcow2,if=none,id=d0,format=qcow2,cache=writeback"
    check 1 disk-chain pass "base.qcow2 (0444, from the OVA's own VMDK) ← overlay.qcow2 (disposable)"
  fi
  # Disposable credentials. No console password is supplied: first boot must
  # mint and print the one-time password (the default bootstrap under test).
  rm -f "$SEC/id_ed25519"* "$SEC/console-pass" "$SEC/console-onetime" "$SEC/console-events"
  ssh-keygen -q -t ed25519 -N '' -C "culvert-lab-$RUN_ID" -f "$SEC/id_ed25519"
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
  : > "$WORK/console.log"; rm -f "$SER_SOCK"
  # ttyS0 is a socket (the authenticated console session attaches to it) whose
  # every byte is ALSO logged, client or not: console.log stays the boot record.
  qemu-system-x86_64 -name culvert-lab "${acc[@]}" -smp "$LAB_CPUS" -m "$LAB_MEM_MB" \
    -drive "$drive" \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=d0,bus=scsi0.0 \
    -drive "file=$WORK/ovfenv.iso,if=none,id=cd0,media=cdrom,readonly=on" -device ide-cd,drive=cd0 \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$LAB_SSH_PORT-:22,hostfwd=tcp:127.0.0.1:$LAB_PROXY_PORT-:8080,hostfwd=tcp:127.0.0.1:$LAB_UI_PORT-:9090" \
    -device e1000,netdev=n0 -display none \
    -chardev "socket,id=ser0,path=$SER_SOCK,server=on,wait=off,logfile=$WORK/console.log,logappend=on" -serial chardev:ser0 \
    -monitor "unix:$MON_SOCK,server,nowait" -pidfile "$WORK/qemu.pid" -daemonize
  printf 'qemu-system-x86_64 %s -smp %s -m %s virtio-scsi(%s) ide-cd(ovfenv.iso) e1000 user-net hostfwd 127.0.0.1:{%s,%s,%s} SeaBIOS serial=socket+logfile\n' \
    "${acc[*]}" "$LAB_CPUS" "$LAB_MEM_MB" "$drive" "$LAB_SSH_PORT" "$LAB_PROXY_PORT" "$LAB_UI_PORT" > "$EV/02-qemu-command.txt"
  save_state BOOT_STARTED "$(date +%s)"
  check 2 boot-started pass "qemu pid $(cat "$WORK/qemu.pid") accel=$ACCEL"
  # Bounded: kernel, operator SSH, then first boot to completion as the
  # product reports it (status-json: the `complete` step recorded).
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
  until gop status-json > "$WORK/status-json.tmp" 2>/dev/null; do
    qemu_alive || { check 2 operator-ssh-up fail "qemu exited during boot (see console.log)"; return 1; }
    (( $(date +%s) < deadline )) || { screendump 02-screen-no-ssh; check 2 operator-ssh-up fail "no culvert-operator SSH within ${LAB_FIRSTBOOT_TIMEOUT}s"; return 1; }
    sleep 10; done
  check 2 operator-ssh-up pass "culvert-operator SSH (OVF-delivered key, status-json) after $(( $(date +%s) - t0 ))s"
  until gop status-json > "$WORK/status-json.tmp" 2>/dev/null && [[ " $(recorded_steps "$WORK/status-json.tmp") " == *" complete "* ]]; do
    # systemd deletes a unit's start job to break an ordering cycle: first boot
    # will then never run, so report it now rather than after the full bound.
    if grep -qa 'Ordering cycle found, skipping.*culvert-firstboot' "$WORK/console.log" 2>/dev/null; then
      check 2 firstboot-complete fail "systemd skipped culvert-firstboot.service (ordering cycle; see console.log)"; return 1; fi
    (( $(date +%s) < deadline )) || { check 2 firstboot-complete fail "first boot not complete within ${LAB_FIRSTBOOT_TIMEOUT}s ($(status_field "$WORK/status-json.tmp" phase))"; return 1; }
    sleep 15; done
  cp "$WORK/status-json.tmp" "$EV/02-status-json-complete.json"
  check 2 firstboot-complete pass "status-json: complete recorded, phase $(status_field "$EV/02-status-json-complete.json" phase), $(( $(date +%s) - t0 ))s from power-on"
}

# ── qualify: vsphere-qualification.md steps 3–8 ─────────────────────────────
STOP=0
gate() { [[ $STOP == 0 ]] || { check "$1" "$2" not-run "an earlier step failed"; return 1; }; }
# boot_timing PREFIX STEP — where boot time went, from the guest's own record
# (systemd-analyze + the unit journals that gate the stack). Evidence only: the
# lab has no timing threshold; this is the capture for the unexplained ESXi
# boot delay, taken the same way on every target.
boot_timing() {
  gpriv --timeout 180 > "$EV/$1-boot-timing.txt" 2>&1 <<'EOS' || true
systemd-analyze 2>&1
echo '--- critical-chain'
systemd-analyze critical-chain multi-user.target docker.service culvert-firstboot.service 2>&1 | head -80
echo '--- blame (top 30)'
systemd-analyze blame 2>&1 | head -30
echo '--- network-online / cloud-init / containerd / docker / first boot (monotonic, this boot)'
journalctl -b --no-pager -o short-monotonic -u systemd-networkd -u systemd-networkd-wait-online -u cloud-init-local -u cloud-init \
  -u cloud-config -u cloud-final -u containerd -u docker -u culvert-firstboot -u culvert-stack-resume 2>&1 | head -400
echo '--- kernel (first lines, monotonic)'
journalctl -b -k --no-pager -o short-monotonic 2>&1 | head -5
EOS
  local s; s="$(grep -m1 '^Startup finished' "$EV/$1-boot-timing.txt" || true)"
  check "$2" boot-timing info "${s:-no systemd-analyze summary (see $1-boot-timing.txt)}; slowest: $(sed -n '/^--- blame/{n;p;n;p;n;p}' "$EV/$1-boot-timing.txt" | xargs | head -c 200)"
}

cmd_qualify() {
  if [[ "$LAB_EXTERNAL" == 1 ]]; then
    [[ -r "$LAB_SSH_KEY" ]] || die "LAB_EXTERNAL=1 needs LAB_SSH_KEY (the key the VM was given)"
    [[ -n "${LAB_PRIV_CMD:-}" ]] || die "LAB_EXTERNAL=1 needs LAB_PRIV_CMD (the authenticated-console transport)"
    gop status-json >/dev/null || die "cannot reach culvert-operator@$LAB_HOST:$LAB_SSH_PORT"
    [[ -n "${ACCEL:-}" ]] || { save_state RUN_ID "$RUN_ID"; save_state ACCEL "external ($LAB_HOST)"; }
    check 2 target info "external appliance at $LAB_HOST (deployed and owned by another tool; up/down not used)"
  else [[ -n "${BOOT_STARTED:-}" ]] || die "run up first"; fi
  ensure_admin_pass
  : > "$JAR"
  local c rc

  # Step 3 — first-boot evidence through the operator interface.
  local orc=0
  gop status > "$EV/03-operator-status.txt" 2>&1 || orc=$?
  gop status-json > "$EV/03-status-json.json" 2>&1 || orc=$?
  gop diagnostics > "$EV/03-operator-diagnostics.txt" 2>&1 || orc=$?
  gop help > "$EV/03-operator-help.txt" 2>&1 || orc=$?
  if [[ $orc == 0 ]] && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$EV/03-status-json.json" 2>/dev/null; then
    check 3 operator-observe pass "culvert-operator: help, status, status-json (valid JSON, version $(status_field "$EV/03-status-json.json" version)), diagnostics"
  else check 3 operator-observe fail "exit $orc: $(head -c 200 "$EV/03-status-json.json")"; fi
  local ss; ss="$(status_field "$EV/03-status-json.json" setup_status)"
  [[ "$ss" == pending ]] && check 3 status-setup-pending pass "status-json setup_status=pending, phase=$(status_field "$EV/03-status-json.json" phase)" || check 3 status-setup-pending fail "setup_status=${ss:-?}"
  local want_steps="access agent complete console images install ovf" got_steps
  got_steps="$(recorded_steps "$EV/03-status-json.json")"
  [[ "$got_steps" == "$want_steps" ]] && check 3 firstboot-steps pass "$got_steps" || check 3 firstboot-steps fail "got '$got_steps' want '$want_steps'"

  # Step 3a — default bootstrap: no console password was supplied, so first
  # boot must have printed a one-time password, and the first login must be
  # forced to replace it. The FIRST privileged call below performs that login.
  if [[ "$LAB_EXTERNAL" != 1 ]]; then
    grep -qa "One-time console login:  user 'culvert'" "$WORK/console.log" \
      && check 3a console-onetime-printed pass "first boot printed a one-time console password on the VM console (ttyS0)" \
      || check 3a console-onetime-printed fail "no one-time console password on the console"
  fi
  rc=0; printf 'id -un; chage -l culvert | sed -n "1p;/must be changed/p"\n' | gpriv --timeout 300 > "$EV/03a-first-privileged.txt" 2>&1 || rc=$?
  if [[ $rc == 0 ]] && grep -qx root "$EV/03a-first-privileged.txt"; then
    if [[ "$LAB_EXTERNAL" == 1 ]]; then check 3a console-login pass "authenticated console login + sudo via LAB_PRIV_CMD"
    elif grep -q '^forced-change ' "$SEC/console-events" 2>/dev/null; then
      check 3a console-login pass "PAM login as culvert with the one-time password → forced change → sudo with the new password → root"
    else check 3a console-login fail "logged in without the forced change at first login"; fi
    ! grep -q 'must be changed' "$EV/03a-first-privileged.txt" && check 3a password-changed pass "chage: no change pending after the forced change" || check 3a password-changed fail "$(tr '\n' ' ' < "$EV/03a-first-privileged.txt")"
  else check 3a console-login fail "console session exit $rc (90-99 = login/transport failure; see the console-session trace in collect)"; STOP=1; fi

  # Step 3b — privileged evidence through that console session.
  if gate 3b privileged-evidence; then
    gpriv > "$EV/03-kernel-before.txt" 2>&1 <<<'uname -r; uname -v' || true
    gpriv > "$EV/03-status-firstboot.txt" 2>&1 <<<'culvert-status' || true
    gpriv > "$EV/03-build-info.json" 2>&1 <<<'cat /var/lib/culvert-appliance/build-info.json' || true
    gpriv > "$EV/03-state-files.txt" 2>&1 <<<'ls /var/lib/culvert-appliance/state/' || true
    gpriv > "$EV/03-stack.txt" 2>&1 <<<'docker compose -f /srv/culvert/docker-compose.yml ps --format "{{.Name}} {{.Image}} {{.Status}}"' || true
    gpriv > "$EV/03-images-kernels-holds.txt" 2>&1 <<<'docker inspect -f "{{.Image}}" culvert; dpkg -l "linux-image-*" | awk "/^ii/{print \$2, \$3}"; apt-mark showhold' || true
    grep -q 'setup pending' "$EV/03-status-firstboot.txt" && check 3 culvert-status-setup-pending pass "$(grep -m1 -i 'State:' "$EV/03-status-firstboot.txt")" || check 3 culvert-status-setup-pending fail "$(grep -m1 -i 'State:' "$EV/03-status-firstboot.txt" || echo 'no State line')"
    local img; img="$(head -1 "$EV/03-images-kernels-holds.txt")"; save_state IMAGE_ID "$img"
    if [[ -n "$LAB_EXPECT_IMAGE_ID" ]]; then [[ "$img" == "$LAB_EXPECT_IMAGE_ID" ]] && check 3 image-identity pass "culvert runs $img" || check 3 image-identity fail "culvert runs $img, want $LAB_EXPECT_IMAGE_ID"
    else check 3 image-identity info "culvert runs $img"; fi
    gpriv <<<'culvert-status' | awk -F': *' '/Setup token:/{print $2}' | awk '{print $1}' | tr -d '\n' > "$SEC/setup-token" || true
    local ctok=""
    [[ "$LAB_EXTERNAL" != 1 ]] && ctok="$(grep -a -A1 'First-admin SETUP TOKEN' "$WORK/console.log" | tail -1 | tr -d '\r' | xargs || true)"
    if [[ $(wc -c < "$SEC/setup-token") -eq 32 ]] && { [[ "$LAB_EXTERNAL" == 1 ]] || [[ "$ctok" == "$(cat "$SEC/setup-token")" ]]; }; then
      check 3 setup-token pass "32 characters, from culvert-status via the authenticated console$([[ "$LAB_EXTERNAL" != 1 ]] && echo '; identical to the token first boot printed on the VM console')"
    else check 3 setup-token fail "token length $(wc -c < "$SEC/setup-token"); console token matches: $([[ -n "$ctok" && "$ctok" == "$(cat "$SEC/setup-token")" ]] && echo yes || echo no)"; STOP=1; fi
  fi

  # Step 3c — the SSH access boundary: everything but the four observations is
  # refused, and the local administrator is not reachable over SSH.
  local refused=() admitted=() x
  for x in bash 'status; id' 'sudo -n id' '/bin/sh -c id' 'status-json --help' 'reboot'; do
    rc=0; gop "$x" > "$WORK/op-cmd.txt" 2>&1 < /dev/null || rc=$?
    if [[ $rc != 0 ]] && ! grep -q 'uid=' "$WORK/op-cmd.txt"; then refused+=("'$x'→$rc"); else admitted+=("'$x'→$rc:$(head -c 80 "$WORK/op-cmd.txt")"); fi
    printf '== %s (exit %s)\n%s\n' "$x" "$rc" "$(head -c 400 "$WORK/op-cmd.txt")" >> "$EV/03c-operator-refusals.txt"
  done
  [[ ${#admitted[@]} == 0 ]] && check 3c operator-commands-refused pass "${refused[*]}" || check 3c operator-commands-refused fail "admitted: ${admitted[*]}"
  local fwd=() fport=$(( 20000 + RANDOM % 20000 ))
  # A local forward is only refused when a connection uses it (direct-tcpip):
  # hold one open and try to reach the guest's admin port through it.
  : > "$WORK/fwd.txt"
  ssh "${SSH_OPTS[@]}" -N -L "127.0.0.1:$fport:127.0.0.1:9090" "culvert-operator@$LAB_HOST" >> "$WORK/fwd.txt" 2>&1 & local fpid=$!
  sleep 4; c="$(curl -ksS -m 8 -o /dev/null -w '%{http_code}' "https://127.0.0.1:$fport/" 2>>"$WORK/fwd.txt" || true)"
  kill "$fpid" 2>/dev/null || true; wait "$fpid" 2>/dev/null || true
  [[ "$c" =~ ^[1-5][0-9][0-9]$ ]] && fwd+=("local-forward:0(http $c)") || fwd+=("local-forward:refused")
  rc=0; timeout 30 ssh "${SSH_OPTS[@]}" -o ExitOnForwardFailure=yes -R "127.0.0.1:$fport:127.0.0.1:22" "culvert-operator@$LAB_HOST" status >> "$WORK/fwd.txt" 2>&1 || rc=$?; fwd+=("remote-forward:$rc")
  rc=0; timeout 30 ssh "${SSH_OPTS[@]}" -W 127.0.0.1:9090 "culvert-operator@$LAB_HOST" < /dev/null >> "$WORK/fwd.txt" 2>&1 || rc=$?; fwd+=("stdio-forward:$rc")
  printf '%s\n' "${fwd[@]}" > "$EV/03c-forwarding.txt"; cat "$WORK/fwd.txt" >> "$EV/03c-forwarding.txt"
  [[ "${fwd[*]}" != *':0'* ]] && check 3c forwarding-refused pass "${fwd[*]}" || check 3c forwarding-refused fail "${fwd[*]}"
  local xfer=() probe="$WORK/scp-probe.txt"; echo lab > "$probe"
  local SCP_OPTS=(-i "$LAB_SSH_KEY" -P "$LAB_SSH_PORT" -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$SEC/known_hosts" -o BatchMode=yes -o ConnectTimeout=10 -o IdentitiesOnly=yes)
  rc=0; timeout 30 scp -O "${SCP_OPTS[@]}" "$probe" "culvert-operator@$LAB_HOST:/tmp/lab-probe" > "$WORK/xfer.txt" 2>&1 || rc=$?; xfer+=("scp-legacy:$rc")
  rc=0; timeout 30 scp "${SCP_OPTS[@]}" "$probe" "culvert-operator@$LAB_HOST:/tmp/lab-probe" >> "$WORK/xfer.txt" 2>&1 || rc=$?; xfer+=("scp-sftp:$rc")
  rc=0; timeout 30 sftp "${SCP_OPTS[@]}" -b /dev/null "culvert-operator@$LAB_HOST" >> "$WORK/xfer.txt" 2>&1 || rc=$?; xfer+=("sftp:$rc")
  printf '%s\n' "${xfer[@]}" > "$EV/03c-file-transfer.txt"; cat "$WORK/xfer.txt" >> "$EV/03c-file-transfer.txt"
  [[ "${xfer[*]}" != *':0'* ]] && check 3c file-transfer-refused pass "${xfer[*]}" || check 3c file-transfer-refused fail "${xfer[*]}"
  rc=0; ssh "${SSH_OPTS[@]}" "culvert@$LAB_HOST" id > "$EV/03c-culvert-ssh.txt" 2>&1 || rc=$?
  [[ $rc != 0 ]] && ! grep -q 'uid=' "$EV/03c-culvert-ssh.txt" && check 3c local-admin-ssh-refused pass "culvert@ with the imported key: exit $rc" || check 3c local-admin-ssh-refused fail "culvert@ admitted (exit $rc)"
  if gate 3c privileged-boundary; then
    gpriv > "$EV/03c-sshd-effective.txt" 2>&1 <<'EOS' || true
sshd -T -C user=culvert-operator,host=lab,addr=127.0.0.1 2>/dev/null | grep -Ei '^(allowusers|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|authenticationmethods|disableforwarding|allowtcpforwarding|allowstreamlocalforwarding|permittunnel|x11forwarding|permituserrc|permituserenvironment|forcecommand|authorizedkeysfile|permitrootlogin) '
echo '--- operator account'
id culvert-operator; getent passwd culvert-operator | cut -d: -f6,7
sudo -l -U culvert-operator 2>&1 | tail -2
ls -l /etc/ssh/culvert-authorized-keys/
EOS
    local bad=()
    grep -qix 'allowusers culvert-operator' "$EV/03c-sshd-effective.txt" || bad+=(allowusers)
    grep -qix 'passwordauthentication no' "$EV/03c-sshd-effective.txt" || bad+=(passwordauthentication)
    grep -qix 'disableforwarding yes' "$EV/03c-sshd-effective.txt" || bad+=(disableforwarding)
    grep -qi '^forcecommand .*culvert-access' "$EV/03c-sshd-effective.txt" || bad+=(forcecommand)
    grep -q 'is not allowed to run sudo' "$EV/03c-sshd-effective.txt" || bad+=(operator-sudo)
    [[ ${#bad[@]} == 0 ]] && check 3c sshd-effective pass "AllowUsers culvert-operator, PasswordAuthentication no, DisableForwarding yes, ForceCommand culvert-access; operator has no sudo" || check 3c sshd-effective fail "unexpected: ${bad[*]}"
    rc=0; printf 'sudo -k; sudo -n true 2>&1; echo "sudo-n-rc=$?"\n' | gpriv --as-user > "$EV/03c-culvert-sudo-n.txt" 2>&1 || rc=$?
    grep -qx 'sudo-n-rc=1' "$EV/03c-culvert-sudo-n.txt" && check 3c local-admin-sudo-needs-password pass "culvert: sudo -n refused (a password is required)" || check 3c local-admin-sudo-needs-password fail "$(tr '\n' ' ' < "$EV/03c-culvert-sudo-n.txt")"
    boot_timing 03d 3d
  fi
  # Step 4 — first administrator; the token is REQUIRED.
  local pass c; pass="$(cat "$SEC/admin-pass")"
  # Step 4a — the temporary bootstrap administrator role shares the setup-token
  # gate (b526f955): before setup, a protected API without the token is
  # refused and the appliance stays unconfigured.
  if gate 4a bootstrap-api-needs-token; then
    local u1 u2 still
    u1="$(api POST /api/auth/users "{\"username\":\"lab-bypass\",\"password\":\"$pass\",\"role\":\"admin\"}" | tee "$EV/04a-users-without-token.txt" | code)"
    u2="$(api PUT /api/settings/default-auth-outcome '{"defaultAuthOutcome":"Exempt"}' | tee "$EV/04a-exempt-without-token.txt" | code)"
    gop status-json > "$EV/04a-status-json.json" 2>&1 || true; still="$(status_field "$EV/04a-status-json.json" setup_status)"
    [[ "$u1 $u2 $still" == "403 403 pending" ]] && check 4a bootstrap-api-needs-token pass "POST /api/auth/users 403, PUT default-auth-outcome 403 without the token; status-json still setup_status=pending" \
      || check 4a bootstrap-api-needs-token fail "users=$u1 exempt=$u2 setup_status=${still:-?} (want 403 403 pending)"
  fi
  if gate 4 setup-without-token; then
    c="$(api POST /api/setup/complete "{\"user\":\"$ADMIN_USER\",\"pass\":\"$pass\"}" | tee "$EV/04-setup-without-token.txt" | code)"
    [[ $c == 403 ]] && check 4 setup-without-token pass "403" || { check 4 setup-without-token fail "http $c (want 403)"; STOP=1; }
    c="$(curl -ksS -m 30 -X POST "$UI/api/setup/complete" -H "Origin: $UI" -H 'Content-Type: application/json' -H "X-Culvert-Setup-Token: $(cat "$SEC/setup-token")" \
          -d "{\"user\":\"$ADMIN_USER\",\"pass\":\"$pass\"}" -w '\n%{http_code}\n' | tee "$EV/04-setup-with-token.txt" | code)"
    [[ $c == 200 ]] && check 4 setup-with-token pass "200" || { check 4 setup-with-token fail "http $c"; STOP=1; }
    c="$(api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$pass\"}" | tee "$EV/04-login.txt" | code)"
    [[ $c == 200 ]] && check 4 admin-login pass "200" || { check 4 admin-login fail "http $c"; STOP=1; }
    gpriv > "$EV/04-status-after-setup.txt" 2>&1 <<<'culvert-status' || true
    grep -qi 'setup complete' "$EV/04-status-after-setup.txt" && check 4 status-setup-complete pass "culvert-status: setup complete" || check 4 status-setup-complete fail "$(grep -m1 -i 'State:' "$EV/04-status-after-setup.txt")"
    gop status-json > "$EV/04-status-json-after-setup.json" 2>&1 || true
    [[ "$(status_field "$EV/04-status-json-after-setup.json" setup_status)" == completed ]] && check 4 operator-setup-complete pass "status-json setup_status=completed, administrator_enrolled=$(status_field "$EV/04-status-json-after-setup.json" administrator_enrolled)" \
      || check 4 operator-setup-complete fail "setup_status=$(status_field "$EV/04-status-json-after-setup.json" setup_status)"
  fi

  # Step 4b — a demoted administrator loses the role on its EXISTING session,
  # without a new login (b526f955). Portal-cookie replay (b7b08958) needs an
  # identity provider, which this lab has none of.
  if gate 4b demotion-immediate; then
    local j2="$SEC/cookies-labop" d1 d2 d3 d4
    : > "$j2"
    d1="$(api POST /api/auth/users "{\"username\":\"labop\",\"password\":\"$pass\",\"role\":\"admin\"}" | tee "$EV/04b-create.txt" | code)"
    d2="$(JAR="$j2" api POST /api/auth/login "{\"user\":\"labop\",\"pass\":\"$pass\"}" | code)"
    d3="$(JAR="$j2" api GET /api/auth/users | code)"
    api POST /api/auth/users '{"username":"labop","role":"viewer"}' > "$EV/04b-demote.txt"
    d4="$(JAR="$j2" api GET /api/auth/users | tee "$EV/04b-after-demotion.txt" | code)"
    printf 'create %s\nlogin %s\nadmin-route-before %s\ndemote %s\nadmin-route-after %s (same session)\n' "$d1" "$d2" "$d3" "$(code < "$EV/04b-demote.txt")" "$d4" > "$EV/04b-demotion.txt"
    [[ "$d1 $d2 $d3 $(code < "$EV/04b-demote.txt") $d4" == "200 200 200 200 403" ]] && check 4b demotion-immediate pass "labop admin session: GET /api/auth/users 200 → demoted to viewer → the same session 403" \
      || check 4b demotion-immediate fail "$(tr '\n' ' ' < "$EV/04b-demotion.txt")"
    api DELETE "/api/auth/users?username=labop" > /dev/null || true; rm -f "$j2"
    check 4b portal-cookie-replay blocked "needs an identity provider (none in this lab); covered by TestUISessionRole_RejectsReplayedPortalCookie and the proxy cookie-boundary tests in CI"
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
    gpriv > "$EV/05-status.txt" 2>&1 <<<'culvert-status' || true
    grep -qi 'ready to enforce' "$EV/05-status.txt" && check 5 status-ready-to-enforce pass "culvert-status: ready to enforce" || check 5 status-ready-to-enforce fail "$(grep -m1 -i 'State:' "$EV/05-status.txt")"
    api GET /api/ca-cert | body | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 > "$EV/05-ca-fingerprint.txt" || true
    [[ -s "$EV/05-ca-fingerprint.txt" ]] && check 5 ca-identity pass "root CA sha256 $(cat "$EV/05-ca-fingerprint.txt")" || check 5 ca-identity fail "no CA certificate"
  fi

  # Step 5b — community category data (the boot-time feed sync), for the persistence check.
  if gate 5b category-data; then
    # Completion is read from the PRODUCT (GET /api/urlcat/feed-status: the
    # running process's last successful UT1 sync), never from `docker logs`:
    # the agent install recreates the proxy container during first boot, and
    # the replaced container's log — with any "sync complete" line — goes with
    # it (run 37185033699). The log grep is kept as diagnostics only.
    local deadline=$(( $(date +%s) + LAB_FEED_TIMEOUT )) fs="" fl=""
    until fs="$(api GET /api/urlcat/feed-status | body | python3 -c 'import json,sys; u=json.load(sys.stdin).get("ut1",{}); print("%s %s" % (u.get("lastSync",""), u.get("entries",0)) if u.get("lastSync") and int(u.get("entries",0))>0 else "")' 2>/dev/null)" && [[ -n "$fs" ]]; do
      (( $(date +%s) < deadline )) || break; sleep 20; done
    fl="$(gpriv 2>/dev/null <<<'docker logs culvert 2>&1 | grep -oE "FeedSync: [^\"]*" | tail -3' | tr '\n' ';' || true)"
    api GET /api/urlcat/feed-status > "$EV/05b-feed-status.txt" || true
    echo "${fs:-no completed UT1 sync reported by /api/urlcat/feed-status within ${LAB_FEED_TIMEOUT}s}; log: ${fl:-none}" > "$EV/05b-feed.txt"
    lookups > "$EV/05b-lookups-before.txt"
    # A built-in (admin/saas tier) match proves nothing about the feed: at
    # least one probe host must resolve through the COMMUNITY (UT1) tier.
    if [[ -n "$fs" ]] && grep -q 'tier=community' "$EV/05b-lookups-before.txt"; then
      check 5b category-data pass "UT1 sync complete (lastSync entries: $fs); $(grep -c 'tier=community' "$EV/05b-lookups-before.txt") of $(wc -l < "$EV/05b-lookups-before.txt") probe hosts resolve via the community tier"
    else check 5b category-data fail "no completed UT1 sync in this process ($(body < "$EV/05b-feed-status.txt" | head -c 160)); log: ${fl:-none}; lookups: $(tr '\n' ' ' < "$EV/05b-lookups-before.txt")"; fi
  fi

  # Step 5c — category ENFORCEMENT from the UT1 tier, through the real proxy.
  # A Block_Page rule on the community category of a UT1-resolved probe host,
  # above an Allow rule for that host: 403 proves the category rule matched
  # (default deny is ruled out by the Allow rule; the control removes the
  # block rule and requires the same request NOT to be 403).
  if gate 5c category-enforcement; then
    local ch cc bid aid c1 c2
    read -r ch cc < <(awk '/tier=community/{for(i=2;i<=NF;i++) if($i ~ /^category=/){sub("category=","",$i); print $1, $i; exit}}' "$EV/05b-lookups-before.txt")
    if [[ -z "${ch:-}" || -z "${cc:-}" ]]; then check 5c category-enforcement fail "no probe host resolved via the community tier"
    else
      aid="$(api POST /api/policy "{\"name\":\"lab-ut1-allow-host\",\"priority\":4,\"action\":\"Allow\",\"destFQDN\":\"$ch\",\"sslAction\":\"Bypass\",\"enabled\":true}" | tee "$EV/05c-allow-rule.txt" | body | python3 -c 'import json,sys;print(json.load(sys.stdin).get("id",""))' 2>/dev/null || true)"
      bid="$(api POST /api/policy "{\"name\":\"lab-ut1-block-category\",\"priority\":3,\"action\":\"Block_Page\",\"destCategory\":\"$cc\",\"sslAction\":\"Bypass\",\"enabled\":true}" | tee "$EV/05c-block-rule.txt" | body | python3 -c 'import json,sys;print(json.load(sys.stdin).get("id",""))' 2>/dev/null || true)"
      c1="$(through_proxy "http://$ch/")"
      [[ -n "$bid" ]] && api DELETE "/api/policy?id=$bid" > /dev/null || true
      c2="$(through_proxy "http://$ch/")"
      [[ -n "$aid" ]] && api DELETE "/api/policy?id=$aid" > /dev/null || true
      printf 'host %s category %s (community tier)\nwith category block rule: %s\nblock rule removed (allow rule only): %s\n' "$ch" "$cc" "$c1" "$c2" > "$EV/05c-enforcement.txt"
      if [[ -n "$aid" && -n "$bid" && "$c1" == 403 && "$c2" != 403 ]]; then
        check 5c category-enforcement pass "$ch ($cc via UT1): category rule → 403; without it → $c2"
      else check 5c category-enforcement fail "$ch ($cc): with rule $c1, without $c2 (rule ids allow=${aid:-?} block=${bid:-?})"; fi
    fi
  fi

  # Step 6 — maintenance agent: backup through the product, restore DRY RUN.
  if gate 6 agent-backup; then
    api GET /api/maintenance-agent > "$EV/06-agent-status.txt" || true
    # L11: the first boot must have INSTALLED the bundled agent (not merely
    # left a pending marker), at the image's own version, and the proxy must
    # reach it over its socket.
    gpriv > "$EV/06-agent-installed.txt" 2>&1 <<<'systemctl is-active culvert-maint; culvert-maint --version; grep -c "^CULVERT_MAINT_GID=" /srv/culvert/.env; ls /var/lib/culvert-appliance/state/' || true
    local appv agv; appv="$(curl -fsS -m 10 "$P/health" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("version",""))' 2>/dev/null || true)"
    agv="$(sed -n 2p "$EV/06-agent-installed.txt")"
    if [[ "$(head -1 "$EV/06-agent-installed.txt")" == active && -n "$agv" && "$agv" == "v${appv#v}" ]] && ! grep -qx 'agent.pending' "$EV/06-agent-installed.txt"; then
      check 6 agent-installed pass "culvert-maint active, version $agv = proxy $appv, no agent.pending"
    else check 6 agent-installed fail "$(tr '\n' ' ' < "$EV/06-agent-installed.txt" | head -c 300) (proxy ${appv:-?})"; fi
    local av; av="$(agent_status_verdict "$EV/06-agent-status.txt")"; check 6 agent-reachable "${av%%|*}" "${av#*|}"
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
    [[ -n "$fn" ]] && grep -qF "$fn" "$EV/06-backups.txt" && check 6 backup-listed pass "$fn listed by /api/backups" || check 6 backup-listed fail "backup ${fn:-?} not listed"
    if [[ -n "$fn" ]]; then
      groot "cd /srv/culvert && docker compose --profile cli run --rm -T cli --restore /backup/$fn --mode full" 900 > "$EV/06-restore-dryrun.txt" 2>&1 || true
      # The CLI prints "Validation: PASS" (or FAIL) and, for a dry run, "No files
      # were written". The old oracle looked for "validation passed", which this
      # CLI never prints, so a passing dry run read as FAIL (run 37185033699).
      if grep -qx 'Validation: PASS' "$EV/06-restore-dryrun.txt" && grep -q 'This was a dry-run. No files were written.' "$EV/06-restore-dryrun.txt" && ! grep -q 'Validation: FAIL' "$EV/06-restore-dryrun.txt"; then
        check 6 restore-dry-run pass "Validation: PASS; dry run, no files written ($(grep -m1 'Culvert version:' "$EV/06-restore-dryrun.txt" | xargs))"
      else check 6 restore-dry-run fail "$(grep -E 'Validation:|FAIL|error' "$EV/06-restore-dryrun.txt" | head -3 | tr '\n' ' ')$(tail -2 "$EV/06-restore-dryrun.txt" | tr '\n' ' ')"; fi
    else check 6 restore-dry-run not-run "no backup file"; fi
    save_state BACKUP_FILE "$fn"
  fi


  # Step 6b — ACTUAL restore of that backup (the documented offline commit),
  # with a change made after the backup as the oracle: it must be gone after
  # the restore, and everything the backup held must still be there.
  if gate 6b restore-commit && [[ -n "${BACKUP_FILE:-}" ]]; then
    local pb rules
    pb="$(api POST /api/policy '{"name":"lab-post-backup","priority":20,"action":"Allow","destFQDN":"example.net","sslAction":"Bypass","enabled":true}' | tee "$EV/06b-post-backup-rule.txt" | code)"
    rules="$(api GET /api/policy | body | python3 -c 'import json,sys;print(" ".join(r["name"] for r in json.load(sys.stdin)["rules"]))' 2>/dev/null || true)"
    [[ "$pb" == 200 && " $rules " == *" lab-post-backup "* ]] || check 6b post-backup-change fail "could not add the post-backup rule (http $pb; rules: $rules)"
    # The proxy holds the data-dir lock for its lifetime: a commit against the
    # RUNNING stack must be refused and change nothing.
    rc=0; groot "cd /srv/culvert && docker compose --profile cli run --rm -T cli --restore /backup/$BACKUP_FILE --mode full --confirm; echo \"commit-rc=\$?\"" 900 > "$EV/06b-restore-live.txt" 2>&1 || rc=$?
    rules="$(api GET /api/policy | body | python3 -c 'import json,sys;print(" ".join(r["name"] for r in json.load(sys.stdin)["rules"]))' 2>/dev/null || true)"
    if grep -qE '^commit-rc=[1-9]' "$EV/06b-restore-live.txt" && [[ " $rules " == *" lab-post-backup "* ]]; then
      check 6b restore-refused-while-running pass "commit against the running stack refused ($(grep -m1 -iE 'lock|running|refus' "$EV/06b-restore-live.txt" | head -c 160)); the post-backup rule is untouched"
    else check 6b restore-refused-while-running fail "$(grep -E '^commit-rc=' "$EV/06b-restore-live.txt") rules after: $rules"; fi
    # Offline: down → commit → up (docs/operator/docker-compose-backup-restore.md §6).
    rc=0; gpriv --timeout 1500 > "$EV/06b-restore-offline.txt" 2>&1 <<EOS || rc=$?
cd /srv/culvert || exit 90
docker compose down 2>&1; echo "down-rc=\$?"
docker compose --profile cli run --rm -T cli --restore /backup/$BACKUP_FILE --mode full --confirm 2>&1; r=\$?; echo "commit-rc=\$r"
docker compose up -d 2>&1; echo "up-rc=\$?"
exit \$r
EOS
    local deadline=$(( $(date +%s) + 600 ))
    until curl -fsS -m 3 "$P/health" >/dev/null 2>&1; do (( $(date +%s) < deadline )) || break; sleep 5; done
    : > "$JAR"; c="$(api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$pass\"}" | code)"
    rules="$(api GET /api/policy | body | python3 -c 'import json,sys;print(" ".join(r["name"] for r in json.load(sys.stdin)["rules"]))' 2>/dev/null || true)"
    local ra; ra="$(through_proxy http://example.com/) $(through_proxy http://example.net/)"
    printf 'exit %s\nlogin %s\nrules %s\ntraffic example.com/example.net %s\n' "$rc" "$c" "$rules" "$ra" >> "$EV/06b-restore-offline.txt"
    if [[ $rc == 0 && $c == 200 && " $rules " == *" lab-allow-example "* && " $rules " != *" lab-post-backup "* && "$ra" == "200 403" ]]; then
      check 6b restore-commit pass "down → restore --confirm → up: login 200, backup rules back ($rules), post-backup rule gone, example.com 200 / example.net 403"
    else check 6b restore-commit fail "exit $rc login $c rules '$rules' traffic $ra ($(grep -E '^(down|commit|up)-rc=' "$EV/06b-restore-offline.txt" | tr '\n' ' '))"; STOP=1; fi
  elif [[ $STOP == 0 ]]; then check 6b restore-commit not-run "no backup file"; fi

  # Step 6c — signed update and rollback through the maintenance agent, with
  # TEST-ONLY trust (LAB_UPDATE_DIR, prepared outside the OVA by the lab).
  if gate 6c signed-update; then
    if [[ -z "$LAB_UPDATE_DIR" || ! -s "$LAB_UPDATE_DIR/refs.env" ]]; then
      check 6c signed-update blocked "no LAB_UPDATE_DIR (registry + fixture evidence are prepared by the lab workflow)"
    else signed_update_rollback; fi
  fi
  # Step 7 — OS update + reboot, kernel BEFORE → AFTER.
  if gate 7 os-update; then
    gpriv > "$EV/07-check-before.txt" 2>&1 <<<'culvert-os-update check' || true
    local rc=0; groot 'culvert-os-update os' 2700 > "$EV/07-os-update.txt" 2>&1 || rc=$?
    [[ $rc == 0 ]] && check 7 os-update pass "culvert-os-update os exit 0 ($(grep -cE '^(Setting up|Unpacking) ' "$EV/07-os-update.txt" || true) package actions)" || check 7 os-update fail "exit $rc: $(tail -3 "$EV/07-os-update.txt" | tr '\n' ' ')"
    gpriv > "$EV/07-check-after-update.txt" 2>&1 <<<'culvert-os-update check; ls -l /var/run/reboot-required 2>/dev/null; dpkg -l "linux-image-*" | awk "/^ii/{print \$2, \$3}"; apt-mark showhold; docker version --format "{{.Server.Version}}"' || true
    # The reboot ends the console session; the next privileged call logs in again.
    gpriv --nowait > "$EV/07-reboot.txt" 2>&1 <<<'culvert-os-update reboot' || true
    local deadline=$(( $(date +%s) + LAB_FIRSTBOOT_TIMEOUT )) t0; t0=$(date +%s); sleep 20
    until curl -fsS -m 3 "$P/health" >/dev/null 2>&1 && gop status-json >/dev/null 2>&1; do
      qemu_alive || { check 7 reboot fail "qemu exited during the reboot"; STOP=1; break; }
      (( $(date +%s) < deadline )) || { check 7 reboot fail "not back within ${LAB_FIRSTBOOT_TIMEOUT}s"; STOP=1; break; }
      sleep 10; done
    if [[ $STOP == 0 ]]; then
      check 7 reboot pass "proxy /health and operator SSH back $(( $(date +%s) - t0 ))s after the reboot command"
      gpriv > "$EV/07-kernel-after.txt" 2>&1 <<<'uname -r; uname -v' || true
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
    gpriv > "$EV/08-status-after-reboot.txt" 2>&1 <<<'culvert-status; ls /var/lib/culvert-appliance/state/' || true
    # F-OSU-REBOOT-1: the stack stopped by `culvert-os-update reboot` is started
    # by culvert-stack-resume.service, which clears its marker only on success.
    gpriv > "$EV/08-stack-resume.txt" 2>&1 <<'EOS' || true
systemctl show culvert-stack-resume.service -p LoadState -p ActiveState -p Result -p ExecMainStatus
journalctl -b -u culvert-stack-resume --no-pager
test -e /var/lib/culvert-appliance/state/stack-resume-on-boot && echo MARKER-PRESENT || echo MARKER-CLEARED
echo "--- /var/log/culvert-os-update.log, resume-stack lines since this boot"
b=$(date -u -d "$(uptime -s)" +%FT%TZ); awk -v b="$b" '$1 >= b && /\[resume-stack\]/' /var/log/culvert-os-update.log
EOS
    # The script's own log file is the durable record: its last line can miss
    # the journal when systemd reaps the unit's cgroup before tee flushes
    # (run 37193814711), so the success line may come from either; only
    # lines stamped after this boot count.
    grep -qx 'Result=success' "$EV/08-stack-resume.txt" && grep -qx 'MARKER-CLEARED' "$EV/08-stack-resume.txt" && grep -q 'stack started after the maintenance reboot' "$EV/08-stack-resume.txt" \
      && grep -q 'holding .* and the maintenance agent lock' "$EV/08-stack-resume.txt" \
      && check 8 stack-resumed pass "culvert-stack-resume.service took the os-update + agent locks, started the stack and cleared its marker" \
      || check 8 stack-resumed fail "$(tr '\n' ' ' < "$EV/08-stack-resume.txt" | head -c 300)"
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
    local av8; av8="$(agent_status_verdict "$EV/08-agent-status.txt")"; check 8 agent-reachable "${av8%%|*}" "${av8#*|} (after the maintenance reboot)"
    gpriv > "$EV/08-firstboot-journal.txt" 2>&1 <<<'journalctl -b -u culvert-firstboot --no-pager | tail -20' || true
    grep -q 'step .*: done' "$EV/08-firstboot-journal.txt" && check 8 firstboot-not-rerun fail "a first-boot step ran again" || check 8 firstboot-not-rerun pass "no first-boot step ran on the second boot"
    cmp -s <(sed -n '/\.done$/p' "$EV/03-state-files.txt") <(sed -n '/\.done$/p' "$EV/08-status-after-reboot.txt") && check 8 state-files pass "first-boot state files unchanged" || check 8 state-files info "state listing changed — see 08-status-after-reboot.txt"
    if [[ ! -s "$EV/06b-restore-offline.txt" ]]; then check 8 restore-persisted not-run "no restore was committed"
    elif grep -qw lab-post-backup "$EV/08-rules.txt"; then check 8 restore-persisted fail "the rule added after the backup is back after the reboot"
    else check 8 restore-persisted pass "the restored policy (no lab-post-backup) survived the reboot"; fi
    gpriv > "$EV/08-image.txt" 2>&1 <<<'docker inspect -f "{{.Image}}" culvert' || true
    if [[ -n "$LAB_EXPECT_IMAGE_ID" ]]; then grep -qx "$LAB_EXPECT_IMAGE_ID" "$EV/08-image.txt" && check 8 image-identity pass "culvert runs $LAB_EXPECT_IMAGE_ID after the reboot$([[ -n "$LAB_UPDATE_DIR" ]] && echo ' (the signed rollback target)')" || check 8 image-identity fail "runs $(head -1 "$EV/08-image.txt"), want $LAB_EXPECT_IMAGE_ID"; fi
    gop status-json > "$EV/08-status-json.json" 2>&1 || true
    [[ "$(status_field "$EV/08-status-json.json" setup_status)" == completed ]] && check 8 operator-status pass "status-json after the reboot: setup_status=completed, phase=$(status_field "$EV/08-status-json.json" phase)" || check 8 operator-status fail "setup_status=$(status_field "$EV/08-status-json.json" setup_status)"
    boot_timing 08d 8
  fi
  redact_tree
}

# ── signed update + rollback (step 6c), TEST-ONLY trust ──────────────────────
# LAB_UPDATE_DIR (prepared by the lab workflow, never part of the OVA):
#   refs.env            BASELINE_REF / TARGET_REF (ghcr.io/kidcarmi/culvert@sha256:…),
#                       REGISTRY_ADDR (how the guest reaches the disposable registry)
#   ca.crt              the disposable registry's CA (its certificate names ghcr.io)
#   keyring.json        the fixture's PUBLIC ed25519 key (the private key was never saved)
#   apply-unsigned.json apply-signed.json rollback-signed.json  agent request bodies
# The guest-side changes are TEST-ONLY and listed in 06c-test-only-trust.txt:
# /etc/hosts maps ghcr.io to the lab registry, docker trusts its CA, the agent
# trusts the fixture keyring (release_trust_keys), and the running image is
# given its registry identity by pulling the SAME index digest it already runs.
# Calls go to the agent socket as the configured proxy peer (allow_peers UID +
# the maintenance group), exactly the identity the product's dispatch uses;
# the proxy's Release Management dispatch itself is NOT exercised here.
AGENT_LIB='set -u
CONF=/etc/culvert-maint/config.toml
U=$(sed -n "s/^allow_peers *= *\[\"\([0-9][0-9]*\)\"\].*/\1/p" "$CONF" | head -1)
G=$(sed -n "s/^CULVERT_MAINT_GID=//p" /srv/culvert/.env | head -1)
SOCK=$(sed -n "s/^socket_path *= *\"\(.*\)\".*/\1/p" "$CONF" | head -1); SOCK=${SOCK:-/run/culvert-maint/culvert-maint.sock}
[ -n "$U" ] && [ -n "$G" ] || { echo "no agent peer identity (allow_peers uid=$U gid=$G)"; exit 90; }
agentq() { setpriv --reuid="$U" --regid="$G" --clear-groups curl -sS -m 120 --unix-socket "$SOCK" -H "Content-Type: application/json" "$@"; }
agent() { agentq -w "\nHTTP %{http_code}\n" "$@"; }
opid() { python3 -c "import json,sys; print(json.loads(sys.stdin.read().rsplit(\"\\nHTTP\",1)[0]).get(\"op_id\",\"\"))" 2>/dev/null; }
wait_op() { local st="" i
  for i in $(seq 1 360); do
    st=$(agentq "http://agent/v1/operations/$1" | python3 -c "import json,sys; print(json.load(sys.stdin).get(\"state\",\"\"))" 2>/dev/null)
    case "$st" in succeeded|failed|cancelled) break ;; esac; sleep 5; done
  echo "op-state=$st"; agentq "http://agent/v1/operations/$1" | head -c 20000; echo
  echo "--- op log (tail)"; agentq "http://agent/v1/operations/$1/logs" | tail -c 6000; echo; }
running() { local img; img=$(docker inspect culvert -f "{{.Image}}"); echo "running-image=$img"
  echo "running-label=$(docker inspect culvert -f "{{index .Config.Labels \"org.culvert.lab-target\"}}")"
  echo "repo-digests=$(docker image inspect "$img" -f "{{json .RepoDigests}}")"; }
install -d -m 0755 /tmp/.lab-upd
'
# embed NAME FILE — a guest line that recreates FILE at /tmp/.lab-upd/NAME (0644).
embed() { printf "echo '%s' | base64 -d > /tmp/.lab-upd/%s; chmod 0644 /tmp/.lab-upd/%s\n" "$(base64 -w0 "$2")" "$1" "$1"; }
signed_update_rollback() {
  local U="$LAB_UPDATE_DIR" BASELINE_REF TARGET_REF REGISTRY_ADDR rc
  # shellcheck source=/dev/null
  BASELINE_REF="$(. "$U/refs.env"; echo "$BASELINE_REF")"; TARGET_REF="$(. "$U/refs.env"; echo "$TARGET_REF")"
  REGISTRY_ADDR="$(. "$U/refs.env"; echo "${REGISTRY_ADDR:-10.0.2.2}")"
  local bdig="${BASELINE_REF#*@}" tdig="${TARGET_REF#*@}"
  cp "$U/refs.env" "$EV/06c-refs.env"; [[ -f "$U/fixture.txt" ]] && cp "$U/fixture.txt" "$EV/06c-fixture.txt"
  # 1. test-only trust + registry identity of the running image
  rc=0; { printf '%s' "$AGENT_LIB"; embed ca.crt "$U/ca.crt"; embed keyring.json "$U/keyring.json"; cat <<EOS; } | gpriv --timeout 600 > "$EV/06c-test-only-trust.txt" 2>&1 || rc=$?
set -e
echo "TEST-ONLY lab trust (never part of the OVA):"
install -d -m 0755 /etc/docker/certs.d/ghcr.io && install -m 0644 -o root -g root /tmp/.lab-upd/ca.crt /etc/docker/certs.d/ghcr.io/ca.crt && echo "  /etc/docker/certs.d/ghcr.io/ca.crt (disposable registry CA)"
grep -qE '[[:space:]]ghcr\.io\$' /etc/hosts || echo "$REGISTRY_ADDR ghcr.io  # culvert lab TEST-ONLY" >> /etc/hosts; echo "  /etc/hosts: \$(grep -E '[[:space:]]ghcr\.io' /etc/hosts)"
install -m 0644 -o root -g root /tmp/.lab-upd/keyring.json /etc/culvert-maint/lab-fixture-keyring.json && echo "  /etc/culvert-maint/lab-fixture-keyring.json (fixture PUBLIC key)"
[ -e "\$CONF.lab-orig" ] || cp -p "\$CONF" "\$CONF.lab-orig"
grep -q '^release_trust_keys' "\$CONF" || sed -i '1i release_trust_keys = "/etc/culvert-maint/lab-fixture-keyring.json"' "\$CONF"
echo "  \$CONF:"; diff -u "\$CONF.lab-orig" "\$CONF" || true
systemctl restart culvert-maint
for i in \$(seq 1 30); do [ -S "\$SOCK" ] && break; sleep 1; done
echo "agent=\$(systemctl is-active culvert-maint)"
echo "--- registry identity: pull the SAME index digest the stack already runs"
docker pull "$BASELINE_REF"
running
EOS
  if [[ $rc == 0 ]] && grep -qx "running-image=$bdig" "$EV/06c-test-only-trust.txt" && grep -q "$BASELINE_REF" "$EV/06c-test-only-trust.txt" && grep -qx 'agent=active' "$EV/06c-test-only-trust.txt"; then
    check 6c test-only-trust pass "registry CA, hosts entry, fixture keyring (public) installed; agent restarted; running image $bdig now carries $BASELINE_REF"
  else check 6c test-only-trust fail "exit $rc: $(tail -5 "$EV/06c-test-only-trust.txt" | tr '\n' ' ' | head -c 300)"; return 0; fi
  # 2. an unsigned request is refused before anything changes
  rc=0; { printf '%s' "$AGENT_LIB"; embed unsigned.json "$U/apply-unsigned.json"; printf '%s\n' 'agent -X POST --data-binary @/tmp/.lab-upd/unsigned.json http://agent/v1/upgrades/apply' 'running'; } \
    | gpriv --timeout 300 > "$EV/06c-apply-unsigned.txt" 2>&1 || rc=$?
  grep -qx 'HTTP 403' "$EV/06c-apply-unsigned.txt" && grep -qx "running-image=$bdig" "$EV/06c-apply-unsigned.txt" \
    && check 6c unsigned-apply-refused pass "apply without release evidence: 403 ($(grep -o '"error":"[^"]*"' "$EV/06c-apply-unsigned.txt" | head -1 | head -c 140)); still running the baseline" \
    || check 6c unsigned-apply-refused fail "$(grep -E '^HTTP|running-image' "$EV/06c-apply-unsigned.txt" | tr '\n' ' ')"
  # 3. signed apply baseline → target
  rc=0; { printf '%s' "$AGENT_LIB"; embed apply.json "$U/apply-signed.json"
          printf '%s\n' 'r=$(agent -X POST --data-binary @/tmp/.lab-upd/apply.json http://agent/v1/upgrades/apply); echo "$r" | tail -c 2000' \
                        'op=$(printf "%s" "$r" | opid); echo "op=$op"; [ -n "$op" ] && wait_op "$op"' 'running'; } \
    | gpriv --timeout 2100 > "$EV/06c-apply-signed.txt" 2>&1 || rc=$?
  local a1 a2 a3
  a1="$(grep -m1 '^op-state=' "$EV/06c-apply-signed.txt" || echo op-state=none)"; a2="$(grep -m1 '^running-image=' "$EV/06c-apply-signed.txt" | tail -1)"; a3="$(grep -m1 '^running-label=' "$EV/06c-apply-signed.txt")"
  local t1 t2; t1="$(through_proxy http://example.com/)"; t2="$(through_proxy http://example.org/)"
  if [[ "$a1" == op-state=succeeded && "$a2" == "running-image=$tdig" && "$a3" == running-label=1 && "$t1 $t2" == "200 403" ]]; then
    check 6c signed-apply pass "agent apply with signed target + baseline evidence: succeeded; running $tdig (lab-target label); enforcement after the swap: example.com $t1, example.org $t2"
  else check 6c signed-apply fail "$a1 $a2 $a3 traffic $t1/$t2 (want succeeded, $tdig)"; return 0; fi
  # 4. signed rollback target → baseline (the agent's ledger holds the captured prior)
  rc=0; { printf '%s' "$AGENT_LIB"; embed rollback.json "$U/rollback-signed.json"
          printf '%s\n' 'r=$(agent -X POST --data-binary @/tmp/.lab-upd/rollback.json http://agent/v1/rollbacks); echo "$r" | tail -c 2000' \
                        'op=$(printf "%s" "$r" | opid); echo "op=$op"; [ -n "$op" ] && wait_op "$op"' 'running'; } \
    | gpriv --timeout 2100 > "$EV/06c-rollback-signed.txt" 2>&1 || rc=$?
  a1="$(grep -m1 '^op-state=' "$EV/06c-rollback-signed.txt" || echo op-state=none)"; a2="$(grep -m1 '^running-image=' "$EV/06c-rollback-signed.txt" | tail -1)"; a3="$(grep -m1 '^running-label=' "$EV/06c-rollback-signed.txt")"
  t1="$(through_proxy http://example.com/)"; t2="$(through_proxy http://example.org/)"
  : > "$JAR"; local lc; lc="$(api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$(cat "$SEC/admin-pass")\"}" | code)"
  if [[ "$a1" == op-state=succeeded && "$a2" == "running-image=$bdig" && "$a3" == running-label= && "$t1 $t2 $lc" == "200 403 200" ]]; then
    check 6c signed-rollback pass "agent image rollback to the signed baseline: succeeded; running $bdig again; example.com $t1, example.org $t2; admin login $lc"
  else check 6c signed-rollback fail "$a1 $a2 $a3 traffic $t1/$t2 login $lc (want succeeded, $bdig)"; fi
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
print("%s category=%s tier=%s matchedBy=%s" % (h, d.get("category") or "", d.get("tier") or "", d.get("matchedBy") or ""))' "$h"
  done; }


# ── collect: guest diagnostics + identities → REPORT.md (redacted) ──────────
# ── recovery: maintenance-reboot recovery time, per storage profile ──────────
# Each reboot is the product's own maintenance reboot (`culvert-os-update
# reboot`: stack stop + resume marker under both locks, then the boot-time
# culvert-stack-resume). Definition (agreed with ASTRA, PR #1528):
#   t0  = AUTHENTICATED acceptance: the root script prints LABACCEPT after the
#         console PAM login and sudo succeeded, before the product's guard or
#         stack stop; console-session returns the host clock at detection.
#   end = completion of the THIRD of three consecutive joint samples started
#         5 s apart. A joint sample passes only if, in that sample:
#           /ready 200 with the clamav row ok; example.com 200 AND example.org
#           403 through the proxy; an EICAR body from the host origin answered
#           `403 Blocked by CLAMAV scan` (a LIVE clamd verdict — clamd down is
#           fail-open, 200; the /ready row is cached up to 30 s); operator
#           status-json phase=ready. Any failed sample resets the count.
# Every probe is stamped when it COMPLETES (monotonic clock), never with the
# sample's start time. After each reboot: the FIRST backup listing must answer
# within 5 s (no retry), and the normalized persisted policy, default action,
# CA identity, image identity and agent availability must equal the baseline
# taken before the first reboot. Every expected profile x reboot case must run:
# a BLOCKED case fails the run. Lab-only guest change: systemd
# DefaultIOAccounting=yes, so per-unit read volume is recorded.
LAB_EICAR_PORT="${LAB_EICAR_PORT:-18431}"
EICAR_URL="http://10.0.2.2:$LAB_EICAR_PORT/eicar.txt"
mono() { python3 -c 'import time; print("%.3f" % time.monotonic())'; }
# since T — seconds from monotonic T to now (one decimal).
since() { python3 -c 'import sys,time; print(round(time.monotonic()-float(sys.argv[1]),1))' "$1"; }
rec_origin_start() {
  mkdir -p "$WORK/eicar-origin"
  # Built at run time, so no file in the repository carries the test signature.
  printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$WORK/eicar-origin/eicar.txt"
  python3 -m http.server "$LAB_EICAR_PORT" --bind 127.0.0.1 --directory "$WORK/eicar-origin" > "$WORK/eicar-origin.log" 2>&1 &
  echo $! > "$WORK/eicar-origin.pid"; sleep 1; }
rec_origin_stop() { [[ -f "$WORK/eicar-origin.pid" ]] && kill "$(cat "$WORK/eicar-origin.pid")" 2>/dev/null; rm -f "$WORK/eicar-origin.pid"; }
# eicar_verdict — "av" when the proxy returned the ClamAV block, else code:body-head.
eicar_verdict() { local out c
  out="$(curl -sS -m 20 -x "$P" -w '\n%{http_code}' "$EICAR_URL" 2>/dev/null || printf '\n000')"
  c="$(tail -n1 <<<"$out")"
  if [[ "$c" == 403 ]] && grep -q 'Blocked by CLAMAV scan' <<<"$out"; then echo av; else echo "$c:$(head -c 60 <<<"$out" | tr -d '\n')"; fi; }
ready_clamav_ok() { local code cv
  code="$(curl -sS -m 5 -o "$WORK/rec-ready.json" -w '%{http_code}' "$P/ready" 2>/dev/null || echo 000)"
  cv="$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); c=d.get("checks",d).get("clamav",{})
print(c.get("status") if isinstance(c,dict) else c)' "$WORK/rec-ready.json" 2>/dev/null || true)"
  [[ "$code" == 200 && "$cv" == ok ]]; }
# rec_state_snapshot FILE — normalized persisted state the reboots must preserve.
rec_state_snapshot() { local out="$1" c pol f img ag
  : > "$JAR"; c="$(api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$(cat "$SEC/admin-pass")\"}" | code)"
  pol="$(api GET /api/policy | body | python3 -c 'import json,sys
d=json.load(sys.stdin); keys=("name","priority","action","enabled","destFQDN","destCategory","destCategoryGroup","destCountry","sslAction")
rules=sorted(([r.get(k) for k in keys] for r in d.get("rules",[])), key=lambda r: (r[1] or 0, r[0] or ""))
print(json.dumps({"default_action":d.get("defaultAction", d.get("default_action")),"rules":rules},sort_keys=True))' 2>/dev/null || echo unreadable)"
  f="$(api GET /api/ca-cert | body | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || true)"
  img="$(gpriv 2>/dev/null <<<'docker inspect -f "{{.Image}}" culvert' | tr -d '\r' | grep -m1 '^sha256:' || true)"
  ag="$(api GET /api/maintenance-agent | body | python3 -c 'import json,sys;print(json.load(sys.stdin).get("available"))' 2>/dev/null || echo unreadable)"
  python3 -c 'import json,sys; print(json.dumps({"login":sys.argv[1],"policy":sys.argv[2],"ca":sys.argv[3],"image":sys.argv[4],"agent_available":sys.argv[5]},sort_keys=True))' \
    "$c" "$pol" "$f" "$img" "$ag" > "$out"; }
recovery_once() { local name="$1" i="$2" budget="$3"; local tag="R-$name-$i"
  local k0 acc t0 st0 st1 ok=0 samples=0 s_start s pr pt pa pp
  local tk="" ts_ready="" ts_traffic="" ts_av="" ts_phase="" first_joint="" end=""
  k0="$(grep -ac 'Linux version' "$WORK/console.log" || true)"
  st0="$(host_disk_stat)"
  printf 'echo "LABACCEPT $(date +%%s.%%N)"\nexec culvert-os-update reboot\n' | gpriv --nowait --timeout 180 > "$EV/$tag-reboot.txt" 2>&1 || true
  # t0 is taken right after console-session returns on the marker; the gap
  # between detection and this line is recorded rather than hidden.
  t0="$(mono)"
  acc="$(grep -m1 -oE 'host_epoch=[0-9.]+' "$EV/$tag-reboot.txt" | cut -d= -f2 || true)"
  if [[ -z "$acc" ]]; then check R "recovery-$name-$i" fail "the maintenance reboot was not accepted (no authenticated acceptance marker): $(tail -c 300 "$EV/$tag-reboot.txt")"; return 1; fi
  local lag; lag="$(python3 -c 'import sys,time; print(round(time.time()-float(sys.argv[1]),3))' "$acc")"
  t0="$(python3 -c 'import sys; print("%.3f" % (float(sys.argv[1]) - float(sys.argv[2])))' "$t0" "$lag")"
  printf 'sample_start_s\tsample_end_s\tready_clamav\ttraffic\teicar\tphase\n' > "$EV/$tag-samples.tsv"
  while :; do
    qemu_alive || { check R "recovery-$name-$i" fail "qemu exited during the reboot"; return 1; }
    s_start="$(mono)"
    python3 -c 'import sys; sys.exit(0 if float(sys.argv[1])-float(sys.argv[2]) < float(sys.argv[3]) else 1)' "$s_start" "$t0" "$LAB_RECOVERY_TIMEOUT" || break
    if [[ -z "$tk" ]]; then
      (( $(grep -ac 'Linux version' "$WORK/console.log" || true) > k0 )) && tk="$(mono)"
      sleep 2; continue
    fi
    samples=$((samples+1))
    if ready_clamav_ok; then pr=ok; else pr=no; fi; s="$(mono)"; [[ $pr == ok && -z "$ts_ready" ]] && ts_ready="$s"
    if [[ "$(through_proxy http://example.com/) $(through_proxy http://example.org/)" == "200 403" ]]; then pt=ok; else pt=no; fi
    s="$(mono)"; [[ $pt == ok && -z "$ts_traffic" ]] && ts_traffic="$s"
    pa="$(eicar_verdict)"; s="$(mono)"; [[ $pa == av && -z "$ts_av" ]] && ts_av="$s"
    if gop status-json > "$WORK/rec-status.json" 2>/dev/null && [[ "$(status_field "$WORK/rec-status.json" phase)" == ready ]]; then pp=ok; else pp=no; fi
    s="$(mono)"; [[ $pp == ok && -z "$ts_phase" ]] && ts_phase="$s"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(python3 -c 'import sys;print(round(float(sys.argv[1])-float(sys.argv[2]),1))' "$s_start" "$t0")" \
      "$(python3 -c 'import sys;print(round(float(sys.argv[1])-float(sys.argv[2]),1))' "$s" "$t0")" "$pr" "$pt" "$pa" "$pp" >> "$EV/$tag-samples.tsv"
    if [[ $pr == ok && $pt == ok && $pa == av && $pp == ok ]]; then
      ok=$((ok+1)); (( ok == 1 )) && first_joint="$s"
      if (( ok == 3 )); then end="$s"; break; fi
    else ok=0; first_joint=""; fi
    # The next sample starts 5 s after this one STARTED, never sooner.
    python3 -c 'import sys,time; d=float(sys.argv[1])+5-time.monotonic(); time.sleep(d if d>0 else 0)' "$s_start"
  done
  st1="$(host_disk_stat)"
  local rec; rec="$(python3 "$HERE/recovery-timeline.py" "$t0" "$tk" "$ts_ready" "$ts_traffic" "$ts_av" "$ts_phase" "$first_joint" "$end" \
    "$st0" "$st1" "$budget" "$acc" "$lag" "$samples" "$EV/$tag-timeline.json")"
  local tl; tl="$(python3 "$HERE/recovery-timeline.py" --describe "$EV/$tag-timeline.json")"
  if [[ "$rec" == none ]]; then check R "recovery-$name-$i" fail "not recovered (3 consecutive joint samples) within ${LAB_RECOVERY_TIMEOUT}s: $tl"; recovery_guest "$tag"; return 1; fi
  if python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) <= float(sys.argv[2]) else 1)' "$rec" "$budget"; then
    check R "recovery-$name-$i" pass "recovered in ${rec}s (budget ${budget}s): $tl"
  else check R "recovery-$name-$i" fail "recovered in ${rec}s — OVER the ${budget}s budget: $tl"; fi
  recovery_backup_first_list "$name" "$i"
  recovery_guest "$tag"
  recovery_state "$name" "$i"
  printf '%s\t%s\t%s\t%s\n' "$name" "$i" "$rec" "$budget" >> "$EV/R-summary.tsv"
}
# The FIRST backup listing after the reboot must answer within 5 s, with the
# baseline backup in it. Never retried: a slow first answer is the finding.
recovery_backup_first_list() { local name="$1" i="$2" t1 c dt
  : > "$JAR"; api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$(cat "$SEC/admin-pass")\"}" > /dev/null
  t1="$(mono)"
  c="$(curl -ksS -m 5 "$UI/api/backups" -H "Origin: $UI" -b "$JAR" -o "$EV/R-$name-$i-backups.json" -w '%{http_code}' 2>/dev/null || echo 000)"
  dt="$(since "$t1")"
  if [[ "$c" == 200 ]] && { [[ -z "${BACKUP_FILE:-}" ]] || grep -qF "$BACKUP_FILE" "$EV/R-$name-$i-backups.json"; }; then
    check R "backup-list-$name-$i" pass "first listing http 200 in ${dt}s${BACKUP_FILE:+, $BACKUP_FILE present}"
  else check R "backup-list-$name-$i" fail "first listing http $c in ${dt}s (limit 5 s, no retry)${BACKUP_FILE:+; $BACKUP_FILE expected}"; fi
}
recovery_guest() {
  gpriv --timeout 300 > "$EV/$1-guest.txt" 2>&1 <<'EOS' || true
echo "--- clock: epoch uptime"; date -u +%s.%N; cat /proc/uptime
systemd-analyze 2>&1
echo '--- blame (top 40)'; systemd-analyze blame 2>&1 | head -40
echo '--- critical-chain'; systemd-analyze critical-chain containerd.service docker.service culvert-stack-resume.service 2>&1 | head -80
echo '--- unit timestamps (monotonic us since kernel start)'
for u in cloud-init-local cloud-init cloud-config cloud-final systemd-networkd-wait-online snapd snapd.seeded ssh containerd docker culvert-maint culvert-stack-resume; do
  systemctl show "$u.service" -p Id -p ExecMainStartTimestampMonotonic -p ActiveEnterTimestampMonotonic -p ExecMainExitTimestampMonotonic | paste -sd' '; done
echo '--- per-unit I/O since boot (DefaultIOAccounting; services and container scopes)'
for u in $(systemctl list-units --all --plain --no-legend --type=service,scope | awk '{print $1}'); do
  printf '%s ' "$u"; systemctl show "$u" -p IOReadBytes -p IOReadOperations -p IOWriteBytes | paste -sd' '; done
echo '--- guest disk counters since boot'; grep -E ' (sda|vda) ' /proc/diskstats
echo '--- io pressure'; cat /proc/pressure/io
echo '--- containers'; for c in culvert-clamav culvert; do docker inspect -f '{{.Name}} started={{.State.StartedAt}} health={{if .State.Health}}{{.State.Health.Status}}{{end}}' "$c"
  docker inspect -f '{{if .State.Health}}{{range .State.Health.Log}}  probe {{.Start}} -> {{.End}} exit={{.ExitCode}}{{"\n"}}{{end}}{{end}}' "$c"; done
echo '--- clamav container log (timestamps)'; docker logs -t culvert-clamav 2>&1 | head -80
echo '--- proxy container log (first lines, timestamps)'; docker logs -t culvert 2>&1 | head -60
echo '--- engine + resume journal (monotonic)'
journalctl -b --no-pager -o short-monotonic -u containerd -u docker -u culvert-stack-resume 2>&1 | head -250
EOS
}
recovery_state() { local name="$1" i="$2"
  rec_state_snapshot "$EV/R-$name-$i-state.json"
  if [[ "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["login"])' "$EV/R-$name-$i-state.json")" == 200 ]] \
     && cmp -s "$EV/R-state-baseline.json" "$EV/R-$name-$i-state.json"; then
    check R "state-$name-$i" pass "admin login, normalized policy + default action, CA, image and agent availability equal the pre-reboot baseline"
  else check R "state-$name-$i" fail "differs from the baseline: $(diff <(python3 -m json.tool "$EV/R-state-baseline.json") <(python3 -m json.tool "$EV/R-$name-$i-state.json") | head -c 600 | tr '\n' ' ')"; fi
}
cmd_recovery() { local prof name r w budget i expected=0 ran=0 v0
  (( LAB_RECOVERY_REBOOTS > 0 )) || return 0
  if [[ "$LAB_EXTERNAL" == 1 || "$LAB_DISK" != dm ]]; then check R recovery fail "BLOCKED: needs a QEMU guest with LAB_DISK=dm"; return 0; fi
  gate R recovery || { check R recovery fail "BLOCKED: an earlier gate did not pass"; return 0; }
  gpriv > "$EV/R-io-accounting.txt" 2>&1 <<'EOS' || true
install -d /etc/systemd/system.conf.d
printf '[Manager]\nDefaultIOAccounting=yes\n' > /etc/systemd/system.conf.d/90-culvert-lab-ioaccounting.conf
systemctl daemon-reexec && echo "DefaultIOAccounting=$(systemctl show -p DefaultIOAccounting --value)"
EOS
  check R io-accounting info "LAB-ONLY guest change for attribution: systemd DefaultIOAccounting=yes ($(tail -1 "$EV/R-io-accounting.txt"))"
  # ClamAV evidence path: an allow rule for the host origin, then prove the
  # verdict is live BEFORE the first reboot (otherwise the gate measures nothing).
  rec_origin_start
  : > "$JAR"; api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$(cat "$SEC/admin-pass")\"}" > /dev/null
  api POST /api/policy '{"name":"lab-allow-eicar-origin","priority":15,"action":"Allow","destFQDN":"10.0.2.2","sslAction":"Bypass","enabled":true}' > "$EV/R-eicar-rule.txt"
  v0="$(eicar_verdict)"
  if [[ "$v0" != av ]]; then check R clamav-evidence fail "BLOCKED: EICAR through the proxy did not draw a ClamAV block before any reboot ($v0)"; rec_origin_stop; return 0; fi
  check R clamav-evidence pass "EICAR from the host origin is answered '403 Blocked by CLAMAV scan' before the first reboot"
  rec_state_snapshot "$EV/R-state-baseline.json"
  printf 'profile\treboot\trecovery_s\tbudget_s\n' > "$EV/R-summary.tsv"
  for prof in $LAB_RECOVERY_PROFILES; do
    IFS=: read -r name r w budget <<<"$prof"
    expected=$((expected + LAB_RECOVERY_REBOOTS))
    if ! set_disk_latency "$r" "$w" > "$EV/R-$name-dm-table.txt" 2>&1; then
      check R "profile-$name" fail "BLOCKED: could not set the disk to read ${r}ms / write ${w}ms: $(tail -1 "$EV/R-$name-dm-table.txt")"; continue; fi
    check R "profile-$name" info "disk: read +${r}ms, write +${w}ms per I/O ($(tr '\n' ' ' < "$EV/R-$name-dm-table.txt" | head -c 160)); budget ${budget}s; ${LAB_RECOVERY_REBOOTS} maintenance reboots"
    for i in $(seq 1 "$LAB_RECOVERY_REBOOTS"); do
      ran=$((ran+1))
      recovery_once "$name" "$i" "$budget" || { check R "profile-$name" fail "stopped after reboot $i; the remaining reboots of this profile did not run"; break; }
    done
  done
  set_disk_latency 0 0 > /dev/null 2>&1 || true
  rec_origin_stop
  if [[ $ran == "$expected" ]]; then check R recovery-cases pass "$ran of $expected profile x reboot cases ran"
  else check R recovery-cases fail "only $ran of $expected profile x reboot cases ran"; fi
  redact_tree
}

cmd_collect() {
  mkdir -p "$EV/guest"
  if { [[ "$LAB_EXTERNAL" == 1 ]] || qemu_alive; } && gop status-json > "$EV/guest/status-json.json" 2>/dev/null; then
    gop diagnostics > "$EV/guest/operator-diagnostics.txt" 2>&1 || true
    gpriv --timeout 300 > "$EV/guest/privileged-diagnostics.txt" 2>&1 <<'EOS' || true
echo '=== culvert-status --json'; culvert-status --json
echo '=== firstboot journal'; journalctl -u culvert-firstboot --no-pager | tail -400
echo '=== firstboot log'; tail -400 /var/log/culvert-firstboot.log
echo '=== cloud-init'; cloud-init status --long; cloud-init query ds 2>/dev/null | head -5
echo '=== runtime'; docker ps -a --format "{{.Names}} {{.Image}} {{.Status}}"; df -h / /var/lib/docker; uname -a
echo '=== agent'; systemctl status culvert-maint --no-pager | head -20; journalctl -u culvert-maint --no-pager | tail -150
echo '=== proxy log tail'; docker logs --tail 200 culvert 2>&1
EOS
  else check C guest-reachable info "guest not reachable at collect time; console log only"; fi
  [[ -f "$WORK/console.log" ]] && tr -d '\r' < "$WORK/console.log" | tail -c 2000000 > "$EV/guest/console.log"
  [[ -f "$WORK/console-session-trace.txt" ]] && tr -d '\r' < "$WORK/console-session-trace.txt" | tail -c 2000000 > "$EV/guest/console-session-trace.txt"
  [[ -f "$SEC/console-events" ]] && cp "$SEC/console-events" "$EV/guest/console-events.txt"
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
    echo "| access | read-only \`culvert-operator\` SSH (imported key) + authenticated local console (\`culvert\`, PAM + sudo) |"
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
    echo; echo "Not qualified by this lab: vSphere/ESXi import (ovftool), the guestinfo OVF transport, VMware Tools, LSI Logic SCSI, the hypervisor's tty1 console (ttyS0 here), datastore/thin-provisioning behaviour, the proxy's Release Management dispatch (6c calls the agent socket as its peer, with TEST-ONLY trust), and F-DISK-1 (owned by the bounded nested-Docker harness; still OPEN)."
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
    # ACPI power button through the monitor: no guest credential needed.
    [[ -S "$MON_SOCK" ]] && python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); time.sleep(0.3); s.send(b"system_powerdown\n"); time.sleep(0.5)' "$MON_SOCK" 2>/dev/null || true
    for _ in $(seq 1 60); do qemu_alive || break; sleep 2; done
    qemu_alive && kill "$(cat "$WORK/qemu.pid")" 2>/dev/null; sleep 3
    qemu_alive && kill -9 "$(cat "$WORK/qemu.pid")" 2>/dev/null || true
  fi
  rm -f "$MON_SOCK" "$SER_SOCK"
  dm_detach
  [[ "${LAB_KEEP_DISKS:-0}" == 1 ]] || rm -rf "$WORK/overlay.qcow2" "$WORK/base.qcow2" "$WORK/disk.raw" "$WORK/ova" "$WORK/ovfenv" "$WORK/ovfenv.iso"
  rm -rf "$SEC"; log "down: guest stopped, disposable disks and credentials removed (evidence kept in $EV)"
}
failures() { grep -c '"result":"fail"' "$JSONL" 2>/dev/null || true; }
# Transport adapters may reuse the guest checks without dispatching QEMU.
[[ "${LAB_LIBRARY_ONLY:-0}" == 1 ]] && return 0
case "${1:-}" in
  selftest) cmd_selftest ;;
  preflight) cmd_preflight ;;
  fingerprint) cmd_fingerprint "${2:?OVA}" "${3:?OUT.tsv}" ;;
  compare) cmd_compare "${2:?REF}" "${3:?CAND}" ;;
  up) cmd_up ;;
  qualify) cmd_qualify; [[ "$(failures)" == 0 ]] ;;
  recovery) cmd_recovery; [[ "$(failures)" == 0 ]] ;;
  collect) cmd_collect ;;
  down) cmd_down ;;
  all)
    trap 'cmd_collect || true; cmd_down || true' EXIT
    cmd_preflight; cmd_up; cmd_qualify; cmd_recovery; n="$(failures)"; log "failures: $n"; [[ "$n" == 0 ]] ;;
  *) sed -n '2,32p' "$0"; exit 2 ;;
esac
