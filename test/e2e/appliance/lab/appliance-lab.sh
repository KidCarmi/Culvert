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
# Diagnostic A/B (LAB-ONLY guest changes, cumulative, applied in order before
# each variant's reboots; "base" changes nothing). Components joined by '+':
#   ra   udev rule: read_ahead_kb=$LAB_RA_KB on whole disks (default 128)
#   svc  mask services the appliance does not use (snapd, ModemManager, udisks2, multipathd, apport)
#   ci   /etc/cloud/cloud-init.disabled (cloud-init skipped on later boots)
#   ird  initramfs MODULES=dep (smaller initrd for the firmware/bootloader to read)
LAB_RECOVERY_VARIANTS="${LAB_RECOVERY_VARIANTS:-base}"
LAB_RA_KB="${LAB_RA_KB:-4096}"
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
SECRET_FILES=(setup-token admin-pass console-pass console-onetime history-phrase log-pass-new)
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
# gop_within SECS ARGS — gop with a hard deadline. `timeout` executes a
# PROGRAM, so it must wrap the ssh argv itself: `timeout 3 gop …` cannot run
# a shell function and fails with 127 every time (ASTRA review of a4797481).
gop_within() { local t="$1"; shift; timeout "$t" ssh "${SSH_OPTS[@]}" "culvert-operator@$LAB_HOST" "$@"; }
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
  # The bounded operator probe must EXECUTE ssh: against a closed port ssh
  # fails (255); 127 would mean timeout could not run the command at all.
  local prc=0; ( LAB_HOST=127.0.0.1; SSH_OPTS=(-p 1 -o ConnectTimeout=2 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=QUIET); gop_within 5 status-json ) >/dev/null 2>&1 || prc=$?
  if [[ $prc == 255 ]]; then log "selftest ok: bounded operator probe executes ssh (closed port -> 255)"; else log "selftest FAILED: bounded operator probe exit $prc (127 = the probe never ran)"; rc=1; fi
  # The console-marks watcher runs in the background for up to an hour; the
  # caller captures its pid with $(...), which must return at once (run
  # 37363074909 lost ~60 min per reboot waiting for the watcher to exit).
  # Bounded: a regression must fail in 2 s, not hang the selftest for an hour.
  local cp n; : > "$d/console.log"
  ( mp="$( WORK="$d" rec_console_marks "$(date +%s.%N)" "$d/marks.tsv" )"; echo "$mp" > "$d/marks.pid" ) & cp=$!
  for n in $(seq 1 20); do [[ -s "$d/marks.pid" ]] && break; sleep 0.1; done
  if [[ -s "$d/marks.pid" ]]; then log "selftest ok: console-marks pid capture returns at once"; kill "$(cat "$d/marks.pid")" 2>/dev/null || true
  else log "selftest FAILED: console-marks pid capture blocked (the watcher holds the substitution pipe)"; rc=1; pkill -P "$cp" 2>/dev/null || true; kill "$cp" 2>/dev/null || true; fi
  # The backup-listing oracle must reject what HTTP 200 + a filename grep
  # accepted (ASTRA 6001710160), and accept the genuine listing.
  printf '%s' '{"filename":"baseline.enc","path":"/backup/baseline.enc","size_bytes":4096,"encrypted":true}' > "$d/exp.json"
  bl() { printf '%s' "$1" > "$d/b.json"; got="$(backup_listing_verdict "$d/b.json" "$d/exp.json" "$2")"
    if [[ "${got%% *}" == "$3" ]]; then log "selftest ok: backup oracle $4 -> ${got%% *}"; else log "selftest FAILED: backup oracle $4 -> $got (want $3)"; rc=1; fi; }
  local good='{"available":true,"count":1,"backups":[{"filename":"baseline.enc","path":"/backup/baseline.enc","size_bytes":4096,"encrypted":true}]}'
  bl "$good" 0.8 PASS "genuine listing"
  bl '{ "available": false, "reason": "could not read baseline.enc", "backups": [], "count": 0 }' 0.8 FAIL "available=false naming the file"
  bl "$good" 5.000001 FAIL "measured just over 5 s"
  bl '{"available":true,"count":2,"backups":[{"filename":"baseline.enc","path":"/backup/baseline.enc","size_bytes":4096,"encrypted":true}]}' 0.8 FAIL "count mismatch"
  bl '{"available":true,"count":1,"backups":[{"filename":"baseline.enc","path":"/backup/baseline.enc","size_bytes":17,"encrypted":true}]}' 0.8 FAIL "size changed"
  bl '{"available":true,"count":1,"backups":[{"filename":"baseline.enc","path":"/backup/baseline.enc","size_bytes":4096,"encrypted":false}]}' 0.8 FAIL "encryption changed"
  bl '{"available":true,"count":2,"backups":[{"filename":"baseline.enc","path":"/backup/baseline.enc","size_bytes":4096,"encrypted":true},{"filename":"baseline.enc","path":"/backup/baseline.enc","size_bytes":4096,"encrypted":true}]}' 0.8 FAIL "duplicate entry"
  bl '{"available":true,"count":0,"backups":[],"note":"baseline.enc"}' 0.8 FAIL "filename only in another field"
  rm -f "$d/exp.json"; bl "$good" 0.8 FAIL "no pre-reboot baseline"
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
    -device e1000,netdev=n0 -vga vmware -display none \
    -chardev "socket,id=ser0,path=$SER_SOCK,server=on,wait=off,logfile=$WORK/console.log,logappend=on" -serial chardev:ser0 \
    -monitor "unix:$MON_SOCK,server,nowait" -pidfile "$WORK/qemu.pid" -daemonize
  # -vga vmware: ESXi's SVGA adapter, so the guest binds vmwgfx (the driver
  # the DRM-node mitigation exists for) and the drm-root-only check tests it.
  printf 'qemu-system-x86_64 %s -smp %s -m %s virtio-scsi(%s) ide-cd(ovfenv.iso) e1000 vga=vmware user-net hostfwd 127.0.0.1:{%s,%s,%s} SeaBIOS serial=socket+logfile\n' \
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
    # Step 3e — recovery-secret custody: the root-only reveal prints exactly the
    # stack .env passphrases. Compared INSIDE the guest; only booleans and key
    # names reach the evidence, never a value.
    gpriv > "$EV/03e-recovery-secrets.txt" 2>&1 <<'EOS' || true
out="$(printf '\n' | /opt/culvert-appliance/bin/culvert-console --host=recovery-secrets 2>&1)"
for k in CULVERT_CA_PASSPHRASE CULVERT_LOG_PASSPHRASE; do
  v="$(sed -n "s/^$k=//p" /srv/culvert/.env | tail -1)"
  if [ -n "$v" ] && printf '%s\n' "$out" | grep -qxF "$k=$v"; then echo "$k=shown-and-matches-env"; else echo "$k=MISMATCH-or-missing"; fi
done
printf '%s\n' "$out" | grep -q 'CULVERT_SETUP_TOKEN' && echo "setup-token=LEAKED" || echo "setup-token=not-shown"
printf '%s\n' "$out" | grep -q 'A backup archive does NOT contain them' && echo "guidance=present" || echo "guidance=missing"
EOS
    printf '/opt/culvert-appliance/bin/culvert-console --host=recovery-secrets </dev/null >/dev/null 2>&1; echo "unprivileged-rc=$?"\n' | gpriv --as-user >> "$EV/03e-recovery-secrets.txt" 2>&1 || true
    if grep -qx 'CULVERT_CA_PASSPHRASE=shown-and-matches-env' "$EV/03e-recovery-secrets.txt" && grep -qx 'CULVERT_LOG_PASSPHRASE=shown-and-matches-env' "$EV/03e-recovery-secrets.txt" \
       && grep -qx 'setup-token=not-shown' "$EV/03e-recovery-secrets.txt" && grep -qx 'guidance=present' "$EV/03e-recovery-secrets.txt" \
       && grep -qE '^unprivileged-rc=[1-9]' "$EV/03e-recovery-secrets.txt"; then
      check 3e recovery-secrets pass "root reveal shows both .env passphrases exactly, no setup token, with custody guidance; unprivileged invocation refused"
    else check 3e recovery-secrets fail "$(tr '\n' ' ' < "$EV/03e-recovery-secrets.txt")"; fi
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
    if [[ -n "$fn" ]] && body < "$EV/06-backups.txt" | python3 -c 'import json,sys
d=json.load(sys.stdin); b=d.get("backups")
sys.exit(0 if d.get("available") is True and isinstance(b,list) and d.get("count")==len(b) and sum(1 for e in b if isinstance(e,dict) and e.get("filename")==sys.argv[1])==1 else 1)' "$fn" 2>/dev/null; then
      check 6 backup-listed pass "$fn listed by /api/backups (available=true, one entry)"
    else check 6 backup-listed fail "backup ${fn:-?} not listed by a valid listing: $(body < "$EV/06-backups.txt" | head -c 200)"; fi
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
docker compose -f docker-compose.yml \$([ -f docker-compose.maint-agent.yml ] && echo -f docker-compose.maint-agent.yml) up -d 2>&1; echo "up-rc=\$?"  # both files, as the runbook says: the second mounts the agent socket
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
    # Structured, like the recovery oracle: a grep also matches available=false.
    if [[ -n "${BACKUP_FILE:-}" ]] && body < "$EV/08-backups.txt" | python3 -c 'import json,sys
d=json.load(sys.stdin); b=d.get("backups")
sys.exit(0 if d.get("available") is True and isinstance(b,list) and d.get("count")==len(b) and sum(1 for e in b if isinstance(e,dict) and e.get("filename")==sys.argv[1])==1 else 1)' "$BACKUP_FILE" 2>/dev/null; then
      check 8 backup-listed pass "$BACKUP_FILE still listed (available=true, one entry)"
    else check 8 backup-listed fail "backup ${BACKUP_FILE:-?} not listed by a valid listing: $(body < "$EV/08-backups.txt" | head -c 200)"; fi
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
install -d -m 0755 /run/culvert-lab-upd
'
# embed NAME FILE — a guest line that recreates FILE at /run/culvert-lab-upd/NAME (0644).
# /run is tmpfs: the pressure phases fill the root disk, and a fixture staged
# there could not be written (lab run 37948667525).
embed() { printf "echo '%s' | base64 -d > /run/culvert-lab-upd/%s; chmod 0644 /run/culvert-lab-upd/%s\n" "$(base64 -w0 "$2")" "$1" "$1"; }
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
install -d -m 0755 /etc/docker/certs.d/ghcr.io && install -m 0644 -o root -g root /run/culvert-lab-upd/ca.crt /etc/docker/certs.d/ghcr.io/ca.crt && echo "  /etc/docker/certs.d/ghcr.io/ca.crt (disposable registry CA)"
grep -qE '[[:space:]]ghcr\.io\$' /etc/hosts || echo "$REGISTRY_ADDR ghcr.io  # culvert lab TEST-ONLY" >> /etc/hosts; echo "  /etc/hosts: \$(grep -E '[[:space:]]ghcr\.io' /etc/hosts)"
install -m 0644 -o root -g root /run/culvert-lab-upd/keyring.json /etc/culvert-maint/lab-fixture-keyring.json && echo "  /etc/culvert-maint/lab-fixture-keyring.json (fixture PUBLIC key)"
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
  rc=0; { printf '%s' "$AGENT_LIB"; embed unsigned.json "$U/apply-unsigned.json"; printf '%s\n' 'agent -X POST --data-binary @/run/culvert-lab-upd/unsigned.json http://agent/v1/upgrades/apply' 'running'; } \
    | gpriv --timeout 300 > "$EV/06c-apply-unsigned.txt" 2>&1 || rc=$?
  grep -qx 'HTTP 403' "$EV/06c-apply-unsigned.txt" && grep -qx "running-image=$bdig" "$EV/06c-apply-unsigned.txt" \
    && check 6c unsigned-apply-refused pass "apply without release evidence: 403 ($(grep -o '"error":"[^"]*"' "$EV/06c-apply-unsigned.txt" | head -1 | head -c 140)); still running the baseline" \
    || check 6c unsigned-apply-refused fail "$(grep -E '^HTTP|running-image' "$EV/06c-apply-unsigned.txt" | tr '\n' ' ')"
  # 3. signed apply baseline → target
  rc=0; { printf '%s' "$AGENT_LIB"; embed apply.json "$U/apply-signed.json"
          printf '%s\n' 'r=$(agent -X POST --data-binary @/run/culvert-lab-upd/apply.json http://agent/v1/upgrades/apply); echo "$r" | tail -c 2000' \
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
          printf '%s\n' 'r=$(agent -X POST --data-binary @/run/culvert-lab-upd/rollback.json http://agent/v1/rollbacks); echo "$r" | tail -c 2000' \
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
mono() { python3 -c 'import time; print("%.3f" % time.monotonic())'; }
mono_raw() { python3 -c 'import time; print("%.9f" % time.monotonic())'; }
# since T — seconds from monotonic T to now (one decimal).
since() { python3 -c 'import sys,time; print(round(time.monotonic()-float(sys.argv[1]),1))' "$1"; }
rec_origin_start() {
  mkdir -p "$WORK/eicar-origin"
  # Built at run time, so no file in the repository carries the test signature.
  printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$WORK/eicar-origin/eicar.txt"

  python3 -m http.server "$LAB_EICAR_PORT" --bind 127.0.0.1 --directory "$WORK/eicar-origin" > "$WORK/eicar-origin.log" 2>&1 &
  echo $! > "$WORK/eicar-origin.pid"; sleep 1; }
# upload_rx_start — a host receiver the GUEST can PUT one file to (10.0.2.2 is
# the host's loopback under QEMU user networking). Used to carry the exact
# bytes of an image the guest built out of the VM: a serial console session
# (gpriv) cannot carry binary. Basename only, length-checked, written beside
# and renamed into place, so a short upload never looks like a file.
LAB_UPLOAD_PORT="${LAB_UPLOAD_PORT:-18432}"
upload_rx_start() {
  mkdir -p "$WORK/upload"; rm -f "$WORK/upload/"* "$WORK/upload/".[!.]* 2>/dev/null || true
  python3 -I -c '
import http.server, os, sys
port, root, limit = int(sys.argv[1]), sys.argv[2], 4 << 30
class H(http.server.BaseHTTPRequestHandler):
    def no(self, c):
        self.send_response(c); self.send_header("Content-Length", "0"); self.end_headers()
    def do_PUT(self):
        name = os.path.basename(self.path)
        n = int(self.headers.get("Content-Length") or -1)
        if not name or name.startswith(".") or n < 0 or n > limit:
            return self.no(400)
        tmp = os.path.join(root, "." + name)
        left = n
        with open(tmp, "wb") as f:
            while left:
                b = self.rfile.read(min(left, 1 << 20))
                if not b: break
                f.write(b); left -= len(b)
        if left:
            os.unlink(tmp); return self.no(400)
        os.replace(tmp, os.path.join(root, name)); self.no(201)
http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
' "$LAB_UPLOAD_PORT" "$WORK/upload" > "$WORK/upload-rx.log" 2>&1 &
  echo $! > "$WORK/upload-rx.pid"; sleep 1; }
upload_rx_stop() { [[ -f "$WORK/upload-rx.pid" ]] && kill "$(cat "$WORK/upload-rx.pid")" 2>/dev/null; rm -f "$WORK/upload-rx.pid"; }
rec_origin_stop() { [[ -f "$WORK/eicar-origin.pid" ]] && kill "$(cat "$WORK/eicar-origin.pid")" 2>/dev/null; rm -f "$WORK/eicar-origin.pid"; }
# fresh_eicar — a NEW body per call: the 68-byte EICAR string followed by a
# unique run of spaces/tabs (the EICAR spec permits trailing whitespace). The
# proxy caches verdicts by body SHA-256, so a repeated body could be answered
# from the cache while clamd is down; a fresh body must reach clamd.
# (Called in a command substitution, so it keeps no shell state: the name and
# the whitespace pattern both come from the nanosecond clock.)
fresh_eicar() { local n
  n="$(python3 -c 'import time; print(time.time_ns())')"
  { cat "$WORK/eicar-origin/eicar.txt"; python3 -c 'import sys,hashlib
h=int.from_bytes(hashlib.sha256(sys.argv[1].encode()).digest()[:8],"big")
sys.stdout.write("".join(" \t"[(h>>i)&1] for i in range(56)))' "$n"; } > "$WORK/eicar-origin/e$n.txt"
  echo "http://10.0.2.2:$LAB_EICAR_PORT/e$n.txt"; }
# eicar_verdict — "av" when the proxy returned the ClamAV block for a FRESH
# body, else code:body-head.
eicar_verdict() { local out c u
  u="$(fresh_eicar)"
  out="$(curl -sS -m 4 -x "$P" -w '\n%{http_code}' "$u" 2>/dev/null || printf '\n000')"
  c="$(tail -n1 <<<"$out")"
  if [[ "$c" == 403 ]] && grep -q 'Blocked by CLAMAV scan' <<<"$out"; then echo av; else echo "$c:$(head -c 60 <<<"$out" | tr -d '\n')"; fi; }
ready_clamav_ok() { local code cv
  code="$(curl -sS -m 2 -o "$WORK/rec-ready.json" -w '%{http_code}' "$P/ready" 2>/dev/null || echo 000)"
  cv="$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); c=d.get("checks",d).get("clamav",{})
print(c.get("status") if isinstance(c,dict) else c)' "$WORK/rec-ready.json" 2>/dev/null || true)"
  [[ "$code" == 200 && "$cv" == ok ]]; }
# rec_state_snapshot FILE — normalized persisted state the reboots must preserve.
rec_state_snapshot() { local out="$1" c pol f img ag
  : > "$JAR"; c="$(api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$(cat "$SEC/admin-pass")\"}" | code)"
  local da; da="$(api GET /api/default-action | body | python3 -c 'import json,sys
a=json.load(sys.stdin).get("defaultAction"); print(a if a in ("allow","deny") else "INVALID:%r" % (a,))' 2>/dev/null || echo unreadable)"
  pol="$(api GET /api/policy | body | python3 -c 'import json,sys
d=json.load(sys.stdin); keys=("name","priority","action","enabled","destFQDN","destCategory","destCategoryGroup","destCountry","sslAction")
rules=sorted(([r.get(k) for k in keys] for r in d.get("rules",[])), key=lambda r: (r[1] or 0, r[0] or ""))
print(json.dumps({"default_action":sys.argv[1],"persisted":d.get("persisted"),"draft":d.get("draft"),"rules":rules},sort_keys=True))' "$da" 2>/dev/null || echo unreadable)"
  f="$(api GET /api/ca-cert | body | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || true)"
  img="$(gpriv 2>/dev/null <<<'docker inspect -f "{{.Image}}" culvert' | tr -d '\r' | grep -m1 '^sha256:' || true)"
  ag="$(api GET /api/maintenance-agent | body | python3 -c 'import json,sys;print(json.load(sys.stdin).get("available"))' 2>/dev/null || echo unreadable)"
  python3 -c 'import json,sys; print(json.dumps({"login":sys.argv[1],"policy":sys.argv[2],"ca":sys.argv[3],"image":sys.argv[4],"agent_available":sys.argv[5]},sort_keys=True))' \
    "$c" "$pol" "$f" "$img" "$ag" > "$out"; }
rec_traffic() { local a b
  a="$(curl -sS -m 2 -x "$P" -o /dev/null -w '%{http_code}' http://example.com/ 2>/dev/null || echo 000)"
  b="$(curl -sS -m 2 -x "$P" -o /dev/null -w '%{http_code}' http://example.org/ 2>/dev/null || echo 000)"
  [[ "$a $b" == "200 403" ]]; }
# rec_console_marks START_EPOCH OUT — timestamp boot-path console markers while
# the reboot runs (shutdown, firmware, bootloader, kernel). Only lines matching
# a fixed marker list are kept, so no console secret reaches the evidence.
# Its stdout goes to /dev/null: called as marks_pid="$(rec_console_marks …)",
# a backgrounded child still holding the substitution's pipe makes the
# caller wait for the child to EXIT (its 3600 s deadline) — which is what
# stretched every reboot cycle to ~64 minutes in run 37363074909.
rec_console_marks() { python3 - "$WORK/console.log" "$2" "$1" > /dev/null 2>&1 <<'PY' &
import os, re, sys, time
log, out, t0 = sys.argv[1], sys.argv[2], float(sys.argv[3])
pat = re.compile(r"(reboot: |Linux version|SeaBIOS|Booting from|iPXE|GRUB|Loading Linux|Loading initial ramdisk|Run /init|EXT4-fs \(sda1\): mounted|systemd\[1\]: (Reached target|Stopping|Stopped|Finished|Started) |Culvert|login:)")
f = open(log, "rb"); f.seek(0, os.SEEK_END); buf = b""
with open(out, "w") as o:
    deadline = time.time() + 3600
    while time.time() < deadline:
        chunk = f.read()
        if not chunk:
            time.sleep(0.2); continue
        now = time.time(); buf += chunk
        *lines, buf = buf.split(b"\n")
        for raw in lines:
            line = raw.decode("utf-8", "replace").replace("\r", "")
            m = pat.search(line)
            if m:
                o.write("%.2f\t%s\n" % (now - t0, re.sub(r"[^ -~]", "", line)[:140])); o.flush()
PY
echo $!; }
recovery_once() { local name="$1" i="$2" budget="$3"; local tag="R-$name-$i"
  local k0 acc t0 st0 st1 ok=0 samples=0 s_start s s_prev="" pr pt pa pp dur gap why marks_pid
  local tk="" ts_ready="" ts_traffic="" ts_av="" ts_phase="" first_joint="" end="" bk_pid=""
  k0="$(grep -ac 'Linux version' "$WORK/console.log" || true)"
  st0="$(host_disk_stat)"
  # Authenticate BEFORE the reboot for the pre-reboot baseline listing. The
  # post-reboot listing cannot reuse this session: the session signing key is
  # per-process unless CULVERT_SESSION_SECRET is set (documented in the
  # state-and-key-custody matrix), so every pre-reboot cookie answers 401.
  : > "$JAR"; api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$(cat "$SEC/admin-pass")\"}" > /dev/null
  recovery_backup_baseline "$EV/$tag-backup-baseline.json"
  marks_pid="$(rec_console_marks "$(date +%s.%N)" "$EV/$tag-console-marks.tsv")"
  # The guest prints LABACCEPT after PAM login and sudo, then WAITS for the
  # controller's go-ahead; the controller takes t0 before sending it.
  printf 'echo "LABACCEPT $(date +%%s.%%N)"\nIFS= read -r -t 120 go || go=\n[[ "$go" == LABGO* ]] || { echo LABNOGO; exit 1; }\nexec culvert-os-update reboot\n' \
    | gpriv --nowait --timeout 180 > "$EV/$tag-reboot.txt" 2>&1 || true
  t0="$(mono)"
  acc="$(grep -m1 -oE 'host_epoch=[0-9.]+' "$EV/$tag-reboot.txt" | cut -d= -f2 || true)"
  if [[ -z "$acc" ]]; then kill "$marks_pid" 2>/dev/null; check R "recovery-$name-$i" fail "the maintenance reboot was not accepted (no authenticated acceptance marker): $(tail -c 300 "$EV/$tag-reboot.txt")"; return 1; fi
  local lag; lag="$(python3 -c 'import sys,time; print("%.6f" % (time.time()-float(sys.argv[1])))' "$acc")"
  t0="$(python3 -c 'import sys; print("%.6f" % (float(sys.argv[1]) - float(sys.argv[2])))' "$t0" "$lag")"
  printf 'sample_start_s\tsample_end_s\tduration_s\tstart_gap_s\tready_clamav\ttraffic\teicar\tphase\tcounted\n' > "$EV/$tag-samples.tsv"
  while :; do
    qemu_alive || { kill "$marks_pid" 2>/dev/null; check R "recovery-$name-$i" fail "qemu exited during the reboot"; return 1; }
    s_start="$(mono)"
    python3 -c 'import sys; sys.exit(0 if float(sys.argv[1])-float(sys.argv[2]) < float(sys.argv[3]) else 1)' "$s_start" "$t0" "$LAB_RECOVERY_TIMEOUT" || break
    if [[ -z "$tk" ]]; then
      (( $(grep -ac 'Linux version' "$WORK/console.log" || true) > k0 )) && tk="$(mono)"
      sleep 2; continue
    fi
    samples=$((samples+1))
    if ready_clamav_ok; then pr=ok; else pr=no; fi; s="$(mono)"; [[ $pr == ok && -z "$ts_ready" ]] && ts_ready="$s"
    if rec_traffic; then pt=ok; else pt=no; fi
    s="$(mono)"; [[ $pt == ok && -z "$ts_traffic" ]] && ts_traffic="$s"
    pa="$(eicar_verdict)"; s="$(mono)"; [[ $pa == av && -z "$ts_av" ]] && ts_av="$s"
    if gop_within 3 status-json > "$WORK/rec-status.json" 2>/dev/null && [[ "$(status_field "$WORK/rec-status.json" phase)" == ready ]]; then pp=ok; else pp=no; fi
    s="$(mono)"; [[ $pp == ok && -z "$ts_phase" ]] && ts_phase="$s"
    # Declared cadence: a sample counts only if it completed within 5 s and
    # started at most 5.5 s after the previous one. Overruns are retained in
    # the TSV and reset the consecutive count (ASTRA review, item 4).
    dur="$(python3 -c 'import sys;print("%.3f"%(float(sys.argv[1])-float(sys.argv[2])))' "$s" "$s_start")"
    gap="$( [[ -n "$s_prev" ]] && python3 -c 'import sys;print("%.3f"%(float(sys.argv[1])-float(sys.argv[2])))' "$s_start" "$s_prev" || echo first)"
    why=yes
    python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) <= 5.0 else 1)' "$dur" || why=overrun-duration
    [[ "$gap" == first ]] || python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) <= 5.5 else 1)' "$gap" || why=overrun-gap
    [[ $pr == ok && $pt == ok && $pa == av && $pp == ok ]] || why=no
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(python3 -c 'import sys;print("%.3f"%(float(sys.argv[1])-float(sys.argv[2])))' "$s_start" "$t0")" \
      "$(python3 -c 'import sys;print("%.3f"%(float(sys.argv[1])-float(sys.argv[2])))' "$s" "$t0")" "$dur" "$gap" "$pr" "$pt" "$pa" "$pp" "$why" >> "$EV/$tag-samples.tsv"
    s_prev="$s_start"
    if [[ $why == yes ]]; then
      ok=$((ok+1)); (( ok == 1 )) && first_joint="$s"
      # The ONE backup-listing attempt starts at the FIRST healthy joint
      # sample, on the session authenticated before the reboot, in the
      # background so the sample cadence is not delayed; its outcome is kept
      # even if a later sample resets the count (ASTRA review of a4797481).
      if [[ -z "$bk_pid" ]]; then recovery_backup_first_list "$name" "$i" & bk_pid=$!; fi
      if (( ok == 3 )); then end="$s"; break; fi
    else ok=0; first_joint=""; fi
    # The next sample starts 5 s after this one STARTED, never sooner.
    python3 -c 'import sys,time; d=float(sys.argv[1])+5-time.monotonic(); time.sleep(d if d>0 else 0)' "$s_start"
  done
  [[ -n "$bk_pid" ]] && wait "$bk_pid"
  [[ -n "$bk_pid" ]] || check R "backup-list-$name-$i" fail "no healthy joint sample, so the backup listing was never attempted"
  kill "$marks_pid" 2>/dev/null || true
  st1="$(host_disk_stat)"
  local rec; rec="$(python3 "$HERE/recovery-timeline.py" "$t0" "$tk" "$ts_ready" "$ts_traffic" "$ts_av" "$ts_phase" "$first_joint" "$end" \
    "$st0" "$st1" "$budget" "$acc" "$lag" "$samples" "$EV/$tag-timeline.json")"
  local tl; tl="$(python3 "$HERE/recovery-timeline.py" --describe "$EV/$tag-timeline.json")"
  if [[ "$rec" == none ]]; then check R "recovery-$name-$i" fail "not recovered (3 consecutive joint samples) within ${LAB_RECOVERY_TIMEOUT}s: $tl"; recovery_guest "$tag"; return 1; fi
  local recd; recd="$(printf '%.1f' "$rec")"
  if python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) <= float(sys.argv[2]) else 1)' "$rec" "$budget"; then
    check R "recovery-$name-$i" pass "recovered in ${recd}s (budget ${budget}s; unrounded $rec): $tl"
  else
    # Still a FAIL. The excess read service time over the injected delay
    # (r ms, from cmd_recovery's profile) says how much of it is the runner's
    # disk: >1 ms means re-measure on one runner, interleaved A/B, before
    # calling it the candidate (evidence/candidate-91e05872-recovery-causation.md).
    local ex; ex="$(python3 "$HERE/recovery-timeline.py" --svc-excess "$EV/$tag-timeline.json" "${r:-0}")"
    check R "recovery-$name-$i" fail "recovered in ${recd}s — OVER the ${budget}s budget (unrounded $rec): $tl; host read service ${ex} ms/request above the injected ${r:-0} ms$(python3 -c 'import sys; print("" if float(sys.argv[1]) <= 1 else " — runner disk slower than the profile: attribute only after a same-runner A/B")' "$ex" 2>/dev/null)"
  fi
  recovery_guest "$tag"
  recovery_state "$name" "$i"
  printf '%s\t%s\t%s\t%s\t%s\n' "${REC_VARIANT:-base}" "$name" "$i" "$rec" "$budget" >> "$EV/R-summary.tsv"
}
# The FIRST backup listing after the reboot must answer within 5 s, with the
# baseline backup in it. Never retried: a slow first answer is the finding.
# Sessions do not survive the restart (per-process signing key), so it logs in
# on its own cookie jar first; the login is timed and reported separately and
# only the listing itself is held to the 5 s limit.
# The oracle is STRUCTURED (ASTRA review 6001710160): HTTP 200 alone, or the
# filename appearing anywhere in the body, also matches
# {"available":false,"reason":"could not read <file>",...}. It requires
# available=true, count == len(backups), exactly one entry for the baseline
# archive and that entry equal to the one listed before the reboot
# (filename, path, size_bytes, encrypted). The 5 s limit is checked against
# the MEASURED, unrounded elapsed time, not only enforced by curl's timeout.
backup_listing_verdict() { python3 - "$1" "$2" "$3" <<'PY'
import json, sys
body, expected, elapsed = sys.argv[1], sys.argv[2], float(sys.argv[3])
problems = []
try:
    d = json.load(open(body))
except Exception as e:
    print("FAIL body is not JSON: %s" % str(e)[:120]); sys.exit(0)
try:
    exp = json.load(open(expected))
except Exception as e:
    print("FAIL no pre-reboot baseline entry: %s" % str(e)[:120]); sys.exit(0)
if not isinstance(d, dict):
    print("FAIL body is not a JSON object"); sys.exit(0)
if d.get("available") is not True:
    problems.append("available=%r reason=%r" % (d.get("available"), str(d.get("reason", ""))[:160]))
b = d.get("backups")
if not isinstance(b, list):
    problems.append("backups is %s, not a list" % type(b).__name__)
    b = []
if d.get("count") != len(b):
    problems.append("count=%r but %d entries" % (d.get("count"), len(b)))
m = [e for e in b if isinstance(e, dict) and e.get("filename") == exp.get("filename")]
if len(m) != 1:
    problems.append("%d entries named %r (want exactly 1)" % (len(m), exp.get("filename")))
else:
    for k in ("filename", "path", "size_bytes", "encrypted"):
        if m[0].get(k) != exp.get(k):
            problems.append("%s=%r, baseline %r" % (k, m[0].get(k), exp.get(k)))
if elapsed > 5.0:
    problems.append("measured %.3fs > 5s" % elapsed)
if problems:
    print("FAIL " + "; ".join(problems))
else:
    print("PASS %s (%d bytes, encrypted=%s) in %.3fs, count=%d" % (exp["filename"], exp["size_bytes"], exp["encrypted"], elapsed, len(b)))
PY
}
# The pre-reboot baseline entry the post-reboot listing must reproduce. A
# listing that is itself not structurally valid yields no baseline, and the
# post-reboot check then fails rather than comparing against nothing.
recovery_backup_baseline() { local out="$1" raw="$1.raw"
  rm -f "$out"
  [[ -n "${BACKUP_FILE:-}" ]] || return 0
  curl -ksS -m 30 "$UI/api/backups" -H "Origin: $UI" -b "$JAR" -o "$raw" 2>/dev/null || return 0
  python3 - "$raw" "$BACKUP_FILE" "$out" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
b = d.get("backups") if isinstance(d, dict) else None
if not (isinstance(d, dict) and d.get("available") is True and isinstance(b, list) and d.get("count") == len(b)):
    sys.exit(0)
m = [e for e in b if isinstance(e, dict) and e.get("filename") == sys.argv[2]]
if len(m) == 1 and all(k in m[0] for k in ("filename", "path", "size_bytes", "encrypted")):
    json.dump({k: m[0][k] for k in ("filename", "path", "size_bytes", "encrypted")}, open(sys.argv[3], "w"))
PY
}
recovery_backup_first_list() { local name="$1" i="$2" t1 t2 c dt v jar="$WORK/rec-backup-jar" l0 lc ldt
  : > "$jar"
  l0="$(mono_raw)"
  lc="$(curl -ksS -m 30 -X POST "$UI/api/auth/login" -H "Origin: $UI" -H 'Content-Type: application/json' -c "$jar" \
    -d "{\"user\":\"$ADMIN_USER\",\"pass\":\"$(cat "$SEC/admin-pass")\"}" -o /dev/null -w '%{http_code}' 2>/dev/null || echo 000)"
  ldt="$(python3 -c 'import sys,time; print("%.3f" % (time.monotonic()-float(sys.argv[1])))' "$l0")"
  if [[ "$lc" != 200 ]]; then
    check R "backup-list-$name-$i" fail "could not log in for the first listing (http $lc in ${ldt}s)"; return 0
  fi
  t1="$(mono_raw)"
  c="$(curl -ksS -m 5 "$UI/api/backups" -H "Origin: $UI" -b "$jar" -o "$EV/R-$name-$i-backups.json" -w '%{http_code}' 2>/dev/null || echo 000)"
  t2="$(mono_raw)"
  dt="$(python3 -c 'import sys; print("%.6f" % (float(sys.argv[2])-float(sys.argv[1])))' "$t1" "$t2")"
  if [[ -z "${BACKUP_FILE:-}" ]]; then
    check R "backup-list-$name-$i" fail "no baseline backup file recorded, so the listing cannot be verified (http $c in ${dt}s)"; return 0
  fi
  if [[ "$c" != 200 ]]; then
    check R "backup-list-$name-$i" fail "first listing http $c in ${dt}s (limit 5 s, no retry); $BACKUP_FILE expected"; return 0
  fi
  v="$(backup_listing_verdict "$EV/R-$name-$i-backups.json" "$EV/R-$name-$i-backup-baseline.json" "$dt")"
  if [[ "$v" == PASS* ]]; then check R "backup-list-$name-$i" pass "first listing http 200: ${v#PASS } (login ${ldt}s, not counted)"
  else check R "backup-list-$name-$i" fail "first listing http 200 in ${dt}s (no retry): ${v#FAIL }"; fi
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
echo '--- previous boot: shutdown tail (wall clock, us precision)'
journalctl -b -1 --no-pager -o short-iso-precise 2>&1 | grep -E 'culvert-os-update|Stopping|Stopped|Reached target|reboot|Shutting|systemd-shutdown|Journal stopped' | tail -60
echo '--- previous boot last entry / this boot first entry'
journalctl -b -1 --no-pager -o short-iso-precise -n 1 2>&1 | tail -1; journalctl -b 0 --no-pager -o short-iso-precise 2>&1 | head -2 | tail -1
echo '--- proxy container log since its start (timestamps)'; docker logs -t --since "$(docker inspect -f '{{.State.StartedAt}}' culvert)" culvert 2>&1 | head -80
EOS
}
# rec_state_valid FILE — the snapshot itself is meaningful: login 200, a valid
# default action from /api/default-action, the policy persisted and not a draft.
rec_state_valid() { python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); p=json.loads(d["policy"]) if d["policy"].startswith("{") else {}
ok = d["login"]=="200" and p.get("default_action") in ("allow","deny") and p.get("persisted") is True and p.get("draft") is False
sys.exit(0 if ok else 1)' "$1"; }
apply_variant() { local v="$1" c
  [[ "$v" == base ]] && { echo "base: no change"; return 0; }
  for c in ${v//+/ }; do
    case "$c" in
      ra) gpriv <<EOS || return 1
printf '%s\n' 'ACTION=="add|change", SUBSYSTEM=="block", ENV{DEVTYPE}=="disk", KERNEL=="sd*|vd*|nvme*n*", ATTR{queue/read_ahead_kb}="$LAB_RA_KB"' > /etc/udev/rules.d/60-culvert-lab-readahead.rules
udevadm control --reload && udevadm trigger --subsystem-match=block --action=change && udevadm settle
echo "ra: \$(for q in /sys/block/sd*/queue/read_ahead_kb /sys/block/vd*/queue/read_ahead_kb; do [ -e "\$q" ] && echo "\$q=\$(cat \$q)"; done | paste -sd' ')"
EOS
      ;;
      svc) gpriv <<'EOS' || return 1
u="snapd.service snapd.socket snapd.seeded.service snapd.apparmor.service ModemManager.service udisks2.service multipathd.service multipathd.socket apport.service"
for x in $u; do systemctl mask "$x" >/dev/null 2>&1 && echo -n "masked:$x "; done; echo
EOS
      ;;
      ci) gpriv <<<'touch /etc/cloud/cloud-init.disabled && echo "ci: cloud-init disabled for later boots"' || return 1 ;;
      ird) gpriv --timeout 900 <<'EOS' || return 1
echo 'MODULES=dep' > /etc/initramfs-tools/conf.d/90-culvert-lab.conf
before=$(stat -c %s "/boot/initrd.img-$(uname -r)")
update-initramfs -u -k "$(uname -r)" >/dev/null 2>&1 || exit 1
echo "ird: initrd $before -> $(stat -c %s "/boot/initrd.img-$(uname -r)") bytes"
EOS
      ;;
      *) echo "unknown variant component: $c"; return 1 ;;
    esac
  done; }
recovery_state() { local name="$1" i="$2"
  rec_state_snapshot "$EV/R-$name-$i-state.json"
  if rec_state_valid "$EV/R-$name-$i-state.json" && cmp -s "$EV/R-state-baseline.json" "$EV/R-$name-$i-state.json"; then
    check R "state-$name-$i" pass "admin login, normalized policy (persisted, not draft) + valid default action, CA, image and agent availability equal the pre-reboot baseline"
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
  # Negative control: with clamd stopped a FRESH body must NOT draw the ClamAV
  # block (fail-open 200, or a scan-unavailable refusal) — otherwise the
  # sample is not live clamd evidence. Then clamd must come back.
  local vdown vup=""
  gpriv <<<'docker stop -t 10 culvert-clamav >/dev/null' > /dev/null 2>&1 || true
  vdown="$(eicar_verdict)"
  gpriv <<<'docker start culvert-clamav >/dev/null' > /dev/null 2>&1 || true
  for _ in $(seq 1 60); do vup="$(eicar_verdict)"; [[ "$vup" == av ]] && break; sleep 5; done
  if [[ "$vdown" == av || "$vup" != av ]]; then
    check R clamav-evidence fail "BLOCKED: the EICAR sample is not live clamd evidence (clamd stopped -> $vdown; restarted -> $vup)"; rec_origin_stop; return 0; fi
  check R clamav-evidence pass "a fresh EICAR body is answered '403 Blocked by CLAMAV scan' with clamd up, NOT with clamd stopped ($vdown), and again after clamd restarts"
  rec_state_snapshot "$EV/R-state-baseline.json"
  if ! rec_state_valid "$EV/R-state-baseline.json"; then
    check R state-baseline fail "BLOCKED: the pre-reboot baseline is not a valid reference (login 200, valid default action, persisted, not draft): $(head -c 400 "$EV/R-state-baseline.json")"; rec_origin_stop; return 0; fi
  # Boot-path inventory (fast disk, before any latency is injected).
  gpriv --timeout 600 > "$EV/R-boot-files.txt" 2>&1 <<'EOS' || true
ls -l /boot; echo '--- initramfs composition (KiB, top 25)'
d=$(mktemp -d); unmkinitramfs "/boot/initrd.img-$(uname -r)" "$d" >/dev/null 2>&1 && (cd "$d" && du -sk */usr/lib/modules/*/kernel/* */usr/lib/firmware */usr/lib/modules */usr/lib/x86_64-linux-gnu */usr/share/plymouth 2>/dev/null | sort -rn | head -25; du -sk . ); rm -rf "$d"
echo '--- read_ahead_kb'; for q in /sys/block/*/queue/read_ahead_kb; do echo "$q $(cat "$q")"; done
echo '--- enabled units'; systemctl list-unit-files --state=enabled --no-legend | awk '{print $1}' | paste -sd' '
EOS
  printf 'variant\tprofile\treboot\trecovery_s\tbudget_s\n' > "$EV/R-summary.tsv"
  local variant
  for variant in $LAB_RECOVERY_VARIANTS; do
  REC_VARIANT="$variant"
  set_disk_latency 0 0 > /dev/null 2>&1 || true
  if ! apply_variant "$variant" > "$EV/R-variant-$variant.txt" 2>&1; then
    check R "variant-$variant" fail "BLOCKED: could not apply lab variant $variant: $(tail -c 300 "$EV/R-variant-$variant.txt")"
    expected=$((expected + LAB_RECOVERY_REBOOTS * $(wc -w <<<"$LAB_RECOVERY_PROFILES"))); continue; fi
  check R "variant-$variant" info "LAB-ONLY guest change set '$variant' applied: $(tr '\n' ' ' < "$EV/R-variant-$variant.txt" | head -c 300)"
  for prof in $LAB_RECOVERY_PROFILES; do
    IFS=: read -r name r w budget <<<"$prof"
    [[ "$variant" == base ]] || name="$variant-$name"
    expected=$((expected + LAB_RECOVERY_REBOOTS))
    if ! set_disk_latency "$r" "$w" > "$EV/R-$name-dm-table.txt" 2>&1; then
      check R "profile-$name" fail "BLOCKED: could not set the disk to read ${r}ms / write ${w}ms: $(tail -1 "$EV/R-$name-dm-table.txt")"; continue; fi
    check R "profile-$name" info "disk: read +${r}ms, write +${w}ms per I/O ($(tr '\n' ' ' < "$EV/R-$name-dm-table.txt" | head -c 160)); budget ${budget}s; ${LAB_RECOVERY_REBOOTS} maintenance reboots"
    for i in $(seq 1 "$LAB_RECOVERY_REBOOTS"); do
      ran=$((ran+1))
      recovery_once "$name" "$i" "$budget" || { check R "profile-$name" fail "stopped after reboot $i; the remaining reboots of this profile did not run"; break; }
    done
  done
  done
  set_disk_latency 0 0 > /dev/null 2>&1 || true
  rec_origin_stop
  if [[ $ran == "$expected" ]]; then check R recovery-cases pass "$ran of $expected profile x reboot cases ran"
  else check R recovery-cases fail "only $ran of $expected profile x reboot cases ran"; fi
  redact_tree
}

# ── history: encrypted request-history recovery (ASTRA item 3, #1528) ───────
# The backup deliberately omits the history store and its key is node-local,
# so the supported recovery is the encrypted history export. Proven here on the
# real appliance with the SOURCE GONE: history on → marker traffic → export via
# the admin API to the RUNNER (never kept in the guest) → backup → stack down →
# the data VOLUME is deleted → restore into a fresh volume with a NEW log
# passphrase (key rotation) → the markers are absent → offline import of the
# runner's archive → the exact exported records are back. Runs LAST: deleting
# the volume also drops the category feed DB, which re-syncs on its own and
# must not disturb the other steps' oracles.
hist_markers() { api GET "/api/logs?source=store&filter=$HIST_TAG&limit=500" | body | python3 -c 'import json,sys
d=json.load(sys.stdin); rows=sorted((e.get("ts"),e.get("host"),e.get("status"),e.get("method")) for e in d.get("logs") or [])
print(json.dumps({"history":d.get("history"),"total":d.get("total"),"rows":rows}))' 2>/dev/null || echo '{}'; }
hist_total() { python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("total",-1))' "$1" 2>/dev/null || echo -1; }
hist_login() { : > "$JAR"; api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$(cat "$SEC/admin-pass")\"}" | code; }
hist_wait_up() { local deadline=$(( $(date +%s) + 600 ))
  until curl -fsS -m 3 "$P/health" >/dev/null 2>&1; do (( $(date +%s) < deadline )) || return 1; sleep 5; done; }
hist_upload() { local src="$1" dst="$2" chunk
  { echo "set -e; rm -f $dst.b64"
    base64 -w 1000 "$src" | while read -r chunk; do echo "echo '$chunk' >> $dst.b64"; done
    # 0644: the cli container runs as the image's unprivileged `proxy`
    # user, which a root-owned 0600 file locks out (the archive is
    # passphrase-encrypted; the passphrase, not the mode, protects it).
    echo "base64 -d $dst.b64 > $dst; rm -f $dst.b64; chmod 0644 $dst; sha256sum $dst"; } | gpriv --timeout 900; }
cmd_history() { local c n tot before after fn op st rc arch="$WORK/history-archive.cvst"
  [[ "${LAB_HISTORY:-1}" == 1 ]] || return 0
  if [[ "$LAB_EXTERNAL" == 1 ]]; then check H history-recovery fail "BLOCKED: needs a QEMU guest"; return 0; fi
  HIST_TAG="hist$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  [[ -s "$SEC/history-phrase" ]] || { head -c 4096 /dev/urandom | tr -dc 'A-Za-z0-9' | cut -c1-28 > "$SEC/history-phrase"; chmod 0600 "$SEC/history-phrase"; }
  [[ -s "$SEC/log-pass-new" ]] || { head -c 4096 /dev/urandom | tr -dc 'A-Za-z0-9' | cut -c1-32 > "$SEC/log-pass-new"; chmod 0600 "$SEC/log-pass-new"; }
  c="$(hist_login)"; [[ $c == 200 ]] || { check H history-recovery fail "BLOCKED: admin login $c"; return 0; }
  # 1. history on, marker traffic (one allowed, the rest default-denied).
  c="$(api PUT /api/logs/retention '{"enabled":true,"retentionDays":30}' | tee "$EV/H-01-enable.txt" | code)"
  [[ $c == 200 ]] || { check H history-enable fail "PUT /api/logs/retention enabled=true: $c $(body < "$EV/H-01-enable.txt" | head -c 200)"; return 0; }
  for n in $(seq 1 12); do through_proxy "http://$HIST_TAG-$n.example.org/p$n" > /dev/null; done
  for _ in $(seq 1 30); do before="$(hist_markers)"; [[ "$(hist_total "$before")" -ge 12 ]] && break; sleep 2; done
  printf '%s\n' "$before" > "$EV/H-02-markers-before.json"
  tot="$(hist_total "$before")"
  [[ "$tot" -ge 12 ]] && check H history-recorded pass "$tot marker requests ($HIST_TAG-*) in the history store" \
    || { check H history-recorded fail "only $tot of 12 marker requests reached the history store"; return 0; }
  # 2. export through the admin API, to the RUNNER.
  c="$(curl -ksS -m 300 -X POST "$UI/api/logs/history/export" -H "Origin: $UI" -H 'Content-Type: application/json' -b "$JAR" \
        --data-binary @<(printf '{"archivePhrase":"%s"}' "$(cat "$SEC/history-phrase")") -o "$arch" -D "$EV/H-03-export-headers.txt" -w '%{http_code}')"
  if [[ $c == 200 && -s "$arch" && "$(head -c 8 "$arch")" == CVRTST01 ]]; then
    check H history-export pass "POST /api/logs/history/export → $(stat -c %s "$arch") bytes, encrypted stream (CVRTST01), sha256 $(sha256sum "$arch" | cut -c1-16)…, held on the runner"
  else check H history-export fail "http $c, $(stat -c %s "$arch" 2>/dev/null || echo 0) bytes"; return 0; fi
  if strings "$arch" | grep -q "$HIST_TAG"; then check H history-export-opaque fail "marker host readable in the archive"
  else check H history-export-opaque pass "no marker host is readable in the archive bytes"; fi
  # 3. backup (it omits the history store by design).
  op="$(api POST /api/backups '{"encrypt":false}' | tee "$EV/H-04-backup.txt" | body)"
  fn="$(printf '%s' "$op" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("filename",""))' 2>/dev/null || true)"
  op="$(printf '%s' "$op" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("opId",""))' 2>/dev/null || true)"
  st=""; for _ in $(seq 1 90); do st="$(api GET "/api/backups/operations/$op" | body | python3 -c 'import json,sys;print(json.load(sys.stdin).get("state",""))' 2>/dev/null || true)"
    case "$st" in succeeded|failed) break ;; esac; sleep 2; done
  [[ "$st" == succeeded && -n "$fn" ]] || { check H history-backup fail "backup op=${op:-none} state=${st:-none}"; return 0; }
  check H history-backup pass "$fn"
  # 4. the source is DESTROYED: stack down, the data volume deleted; restore
  #    into a fresh volume; the log passphrase ROTATED.
  rc=0; gpriv --timeout 1800 > "$EV/H-05-destroy-restore.txt" 2>&1 <<EOS || rc=$?
cd /srv/culvert || exit 90
docker compose down 2>&1; echo "down-rc=\$?"
vol=\$(docker volume ls -q | grep -E '(^|_)proxy-data\$' | head -1); echo "volume=\$vol"
docker volume rm "\$vol" 2>&1; echo "volume-rm-rc=\$?"
docker volume inspect "\$vol" >/dev/null 2>&1 && echo VOLUME-STILL-PRESENT || echo VOLUME-GONE
cp -p .env .env.lab-history-orig
sed -i '/^CULVERT_LOG_PASSPHRASE=/d' .env; echo "CULVERT_LOG_PASSPHRASE=$(cat "$SEC/log-pass-new")" >> .env; echo "log-passphrase-rotated"
docker compose --profile cli run --rm -T cli --restore /backup/$fn --mode full --confirm 2>&1; r=\$?; echo "commit-rc=\$r"
docker compose -f docker-compose.yml \$([ -f docker-compose.maint-agent.yml ] && echo -f docker-compose.maint-agent.yml) up -d 2>&1; echo "up-rc=\$?"  # both files, as the runbook says: the second mounts the agent socket
exit \$r
EOS
  hist_wait_up || true
  if [[ $rc == 0 ]] && grep -qx VOLUME-GONE "$EV/H-05-destroy-restore.txt" && grep -q '^up-rc=0' "$EV/H-05-destroy-restore.txt"; then
    check H history-source-destroyed pass "data volume deleted ($(grep -m1 '^volume=' "$EV/H-05-destroy-restore.txt")), restored from $fn into a fresh volume, CULVERT_LOG_PASSPHRASE rotated"
  else check H history-source-destroyed fail "rc $rc: $(grep -E '^(down|volume|volume-rm|commit|up)-rc=|VOLUME-' "$EV/H-05-destroy-restore.txt" | tr '\n' ' ')"; return 0; fi
  c="$(hist_login)"
  after="$(hist_markers)"; printf '%s\n' "$after" > "$EV/H-06-markers-after-restore.json"
  local hon; hon="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("history"))' "$after" 2>/dev/null)"
  if [[ $c == 200 && "$hon" == True && "$(hist_total "$after")" == 0 ]]; then check H history-gone-after-restore pass "after the restore the history store is ON (new key) and holds 0 marker records — the backup does not carry history"
  else check H history-gone-after-restore fail "login $c, history=$hon, markers $(hist_total "$after") (want history=True, 0)"; return 0; fi
  # 5. import the RUNNER's archive. Refused while the proxy holds the store;
  #    a wrong archive passphrase writes nothing; then offline: verify, import.
  hist_upload "$arch" /srv/culvert/lab-history.cvst > "$EV/H-07-upload.txt" 2>&1 || true
  grep -q "$(sha256sum "$arch" | cut -d' ' -f1)" "$EV/H-07-upload.txt" || { check H history-upload fail "archive hash differs in the guest"; return 0; }
  local imp="docker compose --profile cli run --rm -T -v /srv/culvert/lab-history.cvst:/backup/lab-history.cvst:ro -e CULVERT_HISTORY_PASSPHRASE cli --history-import /backup/lab-history.cvst"
  rc=0; gpriv --timeout 900 > "$EV/H-08-import-live.txt" 2>&1 <<EOS || rc=$?
cd /srv/culvert || exit 90
CULVERT_HISTORY_PASSPHRASE='$(cat "$SEC/history-phrase")' $imp --confirm 2>&1; echo "import-live-rc=\$?"
EOS
  # The oracle names the LOCK refusal, not just a non-zero exit: any other
  # failure (an unreadable archive, a bad mount) also exits non-zero and must
  # not read as "refused while running".
  if grep -qE '^import-live-rc=[1-9]' "$EV/H-08-import-live.txt" && ! grep -q '^imported=' "$EV/H-08-import-live.txt" \
     && grep -q 'locked by another Culvert process' "$EV/H-08-import-live.txt"; then
    check H history-import-refused-while-running pass "refused against the running proxy: $(grep -m1 'locked by another Culvert process' "$EV/H-08-import-live.txt" | head -c 160)"
  else check H history-import-refused-while-running fail "$(tail -3 "$EV/H-08-import-live.txt" | tr '\n' ' ')"; fi
  rc=0; gpriv --timeout 1800 > "$EV/H-09-import-offline.txt" 2>&1 <<EOS || rc=$?
cd /srv/culvert || exit 90
docker compose down 2>&1; echo "down-rc=\$?"
echo "--- wrong archive passphrase"
CULVERT_HISTORY_PASSPHRASE='wrong-passphrase-0000' $imp --confirm 2>&1; echo "wrong-rc=\$?"
echo "--- dry run"
CULVERT_HISTORY_PASSPHRASE='$(cat "$SEC/history-phrase")' $imp 2>&1; echo "dry-rc=\$?"
echo "--- import"
CULVERT_HISTORY_PASSPHRASE='$(cat "$SEC/history-phrase")' $imp --confirm 2>&1; r=\$?; echo "import-rc=\$r"
rm -f /srv/culvert/lab-history.cvst
docker compose -f docker-compose.yml \$([ -f docker-compose.maint-agent.yml ] && echo -f docker-compose.maint-agent.yml) up -d 2>&1; echo "up-rc=\$?"  # both files, as the runbook says: the second mounts the agent socket
exit \$r
EOS
  hist_wait_up || true
  # Same rule: the refusal must be the DECRYPT failure, not any failure.
  grep -qE '^wrong-rc=[1-9]' "$EV/H-09-import-offline.txt" && ! sed -n '/wrong archive/,/dry run/p' "$EV/H-09-import-offline.txt" | grep -q '^imported=' \
    && sed -n '/wrong archive/,/dry run/p' "$EV/H-09-import-offline.txt" | grep -q 'invalid passphrase or tampered' \
    && check H history-wrong-passphrase pass "wrong archive passphrase refused ($(sed -n '/wrong archive/,/dry run/p' "$EV/H-09-import-offline.txt" | grep -m1 -o 'backup decrypt failed[^)]*)')), nothing imported" \
    || check H history-wrong-passphrase fail "$(sed -n '/wrong archive/,/dry run/p' "$EV/H-09-import-offline.txt" | tail -3 | tr '\n' ' ')"
  grep -q '^dry-rc=0' "$EV/H-09-import-offline.txt" && grep -q 'nothing written' "$EV/H-09-import-offline.txt" \
    && check H history-import-dry-run pass "$(grep -m1 'history archive OK' "$EV/H-09-import-offline.txt")" \
    || check H history-import-dry-run fail "$(grep -E '^dry-rc=' "$EV/H-09-import-offline.txt")"
  c="$(hist_login)"
  after="$(hist_markers)"; printf '%s\n' "$after" > "$EV/H-10-markers-after-import.json"
  local same; same="$(python3 -c 'import json,sys;a=json.loads(sys.argv[1]);b=json.loads(sys.argv[2]);print(int(bool(a.get("rows")) and a.get("rows")==b.get("rows")))' "$before" "$after" 2>/dev/null || echo 0)"
  if [[ $rc == 0 && $c == 200 && "$same" == 1 ]]; then
    check H history-recovered pass "$(grep -m1 '^imported=' "$EV/H-09-import-offline.txt"); the $(hist_total "$after") marker records read back identical (ts, host, status, method) under the ROTATED log key"
  else check H history-recovered fail "import rc $rc, login $c, markers $(hist_total "$after") of $(hist_total "$before"), identical=$same ($(grep -E '^(imported|import-rc|up-rc)=' "$EV/H-09-import-offline.txt" | tr '\n' ' '))"; fi
  local ok; ok="$(through_proxy http://example.com/)"
  [[ "$ok" == 200 ]] && check H history-enforcement pass "example.com 200 through the proxy after the recovery" || check H history-enforcement fail "example.com $ok"
  redact_tree
}

# ── Disk pressure (ASTRA 7c round, item 3) ───────────────────────────────────
# Root-filesystem BLOCK exhaustion, then INODE exhaustion, on the disposable
# lab guest, each followed by recovery. The expected behaviour is the product's
# own contract, not an assumption:
#   enforcement  policy is in memory: allowed stays 200, blocked stays 403;
#                a blocked destination answering 200 is a FAIL (fail-open)
#   ClamAV       appliance posture av_unavailable=closed (scanning-outage-
#                posture.md): a body clamd cannot scan is REFUSED (403), never
#                forwarded unscanned — EICAR answering 200 is a FAIL; a clean
#                body may be 200 or a 403 refusal (recorded, not judged)
#   proxy        no crash: the container's restart count and start time do not
#                change (F-DISK-1)
#   backup       backup.go writes <out>.tmp and renames on success, removing the
#                temp file on failure: a failed backup leaves NO new file, no
#                .tmp, and every existing archive byte-identical
#   app update   the agent refuses before any pull when space is short
#                (preflight_space), or fails and rolls back; never a stopped
#                stack or a half-applied image
#   OS update    culvert-os-update fails cleanly: stack serving, dpkg --audit
#                empty, Docker packages still held
#   recovery     once space returns, without a restart: /ready 200 with clamav
#                ok, enforcement, EICAR blocked by ClamAV, a backup succeeds and
#                is a valid archive
# Bounded: the fill is posix_fallocate (real ext4 blocks, no data written), so
# the host's sparse disk file barely grows; the phase aborts if the host has
# less than LAB_PRESSURE_MIN_HOST_FREE_GB free or the disk file grows more than
# LAB_PRESSURE_MAX_HOST_GROWTH_MB. Never pointed at a shared datastore: the
# guest disk is the lab's own disposable copy.
LAB_PRESSURE_MIN_HOST_FREE_GB="${LAB_PRESSURE_MIN_HOST_FREE_GB:-10}"
LAB_PRESSURE_MAX_HOST_GROWTH_MB="${LAB_PRESSURE_MAX_HOST_GROWTH_MB:-3072}"
p_host_alloc_mb() { local f; for f in "$WORK/disk.raw" "$WORK/overlay.qcow2"; do [[ -e "$f" ]] && { du -B1M "$f" | cut -f1; return; }; done; echo 0; }
p_host_free_gb() { df -BG --output=avail "$WORK" | tail -1 | tr -dc 0-9; }
p_bounded() { local grown=$(( $(p_host_alloc_mb) - P_ALLOC0 ))
  if (( grown > LAB_PRESSURE_MAX_HOST_GROWTH_MB )) || (( $(p_host_free_gb) < LAB_PRESSURE_MIN_HOST_FREE_GB / 2 )); then
    check P host-bound fail "host disk file grew ${grown} MiB (cap $LAB_PRESSURE_MAX_HOST_GROWTH_MB) or host free $(p_host_free_gb) GiB; aborting the pressure phase"; return 1; fi; }
p_clean_url() { local n; n="$(python3 -c 'import time; print(time.time_ns())')"
  printf 'culvert pressure clean body %s\n' "$n" > "$WORK/eicar-origin/c$n.txt"; echo "http://10.0.2.2:$LAB_EICAR_PORT/c$n.txt"; }
p_proxy_identity() { groot 'docker inspect -f "{{.RestartCount}} {{.State.StartedAt}} {{.State.Status}}" culvert; docker inspect -f "{{.State.Status}} {{.State.Health.Status}}" culvert-clamav' 60 2>/dev/null | tr '\r' ' ' | grep -E '^[0-9]+ |^(running|exited|restarting)' | tr '\n' ' '; }
# p_sample PHASE TAG — one observation: traffic, AV verdicts, readiness, health.
# p_enforced ALLOWED BLOCKED — "yes" when enforcement is intact: the blocked
# destination is 403, and the allowed one is either delivered (200) or refused
# BECAUSE the AV engine cannot scan it (av_unavailable=closed). The second
# case is what a ClamAV outage must look like since bad788e5 (owner review
# 5478346473): a clean verdict cached before the fault is no longer trusted,
# so the allowed page is re-scanned and refused like any other body. On
# 72c827b7 the same probe answered 200 from that pre-fault cache — the bypass
# the review removed — and this check had encoded it as "unchanged". A 403 on
# the allowed destination for any OTHER reason (a policy block) still fails.
p_enforced() {
  [[ "$2" == 403 ]] || { echo no; return; }
  [[ "$1" == 200 ]] && { echo yes; return; }
  if [[ "$1" == 403 ]] && curl -sS -m 20 -x "$P" http://example.com/ 2>/dev/null | grep -q 'antivirus scanning is currently unavailable'; then
    echo yes; return
  fi
  echo no; }
p_sample() { local ph="$1" tag="$2" a b e c rc hc row
  a="$(through_proxy http://example.com/)"; b="$(through_proxy http://example.org/)"
  e="$(eicar_verdict)"
  c="$(curl -sS -m 6 -x "$P" -o "$WORK/p-clean.body" -w '%{http_code}' "$(p_clean_url)" 2>/dev/null || echo 000)"
  [[ "$c" == 2* ]] || c="$c:$(head -c 60 "$WORK/p-clean.body" 2>/dev/null | tr -d '\n')"
  rc="$(curl -sS -m 4 -o "$WORK/p-ready.json" -w '%{http_code}' "$P/ready" 2>/dev/null || echo 000)"
  hc="$(curl -sS -m 4 -o /dev/null -w '%{http_code}' "$P/health" 2>/dev/null || echo 000)"
  row="$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); c=d.get("checks",d); bad=[]
for k,v in sorted(c.items()):
    st=v.get("status") if isinstance(v,dict) else v
    if st!="ok": bad.append(k+"="+str(st))
print(" ".join(bad))' "$WORK/p-ready.json" 2>/dev/null || echo unreadable)"
  python3 -c 'import json,sys
k=("phase","tag","t","allowed","blocked","eicar","clean","ready","not_ok_rows","health")
print(json.dumps(dict(zip(k,sys.argv[1:]))))' "$ph" "$tag" "$(date -u +%FT%TZ)" "$a" "$b" "$e" "$c" "$rc" "$row" "$hc" >> "$EV/P-samples.jsonl"
  # space-free for `set --`: the EICAR verdict carries a body head
  echo "$a $b ${e%%:*} ${c%%:*} $rc $hc"; }
# p_burst PHASE TAG N — N back-to-back EICAR + clean pairs right after a fill,
# so a transient verdict is observed rather than sampled past.
p_burst() { local i; for i in $(seq 1 "$3"); do p_sample "$1" "$2.$i" > /dev/null; done; }
# p_logs NAME SINCE — the proxy's scan/AV lines and the sidecar's log for the
# phase. Read through the tmpfs-staged console transport, so it works while
# the root disk is full; the output is evidence, not a verdict.
p_logs() { groot "docker logs --since '$2' culvert 2>&1 | grep -E 'SCAN|AV_|av_unavailable|ClamAV|clamav|SecurityScan|antivirus|BLOCKED|ENOSPC|no space|10[.]0[.]2[.]2' | tail -n 600; echo '=== culvert-clamav'; docker logs --since '$2' culvert-clamav 2>&1 | tail -n 300; echo '=== df'; df -B1 / | tail -1; df -i / | tail -1" 300 > "$EV/P-$1-logs.txt" 2>&1 || true; }
p_backup_inventory() { groot 'mp=$(docker volume inspect -f "{{.Mountpoint}}" "$(docker volume ls -q | grep -m1 -E "(^|_)culvert-backups$")"); echo "mp=$mp"; cd "$mp" && find . -maxdepth 1 -type f -printf "%f %s\n" | sort; echo ---; find . -maxdepth 1 -type f ! -name "*.tmp" -exec sha256sum {} + | sort' 120 2>/dev/null; }
p_backup() { local out="$1" op st jar; api POST /api/backups '{"encrypt":false}' > "$out" 2>&1 || true
  # POST /api/backups answers {"opId": …} (camelCase; the agent's own record
  # says op_id). Reading only op_id never polled, and a backup that finished
  # in the background read as "archive set changed" (run 37948667525).
  op="$(body < "$out" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("opId") or d.get("op_id") or "")' 2>/dev/null || true)"; st=""
  if [[ -n "$op" ]]; then for _ in $(seq 1 90); do st="$(api GET "/api/backups/operations/$op" | body | python3 -c 'import json,sys;print(json.load(sys.stdin).get("state",""))' 2>/dev/null || true)"
    case "$st" in succeeded|failed|cancelled) break ;; esac; sleep 5; done; api GET "/api/backups/operations/$op" >> "$out" 2>&1 || true; fi
  echo "op=${op:-none} state=${st:-none} http=$(code < "$out" | head -1)"; }
p_login() { : > "$JAR"; api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$(cat "$SEC/admin-pass")\"}" | code; }
p_os_update() { groot 'culvert-os-update os > /run/culvert-lab-osu.log 2>&1; echo "osu-rc=$?"; grep -E "culvert-lab-pkgfix|^(E|W):|No space|dpkg: error" /run/culvert-lab-osu.log | head -n 20; tail -n 15 /run/culvert-lab-osu.log; echo "fixture=$(dpkg-query -W -f="\${Status} \${Version}" culvert-lab-pkgfix 2>/dev/null)"; echo "dpkg-journal=$(ls /var/lib/dpkg/updates 2>/dev/null | grep -c "^[0-9]")"; echo "dpkg-audit=[$(dpkg --audit 2>&1 | head -c 300)]"; echo "not-installed-ok=$(dpkg -l | awk "NR>5 && \$1 !~ /^(ii|hi|rc)\$/" | wc -l)"; echo "holds=$(dpkg-query -W -f="\${Package} \${db:Status-Want}\n" 2>/dev/null | awk "\$2==\"hold\"{print \$1}" | tr "\n" " ")"' 1800 2>&1; }
p_app_update() { local U="$LAB_UPDATE_DIR" ph="$1" rc=0
  { printf '%s' "$AGENT_LIB"; embed apply.json "$U/apply-pressure-$ph.json"
    printf '%s\n' 'running' 'r=$(agent -X POST --data-binary @/run/culvert-lab-upd/apply.json http://agent/v1/upgrades/apply); echo "$r" | tail -c 1500' \
                  'op=$(printf "%s" "$r" | opid); echo "op=$op"; [ -n "$op" ] && wait_op "$op"' 'echo "after:"' 'running'; } | gpriv --timeout 2100 2>&1 || rc=$?; echo "rc=$rc"; }
# Package-write fixture (ASTRA, #1528: "partial package-write failure" was
# unqualified — with the snapshot already newest, `culvert-os-update os` made 0
# package actions under pressure, so dpkg never wrote anything). A harmless
# local package, culvert-lab-pkgfix, is installed at 1.0 and offered at 2.0 from
# a file: repository, so `culvert-os-update os` (apt-get upgrade from every
# configured source) really unpacks a package under pressure. 2.0 carries a
# 64 MiB blob and 3000 small files: more than the pkg* phases leave free, so the
# unpack fails PART WAY, after dpkg has started writing. Built inside the
# disposable guest; the OVA is untouched. Removed at the end of the scenario.
LAB_PKGFIX_DIR=/var/lib/culvert-lab-pkgfix
p_pkg_setup() { groot "set -e; d=$LAB_PKGFIX_DIR; rm -rf \$d; mkdir -p \$d/repo
mk() { v=\$1; r=\$d/build-\$v; mkdir -p \$r/DEBIAN \$r/usr/share/culvert-lab-pkgfix
  printf 'Package: culvert-lab-pkgfix\nVersion: %s\nArchitecture: all\nMaintainer: lab <lab@invalid>\nDescription: Culvert lab package-write fixture (inert data only)\n' \$v > \$r/DEBIAN/control
  echo \$v > \$r/usr/share/culvert-lab-pkgfix/version
  if [ \$v = 2.0 ]; then head -c 67108864 /dev/urandom > \$r/usr/share/culvert-lab-pkgfix/blob
    mkdir -p \$r/usr/share/culvert-lab-pkgfix/many; for i in \$(seq 1 3000); do echo \$i > \$r/usr/share/culvert-lab-pkgfix/many/f\$i; done; fi
  dpkg-deb -Znone --root-owner-group --build \$r \$d/repo/culvert-lab-pkgfix_\${v}_all.deb >/dev/null; rm -rf \$r; }
mk 1.0; mk 2.0
cd \$d/repo; f=culvert-lab-pkgfix_2.0_all.deb
{ dpkg-deb -f \$f; echo \"Filename: ./\$f\"; echo \"Size: \$(stat -c %s \$f)\"; echo \"SHA256: \$(sha256sum \$f | cut -d' ' -f1)\"; echo; } > Packages
echo 'deb [trusted=yes] file:$LAB_PKGFIX_DIR/repo ./' > /etc/apt/sources.list.d/culvert-lab-pkgfix.list
apt-get update -qq; dpkg -i \$d/repo/culvert-lab-pkgfix_1.0_all.deb >/dev/null
echo fixture=\$(dpkg-query -W -f='\${Status} \${Version}' culvert-lab-pkgfix); apt-cache policy culvert-lab-pkgfix | grep -E 'Installed|Candidate' | tr -s ' ' | tr '\n' ' '; echo
ls -l \$d/repo" 900 > "$EV/P-pkgfix-setup.txt" 2>&1 || true
  if grep -q 'fixture=install ok installed 1.0' "$EV/P-pkgfix-setup.txt" && grep -q 'Candidate: 2.0' "$EV/P-pkgfix-setup.txt"; then
    check P pkgfix-setup pass "culvert-lab-pkgfix 1.0 installed, 2.0 offered (64 MiB blob + 3000 files) from a local file: repository"
  else check P pkgfix-setup fail "fixture not ready: $(tail -3 "$EV/P-pkgfix-setup.txt" | tr '\n' ' ')"; return 1; fi; }
# p_pkg_arm — back to 1.0 before a phase so 2.0 is pending again.
p_pkg_arm() { groot "dpkg -i $LAB_PKGFIX_DIR/repo/culvert-lab-pkgfix_1.0_all.deb >/dev/null 2>&1; echo fixture=\$(dpkg-query -W -f='\${Status} \${Version}' culvert-lab-pkgfix)" 300 2>&1 | grep -m1 '^fixture='; }
p_pkg_teardown() { groot "dpkg -P culvert-lab-pkgfix >/dev/null 2>&1; rm -f /etc/apt/sources.list.d/culvert-lab-pkgfix.list; rm -rf $LAB_PKGFIX_DIR; apt-get update -qq; echo removed=\$(dpkg-query -W culvert-lab-pkgfix >/dev/null 2>&1 && echo no || echo yes)" 600 > "$EV/P-pkgfix-teardown.txt" 2>&1 || true
  check P pkgfix-teardown "$(grep -q removed=yes "$EV/P-pkgfix-teardown.txt" && echo pass || echo fail)" "fixture package, source and repository removed from the disposable guest"; }
# p_pkg_judge NAME OSU WHEN — the package write, under pressure or after recovery.
p_pkg_judge() { local name="$1" osu="$2" when="$3" rc fx reached
  rc="$(grep -m1 -oE '^osu-rc=[0-9]+' <<<"$osu" | cut -d= -f2)"; fx="$(grep -m1 '^fixture=' <<<"$osu" | cut -d= -f2-)"
  reached="$(grep -cE 'Unpacking culvert-lab-pkgfix|culvert-lab-pkgfix_2.0_all.deb' <<<"$osu" || true)"
  local audit_ok=0; grep -q '^dpkg-audit=\[\]$' <<<"$osu" && grep -q '^not-installed-ok=0$' <<<"$osu" && grep -q '^dpkg-journal=0$' <<<"$osu" && audit_ok=1
  if [[ "$when" == pressure ]] && grep -q '^dpkg-journal=[1-9]' <<<"$osu"; then
    check P "$name-pkg-write" info "dpkg wrote part of 2.0, failed (osu-rc=$rc) and could not record it: left INTERRUPTED ($(grep -m1 '^dpkg-journal=' <<<"$osu") journal entries); fixture=[$fx]; repair judged by $name-pkg-recovered"; return; fi
  if [[ "$when" == recovered ]]; then
    [[ "$rc" == 0 && "$fx" == "install ok installed 2.0" && $audit_ok == 1 ]] \
      && check P "$name-pkg-recovered" pass "space back: culvert-os-update os rc=0, culvert-lab-pkgfix now 2.0, dpkg audit empty" \
      || check P "$name-pkg-recovered" fail "after release: osu-rc=$rc fixture=[$fx] audit_ok=$audit_ok ($(grep -E 'dpkg-audit' <<<"$osu" | head -c 200))"
    return; fi
  if [[ "$reached" == 0 ]]; then
    check P "$name-pkg-write" info "dpkg never reached the package (osu-rc=$rc; apt stopped first: $(grep -m1 -E '^(E|W):' <<<"$osu" | head -c 160)); fixture=[$fx]"
  elif [[ "$rc" != 0 && "$fx" == "install ok installed 1.0" && $audit_ok == 1 ]]; then
    check P "$name-pkg-write" pass "dpkg started writing 2.0 and failed (osu-rc=$rc: $(grep -m1 -iE 'no space|cannot copy|failed to write|error processing' <<<"$osu" | head -c 140)); rolled back to 1.0 fully installed, dpkg audit empty"
  elif [[ "$rc" == 0 && "$fx" == "install ok installed 2.0" && $audit_ok == 1 ]]; then
    check P "$name-pkg-write" info "the package write SUCCEEDED under pressure (root's reserve); 2.0 fully installed, audit empty"
  else check P "$name-pkg-write" fail "osu-rc=$rc fixture=[$fx] audit_ok=$audit_ok — a package left part-written or a failure reported as success ($(grep -E '^dpkg-audit' <<<"$osu" | head -c 200))"; fi; }
# p_phase NAME FILLCMD — fill, observe, exercise backup/updates, release, recover.
p_phase() { local name="$1" fill="$2" s id0 id1 inv0 inv1 bk osu up ok lc
  local since; since="$(date -u -d '-2 min' +%FT%TZ)"
  id0="$(p_proxy_identity)"; inv0="$(p_backup_inventory)"; printf '%s\n' "$inv0" > "$EV/P-$name-backups-before.txt"
  # Backstop: a transient timer (state in /run, tmpfs) frees the space even if
  # the full disk takes the SSH path with it; cancelled by the normal release.
  groot 'systemctl stop culvert-pressure-release.timer 2>/dev/null; systemd-run --quiet --unit=culvert-pressure-release --on-active=5400 /bin/rm -rf /var/lib/culvert-pressure && echo backstop=armed' 60 > "$EV/P-$name-backstop.txt" 2>&1 || true
  grep -q backstop=armed "$EV/P-$name-backstop.txt" || { check P "$name-filled" blocked "release backstop timer could not be armed; phase not run"; return 1; }
  [[ -n "${P_PKG:-}" ]] && echo "armed $(p_pkg_arm)" > "$EV/P-$name-pkgfix-arm.txt"
  groot "$fill" 3600 > "$EV/P-$name-fill.txt" 2>&1 || true
  check P "$name-filled" info "$(grep -E '^(filled|files)' "$EV/P-$name-fill.txt" | tr '\n' ' ') host disk file +$(( $(p_host_alloc_mb) - P_ALLOC0 )) MiB"
  p_bounded || return 1
  groot 'df -B1 / | tail -1; df -i / | tail -1' 60 > "$EV/P-$name-df.txt" 2>&1 || true
  # Observations: a burst right after the fill (a transient verdict must be
  # seen, not sampled past), then once the stack has had time to hit it.
  # Every row of the phase counts: blocked must stay 403 and EICAR must never
  # be DELIVERED (av, a 403 refusal, a 5xx or no answer all keep the body
  # away from the client).
  p_burst "$name" b0 6
  for t in 0 60 120; do (( t == 0 )) || sleep 60; p_sample "$name" "+$t" > /dev/null; done
  p_logs "$name" "$since"
  local fails; fails="$(python3 - "$EV/P-samples.jsonl" "$name" <<'PY2'
import json, sys
out = []
for l in open(sys.argv[1]):
    d = json.loads(l)
    if d["phase"] != sys.argv[2] or not (d["tag"].startswith("+") or d["tag"].startswith("b0.")): continue
    if d["blocked"] != "403": out.append(f"blocked={d['blocked']}@{d['tag']}")
    if d["eicar"].startswith("2"): out.append(f"eicar-delivered={d['eicar'][:3]}@{d['tag']}")
print(" ".join(out))
PY2
)"
  lc="$(p_login)"
  [[ -z "$fails" ]] && check P "$name-enforcement" pass "blocked 403 throughout, EICAR never delivered ($(python3 -c 'import json,sys,collections
rows=[json.loads(l) for l in open(sys.argv[1])]; rows=[d for d in rows if d["phase"]==sys.argv[2] and (d["tag"][0]=="+" or d["tag"].startswith("b0."))]
c=collections.Counter((d["eicar"][:3] if d["eicar"]!="av" else "av", d["clean"][:3]) for d in rows)
print(len(rows), "samples; eicar/clean:", ", ".join(f"{e}/{k} x{n}" for (e,k),n in sorted(c.items())))' "$EV/P-samples.jsonl" "$name")); admin login $lc" \
    || check P "$name-enforcement" fail "$fails (see P-$name-logs.txt)"
  # Readiness truth: a sample whose clean body was refused as AV-unavailable
  # must have /ready non-200 with the clamav row failing (operators are told
  # to watch /ready for this outage; PING-only readiness said ok throughout
  # the inode phase of lab run 37957097250).
  local rt; rt="$(python3 - "$EV/P-samples.jsonl" "$name" <<'PY2'
import json, sys
n = bad = 0; out = []
refused = lambda d: "antivirus scanning is currently unavailable" in d["clean"]
rows = [d for d in map(json.loads, open(sys.argv[1]))
        if d["phase"] == sys.argv[2] and (d["tag"].startswith("+") or d["tag"].startswith("b0."))]
# judged only while the outage outlasts the /ready read: the NEXT sample is
# still refused (a 1 s transient can legitimately be over by the read)
for d, nxt in zip(rows, rows[1:]):
    if not (refused(d) and refused(nxt)): continue
    n += 1
    if d["ready"] == "200" or "clamav=" not in d["not_ok_rows"]:
        bad += 1; out.append(f"{d['tag']}:ready={d['ready']}[{d['not_ok_rows']}]")
print(f"{n} {bad} " + " ".join(out[:6]))
PY2
)"
  set -- $rt
  if [[ "${1:-0}" == 0 ]]; then check P "$name-readiness-truth" info "no sample refused content as AV-unavailable"
  elif [[ "$2" == 0 ]]; then check P "$name-readiness-truth" pass "$1 sample(s) refused content as AV-unavailable; /ready was non-200 with the clamav row failing in every one"
  else check P "$name-readiness-truth" fail "$2 of $1 AV-unavailable sample(s) had /ready reporting clamav ok: ${*:3}"; fi
  # backup under pressure: must fail cleanly
  bk="$(p_backup "$EV/P-$name-backup.txt")"; inv1="$(p_backup_inventory)"; printf '%s\n' "$inv1" > "$EV/P-$name-backups-after.txt"
  if grep -q '\.tmp ' <<<"$inv1"; then check P "$name-backup-clean" fail "$bk; a .tmp archive was left behind"
  elif [[ "$(sed -n '/^---$/,$p' <<<"$inv0")" != "$(sed -n '/^---$/,$p' <<<"$inv1")" ]]; then
    if [[ "$bk" == *state=succeeded* ]]; then
      local pv; pv="$(groot "mp=\$(docker volume inspect -f '{{.Mountpoint}}' \"\$(docker volume ls -q | grep -m1 -E '(^|_)culvert-backups\$')\"); f=\$(ls -t \$mp | grep -E '^culvert-backup-.*[.]tar[.]gz\$' | head -1); echo \"newest=\$f\"; tar -tzf \"\$mp/\$f\" > /dev/null 2>&1 && echo archive=valid || echo archive=INVALID" 300 2>&1 | grep -E '^(newest|archive)=' | tr '\n' ' ')"
      if [[ "$pv" == *archive=valid* && "$(diff <(sed -n '/^---$/,$p' <<<"$inv0") <(sed -n '/^---$/,$p' <<<"$inv1") | grep -c '^<')" == 0 ]]; then
        check P "$name-backup-clean" info "$bk: the backup SUCCEEDED under pressure and the new archive is complete ($pv); every existing archive byte-identical"
      else check P "$name-backup-clean" fail "$bk: reported success under pressure but $pv; existing archives changed: $(diff <(sed -n '/^---$/,$p' <<<"$inv0") <(sed -n '/^---$/,$p' <<<"$inv1") | grep -c '^<')"; fi
    else check P "$name-backup-clean" fail "$bk; archive set changed: $(diff <(sed -n '/^---$/,$p' <<<"$inv0") <(sed -n '/^---$/,$p' <<<"$inv1") | tr '\n' ' ' | head -c 300)"; fi
  else check P "$name-backup-clean" pass "$bk; no new archive, no .tmp, $(sed -n '/^---$/,$p' <<<"$inv0" | grep -c ' ') existing archive(s) byte-identical"; fi
  # app update under pressure (signed fixture only exists in build mode)
  if [[ "${P_NO_APP:-0}" == 1 ]]; then check P "$name-app-update" info "not exercised in this phase (the blocks and inodes phases cover it); this phase targets the package write"
  elif [[ -n "${LAB_UPDATE_DIR:-}" && -f "${LAB_UPDATE_DIR}/apply-pressure-$name.json" ]]; then
    up="$(p_app_update "$name")"
    if grep -q '"deduped":true' <<<"$up"; then check P "$name-app-update" fail "the agent returned an EARLIER operation (deduped): nothing was exercised under pressure"; fi; printf '%s\n' "$up" > "$EV/P-$name-app-update.txt"
    local st0 img_b img_a; st0="$(grep -m1 '^op-state=' <<<"$up" || echo op-state=none)"
    img_b="$(grep -m1 '^running-image=' <<<"$up")"; img_a="$(grep '^running-image=' <<<"$up" | tail -1)"
    s="$(p_sample "$name" after-app-update)"; set -- $s
    local why; why="$(grep -oE 'preflight_space[^"]{0,120}|no space left[^"]{0,80}|"error":"[^"]{0,120}' <<<"$up" | head -1)"
    if [[ "$st0" == op-state=failed && "$img_b" == "$img_a" && "$(p_enforced "$1" "$2")" == yes ]]; then
      check P "$name-app-update" pass "failed with nothing changed: $st0 ($why); $img_a; traffic $1/$2"
    elif [[ "$st0" == op-state=none ]] && grep -qE '^HTTP [45][0-9][0-9]$' <<<"$up" && [[ "$img_b" == "$img_a" && "$(p_enforced "$1" "$2")" == yes ]]; then
      check P "$name-app-update" pass "refused before any change: $(grep -m1 -E '^HTTP ' <<<"$up") ($why); $img_a; traffic $1/$2"
    elif [[ "$st0" == op-state=succeeded && "$(p_enforced "$1" "$2")" == yes ]]; then
      P_APP_APPLIED=1; check P "$name-app-update" info "the update SUCCEEDED under pressure ($img_b -> $img_a); traffic $1/$2; rolled back after recovery"
    else check P "$name-app-update" fail "$st0 $img_b -> $img_a traffic $1/$2 (a failed update must leave the running image and enforcement unchanged)"; fi
  else check P "$name-app-update" blocked "no per-phase signed-update fixture in this leg (built only with the OVA build)"; fi
  # OS update under pressure
  # P_PRE_OSU: set the exact headroom right before the update (the stack
  # consumes inodes while the phase runs: 400 left at the fill were gone by
  # the update in run 38012314515, so apt failed before dpkg was reached).
  [[ -n "${P_PRE_OSU:-}" ]] && groot "$P_PRE_OSU" 600 > "$EV/P-$name-pre-osu.txt" 2>&1
  osu="$(p_os_update)"; printf '%s\n' "$osu" > "$EV/P-$name-os-update.txt"
  s="$(p_sample "$name" after-os-update)"; set -- $s
  # dpkg --audit cannot see an INTERRUPTED dpkg (unfinished journal entries in
  # /var/lib/dpkg/updates), after which apt refuses everything: run
  # 38016152802. That state is recorded here and its repair judged by
  # pkg-recovered; it is never a clean failure.
  if grep -q '^dpkg-journal=[1-9]' <<<"$osu" && grep -q 'docker-ce' <<<"$(grep '^holds=' <<<"$osu")" && [[ "$(p_enforced "$1" "$2")" == yes ]]; then
    check P "$name-os-update" info "$(grep -m1 '^osu-rc=' <<<"$osu"); dpkg left INTERRUPTED ($(grep -m1 '^dpkg-journal=' <<<"$osu") journal entries; apt refuses until dpkg --configure -a) — the repair is judged by $name-pkg-recovered; Docker still held, traffic $1/$2"
  elif grep -q '^dpkg-audit=\[\]$' <<<"$osu" && grep -q '^not-installed-ok=0$' <<<"$osu" && grep -q '^dpkg-journal=0$' <<<"$osu" && grep -q 'docker-ce' <<<"$(grep '^holds=' <<<"$osu")" && [[ "$(p_enforced "$1" "$2")" == yes ]]; then
    check P "$name-os-update" pass "$(grep -m1 '^osu-rc=' <<<"$osu"); dpkg consistent (audit empty, journal empty, no half-installed package), Docker still held, traffic $1/$2"
  else check P "$name-os-update" fail "$(grep -E '^(osu-rc|dpkg-audit|dpkg-journal|not-installed-ok|holds|fixture)=' <<<"$osu" | tr '\n' ' ') traffic $1/$2"; fi
  [[ -n "${P_PKG:-}" ]] && p_pkg_judge "$name" "$osu" pressure
  # release and recover without a restart
  groot 'systemctl stop culvert-pressure-release.timer 2>/dev/null; rm -rf /var/lib/culvert-pressure; sync; df -B1 / | tail -1; df -i / | tail -1; echo released=$([ -e /var/lib/culvert-pressure ] && echo no || echo yes)' 3600 > "$EV/P-$name-release.txt" 2>&1 || true
  grep -q 'released=yes' "$EV/P-$name-release.txt" || check P "$name-release" fail "the release over SSH did not complete (see P-$name-release.txt); the guest's backstop timer frees the space"
  ok=0; for _ in $(seq 1 60); do ready_clamav_ok && rec_traffic && [[ "$(eicar_verdict)" == av ]] && { ok=1; break; }; sleep 5; done
  s="$(p_sample "$name" recovered)"
  # Docker must still be held once space is back (a failed OS update must
  # never leave the engine unheld); read from dpkg's status, no temp file.
  local hh; hh="$(groot 'dpkg-query -W -f="\${Package} \${db:Status-Want}\n" | awk "\$2==\"hold\"{print \$1}" | tr "\n" " "' 120 2>/dev/null)"
  [[ "$hh" == *docker-ce\ * ]] || ok=0
  [[ $ok == 1 ]] && check P "$name-recovered" pass "space released; /ready 200 with clamav ok, enforcement, EICAR blocked by ClamAV ($s); held: $hh" \
    || check P "$name-recovered" fail "within 300 s of release: $s; held: [$hh]"
  if [[ -n "${P_PKG:-}" ]]; then osu="$(p_os_update)"; printf '%s\n' "$osu" > "$EV/P-$name-os-update-recovered.txt"; p_pkg_judge "$name" "$osu" recovered; fi
  if [[ "${P_APP_APPLIED:-0}" == 1 ]]; then P_APP_APPLIED=0; local rb rc=0
    rb="$({ printf '%s' "$AGENT_LIB"; embed rollback.json "$LAB_UPDATE_DIR/rollback-pressure-$name.json"
           printf '%s\n' 'r=$(agent -X POST --data-binary @/run/culvert-lab-upd/rollback.json http://agent/v1/rollbacks); echo "$r" | tail -c 1500' \
                         'op=$(printf "%s" "$r" | opid); echo "op=$op"; [ -n "$op" ] && wait_op "$op"' 'running'; } | gpriv --timeout 2100 2>&1)" || rc=$?
    printf '%s\n' "$rb" > "$EV/P-$name-app-rollback.txt"
    check P "$name-app-rollback" "$(grep -qx 'op-state=succeeded' <<<"$rb" && echo pass || echo fail)" "$(grep -m1 '^op-state=' <<<"$rb") $(grep '^running-image=' <<<"$rb" | tail -1) rc=$rc"; fi
  lc="$(p_login)"; bk="$(p_backup "$EV/P-$name-backup-after.txt")"
  local fn; fn="$(body < "$EV/P-$name-backup-after.txt" | python3 -c 'import json,sys
for l in sys.stdin.read().split("\n"):
  try: d=json.loads(l)
  except Exception: continue
  r=d.get("result") or {}; f=r.get("filename") or d.get("filename")
  if f: print(f); break' 2>/dev/null || true)"
  local valid; valid="$(groot "mp=\$(docker volume inspect -f '{{.Mountpoint}}' \"\$(docker volume ls -q | grep -m1 -E '(^|_)culvert-backups\$')\"); f=\$(ls -t \$mp | grep -E '^culvert-backup-.*[.]tar[.]gz\$' | head -1); echo \"newest=\$f\"; tar -tzf \"\$mp/\$f\" > /dev/null 2>&1 && echo archive=valid || echo archive=INVALID" 300 2>&1 | grep -E '^(newest|archive)=' | tr '\n' ' ')"
  [[ "$bk" == *state=succeeded* && "$valid" == *archive=valid* ]] && check P "$name-backup-after" pass "$bk; $valid (gzip tar readable end to end); admin login $lc" \
    || check P "$name-backup-after" fail "$bk; $valid; admin login $lc"
  id1="$(p_proxy_identity)"
  [[ "$(awk '{print $1, $2}' <<<"$id0")" == "$(awk '{print $1, $2}' <<<"$id1")" ]] \
    && check P "$name-no-crash" pass "proxy restart count and start time unchanged across the phase ($(awk '{print $1, $2}' <<<"$id1"))" \
    || check P "$name-no-crash" fail "proxy identity changed: [$id0] -> [$id1]"; }
cmd_pressure() { local free
  ensure_admin_pass; [[ -f "$WORK/eicar-origin.pid" ]] || rec_origin_start
  free="$(p_host_free_gb)"; P_ALLOC0="$(p_host_alloc_mb)"
  if (( free < LAB_PRESSURE_MIN_HOST_FREE_GB )); then check P host-bound blocked "host has $free GiB free (< $LAB_PRESSURE_MIN_HOST_FREE_GB); pressure phase not run"; return 0; fi
  check P host-bound pass "host free $free GiB; disk file allocated ${P_ALLOC0} MiB; caps: growth <= $LAB_PRESSURE_MAX_HOST_GROWTH_MB MiB, abort below $(( LAB_PRESSURE_MIN_HOST_FREE_GB / 2 )) GiB free"
  # The lab EICAR origin's allow rule normally comes from the recovery step;
  # without it every EICAR/clean sample is a POLICY 403 and the AV checks
  # measure nothing (run 38012314515). Install it and require a real ClamAV
  # block before any fill.
  p_login > /dev/null
  api POST /api/policy '{"name":"lab-allow-eicar-origin","priority":15,"action":"Allow","destFQDN":"10.0.2.2","sslAction":"Bypass","enabled":true}' > "$EV/P-eicar-rule.txt"
  local v0; v0="$(eicar_verdict)"
  if [[ "$v0" != av ]]; then check P clamav-baseline fail "EICAR through the proxy did not draw a ClamAV block before any fill ($v0); the AV checks would be vacuous"; return 0; fi
  check P clamav-baseline pass "a fresh EICAR draws the ClamAV block before any fill"
  : > "$EV/P-samples.jsonl"; p_sample baseline 0 > /dev/null
  P_PKG=""; p_pkg_setup && P_PKG=1
  p_phase blocks 'python3 - <<"PY"
import os, errno
d="/var/lib/culvert-pressure"; os.makedirs(d, exist_ok=True)
fd=os.open(d+"/fill", os.O_CREAT|os.O_WRONLY, 0o600)
st=os.statvfs("/"); off=0
try:
    os.posix_fallocate(fd, 0, max(st.f_bfree*st.f_frsize-(16<<20), 0)); off=os.fstat(fd).st_size
except OSError as e: print("bulk:", e)
for step in (1<<20, 1<<16, 4096):
    while True:
        try: os.posix_fallocate(fd, off, step); off+=step
        except OSError as e:
            if e.errno==errno.ENOSPC: break
            raise
os.fsync(fd); os.close(fd)
st=os.statvfs("/"); print(f"filled bytes={off} free_root={st.f_bfree*st.f_frsize} free_user={st.f_bavail*st.f_frsize}")
PY' || return 0
  p_phase inodes 'python3 - <<"PY"
import os, errno, time
d="/var/lib/culvert-pressure/inodes"; os.makedirs(d, exist_ok=True)
t=time.time(); n=0; sub=None
def full(e): return e.errno==errno.ENOSPC
while True:
    if n%10000==0:
        sub=f"{d}/{n//10000}"
        try: os.mkdir(sub)
        except OSError as e:
            if full(e): break
            raise
    try: os.close(os.open(f"{sub}/{n}", os.O_CREAT|os.O_WRONLY, 0o600)); n+=1
    except OSError as e:
        if full(e): break
        raise
st=os.statvfs("/"); print(f"files={n} free_inodes={st.f_ffree} free_blocks_bytes={st.f_bfree*st.f_frsize} secs={time.time()-t:.0f}")
PY' || return 0
  # Headroom phases: enough left for apt and dpkg's own database, not for the
  # 2.0 payload, so the unpack itself is what fails (a part-written package).
  if [[ -n "$P_PKG" ]]; then
    P_NO_APP=1 p_phase pkgblocks "python3 - <<\"PY\"
import os
d=\"/var/lib/culvert-pressure\"; os.makedirs(d, exist_ok=True)
fd=os.open(d+\"/fill\", os.O_CREAT|os.O_WRONLY, 0o600); st=os.statvfs(\"/\")
keep=${LAB_PKG_HEADROOM_MB:-24}<<20
os.posix_fallocate(fd, 0, max(st.f_bfree*st.f_frsize-keep, 4096)); os.fsync(fd); os.close(fd)
st=os.statvfs(\"/\"); print(f\"filled headroom_target={keep} free_root={st.f_bfree*st.f_frsize} free_user={st.f_bavail*st.f_frsize}\")
PY" || true
    P_PRE_OSU="python3 - <<\"PY\"
import os
d=\"/var/lib/culvert-pressure/inodes\"; want=${LAB_PKG_HEADROOM_INODES_AT_UPDATE:-1500}
need=max(want-os.statvfs(\"/\").f_ffree, 0)
for e in os.scandir(d):
    if need <= 0: break
    for f in os.scandir(e.path):
        if need <= 0: break
        os.unlink(f.path); need-=1
print(f\"inode headroom before the update: {os.statvfs('/').f_ffree} (target {want}; the 2.0 payload needs 3000+)\")
PY" P_NO_APP=1 p_phase pkginodes "python3 - <<\"PY\"
import os, errno
d=\"/var/lib/culvert-pressure/inodes\"; os.makedirs(d, exist_ok=True)
keep=${LAB_PKG_HEADROOM_INODES:-400}; n=0; sub=None
target=os.statvfs(\"/\").f_ffree-keep
try:
    while n < target:
        if n%10000==0: sub=f\"{d}/{n//10000}\"; os.mkdir(sub)
        os.close(os.open(f\"{sub}/{n}\", os.O_CREAT|os.O_WRONLY, 0o600)); n+=1
except OSError as e:
    if e.errno!=errno.ENOSPC: raise
st=os.statvfs(\"/\"); print(f\"files={n} headroom_target={keep} free_inodes={st.f_ffree} free_blocks_bytes={st.f_bfree*st.f_frsize}\")
PY" || true
    p_pkg_teardown
  fi
}
# F-P2 controlled reproduction (ASTRA, #1528 item 1). One EICAR was DELIVERED
# at "+0" of the blocks phase in run 37948667525 (dc57bd76, parser fix
# present, /ready 200), with no log surviving the full disk. A reading of
# both sides found no path where clamd answers a plain OK on a write fault,
# and none where Culvert skips ClamAV — so it is reproduced here with the
# clamd conversation itself on record: clamd-tap.py on the ClamAV
# container's host veth, writing to tmpfs, logs what Culvert sent (bytes,
# EICAR or not) and clamd's verbatim reply for every connection. Cycles of
# fill -> immediate EICAR/clean burst -> release, with the headroom left at the
# fill varied from 0 to 4 MiB, since the moment of filling is where it was
# seen. A delivered EICAR is then attributed by its own stream: clamd said
# OK to the EICAR bytes (clamd), or no EICAR stream carries an OK (Culvert).
LAB_FP2_CYCLES="${LAB_FP2_CYCLES:-14}"; LAB_FP2_BURST="${LAB_FP2_BURST:-10}"
cmd_fp2() { local free k h hs rc
  ensure_admin_pass; [[ -f "$WORK/eicar-origin.pid" ]] || rec_origin_start
  free="$(p_host_free_gb)"; P_ALLOC0="$(p_host_alloc_mb)"
  (( free >= LAB_PRESSURE_MIN_HOST_FREE_GB )) || { check F2 host-bound blocked "host has $free GiB free"; return 0; }
  : > "$EV/P-samples.jsonl"; p_login > /dev/null
  # The lab's EICAR origin (10.0.2.2) needs the same allow rule the recovery
  # and adoption steps install; without it the policy, not ClamAV, answers
  # 403 and clamd never sees the body (run 38012773269 — both legs).
  api POST /api/policy '{"name":"lab-allow-eicar-origin","priority":15,"action":"Allow","destFQDN":"10.0.2.2","sslAction":"Bypass","enabled":true}' > "$EV/F2-eicar-rule.txt"
  local v0; v0="$(eicar_verdict)"
  if [[ "$v0" != av ]]; then check F2 clamav-baseline fail "EICAR through the proxy did not draw a ClamAV block before any fill ($v0)"; return 0; fi
  check F2 clamav-baseline pass "a fresh EICAR draws the ClamAV block before any fill"
  groot "mkdir -p /run/culvert-fp2; echo '$(base64 -w0 "$HERE/clamd-tap.py")' | base64 -d > /run/culvert-fp2/tap.py
i=\$(docker exec culvert-clamav cat /sys/class/net/eth0/iflink); v=\$(grep -lx \"\$i\" /sys/class/net/*/ifindex | cut -d/ -f5); echo veth=\$v
systemctl stop culvert-fp2-tap 2>/dev/null; systemd-run --quiet --unit=culvert-fp2-tap python3 -I /run/culvert-fp2/tap.py \"\$v\" /run/culvert-fp2/streams.jsonl && echo tap=started" 120 > "$EV/F2-tap-start.txt" 2>&1 || true
  sleep 2; p_sample fp2 baseline > /dev/null; sleep 2
  groot 'cat /run/culvert-fp2/streams.jsonl' 60 > "$EV/F2-tap-baseline.jsonl" 2>/dev/null || true
  if grep -q '"eicar": true' "$EV/F2-tap-baseline.jsonl" && grep -q 'FOUND' "$EV/F2-tap-baseline.jsonl"; then
    check F2 tap pass "clamd conversations recorded on $(grep -m1 -o 'veth=[^ ]*' "$EV/F2-tap-start.txt"); baseline EICAR stream seen with a FOUND reply"
  else check F2 tap fail "the tap did not record the baseline EICAR conversation ($(tr '\n' ' ' < "$EV/F2-tap-start.txt" | head -c 200)); attribution would be blind"; return 0; fi
  hs=(0 4096 16384 65536 262144 1048576 4194304)
  for k in $(seq 1 "$LAB_FP2_CYCLES"); do h="${hs[$(( (k - 1) % ${#hs[@]} ))]}"
    groot 'systemctl stop culvert-pressure-release.timer 2>/dev/null; systemd-run --quiet --unit=culvert-pressure-release --on-active=1800 /bin/rm -rf /var/lib/culvert-pressure && echo backstop=armed' 60 2>&1 | grep -q backstop=armed \
      || { check F2 "cycle-$k" blocked "release backstop could not be armed; stopping"; break; }
    groot "python3 - <<\"PY\"
import os, errno
d='/var/lib/culvert-pressure'; os.makedirs(d, exist_ok=True)
fd=os.open(d+'/fill', os.O_CREAT|os.O_WRONLY, 0o600); keep=$h
st=os.statvfs('/'); off=max(st.f_bfree*st.f_frsize-keep-(16<<20), 0)
try: os.posix_fallocate(fd, 0, off)
except OSError: off=os.fstat(fd).st_size
for step in (1<<20, 1<<16, 4096):
    while os.statvfs('/').f_bfree*os.statvfs('/').f_frsize > keep:
        try: os.posix_fallocate(fd, off, step); off+=step
        except OSError as e:
            if e.errno==errno.ENOSPC: break
            raise
os.close(fd); st=os.statvfs('/'); print(f'filled headroom={keep} free_root={st.f_bfree*st.f_frsize}')
PY" 1800 >> "$EV/F2-fills.txt" 2>&1 || true
    p_bounded || break
    p_burst fp2 "c$k-h$h" "$LAB_FP2_BURST"
    groot 'systemctl stop culvert-pressure-release.timer 2>/dev/null; rm -rf /var/lib/culvert-pressure; sync; echo released' 1800 > /dev/null 2>&1 || true
    rc=0; for _ in $(seq 1 60); do ready_clamav_ok && [[ "$(eicar_verdict)" == av ]] && { rc=1; break; }; sleep 5; done
    [[ $rc == 1 ]] || check F2 "cycle-$k" fail "not recovered within 300 s of release (headroom $h)"
  done
  groot 'systemctl stop culvert-fp2-tap 2>/dev/null; cat /run/culvert-fp2/streams.jsonl' 120 > "$EV/F2-clamd-streams.jsonl" 2>/dev/null || true
  grep -E '^filled' "$EV/F2-fills.txt" | sort | uniq -c > "$EV/F2-fills-summary.txt" || true
  local res; res="$(python3 - "$EV/P-samples.jsonl" "$EV/F2-clamd-streams.jsonl" <<'PY2'
import json, sys, collections
rows = [d for d in map(json.loads, open(sys.argv[1])) if d["phase"] == "fp2" and d["tag"] != "baseline"]
deliv = [d for d in rows if d["eicar"].startswith("2")]
st = []
for l in open(sys.argv[2]):
    try: st.append(json.loads(l))
    except Exception: pass
def cls(r):
    parts = [p.strip() for p in r["reply"].split("\x00") if p.strip()]
    if not parts: return "empty"
    if any(p.endswith(" FOUND") for p in parts): return "FOUND"
    if any(p.endswith(" ERROR") for p in parts): return "ERROR" + ("+OK" if any(p.endswith(" OK") for p in parts) else "")
    if parts == ["stream: OK"]: return "OK"
    return "other:" + "|".join(parts)[:60]
ec = collections.Counter(cls(r) for r in st if r["eicar"])
cc = collections.Counter(cls(r) for r in st if r["cmd"] == "zINSTREAM" and not r["eicar"])
full = len(set(r["up"] for r in st if r["eicar"]))
print(len(rows), len(deliv), ec.get("OK", 0), "eicar_streams=" + ",".join(f"{k}:{v}" for k, v in sorted(ec.items())),
      "other_streams=" + ",".join(f"{k}:{v}" for k, v in sorted(cc.items())), f"eicar_stream_sizes={full}")
PY2
)"
  set -- $res
  printf '%s\n' "$res" > "$EV/F2-summary.txt"
  # Two separate questions (F-P2, #1528 72c827b7). The PRODUCT check: did
  # Culvert ever deliver an EICAR? The UPSTREAM record: did clamd ever answer
  # a plain OK to an EICAR stream? Since the clean-verdict quarantine, a clamd
  # OK that Culvert refused is the mitigation working, not a product failure;
  # it is recorded (with the quarantine counter) for the ClamAV report.
  local q; : > "$JAR"
  api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$(cat "$SEC/admin-pass")\"}" >/dev/null 2>&1 || true
  q="$(api GET /api/security-scan/status | body | python3 -c 'import json,sys
v=json.load(sys.stdin).get("stat_clam_clean_quarantined"); print("absent" if v is None else v)' 2>/dev/null || echo unreadable)"
  printf 'clam_clean_quarantined=%s\n' "$q" >> "$EV/F2-summary.txt"
  if [[ "$2" == 0 ]]; then check F2 eicar-never-delivered pass "$1 at-fill samples over $LAB_FP2_CYCLES fill cycles: Culvert never delivered an EICAR; clean verdicts quarantined=$q; ${*:4}"
  elif [[ "$3" != 0 ]]; then check F2 eicar-never-delivered fail "REPRODUCED — Culvert delivered $2 of $1 EICAR; clamd answered a plain OK to $3 EICAR stream(s); quarantined=$q; ${*:4} (F2-clamd-streams.jsonl)"
  else check F2 eicar-never-delivered fail "REPRODUCED — $2 of $1 EICAR delivered with NO clamd OK on any EICAR stream: Culvert attribution; quarantined=$q; ${*:4} (F2-clamd-streams.jsonl)"; fi
  if [[ "$3" == 0 ]]; then check F2 clamd-ok-to-eicar info "clamd never answered a plain OK to an EICAR stream in this run (absence over $1 samples is not proof the upstream defect is gone)"
  elif [[ "$2" == 0 ]]; then check F2 clamd-ok-to-eicar info "upstream defect seen $3 time(s): clamd answered a plain OK to an EICAR stream and Culvert refused every one (quarantined=$q) — upstream evidence, F2-clamd-streams.jsonl"
  else check F2 clamd-ok-to-eicar info "upstream defect seen $3 time(s) and NOT contained (see eicar-never-delivered)"; fi; }
# cmd_cachebypass — the owner's cache-bypass regression (review 5478346473,
# follow-up 6097484537), on a disposable guest booted from a RETAINED OVA.
# p_enforced accepts an allowed 200 at any time, so it cannot tell the bypass
# from health; this leg can, because it ESTABLISHES the fault state first.
#   CB1 warm: clean body X served 200 and then from the cache (one clamd
#       stream for X on the tap); EICAR body Y blocked and cached.
#   CB2 fault: new TCP connections to clamd are reset from inside its network
#       namespace (a deterministic engine fault, clamd itself untouched);
#       a fresh body Z is refused and stat_clam_scan_error moves; the reset
#       is lifted; a fresh clean body W reaches clamd, is answered OK, and is
#       REFUSED with stat_clam_clean_quarantined moving: the quarantine is
#       active (on both builds — it shipped in 72c827b7).
#   CB3 inside the window: X must be refused as AV-unavailable. 200 FAILS:
#       a body cached clean before the fault was delivered while the
#       quarantine refused fresh bodies. Y must stay the ClamAV block.
#   CB4 after the window: X must be re-scanned (a new clamd stream for X,
#       after expiry) before it is served 200; a second request is then a
#       cache hit with no further stream.
# Healthy 200s outside the established fault state stay valid (CB1).
LAB_CB_WINDOW="${LAB_CB_WINDOW:-60}"
cb_ctr() { api GET /api/security-scan/status | body | python3 -c 'import json,sys
d=json.load(sys.stdin)
print(" ".join(str(d.get(k,"absent")) for k in ("cache_hits","cache_misses","stat_clam_scan_error","stat_clam_clean_quarantined","stat_clam_clean_cache_stale")))' 2>/dev/null || echo "x x x x x"; }
cb_get() { local out c; out="$(curl -sS -m 20 -x "$P" -w '\n%{http_code}' "$1" 2>/dev/null || printf '\n000')"; c="$(tail -n1 <<<"$out")"
  if [[ "$c" == 403 ]] && grep -q 'antivirus scanning is currently unavailable' <<<"$out"; then echo 403:av_unavailable
  elif [[ "$c" == 403 ]] && grep -q 'Blocked by CLAMAV scan' <<<"$out"; then echo 403:clamav_block
  else echo "$c"; fi; }
# cb_streams UP — clamd INSTREAM conversations of exactly UP bytes (body + 18:
# 10-byte command, 4-byte chunk length, 4-byte terminator) and their replies,
# in order. Judged by COUNT deltas, never by time: the tap stamps with the
# guest clock and the harness runs on the host.
cb_streams() { groot 'cat /run/culvert-cb/streams.jsonl' 60 2>/dev/null | python3 -c 'import json,sys
up=int(sys.argv[1]); n=0; r=[]
for l in sys.stdin:
    try: d=json.loads(l)
    except Exception: continue
    if d.get("cmd")=="zINSTREAM" and d.get("up")==up:
        n+=1; r.append(d.get("reply","").replace("\x00","|").strip("|"))
print(n, ";".join(r) or "-")' "$1"; }
cb_fault() { groot "p=\$(docker inspect -f '{{.State.Pid}}' culvert-clamav); nsenter -t \$p -n iptables -$1 INPUT -p tcp --dport 3310 --syn -j REJECT --reject-with tcp-reset && echo rule=$1" 60 2>&1 | grep -m1 '^rule='; }
cmd_cachebypass() { local X Y Z W ux uy uz uw upx upy c0 c1 c2 c3 c4 c5 s r tf el v
  ensure_admin_pass; [[ -f "$WORK/eicar-origin.pid" ]] || rec_origin_start
  p_login > /dev/null
  api POST /api/policy '{"name":"lab-allow-eicar-origin","priority":15,"action":"Allow","destFQDN":"10.0.2.2","sslAction":"Bypass","enabled":true}' > "$EV/CB-eicar-rule.txt"
  v="$(eicar_verdict)"; [[ "$v" == av ]] || { check CB clamav-baseline blocked "a fresh EICAR did not draw the ClamAV block ($v); nothing below would be meaningful"; return 0; }
  groot "mkdir -p /run/culvert-cb; echo '$(base64 -w0 "$HERE/clamd-tap.py")' | base64 -d > /run/culvert-cb/tap.py
i=\$(docker exec culvert-clamav cat /sys/class/net/eth0/iflink); v=\$(grep -lx \"\$i\" /sys/class/net/*/ifindex | cut -d/ -f5); echo veth=\$v
systemctl stop culvert-cb-tap 2>/dev/null; systemd-run --quiet --unit=culvert-cb-tap python3 -I /run/culvert-cb/tap.py \"\$v\" /run/culvert-cb/streams.jsonl && echo tap=started" 120 > "$EV/CB-tap-start.txt" 2>&1 || true
  sleep 2
  # Distinct sizes so the tap attributes each conversation to its body.
  X="cb-x-$RANDOM.txt"; Y="cb-y-$RANDOM.txt"
  python3 -c 'import sys; sys.stdout.write(("culvert cache-bypass clean body "+sys.argv[1]).ljust(77,".")+"\n")' "$RUN_ID" > "$WORK/eicar-origin/$X"
  { cat "$WORK/eicar-origin/eicar.txt"; printf '%40s' ''; } > "$WORK/eicar-origin/$Y"
  ux="http://10.0.2.2:$LAB_EICAR_PORT/$X"; uy="http://10.0.2.2:$LAB_EICAR_PORT/$Y"
  upx=$(( $(stat -c %s "$WORK/eicar-origin/$X") + 18 )); upy=$(( $(stat -c %s "$WORK/eicar-origin/$Y") + 18 ))
  # ---- CB1 warm
  c0="$(cb_ctr)"; r="$(cb_get "$ux") $(cb_get "$ux")"; c1="$(cb_ctr)"; s="$(cb_streams $upx)"
  printf 'c0=%s\nX x2=%s\nc1=%s\nX streams=%s\n' "$c0" "$r" "$c1" "$s" > "$EV/CB1-warm.txt"
  if [[ "$r" == "200 200" && "${s%% *}" == 1 ]]; then check CB warm-clean pass "X ($X) served 200 twice with ONE clamd stream ($s): the second answer came from the clean-verdict cache; counters hits/misses/err/quar/stale $c0 -> $c1"
  else check CB warm-clean blocked "X not served from a warmed cache ($r; X streams $s); the scenario cannot be established"; return 0; fi
  r="$(cb_get "$uy") $(cb_get "$uy")"; s="$(cb_streams $upy)"; echo "Y x2=$r Y streams=$s" >> "$EV/CB1-warm.txt"
  if [[ "$r" == "403:clamav_block 403:clamav_block" && "${s%% *}" == 1 ]]; then check CB warm-block pass "Y blocked twice by ClamAV with ONE clamd stream ($s): the block is cached"
  else check CB warm-block blocked "Y not blocked from a warmed cache ($r; Y streams $s)"; return 0; fi
  # ---- CB2 fault, then establish the quarantine
  Z="$(p_clean_url)"; [[ "$(cb_fault I)" == rule=I ]] || { check CB fault-inject blocked "could not install the clamd connection reset in its network namespace"; return 0; }
  c2="$(cb_ctr)"; r="$(cb_get "$Z")"; tf="$(date +%s.%N)"; c3="$(cb_ctr)"
  [[ "$(cb_fault D)" == rule=D ]] || { check CB fault-inject fail "the clamd connection reset could not be REMOVED; the guest is left faulted"; return 0; }
  printf 'fault Z=%s\nc2=%s\nc3=%s\ntf=%s\n' "$r" "$c2" "$c3" "$tf" > "$EV/CB2-fault.txt"
  if [[ "$r" == 403:av_unavailable && "$(cut -d' ' -f3 <<<"$c3")" -gt "$(cut -d' ' -f3 <<<"$c2")" ]]; then check CB fault-inject pass "fresh body refused AV-unavailable while clamd connections were reset; stat_clam_scan_error $(cut -d' ' -f3 <<<"$c2") -> $(cut -d' ' -f3 <<<"$c3") (an engine fault); reset lifted"
  else check CB fault-inject blocked "no engine fault recorded (Z=$r; err $(cut -d' ' -f3 <<<"$c2") -> $(cut -d' ' -f3 <<<"$c3"))"; return 0; fi
  W="$(p_clean_url)"; uw="$W"; r="$(cb_get "$uw")"; c4="$(cb_ctr)"
  # W and Z share a size; Z never reached clamd (its connection was reset),
  # so every stream of that size is W's.
  s="$(cb_streams $(( $(stat -c %s "$WORK/eicar-origin/$(basename "$uw")") + 18 )))"
  printf 'W=%s %s\nc4=%s\nW-size streams=%s\n' "$uw" "$r" "$c4" "$s" >> "$EV/CB2-fault.txt"
  if [[ "$r" == 403:av_unavailable && "$s" == *"stream: OK"* && "$(cut -d' ' -f4 <<<"$c4")" -gt "$(cut -d' ' -f4 <<<"$c3")" ]]; then
    check CB quarantine-active pass "a fresh clean body reached clamd (answered OK: $s) and was REFUSED; stat_clam_clean_quarantined $(cut -d' ' -f4 <<<"$c3") -> $(cut -d' ' -f4 <<<"$c4"): the closed-posture quarantine is active"
  else check CB quarantine-active blocked "quarantine not established (W=$r; W streams $s; quarantined $(cut -d' ' -f4 <<<"$c3") -> $(cut -d' ' -f4 <<<"$c4"))"; return 0; fi
  # ---- CB3 inside the window
  r="$(cb_get "$ux")"; el="$(python3 -c 'import sys,time; print(round(time.time()-float(sys.argv[1]),1))' "$tf")"; c5="$(cb_ctr)"; s="$(cb_streams $upx)"
  v="$(cb_get "$uy")"
  printf 'X inside window=%s at +%ss\nc5=%s\nX streams (total)=%s\nY inside window=%s\n' "$r" "$el" "$c5" "$s" > "$EV/CB3-window.txt"
  if python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) < float(sys.argv[2])-10 else 1)' "$el" "$LAB_CB_WINDOW"; then :; else
    check CB cached-clean-in-quarantine blocked "X requested at +${el}s, too close to the ${LAB_CB_WINDOW}s window to judge"; return 0; fi
  if [[ "$r" == 403:av_unavailable ]]; then check CB cached-clean-in-quarantine pass "X, cached clean BEFORE the fault, refused AV-unavailable at +${el}s inside the window; X streams in total: $s (2 = re-scanned, answered OK, refused by the window); stale $(cut -d' ' -f5 <<<"$c4") -> $(cut -d' ' -f5 <<<"$c5")"
  elif [[ "$r" == 200 ]]; then check CB cached-clean-in-quarantine fail "CACHE BYPASS — X, cached clean before the fault, was DELIVERED (200) at +${el}s while the quarantine refused a fresh clean body; X streams in total: $s (still 1 = never re-scanned: served from the pre-fault cache)"
  else check CB cached-clean-in-quarantine fail "unexpected answer for X inside the window: $r"; fi
  if [[ "$v" == 403:clamav_block ]]; then check CB cached-block-in-quarantine pass "Y (cached block) still the ClamAV block inside the window"
  else check CB cached-block-in-quarantine fail "Y inside the window answered $v (a cached block must survive a fault)"; fi
  # ---- CB4 after the window
  python3 -c 'import sys,time; t=float(sys.argv[1])+float(sys.argv[2])+5-time.time(); time.sleep(max(t,0))' "$tf" "$LAB_CB_WINDOW"
  local s0 r2 s2 n0; s0="$(cb_streams $upx)"; n0="${s0%% *}"
  r="$(cb_get "$ux")"; s="$(cb_streams $upx)"; r2="$(cb_get "$ux")"; s2="$(cb_streams $upx)"; v="$(cb_get "$uy")"
  printf 'X streams before=%s\nX after window=%s streams=%s\nX again=%s streams=%s\nY after window=%s\nctr=%s\n' "$s0" "$r" "$s" "$r2" "$s2" "$v" "$(cb_ctr)" > "$EV/CB4-after.txt"
  if [[ "$r" == 200 && "${s%% *}" == $(( n0 + 1 )) && "${s##*;}" == "stream: OK" && "$r2" == 200 && "${s2%% *}" == $(( n0 + 1 )) ]]; then
    check CB rescan-before-recache pass "after the window X was re-scanned by clamd (streams $n0 -> ${s%% *}, last reply OK) before it was served 200; the next request was a cache hit (streams unchanged)"
  else check CB rescan-before-recache fail "after the window: X=$r (streams $n0 -> $s), again=$r2 ($s2) — expected exactly one fresh scan, then a cache hit"; fi
  if [[ "$v" == 403:clamav_block ]]; then check CB cached-block-after pass "Y still the ClamAV block after the window"; else check CB cached-block-after fail "Y after the window: $v"; fi
  check CB scan-spanning-fault info "not judged on the appliance: a scan that starts before a fault and answers inside the 60 s window is refused by the window on BOTH builds, so only a scan longer than the window separates them; covered by TestScanSpanningAFaultIsNotHonoured (internal/secscan, mutation-checked)"
  groot 'systemctl stop culvert-cb-tap 2>/dev/null; cat /run/culvert-cb/streams.jsonl' 60 > "$EV/CB-clamd-streams.jsonl" 2>/dev/null || true
  grep -E 'SecurityScan|ClamAV|av_unavailable|quarantin' <(groot "docker logs --since 15m culvert 2>&1 | tail -n 300" 120 2>/dev/null) > "$EV/CB-proxy-log.txt" || true; }
# cmd_ldap — on-appliance LDAP/AD qualification (owner follow-up 6097484537
# item 4) against a REAL directory: Samba provisioned as an Active Directory
# domain controller on the runner from Ubuntu's own packages (the workflow
# does that; the guest reaches it at 10.0.2.2). It is an AD stand-in, not
# Microsoft AD: Kerberos/NTLM/Negotiate, channel binding, LDAP signing policy
# and nested groups are out of scope and recorded as such.
#   L1 transport matrix via the admin directory test: plain ldap:// (refused
#      by the directory), LDAPS verified against its internal CA (the
#      appliance has no CA setting), LDAPS with the unsafe skip-verify opt-in
#   L2 the LDAP IdP profile is created through the admin API; auth becomes
#      required; a group-scoped allow precedes a block for the same origin
#   L3 credential matrix through the proxy (Proxy-Authorization: Basic)
#   L4 the authenticated identity reaches the request log
#   L6 directory outage: an uncached user fails closed; recovery on evidence
LDAP_DOM="DC=corp,DC=example"; LDAP_USERS="CN=Users,$LDAP_DOM"
ldap_proxy() { curl -sS -m 30 -x "$P" ${2:+--proxy-user "$2"} -o "$WORK/ldap-body" -w '%{http_code}' "$1" 2>/dev/null || echo 000; }
cmd_ldap() { local u c r prof pid
  [[ -s "${LAB_LDAP_SECRETS:-/nonexistent}/passwords.env" ]] || { check L directory blocked "no directory provisioned on the runner (LAB_LDAP_SECRETS)"; return 0; }
  # shellcheck disable=SC1090
  source "$LAB_LDAP_SECRETS/passwords.env"
  ensure_admin_pass; [[ -f "$WORK/eicar-origin.pid" ]] || rec_origin_start
  echo "ldap qualification origin page" > "$WORK/eicar-origin/ldap-ok.txt"; u="http://10.0.2.2:$LAB_EICAR_PORT/ldap-ok.txt"
  p_login > /dev/null
  prof="$(python3 -c 'import json,sys
print(json.dumps({"name":"lab-samba-ad","type":"ldap","enabled":True,"priority":1,"emailDomains":[],
 "ldap":{"url":sys.argv[1],"bindDn":sys.argv[2],"bindPassword":sys.argv[3],"baseDn":sys.argv[4],
         "userFilter":"(sAMAccountName=%s)","groupAttribute":"memberOf","cacheTtlSeconds":30}}))' \
    "ldap://10.0.2.2:389" "CN=svc-culvert,$LDAP_USERS" "$LDAP_SVC_PASS" "$LDAP_DOM")"
  # ---- L1 transport matrix through the admin directory test. The directory
  # keeps Samba's AD default (simple binds need transport encryption), as a
  # hardened Microsoft AD does. Expected: plain ldap:// refused by the
  # directory; LDAPS verified against the directory's own (internal) CA fails
  # because the appliance only trusts the image's public roots; LDAPS with
  # the unsafe skip-verify opt-in works. The rest of the leg can only use the
  # last one, and says so.
  local plain verify skip
  plain="$(api POST /api/idp/test "{\"profile\":$prof,\"testUsername\":\"alice\",\"testPassword\":\"$LDAP_ALICE_PASS\"}" | tee "$EV/L1-plain.txt" | body)"
  verify="$(api POST /api/idp/test "{\"profile\":$(sed 's#ldap://10.0.2.2:389#ldaps://10.0.2.2:636#' <<<"$prof"),\"testUsername\":\"alice\",\"testPassword\":\"$LDAP_ALICE_PASS\"}" | tee "$EV/L1-ldaps-verify.txt" | body)"
  prof="$(sed 's#ldap://10.0.2.2:389#ldaps://10.0.2.2:636#; s#"bindDn"#"tlsSkipVerify":true,"bindDn"#' <<<"$prof")"
  skip="$(api POST /api/idp/test "{\"profile\":$prof,\"testUsername\":\"alice\",\"testPassword\":\"$LDAP_ALICE_PASS\"}" | tee "$EV/L1-ldaps-skipverify.txt" | body)"
  steps() { python3 -c 'import json,sys
d=json.loads(sys.stdin.read()); print(("ok " if d.get("ok") else "FAILED ")+"; ".join(s["name"]+"="+("ok" if s.get("ok") else "FAIL:"+(s.get("error") or "")[:140]) for s in d.get("steps",[])))' 2>/dev/null || echo unreadable; }
  check L plain-ldap info "ldap:// (no TLS): $(steps <<<"$plain") — the directory refuses a simple bind without transport encryption"
  if grep -q '"ok":true' <<<"$verify"; then check L ldaps-verify-internal-ca info "LDAPS verified against the directory's internal CA: $(steps <<<"$verify")"
  else check L ldaps-verify-internal-ca info "FINDING: LDAPS against a directory whose certificate comes from an internal CA cannot be verified, and the appliance offers no CA setting (ldapTLSConfig trusts the image's public roots only): $(steps <<<"$verify")"; fi
  if grep -q '"ok":true' <<<"$skip" && body <<<"$(cat "$EV/L1-ldaps-skipverify.txt")" | python3 -c 'import json,sys
d=json.load(sys.stdin); g=(d.get("identity") or {}).get("groups") or []
sys.exit(0 if any("CN=ProxyUsers" in x for x in g) else 1)' 2>/dev/null; then
    check L directory-test pass "LDAPS with tlsSkipVerify (the only transport that works with an internal-CA directory): dial, TLS, service bind, user search and alice's bind succeeded; her groups include CN=ProxyUsers. The leg below runs on this UNSAFE transport."
  else check L directory-test fail "LDAPS with skip-verify did not succeed either: $(steps <<<"$skip")"; return 0; fi
  # ---- L2 profile + policy
  c="$(api POST /api/idp "$prof" | tee "$EV/L2-idp-create.txt" | code)"
  [[ "$c" == 200 || "$c" == 201 ]] && check L idp-create pass "LDAP profile created and enabled (http $c); bind password write-only: $(body < "$EV/L2-idp-create.txt" | grep -c "$LDAP_SVC_PASS") occurrences in the response" \
    || { check L idp-create fail "http $c $(body < "$EV/L2-idp-create.txt" | head -c 300)"; return 0; }
  api GET /api/idp | body > "$EV/L2-idp-list.json"
  grep -q "$LDAP_SVC_PASS" "$EV/L2-idp-list.json" && check L bind-secret-not-returned fail "the bind password is returned by GET /api/idp" || check L bind-secret-not-returned pass "GET /api/idp does not return the bind password"
  local ra rb
  ra="$(api POST /api/policy "{\"name\":\"lab-ldap-allow-proxyusers\",\"priority\":3,\"action\":\"Allow\",\"destFQDN\":\"10.0.2.2\",\"sourceGroup\":\"CN=ProxyUsers,$LDAP_USERS\",\"sslAction\":\"Bypass\",\"enabled\":true}" | tee "$EV/L2-rule-allow.txt" | code)"
  rb="$(api POST /api/policy '{"name":"lab-ldap-block-others","priority":4,"action":"Block_Page","destFQDN":"10.0.2.2","sslAction":"Bypass","enabled":true}' | tee "$EV/L2-rule-block.txt" | code)"
  [[ "$ra $rb" == "200 200" ]] && check L rules pass "group-scoped allow (priority 3) and a block for everyone else (priority 4) created" \
    || { check L rules fail "rule creation: allow http $ra, block http $rb"; return 0; }
  c="$(api PUT /api/settings/default-auth-outcome '{"defaultAuthOutcome":"Default"}' | tee "$EV/L2-auth-required.txt" | code)"
  [[ "$c" == 200 ]] && check L auth-required pass "default auth outcome = Default (authentication required)" || { check L auth-required fail "http $c"; return 0; }
  # ---- L3 credential matrix
  local m=() exp got name cred bad=0 row
  while IFS='|' read -r name cred exp; do
    got="$(ldap_proxy "$u" "$cred")"; m+=("$name=$got(want $exp)")
    [[ "$got" == "$exp" ]] || bad=1
  done <<EOF2
no-credentials||407
alice (ProxyUsers)|alice:$LDAP_ALICE_PASS|200
alice wrong password|alice:not-the-password|407
bob (no group)|bob:$LDAP_BOB_PASS|403
carol (account disabled)|carol:$LDAP_CAROL_PASS|407
unknown user|mallory:$LDAP_BOB_PASS|407
filter metacharacter|*:$LDAP_ALICE_PASS|407
DN as username|CN=alice,$LDAP_USERS:$LDAP_ALICE_PASS|407
EOF2
  printf '%s\n' "${m[@]}" > "$EV/L3-matrix.txt"
  [[ $bad == 0 ]] && check L credential-matrix pass "$(IFS='; '; echo "${m[*]}")" || check L credential-matrix fail "$(IFS='; '; echo "${m[*]}")"
  # ---- L4 identity in the request log
  sleep 2; api GET "/api/logs?limit=500" | body > "$EV/L4-logs.json"
  if python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); es=d if isinstance(d,list) else d.get("logs",d.get("entries",[]))
s=json.dumps(es); sys.exit(0 if "alice" in s and "bob" in s else 1)' "$EV/L4-logs.json" 2>/dev/null; then
    check L identity-logged pass "request-log entries for the origin name alice (allowed) and bob (blocked)"
  else check L identity-logged fail "identities not found in the request log ($(head -c 300 "$EV/L4-logs.json"))"; fi
  # ---- L6 outage
  if [[ -n "${LAB_LDAP_STOP:-}" ]]; then
    eval "$LAB_LDAP_STOP" > "$EV/L6-stop.txt" 2>&1 || true; sleep 3
    got="$(ldap_proxy "$u" "dave:$LDAP_DAVE_PASS")"
    api GET /api/diagnostics | body > "$EV/L6-diagnostics-down.json"
    [[ "$got" == 407 ]] && check L outage-fail-closed pass "directory stopped: uncached dave (ProxyUsers) refused 407" || check L outage-fail-closed fail "directory stopped: dave answered $got"
    eval "$LAB_LDAP_START" > "$EV/L6-start.txt" 2>&1 || true
    r=000; for _ in $(seq 1 30); do r="$(ldap_proxy "$u" "dave:$LDAP_DAVE_PASS")"; [[ "$r" == 200 ]] && break; sleep 5; done
    api GET /api/diagnostics | body > "$EV/L6-diagnostics-up.json"
    [[ "$r" == 200 ]] && check L outage-recovery pass "directory restarted: dave 200 without any appliance action" || check L outage-recovery fail "directory restarted: dave still $r after 150 s"
  else check L outage blocked "no LAB_LDAP_STOP/START provided"; fi
  api PUT /api/settings/default-auth-outcome '{"defaultAuthOutcome":"Exempt"}' > /dev/null; }
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

# ── engine-surface: who can reach the container engine on the booted guest ──
# Evidence for the Docker/containerd/runc scanner dispositions. govulncheck in
# binary mode reports a vulnerable function as soon as it is LINKED; whether an
# attacker can feed it input depends on how the daemons are exposed here. Each
# check below is a claim a disposition rests on, and it FAILS if the booted
# appliance contradicts it.
cmd_engine_surface() { local f="$EV/E-engine-surface.txt" v
  gpriv --timeout 300 > "$f" 2>&1 <<'EOS' || true
echo "=== kernel"; echo "running=$(uname -r)"; for k in /boot/vmlinuz-*; do echo "installed=${k#/boot/vmlinuz-}"; done
echo "=== snapd"; echo "snapd-status=$(dpkg-query -W -f='${db:Status-Status}' snapd 2>/dev/null || echo absent)"; echo "snap-dir=$( [ -e /snap ] || [ -e /var/lib/snapd ] && echo present || echo absent)"
echo "=== versions"; for p in docker-ce containerd.io docker-compose-plugin; do echo "$p=$(dpkg-query -W -f='${Version}' "$p")"; done
echo "=== tcp listeners"; ss -Hltnp | sed 's/^/listen /'
echo "=== published ports"; docker ps --format '{{.Names}} {{.Ports}}' | sed 's/^/published /'
echo "=== sockets"; for s in /run/containerd/containerd.sock /run/docker.sock; do echo "sock $s $(stat -c '%U:%G %a' "$s" 2>/dev/null || echo missing)"; done
echo "docker-group=$(getent group docker | cut -d: -f4)"
echo "=== dockerd argv"; ps -o args= -C dockerd | sed 's/^/dockerd-argv /'
echo "=== daemon.json"; cat /etc/docker/daemon.json 2>/dev/null | sed 's/^/daemon.json /'
echo "=== containerd plugins"; ctr plugins ls 2>/dev/null | awk '{print "plugin "$1" "$2" "$NF}'
echo "disabled-plugins $(grep -E '^[[:space:]]*disabled_plugins' /etc/containerd/config.toml 2>/dev/null)"
echo "=== kernel identity"
echo "kernel-running=$(uname -r)"
echo "kernel-meta=$(dpkg-query -W -f='${Package}=${Version}' linux-image-virtual-hwe-24.04 2>/dev/null || echo none)"
echo "kernel-ga-meta=$(dpkg-query -W -f='${Package} ' linux-image-virtual linux-image-generic linux-virtual linux-generic 2>/dev/null | tr -s ' ' || true)"
echo "kernel-images=$(dpkg-query -W -f='${Package}\n' 'linux-image-[0-9]*' 2>/dev/null | tr '\n' ' ')"
echo "=== drm nodes"
# Root-only DRM nodes (72-culvert-drm.rules): owner, mode and any POSIX ACL.
# The acl package (getfacl) is not on the appliance, so the ACL is read as the
# xattr logind's uaccess would set: present means someone else was granted it.
for n in /dev/dri/card* /dev/dri/renderD*; do [ -e "$n" ] || continue
  echo "drm $n $(stat -c '%U:%G %a' "$n") acl=$(python3 -c 'import os,sys
try: os.getxattr(sys.argv[1], "system.posix_acl_access"); print("present")
except OSError: pass' "$n")"; done
echo "drm-rule $(sha256sum /etc/udev/rules.d/72-culvert-drm.rules 2>/dev/null | cut -d' ' -f1 || echo missing)"
echo "drm-driver $(basename "$(readlink -f /sys/class/drm/card0/device/driver 2>/dev/null)" 2>/dev/null || echo none)"
# The shipped cmdline carries nomodeset (boot console); with it vmwgfx refuses
# to bind (drm_firmware_drivers_only), so there may be no DRM node at all.
echo "drm-nomodeset $(grep -qw nomodeset /proc/cmdline && echo yes || echo no)"
echo "drm-vmwgfx-loaded $(grep -c '^vmwgfx ' /proc/modules)"
echo "=== ext4 features"
# CVE-2025-40190 needs ea_inode on a mounted ext4 filesystem.
findmnt -rn -t ext4 -o SOURCE,TARGET | while read -r dev tgt; do
  echo "ext4 $tgt $(dumpe2fs -h "$dev" 2>/dev/null | sed -n 's/^Filesystem features: *//p')"; done
echo "=== kernel attack surface"
# Assumptions the kernel CVE dispositions rely on (kernel-cve-prereqs.tsv).
for k in kernel.unprivileged_bpf_disabled kernel.perf_event_paranoid kernel.apparmor_restrict_unprivileged_userns kernel.kptr_restrict kernel.dmesg_restrict dev.tty.ldisc_autoload; do
  echo "sysctl $k=$(sysctl -n "$k" 2>/dev/null || echo unset)"; done
for c in $(docker ps -q); do
  docker inspect -f 'container {{.Name}} privileged={{.HostConfig.Privileged}} capadd={{.HostConfig.CapAdd}} devices={{len .HostConfig.Devices}} seccomp={{.HostConfig.SecurityOpt}} userns={{.HostConfig.UsernsMode}} pid={{.HostConfig.PidMode}} net={{.HostConfig.NetworkMode}}' "$c"
done
echo "nic-drivers $(for i in /sys/class/net/*/device/driver; do basename "$(readlink -f "$i")"; done 2>/dev/null | sort -u | tr '\n' ' ')"
echo "tpm $(ls -l /dev/tpm* 2>/dev/null | awk '{print $1, $3":"$4, $NF}' | tr '\n' ';' || true)"
echo "fuse-mounts $(findmnt -rn -t fuse,fuseblk,fuse.* 2>/dev/null | wc -l) btrfs-mounts $(findmnt -rn -t btrfs 2>/dev/null | wc -l) nfs-mounts $(findmnt -rn -t nfs,nfs4 2>/dev/null | wc -l)"
echo "perf-tool $(command -v perf >/dev/null && echo present || echo absent)"
# Unprivileged network autoload surface (the HWE kernel ships every module):
# each module a socket family / genl family / sock_diag / TCP ULP alias can
# load must be denied or in the shipped reviewed list.
ma="/lib/modules/$(uname -r)/modules.alias"; rv=/opt/culvert-appliance/provision/net-autoload-reviewed.txt
if [ -f "$ma" ] && [ -f "$rv" ]; then
  nl="$(awk '$1=="alias" && $2 ~ /^(net-pf-[0-9]+$|net-pf-[0-9]+-proto-|tcp-ulp-)/ {print $3}' "$ma" | tr - _ | sort -u)"
  dn="$(awk '$1=="install" && $3=="/bin/false"{print $2}' /etc/modprobe.d/culvert-unused.conf | tr - _ | sort -u)"
  rl="$(awk '!/^#/ && NF {print $1}' "$rv" | tr - _ | sort -u)"
  echo "net-autoload total=$(printf '%s\n' "$nl" | grep -c .) denied=$(comm -12 <(printf '%s\n' "$nl") <(printf '%s\n' "$dn") | grep -c .) reviewed=$(comm -12 <(printf '%s\n' "$nl") <(printf '%s\n' "$rl") | grep -c .)"
  echo "net-autoload-unreviewed=[$(comm -23 <(printf '%s\n' "$nl") <(sort -u <(printf '%s\n' "$dn" "$rl")) | tr '\n' ' ' | sed 's/ $//')]"
else echo "net-autoload-unreviewed=[no reviewed list or modules.alias: $ma $rv]"; fi
echo "=== kernel modules"
denied_mods="$(awk '$1=="install" && $3=="/bin/false"{print $2}' /etc/modprobe.d/culvert-unused.conf)"
echo "denied-count $(wc -w <<<"$denied_mods")"
for m in $denied_mods; do
  # FINAL step of the module's own resolution (a dependency's deny must not
  # count), then a REAL load attempt: it must fail and leave the module out.
  # The real attempt records its exit code and WHICH module's install rule
  # kmod reports refusing it. kmod inserts hard dependencies first and stops
  # at the first refusal, so a target whose dependency is itself denied (ksmbd
  # needs ib_core when built with SMB Direct) is refused by THAT rule before
  # its own is reached; the target's own rule is proven by the effective
  # config and by being the final step of its own resolution (above).
  before="$(grep -c "^$m " /proc/modules)"
  final="$(modprobe -n -v "$m" 2>&1 | tail -n 1 | tr -s ' ')"
  err="$(modprobe "$m" 2>&1)"; rc=$?
  by="$(sed -n "s/.*Error running install command '\/bin\/false' for module \([a-z0-9_]*\):.*/\1/p" <<<"$err" | head -n 1)"
  echo "module $m before=$before final=${final% } rc=$rc refused-by=${by:-none} after=$(grep -c "^$m " /proc/modules)"
  echo "module-err $m $(tr '\n' ' ' <<<"$err" | tr -s ' ')"
done
# The EFFECTIVE configuration kmod applies (all of /etc/modprobe.d, /lib/
# modprobe.d and the built-in defaults), for every denied module, plus the
# shipped file's own digest.
echo "denylist-file $(sha256sum /etc/modprobe.d/culvert-unused.conf | cut -d' ' -f1)"
modprobe -c 2>/dev/null | awk -v list=" $(tr '\n' ' ' <<<"$denied_mods")" '($1=="install"||$1=="softdep"||$1=="blacklist"||$1=="remove"||$1=="options") && index(list, " "$2" ") {print "effective "$0}'
echo "sctp-socket=$(python3 -c 'import socket
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132); print("opened")
except OSError as e:
    print("refused:" + (e.strerror or str(e)))' 2>&1) loaded-after=$(grep -c '^sctp ' /proc/modules)"
# module file names may use "-" where the module name has "_" (kvm-amd.ko)
# The GA kernel's two other CRITICALs (nvmet-tcp, ib_srpt) were "absent" there;
# the HWE kernel ships both, so a REAL load attempt must fail and leave them out.
for m in nvmet_tcp ib_srpt; do
  err="$(modprobe "$m" 2>&1)"; rc=$?
  echo "extra-module $m files=$(find /lib/modules/"$(uname -r)" \( -name "$m.ko*" -o -name "${m//_/-}.ko*" \) | wc -l) rc=$rc loaded-after=$(grep -c "^$m " /proc/modules) refused-by=$(sed -n "s/.*install command '\/bin\/false' for module \([a-z0-9_]*\).*/\1/p" <<<"$err" | head -n 1)"; done
echo "=== containerd tracing"; containerd config dump 2>/dev/null | grep -iE 'otlp|tracing|endpoint' | sed 's/^/tracing /'
EOS
  v="$(sed -n 's/^running=//p' "$f")"
  [[ -n "$v" && "$(grep -c '^installed=' "$f")" == 1 && "$(grep '^installed=' "$f")" == "installed=$v" ]] \
    && check E kernel-is-the-only-installed pass "running=$v" || check E kernel-is-the-only-installed fail "$(grep -E '^(running|installed)=' "$f" | tr '\n' ' ')"
  # a purged package is "not-installed" to dpkg while the pin keeps it known
  grep -qE '^snapd-status=(absent|not-installed)$' "$f" && grep -q '^snap-dir=absent' "$f" \
    && check E snapd-absent pass "package and state removed" || check E snapd-absent fail "$(grep -E '^snap' "$f" | tr '\n' ' ')"
  # No engine process listens on TCP: the gRPC and API surfaces are local
  # sockets only. docker-proxy is the userland forwarder for a container's
  # PUBLISHED port (the appliance's own proxy/UI ports), so it may listen
  # only on a port a running container publishes.
  local pub bad=""
  pub="$(grep -E '^published ' "$f" | grep -oE ':[0-9]+->' | tr -d ':>-' | sort -u | tr '\n' ' ')"
  if grep -E '^listen ' "$f" | grep -qE '"(dockerd|containerd|containerd-shim[^"]*|runc)"'; then
    bad="$(grep -E '^listen ' "$f" | grep -E '"(dockerd|containerd|containerd-shim[^"]*|runc)"' | tr '\n' ' ')"
  fi
  while read -r port; do
    [[ -n "$port" ]] || continue
    [[ " $pub " == *" $port "* ]] || bad+="docker-proxy on unpublished port $port "
  done < <(grep -E '^listen .*"docker-proxy"' "$f" | awk '{print $5}' | sed 's/.*://' | sort -u)
  if [[ -n "$bad" ]]; then check E engine-no-tcp-listener fail "$bad"
  else check E engine-no-tcp-listener pass "dockerd/containerd/shim/runc: no TCP listener; docker-proxy only on published ports (${pub% })"; fi
  grep -q '^sock /run/containerd/containerd.sock root:root 660$' "$f" \
    && check E containerd-socket-root-only pass "root:root 0660" || check E containerd-socket-root-only fail "$(grep 'containerd.sock' "$f")"
  if grep -qE '^sock /run/docker.sock root:(root|docker) 660$' "$f" && grep -qx 'docker-group=' "$f"; then
    check E docker-socket-root-only pass "$(grep '^sock /run/docker.sock' "$f" | cut -d' ' -f3-), docker group has no members"
  else check E docker-socket-root-only fail "$(grep -E '^sock /run/docker.sock|^docker-group=' "$f" | tr '\n' ' ')"; fi
  if grep -E '^(dockerd-argv|daemon\.json) ' "$f" | grep -qiE 'tcp://|-H +tcp|--host[= ]+tcp'; then
    check E dockerd-no-tcp-host fail "$(grep -E '^(dockerd-argv|daemon\.json) ' "$f" | tr '\n' ' ')"
  else check E dockerd-no-tcp-host pass "no tcp host in dockerd argv or daemon.json"; fi
  # CRI is the only containerd service that serves untrusted pod specs; Docker's
  # containerd.io package disables it.
  if grep -E '^plugin ' "$f" | grep -E 'grpc\.v1 +cri|cri ' | grep -qw ok; then
    check E containerd-cri-disabled fail "$(grep -E '^plugin .*cri' "$f" | tr '\n' ' ')"
  elif grep -qE '^plugin ' "$f"; then check E containerd-cri-disabled pass "io.containerd.grpc.v1 cri (the CRI API) not loaded; $(grep -E '^disabled-plugins' "$f" | cut -d' ' -f2-)"
  else check E containerd-cri-disabled fail "ctr plugins ls produced nothing"; fi
  # Unused kernel modules: denied by modprobe.d, not loaded, and an actual
  # SCTP socket (which would autoload the module) is refused.
  if ! grep -qE '^module ' "$f"; then check E kernel-modules-denied fail "no module lines (old OVA without the denylist?)"
  elif bad="$(awk '$1=="module"{split($0,a," "); m=$2; ok=($3=="before=0" && $4=="final=install" && $5=="/bin/false" && $6 ~ /^rc=[1-9][0-9]*$/ && $8=="after=0"); by=$7; sub(/^refused-by=/,"",by); den[m]=1; if(!ok) print m; rb[m]=by}
         $1=="effective" && $2=="install" && $4=="/bin/false"{inst[$3]=1}
         $1=="effective" && $2=="softdep" && NF==3{emp[$3]=1}
         END{for(m in den){ if(!(rb[m] in den)) print m" (refused-by="rb[m]")"; if(!inst[m]) print m" (no effective install /bin/false)"; if(!emp[m]) print m" (no effective empty softdep)"}}' "$f" | sort -u | tr '\n' ' ')"; [[ -n "$bad" ]]; then
    check E kernel-modules-denied fail "$bad"
  elif ! grep -qE '^sctp-socket=refused:.* loaded-after=0$' "$f"; then
    check E kernel-modules-denied fail "$(grep '^sctp-socket=' "$f")"
  elif [[ "$(sed -n 's/^denied-count //p' "$f")" -lt 67 ]]; then
    check E kernel-modules-denied fail "the installed denylist names only $(sed -n 's/^denied-count //p' "$f") modules (expected >= 67)"
  else check E kernel-modules-denied pass "$(grep -c '^module ' "$f") denied modules (sctp, nfsd, kvm*, ksmbd, cifs, can*, pppoe, pppox, RDMA core, dccp, tipc, ip_vs, openvswitch, vxlan, LIO target, sound, Bluetooth, rxrpc/kafs, amdgpu, idpf, scsi_debug, the 21 network-autoloadable modules the GA disk did not carry, and the NVMe-oF target nvmet/nvmet_tcp): for each, the effective modprobe -c rules carry install /bin/false + an empty softdep override, /bin/false is the final step of its own resolution, and a real load attempt exits non-zero, refused by a denied module's install rule ($(awk '$1=="module"{by=$7; sub(/^refused-by=/,"",by); if(by==$2) s++; else d++} END{print s+0" by their own rule, "d+0" by a denied dependency first"}' "$f")), unloaded before and after; a real SCTP socket is $(sed -n 's/^sctp-socket=\(refused:.*\) loaded-after.*/\1/p' "$f") and sctp stays unloaded"; fi
  # The kernel is Ubuntu's HWE series, exactly one image, no GA meta, and the
  # running kernel is that image.
  krun="$(sed -n 's/^kernel-running=//p' "$f")"; kimgs="$(sed -n 's/^kernel-images=//p' "$f" | xargs)"
  if [[ "$(sed -n 's/^kernel-meta=//p' "$f")" != linux-image-virtual-hwe-24.04=* ]]; then
    check E kernel-hwe fail "linux-image-virtual-hwe-24.04 not installed ($(grep '^kernel-meta=' "$f"))"
  elif [[ -n "$(sed -n 's/^kernel-ga-meta=//p' "$f" | xargs)" ]]; then
    check E kernel-hwe fail "GA kernel metapackage installed: $(sed -n 's/^kernel-ga-meta=//p' "$f")"
  elif [[ "$kimgs" != "linux-image-$krun" ]]; then
    check E kernel-hwe fail "running $krun, installed images: $kimgs"
  else check E kernel-hwe pass "running $krun = the one installed image; $(sed -n 's/^kernel-meta=//p' "$f"); no GA metapackage"; fi
  # vmwgfx ioctl CVEs: no DRM node may be openable by anyone but root.
  local drule; drule="$(sed -n 's/^drm-rule //p' "$f")"
  if [[ -z "$drule" || "$drule" == missing ]]; then check E drm-root-only fail "72-culvert-drm.rules is not installed"
  elif ! grep -q '^drm ' "$f"; then
    if [[ "$(sed -n 's/^drm-nomodeset //p' "$f")" == yes ]]; then
      check E drm-root-only pass "no DRM node exists: the shipped kernel cmdline carries nomodeset, so vmwgfx does not bind (module loaded: $(sed -n 's/^drm-vmwgfx-loaded //p' "$f")); 72-culvert-drm.rules (${drule:0:12}) stays installed for a node that ever appears"
    else check E drm-root-only fail "no DRM node and no nomodeset on the cmdline (the lab VM has a VMware SVGA adapter; vmwgfx should bind)"; fi
  elif grep '^drm ' "$f" | grep -vqE '^drm \S+ root:root 600 acl=$'; then check E drm-root-only fail "$(grep '^drm ' "$f" | grep -vE ' root:root 600 acl=$' | tr '\n' ' ')"
  else check E drm-root-only pass "$(grep -c '^drm ' "$f") DRM node(s) on driver $(sed -n 's/^drm-driver //p' "$f"), each root:root 0600 with no ACL entry ($(grep '^drm ' "$f" | awk '{print $2}' | tr '\n' ' '))"; fi
  # Assumptions the kernel CVE dispositions rely on (kernel-cve-prereqs.tsv).
  asf=""
  [[ "$(sed -n 's/^sysctl kernel.unprivileged_bpf_disabled=//p' "$f")" =~ ^[12]$ ]] || asf+="unprivileged BPF not disabled; "
  [[ "$(sed -n 's/^sysctl kernel.perf_event_paranoid=//p' "$f")" =~ ^[0-9]+$ && "$(sed -n 's/^sysctl kernel.perf_event_paranoid=//p' "$f")" -ge 2 ]] || asf+="perf_event_paranoid < 2; "
  grep -q '^container ' "$f" || asf+="no container listed; "
  bad_c="$(grep '^container ' "$f" | grep -vE ' privileged=false capadd=(\[\]|<no value>) devices=0 ' || true)"
  [[ -z "$bad_c" ]] || asf+="container with privileges/caps/devices: $bad_c; "
  grep -q '^perf-tool absent' "$f" || asf+="perf tool installed; "
  grep -qE '^fuse-mounts 0 btrfs-mounts 0 nfs-mounts 0$' "$f" || asf+="$(grep '^fuse-mounts' "$f"); "
  [[ "$(sed -n 's/^sysctl kernel.apparmor_restrict_unprivileged_userns=//p' "$f")" == 1 ]] || asf+="unprivileged user namespaces not restricted; "
  [[ "$(sed -n 's/^sysctl dev.tty.ldisc_autoload=//p' "$f")" == 0 ]] || asf+="unprivileged tty line-discipline autoload enabled; "
  grep -qx 'net-autoload-unreviewed=\[\]' "$f" || asf+="unprivileged network autoload neither denied nor reviewed: $(grep '^net-autoload-unreviewed=' "$f"); "
  if [[ -n "$asf" ]]; then check E kernel-cve-assumptions fail "$asf"
  else check E kernel-cve-assumptions pass "unprivileged BPF disabled ($(sed -n 's/^sysctl kernel.unprivileged_bpf_disabled=//p' "$f")), perf_event_paranoid $(sed -n 's/^sysctl kernel.perf_event_paranoid=//p' "$f"), $(grep -c '^container ' "$f") containers unprivileged with no added caps or devices, no perf tool, no FUSE/btrfs/NFS mounts, unprivileged userns restricted, ldisc autoload off, network autoload $(sed -n 's/^net-autoload //p' "$f") (none unreviewed); NICs: $(sed -n 's/^nic-drivers //p' "$f")"; fi
  # CVE-2025-40190: no mounted ext4 filesystem carries ea_inode.
  if ! grep -q '^ext4 ' "$f"; then check E ext4-no-ea-inode fail "no ext4 mount listed"
  elif grep '^ext4 ' "$f" | grep -qw ea_inode; then check E ext4-no-ea-inode fail "$(grep '^ext4 ' "$f" | grep -w ea_inode | tr '\n' ' ')"
  else check E ext4-no-ea-inode pass "$(grep -c '^ext4 ' "$f") ext4 mount(s) without ea_inode: $(grep '^ext4 ' "$f" | awk '{print $2}' | tr '\n' ' ')"; fi
  if ! grep -q '^extra-module ' "$f"; then check E extra-modules-unloadable fail "no extra-module lines recorded"
  elif grep '^extra-module ' "$f" | grep -vqE ' rc=[1-9][0-9]* loaded-after=0 refused-by=[a-z0-9_]+$'; then check E extra-modules-unloadable fail "$(grep '^extra-module' "$f" | tr '\n' ' ')"
  else check E extra-modules-unloadable pass "$(grep '^extra-module' "$f" | tr '\n' ' ')"; fi
  grep -qiE '^tracing .*endpoint *= *"[^"]+"' "$f" && check E containerd-tracing-off fail "$(grep '^tracing' "$f" | tr '\n' ' ')" \
    || check E containerd-tracing-off pass "no OTLP endpoint configured"
  log "engine surface: $f"
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
# ── adoption: does an appliance with the OLD sidecar cached adopt a new one? ─
# ASTRA (#1528): a sidecar content change ships under a NEW local tag, because
# Compose builds the sidecar only when its tag is absent. An application
# upgrade (what the maintenance agent does: retag culvert/proxy:pinned, then
# `compose up`) does not touch host components (upgrade-runbook.md "Host
# components"), so the old compose file and sidecar stay. The documented
# refresh is re-running the installer (`culvert-firstboot --repair-agent` on
# the appliance), which re-extracts the pinned image's bundle — compose file
# AND appliance/clamav — and lets Compose build the new tag. Measured here on
# a booted OVA that carries the old tag, against the new candidate image:
#   A1 app-only upgrade → sidecar unchanged (documented)
#   A2 refresh with outbound 80/443 blocked → old stack keeps serving; what
#      the host compose file names afterwards is recorded
#   A3 refresh online → new tag built and running with the fixed packages,
#      proxy still the upgraded image, enforcement + ClamAV verdicts live
#   A4 maintenance reboot → the new sidecar is what comes back
# Inputs: LAB_ADOPT_IMAGE_TAR (docker-save tar of the new candidate, tagged
# culvert:ci-smoke), LAB_ADOPT_IMAGE_ID, LAB_ADOPT_OLD_REF, LAB_ADOPT_NEW_REF,
# LAB_ADOPT_PKGS (the new sidecar's sorted pcre2/zlib/nghttp2-libs versions).
adopt_state() { local out="$1"
  gpriv --timeout 300 > "$out" 2>&1 <<EOS || true
cd /srv/culvert
echo "compose-ref=\$(awk '/^  clamav:/{f=1} f&&/^    image:/{print \$2; exit}' docker-compose.yml)"
echo "clam-image=\$(docker inspect culvert-clamav -f '{{.Config.Image}}' 2>/dev/null)"
echo "clam-id=\$(docker inspect culvert-clamav -f '{{.Image}}' 2>/dev/null)"
echo "clam-state=\$(docker inspect culvert-clamav -f '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null)"
echo "clam-pkgs=\$(docker exec culvert-clamav sh -c "apk info -v 2>/dev/null | grep -E '^(pcre2|zlib|nghttp2-libs)-[0-9]' | sort | tr '\n' ' '" 2>/dev/null)"
echo "proxy-id=\$(docker inspect culvert -f '{{.Image}}' 2>/dev/null)"
echo "new-tag-present=\$(docker image inspect '$LAB_ADOPT_NEW_REF' >/dev/null 2>&1 && echo yes || echo no)"
EOS
}
kv() { grep -m1 "^$2=" "$1" | cut -d= -f2- | tr -d '\r' | sed 's/[[:space:]]*$//'; }
adopt_wait_clam_healthy() { local f="$1" i
  for i in $(seq 1 60); do adopt_state "$f"; [[ "$(kv "$f" clam-state)" == running/healthy ]] && return 0; sleep 15; done; return 1; }
adopt_compose_up() { printf '%s\n' 'cd /srv/culvert' \
  'if [ -f docker-compose.maint-agent.yml ] && grep -q "^CULVERT_MAINT_GID=" .env; then docker compose -f docker-compose.yml -f docker-compose.maint-agent.yml up -d; else docker compose up -d; fi'; }
# adopt_export_sidecar RUNNING_ID A3_ID OLD_ID — the guest root saves the ref
# culvert-clamav runs, after proving that ref resolves to the RUNNING image
# id, and PUTs the archive to the host; the host re-hashes it and binds it
# (archive → top entry → amd64 manifest → config) to the running id with the
# same script the scan job uses. Output: $LAB_ADOPTED_OUT/adopted-sidecar.tar
# plus $EV/A5-adopted-sidecar.{txt,binding.json}.
adopt_export_sidecar() { local run="$1" a3="$2" old="$3" f="$EV/A5-adopted-sidecar.txt" out got sz
  out="${LAB_ADOPTED_OUT:-$WORK/adopted}"; mkdir -p "$out"; rm -f "$out/adopted-sidecar.tar"
  if [[ -z "$run" || "$run" != "$a3" || "$run" == "$old" ]]; then
    check A5 adopted-sidecar-exported fail "BLOCKED: the running sidecar ($run) is not the adopted one (A3 $a3, old $old)"; return 0; fi
  upload_rx_start
  gpriv --timeout 1200 > "$f" 2>&1 <<EOS || true
set -e
id=\$(docker inspect culvert-clamav -f '{{.Image}}')
rid=\$(docker image inspect '$LAB_ADOPT_NEW_REF' -f '{{.Id}}')
echo "running-id=\$id"; echo "ref-id=\$rid"; echo "ref=$LAB_ADOPT_NEW_REF"
echo "docker-server=\$(docker version -f '{{.Server.Version}}')"
echo "driver-status=\$(docker info -f '{{.Driver}} {{.DriverStatus}}' | tr '\\n' ' ')"
[ "\$id" = "\$rid" ]
rm -f /var/tmp/.lab-adopted.tar
docker save '$LAB_ADOPT_NEW_REF' -o /var/tmp/.lab-adopted.tar
echo "archive-sha256=\$(sha256sum /var/tmp/.lab-adopted.tar | cut -d' ' -f1)"
echo "archive-bytes=\$(stat -c %s /var/tmp/.lab-adopted.tar)"
rc=0; curl -fsS -H 'Expect:' -T /var/tmp/.lab-adopted.tar "http://10.0.2.2:$LAB_UPLOAD_PORT/adopted-sidecar.tar" || rc=\$?
echo "upload-rc=\$rc"
rm -f /var/tmp/.lab-adopted.tar
echo "running-id-after=\$(docker inspect culvert-clamav -f '{{.Image}}')"
EOS
  upload_rx_stop
  got=""; sz=""
  if [[ -f "$WORK/upload/adopted-sidecar.tar" ]]; then
    mv "$WORK/upload/adopted-sidecar.tar" "$out/adopted-sidecar.tar"
    got="$(sha256sum "$out/adopted-sidecar.tar" | cut -d' ' -f1)"; sz="$(stat -c %s "$out/adopted-sidecar.tar")"
  fi
  printf 'host-sha256=%s\nhost-bytes=%s\n' "$got" "$sz" >> "$f"
  if [[ "$(kv "$f" running-id)" == "$run" && "$(kv "$f" ref-id)" == "$run" && "$(kv "$f" running-id-after)" == "$run" \
        && "$(kv "$f" upload-rc)" == 0 && -n "$got" && "$got" == "$(kv "$f" archive-sha256)" && "$sz" == "$(kv "$f" archive-bytes)" ]] \
     && "$HERE/sidecar-scan.sh" bind "$out/adopted-sidecar.tar" "$run" either "$EV/A5-adopted-sidecar.binding.json" > "$EV/A5-bind.txt" 2>&1; then
    cp "$f" "$out/A5-adopted-sidecar.txt"; cp "$EV/A5-adopted-sidecar.binding.json" "$out/"
    check A5 adopted-sidecar-exported pass "$LAB_ADOPT_NEW_REF = running $run (id matched the archive's $(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["id_matched"])' "$EV/A5-adopted-sidecar.binding.json")); archive sha256 $got ($sz bytes), identical on guest and host; config $(cat "$EV/A5-bind.txt")"
  else
    check A5 adopted-sidecar-exported fail "$(tr '\n' ' ' < "$f" | head -c 500) bind: $(tail -n1 "$EV/A5-bind.txt" 2>/dev/null)"
    rm -f "$out/adopted-sidecar.tar"
  fi; }
cmd_adoption() { local f old new rc c v t
  : "${LAB_ADOPT_IMAGE_TAR:?}" "${LAB_ADOPT_IMAGE_ID:?}" "${LAB_ADOPT_OLD_REF:?}" "${LAB_ADOPT_NEW_REF:?}" "${LAB_ADOPT_PKGS:?}"
  gate A adoption || { check A adoption fail "BLOCKED: an earlier gate did not pass"; return 0; }
  rec_origin_start; ln -sf "$LAB_ADOPT_IMAGE_TAR" "$WORK/eicar-origin/culvert-image.tar"
  : > "$JAR"; api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$(cat "$SEC/admin-pass")\"}" > /dev/null
  api POST /api/policy '{"name":"lab-allow-eicar-origin","priority":15,"action":"Allow","destFQDN":"10.0.2.2","sslAction":"Bypass","enabled":true}' > "$EV/A-eicar-rule.txt"
  # A0 baseline: the OVA's own sidecar under the OLD tag.
  f="$EV/A0-state.txt"; adopt_state "$f"; old="$(kv "$f" clam-id)"
  if [[ "$(kv "$f" compose-ref)" == "$LAB_ADOPT_OLD_REF" && "$(kv "$f" clam-image)" == "$LAB_ADOPT_OLD_REF" && -n "$old" ]]; then
    check A0 old-sidecar pass "compose names $LAB_ADOPT_OLD_REF; culvert-clamav runs it ($old; $(kv "$f" clam-pkgs)); $(kv "$f" clam-state)"
  else check A0 old-sidecar fail "BLOCKED: not the old-tag baseline: $(tr '\n' ' ' < "$f" | head -c 400)"; rec_origin_stop; return 0; fi
  # A1 application upgrade, exactly as the agent performs it.
  rc=0; { printf '%s\n' 'set -e' "curl -fsS http://10.0.2.2:$LAB_EICAR_PORT/culvert-image.tar -o /tmp/.lab-adopt.tar" \
      'docker load -q -i /tmp/.lab-adopt.tar; rm -f /tmp/.lab-adopt.tar' 'docker tag culvert:ci-smoke culvert/proxy:pinned'; adopt_compose_up; } \
    | gpriv --timeout 900 > "$EV/A1-app-upgrade.txt" 2>&1 || rc=$?
  for _ in $(seq 1 60); do curl -fsS -m 3 "$P/health" >/dev/null 2>&1 && break; sleep 5; done
  f="$EV/A1-state.txt"; adopt_state "$f"
  if [[ $rc == 0 && "$(kv "$f" proxy-id)" == "$LAB_ADOPT_IMAGE_ID" && "$(kv "$f" clam-id)" == "$old" && "$(kv "$f" compose-ref)" == "$LAB_ADOPT_OLD_REF" ]]; then
    check A1 app-upgrade-keeps-host-components pass "proxy now $LAB_ADOPT_IMAGE_ID; compose file and sidecar unchanged ($LAB_ADOPT_OLD_REF, $old) — an application upgrade replaces the container image only (upgrade-runbook.md)"
  else check A1 app-upgrade-keeps-host-components fail "exit $rc: $(tr '\n' ' ' < "$f" | head -c 400)"; rec_origin_stop; return 0; fi
  # A1b (optional) the installer under test. An appliance runs the installer
  # its OVA baked (/opt/culvert-appliance/bin/culvert-install.sh); the refresh
  # logic lives there, so testing a NEW installer against an appliance that
  # carries the OLD sidecar means putting that installer in place first.
  if [[ -n "${LAB_ADOPT_INSTALLER:-}" ]]; then
    cp "$LAB_ADOPT_INSTALLER" "$WORK/eicar-origin/culvert-install.sh"
    rc=0; printf '%s\n' 'set -e' "curl -fsS http://10.0.2.2:$LAB_EICAR_PORT/culvert-install.sh -o /tmp/.lab-install.sh" \
        'install -m 0755 /tmp/.lab-install.sh /opt/culvert-appliance/bin/culvert-install.sh; rm -f /tmp/.lab-install.sh' \
        'sha256sum /opt/culvert-appliance/bin/culvert-install.sh' | gpriv --timeout 120 > "$EV/A1b-installer.txt" 2>&1 || rc=$?
    if [[ $rc == 0 ]] && grep -q "$(sha256sum "$LAB_ADOPT_INSTALLER" | cut -d' ' -f1)" "$EV/A1b-installer.txt"; then
      check A1b installer-under-test info "appliance installer replaced by ${LAB_ADOPT_INSTALLER_LABEL:-$LAB_ADOPT_INSTALLER} (sha256 $(sha256sum "$LAB_ADOPT_INSTALLER" | cut -c1-16)…)"
    else check A1b installer-under-test fail "could not install the installer under test (exit $rc)"; rec_origin_stop; return 0; fi
  fi
  # A2 host-component refresh with outbound HTTP(S) blocked (an appliance with no
  # route to Docker Hub / the Alpine CDN): the gateway must keep serving.
  rc=0; gpriv --timeout 1800 > "$EV/A2-refresh-offline.txt" 2>&1 <<'EOS' || rc=$?
nft add table inet culvertlab
nft 'add chain inet culvertlab out { type filter hook output priority -10; policy accept; }'
nft 'add chain inet culvertlab fwd { type filter hook forward priority -10; policy accept; }'
nft add rule inet culvertlab out ip daddr != '{ 127.0.0.0/8, 10.0.2.2 }' tcp dport '{ 80, 443 }' reject
nft add rule inet culvertlab out meta nfproto ipv6 tcp dport '{ 80, 443 }' reject
nft add rule inet culvertlab fwd ip daddr != 10.0.2.2 tcp dport '{ 80, 443 }' reject
nft add rule inet culvertlab fwd meta nfproto ipv6 tcp dport '{ 80, 443 }' reject
echo "egress-blocked"
timeout 1500 culvert-firstboot --repair-agent; echo "repair-rc=$?"
nft delete table inet culvertlab; echo "egress-restored"
tail -n 40 /var/log/culvert-firstboot.log 2>/dev/null | sed 's/\(PASSPHRASE\|TOKEN\)=[^ ]*/\1=<redacted>/g'
EOS
  for _ in $(seq 1 30); do curl -fsS -m 3 "$P/health" >/dev/null 2>&1 && break; sleep 5; done
  f="$EV/A2-state.txt"; adopt_state "$f"
  t="traffic=$(rec_traffic && echo ok || echo no) health=$(curl -fsS -m 3 -o /dev/null -w '%{http_code}' "$P/health" 2>/dev/null || echo 000)"
  check A2 refresh-offline info "repair $(grep -m1 '^repair-rc=' "$EV/A2-refresh-offline.txt" || echo 'repair-rc=?'); egress $(grep -c '^egress-' "$EV/A2-refresh-offline.txt")/2 marks"
  if [[ "$(kv "$f" clam-id)" == "$old" && "$(kv "$f" clam-state)" == running/* && "$(kv "$f" proxy-id)" == "$LAB_ADOPT_IMAGE_ID" && "$t" == "traffic=ok health=200" ]]; then
    check A2 offline-refresh-keeps-serving pass "old sidecar still running ($old, $(kv "$f" clam-state)); proxy unchanged; $t"
  else check A2 offline-refresh-keeps-serving fail "$t; $(tr '\n' ' ' < "$f" | head -c 400)"; fi
  if [[ "$(kv "$f" compose-ref)" == "$LAB_ADOPT_NEW_REF" && "$(kv "$f" new-tag-present)" == no ]]; then
    check A2 compose-names-a-buildable-image fail "after the failed offline refresh the host compose file names $LAB_ADOPT_NEW_REF, which does not exist locally: the next stack start (maintenance reboot) must build it and cannot offline"
  else check A2 compose-names-a-buildable-image pass "compose names $(kv "$f" compose-ref) (present locally: $(kv "$f" new-tag-present))"; fi
  # A3 refresh online.
  rc=0; gpriv --timeout 1800 > "$EV/A3-refresh-online.txt" 2>&1 <<'EOS' || rc=$?
timeout 1500 culvert-firstboot --repair-agent; echo "repair-rc=$?"
tail -n 40 /var/log/culvert-firstboot.log 2>/dev/null | sed 's/\(PASSPHRASE\|TOKEN\)=[^ ]*/\1=<redacted>/g'
EOS
  f="$EV/A3-state.txt"; adopt_wait_clam_healthy "$f" || true; new="$(kv "$f" clam-id)"
  for _ in $(seq 1 60); do curl -fsS -m 3 "$P/health" >/dev/null 2>&1 && break; sleep 5; done
  v="$(for _ in $(seq 1 24); do x="$(eicar_verdict)"; [[ $x == av ]] && { echo av; break; }; sleep 5; done)"
  t="traffic=$(rec_traffic && echo ok || echo no) eicar=${v:-none}"
  if [[ "$(kv "$f" compose-ref)" == "$LAB_ADOPT_NEW_REF" && "$(kv "$f" clam-image)" == "$LAB_ADOPT_NEW_REF" && -n "$new" && "$new" != "$old" \
        && "$(kv "$f" clam-pkgs)" == "$LAB_ADOPT_PKGS" && "$(kv "$f" clam-state)" == running/healthy && "$(kv "$f" proxy-id)" == "$LAB_ADOPT_IMAGE_ID" && "$t" == "traffic=ok eicar=av" ]]; then
    check A3 refresh-adopts-new-sidecar pass "$(grep -m1 '^repair-rc=' "$EV/A3-refresh-online.txt"); compose names $LAB_ADOPT_NEW_REF; culvert-clamav runs it ($new, was $old): $(kv "$f" clam-pkgs); healthy; proxy still $LAB_ADOPT_IMAGE_ID (not reseeded); $t"
  else check A3 refresh-adopts-new-sidecar fail "exit $rc $(grep -m1 '^repair-rc=' "$EV/A3-refresh-online.txt"); $t; $(tr '\n' ' ' < "$f" | head -c 500)"; fi
  # A4 maintenance reboot: the adopted sidecar is what comes back.
  gpriv --nowait > "$EV/A4-reboot.txt" 2>&1 <<<'culvert-os-update reboot' || true
  local deadline=$(( $(date +%s) + LAB_FIRSTBOOT_TIMEOUT )); sleep 20
  until curl -fsS -m 3 "$P/health" >/dev/null 2>&1 && gop status-json >/dev/null 2>&1; do
    qemu_alive && (( $(date +%s) < deadline )) || break; sleep 10; done
  f="$EV/A4-state.txt"; adopt_wait_clam_healthy "$f" || true
  v="$(for _ in $(seq 1 24); do x="$(eicar_verdict)"; [[ $x == av ]] && { echo av; break; }; sleep 5; done)"
  t="traffic=$(rec_traffic && echo ok || echo no) eicar=${v:-none}"
  # The NEW sidecar must be what comes back — never "whatever ran before the
  # reboot" (run 37625917513 passed A4 on the old sidecar after A3 had failed).
  if [[ "$(kv "$f" clam-id)" == "$new" && -n "$new" && "$new" != "$old" && "$(kv "$f" clam-pkgs)" == "$LAB_ADOPT_PKGS" && "$(kv "$f" clam-state)" == running/healthy && "$(kv "$f" proxy-id)" == "$LAB_ADOPT_IMAGE_ID" && "$t" == "traffic=ok eicar=av" ]]; then
    check A4 reboot-keeps-new-sidecar pass "after culvert-os-update reboot: culvert-clamav $new healthy; proxy $LAB_ADOPT_IMAGE_ID; $t"
  else check A4 reboot-keeps-new-sidecar fail "$t; $(tr '\n' ' ' < "$f" | head -c 400)"; fi
  # A5 (ASTRA): keep the EXACT adopted sidecar for the scan job. A refresh
  # BUILDS the sidecar on the host (apk at build time), so its bytes differ
  # from the OVA's baked archive and from any rebuild: only these bytes, taken
  # from the host that runs them, may carry a scan result.
  adopt_export_sidecar "$(kv "$f" clam-id)" "$new" "$old"
  rm -f "$WORK/eicar-origin/culvert-image.tar"; rec_origin_stop
  redact_tree
}
# ── console: the boot screen as an operator sees it on ESXi ─────────────────
# VMware SVGA (vmwgfx) and NO serial port, so /dev/console is tty1 exactly as on
# an ESXi VM (the OVA's console=ttyS0 finds no UART). Privileged steps log in on
# a virtio console (hvc0 getty) with the console password supplied through the
# OVF `password` property. Every distinct VGA frame is kept (vga-capture.py)
# through: cold first boot, a maintenance reboot with a slow and a failed unit,
# Esc during the splash, the kernel-log VT, a clean maintenance reboot, and a
# serial-only boot (no display adapter). Run in its own LAB_DIR after preflight.
VGA_CMDS="$WORK/vga-cmds"; VGA_STOP="$WORK/vga-stop"
# A failed row is recorded and the scenario continues (set -e must not end it).
vcheck() { check "$@" || true; }
vmark() { printf 'mark %s\n' "$*" >> "$VGA_CMDS"; log "console: $*"; }
vkey()  { printf 'sendkey %s\n' "$1" >> "$VGA_CMDS"; }
# tty1's text as the kernel holds it (/dev/vcs1): what is on the operator's screen.
vtty() { groot "cat /proc/consoles; echo ---active; cat /sys/class/tty/console/active; echo ---printk; cat /proc/sys/kernel/printk
echo \"---fg \$(fgconsole 2>/dev/null) kdmode-tty1 \$(python3 -c 'import array,fcntl,os,sys;b=array.array(sys.argv[1],[0]);fcntl.ioctl(os.open(sys.argv[2],os.O_RDONLY),0x4B3B,b);print(b[0])' i /dev/tty1 2>/dev/null) (0=text 1=graphics)\"
w=\$(stty -F /dev/tty1 size 2>/dev/null | cut -d' ' -f2); echo \"---size \$(stty -F /dev/tty1 size 2>/dev/null)\"
for v in 1 12; do echo \"---vcs\$v\"; [ -e /dev/vcs\$v ] && fold -w \"\${w:-80}\" /dev/vcs\$v | sed 's/[[:space:]]*\$//' | grep -v '^\$'; done
echo ---journal; journalctl -b -o short-monotonic --no-pager 2>/dev/null | grep -E 'Console: switching|fbcon|vmwgfx|plymouth|Started getty@tty1|LAB-|Startup finished|lab-console' | head -80" 300 > "$1" 2>&1 || true; }
# Lines on tty1 that are not the console UI: kernel log, systemd status lines,
# unit output, the lab's own markers.
# tty1 must be in text mode once the console owns it (0 = KD_TEXT): a VT left in
# graphics mode shows a frozen frame however correct the console's output is.
vkdmode_check() { local m; m="$(sed -n 's/^---fg .* kdmode-tty1 \([0-9]*\).*/\1/p' "$3")"
  if [[ "$m" == 0 ]]; then vcheck "$1" "$2" pass "tty1 KD_TEXT; $(sed -n 's/^---fg //p' "$3")"
  else vcheck "$1" "$2" fail "tty1 KD mode '${m:-unread}' (want 0); $(sed -n 's/^---fg //p' "$3")"; fi; }
# Esc, judged against the documented contract (firstboot-experience.md): the
# first Esc replaces the splash with the boot messages; a second Esc does not
# bring the splash back while it runs. Probe samples are aligned to the
# host's key presses (8 s and 20 s after the splash window opened) through
# the window marker's guest uptime; 2 s either side is left unjudged.
vesc_judge() { grep -a 'LAB-VCS\|LAB-SPLASH-WINDOW-START' "$WORK/console.log" | tr -d '\r' > "$EV/V2-vcs-probe.txt" 2>/dev/null || true
  local r; r="$(python3 - "$EV/V2-vcs-probe.txt" <<'PY'
import re, sys
t0 = None; rows = []
for l in open(sys.argv[1]):
    m = re.search(r"LAB-SPLASH-WINDOW-START up=([0-9.]+)", l)
    if m: t0 = float(m.group(1)); rows = []; continue   # the V2 boot's window
    m = re.search(r"LAB-VCS up=([0-9.]+) plymouth=(\w+) title=(\d) status=(\d+)", l)
    if m: rows.append((float(m.group(1)), m.group(2), int(m.group(3)), int(m.group(4))))
if t0 is None: print("none no-window"); sys.exit()
up = [r for r in rows if r[1] == "up"]
seg = lambda a, b: [r for r in up if t0 + a <= r[0] < t0 + b]
pre, mid, post = seg(0, 6), seg(10, 18), seg(22, 44)
def v(s, want_title):
    if not s: return "unsampled"
    bad = [r for r in s if r[2] != want_title]
    return "ok" if not bad else f"bad:{len(bad)}/{len(s)}"
print(v(pre, 1), v(mid, 0), v(post, 0), f"pre={len(pre)} mid={len(mid)} post={len(post)} mid_status_max={max([r[3] for r in mid] or [0])}")
PY
)"
  set -- $r
  vcheck V2 splash-before-esc "$( [[ "$1" == ok ]] && echo pass || echo fail)" "title on tty1 before the first Esc: $1 (${*:4})"
  vcheck V2 esc-shows-boot-messages "$( [[ "$2" == ok ]] && echo pass || echo fail)" "after the first Esc, with the splash still running, tty1 shows the boot messages, not the title: $2 (${*:4}; V2-vcs-probe.txt)"
  vcheck V2 esc-one-way "$( [[ "$3" == ok ]] && echo pass || echo fail)" "after the second Esc the splash title does not come back while Plymouth runs: $3 (${*:4})"; }
# Whether systemd's TTYReset could run for getty@tty1: it skips the whole reset
# (KD_TEXT included) when it cannot open /dev/console within 1 s.
vttyreset() { groot "systemctl show getty@tty1 -p TTYReset -p TTYVHangup -p TTYPath; echo ---devconsole; readlink -f /dev/console; cat /sys/class/tty/console/active
s=\$(date +%s.%N); timeout 5 sh -c ': > /dev/console' 2>&1; rc=\$?; e=\$(date +%s.%N); echo \"open-rc=\$rc seconds=\$(awk -v a=\$s -v b=\$e 'BEGIN{printf \"%.2f\", b-a}')\"
echo ---getty; journalctl -b -o short-monotonic --no-pager -u getty@tty1 -u plymouth-quit -u plymouth-quit-wait 2>/dev/null | head -40" 120 > "$1" 2>&1 || true; }
# plymouth-start.service's verdict this boot: Result=success on a machine with a
# display, Result=exec-condition (culvert-has-display) on one without.
vplymouth() { groot "systemctl show plymouth-start.service -p ActiveState -p Result -p ExecCondition --no-pager; echo ---has-display; /opt/culvert-appliance/bin/culvert-has-display; echo rc=\$?; echo ---pci-display; grep -l '^0x03' /sys/bus/pci/devices/*/class 2>/dev/null; echo ---journal; journalctl -b -o short-monotonic --no-pager -u plymouth-start -u plymouth-quit -u plymouth-quit-wait 2>/dev/null | head -20" 120 > "$1" 2>&1 || true; }
vplymouth_check() { local r; r="$(sed -n 's/^Result=//p' "$3" | head -1)"
  if [[ "$r" == "$4" ]]; then vcheck "$1" "$2" pass "plymouth-start Result=$r ($(sed -n 's/^rc=//p' "$3" | head -1 | sed 's/^/has-display rc=/'))"
  else vcheck "$1" "$2" fail "plymouth-start Result='${r:-unread}', want $4 ($(tr '\n' ' ' < "$3" | cut -c1-200))"; fi; }
vstray() { sed -n '/^---vcs1$/,/^---vcs12$/p' "$1" | grep -E '^\[ *[0-9]+\.[0-9]+\]|\[ *(OK|FAILED|DEPEND) *\]|LAB-|br-[0-9a-f]{6,}|veth[0-9a-f]|cloud-init|culvert-firstboot:|^ *Start(ing|ed) [A-Za-z].*\.(service|socket|target|mount|timer)' | head -20; }
vwait_ready() { local deadline=$(( $(date +%s) + ${1:-1800} ))
  until gop status-json > "$WORK/status-json.tmp" 2>/dev/null && [[ " $(recorded_steps "$WORK/status-json.tmp") " == *" complete "* ]] \
        && curl -fsS -m 3 "$P/health" >/dev/null 2>&1; do
    qemu_alive && (( $(date +%s) < deadline )) || return 1; sleep 5; done; }
vqemu() { local acc=(-machine "pc,accel=tcg" -cpu max)
  [[ "$ACCEL" == kvm ]] && acc=(-machine "pc,accel=kvm" -cpu host)
  : > "$WORK/console.log"; rm -f "$SER_SOCK" "$MON_SOCK"
  qemu-system-x86_64 -name culvert-console "${acc[@]}" -smp "$LAB_CPUS" -m "$LAB_MEM_MB" \
    -drive "file=$WORK/coverlay.qcow2,if=none,id=d0,format=qcow2,cache=writeback" \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=d0,bus=scsi0.0 \
    -drive "file=$WORK/ovfenv.iso,if=none,id=cd0,media=cdrom,readonly=on" -device ide-cd,drive=cd0 \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$LAB_SSH_PORT-:22,hostfwd=tcp:127.0.0.1:$LAB_PROXY_PORT-:8080,hostfwd=tcp:127.0.0.1:$LAB_UI_PORT-:9090" \
    -device e1000,netdev=n0 "$@" \
    -monitor "unix:$MON_SOCK,server,nowait" -pidfile "$WORK/qemu.pid" -daemonize; }
vcapture_start() { rm -f "$VGA_STOP"; : >> "$VGA_CMDS"
  nohup python3 "$HERE/vga-capture.py" --mon "$MON_SOCK" --out "$EV/V-frames" --stop "$VGA_STOP" --cmds "$VGA_CMDS" \
    --interval "${LAB_VGA_INTERVAL:-0.5}" > "$WORK/vga-capture.log" 2>&1 &
  echo $! > "$WORK/vga-capture.pid"; }
vcapture_stop() { local p; touch "$VGA_STOP"; p="$(cat "$WORK/vga-capture.pid" 2>/dev/null || true)"
  for _ in $(seq 1 20); do [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null || break; sleep 0.5; done; }
# vsheet NAME FROM TO — contact sheet of every other frame captured in [FROM,TO) s.
vsheet() { local name="$1" from="$2" to="$3" files=()
  command -v montage >/dev/null || return 0
  mapfile -t files < <(awk -F'\t' -v a="$from" -v b="$to" -v d="$EV/V-frames" \
    '$2>=a && $2<b {printf "%s/%05d_%08.2f.png\n", d, $1, $2}' "$EV/V-frames/frames.tsv" | awk 'NR%2==1' | head -60)
  (( ${#files[@]} )) || return 0
  montage "${files[@]}" -tile 6x -geometry 360x200+3+3 -label '%t' -pointsize 9 "$EV/$name.png" 2>/dev/null || true; }
vtime() { awk -F'\t' 'END{print $1+0}' "$EV/V-frames/events.tsv" 2>/dev/null || echo 0; }
vstray_check() { local id="$1" name="$2" f="$3" s; s="$(vstray "$f" || true)"
  if [[ -z "$s" ]]; then vcheck "$id" "$name" pass "tty1 ($(sed -n 's/^---size //p' "$f")) holds only the console UI"
  else vcheck "$id" "$name" fail "stray text on tty1: $(printf '%s' "$s" | head -5 | tr '\n' '|' | cut -c1-400)"; fi; }
cmd_console() { local ova got vmdk f t1 t2 t3
  [[ -n "${ACCEL:-}" ]] || die "run preflight first"
  ova="${LAB_OVA:?LAB_OVA}"; got="$(sha256sum "$ova" | cut -d' ' -f1)"
  [[ "$got" == "${LAB_OVA_SHA256:?LAB_OVA_SHA256}" ]] || { vcheck V ova-sha256 fail "got $got want $LAB_OVA_SHA256"; return 1; }
  # Producer identity: every frame below comes from THIS OVA (sha256 checked
  # against the pinned candidate, every .mf digest checked by extract_ova),
  # and V1 checks the guest names the same build on its own console.
  OVA_NAME="$(basename "$ova")"; OVA_SHA256="$got"
  vcheck V ova-sha256 pass "$OVA_NAME sha256 $got (= the pinned candidate)"
  rm -rf "$WORK/ova"; extract_ova "$ova" "$WORK/ova" || { vcheck V ova-manifest fail ".mf mismatch"; return 1; }
  vcheck V ova-manifest pass "every file digest in the OVA's .mf verified"
  vmdk="$(ls "$WORK/ova/"*.vmdk)"; qemu-img convert -O qcow2 "$vmdk" "$WORK/cbase.qcow2" >/dev/null; rm -f "$vmdk"; chmod 0444 "$WORK/cbase.qcow2"
  qemu-img create -q -f qcow2 -F qcow2 -b "$WORK/cbase.qcow2" "$WORK/coverlay.qcow2"
  rm -f "$SEC/id_ed25519"* "$SEC/console-pass"; ssh-keygen -q -t ed25519 -N '' -C "culvert-console-$RUN_ID" -f "$SEC/id_ed25519"
  printf '%s-Lab9\n' "$(head -c 4096 /dev/urandom | tr -dc 'A-Za-z0-9' | cut -c1-20)" > "$SEC/console-pass"; chmod 0600 "$SEC/console-pass"
  mkdir -p "$WORK/ovfenv"
  python3 - "$WORK/ovfenv/ovf-env.xml" "console-$RUN_ID" "$(cat "$SEC/id_ed25519.pub")" "$(cat "$SEC/console-pass")" <<'OVFENV'
import sys
from xml.sax.saxutils import quoteattr
props = {"instance-id": sys.argv[2], "hostname": "culvert-console", "public-keys": sys.argv[3],
         "password": sys.argv[4], "culvert.net.mode": "dhcp"}
p = "\n".join(f'    <Property oe:key={quoteattr(k)} oe:value={quoteattr(v)}/>' for k, v in props.items())
with open(sys.argv[1], "w") as f:
    f.write('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<Environment xmlns="http://schemas.dmtf.org/ovf/environment/1" '
            'xmlns:oe="http://schemas.dmtf.org/ovf/environment/1" oe:id="">\n'
            f'  <PropertySection>\n{p}\n  </PropertySection>\n</Environment>\n')
OVFENV
  if command -v genisoimage >/dev/null; then genisoimage -quiet -o "$WORK/ovfenv.iso" -V OVFENV -r -J "$WORK/ovfenv"
  else xorriso -as mkisofs -quiet -o "$WORK/ovfenv.iso" -V OVFENV -r -J "$WORK/ovfenv"; fi
  # shellcheck disable=SC2054 # QEMU option values contain commas
  local esxi=(-vga vmware -display none -serial none -device virtio-serial-pci
              -chardev "socket,id=hvc,path=$SER_SOCK,server=on,wait=off,logfile=$WORK/console.log,logappend=on"
              -device virtconsole,chardev=hvc)
  # V1 cold first boot.
  vqemu "${esxi[@]}"; vcapture_start; vmark "power-on: cold first boot (VMware SVGA, no serial port)"
  if ! vwait_ready "$LAB_FIRSTBOOT_TIMEOUT"; then
    vcheck V1 first-boot fail "not ready within ${LAB_FIRSTBOOT_TIMEOUT}s"; vcapture_stop; vsheet V1-first-boot 0 99999; return 1; fi
  vmark "first boot complete (status-json complete, /health 200)"; sleep 30
  f="$EV/V1-tty.txt"; vtty "$f"; t1="$(vtime)"
  # On ESXi with no serial port the 8250 legacy port still registers, so
  # /dev/console is a ttyS0 with no hardware behind it (baseline run
  # 37631873993). Recorded, not judged: it is the topology ESXi has.
  vcheck V1 console-topology info "$(sed -n '1,/^---active$/p' "$f" | grep -v '^---' | tr -s ' ' | tr '\n' ';') printk=$(sed -n '/^---printk$/{n;p}' "$f" | tr '\t' ' ')"
  vstray_check V1 tty1-after-first-boot "$f"
  vkdmode_check V1 tty1-text-mode "$f"
  vplymouth "$EV/V1-plymouth.txt"; vplymouth_check V1 splash-on-display "$EV/V1-plymouth.txt" success
  vttyreset "$EV/V1-ttyreset.txt"
  vcheck V1 getty-tty-reset info "$(grep -E '^(TTYReset|TTYVHangup)=|^open-rc=' "$EV/V1-ttyreset.txt" | tr '\n' ' ')(V1-ttyreset.txt)"
  # V2 maintenance reboot with a slow unit ahead of logins and a failing unit.
  gpriv --timeout 120 > "$EV/V2-units.txt" 2>&1 <<'EOS' || true
cat > /etc/systemd/system/lab-console-delay.service <<'U'
[Unit]
Description=Lab console qualification: a slow unit ahead of logins
DefaultDependencies=no
After=local-fs.target systemd-udevd.service
Before=systemd-user-sessions.service plymouth-quit.service plymouth-quit-wait.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'echo "LAB-SPLASH-WINDOW-START up=$(cut -d" " -f1 /proc/uptime)" > /dev/hvc0; echo "<6>LAB-KMSG-INFO during the splash" > /dev/kmsg; echo "<3>LAB-KMSG-ERR during the splash" > /dev/kmsg; echo "LAB-CONSOLE-LINE written to /dev/console during the splash"; sleep 45; echo LAB-SPLASH-WINDOW-END > /dev/hvc0'
StandardOutput=journal+console
[Install]
WantedBy=sysinit.target
U
# What tty1 SHOWS through the splash, every 0.5 s: the title (splash) or not
# (Esc's details view), and how many systemd status lines are on screen.
cat > /usr/local/sbin/lab-console-vcsprobe <<'P'
#!/bin/sh
# Stops once Plymouth has quit: /dev/hvc0 is also the lab's authenticated
# console transport, and a probe still writing there collides with it (the
# V2 tty read of run 38012981822 came back empty).
i=0; seen=0
while [ $i -lt 180 ]; do
  if pidof plymouthd >/dev/null; then seen=1; elif [ $seen = 1 ]; then break; fi
  t=0; grep -qa 'C U L V E R T' /dev/vcs1 2>/dev/null && t=1
  n=$(fold -w 80 /dev/vcs1 2>/dev/null | grep -cE '\[ *(OK|FAILED|DEPEND) *\]|Start(ing|ed) ')
  echo "LAB-VCS up=$(cut -d' ' -f1 /proc/uptime) plymouth=$(pidof plymouthd >/dev/null && echo up || echo down) title=$t status=$n" > /dev/hvc0
  i=$((i+1)); sleep 0.5
done
P
chmod 0755 /usr/local/sbin/lab-console-vcsprobe
cat > /etc/systemd/system/lab-console-vcsprobe.service <<'U'
[Unit]
Description=Lab console qualification: what tty1 shows through the splash (no ordering effect)
DefaultDependencies=no
After=local-fs.target systemd-udevd.service
[Service]
Type=simple
ExecStart=/usr/local/sbin/lab-console-vcsprobe
[Install]
WantedBy=sysinit.target
U
cat > /etc/systemd/system/lab-console-fail.service <<'U'
[Unit]
Description=Lab console qualification: a unit that fails during boot
Before=systemd-user-sessions.service
[Service]
Type=oneshot
ExecStart=/bin/false
[Install]
WantedBy=multi-user.target
U
systemctl daemon-reload && systemctl enable lab-console-delay.service lab-console-fail.service lab-console-vcsprobe.service
EOS
  : > "$WORK/console.log"; vmark "maintenance reboot requested (slow + failing unit installed)"
  gpriv --nowait > "$EV/V2-reboot.txt" 2>&1 <<<'culvert-os-update reboot' || true
  for _ in $(seq 1 600); do grep -qa LAB-SPLASH-WINDOW-START "$WORK/console.log" 2>/dev/null && break; sleep 0.5; done
  if grep -qa LAB-SPLASH-WINDOW-START "$WORK/console.log"; then
    vmark "slow unit running (splash window open)"; sleep 8; vmark "Esc pressed"; vkey esc; sleep 12
    vmark "Esc pressed again"; vkey esc; sleep 8
  else vcheck V2 splash-window info "the slow unit's start marker never reached hvc0"; fi
  vwait_ready 900 || vcheck V2 maintenance-reboot fail "not ready after the maintenance reboot"
  vmark "ready after maintenance reboot"; sleep 20
  f="$EV/V2-tty.txt"; vtty "$f"; vstray_check V2 tty1-after-reboot-with-failures "$f"; vkdmode_check V2 tty1-text-mode "$f"
  vesc_judge
  # V3 after boot: kernel messages and /dev/console output while the console UI is up.
  gpriv --timeout 300 > "$EV/V3-writes.txt" 2>&1 <<'EOS' || true
echo "<6>LAB-KMSG-POSTBOOT info" > /dev/kmsg; echo "<3>LAB-KMSG-POSTBOOT err" > /dev/kmsg
echo "LAB-CONSOLE-POSTBOOT line" > /dev/console
docker restart culvert-clamav >/dev/null
EOS
  vmark "post-boot kernel + /dev/console writes, clamav restarted"; sleep 15
  f="$EV/V3-tty.txt"; vtty "$f"; vstray_check V3 tty1-after-postboot-writes "$f"
  vmark "Alt+F12"; vkey alt-f12; sleep 4; vmark "Alt+F1"; vkey alt-f1; sleep 4
  # V4 clean maintenance reboot.
  groot 'systemctl disable lab-console-delay.service lab-console-fail.service lab-console-vcsprobe.service; rm -f /etc/systemd/system/lab-console-delay.service /etc/systemd/system/lab-console-fail.service /etc/systemd/system/lab-console-vcsprobe.service /usr/local/sbin/lab-console-vcsprobe; systemctl daemon-reload' 120 > /dev/null 2>&1 || true
  # Guest-side truth for the clean reboot's frames: the foreground VT and
  # tty1's KD mode every 0.25 s from early boot (a frozen frame is either a
  # VT left in graphics mode or the emulated display not refreshing).
  gpriv --timeout 120 > "$EV/V4-probe-unit.txt" 2>&1 <<'EOS' || true
cat > /usr/local/sbin/lab-console-probe <<'P'
#!/bin/sh
i=0
while [ $i -lt 120 ]; do
  m=$(python3 -c 'import array,fcntl,os,sys;b=array.array(sys.argv[1],[0]);fcntl.ioctl(os.open(sys.argv[2],os.O_RDONLY),0x4B3B,b);print(b[0])' i /dev/tty1 2>/dev/null)
  echo "LAB-PROBE up=$(cut -d' ' -f1 /proc/uptime) fg=$(fgconsole 2>/dev/null) kdmode=$m plymouth=$(pidof plymouthd >/dev/null && echo up || echo down)" > /dev/hvc0
  i=$((i+1)); sleep 0.25
done
P
chmod 0755 /usr/local/sbin/lab-console-probe
cat > /etc/systemd/system/lab-console-probe.service <<'U'
[Unit]
Description=Lab console qualification: VT/KD-mode probe (no ordering effect)
DefaultDependencies=no
After=local-fs.target systemd-udevd.service
[Service]
Type=simple
ExecStart=/usr/local/sbin/lab-console-probe
[Install]
WantedBy=sysinit.target
U
systemctl daemon-reload && systemctl enable lab-console-probe.service
EOS
  t2="$(vtime)"; vmark "clean maintenance reboot requested"
  gpriv --nowait > "$EV/V4-reboot.txt" 2>&1 <<<'culvert-os-update reboot' || true
  sleep 20; vwait_ready 900 || vcheck V4 maintenance-reboot fail "not ready after the clean maintenance reboot"
  vmark "ready after clean maintenance reboot"; sleep 20
  f="$EV/V4-tty.txt"; vtty "$f"; vstray_check V4 tty1-after-clean-reboot "$f"; vkdmode_check V4 tty1-text-mode "$f"
  grep -a 'LAB-PROBE' "$WORK/console.log" > "$EV/V4-probe.txt" 2>/dev/null || true
  vcheck V4 vt-probe info "$(wc -l < "$EV/V4-probe.txt") samples; $(sed -n 's/^---fg //p' "$f"); first: $(head -1 "$EV/V4-probe.txt" | tr -d '\r'); last: $(tail -1 "$EV/V4-probe.txt" | tr -d '\r')"
  # Once plymouth has exited nothing may hold tty1 in graphics mode (the
  # defect: KD mode 1 from 4.2 s to 37 s with plymouth gone).
  local stuck; stuck="$(tr -d '\r' < "$EV/V4-probe.txt" | grep -c 'plymouth=down' || true)"
  if [[ "${stuck:-0}" == 0 ]]; then vcheck V4 no-graphics-after-splash fail "no probe sample after plymouth exited"
  elif tr -d '\r' < "$EV/V4-probe.txt" | grep 'plymouth=down' | grep -qv 'kdmode=0'; then
    vcheck V4 no-graphics-after-splash fail "tty1 not in text mode after plymouth exited: $(tr -d '\r' < "$EV/V4-probe.txt" | grep 'plymouth=down' | grep -v 'kdmode=0' | head -2 | tr '\n' ' ')"
  else vcheck V4 no-graphics-after-splash pass "$stuck samples after plymouth exited, all kdmode=0"; fi
  # The text splash draws at once (DeviceTimeout=0.1): while plymouth is up
  # tty1 is in graphics mode only briefly, never for Ubuntu's 8 s wait.
  vcheck V4 splash-graphics-window info "$(tr -d '\r' < "$EV/V4-probe.txt" | grep 'plymouth=up' | grep -c 'kdmode=1' || true) samples (x0.25 s) in graphics mode while plymouth was up"
  # Producer identity, read once the guest has printed its login banner on
  # the console (it does after a reboot; at first boot the check ran before).
  local want_ver; want_ver="$(sed -n 's/^culvert-appliance-\(.*\)-ubuntu-[0-9.]*\.ova$/\1/p' <<<"$OVA_NAME")"
  # tty1's Build field is width-limited ("1.0.260-candidate.g91e..."): the
  # shown text, ellipsis removed, must be a prefix of the version (>= 12 chars).
  local shown; shown="$(grep -m1 -o 'Build  *[^ ]*' "$EV/V4-tty.txt" | awk '{print $2}')"; shown="${shown%...}"
  if [[ -n "$want_ver" ]] && tr -d '\r' < "$WORK/console.log" | grep -qaF "Culvert appliance $want_ver (" \
     && (( ${#shown} >= 12 )) && [[ "$want_ver" == "$shown"* ]]; then
    vcheck V4 console-build-identity pass "the guest's console banner and tty1 Build line name $want_ver, the version of the booted OVA $OVA_SHA256"
  else vcheck V4 console-build-identity fail "want '$want_ver' on the console banner and tty1 Build line; banner: $(tr -d '\r' < "$WORK/console.log" | grep -a -m1 -o 'Culvert appliance [0-9][^ ]*' ); tty1: $(grep -m1 -o 'Build  *[^ ]*' "$EV/V4-tty.txt")"; fi
  groot 'systemctl disable lab-console-probe.service; rm -f /etc/systemd/system/lab-console-probe.service /usr/local/sbin/lab-console-probe; systemctl daemon-reload' 120 > /dev/null 2>&1 || true
  t3="$(vtime)"; vcapture_stop
  vsheet V1-first-boot 0 "$t1"; vsheet V2-V3-reboot-esc-postboot "$t1" "$t2"; vsheet V4-clean-reboot "$t2" "$t3"
  vcheck V frames info "$(wc -l < "$EV/V-frames/frames.tsv") distinct frames, $(grep -c . "$EV/V-frames/events.tsv") events (V-frames/, V*-*.png contact sheets)"
  # V5 serial-only: no display adapter; the serial port is the only console.
  groot 'systemctl poweroff' 60 > /dev/null 2>&1 || true
  for _ in $(seq 1 60); do qemu_alive || break; sleep 2; done
  if qemu_alive; then kill "$(cat "$WORK/qemu.pid")" 2>/dev/null || true; sleep 2; fi
  vqemu -vga none -display none -chardev "socket,id=ser0,path=$SER_SOCK,server=on,wait=off,logfile=$WORK/console.log,logappend=on" -serial chardev:ser0
  vwait_ready 900 || vcheck V5 serial-only-boot fail "not ready without a display adapter"
  sleep 10; cp "$WORK/console.log" "$EV/V5-serial.log"
  vplymouth "$EV/V5-plymouth.txt"; vplymouth_check V5 no-splash-without-display "$EV/V5-plymouth.txt" exec-condition
  if grep -qa 'Linux version' "$EV/V5-serial.log" && grep -qaE 'OK .*(Started|Finished|Reached)' "$EV/V5-serial.log" && grep -qa 'login:' "$EV/V5-serial.log"; then
    vcheck V5 serial-only-boot pass "serial carries the kernel log ($(grep -ac '^\[ *[0-9]' "$EV/V5-serial.log") lines), systemd status and a login prompt"
  else vcheck V5 serial-only-boot fail "serial log incomplete (kernel=$(grep -ac 'Linux version' "$EV/V5-serial.log") ok=$(grep -acE 'OK .*(Started|Finished|Reached)' "$EV/V5-serial.log") login=$(grep -ac 'login:' "$EV/V5-serial.log"))"; fi
  # Shutdown on serial: with no display no Plymouth shutdown splash either, so
  # systemd's stop lines and the kernel's last line reach the serial console.
  local off; off="$(wc -c < "$WORK/console.log")"
  gpriv --nowait > "$EV/V5-poweroff.txt" 2>&1 <<<'systemctl poweroff' || true
  for _ in $(seq 1 90); do qemu_alive || break; sleep 2; done
  tail -c "+$((off + 1))" "$WORK/console.log" > "$EV/V5-shutdown.log" 2>/dev/null || true
  if grep -qaE 'OK .*Stopped' "$EV/V5-shutdown.log" && grep -qa 'reboot: Power down' "$EV/V5-shutdown.log"; then
    vcheck V5 serial-shutdown pass "serial carries $(grep -acE 'OK .*Stopped' "$EV/V5-shutdown.log") systemd stop lines and the kernel's power-down line"
  else vcheck V5 serial-shutdown fail "serial shutdown log incomplete (stopped=$(grep -acE 'OK .*Stopped' "$EV/V5-shutdown.log") powerdown=$(grep -ac 'reboot: Power down' "$EV/V5-shutdown.log"); qemu $(qemu_alive && echo still running || echo exited))"; fi
  redact_tree
}
failures() { grep -c '"result":"fail"' "$JSONL" 2>/dev/null || true; }
# LAB_FAIL_FAST=1 (iteration runs only): after each phase, stop as soon as any
# check has failed. The EXIT trap still collects evidence and tears the guest
# down, so a red iteration run ends ~20 min sooner with the same evidence up to
# the failure. A FINAL qualification run must leave it unset so every phase is
# recorded even when one fails.
fail_fast_after() {
  [[ "${LAB_FAIL_FAST:-0}" == 1 ]] || return 0
  local n; n="$(failures)"; [[ "$n" == 0 ]] && return 0
  check F fail-fast info "LAB_FAIL_FAST=1: stopped after phase '$1' with $n failure(s); later phases did not run (iteration run, not a qualification)"
  log "failures: $n"; exit 1
}
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
  history) cmd_history; [[ "$(failures)" == 0 ]] ;;
  adoption) cmd_adoption; [[ "$(failures)" == 0 ]] ;;
  engine-surface) cmd_engine_surface; [[ "$(failures)" == 0 ]] ;;
  console) trap 'cmd_collect || true; cmd_down || true' EXIT; cmd_console; [[ "$(failures)" == 0 ]] ;;
  fp2) cmd_fp2; [[ "$(failures)" == 0 ]] ;;
  cachebypass) cmd_cachebypass; [[ "$(failures)" == 0 ]] ;;
  ldap) cmd_ldap; [[ "$(failures)" == 0 ]] ;;
  collect) cmd_collect ;;
  down) cmd_down ;;
  all)
    trap 'cmd_collect || true; cmd_down || true' EXIT
    cmd_preflight; cmd_up; cmd_qualify; fail_fast_after qualify
    if [[ "${LAB_FP2:-0}" == 1 ]]; then cmd_fp2; n="$(failures)"; log "failures: $n"; [[ "$n" == 0 ]]; exit; fi
    if [[ "${LAB_CACHEBYPASS:-0}" == 1 ]]; then cmd_cachebypass; n="$(failures)"; log "failures: $n"; [[ "$n" == 0 ]]; exit; fi
    if [[ "${LAB_LDAP:-0}" == 1 ]]; then cmd_ldap; n="$(failures)"; log "failures: $n"; [[ "$n" == 0 ]]; exit; fi
    if [[ "${LAB_ENGINE_SURFACE:-0}" == 1 ]]; then cmd_engine_surface; fail_fast_after engine-surface; fi
    cmd_recovery; fail_fast_after recovery
    if [[ -n "${LAB_ADOPT_IMAGE_TAR:-}" ]]; then cmd_adoption; fail_fast_after adoption; fi
    cmd_history
    if [[ "${LAB_PRESSURE:-0}" == 1 ]]; then cmd_pressure; fi
    n="$(failures)"; log "failures: $n"; [[ "$n" == 0 ]] ;;
  *) sed -n '2,32p' "$0"; exit 2 ;;
esac
