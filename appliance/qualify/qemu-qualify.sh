#!/usr/bin/env bash
# qemu-qualify.sh — boots a BUILT appliance image under QEMU and qualifies it:
#
#   phase 1 (offline, restrict=on): first boot provisions with NO network at all;
#           wait for /var/lib/culvert-appliance/provisioned, capture the console
#           banner, /health, /ready, setup status, agent status; then power off.
#   phase 2 (restrict=off): boot again; complete the first-admin setup through the
#           public API; drive one allowed and one blocked request through the
#           proxy (the blocked host via the blocklist API; the allowed one via an
#           optional parent proxy, since the proxy refuses private destinations);
#           optional OS update (apt via an optional proxy) ; reboot; re-verify
#           /ready, /data persistence, agent, enforcement.
#
#   qemu-qualify.sh --image <qcow2> --work <dir> [--accel auto|kvm|tcg]
#                   [--parent-proxy http://10.0.2.2:PORT] [--apt-proxy http://10.0.2.2:PORT]
#                   [--allowed-url http://example.com/] [--skip-update] [--phase 1|2|all]
#
# Everything it observes is written to <work>/evidence/*.txt; the summary is
# <work>/evidence/RESULT.txt (PASS/FAIL per check). Exit 0 only when all PASS.
set -euo pipefail

IMAGE=""; WORK=""; ACCEL=auto; PARENT_PROXY=""; APT_PROXY=""; ALLOWED_URL="http://archive.ubuntu.com/"; SKIP_UPDATE=0; PHASE=all
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="$2"; shift ;;
    --work) WORK="$2"; shift ;;
    --accel) ACCEL="$2"; shift ;;
    --parent-proxy) PARENT_PROXY="$2"; shift ;;
    --apt-proxy) APT_PROXY="$2"; shift ;;
    --allowed-url) ALLOWED_URL="$2"; shift ;;
    --skip-update) SKIP_UPDATE=1 ;;
    --phase) PHASE="$2"; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac; shift
done
[[ -f "$IMAGE" && -n "$WORK" ]] || { echo "need --image <qcow2> --work <dir>" >&2; exit 2; }
mkdir -p "$WORK/evidence"; WORK="$(cd "$WORK" && pwd)"; EV="$WORK/evidence"
if [[ "$ACCEL" == auto ]]; then if [[ -w /dev/kvm ]]; then ACCEL=kvm; else ACCEL=tcg; fi; fi
case "$ACCEL" in kvm) CPU=host ;; *) CPU=max ;; esac
SSH_PORT=2222; PROXY_PORT=18080; ADMIN_PORT=19090
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile="$WORK/known_hosts" -o ConnectTimeout=10 -o LogLevel=ERROR -i "$WORK/id_ed25519" -p "$SSH_PORT")
RESULT="$EV/RESULT.txt"
log() { printf '%s [qualify] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$EV/qualify.log" >&2; }
check() { # check NAME PASS|FAIL detail
  printf '%-44s %s  %s\n' "$1" "$2" "${3:-}" | tee -a "$RESULT" >&2
}
# shellcheck disable=SC2029  # client-side expansion is intended
vm_ssh() { ssh "${SSH_OPTS[@]}" culvert@127.0.0.1 "$@"; }
vm_wait_ssh() { local _i; for _i in $(seq 1 "$1"); do vm_ssh true 2>/dev/null && return 0; sleep 10; done; return 1; }
boot() { # boot restrict(on|off) label
  local restrict="$1" label="$2"
  log "booting (accel=$ACCEL, restrict=$restrict) → serial $EV/serial-$label.log"
  qemu-system-x86_64 -machine q35,accel="$ACCEL" -cpu "$CPU" -smp 2 -m 4096 \
    -display none -monitor none -serial "file:$EV/serial-$label.log" \
    -drive "file=$WORK/disk.qcow2,if=virtio,format=qcow2" \
    -drive "file=$WORK/seed.iso,if=virtio,format=raw,readonly=on" \
    -netdev "user,id=n0,restrict=$restrict,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22,hostfwd=tcp:127.0.0.1:$PROXY_PORT-:8080,hostfwd=tcp:127.0.0.1:$ADMIN_PORT-:9090" \
    -device virtio-net-pci,netdev=n0 \
    -object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0 \
    > "$EV/qemu-$label.log" 2>&1 &
  echo $! > "$WORK/qemu.pid"
}
shutdown_vm() {
  vm_ssh sudo systemctl poweroff >/dev/null 2>&1 || true
  local _i; for _i in $(seq 1 60); do kill -0 "$(cat "$WORK/qemu.pid")" 2>/dev/null || return 0; sleep 5; done
  log "VM did not power off in 5 min — killing"; kill "$(cat "$WORK/qemu.pid")" 2>/dev/null || true
}
curl_j() { curl -sS -m 15 -c "$WORK/cookies" -b "$WORK/cookies" "$@"; }

# ── prep ─────────────────────────────────────────────────────────────────────
if [[ "$PHASE" == all || "$PHASE" == 1 ]]; then
  : > "$RESULT"
  rm -f "$WORK/disk.qcow2" "$WORK/cookies" "$WORK/known_hosts"
  qemu-img create -q -f qcow2 -F qcow2 -b "$IMAGE" "$WORK/disk.qcow2"
  [[ -f "$WORK/id_ed25519" ]] || ssh-keygen -q -t ed25519 -N '' -f "$WORK/id_ed25519"
  cat > "$WORK/user-data" <<YAML
#cloud-config
hostname: culvert-qual
ssh_authorized_keys:
  - $(cat "$WORK/id_ed25519.pub")
YAML
  printf 'instance-id: culvert-qual-1\nlocal-hostname: culvert-qual\n' > "$WORK/meta-data"
  cloud-localds "$WORK/seed.iso" "$WORK/user-data" "$WORK/meta-data"

  # ── phase 1: OFFLINE first boot ─────────────────────────────────────────────
  boot on p1-firstboot
  if vm_wait_ssh 90; then check "p1.ssh-reachable(key-only)" PASS; else check "p1.ssh-reachable(key-only)" FAIL "no ssh in 15 min"; fi
  vm_ssh 'ip -4 -o addr; cat /etc/machine-id; ls -l /etc/ssh/ssh_host_*_key.pub; ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub' > "$EV/p1-identity.txt" 2>&1 || true
  if grep -q 'ssh_host_ed25519_key.pub' "$EV/p1-identity.txt" && [[ "$(sed -n 2p "$EV/p1-identity.txt" | wc -c)" -gt 20 ]]; then check "p1.host-keys+machine-id-minted" PASS "$(sed -n 2p "$EV/p1-identity.txt")"; else check "p1.host-keys+machine-id-minted" FAIL; fi
  # offline proof: the guest must have NO route to anything
  if vm_ssh 'curl -sS -m 5 -o /dev/null http://archive.ubuntu.com/ 2>&1 | grep -qiE "Could not resolve|Failed to connect|timed out|Network is unreachable"'; then check "p1.offline(no-egress)" PASS; else check "p1.offline(no-egress)" FAIL "guest reached the internet"; fi
  log "waiting for first-boot provisioning (up to 45 min)"
  phase=""; for _ in $(seq 1 270); do
    phase="$(vm_ssh cat /var/lib/culvert-appliance/phase 2>/dev/null || echo unknown)"
    [[ "$phase" == provisioned || "$phase" == failed ]] && break; sleep 10
  done
  vm_ssh 'sudo cat /var/log/culvert-appliance/firstboot.log' > "$EV/p1-firstboot.log" 2>&1 || true
  vm_ssh 'cat /etc/issue' > "$EV/p1-console-banner.txt" 2>&1 || true
  vm_ssh 'sudo cat /var/lib/culvert-appliance/provisioned.env; sudo cat /var/lib/culvert-appliance/error 2>/dev/null' > "$EV/p1-provisioned.txt" 2>&1 || true
  if [[ "$phase" == provisioned ]]; then check "p1.firstboot-provisioned-offline" PASS "$(grep -c . "$EV/p1-firstboot.log") log lines"; else check "p1.firstboot-provisioned-offline" FAIL "phase=$phase"; fi
  curl -sS -m 10 "http://127.0.0.1:$PROXY_PORT/health" > "$EV/p1-health.json" 2>&1 || true
  curl -sS -m 10 -o "$EV/p1-ready.json" -w '%{http_code}' "http://127.0.0.1:$PROXY_PORT/ready" > "$EV/p1-ready.code" 2>/dev/null || echo 000 > "$EV/p1-ready.code"
  curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PROXY_PORT/ready?strict=1" > "$EV/p1-ready-strict.code" 2>/dev/null || echo 000 > "$EV/p1-ready-strict.code"
  curl -sk -m 10 "https://127.0.0.1:$ADMIN_PORT/api/setup/status" > "$EV/p1-setup-status.json" 2>&1 || true
  if [[ "$(cat "$EV/p1-ready.code")" == 200 ]]; then check "p1./ready==200" PASS "status=$(sed -n 's/.*"status":"\([a-z]*\)".*/\1/p' "$EV/p1-ready.json")"; else check "p1./ready==200" FAIL "http=$(cat "$EV/p1-ready.code")"; fi
  if grep -q '"needsSetup":true' "$EV/p1-setup-status.json"; then check "p1.setup-status=needsSetup" PASS; else check "p1.setup-status=needsSetup" FAIL "$(head -c 120 "$EV/p1-setup-status.json")"; fi
  if grep -q 'one-time password' "$EV/p1-console-banner.txt"; then check "p1.console-banner(one-time-password)" PASS; else check "p1.console-banner(one-time-password)" FAIL; fi
  vm_ssh 'systemctl is-active culvert-maint docker containerd culvert-appliance-console.timer; /usr/local/bin/culvert-maint --version; sudo docker compose -f /srv/culvert/docker-compose.yml -f /srv/culvert/docker-compose.maint-agent.yml ps --format "{{.Name}} {{.State}} {{.Health}} {{.Image}}"; sudo docker image inspect culvert/proxy:pinned --format "pinned={{.Id}} {{json .RepoDigests}}"; sudo docker volume ls --format "{{.Name}}"; sudo ls -l /var/lib/docker/volumes/culvert_proxy-data/_data | head -20; sudo cat /etc/culvert-maint/config.toml | grep -E "^allow_peers|^compose_override_file|^proxy_repo"' > "$EV/p1-stack.txt" 2>&1 || true
  if grep -qE '^culvert-maint active|^active$' <(sed -n 1p "$EV/p1-stack.txt"); then check "p1.maint-agent-active" PASS "$(sed -n 5p "$EV/p1-stack.txt")"; else check "p1.maint-agent-active" FAIL "$(sed -n 1p "$EV/p1-stack.txt")"; fi
  if grep -q 'culvert running healthy' "$EV/p1-stack.txt"; then check "p1.proxy-container-healthy" PASS; else check "p1.proxy-container-healthy" FAIL "$(grep -E '^culvert ' "$EV/p1-stack.txt" || true)"; fi
  if grep -q 'culvert-clamav running healthy' "$EV/p1-stack.txt"; then check "p1.clamav-healthy-offline(bundled-db)" PASS; else check "p1.clamav-healthy-offline(bundled-db)" FAIL "$(grep -E '^culvert-clamav' "$EV/p1-stack.txt" || true)"; fi
  if grep -q 'ca.bundle' "$EV/p1-stack.txt"; then check "p1./data-volume-populated(ca.bundle)" PASS; else check "p1./data-volume-populated(ca.bundle)" FAIL; fi
  vm_ssh 'sudo curl -sS --unix-socket /run/culvert-maint/culvert-maint.sock http://unix/v1/health 2>&1 || sudo -u "#100" curl -sS --unix-socket /run/culvert-maint/culvert-maint.sock http://unix/v1/health' > "$EV/p1-agent-health.txt" 2>&1 || true
  vm_ssh 'sudo docker compose -f /srv/culvert/docker-compose.yml exec -T proxy wget -qO- --timeout=5 http://127.0.0.1:9090/api/maintenance-agent 2>/dev/null || true' > "$EV/p1-agent-status-from-proxy.txt" 2>&1 || true
  vm_ssh 'sudo rm -f /tmp/x; ls -la /etc/ssh/sshd_config.d/; sudo sshd -T 2>/dev/null | grep -iE "^passwordauthentication|^permitrootlogin"; sudo nft list tables; cat /etc/cloud/cloud.cfg.d/90-culvert-appliance.cfg | head -5; id culvert; sudo passwd -S culvert' > "$EV/p1-hardening.txt" 2>&1 || true
  if grep -q 'passwordauthentication no' "$EV/p1-hardening.txt"; then check "p1.sshd-password-auth-off" PASS; else check "p1.sshd-password-auth-off" FAIL; fi
  log "phase 1 done; powering off"
  shutdown_vm
fi

# ── phase 2: online verify, setup, enforcement, update, reboot ───────────────
if [[ "$PHASE" == all || "$PHASE" == 2 ]]; then
  boot off p2-online
  vm_wait_ssh 90 || { check "p2.ssh-after-poweroff" FAIL; exit 1; }
  check "p2.ssh-after-poweroff" PASS
  for _ in $(seq 1 60); do curl -sS -m 5 -o /dev/null "http://127.0.0.1:$PROXY_PORT/health" 2>/dev/null && break; sleep 5; done
  # second boot must NOT re-run first boot
  if vm_ssh 'systemctl show -p ActiveState culvert-appliance-firstboot.service | grep -q inactive && test -f /var/lib/culvert-appliance/provisioned'; then check "p2.firstboot-not-rerun" PASS; else check "p2.firstboot-not-rerun" FAIL; fi
  # first admin through the public API (what the setup wizard POSTs)
  code="$(curl_j -sk -o "$EV/p2-setup-complete.json" -w '%{http_code}' -H 'Content-Type: application/json' -d '{"user":"qualadmin","pass":"QualPass123"}' "https://127.0.0.1:$ADMIN_PORT/api/setup/complete" || echo 000)"
  if [[ "$code" == 200 ]]; then check "p2.setup-complete(first-admin)" PASS; else check "p2.setup-complete(first-admin)" FAIL "http=$code $(head -c 120 "$EV/p2-setup-complete.json")"; fi
  curl_j -sk "https://127.0.0.1:$ADMIN_PORT/api/auth/status" > "$EV/p2-auth-status.json" 2>&1 || true
  # replay must be refused
  code2="$(curl -sk -m 10 -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{"user":"x","pass":"QualPass123"}' "https://127.0.0.1:$ADMIN_PORT/api/setup/complete" || echo 000)"
  if [[ "$code2" == 403 ]]; then check "p2.setup-complete-is-one-time(403)" PASS; else check "p2.setup-complete-is-one-time(403)" FAIL "http=$code2"; fi
  # enforcement: blocklist a host, then one blocked + one allowed request THROUGH the proxy, from inside the guest
  curl_j -sk -o "$EV/p2-blocklist-add.json" -w '%{http_code}\n' -H 'Content-Type: application/json' -d '{"host":"blocked.qual.test"}' "https://127.0.0.1:$ADMIN_PORT/api/blocklist" > "$EV/p2-blocklist-add.code" || true
  bcode="$(vm_ssh "curl -s -m 15 -o /tmp/blocked.html -w '%{http_code}' -x http://127.0.0.1:8080 http://blocked.qual.test/ ; echo; head -c 200 /tmp/blocked.html" 2>&1 | tee "$EV/p2-blocked-request.txt" | head -n1)"
  if [[ "$bcode" == 403 ]]; then check "p2.proxy-BLOCKS-blocklisted-host(403)" PASS; else check "p2.proxy-BLOCKS-blocklisted-host(403)" FAIL "http=$bcode"; fi
  if [[ -n "$PARENT_PROXY" ]]; then
    # parent proxy for egress (the qualification host has no direct egress); recorded as test wiring
    pp_host="${PARENT_PROXY#http://}"; pp_host="${pp_host%%/*}"
    curl_j -sk -o "$EV/p2-upstream-add.json" -w '%{http_code}\n' -H 'Content-Type: application/json' -d "{\"scheme\":\"http\",\"host\":\"${pp_host%%:*}\",\"port\":${pp_host##*:},\"revision\":1}" "https://127.0.0.1:$ADMIN_PORT/api/upstream/entries" > "$EV/p2-upstream-add.code" || true
    sleep 3
  fi
  acode="$(vm_ssh "curl -s -m 30 -o /tmp/allowed.html -w '%{http_code}' -x http://127.0.0.1:8080 '$ALLOWED_URL'; echo; head -c 200 /tmp/allowed.html" 2>&1 | tee "$EV/p2-allowed-request.txt" | head -n1)"
  if [[ "$acode" == 200 ]]; then check "p2.proxy-ALLOWS-unlisted-host(200)" PASS "$ALLOWED_URL"; else check "p2.proxy-ALLOWS-unlisted-host(200)" FAIL "http=$acode (parent-proxy='${PARENT_PROXY:-none}')"; fi
  vm_ssh 'sudo tail -n 20 /var/lib/docker/volumes/culvert_proxy-data/_data/proxy.log 2>/dev/null || sudo docker compose -f /srv/culvert/docker-compose.yml logs --tail 20 proxy' > "$EV/p2-proxy-log-tail.txt" 2>&1 || true
  if grep -qE 'BLOCK|blocked.qual.test' "$EV/p2-proxy-log-tail.txt"; then check "p2.proxy-log-records-decision" PASS; else check "p2.proxy-log-records-decision" FAIL; fi
  # OS update (layer 1) + reboot
  if [[ "$SKIP_UPDATE" == 0 ]]; then
    aptopt=""; [[ -n "$APT_PROXY" ]] && aptopt="-o Acquire::http::Proxy=$APT_PROXY -o Acquire::https::Proxy=$APT_PROXY"
    vm_ssh "sudo DEBIAN_FRONTEND=noninteractive apt-get $aptopt -qq update 2>&1 | tail -n 3; apt list --upgradable 2>/dev/null | tail -n +2 | head -n 40; echo '--- unattended-upgrade dry-run'; sudo unattended-upgrade $aptopt --dry-run -v 2>&1 | tail -n 15; echo '--- apply security updates (unattended-upgrade)'; sudo unattended-upgrade $aptopt -v 2>&1 | tail -n 25; echo '--- dist-upgrade'; sudo DEBIAN_FRONTEND=noninteractive apt-get $aptopt -y -qq dist-upgrade 2>&1 | tail -n 15; dpkg -l docker-ce containerd.io docker-compose-plugin | tail -n 3; ls /var/run/reboot-required* 2>/dev/null; echo rc=\$?" > "$EV/p2-os-update.txt" 2>&1 || true
    if grep -qE 'Reading package lists|Packages that will be upgraded|No packages found that can be upgraded|^0 upgraded|packages upgraded' "$EV/p2-os-update.txt"; then check "p2.os-update-executed" PASS "$(grep -cE '^[a-z0-9.+-]+/' "$EV/p2-os-update.txt") upgradable listed"; else check "p2.os-update-executed" FAIL "see p2-os-update.txt"; fi
    if grep -q 'docker-ce' "$EV/p2-os-update.txt" && ! grep -qE '^Inst docker-ce|Unpacking docker-ce' "$EV/p2-os-update.txt"; then check "p2.docker-not-touched-by-os-update" PASS; else check "p2.docker-not-touched-by-os-update" FAIL; fi
  fi
  log "rebooting"
  vm_ssh sudo systemctl reboot >/dev/null 2>&1 || true
  sleep 30; vm_wait_ssh 90 || { check "p2.ssh-after-reboot" FAIL; exit 1; }
  check "p2.ssh-after-reboot" PASS
  for _ in $(seq 1 90); do c="$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PROXY_PORT/ready" 2>/dev/null || echo 000)"; [[ "$c" == 200 ]] && break; sleep 5; done
  curl -sS -m 10 "http://127.0.0.1:$PROXY_PORT/ready" > "$EV/p2-ready-after-reboot.json" 2>&1 || true
  if [[ "$c" == 200 ]]; then check "p2./ready==200-after-reboot" PASS; else check "p2./ready==200-after-reboot" FAIL "http=$c"; fi
  curl -sk -m 10 "https://127.0.0.1:$ADMIN_PORT/api/setup/status" > "$EV/p2-setup-status-after-reboot.json" 2>&1 || true
  if grep -q '"needsSetup":false' "$EV/p2-setup-status-after-reboot.json"; then check "p2.admin-persisted-across-reboot" PASS; else check "p2.admin-persisted-across-reboot" FAIL; fi
  vm_ssh 'systemctl is-active culvert-maint docker; sudo docker compose -f /srv/culvert/docker-compose.yml ps --format "{{.Name}} {{.State}} {{.Health}}"; sudo ls /var/lib/docker/volumes/culvert_proxy-data/_data | tr "\n" " "; echo; uname -r; cat /etc/machine-id; ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub; cat /etc/issue' > "$EV/p2-after-reboot.txt" 2>&1 || true
  if grep -q 'ui_users.json' "$EV/p2-after-reboot.txt"; then check "p2./data-persisted(ui_users.json)" PASS; else check "p2./data-persisted(ui_users.json)" FAIL; fi
  if sed -n 1p "$EV/p2-after-reboot.txt" | grep -q active; then check "p2.maint-agent-active-after-reboot" PASS; else check "p2.maint-agent-active-after-reboot" FAIL; fi
  if [[ "$(sed -n 2p "$EV/p1-identity.txt" 2>/dev/null)" == "$(grep -E '^[0-9a-f]{32}$' "$EV/p2-after-reboot.txt" | head -n1)" ]]; then check "p2.machine-id-stable-across-reboot" PASS; else check "p2.machine-id-stable-across-reboot" FAIL; fi
  bcode2="$(vm_ssh "curl -s -m 15 -o /dev/null -w '%{http_code}' -x http://127.0.0.1:8080 http://blocked.qual.test/" 2>&1 | tail -c 3)"
  if [[ "$bcode2" == 403 ]]; then check "p2.enforcement-persists-after-reboot(403)" PASS; else check "p2.enforcement-persists-after-reboot(403)" FAIL "http=$bcode2"; fi
  log "phase 2 done; powering off"
  shutdown_vm
fi
echo; cat "$RESULT"
! grep -q ' FAIL ' "$RESULT"
