# vSphere / ESXi qualification of the candidate OVA — copy-paste procedure

One pass, top to bottom, on the pilot hypervisor. Every block runs on the
**admin workstation** (Linux/macOS shell with `ovftool`, `ssh`, `curl`,
`python3`) unless it says otherwise; appliance-side commands go over SSH.
Each block appends to `$EV/`, so the evidence travels as one tarball at the
end. Nothing here needs internet access from the workstation except the
enforcement probe in step 5.

**Candidate under qualification** (filled from the build record; do not
substitute another file):

| | |
|---|---|
| OVA | `culvert-appliance-dev-candidate.4c4b7728c0e6-ubuntu-24.04.ova` |
| OVA SHA-256 | `e24eb542f973fb70360bad5124ef81fdab8b6f8d67af601720613cbcca3700a4` |
| Application image | `sha256:384f4c4b1bad91be93dc8b78adb974b6c57dd9b4c8f534bfdbafc2c1e4f1ab04` (Deep PR Gate artifact `deep-gate-image`, run `37124197333`) |
| Source commit (image AND provisioning, no drift) | `4c4b7728c0e6a1746e968d935b635fc652647e6f` |

This is a **candidate** build: unsigned CI image, never for customers. First
boot logs `CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1` on the console for that
reason; a release OVA never does.

## 0. Variables (edit once)

```bash
export OVA=./culvert-appliance-dev-candidate.4c4b7728c0e6-ubuntu-24.04.ova
export VI='vi://administrator@vsphere.local@vcenter.example/DC/host/Cluster'   # target
export NET='VM Network'           # port group carrying management + proxy traffic
export VMNAME=culvert-qual-01
export KEY=~/.ssh/id_ed25519      # its .pub is injected as the only SSH credential
# Static addressing (leave ADDR empty for DHCP; then set ADDR after step 2)
export ADDR=10.0.10.5 PREFIX=24 GW=10.0.10.1 DNS=10.0.10.2
export ADMIN_USER=pilotadmin ADMIN_PASS='Change-Me-Pilot-2026!'   # first admin, min 8 chars
export EV=./culvert-qual-evidence; mkdir -p "$EV"
```

## 1. Verify the artefact

```bash
echo "e24eb542f973fb70360bad5124ef81fdab8b6f8d67af601720613cbcca3700a4  $OVA" | sha256sum -c - | tee "$EV/01-ova-sha256.txt"
tar -xOf "$OVA" "$(tar -tf "$OVA" | grep '\.ovf$')" | grep -E 'CANDIDATE|Version|ovf:capacity' | tee "$EV/01-ovf-head.txt"
```

Pass: `OK`, and the OVF product line says CANDIDATE.

## 2. Import and power on

```bash
ovftool --acceptAllEulas --diskMode=thin --powerOn --name="$VMNAME" \
  --net:"VM Network"="$NET" \
  --prop:hostname="$VMNAME" --prop:public-keys="$(cat "$KEY.pub")" \
  ${ADDR:+--prop:culvert.net.mode=static --prop:culvert.net.address=$ADDR/$PREFIX --prop:culvert.net.gateway=$GW --prop:culvert.net.dns=$DNS} \
  "$OVA" "$VI" 2>&1 | tee "$EV/02-ovftool.txt"
```

Deploying straight to a standalone ESXi host (no vCenter) instead: add
`--X:injectOvfEnv` so the vApp properties (SSH key, static address) reach the
guest; vCenter delivers them without it.

Open the VM console. Within 3–8 minutes the banner moves from
`provisioning (running)` to `services running — setup pending` and prints
the **setup token**. With DHCP, read the address from the banner and
`export ADDR=<it>`. Photograph or copy the banner into `$EV/02-console.txt`.

## 3. First-boot evidence and kernel BEFORE

```bash
SSH="ssh -i $KEY -o StrictHostKeyChecking=accept-new culvert@$ADDR"
$SSH 'uname -r; uname -v' | tee "$EV/03-kernel-before.txt"
$SSH 'sudo culvert-status' | tee "$EV/03-status-firstboot.txt"
$SSH 'cat /var/lib/culvert-appliance/build-info.json' | tee "$EV/03-build-info.json"
$SSH 'ls /var/lib/culvert-appliance/state/; sudo docker compose -f /srv/culvert/docker-compose.yml ps --format "{{.Name}} {{.Image}} {{.Status}}"' | tee "$EV/03-stack.txt"
$SSH 'sudo docker inspect -f "{{.Image}}" culvert; dpkg -l "linux-image-*" | awk "/^ii/{print \$2, \$3}"; apt-mark showhold' | tee "$EV/03-images-kernels-holds.txt"
export TOKEN="$($SSH 'sudo culvert-status' | awk -F': *' '/Setup token:/{print $2}' | awk '{print $1}')"; echo "token captured: ${#TOKEN} chars"
```

Pass: `State: services running — setup pending`; `state/` lists
`ovf console images install agent complete` `.done` files; the `culvert` container
runs `sha256:384f4c4b1bad91be93dc8b78adb974b6c57dd9b4c8f534bfdbafc2c1e4f1ab04`; the token is 32 characters.

## 4. Enrol the first administrator (setup token is required)

```bash
UI="https://$ADDR:9090"; JAR="$EV/cookies"; : > "$JAR"
# api prints the response body, then the HTTP status on its own last line.
# body() keeps only the body (for JSON parsing); code() keeps only the status.
api(){ curl -ksS -m 20 -X "$1" "$UI$2" -H "Origin: $UI" -H 'Content-Type: application/json' -b "$JAR" -c "$JAR" ${3:+-d "$3"} -w '\n%{http_code}\n'; }
body(){ sed '$d'; }; code(){ tail -n1; }
api POST /api/setup/complete "{\"user\":\"$ADMIN_USER\",\"pass\":\"$ADMIN_PASS\"}" | tee "$EV/04-setup-without-token.txt"   # expect last line 403
curl -ksS -X POST "$UI/api/setup/complete" -H "Origin: $UI" -H 'Content-Type: application/json' \
  -H "X-Culvert-Setup-Token: $TOKEN" -d "{\"user\":\"$ADMIN_USER\",\"pass\":\"$ADMIN_PASS\"}" -w '\n%{http_code}\n' | tee "$EV/04-setup-with-token.txt"   # expect last line 200
api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$ADMIN_PASS\"}" | tee "$EV/04-login.txt"                 # expect last line 200
$SSH 'sudo culvert-status' | tee "$EV/04-status-after-setup.txt"
```

Pass: last lines 403, then 200, then 200; status says `setup complete`.

## 5. Enforcement (default deny, then one allow rule)

Run from a client that may reach `$ADDR:8080` and whose path to the
internet goes through the appliance. Pilot posture (`first-boot.md` step 8):
clients are not asked to authenticate and policy decides by destination —
without this step every probe below answers 407 (proxy authentication
required), which is correct but not what is being qualified.

```bash
P="http://$ADDR:8080"
api PUT /api/settings/default-auth-outcome '{"defaultAuthOutcome":"Exempt"}' | tee "$EV/05-auth-exempt.txt"   # expect last line 200
api GET /api/default-action | tee "$EV/05-default-action.txt"                                    # expect {"defaultAction":"deny"}
curl -sS -m 15 -x "$P" -o /dev/null -w 'before-rule http=%{http_code}\n' http://example.com/ | tee "$EV/05-before-rule.txt"   # expect 403
api POST /api/policy '{"name":"qual-allow-example","priority":10,"action":"Allow","destFQDN":"example.com","sslAction":"Bypass","enabled":true}' | tee "$EV/05-rule.txt"
curl -sS -m 15 -x "$P" -o /dev/null -w 'after-rule http=%{http_code}\n' http://example.com/ | tee "$EV/05-after-rule.txt"     # expect 200
curl -sS -m 15 -x "$P" -o /dev/null -w 'other-host http=%{http_code}\n' http://example.org/ | tee "$EV/05-other-host.txt"     # expect 403
curl -sS "$P/ready" | python3 -m json.tool | tee "$EV/05-ready.json"
$SSH 'sudo culvert-status' | tee "$EV/05-status.txt"
```

Pass: 403 / 200 / 403; `/ready` HTTP 200 with `policy_loaded`,
`policy_posture` and `ca` ok; status says `ready to enforce`.

## 6. Maintenance agent: a real privileged operation, through the product

The admin API asks the proxy, which calls the host agent over its socket
(`SO_PEERCRED` + `allow_peers`, then the sudoers allowlist and the `cli`
container) — the same chain an application upgrade uses. A backup changes
nothing in the running stack; the restore DRY RUN only validates the archive.

```bash
api GET /api/maintenance-agent | tee "$EV/06-agent-status.txt"                     # reachable, privilege posture
OPJSON="$(api POST /api/backups '{"encrypt":false}' | tee "$EV/06-backup-trigger.txt")"
OP="$(printf '%s\n' "$OPJSON" | body | python3 -c 'import json,sys;print(json.load(sys.stdin)["opId"])')"
FN="$(printf '%s\n' "$OPJSON" | body | python3 -c 'import json,sys;print(json.load(sys.stdin)["filename"])')"
for i in $(seq 90); do st="$(api GET "/api/backups/operations/$OP" | body | python3 -c 'import json,sys;print(json.load(sys.stdin).get("state",""))')"; case "$st" in succeeded|failed) break;; esac; sleep 2; done
echo "backup $FN op=$OP state=$st" | tee "$EV/06-backup-result.txt"
api GET /api/backups | tee "$EV/06-backups.txt"
$SSH "cd /srv/culvert && sudo docker compose --profile cli run --rm -T cli --restore /backup/$FN --mode full" 2>&1 | tail -15 | tee "$EV/06-restore-dryrun.txt"
```

Pass: the agent is reachable; the backup op `succeeded` and the archive is
listed with a non-zero size; the dry run ends `validation passed` (no
`--confirm`, nothing restored). An application UPGRADE is not exercised
here because a candidate OVA has no newer signed release to move to; the
same agent chain is qualified for upgrades by the CI jobs `Agent day-2
upgrade through real sudoers` and `appliance-agent`.

## 7. OS update and reboot (kernel BEFORE → AFTER)

```bash
$SSH 'sudo culvert-os-update check' | tee "$EV/07-check-before.txt"
$SSH 'sudo culvert-os-update os' 2>&1 | tee "$EV/07-os-update.txt"
$SSH 'sudo culvert-os-update check; ls -l /var/run/reboot-required 2>/dev/null; dpkg -l "linux-image-*" | awk "/^ii/{print \$2, \$3}"; apt-mark showhold; sudo docker version --format "{{.Server.Version}}"' | tee "$EV/07-check-after-update.txt"
$SSH 'sudo culvert-os-update reboot' 2>&1 | tee "$EV/07-reboot.txt" || true     # the SSH session drops here
until curl -fsS -m 3 "http://$ADDR:8080/health" >/dev/null 2>&1; do sleep 5; done; date -u | tee "$EV/07-back-up-at.txt"
$SSH 'uname -r; uname -v' | tee "$EV/07-kernel-after.txt"
diff "$EV/03-kernel-before.txt" "$EV/07-kernel-after.txt" && echo "KERNEL UNCHANGED" || echo "KERNEL CHANGED"
```

Record both kernel strings in the report. `culvert-os-update os` runs
`apt-get upgrade --with-new-pkgs`, so a newer kernel ABI published since the
build IS installed (beside the running one) and is the one booted after the
reboot; an unchanged kernel is acceptable only if `07-check-after-update.txt`
lists no newer `linux-image`. The Docker packages must still be held and the
engine version unchanged (only `culvert-os-update docker` moves it). If the
os mode refuses with exit 3, the maintenance agent has an operation in
flight — wait for it (do not use `--force` during qualification).

## 8. Persistence and readiness after the reboot

```bash
$SSH 'sudo culvert-status; ls /var/lib/culvert-appliance/state/' | tee "$EV/08-status-after-reboot.txt"
: > "$JAR"; api POST /api/auth/login "{\"user\":\"$ADMIN_USER\",\"pass\":\"$ADMIN_PASS\"}" | tee "$EV/08-login.txt"   # expect last line 200
api GET /api/policy | body | python3 -c 'import json,sys;print([r["name"] for r in json.load(sys.stdin)["rules"]])' | tee "$EV/08-rules.txt"   # expect ['qual-allow-example']
curl -sS -m 15 -x "$P" -o /dev/null -w 'after-reboot allowed http=%{http_code}\n' http://example.com/ | tee "$EV/08-enforce.txt"   # expect 200
curl -sS -m 15 -x "$P" -o /dev/null -w 'after-reboot denied http=%{http_code}\n' http://example.org/ | tee -a "$EV/08-enforce.txt"  # expect 403
curl -sS "$P/ready" -o /dev/null -w 'ready http=%{http_code}\n' | tee "$EV/08-ready.txt"                                          # expect 200
api GET /api/backups | tee "$EV/08-backups.txt"                                                                                  # step-6 backup still listed
api GET /api/maintenance-agent | tee "$EV/08-agent-status.txt"                                                                    # agent reachable after reboot
$SSH 'sudo journalctl -b -u culvert-firstboot --no-pager | tail -5' | tee "$EV/08-firstboot-not-rerun.txt"
```

(The step-8 probes come from an unauthenticated client, so 200/403 rather
than 407 also proves the Exempt authentication posture survived the reboot.)

Pass: same state as before the reboot (`setup complete`, `ready to
enforce`), login 200, the rule still present, 200 / 403, `/ready` 200, the
backup still listed, and no first-boot step re-ran (all `.done` files from
step 3, no new run in the journal).

## 9. Data-disk alarm delivery (pilot acceptance — readiness report F-DISK-1)

A filesystem that fills during a database write stops the proxy (F-DISK-1,
open). The appliance cannot page anyone about it: `culvert-status` only SHOWS
the data filesystem's usage. Before the pilot carries traffic, prove that YOUR
monitoring pages an operator for the guest filesystem holding the data volume,
and that the datastore under the VM is alarmed too (a thin-provisioned
datastore can fill while the guest still reports free space).

1. Configure a guest-filesystem alarm at ≤ 80 % used on the path printed by
   `culvert-status` (`/var/lib/docker` on this OVA), and a capacity alarm on
   the backing datastore.
2. Cross the threshold with a temporary file. The block refuses unless at
   least 2 GiB stays free, so it can never reproduce F-DISK-1 itself.

```bash
$SSH 'sudo culvert-status | grep "Data disk"; df -Pk /var/lib/docker' | tee "$EV/09-before.txt"
$SSH 'set -e; read -r used avail <<<"$(df -Pk /var/lib/docker | awk "NR==2{print \$3, \$4}")"
  fill=$(( avail - (used + avail) * 15 / 100 ))           # target: 85 % used
  [ "$fill" -gt 0 ] && [ $(( avail - fill )) -ge 2097152 ] || { echo "REFUSED: would leave $(( (avail - fill) / 1024 )) MiB free"; exit 1; }
  sudo fallocate -l "$(( fill * 1024 ))" /var/lib/docker/culvert-alarm-test.tmp
  df -Pk /var/lib/docker; sudo culvert-status | grep "Data disk"' | tee "$EV/09-filled.txt"
date -u | tee "$EV/09-threshold-crossed-at.txt"
```

3. Wait for the alarm to reach the on-call operator. Record WHO received it,
   through which channel and WHEN, in `$EV/09-alarm-received.txt` (with a
   screenshot if the channel allows it). No delivery within your monitoring's
   own interval is a FAIL of this step.
4. Remove the file and confirm the alarm clears:

```bash
$SSH 'sudo rm -f /var/lib/docker/culvert-alarm-test.tmp; sudo culvert-status | grep "Data disk"' | tee "$EV/09-cleared.txt"
```

Pass: `09-filled.txt` shows `LOW` and ≥ 2 GiB free; the operator received the
alarm (recorded); the alarm cleared after removal; a datastore alarm is
configured (screenshot of its definition). Also rehearse the F-DISK-1
recovery procedure once (`readiness-report.md` §6) — on the healthy VM its
last step is the one that matters, and it costs a few seconds of proxy
downtime:

```bash
$SSH 'cd /srv/culvert && sudo docker compose up -d --force-recreate proxy && sleep 20 && sudo culvert-status --brief' | tee "$EV/09-recovery-rehearsal.txt"
curl -sS -m 15 -x "$P" -o /dev/null -w 'after-recreate allowed http=%{http_code}\n' http://example.com/ | tee -a "$EV/09-recovery-rehearsal.txt"   # expect 200
```

Then repeat step 8's persistence checks (state survives a recreate: `/data`
is a named volume) and confirm ≥ 2 GiB free at go-live.

## 10. Return the evidence

```bash
tar -czf culvert-qual-evidence.tgz "$EV" && sha256sum culvert-qual-evidence.tgz
```

Return `culvert-qual-evidence.tgz` and its SHA-256. The result is recorded in
`readiness-report.md` only from that tarball.
