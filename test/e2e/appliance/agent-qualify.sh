#!/usr/bin/env bash
# test/e2e/appliance/agent-qualify.sh — maintenance-agent update-flow
# qualification against the REAL agent binary (built from cmd/culvert-maint),
# the REAL deploy-bundle compose file and REAL images, through a throwaway
# local registry so the registry can be taken away mid-test.
#
# Scenarios:
#   F1 apply PRED → CUR through POST /v1/upgrades/apply (pull by digest, tag,
#      compose up, health gate, verify) — running digest flips, state kept
#   F2 duplicate apply with the same idempotency_key ⇒ deduped (200, same op)
#   F3 agent killed mid-apply, restarted ⇒ interrupted op classified on
#      /v1/status (attention_required / adopted) and, when a tag hazard or
#      stale container is found, converged ONLY through POST /v1/reconcile
#   F4 standalone image rollback to PRED with the registry STOPPED ⇒ succeeds
#      from the local image cache (rollback_pull skipped), running digest = PRED
#   F5 agent restart idempotency: a repeated apply key after the agent restart
#      returns the prior op (no second mutation)
#
# Privilege mode: this sandbox has no systemd, so the agent runs with
# privilege_mode=docker_group_lab as root (the e2e workflows' lab shape). The
# sudoers-bound production mode is exercised by
# .github/workflows/install-lifecycle-e2e.yml (agent-day2-update job). Record
# that distinction in the evidence; it is NOT a claim about sudoers here.
set -euo pipefail
CUR_IMAGE="${CUR_IMAGE:?}"; PRED_IMAGE="${PRED_IMAGE:-ghcr.io/kidcarmi/culvert:v1.0.259}"
EVID="${EVID:-$PWD/agent-evidence}"; HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
REG_PORT="${REG_PORT:-5055}"; REPO="127.0.0.1:$REG_PORT/culvert"; PINNED="culvert/proxy:pinned"
mkdir -p "$EVID"; JSONL="$EVID/checks.jsonl"; MD="$EVID/REPORT.md"; : > "$JSONL"; FAILS=0; RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
log(){ printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
check(){ local sc="$1" n="$2" r="$3" d="${4:-}"; printf '{"run":"%s","scenario":"%s","check":"%s","result":"%s","detail":%s}\n' "$RUN_ID" "$sc" "$n" "$r" "$(printf '%s' "$d" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')" >> "$JSONL"; [[ "$r" == fail ]] && { FAILS=$((FAILS+1)); log "FAIL [$sc] $n: $d"; } || log "$r [$sc] $n: $d"; }
# The agent runs `docker compose -f … up -d` from compose_project_dir, so the
# compose PROJECT NAME is the directory basename; the harness must start the
# stack under the same name or the agent's `up` collides with our containers.
PDIR="$EVID/proj"; PROJ="proj"; rm -rf "$PDIR"; mkdir -p "$PDIR"
dc(){ docker compose -p "$PROJ" --project-directory "$PDIR" -f "$PDIR/docker-compose.yml" -f "$PDIR/docker-compose.override.yml" "$@"; }
cleanup(){ pkill -f "culvert-maint --config $PDIR/config.toml" 2>/dev/null || true; rm -rf "${SOCKDIR:-}"; [[ -z "${AGENT_STATE:-}" ]] || rm -rf "$AGENT_STATE"; dc down -v --remove-orphans >/dev/null 2>&1 || true; docker rm -f aqa-registry >/dev/null 2>&1 || true; rm -rf "/etc/docker/certs.d/127.0.0.1:$REG_PORT"; [[ -z "${TRUST_FILE:-}" ]] || rm -f "$TRUST_FILE"; }
trap cleanup EXIT

# ── registry + images ────────────────────────────────────────────────────────
# TLS registry trusted by the daemon (and by `docker manifest inspect`, which
# the agent's resolve_target template runs WITHOUT --insecure — correctly, a
# production registry is never plain HTTP). Same shape as the CI e2e workflows.
docker rm -f aqa-registry >/dev/null 2>&1 || true
CERTD="$PDIR/registry-certs"; mkdir -p "$CERTD"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$CERTD/tls.key" -out "$CERTD/tls.crt" \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
mkdir -p "/etc/docker/certs.d/127.0.0.1:$REG_PORT"; cp "$CERTD/tls.crt" "/etc/docker/certs.d/127.0.0.1:$REG_PORT/ca.crt"
docker run -d --name aqa-registry -p "127.0.0.1:$REG_PORT:5000" -v "$CERTD:/certs:ro" \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/tls.crt -e REGISTRY_HTTP_TLS_KEY=/certs/tls.key registry:2 >/dev/null
for _ in $(seq 1 20); do curl -fsS --cacert "$CERTD/tls.crt" "https://127.0.0.1:$REG_PORT/v2/" >/dev/null 2>&1 && break; sleep 1; done
# The digest the REGISTRY serves for the pushed tag (Docker-Content-Digest):
# with the containerd image store a locally built image's .Id / RepoDigests
# can name an index the registry never received (attestation manifests), so
# the local view is not the truth the agent's `docker manifest inspect` sees.
push_digest(){ docker tag "$1" "$REPO:$2" >/dev/null; docker push -q "$REPO:$2" >/dev/null
  local d; d="$(curl -sI -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' --cacert "$PDIR/registry-certs/tls.crt" "https://127.0.0.1:$REG_PORT/v2/culvert/manifests/$2" | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}')"
  [[ -n "$d" ]] || { echo "registry returned no digest for $REPO:$2" >&2; return 1; }
  echo "$REPO@$d"; }
PRED_REF="$(push_digest "$PRED_IMAGE" pred)"; CUR_REF="$(push_digest "$CUR_IMAGE" cur)"
log "pred=$PRED_REF cur=$CUR_REF"
PROOFD="$PDIR/release-proof"
( cd "$ROOT" && go run ./test/e2e/release-proof-fixture --output "$PROOFD" --ref "prior=$PRED_REF" --ref "current=$CUR_REF" )
TRUST_FILE="/etc/culvert-release-fixture/aq-$$.json"
install -d -o root -g root -m 0755 /etc/culvert-release-fixture
install -o root -g root -m 0644 "$PROOFD/keyring.json" "$TRUST_FILE"
proof_request(){ python3 "$ROOT/test/e2e/release-proof-fixture/request.py" --proofs "$PROOFD/proofs.json" "$@"; }

# ── compose project from the CUR deploy bundle ───────────────────────────────
cid="$(docker create "$CUR_IMAGE")"; docker cp "$cid:/app/deploy/docker-compose.yml" "$PDIR/docker-compose.yml" >/dev/null; docker rm -f "$cid" >/dev/null
cp "$HERE/docker-compose.qualify.yml" "$PDIR/docker-compose.override.yml"
printf 'CULVERT_CA_PASSPHRASE=agentqual-ca-0123456789\nCULVERT_LOG_PASSPHRASE=agentqual-ca-0123456789\n' > "$PDIR/.env"
docker tag "$PRED_IMAGE" "$PINNED"
dc up -d >/dev/null 2>&1
for _ in $(seq 1 40); do curl -fsS -m 3 http://127.0.0.1:8080/health >/dev/null 2>&1 && break; sleep 2; done
# Seed state on PRED so the upgrade has something to preserve.
JAR="$PDIR/jar"; UI=https://127.0.0.1:9090
api(){ curl -ksS -m 20 -X "$1" "$UI$2" -H "Origin: $UI" -H 'Content-Type: application/json' -b "$JAR" -c "$JAR" ${3:+-d "$3"} -w '\n%{http_code}'; }
api POST /api/setup/complete '{"user":"agentadmin","pass":"Agent-Qual-2026!x"}' | tail -n1 >/dev/null
check F0 seeded-predecessor pass "running $(curl -fsS http://127.0.0.1:8080/health | python3 -c 'import json,sys;print(json.load(sys.stdin)["version"])')"

# ── agent ────────────────────────────────────────────────────────────────────
( cd "$ROOT/cmd/culvert-maint" && go build -o "$PDIR/culvert-maint" . )
# A Unix socket path is limited to ~108 bytes; keep it short and outside the
# (possibly deep) evidence directory.
SOCKDIR="$(mktemp -d /tmp/aqsock.XXXXXX)"; SOCK="$SOCKDIR/agent.sock"
AGENT_STATE="$(mktemp -d /tmp/aqstate.XXXXXX)"
cat > "$PDIR/config.toml" <<CFG
privilege_mode = "docker_group_lab"
compose_project_dir = "$PDIR"
compose_file = "docker-compose.yml"
compose_override_file = "docker-compose.override.yml"
socket_path = "$SOCK"
state_dir = "$AGENT_STATE"
proxy_repo = "$REPO"
release_catalog_repo = "$REPO"
release_trust_keys = "$TRUST_FILE"
image_allowlist = "^127\\\\.0\\\\.0\\\\.1:$REG_PORT/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})\$"
allow_peers = ["$(id -u)"]
health_base_url = "http://127.0.0.1:8080"
health_path = "/health"
ready_path = "/ready"
operation_timeout = "20m"
stage_timeout = "8m"
reconcile_on_startup = true
CFG
start_agent(){ nohup "$PDIR/culvert-maint" --config "$PDIR/config.toml" >> "$PDIR/agent.log" 2>&1 & for _ in $(seq 1 30); do [[ -S "$SOCK" ]] && curl -fsS --unix-socket "$SOCK" http://unix/v1/health >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
stop_agent(){ pkill -f "culvert-maint --config $PDIR/config.toml" 2>/dev/null || true; sleep 1; }
kill_agent(){ pkill -9 -f "culvert-maint --config $PDIR/config.toml" 2>/dev/null || true; sleep 1; }
ag(){ curl -sS --unix-socket "$SOCK" -H 'Content-Type: application/json' "$@"; }
wait_op(){ for _ in $(seq 1 240); do local j; j="$(ag "http://unix/v1/operations/$1" 2>/dev/null || true)"; local st; st="$(echo "$j" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("state",""))
except Exception: print("")' )"; case "$st" in succeeded|failed) echo "$j"; return 0;; esac; sleep 2; done; echo '{"state":"timeout"}'; }
running_digest(){ docker inspect --format '{{index .Image}}' culvert 2>/dev/null; docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$(docker inspect --format '{{.Image}}' culvert)" | grep "^$REPO@" | head -1; }
start_agent || { check F0 agent-start fail "$(tail -5 "$PDIR/agent.log")"; exit 1; }
check F0 agent-start pass "$(ag http://unix/v1/health)"
unsigned_code="$(ag -X POST http://unix/v1/upgrades/apply -d "{\"image_ref\":\"$CUR_REF\",\"pre_backup\":false}" -o /dev/null -w '%{http_code}')"
[[ "$unsigned_code" == 403 ]] && check F0 unsigned-release-refused pass "http 403" || { check F0 unsigned-release-refused fail "http $unsigned_code"; exit 1; }

# ── F1 apply PRED → CUR ──────────────────────────────────────────────────────
KEY="aq-$RUN_ID"
r="$(ag -X POST http://unix/v1/upgrades/apply -d "$(printf '%s' "{\"image_ref\":\"$CUR_REF\",\"pre_backup\":false,\"rollback_on_failure\":true,\"idempotency_key\":\"$KEY\"}" | proof_request --prior "$PRED_REF")" -w '\n%{http_code}')"
OP="$(echo "$r" | sed '$d' | python3 -c 'import json,sys;print(json.load(sys.stdin).get("op_id",""))')"
[[ -n "$OP" ]] && check F1 apply-accepted pass "op=$OP http=$(echo "$r"|tail -n1)" || check F1 apply-accepted fail "$r"
j="$(wait_op "$OP")"; st="$(echo "$j" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("state"))')"
[[ "$st" == succeeded ]] && check F1 apply-succeeded pass "state=$st" || check F1 apply-succeeded fail "$j"
rd="$(running_digest | tail -n1)"; [[ "$rd" == "$CUR_REF" ]] && check F1 running-is-target pass "$rd" || check F1 running-is-target fail "running=$rd want=$CUR_REF"
c="$(api POST /api/auth/login '{"user":"agentadmin","pass":"Agent-Qual-2026!x"}' | tail -n1)"; [[ "$c" == 200 ]] && check F1 state-preserved pass "admin login http $c after upgrade" || check F1 state-preserved fail "http $c"
# ── F2 duplicate request ─────────────────────────────────────────────────────
r="$(ag -X POST http://unix/v1/upgrades/apply -d "$(printf '%s' "{\"image_ref\":\"$CUR_REF\",\"pre_backup\":false,\"rollback_on_failure\":true,\"idempotency_key\":\"$KEY\"}" | proof_request --prior "$PRED_REF")" -w '\n%{http_code}')"
code="$(echo "$r" | tail -n1)"; dup="$(echo "$r" | sed '$d' | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("op_id",""),d.get("deduped"))')"
[[ "$code" == 200 && "$dup" == "$OP True" ]] && check F2 duplicate-deduped pass "http 200 $dup" || check F2 duplicate-deduped fail "http $code $dup"
# ── F5 idempotency across agent restart ──────────────────────────────────────
stop_agent; start_agent || true
r="$(ag -X POST http://unix/v1/upgrades/apply -d "$(printf '%s' "{\"image_ref\":\"$CUR_REF\",\"pre_backup\":false,\"rollback_on_failure\":true,\"idempotency_key\":\"$KEY\"}" | proof_request --prior "$PRED_REF")" -w '\n%{http_code}')"
code="$(echo "$r" | tail -n1)"; dup="$(echo "$r" | sed '$d' | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("op_id",""),d.get("deduped"))')"
[[ "$code" == 200 && "$dup" == "$OP True" ]] && check F5 duplicate-after-agent-restart pass "http 200 $dup" || check F5 duplicate-after-agent-restart fail "http $code $dup"
# ── F3 kill mid-apply (PRED ← CUR → PRED again as a fresh target) ──────────────
# Apply back to PRED; SIGKILL the agent as soon as the op passes the pull
# stage (the restart stage is where the tag advances). Then restart the agent
# and read what reconcile classified.
r="$(ag -X POST http://unix/v1/upgrades/apply -d "$(printf '%s' "{\"image_ref\":\"$PRED_REF\",\"pre_backup\":false,\"rollback_on_failure\":false,\"idempotency_key\":\"aq-kill-$RUN_ID\"}" | proof_request --prior "$CUR_REF")" -w '\n%{http_code}')"
OP2="$(echo "$r" | sed '$d' | python3 -c 'import json,sys;print(json.load(sys.stdin).get("op_id",""))')"
killed=no
for _ in $(seq 1 300); do
  # The op log is tab-separated "<ts>\t<stage>\t<event>"; wait for the apply's
  # OWN restart stage to START (the tag advance + compose up window).
  if ag "http://unix/v1/operations/$OP2/logs" 2>/dev/null | grep -qP "\trestart\tSTART"; then kill_agent; killed=yes; break; fi
  st="$(ag "http://unix/v1/operations/$OP2" 2>/dev/null | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("state",""))
except Exception: print("")')"; [[ "$st" == succeeded || "$st" == failed ]] && break
  sleep 0.2
done
if [[ "$killed" == yes ]]; then
  check F3 killed-mid-apply pass "SIGKILL at the restart stage of $OP2"
  sleep 3; start_agent || true
  stj="$(ag http://unix/v1/status)"
  echo "$stj" > "$EVID/status-after-kill.json"
  summary="$(echo "$stj" | python3 -c 'import json,sys;d=json.load(sys.stdin);io=d.get("interrupted_operations") or [];print("attention_required=%s interrupted=%d verdicts=%s"%(d.get("attention_required"),len(io),[(o.get("op_id"),o.get("verdict"),o.get("tag_hazard")) for o in io]))')"
  check F3 reconcile-classified pass "$summary"
  rd="$(running_digest | tail -n1)"
  need="$(echo "$stj" | python3 -c 'import json,sys;d=json.load(sys.stdin);io=d.get("interrupted_operations") or [];print(io[0]["op_id"] if io else "")')"
  if [[ -n "$need" ]]; then
    r="$(ag -X POST "http://unix/v1/reconcile/$need" -d '{"action":"resolve","acknowledge_tag_hazard":true}' -w '\n%{http_code}')"; code="$(echo "$r"|tail -n1)"
    rop="$(echo "$r" | sed '$d' | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("op_id",""))
except Exception: print("")')"
    [[ -n "$rop" ]] && j="$(wait_op "$rop")" || j='{}'
    rd2="$(running_digest | tail -n1)"
    [[ "$rd2" == "$PRED_REF" ]] && check F3 explicit-resolve-converged pass "http $code resolve op=$rop running=$rd2" || check F3 explicit-resolve-converged fail "http $code $r running=$rd2 want=$PRED_REF op=$j"
    r2="$(ag -X POST "http://unix/v1/reconcile/$need" -d '{"action":"resolve"}' -w '\n%{http_code}' | tail -n1)"; [[ "$r2" == 404 || "$r2" == 409 ]] && check F3 duplicate-resolve-refused pass "http $r2" || check F3 duplicate-resolve-refused fail "http $r2"
  else
    [[ "$rd" == "$PRED_REF" ]] && check F3 adopted-or-noop pass "no attention needed; running=$rd (adopted/noop by startup reconcile)" || check F3 adopted-or-noop fail "running=$rd, nothing surfaced"
  fi
else
  check F3 killed-mid-apply blocked "could not observe the restart stage window of $OP2 (op state=$st); covered by cmd/culvert-maint unit gates (reconcile_startup_test.go)"
fi
# ensure we are on PRED now for the rollback test; if not, apply CUR and roll back to PRED
rd="$(running_digest | tail -n1)"
if [[ "$rd" != "$CUR_REF" ]]; then
  r="$(ag -X POST http://unix/v1/upgrades/apply -d "$(printf '%s' "{\"image_ref\":\"$CUR_REF\",\"pre_backup\":false,\"rollback_on_failure\":false,\"idempotency_key\":\"aq-recur-$RUN_ID\"}" | proof_request --prior "$PRED_REF")")"
  wait_op "$(echo "$r" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("op_id",""))')" >/dev/null
fi
# ── F4 rollback with the registry STOPPED ────────────────────────────────────
docker stop aqa-registry >/dev/null
r="$(ag -X POST http://unix/v1/rollbacks -d "$(printf '%s' "{\"mode\":\"image\",\"image_ref\":\"$PRED_REF\",\"idempotency_key\":\"aq-rb-$RUN_ID\"}" | proof_request)" -w '\n%{http_code}')"
ROP="$(echo "$r" | sed '$d' | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("op_id",""))
except Exception: print("")')"
[[ -n "$ROP" ]] && check F4 rollback-accepted pass "op=$ROP (registry stopped)" || check F4 rollback-accepted fail "$r"
j="$(wait_op "$ROP")"; st="$(echo "$j" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("state"))')"
logs="$(ag "http://unix/v1/operations/$ROP/logs" 2>/dev/null || true)"
echo "$logs" > "$EVID/rollback-op.log"
[[ "$st" == succeeded ]] && check F4 rollback-succeeded-offline pass "state=$st" || check F4 rollback-succeeded-offline fail "$j"
echo "$logs" | grep -q "skipped (image present locally)" && check F4 pull-skipped-local pass "rollback_pull: skipped (image present locally)" || check F4 pull-skipped-local fail "no skip marker in op log"
rd="$(running_digest | tail -n1)"; [[ "$rd" == "$PRED_REF" ]] && check F4 running-is-prior pass "$rd" || check F4 running-is-prior fail "running=$rd want=$PRED_REF"
c="$(api POST /api/auth/login '{"user":"agentadmin","pass":"Agent-Qual-2026!x"}' | tail -n1)"; [[ "$c" == 200 ]] && check F4 state-preserved-after-rollback pass "http $c" || check F4 state-preserved-after-rollback fail "http $c"
docker start aqa-registry >/dev/null
cp "$PDIR/agent.log" "$EVID/agent.log"
{ echo "# Maintenance-agent update-flow qualification — run $RUN_ID"; echo; echo "| artifact | reference |"; echo "|---|---|"; echo "| image under qualification | \`$CUR_IMAGE\` → \`$CUR_REF\` |"; echo "| predecessor | \`$PRED_IMAGE\` → \`$PRED_REF\` |"; echo "| agent | built from \`cmd/culvert-maint\` at $(git -C "$ROOT" rev-parse --short HEAD), privilege_mode=docker_group_lab (no systemd in this environment) |"; echo; echo "| scenario | check | result | detail |"; echo "|---|---|---|---|"
python3 - "$JSONL" <<'PY'
import json,sys
for line in open(sys.argv[1]):
    d=json.loads(line); print(f"| {d['scenario']} | {d['check']} | **{d['result'].upper()}** | {d['detail'].replace('|','/').replace(chr(10),' ')[:240]} |")
PY
echo; echo "Failures: $FAILS"; } > "$MD"
log "evidence: $MD ($FAILS failure(s))"; exit $(( FAILS > 0 ))
