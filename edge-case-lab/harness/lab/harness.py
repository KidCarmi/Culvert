#!/usr/bin/env python3
"""
Culvert Edge-Case Validation Lab — core harness (roles: Culvert Operator,
Traffic Executor, Failure Reviewer, and the campaign Runner glue).

Isolation model:
  Culvert hardcodes dataDir=/data (no -data-dir flag), so strong per-scenario
  filesystem isolation is achieved by wiping /data and restarting the process.
  For throughput within a batch we ALSO support fast API-level reset (delete all
  policy rules + reset defaults + verify empty). The Runner restarts the process
  fresh per batch and additionally re-confirms every candidate PRODUCT_BUG in a
  clean freshly-restarted instance (the confirmation contract).
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from . import oracle

# ---- Lab configuration (single source of truth) ----------------------------
REPO = "/home/user/Culvert"
LAB = os.path.join(REPO, "edge-case-lab")
# CULVERT_LAB_BIN lets mutation-validation / acceptance-review runs point the lab at
# an alternate (e.g. deliberately-mutated, worktree-built) binary WITHOUT editing the
# main tree. Defaults to the repo binary for normal campaigns.
CULVERT_BIN = os.environ.get("CULVERT_LAB_BIN", os.path.join(REPO, "culvert"))
DATA_DIR = "/data"
PROXY_PORT = 18080
UI_PORT = 19090
SOCKS5_PORT = 11080
PROXY = f"http://127.0.0.1:{PROXY_PORT}"
UI = f"http://127.0.0.1:{UI_PORT}"
CULVERT_LOG = "/tmp/culvert.log"
CA_PASSPHRASE = "labtest123"
# R1: durable policy store — mirrors the shipped docker-compose contract
# (`-policy /data/policy.json`). Every admin-API mutation calls policyStore.Save(),
# which persists here; on restart-without-wipe the store is reloaded.
POLICY_STORE = os.path.join(DATA_DIR, "policy.json")
FIXTURE_IP = "192.0.2.2"
FIXTURE_HTTP = 18091
FIXTURE_HTTPS = 18453
FIXTURE_CA = os.path.join(LAB, "fixtures/certs/fixture.crt")
CULVERT_CA = "/tmp/culvert-ca.pem"
# Two controllable client source IPs (infra limit: only these two are locally bindable).
SRC_CORP = "192.0.2.2"     # matches "corporate" subnet 192.0.2.0/24
SRC_OTHER = "127.0.0.1"    # the "other/guest" source


# Admin-API auth state. None => open mode (unconfigured, admin granted to all).
# "user:pass" => instance is configured; send HTTP Basic Auth on every admin call.
import base64 as _b64
STATE = {"auth": None}


def _http(method: str, url: str, body: Optional[dict] = None, timeout=10) -> tuple[int, str]:
    # Retry on 429 with exponential backoff — the admin API rate-limits mutating
    # requests per client IP; a real admin client (and this harness) must back off.
    backoffs = [0.4, 0.8, 1.6, 3.2, 5.0]
    attempt = 0
    while True:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if STATE["auth"]:
            req.add_header("Authorization", "Basic " + _b64.b64encode(STATE["auth"].encode()).decode())
        # deliberately NO Origin header (open-mode CSRF contract)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.getcode(), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < len(backoffs):
                time.sleep(backoffs[attempt]); attempt += 1; continue
            return e.code, e.read().decode("utf-8", "replace")
        except Exception as e:  # noqa
            return 0, f"__error__:{e}"


# =============================================================================
# Culvert lifecycle
# =============================================================================
class OwnershipError(RuntimeError):
    """R2: raised when the harness cannot prove exclusive ownership of the ports."""


def _port_in_use(port: int) -> bool:
    import socket
    # (1) connect probe — detects an ACCEPTING listener (e.g. a live culvert).
    c = socket.socket()
    c.settimeout(0.3)
    try:
        if c.connect_ex(("127.0.0.1", port)) == 0:
            return True
    finally:
        c.close()
    # (2) bind probe — detects a socket BOUND to the port even if it is not
    # accepting (backlog full / no accept loop). Use SO_REUSEADDR to MATCH culvert's
    # own bind semantics: this fails on an ACTIVE listener (real occupancy) but
    # succeeds over TIME_WAIT connections (which culvert would also bind over), so a
    # just-killed stray's lingering connections are not mistaken for occupancy.
    b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    b.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        b.bind(("0.0.0.0", port))
        return False
    except OSError:
        return True
    finally:
        b.close()


def _ports_in_use() -> list[int]:
    return [p for p in (PROXY_PORT, UI_PORT, SOCKS5_PORT) if _port_in_use(p)]


class Culvert:
    def __init__(self):
        self.proc: Optional[subprocess.Popen] = None
        self.commit = _git_commit()
        self.dirty = False  # True once configured (admin created); needs fresh restart to reopen
        self.pid: Optional[int] = None
        self.pgid: Optional[int] = None
        self.start_time: Optional[float] = None
        self.config_path = POLICY_STORE

    def info(self) -> dict:
        """R2: ownership/provenance record for evidence."""
        return {
            "pid": self.pid,
            "pgid": self.pgid,
            "start_time": self.start_time,
            "start_time_iso": (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.start_time))
                               if self.start_time else None),
            "commit": self.commit,
            "config_path": self.config_path,
            "binary": CULVERT_BIN,
            "policy_store_present": os.path.isfile(self.config_path),
        }

    def wipe_data(self):
        for name in os.listdir(DATA_DIR):
            p = os.path.join(DATA_DIR, name)
            try:
                shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
            except Exception:
                pass

    def configure_admin(self, user="labadmin", password="LabPass123!"):
        """Complete first-run setup to create an admin (configured mode).
        After this the admin API requires Basic Auth (set in STATE) and the
        PROXY will challenge unauthenticated traffic (auth-family scenarios)."""
        STATE["auth"] = None
        code, _ = _http("POST", f"{UI}/api/setup/complete", {"user": user, "pass": password})
        STATE["auth"] = f"{user}:{password}"
        self.admin_creds = (user, password)
        self.dirty = True
        return code

    def start(self, fresh=True):
        # R2: deterministic ownership. ALWAYS stop our own process, reap strays,
        # and PROVE the ports are released before starting. Refuse to start when an
        # UNMANAGED instance still owns the ports (fail-closed, no second instance).
        self.stop()
        _kill_stray_on_ports()
        self._await_ports_released(timeout=8)
        still = _ports_in_use()
        if still:
            raise OwnershipError(
                f"refusing to start: ports {still} owned by an unmanaged process "
                f"(harness could not prove exclusive ownership)")
        if fresh:
            self.wipe_data()
            STATE["auth"] = None  # fresh instance starts in open mode
            self.dirty = False
        env = dict(os.environ, CULVERT_CA_PASSPHRASE=CA_PASSPHRASE)
        logf = open(CULVERT_LOG, "w")
        self.proc = subprocess.Popen(
            [CULVERT_BIN, "-port", str(PROXY_PORT), "-ui-port", str(UI_PORT),
             "-ui-no-tls", "-ca-path", os.path.join(DATA_DIR, "ca.bundle"),
             "-policy", POLICY_STORE,                     # R1: durable policy store
             "-socks5-port", str(SOCKS5_PORT)],
            stdout=logf, stderr=subprocess.STDOUT, env=env,
            preexec_fn=os.setsid)
        self.pid = self.proc.pid
        try:
            self.pgid = os.getpgid(self.pid)
        except Exception:
            self.pgid = None
        self.start_time = time.time()
        self._await_ready()
        # cache the MITM CA for inspection probes
        try:
            with urllib.request.urlopen(f"{UI}/api/ca-cert", timeout=5) as r:
                open(CULVERT_CA, "w").write(r.read().decode())
        except Exception:
            pass

    def _await_ready(self, timeout=25):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self.proc and self.proc.poll() is not None:
                raise RuntimeError(f"culvert exited during startup (rc={self.proc.returncode}); "
                                   f"see {CULVERT_LOG}")
            code, _ = _http("GET", f"{UI}/api/setup/status", timeout=2)
            if code == 200:
                return
            time.sleep(0.3)
        raise RuntimeError("culvert did not become ready")

    def _await_ports_released(self, timeout=8):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if not _ports_in_use():
                return True
            time.sleep(0.25)
        return False

    def stop(self):
        # R2: terminate + REAP the whole process group, then prove ports released.
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                self.proc.wait(timeout=10)
            except Exception:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                    self.proc.wait(timeout=5)
                except Exception:
                    pass
        if self.proc:
            try:
                self.proc.wait(timeout=1)  # reap
            except Exception:
                pass
        self.proc = None
        self.pid = None
        self.pgid = None

    def log_offset(self) -> int:
        try:
            return os.path.getsize(CULVERT_LOG)
        except OSError:
            return 0

    def log_since(self, offset: int) -> list[str]:
        try:
            with open(CULVERT_LOG, "r", errors="replace") as f:
                f.seek(offset)
                return [ln.rstrip("\n") for ln in f.readlines()]
        except OSError:
            return []

    def reset_config(self):
        """Fast API-level reset between scenarios in a batch."""
        code, body = _http("GET", f"{UI}/api/policy")
        if code == 200:
            try:
                for r in json.loads(body).get("rules", []):
                    if r.get("id"):
                        _http("DELETE", f"{UI}/api/policy?id={r['id']}")
            except Exception:
                pass
        # auth rules
        code, body = _http("GET", f"{UI}/api/authpolicy")
        if code == 200:
            try:
                data = json.loads(body)
                for r in (data.get("rules", data) if isinstance(data, dict) else data):
                    rid = r.get("id") if isinstance(r, dict) else None
                    if rid:
                        _http("DELETE", f"{UI}/api/authpolicy?id={rid}")
            except Exception:
                pass
        _http("POST", f"{UI}/api/default-action", {"action": "allow"})
        # NB: do NOT touch default-auth-outcome here — setting Exempt flips
        # IsConfigured() and drops the instance out of open mode.


def _kill_stray_on_ports():
    """Belt-and-suspenders: kill any stray culvert bound to our ports (zombie cleanup)."""
    try:
        out = subprocess.check_output(["ps", "-eo", "pid,args"], text=True)
    except Exception:
        return
    for line in out.splitlines():
        if f"-port {PROXY_PORT}" in line and "culvert" in line and "run_campaign" not in line:
            pid = line.strip().split(None, 1)[0]
            if pid.isdigit():
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except Exception:
                    pass
    time.sleep(0.3)


def _git_commit() -> str:
    try:
        return subprocess.check_output(["git", "-C", REPO, "rev-parse", "HEAD"]).decode().strip()
    except Exception:
        return "unknown"


# =============================================================================
# Operator — translate abstract intent -> Culvert API, apply, read back
# =============================================================================
_ACTION_MAP = {"allow": "Allow", "block_page": "Block_Page", "drop": "Drop", "redirect": "Redirect"}
_SSL_MAP = {"inspect": "Inspect", "bypass": "Bypass", None: "", "": ""}


class Operator:
    def __init__(self, cv: Culvert):
        self.cv = cv
        self.api_log: list[dict] = []

    def _call(self, method, path, body=None):
        code, resp = _http(method, f"{UI}{path}", body)
        self.api_log.append({"method": method, "path": path, "req": body,
                             "status": code, "resp_head": resp[:400]})
        return code, resp

    def apply(self, intent: dict) -> dict:
        """Apply the scenario intent; return an apply-report with any anomalies."""
        report = {"errors": [], "warnings": [], "created": []}
        obj = intent.get("objects", {})

        # 1. supporting objects first (categories -> groups -> profiles -> lists)
        for name, hosts in (obj.get("categories") or {}).items():
            code, resp = self._call("POST", "/api/urlcat", {"name": name, "hosts": hosts})
            if code not in (200, 201):
                report["errors"].append(f"urlcat {name}: {code} {resp[:120]}")
            else:
                report["created"].append(f"category:{name}")
        for name, cats in (obj.get("category_groups") or {}).items():
            code, resp = self._call("POST", "/api/category-groups", {"name": name, "categories": cats})
            if code not in (200, 201):
                report["errors"].append(f"category-group {name}: {code} {resp[:120]}")
        for name, prof in (obj.get("decryption_profiles") or {}).items():
            payload = {"name": name}
            payload.update(prof.get("api", {}))
            code, resp = self._call("POST", "/api/decryption-profiles", payload)
            if code not in (200, 201):
                report["errors"].append(f"decryption-profile {name}: {code} {resp[:120]}")
        if obj.get("blocklist"):
            code, resp = self._call("POST", "/api/blocklist", {"hosts": obj["blocklist"]})
            if code not in (200, 201):
                report["errors"].append(f"blocklist: {code} {resp[:120]}")
        for pat in (obj.get("ssl_bypass") or []):
            code, resp = self._call("POST", "/api/ssl-bypass", {"pattern": pat})
            if code not in (200, 201):
                report["warnings"].append(f"ssl-bypass {pat}: {code} {resp[:120]}")

        # 2. defaults
        self._call("POST", "/api/default-action", {"action": intent.get("default_action", "allow")})
        # Only set default-auth-outcome for auth-family scenarios (configured mode).
        # In open mode this call would flip IsConfigured() and break subsequent
        # unauthenticated admin calls, so it is gated on configure_auth.
        if intent.get("configure_auth"):
            code, resp = self._call("PUT", "/api/settings/default-auth-outcome",
                                    {"defaultAuthOutcome": intent.get("default_auth", "Default")})
            if code not in (200, 201):
                report["warnings"].append(f"default-auth-outcome: {code} {resp[:120]}")

        # 3. access rules
        for r in intent.get("rules", []):
            if r.get("kind", "access") != "access":
                continue
            body = self._rule_body(r)
            code, resp = self._call("POST", "/api/policy", body)
            if code not in (200, 201):
                report["errors"].append(f"rule {r.get('name')}: {code} {resp[:160]}")

        # 4. optional post-apply mutations (object lifecycle: delete-referenced, etc.)
        report["post_apply"] = []
        for op in (intent.get("post_apply") or []):
            code, resp = self._call(op["method"], op["path"], op.get("body"))
            report["post_apply"].append({"label": op.get("label", ""), "path": op["path"],
                                        "method": op["method"], "status": code,
                                        "expected_status": op.get("expect_status"),
                                        "resp_head": resp[:200]})

        # settle + readback verification
        time.sleep(0.4)
        report["readback"] = self.verify(intent)
        return report

    def _rule_body(self, r: dict) -> dict:
        m = r.get("match", {})
        body = {
            "name": r["name"],
            "priority": r.get("priority", 100),
            "sourceIP": m.get("src_ip", "") or "",
            "sourceIdentity": m.get("identity", "") or "",
            "sourceGroup": m.get("group", "") or "",
            "authSource": m.get("auth_source", "") or "",
            "destFQDN": m.get("fqdn", "") or "",
            "destCategory": m.get("category", "") or "",
            "destCategoryGroup": m.get("category_group", "") or "",
            "action": _ACTION_MAP.get(r.get("action", "allow"), "Allow"),
            "sslAction": _SSL_MAP.get(r.get("ssl", ""), ""),
        }
        if m.get("country"):
            body["destCountry"] = m["country"]
        if m.get("schedule"):
            s = m["schedule"]
            body["schedule"] = {
                "days": s.get("days", []),
                "timeStart": s.get("start", s.get("timeStart", "")),
                "timeEnd": s.get("end", s.get("timeEnd", "")),
                "timezone": s.get("tz", s.get("timezone", "")),
            }
        if r.get("tls_skip_verify"):
            body["tlsSkipVerify"] = True
        if r.get("decryption_profile"):
            body["decryptionProfile"] = r["decryption_profile"]
        if r.get("file_profile"):
            body["fileProfile"] = r["file_profile"]
            body["fileFiltering"] = True
        if r.get("redirect_url"):
            body["redirectURL"] = r["redirect_url"]
        if r.get("enabled") is False:
            body["enabled"] = False
        return body

    def verify(self, intent: dict) -> dict:
        """Read policy back and confirm persistence; detect silent drops."""
        out = {"persisted_rules": 0, "expected_rules": 0, "mismatches": []}
        expected = [r for r in intent.get("rules", []) if r.get("kind", "access") == "access"]
        out["expected_rules"] = len(expected)
        code, body = self._call("GET", "/api/policy")
        if code != 200:
            out["mismatches"].append(f"readback GET failed: {code}")
            return out
        rules = {r["name"]: r for r in json.loads(body).get("rules", [])}
        out["persisted_rules"] = len(rules)
        for r in expected:
            got = rules.get(r["name"])
            if not got:
                out["mismatches"].append(f"rule '{r['name']}' did not persist")
                continue
            # spot-check a few fields for silent coercion
            m = r.get("match", {})
            if m.get("fqdn") and got.get("destFQDN", "").lower() != m["fqdn"].lower():
                out["mismatches"].append(
                    f"rule '{r['name']}' destFQDN '{got.get('destFQDN')}' != '{m['fqdn']}'")
            if _ACTION_MAP.get(r.get("action")) and got.get("action") != _ACTION_MAP.get(r.get("action")):
                out["mismatches"].append(
                    f"rule '{r['name']}' action '{got.get('action')}' != '{_ACTION_MAP.get(r.get('action'))}'")
        return out

    def export_effective(self) -> dict:
        code, body = self._call("GET", "/api/config/export")
        try:
            return json.loads(body)
        except Exception:
            return {}


# =============================================================================
# Traffic Executor — drive real traffic, capture rich evidence
# =============================================================================
# R3: fine-grained enforcement attribution vocabulary. The coarse `disposition`
# (allow/block_page/drop/redirect/auth_challenge/conn_fail) is what the Oracle
# compares against; `attribution` is the AUTHORITATIVE root cause used for evidence
# and to guarantee a BLOCK is never inferred from a status code alone.
ATTR_ALLOW = "allow"
ATTR_POLICY_BLOCK = "policy_block"          # POLICY_BLOCK trace
ATTR_DEFAULT_DENY = "default_deny"          # POLICY_DEFAULT_DENY trace
ATTR_POLICY_DROP = "policy_drop"            # POLICY_DROP trace (silent RST)
ATTR_POLICY_REDIRECT = "policy_redirect"    # POLICY_REDIRECT trace
ATTR_FILE_BLOCK = "file_block"              # FILE_BLOCKED trace
ATTR_THREAT_BLOCK = "threat_block"          # THREAT_BLOCKED / blocklist trace
ATTR_AUTH_CHALLENGE = "auth_challenge"      # CRED_REQUIRED/AUTH_FAIL/407
ATTR_TLS_VALIDATION_FAIL = "tls_validation_fail"  # SSL_INSPECT cert/handshake error on upstream
ATTR_UPSTREAM_FAIL = "upstream_fail"        # proxy allowed, origin unreachable (502/504/reset)
ATTR_DNS_FAIL = "dns_fail"                  # curl 6
ATTR_FIXTURE_FAIL = "fixture_fail"          # origin down, no proxy decision / 502 w/o allow trace
ATTR_CLIENT_TRUST_FAIL = "client_trust_fail"  # curl 60 (client didn't trust presented cert)
ATTR_TLS_HANDSHAKE = "tls_handshake_fail"   # curl 35
ATTR_TIMEOUT = "timeout"                    # curl 28
ATTR_CONN_RESET = "conn_reset"              # curl 7/56
ATTR_UNATTRIBUTED_BLOCKISH = "unattributed_blockish"  # 4xx/blockpage with NO Culvert marker
ATTR_UNKNOWN = "unknown"

# Which attributions are AUTHORITATIVE Culvert enforcement decisions (evidence-backed).
BLOCK_ATTRS = {ATTR_POLICY_BLOCK, ATTR_DEFAULT_DENY, ATTR_FILE_BLOCK, ATTR_THREAT_BLOCK}


@dataclass
class ActualResult:
    disposition: str
    tls: Optional[str] = None
    http_status: int = 0
    curl_exit: int = 0
    curl_err: str = ""
    body_head: str = ""
    is_block_page: bool = False
    attribution: str = ""          # R3: authoritative root cause
    evidence: str = ""             # the specific trace line / signal that decided it
    decision_trace: list = field(default_factory=list)
    stats_delta: dict = field(default_factory=dict)
    probes: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


class Executor:
    def __init__(self, cv: Culvert):
        self.cv = cv

    def _stats(self) -> dict:
        code, body = _http("GET", f"{UI}/api/stats")
        try:
            j = json.loads(body)
            return {"total": j.get("total", 0), "blocked": j.get("blocked", 0), "allowed": j.get("allowed", 0)}
        except Exception:
            return {}

    def _curl(self, args: list[str], timeout=20) -> tuple[int, str, str]:
        try:
            p = subprocess.run(["curl", "-s", "--max-time", str(timeout)] + args,
                               capture_output=True, text=True, timeout=timeout + 5)
            return p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            return 28, "", "timeout"

    def run(self, vec: dict) -> ActualResult:
        off = self.cv.log_offset()
        s0 = self._stats()
        scheme = vec.get("scheme", "http")
        if scheme == "https":
            res = self._run_https(vec)
        elif scheme == "socks5":
            res = self._run_socks5(vec)
        else:
            res = self._run_http(vec)
        time.sleep(0.25)
        s1 = self._stats()
        res.stats_delta = {k: s1.get(k, 0) - s0.get(k, 0) for k in ("total", "blocked", "allowed")}
        res.decision_trace = [ln for ln in self.cv.log_since(off)
                              if any(t in ln for t in ("POLICY_", "SSL_", "AUTH_", "THREAT_",
                                                        "FILE_", "CRED_", "SSO_", "BLOCK", "DENY", "DROP"))]
        # R3: authoritative attribution — sets disposition + attribution + evidence.
        self._attribute(res)
        return res

    def _attribute(self, res: ActualResult):
        """R3: derive the disposition from AUTHORITATIVE Culvert evidence first.
        A BLOCK/DROP/REDIRECT disposition REQUIRES a Culvert decision-trace marker; a
        bare status code (e.g. an origin 403 or a 502) can NEVER by itself be scored as
        a policy block. Failure modes are differentiated for the evidence record."""
        trace = res.decision_trace
        st, rc, err = res.http_status, res.curl_exit, (res.curl_err or "")

        def first(marker):
            for ln in trace:
                if marker in ln:
                    return ln[-160:]
            return ""

        def has(*ms):
            return any(m in ln for m in ms for ln in trace)

        proxy_allowed = has("POLICY_ALLOW", "AUTH_DEFAULT_EXEMPT", "default-allow", "SSL_INNER")

        # 1) Authoritative Culvert enforcement decisions (trace-backed).
        if has("POLICY_DROP"):
            res.disposition, res.attribution, res.evidence = oracle.DROP, ATTR_POLICY_DROP, first("POLICY_DROP")
        elif has("POLICY_DEFAULT_DENY"):
            res.disposition, res.attribution, res.evidence = oracle.BLOCK_PAGE, ATTR_DEFAULT_DENY, first("POLICY_DEFAULT_DENY")
        elif has("POLICY_BLOCK"):
            res.disposition, res.attribution, res.evidence = oracle.BLOCK_PAGE, ATTR_POLICY_BLOCK, first("POLICY_BLOCK")
        elif has("FILE_BLOCKED"):
            res.disposition, res.attribution, res.evidence = oracle.BLOCK_PAGE, ATTR_FILE_BLOCK, first("FILE_BLOCKED")
        elif has("THREAT_BLOCKED"):
            res.disposition, res.attribution, res.evidence = oracle.BLOCK_PAGE, ATTR_THREAT_BLOCK, first("THREAT_BLOCKED")
        elif has("SOCKS5 BLOCKED") or (has("BLOCKED") and not proxy_allowed and not has("POLICY_")):
            res.disposition, res.attribution, res.evidence = oracle.BLOCK_PAGE, ATTR_THREAT_BLOCK, first("BLOCKED")
        elif has("POLICY_REDIRECT"):
            res.disposition, res.attribution, res.evidence = oracle.REDIRECT, ATTR_POLICY_REDIRECT, first("POLICY_REDIRECT")
        elif has("CRED_REQUIRED", "AUTH_FAIL", "SSO_") or st == 407:
            res.disposition, res.attribution, res.evidence = oracle.AUTH_CHALLENGE, ATTR_AUTH_CHALLENGE, (first("CRED_REQUIRED") or first("AUTH_FAIL") or "407")
        # 2) Proxy ALLOWED the request — the CLIENT outcome decides allow vs failure.
        elif proxy_allowed:
            tls_upstream_err = has("SSL_INSPECT") and ("handshake error" in " ".join(trace) or "certificate" in " ".join(trace).lower())
            if res.tls == oracle.TLS_INTERCEPTED or res.tls == oracle.TLS_PASSTHROUGH:
                if st and 200 <= st < 400:
                    res.disposition, res.attribution = oracle.ALLOW, ATTR_ALLOW
                else:
                    res.disposition, res.attribution = oracle.CONN_FAIL, ATTR_UPSTREAM_FAIL
            elif st in (502, 504):
                res.disposition, res.attribution = oracle.CONN_FAIL, ATTR_UPSTREAM_FAIL
            elif rc in (7, 56):
                res.disposition, res.attribution = oracle.CONN_FAIL, ATTR_CONN_RESET
            elif rc == 28:
                res.disposition, res.attribution = oracle.CONN_FAIL, ATTR_TIMEOUT
            elif st and 200 <= st < 300:
                res.disposition, res.attribution = oracle.ALLOW, ATTR_ALLOW
            elif st in (301, 302, 303, 307, 308):
                # origin-issued redirect passed through an ALLOW — not a policy redirect
                res.disposition, res.attribution = oracle.ALLOW, ATTR_ALLOW
            elif st == 0 and (tls_upstream_err or "bad record MAC" not in err):
                # allowed CONNECT but the tunnel never carried an HTTP response and no
                # client probe completed → upstream/inspect-leg failure, not a block.
                res.disposition, res.attribution = oracle.CONN_FAIL, (
                    ATTR_TLS_VALIDATION_FAIL if tls_upstream_err else ATTR_UPSTREAM_FAIL)
            else:
                res.disposition, res.attribution = oracle.ALLOW, ATTR_ALLOW
            res.evidence = first("POLICY_ALLOW") or first("AUTH_DEFAULT_EXEMPT") or "proxy-allowed"
            if res.attribution == ATTR_UPSTREAM_FAIL:
                res.probes["upstream_fail"] = True
        # 3) NO authoritative Culvert marker — cannot be a confirmed policy decision.
        else:
            if rc == 6:
                res.disposition, res.attribution = oracle.CONN_FAIL, ATTR_DNS_FAIL
            elif rc == 28:
                res.disposition, res.attribution = oracle.CONN_FAIL, ATTR_TIMEOUT
            elif rc in (35, 51, 53):
                res.disposition, res.attribution = oracle.CONN_FAIL, ATTR_TLS_HANDSHAKE
            elif rc == 60:
                res.disposition, res.attribution = oracle.CONN_FAIL, ATTR_CLIENT_TRUST_FAIL
            elif st in (502, 504):
                res.disposition, res.attribution = oracle.CONN_FAIL, ATTR_FIXTURE_FAIL
                res.probes["upstream_fail"] = True
            elif st == 403 and res.is_block_page:
                # a block-looking page WITHOUT any Culvert marker: do NOT trust it as a
                # policy block — flag as unattributed for triage.
                res.disposition, res.attribution = oracle.BLOCK_PAGE, ATTR_UNATTRIBUTED_BLOCKISH
            elif st == 407:
                res.disposition, res.attribution = oracle.AUTH_CHALLENGE, ATTR_AUTH_CHALLENGE
            elif st == 0:
                res.disposition, res.attribution = oracle.CONN_FAIL, ATTR_FIXTURE_FAIL
            elif 200 <= st < 400:
                res.disposition, res.attribution = oracle.ALLOW, ATTR_ALLOW
            else:
                res.disposition, res.attribution = oracle.CONN_FAIL, ATTR_UNKNOWN
            res.evidence = f"no-culvert-marker; status={st} rc={rc}"

    def _src_iface(self, vec) -> list[str]:
        src = vec.get("client_ip")
        if src == SRC_CORP:
            return ["--interface", SRC_CORP]
        return []  # default source = 127.0.0.1

    def _proxy_url(self, vec) -> str:
        # When binding a non-loopback source we must reach the proxy on that iface.
        return f"http://{FIXTURE_IP}:{PROXY_PORT}" if vec.get("client_ip") == SRC_CORP else PROXY

    def _run_http(self, vec: dict) -> ActualResult:
        host = vec["host"]; port = vec.get("port", FIXTURE_HTTP); path = vec.get("path", "/")
        url = f"http://{host}:{port}{path}"
        args = ["-x", self._proxy_url(vec), "-o", "/tmp/body.out",
                "-w", "%{http_code}", "-H", "Connection: close"] + self._src_iface(vec)
        for hk, hv in (vec.get("inject_headers") or {}).items():
            args += ["-H", f"{hk}: {hv}"]
        if vec.get("method", "GET") != "GET":
            args += ["-X", vec["method"]]
        rc, out, err = self._curl(args + [url])
        body = _read_head("/tmp/body.out")
        status = int(out) if out.strip().isdigit() else 0
        blockpage = _looks_like_block_page(body)
        res = ActualResult(disposition=oracle.ALLOW, http_status=status, curl_exit=rc,
                           curl_err=err[-160:], body_head=body[:300], is_block_page=blockpage)
        self._check_header_assertions(vec, body, res)
        return res

    def _check_header_assertions(self, vec, body, res):
        """For /echo responses, assert forwarded-header hygiene (identity scrub)."""
        want_absent = vec.get("assert_header_absent")
        if want_absent:
            try:
                echoed = json.loads(body).get("headers", {})
                present = any(k.lower() == want_absent.lower() for k in echoed)
                res.probes["header_scrub"] = {"header": want_absent, "leaked": present,
                                             "echoed_keys": list(echoed.keys())}
            except Exception:
                res.probes["header_scrub"] = {"header": want_absent, "leaked": None,
                                             "note": "echo body not parseable"}

    def _run_socks5(self, vec: dict) -> ActualResult:
        host = vec["host"]; port = vec.get("port", FIXTURE_HTTP); path = vec.get("path", "/")
        # curl --socks5-hostname resolves the name at the proxy (CONNECT-style).
        url = f"http://{host}:{port}{path}"
        args = ["--socks5-hostname", f"127.0.0.1:{SOCKS5_PORT}", "-o", "/tmp/body.out",
                "-w", "%{http_code}", "-H", "Connection: close", url]
        rc, out, err = self._curl(args)
        body = _read_head("/tmp/body.out")
        status = int(out) if out.strip().isdigit() else 0
        blockpage = _looks_like_block_page(body)
        res = ActualResult(disposition=oracle.ALLOW, http_status=status, curl_exit=rc,
                           curl_err=err[-160:], body_head=body[:200], is_block_page=blockpage,
                           probes={"transport": "socks5"})
        return res

    def _run_https(self, vec: dict) -> ActualResult:
        host = vec["host"]; port = vec.get("port", FIXTURE_HTTPS); path = vec.get("path", "/")
        url = f"https://{host}:{port}{path}"
        base = ["-x", self._proxy_url(vec), "-o", "/tmp/body.out", "-w", "%{http_code}"] + self._src_iface(vec)
        # Probe with both trust anchors to detect interception vs passthrough.
        rc_c, out_c, err_c = self._curl(base + ["--cacert", CULVERT_CA, url])
        body_c = _read_head("/tmp/body.out")
        st_c = int(out_c) if out_c.strip().isdigit() else 0
        rc_f, out_f, err_f = self._curl(base + ["--cacert", FIXTURE_CA, url])
        body_f = _read_head("/tmp/body.out")
        st_f = int(out_f) if out_f.strip().isdigit() else 0
        probes = {"culvert_ca": {"rc": rc_c, "status": st_c, "err": err_c[-120:]},
                  "fixture_ca": {"rc": rc_f, "status": st_f, "err": err_f[-120:]}}
        # Determine disposition
        c_ok = st_c and 200 <= st_c < 500
        f_ok = st_f and 200 <= st_f < 500
        tls = None
        if c_ok and not f_ok:
            tls = oracle.TLS_INTERCEPTED
            status, body = st_c, body_c
        elif f_ok and not c_ok:
            tls = oracle.TLS_PASSTHROUGH
            status, body = st_f, body_f
        elif c_ok and f_ok:
            # Both succeeded (shouldn't usually happen); prefer content
            tls = oracle.TLS_PASSTHROUGH
            status, body = st_f, body_f
        else:
            # neither completed: blocked CONNECT or conn fail
            status, body = (st_c or st_f), (body_c or body_f)
        blockpage = _looks_like_block_page(body)
        # Provisional disposition; _attribute() finalizes from the decision trace.
        disp = oracle.ALLOW if tls else oracle.CONN_FAIL
        curl_exit = 0 if (c_ok or f_ok) else (rc_c or rc_f)
        curl_err = (err_c if not c_ok else "") + " " + (err_f if not f_ok else "")
        return ActualResult(disposition=disp, tls=tls, http_status=status,
                            curl_exit=curl_exit, curl_err=curl_err[-200:], body_head=body[:300],
                            is_block_page=blockpage, probes=probes)


def _read_head(path, n=500) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(n)
    except OSError:
        return ""


def _looks_like_block_page(body: str) -> bool:
    b = body.lower()
    return ("<!doctype html" in b or "<html" in b) and (
        "block" in b or "denied" in b or "not permitted" in b or "culvert" in b or "policy" in b)


# =============================================================================
# Failure Reviewer — compare oracle expectation vs actual, classify
# =============================================================================
PASS = "PASS"
PRODUCT_BUG = "PRODUCT_BUG"
MISSING_CAPABILITY = "MISSING_CAPABILITY"
CONFIG_CONTRACT_GAP = "CONFIGURATION_CONTRACT_GAP"
UX_GAP = "UX_GAP"
OBSERVABILITY_GAP = "OBSERVABILITY_GAP"
DOCUMENTATION_GAP = "DOCUMENTATION_GAP"
EXPECTED_LIMITATION = "EXPECTED_LIMITATION"
TEST_INFRA_FAILURE = "TEST_INFRA_FAILURE"
INVALID_SCENARIO = "INVALID_SCENARIO"


class Reviewer:
    def classify_vector(self, exp: oracle.Expectation, act: ActualResult,
                        apply_report: dict, sc: dict = None) -> dict:
        """Return {verdict, primary, confidence, reason} for one vector."""
        agree = self._agree(exp, act)
        if agree:
            return {"verdict": PASS, "primary": PASS, "confidence": 0.95,
                    "reason": f"actual '{act.disposition}' matches expected '{exp.disposition}'"}

        # Divergence. If the scenario declares a documented triage class (e.g. a
        # known architectural boundary), the Failure Reviewer applies it — the
        # Oracle expectation was still derived independently from general SWG norms.
        triage = (sc or {}).get("intent", {}).get("triage") if sc else None
        if triage:
            return {"verdict": triage["class"], "primary": triage["class"], "confidence": 0.85,
                    "reason": f"expected '{exp.disposition}' but actual '{act.disposition}'. "
                              f"Triage: {triage['note'][:200]}"}

        # Divergence. Triage.
        if act.disposition == oracle.CONN_FAIL and exp.disposition != oracle.CONN_FAIL:
            # Proxy ALLOWED the request but the upstream fixture was unreachable
            # (502/504) — an origin/infra failure, never a Culvert policy block.
            if act.probes.get("upstream_fail"):
                return {"verdict": TEST_INFRA_FAILURE, "primary": TEST_INFRA_FAILURE,
                        "confidence": 0.5,
                        "reason": f"proxy allowed (trace={act.decision_trace[:1]}) but upstream "
                                  f"fixture unreachable (status={act.http_status}); infra, not policy"}
            # Could be infra (fixture) — flagged for confirmation, not a bug yet.
            if not act.decision_trace and act.http_status == 0:
                return {"verdict": TEST_INFRA_FAILURE, "primary": TEST_INFRA_FAILURE,
                        "confidence": 0.4,
                        "reason": "connection failed with no proxy decision trace; likely fixture/infra"}
        if exp.certainty == "uncertain":
            return {"verdict": DOCUMENTATION_GAP, "primary": DOCUMENTATION_GAP, "confidence": 0.3,
                    "reason": f"expected '{exp.disposition}' but expectation is uncertain "
                              f"({exp.rationale}); actual '{act.disposition}'"}
        if apply_report.get("errors"):
            return {"verdict": CONFIG_CONTRACT_GAP, "primary": CONFIG_CONTRACT_GAP, "confidence": 0.6,
                    "reason": f"config apply errors: {apply_report['errors'][:2]}; "
                              f"actual '{act.disposition}' vs expected '{exp.disposition}'"}
        # Enforcement divergence with clean config + deterministic expectation.
        return {"verdict": PRODUCT_BUG, "primary": PRODUCT_BUG, "confidence": 0.7,
                "reason": f"deterministic expected '{exp.disposition}' (rule={exp.matched_rule}) "
                          f"but actual '{act.disposition}' (status={act.http_status}, "
                          f"trace={act.decision_trace[:1]})"}

    def _agree(self, exp: oracle.Expectation, act: ActualResult) -> bool:
        if exp.disposition != act.disposition:
            # tolerate block_page vs drop family under CONNECT where proxy may reset
            if {exp.disposition, act.disposition} == {oracle.BLOCK_PAGE, oracle.CONN_FAIL} and act.tls is None:
                return True
            # a silent DROP manifests to the client as a connection reset (CONN_FAIL)
            if exp.disposition == oracle.DROP and act.disposition in (oracle.DROP, oracle.CONN_FAIL):
                return True
            return False
        # if a TLS expectation is set, check it
        if exp.tls and act.tls and exp.tls != act.tls:
            return False
        return True
