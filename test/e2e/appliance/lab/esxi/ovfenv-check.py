#!/usr/bin/env python3
"""ovfenv-check.py READBACK_FILE EXPECTED_JSON

Validates a guestinfo.ovfEnv value READ BACK FROM ESXi against what the
OVA 325c142a guest will actually consume at first boot. It parses the value
with BOTH consumers' code and requires them to agree:

  * cloud-init 26.2 DataSourceOVF.get_properties (verbatim below; the guest
    ships cloud-init 26.2-0ubuntu1~24.04.2) - delivers hostname + public-keys;
  * culvert-firstboot.sh ovf_prop (verbatim logic below, source 0648adeb) -
    delivers culvert.net.* (static network). It reads once, at first boot.

EXPECTED_JSON: {"hostname": "...", "address": "a.b.c.d/nn", "gateway": "...",
                "dns": "x,y", "search": "" (optional), "ssh_fingerprints": ["SHA256:..."]}
Prints a JSON verdict (fingerprints only, never key material). Exit 0 = PASS.
"""
import base64, hashlib, ipaddress, json, sys
import xml.etree.ElementTree as ET
from xml.dom import minidom

ALLOWED = {"instance-id", "hostname", "public-keys", "password",
           "culvert.net.mode", "culvert.net.address", "culvert.net.gateway",
           "culvert.net.dns", "culvert.net.search"}   # the OVF descriptor's keys

# ---- cloud-init 26.2 cloudinit/sources/DataSourceOVF.py (verbatim) --------
class XmlError(Exception):
    pass

def find_child(node, filter_func):
    ret = []
    if not node.hasChildNodes():
        return ret
    for child in node.childNodes:
        if filter_func(child):
            ret.append(child)
    return ret

def get_properties(contents):
    dom = minidom.parseString(contents)  # nosec B318
    if dom.documentElement.localName != "Environment":
        raise XmlError("No Environment Node")
    if not dom.documentElement.hasChildNodes():
        raise XmlError("No Child Nodes")
    envNsURI = "http://schemas.dmtf.org/ovf/environment/1"
    propSections = find_child(
        dom.documentElement, lambda n: n.localName == "PropertySection"
    )
    if not propSections:
        raise XmlError("No 'PropertySection's")
    props = {}
    propElems = find_child(
        propSections[0], (lambda n: n.localName == "Property")
    )
    for elem in propElems:
        key = elem.attributes.getNamedItemNS(envNsURI, "key").value
        val = elem.attributes.getNamedItemNS(envNsURI, "value").value
        props[key] = val
    return props
# ---------------------------------------------------------------------------

def firstboot_prop(raw, key):
    """culvert-firstboot.sh read_ovf_env + ovf_prop, same semantics."""
    if "<Environment" not in raw:          # read_ovf_env's acceptance test
        return None
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return ""
    for el in root.iter():
        if el.tag.endswith('}Property') or el.tag == 'Property':
            k = el.get('{http://schemas.dmtf.org/ovf/environment/1}key') or el.get('key')
            if k == key:
                return el.get('{http://schemas.dmtf.org/ovf/environment/1}value') or el.get('value') or ''
    return ""

def fingerprint(line):
    parts = line.split()
    if len(parts) < 2 or not (parts[0].startswith("ssh-") or parts[0].startswith("ecdsa-")):
        raise ValueError("not an OpenSSH public key line")
    blob = base64.b64decode(parts[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")

def main():
    raw = open(sys.argv[1], encoding="utf-8").read()
    exp = json.load(open(sys.argv[2]))
    problems, facts = [], {}
    if not raw.strip():
        problems.append("guestinfo.ovfEnv is empty")
    elif "<Environment" not in raw:
        problems.append("no <Environment: culvert-firstboot would treat it as absent (DHCP)")
    if "PRIVATE KEY" in raw:
        problems.append("private key material present")
    ci = None
    if not problems:
        try:
            ci = get_properties(raw)
        except Exception as e:  # cloud-init would fail the datasource
            problems.append("cloud-init get_properties fails: %s: %s" % (type(e).__name__, e))
    if ci is not None:
        # duplicates: cloud-init keeps the LAST, firstboot the FIRST
        root = ET.fromstring(raw)
        keys = [el.get('{http://schemas.dmtf.org/ovf/environment/1}key') for el in root.iter()
                if el.tag.endswith('}Property')]
        dup = sorted({k for k in keys if keys.count(k) > 1})
        if dup:
            problems.append("duplicate keys %s (the two consumers disagree on which wins)" % dup)
        extra = sorted(set(ci) - ALLOWED)
        if extra:
            problems.append("keys outside the OVF descriptor %s (e.g. user-data/seedfrom/network-config change cloud-init behaviour)" % extra)
        if ci.get("password", ""):
            problems.append("a non-empty password property is set (cloud-init would apply it)")
        for k in ("hostname", "culvert.net.mode", "culvert.net.address", "culvert.net.gateway", "culvert.net.dns"):
            fb = firstboot_prop(raw, k)
            if k.startswith("culvert.") and fb != ci.get(k, ""):
                problems.append("%s: cloud-init sees %r, culvert-firstboot sees %r" % (k, ci.get(k), fb))
        def want(k, v):
            if ci.get(k, "") != v:
                problems.append("%s is %r, expected %r" % (k, ci.get(k, ""), v))
        want("hostname", exp["hostname"])
        want("culvert.net.mode", "static")
        want("culvert.net.address", exp["address"])
        want("culvert.net.gateway", exp["gateway"])
        want("culvert.net.dns", exp["dns"])
        want("culvert.net.search", exp.get("search", ""))
        try:
            iface = ipaddress.ip_interface(ci.get("culvert.net.address", ""))
            gw = ipaddress.ip_address(ci.get("culvert.net.gateway", ""))
            if gw not in iface.network or gw == iface.ip:
                problems.append("gateway %s not a distinct host in %s" % (gw, iface.network))
            facts["address"] = str(iface); facts["gateway"] = str(gw)
        except ValueError as e:
            problems.append("address/gateway not parseable: %s" % e)
        for d in filter(None, ci.get("culvert.net.dns", "").split(",")):
            try: ipaddress.ip_address(d.strip())
            except ValueError: problems.append("dns entry %r is not an address" % d)
        fps = []
        for line in filter(None, (l.strip() for l in ci.get("public-keys", "").splitlines())):
            try: fps.append(fingerprint(line))
            except Exception as e: problems.append("public-keys line not a valid public key (%s)" % e)
        facts["ssh_fingerprints"] = fps
        if sorted(fps) != sorted(exp["ssh_fingerprints"]):
            problems.append("public-keys fingerprints %s, expected exactly %s" % (fps, exp["ssh_fingerprints"]))
        facts["keys"] = sorted(ci)
    print(json.dumps({"verdict": "FAIL" if problems else "PASS", "problems": problems, "facts": facts}, indent=1))
    sys.exit(1 if problems else 0)

if __name__ == "__main__":
    main()
