#!/usr/bin/env bash
# Fail-closed receipts for ovfenv-check.py: one good guestinfo.ovfEnv in the
# govmomi shape must PASS; every listed defect must FAIL. Throwaway keys.
set -uo pipefail
H="$(cd "$(dirname "$0")" && pwd)"; T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
cd "$T" && ssh-keygen -q -t ed25519 -N '' -f k1 -C qual && ssh-keygen -q -t ed25519 -N '' -f k2 -C other
FP=$(ssh-keygen -lf k1.pub | awk '{print $2}'); K1="$(cat k1.pub)"; K2="$(cat k2.pub)"
printf '{"hostname":"culvert-esxi-325c142a","address":"192.168.1.99/24","gateway":"192.168.1.1","dns":"192.168.1.10,192.168.1.1","ssh_fingerprints":["%s"]}\n' "$FP" > exp.json
mk(){ python3 -I "$H/ovfenv-mkenv.py" "$1" "${2:-ns}"; }
edit(){ python3 -I -c "import json,sys;p=json.loads(sys.argv[1]);$2;print(json.dumps(p))" "$(base)" "${3:-}"; }
base(){ python3 -I -c "import json,sys;print(json.dumps([['instance-id','iid-culvert-appliance'],['hostname','culvert-esxi-325c142a'],['public-keys',sys.argv[1]],['culvert.net.mode','static'],['culvert.net.address','192.168.1.99/24'],['culvert.net.gateway','192.168.1.1'],['culvert.net.dns','192.168.1.10,192.168.1.1']]))" "$K1"; }
n=0; wrong=0
run(){ local out rc v; out="$(python3 -I "$H/ovfenv-check.py" "$2" exp.json)"; rc=$?; v=$([ $rc = 0 ] && echo PASS || echo FAIL)
  n=$((n+1)); if [ "$v" = "$3" ]; then echo "ok	$1	$v"; else wrong=$((wrong+1)); echo "WRONG	$1	$v	$out"; fi; }
mk "$(base)" > good.xml;                                                   run "good (govmomi shape)" good.xml PASS
: > empty.xml;                                                             run "empty value (ESXi readback 28 Oct)" empty.xml FAIL
echo "not xml" > junk.xml;                                                 run "no <Environment" junk.xml FAIL
mk "$(base)" plain > plain.xml;                                            run "non-namespaced attrs (cloud-init fails)" plain.xml FAIL
mk "$(edit x 'p.append(["culvert.net.address","192.168.1.98/24"])')" > d.xml; run "duplicate key" d.xml FAIL
mk "$(edit x 'p[4][1]="192.168.1.141/24"')" > ip.xml;                     run "wrong address" ip.xml FAIL
mk "$(edit x 'p[5][1]="10.0.0.1"')" > gw.xml;                             run "gateway outside subnet" gw.xml FAIL
mk "$(edit x 'p[2][1]=sys.argv[2]' "$K2")" > wk.xml;                       run "wrong SSH key" wk.xml FAIL
mk "$(edit x 'p[2][1]+="\n"+sys.argv[2]' "$K2")" > xk.xml;                 run "extra SSH key" xk.xml FAIL
mk "$(edit x 'p.append(["user-data","I2Nsb3VkLWNvbmZpZw=="])')" > ud.xml; run "user-data injected" ud.xml FAIL
mk "$(edit x 'p.append(["seedfrom","http://x/"])')" > sf.xml;             run "seedfrom injected" sf.xml FAIL
mk "$(edit x 'p.append(["password","x"])')" > pw.xml;                      run "password set" pw.xml FAIL
mk "$(edit x 'p[2][1]=open("k1").read()')" > pk.xml;                       run "private key material" pk.xml FAIL
mk "$(edit x 'del p[3]')" > nm.xml;                                         run "mode missing (DHCP)" nm.xml FAIL
mk "[]" > np.xml;                                                           run "no properties" np.xml FAIL
echo "$n cases, $wrong wrong"; [ "$wrong" = 0 ]
