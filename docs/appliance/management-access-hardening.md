# Management access policy and network isolation

The admin UI's existing IP allowlist is configured through **Settings → UI
access IPs**, `POST /api/ui-allow-ips`, `ui_allow_ips` in application YAML, or
`-ui-allow-ip`. It filters HTTP requests to the management listener, including
setup and authentication. It is not a host firewall or a separate management
network. IPv4 and IPv6 addresses and CIDRs are supported; an explicitly empty
array removes the restriction. Blank entries are invalid in the API; in the
YAML/CLI startup seed they carry no intent and are skipped (a trailing comma in
`-ui-allow-ip` is not an error).

An invalid startup CIDR refuses all management requests until the YAML/CLI
source is corrected and the application restarted, instead of exposing an
unrestricted admin listener. It does not stop the process: the proxy keeps
serving (the management plane never terminates the data plane). A malformed
saved list likewise refuses all management requests with
`503 ui_access_policy_unavailable`; the proxy data plane is not disabled by
this management guard. `/ready` includes a report-only `ui_access_policy` fail
row. The original malformed list survives unrelated settings saves and restart.

Unreadable or corrupt saved settings also refuse management because the previous
allowlist cannot be established. Such a load blocks omnibus settings saves, so
an unrelated mutation cannot replace unknown policy with unrestricted defaults.
Corrupt JSON remains quarantined using the existing storage-recovery mechanism.
A leftover quarantine plus a replacement document without an explicit UI policy
does not silently reopen management. A genuinely absent first-run settings file
without quarantine retains the normal setup flow.

API updates validate the entire list before changing anything and save it before
publishing it to live requests. A pre-rename write failure returns
`503 ui_allow_ips_not_saved` and preserves the running policy. If replacement
lands but parent-directory synchronization fails, disk and runtime use the new
policy, the change is audited, and the API returns
`503 ui_allow_ips_persistence_uncertain`: success and crash durability are not
claimed. Check storage and read back the effective policy before restarting.
The internal `ui_allow_ips_saved` marker makes an explicitly empty saved list
authoritative over a YAML/CLI seed on restart; it is not another user setting.
It is written only by an explicit policy change (or carried forward from a
document that already holds it): an unrelated settings save never claims that
the administrator chose an open policy.

For recovery, authenticate through the VM's local console as `culvert`. Preserve
the settings file and any quarantined copy before repairing the existing
`admin_settings.json` on the appliance data volume. Restore the intended valid
`ui_allow_ips` array; set `ui_allow_ips_saved: true` when deliberately restoring
an empty array. Restart the application after repairing its stored policy.
This repair of a corrupt settings file is a tested procedure:
`TestUIAccessCorruptSettingsDocumentedRecovery` (`ui_access_recovery_e2e_test.go`)
runs it end to end. A corrupt file refuses management and omnibus saves. A
replacement without an explicit policy stays refused. A repaired restricted list
admits only its peers. An explicit open list admits all peers. The quarantined
copy survives the repair, the restart and later saves.
There is no unauthenticated, loopback, or routine-SSH bypass. A malformed startup
YAML/CLI policy must be repaired at its source; management stays refused until
the corrected configuration is loaded by a restart.

## Remaining network boundary

The current Compose deployment publishes host port 9090 on all addresses.
Docker routes published container traffic through NAT/forwarding; restricting
only the appliance host's INPUT chain does not isolate that path. This follows
[Docker's firewall documentation](https://docs.docker.com/engine/network/packet-filtering-firewalls/).
The current appliance supplies one physical interface and has no authoritative
customer management CIDR. No private subnet or additional interface is inferred.

A separate host-isolation change needs operator-supplied IPv4/IPv6 management
sources or an explicit management interface, and an appliance-owned nftables
guard covering both host INPUT and Docker FORWARD paths. It must not flush or
rewrite Docker-owned tables, block proxy port 8080, or disable forwarding.
[Docker's nftables guidance](https://docs.docker.com/engine/network/firewall-nftables/)
supports separate tables and hook priorities for such filtering. It also needs
its own tested local recovery path for a bad firewall policy. The application
settings recovery above is tested, but it does not cover a host firewall.
Bootstrap reachability and policy persistence across Docker restart, OS update,
reboot, and restore must be qualified before claiming management-network
isolation.

These source changes do not update an existing deployed or previously qualified
OVA. A matching image and a new appliance qualification remain required.
