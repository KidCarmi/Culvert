# Culvert on-prem pilot — customer questionnaire

Short answers are enough; each question maps to a row of
`requirements-matrix.md`. Questions marked **(pilot-blocking)** change what
we ship.

## Platform
1. **(pilot-blocking)** Hypervisor and version (vSphere/ESXi 7.x/8.x, Hyper-V,
   KVM/Proxmox, other)? Is OVA import allowed, or do you deploy from a
   template store?
2. Expected number of proxied users and peak requests/second? Any destinations
   that must be SSL-inspected (vs. bypassed)?
3. Can you allocate 4 vCPU / 8 GB RAM / 40 GB disk per appliance?

## Network
4. **(pilot-blocking)** DHCP or static IPv4 for the appliance? Management
   VLAN/subnet, default gateway, DNS servers, NTP servers.
5. Who may reach the admin UI (:9090) — a jump host, an admin subnet, or
   anyone on the LAN? (The first-boot setup window is protected only by
   network reach.)
6. How do clients reach the proxy (:8080): explicit browser/PAC config,
   WPAD, or transparent? (Transparent/inline is OUT of the pilot.)

## Egress and dependencies
7. **(pilot-blocking)** Does the appliance have direct HTTPS egress? If
   egress is restricted, can these be allowed: `ghcr.io`, `catalog.culvertlabs.com`,
   `registry-1.docker.io`, `download.docker.com`, `database.clamav.net`,
   `urlhaus.abuse.ch`/`openphish.com`, `github.com`, `*.sigstore.dev`?
8. Is there a corporate upstream proxy the appliance must chain through
   (host, port, auth)? Is a private registry mirror required? (Mirrors are
   supported by code but not qualified for the pilot.)

## Identity, TLS, logging
9. Will the pilot use local admin accounts only, or LDAP/OIDC/SAML for
   admins or users? (LDAP does not provide transparent Kerberos SSO.)
10. Can you issue a TLS certificate for the admin UI hostname, or is the
    self-signed certificate acceptable for the pilot?
11. Will client devices be able to trust the appliance's SSL-inspection CA
    (distributed via GPO/MDM)? If not, inspection stays off.
12. SIEM/syslog destination (UDP/TCP, RFC 3164/5424)? Retention expectations
    for the local request log?

## Operations
13. **(pilot-blocking)** Backup destination: copy the `culvert-backups`
    volume to your storage, or mount NFS/SMB at `/backup`? Who holds the
    backup passphrase and the CA passphrase (separate custody)?
14. Maintenance windows for (a) application upgrades (one proxy restart),
    (b) OS security patches with reboot (one appliance reboot)? Who approves
    emergency patches?
15. Who owns OS patching on your side (if anyone)? Is unattended security
    patching acceptable with reboots deferred to your window?
16. Recovery expectations: acceptable data loss (RPO) and time to restore
    (RTO)? Is a second standby appliance in scope later (HA is out of the
    pilot)?
17. Support access: may our engineers receive redacted support bundles? Any
    constraints on what a bundle may contain?
