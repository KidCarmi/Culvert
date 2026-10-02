# Customer requirements questionnaire (on-prem appliance pilot)

Concise. Each answer changes a row in `requirements-matrix.md`. Default
assumptions the pilot uses when a question is unanswered are in brackets.

## Platform
1. Hypervisor and version for the pilot VM? [vSphere/ESXi 7.0U3+]
2. Can you allocate 2 vCPU / 4 GB RAM / 40 GB thin disk? [yes]
3. Do you need an arm64 build? [no; x86-64 only]

## Networking
4. Static IPv4 for the appliance (address, mask, gateway)? DHCP is not used in the pilot. [static, supplied at first boot]
5. Internal DNS servers and search domain? NTP servers? [customer-supplied]
6. Is there ONE network for both proxy clients and administration, or separate networks? The appliance has a single interface and binds all services on it; management isolation is done by ACL/firewall. [one network + firewall ACL on 9090]
7. Which admin workstation addresses/ranges may reach port 9090? (Set as `-ui-allow-ip` after setup.) [required answer]
8. How will clients reach the proxy: browser/OS proxy setting, PAC file, or GPO? [explicit proxy setting]

## Egress and dependencies
9. May the appliance reach these on the internet: `ghcr.io` + `pkg-containers.githubusercontent.com` (image updates), `catalog.culvertlabs.com` (signed release catalog), Ubuntu and Docker apt repositories (OS patching), `urlhaus.abuse.ch` / `openphish.com` (threat feeds, optional)? [yes, via your egress firewall]
10. Is there an egress proxy the appliance itself must use for those fetches? [no]
11. Is a fully air-gapped deployment required? (Not supported in the pilot.) [no]

## Identity
12. Should proxy users authenticate? If so: LDAPS host, service-account DN, base DN, group for allowed users. Kerberos/transparent SSO is not provided. [no proxy authentication in week 1; LDAPS in week 2]
13. Who are the named appliance administrators (at least two)? [two local admin accounts, TOTP optional]

## TLS / PKI
14. Will you issue a certificate for the admin UI hostname from your internal CA? (PEM cert + key.) [yes]
15. Is TLS inspection in scope for the pilot? If yes, the appliance's own generated inspection CA must be distributed to clients (GPO). Bring-your-own inspection CA is not in the pilot. [inspection OFF in week 1]

## Logging, diagnostics, support
16. Syslog/SIEM destination (UDP/TCP, RFC 3164/5424)? [none]
17. Who may run a redacted support bundle and where is it delivered? [customer admin, by email/ticket]
18. Is SSH access to the guest OS acceptable for your own administrators? (No vendor remote access exists.) [yes, key-based]

## Backup, recovery, maintenance
19. Where should encrypted backups be copied (SMB/NFS/S3/other)? Who holds the backup passphrase and the CA passphrase? [customer backup job; passphrases in the customer vault]
20. Recovery objective: how much configuration loss is acceptable (hours/days)? [daily backup]
21. Maintenance window for application updates (minutes, no reboot) and for kernel updates (reboot)? [weekly, out of hours]
22. Who owns guest OS patching after handover: customer IT or a vendor-provided OVA refresh cadence? [customer applies security updates; vendor publishes quarterly OVA]

## Scope confirmation
23. Single node only for the pilot (no HA)? [yes]
24. Features to exercise in the pilot: URL/category policy, blocklists, ClamAV; YARA/DPI, CDR and MCP gateway excluded? [as listed]
