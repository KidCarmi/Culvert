# 2a replacement intake — 2026-10-08

**Offline intake only; not ESXi-qualified or production-ready.** This replacement appeared while the [cd8 ESXi report](esxi-cd8-20261008.md) was being closed. The existing restored cd8 VM remains retained; no replacement VM has been imported.

- Expected source: `2a82320c746a6d146df19a6f5af9676d76b72286`.
- Builder: [run 37703962783](https://github.com/KidCarmi/Culvert/actions/runs/37703962783), lab revision `c48539f26933651ad2593264611ee5d2217119d5`.
- [Unqualified LAB OVA artifact 11519101999](https://github.com/KidCarmi/Culvert/actions/runs/37703962783/artifacts/11519101999).
- GitHub artifact ZIP SHA256: `23e79e4777a1b26275017d1dad32eb6e03aad0500d40ff085100f3bc9ba3463c`; 1,313,746,463 bytes.
- OVA SHA256: **`0f44483d3fc9a3c7017d7324cc21e36dd770ddec57699db3c84f8dd16fb01569`**; 1,313,740,800 bytes.
- **PASS:** download matches the GitHub ZIP digest, OVA payload has a complete SHA256 manifest, and every OVF/VMDK member matches. Declared hardware is 2 vCPU, 4 GiB RAM and 40 GiB disk. No ESXi import or guest execution.
- [Intake receipt](evidence/2a-intake-20261008/download-receipt.json) and [offline verification](evidence/2a-intake-20261008/offline-verification.json).

The queried 16 workflows for the source revision were completed successfully, including Fast and Deep. The replacement builder was still running when intake started; its QEMU/adoption/scanner results and full source/image/OVA handoff have not been independently qualified here. A green source workflow is not artifact qualification.

The [independent SAML source audit](evidence/cd8-esxi-20261008/integration-followup.md) confirms the cd8 callback failure and the fixed source's eight cookie-purpose controls. The newer [browser follow-up](evidence/2a-intake-20261008/browser-followup.md) verifies Chromium's cookie routing through a Node recording proxy: the UI-host cookie does not reach other HTTP destinations or CONNECT. That browser leg runs neither Culvert nor a SAML provider. Source review finds no alternate post-login identity binding; it supports a browser-to-proxy SSO transport gap but is not a live appliance reproduction.

Production closeout therefore still requires browser-bound SAML/OIDC state, a defined browser-to-proxy identity transport with real browser enforcement controls, the exact adopted-sidecar scan, and supported historical-log recovery with rotation-key custody. These are coordinated with Opus in [the production PR](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6049257959). No merge, release or risk acceptance is authorized.
