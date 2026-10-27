# Sidecar libcurl CVE-2026-92392: static reachability (ASTRA 08:55)

**This is static evidence only. It is not a disposition.** The choice to fix (pin libcurl 8.23.0-r0, which means a new sidecar identity and a fresh F-P2 proof) or to accept a bounded residual belongs to the owner. ASTRA owns the verdict.

**Why this exists:** the dispatch CI on `c1b08dbe` failed the Deep gate's sidecar CVE check on one row (`deep-sidecar-cve-gate.txt`):

| Image | Library | CVE | Severity | Installed | Fixed |
|---|---|---|---|---|---|
| `culvert/clamav:1.5.4-culvert.3` (Alpine 3.24.2) | libcurl | CVE-2026-92392 | HIGH | 8.22.0-r0 | 8.23.0-r0 |

M1 does not touch the sidecar. The row is a new advisory against an unchanged image.

## The advisory (curl's own record)

- **Summary:** "HTTP/2 upload Use-After-Free".
- **Details:** "During an upload, curl mishandles HTTP/2 `RST_STREAM` received from the server (with reason `HTTP_1_1_REQUIRED` or `REFUSED_STREAM`) leading to a use after free of a `struct Curl_easy` object."
- **Affected ranges:** 8.12.0–8.14.3, 8.15.0–8.16.2, 8.17.0–8.20.2, 8.21.0–8.23.0 (each range excludes its fixed version). The installed 8.22.0 is in the last range.
- **Conditions it needs, as stated:** an **upload**, over **HTTP/2**, and a server that sends one of those two `RST_STREAM` codes.

## What was inspected

- **Base image.** `appliance/clamav/Dockerfile` builds `FROM docker.io/clamav/clamav@sha256:638d90201ee7ee6a82d249a2fc23b132e578673b5f1f2766852b127676ca1ef6`.
  - The amd64 manifest was fetched by digest; its file hashes to `705e0723f02fc13bf6e5e8a8e13a8c44420acf5e7ed06dfa2197081da00c7a73`. Config `sha256:5ae9675f…`.
  - All 7 layers were downloaded and each re-hashed to its manifest digest before extraction.
  - Alpine 3.24.2. The apk database lists `libcurl` `V:8.22.0-r0`.
- **Not inspected directly: the shipped sidecar image** (`culvert.3`, amd64 manifest `4c365e40`). Its Dockerfile adds exactly one `RUN apk add --no-cache --upgrade` of pcre2, zlib, nghttp2-libs, musl, musl-utils and brotli-libs, then removes the apk log and cache. It installs no ClamAV binary and no libcurl. The Trivy row above confirms that libcurl is still 8.22.0-r0 in the shipped image. **It is an inference, not a byte check, that the ClamAV binaries below are the same in the shipped image.**
- **ClamAV source.** `clamav-1.5.4.tar.gz` from clamav.net:
  - sha256 `1af1117a228f1b5bc7fa91a0dabc37848a99e7d25188e9be8043332ce721dfd3`;
  - detached signature `GOODSIG`/`VALIDSIG` from Talos key `5BADCA2665EF59DCF8A23D8B707F0DB480836771`.
  - **Key-provenance caveat:** that key was fetched from keys.openpgp.org for this check. It was not pinned in the repository beforehand.
- **Source ↔ binary link.** This is weak and supporting only, because the image is upstream's build:
  - `libclamav` reports `1.5.4`.
  - The log strings quoted below appear in the image's `clamsubmit` (1 hit) and `libfreshclam.so.4.0.0` (2 hits).

## Which binaries can use libcurl

These are the `readelf -d` NEEDED entries across all ELF files in the extracted base. There are only three consumers, and there is no `curl` command-line tool in the image.

| File | sha256 | Links libcurl |
|---|---|---|
| `/usr/lib/libcurl.so.4.8.0` | `29c95705…c2f8b0` | (the library) |
| `/usr/lib/libfreshclam.so.4.0.0` | `bbada56d…8123ec` | yes |
| `/usr/bin/freshclam` | `a674e6c8…4ca7c6` | yes, through libfreshclam |
| `/usr/bin/clamsubmit` | `20d741cb…726deb` | yes |
| `clamd`, `clamscan`, `clamdscan`, `sigtool`, `clamconf` and the rest | — | **no** |
| `clamonacc` (source in `clamonacc/client/client.c` calls `curl_easy_init`) | — | **not shipped** |

## What runs

- **Image entrypoint** (`/init`, sha256 `4034f6d6…`):
  - It runs `freshclam --foreground` once if `/var/lib/clamav/main.cvd` is missing. This happens **regardless** of `CLAMAV_NO_FRESHCLAMD`.
  - It then starts the `freshclam --daemon` loop unless `CLAMAV_NO_FRESHCLAMD=true`.
  - It starts `clamd`, and starts milter unless `CLAMAV_NO_MILTERD=true`.
  - **It never runs `clamsubmit`.**
- **Appliance stack:**
  - `docker-compose.yml:54` (and `docker-compose.ha.yml:56`) set `CLAMAV_NO_FRESHCLAMD=false`, so **freshclam runs on the appliance** and reaches the network on each check.
  - The lab and F-P2 harnesses set it to `true`. That covers tests only.
- **Repository references to `clamsubmit`** (tree `22245a12`): one, an SBOM file list (`appliance/sbom/evidence/clamav-candidate-pcre2.spdx.json`). No code, script or compose file runs it.

## What each consumer asks libcurl to do (ClamAV 1.5.4 source)

**`libfreshclam` (`libfreshclam/libfreshclam_internal.c`), the path that runs:**

- Requests are `GET` only: `CURLOPT_HTTPGET` at lines 969 (`remote_cvdhead`) and 1285 (`downloadFile`).
- There is no `CURLOPT_UPLOAD`, `POST`, `POSTFIELDS`, `READFUNCTION`, `READDATA`, `MIMEPOST`, `HTTPPOST`, `INFILESIZE` or `CUSTOMREQUEST` anywhere in libfreshclam. That file is the only libfreshclam source that sets curl options.
- No `CURLOPT_HTTP_VERSION` is set. libcurl's default is therefore in effect, and this libcurl links `libnghttp2`, so **HTTP/2 over TLS (by ALPN) is possible**.
- **Result: HTTP/2 can be used, but no request is an upload.**

**`clamsubmit` (`clamsubmit/clamsubmit.c`), not run:**

- It **uploads**: `curl_formadd` at lines 478–529 (including `CURLFORM_FILE` at 529), then `CURLOPT_HTTPPOST` at 534 and 579.
- It **requests HTTP/1.1** on both of its handles (`CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1` at 290 and 465). The comment says this is "to prevent 2.0 responses which we don't yet parse properly".
- That request can fail. On failure the code only logs an error and continues, so HTTP/1.1 is what the code asks for, not a guarantee.
- **Result: it uploads, it asks for HTTP/1.1, and nothing on the appliance runs it.**

## What this shows, and what it does not

**Shown statically:**

- The process that runs and uses libcurl (freshclam) issues **no upload**. The advisory is stated for uploads.
- The only code that uploads (`clamsubmit`) is **not started** by the image or by the appliance. It also asks libcurl for HTTP/1.1. Reaching it would require executing a command inside the sidecar container, which is already privileged access to that container.

**Not shown:**

- **No runtime proof.** No trace or network capture was taken, and no lab was run.
- **"No upload" means no upload request type.** It does not exclude a curl-internal path that the advisory text does not describe. The upstream fix commit (`8b0744af`) was not reviewed.
- **freshclam's peer is the configured mirror** (`DatabaseMirror database.clamav.net` in the image's `/etc/clamav/freshclam.conf:92`, unless the operator changes it). That is a network peer, and a malicious or intercepted HTTP/2 server could send `RST_STREAM`. Whether a GET-only client can reach the faulty code depends on the "during an upload" condition holding as written.
- **The ClamAV binaries were not byte-compared** between the base and the shipped `culvert.3` image (see "What was inspected").
- **Other images were not checked.** The host and the app image were not part of this check.

**Owner options as raised earlier** (no recommendation here):

1. Pin `libcurl=8.23.0-r0` in `appliance/clamav/Dockerfile`. This yields a new sidecar identity and needs a fresh F-P2 proof and new BOM entries.
2. Record a bounded residual, using the evidence above.

**Outcome (27 Oct, user directive):** option 1 was taken. `libcurl=8.23.0-r0` is pinned in its own `apk add` (no `--upgrade`, so its dependencies do not float), under the new tag `culvert/clamav:1.5.4-culvert.4`. See the libcurl follow-up in `docs/appliance/r6-r7-security-dispositions.md`. F-P2 on the new bytes is still to run.
