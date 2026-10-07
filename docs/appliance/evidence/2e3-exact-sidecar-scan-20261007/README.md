# Exact baked ClamAV scan — independent binding review

The earlier scan-to-deliverable gap is closed for OVA `55e98116…`.
Artifact11482536911 from [run37622491925](https://github.com/KidCarmi/Culvert/actions/runs/37622491925)
scanned the retained archive, without rebuilding. Config `098ca807…`, all8 layer
digests and rootfs DiffIDs match the authenticated ESXi guest metadata. The
CycloneDX SBOM contains42 components. `review.json` records the full identities.

The configured fixable HIGH/CRITICAL gate passes. The full JSON retains two
fixable findings; this is not a zero-vulnerability result. PCRE2 10.49-r0 is present.

The nghttp2 finding concerns the nghttpx proxy, absent from the inspected image;
the [upstream change](https://github.com/nghttp2/nghttp2/commit/ab28105c4a0197da24f8bfc414bc116055249e1e)
changes proxy code. The [zlib advisory](https://www.vulncheck.com/advisories/zlib-1.3.1.2-through-1.3.2-heap-buffer-overflow-via-gz-vacate)
requires a stalled nonblocking write followed by gzprintf/gzvprintf. Recorded
inspection finds no dynamic imports of those entry points among59 ELF files.
That supports a bounded applicability argument; it does not prove absence of
static or dynamically resolved calls. Final scoped zlib disposition remains
requested from Opus. No finding was dismissed or accepted by default.

The zlib scanner severity is MEDIUM; the CNA rates it HIGH. Both facts remain
explicit. Only linux/amd64 was scanned. See the full report, scan settings,
database timestamp, reachability output and SHA256SUMS in this directory.

Opus has confirmed the focused package upgrades and a new sidecar tag are being
implemented under the existing authorization. A replacement candidate follows;
the completed2e3 qualification does not transfer to its changed bytes.
