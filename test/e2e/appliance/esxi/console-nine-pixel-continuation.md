# Exact nine-pixel console observation

The cd8 cold-boot capture `frame-0024.png` is 720x400, an 80x25 console
with 9x16 cells. SHA256:
`f07e308a5e2b665f38677763a4ec198b5ea5750f92cf2249e9ba12a9478991df`.
Offline inspection found 635 nonblank and 1,365 blank cells, all matching
the existing pinned Uni2-Fixed16 font exactly at nine-pixel pitch. Every
ninth column was blank. No new font, character inference or image resizing
is required. The 8x16 VGA/kernel font candidates did not match these glyphs.
The corrected decoder yielded zero unknown cells and a valid credential
parse in memory; no credential text was printed or copied into this report.

Font pins remain unchanged:

- Uni2-Fixed16: `d9025175dcf18f8b7442009a1870837f6ae974fa9561e9d8dae5eb145566fee7`
- Ethiopian-Goha16: `1b8ee210c00ee77a3781c1c10fa0d00520ec4b0bc4f30018e4f656e8049605bb`

Set `"console_cell_width": 9` in the new frozen continuation scope, pointing
to the **same original run directory and owned VM**. Existing scopes default
to eight. Geometry is explicit and validated; it is never selected by font
scoring. Nine-pixel ASCII requires a blank ninth column; ink, overlays or
uncertainty there produce U+FFFD. The original single-global-font and
ambiguous-character refusals remain. Both default bootstrap and privileged
console observation use the same scope-bound decoder call. At width nine,
the pinned font path-list is required; there is no fallback to generic OCR.

Let the original 900-second observation finish and preserve its blocked
`initial-capture` marker and all screenshots. Verify no authentication or
credential-file creation occurred. Then the existing explicit
`--resume-initial-observation --initial-timeout 900` command may run once,
using the new scope/controller. It requires the same UUID, blocked
pre-authentication stage, absent bootstrap password and absent continuation
marker, and records a separate exclusive extension with original marker
hashes, unchanged keyboard source hash, decoder hash and selected width.
No resume is permitted for started, authenticated or ambiguous attempts.

Keep the original `91fd17fb` controller/scope and preflight unchanged for
passive screenshots and reviewed key probes. The geometry continuation does
not reimport, rerun preflight, alter the appliance or replace the prior
evidence. Report both controller revisions and the initial observation
failure. A subsequent incompatible display geometry must stop exact
decoding; it must not trigger guessed rescaling or credential repair.
