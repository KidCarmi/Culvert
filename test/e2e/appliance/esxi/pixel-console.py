"""Exact 8x16 console glyph decoding, with no OCR corrections or fuzzy matches.

The optional font is Ubuntu console-setup-linux 1.226ubuntu1.1's decompressed
Uni2-Fixed16.psf.gz. It is a controller dependency, never guest content.
Unknown/ambiguous cells stay U+FFFD so credentials cannot be inferred.
"""
import hashlib
from pathlib import Path
from PIL import Image

FONT_SHA256 = 'd9025175dcf18f8b7442009a1870837f6ae974fa9561e9d8dae5eb145566fee7'


def decode(image_path, font_path):
    data = Path(font_path).read_bytes()
    if hashlib.sha256(data).hexdigest() != FONT_SHA256 or data[:2] != b'\x36\x04' or data[3] != 16:
        raise ValueError('pinned console font identity mismatch')
    table = {}
    for code in range(32, 127):
        glyph = data[4 + code * 16:4 + (code + 1) * 16]
        table[glyph] = chr(code) if glyph not in table else '\ufffd'
    with Image.open(image_path) as original:
        if original.width > 4096 or original.height > 4096 or original.width * original.height > 16777216:
            raise ValueError('console image exceeds bounds')
        if original.width % 8 or original.height % 16:
            raise ValueError('console image contains partial glyph cells')
        pixels = original.convert('RGB')
        background = pixels.getpixel((0, 0))
        if background not in {(0, 0, 0), (1, 1, 1)}:
            raise ValueError('console background is not the expected black')
        rows = []
        for y in range(0, pixels.height - 15, 16):
            row = []
            for x in range(0, pixels.width - 7, 8):
                colors = {pixels.getpixel((x+i, y+j)) for j in range(16) for i in range(8)}
                # Standard console glyphs are one flat foreground on black.
                # Antialiasing, inversion or overlays are not interpreted.
                foreground = colors - {background}
                if len(foreground) > 1:
                    row.append('\ufffd')
                    continue
                glyph = bytes(sum(1 << (7-i) for i in range(8)
                                  if pixels.getpixel((x+i, y+j)) != background) for j in range(16))
                row.append(table.get(glyph, '\ufffd'))
            rows.append(''.join(row).rstrip())
        return '\n'.join(rows)
