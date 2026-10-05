"""Exact 8x16 console glyph decoding, with no OCR corrections or fuzzy matches.

The optional font is Ubuntu console-setup-linux 1.226ubuntu1.1's decompressed
Uni2-Fixed16.psf.gz or Ethiopian-Goha16.psf.gz. A path-list may include both.
A capture must have one globally consistent font; mixed fonts and ambiguous
character mappings remain unknown. Each font is a controller dependency, never guest content.
Unknown/ambiguous cells stay U+FFFD so credentials cannot be inferred.
"""
import hashlib
import os
from pathlib import Path
from PIL import Image

FONT_SHA256 = 'd9025175dcf18f8b7442009a1870837f6ae974fa9561e9d8dae5eb145566fee7'

GOHA_FONT_SHA256 = '1b8ee210c00ee77a3781c1c10fa0d00520ec4b0bc4f30018e4f656e8049605bb'


def font_table(font_path):
    data = Path(font_path).read_bytes()
    if (hashlib.sha256(data).hexdigest() not in {FONT_SHA256, GOHA_FONT_SHA256}
            or len(data) < 4 + 256 * 16 or data[:2] != b'\x36\x04' or data[3] != 16):
        raise ValueError('pinned console font identity mismatch')
    table = {}
    for code in range(32, 127):
        glyph = data[4 + code * 16:4 + (code + 1) * 16]
        table[glyph] = chr(code) if glyph not in table else '\ufffd'
    return table


def decode(image_path, font_path):
    paths = str(font_path).split(os.pathsep)
    if not 1 <= len(paths) <= 2 or any(not path for path in paths):
        raise ValueError('one or two pinned console fonts required')
    tables = [font_table(path) for path in paths]
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
                    row.append(None)
                    continue
                glyph = bytes(sum(1 << (7-i) for i in range(8)
                                  if pixels.getpixel((x+i, y+j)) != background) for j in range(16))
                row.append(glyph)
            rows.append(row)
        # Every glyph recognized by any configured font must fit one global
        # font. Never assemble a credential from different fonts cell by cell.
        recognized = {cell for row in rows for cell in row
                      if cell is not None and any(cell in table for table in tables)}
        candidates = [table for table in tables if recognized <= table.keys()]
        result = []
        for row in rows:
            text = []
            for cell in row:
                meanings = {table.get(cell, '\ufffd') for table in candidates}
                text.append(next(iter(meanings)) if len(meanings) == 1 else '\ufffd')
            result.append(''.join(text).rstrip())
        return '\n'.join(result)
