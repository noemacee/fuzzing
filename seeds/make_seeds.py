#!/usr/bin/env python3
"""Generate a small set of valid PNGs covering different color types
and bit depths. Run from the repo root: python3 seeds/make_seeds.py
"""
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SIG  = b'\x89PNG\r\n\x1a\n'


def _chunk(name, data):
    crc = zlib.crc32(name + data) & 0xffffffff
    return struct.pack(">I", len(data)) + name + data + struct.pack(">I", crc)


def write_png(path, w, h, color_type, bit_depth, rows, palette=None):
    ihdr = struct.pack(">IIBBBBB", w, h, bit_depth, color_type, 0, 0, 0)
    parts = [SIG, _chunk(b'IHDR', ihdr)]
    if palette is not None:
        parts.append(_chunk(b'PLTE', palette))
    raw = b''.join(b'\x00' + r for r in rows)
    parts.append(_chunk(b'IDAT', zlib.compress(raw, 9)))
    parts.append(_chunk(b'IEND', b''))
    with open(os.path.join(HERE, path), 'wb') as f:
        for p in parts:
            f.write(p)


# 8x8 grayscale, 8-bit
gray8 = [bytes((i * 32 + j * 4) % 256 for j in range(8)) for i in range(8)]
write_png('grayscale.png', 8, 8, 0, 8, gray8)

# 8x8 RGB, 8-bit
rgb = []
for i in range(8):
    row = bytearray()
    for j in range(8):
        row += bytes((i * 30 % 256, j * 30 % 256, 128))
    rgb.append(bytes(row))
write_png('rgb.png', 8, 8, 2, 8, rgb)

# 4x4 palette
palette = bytes((255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0))
write_png('palette.png', 4, 4, 3, 8, [bytes((0, 1, 2, 3))] * 4, palette=palette)

# 4x4 RGBA, 8-bit
rgba = []
for i in range(4):
    row = bytearray()
    for j in range(4):
        row += bytes((255 - i * 60, j * 60, 64, 200))
    rgba.append(bytes(row))
write_png('rgba.png', 4, 4, 6, 8, rgba)

# 8x8 grayscale, 1-bit  -> exercises png_set_expand
g1 = []
for i in range(8):
    v = 0
    for j in range(8):
        if (i + j) & 1:
            v |= 1 << (7 - j)
    g1.append(bytes((v,)))
write_png('gray_1bit.png', 8, 8, 0, 1, g1)

# 4x4 grayscale, 16-bit -> exercises png_set_strip_16
g16 = []
for i in range(4):
    row = bytearray()
    for j in range(4):
        row += struct.pack(">H", (i * 4 + j) * 4096)
    g16.append(bytes(row))
write_png('gray_16bit.png', 4, 4, 0, 16, g16)

print("wrote 6 seeds to", HERE)
