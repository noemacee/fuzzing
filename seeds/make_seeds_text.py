#!/usr/bin/env python3
"""
Seeds for png_fuzz_text (CVE-2016-10087 harness).

These PNGs have no text chunks (tEXt/zTXt/iTXt) so AFL can calibrate them
without crashing.  Each seed contains a tRNS chunk between IHDR and IDAT.

tRNS is the best mutation target for AFL because:
  - "tRNS" = 74 52 4E 53
  - "tEXt" = 74 45 58 74
  - First byte is identical; only 3 bytes need to change.
  - When AFL replaces "tRNS" with "tEXt", libpng processes the tRNS data as a
    text chunk (CRC ignored via nocrc patch), png_set_text_2 is called, and
    max_text becomes 9.  png_read_info then finds IDAT and completes normally.
    The trigger sequence (png_free_data + png_set_text) then fires the crash.
"""
import struct
import zlib
import os

def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack('>I', len(data)) + chunk_type + data + struct.pack('>I', crc)

PNG_SIG = b'\x89PNG\r\n\x1a\n'

out_dir = os.path.dirname(os.path.abspath(__file__))

# Seed 1: 1x1 8-bit grayscale with tRNS (2 bytes: 16-bit transparent level)
# tRNS data = [0x00, 0x80] — first byte null, which already acts as an empty
# key when AFL mutates the chunk type to tEXt.
ihdr_gray = struct.pack('>IIBBBBB', 1, 1, 8, 0, 0, 0, 0)
trns_gray = struct.pack('>H', 0x0080)
idat_gray = zlib.compress(b'\x00\x80')
png1 = (PNG_SIG
        + make_chunk(b'IHDR', ihdr_gray)
        + make_chunk(b'tRNS', trns_gray)
        + make_chunk(b'IDAT', idat_gray)
        + make_chunk(b'IEND', b''))
with open(os.path.join(out_dir, 'gray_trns.png'), 'wb') as f:
    f.write(png1)
print(f'gray_trns.png  {len(png1)} bytes')

# Seed 2: 1x1 8-bit RGB with tRNS (6 bytes: three 16-bit RGB transparent color)
# tRNS data = [0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF] — starts with null byte.
ihdr_rgb = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
trns_rgb  = struct.pack('>HHH', 0x00FF, 0x00FF, 0x00FF)
idat_rgb  = zlib.compress(b'\x00\xFF\x00\xFF')
png2 = (PNG_SIG
        + make_chunk(b'IHDR', ihdr_rgb)
        + make_chunk(b'tRNS', trns_rgb)
        + make_chunk(b'IDAT', idat_rgb)
        + make_chunk(b'IEND', b''))
with open(os.path.join(out_dir, 'rgb_trns.png'), 'wb') as f:
    f.write(png2)
print(f'rgb_trns.png   {len(png2)} bytes')

# Seed 3: 1x1 indexed (palette) with tRNS (1 byte: alpha for palette entry 0)
# tRNS data = [0x00] — single null byte.  When mutated to tEXt: key="", text="".
ihdr_pal  = struct.pack('>IIBBBBB', 1, 1, 8, 3, 0, 0, 0)
plte_pal  = b'\xFF\x00\x00' + b'\x00\xFF\x00'  # 2-entry palette
trns_pal  = b'\x00'  # palette entry 0 is transparent
idat_pal  = zlib.compress(b'\x00\x00')
png3 = (PNG_SIG
        + make_chunk(b'IHDR', ihdr_pal)
        + make_chunk(b'PLTE', plte_pal)
        + make_chunk(b'tRNS', trns_pal)
        + make_chunk(b'IDAT', idat_pal)
        + make_chunk(b'IEND', b''))
with open(os.path.join(out_dir, 'palette_trns.png'), 'wb') as f:
    f.write(png3)
print(f'palette_trns.png {len(png3)} bytes')

print('done — no text chunks, safe for AFL calibration')
