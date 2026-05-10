#!/usr/bin/env python3
"""Generate minimal seed corpus for SDL 1.2.15 WAV and BMP fuzzing.

WAV seeds cover three format codes that map to distinct SDL decode paths:
  - PCM (0x0001)        : baseline, exercises the RIFF parser and sample copy
  - MS-ADPCM (0x0002)   : exercises InitMS_ADPCM + MS_ADPCM_decode (CVE-2019-7575)
  - IMA-ADPCM (0x0011)  : exercises InitIMA_ADPCM + IMA_ADPCM_decode (CVE-2019-7572..7578)

BMP seeds cover four bit-depths, which map to different SDL colour-conversion
paths (1/4/8 bpp use a palette; 24 bpp is direct RGB; 32 bpp adds a fourth
channel that exercises different blitting code):
  1bpp  palette (2 colours)
  4bpp  palette (16 colours)
  8bpp  palette (256 colours)
  24bpp truecolour
  32bpp truecolour + alpha / padding

All files are kept as small as possible (single pixel / single sample block)
so AFL++ calibration is fast and the seeds contribute tight coverage.
"""

import struct
import os

HERE = os.path.dirname(os.path.abspath(__file__))
WAV_DIR = os.path.join(HERE, "wav")
BMP_DIR = os.path.join(HERE, "bmp")
os.makedirs(WAV_DIR, exist_ok=True)
os.makedirs(BMP_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# WAV helpers
# ---------------------------------------------------------------------------

def riff_wrap(payload: bytes) -> bytes:
    return b"RIFF" + struct.pack("<I", 4 + len(payload)) + b"WAVE" + payload


def chunk(tag: bytes, data: bytes) -> bytes:
    assert len(tag) == 4
    return tag + struct.pack("<I", len(data)) + data


def pcm_wav(channels=1, rate=8000, bits=16, n_samples=8) -> bytes:
    block_align = channels * bits // 8
    fmt = struct.pack("<HHIIHH",
        0x0001, channels, rate,
        rate * block_align, block_align, bits)
    samples = bytes(n_samples * block_align)
    return riff_wrap(chunk(b"fmt ", fmt) + chunk(b"data", samples))


def ms_adpcm_wav(channels=1, rate=8000) -> bytes:
    """Minimal MS-ADPCM WAV (format 0x0002).
    Standard 7 predictor-coefficient pairs embedded; block_align=512.
    """
    block_align = 512
    samples_per_block = (block_align - channels * 7) * 2 // channels + 2

    coeffs = [(256, 0), (512, -256), (0, 0), (192, 64),
              (240, 0), (460, -208), (392, -232)]
    coeff_bytes = b"".join(struct.pack("<hh", c1, c2) for c1, c2 in coeffs)

    fmt = struct.pack("<HHIIHHHh",
        0x0002, channels, rate,
        rate * block_align // samples_per_block,
        block_align, 4,
        4 + len(coeff_bytes),
        len(coeffs))
    fmt += coeff_bytes

    fact = struct.pack("<I", samples_per_block)
    block = bytes(block_align)
    return riff_wrap(chunk(b"fmt ", fmt) + chunk(b"fact", fact) +
                     chunk(b"data", block))


def ima_adpcm_wav(channels=1, rate=8000) -> bytes:
    """Minimal IMA-ADPCM WAV (format 0x0011).
    Block header: 2-byte predictor + 1-byte step index + 1-byte pad per channel.
    """
    block_align = 512
    samples_per_block = (block_align - channels * 4) * 2 // channels + 1

    fmt = struct.pack("<HHIIHHHh",
        0x0011, channels, rate,
        rate * block_align // samples_per_block,
        block_align, 4,
        2, samples_per_block)

    fact = struct.pack("<I", samples_per_block)
    block = bytes(block_align)
    return riff_wrap(chunk(b"fmt ", fmt) + chunk(b"fact", fact) +
                     chunk(b"data", block))


# ---------------------------------------------------------------------------
# BMP helpers
# ---------------------------------------------------------------------------

def bmp_file_header(file_size: int, data_offset: int) -> bytes:
    return b"BM" + struct.pack("<IHH I", file_size, 0, 0, data_offset)


def bmp_info_header(width, height, bpp, compression=0,
                    clr_used=0, clr_important=0) -> bytes:
    return struct.pack("<IiiHHIIiiII",
        40, width, height, 1, bpp, compression, 0,
        2835, 2835, clr_used, clr_important)


def palette(n_colors: int) -> bytes:
    entry = struct.pack("<BBBB", 0xFF, 0xFF, 0xFF, 0x00)
    return b"\x00\x00\x00\x00" + entry * (n_colors - 1)


def row_bytes(width: int, bpp: int) -> int:
    return ((width * bpp + 31) // 32) * 4


def bmp_1bpp(width=8, height=1) -> bytes:
    pal = palette(2)
    stride = row_bytes(width, 1)
    pixels = bytes(stride * height)
    data_off = 14 + 40 + len(pal)
    return (bmp_file_header(data_off + len(pixels), data_off) +
            bmp_info_header(width, height, 1, clr_used=2) + pal + pixels)


def bmp_4bpp(width=4, height=1) -> bytes:
    pal = palette(16)
    stride = row_bytes(width, 4)
    pixels = bytes(stride * height)
    data_off = 14 + 40 + len(pal)
    return (bmp_file_header(data_off + len(pixels), data_off) +
            bmp_info_header(width, height, 4, clr_used=16) + pal + pixels)


def bmp_8bpp(width=4, height=4) -> bytes:
    pal = palette(256)
    stride = row_bytes(width, 8)
    pixels = bytes(stride * height)
    data_off = 14 + 40 + len(pal)
    return (bmp_file_header(data_off + len(pixels), data_off) +
            bmp_info_header(width, height, 8, clr_used=256) + pal + pixels)


def bmp_24bpp(width=4, height=4) -> bytes:
    stride = row_bytes(width, 24)
    pixels = bytes(stride * height)
    data_off = 14 + 40
    return (bmp_file_header(data_off + len(pixels), data_off) +
            bmp_info_header(width, height, 24) + pixels)


def bmp_32bpp(width=4, height=4) -> bytes:
    stride = row_bytes(width, 32)
    pixels = bytes(stride * height)
    data_off = 14 + 40
    return (bmp_file_header(data_off + len(pixels), data_off) +
            bmp_info_header(width, height, 32) + pixels)


# ---------------------------------------------------------------------------
# Write seeds
# ---------------------------------------------------------------------------

def write(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)
    print(f"  {path} ({len(data)} bytes)")


print("WAV seeds:")
write(os.path.join(WAV_DIR, "pcm_s16le.wav"),    pcm_wav())
write(os.path.join(WAV_DIR, "ms_adpcm.wav"),     ms_adpcm_wav())
write(os.path.join(WAV_DIR, "ima_adpcm.wav"),    ima_adpcm_wav())

print("BMP seeds:")
write(os.path.join(BMP_DIR, "mono_1bpp.bmp"),    bmp_1bpp())
write(os.path.join(BMP_DIR, "indexed_4bpp.bmp"), bmp_4bpp())
write(os.path.join(BMP_DIR, "indexed_8bpp.bmp"), bmp_8bpp())
write(os.path.join(BMP_DIR, "rgb24.bmp"),         bmp_24bpp())
write(os.path.join(BMP_DIR, "rgb32.bmp"),         bmp_32bpp())
