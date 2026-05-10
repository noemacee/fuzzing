# NOTES — decision log

---

## Target choice

**SDL 1.2.15**, the last stable release of the SDL 1.2 series.

### Why SDL 1.2.15

The initial campaign targeted **libpng 1.2.56** for 2 hours. The run
reached ~27 % edge coverage and then went 30 minutes without discovering a
new path — genuine saturation of the surface reachable from a standard
`png_read_info → png_read_image` harness. Zero crashes were found.

SDL 1.2.15 was chosen as the replacement for the following reasons:

1. **Directly reachable CVEs in the WAV decode path.**  
   CVE-2019-7572 through CVE-2019-7578 are all in `audio/SDL_wave.c`
   (`InitMS_ADPCM`, `MS_ADPCM_decode`, `InitIMA_ADPCM`, `IMA_ADPCM_decode`).
   These functions are called *by `SDL_LoadWAV_RW` itself*, so the harness
   reaches them on the very first valid ADPCM seed — no deep mutation budget
   required. By contrast, the libpng CVEs were gated behind chunk-handler
   paths the fuzzer never reached in 2 hours.

2. **No checksum patch required.**  
   RIFF/WAV and BMP have no CRC that would cause the parser to reject
   mutated inputs before reaching the interesting code. The libpng-nocrc.patch
   was necessary for libpng; nothing analogous is needed here.

3. **Two independent attack surfaces.**  
   WAV ADPCM decoding (`SDL_wave.c`) and BMP pixel-format conversion
   (`SDL_bmp.c` / `SDL_pixels.c`) are completely separate code paths. We run
   two campaigns with separate seed corpora and harnesses.

4. **AFL++ arithmetic mutations align with the bug class.**  
   The ADPCM CVEs are integer overflows driven by attacker-controlled
   `nBlockAlign`, `wSamplesPerBlock`, and channel-count fields. AFL++'s
   arithmetic mutation stage (increment/decrement bytes/words) is specifically
   good at finding this class of bug.

5. **Lab PDF endorses older versions with known CVEs.**  
   Section 2: *"Using an older version with known CVEs is acceptable and even
   encouraged."* SDL 1.2.15 fits this guidance precisely.

### CVE inventory

| CVE | Location | Bug class | Trigger |
|---|---|---|---|
| CVE-2019-7572 | `InitIMA_ADPCM` | heap over-read | IMA-ADPCM WAV with crafted `nBlockAlign` |
| CVE-2019-7573 | `InitMS_ADPCM` | heap over-read | MS-ADPCM WAV with crafted block header |
| CVE-2019-7574 | `IMA_ADPCM_decode` | heap over-read | IMA-ADPCM decode loop bounds |
| CVE-2019-7575 | `MS_ADPCM_decode` | heap overflow | MS-ADPCM decode loop overrun |
| CVE-2019-7576 | `InitMS_ADPCM` | heap over-read | MS-ADPCM predictor table read |
| CVE-2019-7578 | `InitIMA_ADPCM` | heap over-read | IMA-ADPCM header read |
| CVE-2019-7635 | `Blit1to4` | heap over-read | BMP → 32-bit surface blit |
| CVE-2019-7636 | `SDL_GetRGB` | heap over-read | palette-indexed BMP colour lookup |
| CVE-2019-7637 | `SDL_FillRect` | heap overflow | BMP surface initialisation |
| CVE-2019-7638 | `Map1toN` | heap over-read | BMP pixel-format map construction |

---

## Architecture

Host is **Apple Silicon (arm64)**. The `aflplusplus/aflplusplus` image is
multi-arch; the Dockerfile does not pin a platform. SDL_VIDEODRIVER=dummy and
SDL_AUDIODRIVER=dummy are set in the container ENV so that `SDL_Init` succeeds
in the headless Docker environment without a display or audio device.

---

## Harness design

### WAV harness (`src/harness_wav.c`) — main campaign

Entry-point sequence:
```
SDL_Init(0)
SDL_RWFromFile(argv[1], "rb")
SDL_LoadWAV_RW(rw, freesrc=1, &spec, &buf, &len)
SDL_FreeWAV(buf)
SDL_Quit()
```

Key design choices:
- **No `setjmp` needed.** SDL signals errors via return value (NULL), not
  `longjmp`. Malformed inputs are silently rejected; only real memory bugs
  (caught by ASan) produce a non-zero exit that AFL records as a crash.
- **`SDL_Init(0)`** initialises SDL's internal allocator and error-string
  tables without starting video or audio output subsystems. `SDL_LoadWAV_RW`
  is a pure file-parsing function that does not require either subsystem.
- **`freesrc=1`** delegates SDL_RWclose to SDL, preventing a double-free on
  both the success and error paths.

### BMP harness (`src/harness_bmp.c`) — secondary campaign

Entry-point sequence:
```
SDL_Init(SDL_INIT_VIDEO)   ← SDL_VIDEODRIVER=dummy in ENV
SDL_RWFromFile(argv[1], "rb")
SDL_LoadBMP_RW(rw, freesrc=1)
SDL_CreateRGBSurface(32-bit ARGB)
SDL_BlitSurface(src, NULL, dst, NULL)
SDL_FreeSurface × 2
SDL_Quit()
```

The `SDL_BlitSurface` step is required to exercise the pixel-format
conversion code (`Blit1to4`, `Map1toN`, `SDL_GetRGB`) where most BMP CVEs
live. Loading alone does not reach those paths.

### Persistent harness (`src/harness_wav_persistent.c`) — Q8

Uses `SDL_RWFromMem` to wrap AFL++'s shared-memory buffer directly, avoiding
file I/O overhead in the inner loop. `__AFL_LOOP(10000)` keeps the process
alive for 10,000 iterations before allowing a re-fork to avoid state drift.

---

## Seeds

| File | Format | Purpose |
|---|---|---|
| `seeds/wav/pcm_s16le.wav` | PCM 0x0001 | Baseline RIFF parser coverage |
| `seeds/wav/ms_adpcm.wav` | MS-ADPCM 0x0002 | Reaches CVE-2019-7573/7575/7576 immediately |
| `seeds/wav/ima_adpcm.wav` | IMA-ADPCM 0x0011 | Reaches CVE-2019-7572/7574/7578 immediately |
| `seeds/bmp/mono_1bpp.bmp` | 1 bpp palette | Exercises 1-bit palette path |
| `seeds/bmp/indexed_4bpp.bmp` | 4 bpp palette | Exercises `Blit1to4` path |
| `seeds/bmp/indexed_8bpp.bmp` | 8 bpp palette | Exercises `Map1toN` / `SDL_GetRGB` |
| `seeds/bmp/rgb24.bmp` | 24 bpp | Exercises direct RGB copy |
| `seeds/bmp/rgb32.bmp` | 32 bpp | Exercises 4-byte-per-pixel path |

The ADPCM seeds are the most critical: they immediately place AFL in the
ADPCM decode code paths where the CVEs live. Without them, AFL would only
see PCM WAVs (format code 0x0001) and never reach `MS_ADPCM_decode` or
`IMA_ADPCM_decode` via random mutation (each 2-byte format code is 1-in-65536
by chance).

---

## Dictionary (`sdl.dict`)

Custom dictionary (AFL++ does not ship one for WAV/BMP). Contains:
- RIFF chunk-type tags: `RIFF`, `WAVE`, `fmt `, `data`, `fact`, `LIST`, …
- WAV format codes: `\x01\x00` (PCM), `\x02\x00` (MS-ADPCM), `\x11\x00` (IMA-ADPCM)
- BMP magic bytes and compression codes

---

## Issues encountered

### SDL configure fails on audio backend detection

The AFL++ Docker image (Ubuntu) does not have ALSA/OSS/ESD headers. The
`./configure` script auto-detects and disables unavailable backends, so no
explicit `--disable-*` flags are strictly required for audio output. The ENV
`SDL_AUDIODRIVER=dummy` ensures runtime fallback regardless.

To be explicit and reproducible, `SDL_CFG` in the Dockerfile enumerates the
disable flags for every platform display and audio backend we know about.
