# CS-412 Fuzzing Lab — SDL 1.2.15 with AFL++

Coverage-guided fuzzing of **SDL 1.2.15** with **AFL++**, targeting two
independent file-parsing surfaces:

1. **WAV / ADPCM decoding** (`audio/SDL_wave.c`) — main campaign.  
   Targets CVE-2019-7572 … CVE-2019-7578: heap over-reads and overflows in
   the MS-ADPCM and IMA-ADPCM decoders, triggered directly by
   `SDL_LoadWAV_RW`.

2. **BMP pixel-format conversion** (`video/SDL_bmp.c`, `SDL_pixels.c`) —
   secondary campaign.  
   Targets CVE-2019-7635 … CVE-2019-7638: heap over-reads and overflows in
   the BMP surface blit path, triggered by `SDL_LoadBMP_RW` +
   `SDL_BlitSurface`.

Both campaigns run in two modes:
- **Source-available (white-box):** SDL compiled with AFL++ instrumentation
  and AddressSanitizer.
- **Binary-only (black-box):** vanilla `gcc` build, fuzzed via AFL++ QEMU
  mode (`-Q`).

---

## Why SDL 1.2.15?

The initial libpng 1.2.56 campaign saturated after 2 hours (no new edges for
30 min, 0 crashes). The reachable attack surface for a standard PNG read
harness was exhausted at ~27 % edge coverage. SDL 1.2.15 was chosen because:

- **CVEs are directly in the decode path.** `SDL_LoadWAV_RW` calls
  `InitMS_ADPCM` / `MS_ADPCM_decode` / `InitIMA_ADPCM` / `IMA_ADPCM_decode`
  internally. No deep mutation budget is required to reach the buggy code —
  the ADPCM seed files put AFL in the right path on iteration 1.
- **No checksum to patch.** RIFF/WAV and BMP have no CRC that would cause the
  parser to reject mutated inputs before the interesting code runs.
- **Two independent surfaces.** WAV and BMP share no parser code, so both
  campaigns contribute distinct coverage.

See `NOTES.md` for the full target-choice rationale and the CVE inventory.

---

## Prerequisites

- **Docker** (Docker Desktop on macOS / Windows, or `docker` on Linux).
- ~2 GB free disk.
- ~5 minutes for the image build, 2+ hours per fuzzing campaign.

---

## Quick start

```bash
make build               # build the docker image (~3–5 min)
make sanity-wav          # smoke-test WAV harness — must print "exit=0"
make sanity-bmp          # smoke-test BMP harness — must print "exit=0"

make fuzz      TIME=7200  # 2-hour WAV instrumented campaign  → findings/
make fuzz-bmp  TIME=3600  # 1-hour BMP instrumented campaign  → findings-bmp/
make fuzz-qemu TIME=7200  # 2-hour WAV QEMU-mode campaign     → findings-qemu/

make plot                 # afl-plot from findings/            → plot_output/
make plot-qemu            # afl-plot from findings-qemu/       → plot_output_qemu/
```

`make help` lists every target.

For the **Q8 exec-speed comparison** (three configurations):

```bash
make fuzz-no-san     TIME=30   # config (1): no sanitizer + fork
make fuzz            TIME=30   # config (2): ASan + fork
make fuzz-persistent TIME=30   # config (3): ASan + persistent
```

---

## Repo layout

```
fuzzing/
├── Dockerfile                  image recipe
│                                 - SDL 1.2.15 built three ways
│                                   (instrumented+ASan / instrumented / vanilla)
│                                 - five harness binaries
├── Makefile                    host wrapper (make build / fuzz / plot / clean)
├── README.md                   this file
├── NOTES.md                    target choice, CVE inventory, harness design
├── RUNBOOK.md                  step-by-step commands for each phase
├── REPORT_DRAFTS.md            draft prose for Q1–Q8 (→ LaTeX)
│
├── src/
│   ├── harness_wav.c           WAV fork-mode harness — main campaign
│   ├── harness_bmp.c           BMP fork-mode harness — secondary campaign
│   └── harness_wav_persistent.c  persistent-mode WAV harness for Q8
│
├── seeds/
│   ├── wav/                    3 WAV seeds (PCM, MS-ADPCM, IMA-ADPCM)
│   ├── bmp/                    5 BMP seeds (1/4/8/24/32 bpp)
│   └── make_seeds.py           seed generator
│
├── sdl.dict                    custom dictionary (RIFF/WAV tags + BMP tokens)
│
├── findings/                   WAV instrumented campaign output  (gitignored)
├── findings-bmp/               BMP instrumented campaign output  (gitignored)
├── findings-qemu/              WAV QEMU campaign output          (gitignored)
├── plot_output/                afl-plot for WAV instrumented run (gitignored)
└── plot_output_qemu/           afl-plot for WAV QEMU run         (gitignored)
```

---

## Mental model — what each piece does

- **The harness** (`src/harness_wav.c`) calls `SDL_LoadWAV_RW` on AFL++'s
  mutated input file. SDL parses the RIFF container, reads the `fmt ` chunk to
  determine the codec (PCM / MS-ADPCM / IMA-ADPCM), then decodes the audio
  data. The harness is the *driver* that bridges AFL++ and the library.
- **AFL++** mutates bytes in the input, runs the harness, and watches which
  code edges in SDL get exercised. Inputs that hit new edges are kept as
  corpus seeds for further mutation.
- **AddressSanitizer** turns silent heap overflows (the ADPCM CVEs write past
  allocated buffers by a few bytes — no segfault without ASan) into immediate
  aborts with a full stack trace.
- **The dictionary** (`sdl.dict`) contains RIFF chunk tags and WAV format
  codes. The 2-byte format code (`\x02\x00` = MS-ADPCM, `\x11\x00` =
  IMA-ADPCM) gates which decoder runs. Without the dictionary, AFL++ would
  need to guess these values by chance (1-in-65536 per mutation).
- **The ADPCM seeds** are the most critical corpus items. They immediately
  place AFL++ in the ADPCM decode paths where the CVEs live, rather than
  spending the entire campaign exploring only PCM code.

---

## Evidence map

| # | Topic | Evidence |
|---|---|---|
| Q1 | Harness design | `src/harness_wav.c`; `NOTES.md` § Harness design |
| Q2 | Instrumentation & sanitizers | `Dockerfile` (every CFLAG/LDFLAG); `NOTES.md` § SDL configure |
| Q3 | Seeds and dictionary | `seeds/wav/`, `seeds/bmp/`, `sdl.dict`; AFL++ status screen strategy yields |
| Q4 | Campaign analysis | `findings/default/fuzzer_stats`, `plot_output/edges.png` |
| Q5 | Crash triage | `findings/default/crashes/`; ASan stack trace; `afl-tmin` output |
| Q6 | Attack surface | `REPORT_DRAFTS.md` § Q6 |
| Q7 | QEMU comparison | `findings-qemu/default/fuzzer_stats`, `plot_output_qemu/` |
| Q8 | Depth & performance | `findings-persistent/`, `findings-no-san/`; `AFL_DEBUG=1` edge counts |

---

## Background reading

- AFL++ documentation: <https://aflplus.plus/docs/>
- SDL 1.2.15 source: <https://www.libsdl.org/release/SDL-1.2.15.tar.gz>
- CVE-2019-7575 (MS-ADPCM heap overflow): <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7575>
- AddressSanitizer paper: Serebryany et al., USENIX ATC 2012
