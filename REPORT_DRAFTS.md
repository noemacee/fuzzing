# Report drafts — SDL 1.2.15 fuzzing lab

Draft prose for Q1–Q8. Numbers in [brackets] are placeholders to fill in
from actual campaign runs. Port to USENIX LaTeX for the final submission.

---

## Q1 — Harness design

> **WAV harness (`src/harness_wav.c`).** The harness drives SDL's WAV decode
> pipeline against a single input file passed by AFL++ via the `@@`
> placeholder. The entry-point sequence is: `SDL_Init(0)` →
> `SDL_RWFromFile(argv[1], "rb")` → `SDL_LoadWAV_RW(rw, 1, &spec, &buf,
> &len)` → `SDL_FreeWAV(buf)` → `SDL_Quit()`.
>
> We chose this surface for three reasons.
>
> First, **WAV parsing over encoding.** The realistic threat model is an
> attacker who supplies a crafted audio file to a player or SDK that calls
> `SDL_LoadWAV`. Encoding (SDL has no WAV encoder) is not a relevant attack
> vector.
>
> Second, **`SDL_LoadWAV_RW` covers all three codec paths in one call.**
> Depending on the `wFormatTag` field in the `fmt ` chunk, SDL dispatches to
> `InitMS_ADPCM` + `MS_ADPCM_decode` (format 0x0002) or `InitIMA_ADPCM` +
> `IMA_ADPCM_decode` (format 0x0011) or the simple PCM copy. All three paths
> are reachable from our single harness entry point, gated only by a 2-byte
> format code that the dictionary provides immediately.
>
> Third, **no `setjmp` needed.** SDL signals errors via return value (NULL),
> not `longjmp`. Malformed inputs that SDL cannot parse are silently rejected
> with a NULL return; only genuine memory-safety bugs — caught by
> AddressSanitizer — cause a non-zero process exit that AFL++ records as a
> crash. This avoids the false-positive flood that the libpng harness had to
> defend against with `setjmp`.
>
> **Design choices justified:**
>
> | Choice | Justification |
> |---|---|
> | `SDL_Init(0)` — no subsystems | `SDL_LoadWAV_RW` is a pure file-parsing function; no audio output device is needed. Requesting no subsystems avoids the `SDL_AUDIODRIVER=dummy` fallback path being exercised at init rather than during parsing. |
> | `freesrc=1` | SDL calls `SDL_RWclose` on the `SDL_RWops` after parsing (success or error), so we do not need to close it separately. Without `freesrc=1` we would need error-path cleanup code that mirrors what SDL already does. |
> | No dimension / size guard | SDL's ADPCM decoders do their own size validation; any OOM from a crafted large `nBlockAlign` is an SDL bug, not a fuzzing false positive. We do not guard against it. |
>
> **BMP harness (`src/harness_bmp.c`).** Secondary campaign. Entry-point:
> `SDL_Init(SDL_INIT_VIDEO)` (using `SDL_VIDEODRIVER=dummy`) →
> `SDL_LoadBMP_RW(rw, 1)` → `SDL_CreateRGBSurface(32-bit ARGB)` →
> `SDL_BlitSurface(src, NULL, dst, NULL)`. The `SDL_BlitSurface` step is
> required to exercise the pixel-format conversion code (`Blit1to4`,
> `Map1toN`, `SDL_GetRGB`) where CVE-2019-7635 … CVE-2019-7638 live.
> Loading alone does not reach those paths.

---

## Q2 — Instrumentation and sanitizers

> **Build flags and their purpose:**
>
> | Flag / setting | What it does | Effect of omitting |
> |---|---|---|
> | `CC=afl-clang-fast` | Injects a PC-guard probe at every basic-block entry. Probes feed AFL++'s coverage bitmap. | Without compile-time instrumentation, AFL++ degenerates to blind random fuzzing — equivalent to QEMU mode but without QEMU's systematic BB-level tracking. |
> | `-fsanitize=address` | Shadow-memory checks on every load/store; heap/stack redzones; malloc/free hooks. | The ADPCM CVEs overflow heap allocations by a small number of bytes. Without ASan, these do not segfault — the overflow silently corrupts adjacent heap metadata. AFL++ would see no crash. |
> | `-g` | DWARF debug symbols. | ASan's `llvm-symbolizer` cannot map crash addresses to `file:line`. Stack traces become hex-only addresses; triage is much harder. |
> | `-O1` | Modest optimization. | `-O0` adds ~2–3× execution overhead (every variable lives in memory). `-O2`/`-O3` can merge distinct CFG edges, reducing coverage signal. `-O1` is the AFL++-recommended compromise. |
> | `--disable-shared` | Static-only SDL build. | Shared library requires runtime `LD_LIBRARY_PATH` setup inside the container, complicates the fork-server, and prevents the linker from dropping unreferenced object files. |
> | `SDL_VIDEODRIVER=dummy` | Headless video driver. | `SDL_Init(SDL_INIT_VIDEO)` (used by the BMP harness for `SDL_CreateRGBSurface`) would fail in the container without a display. |
> | No CRC / checksum patch | Not applicable — WAV and BMP have no integrity field that would cause the parser to reject mutated inputs before reaching the interesting code. | (N/A — this is an advantage over libpng.) |

---

## Q3 — Seed corpus and dictionary

> **Seeds.** The WAV corpus is bootstrapped from three hand-crafted files:
> `pcm_s16le.wav` (format 0x0001, PCM), `ms_adpcm.wav` (format 0x0002,
> MS-ADPCM), and `ima_adpcm.wav` (format 0x0011, IMA-ADPCM). The ADPCM seeds
> are critical: they immediately place AFL++ inside the `InitMS_ADPCM` /
> `MS_ADPCM_decode` and `InitIMA_ADPCM` / `IMA_ADPCM_decode` functions on the
> very first execution. Without them, AFL++ would only see PCM code until it
> randomly mutated the 2-byte `wFormatTag` field to 0x0002 or 0x0011 — a
> 1-in-65,536 event per mutation attempt. Five BMP seeds cover the four
> canonical SDL bit-depth paths (1/4/8/24/32 bpp), each routing through a
> different pixel-format conversion function.
>
> **Dictionary.** `sdl.dict` is a custom dictionary (AFL++ ships none for
> WAV/BMP). It contains RIFF chunk-type tags (`RIFF`, `WAVE`, `fmt `, `data`,
> `fact`, `LIST`, …), WAV format codes (`\x01\x00`, `\x02\x00`, `\x11\x00`),
> BMP magic bytes (`BM`, `BA`, …), and BMP compression codes. The chunk tags
> are 4-byte tokens that AFL++ can splice into mutated inputs to construct
> parseable RIFF structures from random bytes; the format codes gate which
> decoder runs and are 2-byte tokens that random bit-flips would statistically
> never construct.
>
> **Strategy yields after [X] min** (from AFL++ status screen):
>
> | Strategy | Paths / Execs | Notes |
> |---|---|---|
> | havoc/splice | [TODO] | |
> | bit/byte flips | [TODO] | |
> | arithmetic | [TODO] | |
> | dictionary | [TODO] | |

---

## Q4 — Campaign analysis

> **Instrumented WAV campaign — [X]-min run.**
>
> | Field | Value |
> |---|---|
> | run_time | [TODO] |
> | execs_done | [TODO] |
> | execs_per_sec | [TODO] |
> | corpus_count | [TODO] |
> | edges_found | [TODO] |
> | bitmap_cvg | [TODO] % |
> | stability | [TODO] % |
> | cycles_done | [TODO] |
> | saved_crashes | [TODO] |
>
> [Interpret edges-vs-time curve: initial ramp / ADPCM exploration / plateau.]
> [Discuss stability: 100 % confirms harness determinism.]

---

## Q5 — Crash triage

> **Crash triage.** The [X]-min instrumented WAV campaign found [N] crash(es).
>
> [If crashes found:]
> We selected the earliest crash (`id:000000,…`) for triage. Reproduction:
> `./sdl_wav_fuzz findings/default/crashes/id:000000,…` prints an ASan
> `heap-buffer-overflow` abort. We minimized the input with `afl-tmin`:
> the original [X]-byte file reduced to [Y] bytes — a RIFF envelope with a
> `fmt ` chunk setting `wFormatTag=0x0002` (MS-ADPCM) and `nBlockAlign=[Z]`,
> followed by a single `data` block. This maps to **CVE-2019-7575**:
> `MS_ADPCM_decode` in `audio/SDL_wave.c` computes the output buffer size
> from `nBlockAlign` and `wSamplesPerBlock` without bounds-checking the
> result, then writes [Z] bytes beyond the end of the allocation.
>
> ASan stack trace (abbreviated):
> ```
> WRITE of size 2 at offset [N] of [M]-byte region
>   #0 MS_ADPCM_decode (SDL_wave.c:[LINE])
>   #1 SDL_LoadWAV_RW  (SDL_wave.c:[LINE])
>   #2 main            (harness_wav.c:[LINE])
> ```
>
> [If no crashes found — unexpected but handled:]
> The campaign found no crashes. This is unexpected given the known CVEs in
> SDL 1.2.15. Possible explanations: [runtime too short / ADPCM paths not
> reached / SDL version used has a backported fix]. We extended the run to
> [Y] hours; alternatively, run with the BMP harness targeting
> CVE-2019-7637 (SDL_FillRect heap overflow).

---

## Q6 — Attack surface

> **Attack surface.** SDL 1.2.15 is used by thousands of games, emulators,
> and media players as their primary platform-abstraction layer. Two
> representative deployments with high attacker-controlled input exposure:
>
> **1. Game engines / emulators (e.g., DOSBox, ScummVM).**  
> These applications call `SDL_LoadWAV` or `SDL_LoadWAV_RW` on audio assets
> that may be loaded from user-supplied game data directories, mod archives,
> or downloaded content. An attacker who can influence the `.wav` files in a
> game's asset bundle — via a malicious mod, a compromised CDN, or a
> man-in-the-middle on an unencrypted asset download — can trigger the ADPCM
> heap overflows and gain arbitrary-write primitives in the game process.
>
> **2. Media players using SDL 1.2.x (e.g., older MPlayer builds, custom
> kiosk/embedded players).**  
> Players that accept user-supplied audio files as command-line arguments or
> via a file-picker directly call `SDL_LoadWAV` on attacker-controlled
> content. No user interaction beyond "open file" is required to trigger the
> bug.
>
> **Code paths our harness does not exercise:**
>
> 1. `SDL_mixer` (`Mix_LoadWAV`, `Mix_LoadMUS`). SDL_mixer is a separate
>    library that wraps SDL's audio subsystem and adds OGG, MP3, FLAC, and
>    MIDI support. Our harness calls `SDL_LoadWAV_RW` directly and does not
>    exercise the mixer layer. Bugs in `SDL_mixer`'s format dispatch or
>    codec wrappers are invisible to our campaign.
>
> 2. SDL_net / SDL_image. SDL has companion libraries for networking and
>    image loading. These are entirely separate from the core SDL audio/video
>    code and are not reached by our harness.

---

## Q7 — QEMU comparison

> **QEMU-mode campaign.**
>
> | Metric | Instrumented + ASan | QEMU mode | Δ |
> |---|---|---|---|
> | exec speed (last min) | [TODO] / sec | [TODO] / sec | [TODO] |
> | total execs | [TODO] | [TODO] | [TODO] |
> | corpus count | [TODO] | [TODO] | [TODO] |
> | cycles done | [TODO] | [TODO] | [TODO] |
> | edges_found / denominator | [TODO] | [TODO] | — |
> | stability | [TODO] % | [TODO] % | — |
> | saved crashes | [TODO] | [TODO] | — |
>
> [Explain speed difference: ASan shadow-memory cost vs. QEMU BB-translation
> cost. Explain denominator difference: compile-time edge count vs. AFL bitmap
> size. Explain crash detection gap: ASan catches silent overflows; QEMU mode
> only sees signal-raising crashes.]

---

## Q8 — Instrumentation depth and performance

> **Edge counts (`AFL_DEBUG=1`):**
>
> | Binary | Edges | Built with |
> |---|---|---|
> | `sdl_wav_fuzz` | [TODO] | afl-clang-fast + ASan + fork |
> | `sdl_wav_fuzz_no_san` | [TODO] | afl-clang-fast + fork (no ASan) |
> | `sdl_wav_fuzz_persistent` | [TODO] | afl-clang-fast + ASan + persistent |
> | SDL alone (whole-archive) | [TODO] | afl-clang-fast over libSDL.a |
>
> **Three-config exec speed:**
>
> | Config | Edges | Exec/sec | Execs in 30 s | Stability |
> |---|---|---|---|---|
> | (1) no ASan + fork | [TODO] | [TODO] | [TODO] | [TODO] % |
> | (2) ASan + fork (main) | [TODO] | [TODO] | [TODO] | [TODO] % |
> | (3) ASan + persistent | [TODO] | [TODO] | [TODO] | [TODO] % |
>
> [Explain persistent-mode speedup: fork elimination, shared-memory buffer,
> no shadow-init per iteration. Explain ASan overhead: shadow-memory check on
> every load/store. Explain stability drop in persistent mode if observed:
> SDL global state leaking between iterations.]
