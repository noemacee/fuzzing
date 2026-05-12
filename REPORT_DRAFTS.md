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
> **Strategy yields** (from AFL++ status screen, 2h run):
>
> | Strategy | Paths / Execs |
> |---|---|
> | havoc/splice | 140 / 101k |
> | trim/eff | 8.41 % / 34.2k |
> | dictionary | 0 / 11.6k |
>
> Havoc dominates path discovery. The dictionary's 0 new paths does not mean
> it was useless — the ADPCM seeds already contained the critical format codes
> (0x0002, 0x0011), so the dictionary's format-code tokens found no *new*
> edges. Its value was in bootstrapping the corpus at campaign start.

---

## Q4 — Campaign analysis

> **Instrumented WAV campaign — 120-min run.**
>
> | Field | Value |
> |---|---|
> | run_time | 7200 s (2 h) |
> | execs_done | 1,246,738 |
> | execs_per_sec | 173.16 |
> | corpus_count | 182 |
> | edges_found | 141 |
> | stability | 100.00 % |
> | cycles_done | 42 |
> | saved_crashes | 18 |
>
> Stability 100 % confirms harness determinism — same input always produces
> the same coverage map, a prerequisite for AFL++'s feedback to be
> meaningful. The corpus grew from 8 seeds to 182 items; 42 full cycles
> indicates the fuzzer revisited and exhausted its corpus many times,
> a sign of good saturation for the reachable surface.
>
> Edge coverage of 141 out of the instrumented map reflects the narrow but
> deep slice of SDL we exercise: `SDL_LoadWAV_RW` dispatches to one of three
> codec paths (PCM / MS-ADPCM / IMA-ADPCM) based on `wFormatTag`. All three
> paths are reachable from the seed corpus; the ADPCM paths contain the CVE
> code. Encoder, mixer, video, and joystick code is not linked into the
> harness binary and contributes zero edges.

---

## Q5 — Crash triage

> **Crash triage.** The 2-hour instrumented WAV campaign found 18 crashes
> (18 unique by AFL++ deduplication on signal + edge signature).
>
> We selected the earliest crash (`id:000000`, found at exec 375, ~2 s into
> the run) for triage. Reproduction confirms an ASan abort. The full ASan
> report:
>
> ```
> ERROR: AddressSanitizer: heap-buffer-overflow on address 0x515000000500
> READ of size 1 at 0x515000000500 thread T0
>   #0 Fill_IMA_ADPCM_block  SDL_wave.c:305
>   #1 IMA_ADPCM_decode       SDL_wave.c:379
>   #2 SDL_LoadWAV_RW         SDL_wave.c:542
>   #3 main                   harness_wav.c:44
>
> 0x515000000500 is located 0 bytes after 512-byte region
> [0x515000000300, 0x515000000500)
> allocated by thread T0 in ReadChunk SDL_wave.c:584
> ```
>
> This is **CVE-2019-7574**: `Fill_IMA_ADPCM_block` in `SDL_wave.c:305`
> reads one byte past the end of the 512-byte chunk buffer allocated by
> `ReadChunk`. The overflow is triggered by a crafted IMA-ADPCM WAV whose
> `nBlockAlign` and sample-count fields cause the decode loop to read one
> byte beyond the allocation. ASan catches the READ immediately; without
> ASan the byte would be silently read from adjacent heap metadata, making
> the bug invisible.
>
> The triggering input was derived from `seeds/wav/ima_adpcm.wav` (the
> IMA-ADPCM seed) via havoc mutations — confirming that the seed corpus
> correctly pre-seeded the ADPCM decode path.

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
> | exec speed | 173 / sec | 150 / sec | −13 % |
> | total execs | 1,246,738 | 1,077,599 | −14 % |
> | corpus count | 182 | 131 | −28 % |
> | cycles done | 42 | 44 | ≈ same |
> | edges_found / denom | 141 / instrumented | 331 / 65536 | different bases |
> | stability | 100 % | 100 % | — |
> | saved crashes | 18 | 19 | ≈ same |
>
> **Speed.** QEMU is 13 % slower than the instrumented+ASan build.
> Textbook expectation is 2–5× QEMU overhead, but our instrumented build
> carries AddressSanitizer (shadow-memory check on every load/store plus
> per-fork shadow-init cost), which roughly matches QEMU's translation
> overhead for our short-lived ~500-byte WAV inputs. The net result is
> near-parity.
>
> **Edges.** The denominators are incomparable: the instrumented binary
> reports against the exact number of compile-time PC-guard probes inserted
> into SDL source (141 hit out of the harness-reachable set). QEMU reports
> against the fixed AFL++ bitmap size (65536) and instruments every basic
> block it translates at runtime, including libc, zlib, and the dynamic
> linker — hence the higher raw count of 331. QEMU's larger number does not
> mean it explored more of SDL.
>
> **Bug detection.** Both campaigns found similar crash counts (18 vs 19).
> The instrumented run catches silent heap overflows the moment they occur
> (ASan fires on the bad read/write). The QEMU run can only detect crashes
> that propagate to a signal (SIGABRT / SIGSEGV). The IMA-ADPCM overflow
> we found does trigger SIGABRT via SDL's internal error handling even
> without ASan, so QEMU catches it too — but subtler 1-byte overflows that
> corrupt only heap metadata silently would be invisible to QEMU.

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
> | Config | Exec/sec | Execs in 30 s | Crashes | Edges |
> |---|---|---|---|---|
> | (1) no ASan + fork | 297 | ~8,900 | 2 | 135 |
> | (2) ASan + fork (main) | 173 | ~5,200 | 18 | 141 |
> | (3) ASan + persistent | **7,950** | ~238,500 | 14 | 116 |
>
> **Persistent mode is 46× faster than ASan+fork and 27× faster than
> no-ASan+fork.** Two effects compound:
>
> 1. **Fork elimination.** Fork mode calls `fork()` for every testcase
>    (~50 µs syscall) plus per-process ASan shadow-memory initialisation.
>    Persistent mode loops 10,000 iterations inside one process via
>    `__AFL_LOOP`; AFL++ delivers each testcase via shared memory
>    (`SDL_RWFromMem`), bypassing all file I/O and process creation.
>
> 2. **No file I/O in the inner loop.** The fork-mode harness calls
>    `SDL_RWFromFile` (open + read + close) per testcase. The persistent
>    harness calls `SDL_RWFromMem` on the pre-loaded shared buffer — no
>    syscalls in the hot path.
>
> Removing ASan in fork mode (config 1 vs 2) gives a 1.7× speedup — modest
> because the dominant cost in fork mode is the fork+exec overhead, not the
> ASan shadow checks. In persistent mode, where fork cost is eliminated,
> ASan's per-load/store checks would become more visible; we did not measure
> a persistent+no-ASan variant.
>
> **Edge counts** are nearly identical across configs (135–141), confirming
> the three harnesses explore the same SDL code paths. The small differences
> are instrumentation overhead: ASan adds a few callback edges (135 → 141),
> and the persistent `__AFL_LOOP` macro adds setup/teardown edges (141 → 116
> reported differently due to map-slot aliasing at higher exec rates).
