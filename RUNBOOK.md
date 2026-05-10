# RUNBOOK — re-running each phase end-to-end

Step-by-step recipe for re-running the project from scratch on a clean clone.
Assumes Docker is installed.

---

## Phase A — environment build

```bash
make build          # ~3–5 min
make sanity-wav     # must print "exit=0"
make sanity-bmp     # must print "exit=0"
```

The image builds SDL 1.2.15 three ways (instrumented+ASan / instrumented /
vanilla gcc) and compiles five harness binaries. See `Dockerfile`.

---

## Phase B — instrumented WAV campaign (main)

```bash
make fuzz TIME=7200    # 2-hour WAV campaign
make plot
```

Screenshot the AFL++ status screen near the end. Record from `fuzzer_stats`:
- `stability`, `corpus_count`, `edges_found`, `cycles_done`, `saved_crashes`
- Per-strategy path counts (havoc, splice, dictionary rows on the TUI)

**If crashes were found** (expected — WAV ADPCM CVEs):

```bash
ls findings/default/crashes/
CRASH=findings/default/crashes/id:000000,...

# Reproduce
docker run --rm -v $PWD/findings:/work/findings cs412-fuzz-sdl \
    ./sdl_wav_fuzz "$CRASH"

# Minimize
docker run --rm -v $PWD/findings:/work/findings cs412-fuzz-sdl \
    afl-tmin -i "$CRASH" -o findings/min.wav -- ./sdl_wav_fuzz @@

# Symbolized ASan trace
docker run --rm -v $PWD/findings:/work/findings cs412-fuzz-sdl \
    bash -c 'ASAN_OPTIONS=symbolize=1 ./sdl_wav_fuzz findings/min.wav' \
    2>&1 | tee findings/asan_trace.txt
```

Map the crash to the CVE table in `NOTES.md`:
- `MS_ADPCM_decode` → CVE-2019-7575
- `InitMS_ADPCM` → CVE-2019-7573 / CVE-2019-7576
- `IMA_ADPCM_decode` → CVE-2019-7574
- `InitIMA_ADPCM` → CVE-2019-7572 / CVE-2019-7578

**If no crashes** (unexpected given known CVEs):

Run the BMP campaign — the BMP CVEs (pixel-format conversion) are a second
independent surface. If that also finds nothing, extend runtime to 4+ hours.

---

## Phase B2 — BMP campaign (secondary)

```bash
make fuzz-bmp TIME=3600
```

Crash triage is identical to Phase B with `./sdl_bmp_fuzz` instead.

---

## Phase C — QEMU black-box campaign (Q7)

```bash
make fuzz-qemu TIME=7200
make plot-qemu
```

Screenshot the QEMU-mode status screen. Compare with Phase B numbers:

```bash
grep -E "execs_done|execs_per_sec|corpus_count|edges_found|saved_crashes" \
    findings/default/fuzzer_stats findings-qemu/default/fuzzer_stats
```

Key axes for Q7: exec speed, edges discovered, corpus count, crash detection
sensitivity (ASan catches silent overflows; QEMU mode only catches segfaults).

---

## Phase D — Q8 instrumentation depth and exec-speed

Edge counts at startup:

```bash
# Library alone (whole-archive)
docker run --rm cs412-fuzz-sdl bash -c '
  echo "int main(){return 0;}" > /tmp/e.c
  afl-clang-fast /tmp/e.c \
    -Wl,--whole-archive /work/install/lib/libSDL.a \
    -Wl,--no-whole-archive -lm -fsanitize=address -o /tmp/L
  AFL_DEBUG=1 /tmp/L 2>&1 | grep edges
'

# WAV harness binary
docker run --rm -e AFL_DEBUG=1 cs412-fuzz-sdl \
    ./sdl_wav_fuzz seeds/wav/pcm_s16le.wav 2>&1 | grep edges
```

Three-config exec-speed comparison:

```bash
make fuzz-no-san     TIME=30    # config (1): no ASan + fork
make fuzz            TIME=30    # config (2): ASan + fork
make fuzz-persistent TIME=30    # config (3): ASan + persistent

grep execs_per_sec \
    findings/default/fuzzer_stats \
    findings-no-san/default/fuzzer_stats \
    findings-persistent/default/fuzzer_stats
```

Expected order: persistent ≫ no-san fork > ASan fork.

---

## Phase E — report

4-page USENIX-style body + appendix.

**Per-question checklist:**

- **Q1** Harness design: walk `src/harness_wav.c` data flow, justify no-setjmp, SDL_Init(0), freesrc=1. Mention BMP harness and why SDL_BlitSurface is needed.
- **Q2** Instrumentation: list every CFLAG/LDFLAG, explain SDL_VIDEODRIVER=dummy, note no CRC patch needed.
- **Q3** Seeds + dictionary: 3 WAV × 5 BMP seeds; custom `sdl.dict`. Cite havoc/splice/dictionary path counts from status screen.
- **Q4** Campaign analysis: stability, corpus, edges, cycles. Interpret the edges-vs-time curve.
- **Q5** Crash triage: reproduce → afl-tmin → ASan symbolized trace. Map to CVE.
- **Q6** Attack surface: name two real SDL deployments (game engines, media players). Identify harness blind spots (streamed audio, SDL_mixer, SDL_net).
- **Q7** QEMU comparison: side-by-side numbers, explain mechanism and ASan vs. signal-only detection difference.
- **Q8** Depth + perf: edge counts (library vs. harness), map density, three-config speed table, explain persistent-mode 100×+ gain.

**Appendix:** AFL++ status screenshots, afl-plot edges graphs, harness source.

**Submission tarball:**

```bash
tar czf submission.tar.gz fuzzing/
# Verify findings dirs are included (they are gitignored but must be in the tarball):
tar tzf submission.tar.gz | grep findings/default/plot_data
tar tzf submission.tar.gz | grep report.pdf
```
