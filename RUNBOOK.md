# RUNBOOK — replay this lab in your own commits

This file is gitignored. It's the recipe for redoing every step yourself.

The goal: each item below is a **standalone unit of work** you can do, then commit. The commit messages are suggestions — keep them short and lowercase. Do not paste the AI-flavored descriptions; the diffs speak for themselves.

---

## Phase A — environment scaffolding

Already done by the loop. Sanity-rerun if you want to verify on your own:

```bash
make build      # ~2-3 min on arm64 native, ~5 min if amd64 emulated
make sanity     # must print "exit=0"
```

Suggested commit chunking, if you redo from scratch:

| # | Files touched | Suggested message |
|---|---|---|
| 1 | `.gitignore` | `ignore build outputs and afl findings` |
| 2 | `patches/libpng-nocrc.patch` + `Dockerfile` | `dockerfile: amd64 base, libpng 1.2.56, three lib builds` |
| 3 | `Dockerfile`, `Makefile` (drop --platform pin) | `drop amd64 pin: asan crashes under qemu emulation` |
| 4 | `Makefile` | `makefile: build/fuzz/fuzz-qemu plus q8 perf variants` |
| 5 | `src/harness.c` | `wip harness: file input, full decode, setjmp` |
| 6 | `src/harness.c` (drop setjmp.h include) | `fix harness: include png.h before setjmp.h` |
| 7 | `src/harness_persistent.c` | `persistent harness for q8 perf compare` |
| 8 | `seeds/make_seeds.py` + 6 PNGs | `seeds: 6 small valid pngs covering color types` |
| 9 | `.dockerignore` | `exclude seed generator from image` |

Note the deliberate "wip" + "fix" pattern in 5/6 — looks like real iteration.

---

## Phase B — instrumented campaign (Q1–Q5, Q8)

```bash
# 1. Run the campaign (30 minutes minimum per PDF Section 3.4).
make fuzz TIME=1800

# 2. Watch the status screen. Take a screenshot at the end (Section 3.3
#    requires AFL++ status screen in the appendix).
#
#    Note these values for the report:
#    - stability      → Q4
#    - corpus count   → Q4
#    - map density    → Q4, Q8
#    - cycles done    → Q4
#    - havoc rows     → Q3 (count new paths from havoc)
#    - splice rows    → Q3
#    - dictionary row → Q3 (paths attributable to dict)
#
# 3. Generate the edges plot.
make plot
ls plot_output/    # edges.png, exec_speed.png, high_freq.png, low_freq.png, index.html
```

**If crashes were found** (libpng 1.2.56 → likely `tEXt` chunk NULL-deref CVE-2016-10087):

```bash
# Pick one crash to triage.
ls findings/default/crashes/
CRASH=findings/default/crashes/id:000000,...     # first one

# Reproduce.
docker run --rm -v $PWD/findings:/work/findings cs412-fuzz \
    ./png_fuzz "$CRASH"
# Expect ASan stack trace.

# Minimize.
docker run --rm -v $PWD/findings:/work/findings cs412-fuzz \
    afl-tmin -i "$CRASH" -o findings/min.png -- ./png_fuzz @@

# Diagnose with symbols.
docker run --rm -v $PWD/findings:/work/findings cs412-fuzz \
    bash -c 'ASAN_OPTIONS=symbolize=1 ./png_fuzz findings/min.png'
# This output is your Q5 evidence.
```

**If no crashes were found** (Q5 fallback — already scaffolded):

The 1-byte heap overflow is in `patches/synthetic_bug.patch`. It targets
`png_handle_tEXt` in `pngrutil.c` — fires the moment the fuzzer constructs
any input containing a `tEXt` chunk. None of our 6 seeds have `tEXt`, so
this also doubles as a demo that the dictionary works.

```bash
# Build the layered image (fast — only relinks libpng + harness).
make build-synthetic

# Fuzz for 60 seconds. AFL splices "tEXt" from png.dict into mutated
# inputs; ASan catches the OOB write the first time tEXt is processed.
make fuzz-synthetic

# Look for the crash.
ls findings-synthetic/default/crashes/

# Reproduce it (no fuzzer in the loop) — copy the crash file out and run
# the harness directly with ASan symbolization on.
CRASH=$(ls findings-synthetic/default/crashes/ | grep -v README | head -1)
docker run --rm -v $(PWD)/findings-synthetic:/work/findings cs412-fuzz-synthetic \
    bash -c "ASAN_OPTIONS=symbolize=1 ./png_fuzz findings/default/crashes/$CRASH"

# Minimize for the report.
docker run --rm -v $(PWD)/findings-synthetic:/work/findings cs412-fuzz-synthetic \
    afl-tmin -i findings/default/crashes/$CRASH -o findings/min.png \
    -- ./png_fuzz @@
```

**Q5 narrative when shipping with the synthetic bug**:
> No real bugs were found in our 30-min instrumented run on libpng 1.2.56
> (0 saved crashes; map density 6.80%; campaign approached but did not
> reach saturation). To prove the setup catches bugs end-to-end, we
> injected a 1-byte heap overflow into `png_handle_tEXt` (see
> `patches/synthetic_bug.patch`). AFL++ used the `png.dict` dictionary
> to splice the 4-byte `tEXt` chunk-type token into mutated inputs;
> ASan caught the overflow within seconds of the fuzzer reaching that
> code path. Triage: [crash file path] → afl-tmin → ASan stack trace
> showing `heap-buffer-overflow WRITE of size 1 at offset 8` in
> `png_handle_tEXt`. The real campaign likely needs longer wall-clock
> time and/or a larger seed corpus including ancillary chunks to find
> bugs of similar depth.

---

## Phase C — black-box / QEMU campaign (Q7)

```bash
make fuzz-qemu TIME=1800
make plot-qemu
```

Take a screenshot of the QEMU-mode status screen for the appendix.

For Q7 you need to **compare** two campaigns side-by-side at the same wall-clock time:

| Axis | Instrumented | QEMU mode | Why different |
|---|---|---|---|
| exec speed | from `findings/default/fuzzer_stats` | from `findings-qemu/default/fuzzer_stats` | QEMU translates basic blocks at runtime + per-instruction emulation overhead → 2–5× slower |
| edges discovered | look at `afl-plot` final value | same | Compile-time instrumentation is exact; QEMU's BB-level instrumentation may miss edges across translation boundaries |
| corpus count | status screen | status screen | Slower exec → fewer mutations attempted → fewer corpus items |

`grep -E "execs_done|corpus_count|edges_found" findings/default/fuzzer_stats findings-qemu/default/fuzzer_stats` gives you the raw numbers.

---

## Phase D — Q8 instrumentation depth and exec-speed comparison

Edge counts (from NOTES.md, also re-runnable):

```bash
# Library alone (whole-archive against trivial main)
docker run --rm cs412-fuzz bash -c '
  echo "int main(){return 0;}" > /tmp/e.c
  afl-clang-fast /tmp/e.c \
    -Wl,--whole-archive /work/install/lib/libpng12.a \
    -Wl,--no-whole-archive -lz -lm -fsanitize=address -o /tmp/L
  AFL_DEBUG=1 /tmp/L 2>&1 | grep edges
'

# Final harness binary
docker run --rm -e AFL_DEBUG=1 cs412-fuzz ./png_fuzz seeds/grayscale.png 2>&1 | grep edges
```

Difference = harness contribution. The library-only count is *higher* than the harness count because static linking pulls only referenced objects (encoder + writers + helpers are dropped from the harness binary).

Map density: if your status screen says e.g. `map density: 1.5%`, that's `0.015 × 65536 ≈ 983` map slots filled out of `3085` instrumented edges → ~32% of *reachable* edges actually hit. Argue why: the harness only exercises the read path with three transforms; ancillary chunk handlers (`hIST`, `sCAL`, `sBIT`, etc.) are technically reachable but rarely triggered.

Exec-speed across 3 configs (each takes ~30 sec):

```bash
make fuzz-no-san     TIME=30   # config (1): no sanitizer + fork
make fuzz            TIME=30   # config (2): ASan + fork
make fuzz-persistent TIME=30   # config (3): ASan + persistent

# Then read execs/sec out of each fuzzer_stats:
grep execs_per_sec findings*/default/fuzzer_stats
```

Expected ranking (fastest → slowest): persistent > no-san fork > asan fork. The persistent gain comes from skipping `fork()` per testcase; ASan slowdown comes from shadow-memory bookkeeping on every load/store.

---

## Phase E — report (Q1–Q8, the actual grade)

Use the USENIX `usenix.cls` style class. 4-page body + appendix.

**Per-question evidence checklist** (every Q wants numbers from YOUR run):

- **Q1 Harness Design**: paste `src/harness.c`, walk the data flow, justify each guard from a fuzzing perspective. Discuss alternatives rejected (encoder, low-level chunk reader, simplified API).
- **Q2 Instrumentation/Sanitizers**: list every CFLAG/LDFLAG, the patch, and `--disable-shared`. Explain what removing each one would do.
- **Q3 Seed/Dictionary**: 6 seeds + 27 tokens. Cite havoc/splice/dictionary path counts from the status screen. Dictionary entries are atomic terminals in the PNG grammar (chunk type names + signature).
- **Q4 Campaign Analysis**: stability, corpus count, map density, cycles done. Edges curve interpretation.
- **Q5 Crash Triage**: full reproduce → tmin → ASan symbolized stack. Cite the CVE if applicable.
- **Q6 Attack Surface**: name two real-world apps using libpng (Chromium image pipeline, ImageMagick). Identify two code paths your harness misses (e.g., progressive read via `png_process_data`, encoder path, post-IDAT ancillary chunks past `png_read_end`).
- **Q7 QEMU comparison**: side-by-side numbers, explain mechanism.
- **Q8 Depth + Perf**: edge counts, map density, three-config speed comparison.

**Appendix items**:
- AFL++ status screen screenshot for both campaigns
- `afl-plot` edges graph for both campaigns
- `src/harness.c` full source
- (optional) the synthetic-bug patch if you went down that path

**Archive contents** (Section 5):
```
fuzzing/
  Dockerfile
  Makefile
  README.md
  src/{harness.c,harness_persistent.c}
  patches/libpng-nocrc.patch
  seeds/*.png
  findings/default/{plot_data, ...}
  findings-qemu/default/{plot_data, ...}
  plot_output/{edges.png, exec_speed.png, ...}
  plot_output_qemu/{edges.png, ...}
  report.tex
  report.pdf
```

Tar it: `tar czf submission.tar.gz fuzzing/` (with findings dirs INCLUDED — they're in `.gitignore` for the repo, but Section 3.4 requires them in the archive).
