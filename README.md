# CS-412 Fuzzing Lab — libpng with AFL++

Coverage-guided fuzzing of **libpng 1.2.56** with **AFL++**, in two modes:

1. **Source-available (white-box):** library compiled with AFL++ instrumentation
   and AddressSanitizer. The main bug-finding campaign.
2. **Binary-only (black-box):** same library compiled with vanilla `gcc` (no
   instrumentation, no sanitizer), fuzzed via AFL++ QEMU mode (`-Q`).

The full lab specification is in `Exercise Fuzzing.pdf` (one directory up).

---

## Why libpng 1.2.56?

- **CRC patch.** AFL++ ships `utils/libpng_no_checksum/libpng-nocrc.patch`, written
  for the 1.2.x series. The patch disables libpng's CRC-32 chunk check, which
  would otherwise reject ~99.99 % of mutated inputs. It applies cleanly to 1.2.56
  with `patch -p0`.
- **Known unfixed CVEs reachable from the public API** (e.g., CVE-2016-10087,
  NULL-deref in `png_set_text_2`). Increases the chance of finding real bugs
  during a 30-minute campaign.
- **The lab PDF (Section 2) explicitly endorses older versions:** *"Using an
  older version with known CVEs is acceptable and even encouraged."*

See `NOTES.md` for the full target-choice rationale and the alternatives that
were considered and rejected.

---

## Prerequisites

- **Docker** (Docker Desktop on macOS / Windows, or `docker` on Linux).
- ~2 GB free disk.
- ~5 minutes for the image build, 30+ minutes per fuzzing campaign.

The Docker container handles all toolchain setup (AFL++, libpng, sanitizers).
Nothing is installed on the host. The `aflplusplus/aflplusplus` base image is
multi-arch, so the container runs natively on both x86\_64 Linux and Apple
Silicon.

---

## Quick start

```bash
make build               # build the docker image (~3–5 min)
make sanity              # smoke-test the harness on a known-good seed
                         # must print "exit=0"

make fuzz TIME=1800      # 30-min instrumented + ASan campaign  → findings/
make fuzz-qemu TIME=1800 # 30-min QEMU-mode campaign            → findings-qemu/

make plot                # afl-plot pngs from findings/         → plot_output/
make plot-qemu           # afl-plot pngs from findings-qemu/    → plot_output_qemu/
```

`make help` lists every target.

For the **Q8 instrumentation-depth comparison** (three exec-speed configurations):

```bash
make fuzz-no-san     TIME=30   # config (1): no sanitizer + fork
make fuzz            TIME=30   # config (2): ASan + fork (smoke)
make fuzz-persistent TIME=30   # config (3): ASan + persistent
```

For the **Q5 synthetic-bug demo** (used when the main campaign finds no real
crashes — proves the toolchain catches bugs end-to-end):

```bash
make build-synthetic
make fuzz-synthetic           # 60-second run; AFL catches the injected bug
```

---

## Repo layout

```
fuzzing/
├── Dockerfile                  image recipe
│                                 - AFL++ toolchain
│                                 - libpng 1.2.56 built three ways
│                                   (instrumented + ASan / instrumented / vanilla)
│                                 - four harness binaries
├── Dockerfile.synthetic        layered image for the Q5 synthetic-bug demo
├── Makefile                    host wrapper (make build / fuzz / plot / clean)
├── README.md                   this file
├── NOTES.md                    decisions and rationale (target, harness, patches)
├── RUNBOOK.md                  step-by-step runbook for re-running each phase
├── REPORT_DRAFTS.md            draft prose for the Q1–Q8 report (→ LaTeX)
│
├── src/
│   ├── harness.c               fork-mode harness — main campaign target
│   └── harness_persistent.c    persistent-mode harness — Q8 perf comparison
│
├── patches/
│   ├── libpng-nocrc.patch      AFL++ CRC-removal patch (libpng 1.2.x)
│   └── synthetic_bug.patch     Q5 fallback: 1-byte heap overflow in
│                               png_handle_tEXt
│
├── seeds/                      6 small valid PNGs (one per color type / depth)
│   └── make_seeds.py           generator (excluded from the docker image)
│
├── findings/                   instrumented campaign output       (gitignored)
├── findings-qemu/              QEMU campaign output               (gitignored)
├── findings-persistent/        Q8 perf-test output                (gitignored)
├── findings-no-san/            Q8 perf-test output                (gitignored)
├── findings-synthetic/         Q5 demo output                     (gitignored)
├── plot_output/                afl-plot for the instrumented run  (gitignored)
└── plot_output_qemu/           afl-plot for the QEMU run          (gitignored)
```

The `findings*/` and `plot_output*/` directories are **gitignored** because the
files are large and regenerated on every run. They **must be included in the
final submission tarball** even though they are not in git — see the *Submission*
section below.

---

## Mental model — what each piece does

If you are new to fuzzing, here is the one-paragraph version:

- **The harness** (`src/harness.c`) is a small C program that takes one input
  file and feeds its bytes to libpng's decode pipeline (`png_read_info` →
  `png_set_expand` → `png_read_image` → `png_read_end`). The harness is the
  *driver* that bridges the fuzzer and the library.
- **AFL++** mutates random bytes in the input file (bit flips, arithmetic,
  splicing dictionary tokens, "havoc"), runs the harness on each mutation, and
  watches which code edges in libpng get exercised. Inputs that hit *new* edges
  are saved into the corpus and become the basis for further mutation.
- **AddressSanitizer (ASan)** is compiler-injected instrumentation that turns
  silent memory bugs (buffer overflows, use-after-free) into immediate, loud
  aborts with a full stack trace. Without it, only bugs that cause a segfault
  on their own are visible to the fuzzer.
- **The CRC patch** disables libpng's chunk-CRC check. Without it, every byte
  AFL++ mutates inside a PNG chunk would invalidate the CRC and libpng would
  reject the input before reaching the parser — coverage would plateau within
  minutes.
- **The dictionary** (`png.dict`, shipped with AFL++) is a list of 4-byte chunk
  type tokens (`IHDR`, `PLTE`, `IDAT`, `tEXt`, …). AFL++ splices them into
  mutated inputs so the fuzzer can reach chunk handlers that random bit flips
  would never construct (each 4-byte chunk type is 1 in 2³² by chance).

For full design rationale (why this harness shape, why 1.2.56, why ASan + fork
mode for the main run, why the persistent harness for Q8), see `NOTES.md`.

---

## How to find evidence for each evaluation question

| #  | Topic                          | Evidence                                                                                          |
|----|--------------------------------|---------------------------------------------------------------------------------------------------|
| Q1 | Harness design                 | `src/harness.c`; `NOTES.md` § *Harness design*; `REPORT_DRAFTS.md` § Q1                            |
| Q2 | Instrumentation & sanitizers   | `Dockerfile` (every `CFLAGS`/`LDFLAGS`); `patches/libpng-nocrc.patch`; `REPORT_DRAFTS.md` § Q2     |
| Q3 | Seeds and dictionary           | `seeds/`; container's `/work/png.dict`; AFL++ status screen (per-strategy yields)                  |
| Q4 | Campaign analysis              | `findings/default/fuzzer_stats`, `findings/default/plot_data`, `plot_output/edges.png`             |
| Q5 | Crash triage                   | `findings-synthetic/default/crashes/`; `findings-synthetic/min.png`; `patches/synthetic_bug.patch` |
| Q6 | Attack surface                 | `REPORT_DRAFTS.md` § Q6                                                                            |
| Q7 | QEMU comparison                | `findings-qemu/default/fuzzer_stats`, `plot_output_qemu/`; `REPORT_DRAFTS.md` § Q7                 |
| Q8 | Depth & performance            | `findings-persistent/default/fuzzer_stats`, `findings-no-san/default/fuzzer_stats`; edge counts via `AFL_DEBUG=1` |

---

## Status

| Item                                                          | Status |
|---------------------------------------------------------------|--------|
| Reproducible Dockerfile                                       | ✓      |
| Makefile (build / fuzz / plot / clean)                        | ✓      |
| Fork-mode harness `src/harness.c`                             | ✓      |
| Persistent-mode harness for Q8                                | ✓      |
| CRC-removal patch                                             | ✓      |
| Synthetic-bug patch (Q5 fallback)                             | ✓      |
| Seed corpus (6 PNGs covering all canonical color types)       | ✓      |
| Instrumented campaign, ≥30 min                                | ✓      |
| QEMU campaign, ≥30 min                                        | ✓      |
| `afl-plot` output for both campaigns                          | ✓      |
| Q5 synthetic-bug demo (saved crashes, minimized PoC)          | ✓      |
| Q1–Q8 prose drafts (in `REPORT_DRAFTS.md`)                    | ✓      |
| Q5 ASan stack trace captured to a file                        | ✗      |
| `AFL_DEBUG=1` edge counts captured to a file                  | ✗      |
| AFL++ status-screen screenshots (both campaigns, for appendix) | ✗      |
| `report.pdf` (USENIX class, ≤4 pages)                         | ✗      |
| Final submission tarball                                      | ✗      |

---

## Next steps to finalize the submission

1. **Re-run the main campaigns longer.** The current `findings/` shows
   `cycles_done = 1` after 30 minutes, which makes the Q4 saturation argument
   weak. Aim for 2–4 hours each so the edges curve clearly flattens:
   ```bash
   make clean
   make fuzz       TIME=14400   # 4 hours instrumented
   make fuzz-qemu  TIME=14400   # 4 hours QEMU
   make plot
   make plot-qemu
   ```
   While the campaigns are running, screenshot the AFL++ status screen near the
   end of each. The "fuzzing strategy yields" rows on that screen are the only
   place the per-stage path counts (havoc, splice, dictionary, …) appear, and Q3
   cites them.

2. **Capture missing artifacts.**
   ```bash
   # Q5 ASan stack trace
   docker run --rm -v $(pwd)/findings-synthetic:/work/findings cs412-fuzz-synthetic \
       bash -c 'ASAN_OPTIONS=symbolize=1 ./png_fuzz findings/min.png' \
       > findings-synthetic/asan_trace.txt 2>&1

   # Q8 instrumented edge counts
   mkdir -p docs
   for bin in png_fuzz png_fuzz_no_san png_fuzz_persistent; do
       echo "=== $bin ===" >> docs/edge_counts.txt
       docker run --rm -e AFL_DEBUG=1 cs412-fuzz ./$bin seeds/grayscale.png 2>&1 \
           | grep -E 'edges|map' >> docs/edge_counts.txt
   done
   ```

3. **Take screenshots** of the AFL++ TUI at the end of each campaign:
   - `appendix/status_main.png`  — instrumented run
   - `appendix/status_qemu.png`  — QEMU run

4. **Write the report.** Set up `usenix.cls`, port the Q1–Q8 prose from
   `REPORT_DRAFTS.md`, trim to ≤4 pages, attach the appendix figures and
   screenshots. Output: `report.pdf`.

5. **Build the submission tarball.** From one level above this repo:
   ```bash
   tar czf submission.tar.gz fuzzing/
   ```
   The tarball must include `findings/`, `findings-qemu/`, `plot_output/`,
   `plot_output_qemu/`, and `report.pdf` even though those paths are gitignored
   in the repo. Verify before uploading:
   ```bash
   tar tzf submission.tar.gz | grep findings/default/plot_data
   tar tzf submission.tar.gz | grep report.pdf
   ```

See `RUNBOOK.md` for the detailed phase-by-phase commands.

---

## Background reading

- AFL++ documentation: <https://aflplus.plus/docs/>
- AFL++ "fuzzing in depth": <https://aflplus.plus/docs/fuzzing_in_depth/>
- libpng manual: <http://www.libpng.org/pub/png/libpng-manual.txt>
- PNG file format spec (1.2): <http://www.libpng.org/pub/png/spec/1.2/PNG-Contents.html>
- AFL++ libpng CRC patch: `AFLplusplus/utils/libpng_no_checksum/`
- AFL++ PNG dictionary: `AFLplusplus/dictionaries/png.dict`
- AddressSanitizer paper: Serebryany et al., USENIX ATC 2012, *AddressSanitizer: A Fast Address Sanity Checker*
